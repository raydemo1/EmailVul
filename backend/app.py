from flask import Flask, request, jsonify
from werkzeug.utils import secure_filename
import os
import uuid
from .utils.email_parser import parse_email_file
from .detectors.ensemble import compute_risk
from flask import Response
from datetime import datetime, timezone
from .services.gemini_llm import _client as gemini_client
from .services.glm_llm import ensure_ready as glm_ready
from .services.gemini_llm import configure as gemini_configure
from .services.glm_llm import configure as glm_configure
from .services.advice import get_advice
from .services.gemini_llm import analyze_text as gemini_analyze_text
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.lib.utils import ImageReader
from reportlab.graphics.shapes import Drawing, Rect, String
from reportlab.graphics import renderPM
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.charts.barcharts import VerticalBarChart
from reportlab.graphics.charts.lineplots import LinePlot
import io
import datetime as dt

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024
app.config["UPLOAD_FOLDER"] = os.path.join(os.path.dirname(__file__), "uploads")
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

JOBS = {}
REPORTS = {}
HISTORY = []

def new_id():
    return uuid.uuid4().hex

@app.route("/api/emails/upload", methods=["POST"])
def upload_emails():
    model_choice = request.args.get("model", "gemini")
    try:
        prov = request.headers.get("X-LLM-Provider")
        if prov == "openai":
            from .services.custom_llm import configure as custom_configure, ensure_ready as custom_ready
            mk = request.headers.get("X-LLM-Model")
            ak = request.headers.get("X-LLM-API-Key")
            bu = request.headers.get("X-LLM-Base-URL")
            if mk or ak or bu:
                custom_configure(model=mk, api_key=ak, base_url=bu)
            custom_ready()
            model_choice = "custom"
        elif model_choice == "glm46":
            mk = request.headers.get("X-LLM-Model")
            ak = request.headers.get("X-LLM-API-Key")
            if mk or ak:
                glm_configure(model=mk, api_key=ak)
            glm_ready()
        else:
            mk = request.headers.get("X-LLM-Model")
            ak = request.headers.get("X-LLM-API-Key")
            if mk or ak:
                gemini_configure(model=mk, api_key=ak)
            gemini_client()
    except Exception as e:
        return jsonify({"error": "llm_required", "message": str(e)}), 500
    files = request.files.getlist("files")
    if not files:
        return jsonify({"error": "no_files"}), 400
    job_id = new_id()
    JOBS[job_id] = {"status": "processing", "total": len(files), "done": 0}
    result_ids = []
    for f in files:
        filename = secure_filename(f.filename)
        if not filename:
            continue
        path = os.path.join(app.config["UPLOAD_FOLDER"], new_id() + "_" + filename)
        f.save(path)
        parsed = parse_email_file(path)
        try:
            risk = compute_risk(parsed, model_choice)
        except Exception as e:
            JOBS[job_id]["status"] = "failed"
            return jsonify({"error": "llm_required", "message": str(e)}), 500
        report_id = new_id()
        report = {"id": report_id, "filename": filename, "risk": risk["score"], "confidence": risk["confidence"], "level": risk["level"], "features": risk["features"], "summary": risk["summary"], "meta": parsed["meta"], "threats": risk.get("threats", []), "chain": risk.get("chain", [])}
        REPORTS[report_id] = report
        HISTORY.append({"id": report_id, "level": report["level"], "score": report["risk"], "filename": filename, "ts": datetime.now(timezone.utc).isoformat()})
        result_ids.append(report_id)
        JOBS[job_id]["done"] += 1
    JOBS[job_id]["status"] = "done"
    return jsonify({"job_id": job_id, "report_ids": result_ids})

@app.route("/api/jobs/<job_id>", methods=["GET"])
def job_status(job_id):
    job = JOBS.get(job_id)
    if not job:
        return jsonify({"error": "not_found"}), 404
    return jsonify(job)

@app.route("/api/reports/<report_id>", methods=["GET"])
def get_report(report_id):
    report = REPORTS.get(report_id)
    if not report:
        return jsonify({"error": "not_found"}), 404
    return jsonify(report)

@app.route("/api/history", methods=["GET"])
def history():
    level = request.args.get("level")
    result = HISTORY
    if level:
        result = [r for r in HISTORY if r["level"] == level]
    return jsonify({"items": result})

@app.route("/api/alerts", methods=["GET"])
def alerts():
    result = [r for r in HISTORY if r["level"] in ["高", "危急"]]
    return jsonify({"items": result})

@app.route("/api/advice", methods=["GET"])
def advice():
    name = request.args.get("name")
    if not name:
        return jsonify({"error": "missing_name"}), 400
    return jsonify({"name": name, "recommendation": get_advice(name)})

@app.route("/api/llm/gemini/test", methods=["GET"])
def gemini_test():
    try:
        client = gemini_client()
        from .services.gemini_llm import DEFAULT_MODEL
        r = client.models.generate_content(model=DEFAULT_MODEL, contents=["ping"])
        text = getattr(r, "text", None) or getattr(r, "output_text", "") or ""
        return jsonify({"ok": True, "model": DEFAULT_MODEL, "text": text[:100]})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

@app.route("/api/llm/gemini/analyze", methods=["GET"])
def gemini_analyze():
    text = request.args.get("text", "")
    try:
        data = gemini_analyze_text(text)
        return jsonify({"ok": True, "data": data})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

@app.route("/api/v1/report/export", methods=["GET"])
def export_report():
    rid = request.args.get("id")
    fmt = request.args.get("format", "pdf").lower()
    if not rid:
        return jsonify({"error": "missing_id"}), 400
    rep = REPORTS.get(rid)
    if not rep:
        return jsonify({"error": "not_found"}), 404
    level = rep.get("level", "未知")
    date_str = dt.datetime.now().strftime("%Y%m%d")
    if fmt == "json":
        buf = io.BytesIO()
        import json
        buf.write(json.dumps(rep, ensure_ascii=False, indent=2).encode("utf-8"))
        buf.seek(0)
        return Response(buf.read(), headers={"Content-Disposition": f"attachment; filename=report_{date_str}_{level}.json"}, mimetype="application/json")
    else:
        buf = io.BytesIO()
        c = canvas.Canvas(buf, pagesize=A4)
        w, h = A4
        y = h - 20*mm
        c.setFont("Helvetica", 14)
        c.drawString(20*mm, y, "钓鱼邮件检测报告")
        y -= 10*mm
        c.setFont("Helvetica", 10)
        c.drawString(20*mm, y, f"文件: {rep.get('filename')}  等级: {level}  风险分: {rep.get('risk')}  置信度: {rep.get('confidence')}")
        y -= 8*mm
        def _make_bar_png(labels, counts, title):
            dw = 500; dh = 260
            d = Drawing(dw, dh)
            bc = VerticalBarChart()
            bc.x = 40; bc.y = 40
            bc.width = dw - 80; bc.height = dh - 90
            bc.data = [list(map(int, counts))]
            bc.categoryAxis.categoryNames = [str(x) for x in labels]
            bc.categoryAxis.labels.angle = 45
            bc.categoryAxis.labels.fontSize = 8
            bc.bars.strokeWidth = 0
            d.add(bc)
            d.add(String(20, dh-20, title, fontSize=12))
            return renderPM.drawToString(d, fmt='PNG')
        def _make_pie_png(labels, counts, title):
            dw = 500; dh = 260
            d = Drawing(dw, dh)
            p = Pie()
            p.x = 20; p.y = 40
            p.width = dw - 40; p.height = dh - 80
            p.data = list(map(int, counts))
            p.labels = [str(x) for x in labels]
            d.add(p)
            d.add(String(20, dh-20, title, fontSize=12))
            return renderPM.drawToString(d, fmt='PNG')
        def _make_line_png(labels, counts, title):
            dw = 680; dh = 250
            d = Drawing(dw, dh)
            lp = LinePlot()
            lp.x = 40; lp.y = 40
            lp.width = dw - 80; lp.height = dh - 90
            xs = list(range(len(labels)))
            lp.data = [list(zip(xs, list(map(int, counts))))]
            lp.lineLabels.fontSize = 8
            lp.xValueAxis.valueMin = 0
            lp.xValueAxis.valueMax = max(xs) if xs else 1
            lp.xValueAxis.labelTextFormat = lambda i: labels[int(i)] if 0 <= int(i) < len(labels) else ''
            lp.xValueAxis.labels.angle = 45
            lp.xValueAxis.labels.fontSize = 8
            lp.yValueAxis.visible = False
            d.add(lp)
            d.add(String(20, dh-20, title, fontSize=12))
            return renderPM.drawToString(d, fmt='PNG')
        def _stats_data():
            total = len(HISTORY)
            levels = {"低":0, "中":0, "高":0, "危急":0}
            hist = [0]*10
            daily = {}
            for hitem in HISTORY:
                levels[hitem["level"]] = levels.get(hitem["level"], 0) + 1
                s = int(hitem.get("score", 0))
                b = min(9, max(0, s // 10))
                hist[b] += 1
                ts = hitem.get("ts")
                date = (ts[:10] if isinstance(ts, str) and len(ts) >= 10 else datetime.now(timezone.utc).date().isoformat())
                daily[date] = daily.get(date, 0) + 1
            return {"levels": levels, "hist": hist, "daily": sorted([{"date": d, "count": c} for d, c in daily.items()], key=lambda x: x["date"])}
        sd = _stats_data()
        try:
            lpng = _make_pie_png(list(sd["levels"].keys()), list(sd["levels"].values()), "等级分布")
            rpng = _make_bar_png([f"{i*10}-{(i+1)*10}" for i in range(10)], sd["hist"], "风险直方图")
            limg = ImageReader(io.BytesIO(lpng)) if lpng else None
            rimg = ImageReader(io.BytesIO(rpng)) if rpng else None
            if limg:
                c.drawImage(limg, 20*mm, y-60*mm, width=80*mm, height=50*mm, preserveAspectRatio=True, mask='auto')
            if rimg:
                c.drawImage(rimg, 110*mm, y-60*mm, width=80*mm, height=50*mm, preserveAspectRatio=True, mask='auto')
            y -= 60*mm
            ditems = sd["daily"][-30:]
            dlabels = [x["date"] for x in ditems]
            dcounts = [x["count"] for x in ditems]
            dpng = _make_line_png(dlabels, dcounts, "每日处理量")
            if dpng:
                dimg = ImageReader(io.BytesIO(dpng))
                c.drawImage(dimg, 20*mm, y-55*mm, width=170*mm, height=45*mm, preserveAspectRatio=True, mask='auto')
                y -= 55*mm
        except Exception:
            pass
        c.drawString(20*mm, y, "检测依据：")
        y -= 6*mm
        for line in (rep.get("summary") or "").split():
            c.drawString(25*mm, y, line)
            y -= 6*mm
            if y < 30*mm:
                c.showPage(); y = h - 20*mm
        c.drawString(20*mm, y, "威胁列表：")
        y -= 6*mm
        for th in rep.get("threats", []):
            c.drawString(25*mm, y, f"- {th.get('name')} [{th.get('severity')}] 向量:{th.get('vector')}" )
            y -= 6*mm
            c.drawString(25*mm, y, f"受影响:{','.join(th.get('affected',[]))} 后果:{th.get('impact')}" )
            y -= 6*mm
            evs = th.get('evidence', [])
            for ev in evs:
                c.drawString(25*mm, y, f"证据:{ev}")
                y -= 6*mm
                if y < 30*mm:
                    c.showPage(); y = h - 20*mm
            if y < 30*mm:
                c.showPage(); y = h - 20*mm
        c.drawString(20*mm, y, "攻击链：")
        y -= 6*mm
        c.drawString(25*mm, y, " → ".join(rep.get("chain", [])))
        y -= 10*mm
        c.drawString(20*mm, y, "签名：本报告包含摘要哈希以供校验")
        import hashlib
        hval = hashlib.sha256((rep.get("summary") or "").encode("utf-8")).hexdigest()
        y -= 6*mm
        c.drawString(25*mm, y, f"摘要SHA256: {hval}")
        c.showPage()
        c.save()
        buf.seek(0)
        return Response(buf.read(), headers={"Content-Disposition": f"attachment; filename=report_{date_str}_{level}.pdf", "Cache-Control": "no-store"}, mimetype="application/pdf")

@app.route("/api/stats", methods=["GET"])
def stats():
    total = len(HISTORY)
    levels = {"低":0, "中":0, "高":0, "危急":0}
    hist = [0]*10
    daily = {}
    avg = {"risk": 0.0}
    feat_avg = {"keyword":0.0, "url":0.0, "attachment":0.0}
    llm_avg = {"style_anomaly":0.0, "social_engineering":0.0, "llm_generated_probability":0.0, "available_ratio":0.0}
    llm_count = 0
    for h in HISTORY:
        levels[h["level"]] = levels.get(h["level"], 0) + 1
        s = int(h.get("score", 0))
        b = min(9, max(0, s // 10))
        hist[b] += 1
        ts = h.get("ts")
        date = (ts[:10] if isinstance(ts, str) and len(ts) >= 10 else datetime.now(timezone.utc).date().isoformat())
        daily[date] = daily.get(date, 0) + 1
        avg["risk"] += s
        rid = h["id"]
        rep = REPORTS.get(rid)
        if rep:
            rules = rep.get("features", {}).get("rules", {})
            feat_avg["keyword"] += float(rules.get("keyword", 0))
            feat_avg["url"] += float(rules.get("url", 0))
            feat_avg["attachment"] += float(rules.get("attachment", 0))
            llm = rep.get("features", {}).get("llm", {})
            if isinstance(llm, dict) and llm:
                llm_count += 1
                llm_avg["style_anomaly"] += float(llm.get("style_anomaly", 0))
                llm_avg["social_engineering"] += float(llm.get("social_engineering", 0))
                llm_avg["llm_generated_probability"] += float(llm.get("llm_generated_probability", 0))
    if total > 0:
        avg["risk"] = round(avg["risk"] / total, 2)
        feat_avg = {k: round(v / total, 2) for k, v in feat_avg.items()}
    if llm_count > 0:
        llm_avg["style_anomaly"] = round(llm_avg["style_anomaly"] / llm_count, 2)
        llm_avg["social_engineering"] = round(llm_avg["social_engineering"] / llm_count, 2)
        llm_avg["llm_generated_probability"] = round(llm_avg["llm_generated_probability"] / llm_count, 2)
    llm_avg["available_ratio"] = round((llm_count / total) if total else 0.0, 2)
    daily_items = sorted([{"date": d, "count": c} for d, c in daily.items()], key=lambda x: x["date"]) 
    return jsonify({
        "total": total,
        "levels": levels,
        "avg": avg,
        "risk_histogram": {"bins": [f"{i*10}-{(i+1)*10}" for i in range(10)], "counts": hist},
        "daily": daily_items,
        "features_avg": feat_avg,
        "llm_avg": llm_avg,
    })

@app.route("/", methods=["GET"])
def index_page():
    base = os.path.dirname(os.path.dirname(__file__))
    path = os.path.join(base, "frontend", "index.html")
    if not os.path.exists(path):
        return Response("frontend missing", status=404)
    with open(path, "rb") as f:
        data = f.read()
    return Response(data, mimetype="text/html")

def create_app():
    return app

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)
