from flask import Flask, request, jsonify
from werkzeug.utils import secure_filename
import os
import uuid
from .utils.email_parser import parse_email_file
from .detectors.ensemble import compute_risk
from flask import Response
from flask import send_from_directory
from datetime import datetime, timezone
from .services.gemini_llm import _client as gemini_client
from .services.glm_llm import ensure_ready as glm_ready
from .services.gemini_llm import configure as gemini_configure
from .services.glm_llm import configure as glm_configure
from .services.advice import get_advice
from .services.gemini_llm import analyze_text as gemini_analyze_text

# --- 升级后的 PDF 生成库引入 ---
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    Image,
    PageBreak,
)
from reportlab.graphics.shapes import Drawing
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.charts.barcharts import VerticalBarChart
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
import re

import io
import datetime as dt
import random
import logging

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024
app.config["UPLOAD_FOLDER"] = os.path.join(os.path.dirname(__file__), "uploads")
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

# 确保 data 目录存在
DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
os.makedirs(DATA_DIR, exist_ok=True)

JOBS = {}
REPORTS = {}
HISTORY = []

BASE_DIR = os.path.dirname(os.path.dirname(__file__))
FRONTEND_DIR = os.path.join(BASE_DIR, "frontend")
STORAGE_PATH = os.path.join(os.path.dirname(__file__), "storage.json")
DELETED_IDS = set()
DELETED_META = {}
_NOT_FOUND_LOG = {}


# --- 字体注册逻辑 ---
def register_chinese_font():
    """尝试注册中文字体"""
    font_name = "Helvetica"
    candidates = [
        os.path.join(DATA_DIR, "SimHei.ttf"),
        os.path.join(DATA_DIR, "msyh.ttf"),
        "/usr/share/fonts/truetype/droid/DroidSansFallbackFull.ttf",
        "C:\\Windows\\Fonts\\simhei.ttf",
    ]

    for path in candidates:
        if os.path.exists(path):
            try:
                pdfmetrics.registerFont(TTFont("ChineseFont", path))
                font_name = "ChineseFont"
                break
            except Exception as e:
                print(f"Failed to load font {path}: {e}")
                continue

    return font_name


APP_FONT = register_chinese_font()


def _save_storage():
    try:
        import json

        data = {
            "reports": REPORTS,
            "history": HISTORY,
            "deleted_ids": list(DELETED_IDS),
            "deleted_meta": DELETED_META,
        }
        with open(STORAGE_PATH, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    except Exception:
        pass


def _load_storage():
    try:
        import json

        if os.path.exists(STORAGE_PATH):
            with open(STORAGE_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
            REPORTS.update(data.get("reports", {}))
            HISTORY.extend(data.get("history", []))
            for rid in data.get("deleted_ids", []):
                DELETED_IDS.add(rid)
            meta = data.get("deleted_meta", {})
            if isinstance(meta, dict):
                DELETED_META.update(meta)
    except Exception:
        pass


def new_id():
    return uuid.uuid4().hex


@app.route("/api/emails/upload", methods=["POST"])
def upload_emails():
    model_choice = request.args.get("model", "gemini")
    # ... (省略中间保持不变的上传逻辑) ...
    # 为了节省空间，此处仅展示未修改部分的占位，实际运行时请保留原有代码逻辑
    # 您提供的原文件逻辑这里没有变化
    try:
        prov = request.headers.get("X-LLM-Provider")
        if prov == "openai":
            from .services.custom_llm import (
                configure as custom_configure,
                ensure_ready as custom_ready,
            )

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
            print(f"Error computing risk for {filename}: {e}")
            report_id = new_id()
            report = {
                "id": report_id,
                "filename": filename,
                "risk": 0,
                "confidence": 0,
                "level": "错误",
                "features": {},
                "summary": f"分析失败: {str(e)}",
                "meta": {},
                "threats": [],
                "chain": [],
            }
            REPORTS[report_id] = report
            result_ids.append(report_id)
            JOBS[job_id]["done"] += 1
            continue

        report_id = new_id()
        report = {
            "id": report_id,
            "filename": filename,
            "risk": risk["score"],
            "confidence": risk["confidence"],
            "level": risk["level"],
            "features": risk["features"],
            "summary": risk["summary"],
            "meta": parsed["meta"],
            "threats": risk.get("threats", []),
            "chain": risk.get("chain", []),
        }
        REPORTS[report_id] = report
        HISTORY.append(
            {
                "id": report_id,
                "level": report["level"],
                "score": report["risk"],
                "filename": filename,
                "ts": datetime.now(timezone.utc).isoformat(),
            }
        )
        result_ids.append(report_id)
        JOBS[job_id]["done"] += 1

    JOBS[job_id]["status"] = "done"
    _save_storage()
    return jsonify({"job_id": job_id, "report_ids": result_ids})


@app.route("/api/jobs/<job_id>", methods=["GET"])
def job_status(job_id):
    job = JOBS.get(job_id)
    if not job:
        return jsonify({"error": "not_found"}), 404
    return jsonify(job)


@app.route("/api/reports/<report_id>", methods=["GET"])
def get_report(report_id):
    if report_id in DELETED_IDS:
        return jsonify({"error": "deleted", "message": "该报告已被删除"}), 410
    report = REPORTS.get(report_id)
    if not report:
        return jsonify({"error": "not_found"}), 404
    return jsonify(report)


@app.route("/api/reports", methods=["GET"])
def list_reports():
    items = []
    ts_map = {h["id"]: h.get("ts") for h in HISTORY}
    for rid, rep in REPORTS.items():
        items.append(
            {
                "id": rid,
                "filename": rep.get("filename"),
                "risk": rep.get("risk"),
                "level": rep.get("level"),
                "ts": ts_map.get(rid),
                "deleted": rid in DELETED_IDS,
            }
        )
    items.sort(key=lambda x: (x.get("ts") or ""), reverse=True)
    return jsonify({"items": items})


@app.route("/api/reports/latest", methods=["GET"])
def latest_report():
    if not HISTORY:
        return jsonify({"error": "not_found"}), 404
    items = sorted(HISTORY, key=lambda x: x.get("ts") or "", reverse=True)
    rid = items[0]["id"]
    if rid in DELETED_IDS:
        return jsonify({"error": "deleted", "message": "该报告已被删除"}), 410
    rep = REPORTS.get(rid)
    if not rep:
        return jsonify({"error": "not_found"}), 404
    return jsonify(rep)


@app.route("/api/history", methods=["GET"])
def history():
    level = request.args.get("level")
    result = []
    for r in HISTORY:
        item = dict(r)
        item["deleted"] = r.get("id") in DELETED_IDS
        result.append(item)
    if level:
        result = [r for r in result if r["level"] == level]
    return jsonify({"items": result})


@app.route("/api/engine/status", methods=["GET"])
def engine_status():
    return jsonify({"online": True})


@app.route("/api/engine/latency", methods=["GET"])
def engine_latency():
    return jsonify({"latency": random.randint(80, 280)})


def _mock_events():
    evs = []
    for h in HISTORY[-20:]:
        evs.append(
            {
                "ts": h.get("ts"),
                "src": "10.0.%d.%d" % (random.randint(0, 255), random.randint(1, 254)),
                "type": "phish" if h.get("level") in ["高", "危急"] else "other",
                "summary": "文件:%s 等级:%s 风险:%s"
                % (h.get("filename"), h.get("level"), h.get("score")),
                "risk": int(h.get("score") or 0),
            }
        )
    return evs[-10:]


@app.route("/api/events/latest", methods=["GET"])
def events_latest():
    return jsonify(_mock_events())


@app.route("/ws/events", methods=["GET"])
def ws_events():
    return jsonify({"error": "websocket_not_supported"}), 426


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


# --- Markdown 转换辅助函数 ---
def md_to_rml(text):
    """将简单的 Markdown 转换为 ReportLab 支持的 XML 标签"""
    if not text:
        return ""
    # 转义特殊字符
    text = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    # 加粗 **text** -> <b>text</b>
    text = re.sub(r"\*\*(.*?)\*\*", r"<b>\1</b>", text)
    # 列表 - item -> <bullet>•</bullet> item (需配合 Paragraph 样式)
    # 这里简单处理换行
    text = text.replace("\n", "<br/>")
    return text


@app.route("/api/v1/report/export", methods=["GET"])
def export_report():
    rid = request.args.get("id")
    fmt = request.args.get("format", "pdf").lower()
    if not rid:
        return jsonify({"error": "missing_id"}), 400
    if rid in DELETED_IDS:
        return jsonify({"error": "deleted", "message": "该报告已被删除"}), 410

    rep = REPORTS.get(rid)
    if not rep:
        return jsonify({"error": "not_found"}), 404

    level = rep.get("level", "未知")
    date_str = dt.datetime.now().strftime("%Y%m%d")

    if fmt == "json":
        buf = io.BytesIO()
        import json
        from urllib.parse import quote

        buf.write(json.dumps(rep, ensure_ascii=False, indent=2).encode("utf-8"))
        buf.seek(0)
        filename = f"report_{date_str}_{level}.json"
        quoted_filename = quote(filename)
        return Response(
            buf.read(),
            headers={
                "Content-Disposition": f"attachment; filename*=UTF-8''{quoted_filename}"
            },
            mimetype="application/json",
        )
    else:
        # --- 使用 Platypus 引擎生成美观的 PDF ---
        try:
            from urllib.parse import quote

            buf = io.BytesIO()
            doc = SimpleDocTemplate(
                buf,
                pagesize=A4,
                rightMargin=20 * mm,
                leftMargin=20 * mm,
                topMargin=20 * mm,
                bottomMargin=20 * mm,
            )
            story = []
            styles = getSampleStyleSheet()

            # 定义支持中文的样式
            title_style = ParagraphStyle(
                name="TitleStyle",
                parent=styles["Heading1"],
                fontName=APP_FONT,
                fontSize=24,
                leading=30,
                alignment=1,  # Center
                spaceAfter=20,
            )

            heading_style = ParagraphStyle(
                name="HeadingStyle",
                parent=styles["Heading2"],
                fontName=APP_FONT,
                fontSize=16,
                leading=20,
                spaceBefore=15,
                spaceAfter=10,
                textColor=colors.HexColor("#2563eb"),
            )

            normal_style = ParagraphStyle(
                name="NormalStyle",
                parent=styles["Normal"],
                fontName=APP_FONT,
                fontSize=10,
                leading=14,
                spaceAfter=6,
            )

            bold_style = ParagraphStyle(
                name="BoldStyle",
                parent=normal_style,
                fontName=APP_FONT,  # 需粗体字体文件才生效，否则仅依靠标签
            )

            # 1. 标题
            story.append(Paragraph("钓鱼邮件检测报告", title_style))
            story.append(Spacer(1, 10))

            # 2. 基础信息表格
            meta_data = [
                [
                    "文件名称",
                    rep.get("filename"),
                    "检测时间",
                    dt.datetime.now().strftime("%Y-%m-%d %H:%M"),
                ],
                ["风险等级", level, "风险评分", str(rep.get("risk"))],
                [
                    "置信度",
                    str(rep.get("confidence")),
                    "报告ID",
                    rep.get("id")[:8] + "...",
                ],
            ]

            t = Table(meta_data, colWidths=[30 * mm, 55 * mm, 30 * mm, 55 * mm])
            t.setStyle(
                TableStyle(
                    [
                        ("FONTNAME", (0, 0), (-1, -1), APP_FONT),
                        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f1f5f9")),
                        ("BACKGROUND", (2, 0), (2, -1), colors.HexColor("#f1f5f9")),
                        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                        ("PADDING", (0, 0), (-1, -1), 6),
                        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                    ]
                )
            )
            story.append(t)
            story.append(Spacer(1, 20))

            # 3. 智能摘要 (支持 Markdown 渲染)
            story.append(Paragraph("智能分析摘要", heading_style))
            summary_text = rep.get("summary", "暂无摘要")
            # 处理 Markdown 文本
            formatted_summary = md_to_rml(summary_text)
            story.append(Paragraph(formatted_summary, normal_style))
            story.append(Spacer(1, 15))

            # 4. 统计图表 (Pie & Bar)
            # 为了美观，我们并排展示
            # 计算数据
            hist = [0] * 10
            # 这里简单复用逻辑，只展示当前风险分布意义不大，展示历史分布
            levels = {"低": 0, "中": 0, "高": 0, "危急": 0}
            for hitem in HISTORY:
                lv = hitem.get("level", "低")
                levels[lv] = levels.get(lv, 0) + 1

            # 饼图 Drawing
            d_pie = Drawing(200, 150)
            pc = Pie()
            pc.x = 50
            pc.y = 10
            pc.width = 100
            pc.height = 100
            pc.data = list(levels.values()) or [1]
            pc.labels = list(levels.keys()) or ["无"]
            for i in range(len(pc.data)):
                pc.slices[i].fontName = APP_FONT
                pc.slices[i].fontSize = 10
            d_pie.add(pc)

            # 5. 威胁详情 (卡片式/表格)
            story.append(Paragraph("威胁详情", heading_style))
            threats = rep.get("threats", [])
            if not threats:
                story.append(Paragraph("未检测到明显威胁。", normal_style))
            else:
                for th in threats:
                    # 每个威胁用一个带有边框的表格块展示
                    th_name = th.get("name", "未知威胁")
                    th_severity = th.get("severity", "低")
                    th_color = (
                        colors.red if th_severity in ["高", "危急"] else colors.orange
                    )

                    # 标题行
                    header_para = Paragraph(
                        f"<b>{th_name}</b> <font color='{th_color}'>[{th_severity}]</font>",
                        normal_style,
                    )

                    # 内容
                    content_rows = []
                    if th.get("impact"):
                        content_rows.append(
                            [
                                Paragraph(
                                    f"<b>后果:</b> {th.get('impact')}", normal_style
                                )
                            ]
                        )
                    if th.get("recommendation"):
                        content_rows.append(
                            [
                                Paragraph(
                                    f"<b>建议:</b> {md_to_rml(th.get('recommendation'))}",
                                    normal_style,
                                )
                            ]
                        )
                    if th.get("evidence"):
                        ev_text = "<br/>".join([f"• {e}" for e in th.get("evidence")])
                        content_rows.append(
                            [Paragraph(f"<b>证据:</b><br/>{ev_text}", normal_style)]
                        )

                    # 组装内部表格
                    inner_t = Table(content_rows, colWidths=[160 * mm])
                    inner_t.setStyle(
                        TableStyle(
                            [
                                ("LEFTPADDING", (0, 0), (-1, -1), 0),
                                ("TOPPADDING", (0, 0), (-1, -1), 2),
                            ]
                        )
                    )

                    # 外层容器表格
                    container_data = [[header_para], [inner_t]]
                    container_t = Table(container_data, colWidths=[170 * mm])
                    container_t.setStyle(
                        TableStyle(
                            [
                                (
                                    "BOX",
                                    (0, 0),
                                    (-1, -1),
                                    1,
                                    colors.HexColor("#e2e8f0"),
                                ),
                                (
                                    "BACKGROUND",
                                    (0, 0),
                                    (0, 0),
                                    colors.HexColor("#f8fafc"),
                                ),
                                ("PADDING", (0, 0), (-1, -1), 10),
                                ("BOTTOMPADDING", (0, 0), (0, 0), 10),
                            ]
                        )
                    )
                    story.append(container_t)
                    story.append(Spacer(1, 10))

            # 6. 攻击链
            story.append(Paragraph("攻击链分析", heading_style))
            chain = rep.get("chain", [])
            if chain:
                chain_str = "  →  ".join(chain)
                story.append(Paragraph(chain_str, normal_style))
            else:
                story.append(Paragraph("无攻击链数据", normal_style))

            # 生成
            doc.build(story)

            buf.seek(0)
            filename = f"report_{date_str}_{level}.pdf"
            quoted_filename = quote(filename)
            return Response(
                buf.read(),
                headers={
                    "Content-Disposition": f"attachment; filename*=UTF-8''{quoted_filename}",
                    "Cache-Control": "no-store",
                },
                mimetype="application/pdf",
            )
        except Exception as e:
            import traceback

            traceback.print_exc()
            return jsonify({"error": "export_error", "message": str(e)}), 500


@app.route("/api/stats", methods=["GET"])
def stats():
    total = len(HISTORY)
    levels = {"低": 0, "中": 0, "高": 0, "危急": 0}
    hist = [0] * 10
    daily = {}
    avg = {"risk": 0.0}
    feat_avg = {"keyword": 0.0, "url": 0.0, "attachment": 0.0}
    llm_avg = {
        "style_anomaly": 0.0,
        "social_engineering": 0.0,
        "llm_generated_probability": 0.0,
        "available_ratio": 0.0,
    }
    llm_count = 0

    for h in HISTORY:
        lv = h.get("level", "低")
        levels[lv] = levels.get(lv, 0) + 1
        s = int(h.get("score", 0))
        b = min(9, max(0, s // 10))
        hist[b] += 1
        ts = h.get("ts")
        date = (
            ts[:10]
            if isinstance(ts, str) and len(ts) >= 10
            else datetime.now(timezone.utc).date().isoformat()
        )
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
                llm_avg["llm_generated_probability"] += float(
                    llm.get("llm_generated_probability", 0)
                )

    if total > 0:
        avg["risk"] = round(avg["risk"] / total, 2)
        feat_avg = {k: round(v / total, 2) for k, v in feat_avg.items()}
    if llm_count > 0:
        llm_avg["style_anomaly"] = round(llm_avg["style_anomaly"] / llm_count, 2)
        llm_avg["social_engineering"] = round(
            llm_avg["social_engineering"] / llm_count, 2
        )
        llm_avg["llm_generated_probability"] = round(
            llm_avg["llm_generated_probability"] / llm_count, 2
        )

    llm_avg["available_ratio"] = round((llm_count / total) if total else 0.0, 2)
    daily_items = sorted(
        [{"date": d, "count": c} for d, c in daily.items()], key=lambda x: x["date"]
    )

    return jsonify(
        {
            "total": total,
            "levels": levels,
            "avg": avg,
            "risk_histogram": {
                "bins": [f"{i*10}-{(i+1)*10}" for i in range(10)],
                "counts": hist,
            },
            "daily": daily_items,
            "features_avg": feat_avg,
            "llm_avg": llm_avg,
        }
    )


@app.route("/assets/<path:filename>", methods=["GET"])
def frontend_assets(filename):
    assets_dir = os.path.join(FRONTEND_DIR, "assets")
    if not os.path.exists(os.path.join(assets_dir, filename)):
        return jsonify({"error": "not_found"}), 404
    return send_from_directory(assets_dir, filename)


@app.route("/<page>.html", methods=["GET"])
def frontend_pages(page):
    filename = f"{page}.html"
    if not os.path.exists(os.path.join(FRONTEND_DIR, filename)):
        return jsonify({"error": "not_found"}), 404
    return send_from_directory(FRONTEND_DIR, filename)


@app.route("/index", methods=["GET"])
def frontend_index_alias():
    return frontend_pages("index")


@app.route("/upload", methods=["GET"])
def frontend_upload_alias():
    return frontend_pages("upload")


@app.route("/reports", methods=["GET"])
def frontend_reports_alias():
    return frontend_pages("reports")


@app.route("/settings", methods=["GET"])
def frontend_settings_alias():
    return frontend_pages("settings")


@app.route("/<page>", methods=["GET"])
def frontend_page_alias_simple(page):
    if page in {"index", "upload", "reports", "settings"}:
        return frontend_pages(page)
    return jsonify({"error": "not_found"}), 404


@app.route("/", methods=["GET"])
def index_page():
    path = os.path.join(FRONTEND_DIR, "index.html")
    if not os.path.exists(path):
        return Response("frontend missing", status=404)
    with open(path, "rb") as f:
        data = f.read()
    return Response(data, mimetype="text/html")


@app.route("/api/reports/<report_id>", methods=["DELETE"])
def delete_report(report_id):
    existed = REPORTS.pop(report_id, None)
    try:
        HISTORY[:] = [h for h in HISTORY if h.get("id") != report_id]
    except Exception:
        pass
    from time import strftime, localtime

    DELETED_IDS.add(report_id)
    DELETED_META[report_id] = {
        "deleted_at": strftime("%Y-%m-%d %H:%M:%S", localtime()),
        "had_record": bool(existed),
    }
    _save_storage()
    return jsonify({"ok": True, "deleted": report_id, "message": "该报告已被删除"}), 200


def create_app():
    return app


if __name__ == "__main__":
    _load_storage()
    app.run(host="0.0.0.0", port=8000)
