from ..features.rules import basic_rules
from ..features.text import text_stats
from ..services.gemini_llm import analyze_text as gemini_analyze
from ..services.glm_llm import analyze_text as glm_analyze
from ..services.custom_llm import analyze_text as custom_analyze
from ..services.advice import get_advice
from ..utils.domain import extract_domain, visual_similarity, embedding_similarity, normalize_homoglyph
from ..utils.whois_ct_ssl import get_whois, get_ssl_cert, get_ct_logs
import os
import json

def level_from_score(score):
    if score < 30:
        return "低"
    if score < 60:
        return "中"
    if score < 85:
        return "高"
    return "危急"

def compute_risk(parsed, model: str = "gemini"):
    r = basic_rules(parsed)
    t = text_stats(parsed.get("text"))
    if model == "glm46":
        llm = glm_analyze(parsed.get("text"))
    elif model == "custom":
        llm = custom_analyze(parsed.get("text"))
    else:
        llm = gemini_analyze(parsed.get("text"))
    score = min(100, int(
        0.45 * r["keyword"] +
        0.25 * r["url"] +
        0.15 * r["attachment"] +
        0.15 * t["perplexity"] +
        0.10 * t["burstiness"] +
        0.20 * llm.get("style_anomaly", 0) +
        0.20 * llm.get("social_engineering", 0) +
        0.15 * llm.get("llm_generated_probability", 0)
    ))
    level = level_from_score(score)
    confidence = 0.5 + (score / 200.0)
    summary = "关键词:{} URL:{} 附件:{} 文本困惑度:{} 突发度:{}".format(r["keyword"], r["url"], r["attachment"], round(t["perplexity"],2), round(t["burstiness"],2))
    summary += " LLM风格异常:{} 社工评分:{} 生成概率:{}".format(llm.get("style_anomaly",0), llm.get("social_engineering",0), llm.get("llm_generated_probability",0))
    threats = []
    def sev(v):
        return "危急" if v >= 85 else ("高" if v >= 60 else ("中" if v >= 30 else "低"))
    if r["keyword"] >= 30 or llm.get("social_engineering",0) >= 30:
        threats.append({
            "name": "社会工程诱导",
            "severity": sev(max(r["keyword"], llm.get("social_engineering",0))),
            "vector": "钓鱼话术与敏感信息索取",
            "affected": ["邮箱收件人","账户登录接口"],
            "impact": "凭据泄露与账户接管",
            "sample": (parsed.get("text") or "")[:200],
            "recommendation": get_advice("社会工程诱导")
        })
    if r["url"] > 0:
        url = (parsed.get("urls") or [""])[0]
        threats.append({
            "name": "恶意链接",
            "severity": sev(max(r["url"], llm.get("semantic_consistency",0))),
            "vector": "链接重定向与仿冒站点",
            "affected": ["浏览器","登录表单"],
            "impact": "会话劫持与凭据收集",
            "sample": url,
            "recommendation": get_advice("恶意链接")
        })
        dom = extract_domain(url)
    else:
        dom = ""
    if r["attachment"] > 0:
        att = (parsed.get("attachments") or [""])[0]
        threats.append({
            "name": "危险附件",
            "severity": sev(r["attachment"]),
            "vector": "可执行或宏文档",
            "affected": ["终端系统","办公组件"],
            "impact": "代码执行与持久化",
            "sample": att,
            "recommendation": get_advice("危险附件")
        })
    if llm.get("style_anomaly",0) >= 40 or llm.get("llm_generated_probability",0) >= 40:
        threats.append({
            "name": "生成文本伪装",
            "severity": sev(max(llm.get("style_anomaly",0), llm.get("llm_generated_probability",0))),
            "vector": "风格异常与模板化表述",
            "affected": ["人机信任","审阅流程"],
            "impact": "提高欺骗成功率",
            "sample": summary,
            "recommendation": get_advice("生成文本伪装")
        })

    bpath = os.path.join(os.path.dirname(__file__), "..", "data", "brands.json")
    try:
        brands_data = json.load(open(bpath, "r", encoding="utf-8"))
    except Exception:
        brands_data = []
    text_all = (parsed.get("text") or "") + " " + (parsed.get("meta",{}).get("subject") or "")
    brand_hit = None
    brand_dom_hit = None
    score_sim = 0.0
    for b in brands_data:
        name = b.get("name") or ""
        domains = b.get("domains") or []
        cond = (name.lower() in text_all.lower()) or (dom and name.lower() in dom.lower())
        for bd in domains:
            s = embedding_similarity(dom or bd, bd)
            if s > score_sim and (cond or s >= 0.6):
                score_sim = s
                brand_hit = name
                brand_dom_hit = bd
    if brand_hit:
        w = get_whois(dom) if dom else {"ok": False}
        c = get_ssl_cert(dom) if dom else {"ok": False}
        ct = get_ct_logs(dom) if dom else {"ok": False, "entries": []}
        boost = 0
        try:
            dstr = (w.get("creation_date") or "")
            boost += 10 if (dstr and any(x in dstr for x in ["2025","2024","2023"])) else 0
        except Exception:
            pass
        try:
            sans = c.get("sans") or []
            boost += 10 if (dom and dom not in sans) else 0
        except Exception:
            pass
        ct_count = len(ct.get("entries") or [])
        boost += 5 if ct_count == 0 else 0
        sev_val = max(0, min(100, int(score_sim * 100) + boost))
        threats.append({
            "name": "品牌冒充",
            "severity": sev(sev_val),
            "vector": "仿冒品牌名称与视觉相似域名",
            "affected": ["品牌信誉","用户信任"],
            "impact": "用户受骗与品牌侵权",
            "sample": brand_hit,
            "recommendation": "核验品牌官方域与签名，阻断仿冒内容。",
            "evidence": [
                f"品牌名称: {brand_hit}",
                f"官方域: {brand_dom_hit or 'N/A'}",
                f"相似度评分: {round(score_sim*100,2)}",
                f"WHOIS注册商: {w.get('registrar') if w.get('ok') else 'N/A'}",
                f"WHOIS注册时间: {w.get('creation_date') if w.get('ok') else 'N/A'}",
                f"证书CN: {c.get('subject_cn') if c.get('ok') else 'N/A'}",
                f"证书颁发者: {c.get('issuer_cn') if c.get('ok') else 'N/A'}",
                f"CT条目数: {ct_count}",
                f"证据内容: {(text_all or '')[:200]}"
            ]
        })

    if dom:
        norm_dom = normalize_homoglyph(dom)
        sim = visual_similarity(dom, norm_dom)
        w2 = get_whois(dom)
        c2 = get_ssl_cert(dom)
        ct2 = get_ct_logs(dom)
        ct_count2 = len(ct2.get("entries") or [])
        if sim >= 0.6:
            threats.append({
                "name": "域名同形异义",
                "severity": sev(int(sim * 100)),
                "vector": "字符同形混淆与视觉相似",
                "affected": ["浏览器地址栏","域名解析"],
                "impact": "引导访问仿冒站点",
                "sample": dom,
                "recommendation": "启用同形域名检测与阻断策略。",
                "evidence": [
                    f"原始域名: {dom}",
                    f"归一域名: {norm_dom}",
                    f"WHOIS注册商: {w2.get('registrar') if w2.get('ok') else 'N/A'}",
                    f"WHOIS注册时间: {w2.get('creation_date') if w2.get('ok') else 'N/A'}",
                    f"证书CN: {c2.get('subject_cn') if c2.get('ok') else 'N/A'}",
                    f"CT条目数: {ct_count2}",
                    f"视觉相似度: {round(sim*100,2)}"
                ]
            })

    headers = parsed.get("meta", {}).get("headers", {})
    auth = headers.get("Authentication-Results") or ""
    spf = headers.get("Received-SPF") or ""
    dkim = headers.get("DKIM-Signature") or ""
    if not auth or ("fail" in auth.lower()) or ("softfail" in auth.lower()) or (not dkim):
        threats.append({
            "name": "邮件头伪造",
            "severity": sev(70),
            "vector": "认证失败或缺失",
            "affected": ["邮件网关","收件人"],
            "impact": "冒充发件域与绕过过滤",
            "sample": headers.get("From") or "",
            "recommendation": "强制 SPF/DKIM/DMARC 校验与拒收策略。",
            "evidence": [f"邮件头: 完整记录", f"SPF: {spf or 'N/A'}", f"DKIM: {('存在' if dkim else '缺失')}", f"认证结果: {auth or 'N/A'}"]
        })
    chain = []
    if r["url"] > 0:
        chain = ["诱导内容","点击链接","凭据输入","账号被控"]
    elif r["attachment"] > 0:
        chain = ["诱导内容","下载附件","执行宏/程序","系统受控"]
    else:
        chain = ["诱导内容","信息索取","数据泄露"]
    return {"score": score, "confidence": round(min(1.0, confidence), 2), "level": level, "features": {"rules": r, "text": t, "llm": llm}, "summary": summary, "threats": threats, "chain": chain}
