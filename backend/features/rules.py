import re

SUSPICIOUS_KEYWORDS = [
    "紧急","账户异常","验证","密码","限时","点击链接","确认信息","支付失败","安全更新","复核账户",
    "urgent","verify","password","click here","account locked","security update","confirm"
]

DANGEROUS_EXTS = ["exe","js","vbs","ps1","bat","cmd","scr","jar","hta","pkg"]

def keyword_score(text):
    if not text:
        return 0
    count = 0
    t = text.lower()
    for kw in SUSPICIOUS_KEYWORDS:
        if kw.lower() in t:
            count += 1
    return min(100, count * 10)

def url_score(urls):
    if not urls:
        return 0
    return min(100, len(urls) * 8)

def attachment_score(attachments):
    if not attachments:
        return 0
    score = 0
    for name in attachments:
        ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
        if ext in DANGEROUS_EXTS:
            score += 40
        elif ext in ["doc","docm","xls","xlsm","pptm"]:
            score += 25
        elif ext in ["zip","rar","7z"]:
            score += 15
        else:
            score += 5
    return min(100, score)

def basic_rules(parsed):
    ks = keyword_score(parsed.get("text"))
    us = url_score(parsed.get("urls"))
    ascore = attachment_score(parsed.get("attachments"))
    return {"keyword": ks, "url": us, "attachment": ascore}
