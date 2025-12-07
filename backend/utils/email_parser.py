import os
import re
import email
from email import policy
from email.parser import BytesParser
import html as html_lib

URL_REGEX = re.compile(r"https?://[\w\-\.\:/\?\#\%\&\=\+]+", re.IGNORECASE)

SCRIPT_RE = re.compile(r"<script[\s\S]*?</script>", re.IGNORECASE)
STYLE_RE = re.compile(r"<style[\s\S]*?</style>", re.IGNORECASE)
TAG_RE = re.compile(r"<[^>]+>")

def strip_html(s):
    if not s:
        return ""
    x = SCRIPT_RE.sub("", s)
    x = STYLE_RE.sub("", x)
    x = x.replace("<br>", "\n").replace("<br/>", "\n").replace("</p>", "\n")
    x = TAG_RE.sub("", x)
    x = html_lib.unescape(x)
    return x

def read_bytes(path):
    with open(path, "rb") as f:
        return f.read()

def extract_text(msg):
    parts = []
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            if ctype in ["text/plain", "text/html"]:
                try:
                    content = part.get_content()
                    if ctype == "text/html":
                        content = strip_html(content)
                    parts.append(content)
                except Exception:
                    continue
    else:
        try:
            parts.append(msg.get_content())
        except Exception:
            pass
    return "\n".join([p if isinstance(p, str) else str(p) for p in parts])

def extract_urls(text):
    if not text:
        return []
    return list({m.group(0) for m in URL_REGEX.finditer(text)})

def extract_attachments(msg):
    items = []
    for part in msg.walk():
        filename = part.get_filename()
        if filename:
            items.append(filename)
    return items

def parse_eml(path):
    data = read_bytes(path)
    msg = BytesParser(policy=policy.default).parsebytes(data)
    text = extract_text(msg)
    urls = extract_urls(text)
    attachments = extract_attachments(msg)
    meta = {
        "from": msg.get("From"),
        "to": msg.get("To"),
        "subject": msg.get("Subject"),
        "message_id": msg.get("Message-ID"),
        "date": msg.get("Date"),
        "headers": {k: msg.get(k) for k in ["From","To","Subject","Message-ID","Date","Return-Path","DKIM-Signature","Received-SPF","Authentication-Results"]}
    }
    return {"text": text, "urls": urls, "attachments": attachments, "meta": meta}

def parse_txt(path):
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        text = f.read()
    urls = extract_urls(text)
    return {"text": text, "urls": urls, "attachments": [], "meta": {"from": None, "to": None, "subject": None}}

def parse_msg(path):
    return parse_txt(path)

def parse_email_file(path):
    ext = os.path.splitext(path)[1].lower()
    if ext == ".eml":
        return parse_eml(path)
    if ext == ".txt":
        return parse_txt(path)
    if ext == ".msg":
        return parse_msg(path)
    return parse_txt(path)
