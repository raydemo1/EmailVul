import os
import json
import time
import concurrent.futures
import html as html_lib
import re
import urllib.request

DEFAULT_MODEL = os.environ.get("CUSTOM_MODEL", "gpt-4o-mini")
MAX_CHARS = int(os.environ.get("GEMINI_MAX_CHARS", "50000"))
RETRIES = int(os.environ.get("GEMINI_RETRIES", "2"))
TIMEOUT = int(os.environ.get("GEMINI_TIMEOUT", "60"))

_API_KEY_OVERRIDE = None
_MODEL_OVERRIDE = None
_BASE_URL_OVERRIDE = None

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

def _safe_int(x, lo=0, hi=100):
    try:
        v = int(float(x))
    except Exception:
        v = 0
    return max(lo, min(hi, v))

def _parse_json(text):
    try:
        return json.loads(text)
    except Exception:
        start = text.find("{")
        end = text.rfind("}")
        if start != -1 and end != -1 and end > start:
            try:
                return json.loads(text[start:end+1])
            except Exception:
                pass
    return {}

def ensure_ready():
    api_key = _API_KEY_OVERRIDE or os.environ.get("CUSTOM_API_KEY")
    base_url = _BASE_URL_OVERRIDE or os.environ.get("CUSTOM_BASE_URL")
    if not api_key:
        raise RuntimeError("缺少自定义模型 API Key")
    if not base_url:
        raise RuntimeError("缺少自定义模型 Base URL")

def configure(model=None, api_key=None, base_url=None):
    global _API_KEY_OVERRIDE, _MODEL_OVERRIDE, _BASE_URL_OVERRIDE, DEFAULT_MODEL
    if api_key:
        _API_KEY_OVERRIDE = api_key
    if base_url:
        _BASE_URL_OVERRIDE = base_url
    if model:
        _MODEL_OVERRIDE = model
        DEFAULT_MODEL = model

def analyze_text(text):
    ensure_ready()
    api_key = _API_KEY_OVERRIDE or os.environ.get("CUSTOM_API_KEY")
    base_url = _BASE_URL_OVERRIDE or os.environ.get("CUSTOM_BASE_URL")
    model = _MODEL_OVERRIDE or DEFAULT_MODEL
    prompt = (
        "你是安全检测助手。对给定邮件正文进行钓鱼风险分析，输出 JSON：\n"
        "{\n"
        "  \"semantic_consistency\": 0-100,\n"
        "  \"style_anomaly\": 0-100,\n"
        "  \"social_engineering\": 0-100,\n"
        "  \"llm_generated_probability\": 0-100,\n"
        "  \"evidence\": \"关键依据简述\"\n"
        "}。仅返回 JSON，不要解释。\n"
    )
    clean = strip_html(text or "")
    truncated = clean[:MAX_CHARS]
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": prompt},
            {"role": "user", "content": truncated}
        ]
    }

    def _call():
        url = base_url.rstrip("/") + "/v1/chat/completions"
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(url, data=data, method="POST")
        req.add_header("Content-Type", "application/json")
        req.add_header("Authorization", "Bearer " + api_key)
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            return r.read().decode("utf-8")

    last_err = None
    for attempt in range(RETRIES + 1):
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
                fut = ex.submit(_call)
                resp = fut.result(timeout=TIMEOUT + 5)
            obj = json.loads(resp)
            choices = obj.get("choices") or []
            if not choices:
                raise RuntimeError("无响应内容")
            msg = choices[0].get("message") or {}
            out = msg.get("content") or ""
            data = _parse_json(out)
            if not data:
                raise RuntimeError("LLM 响应解析失败，未返回有效 JSON")
            return {
                "semantic_consistency": _safe_int(data.get("semantic_consistency", 0)),
                "style_anomaly": _safe_int(data.get("style_anomaly", 0)),
                "social_engineering": _safe_int(data.get("social_engineering", 0)),
                "llm_generated_probability": _safe_int(data.get("llm_generated_probability", 0)),
                "evidence": data.get("evidence", ""),
            }
        except Exception as e:
            last_err = e
            if attempt < RETRIES:
                time.sleep(0.5 * (2 ** attempt))
            else:
                raise RuntimeError(f"自定义模型调用失败: {last_err}")
