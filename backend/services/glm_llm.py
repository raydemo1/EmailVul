import os
import json
import time
import concurrent.futures
import html as html_lib
import re
HAS_ZHIPU = True
try:
    from zhipuai import ZhipuAI
except Exception:
    HAS_ZHIPU = False

DEFAULT_MODEL = os.environ.get("GLM_MODEL", "glm-4.6")
MAX_CHARS = int(os.environ.get("GEMINI_MAX_CHARS", "50000"))
RETRIES = int(os.environ.get("GEMINI_RETRIES", "2"))
TIMEOUT = int(os.environ.get("GEMINI_TIMEOUT", "60"))
_API_KEY_OVERRIDE = None
_MODEL_OVERRIDE = None

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

def ensure_ready():
    if not HAS_ZHIPU:
        raise RuntimeError("zhipuai 未安装或不可用")
    api_key = _API_KEY_OVERRIDE or os.environ.get("GLM_API_KEY")
    if not api_key:
        raise RuntimeError("缺少 GLM_API_KEY，无法执行 GLM 分析")

def analyze_text(text):
    ensure_ready()
    api_key = _API_KEY_OVERRIDE or os.environ.get("GLM_API_KEY")
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
        "model": (_MODEL_OVERRIDE or DEFAULT_MODEL),
        "messages": [
            {"role": "system", "content": prompt},
            {"role": "user", "content": truncated}
        ]
    }

    def _call():
        client = ZhipuAI(api_key=api_key)
        return client.chat.completions.create(**payload)

    last_err = None
    for attempt in range(RETRIES + 1):
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
                fut = ex.submit(_call)
                resp = fut.result(timeout=TIMEOUT)
            choices = getattr(resp, "choices", None) or []
            if not choices:
                raise RuntimeError("无响应内容")
            msg = getattr(choices[0], "message", None) or {}
            out = getattr(msg, "content", None) or (msg.get("content") if isinstance(msg, dict) else "")
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
                raise RuntimeError(f"GLM 调用失败: {last_err}")

def configure(model=None, api_key=None):
    global _API_KEY_OVERRIDE, _MODEL_OVERRIDE, DEFAULT_MODEL
    if api_key:
        _API_KEY_OVERRIDE = api_key
    if model:
        _MODEL_OVERRIDE = model
        DEFAULT_MODEL = model
