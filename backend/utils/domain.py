import re
import math


def extract_domain(url: str) -> str:
    if not url:
        return ""
    m = re.match(r"https?://([^/]+)", url.strip(), re.IGNORECASE)
    return m.group(1).lower() if m else ""

CONF_MAP = {
    '0': 'o', '1': 'l', '3': 'e', '5': 's', '7': 't',
    '@': 'a', '$': 's', '!': 'i', '|': 'l', '€': 'e',
}

def normalize_homoglyph(s: str) -> str:
    if not s:
        return ""
    out = []
    for ch in s.lower():
        out.append(CONF_MAP.get(ch, ch))
    return "".join(out)

def visual_similarity(a: str, b: str) -> float:
    a2 = normalize_homoglyph(a)
    b2 = normalize_homoglyph(b)
    if not a2 or not b2:
        return 0.0
    sa = set(a2)
    sb = set(b2)
    inter = len(sa & sb)
    union = len(sa | sb)
    return inter / union if union else 0.0

def _ngrams(s: str, n: int = 3):
    s2 = normalize_homoglyph(s)
    arr = []
    for i in range(max(0, len(s2) - n + 1)):
        arr.append(s2[i:i+n])
    return arr

def _vec(s: str):
    vs = {}
    for g in _ngrams(s, 3):
        vs[g] = vs.get(g, 0) + 1
    norm = math.sqrt(sum(v*v for v in vs.values())) or 1.0
    for k in list(vs.keys()):
        vs[k] = vs[k] / norm
    return vs

def embedding_similarity(a: str, b: str) -> float:
    va = _vec(a or "")
    vb = _vec(b or "")
    if not va or not vb:
        return 0.0
    keys = set(va.keys()) & set(vb.keys())
    return sum(va[k]*vb[k] for k in keys)
