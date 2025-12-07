import os
import json
import time
import socket
import ssl
import urllib.request
import urllib.parse
import whois

CACHE_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "whois_cache.json")
TTL = 86400

def _idna(domain):
    try:
        return domain.encode("idna").decode("ascii")
    except Exception:
        return domain

def _load_cache():
    try:
        with open(CACHE_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}

def _save_cache(data):
    os.makedirs(os.path.dirname(CACHE_PATH), exist_ok=True)
    with open(CACHE_PATH, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False)

def get_whois(domain):
    d = (_idna(domain) or "").lower()
    if not d:
        return {"ok": False}
    cache = _load_cache()
    now = int(time.time())
    ent = cache.get(d)
    if ent and (now - ent.get("ts", 0) < TTL):
        return ent.get("data", {"ok": False})
    try:
        w = whois.whois(d)
        data = {
            "ok": True,
            "domain": d,
            "registrar": getattr(w, "registrar", None),
            "creation_date": str(getattr(w, "creation_date", None)),
            "expiration_date": str(getattr(w, "expiration_date", None)),
            "emails": getattr(w, "emails", None),
            "name_servers": getattr(w, "name_servers", None),
            "country": getattr(w, "country", None)
        }
    except Exception:
        data = {"ok": False}
    cache[d] = {"ts": now, "data": data}
    _save_cache(cache)
    return data

def get_ssl_cert(domain, port=443):
    d = _idna(domain)
    if not d:
        return {"ok": False}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((d, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=d) as ssock:
                cert = ssock.getpeercert()
        subj = dict(x for x in cert.get("subject", []) for x in x)
        issr = dict(x for x in cert.get("issuer", []) for x in x)
        san = [t[1] for t in cert.get("subjectAltName", []) if t and len(t) > 1]
        return {
            "ok": True,
            "subject_cn": subj.get("commonName"),
            "issuer_cn": issr.get("commonName"),
            "not_before": cert.get("notBefore"),
            "not_after": cert.get("notAfter"),
            "sans": san
        }
    except Exception:
        return {"ok": False}

def get_ct_logs(domain, limit=20):
    d = _idna(domain)
    if not d:
        return {"ok": False, "entries": []}
    try:
        url = "https://crt.sh/?q=" + urllib.parse.quote(d) + "&output=json"
        with urllib.request.urlopen(url, timeout=5) as r:
            data = r.read()
        arr = json.loads(data.decode("utf-8"))
        out = []
        for e in arr[:limit]:
            out.append({
                "issuer": e.get("issuer_name"),
                "name_value": e.get("name_value"),
                "not_before": e.get("not_before"),
                "not_after": e.get("not_after")
            })
        return {"ok": True, "entries": out}
    except Exception:
        return {"ok": False, "entries": []}

