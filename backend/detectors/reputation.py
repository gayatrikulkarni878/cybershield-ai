"""
Live domain-reputation lookup against URLhaus (abuse.ch) — a free, public
threat-intelligence feed with no API key required. This is a *second*
signal layered on top of the structural heuristics in url_detector.py:
structural checks always run (even fully offline); this adds real-world
"has this domain actually been reported as malicious" evidence when
internet access is available.

Fails gracefully: if the request times out or the service is unreachable
(e.g. offline demo), this returns None and the caller should just skip
this signal rather than error out.
"""
import requests

URLHAUS_HOST_ENDPOINT = "https://urlhaus-api.abuse.ch/v1/host/"


def check_domain_reputation(host: str, timeout: float = 2.5):
    try:
        resp = requests.post(URLHAUS_HOST_ENDPOINT, data={"host": host}, timeout=timeout)
        resp.raise_for_status()
        data = resp.json()
    except Exception:
        return None

    if data.get("query_status") != "ok":
        return {"listed": False, "threat_types": []}

    urls = data.get("urls") or []
    threat_types = sorted({u.get("threat") for u in urls if u.get("threat")})
    return {"listed": bool(urls), "threat_types": threat_types}
