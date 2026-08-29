"""
Heuristic malicious-URL detector.

This gives you a working, explainable prototype today. Swap `score_url`'s
body for a trained model (e.g. scikit-learn RandomForest on the UCI Phishing
Websites dataset or a Kaggle malicious-URLs dataset) later -- keep the same
function signature (returns score 0-100 + list of indicator strings) so the
rest of the app (report builder, frontend) never has to change.
"""
import re
from urllib.parse import urlparse

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rb.gy"}
SENSITIVE_KEYWORDS = [
    "login", "verify", "secure", "account", "update", "bank", "confirm",
    "signin", "password", "billing", "suspended", "unlock", "reward",
]
BRAND_KEYWORDS = ["paypal", "amazon", "google", "microsoft", "apple", "sbi", "hdfc", "icici", "gov"]
MIRROR_PROXY_KEYWORDS = [
    "mirror", "proxy", "unblock", "netmirror", "sflix", "fmovies",
    "gomovies", "solarmovie", "putlocker", "9anime", "1337x",
]


def _has_ip_host(host: str) -> bool:
    return bool(re.fullmatch(r"(\d{1,3}\.){3}\d{1,3}", host))


def score_url(raw_url: str):
    indicators = []
    score = 0

    url = raw_url.strip()
    if not re.match(r"^[a-zA-Z]+://", url):
        url = "http://" + url

    parsed = urlparse(url)
    host = parsed.netloc.lower()
    path = parsed.path.lower()
    full = url.lower()

    if parsed.scheme != "https":
        score += 15
        indicators.append("Connection is not HTTPS")

    if _has_ip_host(host.split(":")[0]):
        score += 30
        indicators.append("Domain is a raw IP address instead of a name")

    if any(s in host for s in SHORTENERS):
        score += 15
        indicators.append("Uses a URL shortening service (destination is hidden)")

    if "@" in url:
        score += 25
        indicators.append("Contains '@', which can mask the real destination")

    if host.count("-") >= 2:
        score += 10
        indicators.append("Domain contains multiple hyphens (common in look-alike domains)")

    if host.count(".") >= 4:
        score += 15
        indicators.append("Unusually deep subdomain structure")

    if len(url) > 90:
        score += 10
        indicators.append("Unusually long URL")

    kw_hits = [k for k in SENSITIVE_KEYWORDS if k in full]
    if kw_hits:
        score += min(20, 5 * len(kw_hits))
        indicators.append(f"Contains sensitive-action keywords ({', '.join(kw_hits[:3])})")

    brand_in_domain = [b for b in BRAND_KEYWORDS if b in host]
    if brand_in_domain and not any(host.endswith(f"{b}.com") or host.endswith(f"{b}.in") for b in brand_in_domain):
        score += 25
        indicators.append(f"Impersonates a known brand name ('{brand_in_domain[0]}') in a non-official domain")

    if re.search(r"\d{4,}", host):
        score += 10
        indicators.append("Domain contains an unusually long digit sequence")

    mirror_hits = [k for k in MIRROR_PROXY_KEYWORDS if k in host]
    if mirror_hits:
        score += 20
        indicators.append(
            f"Domain name pattern matches known mirror/proxy/piracy-style sites ('{mirror_hits[0]}')"
        )

    score = min(score, 100)
    if not indicators:
        indicators.append("No common phishing indicators detected in the URL structure")

    return score, indicators


def classify_score(score: int):
    if score >= 70:
        return "CRITICAL"
    if score >= 45:
        return "HIGH"
    if score >= 20:
        return "MEDIUM"
    return "LOW"
