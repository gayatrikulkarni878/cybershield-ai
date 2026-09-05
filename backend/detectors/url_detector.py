import re
from urllib.parse import urlparse

# Known URL Shortener Domains
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "rb.gy", "is.gd",
    "buff.ly", "adf.ly", "cutt.ly", "shorturl.at", "v.gd", "qr.ae", "tr.ee"
}

# Known Phishing & Sensitive Keywords
SUSPICIOUS_KEYWORDS = [
    "login", "verify", "banking", "secure", "update", "account", "free",
    "bonus", "claim", "kyc", "support", "wallet", "payroll", "credential",
    "signin", "auth", "confirm", "security", "customer-service", "helpdesk",
    "password", "verify-account", "bank-update", "refund", "prize", "gift"
]

# High-Risk / Suspicious TLDs
SUSPICIOUS_TLDS = {
    "xyz", "top", "club", "work", "click", "gq", "cf", "tk", "ml", "ru",
    "su", "cam", "zip", "mov", "fit", "online", "site", "vip", "icu", "biz"
}

def analyze_url(url_str: str) -> dict:
    """
    Analyzes a URL using transparent, rule-based cybersecurity heuristics.
    Returns score (0-100), risk level, threat type, detected indicators, and advice.
    """
    url_clean = (url_str or "").strip()
    if not url_clean:
        return {
            "error": "URL cannot be empty.",
            "url": "",
            "risk_score": 0,
            "risk_level": "SAFE",
            "threat_type": "None",
            "indicators": [],
            "explanation": "No input provided.",
            "recommendation": "Please enter a valid web link to analyze."
        }

    # Ensure URL scheme for parsing
    has_scheme = bool(re.match(r'^[a-zA-Z][a-zA-Z0-9+\-.]*://', url_clean))
    parsing_target = url_clean if has_scheme else "http://" + url_clean

    parsed = urlparse(parsing_target)
    domain = parsed.netloc.split(':')[0].lower() if parsed.netloc else parsed.path.split('/')[0].split(':')[0].lower()
    full_path = (parsed.path + ("?" + parsed.query if parsed.query else "")).lower()

    indicators = []
    total_score = 0

    # 1. Scheme Check (Missing HTTPS)
    if not url_clean.lower().startswith("https://"):
        score_add = 15
        total_score += score_add
        indicators.append({
            "code": "NO_HTTPS",
            "title": "Unencrypted HTTP Connection",
            "points": score_add,
            "category": "Protocol Security",
            "description": "The URL does not use HTTPS. Data sent over HTTP is unencrypted and vulnerable to eavesdropping."
        })

    # 2. IP Address in Hostname
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if re.match(ip_pattern, domain):
        score_add = 25
        total_score += score_add
        indicators.append({
            "code": "IP_HOSTNAME",
            "title": "Raw IP Hostname Used",
            "points": score_add,
            "category": "Domain Identity",
            "description": "The link points directly to an IP address instead of a domain name, a tactic commonly used to conceal malicious hosts."
        })

    # 3. URL Shortener Detection
    if domain in URL_SHORTENERS:
        score_add = 20
        total_score += score_add
        indicators.append({
            "code": "URL_SHORTENER",
            "title": "Shortened / Masked URL",
            "points": score_add,
            "category": "Redirection",
            "description": f"Domain '{domain}' is a URL shortener service that hides the actual destination endpoint."
        })

    # 4. Phishing Keywords in Path / Domain
    found_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in domain or kw in full_path]
    if found_keywords:
        score_add = 15
        total_score += score_add
        indicators.append({
            "code": "SUSPICIOUS_KEYWORDS",
            "title": "Sensitive Keywords Found",
            "points": score_add,
            "category": "Content Pattern",
            "description": f"Contains security/banking keywords: {', '.join(found_keywords[:3])}."
        })

    # 5. Excessive Subdomains (>3 dots in domain)
    dot_count = domain.count(".")
    if dot_count > 3 and not re.match(ip_pattern, domain):
        score_add = 10
        total_score += score_add
        indicators.append({
            "code": "EXCESSIVE_SUBDOMAINS",
            "title": "Excessive Subdomains",
            "points": score_add,
            "category": "Domain Identity",
            "description": f"Domain contains {dot_count} subdomains, which may be an attempt to spoof legitimate sites (e.g., login.bank.com.attacker.com)."
        })

    # 6. Suspicious Characters / Brand Spoofing Hyphens
    suspicious_chars = []
    if "@" in url_clean:
        suspicious_chars.append("User auth symbol '@'")
    if domain.count("-") >= 3:
        suspicious_chars.append("Hyphen overloading in domain")
    if "//" in full_path:
        suspicious_chars.append("Multiple slashes in path")

    if suspicious_chars:
        score_add = 10
        total_score += score_add
        indicators.append({
            "code": "SUSPICIOUS_CHARS",
            "title": "Obfuscated / Suspicious Formatting",
            "points": score_add,
            "category": "URL Structure",
            "description": f"Detected suspicious URL structure: {', '.join(suspicious_chars)}."
        })

    # 7. Unusual or High-Risk TLD
    tld = domain.split(".")[-1] if "." in domain else ""
    if tld in SUSPICIOUS_TLDS:
        score_add = 15
        total_score += score_add
        indicators.append({
            "code": "SUSPICIOUS_TLD",
            "title": f"High-Risk Top-Level Domain (.{tld})",
            "points": score_add,
            "category": "TLD Reputation",
            "description": f"The top-level domain '.{tld}' is frequently associated with disposable or phishing domains."
        })

    # 8. Excessive URL Length
    if len(url_clean) > 75:
        score_add = 10
        total_score += score_add
        indicators.append({
            "code": "EXCESSIVE_LENGTH",
            "title": "Unusually Long URL",
            "points": score_add,
            "category": "URL Structure",
            "description": f"URL length is {len(url_clean)} characters. Excessively long URLs are often used to conceal target parameters."
        })

    # Cap score at 100 max
    final_score = min(total_score, 100)

    # Determine Risk Level
    if final_score >= 85:
        risk_level = "CRITICAL"
    elif final_score >= 65:
        risk_level = "HIGH"
    elif final_score >= 40:
        risk_level = "MEDIUM"
    elif final_score >= 20:
        risk_level = "LOW"
    else:
        risk_level = "SAFE"

    # Determine Threat Type
    if "IP_HOSTNAME" in [i["code"] for i in indicators] and "SUSPICIOUS_KEYWORDS" in [i["code"] for i in indicators]:
        threat_type = "Credential Harvesting via IP Host"
    elif "SUSPICIOUS_KEYWORDS" in [i["code"] for i in indicators] and ("SUSPICIOUS_CHARS" in [i["code"] for i in indicators] or "EXCESSIVE_SUBDOMAINS" in [i["code"] for i in indicators]):
        threat_type = "Phishing / Brand Spoofing"
    elif "URL_SHORTENER" in [i["code"] for i in indicators]:
        threat_type = "Masked Shortened URL Redirect"
    elif final_score >= 40:
        threat_type = "Suspicious Link Pattern"
    else:
        threat_type = "Clean / Low Risk URL"

    # Explanations & Recommendations
    if risk_level in ["CRITICAL", "HIGH"]:
        explanation = (
            f"CyberShield AI identified multiple critical indicators totaling a risk score of {final_score}/100. "
            "This link demonstrates patterns heavily aligned with phishing, credential harvesting, or identity masking."
        )
        recommendation = "DO NOT open this link or enter any personal credentials. Verify through official organization channels."
    elif risk_level == "MEDIUM":
        explanation = (
            f"The link exhibits moderate risk characteristics (Score: {final_score}/100). "
            "While it may be legitimate, certain attributes (such as HTTP or keyword patterns) warrant caution."
        )
        recommendation = "Proceed with caution. Check the domain carefully before providing sensitive information."
    elif risk_level == "LOW":
        explanation = (
            f"Minor risk indicators were detected (Score: {final_score}/100). "
            "The link appears relatively safe, but basic hygiene rules apply."
        )
        recommendation = "Verify the recipient and ensure you intended to visit this link."
    else:
        explanation = "No significant threat indicators were detected. The URL adheres to standard secure web patterns."
        recommendation = "The link appears safe based on rule-based heuristic checks. Always practice standard web safety."

    return {
        "url": url_clean,
        "risk_score": final_score,
        "risk_level": risk_level,
        "threat_type": threat_type,
        "indicators": indicators,
        "explanation": explanation,
        "recommendation": recommendation,
        "analysis_type": "Heuristic Rule-Based Analysis"
    }
