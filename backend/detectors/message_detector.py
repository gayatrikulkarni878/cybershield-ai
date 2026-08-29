"""
Heuristic phishing / social-engineering message detector.

Same idea as url_detector: rule-based today so the demo is fast and fully
explainable, structured so you can later add an LLM call (Claude API) or a
trained TF-IDF + Logistic Regression classifier on an SMS-spam dataset
without changing the calling code.
"""
import re

URGENCY_WORDS = ["immediately", "urgent", "right away", "within 24 hours", "act now", "expire", "last chance"]
THREAT_WORDS = ["suspended", "blocked", "locked", "deactivated", "legal action", "penalty", "fine"]
REWARD_WORDS = ["congratulations", "winner", "won", "reward", "prize", "cashback", "free gift", "lottery"]
SENSITIVE_REQUESTS = ["otp", "password", "pin", "cvv", "card number", "aadhar", "bank details", "login details"]
URL_PATTERN = re.compile(r"(https?://\S+|www\.\S+|\b\S+\.(com|in|net|org|xyz|info)\b)", re.IGNORECASE)


def score_message(text: str):
    indicators = []
    score = 0
    t = text.lower()

    urgency_hits = [w for w in URGENCY_WORDS if w in t]
    if urgency_hits:
        score += 20
        indicators.append(f"Creates urgency ('{urgency_hits[0]}')")

    threat_hits = [w for w in THREAT_WORDS if w in t]
    if threat_hits:
        score += 20
        indicators.append(f"Uses a threat of consequence ('{threat_hits[0]}')")

    reward_hits = [w for w in REWARD_WORDS if w in t]
    if reward_hits:
        score += 20
        indicators.append(f"Offers an unexpected reward ('{reward_hits[0]}')")

    sensitive_hits = [w for w in SENSITIVE_REQUESTS if w in t]
    if sensitive_hits:
        score += 25
        indicators.append(f"Requests sensitive information ('{sensitive_hits[0]}')")

    url_match = URL_PATTERN.search(text)
    if url_match:
        score += 15
        indicators.append("Contains a link the reader is pressured to click")

    if re.search(r"dear (customer|user|sir/madam)", t):
        score += 5
        indicators.append("Uses a generic greeting instead of your real name")

    score = min(score, 100)
    if not indicators:
        indicators.append("No common social-engineering patterns detected")

    embedded_url = url_match.group(0) if url_match else None
    return score, indicators, embedded_url


def classify_score(score: int):
    if score >= 70:
        return "CRITICAL"
    if score >= 45:
        return "HIGH"
    if score >= 20:
        return "MEDIUM"
    return "LOW"
