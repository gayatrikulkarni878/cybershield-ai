import re
from typing import List, Dict, Any
from .url_detector import analyze_url

# Keywords and patterns across English, Hindi, and Marathi
INDICATOR_PATTERNS = {
    "URGENCY": {
        "title": "Urgency & Time Pressure",
        "points": 15,
        "category": "Social Engineering",
        "keywords": {
            "en": ["urgent", "immediately", "right now", "within 24 hours", "action required", "hurry", "expire", "limited time", "due today"],
            "hi": ["तुरंत", "अतिआवश्यक", "अभी", "जल्दी", "24 घंटे", "समाप्त", "समय सीमा"],
            "mr": ["तातडीने", "त्वरित", "लगेच", "मुदतीत", "२४ तासांत", "कालावधी"]
        },
        "desc": "Uses artificial time pressure to induce panic and prevent careful decision-making."
    },
    "FEAR_SUSPENSION": {
        "title": "Threat & Account Suspension Warning",
        "points": 20,
        "category": "Social Engineering",
        "keywords": {
            "en": ["suspended", "blocked", "closed", "terminated", "legal action", "police", "unauthorized access", "deactivated", "penalty", "frozen"],
            "hi": ["बंद", "निलंबित", "कार्रवाई", "अवैध", "अवरुद्ध", "ब्लॉक", "जुर्माना", "कार्रवाई की जाएगी"],
            "mr": ["बंद", "गोठवले", "कारवाई", "अटकाव", "ब्लॉक", "दंड", "कायदेशीर कार्रवाई"]
        },
        "desc": "Threatens account suspension or legal consequences to force rapid compliance."
    },
    "REWARD_PRIZE": {
        "title": "Unrealistic Reward / Prize Offer",
        "points": 18,
        "category": "Baiting",
        "keywords": {
            "en": ["won", "prize", "lottery", "cashback", "gift card", "congratulations", "free bonus", "reward", "claimed", "draw"],
            "hi": ["जीत", "पुरस्कार", "इनाम", "लॉटरी", "बोनस", "बधाई", "रुपये मिले", "फ्री"],
            "mr": ["जिंकले", "बक्षीस", "इनाम", "लॉटरी", "बोनस", "अभिनंदन", "रुपये मिळाले"]
        },
        "desc": "Promises unverified monetary rewards or prizes to entice clicking."
    },
    "SENSITIVE_INFO": {
        "title": "Request for Sensitive Credentials",
        "points": 25,
        "category": "Credential Theft",
        "keywords": {
            "en": ["otp", "password", "pin", "cvv", "card number", "bank account", "ssn", "credentials", "netbanking", "login details", "kyc"],
            "hi": ["ओटीपी", "पासवर्ड", "पिन", "कार्ड", "खाता संख्या", "बैंक विवरण", "केवाईसी"],
            "mr": ["ओटीपी", "पासवर्ड", "पिन", "कार्ड", "खाते क्रमांक", "बँक तपशील", "केवायसी"]
        },
        "desc": "Directly requests confidential credentials such as OTP, password, or PIN."
    },
    "SUSPICIOUS_ACTION": {
        "title": "Suspicious Instruction / Click Demand",
        "points": 20,
        "category": "Malicious Action",
        "keywords": {
            "en": ["click here", "click below", "visit link", "download app", "verify now", "login here", "call immediately", "update info"],
            "hi": ["क्लिक करें", "लिंक पर जाएं", "सत्यापित करें", "ऐप डाउनलोड करें", "कॉल करें"],
            "mr": ["क्लिक करा", "लिंकवर जा", "सत्यापित करा", "ॲप डाउनलोड करा", "कॉल करा"]
        },
        "desc": "Urges the user to follow unsafe links or download unknown applications."
    },
    "IMPERSONATION": {
        "title": "Brand / Authority Impersonation",
        "points": 15,
        "category": "Impersonation",
        "keywords": {
            "en": ["rbi", "sbi", "hdfc", "icici", "income tax", "electricity department", "fedex", "amazon", "whatsapp", "telegram", "police", "customs", "bank"],
            "hi": ["आरबीआई", "एसबीआई", "आयकर", "बिजली विभाग", "बैंक", "पुलिस"],
            "mr": ["आरबीआय", "एसबीआय", "बँक", "आयकर", "वीज विभाग", "पोलिस"]
        },
        "desc": "Impersonates trusted organizations, banks, or government departments."
    }
}

# Devanagari script regex range
DEVANAGARI_REGEX = re.compile(r'[\u0900-\u097F]')

# Specific Marathi Vocabulary Markers
MARATHI_MARKERS = ["तुमचे", "खालील", "तातडीने", "झाले", "आहे", "करा", "खाते", "लिंकवर", "अकाऊंट", "कृपया", "बँक", "केले"]
HINDI_MARKERS = ["आपके", "नीचे", "तुरंत", "हुआ", "है", "करें", "खाता", "लिंक पर", "अकाउंट", "कृपया", "बैंक", "किया"]

def detect_language(text: str) -> str:
    """
    Detects whether text is in English, Hindi, or Marathi based on script and vocabulary.
    """
    devanagari_chars = DEVANAGARI_REGEX.findall(text)
    if len(devanagari_chars) > 3:
        text_lower = text.lower()
        marathi_hits = sum(1 for w in MARATHI_MARKERS if w in text)
        hindi_hits = sum(1 for w in HINDI_MARKERS if w in text)
        if marathi_hits > hindi_hits or "तुमचे" in text or "करा" in text or "लिंकवर" in text:
            return "Marathi"
        return "Hindi"
    return "English"

def extract_urls(text: str) -> List[str]:
    """
    Extracts URLs embedded inside text content.
    """
    url_pattern = r'https?://[^\s>"]+|www\.[^\s>"]+'
    return re.findall(url_pattern, text)

def analyze_message(message_text: str) -> Dict[str, Any]:
    """
    Analyzes SMS/Email/WhatsApp messages for phishing indicators in EN/HI/MR.
    """
    text_clean = (message_text or "").strip()
    if not text_clean:
        return {
            "error": "Message text cannot be empty.",
            "risk_score": 0,
            "risk_level": "SAFE",
            "threat_type": "None",
            "detected_language": "Unknown",
            "indicators": [],
            "links_found": [],
            "explanation": "No text provided for analysis.",
            "recommendation": "Please paste a message or email body to evaluate."
        }

    detected_lang = detect_language(text_clean)
    text_lower = text_clean.lower()

    indicators = []
    total_score = 0

    # 1. Evaluate Social Engineering Patterns
    for code, rule in INDICATOR_PATTERNS.items():
        matched_words = []
        # Check all languages in rule
        for lang_code, kw_list in rule["keywords"].items():
            for kw in kw_list:
                if kw in text_lower:
                    matched_words.append(kw)

        if matched_words:
            # Deduplicate matched keywords
            unique_matches = list(set(matched_words))[:3]
            points = rule["points"]
            total_score += points
            indicators.append({
                "code": code,
                "title": rule["title"],
                "points": points,
                "category": rule["category"],
                "description": f"{rule['desc']} (Matched terms: {', '.join(unique_matches)})"
            })

    # 2. Check for Embedded Links
    links = extract_urls(text_clean)
    analyzed_links = []
    if links:
        points = 12
        total_score += points
        indicators.append({
            "code": "EMBEDDED_LINK",
            "title": "Embedded Hyperlink Found",
            "points": points,
            "category": "External Vector",
            "description": f"Message contains {len(links)} embedded link(s). Phishing messages commonly use links to redirect victims to fake portals."
        })

        for l in links:
            url_res = analyze_url(l)
            analyzed_links.append(url_res)
            # If an embedded link is HIGH/CRITICAL, elevate total message score
            if url_res.get("risk_score", 0) > 60:
                total_score += 15

    # Cap score at 100
    final_score = min(total_score, 100)

    # Risk level determination
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

    # Threat type determination
    indicator_codes = [i["code"] for i in indicators]
    if "SENSITIVE_INFO" in indicator_codes and "EMBEDDED_LINK" in indicator_codes:
        threat_type = "High-Risk Credential Harvesting Phish"
    elif "FEAR_SUSPENSION" in indicator_codes and "URGENCY" in indicator_codes:
        threat_type = "Urgent Account Impersonation Scam"
    elif "REWARD_PRIZE" in indicator_codes:
        threat_type = "Financial Bait / Lottery Scam"
    elif final_score >= 40:
        threat_type = "Suspicious Phishing Message"
    else:
        threat_type = "Legitimate / Low Risk Message"

    # Explanation and recommendation
    if risk_level in ["CRITICAL", "HIGH"]:
        explanation = (
            f"CyberShield AI flagged high-severity phishing indicators resulting in a risk score of {final_score}/100. "
            f"The message ({detected_lang}) employs tactics like urgency, fear, or credential requests to deceive the reader."
        )
        recommendation = "Do NOT click links, call numbers provided, or share OTPs/passwords. Report and block the sender immediately."
    elif risk_level == "MEDIUM":
        explanation = (
            f"Moderate risk indicators detected (Score: {final_score}/100) in {detected_lang} text. "
            "The message exhibits characteristics typical of promotional spam or suspicious requests."
        )
        recommendation = "Verify the authenticity of the message with the official entity before taking any action."
    elif risk_level == "LOW":
        explanation = f"Low risk score ({final_score}/100). Minimal suspicious indicators detected in {detected_lang} content."
        recommendation = "Always double-check sender details if unexpected."
    else:
        explanation = f"The message appears clean with no obvious phishing signatures (Score: {final_score}/100)."
        recommendation = "No threats detected. Standard awareness recommended."

    return {
        "message": text_clean,
        "detected_language": detected_lang,
        "risk_score": final_score,
        "risk_level": risk_level,
        "threat_type": threat_type,
        "indicators": indicators,
        "links_found": analyzed_links,
        "explanation": explanation,
        "recommendation": recommendation,
        "analysis_type": "Multilingual Heuristic Phishing Engine"
    }
