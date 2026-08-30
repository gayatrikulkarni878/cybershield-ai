from typing import Dict, List
import re


class AdvancedPhishingDetector:
    """Enhanced phishing detection with multilingual support"""

    def __init__(self):
        self.patterns = {
            'urgency': {
                'words': [
                    'immediately', 'urgent', 'asap', 'now', 'hurry',
                    'quickly', 'act now', 'limited time', 'deadline',
                    "don't wait", 'right now'
                ],
                'weight': 15
            },

            'fear': {
                'words': [
                    'blocked', 'suspended', 'restricted', 'closed',
                    'locked', 'freeze', 'danger', 'hack', 'fraud',
                    'unauthorized', 'security alert', 'warning', 'compromise'
                ],
                'weight': 20
            },

            'reward': {
                'words': [
                    'won', 'prize', 'reward', 'gift', 'free', 'bonus',
                    'congratulations', 'lucky', 'selected', 'claim',
                    'cashback', 'refund', 'money', 'earn'
                ],
                'weight': 18
            },

            'sensitive': {
                'words': [
                    'password', 'pin', 'otp', 'cvv', 'card number',
                    'credit card', 'debit card', 'aadhaar', 'pan',
                    'ssn', 'account number', 'ifsc'
                ],
                'weight': 25
            },

            'actions': {
                'words': [
                    'click here', 'click link', 'verify account',
                    'confirm identity', 'update password', 'reset password',
                    'open attachment', 'download file'
                ],
                'weight': 20
            }
        }

        self.hindi_patterns = {
            'urgency': {
                'words': [
                    'तुरंत', 'आपातकालीन', 'अभी', 'जल्दी', 'देरी न करें'
                ],
                'weight': 15
            },

            'fear': {
                'words': [
                    'ब्लॉक', 'निलंबित', 'खतरा', 'धोखा', 'चेतावनी'
                ],
                'weight': 20
            },

            'reward': {
                'words': [
                    'जीता', 'पुरस्कार', 'उपहार', 'मुफ्त', 'बोनस'
                ],
                'weight': 18
            }
        }

    def analyze(self, message: str) -> Dict:
        """Comprehensive phishing analysis"""

        score = 0
        indicators = []
        threat_type = "Unknown"
        message_lower = message.lower()

        language = self._detect_language(message)
        patterns = self.hindi_patterns if language == 'hindi' else self.patterns

        for category, pattern_data in patterns.items():
            matches = sum(
                1 for word in pattern_data['words']
                if word in message_lower
            )

            if matches > 0:
                category_name = category.upper()
                indicators.append(
                    f"⚠️ {category_name}: {matches} indicator(s)"
                )
                score += pattern_data['weight'] * matches

                if 'fear' in category:
                    threat_type = "Account Takeover Scam"
                elif 'reward' in category:
                    threat_type = "Prize/Reward Scam"
                elif 'sensitive' in category:
                    threat_type = "Identity Theft"

        links = re.findall(r'https?://\S+', message)

        if links:
            indicators.append(f"🔗 Contains {len(links)} link(s)")
            score += 12 * len(links)

        impersonate_words = ['from', 'behalf', 'verified by', 'official']

        if any(word in message_lower for word in impersonate_words):
            indicators.append("🚨 Possible impersonation")
            score += 15

        if len(message) < 15:
            indicators.append("⚠️ Very short message (automated scam)")
            score += 8

        elif len(message) > 500:
            indicators.append("⚠️ Suspiciously long message")
            score += 5

        score = min(score, 100)
        risk_level = self._get_risk_level(score)

        return {
            'message': message[:150],
            'risk_level': risk_level,
            'risk_score': score,
            'threat_type': (
                threat_type
                if threat_type != "Unknown"
                else "Phishing/Social Engineering"
            ),
            'indicators': indicators,
            'language_detected': language,
            'explanation': self._generate_explanation(indicators),
            'recommendation': self._get_recommendation(score),
            'links_found': len(links)
        }

    def _detect_language(self, text: str) -> str:
        """Detect if message is Hindi or English"""

        hindi_chars = re.findall(r'[\u0900-\u097F]', text)

        return (
            'hindi'
            if len(hindi_chars) > len(text) * 0.3
            else 'english'
        )

    def _get_risk_level(self, score: int) -> str:

        if score >= 85:
            return "CRITICAL 🔴"

        elif score >= 65:
            return "HIGH 🟠"

        elif score >= 40:
            return "MEDIUM 🟡"

        elif score >= 20:
            return "LOW 🟢"

        else:
            return "SAFE ✅"

    def _generate_explanation(self, indicators: List[str]) -> str:

        if not indicators:
            return (
                "This message does not show typical phishing characteristics."
            )

        return " | ".join(indicators)

    def _get_recommendation(self, score: int) -> str:

        if score >= 85:
            return (
                "🚨 DANGER: Likely scam. DO NOT click links or reply. "
                "Delete immediately."
            )

        elif score >= 65:
            return (
                "⚠️ WARNING: Suspicious message. Do not click links "
                "or provide information."
            )

        elif score >= 40:
            return (
                "⚡ CAUTION: Message has warning signs. "
                "Verify the sender independently."
            )

        elif score >= 20:
            return (
                "✓ Minor concerns. Be cautious but may be legitimate."
            )

        else:
            return "✅ Appears safe based on content analysis."