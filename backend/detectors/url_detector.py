import re
from urllib.parse import urlparse
from typing import Dict, List


class AdvancedURLDetector:
    """Enhanced URL detection with 10+ checks"""

    def __init__(self):
        self.phishing_keywords = {
            'paypal': 25,
            'amazon': 25,
            'apple': 20,
            'google': 20,
            'facebook': 20,
            'bank': 30,
            'verify': 25,
            'confirm': 25,
            'login': 20,
            'secure': 15,
            'update': 15,
            'wallet': 20,
            'crypto': 20,
            'whatsapp': 20,
            'dropbox': 15,
            'microsoft': 15
        }

        self.high_risk_tlds = ['.tk', '.ml', '.ga', '.cf']
        self.url_shorteners = [
            'bit.ly',
            'tinyurl',
            'short.link',
            'goo.gl',
            'ow.ly'
        ]

    def analyze(self, url: str) -> Dict:
        """Analyze URL for phishing indicators"""

        score = 0
        indicators = []
        threat_type = "Unknown"

        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url

        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            path = parsed.path.lower()
            query = parsed.query.lower()
        except Exception:
            return self._create_report(
                "CRITICAL",
                100,
                ["Invalid URL"],
                "Malformed URL format",
                "Invalid URL"
            )

        # CHECK 1: HTTPS
        if not url.startswith('https://'):
            indicators.append("❌ No HTTPS encryption")
            score += 20
        else:
            indicators.append("✅ Has HTTPS encryption")

        # CHECK 2: IP-BASED URL
        if re.match(
            r'^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}',
            domain
        ):
            indicators.append("🚨 IP-based URL instead of domain")
            score += 40
            threat_type = "IP-Based Phishing"

        # CHECK 3: URL LENGTH
        if len(url) > 75:
            indicators.append("⚠️ Abnormally long URL")
            score += 15

        # CHECK 4: HIGH-RISK TLD
        for tld in self.high_risk_tlds:
            if domain.endswith(tld):
                indicators.append(f"🚨 High-risk TLD: {tld}")
                score += 30
                threat_type = "Suspicious Domain"
                break

        # CHECK 5: DOMAIN LENGTH
        if len(domain) > 40:
            indicators.append("⚠️ Unusually long domain")
            score += 12

        # CHECK 6: EXCESSIVE HYPHENS
        hyphen_count = domain.count('-')

        if hyphen_count > 2:
            indicators.append(
                f"🚨 Multiple hyphens ({hyphen_count}) - typosquatting"
            )
            score += 25
            threat_type = "Typosquatting"

        # CHECK 7: PHISHING KEYWORDS
        for keyword, keyword_score in self.phishing_keywords.items():
            if (
                keyword in domain
                and 'official' not in domain
                and 'genuine' not in domain
            ):
                indicators.append(
                    f"🚨 Contains '{keyword}' - brand impersonation"
                )
                score += keyword_score
                threat_type = "Brand Impersonation"
                break

        # CHECK 8: URL SHORTENERS
        for shortener in self.url_shorteners:
            if shortener in url:
                indicators.append(
                    f"⚠️ Uses URL shortener ({shortener})"
                )
                score += 25
                threat_type = "Obfuscated URL"
                break

        # CHECK 9: SUSPICIOUS PARAMETERS
        suspicious_params = [
            'verify',
            'login',
            'signin',
            'confirm',
            'update',
            'reset'
        ]

        for param in suspicious_params:
            if param in query:
                indicators.append(
                    f"🚨 Suspicious parameter: '{param}'"
                )
                score += 15
                break

        # CHECK 10: CREDENTIAL HIDING
        if '@' in parsed.netloc:
            indicators.append(
                "🚨 Contains @ symbol - credential hiding"
            )
            score += 35
            threat_type = "Credential Injection"

        score = min(score, 100)
        risk_level = self._get_risk_level(score)

        explanation = self._generate_explanation(indicators)
        recommendation = self._get_recommendation(score)

        return {
            'url': url,
            'risk_level': risk_level,
            'risk_score': score,
            'threat_type': (
                threat_type
                if threat_type != "Unknown"
                else "Phishing/Malicious URL"
            ),
            'indicators': indicators,
            'explanation': explanation,
            'recommendation': recommendation,
            'detailed_checks': {
                'has_https': url.startswith('https://'),
                'domain': domain,
                'domain_length': len(domain),
                'url_length': len(url),
                'uses_shortener': any(
                    s in url for s in self.url_shorteners
                )
            }
        }

    def _get_risk_level(self, score: int) -> str:
        if score >= 85:
            return "CRITICAL 🔴"
        elif score >= 65:
            return "HIGH 🟠"
        elif score >= 40:
            return "MEDIUM 🟡"
        else:
            return "LOW 🟢"

    def _generate_explanation(self, indicators: List[str]) -> str:
        if not indicators:
            return (
                "This URL appears to be legitimate based on structural analysis."
            )

        negative = [
            i for i in indicators
            if '🚨' in i or '⚠️' in i
        ]

        positive = [
            i for i in indicators
            if '✅' in i
        ]

        explanation = ""

        if negative:
            explanation += (
                "Issues found: "
                + ", ".join(
                    i.replace('🚨', '').replace('⚠️', '').strip()
                    for i in negative
                )
            )

        if positive and explanation:
            explanation += (
                " | Positive: "
                + ", ".join(
                    i.replace('✅', '').strip()
                    for i in positive
                )
            )

        return (
            explanation.strip()
            if explanation
            else "URL analysis complete"
        )

    def _get_recommendation(self, score: int) -> str:
        if score >= 85:
            return (
                "⛔ DO NOT visit this URL. "
                "Do not click any links. Report it."
            )
        elif score >= 65:
            return (
                "⚠️ CAUTION: Highly suspicious URL. "
                "Do not enter passwords or payment info."
            )
        elif score >= 40:
            return (
                "⚡ SUSPICIOUS: Verify with official website "
                "before entering information."
            )
        else:
            return (
                "✅ LIKELY SAFE: But always verify links "
                "from unknown sources."
            )

    def _create_report(
        self,
        risk_level,
        score,
        indicators,
        explanation,
        threat_type
    ):
        return {
            'risk_level': risk_level,
            'risk_score': score,
            'indicators': indicators,
            'explanation': explanation,
            'threat_type': threat_type,
            'recommendation': self._get_recommendation(score)
        }