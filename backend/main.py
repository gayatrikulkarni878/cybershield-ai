from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from urllib.parse import urlparse

from schemas import ThreatReport, URLRequest, MessageRequest
from detectors import url_detector, message_detector, qr_detector, reputation

app = FastAPI(title="CyberShield AI", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # tighten before real deployment
    allow_methods=["*"],
    allow_headers=["*"],
)


def build_url_report(raw_url: str) -> ThreatReport:
    score, indicators = url_detector.score_url(raw_url)

    # Live threat-intel check (URLhaus). Skips silently if offline/unreachable
    # so the demo never breaks without internet.
    host = urlparse(raw_url if "://" in raw_url else f"http://{raw_url}").netloc.split(":")[0]
    rep = reputation.check_domain_reputation(host) if host else None
    if rep and rep["listed"]:
        score = min(100, score + 40)
        threat_label = ", ".join(rep["threat_types"]) or "malware/phishing"
        indicators.append(f"Domain is listed in a live threat-intelligence feed ({threat_label})")

    level = url_detector.classify_score(score)
    return ThreatReport(
        input_type="url",
        input_value=raw_url,
        risk_level=level,
        risk_score=score,
        threat_type="Malicious URL / Phishing" if score >= 20 else "No significant threat",
        indicators=indicators,
        explanation=(
            f"This URL was scored {score}/100 based on {len(indicators)} structural "
            f"indicator(s) commonly associated with phishing or malicious links."
        ),
        recommended_action=(
            "Do not enter login credentials or payment details on this site. Verify the "
            "domain directly by typing it into your browser instead of clicking the link."
            if score >= 20
            else "No major red flags found, but always verify the domain before entering sensitive information."
        ),
    )


@app.post("/analyze/url", response_model=ThreatReport)
def analyze_url(payload: URLRequest):
    return build_url_report(payload.url)


@app.post("/analyze/message", response_model=ThreatReport)
def analyze_message(payload: MessageRequest):
    score, indicators, embedded_url = message_detector.score_message(payload.text)
    level = message_detector.classify_score(score)

    # If the message contains a URL, factor its own risk score in too
    if embedded_url:
        url_score, url_indicators = url_detector.score_url(embedded_url)
        score = min(100, max(score, int(0.6 * score + 0.4 * url_score)))
        indicators.extend([f"[link] {i}" for i in url_indicators])
        level = message_detector.classify_score(score)

    return ThreatReport(
        input_type="message",
        input_value=payload.text,
        risk_level=level,
        risk_score=score,
        threat_type="Phishing / Social Engineering" if score >= 20 else "No significant threat",
        indicators=indicators,
        explanation=(
            f"This message was scored {score}/100 based on {len(indicators)} manipulation "
            f"and/or technical indicator(s) commonly used in scam messages."
        ),
        recommended_action=(
            "Do not click any links or share OTPs, passwords, or account details from this "
            "message. Contact the organisation directly using its official app or website."
            if score >= 20
            else "No major red flags found, but stay cautious with unexpected messages."
        ),
    )


@app.post("/analyze/qr", response_model=ThreatReport)
async def analyze_qr(file: UploadFile = File(...)):
    contents = await file.read()
    decoded = qr_detector.decode_qr(contents)
    if decoded is None:
        raise HTTPException(status_code=400, detail="No QR code detected in the uploaded image")

    if decoded.startswith("http://") or decoded.startswith("https://") or "." in decoded:
        report = build_url_report(decoded)
        report.input_type = "qr"
        report.explanation = f"QR code decoded to: {decoded}. " + report.explanation
        return report

    # Non-URL QR payload (plain text) - run through the message detector instead
    score, indicators, _ = message_detector.score_message(decoded)
    level = message_detector.classify_score(score)
    return ThreatReport(
        input_type="qr",
        input_value=decoded,
        risk_level=level,
        risk_score=score,
        threat_type="Suspicious QR Payload" if score >= 20 else "No significant threat",
        indicators=indicators,
        explanation=f"QR code decoded to plain text: '{decoded}'.",
        recommended_action="Treat any unexpected QR code with caution before acting on its content.",
    )


@app.get("/health")
def health():
    return {"status": "ok"}
