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


@app.post("/api/analyze/url")
async def analyze_url(request: dict):
    """Analyze URL with error handling"""
    try:
        url = request.get("url", "").strip()

        if not url:
            return JSONResponse(
                status_code=400,
                content={
                    "error": "URL cannot be empty",
                    "code": "EMPTY_INPUT"
                }
            )

        if len(url) > 2048:
            return JSONResponse(
                status_code=400,
                content={
                    "error": "URL too long (max 2048 chars)",
                    "code": "URL_TOO_LONG"
                }
            )

        result = url_detector.analyze(url)
        return {"success": True, "data": result}

    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={
                "error": f"Analysis failed: {str(e)}",
                "code": "ANALYSIS_ERROR"
            }
        )


@app.post("/api/analyze/message")
async def analyze_message(request: dict):
    """Analyze message with error handling"""
    try:
        message = request.get("message", "").strip()

        if not message:
            return JSONResponse(
                status_code=400,
                content={
                    "error": "Message cannot be empty",
                    "code": "EMPTY_INPUT"
                }
            )

        if len(message) < 5:
            return JSONResponse(
                status_code=400,
                content={
                    "error": "Message too short (min 5 chars)",
                    "code": "MESSAGE_TOO_SHORT"
                }
            )

        result = message_detector.analyze(message)
        return {"success": True, "data": result}

    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={
                "error": f"Analysis failed: {str(e)}",
                "code": "ANALYSIS_ERROR"
            }
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


@app.get("/api/health")
async def health():
    """Health check endpoint"""
    return {"status": "healthy", "version": "2.0"}
