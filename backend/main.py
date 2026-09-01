from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from detectors import url_detector, message_detector, qr_detector


url_detector_engine = url_detector.AdvancedURLDetector()
message_detector_engine = message_detector.AdvancedPhishingDetector()


app = FastAPI(
    title="CyberShield AI",
    version="2.0"
)


# Allow the Vercel frontend to communicate with the backend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
async def root():
    return {
        "status": "online",
        "message": "CyberShield AI backend is running"
    }


@app.get("/api/health")
async def health():
    return {
        "status": "healthy",
        "version": "2.0"
    }


@app.post("/api/analyze/url")
async def analyze_url(request: dict):
    try:
        url = request.get("url", "").strip()

        if not url:
            return {
                "success": False,
                "error": "URL cannot be empty"
            }

        if len(url) > 2048:
            return {
                "success": False,
                "error": "URL too long"
            }

        result = url_detector_engine.analyze(url)

        return {
            "success": True,
            "data": result
        }

    except Exception as e:
        return {
            "success": False,
            "error": f"Analysis failed: {str(e)}"
        }


@app.post("/api/analyze/message")
async def analyze_message(request: dict):
    try:
        message = request.get("message", "").strip()

        if not message:
            return {
                "success": False,
                "error": "Message cannot be empty"
            }

        if len(message) < 5:
            return {
                "success": False,
                "error": "Message too short"
            }

        result = message_detector_engine.analyze(message)

        return {
            "success": True,
            "data": result
        }

    except Exception as e:
        return {
            "success": False,
            "error": f"Analysis failed: {str(e)}"
        }


@app.post("/api/analyze/qr")
async def analyze_qr(file: UploadFile = File(...)):
    try:
        contents = await file.read()

        decoded = qr_detector.decode_qr(contents)

        if decoded is None:
            raise HTTPException(
                status_code=400,
                detail="No QR code detected"
            )

        # If QR contains a URL
        if decoded.startswith("http://") or decoded.startswith("https://"):
            result = url_detector_engine.analyze(decoded)

            return {
                "success": True,
                "data": {
                    "input_type": "qr",
                    "input_value": decoded,
                    **result
                }
            }

        # If QR contains normal text
        result = message_detector_engine.analyze(decoded)

        return {
            "success": True,
            "data": {
                "input_type": "qr",
                "input_value": decoded,
                **result
            }
        }

    except HTTPException:
        raise

    except Exception as e:
        return {
            "success": False,
            "error": f"QR analysis failed: {str(e)}"
        }
