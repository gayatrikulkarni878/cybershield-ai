import io
import re
from PIL import Image
from .url_detector import analyze_url

def decode_qr_image(image_bytes: bytes) -> dict:
    """
    Decodes a QR code image locally and analyzes any embedded URL or payload.
    """
    if not image_bytes:
        return {
            "error": "No image data provided.",
            "decoded_content": None,
            "is_url": False,
            "risk_score": 0,
            "risk_level": "SAFE",
            "threat_type": "None",
            "indicators": [],
            "explanation": "No file uploaded.",
            "recommendation": "Please upload a valid QR code image."
        }

    try:
        img = Image.open(io.BytesIO(image_bytes))
    except Exception as e:
        return {
            "error": f"Invalid image format: {str(e)}",
            "decoded_content": None,
            "is_url": False,
            "risk_score": 0,
            "risk_level": "SAFE",
            "threat_type": "None",
            "indicators": [],
            "explanation": "The uploaded file could not be parsed as an image.",
            "recommendation": "Upload a clean PNG, JPG, or WEBP image."
        }

    decoded_text = None

    # Attempt decoding using pyzbar if available in Python environment
    try:
        from pyzbar.pyzbar import decode
        decoded_objs = decode(img)
        if decoded_objs:
            decoded_text = decoded_objs[0].data.decode("utf-8", errors="ignore")
    except Exception:
        pass

    # If pyzbar is not installed or returned None, try OpenCV QRCodeDetector if available
    if not decoded_text:
        try:
            import cv2
            import numpy as np
            # Convert PIL Image to OpenCV format
            open_cv_image = np.array(img.convert('RGB'))
            open_cv_image = open_cv_image[:, :, ::-1].copy()
            detector = cv2.QRCodeDetector()
            data, bbox, _ = detector.detectAndDecode(open_cv_image)
            if data:
                decoded_text = data
        except Exception:
            pass

    # High-level fallback: If neither pyzbar nor cv2 are available, check image metadata/EXIF/comments
    # or return friendly guidance for manual decode / demo testing
    if not decoded_text:
        # Check image info dictionary (PNG tEXt chunks, comments)
        if hasattr(img, 'info') and img.info:
            for k, v in img.info.items():
                if isinstance(v, str) and ("http://" in v or "https://" in v):
                    decoded_text = v
                    break

    if not decoded_text:
        return {
            "success": False,
            "decoded_content": None,
            "is_url": False,
            "risk_score": 0,
            "risk_level": "SAFE",
            "threat_type": "No QR Code Detected",
            "indicators": [{
                "code": "NO_QR_FOUND",
                "title": "Unreadable or Missing QR Code",
                "points": 0,
                "category": "Scanner Alert",
                "description": "Could not detect a valid QR barcode pattern in the uploaded image."
            }],
            "explanation": "No QR code could be extracted from the uploaded image. Please ensure the image is clear and well-lit.",
            "recommendation": "Try uploading a clearer image or use one of the interactive DEMO QR buttons."
        }

    # Clean decoded text
    decoded_text = decoded_text.strip()

    # Check if decoded text is a URL
    is_url = bool(re.match(r'^(https?://|www\.)', decoded_text, re.IGNORECASE))

    if is_url:
        # Pass decoded URL through URL detector engine!
        url_analysis = analyze_url(decoded_text)
        return {
            "success": True,
            "decoded_content": decoded_text,
            "is_url": True,
            "risk_score": url_analysis["risk_score"],
            "risk_level": url_analysis["risk_level"],
            "threat_type": f"QR Payload: {url_analysis['threat_type']}",
            "indicators": [
                {
                    "code": "QR_URL_PAYLOAD",
                    "title": "QR Code Contains Web URL",
                    "points": 5,
                    "category": "Vector Analysis",
                    "description": f"Decoded QR code redirects to external destination: {decoded_text}"
                }
            ] + url_analysis["indicators"],
            "explanation": f"Decoded QR Code payload: '{decoded_text}'. " + url_analysis["explanation"],
            "recommendation": url_analysis["recommendation"],
            "url_analysis": url_analysis
        }
    else:
        # Non-URL payload (Text, vCard, Wifi config, etc.)
        return {
            "success": True,
            "decoded_content": decoded_text,
            "is_url": False,
            "risk_score": 10 if ("password" in decoded_text.lower() or "pin" in decoded_text.lower()) else 0,
            "risk_level": "LOW" if ("password" in decoded_text.lower() or "pin" in decoded_text.lower()) else "SAFE",
            "threat_type": "Plain Text / QR Payload",
            "indicators": [
                {
                    "code": "QR_TEXT_PAYLOAD",
                    "title": "Plain Text Payload",
                    "points": 0,
                    "category": "Content",
                    "description": f"QR Code contains text/data: '{decoded_text[:60]}...'"
                }
            ],
            "explanation": f"Decoded QR payload: '{decoded_text}'. No web redirects or automatic executable links were found.",
            "recommendation": "Review the decoded text before sharing or copying."
        }
