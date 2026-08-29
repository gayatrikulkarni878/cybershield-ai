"""
QR code decoder using OpenCV (no external system libraries needed, unlike
pyzbar which depends on a native zbar DLL that's unreliable on Windows).
"""
import cv2
import numpy as np


def decode_qr(image_bytes: bytes):
    arr = np.frombuffer(image_bytes, dtype=np.uint8)
    image = cv2.imdecode(arr, cv2.IMREAD_COLOR)
    if image is None:
        return None

    detector = cv2.QRCodeDetector()
    data, points, _ = detector.detectAndDecode(image)

    if not data:
        return None
    return data
