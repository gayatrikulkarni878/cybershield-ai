from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional

from detectors.url_detector import analyze_url
from detectors.message_detector import analyze_message
from detectors.qr_detector import decode_qr_image

app = FastAPI(
    title="CyberShield AI API",
    description="Intelligent Cybersecurity Threat Detection & Awareness Platform API",
    version="1.0.0"
)

# Allow CORS for local frontend execution
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class URLRequest(BaseModel):
    url: str

class MessageRequest(BaseModel):
    message: str

@app.get("/")
def read_root():
    return {
        "title": "CyberShield AI Backend",
        "status": "Online",
        "tagline": "Your Intelligent Shield Against Digital Threats"
    }

@app.get("/api/health")
def health_check():
    return {
        "status": "ok",
        "service": "CyberShield AI Backend",
        "version": "1.0.0"
    }

@app.post("/api/analyze/url")
def analyze_url_endpoint(req: URLRequest):
    if not req.url:
        raise HTTPException(status_code=400, detail="URL field is required.")
    return analyze_url(req.url)

@app.post("/api/analyze/message")
def analyze_message_endpoint(req: MessageRequest):
    if not req.message:
        raise HTTPException(status_code=400, detail="Message field is required.")
    return analyze_message(req.message)

@app.post("/api/analyze/qr")
async def analyze_qr_endpoint(file: UploadFile = File(...)):
    if not file:
        raise HTTPException(status_code=400, detail="No file uploaded.")
    contents = await file.read()
    return decode_qr_image(contents)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
