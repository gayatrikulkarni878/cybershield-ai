# CyberShield AI — SIH Prototype

An explainable threat-detection prototype: paste a URL, paste a suspicious
message, or upload a QR code, and get back a risk score with a plain-language
explanation of *why* it's risky.

## What's here

- `backend/` — FastAPI service with 3 endpoints (`/analyze/url`,
  `/analyze/message`, `/analyze/qr`). Detection is currently rule-based
  (heuristics), chosen for speed and 100% explainability. Each detector is
  isolated in `backend/detectors/` so you can swap in a trained ML model
  later without touching the API or frontend.
- `frontend/` — React + Vite app with a tabbed input panel and an
  animated "case file" report card.

## Running it locally

### Backend
```bash
cd backend
pip install -r requirements.txt
uvicorn main:app --reload --port 8123
```
Runs at http://127.0.0.1:8123 — check http://127.0.0.1:8123/docs for the
interactive API explorer.

### Frontend
```bash
cd frontend
npm install
npm run dev
```
Runs at http://localhost:5173 and proxies `/api/*` to the backend
(see `vite.config.js`).

## Next steps (roadmap)

1. Swap `url_detector.score_url` for a trained model (UCI Phishing Websites
   dataset or a Kaggle malicious-URLs dataset + scikit-learn RandomForest),
   keeping the same `(score, indicators)` return shape.
2. Swap `message_detector.score_message` for either an LLM call (structured
   JSON output) or a TF-IDF + Logistic Regression model trained on an
   SMS-spam dataset.
3. Add a lightweight "fake website" heuristic module (domain age, SSL cert
   issuer, brand-keyword-vs-domain mismatch) following the same pattern.
4. Deploy: backend to Render/Railway, frontend to Vercel/Netlify, or just
   run both locally + ngrok for the demo.
5. Prepare 3–4 canned demo inputs (a real-looking phishing URL, a scam SMS,
   a scam QR code) so the live demo is reliable on stage.
