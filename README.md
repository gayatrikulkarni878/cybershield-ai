# CyberShield AI 🛡️
> **"Your Intelligent Shield Against Digital Threats"**

CyberShield AI is a complete, offline-ready cybersecurity awareness and threat-analysis platform designed for college hackathon demonstrations. It analyzes potentially malicious URLs, phishing messages (supporting English, Hindi, and Marathi), and suspicious QR codes using transparent, rule-based cybersecurity heuristics.

---

## 🌟 Key Features

1. **URL Threat Analyzer**
   - Evaluates links for HTTPS encryption, raw IP hosts, URL shorteners, excessive subdomains, brand spoofing hyphens, and high-risk TLDs.
   - Calculates a transparent Risk Score (0–100) and Risk Level (`SAFE`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).

2. **Multilingual Phishing & Message Analyzer**
   - Detects social engineering traps, urgency language, threat/suspension warnings, and OTP credential harvesting requests.
   - Automatically detects and analyzes text in **English**, **Hindi**, and **Marathi**.
   - Extracts embedded links and recursively checks their risk score.

3. **QR Code Threat Scanner**
   - Decodes uploaded QR code images locally.
   - Routes extracted URLs directly through the threat engine to prevent "Quishing" attacks.

4. **Security Dashboard**
   - Real-time session analytics tracking URLs analyzed, messages evaluated, QR scans, and flagged threats stored in `localStorage`.

5. **Interactive Hackathon DEMO Mode**
   - Built-in one-click demo sample buttons for URLs, multilingual messages, and QR codes for seamless judge presentation.

6. **Offline / Dual Execution Engine**
   - Python FastAPI backend with local JavaScript heuristic fallback (`detectorEngine.js`). Even if the backend server is stopped, the frontend continues to work 100% locally with zero external API dependencies.

---

## 🚀 Quick Launch (Windows)

Simply double-click `run.bat` in the root folder! It will automatically open:
- **Backend API**: `http://localhost:8000`
- **Frontend UI**: `http://localhost:5173`

---

## 🛠️ Manual Launch Instructions

### 1. Backend (FastAPI)
```bash
cd backend
python -m pip install -r requirements.txt
python -m uvicorn main:app --reload --port 8000
```

### 2. Frontend (Vite + React)
```bash
cd frontend
corepack pnpm install   # or npm install
corepack pnpm dev       # or npm run dev
```

---

## ⚖️ Security Disclaimer

CyberShield AI provides rule-based heuristic analysis for cybersecurity awareness and educational purposes. It does not guarantee that a URL, message, or QR code is 100% safe. Always verify suspicious content through official trusted channels.
