// API Service Layer with Smart Fallback Engine
import { analyzeUrlLocal, analyzeMessageLocal } from './utils/detectorEngine.js';
import { decodeQrImageClient } from './utils/qrScanner.js';

const API_BASE_URL = 'http://localhost:8000/api';

export async function checkBackendHealth() {
  try {
    const res = await fetch(`${API_BASE_URL}/health`, { method: 'GET', signal: AbortSignal.timeout(1500) });
    if (res.ok) {
      const data = await res.json();
      return { online: true, data };
    }
  } catch (e) {
    // Backend server unavailable
  }
  return { online: false, data: null };
}

export async function analyzeUrl(urlStr) {
  try {
    const res = await fetch(`${API_BASE_URL}/analyze/url`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: urlStr }),
      signal: AbortSignal.timeout(2500)
    });
    if (res.ok) {
      const data = await res.json();
      return { ...data, source: 'Python FastAPI Backend' };
    }
  } catch (err) {
    console.warn("Backend API unavailable. Falling back to local JS heuristic engine.", err);
  }

  // Local fallback
  const localRes = analyzeUrlLocal(urlStr);
  return { ...localRes, source: 'Local Heuristic Engine (Offline Mode)' };
}

export async function analyzeMessage(messageText) {
  try {
    const res = await fetch(`${API_BASE_URL}/analyze/message`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ message: messageText }),
      signal: AbortSignal.timeout(2500)
    });
    if (res.ok) {
      const data = await res.json();
      return { ...data, source: 'Python FastAPI Backend' };
    }
  } catch (err) {
    console.warn("Backend API unavailable. Falling back to local JS heuristic engine.", err);
  }

  // Local fallback
  const localRes = analyzeMessageLocal(messageText);
  return { ...localRes, source: 'Local Heuristic Engine (Offline Mode)' };
}

export async function analyzeQr(file) {
  try {
    const formData = new FormData();
    formData.append('file', file);
    const res = await fetch(`${API_BASE_URL}/analyze/qr`, {
      method: 'POST',
      body: formData,
      signal: AbortSignal.timeout(3500)
    });
    if (res.ok) {
      const data = await res.json();
      if (data.success !== false) {
        return { ...data, source: 'Python FastAPI Backend' };
      }
    }
  } catch (err) {
    console.warn("Backend API QR decoder unavailable. Falling back to local browser scanner.", err);
  }

  // Local browser scanner fallback
  const localRes = await decodeQrImageClient(file);
  return { ...localRes, source: 'Local Browser Scanner (Offline Mode)' };
}
