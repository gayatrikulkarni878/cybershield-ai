import React, { useState, useRef } from 'react';
import { QrCode, Upload, Search, RotateCcw, Loader2, Sparkles, Image as ImageIcon, FileText } from 'lucide-react';
import { analyzeQr } from '../api.js';
import { analyzeUrlLocal } from '../utils/detectorEngine.js';
import ResultsCard from './ResultsCard.jsx';

export default function QrAnalyzer({ onAnalysisDone }) {
  const [selectedFile, setSelectedFile] = useState(null);
  const [imagePreview, setImagePreview] = useState(null);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [errorMsg, setErrorMsg] = useState('');
  const fileInputRef = useRef(null);

  const handleFileChange = (e) => {
    const file = e.target.files?.[0];
    if (file) {
      processFile(file);
    }
  };

  const processFile = (file) => {
    setSelectedFile(file);
    setErrorMsg('');
    setResult(null);

    const reader = new FileReader();
    reader.onload = () => {
      setImagePreview(reader.result);
    };
    reader.readAsDataURL(file);
  };

  const handleAnalyze = async (fileToScan) => {
    const targetFile = fileToScan || selectedFile;
    if (!targetFile) {
      setErrorMsg('Please upload a QR code image or select a DEMO sample.');
      return;
    }
    setErrorMsg('');
    setLoading(true);
    setResult(null);

    try {
      const res = await analyzeQr(targetFile);
      setResult(res);
      if (onAnalysisDone) {
        onAnalysisDone('qr', res.risk_score > 40);
      }
    } catch (err) {
      setErrorMsg('Failed to process QR code image.');
    } finally {
      setLoading(false);
    }
  };

  // Helper to generate a Demo QR canvas image blob for instant hackathon testing
  const handleDemoQr = (demoUrl, label) => {
    // Create a QR SVG/Canvas programmatically or generate a synthetic QR image file for demo
    const canvas = document.createElement('canvas');
    canvas.width = 250;
    canvas.height = 250;
    const ctx = canvas.getContext('2d');
    
    // Draw background & mock QR pattern visually
    ctx.fillStyle = '#ffffff';
    ctx.fillRect(0, 0, 250, 250);
    ctx.fillStyle = '#000000';
    // Draw finder patterns
    const drawFinder = (x, y) => {
      ctx.fillRect(x, y, 50, 50);
      ctx.fillStyle = '#ffffff';
      ctx.fillRect(x + 10, y + 10, 30, 30);
      ctx.fillStyle = '#000000';
      ctx.fillRect(x + 20, y + 20, 10, 10);
    };
    drawFinder(20, 20);
    drawFinder(180, 20);
    drawFinder(20, 180);

    // Add encoded data pixels
    for (let i = 0; i < 40; i++) {
      const rx = Math.floor(Math.random() * 200) + 20;
      const ry = Math.floor(Math.random() * 200) + 20;
      ctx.fillRect(rx, ry, 12, 12);
    }

    canvas.toBlob((blob) => {
      const file = new File([blob], `${label.toLowerCase().replace(/\s+/g, '_')}.png`, { type: 'image/png' });
      // Store demo metadata so decoder knows payload if canvas pixels are random
      file.demoPayload = demoUrl;
      setSelectedFile(file);
      setImagePreview(canvas.toDataURL());
      
      // Analyze demo directly
      handleAnalyzeDemoFile(demoUrl, label);
    });
  };

  const handleAnalyzeDemoFile = async (demoUrl, label) => {
    setLoading(true);
    setResult(null);
    setErrorMsg('');

    const urlAnalysis = analyzeUrlLocal(demoUrl);

    setTimeout(() => {
      const demoRes = {
        success: true,
        decoded_content: demoUrl,
        is_url: true,
        risk_score: urlAnalysis.risk_score,
        risk_level: urlAnalysis.risk_level,
        threat_type: `QR Payload: ${urlAnalysis.threat_type}`,
        indicators: [
          {
            code: "QR_DEMO_PAYLOAD",
            title: "QR Code Contains Web Destination",
            points: 5,
            category: "Vector Analysis",
            description: `Extracted QR link: ${demoUrl}`
          },
          ...urlAnalysis.indicators
        ],
        explanation: `Decoded QR payload: '${demoUrl}'. ${urlAnalysis.explanation}`,
        recommendation: urlAnalysis.recommendation,
        source: 'Local Browser QR Engine (Demo Mode)'
      };

      setResult(demoRes);
      if (onAnalysisDone) onAnalysisDone('qr', demoRes.risk_score > 40);
      setLoading(false);
    }, 600);
  };

  const handleClear = () => {
    setSelectedFile(null);
    setImagePreview(null);
    setResult(null);
    setErrorMsg('');
    if (fileInputRef.current) fileInputRef.current.value = '';
  };

  return (
    <div className="analyzer-wrapper">
      <div className="analyzer-card">
        <div className="analyzer-header">
          <div className="analyzer-title-group">
            <QrCode className="analyzer-icon emerald" size={24} />
            <div>
              <h2>QR Code Threat Scanner</h2>
              <p>Upload a QR code image to decode content locally and check destination link security.</p>
            </div>
          </div>
        </div>

        <div className="upload-dropzone" onClick={() => fileInputRef.current?.click()}>
          <input
            type="file"
            ref={fileInputRef}
            onChange={handleFileChange}
            accept="image/png, image/jpeg, image/webp"
            style={{ display: 'none' }}
          />

          {imagePreview ? (
            <div className="preview-box">
              <img src={imagePreview} alt="Uploaded QR preview" className="qr-preview-img" />
              <p className="preview-filename">{selectedFile?.name}</p>
            </div>
          ) : (
            <div className="dropzone-prompt">
              <Upload size={36} className="emerald" />
              <p className="dropzone-text">Click or drag & drop a QR image here</p>
              <p className="dropzone-sub">Supports PNG, JPG, WEBP • 100% Offline Local Scan</p>
            </div>
          )}
        </div>

        <div className="action-row">
          <button className="btn-secondary" onClick={handleClear} disabled={!selectedFile && !result}>
            <RotateCcw size={16} />
            <span>Clear File</span>
          </button>

          <button
            className="btn-primary analyze-btn"
            onClick={() => handleAnalyze()}
            disabled={loading || !selectedFile}
          >
            {loading ? <Loader2 size={18} className="spin" /> : <Search size={18} />}
            <span>{loading ? 'Scanning QR...' : 'Scan QR Code'}</span>
          </button>
        </div>

        {errorMsg && <div className="error-alert">{errorMsg}</div>}

        <div className="demo-section">
          <div className="demo-label">
            <Sparkles size={15} className="emerald" />
            <span>Interactive DEMO QR Samples (Click to scan):</span>
          </div>
          <div className="demo-buttons-flex">
            <button
              className="demo-pill danger"
              onClick={() => handleDemoQr('http://192.168.1.1/login', 'Phishing IP QR')}
            >
              Demo QR (Phishing IP)
            </button>

            <button
              className="demo-pill warning"
              onClick={() => handleDemoQr('https://bit.ly/login-verify', 'Shortener QR')}
            >
              Demo QR (URL Shortener)
            </button>

            <button
              className="demo-pill safe"
              onClick={() => handleDemoQr('https://www.google.com', 'Google Safe QR')}
            >
              Demo QR (Safe Link)
            </button>
          </div>
        </div>
      </div>

      {result && (
        <div className="qr-payload-card">
          <div className="payload-box">
            <FileText size={18} className="cyan" />
            <span>Decoded Payload: <strong>{result.decoded_content || 'None'}</strong></span>
          </div>
          <ResultsCard result={result} />
        </div>
      )}
    </div>
  );
}
