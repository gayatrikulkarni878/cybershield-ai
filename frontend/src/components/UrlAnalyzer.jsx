import React, { useState } from 'react';
import { Globe, Search, RotateCcw, Loader2, Sparkles } from 'lucide-react';
import { analyzeUrl } from '../api.js';
import ResultsCard from './ResultsCard.jsx';

export default function UrlAnalyzer({ onAnalysisDone }) {
  const [inputUrl, setInputUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [errorMsg, setErrorMsg] = useState('');

  const demoUrls = [
    { label: 'Google (Safe)', url: 'https://www.google.com', tag: 'safe' },
    { label: 'Bitly Link (Shortener)', url: 'https://bit.ly/example', tag: 'warning' },
    { label: 'IP Login (Raw Host)', url: 'http://192.168.1.1/login', tag: 'danger' },
    { label: 'Secure Verify (Phishing Sample)', url: 'https://secure-account-verify-example.com/login', tag: 'danger' }
  ];

  const handleAnalyze = async (urlToTest) => {
    const target = urlToTest || inputUrl;
    if (!target.trim()) {
      setErrorMsg('Please enter a URL or select a DEMO sample.');
      return;
    }
    setErrorMsg('');
    setLoading(true);
    setResult(null);

    try {
      const res = await analyzeUrl(target);
      setResult(res);
      if (onAnalysisDone) {
        onAnalysisDone('url', res.risk_score > 40);
      }
    } catch (err) {
      setErrorMsg('Error performing analysis. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const handleSelectDemo = (url) => {
    setInputUrl(url);
    handleAnalyze(url);
  };

  const handleClear = () => {
    setInputUrl('');
    setResult(null);
    setErrorMsg('');
  };

  return (
    <div className="analyzer-wrapper">
      <div className="analyzer-card">
        <div className="analyzer-header">
          <div className="analyzer-title-group">
            <Globe className="analyzer-icon cyan" size={24} />
            <div>
              <h2>URL Threat Analyzer</h2>
              <p>Evaluate link safety, domain reputational markers, and heuristic risk indicators.</p>
            </div>
          </div>
        </div>

        <div className="input-group">
          <div className="input-field-wrapper">
            <Search className="input-icon" size={20} />
            <input
              type="text"
              className="text-input"
              placeholder="Paste link (e.g., https://example-bank-login.com)..."
              value={inputUrl}
              onChange={(e) => setInputUrl(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handleAnalyze()}
            />
            {inputUrl && (
              <button className="clear-btn" onClick={handleClear} title="Clear text">
                <RotateCcw size={16} />
              </button>
            )}
          </div>

          <button
            className="btn-primary analyze-btn"
            onClick={() => handleAnalyze()}
            disabled={loading}
          >
            {loading ? <Loader2 size={18} className="spin" /> : <Search size={18} />}
            <span>{loading ? 'Analyzing...' : 'Analyze URL'}</span>
          </button>
        </div>

        {errorMsg && <div className="error-alert">{errorMsg}</div>}

        <div className="demo-section">
          <div className="demo-label">
            <Sparkles size={15} className="purple" />
            <span>Interactive DEMO Examples (Click to run):</span>
          </div>
          <div className="demo-buttons-flex">
            {demoUrls.map((demo, idx) => (
              <button
                key={idx}
                className={`demo-pill ${demo.tag}`}
                onClick={() => handleSelectDemo(demo.url)}
              >
                {demo.label}
              </button>
            ))}
          </div>
        </div>
      </div>

      {result && <ResultsCard result={result} />}
    </div>
  );
}
