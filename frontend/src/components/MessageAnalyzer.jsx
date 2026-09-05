import React, { useState } from 'react';
import { MessageSquare, Search, RotateCcw, Loader2, Sparkles, Languages } from 'lucide-react';
import { analyzeMessage } from '../api.js';
import ResultsCard from './ResultsCard.jsx';

export default function MessageAnalyzer({ onAnalysisDone }) {
  const [messageText, setMessageText] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [errorMsg, setErrorMsg] = useState('');

  const demoMessages = [
    {
      label: 'English Phish Sample',
      lang: 'English',
      text: 'URGENT! Your bank account has been suspended. Click here immediately to verify your account and enter your OTP: https://example.com'
    },
    {
      label: 'Hindi Phish Sample (हिंदी)',
      lang: 'Hindi',
      text: 'तुरंत अपने खाते की जानकारी सत्यापित करें। आपका खाता बंद किया जा सकता है। लिंक पर क्लिक करें।'
    },
    {
      label: 'Marathi Phish Sample (मराठी)',
      lang: 'Marathi',
      text: 'तातडीने तुमचे खाते सत्यापित करा. तुमचे खाते बंद केले जाऊ शकते. खालील लिंकवर क्लिक करा.'
    }
  ];

  const handleAnalyze = async (textToTest) => {
    const target = textToTest || messageText;
    if (!target.trim()) {
      setErrorMsg('Please enter or paste a message to analyze.');
      return;
    }
    setErrorMsg('');
    setLoading(true);
    setResult(null);

    try {
      const res = await analyzeMessage(target);
      setResult(res);
      if (onAnalysisDone) {
        onAnalysisDone('message', res.risk_score > 40);
      }
    } catch (err) {
      setErrorMsg('Error evaluating message text. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const handleSelectDemo = (item) => {
    setMessageText(item.text);
    handleAnalyze(item.text);
  };

  const handleClear = () => {
    setMessageText('');
    setResult(null);
    setErrorMsg('');
  };

  return (
    <div className="analyzer-wrapper">
      <div className="analyzer-card">
        <div className="analyzer-header">
          <div className="analyzer-title-group">
            <MessageSquare className="analyzer-icon purple" size={24} />
            <div>
              <h2>Multilingual Phishing & Message Analyzer</h2>
              <p>Detect social engineering, urgency, credential harvesting, and suspicious links in English, Hindi, & Marathi.</p>
            </div>
          </div>
        </div>

        <div className="textarea-wrapper">
          <textarea
            className="large-textarea"
            rows="5"
            placeholder="Paste suspicious SMS, WhatsApp message, or email body here..."
            value={messageText}
            onChange={(e) => setMessageText(e.target.value)}
          ></textarea>
        </div>

        <div className="action-row">
          <button className="btn-secondary" onClick={handleClear} disabled={!messageText && !result}>
            <RotateCcw size={16} />
            <span>Clear</span>
          </button>

          <button
            className="btn-primary analyze-btn"
            onClick={() => handleAnalyze()}
            disabled={loading}
          >
            {loading ? <Loader2 size={18} className="spin" /> : <Search size={18} />}
            <span>{loading ? 'Evaluating...' : 'Analyze Message'}</span>
          </button>
        </div>

        {errorMsg && <div className="error-alert">{errorMsg}</div>}

        <div className="demo-section">
          <div className="demo-label">
            <Languages size={15} className="cyan" />
            <span>Multilingual DEMO Examples (Click to run):</span>
          </div>
          <div className="demo-buttons-flex">
            {demoMessages.map((demo, idx) => (
              <button
                key={idx}
                className="demo-pill danger"
                onClick={() => handleSelectDemo(demo)}
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
