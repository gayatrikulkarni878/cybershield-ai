import React from 'react';
import { Shield, Globe, MessageSquare, QrCode, ArrowRight, Zap, CheckCircle2, Lock } from 'lucide-react';

export default function Landing({ onStart }) {
  return (
    <div className="landing-container">
      <div className="hero-section">
        <div className="hero-badge">
          <Zap size={14} className="hero-badge-icon" />
          <span>Hackathon Edition • Rule-Based Cybersecurity Engine</span>
        </div>

        <h1 className="hero-title">
          CyberShield <span className="text-gradient">AI</span>
        </h1>
        
        <p className="hero-tagline">"Your Intelligent Shield Against Digital Threats"</p>
        
        <p className="hero-description">
          Analyze suspicious URLs, phishing messages, and malicious QR codes in real time using 
          transparent cybersecurity heuristics. Fast, offline-capable, and explainable threat scoring.
        </p>

        <div className="hero-actions">
          <button className="btn-primary" onClick={onStart}>
            <span>Start Threat Analysis</span>
            <ArrowRight size={20} />
          </button>
        </div>
      </div>

      <div className="features-grid">
        <div className="feature-card">
          <div className="feature-icon-wrapper cyan">
            <Globe size={28} />
          </div>
          <h3>URL Protection</h3>
          <p>
            Detects protocol vulnerabilities, raw IP hostnames, URL shorteners, brand spoofing hyphens, 
            excessive subdomains, and suspicious TLDs.
          </p>
          <ul className="feature-list">
            <li><CheckCircle2 size={16} /> HTTPS protocol validation</li>
            <li><CheckCircle2 size={16} /> Shortened domain unmasking</li>
            <li><CheckCircle2 size={16} /> Keyword & pattern heuristic checks</li>
          </ul>
        </div>

        <div className="feature-card">
          <div className="feature-icon-wrapper purple">
            <MessageSquare size={28} />
          </div>
          <h3>Multilingual Phishing Detection</h3>
          <p>
            Scans SMS, WhatsApp messages, and emails for social engineering tactics. Automatically 
            detects English, Hindi, and Marathi text.
          </p>
          <ul className="feature-list">
            <li><CheckCircle2 size={16} /> Auto language detection (EN, HI, MR)</li>
            <li><CheckCircle2 size={16} /> Urgency & account suspension traps</li>
            <li><CheckCircle2 size={16} /> OTP / credential harvesting flags</li>
          </ul>
        </div>

        <div className="feature-card">
          <div className="feature-icon-wrapper emerald">
            <QrCode size={28} />
          </div>
          <h3>QR Safety Scanner</h3>
          <p>
            Extracts QR barcode payloads locally from uploaded image files to prevent malicious "Quishing" 
            attacks and phishing redirects.
          </p>
          <ul className="feature-list">
            <li><CheckCircle2 size={16} /> 100% offline local QR decoding</li>
            <li><CheckCircle2 size={16} /> Instant payload URL inspection</li>
            <li><CheckCircle2 size={16} /> Zero external API privacy guarantee</li>
          </ul>
        </div>
      </div>

      <div className="security-banner">
        <div className="security-banner-icon">
          <Lock size={24} />
        </div>
        <div className="security-banner-text">
          <h4>Transparent & Explainable Security</h4>
          <p>
            CyberShield AI uses a weighted heuristic scoring algorithm. Every risk score is accompanied by 
            a breakdown of detected threat indicators and clear safety recommendations.
          </p>
        </div>
      </div>
    </div>
  );
}
