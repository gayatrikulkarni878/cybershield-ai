import React from 'react';
import { ArrowDown, Layers, ShieldCheck, Cpu, Sliders, FileText, AlertTriangle } from 'lucide-react';

export default function HowItWorks() {
  const steps = [
    {
      num: '01',
      title: 'INPUT COLLECTION',
      desc: 'User inputs a web URL, pastes a message (SMS/email/WhatsApp), or uploads a QR code image.',
      icon: Layers,
      color: 'cyan'
    },
    {
      num: '02',
      title: 'PREPROCESSING & PARSING',
      desc: 'Normalizes input, extracts embedded links, parses domain structures, and detects message language (English, Hindi, Marathi).',
      icon: Cpu,
      color: 'purple'
    },
    {
      num: '03',
      title: 'HEURISTIC THREAT DETECTION',
      desc: 'Runs multi-layered rule sets checking HTTPS, raw IP hosts, shorteners, urgency traps, credential harvesting phrases, and brand impersonation.',
      icon: Sliders,
      color: 'yellow'
    },
    {
      num: '04',
      title: 'WEIGHTED RISK SCORING',
      desc: 'Calculates a cumulative risk score (0 to 100) using weighted threat severity contributions capped at 100.',
      icon: AlertTriangle,
      color: 'red'
    },
    {
      num: '05',
      title: 'EXPLANATION & RECOMMENDATION',
      desc: 'Generates transparent human-readable explanations of every flagged indicator alongside actionable safety advice.',
      icon: ShieldCheck,
      color: 'green'
    }
  ];

  return (
    <div className="how-it-works-container">
      <div className="section-title-box">
        <h2>How CyberShield AI Works</h2>
        <p>A transparent, multi-layered cybersecurity analysis pipeline built for local threat awareness.</p>
      </div>

      <div className="pipeline-flow">
        {steps.map((step, idx) => {
          const Icon = step.icon;
          return (
            <React.Fragment key={idx}>
              <div className={`pipeline-card ${step.color}`}>
                <div className="step-badge">{step.num}</div>
                <div className="step-icon-wrapper">
                  <Icon size={24} />
                </div>
                <div className="step-content">
                  <h3>{step.title}</h3>
                  <p>{step.desc}</p>
                </div>
              </div>

              {idx < steps.length - 1 && (
                <div className="flow-arrow">
                  <ArrowDown size={22} />
                </div>
              )}
            </React.Fragment>
          );
        })}
      </div>

      <div className="scoring-matrix-card">
        <h3>Weighted Scoring Engine Rules</h3>
        <p className="matrix-desc">
          CyberShield AI combines multiple indicators rather than relying on a single rule to prevent false positives.
        </p>

        <div className="matrix-grid">
          <div className="matrix-column">
            <h4>URL Heuristic Weights</h4>
            <ul>
              <li><span>Raw IP Address Host</span> <strong>+25 pts</strong></li>
              <li><span>URL Shortener Masking</span> <strong>+20 pts</strong></li>
              <li><span>Missing HTTPS (Unencrypted)</span> <strong>+15 pts</strong></li>
              <li><span>Phishing / Security Keywords</span> <strong>+15 pts</strong></li>
              <li><span>Suspicious TLD (.xyz, .top, etc.)</span> <strong>+15 pts</strong></li>
              <li><span>Excessive Subdomains (&gt;3 dots)</span> <strong>+10 pts</strong></li>
              <li><span>Obfuscated Chars (@, hyphens)</span> <strong>+10 pts</strong></li>
              <li><span>Long URL (&gt;75 chars)</span> <strong>+10 pts</strong></li>
            </ul>
          </div>

          <div className="matrix-column">
            <h4>Message Heuristic Weights</h4>
            <ul>
              <li><span>Credential Request (OTP/PIN/Card)</span> <strong>+25 pts</strong></li>
              <li><span>Account Suspension / Fear Threat</span> <strong>+20 pts</strong></li>
              <li><span>Action / Click Instruction</span> <strong>+20 pts</strong></li>
              <li><span>Reward / Prize / Lottery Claim</span> <strong>+18 pts</strong></li>
              <li><span>Urgency / Time Pressure</span> <strong>+15 pts</strong></li>
              <li><span>Brand / Bank Impersonation</span> <strong>+15 pts</strong></li>
              <li><span>Embedded Hyperlink Present</span> <strong>+12 pts</strong></li>
            </ul>
          </div>
        </div>

        <div className="matrix-legend">
          <div className="legend-chip safe">0–19 SAFE</div>
          <div className="legend-chip low">20–39 LOW</div>
          <div className="legend-chip medium">40–64 MEDIUM</div>
          <div className="legend-chip high">65–84 HIGH</div>
          <div className="legend-chip critical">85–100 CRITICAL</div>
        </div>
      </div>
    </div>
  );
}
