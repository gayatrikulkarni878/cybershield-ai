import React from 'react';
import { ShieldCheck, ShieldAlert, AlertTriangle, AlertCircle, Info, CheckCircle2, ChevronRight, Zap } from 'lucide-react';

export default function ResultsCard({ result }) {
  if (!result) return null;

  const score = result.risk_score || 0;
  const level = (result.risk_level || 'SAFE').toUpperCase();

  // Color mapping based on risk level
  const getLevelTheme = (lvl) => {
    switch (lvl) {
      case 'CRITICAL':
        return { color: '#dc2626', badgeBg: 'rgba(220, 38, 38, 0.2)', icon: ShieldAlert, label: 'CRITICAL THREAT' };
      case 'HIGH':
        return { color: '#ef4444', badgeBg: 'rgba(239, 68, 68, 0.2)', icon: ShieldAlert, label: 'HIGH RISK' };
      case 'MEDIUM':
        return { color: '#f59e0b', badgeBg: 'rgba(245, 158, 11, 0.2)', icon: AlertTriangle, label: 'MEDIUM RISK' };
      case 'LOW':
        return { color: '#84cc16', badgeBg: 'rgba(132, 204, 22, 0.2)', icon: AlertCircle, label: 'LOW RISK' };
      case 'SAFE':
      default:
        return { color: '#10b981', badgeBg: 'rgba(16, 185, 129, 0.2)', icon: ShieldCheck, label: 'SAFE' };
    }
  };

  const theme = getLevelTheme(level);
  const LevelIcon = theme.icon;

  // Circular gauge SVG parameters
  const radius = 54;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (score / 100) * circumference;

  return (
    <div className="results-container animate-fade-in">
      <div className="results-header-card" style={{ borderColor: theme.color }}>
        <div className="results-gauge-wrapper">
          <svg className="gauge-svg" width="140" height="140" viewBox="0 0 140 140">
            <circle
              className="gauge-bg"
              cx="70"
              cy="70"
              r={radius}
              strokeWidth="10"
            />
            <circle
              className="gauge-progress"
              cx="70"
              cy="70"
              r={radius}
              strokeWidth="10"
              stroke={theme.color}
              strokeDasharray={circumference}
              strokeDashoffset={strokeDashoffset}
              strokeLinecap="round"
              transform="rotate(-90 70 70)"
            />
          </svg>
          <div className="gauge-text">
            <span className="gauge-score" style={{ color: theme.color }}>{score}</span>
            <span className="gauge-max">/ 100</span>
          </div>
        </div>

        <div className="results-summary">
          <div className="level-badge" style={{ backgroundColor: theme.badgeBg, color: theme.color, borderColor: theme.color }}>
            <LevelIcon size={18} />
            <span>{theme.label}</span>
          </div>

          <h3 className="threat-type-title">
            {result.threat_type || 'Threat Analysis Completed'}
          </h3>

          {result.detected_language && (
            <div className="lang-tag">
              <span>Detected Language: <strong>{result.detected_language}</strong></span>
            </div>
          )}

          <p className="analysis-source-tag">
            <Zap size={13} /> {result.analysis_type || result.source || 'Rule-Based Cybersecurity Engine'}
          </p>
        </div>
      </div>

      <div className="results-details-grid">
        {/* Detected Indicators */}
        <div className="detail-card">
          <div className="card-header">
            <AlertTriangle className="card-header-icon yellow" size={20} />
            <h4>Detected Indicators ({result.indicators ? result.indicators.length : 0})</h4>
          </div>
          <div className="card-body">
            {result.indicators && result.indicators.length > 0 ? (
              <div className="indicators-list">
                {result.indicators.map((ind, idx) => (
                  <div key={idx} className="indicator-item">
                    <div className="indicator-top">
                      <span className="indicator-title">{ind.title}</span>
                      <span className="indicator-points">+{ind.points} pts</span>
                    </div>
                    <div className="indicator-meta">
                      <span className="indicator-category">{ind.category}</span>
                    </div>
                    <p className="indicator-desc">{ind.description}</p>
                  </div>
                ))}
              </div>
            ) : (
              <div className="no-threats-msg">
                <CheckCircle2 size={24} className="green" />
                <p>No threat indicators flagged by heuristic checks.</p>
              </div>
            )}
          </div>
        </div>

        {/* Detailed Explanation */}
        <div className="detail-card">
          <div className="card-header">
            <Info className="card-header-icon cyan" size={20} />
            <h4>Threat Explanation</h4>
          </div>
          <div className="card-body">
            <p className="explanation-text">{result.explanation}</p>
          </div>
        </div>

        {/* Safety Recommendation */}
        <div className="detail-card full-width">
          <div className="card-header">
            <ShieldCheck className="card-header-icon green" size={20} />
            <h4>Safety Recommendation</h4>
          </div>
          <div className="card-body">
            <div className="recommendation-box" style={{ borderLeftColor: theme.color }}>
              <p>{result.recommendation}</p>
            </div>
          </div>
        </div>

        {/* Embedded links if present */}
        {result.links_found && result.links_found.length > 0 && (
          <div className="detail-card full-width">
            <div className="card-header">
              <Info className="card-header-icon purple" size={20} />
              <h4>Extracted Hyperlinks ({result.links_found.length})</h4>
            </div>
            <div className="card-body">
              <div className="extracted-links-list">
                {result.links_found.map((lnk, i) => (
                  <div key={i} className="extracted-link-item">
                    <span className="extracted-url">{lnk.url}</span>
                    <span className={`extracted-badge ${lnk.risk_level?.toLowerCase()}`}>
                      {lnk.risk_level} ({lnk.risk_score}/100)
                    </span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}
      </div>

      <div className="disclaimer-note">
        <p>
          <strong>Notice:</strong> CyberShield AI relies on rule-based heuristic threat detection for security awareness. 
          No automated security tool can guarantee 100% safety. Always verify suspicious communications through official channels.
        </p>
      </div>
    </div>
  );
}
