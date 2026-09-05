import React from 'react';
import { Globe, MessageSquare, QrCode, ShieldAlert, ArrowRight, RotateCcw, ShieldCheck, Activity } from 'lucide-react';

export default function Dashboard({ stats, onResetStats, onNavigate }) {
  return (
    <div className="dashboard-container">
      <div className="dashboard-header">
        <div>
          <h2 className="dashboard-title">Security Dashboard</h2>
          <p className="dashboard-subtitle">Local Session Threat Monitoring & Analytics</p>
        </div>
        <button className="btn-secondary" onClick={onResetStats} title="Reset Session Statistics">
          <RotateCcw size={16} />
          <span>Reset Stats</span>
        </button>
      </div>

      <div className="stats-grid">
        <div className="stat-card cyan" onClick={() => onNavigate('url')} style={{ cursor: 'pointer' }}>
          <div className="stat-icon-wrapper">
            <Globe size={24} />
          </div>
          <div className="stat-info">
            <span className="stat-value">{stats.urlsAnalyzed}</span>
            <span className="stat-label">URLs Analyzed</span>
          </div>
          <ArrowRight className="stat-arrow" size={18} />
        </div>

        <div className="stat-card purple" onClick={() => onNavigate('message')} style={{ cursor: 'pointer' }}>
          <div className="stat-icon-wrapper">
            <MessageSquare size={24} />
          </div>
          <div className="stat-info">
            <span className="stat-value">{stats.messagesAnalyzed}</span>
            <span className="stat-label">Messages Analyzed</span>
          </div>
          <ArrowRight className="stat-arrow" size={18} />
        </div>

        <div className="stat-card emerald" onClick={() => onNavigate('qr')} style={{ cursor: 'pointer' }}>
          <div className="stat-icon-wrapper">
            <QrCode size={24} />
          </div>
          <div className="stat-info">
            <span className="stat-value">{stats.qrScans}</span>
            <span className="stat-label">QR Scans</span>
          </div>
          <ArrowRight className="stat-arrow" size={18} />
        </div>

        <div className="stat-card red">
          <div className="stat-icon-wrapper">
            <ShieldAlert size={24} />
          </div>
          <div className="stat-info">
            <span className="stat-value">{stats.threatsDetected}</span>
            <span className="stat-label">Threats Flagged</span>
          </div>
          <Activity className="stat-arrow pulse" size={18} />
        </div>
      </div>

      <div className="quick-actions-section">
        <h3>Launch Quick Analysis</h3>
        <div className="quick-buttons-grid">
          <button className="quick-action-btn" onClick={() => onNavigate('url')}>
            <Globe className="quick-icon cyan" size={20} />
            <div className="quick-text">
              <span className="quick-title">Analyze Web Link</span>
              <span className="quick-desc">Scan suspicious URLs for phishing heuristics</span>
            </div>
            <ArrowRight size={18} />
          </button>

          <button className="quick-action-btn" onClick={() => onNavigate('message')}>
            <MessageSquare className="quick-icon purple" size={20} />
            <div className="quick-text">
              <span className="quick-title">Analyze Phishing Message</span>
              <span className="quick-desc">Multilingual text analysis (EN, HI, MR)</span>
            </div>
            <ArrowRight size={18} />
          </button>

          <button className="quick-action-btn" onClick={() => onNavigate('qr')}>
            <QrCode className="quick-icon emerald" size={20} />
            <div className="quick-text">
              <span className="quick-title">Scan QR Code</span>
              <span className="quick-desc">Extract and inspect QR payloads locally</span>
            </div>
            <ArrowRight size={18} />
          </button>
        </div>
      </div>
    </div>
  );
}
