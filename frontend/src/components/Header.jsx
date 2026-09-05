import React from 'react';
import { Shield, ShieldAlert, Globe, MessageSquare, QrCode, LayoutDashboard, HelpCircle } from 'lucide-react';

export default function Header({ activeTab, setActiveTab, backendStatus }) {
  const navItems = [
    { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
    { id: 'url', label: 'URL Analyzer', icon: Globe },
    { id: 'message', label: 'Message Analyzer', icon: MessageSquare },
    { id: 'qr', label: 'QR Scanner', icon: QrCode },
    { id: 'how-it-works', label: 'How It Works', icon: HelpCircle },
  ];

  return (
    <header className="header-nav">
      <div className="nav-container">
        <div className="logo-brand" onClick={() => setActiveTab('landing')} style={{ cursor: 'pointer' }}>
          <div className="logo-icon-wrapper">
            <Shield className="logo-icon" />
          </div>
          <div className="logo-text-group">
            <span className="logo-title">CyberShield <span className="logo-accent">AI</span></span>
            <span className="logo-tagline">Threat Intelligence Platform</span>
          </div>
        </div>

        <nav className="nav-links">
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = activeTab === item.id;
            return (
              <button
                key={item.id}
                onClick={() => setActiveTab(item.id)}
                className={`nav-btn ${isActive ? 'active' : ''}`}
              >
                <Icon size={18} />
                <span>{item.label}</span>
              </button>
            );
          })}
        </nav>

        <div className="backend-badge">
          <span className={`status-dot ${backendStatus ? 'online' : 'offline'}`}></span>
          <span className="status-text">
            {backendStatus ? 'FastAPI Engine Active' : 'Local JS Engine Active'}
          </span>
        </div>
      </div>
    </header>
  );
}
