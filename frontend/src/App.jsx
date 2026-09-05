import React, { useState, useEffect } from 'react';
import Header from './components/Header.jsx';
import Landing from './components/Landing.jsx';
import Dashboard from './components/Dashboard.jsx';
import UrlAnalyzer from './components/UrlAnalyzer.jsx';
import MessageAnalyzer from './components/MessageAnalyzer.jsx';
import QrAnalyzer from './components/QrAnalyzer.jsx';
import HowItWorks from './components/HowItWorks.jsx';
import Disclaimer from './components/Disclaimer.jsx';
import { checkBackendHealth } from './api.js';

export default function App() {
  const [activeTab, setActiveTab] = useState('landing');
  const [backendStatus, setBackendStatus] = useState(false);

  // Initialize stats from localStorage
  const [stats, setStats] = useState(() => {
    try {
      const saved = localStorage.getItem('cybershield_stats');
      if (saved) return JSON.parse(saved);
    } catch (e) {}
    return { urlsAnalyzed: 0, messagesAnalyzed: 0, qrScans: 0, threatsDetected: 0 };
  });

  // Save stats to localStorage
  useEffect(() => {
    try {
      localStorage.setItem('cybershield_stats', JSON.stringify(stats));
    } catch (e) {}
  }, [stats]);

  // Check backend connectivity on mount
  useEffect(() => {
    const verifyHealth = async () => {
      const health = await checkBackendHealth();
      setBackendStatus(health.online);
    };
    verifyHealth();
    const interval = setInterval(verifyHealth, 10000);
    return () => clearInterval(interval);
  }, []);

  const handleAnalysisDone = (type, isThreat) => {
    setStats((prev) => {
      const updated = { ...prev };
      if (type === 'url') updated.urlsAnalyzed += 1;
      if (type === 'message') updated.messagesAnalyzed += 1;
      if (type === 'qr') updated.qrScans += 1;
      if (isThreat) updated.threatsDetected += 1;
      return updated;
    });
  };

  const handleResetStats = () => {
    const resetState = { urlsAnalyzed: 0, messagesAnalyzed: 0, qrScans: 0, threatsDetected: 0 };
    setStats(resetState);
    localStorage.removeItem('cybershield_stats');
  };

  return (
    <div className="app-shell">
      <Header
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        backendStatus={backendStatus}
      />

      <main className="main-content">
        {activeTab === 'landing' && (
          <Landing onStart={() => setActiveTab('dashboard')} />
        )}

        {activeTab === 'dashboard' && (
          <Dashboard
            stats={stats}
            onResetStats={handleResetStats}
            onNavigate={(tab) => setActiveTab(tab)}
          />
        )}

        {activeTab === 'url' && (
          <UrlAnalyzer onAnalysisDone={handleAnalysisDone} />
        )}

        {activeTab === 'message' && (
          <MessageAnalyzer onAnalysisDone={handleAnalysisDone} />
        )}

        {activeTab === 'qr' && (
          <QrAnalyzer onAnalysisDone={handleAnalysisDone} />
        )}

        {activeTab === 'how-it-works' && (
          <HowItWorks />
        )}
      </main>

      <Disclaimer />
    </div>
  );
}
