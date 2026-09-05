import React from 'react';
import { ShieldAlert, Info } from 'lucide-react';

export default function Disclaimer() {
  return (
    <footer className="global-disclaimer-footer">
      <div className="disclaimer-content">
        <ShieldAlert size={20} className="disclaimer-icon" />
        <p>
          <strong>Important Security Disclaimer:</strong> CyberShield AI provides rule-based heuristic analysis for cybersecurity 
          awareness and educational purposes. It does not guarantee that a URL, message, or QR code is 100% safe. Always verify 
          suspicious content through official trusted channels.
        </p>
      </div>
    </footer>
  );
}
