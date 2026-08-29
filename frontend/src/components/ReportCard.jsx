import React from "react";
import RiskMeter from "./RiskMeter.jsx";

export default function ReportCard({ report }) {
  if (!report) return null;

  return (
    <div className="report-card" key={report.input_value}>
      <div className="report-card__scanline" />

      <div className="report-card__header">
        <span className="report-card__eyebrow">CASE FILE · {report.input_type.toUpperCase()}</span>
        <h2>{report.threat_type}</h2>
      </div>

      <p className="report-card__input" title={report.input_value}>
        {report.input_value}
      </p>

      <RiskMeter level={report.risk_level} score={report.risk_score} />

      <div className="report-card__section">
        <h3>Detected indicators</h3>
        <ul>
          {report.indicators.map((ind, i) => (
            <li key={i}>{ind}</li>
          ))}
        </ul>
      </div>

      <div className="report-card__section">
        <h3>Why this matters</h3>
        <p>{report.explanation}</p>
      </div>

      <div className="report-card__action">
        <h3>Recommended action</h3>
        <p>{report.recommended_action}</p>
      </div>
    </div>
  );
}
