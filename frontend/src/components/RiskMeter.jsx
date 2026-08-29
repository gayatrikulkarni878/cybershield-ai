import React from "react";

const LEVELS = ["LOW", "MEDIUM", "HIGH", "CRITICAL"];

export default function RiskMeter({ level, score }) {
  const activeIndex = LEVELS.indexOf(level);

  return (
    <div className="risk-meter">
      <div className="risk-meter__segments">
        {LEVELS.map((l, i) => (
          <div
            key={l}
            className={
              "risk-meter__segment" +
              (i <= activeIndex ? " is-filled" : "") +
              (i === activeIndex ? ` is-active risk-${l.toLowerCase()}` : "")
            }
          />
        ))}
      </div>
      <div className="risk-meter__labels">
        {LEVELS.map((l) => (
          <span key={l} className={l === level ? "is-active" : ""}>
            {l}
          </span>
        ))}
      </div>
      <div className={`risk-meter__score risk-${level.toLowerCase()}`}>
        {score}
        <span>/100</span>
      </div>
    </div>
  );
}
