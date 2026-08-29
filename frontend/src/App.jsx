import React, { useState } from "react";
import ReportCard from "./components/ReportCard.jsx";
import { analyzeUrl, analyzeMessage, analyzeQr } from "./api.js";

const TABS = [
  { id: "url", label: "URL" },
  { id: "message", label: "Message" },
  { id: "qr", label: "QR Code" },
];

export default function App() {
  const [tab, setTab] = useState("url");
  const [urlInput, setUrlInput] = useState("");
  const [messageInput, setMessageInput] = useState("");
  const [qrFile, setQrFile] = useState(null);
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  async function handleSubmit(e) {
    e.preventDefault();
    setError(null);
    setLoading(true);
    setReport(null);
    try {
      let result;
      if (tab === "url") result = await analyzeUrl(urlInput.trim());
      else if (tab === "message") result = await analyzeMessage(messageInput.trim());
      else if (tab === "qr") {
        if (!qrFile) throw new Error("Upload a QR code image first");
        result = await analyzeQr(qrFile);
      }
      setReport(result);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  const canSubmit =
    (tab === "url" && urlInput.trim()) ||
    (tab === "message" && messageInput.trim()) ||
    (tab === "qr" && qrFile);

  return (
    <div className="app">
      <header className="app__header">
        <span className="app__mark">◈</span>
        <div>
          <h1>CyberShield AI</h1>
          <p>Threat detection with a plain-language explanation for every verdict.</p>
        </div>
      </header>

      <main className="console">
        <form className="console__panel" onSubmit={handleSubmit}>
          <div className="tabs">
            {TABS.map((t) => (
              <button
                type="button"
                key={t.id}
                className={"tabs__item" + (tab === t.id ? " is-active" : "")}
                onClick={() => {
                  setTab(t.id);
                  setError(null);
                }}
              >
                {t.label}
              </button>
            ))}
          </div>

          {tab === "url" && (
            <input
              className="field"
              type="text"
              placeholder="Paste a URL, e.g. http://secure-paypal-login.xyz"
              value={urlInput}
              onChange={(e) => setUrlInput(e.target.value)}
            />
          )}

          {tab === "message" && (
            <textarea
              className="field field--textarea"
              placeholder="Paste a suspicious SMS, email, or chat message"
              rows={5}
              value={messageInput}
              onChange={(e) => setMessageInput(e.target.value)}
            />
          )}

          {tab === "qr" && (
            <label className="dropzone">
              <input
                type="file"
                accept="image/*"
                onChange={(e) => setQrFile(e.target.files?.[0] ?? null)}
              />
              {qrFile ? qrFile.name : "Click to upload a QR code image"}
            </label>
          )}

          <button className="submit-btn" type="submit" disabled={!canSubmit || loading}>
            {loading ? "Scanning…" : "Analyze"}
          </button>

          {error && <p className="error-text">{error}</p>}
        </form>

        <div className="console__output">
          {!report && !loading && (
            <div className="empty-state">
              <p>Submit a URL, message, or QR code to generate a threat report.</p>
            </div>
          )}
          {loading && <div className="empty-state">Analyzing…</div>}
          <ReportCard report={report} />
        </div>
      </main>
    </div>
  );
}
