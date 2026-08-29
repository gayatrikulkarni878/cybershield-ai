const BASE = "/api";

export async function analyzeUrl(url) {
  const res = await fetch(`${BASE}/analyze/url`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url }),
  });
  if (!res.ok) throw new Error("Analysis failed");
  return res.json();
}

export async function analyzeMessage(text) {
  const res = await fetch(`${BASE}/analyze/message`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ text }),
  });
  if (!res.ok) throw new Error("Analysis failed");
  return res.json();
}

export async function analyzeQr(file) {
  const form = new FormData();
  form.append("file", file);
  const res = await fetch(`${BASE}/analyze/qr`, { method: "POST", body: form });
  if (!res.ok) throw new Error((await res.json()).detail || "Analysis failed");
  return res.json();
}
