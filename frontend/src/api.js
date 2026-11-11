// Thin client for the FastAPI backend. Every value shown in the dashboard comes from these calls.
export async function api(path, options = {}) {
  const res = await fetch(path, options);
  const text = await res.text();
  let body;
  try { body = text ? JSON.parse(text) : null; } catch { body = text; }
  if (!res.ok) {
    const detail = body && body.detail ? (typeof body.detail === "string" ? body.detail : JSON.stringify(body.detail)) : res.statusText;
    throw new Error(`${res.status}: ${detail}`);
  }
  return body;
}

export const fmt = (v, d = 3) => (v === null || v === undefined || Number.isNaN(v) ? "—" : Number(v).toFixed(d));
export const pct = (v, d = 2) => (v === null || v === undefined ? "—" : `${(100 * v).toFixed(d)}%`);
export const ms = (s) => (s && s.mean !== undefined ? s : null);
// A single-seed result has no spread; say so instead of showing a misleading "± 0".
export const meanStd = (s, d = 3) => (!s ? "—" : s.n === 1 ? `${fmt(s.mean, d)} (1 seed)` : `${fmt(s.mean, d)} ± ${fmt(s.std, d)}`);
export const int = (v) => (v === null || v === undefined ? "—" : Number(v).toLocaleString());
