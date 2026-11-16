// Display helpers. Every time is shown with its zone (UTC); every measurement is a real API value.
export const int = (v) => (v === null || v === undefined ? "—" : Number(v).toLocaleString("en-GB"));

export function bytes(v) {
  if (v === null || v === undefined) return "—";
  const u = ["B", "kB", "MB", "GB", "TB"];
  let i = 0;
  let n = Number(v);
  while (n >= 1000 && i < u.length - 1) { n /= 1000; i += 1; }
  return `${n >= 100 || i === 0 ? n.toFixed(0) : n.toFixed(1)} ${u[i]}`;
}

export function utcTime(iso) {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "—";
  return `${d.toISOString().slice(11, 19)} UTC`;
}

export function utcDateTime(iso) {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "—";
  return `${d.toISOString().slice(0, 10)} ${d.toISOString().slice(11, 19)} UTC`;
}

export const pct = (v, d = 1) => (v === null || v === undefined ? "—" : `${(100 * v).toFixed(d)}%`);
export const num = (v, d = 2) => (v === null || v === undefined || Number.isNaN(v) ? "—" : Number(v).toFixed(d));

export const RULES = {
  port_scan: "Port scan", host_sweep: "Host sweep", connection_rate: "Connection flood", traffic_volume: "Data volume",
  brute_force: "Brute force", unexpected_communication: "Unexpected communication",
};
export const ruleLabel = (r) => RULES[r] || (r && r.startsWith("ml_") ? `ML: ${r.slice(3)}` : (r || "").replace(/_/g, " "));

export const SCENARIOS = {
  normal: "Normal traffic only", port_scan: "Port scan", dos: "Denial of service", lateral_movement: "Lateral movement",
  brute_force: "Brute-force login", suspicious_outbound: "Suspicious outbound",
};

export const STATUS_LABELS = {
  open: "Open", acknowledged: "Acknowledged", investigating: "Investigating", resolved: "Resolved", false_positive: "False positive",
};
// Mirrors src/simulation/incidents.py TRANSITIONS; the server validates every change.
export const TRANSITIONS = {
  open: ["acknowledged", "investigating", "resolved", "false_positive"], acknowledged: ["investigating", "resolved", "false_positive"],
  investigating: ["resolved", "false_positive"], resolved: ["open"], false_positive: ["open"],
};

export const ROLE_LABELS = {
  workstation: "Workstation", laptop: "Laptop", app_server: "Application server", db_server: "Database server",
  dns_server: "DNS server", router: "Router", external: "External endpoint",
};
