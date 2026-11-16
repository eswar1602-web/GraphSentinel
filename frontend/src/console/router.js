// Hash routing with state in the URL: #/alerts?severity=high&id=AL-... (filters and selection survive reloads).
import { useEffect, useState } from "react";

export const ROUTES = ["network", "alerts", "incidents", "monitoring", "scan", "audit"];

// Hash links of the earlier dashboard (#Security%20audit, ...) open the matching screen of the console.
const LEGACY = { Overview: "network", Detection: "scan", "Detection history": "scan", "Network graph": "network",
  "Training data": "monitoring", "Security audit": "audit" };

export function parseHash(hash = window.location.hash) {
  let name = hash.replace(/^#/, "");
  try { name = decodeURIComponent(name); } catch { /* a malformed escape is just an unknown route */ }
  const old = LEGACY[name];
  if (old) return { path: old, params: {} };
  const raw = hash.replace(/^#\/?/, "");
  const [path, query = ""] = raw.split("?");
  const params = Object.fromEntries(new URLSearchParams(query));
  return { path: ROUTES.includes(path) ? path : "network", params };
}

export function href(path, params = {}) {
  const q = new URLSearchParams(Object.entries(params).filter(([, v]) => v !== undefined && v !== null && v !== ""));
  const s = q.toString();
  return `#/${path}${s ? `?${s}` : ""}`;
}

export function go(path, params = {}) {
  window.location.hash = href(path, params);
}

// Merge into the current route's params (null removes a key).
export function setParams(update) {
  const { path, params } = parseHash();
  go(path, { ...params, ...update });
}

export function useRoute() {
  const [route, setRoute] = useState(parseHash);
  useEffect(() => {
    const on = () => setRoute(parseHash());
    window.addEventListener("hashchange", on);
    return () => window.removeEventListener("hashchange", on);
  }, []);
  return route;
}
