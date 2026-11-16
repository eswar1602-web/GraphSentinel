// One WebSocket to /api/sim/ws for the whole console: simulation status, the topology (kept current from
// graph_update deltas), the latest alerts and incidents, and the flow count of every tick. Reconnects with backoff
// and resynchronises from the REST API after each (re)connect. All buffers are bounded.
import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from "react";
import { api } from "../api";

const LiveContext = createContext(null);
const TICKS_KEPT = 240;
const FEED_KEPT = 40;

function wsUrl() {
  const proto = window.location.protocol === "https:" ? "wss" : "ws";
  // Individual flow records are not streamed to the console; per-tick counts come from status messages.
  return `${proto}://${window.location.host}/api/sim/ws?topics=status,graph_update,detection,incident,scenario`;
}

function upsertFeed(list, item) {
  const rest = list.filter((x) => x.id !== item.id);
  return [item, ...rest].slice(0, FEED_KEPT);
}

export function LiveProvider({ children }) {
  const [connection, setConnection] = useState("connecting");   // connecting | live | offline
  const [status, setStatus] = useState(null);
  const [statusError, setStatusError] = useState(null);
  const [graph, setGraph] = useState({ nodes: new Map(), edges: new Map(), version: 0, meta: null, error: null });
  const [ticks, setTicks] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [incidents, setIncidents] = useState([]);
  const [versions, setVersions] = useState({ alerts: 0, incidents: 0, scenarios: 0 });
  const pending = useRef({ nodes: new Map(), edges: new Map(), reset: null });
  const flushTimer = useRef(null);
  const runRef = useRef(null);

  const loadTopology = useCallback(async () => {
    try {
      const t = await api("/api/sim/topology");
      setGraph({ nodes: new Map(t.nodes.map((n) => [n.id, n])), edges: new Map(t.edges.map((e) => [e.id, e])),
                 version: Date.now(), meta: { counts: t.counts, run_id: t.run_id, address_note: t.address_note }, error: null });
    } catch (error) {
      setGraph((g) => ({ ...g, error }));
    }
  }, []);

  const loadStatus = useCallback(async () => {
    try {
      const s = await api("/api/sim/status");
      setStatus(s);
      setStatusError(null);
      return s;
    } catch (error) {
      setStatusError(error);
      return null;
    }
  }, []);

  // Graph deltas arrive every tick; apply them at most four times a second.
  const flush = useCallback(() => {
    flushTimer.current = null;
    const p = pending.current;
    pending.current = { nodes: new Map(), edges: new Map(), reset: null };
    setGraph((g) => {
      const base = p.reset ? { nodes: new Map(), edges: new Map() } : g;
      const nodes = new Map(base.nodes);
      const edges = new Map(base.edges);
      if (p.reset) p.reset.nodes.forEach((n) => nodes.set(n.id, n));
      if (p.reset) p.reset.edges.forEach((e) => edges.set(e.id, e));
      p.nodes.forEach((n, id) => nodes.set(id, n));
      p.edges.forEach((e, id) => edges.set(id, e));
      return { nodes, edges, version: g.version + 1, meta: p.reset ? { counts: p.reset.counts, run_id: p.reset.run_id } : g.meta, error: null };
    });
  }, []);

  const onMessage = useCallback((m) => {
    const d = m.data;
    if (m.type === "hello") { setStatus(d.status); return; }
    if (m.type === "status") {
      if (runRef.current && d.run_id !== runRef.current) { setTicks([]); setAlerts([]); setIncidents([]); }
      runRef.current = d.run_id;
      setStatus(d);
      setTicks((t) => (t.length && t[t.length - 1].run_id === d.run_id && t[t.length - 1].sim_t === d.sim_elapsed_s ? t
        : [...t, { sim_t: d.sim_elapsed_s, flows: d.flows_generated, run_id: d.run_id }].slice(-TICKS_KEPT)));
      return;
    }
    if (m.type === "graph_update") {
      if (d.reset) pending.current = { nodes: new Map(), edges: new Map(), reset: d };
      else {
        d.nodes.forEach((n) => pending.current.nodes.set(n.id, n));
        d.edges.forEach((e) => pending.current.edges.set(e.id, e));
      }
      if (!flushTimer.current) flushTimer.current = setTimeout(flush, 250);
      return;
    }
    if (m.type === "detection") {
      setAlerts((a) => upsertFeed(a, d));
      setVersions((v) => ({ ...v, alerts: v.alerts + 1 }));
      return;
    }
    if (m.type === "incident") {
      setIncidents((a) => upsertFeed(a, d));
      setVersions((v) => ({ ...v, incidents: v.incidents + 1 }));
      return;
    }
    if (m.type === "scenario") setVersions((v) => ({ ...v, scenarios: v.scenarios + 1 }));
  }, [flush]);

  useEffect(() => {
    let ws = null;
    let retry = 0;
    let timer = null;
    let closed = false;
    const connect = () => {
      setConnection((c) => (c === "live" ? c : "connecting"));
      try {
        ws = new WebSocket(wsUrl());
      } catch {
        schedule();
        return;
      }
      ws.onopen = () => { retry = 0; setConnection("live"); loadStatus(); loadTopology(); };
      ws.onmessage = (e) => { try { onMessage(JSON.parse(e.data)); } catch { /* ignore malformed frames */ } };
      ws.onclose = () => { if (!closed) { setConnection("offline"); schedule(); } };
      ws.onerror = () => { try { ws.close(); } catch { /* already closed */ } };
    };
    const schedule = () => {
      clearTimeout(timer);
      timer = setTimeout(connect, Math.min(10000, 1000 * 2 ** retry));
      retry += 1;
    };
    loadStatus();
    loadTopology();
    connect();
    return () => {
      closed = true;
      clearTimeout(timer);
      clearTimeout(flushTimer.current);
      if (!ws) return;
      ws.onmessage = null; ws.onclose = null; ws.onerror = null;
      // Closing a socket that is still connecting logs a browser warning; close it as soon as it opens instead.
      if (ws.readyState === WebSocket.CONNECTING) ws.onopen = () => ws.close(); else ws.close();
    };
  }, [loadStatus, loadTopology, onMessage]);

  const value = useMemo(() => ({
    connection, status, statusError, graph, ticks, alerts, incidents, versions,
    refreshStatus: loadStatus, refreshTopology: loadTopology,
  }), [connection, status, statusError, graph, ticks, alerts, incidents, versions, loadStatus, loadTopology]);
  return <LiveContext.Provider value={value}>{children}</LiveContext.Provider>;
}

export function useLive() {
  const v = useContext(LiveContext);
  if (!v) throw new Error("useLive outside LiveProvider");
  return v;
}

// Flows per simulated second over the last `n` status samples of the current run (counts from the stream).
export function flowRate(ticks, status, n = 12) {
  const t = ticks.filter((x) => !status || x.run_id === status.run_id).slice(-n);
  if (t.length < 2) return null;
  const span = t[t.length - 1].sim_t - t[0].sim_t;
  return span > 0 ? (t[t.length - 1].flows - t[0].flows) / span : null;
}

// Per-interval rates for a chart: [{ sim_t, rate }] between consecutive samples.
export function rateSeries(ticks, status) {
  const t = ticks.filter((x) => !status || x.run_id === status.run_id);
  const out = [];
  for (let i = 1; i < t.length; i += 1) {
    const dt = t[i].sim_t - t[i - 1].sim_t;
    if (dt > 0) out.push({ sim_t: t[i].sim_t, rate: (t[i].flows - t[i - 1].flows) / dt });
  }
  return out;
}
