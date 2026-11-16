import { useCallback, useMemo, useState } from "react";
import { api } from "../../api";
import { href, setParams, useRoute } from "../router";
import { flowRate, useLive } from "../live";
import Topology from "../Topology";
import { Empty, Failure, Field, Figures, KV, Loading, PageHead, Section, Severity, StatusWord, useData } from "../ui";
import { bytes, int, ROLE_LABELS, ruleLabel, SCENARIOS, utcTime } from "../format";

const SPEEDS = [1, 5, 20, 50];
const DURATIONS = [["60", "1 simulated minute"], ["120", "2 simulated minutes"], ["300", "5 simulated minutes"], ["", "Until stopped"]];
const INTENSITIES = ["0.5", "1", "2", "5"];

const post = (path, body) => api(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body || {}) });

function useAction() {
  const [busy, setBusy] = useState(null);
  const [error, setError] = useState(null);
  const run = useCallback(async (name, fn) => {
    setBusy(name);
    setError(null);
    try { return await fn(); } catch (e) { setError(e); return null; } finally { setBusy(null); }
  }, []);
  return { busy, error, run, clear: () => setError(null) };
}

function elapsed(s) {
  if (s === undefined || s === null) return "—";
  const m = Math.floor(s / 60);
  return m >= 60 ? `${Math.floor(m / 60)} h ${m % 60} min` : `${m} min ${Math.floor(s % 60)} s`;
}

function SimControls({ status, act, refresh }) {
  const [speed, setSpeed] = useState(String(status?.clock?.speed ?? 5));
  const running = status?.status === "running";
  const done = status?.status === "completed";
  const start = () => act.run("start", async () => { await post("/api/sim/start", { speed: Number(speed), tick_interval_s: 1 }); refresh(); });
  const stop = () => act.run("stop", async () => { await post("/api/sim/stop"); refresh(); });
  const reset = () => {
    if (!window.confirm("Reset starts a new run: the graph and counters clear. Alerts and incidents of this run stay in the database. Continue?")) return;
    act.run("reset", async () => { await post("/api/sim/reset", { seed: status?.seed }); refresh(); });
  };
  const step = () => act.run("step", async () => { await post("/api/sim/step", { seconds: 30 }); refresh(); });
  return (
    <Section title="Simulation" note={status ? <>Run <span className="measure">{status.run_id}</span>, seed <span className="measure">{status.seed}</span></> : null}>
      <div className="sim-state">
        <StatusWord status={status?.status || "idle"} />
        {status?.active_scenarios?.length ? <span className="muted">{status.active_scenarios.length} attack scenario{status.active_scenarios.length > 1 ? "s" : ""} active</span>
          : <span className="muted">Normal traffic only</span>}
      </div>
      <div className="control-row">
        <Field label="Speed" htmlFor="sim-speed" hint={running ? "Stop to change the speed" : "Simulated seconds per real second"}>
          <select id="sim-speed" name="speed" className="control" value={speed} disabled={running} onChange={(e) => setSpeed(e.target.value)}>
            {SPEEDS.map((s) => <option key={s} value={s}>{s}×</option>)}
          </select>
        </Field>
      </div>
      <div className="btn-row">
        {running
          ? <button type="button" className="btn btn--quiet" onClick={stop} disabled={!!act.busy} aria-busy={act.busy === "stop"}>Stop</button>
          : <button type="button" className="btn btn--primary" onClick={start} disabled={!!act.busy || done} aria-busy={act.busy === "start"}>
              {status?.status === "stopped" ? "Resume simulation" : "Start simulation"}</button>}
        {!running && !done && <button type="button" className="btn btn--quiet" onClick={step} disabled={!!act.busy}>Advance 30 s</button>}
        <button type="button" className="btn btn--quiet" onClick={reset} disabled={!!act.busy}>Reset</button>
      </div>
      {done && <p className="note">This run reached its duration. Reset to start a new one.</p>}
    </Section>
  );
}

function ScenarioLauncher({ status, devices, act, refresh, scenarios, primary }) {
  const [name, setName] = useState("port_scan");
  const [attacker, setAttacker] = useState("");
  const [target, setTarget] = useState("");
  const [duration, setDuration] = useState("120");
  const [intensity, setIntensity] = useState("1");
  const cat = scenarios.data?.catalog || [];
  const meta = cat.find((c) => c.name === name);
  const normal = name === "normal";
  const submit = (e) => {
    e.preventDefault();
    const body = normal ? { name } : { name, intensity: Number(intensity), ...(attacker && { attacker }), ...(target && { targets: [target] }),
      ...(duration && { duration_s: Number(duration) }) };
    act.run("launch", async () => { await post("/api/sim/scenarios", body); scenarios.reload(); refresh(); });
  };
  const sorted = [...devices].sort((a, b) => a.id.localeCompare(b.id, "en", { numeric: true }));
  return (
    <Section title="Scenario" note="Synthetic records only: no packet is sent and no host is contacted.">
      <form className="stack" onSubmit={submit}>
        <Field label="Traffic" htmlFor="sc-name" hint={meta?.description}>
          <select id="sc-name" name="name" className="control" value={name} onChange={(e) => setName(e.target.value)}>
            {Object.entries(SCENARIOS).map(([k, l]) => <option key={k} value={k}>{l}</option>)}
          </select>
        </Field>
        {!normal && (
          <div className="form-grid">
            <Field label="Source" htmlFor="sc-attacker" hint={meta?.default_attacker ? `Default: ${meta.default_attacker}` : ""}>
              <select id="sc-attacker" name="attacker" className="control" value={attacker} onChange={(e) => setAttacker(e.target.value)}>
                <option value="">Default</option>
                {sorted.map((d) => <option key={d.id} value={d.id}>{d.id}</option>)}
              </select>
            </Field>
            <Field label="Target" htmlFor="sc-target" hint={meta?.default_target ? `Default: ${meta.default_target}` : ""}>
              <select id="sc-target" name="target" className="control" value={target} onChange={(e) => setTarget(e.target.value)}>
                <option value="">Default</option>
                {sorted.map((d) => <option key={d.id} value={d.id}>{d.id}</option>)}
              </select>
            </Field>
            <Field label="Duration" htmlFor="sc-duration">
              <select id="sc-duration" name="duration_s" className="control" value={duration} onChange={(e) => setDuration(e.target.value)}>
                {DURATIONS.map(([v, l]) => <option key={l} value={v}>{l}</option>)}
              </select>
            </Field>
            <Field label="Intensity" htmlFor="sc-intensity">
              <select id="sc-intensity" name="intensity" className="control" value={intensity} onChange={(e) => setIntensity(e.target.value)}>
                {INTENSITIES.map((v) => <option key={v} value={v}>{v}×</option>)}
              </select>
            </Field>
          </div>
        )}
        <div className="btn-row">
          <button type="submit" className={`btn ${primary ? "btn--primary" : "btn--quiet"}`} disabled={!!act.busy || status?.status === "completed"}
            aria-busy={act.busy === "launch"}>{normal ? "Stop all attacks" : "Launch scenario"}</button>
        </div>
      </form>
    </Section>
  );
}

function ActiveScenarios({ status, act, refresh, scenarios }) {
  const active = status?.active_scenarios || [];
  if (!active.length) return null;
  const stop = (id) => act.run(`stop-${id}`, async () => { await api(`/api/sim/scenarios/${encodeURIComponent(id)}`, { method: "DELETE" }); scenarios.reload(); refresh(); });
  return (
    <Section title="Active scenarios">
      <ul className="rows">
        {active.map((s) => (
          <li key={s.id} className="row">
            <div>
              <strong>{SCENARIOS[s.name] || s.name}</strong>
              <p className="note"><span className="measure">{s.attacker}</span> to <span className="measure">{s.targets.join(", ")}</span>,
                {" "}<span className="measure">{int(s.flows_generated)}</span> flows{s.end_t ? <>, ends at <span className="measure">{Math.round(s.end_t)} s</span></> : ""}</p>
            </div>
            <button type="button" className="btn btn--quiet btn--sm" onClick={() => stop(s.id)} disabled={!!act.busy}>Stop</button>
          </li>
        ))}
      </ul>
    </Section>
  );
}

function DevicePanel({ id, node }) {
  const flows = useData(id ? `/api/sim/flows?src=${encodeURIComponent(id)}&limit=8` : null, [node?.flows_out]);
  if (!id || !node) {
    return (
      <Section title="Device">
        <Empty>Select a device in the diagram or the list above to see its role, traffic and indicators.</Empty>
      </Section>
    );
  }
  return (
    <Section title={node.hostname} note={`${ROLE_LABELS[node.role] || node.role}, ${node.internal ? "internal" : "external"}`}
      actions={<button type="button" className="btn btn--quiet btn--sm" onClick={() => setParams({ device: null })}>Close</button>}>
      <KV items={[
        ["Address", node.ip, true], ["Services", node.services.join(", ") || "none", true],
        ["Flows out / in", `${int(node.flows_out)} / ${int(node.flows_in)}`, true],
        ["Bytes out / in", `${bytes(node.bytes_out)} / ${bytes(node.bytes_in)}`, true],
        ["Peers out / in", `${node.out_degree} / ${node.in_degree}`, true],
        ["Indicators", node.indicators.length ? node.indicators.map(ruleLabel).join(", ") : "none"],
        node.incident_ids.length ? ["Incidents", <span className="links">{node.incident_ids.map((i) => <a key={i} href={href("incidents", { id: i })}>{i}</a>)}</span>] : null,
      ]} />
      <h3 className="sub">Latest outgoing flows</h3>
      {flows.error && !flows.data ? <Failure error={flows.error} onRetry={flows.reload} />
        : flows.loading && !flows.data ? <Loading rows={3} />
          : !flows.data.flows.length ? <Empty>No outgoing flows from this device in the in-memory buffer.</Empty>
            : (
              <div className="table-wrap">
                <table className="table">
                  <thead><tr><th>Time</th><th>To</th><th className="num">Port</th><th className="num">Bytes</th><th>Flags</th></tr></thead>
                  <tbody>
                    {flows.data.flows.map((f) => (
                      <tr key={f.flow_id} className={f.alert_ids.length ? "is-flagged" : undefined}>
                        <td className="measure">{utcTime(f.timestamp)}</td><td className="measure">{f.dst}</td>
                        <td className="num measure">{f.dst_port}</td><td className="num measure">{bytes(f.fwd_bytes + f.bwd_bytes)}</td>
                        <td>{f.alert_ids.length ? "alert" : ""}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
    </Section>
  );
}

function AlertFeed({ versions, status }) {
  // Persisted detections of the current run, re-read whenever the stream reports a new or updated one.
  const feed = useData("/api/sim/detections?limit=8", [versions.alerts, status?.run_id]);
  return (
    <Section title="Latest alerts" actions={<a className="link" href={href("alerts")}>All alerts</a>}>
      {feed.error && !feed.data ? <Failure error={feed.error} onRetry={feed.reload} />
        : feed.loading && !feed.data ? <Loading rows={4} />
          : !feed.data.length ? <Empty>No alerts in this run yet. Start the simulation and launch a scenario; detections appear here as they happen.</Empty> : (
        <ul className="rows">
          {feed.data.map((a) => (
            <li key={a.id} className="row row--link">
              <a href={href("alerts", { id: a.id })}>
                <span className="measure muted">{utcTime(a.last_seen_at)}</span>
                <Severity level={a.severity} />
                <span className="row-title">{a.title}</span>
              </a>
            </li>
          ))}
        </ul>
      )}
    </Section>
  );
}

export default function Network() {
  const { params } = useRoute();
  const { status, statusError, graph, ticks, versions, connection, refreshStatus } = useLive();
  const act = useAction();
  const scenarios = useData("/api/sim/scenarios");
  const devices = useMemo(() => [...graph.nodes.values()], [graph]);
  const selected = params.device && graph.nodes.has(params.device) ? params.device : null;
  const onSelect = useCallback((id) => setParams({ device: id }), []);
  const rate = flowRate(ticks, status);
  const running = status?.status === "running";
  const suspicious = [...graph.edges.values()].filter((e) => e.suspicious).length;
  const counts = graph.meta?.counts;
  const lead = counts
    ? `A simulated enterprise network of ${devices.length} devices: ${counts.workstation} workstations, ${counts.laptop} laptops, ${counts.app_server + counts.db_server + counts.dns_server} servers, ${counts.router} router and ${counts.external} external endpoints. All traffic is synthetic.`
    : "A simulated enterprise network. All traffic is synthetic.";

  return (
    <>
      <PageHead title="Network">{lead}</PageHead>
      {statusError && !status ? <Failure error={statusError} onRetry={refreshStatus} /> : (
        <Figures items={[
          ["Simulated time", status ? utcTime(status.sim_time) : "—"],
          ["Elapsed", status ? elapsed(status.sim_elapsed_s) : "—"],
          ["Flows", status ? int(status.flows_generated) : "—"],
          ["Flow rate", rate === null ? "—" : rate.toFixed(1), rate === null ? null : "per s"],
          ["Open incidents", status ? int(status.open_incidents) : "—"],
        ]} />
      )}
      {act.error && <div className="failure" role="alert"><p><strong>That did not work.</strong> {act.error.message}</p>
        <button type="button" className="btn btn--quiet btn--sm" onClick={act.clear}>Dismiss</button></div>}
      <div className="network-grid">
        <section className="canvas" aria-labelledby="topo-h">
          <div className="canvas-head">
            <h2 id="topo-h">Topology</h2>
            <p className="legend">
              <span><span className="key key--acting" aria-hidden="true" />acting in a flagged connection</span>
              <span><span className="key key--receiving" aria-hidden="true" />receiving one</span>
              <span><span className="key key--line" aria-hidden="true" />line width: flows</span>
            </p>
          </div>
          {graph.error && !graph.nodes.size ? <Failure error={graph.error} />
            : !graph.nodes.size ? <Loading rows={6} label="Loading topology" />
              : (
                <div className="topology-scroll" tabIndex={0} aria-label="Topology diagram, scrolls sideways on small screens">
                  <Topology graph={graph} selected={selected} onSelect={onSelect}
                    label={`Network diagram: ${devices.length} devices, ${graph.edges.size} connections, ${suspicious} flagged. Use the device list to inspect one.`} />
                </div>
              )}
          <div className="canvas-foot">
            <Field label="Device" htmlFor="device-pick">
              <select id="device-pick" className="control" value={selected || ""} onChange={(e) => setParams({ device: e.target.value || null })}>
                <option value="">Choose a device</option>
                {[...devices].sort((a, b) => a.id.localeCompare(b.id, "en", { numeric: true }))
                  .map((d) => <option key={d.id} value={d.id}>{d.id} ({ROLE_LABELS[d.role]}, {d.ip})</option>)}
              </select>
            </Field>
            <p className="note measure">{int(graph.edges.size)} connections, {int(suspicious)} flagged{connection !== "live" ? ", stream reconnecting" : ""}</p>
          </div>
        </section>
        <div className="side">
          <SimControls status={status} act={act} refresh={refreshStatus} />
          <ScenarioLauncher status={status} devices={devices} act={act} refresh={refreshStatus} scenarios={scenarios} primary={running} />
          <ActiveScenarios status={status} act={act} refresh={refreshStatus} scenarios={scenarios} />
        </div>
      </div>
      <div className="grid-2">
        <DevicePanel id={selected} node={selected ? graph.nodes.get(selected) : null} />
        <AlertFeed versions={versions} status={status} />
      </div>
    </>
  );
}
