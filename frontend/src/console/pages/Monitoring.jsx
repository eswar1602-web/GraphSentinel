import { useEffect } from "react";
import { rateSeries, useLive } from "../live";
import { Bars, Empty, Failure, Figures, KV, Loading, PageHead, Section, useData } from "../ui";
import { bytes, int, num, pct, ruleLabel, SCENARIOS, utcDateTime } from "../format";

function RateChart({ series }) {
  if (series.length < 2) {
    return <Empty>The flow-rate line starts once the simulation has run for a few ticks while this console is open.</Empty>;
  }
  const W = 640;
  const H = 180;
  const pad = { l: 44, r: 12, t: 12, b: 26 };
  const t0 = series[0].sim_t;
  const t1 = series[series.length - 1].sim_t;
  const max = Math.max(1, ...series.map((p) => p.rate));
  const x = (t) => pad.l + ((t - t0) / Math.max(1e-9, t1 - t0)) * (W - pad.l - pad.r);
  const y = (r) => H - pad.b - (r / max) * (H - pad.t - pad.b);
  const d = series.map((p, i) => `${i ? "L" : "M"}${x(p.sim_t).toFixed(1)},${y(p.rate).toFixed(1)}`).join(" ");
  const last = series[series.length - 1].rate;
  return (
    <figure className="chart">
      <svg viewBox={`0 0 ${W} ${H}`} role="img" aria-label={`Flows per simulated second, from ${Math.round(t0)} s to ${Math.round(t1)} s of the run; latest ${last.toFixed(1)}, peak ${max.toFixed(1)}.`}>
        <line className="chart-axis" x1={pad.l} x2={W - pad.r} y1={H - pad.b} y2={H - pad.b} />
        <line className="chart-grid" x1={pad.l} x2={W - pad.r} y1={y(max)} y2={y(max)} />
        <text className="chart-tick" x={pad.l - 6} y={y(max) + 4} textAnchor="end">{max.toFixed(0)}</text>
        <text className="chart-tick" x={pad.l - 6} y={H - pad.b + 4} textAnchor="end">0</text>
        <text className="chart-tick" x={pad.l} y={H - 6}>{Math.round(t0)} s</text>
        <text className="chart-tick" x={W - pad.r} y={H - 6} textAnchor="end">{Math.round(t1)} s</text>
        <path className="chart-line" d={d} />
      </svg>
      <figcaption className="note">Flows per simulated second between consecutive status updates, since this console connected. Latest <span className="measure">{last.toFixed(1)}</span>, peak <span className="measure">{max.toFixed(1)}</span>.</figcaption>
    </figure>
  );
}

export default function Monitoring() {
  const { status, ticks, versions } = useLive();
  const stats = useData("/api/sim/stats", [versions.alerts, versions.incidents, status?.run_id]);
  const runs = useData("/api/sim/runs?limit=8", [status?.run_id, status?.status]);
  const running = status?.status === "running";
  const { reload } = stats;
  useEffect(() => {
    if (!running) return undefined;
    const t = setInterval(reload, 3000);
    return () => clearInterval(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [running]);
  const s = stats.data;
  const ev = s?.evaluation_against_ground_truth;
  const ml = s?.ml;

  return (
    <>
      <PageHead title="Monitoring">Traffic, detections and the health of the simulation engine for the current run.</PageHead>
      {stats.error && !s ? <Failure error={stats.error} onRetry={stats.reload} /> : stats.loading && !s ? <Loading rows={3} /> : (
        <>
          <Figures items={[
            ["Flows", int(s.totals.flows)], ["Packets", int(s.totals.packets)], ["Data", bytes(s.totals.bytes)],
            ["Alerts", int(s.totals.alerts)], ["Incidents", int(s.totals.incidents)],
          ]} />
          <div className="grid-2 grid-2--wide">
            <Section title="Flow rate"><RateChart series={rateSeries(ticks, status)} /></Section>
            <Section title="Alerts by rule" note="Every alert of this run, including those merged into later updates.">
              {Object.keys(s.alerts_by_rule).length
                ? <Bars rows={Object.entries(s.alerts_by_rule).sort((a, b) => b[1] - a[1]).map(([r, n]) => [ruleLabel(r), n])} />
                : <Empty>No alerts in this run.</Empty>}
            </Section>
          </div>
          <div className="grid-2">
            <Section title="Detection against the simulator's labels"
              note="The simulator knows which flows each scenario generated. No detector reads these labels; they are used only here, to check the detectors.">
              <KV items={[
                ["Alerts mostly on attack flows", int(ev.alerts.true_positive || 0), true],
                ["Alerts mostly on normal flows", int(ev.alerts.false_positive || 0), true],
                ev.alerts.unknown ? ["Alerts whose flows left the buffer", int(ev.alerts.unknown), true] : null,
              ]} />
              <h3 className="sub">First alert per scenario</h3>
              {Object.keys(ev.first_detection_by_scenario_instance).length ? (
                <div className="table-wrap">
                  <table className="table">
                    <thead><tr><th>Scenario</th><th>First rule</th><th className="num">After</th></tr></thead>
                    <tbody>
                      {Object.entries(ev.first_detection_by_scenario_instance).map(([k, v]) => (
                        <tr key={k}><td>{SCENARIOS[v.scenario] || v.scenario} <span className="measure muted">{k.split("-").pop()}</span></td>
                          <td>{ruleLabel(v.rule)}</td><td className="num measure">{v.latency_sim_s === null ? "—" : `${num(v.latency_sim_s, 1)} s`}</td></tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : <Empty>No scenario has been detected in this run yet.</Empty>}
            </Section>
            <Section title="ML detector" note={ml?.caveat}>
              {!ml?.available || !ml?.compatible ? (
                <Empty>ML detection is off: {ml?.reason || "the model is not available"}. No predictions are made; the behavioural rules still run.</Empty>
              ) : (
                <>
                  <KV items={[
                    ["Model", ml.model, true], ["Flows scored", int(ml.scored_flows), true],
                    ["Features computed", `${ml.computed_columns} of ${ml.required_raw_columns} required, ${ml.missing_features.length} missing`, true],
                    ["Precision on attack flows", ev.ml_attack_vs_benign.precision === null ? "—" : pct(ev.ml_attack_vs_benign.precision), true],
                    ["Recall on attack flows", ev.ml_attack_vs_benign.recall === null ? "—" : pct(ev.ml_attack_vs_benign.recall), true],
                    ["False positive rate", ev.ml_attack_vs_benign.false_positive_rate === null ? "—" : pct(ev.ml_attack_vs_benign.false_positive_rate, 2), true],
                  ]} />
                  <h3 className="sub">Predicted families</h3>
                  {Object.keys(ml.predicted_family_counts).length
                    ? <Bars rows={Object.entries(ml.predicted_family_counts).sort((a, b) => b[1] - a[1])} total={ml.scored_flows} />
                    : <Empty>No flows scored yet.</Empty>}
                </>
              )}
            </Section>
          </div>
          <div className="grid-2">
            <Section title="Graph" note={`Structure of the ${int(s.graph.structure_recent.window_flows)} most recent flows.`}>
              <KV items={[
                ["Active devices", `${s.graph.active_devices} of ${s.graph.devices}`, true], ["Connections", int(s.graph.edges), true],
                ["Flagged devices", int(s.graph.suspicious_devices), true], ["Flagged connections", int(s.graph.suspicious_edges), true],
                s.graph.structure_recent.density !== undefined ? ["Density", num(s.graph.structure_recent.density, 3), true] : null,
                s.graph.structure_recent.weakly_connected_components !== undefined ? ["Connected components", s.graph.structure_recent.weakly_connected_components, true] : null,
                ["Protocols", Object.entries(s.protocols).map(([p, n]) => `${p} ${int(n)}`).join(", ") || "—", true],
              ]} />
            </Section>
            <Section title="Engine" note="Memory is bounded: older flows leave the buffer, and alerts and incidents stay in the database.">
              <KV items={[
                ["Last tick", `${num(s.performance.last_tick_ms, 1)} ms`, true],
                ["Flow buffer", `${int(s.memory.flow_buffer)} of ${int(s.memory.flow_buffer_limit)}`, true],
                ["Invalid / dropped flows", `${int(s.totals.invalid_flows)} / ${int(s.totals.dropped_flows)}`, true],
                ["Live clients", int(s.websocket.clients), true],
                ["Stream messages sent / dropped", `${int(s.websocket.messages_sent)} / ${int(s.websocket.messages_dropped)}`, true],
                ["Audit write failures", int(s.audit_failures), true],
              ]} />
            </Section>
          </div>
        </>
      )}
      <Section title="Runs" note="Every simulation run is kept in the database.">
        {runs.error && !runs.data ? <Failure error={runs.error} onRetry={runs.reload} /> : runs.loading && !runs.data ? <Loading rows={3} />
          : !runs.data.length ? <Empty>No runs recorded yet.</Empty> : (
            <div className="table-wrap">
              <table className="table">
                <thead><tr><th>Run</th><th>Created</th><th>Status</th><th className="num">Seed</th><th className="num">Simulated</th><th className="num">Flows</th></tr></thead>
                <tbody>
                  {runs.data.map((r) => (
                    <tr key={r.run_id} aria-current={r.run_id === status?.run_id ? "true" : undefined}>
                      <td className="measure">{r.run_id}{r.run_id === status?.run_id ? " (current)" : ""}</td>
                      <td className="measure">{utcDateTime(r.created_at)}</td><td>{r.status}</td>
                      <td className="num measure">{r.seed}</td><td className="num measure">{Math.round(r.sim_elapsed_s)} s</td>
                      <td className="num measure">{int(r.flows_generated)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
      </Section>
    </>
  );
}
