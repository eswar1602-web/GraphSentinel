import { useState } from "react";
import { api } from "../../api";
import { href, setParams, useRoute } from "../router";
import { useLive } from "../live";
import { Empty, Failure, Field, KV, Loading, PageHead, Section, Severity, useData } from "../ui";
import { bytes, int, ruleLabel, RULES, utcDateTime, utcTime } from "../format";

const SEVERITIES = ["critical", "high", "medium", "low"];

function query(params) {
  const q = new URLSearchParams({ limit: "200" });
  if (params.severity) q.set("severity", params.severity);
  if (params.rule) q.set("rule", params.rule);
  if (params.run === "all") q.set("run_id", "all");
  return `/api/sim/detections?${q}`;
}

function evidenceRows(ev) {
  return Object.entries(ev || {}).map(([k, v]) => [k.replace(/_/g, " "), Array.isArray(v) ? v.join(", ") : typeof v === "object" && v !== null ? JSON.stringify(v) : String(v), true]);
}

function FlowLookup({ id }) {
  const [state, setState] = useState(null);
  const open = async () => {
    if (state) { setState(null); return; }
    setState({ loading: true });
    try { setState({ data: await api(`/api/sim/flows/${encodeURIComponent(id)}`) }); } catch (error) { setState({ error }); }
  };
  return (
    <li>
      <button type="button" className="flow-id" aria-expanded={!!state} onClick={open}>{id}</button>
      {state?.loading && <Loading rows={1} />}
      {state?.error && <p className="note">{/404/.test(state.error.message) ? "No longer in the in-memory flow buffer (the 5,000 most recent flows); the ID stays as evidence." : state.error.message}</p>}
      {state?.data && (
        <KV items={[
          ["Time", utcDateTime(state.data.timestamp), true],
          ["Connection", `${state.data.src} (${state.data.src_ip}):${state.data.src_port} to ${state.data.dst} (${state.data.dst_ip}):${state.data.dst_port} ${state.data.protocol}`, true],
          ["Duration", `${state.data.duration_s.toFixed(4)} s`, true],
          ["Packets out / back", `${state.data.fwd_packets} / ${state.data.bwd_packets}`, true],
          ["Bytes out / back", `${bytes(state.data.fwd_bytes)} / ${bytes(state.data.bwd_bytes)}`, true],
          ["TCP flags", state.data.tcp_flags || "none", true],
          ["ML prediction", state.data.ml ? `${state.data.ml.family} (${state.data.ml.confidence.toFixed(3)})` : "not scored"],
          ["Simulator ground truth", state.data.ground_truth_scenario],
        ]} />
      )}
    </li>
  );
}

function AlertDetail({ id, version }) {
  const a = useData(`/api/sim/detections/${encodeURIComponent(id)}`, [version]);
  return (
    <Section title={a.data ? a.data.title : "Alert"} note={a.data ? <><span className="measure">{a.data.id}</span>, {a.data.source === "ml" ? "machine-learning detector" : "behavioural rule"}</> : null}
      actions={<button type="button" className="btn btn--quiet btn--sm" onClick={() => setParams({ id: null })}>Close</button>} className="detail">
      {a.error && !a.data ? <Failure error={a.error} onRetry={a.reload} /> : a.loading && !a.data ? <Loading rows={6} /> : (
        <>
          <div className="detail-top"><Severity level={a.data.severity} /><span>{ruleLabel(a.data.rule)}</span></div>
          <p className="explain">{a.data.explanation}</p>
          <KV items={[
            ["Source", a.data.src, true], ["Destination", a.data.dst_devices.join(", "), true],
            ["First seen", utcDateTime(a.data.first_seen_at), true], ["Last seen", utcDateTime(a.data.last_seen_at), true],
            ["Occurrences", int(a.data.occurrences), true],
            ["Incident", a.data.incident_id ? <a href={href("incidents", { id: a.data.incident_id })}>{a.data.incident_id}</a> : "not part of an incident"],
          ]} />
          <h3 className="sub">Evidence</h3>
          <KV items={evidenceRows(a.data.evidence)} />
          <h3 className="sub">Supporting flows <span className="measure muted">{a.data.flow_ids.length}</span></h3>
          <p className="note">Select a flow ID to see its record.</p>
          <ul className="flow-ids">{a.data.flow_ids.slice().reverse().map((f) => <FlowLookup key={f} id={f} />)}</ul>
        </>
      )}
    </Section>
  );
}

export default function Alerts() {
  const { params } = useRoute();
  const { versions, status } = useLive();
  const list = useData(query(params), [versions.alerts, status?.run_id]);
  const rows = list.data || [];
  return (
    <>
      <PageHead title="Alerts">
        Detections from the behavioural rules and the ML classifier on simulated traffic, newest first. Repeats of the same finding update one alert.
      </PageHead>
      <form className="filters" onSubmit={(e) => e.preventDefault()} aria-label="Filter alerts">
        <Field label="Severity" htmlFor="f-sev">
          <select id="f-sev" className="control" value={params.severity || ""} onChange={(e) => setParams({ severity: e.target.value || null, id: null })}>
            <option value="">All severities</option>
            {SEVERITIES.map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
        </Field>
        <Field label="Rule" htmlFor="f-rule">
          <select id="f-rule" className="control" value={params.rule || ""} onChange={(e) => setParams({ rule: e.target.value || null, id: null })}>
            <option value="">All rules</option>
            {Object.entries(RULES).map(([k, l]) => <option key={k} value={k}>{l}</option>)}
            <option value="ml_dos">ML: DoS</option>
          </select>
        </Field>
        <Field label="Run" htmlFor="f-run">
          <select id="f-run" className="control" value={params.run || ""} onChange={(e) => setParams({ run: e.target.value || null, id: null })}>
            <option value="">Current run</option>
            <option value="all">All runs</option>
          </select>
        </Field>
        <p className="note measure filters-count">{list.data ? `${rows.length}${rows.length === 200 ? "+" : ""} ${rows.length === 1 ? "alert" : "alerts"}` : ""}</p>
      </form>
      <div className={params.id ? "split" : undefined}>
        <section aria-label="Alert list">
          {list.error && !list.data ? <Failure error={list.error} onRetry={list.reload} />
            : list.loading && !list.data ? <Loading rows={8} />
              : !rows.length ? (
                <Empty action={<a className="btn btn--quiet" href={href("network")}>Go to the network</a>}>
                  {params.severity || params.rule ? "No alerts match these filters." : "No alerts yet. Launch a scenario on the network page and they will appear here."}
                </Empty>
              ) : (
                <div className="table-wrap">
                  <table className="table table--select">
                    <thead><tr><th>Last seen</th><th>Severity</th><th>Rule</th><th>Source</th><th>Destination</th><th className="num">Seen</th><th>Incident</th></tr></thead>
                    <tbody>
                      {rows.map((a) => (
                        <tr key={a.id} aria-selected={params.id === a.id}>
                          <td className="measure"><a className="row-link" href={href("alerts", { ...params, id: a.id })}>{utcTime(a.last_seen_at)}</a></td>
                          <td><Severity level={a.severity} /></td>
                          <td>{ruleLabel(a.rule)}</td>
                          <td className="measure">{a.src}</td>
                          <td className="measure">{a.dst_devices.length > 2 ? `${a.dst_devices.slice(0, 2).join(", ")} +${a.dst_devices.length - 2}` : a.dst_devices.join(", ")}</td>
                          <td className="num measure">{int(a.occurrences)}</td>
                          <td className="measure">{a.incident_id ? a.incident_id.split("-").pop() : "—"}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
        </section>
        {params.id && <AlertDetail key={params.id} id={params.id} version={versions.alerts} />}
      </div>
    </>
  );
}
