import { useState } from "react";
import { api } from "../../api";
import { href, setParams, useRoute } from "../router";
import { useLive } from "../live";
import { Empty, Failure, Field, KV, Loading, PageHead, Section, Severity, useData } from "../ui";
import { int, ruleLabel, STATUS_LABELS, TRANSITIONS, utcDateTime, utcTime } from "../format";

function StatusForm({ inc, onDone }) {
  const options = TRANSITIONS[inc.status] || [];
  const [to, setTo] = useState(options[0] || "");
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const submit = async (e) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await api(`/api/sim/incidents/${encodeURIComponent(inc.id)}`, { method: "PATCH", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ status: to, ...(note.trim() && { note: note.trim() }) }) });
      setNote("");
      onDone();
    } catch (err) { setError(err); } finally { setBusy(false); }
  };
  return (
    <form className="stack status-form" onSubmit={submit}>
      <div className="form-grid">
        <Field label="New status" htmlFor="inc-status">
          <select id="inc-status" name="status" className="control" value={to} onChange={(e) => setTo(e.target.value)}>
            {options.map((s) => <option key={s} value={s}>{STATUS_LABELS[s]}</option>)}
          </select>
        </Field>
        <Field label="Note" htmlFor="inc-note" hint={`${note.length}/500, saved in the incident history and the audit log`}>
          <input id="inc-note" name="note" className="control" maxLength={500} autoComplete="off" value={note} onChange={(e) => setNote(e.target.value)}
            placeholder="What you checked or decided" />
        </Field>
      </div>
      {error && <p className="field-error" role="alert">{error.message}</p>}
      <div className="btn-row">
        <button type="submit" className="btn btn--primary" disabled={busy || !to} aria-busy={busy}>Update status</button>
      </div>
    </form>
  );
}

function IncidentDetail({ id, onChanged, version }) {
  const d = useData(`/api/sim/incidents/${encodeURIComponent(id)}`, [version]);
  const inc = d.data;
  return (
    <Section title={inc ? inc.title : "Incident"} note={inc ? <><span className="measure">{inc.id}</span>, {STATUS_LABELS[inc.status]}</> : null} className="detail"
      actions={<button type="button" className="btn btn--quiet btn--sm" onClick={() => setParams({ id: null })}>Close</button>}>
      {d.error && !inc ? <Failure error={d.error} onRetry={d.reload} /> : d.loading && !inc ? <Loading rows={8} /> : (
        <>
          <div className="detail-top"><Severity level={inc.severity} /><span>{inc.rules.map(ruleLabel).join(", ")}</span></div>
          <p className="explain">{inc.summary}</p>
          <KV items={[
            ["Acting device", inc.actor, true], ["Targets", inc.targets.join(", ") || "none", true],
            inc.pivots.length ? ["Possible pivots", inc.pivots.join(", "), true] : null,
            ["First seen", utcDateTime(inc.first_seen_at), true], ["Last seen", utcDateTime(inc.last_seen_at), true],
            ["Supporting flows", int(inc.flow_ids.length), true],
          ]} />
          <h3 className="sub">Change status</h3>
          <p className="note">Status is your record of the investigation. GraphSentinel never blocks traffic or takes action on its own.</p>
          <StatusForm key={inc.status} inc={inc} onDone={() => { d.reload(); onChanged(); }} />
          <h3 className="sub">Alerts <span className="measure muted">{inc.detections.length}</span></h3>
          <ul className="rows">
            {inc.detections.map((a) => (
              <li key={a.id} className="row row--link">
                <a href={href("alerts", { id: a.id, run: "all" })}>
                  <span className="measure muted">{utcTime(a.first_seen_at)}</span><Severity level={a.severity} /><span className="row-title">{a.title}</span>
                </a>
              </li>
            ))}
          </ul>
          <h3 className="sub">History</h3>
          <p className="note">Recorded in real time (UTC). Alert and incident times above are simulated time.</p>
          <ol className="history">
            {inc.history.slice().reverse().map((h, i) => (
              <li key={`${h.at}-${i}`}>
                <span className="measure muted">{utcDateTime(h.at)}</span>
                <span><strong>{STATUS_LABELS[h.status]}</strong> by {h.by}{h.note ? `: ${h.note}` : ""}</span>
              </li>
            ))}
          </ol>
        </>
      )}
    </Section>
  );
}

export default function Incidents() {
  const { params } = useRoute();
  const { versions, status } = useLive();
  const q = new URLSearchParams({ limit: "200" });
  if (params.status) q.set("status", params.status);
  if (params.run === "all") q.set("run_id", "all");
  const list = useData(`/api/sim/incidents?${q}`, [versions.incidents, status?.run_id]);
  const rows = list.data || [];
  return (
    <>
      <PageHead title="Incidents">
        Related alerts grouped by the device that acts in them. Work them here: acknowledge, investigate, resolve or mark as a false positive.
      </PageHead>
      <form className="filters" onSubmit={(e) => e.preventDefault()} aria-label="Filter incidents">
        <Field label="Status" htmlFor="f-status">
          <select id="f-status" className="control" value={params.status || ""} onChange={(e) => setParams({ status: e.target.value || null, id: null })}>
            <option value="">All statuses</option>
            {Object.entries(STATUS_LABELS).map(([k, l]) => <option key={k} value={k}>{l}</option>)}
          </select>
        </Field>
        <Field label="Run" htmlFor="f-irun">
          <select id="f-irun" className="control" value={params.run || ""} onChange={(e) => setParams({ run: e.target.value || null, id: null })}>
            <option value="">Current run</option>
            <option value="all">All runs</option>
          </select>
        </Field>
        <p className="note measure filters-count">{list.data ? `${rows.length} ${rows.length === 1 ? "incident" : "incidents"}` : ""}</p>
      </form>
      <div className={params.id ? "split" : undefined}>
        <section aria-label="Incident list">
          {list.error && !list.data ? <Failure error={list.error} onRetry={list.reload} />
            : list.loading && !list.data ? <Loading rows={6} />
              : !rows.length ? (
                <Empty action={<a className="btn btn--quiet" href={href("network")}>Go to the network</a>}>
                  {params.status ? "No incidents with this status." : "No incidents in this run. An incident opens when an alert of medium severity or higher fires."}
                </Empty>
              ) : (
                <div className="table-wrap">
                  <table className="table table--select">
                    <thead><tr><th>Severity</th><th>Incident</th><th>Acting device</th><th className="num">Alerts</th><th>Last seen</th><th>Status</th></tr></thead>
                    <tbody>
                      {rows.map((i) => (
                        <tr key={i.id} aria-selected={params.id === i.id}>
                          <td><Severity level={i.severity} /></td>
                          <td><a className="row-link" href={href("incidents", { ...params, id: i.id })}>{i.title}</a></td>
                          <td className="measure">{i.actor}</td>
                          <td className="num measure">{int(i.alert_ids.length)}</td>
                          <td className="measure">{utcTime(i.last_seen_at)}</td>
                          <td><span className={`status status--${i.status}`}>{STATUS_LABELS[i.status]}</span></td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
        </section>
        {params.id && <IncidentDetail key={params.id} id={params.id} onChanged={list.reload} version={versions.incidents} />}
      </div>
    </>
  );
}
