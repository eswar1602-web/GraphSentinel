// Operational NIDS views. Every figure comes from the FastAPI backend: /api/health, /api/detect,
// /api/detections, /api/dataset, /api/graph and /api/audit/*. Research views live in ./research.jsx.
import { useMemo, useState } from "react";
import { api, fmt, pct, int } from "./api";
import { useApi } from "./hooks";
import { Chip, ErrorState, Field, Graph, Heatmap, Note, Panel, Plot, Segmented, Stats, Status, Table } from "./components";
import { Icon } from "./icons";
import { cssColor, useThemeKey } from "./theme";

const Code = ({ children }) => <code className="ident">{children}</code>;
const familyColor = (f) => cssColor(f === "Benign" ? "--color-accent" : "--color-bad");
const navTo = (page) => (e) => { if (e) e.preventDefault(); window.location.hash = encodeURIComponent(page); };
const fileName = (p) => String(p || "").split(/[\\/]/).pop();
const when = (iso) => { const d = new Date(iso); return Number.isNaN(d.getTime()) ? iso : d.toLocaleString(); };
const whenShort = (iso) => { const d = new Date(iso); return Number.isNaN(d.getTime()) ? iso : d.toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" }); };
const PAGE_SIZE = 25;
const clip = (t, n) => { const x = String(t || ""); return x.length > n ? `${x.slice(0, n - 1)}…` : x; };
const rate = (a, n) => (n ? a / n : null);
const attackCounts = (counts = {}) => Object.entries(counts).filter(([k]) => k !== "Benign" && k !== "invalid_record");
const topAttack = (counts) => { const a = attackCounts(counts).sort((x, y) => y[1] - x[1]); return a.length ? a[0][0] : null; };

/** A horizontal bar per class: benign in teal, attack classes in red. */
function ClassBars({ counts, label, height }) {
  useThemeKey();
  const rows = Object.entries(counts).filter(([k]) => k !== "invalid_record").sort((a, b) => a[1] - b[1]);
  if (!rows.length) return <p className="empty">Nothing to show.</p>;
  return (
    <Plot height={height || Math.max(200, 40 * rows.length + 64)} label={label} data={[{ type: "bar", orientation: "h",
      y: rows.map((r) => r[0]), x: rows.map((r) => r[1]), marker: { color: rows.map((r) => familyColor(r[0])) },
      text: rows.map((r) => int(r[1])), textposition: "outside", cliponaxis: false, hovertemplate: "%{y}: %{x:,} flows<extra></extra>" }]}
      layout={{ xaxis: { title: "flows" }, yaxis: { showgrid: false }, margin: { l: 8, r: 64, t: 8, b: 8 } }} />
  );
}

/** Alert share as a two-part bar; the figure beside it is the real rate. */
function AlertRate({ alerts, scored }) {
  const r = rate(alerts, scored);
  if (r === null) return <span className="muted">n/a</span>;
  return (
    <span className="rate">
      <span className="rate-bar" aria-hidden="true"><span className="rate-on" style={{ flexGrow: alerts }} /><span className="rate-off" style={{ flexGrow: Math.max(0, scored - alerts) }} /></span>
      <span className="mono">{pct(r, 1)}</span>
    </span>
  );
}

/* ---------------------------------------------------------------- Overview */

function SystemStatus() {
  const h = useApi("/api/health");
  const v = useApi("/api/audit/verify");
  const rows = [];
  if (h.error) rows.push({ ok: false, name: "API", state: "Unreachable", detail: String(h.error.message || h.error) });
  else if (h.data) {
    rows.push({ ok: h.data.status === "ok", name: "API", state: h.data.status === "ok" ? "Online" : h.data.status, detail: "FastAPI backend answering" });
    rows.push({ ok: h.data.detector_model, name: "Detection engine", state: h.data.detector_model ? "Ready" : "Model missing", detail: "Saved XGBoost flow classifier" });
    rows.push({ ok: h.data.processed_data, name: "Traffic data", state: h.data.processed_data ? "Loaded" : "Missing", detail: "Processed CICIDS2017 flows for the graph view" });
  }
  if (v.data) rows.push({ ok: v.data.valid, name: "Audit chain", state: v.data.valid ? "Verified" : "Tampering detected", detail: `${int(v.data.records)} records, HMAC-SHA256` });
  else if (v.error) rows.push({ ok: false, name: "Audit chain", state: "Unverified", detail: String(v.error.message || v.error) });
  const loading = (h.loading && !h.data) || (v.loading && !v.data);
  return (
    <Panel title="System status" note="Checked from the backend when this page loads." actions={
      <button type="button" className="btn btn--quiet btn--sm" onClick={() => { h.reload(); v.reload(); }}><Icon name="refresh" size={16} />Recheck</button>}>
      {loading ? <p className="muted">Checking…</p> : (
        <ul className="status-list">
          {rows.map((r) => (
            <li key={r.name} className={r.ok ? "is-ok" : "is-bad"}>
              <Icon name={r.ok ? "check" : "alert"} size={18} />
              <span className="status-name">{r.name}</span>
              <span className="status-state">{r.state}</span>
              <span className="status-detail">{r.detail}</span>
            </li>
          ))}
        </ul>
      )}
    </Panel>
  );
}

export function Overview() {
  const hist = useApi("/api/detections?limit=500");
  return <>
    <Status q={hist} height={260}>{(h) => {
      if (!h.length) return (
        <section className="hero-empty">
          <Icon name="detection" size={28} />
          <div>
            <h2>No traffic analysed yet</h2>
            <p>Upload a flow file to classify its traffic and raise alerts. Results and history appear here.</p>
          </div>
          <a className="btn btn--primary" href="#Detection" onClick={navTo("Detection")}><Icon name="upload" size={16} />Analyse traffic</a>
        </section>
      );
      const flows = h.reduce((a, d) => a + d.n_flows, 0), scored = h.reduce((a, d) => a + d.n_scored, 0), alerts = h.reduce((a, d) => a + d.n_alerts, 0);
      const byClass = {};
      h.forEach((d) => attackCounts(d.summary?.predicted_family_counts).forEach(([k, n]) => { byClass[k] = (byClass[k] || 0) + n; }));
      const last = h[0];
      return <>
        <section className="verdict" aria-labelledby="verdict-h">
          <div className="verdict-main">
            <h2 id="verdict-h" className="reading-label">Alerts raised across all scans</h2>
            <p className={`reading ${alerts ? "tone-bad" : "tone-ok"}`}>{int(alerts)}</p>
            <p className="muted">from <span className="mono">{int(scored)}</span> scored flows in <span className="mono">{int(h.length)}</span> uploaded {h.length === 1 ? "file" : "files"}{h.length === 500 ? " (latest 500 shown)" : ""}</p>
          </div>
          <dl className="verdict-facts">
            <div><dt>Alert rate</dt><dd><AlertRate alerts={alerts} scored={scored} /></dd></div>
            <div><dt>Most frequent attack class</dt><dd>{topAttack(byClass) || "none"}</dd></div>
            <div><dt>Last scan</dt><dd className="mono">{when(last.created_at)}</dd></div>
            <div><dt>Last file</dt><dd className="mono ellipsis" title={last.filename}>{last.filename}</dd></div>
          </dl>
        </section>
        <Stats items={[
          { label: "Scans run", value: int(h.length) },
          { label: "Flows analysed", value: int(flows) },
          { label: "Alerts", value: int(alerts), tone: alerts ? "bad" : "ok" },
          { label: "Classes detected", value: int(Object.keys(byClass).length), note: "Distinct attack classes predicted" },
        ]} />
        <div className="grid grid--halves">
          <Panel title="Alerts by attack class" note="Predicted attack flows summed over every scan.">
            {Object.keys(byClass).length ? <ClassBars counts={byClass} label="Alerts by attack class" /> : <p className="empty">No attack traffic has been predicted in any scan.</p>}
          </Panel>
          <Panel title="Recent scans" flush actions={<a className="btn btn--quiet btn--sm" href="#Detection%20history" onClick={navTo("Detection history")}>All scans</a>}>
            <Table caption="Recent scans" rows={h.slice(0, 6)} columns={[
              { label: "File", render: (r) => <span className="mono" title={r.filename}>{clip(r.filename, 24)}</span> },
              { label: "Time", render: (r) => <span className="mono nowrap" title={when(r.created_at)}>{whenShort(r.created_at)}</span> },
              { label: "Alerts", num: true, render: (r) => int(r.n_alerts) },
              { label: "Alert rate", render: (r) => <AlertRate alerts={r.n_alerts} scored={r.n_scored} /> }]} />
          </Panel>
        </div>
      </>;
    }}</Status>
    <SystemStatus />
  </>;
}

/* --------------------------------------------------------------- Detection */

const FLOW_FILTERS = [{ value: "all", label: "All flows" }, { value: "alerts", label: "Alerts" }, { value: "benign", label: "Benign" }];

export function Detection() {
  const [file, setFile] = useState(null);
  const [res, setRes] = useState(null);
  const [err, setErr] = useState(null);
  const [busy, setBusy] = useState(false);
  const [drag, setDrag] = useState(false);
  const [show, setShow] = useState("all");
  const [cls, setCls] = useState("");
  const [pg, setPg] = useState(0);
  useThemeKey();
  const run = async () => {
    if (!file) return;
    setBusy(true); setErr(null); setRes(null); setShow("all"); setCls(""); setPg(0);
    const fd = new FormData(); fd.append("file", file);
    try { setRes(await api("/api/detect", { method: "POST", body: fd })); window.dispatchEvent(new Event("gs-audit-changed")); } catch (e) { setErr(e.message); }
    setBusy(false);
  };
  const onDrop = (e) => { e.preventDefault(); setDrag(false); const f = e.dataTransfer.files && e.dataTransfer.files[0]; if (f) setFile(f); };
  const gt = res && res.ground_truth_evaluation;
  const rows = useMemo(() => (res ? res.preview.filter((r) => (show === "alerts" ? r.predicted !== "Benign" && r.predicted !== "invalid_record" : show === "benign" ? r.predicted === "Benign" : true))
    .filter((r) => !cls || r.predicted === cls) : []), [res, show, cls]);
  const classes = res ? Object.keys(res.predicted_family_counts) : [];
  const pages = Math.max(1, Math.ceil(rows.length / PAGE_SIZE));
  const cur = Math.min(pg, pages - 1);
  const pageRows = rows.slice(cur * PAGE_SIZE, (cur + 1) * PAGE_SIZE);

  return <>
    <Panel title="Analyse a traffic capture">
      <div className="upload">
        <div className="upload-copy">
          <p>Upload flow records in CICIDS2017 CSV format (CICFlowMeter columns), up to 25 MB and 200k rows.
            Each flow is classified by the saved XGBoost detection model as benign or as an attack class, and the scan is written to the audit log.</p>
          <p className="muted">A <Code>Label</Code> column, if present, is used only to measure accuracy, never as an input. Make a sample file with <Code>python -m src.api.make_sample</Code>.</p>
        </div>
        <div className="upload-action">
          <label className={`dropzone${drag ? " is-drag" : ""}${file ? " has-file" : ""}`}
            onDragOver={(e) => { e.preventDefault(); setDrag(true); }} onDragLeave={() => setDrag(false)} onDrop={onDrop}>
            <input className="visually-hidden" type="file" name="file" accept=".csv" onChange={(e) => setFile(e.target.files[0])} />
            <Icon name={file ? "file" : "upload"} size={22} />
            {file
              ? <span className="dz-main"><span className="mono">{file.name}</span><span className="dz-sub">{(file.size / 1048576).toFixed(2)} MB, choose another to replace it</span></span>
              : <span className="dz-main"><span>Choose a CSV file</span><span className="dz-sub">or drop it here</span></span>}
          </label>
          <button type="button" className="btn btn--primary" disabled={!file || busy} aria-busy={busy} onClick={run}>
            <Icon name="play" size={16} />{busy ? "Analysing…" : "Run detection"}
          </button>
        </div>
      </div>
      {err && <p className="inline-error" role="alert">The file was not analysed: {err}</p>}
    </Panel>

    {busy && <div className="skeleton" style={{ minHeight: 220 }} role="status"><span className="skeleton-text">Classifying flows…</span></div>}

    {res && <>
      <section className={`verdict ${res.n_alerts ? "is-bad" : "is-ok"}`} aria-labelledby="result-h">
        <div className="verdict-main">
          <h2 id="result-h" className="reading-label">{res.n_alerts ? "Intrusion alerts raised" : "No intrusions detected"}</h2>
          <p className={`reading ${res.n_alerts ? "tone-bad" : "tone-ok"}`}><Icon name={res.n_alerts ? "alert" : "check"} size={30} />{int(res.n_alerts)}</p>
          <p className="muted">alert{res.n_alerts === 1 ? "" : "s"} in <span className="mono">{int(res.n_scored)}</span> scored flows of <span className="mono">{res.filename}</span></p>
        </div>
        <dl className="verdict-facts">
          <div><dt>Alert rate</dt><dd><AlertRate alerts={res.n_alerts} scored={res.n_scored} /></dd></div>
          <div><dt>Top attack class</dt><dd>{topAttack(res.predicted_family_counts) || "none"}</dd></div>
          <div><dt>Unscored records</dt><dd className="mono">{int(res.n_invalid_negative_duration)}</dd></div>
          <div><dt>Audit event</dt><dd className="mono">#{res.audit_event_id}</dd></div>
        </dl>
      </section>

      <div className="grid grid--halves">
        <Panel title="Attack classification" note="Predicted class for every scored flow.">
          <ClassBars counts={res.predicted_family_counts} label="Predicted class counts" />
        </Panel>
        {gt ? (
          <Panel title="Validation against the file’s labels" note={`${int(gt.n)} labelled flows`}>
            <dl className="inline-stats inline-stats--lg">
              <div><dt>Macro-F1</dt><dd className="mono">{fmt(gt.overall.macro_f1)}</dd></div>
              <div><dt>Accuracy</dt><dd className="mono">{fmt(gt.overall.accuracy)}</dd></div>
              <div><dt>False positive rate</dt><dd className="mono">{gt.overall.fpr === undefined || gt.overall.fpr === null ? "n/a" : pct(gt.overall.fpr)}</dd></div>
            </dl>
            <Heatmap matrix={gt.confusion_matrix} labels={gt.classes} title="upload" />
          </Panel>
        ) : (
          <Panel title="Validation against the file’s labels"><p className="empty">This file has no <Code>Label</Code> column, so the predictions cannot be checked against ground truth.</p></Panel>
        )}
      </div>

      <Panel title="Flow predictions" note={`The first ${int(res.preview.length)} of ${int(res.n_flows)} flows, as returned by the detector.`} flush>
        <div className="table-tools">
          <Segmented label="Show" name="flow-filter" hideLabel value={show} onChange={(v) => { setShow(v); setPg(0); }} options={FLOW_FILTERS} />
          <Field label="Class">
            <select className="control" value={cls} onChange={(e) => { setCls(e.target.value); setPg(0); }}>
              <option value="">Every class</option>
              {classes.map((c) => <option key={c} value={c}>{c}</option>)}
            </select>
          </Field>
          <p className="table-count" role="status"><span className="mono">{int(rows.length)}</span> of <span className="mono">{int(res.preview.length)}</span> shown</p>
        </div>
        <Table caption="Flow predictions" empty="No flows in this preview match the filter." rows={pageRows} columns={[{ label: "Row", key: "row", num: true },
          { label: "Source", key: "Source IP", mono: true }, { label: "Destination", key: "Destination IP", mono: true },
          { label: "Time", key: "Timestamp", mono: true },
          { label: "Prediction", render: (r) => <Chip tone={r.predicted === "Benign" ? "ok" : r.predicted === "invalid_record" ? "neutral" : "bad"}>{r.predicted}</Chip> },
          { label: "Confidence", num: true, render: (r) => (r.confidence === null || r.confidence === undefined ? "n/a" : pct(r.confidence, 1)) }]} />
        {pages > 1 && (
          <nav className="pager" aria-label="Flow prediction pages">
            <button type="button" className="btn btn--quiet btn--sm" disabled={cur === 0} onClick={() => setPg(cur - 1)}>Previous</button>
            <span className="pager-pos">Rows <span className="mono">{int(cur * PAGE_SIZE + 1)}</span> to <span className="mono">{int(Math.min(rows.length, (cur + 1) * PAGE_SIZE))}</span> of <span className="mono">{int(rows.length)}</span></span>
            <button type="button" className="btn btn--quiet btn--sm" disabled={cur >= pages - 1} onClick={() => setPg(cur + 1)}>Next</button>
          </nav>
        )}
      </Panel>
    </>}

    {!res && !busy && <p className="fine">Past scans are listed under <a href="#Detection%20history" onClick={navTo("Detection history")}>Detection history</a>.</p>}
  </>;
}

/* ------------------------------------------------------- Detection history */

export function History() {
  const q = useApi("/api/detections?limit=200");
  const [sel, setSel] = useState(null);
  useThemeKey();
  return <Status q={q} height={300}>{(h) => {
    if (!h.length) return (
      <section className="hero-empty">
        <Icon name="file" size={28} />
        <div><h2>No scans yet</h2><p>Every file analysed on the Detection page is recorded here with its alerts and audit trail.</p></div>
        <a className="btn btn--primary" href="#Detection" onClick={navTo("Detection")}><Icon name="upload" size={16} />Analyse traffic</a>
      </section>
    );
    const cur = h.find((d) => d.id === sel) || h[0];
    const flows = h.reduce((a, d) => a + d.n_flows, 0), alerts = h.reduce((a, d) => a + d.n_alerts, 0);
    return <>
      <Stats items={[
        { label: "Scans", value: int(h.length), note: h.length === 200 ? "Latest 200" : undefined },
        { label: "Flows analysed", value: int(flows) },
        { label: "Alerts", value: int(alerts), tone: alerts ? "bad" : "ok" },
        { label: "Scans with alerts", value: int(h.filter((d) => d.n_alerts > 0).length) },
      ]} />
      <div className="grid grid--third-right">
        <Panel title="Scans" note="Newest first. Select a scan to see its breakdown." flush>
          <div className="table-wrap" tabIndex={0} role="region" aria-label="Scans">
            <table className="select-table">
              <caption className="visually-hidden">Detection history</caption>
              <thead><tr><th scope="col" className="num">ID</th><th scope="col">Time</th><th scope="col">File</th><th scope="col" className="num">Flows</th><th scope="col" className="num">Alerts</th><th scope="col">Alert rate</th><th scope="col">Top attack</th></tr></thead>
              <tbody>{h.map((d) => (
                <tr key={d.id} className={cur.id === d.id ? "is-selected" : ""}>
                  <td className="num"><button type="button" className="row-btn" aria-pressed={cur.id === d.id} onClick={() => setSel(d.id)}><span className="visually-hidden">Show scan </span>{d.id}</button></td>
                  <td className="mono"><span className="nowrap" title={when(d.created_at)}>{whenShort(d.created_at)}</span></td>
                  <td className="mono"><span title={d.filename}>{clip(d.filename, 22)}</span></td>
                  <td className="num">{int(d.n_flows)}</td>
                  <td className="num">{int(d.n_alerts)}</td>
                  <td><AlertRate alerts={d.n_alerts} scored={d.n_scored} /></td>
                  <td>{topAttack(d.summary?.predicted_family_counts) ? <Chip tone="bad">{topAttack(d.summary.predicted_family_counts)}</Chip> : <Chip tone="ok">None</Chip>}</td>
                </tr>
              ))}</tbody>
            </table>
          </div>
        </Panel>
        <Panel title={`Scan #${cur.id}`} note={when(cur.created_at)}>
          <dl className="kv kv--stack">
            <div><dt>File</dt><dd className="mono">{cur.filename}</dd></div>
            <div><dt>SHA-256</dt><dd className="mono hash">{cur.file_sha256}</dd></div>
            <div><dt>Model</dt><dd className="mono">{fileName(cur.model)}</dd></div>
            <div><dt>Flows, scored, alerts</dt><dd className="mono">{int(cur.n_flows)}, {int(cur.n_scored)}, {int(cur.n_alerts)}</dd></div>
            <div><dt>Unscored records</dt><dd className="mono">{int(cur.summary?.n_invalid_negative_duration)}</dd></div>
            <div><dt>Value corrections</dt><dd className="mono">{int(cur.summary?.value_corrections)}</dd></div>
            <div><dt>Accuracy vs file labels</dt><dd className="mono">{cur.summary?.ground_truth_macro_f1 === undefined || cur.summary?.ground_truth_macro_f1 === null ? "no labels" : `macro-F1 ${fmt(cur.summary.ground_truth_macro_f1)}`}</dd></div>
          </dl>
          {cur.summary?.predicted_family_counts && <ClassBars counts={cur.summary.predicted_family_counts} label={`Predicted classes for scan ${cur.id}`} />}
        </Panel>
      </div>
    </>;
  }}</Status>;
}

/* ------------------------------------------------------------------- Graph */

export function GraphPage() {
  // merge_factor stays at 1 (real endpoints); the aggregation control is a research view (see research.jsx).
  const [p, setP] = useState({ day: "2017-07-05", start: "10:40", minutes: 5, max_nodes: 60, merge_factor: 1 });
  const [qp, setQp] = useState(p);
  const q = useApi(`/api/graph?${new URLSearchParams(qp)}`);
  const set = (k) => (e) => setP({ ...p, [k]: e.target.value });
  const dirty = JSON.stringify(p) !== JSON.stringify(qp);
  return <>
    <form className="toolbar" onSubmit={(e) => { e.preventDefault(); setQp(p); }}>
      <Field label="Capture day"><select className="control" name="day" value={p.day} onChange={set("day")}>{["03", "04", "05", "06", "07"].map((x) => <option key={x}>{`2017-07-${x}`}</option>)}</select></Field>
      <Field label="Start time"><input className="control control--s" name="start" value={p.start} onChange={set("start")} size={5} inputMode="numeric" autoComplete="off" /></Field>
      <Field label="Window (minutes)"><input className="control control--s" name="minutes" type="number" min={1} max={60} value={p.minutes} onChange={set("minutes")} /></Field>
      <Field label="Max hosts"><input className="control control--s" name="max_nodes" type="number" min={5} max={300} value={p.max_nodes} onChange={set("max_nodes")} /></Field>
      <button type="submit" className="btn btn--primary" disabled={q.loading && !dirty}>{q.loading ? "Building…" : "Show traffic"}</button>
    </form>

    <Status q={q} height={560} loadingText="Building the traffic graph for this window">{(g) => (
      <div className="graph-layout">
        <div className="graph-main">
          {g.nodes.length ? <Graph nodes={g.nodes} edges={g.edges} /> : <p className="empty">No flows in this window. Try another start time or a longer window.</p>}
        </div>
        <aside className="graph-side">
          <dl className="side-stats">
            <div><dt>Flows in window</dt><dd className="mono">{int(g.flows)}</dd></div>
            <div><dt>Between shown hosts</dt><dd className="mono">{int(g.flows_shown)}</dd></div>
            <div><dt>Hosts, connections</dt><dd className="mono">{int(g.nodes.length)}, {int(g.edges.length)}</dd></div>
          </dl>
          <div>
            <h3 className="side-h">Traffic classes</h3>
            <ul className="chips">{Object.entries(g.family_counts).map(([k, v]) => <li key={k}><Chip tone={k === "Benign" ? "ok" : "bad"}>{k} <span className="mono">{int(v)}</span></Chip></li>)}</ul>
          </div>
          <div>
            <h3 className="side-h">Colour</h3>
            <div className="ramp" aria-hidden="true"><span /><span /><span /><span /><span /></div>
            <p className="ramp-labels"><span>Benign</span><span>Attack share</span><span>Attack</span></p>
          </div>
          <p className="fine">Recorded CICIDS2017 traffic, not a live feed. Nodes are IP hosts sized by flow count; arrows are directed connections coloured by their share of labelled attack flows.
            Times are 24-hour local capture time.</p>
        </aside>
      </div>
    )}</Status>
  </>;
}

/* ----------------------------------------------------------- Training data */

export function TrainingData() {
  const q = useApi("/api/dataset");
  useThemeKey();
  return <Status q={q} height={420}>{(d) => {
    const s = d.dataset_stats, p = d.preprocessing;
    const checks = Object.entries(p.expected_count_checks);
    const passed = checks.filter(([, v]) => v.observed === v.expected).length;
    const fam = Object.entries(s.label_family).sort((a, b) => a[1] - b[1]);
    return <>
      <Stats items={[
        { label: "Labelled flows", value: int(s.rows), note: "CICIDS2017, five capture days" },
        { label: "Hosts", value: int(s.unique_endpoints) },
        { label: "Traffic classes", value: int(fam.length) },
        { label: "Data checks passed", value: `${passed} / ${checks.length}`, tone: passed === checks.length ? "ok" : "bad" },
      ]} />
      <div className="grid grid--halves">
        <Panel title="Traffic composition" note="Flows per class in the data the detector learned from. Log scale.">
          <Plot height={360} label="Training flows by class, log scale" data={[{ type: "bar", orientation: "h",
            y: fam.map((r) => r[0]), x: fam.map((r) => r[1]), marker: { color: fam.map((r) => familyColor(r[0])) }, text: fam.map((r) => int(r[1])), textposition: "outside", cliponaxis: false,
            hovertemplate: "%{y}: %{x:,} flows<extra></extra>" }]}
            layout={{ xaxis: { type: "log", title: "flows" }, yaxis: { showgrid: false }, margin: { l: 8, r: 64, t: 8, b: 8 } }} />
        </Panel>
        <Panel title="Data quality checks" note="Asserted by the preprocessing pipeline on every run." flush>
          <Table caption="Data quality checks" rows={checks.map(([k, v]) => ({ k, ...v }))} columns={[
            { label: "Check", key: "k", render: (r) => <Code>{r.k}</Code> },
            { label: "Observed", num: true, render: (r) => int(r.observed) },
            { label: "Expected", num: true, render: (r) => int(r.expected) },
            { label: "Result", render: (r) => (r.observed === r.expected ? <Chip tone="ok"><Icon name="check" size={14} />Pass</Chip> : <Chip tone="bad"><Icon name="cross" size={14} />Fail</Chip>) }]} />
        </Panel>
      </div>
      <Note>
        <p><strong>Identity fields are never model inputs.</strong> The detector classifies flows from their traffic features only, so it does not learn to trust or distrust particular hosts.</p>
        <ul className="chips">{[...d.identity_columns_never_features, "Label", "flow_uid"].map((c) => <li key={c}><Chip>{c}</Chip></li>)}</ul>
      </Note>
    </>;
  }}</Status>;
}

/* ------------------------------------------------------------------- Audit */

export function Audit() {
  const q = useApi("/api/audit/records?limit=200");
  const v = useApi("/api/audit/verify", [q.data]);
  const [demo, setDemo] = useState(null), [cp, setCp] = useState({ id: "", hash: "" }), [cpRes, setCpRes] = useState(null);
  const [demoBusy, setDemoBusy] = useState(false), [actErr, setActErr] = useState(null);
  const runDemo = async () => {
    setDemoBusy(true); setActErr(null);
    try { setDemo(await api("/api/audit/demo", { method: "POST" })); window.dispatchEvent(new Event("gs-audit-changed")); } catch (e) { setActErr(e.message); }
    setDemoBusy(false);
  };
  const checkCp = async (e) => {
    if (e) e.preventDefault();
    setActErr(null);
    try { setCpRes(await api(`/api/audit/verify?checkpoint_event_id=${cp.id}&checkpoint_hash=${cp.hash}`)); } catch (e2) { setActErr(e2.message); }
  };
  return <>
    <Status q={v} height={200}>{(r) => (
      <section className={`chain-panel ${r.valid ? "is-ok" : "is-bad"}`} aria-labelledby="chain-h">
        <div className="chain-verdict">
          <h2 id="chain-h" className="reading-label">Log integrity</h2>
          <p className={`reading ${r.valid ? "tone-ok" : "tone-bad"}`}><Icon name={r.valid ? "check" : "alert"} size={32} />{r.valid ? "Verified" : "Tampered"}</p>
          <p className="muted"><span className="mono">{int(r.records)}</span> records checked</p>
        </div>
        <dl className="chain-facts">
          <div><dt>Head hash</dt><dd className="mono hash">{r.head_hash}</dd></div>
          <div><dt>Rule</dt><dd>H<sub>i</sub> = SHA256(H<sub>i−1</sub> ‖ CanonicalRecord<sub>i</sub>), each record authenticated with HMAC-SHA256 (key outside git).</dd></div>
          <div><dt>Limit</dt><dd>Without a trusted checkpoint, deleting the newest records cannot be detected; store the head checkpoint elsewhere.</dd></div>
        </dl>
        {r.errors.length > 0 && <ul className="chain-errors">{r.errors.slice(0, 10).map((e, i) => <li key={i}><span className="mono">#{e.event_id}</span> {e.error}</li>)}</ul>}
      </section>
    )}</Status>

    {actErr && <ErrorState error={actErr} />}

    <div className="grid grid--third-left">
      <Panel title="Verify against a checkpoint" note="Paste an event id and the hash you stored for it.">
        <form className="stack" onSubmit={checkCp}>
          <Field label="Checkpoint event id"><input className="control" name="checkpoint_event_id" value={cp.id} onChange={(e) => setCp({ ...cp, id: e.target.value })} size={6} inputMode="numeric" autoComplete="off" /></Field>
          <Field label="Hash"><input className="control mono" name="checkpoint_hash" value={cp.hash} onChange={(e) => setCp({ ...cp, hash: e.target.value })} size={40} autoComplete="off" spellCheck={false} /></Field>
          <div className="row">
            <button type="submit" className="btn btn--quiet" disabled={!cp.id || !cp.hash}>Verify</button>
            {cpRes && (cpRes.valid
              ? <Chip tone="ok"><Icon name="check" size={14} />Matches</Chip>
              : <Chip tone="bad"><Icon name="cross" size={14} />{cpRes.errors.map((e) => e.error).join("; ")}</Chip>)}
          </div>
        </form>
      </Panel>
      <Panel title="Tamper demonstration" note="Runs on a temporary log, never the real one.">
        <div className="stack">
          <div className="row"><button type="button" className="btn btn--primary" onClick={runDemo} disabled={demoBusy} aria-busy={demoBusy}><Icon name="play" size={16} />{demoBusy ? "Running…" : "Run demo"}</button></div>
          {demo
            ? <Table caption="Tamper demonstration results" rows={Object.entries(demo).map(([k, r2]) => ({ k, ...r2 }))} columns={[{ label: "Scenario", key: "k", render: (r2) => <Code>{r2.k}</Code> },
                { label: "Valid", render: (r2) => (r2.valid ? <Chip tone="ok">Yes</Chip> : <Chip tone="bad">No</Chip>) },
                { label: "First invalid", num: true, render: (r2) => r2.first_invalid_event_id ?? "n/a" },
                { label: "Errors", render: (r2) => <span className="cell-prose">{[...new Set(r2.errors.map((e) => e.error))].join("; ") || "none"}</span> }]} />
            : <p className="empty">The demo writes a log, tampers with it in several ways and shows which check catches each one.</p>}
        </div>
      </Panel>
    </div>

    <Panel title="Audit records" note="Newest first." flush>
      <Status q={q} height={200}>{(d) => <Table caption="Audit records" empty="The audit log has no records yet." rows={[...d.records].reverse()} columns={[
        { label: "#", key: "event_id", num: true }, { label: "Time (UTC)", key: "timestamp", mono: true },
        { label: "Event", render: (r) => <Chip tone={r.event_type === "detection" ? "cool" : "neutral"}>{r.event_type}</Chip> },
        { label: "Details", render: (r) => <code className="details">{JSON.stringify(r.details)}</code> },
        { label: "Hash", render: (r) => <code className="ident" title={r.hash}>{r.hash.slice(0, 12)}…</code> },
        { label: "HMAC", render: (r) => <code className="ident" title={r.hmac}>{r.hmac.slice(0, 12)}…</code> }]} />}</Status>
    </Panel>
  </>;
}

export const PAGES = { Overview, Detection, "Detection history": History, "Network graph": GraphPage,
  "Training data": TrainingData, "Security audit": Audit };
export const usePages = () => useMemo(() => PAGES, []);
