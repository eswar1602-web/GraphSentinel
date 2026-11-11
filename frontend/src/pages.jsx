import { useMemo, useState } from "react";
import { api, fmt, pct, int, meanStd } from "./api";
import { useApi } from "./hooks";
import { Graph, Heatmap, Kpi, Plot, Status, Table } from "./components";

const EXPERIMENTS = ["primary_family_default", "primary_family_dstport", "dayholdout_binary_default",
  "dayholdout_binary_dstport", "primary_family_default_dominant_pair_ablation"];
const m = (s) => (s && s.mean !== undefined ? s.mean : null);

export function Overview() {
  const q = useApi("/api/overview");
  return <Status q={q}>{(d) => (
    <>
      <div className="kpis">
        <Kpi label="flows (processed v1)" value={int(d.rows)} note={`contract ${d.contract_version} · data ${d.data_version}`} />
        <Kpi label="result files indexed" value={d.result_files} />
        <Kpi label="detections run" value={d.detections} />
        <Kpi label="audit chain" value={d.audit.valid ? "valid" : "INVALID"} note={`${d.audit.records} records`} />
      </div>
      <div className="warn">
        <b>Threat to validity: NAT endpoint concentration.</b> {pct(d.dominant_pair.attack_share_on_pair)} of attack flows lie on
        the single pair 172.16.0.1 → 192.168.10.50, and {pct(d.dominant_pair.attack_fraction_within_pair)} of that pair's flows
        are attacks. The original data is the <code>native_identity_baseline</code> (merge factor 1), not an un-aggregated network.
        Every comparison below also shows off-pair results.
      </div>
      <h3>Best test macro-F1 per experiment (mean over seeds)</h3>
      <Table rows={Object.entries(d.best_by_experiment).map(([k, v]) => ({ exp: k, ...v }))} columns={[
        { label: "experiment", key: "exp" }, { label: "model", key: "model" },
        { label: "macro-F1", num: true, render: (r) => (r.n_seeds === 1 ? `${fmt(r.macro_f1)} (1 seed)` : `${fmt(r.macro_f1)} ± ${fmt(r.macro_f1_std)}`) },
        { label: "FPR", num: true, render: (r) => pct(r.fpr) }]} />
      <p className="muted">Primary-split and day-holdout results answer different questions and are never pooled.</p>
      <h3>Flows by family</h3>
      <Plot data={[{ type: "bar", x: Object.keys(d.label_family), y: Object.values(d.label_family) }]} layout={{ yaxis: { type: "log", title: "flows (log)" } }} />
    </>)}</Status>;
}

export function Dataset() {
  const q = useApi("/api/dataset");
  return <Status q={q}>{(d) => {
    const s = d.dataset_stats, p = d.preprocessing;
    const fams = Object.keys(d.split_primary.counts_label_family);
    return <>
      <div className="kpis">
        <Kpi label="flows" value={int(s.rows)} /><Kpi label="endpoints" value={int(s.unique_endpoints)} />
        <Kpi label="timestamps corrected" value={int(p.expected_count_checks.timestamp_corrected_rows.observed)} note="12-hour clock, hours 1–5 → +12" />
        <Kpi label="removed rows" value={int(Object.values(p.removed_rows_by_reason).reduce((a, b) => a + b, 0))} />
      </div>
      <h3>Contract count checks (asserted by the pipeline)</h3>
      <Table rows={Object.entries(p.expected_count_checks).map(([k, v]) => ({ k, ...v }))} columns={[
        { label: "check", key: "k" }, { label: "observed", num: true, render: (r) => int(r.observed) },
        { label: "expected", num: true, render: (r) => int(r.expected) }, { label: "ok", render: (r) => (r.observed === r.expected ? "✓" : "✗") }]} />
      <h3>Family counts per split</h3>
      {["primary", "dayholdout"].map((sc) => (
        <div key={sc}><h4>{sc} split ({Object.entries(d[`split_${sc}`].rows_by_split).map(([k, v]) => `${k}: ${int(v)}`).join(" · ")})</h4>
          <Plot height={300} data={["train", "val", "test", "purged"].map((sp) => ({ type: "bar", name: sp, x: fams,
            y: fams.map((f) => d[`split_${sc}`].counts_label_family[f]?.[sp] || 0) }))} layout={{ barmode: "group", yaxis: { type: "log" } }} />
          <p className="muted">Without purge gap (weaker temporal protection): {d[`split_${sc}`].groups_without_purge_gap.join("; ") || "none"}.
            {d[`split_${sc}`].groups_minute_boundary?.length ? ` Whole-minute-boundary groups: ${d[`split_${sc}`].groups_minute_boundary.join("; ")}.` : ""}</p>
        </div>))}
      <h3>Exact cross-label feature collisions</h3>
      <Table rows={["default", "dstport"].map((k) => ({ k, ...s.label_collisions[k] }))} columns={[
        { label: "feature set", key: "k" }, { label: "groups", num: true, key: "groups" }, { label: "rows", num: true, render: (r) => int(r.rows) },
        { label: "PortScan rows identical to a BENIGN flow", num: true, render: (r) => `${int(r.portscan_rows_colliding_with_benign)} / ${int(r.portscan_rows_total)}` }]} />
      <p className="muted">Never used as features: {d.identity_columns_never_features.join(", ")}, Label, flow_uid. Destination Port is excluded from the default set (E-PS1 ablation).</p>
    </>;
  }}</Status>;
}

export function Detection() {
  const [file, setFile] = useState(null);
  const [res, setRes] = useState(null);
  const [err, setErr] = useState(null);
  const [busy, setBusy] = useState(false);
  const hist = useApi("/api/detections", [res]);
  const run = async () => {
    if (!file) return;
    setBusy(true); setErr(null); setRes(null);
    const fd = new FormData(); fd.append("file", file);
    try { setRes(await api("/api/detect", { method: "POST", body: fd })); } catch (e) { setErr(e.message); }
    setBusy(false);
  };
  return <>
    <p>Upload CICIDS2017-format flow records (CSV, ≤ 25 MB, ≤ 200k rows). Flows are scored by the saved XGBoost model of
      <code> primary_family_default</code> (no Destination Port), using the Milestone-1 corrections and train-only transforms.
      A <code>Label</code> column, if present, is used only to report accuracy. Make a real sample with
      <code> python -m src.api.make_sample</code>.</p>
    <div className="row"><input type="file" accept=".csv" onChange={(e) => setFile(e.target.files[0])} />
      <button disabled={!file || busy} onClick={run}>{busy ? "Scoring…" : "Detect"}</button></div>
    {err && <p className="error">{err}</p>}
    {res && <>
      <div className="kpis"><Kpi label="flows" value={int(res.n_flows)} /><Kpi label="scored" value={int(res.n_scored)} />
        <Kpi label="alerts" value={int(res.n_alerts)} /><Kpi label="audit event" value={`#${res.audit_event_id}`} note={res.file_sha256.slice(0, 16) + "…"} /></div>
      <Plot height={280} data={[{ type: "bar", x: Object.keys(res.predicted_family_counts), y: Object.values(res.predicted_family_counts) }]} layout={{ title: { text: "predicted family" } }} />
      {res.ground_truth_evaluation && <>
        <h3>Against the file's own labels (n = {int(res.ground_truth_evaluation.n)})</h3>
        <p>macro-F1 {fmt(res.ground_truth_evaluation.overall.macro_f1)} · accuracy {fmt(res.ground_truth_evaluation.overall.accuracy)} · FPR {pct(res.ground_truth_evaluation.overall.fpr)}</p>
        <Heatmap matrix={res.ground_truth_evaluation.confusion_matrix} labels={res.ground_truth_evaluation.classes} title="confusion matrix (upload)" />
      </>}
      <h3>First rows</h3>
      <Table rows={res.preview.slice(0, 50)} columns={[{ label: "row", key: "row", num: true }, { label: "source", key: "Source IP" },
        { label: "destination", key: "Destination IP" }, { label: "time", key: "Timestamp" }, { label: "predicted", key: "predicted" },
        { label: "confidence", num: true, render: (r) => fmt(r.confidence) }]} />
    </>}
    <h3>Detection history</h3>
    <Status q={hist}>{(h) => <Table rows={h} columns={[{ label: "id", key: "id", num: true }, { label: "time (UTC)", key: "created_at" },
      { label: "file", key: "filename" }, { label: "flows", num: true, render: (r) => int(r.n_flows) }, { label: "alerts", num: true, render: (r) => int(r.n_alerts) },
      { label: "GT macro-F1", num: true, render: (r) => fmt(r.summary.ground_truth_macro_f1) }]} />}</Status>
  </>;
}

export function GraphPage() {
  const [p, setP] = useState({ day: "2017-07-05", start: "10:40", minutes: 5, max_nodes: 60, merge_factor: 1 });
  const [qp, setQp] = useState(p);
  const q = useApi(`/api/graph?${new URLSearchParams(qp)}`);
  const set = (k) => (e) => setP({ ...p, [k]: e.target.value });
  return <>
    <div className="row">
      <label>day <select value={p.day} onChange={set("day")}>{["03", "04", "05", "06", "07"].map((x) => <option key={x}>{`2017-07-${x}`}</option>)}</select></label>
      <label>start <input value={p.start} onChange={set("start")} size={5} /></label>
      <label>minutes <input type="number" min={1} max={60} value={p.minutes} onChange={set("minutes")} /></label>
      <label>max nodes <input type="number" min={5} max={300} value={p.max_nodes} onChange={set("max_nodes")} /></label>
      <label>merge factor <select value={p.merge_factor} onChange={set("merge_factor")}>{[1, 2, 4, 8, 16, 32].map((x) => <option key={x}>{x}</option>)}</select></label>
      <button onClick={() => setQp(p)}>Show</button>
    </div>
    <p className="muted">Real flows from the processed dataset in the chosen window. Nodes = endpoints (or synthetic buckets when
      merge factor &gt; 1); colour = attack fraction (blue benign → red attack). Times are corrected 24-hour local capture time.</p>
    <Status q={q}>{(g) => <>
      <p>{int(g.flows)} flows in window, {int(g.flows_shown)} among the shown nodes. Families: {Object.entries(g.family_counts).map(([k, v]) => `${k} ${int(v)}`).join(" · ")}</p>
      {g.nodes.length ? <Graph nodes={g.nodes} edges={g.edges} /> : <p className="muted">No flows in this window.</p>}
    </>}</Status>
  </>;
}

export function Aggregation() {
  const q = useApi("/api/aggregation/structure");
  const [k, setK] = useState(4), [seed, setSeed] = useState(2017), [sim, setSim] = useState(null), [err, setErr] = useState(null);
  const run = async () => { setErr(null); try { setSim(await api(`/api/aggregation/simulate?merge_factor=${k}&seed=${seed}`)); } catch (e) { setErr(e.message); } };
  return <>
    <div className="warn">The simulator is a controlled identity-collision stress test, not a NAT emulator. Merge factor 1 is the
      <code> native_identity_baseline</code> (already NAT-aggregated); higher factors add synthetic aggregation with one shared seeded mapping.</div>
    <Status q={q}>{(s) => {
      const L = Object.values(s.levels), x = L.map((l) => (l.merge_factor === 1 ? "×1 native" : `×${l.merge_factor}`));
      return <>
        <div className="grid2">
          <Plot height={280} data={[{ x, y: L.map((l) => l.buckets), name: "nodes/buckets", mode: "lines+markers" },
            { x, y: L.map((l) => l.all_flows.unique_directed_pairs), name: "unique directed pairs", mode: "lines+markers" }]}
            layout={{ xaxis: { type: "category", title: "merge factor" }, yaxis: { type: "log" }, title: { text: "graph size" } }} />
          <Plot height={280} data={[{ x, y: L.map((l) => l.neighbourhood_change.mean_jaccard), name: "mean neighbourhood Jaccard", mode: "lines+markers" },
            { x, y: L.map((l) => l.all_flows.self_loop_flows / l.all_flows.flows), name: "self-loop flow fraction", mode: "lines+markers" },
            { x, y: L.map((l) => l.all_flows.largest_component_fraction), name: "largest component fraction", mode: "lines+markers" }]}
            layout={{ xaxis: { type: "category", title: "merge factor" }, yaxis: { range: [0, 1.05] }, title: { text: "neighbourhood change" } }} />
        </div>
        <Table rows={Object.entries(s.levels).map(([n, l]) => ({ n, ...l }))} columns={[
          { label: "level", key: "n" }, { label: "buckets", num: true, render: (r) => int(r.buckets) },
          { label: "pairs", num: true, render: (r) => int(r.all_flows.unique_directed_pairs) },
          { label: "avg degree", num: true, render: (r) => fmt(r.all_flows.avg_degree_distinct_pairs, 2) },
          { label: "density", num: true, render: (r) => r.all_flows.density.toExponential(2) },
          { label: "components", num: true, key: "x", render: (r) => int(r.all_flows.weakly_connected_components) },
          { label: "self-loop flows", num: true, render: (r) => int(r.all_flows.self_loop_flows) },
          { label: "attack flows on mixed pairs", num: true, render: (r) => int(r.label_mixing_all_flows.attack_flows_on_mixed_pairs) },
          { label: "dominant bucket pair attack fraction", num: true, render: (r) => pct(r.dominant_pair.attack_fraction_on_bucket_pair) }]} />
      </>;
    }}</Status>
    <h3>Live simulation (all {""}flows)</h3>
    <div className="row"><label>merge factor <input type="number" min={1} max={1024} value={k} onChange={(e) => setK(e.target.value)} /></label>
      <label>seed <input type="number" value={seed} onChange={(e) => setSeed(e.target.value)} /></label><button onClick={run}>Simulate</button></div>
    {err && <p className="error">{err}</p>}
    {sim && <Table rows={Object.entries(sim.structure).filter(([, v]) => typeof v !== "object").map(([k2, v]) => ({ k: k2, v }))}
      columns={[{ label: "metric", key: "k" }, { label: "value", num: true, render: (r) => (Number.isInteger(r.v) ? int(r.v) : fmt(r.v, 4)) }]} />}
  </>;
}

export function Models() {
  const [exp, setExp] = useState("primary_family_default");
  const q = useApi(`/api/results/comparison?experiment=${exp}`);
  const e1 = useApi("/api/results/eps1");
  const md = useApi(`/api/results/modes?experiment=${exp}`);
  const [sel, setSel] = useState(0);
  return <>
    <div className="row"><label>experiment <select value={exp} onChange={(e) => { setExp(e.target.value); setSel(0); }}>{EXPERIMENTS.map((x) => <option key={x}>{x}</option>)}</select></label></div>
    {exp.startsWith("dayholdout") && <div className="warn">Day-holdout (train Mon–Wed, test Thu–Fri, binary): a generalization experiment, reported separately from the primary split.</div>}
    <Status q={q}>{(d) => d.models.length ? <>
      <Table rows={d.models} columns={[{ label: "model", key: "model" }, { label: "identity-free", render: (r) => (r.identity_free ? "yes" : "no") },
        { label: "seeds", key: "n_seeds", num: true }, { label: "macro-F1", num: true, render: (r) => meanStd(r.macro_f1) },
        { label: "FPR", num: true, render: (r) => (r.fpr ? `${pct(r.fpr.mean)} ± ${pct(r.fpr.std)}` : "—") },
        { label: "macro PR-AUC", num: true, render: (r) => meanStd(r.macro_pr_auc) },
        { label: "off-pair macro-F1", num: true, render: (r) => meanStd(r.off_pair_macro_f1) },
        { label: "dedup-test macro-F1 (seed 0)", num: true, render: (r) => fmt(r.dedup_test_seed0?.macro_f1) },
        { label: "ms / 1k flows", num: true, render: (r) => fmt(r.predict_ms_per_1k_flows, 1) }]} />
      <h3>Per-class F1 (mean over seeds)</h3>
      <Plot data={d.models.map((mm) => ({ type: "bar", name: mm.model, x: mm.classes, y: mm.classes.map((c) => m(mm.per_class_f1?.[c])),
        error_y: { type: "data", array: mm.classes.map((c) => mm.per_class_f1?.[c]?.std || 0) } }))} layout={{ barmode: "group", yaxis: { range: [0, 1.05], title: "F1" } }} />
      <h3>Per-attack recall off the dominant pair (contract view 2)</h3>
      <Plot data={d.models.map((mm) => { const ks = Object.keys(mm.off_pair_per_attack_recall || {}); return { type: "bar", name: mm.model, x: ks, y: ks.map((c) => m(mm.off_pair_per_attack_recall[c])) }; })}
        layout={{ barmode: "group", yaxis: { range: [0, 1.05], title: "recall" } }} />
      <h3>Dominant vs non-dominant pair (seed 0, contract view 4)</h3>
      <Table rows={d.models.flatMap((mm) => Object.entries(mm.dominant_vs_non_dominant_seed0).map(([k, v]) => ({ model: mm.model, k, ...v })))}
        columns={[{ label: "model", key: "model" }, { label: "subset", key: "k" }, { label: "flows", num: true, render: (r) => int(r.n) },
          { label: "macro-F1", num: true, render: (r) => fmt(r.macro_f1) }, { label: "FPR", num: true, render: (r) => pct(r.fpr) }]} />
      <h3>Confusion matrix (seed 0)</h3>
      <div className="row">{d.models.map((mm, i) => <button key={mm.model} className={i === sel ? "active" : ""} onClick={() => setSel(i)}>{mm.model}</button>)}</div>
      {d.models[sel] && <Heatmap matrix={d.models[sel].confusion_matrix_seed0} labels={d.models[sel].classes} title={d.models[sel].model} />}
    </> : <p className="muted">No results yet for this experiment.</p>}</Status>
    <h3>GraphSAGE context modes (contract §6.3, native identities)</h3>
    <Status q={md}>{(d) => <Table rows={d.models.flatMap((mm) => Object.entries(mm.modes).map(([k, v]) => ({ model: mm.model, k, ...v })))}
      columns={[{ label: "model", key: "model" }, { label: "mode", key: "k" }, { label: "macro-F1", num: true, render: (r) => meanStd(r.macro_f1) },
        { label: "FPR", num: true, render: (r) => (r.fpr ? pct(r.fpr.mean) : "—") }, { label: "off-pair macro-F1", num: true, render: (r) => meanStd(r.off_pair_macro_f1) }]} />}</Status>
    <h3>E-PS1: PortScan with vs without Destination Port</h3>
    <Status q={e1}>{(d) => <>
      <Table rows={d.rows} columns={[{ label: "feature set", key: "feature_set" }, { label: "model", key: "model" },
        { label: "PortScan recall", num: true, render: (r) => meanStd(r.portscan_recall) }, { label: "PortScan F1", num: true, render: (r) => meanStd(r.portscan_f1) },
        { label: "precision (seed 0)", num: true, render: (r) => fmt(r.portscan_precision_seed0) }, { label: "macro-F1", num: true, render: (r) => meanStd(r.macro_f1) }]} />
      <p className="muted">Test PortScan flows whose exact feature vector occurs in train with another label: {Object.entries(d.test_portscan_rows_with_train_twin_of_other_label).map(([k, v]) => `${k} ${int(v)}`).join(" · ")}. {d.interpretation}</p>
    </>}</Status>
  </>;
}

export function Robustness() {
  const [exp, setExp] = useState("primary_family_default");
  const q = useApi(`/api/results/robustness?experiment=${exp}`);
  const [metric, setMetric] = useState("macro_f1");
  return <>
    <div className="row"><label>experiment <select value={exp} onChange={(e) => setExp(e.target.value)}>{EXPERIMENTS.map((x) => <option key={x}>{x}</option>)}</select></label>
      <label>metric <select value={metric} onChange={(e) => setMetric(e.target.value)}><option value="macro_f1">macro-F1</option><option value="fpr">FPR</option><option value="off_pair_macro_f1">off-pair macro-F1</option></select></label></div>
    <p className="muted">native_identity_baseline = merge factor 1 (already NAT-aggregated). Aggregation-aware models trained with merge factors 2/4/8; 16 and 32 are unseen. RF/XGBoost use no endpoint identity, so their inputs are identical at every level (flat by construction).</p>
    <Status q={q}>{(d) => {
      const lv = d.levels;
      const x = lv.map((l) => (l === "native_identity_baseline" ? 1 : Number(l.split("_").pop())));
      return d.models.length ? <>
        <Plot height={400} data={d.models.map((mm) => ({ x, y: lv.map((l) => m(mm.levels[l]?.[metric])), name: mm.model, mode: "lines+markers",
          line: { dash: mm.invariant_by_construction ? "dot" : "solid" }, error_y: { type: "data", array: lv.map((l) => mm.levels[l]?.[metric]?.std || 0) } }))}
          layout={{ xaxis: { type: "log", title: "merge factor (1 = native_identity_baseline)", tickvals: x }, yaxis: { title: metric },
            shapes: [{ type: "rect", x0: 12, x1: 40, y0: 0, y1: 1, yref: "paper", fillcolor: "rgba(220,38,38,0.07)", line: { width: 0 } }] }} />
        <Table rows={d.models} columns={[{ label: "model", key: "model" }, ...lv.map((l) => ({ label: l.replace("merge_factor_", "×"), num: true, render: (r) => meanStd(r.levels[l]?.[metric]) }))]} />
      </> : <p className="muted">No graph results for this experiment.</p>;
    }}</Status>
  </>;
}

export function Audit() {
  const q = useApi("/api/audit/records?limit=200");
  const v = useApi("/api/audit/verify", [q.data]);
  const [demo, setDemo] = useState(null), [cp, setCp] = useState({ id: "", hash: "" }), [cpRes, setCpRes] = useState(null);
  const runDemo = async () => setDemo(await api("/api/audit/demo", { method: "POST" }));
  const checkCp = async () => setCpRes(await api(`/api/audit/verify?checkpoint_event_id=${cp.id}&checkpoint_hash=${cp.hash}`));
  return <>
    <p>H<sub>i</sub> = SHA256(H<sub>i-1</sub> ‖ CanonicalRecord<sub>i</sub>), each record authenticated with HMAC-SHA256 (key outside git).
      Without a trusted checkpoint, deleting the newest records cannot be detected; store the head checkpoint elsewhere.</p>
    <Status q={v}>{(r) => <div className={r.valid ? "ok" : "error"}>Chain {r.valid ? "VALID" : "INVALID"} — {r.records} records, head {r.head_hash.slice(0, 20)}…
      {r.errors.length > 0 && <ul>{r.errors.slice(0, 10).map((e, i) => <li key={i}>#{e.event_id}: {e.error}</li>)}</ul>}</div>}</Status>
    <div className="row"><label>checkpoint event id <input value={cp.id} onChange={(e) => setCp({ ...cp, id: e.target.value })} size={6} /></label>
      <label>hash <input value={cp.hash} onChange={(e) => setCp({ ...cp, hash: e.target.value })} size={40} /></label>
      <button onClick={checkCp} disabled={!cp.id || !cp.hash}>Verify against checkpoint</button>
      {cpRes && <span className={cpRes.valid ? "ok" : "error"}>{cpRes.valid ? "matches" : cpRes.errors.map((e) => e.error).join("; ")}</span>}</div>
    <h3>Tamper demonstration (temporary log, never the real one)</h3>
    <button onClick={runDemo}>Run demo</button>
    {demo && <Table rows={Object.entries(demo).map(([k, r]) => ({ k, ...r }))} columns={[{ label: "scenario", key: "k" },
      { label: "valid", render: (r) => (r.valid ? "yes" : "no") }, { label: "first invalid", render: (r) => r.first_invalid_event_id ?? "—" },
      { label: "errors", render: (r) => [...new Set(r.errors.map((e) => e.error))].join("; ") || "—" }]} />}
    <h3>Records</h3>
    <Status q={q}>{(d) => <Table rows={[...d.records].reverse()} columns={[{ label: "#", key: "event_id", num: true }, { label: "time (UTC)", key: "timestamp" },
      { label: "type", key: "event_type" }, { label: "details", render: (r) => <code>{JSON.stringify(r.details)}</code> },
      { label: "hash", render: (r) => <code>{r.hash.slice(0, 12)}…</code> }, { label: "HMAC", render: (r) => <code>{r.hmac.slice(0, 12)}…</code> }]} />}</Status>
  </>;
}

export const PAGES = { Overview, Dataset, Detection, "Graph visualization": GraphPage, "Aggregation simulator": Aggregation,
  "Model comparison": Models, Robustness, "Audit verification": Audit };
export const usePages = () => useMemo(() => PAGES, []);
