// Research views, hidden from the operational dashboard but kept intact so they can be restored.
// They are added to the navigation only when the build sets VITE_SHOW_RESEARCH=true (see src/config.js).
// Nothing here was changed except the export names at the bottom; the backend research APIs are untouched.
import { useState } from "react";
import { api, fmt, pct, int, meanStd } from "./api";
import { useApi } from "./hooks";
import { Chip, Field, Heatmap, Note, Panel, Plot, Segmented, Stats, Status, Table } from "./components";
import { Icon } from "./icons";
import { cssColor, modelColor, useThemeKey } from "./theme";

const EXPERIMENTS = ["primary_family_default", "primary_family_dstport", "dayholdout_binary_default",
  "dayholdout_binary_dstport", "primary_family_default_dominant_pair_ablation"];
const m = (s) => (s && s.mean !== undefined ? s.mean : null);
const Code = ({ children }) => <code className="ident">{children}</code>;
const familyColor = (f) => cssColor(f === "Benign" ? "--color-accent" : "--color-bad");

function ExperimentSelect({ value, onChange }) {
  return (
    <Field label="Experiment" wide>
      <select className="control" value={value} onChange={(e) => onChange(e.target.value)}>
        {EXPERIMENTS.map((x) => <option key={x}>{x}</option>)}
      </select>
    </Field>
  );
}

/* ---------------------------------------------------------------- Overview */

export function ResearchOverview() {
  const q = useApi("/api/overview");
  useThemeKey();
  return <Status q={q} height={520}>{(d) => {
    const fams = Object.entries(d.label_family).sort((a, b) => a[1] - b[1]);
    const dp = d.dominant_pair;
    const onPair = dp.attack_rows_on_pair, elsewhere = dp.attack_rows_total - dp.attack_rows_on_pair;
    return <>
      <Stats items={[
        { label: "Flows processed", value: int(d.rows), note: `Contract ${d.contract_version}, data ${d.data_version}` },
        { label: "Result files indexed", value: int(d.result_files) },
        { label: "Detections run", value: int(d.detections) },
        { label: "Audit chain", value: d.audit.valid ? "Valid" : "Invalid", tone: d.audit.valid ? "ok" : "bad", note: `${int(d.audit.records)} records` },
      ]} />

      <section className="validity" aria-labelledby="validity-h">
        <div className="validity-copy">
          <h2 id="validity-h">Threat to validity: NAT endpoint concentration</h2>
          <p>Almost every attack flow sits on one directed pair, <span className="mono">172.16.0.1 → 192.168.10.50</span>.
            The original data is the <Code>native_identity_baseline</Code> (merge factor 1), not an un-aggregated network.
            Every comparison in this dashboard also shows off-pair results.</p>
        </div>
        <dl className="readings">
          <div><dt>Attack flows on that pair</dt><dd className="reading">{pct(dp.attack_share_on_pair)}</dd></div>
          <div><dt>Of that pair’s flows are attacks</dt><dd className="reading">{pct(dp.attack_fraction_within_pair)}</dd></div>
        </dl>
        <div className="share" aria-hidden="true">
          <span className="share-on" style={{ flexGrow: onPair }} />
          <span className="share-off" style={{ flexGrow: Math.max(elsewhere, onPair / 400) }} />
        </div>
        <p className="share-legend"><span className="mono">{int(onPair)}</span> of <span className="mono">{int(dp.attack_rows_total)}</span> attack flows are on the pair; <span className="mono">{int(elsewhere)}</span> are elsewhere.</p>
      </section>

      <div className="grid">
        <Panel title="Best test macro-F1 per experiment" note="Mean over seeds. Primary-split and day-holdout results answer different questions and are never pooled." flush>
          <Table caption="Best test macro-F1 per experiment" rows={Object.entries(d.best_by_experiment).map(([k, v]) => ({ exp: k, ...v }))} columns={[
            { label: "Experiment", key: "exp", render: (r) => <Code>{r.exp}</Code> },
            { label: "Model", key: "model", render: (r) => <Code>{r.model}</Code> },
            { label: "Macro-F1", num: true, render: (r) => (r.n_seeds === 1 ? `${fmt(r.macro_f1)} (1 seed)` : `${fmt(r.macro_f1)} ± ${fmt(r.macro_f1_std)}`) },
            { label: "FPR", num: true, render: (r) => pct(r.fpr) }]} />
        </Panel>
        <Panel title="Flows by family" note="Log scale. Benign in teal, attack families in red.">
          <Plot height={320} label="Flows by family, log scale" data={[{ type: "bar", orientation: "h", y: fams.map((f) => f[0]), x: fams.map((f) => f[1]),
            marker: { color: fams.map((f) => familyColor(f[0])) }, text: fams.map((f) => int(f[1])), textposition: "outside", cliponaxis: false,
            textfont: { size: 11 }, hovertemplate: "%{y}: %{x:,} flows<extra></extra>" }]}
            layout={{ xaxis: { type: "log", title: "flows", showgrid: true }, yaxis: { showgrid: false }, margin: { l: 8, r: 56, t: 8, b: 8 } }} />
        </Panel>
      </div>
    </>;
  }}</Status>;
}

/* ----------------------------------------------------------------- Dataset */

export function ResearchDataset() {
  const q = useApi("/api/dataset");
  useThemeKey();
  return <Status q={q} height={520}>{(d) => {
    const s = d.dataset_stats, p = d.preprocessing;
    const fams = Object.keys(d.split_primary.counts_label_family);
    const splits = ["train", "val", "test", "purged"];
    return <>
      <Stats items={[
        { label: "Flows", value: int(s.rows) },
        { label: "Endpoints", value: int(s.unique_endpoints) },
        { label: "Timestamps corrected", value: int(p.expected_count_checks.timestamp_corrected_rows.observed), note: "12-hour clock: hours 1 to 5 shifted by 12" },
        { label: "Rows removed", value: int(Object.values(p.removed_rows_by_reason).reduce((a, b) => a + b, 0)) },
      ]} />

      <Panel title="Contract count checks" note="Asserted by the pipeline on every run." flush>
        <Table caption="Contract count checks" rows={Object.entries(p.expected_count_checks).map(([k, v]) => ({ k, ...v }))} columns={[
          { label: "Check", key: "k", render: (r) => <Code>{r.k}</Code> },
          { label: "Observed", num: true, render: (r) => int(r.observed) },
          { label: "Expected", num: true, render: (r) => int(r.expected) },
          { label: "Result", render: (r) => (r.observed === r.expected ? <Chip tone="ok"><Icon name="check" size={14} />Pass</Chip> : <Chip tone="bad"><Icon name="cross" size={14} />Fail</Chip>) }]} />
      </Panel>

      <h2 className="section-head">Family counts per split</h2>
      <div className="grid grid--halves">
        {["primary", "dayholdout"].map((sc) => {
          const sp = d[`split_${sc}`];
          return (
            <Panel key={sc} title={sc === "primary" ? "Primary split" : "Day-holdout split"}>
              <dl className="inline-stats">
                {Object.entries(sp.rows_by_split).map(([k, v]) => <div key={k}><dt>{k}</dt><dd className="mono">{int(v)}</dd></div>)}
              </dl>
              <Plot height={300} label={`${sc} split family counts, log scale`} data={splits.map((x, i) => ({ type: "bar", name: x, x: fams,
                y: fams.map((f) => sp.counts_label_family[f]?.[x] || 0), marker: { color: cssColor(`--series-split-${i + 1}`) } }))}
                layout={{ barmode: "group", yaxis: { type: "log", title: "flows" }, xaxis: { showgrid: false, tickangle: -30 } }} />
              <p className="fine">Without purge gap (weaker temporal protection): {sp.groups_without_purge_gap.join("; ") || "none"}.
                {sp.groups_minute_boundary?.length ? ` Whole-minute-boundary groups: ${sp.groups_minute_boundary.join("; ")}.` : ""}</p>
            </Panel>
          );
        })}
      </div>

      <Panel title="Exact cross-label feature collisions" note="Rows whose feature vectors are identical but whose labels differ." flush>
        <Table caption="Exact cross-label feature collisions" rows={["default", "dstport"].map((k) => ({ k, ...s.label_collisions[k] }))} columns={[
          { label: "Feature set", key: "k", render: (r) => <Code>{r.k}</Code> },
          { label: "Groups", num: true, render: (r) => int(r.groups) },
          { label: "Rows", num: true, render: (r) => int(r.rows) },
          { label: "PortScan rows identical to a benign flow", num: true, render: (r) => `${int(r.portscan_rows_colliding_with_benign)} / ${int(r.portscan_rows_total)}` }]} />
      </Panel>

      <Note>
        <p><strong>Never used as features:</strong></p>
        <ul className="chips">{[...d.identity_columns_never_features, "Label", "flow_uid"].map((c) => <li key={c}><Chip>{c}</Chip></li>)}</ul>
        <p className="muted">Destination Port is excluded from the default feature set (E-PS1 ablation).</p>
      </Note>
    </>;
  }}</Status>;
}

/* ------------------------------------------------------------- Aggregation */

export function Aggregation() {
  const q = useApi("/api/aggregation/structure");
  const [k, setK] = useState(4), [seed, setSeed] = useState(2017), [sim, setSim] = useState(null), [err, setErr] = useState(null), [busy, setBusy] = useState(false);
  useThemeKey();
  const run = async (e) => {
    if (e) e.preventDefault();
    setErr(null); setBusy(true);
    try { setSim(await api(`/api/aggregation/simulate?merge_factor=${k}&seed=${seed}`)); } catch (e2) { setErr(e2.message); }
    setBusy(false);
  };
  return <>
    <Note tone="warn">
      <p>The simulator is a controlled identity-collision stress test, not a NAT emulator. Merge factor 1 is
        the <Code>native_identity_baseline</Code> (already NAT-aggregated); higher factors add synthetic aggregation with one shared seeded mapping.</p>
    </Note>
    <Status q={q} height={420}>{(s) => {
      const L = Object.values(s.levels), x = L.map((l) => (l.merge_factor === 1 ? "×1 native" : `×${l.merge_factor}`));
      const line = (name, y, color, dash) => ({ x, y, name, mode: "lines+markers", line: { color, width: 2, dash }, marker: { color, size: 7 } });
      return <>
        <div className="grid grid--halves">
          <Panel title="Graph size" note="Log scale.">
            <Plot height={300} label="Graph size by merge factor" data={[
              line("Nodes or buckets", L.map((l) => l.buckets), cssColor("--series-sage-1")),
              line("Unique directed pairs", L.map((l) => l.all_flows.unique_directed_pairs), cssColor("--series-agg-2"))]}
              layout={{ xaxis: { type: "category", title: "merge factor" }, yaxis: { type: "log" } }} />
          </Panel>
          <Panel title="Neighbourhood change" note="Fractions from 0 to 1.">
            <Plot height={300} label="Neighbourhood change by merge factor" data={[
              line("Mean neighbourhood Jaccard", L.map((l) => l.neighbourhood_change.mean_jaccard), cssColor("--series-sage-1")),
              line("Self-loop flow fraction", L.map((l) => l.all_flows.self_loop_flows / l.all_flows.flows), cssColor("--color-bad")),
              line("Largest component fraction", L.map((l) => l.all_flows.largest_component_fraction), cssColor("--series-agg-2"), "dot")]}
              layout={{ xaxis: { type: "category", title: "merge factor" }, yaxis: { range: [0, 1.05] } }} />
          </Panel>
        </div>
        <Panel title="Structure per level" flush>
          <Table caption="Graph structure per aggregation level" rows={Object.entries(s.levels).map(([n, l]) => ({ n, ...l }))} columns={[
            { label: "Level", key: "n", render: (r) => <Code>{r.n}</Code> }, { label: "Buckets", num: true, render: (r) => int(r.buckets) },
            { label: "Pairs", num: true, render: (r) => int(r.all_flows.unique_directed_pairs) },
            { label: "Avg degree", num: true, render: (r) => fmt(r.all_flows.avg_degree_distinct_pairs, 2) },
            { label: "Density", num: true, render: (r) => r.all_flows.density.toExponential(2) },
            { label: "Components", num: true, key: "x", render: (r) => int(r.all_flows.weakly_connected_components) },
            { label: "Self-loop flows", num: true, render: (r) => int(r.all_flows.self_loop_flows) },
            { label: "Attack flows on mixed pairs", num: true, render: (r) => int(r.label_mixing_all_flows.attack_flows_on_mixed_pairs) },
            { label: "Dominant bucket pair attack fraction", num: true, render: (r) => pct(r.dominant_pair.attack_fraction_on_bucket_pair) }]} />
        </Panel>
      </>;
    }}</Status>

    <Panel title="Live simulation on all flows" note="Runs the simulator in the backend with your merge factor and seed.">
      <form className="toolbar toolbar--flat" onSubmit={run}>
        <Field label="Merge factor"><input className="control control--s" name="merge_factor" type="number" min={1} max={1024} value={k} onChange={(e) => setK(e.target.value)} /></Field>
        <Field label="Seed"><input className="control control--s" name="seed" type="number" value={seed} onChange={(e) => setSeed(e.target.value)} /></Field>
        <button type="submit" className="btn btn--primary" disabled={busy} aria-busy={busy}><Icon name="play" size={16} />{busy ? "Simulating…" : "Simulate"}</button>
      </form>
      {err && <p className="inline-error" role="alert">The simulation did not run: {err}</p>}
      {sim && (
        <dl className="metric-grid">
          {Object.entries(sim.structure).filter(([, v]) => typeof v !== "object").map(([k2, v]) => (
            <div key={k2}><dt><Code>{k2}</Code></dt><dd className="mono">{Number.isInteger(v) ? int(v) : fmt(v, 4)}</dd></div>
          ))}
        </dl>
      )}
      {!sim && !err && <p className="empty">No simulation yet. Pick a merge factor and a seed, then simulate.</p>}
    </Panel>
  </>;
}

/* ------------------------------------------------------------------ Models */

export function Models() {
  const [exp, setExp] = useState("primary_family_default");
  const q = useApi(`/api/results/comparison?experiment=${exp}`);
  const e1 = useApi("/api/results/eps1");
  const md = useApi(`/api/results/modes?experiment=${exp}`);
  const [sel, setSel] = useState(0);
  useThemeKey();
  return <>
    <div className="toolbar">
      <ExperimentSelect value={exp} onChange={(v) => { setExp(v); setSel(0); }} />
    </div>
    {exp.startsWith("dayholdout") && <Note tone="warn"><p>Day-holdout (train Monday to Wednesday, test Thursday and Friday, binary) is a generalization experiment, reported separately from the primary split.</p></Note>}

    <Status q={q} height={420}>{(d) => d.models.length ? <>
      <Panel title="Test results by model" note="Mean ± std over seeds, unless marked as one seed." flush>
        <Table caption="Test results by model" rows={d.models} columns={[
          { label: "Model", key: "model", render: (r) => <span className="model-cell"><span className="swatch" style={{ background: modelColor(r.model) }} /><Code>{r.model}</Code></span> },
          { label: "Identity-free", render: (r) => (r.identity_free ? <Chip tone="ok">Yes</Chip> : <Chip>No</Chip>) },
          { label: "Seeds", key: "n_seeds", num: true }, { label: "Macro-F1", num: true, render: (r) => meanStd(r.macro_f1) },
          { label: "FPR", num: true, render: (r) => (r.fpr ? `${pct(r.fpr.mean)} ± ${pct(r.fpr.std)}` : "n/a") },
          { label: "Macro PR-AUC", num: true, render: (r) => meanStd(r.macro_pr_auc) },
          { label: "Off-pair macro-F1", num: true, render: (r) => meanStd(r.off_pair_macro_f1) },
          { label: "Dedup-test macro-F1 (seed 0)", num: true, render: (r) => fmt(r.dedup_test_seed0?.macro_f1) },
          { label: "ms per 1k flows", num: true, render: (r) => fmt(r.predict_ms_per_1k_flows, 1) }]} />
      </Panel>

      <div className="grid grid--halves">
        <Panel title="Per-class F1" note="Mean over seeds; whiskers show the spread.">
          <Plot height={360} label="Per-class F1 by model" data={d.models.map((mm, i) => ({ type: "bar", name: mm.model, x: mm.classes, y: mm.classes.map((c) => m(mm.per_class_f1?.[c])),
            marker: { color: modelColor(mm.model, i) }, error_y: { type: "data", array: mm.classes.map((c) => mm.per_class_f1?.[c]?.std || 0), color: cssColor("--color-muted"), thickness: 1, width: 2 } }))}
            layout={{ barmode: "group", yaxis: { range: [0, 1.05], title: "F1" }, xaxis: { showgrid: false, tickangle: -30 } }} />
        </Panel>
        <Panel title="Per-attack recall off the dominant pair" note="Contract view 2: attacks that do not use the NAT pair.">
          <Plot height={360} label="Off-pair per-attack recall by model" data={d.models.map((mm, i) => { const ks = Object.keys(mm.off_pair_per_attack_recall || {}); return { type: "bar", name: mm.model, x: ks, y: ks.map((c) => m(mm.off_pair_per_attack_recall[c])), marker: { color: modelColor(mm.model, i) } }; })}
            layout={{ barmode: "group", yaxis: { range: [0, 1.05], title: "recall" }, xaxis: { showgrid: false } }} />
        </Panel>
      </div>

      <Panel title="Dominant vs non-dominant pair" note="Seed 0, contract view 4." flush>
        <Table caption="Dominant versus non-dominant pair" rows={d.models.flatMap((mm) => Object.entries(mm.dominant_vs_non_dominant_seed0).map(([k, v]) => ({ model: mm.model, k, ...v })))}
          columns={[{ label: "Model", key: "model", render: (r) => <Code>{r.model}</Code> }, { label: "Subset", key: "k", render: (r) => <Code>{r.k}</Code> },
            { label: "Flows", num: true, render: (r) => int(r.n) },
            { label: "Macro-F1", num: true, render: (r) => fmt(r.macro_f1) }, { label: "FPR", num: true, render: (r) => pct(r.fpr) }]} />
      </Panel>

      <Panel title="Confusion matrix" note="Seed 0, row-normalised; cells show flow counts.">
        <Segmented label="Model" name="cm-model" hideLabel value={sel} onChange={(v) => setSel(Number(v))}
          options={d.models.map((mm, i) => ({ value: i, label: mm.model }))} />
        {d.models[sel] && <Heatmap matrix={d.models[sel].confusion_matrix_seed0} labels={d.models[sel].classes} title={d.models[sel].model} />}
      </Panel>
    </> : <p className="empty">No results yet for this experiment. Run its training spec, then reload this page.</p>}</Status>

    <Panel title="GraphSAGE context modes" note="Contract §6.3, native identities." flush>
      <Status q={md} height={140}>{(d) => <Table caption="GraphSAGE context modes" empty="No context-mode results for this experiment." rows={d.models.flatMap((mm) => Object.entries(mm.modes).map(([k, v]) => ({ model: mm.model, k, ...v })))}
        columns={[{ label: "Model", key: "model", render: (r) => <Code>{r.model}</Code> }, { label: "Mode", key: "k", render: (r) => <Code>{r.k}</Code> },
          { label: "Macro-F1", num: true, render: (r) => meanStd(r.macro_f1) },
          { label: "FPR", num: true, render: (r) => (r.fpr ? pct(r.fpr.mean) : "n/a") }, { label: "Off-pair macro-F1", num: true, render: (r) => meanStd(r.off_pair_macro_f1) }]} />}</Status>
    </Panel>

    <Panel title="E-PS1: PortScan with and without Destination Port" flush>
      <Status q={e1} height={140}>{(d) => <>
        <Table caption="E-PS1 PortScan ablation" rows={d.rows} columns={[{ label: "Feature set", key: "feature_set", render: (r) => <Code>{r.feature_set}</Code> },
          { label: "Model", key: "model", render: (r) => <Code>{r.model}</Code> },
          { label: "PortScan recall", num: true, render: (r) => meanStd(r.portscan_recall) }, { label: "PortScan F1", num: true, render: (r) => meanStd(r.portscan_f1) },
          { label: "Precision (seed 0)", num: true, render: (r) => fmt(r.portscan_precision_seed0) }, { label: "Macro-F1", num: true, render: (r) => meanStd(r.macro_f1) }]} />
        <p className="fine panel-foot">Test PortScan flows whose exact feature vector occurs in train with another label: {Object.entries(d.test_portscan_rows_with_train_twin_of_other_label).map(([k, v]) => `${k} ${int(v)}`).join(", ")}. {d.interpretation}</p>
      </>}</Status>
    </Panel>
  </>;
}

/* -------------------------------------------------------------- Robustness */

const METRICS = [{ value: "macro_f1", label: "Macro-F1" }, { value: "fpr", label: "FPR" }, { value: "off_pair_macro_f1", label: "Off-pair macro-F1" }];

export function Robustness() {
  const [exp, setExp] = useState("primary_family_default");
  const q = useApi(`/api/results/robustness?experiment=${exp}`);
  const [metric, setMetric] = useState("macro_f1");
  useThemeKey();
  const metricLabel = METRICS.find((x) => x.value === metric).label;
  return <>
    <div className="toolbar">
      <ExperimentSelect value={exp} onChange={setExp} />
      <Segmented label="Metric" name="metric" value={metric} onChange={setMetric} options={METRICS} />
    </div>
    <Note>
      <p><Code>native_identity_baseline</Code> is merge factor 1 (already NAT-aggregated). Aggregation-aware models trained with merge factors 2, 4 and 8; 16 and 32 are unseen.
        RF and XGBoost use no endpoint identity, so their inputs are identical at every level: flat by construction, drawn dotted.</p>
    </Note>
    <Status q={q} height={460}>{(d) => {
      const lv = d.levels;
      const x = lv.map((l) => (l === "native_identity_baseline" ? 1 : Number(l.split("_").pop())));
      return d.models.length ? <>
        <Panel title={`${metricLabel} by merge factor`} note="Mean over seeds with the spread as whiskers. The shaded band marks merge factors never seen in training.">
          <Plot height={440} label={`${metricLabel} by merge factor for each model`} data={d.models.map((mm, i) => {
            const color = modelColor(mm.model, i);
            return { x, y: lv.map((l) => m(mm.levels[l]?.[metric])), name: mm.model, mode: "lines+markers",
              line: { color, width: 2, dash: mm.invariant_by_construction ? "dot" : "solid" }, marker: { color, size: 6 },
              error_y: { type: "data", array: lv.map((l) => mm.levels[l]?.[metric]?.std || 0), color, thickness: 1, width: 3 } };
          })}
            layout={{ xaxis: { type: "log", title: "merge factor (1 = native_identity_baseline)", tickvals: x, ticktext: x.map(String) }, yaxis: { title: metricLabel },
              shapes: [{ type: "rect", x0: 12, x1: 40, y0: 0, y1: 1, yref: "paper", fillcolor: cssColor("--color-bad", 0.08), line: { width: 0 }, layer: "below" }],
              annotations: [{ x: Math.log10(22), y: 1, yref: "paper", yanchor: "bottom", text: "unseen", showarrow: false, font: { size: 11, color: cssColor("--color-bad-ink") } }],
              legend: { orientation: "h", x: 0, y: -0.2, yanchor: "top" } }} />
        </Panel>
        <Panel title={`${metricLabel} table`} flush>
          <Table caption={`${metricLabel} by model and level`} rows={d.models} columns={[
            { label: "Model", key: "model", render: (r) => <span className="model-cell"><span className="swatch" style={{ background: modelColor(r.model) }} /><Code>{r.model}</Code></span> },
            ...lv.map((l) => ({ label: l === "native_identity_baseline" ? "native" : l.replace("merge_factor_", "×"), num: true, render: (r) => meanStd(r.levels[l]?.[metric]) }))]} />
        </Panel>
      </> : <p className="empty">No graph results for this experiment.</p>;
    }}</Status>
  </>;
}

export const RESEARCH_PAGES = { "Research overview": ResearchOverview, "Dataset audit": ResearchDataset,
  "Aggregation simulator": Aggregation, "Model comparison": Models, Robustness };
