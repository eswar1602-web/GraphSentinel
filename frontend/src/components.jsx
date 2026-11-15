import { useEffect, useRef, useState } from "react";
import Plotly from "plotly.js-dist-min";
import cytoscape from "cytoscape";
import { cssColor, cssFont, isDark, useThemeKey } from "./theme";
import { Icon } from "./icons";

// Plotly rejects NaN/undefined in some traces (the old "axis scaling" crash); send nulls instead.
const clean = (v) => (v === undefined || (typeof v === "number" && !Number.isFinite(v)) ? null : v);
const cleanTrace = (t) => {
  const out = { ...t };
  ["x", "y"].forEach((k) => { if (Array.isArray(out[k])) out[k] = out[k].map(clean); });
  if (out.error_y && Array.isArray(out.error_y.array)) out.error_y = { ...out.error_y, array: out.error_y.array.map((v) => clean(v) ?? 0) };
  return out;
};

function axis(a = {}, c) {
  const { title, ...rest } = a;
  return {
    gridcolor: c.rule, zerolinecolor: c.rule, linecolor: c.rule, tickcolor: c.rule, automargin: true,
    tickfont: { color: c.muted, size: 11 },
    ...(rest.type === "log" && rest.dtick === undefined ? { dtick: 1 } : {}),
    ...(title ? { title: { text: typeof title === "string" ? title : title.text, font: { color: c.muted, size: 12 }, standoff: 10 } } : {}),
    ...rest,
  };
}

/** A Plotly chart drawn in the dashboard's tokens. `data` traces may reference no colours; pass them already resolved. */
export function Plot({ data, layout = {}, height = 340, label }) {
  const ref = useRef(null);
  const themeKey = useThemeKey();
  const [err, setErr] = useState(null);
  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    const c = { ink: cssColor("--color-ink"), ink2: cssColor("--color-ink-2"), muted: cssColor("--color-muted"),
      rule: cssColor("--color-rule"), rule2: cssColor("--color-rule-2"), panel: cssColor("--color-paper-2") };
    const { xaxis, yaxis, ...rest } = layout;
    const full = {
      height, autosize: true, margin: { l: 8, r: 16, t: 8, b: 8 }, paper_bgcolor: "transparent", plot_bgcolor: "transparent",
      font: { family: cssFont(), color: c.ink2, size: 12 }, bargap: 0.28, bargroupgap: 0.08,
      hoverlabel: { bgcolor: c.panel, bordercolor: c.rule2, font: { family: cssFont(), color: c.ink, size: 12 } },
      legend: { orientation: "h", x: 0, xanchor: "left", y: 1.02, yanchor: "bottom", font: { size: 12, color: c.ink2 } },
      xaxis: axis(xaxis, c), yaxis: axis(yaxis, c), ...rest,
    };
    setErr(null);
    try {
      Promise.resolve(Plotly.react(el, data.map(cleanTrace), full, {
        displaylogo: false, responsive: true, displayModeBar: "hover",
        modeBarButtonsToRemove: ["lasso2d", "select2d", "autoScale2d", "toggleSpikelines", "hoverCompareCartesian", "hoverClosestCartesian"],
      })).catch((e) => setErr(e));
    } catch (e) { setErr(e); }
  }, [data, layout, height, themeKey]);
  // Keep the chart inside its column when the grid settles (web fonts, sidebar, window resize).
  useEffect(() => {
    const el = ref.current;
    if (!el || typeof ResizeObserver === "undefined") return undefined;
    let frame = 0;
    const ro = new ResizeObserver(() => {
      cancelAnimationFrame(frame);
      frame = requestAnimationFrame(() => { if (el._fullLayout) Plotly.Plots.resize(el); });
    });
    ro.observe(el);
    return () => { cancelAnimationFrame(frame); ro.disconnect(); };
  }, []);
  useEffect(() => () => { if (ref.current) Plotly.purge(ref.current); }, []);
  return (
    <>
      <div ref={ref} className="plot" role="img" aria-label={label || "chart"} />
      {err && <p className="inline-error" role="alert">This chart could not be drawn: {String(err.message || err)}</p>}
    </>
  );
}

/** Row-normalised confusion matrix; cell text keeps the raw flow counts. */
export function Heatmap({ matrix, labels, title }) {
  useThemeKey(); // re-resolve the colour scale when the theme changes
  if (!matrix) return null;
  const rowSum = matrix.map((r) => r.reduce((a, b) => a + b, 0) || 1);
  const z = matrix.map((r, i) => r.map((v) => v / rowSum[i]));
  const lo = cssColor("--color-paper-3"), mid = cssColor("--series-agg-3"), hi = cssColor("--series-agg-1");
  // Cell text takes the colour that reads against its own fill: ink on pale cells, the panel colour on saturated ones.
  const dark = isDark();
  const onStrong = cssColor(dark ? "--color-paper-3" : "--color-paper-2"), onWeak = cssColor("--color-ink");
  const annotations = matrix.flatMap((r, i) => r.map((v, j) => ({ x: labels[j], y: labels[i], text: v.toLocaleString(), showarrow: false,
    font: { size: 11, color: z[i][j] > 0.55 ? onStrong : onWeak } })));
  return (
    <Plot height={460} label={`Confusion matrix, ${title}`} data={[{ type: "heatmap", z, x: labels, y: labels,
      colorscale: [[0, lo], [0.5, mid], [1, hi]], zmin: 0, zmax: 1, xgap: 1, ygap: 1,
      colorbar: { thickness: 10, outlinewidth: 0, tickformat: ".0%", len: 0.9 },
      text: matrix.map((r) => r.map((v) => v.toLocaleString())),
      hovertemplate: "true %{y}<br>predicted %{x}<br>%{text} flows (%{z:.1%} of row)<extra></extra>" }]}
      layout={{ annotations, xaxis: { title: "predicted", side: "bottom", showgrid: false }, yaxis: { title: "true", autorange: "reversed", showgrid: false } }} />
  );
}

/** Endpoint graph for one time window. Colour runs from benign (teal) to attack (red) by attack fraction. */
export function Graph({ nodes, edges }) {
  const ref = useRef(null);
  const cyRef = useRef(null);
  const themeKey = useThemeKey();
  const [info, setInfo] = useState(null);
  useEffect(() => {
    if (!ref.current) return;
    const benign = cssColor("--color-accent"), attack = cssColor("--color-bad"), edge = cssColor("--color-rule-2");
    const ink2 = cssColor("--color-ink-2"), panel = cssColor("--color-paper-2"), focus = cssColor("--color-focus");
    const maxF = Math.max(1, ...nodes.map((n) => n.flows));
    // Label only the busiest nodes on the canvas; every label appears on hover or selection, and in full in the details panel.
    const busiest = new Set([...nodes].sort((a, b) => b.flows - a.flows).slice(0, 12).map((n) => n.id));
    const short = (l) => String(l).replace(/\s*\(\d+ endpoints?\)$/, "");
    const cy = cytoscape({
      container: ref.current,
      elements: [
        ...nodes.map((n) => ({ data: { ...n, frac: n.flows ? n.attack_flows / n.flows : 0, size: 12 + 44 * Math.sqrt(n.flows / maxF),
          shown: busiest.has(n.id) ? short(n.label) : "", short: short(n.label) } })),
        ...edges.map((e) => ({ data: { ...e, w: 1 + 5 * Math.min(1, Math.log10(1 + e.flows) / 4) } })),
      ],
      style: [
        { selector: "node", style: { width: "data(size)", height: "data(size)", label: "data(shown)", "font-size": 9, "font-family": cssFont("--font-outlier"),
          color: ink2, "text-valign": "bottom", "text-margin-y": 4, "text-background-color": panel, "text-background-opacity": 0.85, "text-background-padding": 1,
          "background-color": `mapData(frac, 0, 1, ${benign}, ${attack})`, "border-width": 1.5, "border-color": panel } },
        { selector: "edge", style: { width: "data(w)", "curve-style": "bezier", "target-arrow-shape": "triangle", "arrow-scale": 0.7,
          "line-color": `mapData(attack_fraction, 0, 1, ${edge}, ${attack})`, "target-arrow-color": `mapData(attack_fraction, 0, 1, ${edge}, ${attack})`, opacity: 0.85 } },
        { selector: "node.hover, node:selected", style: { label: "data(short)", "z-index": 10 } },
        { selector: ":selected", style: { "border-width": 3, "border-color": focus, "line-color": focus, "target-arrow-color": focus, opacity: 1 } },
      ],
      layout: { name: "cose", animate: false, nodeRepulsion: 9000, idealEdgeLength: 90, padding: 24 },
      wheelSensitivity: 0.25,
    });
    cy.on("tap", "node, edge", (evt) => setInfo(evt.target.data()));
    cy.on("mouseover", "node", (evt) => evt.target.addClass("hover"));
    cy.on("mouseout", "node", (evt) => evt.target.removeClass("hover"));
    cy.on("tap", (evt) => { if (evt.target === cy) setInfo(null); });
    cyRef.current = cy;
    return () => { cy.destroy(); cyRef.current = null; };
  }, [nodes, edges, themeKey]);

  const fit = () => cyRef.current && cyRef.current.fit(undefined, 24);
  const relayout = () => cyRef.current && cyRef.current.layout({ name: "cose", animate: false, nodeRepulsion: 9000, idealEdgeLength: 90, padding: 24, randomize: true }).run();

  return (
    <div className="graph-stage">
      <div className="graph-tools" role="toolbar" aria-label="Graph view">
        <button type="button" className="btn btn--quiet btn--sm" onClick={fit}><Icon name="fit" size={16} />Fit</button>
        <button type="button" className="btn btn--quiet btn--sm" onClick={relayout}><Icon name="refresh" size={16} />Re-run layout</button>
      </div>
      <div ref={ref} className="cy" role="img" aria-label={`Network graph of ${nodes.length} endpoints and ${edges.length} directed edges`} />
      <div id="cy-info" className="graph-info" aria-live="polite">
        {!info && <p className="muted">Select a node or an edge to see its flows.</p>}
        {info && info.source && (
          <dl className="kv">
            <div><dt>Edge</dt><dd className="mono">{info.source} → {info.target}</dd></div>
            <div><dt>Flows</dt><dd className="mono">{Number(info.flows).toLocaleString()}</dd></div>
            <div><dt>Attack fraction</dt><dd className="mono">{(100 * info.attack_fraction).toFixed(1)}%</dd></div>
            <div><dt>Top family</dt><dd>{info.top_family}</dd></div>
          </dl>
        )}
        {info && !info.source && (
          <dl className="kv">
            <div><dt>Node</dt><dd className="mono">{info.label}</dd></div>
            <div><dt>Flows</dt><dd className="mono">{Number(info.flows).toLocaleString()}</dd></div>
            <div><dt>Attack flows</dt><dd className="mono">{Number(info.attack_flows).toLocaleString()}</dd></div>
            {info.members_sample && info.members_sample.length > 0 && <div><dt>Members, e.g.</dt><dd className="mono">{info.members_sample.join(", ")}</dd></div>}
          </dl>
        )}
      </div>
    </div>
  );
}

/** Loading, error and full states for one API region. */
export function Status({ q, children, height = 180, loadingText = "Loading" }) {
  if (q.loading) return <Skeleton height={height} text={loadingText} />;
  if (q.error) return <ErrorState error={q.error} onRetry={q.reload} />;
  return children(q.data);
}

export function Skeleton({ height = 180, text = "Loading" }) {
  return (
    <div className="skeleton" style={{ minHeight: height }} role="status">
      <span className="skeleton-text">{text}…</span>
    </div>
  );
}

export function ErrorState({ error, onRetry }) {
  return (
    <div className="note note--bad" role="alert">
      <Icon name="alert" />
      <div className="note-body">
        <p><strong>The API did not answer this request.</strong> {String(error.message || error)}</p>
        <p className="muted">Check that the FastAPI backend is running on port 8000, then retry.</p>
        {onRetry && <button type="button" className="btn btn--quiet btn--sm" onClick={onRetry}><Icon name="refresh" size={16} />Retry</button>}
      </div>
    </div>
  );
}

/** A row of figures cut from one surface, parted by hairlines. */
export function Stats({ items }) {
  return (
    <dl className="stats">
      {items.map((it) => (
        <div className="stat" key={it.label}>
          <dt>{it.label}</dt>
          <dd className={`stat-v${it.tone ? ` tone-${it.tone}` : ""}`}>{it.value}</dd>
          {it.note && <dd className="stat-n">{it.note}</dd>}
        </div>
      ))}
    </dl>
  );
}

/** Kept for compatibility with earlier imports; prefer <Stats>. */
export function Kpi({ label, value, note }) {
  return <Stats items={[{ label, value, note }]} />;
}

export function Panel({ title, note, actions, children, className = "", id, flush = false }) {
  return (
    <section className={`panel ${className}`} aria-labelledby={id ? `${id}-h` : undefined}>
      {(title || actions) && (
        <header className="panel-head">
          <div className="panel-title">
            {title && <h3 id={id ? `${id}-h` : undefined}>{title}</h3>}
            {note && <p className="panel-note">{note}</p>}
          </div>
          {actions && <div className="panel-actions">{actions}</div>}
        </header>
      )}
      <div className={flush ? "panel-flush" : "panel-body"}>{children}</div>
    </section>
  );
}

export function Note({ tone = "info", icon, children }) {
  return (
    <aside className={`note note--${tone}`}>
      <Icon name={icon || (tone === "info" ? "info" : "alert")} />
      <div className="note-body">{children}</div>
    </aside>
  );
}

export function Chip({ tone = "neutral", children }) {
  return <span className={`chip chip--${tone}`}>{children}</span>;
}

export function Field({ label, children, wide = false }) {
  return <label className={`field${wide ? " field--wide" : ""}`}><span className="field-label">{label}</span>{children}</label>;
}

/** A choice between a few: radios in the flow, the label carrying state and focus. */
export function Segmented({ label, name, value, options, onChange, hideLabel = false }) {
  return (
    <fieldset className="seg">
      <legend className={hideLabel ? "visually-hidden" : "field-label"}>{label}</legend>
      <div className="seg-track">
        {options.map((o) => (
          <label key={o.value} className="seg-opt">
            <input type="radio" name={name} value={o.value} checked={String(value) === String(o.value)} onChange={() => onChange(o.value)} />
            <span>{o.label}</span>
          </label>
        ))}
      </div>
    </fieldset>
  );
}

export function Table({ columns, rows, empty = "No rows.", caption }) {
  if (!rows || rows.length === 0) return <p className="empty">{empty}</p>;
  return (
    <div className="table-wrap" tabIndex={0} role="region" aria-label={caption || "table"}>
      <table>
        {caption && <caption className="visually-hidden">{caption}</caption>}
        <thead><tr>{columns.map((c) => <th key={c.key || c.label} className={c.num ? "num" : ""} scope="col">{c.label}</th>)}</tr></thead>
        <tbody>{rows.map((r, i) => <tr key={i}>{columns.map((c) => <td key={c.key || c.label} className={`${c.num ? "num" : ""}${c.mono ? " mono" : ""}`}>{c.render ? c.render(r) : r[c.key]}</td>)}</tr>)}</tbody>
      </table>
    </div>
  );
}
