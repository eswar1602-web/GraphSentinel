import { useEffect, useRef } from "react";
import Plotly from "plotly.js-dist-min";
import cytoscape from "cytoscape";

const dark = () => window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches;
export const PALETTE = ["#2563eb", "#dc2626", "#16a34a", "#d97706", "#7c3aed", "#0891b2", "#db2777", "#65a30d", "#475569", "#ea580c"];

export function Plot({ data, layout = {}, height = 340 }) {
  const ref = useRef(null);
  useEffect(() => {
    if (!ref.current) return;
    const d = dark();
    const fg = d ? "#e5e7eb" : "#111827";
    const grid = d ? "#374151" : "#e5e7eb";
    Plotly.react(ref.current, data, {
      height, margin: { l: 60, r: 20, t: 36, b: 95 }, paper_bgcolor: "rgba(0,0,0,0)", plot_bgcolor: "rgba(0,0,0,0)",
      font: { color: fg, size: 12 }, colorway: PALETTE,
      xaxis: { gridcolor: grid, zerolinecolor: grid, ...(layout.xaxis || {}) },
      yaxis: { gridcolor: grid, zerolinecolor: grid, ...(layout.yaxis || {}) },
      legend: { orientation: "h", y: -0.38, yanchor: "top" }, ...layout,
    }, { displaylogo: false, responsive: true });
  }, [data, layout, height]);
  useEffect(() => () => ref.current && Plotly.purge(ref.current), []);
  return <div ref={ref} className="plot" />;
}

export function Heatmap({ matrix, labels, title }) {
  if (!matrix) return null;
  const rowSum = matrix.map((r) => r.reduce((a, b) => a + b, 0) || 1);
  const z = matrix.map((r, i) => r.map((v) => v / rowSum[i]));
  return (
    <Plot height={420} data={[{ type: "heatmap", z, x: labels, y: labels, colorscale: "Blues", zmin: 0, zmax: 1,
      text: matrix.map((r) => r.map((v) => v.toLocaleString())), texttemplate: "%{text}", hovertemplate: "true %{y}<br>pred %{x}<br>%{text} flows (%{z:.1%} of row)<extra></extra>" }]}
      layout={{ title: { text: title, font: { size: 13 } }, xaxis: { title: "predicted" }, yaxis: { title: "true", autorange: "reversed" }, margin: { l: 110, b: 100, t: 40, r: 20 } }} />
  );
}

export function Graph({ nodes, edges }) {
  const ref = useRef(null);
  useEffect(() => {
    if (!ref.current) return;
    const d = dark();
    const maxF = Math.max(1, ...nodes.map((n) => n.flows));
    const cy = cytoscape({
      container: ref.current,
      elements: [
        ...nodes.map((n) => ({ data: { ...n, frac: n.flows ? n.attack_flows / n.flows : 0, size: 14 + 46 * Math.sqrt(n.flows / maxF) } })),
        ...edges.map((e) => ({ data: { ...e, w: 1 + 5 * Math.min(1, Math.log10(1 + e.flows) / 4) } })),
      ],
      style: [
        { selector: "node", style: { width: "data(size)", height: "data(size)", label: "data(label)", "font-size": 9,
          color: d ? "#e5e7eb" : "#111827", "text-valign": "bottom", "text-margin-y": 3,
          "background-color": "mapData(frac, 0, 1, #3b82f6, #dc2626)", "border-width": 1, "border-color": d ? "#111827" : "#fff" } },
        { selector: "edge", style: { width: "data(w)", "curve-style": "bezier", "target-arrow-shape": "triangle", "arrow-scale": 0.7,
          "line-color": "mapData(attack_fraction, 0, 1, #94a3b8, #dc2626)", "target-arrow-color": "mapData(attack_fraction, 0, 1, #94a3b8, #dc2626)", opacity: 0.8 } },
      ],
      layout: { name: "cose", animate: false, nodeRepulsion: 9000, idealEdgeLength: 90 },
    });
    cy.on("tap", "node, edge", (evt) => {
      const x = evt.target.data();
      const el = document.getElementById("cy-info");
      if (el) el.textContent = x.source ? `${x.source} → ${x.target}: ${x.flows} flows, attack fraction ${(100 * x.attack_fraction).toFixed(1)}%, top family ${x.top_family}`
        : `${x.label}: ${x.flows} flows, ${x.attack_flows} attack flows${x.members_sample && x.members_sample.length ? `; members e.g. ${x.members_sample.join(", ")}` : ""}`;
    });
    return () => cy.destroy();
  }, [nodes, edges]);
  return <><div ref={ref} className="cy" /><p id="cy-info" className="muted">Click a node or edge for details.</p></>;
}

export function Status({ q, children }) {
  if (q.loading) return <p className="muted">Loading…</p>;
  if (q.error) return <p className="error">Error: {String(q.error.message || q.error)}</p>;
  return children(q.data);
}

export function Kpi({ label, value, note }) {
  return <div className="kpi"><div className="kpi-v">{value}</div><div className="kpi-l">{label}</div>{note && <div className="kpi-n">{note}</div>}</div>;
}

export function Table({ columns, rows }) {
  return (
    <div className="table-wrap"><table>
      <thead><tr>{columns.map((c) => <th key={c.key || c.label}>{c.label}</th>)}</tr></thead>
      <tbody>{rows.map((r, i) => <tr key={i}>{columns.map((c) => <td key={c.key || c.label} className={c.num ? "num" : ""}>{c.render ? c.render(r) : r[c.key]}</td>)}</tr>)}</tbody>
    </table></div>
  );
}
