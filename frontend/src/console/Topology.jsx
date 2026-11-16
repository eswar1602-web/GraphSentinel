// The live topology: devices in fixed rows by role (external, router, servers, workstations, laptops), so the
// diagram never jumps while traffic arrives. Edges are directed connections; their width follows the flow count.
// Orange marks what the detectors flagged: a filled square is a device acting in a suspicious connection, an
// orange outline a device on the receiving end. Updates are applied incrementally from the live stream.
import { useEffect, useMemo, useRef } from "react";
import cytoscape from "cytoscape";
import { cssColor } from "../theme";

const ROWS = [
  ["external", "External"], ["router", "Router"], ["servers", "Servers"], ["workstation", "Workstations"], ["laptop", "Laptops"],
];
const ROW_OF = { external: "external", router: "router", app_server: "servers", db_server: "servers", dns_server: "servers",
  workstation: "workstation", laptop: "laptop" };
const ROW_Y = { external: 0, router: 95, servers: 190, workstation: 305, laptop: 400 };
const X0 = 110;
const X1 = 820;

function positions(nodes) {
  const byRow = {};
  nodes.forEach((n) => { (byRow[ROW_OF[n.role]] ||= []).push(n); });
  const pos = {};
  Object.entries(byRow).forEach(([row, list]) => {
    list.sort((a, b) => a.id.localeCompare(b.id, "en", { numeric: true }));
    const step = list.length > 1 ? Math.min(80, (X1 - X0) / (list.length - 1)) : 0;
    const start = (X0 + X1) / 2 - (step * (list.length - 1)) / 2;
    list.forEach((n, i) => { pos[n.id] = { x: start + i * step, y: ROW_Y[row] }; });
  });
  return pos;
}

function palette() {
  return { ink: cssColor("--color-ink"), ink2: cssColor("--color-ink-2"), muted: cssColor("--color-muted"),
    muted2: cssColor("--color-muted-2"), rule: cssColor("--color-rule"), paper: cssColor("--color-paper"),
    paper2: cssColor("--color-paper-2"), paper3: cssColor("--color-paper-3"), accent: cssColor("--color-accent"), accentInk: cssColor("--color-accent-ink"),
    blue: cssColor("--color-accent-2"), edge: cssColor("--color-muted-2", 0.55) };
}

const width = (flows) => Math.min(3.5, 0.6 + Math.log10(Math.max(1, flows)) * 0.7);

export default function Topology({ graph, selected, onSelect, label }) {
  const box = useRef(null);
  const cy = useRef(null);
  const ids = useRef("");
  const nodes = useMemo(() => [...graph.nodes.values()], [graph]);
  const edges = useMemo(() => [...graph.edges.values()], [graph]);
  const acting = useMemo(() => new Set(edges.filter((e) => e.suspicious).map((e) => e.source)), [edges]);
  const receiving = useMemo(() => new Set(edges.filter((e) => e.suspicious).map((e) => e.target)), [edges]);

  useEffect(() => {
    const c = palette();
    const mono = getComputedStyle(document.documentElement).getPropertyValue("--font-outlier").trim();
    ids.current = "";                                   // a new instance starts empty: the next update rebuilds it
    cy.current = cytoscape({
      container: box.current, elements: [], layout: { name: "preset" }, autoungrabify: true, boxSelectionEnabled: false,
      userZoomingEnabled: false, userPanningEnabled: false, minZoom: 0.2, maxZoom: 2,
      style: [
        { selector: "node.device", style: { shape: "rectangle", width: 15, height: 15, "background-color": c.paper2,
          "border-width": 1, "border-color": c.muted2, label: "data(label)", "font-family": mono, "font-size": 11,
          color: c.muted, "text-valign": "bottom", "text-margin-y": 5, "text-background-color": c.paper3, "text-background-opacity": 0.85,
          "text-background-padding": 2, "text-background-shape": "rectangle", "transition-property": "background-color, border-color", "transition-duration": 220 } },
        { selector: "node.device.active", style: { "border-color": c.ink2, color: c.ink2 } },
        { selector: "node.device.receiving", style: { "border-color": c.accent, "border-width": 2, color: c.accent } },
        { selector: "node.device.acting", style: { "background-color": c.accent, "border-color": c.accent, color: c.accent } },
        { selector: "node.device:selected", style: { "border-color": c.blue, "border-width": 3, color: c.blue, "overlay-opacity": 0 } },
        { selector: "node.row", style: { shape: "rectangle", width: 1, height: 1, "background-opacity": 0, "border-width": 0,
          label: "data(label)", "font-family": getComputedStyle(document.documentElement).getPropertyValue("--font-body").trim(),
          "font-size": 12, color: c.muted, "text-halign": "right", "text-valign": "center", events: "no" } },
        { selector: "node.device.dim", style: { opacity: 0.5 } },
        { selector: "edge", style: { width: "data(w)", "line-color": c.edge, "curve-style": "bezier", opacity: 0.45,
          "target-arrow-shape": "none", "overlay-opacity": 0 } },
        { selector: "edge.same-row", style: { "curve-style": "unbundled-bezier", "control-point-distances": 36, "control-point-weights": 0.5 } },
        { selector: "edge.suspicious", style: { "line-color": c.accent, opacity: 1, "z-index": 10, "target-arrow-shape": "triangle",
          "target-arrow-color": c.accent, "arrow-scale": 0.8 } },
      ],
    });
    if (import.meta.env.DEV) window.__gsTopology = cy.current;     // inspection hook for dev-mode browser tests
    cy.current.on("tap", "node.device", (e) => onSelect(e.target.id()));
    cy.current.on("tap", (e) => { if (e.target === cy.current) onSelect(null); });
    const ro = new ResizeObserver(() => { if (cy.current) { cy.current.resize(); cy.current.fit(undefined, 28); } });
    ro.observe(box.current);
    return () => { ro.disconnect(); cy.current.destroy(); cy.current = null; };
    // onSelect is stable for the page's lifetime
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    const c = cy.current;
    if (!c) return;
    const key = nodes.map((n) => n.id).sort().join(",");
    let rebuilt = false;
    c.batch(() => {
      if (key !== ids.current) {                        // a new run or topology: rebuild
        c.elements().remove();
        const pos = positions(nodes);
        const rowsPresent = new Set(nodes.map((n) => ROW_OF[n.role]));
        c.add(ROWS.filter(([r]) => rowsPresent.has(r)).map(([r, l]) => ({ group: "nodes", data: { id: `row:${r}`, label: l },
          classes: "row", position: { x: 0, y: ROW_Y[r] } })));
        c.add(nodes.map((n) => ({ group: "nodes", data: { id: n.id, label: n.label }, classes: "device", position: pos[n.id] })));
        ids.current = key;
        rebuilt = true;
      }
      nodes.forEach((n) => {
        const el = c.getElementById(n.id);
        el.toggleClass("active", !!n.active);
        el.toggleClass("dim", !n.active);
        el.toggleClass("acting", acting.has(n.id));
        el.toggleClass("receiving", !acting.has(n.id) && receiving.has(n.id));
      });
      edges.forEach((e) => {
        let el = c.getElementById(e.id);
        if (el.empty()) {
          const sr = c.getElementById(e.source);
          const tg = c.getElementById(e.target);
          if (sr.empty() || tg.empty()) return;
          el = c.add({ group: "edges", data: { id: e.id, source: e.source, target: e.target, w: width(e.flows) } });
          if (sr.position("y") === tg.position("y")) el.addClass("same-row");
        } else {
          el.data("w", width(e.flows));
        }
        el.toggleClass("suspicious", !!e.suspicious);
      });
      c.$("node.device").unselect();
      if (selected) c.getElementById(selected).select();
    });
    if (rebuilt) c.fit(undefined, 28);
  }, [nodes, edges, acting, receiving, selected]);

  return <div className="topology" ref={box} role="img" aria-label={label} />;
}
