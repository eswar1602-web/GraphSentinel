// Bridges the CSS tokens to Plotly and Cytoscape, which need concrete colours.
// Every chart colour is read from tokens.css at render time, so light/dark and the toggle stay in one place.
import { useEffect, useState } from "react";

const STORE = "graphsentinel-theme";
let probe = null;
let canvas = null;

// Parse the computed colour string ourselves: canvas silently ignores formats it cannot read,
// which made every chart series come out the same colour.
function parseColor(str) {
  const nums = (s) => s.split(/[\s,/]+/).filter(Boolean);
  let mt = /^rgba?\(([^)]+)\)$/.exec(str);
  if (mt) {
    const p = nums(mt[1]).map(parseFloat);
    return [Math.round(p[0]), Math.round(p[1]), Math.round(p[2]), p.length > 3 ? p[3] : 1];
  }
  mt = /^oklch\(([^)]+)\)$/.exec(str);
  if (!mt) return null;
  const p = nums(mt[1]);
  const num = (v, pctScale) => (v.endsWith("%") ? (parseFloat(v) / 100) * pctScale : v === "none" ? 0 : parseFloat(v));
  const L = num(p[0], 1), C = num(p[1], 0.4), H = (num(p[2], 360) * Math.PI) / 180;
  const A = p.length > 3 ? num(p[3], 1) : 1;
  const a = C * Math.cos(H), b = C * Math.sin(H);
  const l = (L + 0.3963377774 * a + 0.2158037573 * b) ** 3;
  const m = (L - 0.1055613458 * a - 0.0638541728 * b) ** 3;
  const s = (L - 0.0894841775 * a - 1.291485548 * b) ** 3;
  const lin = [4.0767416621 * l - 3.3077115913 * m + 0.2309699292 * s,
    -1.2684380046 * l + 2.6097574011 * m - 0.3413193965 * s,
    -0.0041960863 * l - 0.7034186147 * m + 1.707614701 * s];
  const enc = (x) => { const c = Math.min(1, Math.max(0, x)); return Math.round(255 * (c <= 0.0031308 ? 12.92 * c : 1.055 * c ** (1 / 2.4) - 0.055)); };
  return [enc(lin[0]), enc(lin[1]), enc(lin[2]), A];
}

/** Resolve a CSS custom property (e.g. "--color-ink") to an rgba() string Plotly/Cytoscape understand. */
export function cssColor(name, alpha = 1) {
  if (!probe) {
    probe = document.createElement("span");
    probe.setAttribute("aria-hidden", "true");
    probe.style.position = "absolute"; probe.style.width = "0"; probe.style.height = "0"; probe.style.overflow = "hidden";
    document.body.appendChild(probe);
    canvas = document.createElement("canvas"); canvas.width = 1; canvas.height = 1;
  }
  probe.style.color = `var(${name})`;
  const resolved = getComputedStyle(probe).color;
  const direct = parseColor(resolved);
  if (direct) return `rgba(${direct[0]}, ${direct[1]}, ${direct[2]}, ${(direct[3] * alpha).toFixed(3)})`;
  const ctx = canvas.getContext("2d", { willReadFrequently: true });
  ctx.clearRect(0, 0, 1, 1);
  ctx.fillStyle = resolved;
  ctx.fillRect(0, 0, 1, 1);
  const [r, g, b, a] = ctx.getImageData(0, 0, 1, 1).data;
  return `rgba(${r}, ${g}, ${b}, ${((a / 255) * alpha).toFixed(3)})`;
}

/** The font stack declared in tokens.css, for chart text. */
export const cssFont = (name = "--font-body") => getComputedStyle(document.documentElement).getPropertyValue(name).trim();

export function getThemePref() {
  try { return localStorage.getItem(STORE) || "system"; } catch { return "system"; }
}

export function setThemePref(pref) {
  try { if (pref === "system") localStorage.removeItem(STORE); else localStorage.setItem(STORE, pref); } catch { /* storage blocked */ }
  if (pref === "system") delete document.documentElement.dataset.theme;
  else document.documentElement.dataset.theme = pref;
  window.dispatchEvent(new Event("gs-themechange"));
}

export const isDark = () => {
  const t = document.documentElement.dataset.theme;
  if (t) return t === "dark";
  return window.matchMedia("(prefers-color-scheme: dark)").matches;
};

/** A counter that changes whenever the effective theme changes; charts re-render on it. */
export function useThemeKey() {
  const [key, setKey] = useState(0);
  useEffect(() => {
    const bump = () => setKey((k) => k + 1);
    const mq = window.matchMedia("(prefers-color-scheme: dark)");
    mq.addEventListener("change", bump);
    window.addEventListener("gs-themechange", bump);
    // Web fonts change label metrics; redraw once they are in.
    if (document.fonts && document.fonts.ready) document.fonts.ready.then(bump);
    return () => { mq.removeEventListener("change", bump); window.removeEventListener("gs-themechange", bump); };
  }, []);
  return key;
}

/** Colour for a model series, grouped by family so related models read as one ramp. */
export function modelColor(model, i = 0) {
  if (model.startsWith("aggaware")) {
    const order = ["aggaware_consistency_and_robustness", "aggaware_consistency_only", "aggaware_robustness_only", "aggaware_strong_consistency"];
    const k = order.indexOf(model);
    return cssColor(`--series-agg-${(k < 0 ? i % 4 : k) + 1}`);
  }
  if (model === "graphsage_standard") return cssColor("--series-sage-1");
  if (model.startsWith("graphsage")) return cssColor("--series-sage-2");
  if (model === "random_forest") return cssColor("--series-tree-1");
  if (model === "xgboost") return cssColor("--series-tree-2");
  return cssColor(`--series-split-${(i % 4) + 1}`);
}
