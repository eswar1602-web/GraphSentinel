import { StrictMode, useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import { PAGES } from "./pages";
import { RESEARCH_PAGES } from "./research";
import { SHOW_RESEARCH } from "./config";
import { useApi } from "./hooks";
import { Icon } from "./icons";
import { getThemePref, setThemePref } from "./theme";
import "./style.css";

// Operational pages are always shown; research pages only when the build sets VITE_SHOW_RESEARCH=true.
const ALL_PAGES = SHOW_RESEARCH ? { ...PAGES, ...RESEARCH_PAGES } : PAGES;
const RESEARCH_NAMES = SHOW_RESEARCH ? Object.keys(RESEARCH_PAGES) : [];

const ICONS = { Overview: "overview", Detection: "detection", "Detection history": "history", "Network graph": "graph",
  "Training data": "dataset", "Security audit": "audit",
  "Research overview": "overview", "Dataset audit": "dataset", "Aggregation simulator": "aggregation", "Model comparison": "models", Robustness: "robustness" };

const ABOUT = {
  Overview: "Alerts, recent scans and the health of the detection system.",
  Detection: "Upload captured flow records and classify every flow as benign or as an attack.",
  "Detection history": "Every analysed file, its alerts and its attack classes.",
  "Network graph": "Recorded traffic in one time window, drawn as hosts and directed connections.",
  "Training data": "The labelled traffic the detection model learned from, and the checks it passed.",
  "Security audit": "A SHA-256 hash chain with an HMAC-SHA256 on every record. Verify it, or watch tampering get caught.",
  "Research overview": "The processed CICIDS2017 flows, the best result per experiment, and the main threat to validity.",
  "Dataset audit": "What preprocessing kept and removed, the counts the contract asserts, and how the flows split.",
  "Aggregation simulator": "How synthetic identity aggregation reshapes the flow graph at each merge factor.",
  "Model comparison": "Test results per model for one experiment, with the off-pair and dominant-pair views.",
  Robustness: "How each model holds up as identities merge, including merge factors never seen in training.",
};

function EngineStatus() {
  const h = useApi("/api/health");
  if (h.loading && !h.data) return <p className="chain chain--idle" role="status">Checking detection engine…</p>;
  const ok = !h.error && h.data.status === "ok" && h.data.detector_model;
  return (
    <p className={`chain ${ok ? "chain--ok" : "chain--bad"}`} role="status">
      <Icon name={ok ? "check" : "alert"} size={16} />
      <span>Detection engine {h.error ? "unreachable" : ok ? "ready" : "not ready"}<span className="chain-n">{h.error ? "API offline" : "XGBoost flow classifier"}</span></span>
    </p>
  );
}

const pageFromHash = (names) => {
  const h = decodeURIComponent(window.location.hash.slice(1));
  return names.includes(h) ? h : names[0];
};

function ChainStatus({ page }) {
  const v = useApi("/api/audit/verify", [page]);
  // Detections and audit actions append records; refresh the status when a page says so.
  useEffect(() => {
    const again = () => v.reload();
    window.addEventListener("gs-audit-changed", again);
    return () => window.removeEventListener("gs-audit-changed", again);
  });
  if (v.loading && !v.data) return <p className="chain chain--idle" role="status">Checking audit chain…</p>;
  if (v.error) return <p className="chain chain--bad" role="status"><Icon name="alert" size={16} />Audit chain unreachable</p>;
  const ok = v.data.valid;
  return (
    <p className={`chain ${ok ? "chain--ok" : "chain--bad"}`} role="status">
      <Icon name={ok ? "check" : "alert"} size={16} />
      <span>Audit chain {ok ? "valid" : "invalid"}<span className="chain-n">{Number(v.data.records).toLocaleString()} records</span></span>
    </p>
  );
}

function ThemeSwitch() {
  const [pref, setPref] = useState(getThemePref());
  const pick = (p) => { setPref(p); setThemePref(p); };
  const opts = [["system", "monitor", "Match system theme"], ["light", "sun", "Light theme"], ["dark", "moon", "Dark theme"]];
  return (
    <div className="theme-switch" role="group" aria-label="Colour theme">
      {opts.map(([p, icon, label]) => (
        <button key={p} type="button" aria-label={label} title={label} aria-pressed={pref === p} onClick={() => pick(p)}>
          <Icon name={icon} size={16} />
        </button>
      ))}
    </div>
  );
}

function App() {
  const names = Object.keys(ALL_PAGES);
  const [page, setPage] = useState(() => pageFromHash(names));
  const [menuOpen, setMenuOpen] = useState(false);

  useEffect(() => { window.location.hash = encodeURIComponent(page); }, [page]);
  useEffect(() => {
    const onHash = () => { setPage(pageFromHash(names)); setMenuOpen(false); window.scrollTo(0, 0); };
    window.addEventListener("hashchange", onHash);
    return () => window.removeEventListener("hashchange", onHash);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
  useEffect(() => { document.title = `${page}, GraphSentinel`; }, [page]);

  const go = (n) => (e) => { e.preventDefault(); setPage(n); setMenuOpen(false); window.scrollTo(0, 0); };
  const Page = ALL_PAGES[page];

  return (
    <div className="shell">
      <a className="skip" href="#main" onClick={(e) => { e.preventDefault(); document.getElementById("main").focus(); }}>Skip to content</a>
      <aside className="sidebar" data-open={menuOpen}>
        <div className="sidebar-inner">
        <div className="brand-row">
          <a className="brand" href={`#${encodeURIComponent(names[0])}`} onClick={go(names[0])} aria-label="GraphSentinel, overview">
            <span className="brand-mark"><Icon name="shield" size={20} /></span>
            <span className="brand-name">GraphSentinel</span>
          </a>
          <button type="button" className="menu-btn" aria-expanded={menuOpen} aria-controls="primary-nav" onClick={() => setMenuOpen((o) => !o)}>
            <Icon name={menuOpen ? "cross" : "menu"} size={20} /><span className="visually-hidden">Menu</span>
          </button>
        </div>
        <p className="brand-sub">Network intrusion detection</p>
        <nav id="primary-nav" className="nav" aria-label="Dashboard sections">
          <ul>
            {names.map((n) => (
              <li key={n} className={n === RESEARCH_NAMES[0] ? "nav-group-start" : undefined}>
                <a className="nav-item" href={`#${encodeURIComponent(n)}`} aria-current={n === page ? "page" : undefined} onClick={go(n)}>
                  <Icon name={ICONS[n]} size={18} /><span>{n}</span>
                </a>
              </li>
            ))}
          </ul>
        </nav>
        <div className="sidebar-foot">
          <EngineStatus />
          <ChainStatus page={page} />
          <ThemeSwitch />
        </div>
        </div>
      </aside>
      <main id="main" className="workspace" tabIndex={-1}>
        <div className="page">
          <header className="page-head">
            <h1>{page}</h1>
            <p className="lead">{ABOUT[page]}</p>
          </header>
          <Page key={page} />
        </div>
      </main>
    </div>
  );
}

createRoot(document.getElementById("root")).render(<StrictMode><App /></StrictMode>);
