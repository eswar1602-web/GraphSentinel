// Shared console components. Square, hairline-divided surfaces; measurements in mono; every data region has
// loading, empty, error and full states.
import { Component, useEffect, useState } from "react";
import { api } from "../api";

// Fetch JSON; keeps the previous data while a new request runs (filters do not flash empty). `loading` is true
// until a response for the current path has arrived, so a caller never sees "not loading and no data".
export function useData(path, deps = []) {
  const [s, setS] = useState({ data: null, error: null, loading: true, for: undefined });
  const [n, setN] = useState(0);
  useEffect(() => {
    if (!path) { setS({ data: null, error: null, loading: false, for: path }); return undefined; }
    let alive = true;
    setS((p) => ({ ...p, loading: true, error: null }));
    api(path).then((data) => alive && setS({ data, error: null, loading: false, for: path }))
      .catch((error) => alive && setS((p) => ({ data: p.data, error, loading: false, for: path })));
    return () => { alive = false; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [path, n, ...deps]);
  const settled = s.for === path;
  return { data: s.data, error: settled ? s.error : null, loading: s.loading || !settled, reload: () => setN((x) => x + 1) };
}

export class Boundary extends Component {
  constructor(props) { super(props); this.state = { error: null }; }
  static getDerivedStateFromError(error) { return { error }; }
  componentDidCatch(error, info) { console.error("console page failed", error, info.componentStack); }
  render() {
    if (!this.state.error) return this.props.children;
    return (
      <div className="failure" role="alert">
        <p><strong>This page hit an error.</strong> {String(this.state.error.message || this.state.error)}</p>
        <button type="button" className="btn btn--quiet btn--sm" onClick={() => this.setState({ error: null })}>Try again</button>
      </div>
    );
  }
}

export function PageHead({ title, children, actions }) {
  return (
    <header className="page-head">
      <div>
        <h1>{title}</h1>
        {children && <p className="lead">{children}</p>}
      </div>
      {actions && <div className="page-actions">{actions}</div>}
    </header>
  );
}

export function Section({ title, note, actions, children, className = "", id }) {
  return (
    <section className={`section ${className}`} aria-labelledby={id ? `${id}-h` : undefined}>
      <div className="section-head">
        <div>
          <h2 id={id ? `${id}-h` : undefined}>{title}</h2>
          {note && <p className="note">{note}</p>}
        </div>
        {actions && <div className="section-actions">{actions}</div>}
      </div>
      {children}
    </section>
  );
}

export function Figures({ items }) {
  return (
    <dl className="figures">
      {items.map(([label, value, unit]) => (
        <div key={label}>
          <dt>{label}</dt>
          <dd><span className="measure">{value}</span>{unit && <span className="unit">{unit}</span>}</dd>
        </div>
      ))}
    </dl>
  );
}

export function Severity({ level }) {
  return <span className={`sev sev--${level}`}><span className="sev-mark" aria-hidden="true" />{level}</span>;
}

export function StatusWord({ status }) {
  const label = { idle: "Idle", running: "Running", stopped: "Stopped", completed: "Completed", error: "Error" }[status] || status;
  return <span className={`state state--${status}`}>{label}</span>;
}

export function Loading({ rows = 4, label = "Loading" }) {
  return (
    <div className="skeleton" role="status" aria-label={label}>
      {Array.from({ length: rows }, (_, i) => <span key={i} style={{ width: `${92 - i * 11}%` }} />)}
    </div>
  );
}

export function Empty({ children, action }) {
  return <div className="empty"><p>{children}</p>{action}</div>;
}

export function Failure({ error, onRetry }) {
  return (
    <div className="failure" role="alert">
      <p><strong>Could not load this.</strong> {String(error?.message || error)}</p>
      {onRetry && <button type="button" className="btn btn--quiet btn--sm" onClick={onRetry}>Try again</button>}
    </div>
  );
}

// Loading / error / empty / full for one region.
export function Region({ state, isEmpty, emptyView, rows, children }) {
  if (state.error && !state.data) return <Failure error={state.error} onRetry={state.reload} />;
  if (state.loading && !state.data) return <Loading rows={rows} />;
  if (isEmpty && isEmpty(state.data)) return emptyView;
  return children(state.data);
}

export function KV({ items }) {
  return (
    <dl className="kv">
      {items.filter(Boolean).map(([k, v, mono]) => (
        <div key={k}><dt>{k}</dt><dd className={mono ? "measure" : undefined}>{v}</dd></div>
      ))}
    </dl>
  );
}

export function Field({ label, children, hint, htmlFor }) {
  return (
    <div className="field">
      <label htmlFor={htmlFor}>{label}</label>
      {children}
      <p className="hint">{hint || ""}</p>
    </div>
  );
}

export function Bars({ rows, total }) {
  const max = Math.max(1, ...rows.map((r) => r[1]));
  return (
    <ul className="bars">
      {rows.map(([label, n]) => (
        <li key={label}>
          <span className="bars-label">{label}</span>
          <span className="bars-track" aria-hidden="true"><span style={{ transform: `scaleX(${n / max})` }} /></span>
          <span className="measure">{n.toLocaleString("en-GB")}{total ? <span className="unit"> {Math.round((100 * n) / total)}%</span> : null}</span>
        </li>
      ))}
    </ul>
  );
}
