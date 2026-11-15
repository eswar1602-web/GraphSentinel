// One icon set for the whole dashboard: 24px grid, 1.75 stroke, currentColor. Decorative, so aria-hidden.
const P = {
  overview: <><rect x="3.5" y="3.5" width="7" height="9" rx="1.5" /><rect x="13.5" y="3.5" width="7" height="5" rx="1.5" /><rect x="13.5" y="11.5" width="7" height="9" rx="1.5" /><rect x="3.5" y="15.5" width="7" height="5" rx="1.5" /></>,
  dataset: <><ellipse cx="12" cy="5.5" rx="7.5" ry="2.5" /><path d="M4.5 5.5v6.5c0 1.4 3.4 2.5 7.5 2.5s7.5-1.1 7.5-2.5V5.5" /><path d="M4.5 12v6.5c0 1.4 3.4 2.5 7.5 2.5s7.5-1.1 7.5-2.5V12" /></>,
  detection: <><path d="M12 3l7.5 3v5.5c0 4.6-3.2 8.3-7.5 9.5-4.3-1.2-7.5-4.9-7.5-9.5V6L12 3z" /><path d="M8.8 12.2l2.2 2.2 4.3-4.6" /></>,
  graph: <><circle cx="6" cy="6" r="2.5" /><circle cx="18" cy="8" r="2.5" /><circle cx="9" cy="18" r="2.5" /><path d="M8.3 7.1l7.3.6M7 8.3l1.3 7.3M10.9 16.4l5.5-6.4" /></>,
  aggregation: <><circle cx="5.5" cy="5.5" r="2" /><circle cx="5.5" cy="18.5" r="2" /><circle cx="5.5" cy="12" r="2" /><circle cx="18.5" cy="12" r="2.5" /><path d="M7.4 6.3l8.9 4.6M7.5 12h8.5M7.4 17.7l8.9-4.6" /></>,
  models: <><path d="M4 20h16" /><rect x="5.5" y="11" width="3" height="7" rx="0.5" /><rect x="10.5" y="5" width="3" height="13" rx="0.5" /><rect x="15.5" y="8.5" width="3" height="9.5" rx="0.5" /></>,
  robustness: <><path d="M3.5 12h3.5l2.5-6.5 5 13 2.5-6.5h3.5" /></>,
  audit: <><path d="M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1.2 1.2" /><path d="M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1.2-1.2" /></>,
  upload: <><path d="M12 15.5V4.5M7.5 9L12 4.5 16.5 9" /><path d="M4.5 15v3a2 2 0 0 0 2 2h11a2 2 0 0 0 2-2v-3" /></>,
  play: <><path d="M7.5 5.2v13.6a.8.8 0 0 0 1.2.7l10.6-6.8a.8.8 0 0 0 0-1.4L8.7 4.5a.8.8 0 0 0-1.2.7z" /></>,
  refresh: <><path d="M19.5 12a7.5 7.5 0 1 1-2.2-5.3" /><path d="M19.5 4.5v4h-4" /></>,
  check: <><path d="M5 12.5l4.5 4.5L19 7.5" /></>,
  cross: <><path d="M6.5 6.5l11 11M17.5 6.5l-11 11" /></>,
  alert: <><path d="M12 4l9 15.5H3L12 4z" /><path d="M12 10v4.2M12 17.2v.3" /></>,
  info: <><circle cx="12" cy="12" r="8.5" /><path d="M12 11v5.5M12 7.8v.3" /></>,
  fit: <><path d="M4.5 9V4.5H9M15 4.5h4.5V9M19.5 15v4.5H15M9 19.5H4.5V15" /></>,
  sun: <><circle cx="12" cy="12" r="3.8" /><path d="M12 2.8v2M12 19.2v2M2.8 12h2M19.2 12h2M5.5 5.5l1.4 1.4M17.1 17.1l1.4 1.4M5.5 18.5l1.4-1.4M17.1 6.9l1.4-1.4" /></>,
  moon: <><path d="M19.5 14.2A7.8 7.8 0 0 1 9.8 4.5a7.8 7.8 0 1 0 9.7 9.7z" /></>,
  monitor: <><rect x="3.5" y="4.5" width="17" height="11.5" rx="1.5" /><path d="M9 20h6M12 16v4" /></>,
  menu: <><path d="M4 7h16M4 12h16M4 17h16" /></>,
  file: <><path d="M14 3.5H7a1.5 1.5 0 0 0-1.5 1.5v14A1.5 1.5 0 0 0 7 20.5h10a1.5 1.5 0 0 0 1.5-1.5V8z" /><path d="M14 3.5V8h4.5" /></>,
  history: <><path d="M4.5 12a7.5 7.5 0 1 0 2.2-5.3" /><path d="M4.5 4.5v4h4" /><path d="M12 8v4.2l2.8 1.8" /></>,
  shield: <><path d="M12 3l7.5 3v5.5c0 4.6-3.2 8.3-7.5 9.5-4.3-1.2-7.5-4.9-7.5-9.5V6L12 3z" /></>,
};

export function Icon({ name, size = 18, className = "" }) {
  return (
    <svg className={`icon ${className}`} width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor"
      strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" focusable="false">
      {P[name]}
    </svg>
  );
}
