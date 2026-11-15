// Feature switches for the dashboard build.
// The research views (aggregation simulator, robustness, model comparison, NAT diagnostics) are kept in
// src/research.jsx and hidden by default. Restore them with:  $env:VITE_SHOW_RESEARCH="true"; npm run build
export const SHOW_RESEARCH = import.meta.env.VITE_SHOW_RESEARCH === "true";
