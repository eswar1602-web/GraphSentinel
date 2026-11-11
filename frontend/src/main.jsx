import { StrictMode, useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import { PAGES } from "./pages";
import "./style.css";

function App() {
  const names = Object.keys(PAGES);
  const initial = decodeURIComponent(window.location.hash.slice(1)) || names[0];
  const [page, setPage] = useState(names.includes(initial) ? initial : names[0]);
  useEffect(() => { window.location.hash = encodeURIComponent(page); }, [page]);
  const Page = PAGES[page];
  return (
    <div className="app">
      <nav>
        <div className="brand">GraphSentinel</div>
        <div className="sub">graph-based NIDS · CICIDS2017</div>
        {names.map((n) => <button key={n} className={n === page ? "active" : ""} onClick={() => setPage(n)}>{n}</button>)}
      </nav>
      <main><h2>{page}</h2><Page /></main>
    </div>
  );
}

createRoot(document.getElementById("root")).render(<StrictMode><App /></StrictMode>);
