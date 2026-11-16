import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Dev: `npm run dev` on :5173 proxies /api (REST and the /api/sim/ws WebSocket) to the FastAPI backend on :8000,
// or to GRAPHSENTINEL_API if set (e.g. $env:GRAPHSENTINEL_API="http://127.0.0.1:8001").
// Prod: `npm run build` -> dist/, served by FastAPI at http://127.0.0.1:8000/.
const API = process.env.GRAPHSENTINEL_API || "http://127.0.0.1:8000";

export default defineConfig({
  plugins: [react()],
  server: { port: 5173, proxy: { "/api": { target: API, ws: true } } },
  // index.html: the live security console (src/console). legacy.html: the earlier dashboard (src/main.jsx), unchanged.
  build: { outDir: "dist", chunkSizeWarningLimit: 6000,
           rollupOptions: { input: { main: "index.html", legacy: "legacy.html" } } },
});
