"""Acceptance demo against a running GraphSentinel server (REST + WebSocket). Synthetic traffic only.

    python -m uvicorn src.api.main:app --host 127.0.0.1 --port 8000      # terminal 1
    python -m src.simulation.demo --url http://127.0.0.1:8000             # terminal 2

Steps: reset -> start -> normal traffic and graph -> port scan -> detection -> incident -> SQLite -> audit ->
WebSocket stream -> stop. Prints what the server returned; exits non-zero if a step fails.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
from typing import Any

import httpx
import websockets


def _ok(step: str, detail: str) -> None:
    print(f"[ok] {step}: {detail}", flush=True)


async def run(url: str, seed: int, speed: float, timeout: float) -> int:
    ws_url = url.replace("http", "ws", 1).rstrip("/") + "/api/sim/ws?topics=status,graph_update,detection,incident"
    async with httpx.AsyncClient(base_url=url, timeout=30) as http, websockets.connect(ws_url, max_size=2**24) as ws:
        hello = json.loads(await ws.recv())
        _ok("websocket", f"connected as client {hello['data']['client_id']}")
        st = (await http.post("/api/sim/reset", json={"seed": seed})).raise_for_status().json()
        _ok("reset", f"run {st['run_id']}, {st['devices']} devices, ML available={st['ml']['available']} compatible={st['ml']['compatible']}")
        st = (await http.post("/api/sim/start", json={"speed": speed, "tick_interval_s": 0.5})).raise_for_status().json()
        _ok("1 start", f"status={st['status']} speed={st['clock']['speed']}x")
        counts: dict[str, int] = {}
        found: dict[str, dict[str, Any]] = {}
        t0 = time.time()

        async def pump(until: float, stop_when=lambda: False) -> None:
            while time.time() < until and not stop_when():
                try:
                    m = json.loads(await asyncio.wait_for(ws.recv(), timeout=max(0.1, until - time.time())))
                except asyncio.TimeoutError:
                    return
                counts[m["type"]] = counts.get(m["type"], 0) + 1
                if m["type"] == "detection" and m["data"]["rule"] == "port_scan":
                    found.setdefault("detection", m["data"])
                if m["type"] == "incident" and "port_scan" in m["data"]["rules"]:
                    found.setdefault("incident", m["data"])
                if m["type"] == "status":
                    found["status"] = m["data"]

        await pump(t0 + timeout, lambda: found.get("status", {}).get("sim_elapsed_s", 0) >= 150)
        topo = (await http.get("/api/sim/topology", params={"active_only": True})).raise_for_status().json()
        _ok("2 normal traffic", f"{found['status']['flows_generated']} flows in {found['status']['sim_elapsed_s']:.0f} simulated s")
        _ok("3 graph", f"{len(topo['nodes'])} active devices, {len(topo['edges'])} directed edges; "
                       f"{counts.get('graph_update', 0)} graph updates streamed")
        sc = (await http.post("/api/sim/scenarios", json={"name": "port_scan"})).raise_for_status().json()
        _ok("4 port scan", f"{sc['id']}: {sc['attacker']} -> {sc['targets']}")
        await pump(time.time() + timeout, lambda: "detection" in found and "incident" in found)
        if "detection" not in found or "incident" not in found:
            print("[fail] the port scan was not detected in time", file=sys.stderr)
            await http.post("/api/sim/stop")
            return 1
        d, i = found["detection"], found["incident"]
        _ok("5 detection", f"{d['id']} [{d['severity']}] {d['explanation']}")
        _ok("6 incident", f"{i['id']} [{i['severity']}] {i['title']}; {len(i['flow_ids'])} supporting flow IDs, e.g. {i['flow_ids'][:3]}")
        stored = (await http.get(f"/api/sim/incidents/{i['id']}")).raise_for_status().json()
        _ok("7 SQLite", f"incident persisted with {len(stored['detections'])} detection(s): {[x['rule'] for x in stored['detections']]}")
        recs = (await http.get("/api/audit/records", params={"limit": 1000})).raise_for_status().json()["records"]
        kinds = sorted({r["event_type"] for r in recs if r["event_type"].startswith(("simulation", "scenario", "detection_alert", "incident"))})
        ver = (await http.get("/api/audit/verify")).raise_for_status().json()
        _ok("8 audit", f"chain valid={ver['valid']} ({ver['records']} records); simulation events: {kinds}")
        _ok("9 websocket", f"messages received by type: {counts}")
        st = (await http.post("/api/sim/stop")).raise_for_status().json()
        _ok("10 stop", f"status={st['status']} after {st['flows_generated']} flows, {st['alerts']} alerts, {st['incidents']} incidents")
        ver = (await http.get("/api/audit/verify")).raise_for_status().json()
        return 0 if ver["valid"] and st["status"] == "stopped" else 1


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--url", default="http://127.0.0.1:8000")
    ap.add_argument("--seed", type=int, default=2017)
    ap.add_argument("--speed", type=float, default=20.0, help="simulated seconds per wall second")
    ap.add_argument("--timeout", type=float, default=60.0, help="wall seconds to wait for each phase")
    a = ap.parse_args(argv)
    try:
        sys.exit(asyncio.run(run(a.url, a.seed, a.speed, a.timeout)))
    except (httpx.HTTPError, OSError) as exc:
        sys.exit(f"cannot reach {a.url}: {exc} (is the server running?)")


if __name__ == "__main__":
    main()
