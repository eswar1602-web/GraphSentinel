"""REST and WebSocket tests of the live-simulation API (/api/sim), using a real model trained on synthetic data."""
from __future__ import annotations

import time
from pathlib import Path

import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402
from starlette.websockets import WebSocketDisconnect  # noqa: E402

from src.api import db, results, services, simulation  # noqa: E402


@pytest.fixture()
def client(trained_detector: dict, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    cfg = tmp_path / "simulation.yaml"
    cfg.write_text("seed: 21\nstart_time: 2026-03-02T08:00:00Z\nclock: {speed: 30, tick_interval_s: 0.05}\n", encoding="utf-8")
    monkeypatch.setenv("GRAPHSENTINEL_SIM_CONFIG", str(cfg))
    monkeypatch.setattr(services, "PROCESSED", trained_detector["processed"])
    monkeypatch.setattr(services, "DETECTOR_MODEL", trained_detector["model"])
    monkeypatch.setattr(results, "RESULTS", tmp_path / "results")
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "api.sqlite")
    monkeypatch.setenv("GRAPHSENTINEL_HMAC_KEY_FILE", str(tmp_path / "keys" / "hmac.key"))
    monkeypatch.delenv("GRAPHSENTINEL_HMAC_KEY", raising=False)
    services.Detector.load.__func__.cache_clear()
    simulation.STATE.clear()
    from src.api.main import app
    with TestClient(app) as c:
        yield c
    simulation.STATE.clear()
    services.Detector.load.__func__.cache_clear()


def wait_for(ws, types: set[str], timeout: float = 30.0) -> dict[str, dict]:
    seen: dict[str, dict] = {}
    t = time.time()
    while not types <= seen.keys():
        assert time.time() - t < timeout, f"timed out; saw {sorted(seen)}"
        m = ws.receive_json()
        seen.setdefault(m["type"], m)
    return seen


def test_status_ml_and_topology(client: TestClient) -> None:
    st = client.get("/api/sim/status").json()
    assert st["status"] == "idle" and st["seed"] == 21 and st["sim_start"].startswith("2026-03-02T08:00:00")
    assert st["ml"]["available"] and st["ml"]["compatible"]
    ml = client.get("/api/sim/ml").json()
    assert ml["missing_features"] == [] and "out-of-distribution" in ml["caveat"]
    topo = client.get("/api/sim/topology").json()
    roles = {n["role"] for n in topo["nodes"]}
    assert roles == {"workstation", "laptop", "app_server", "db_server", "dns_server", "router", "external"}
    assert topo["edges"] == [] and topo["counts"]["workstation"] == 12
    cat = client.get("/api/sim/scenarios").json()["catalog"]
    assert [c["name"] for c in cat] == ["normal", "port_scan", "dos", "lateral_movement", "brute_force", "suspicious_outbound"]


def test_acceptance_flow_over_rest_and_websocket(client: TestClient) -> None:
    """Start -> normal traffic -> graph -> port scan -> detection -> incident -> SQLite -> audit -> WS -> stop."""
    with client.websocket_connect("/api/sim/ws") as ws:
        hello = ws.receive_json()
        assert hello["type"] == "hello" and hello["data"]["status"]["status"] == "idle"
        r = client.post("/api/sim/start", json={"speed": 40, "tick_interval_s": 0.05})
        assert r.status_code == 200 and r.json()["status"] == "running"
        assert client.post("/api/sim/start").status_code == 409
        got = wait_for(ws, {"flows", "graph_update", "status"})
        assert got["flows"]["data"]["count"] >= 0 and "nodes" in got["graph_update"]["data"]
        t = time.time()
        while client.get("/api/sim/status").json()["sim_elapsed_s"] < 150:      # baseline warm-up (120 s)
            assert time.time() - t < 60
            time.sleep(0.05)
        r = client.post("/api/sim/scenarios", json={"name": "port_scan", "attacker": "ws-04", "targets": ["app-01"]})
        assert r.status_code == 200 and r.json()["attacker"] == "ws-04"
        t = time.time()
        det = inc = None
        while det is None or inc is None:
            assert time.time() - t < 60, "port scan not detected"
            m = ws.receive_json()
            if m["type"] == "detection" and m["data"]["rule"] == "port_scan":
                det = m["data"]
            if m["type"] == "incident" and m["data"]["actor"] == "ws-04":
                inc = m["data"]
        r = client.post("/api/sim/stop")
        assert r.status_code == 200 and r.json()["status"] == "stopped"
    assert det["src"] == "ws-04" and det["dst_devices"] == ["app-01"] and det["evidence"]["distinct_ports"] >= 20
    assert det["flow_ids"] and "distinct ports" in det["explanation"]
    # graph reflects traffic and the indicator
    topo = client.get("/api/sim/topology", params={"suspicious_only": True}).json()
    edge = next(e for e in topo["edges"] if e["source"] == "ws-04" and e["target"] == "app-01")
    assert "port_scan" in edge["indicators"] and edge["distinct_ports"] >= 20
    assert client.get("/api/sim/topology", params={"active_only": True}).json()["edges"]
    # flows
    fl = client.get("/api/sim/flows", params={"src": "ws-04", "suspicious_only": True, "limit": 5}).json()
    assert fl["returned"] == 5 and all(f["alert_ids"] for f in fl["flows"])
    one = client.get(f"/api/sim/flows/{det['flow_ids'][-1]}").json()
    assert one["ground_truth_scenario"] == "port_scan" and len(one["features"]) == 69 and one["ml"] is not None
    assert client.get("/api/sim/flows/nope").status_code == 404
    # persisted detections and incidents (SQLite)
    dets = client.get("/api/sim/detections", params={"rule": "port_scan"}).json()
    assert dets and dets[0]["id"] == det["id"] and dets[0]["incident_id"]
    incs = client.get("/api/sim/incidents").json()
    i = next(x for x in incs if x["actor"] == "ws-04")
    full = client.get(f"/api/sim/incidents/{i['id']}").json()
    assert any(d["id"] == det["id"] for d in full["detections"]) and full["flow_ids"]
    with db.connect() as c:
        assert c.execute("SELECT COUNT(*) FROM sim_alerts WHERE rule='port_scan'").fetchone()[0] >= 1
        assert c.execute("SELECT status FROM sim_runs").fetchone()[0] == "stopped"
    # incident workflow
    r = client.patch(f"/api/sim/incidents/{i['id']}", json={"status": "investigating", "note": "scan from ws-04"})
    assert r.status_code == 200 and r.json()["history"][-1]["note"] == "scan from ws-04"
    assert client.patch(f"/api/sim/incidents/{i['id']}", json={"status": "acknowledged"}).status_code == 422
    assert client.patch(f"/api/sim/incidents/{i['id']}", json={"status": "deleted"}).status_code == 422
    assert client.patch("/api/sim/incidents/INC-x-0001", json={"status": "resolved"}).status_code == 404
    # audit chain records the security events and verifies
    kinds = [x["event_type"] for x in client.get("/api/audit/records", params={"limit": 1000}).json()["records"]]
    for k in ("simulation_start", "scenario_started", "detection_alert", "incident_created", "simulation_stopped",
              "incident_status_changed"):
        assert k in kinds, k
    assert client.get("/api/audit/verify").json()["valid"]
    st = client.get("/api/sim/stats").json()
    assert st["totals"]["flows"] > 0 and st["alerts_by_rule"]["port_scan"] >= 1 and st["websocket"]["messages_sent"] > 0
    assert st["evaluation_against_ground_truth"]["flows_by_scenario"]["port_scan"] > 0
    assert client.get("/api/sim/runs").json()[0]["status"] == "stopped"


def test_manual_step_reset_and_validation(client: TestClient) -> None:
    assert client.post("/api/sim/stop").status_code == 409
    r = client.post("/api/sim/step", json={"seconds": 130})
    assert r.status_code == 200 and r.json()["flows"] > 0 and r.json()["status"]["sim_elapsed_s"] == 130
    assert client.post("/api/sim/scenarios", json={"name": "brute_force"}).status_code == 200
    r = client.post("/api/sim/step", json={"seconds": 30})
    assert any(d["rule"] == "brute_force" for d in r.json()["detections"])
    sc = client.get("/api/sim/scenarios").json()["active"]
    assert len(sc) == 1
    assert client.delete(f"/api/sim/scenarios/{sc[0]['id']}").status_code == 200
    assert client.delete("/api/sim/scenarios/SC-x").status_code == 404
    assert client.post("/api/sim/scenarios", json={"name": "teleport"}).status_code == 422
    assert client.post("/api/sim/scenarios", json={"name": "dos", "attacker": "x; DROP"}).status_code == 422
    assert client.post("/api/sim/scenarios", json={"name": "dos", "attacker": "ws-99"}).status_code == 404
    assert client.post("/api/sim/scenarios", json={"name": "dos", "intensity": 50}).status_code == 422
    assert client.post("/api/sim/scenarios", json={"name": "dos", "targets": ["bad id"]}).status_code == 422
    assert client.post("/api/sim/step", json={"seconds": 0}).status_code == 422
    assert client.post("/api/sim/start", json={"speed": 0}).status_code == 422
    old = client.get("/api/sim/status").json()["run_id"]
    r = client.post("/api/sim/reset", json={"seed": 99, "network": {"workstations": 4}})
    assert r.status_code == 200 and r.json()["run_id"] != old and r.json()["devices"] < 30
    assert client.post("/api/sim/reset", json={"network": {"workstations": 1}}).status_code == 422
    assert client.get("/api/sim/detections").json() == []                       # new run: nothing yet
    assert client.get("/api/sim/detections", params={"run_id": "all"}).json()  # earlier run still persisted
    assert client.get("/api/sim/detections", params={"severity": "urgent"}).status_code == 422


def test_websocket_topics_and_actions(client: TestClient) -> None:
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect("/api/sim/ws?topics=bogus") as ws:
            ws.receive_json()
    with client.websocket_connect("/api/sim/ws?topics=incident") as ws:
        assert ws.receive_json()["data"]["topics"] == ["incident"]
        ws.send_json({"action": "ping"})
        assert ws.receive_json()["type"] == "pong"
        ws.send_text("not json")
        assert ws.receive_json()["type"] == "error"
        ws.send_json({"action": "snapshot"})
        snap = ws.receive_json()
        assert snap["type"] == "snapshot" and snap["data"]["topology"]["nodes"]
        client.post("/api/sim/step", json={"seconds": 10})          # flows only: filtered out for this client
        ws.send_json({"action": "subscribe", "topics": ["status"]})
        assert ws.receive_json()["type"] == "subscribed"
        client.post("/api/sim/step", json={"seconds": 5})
        assert ws.receive_json()["type"] == "status"


def test_server_shutdown_stops_running_simulation(client: TestClient) -> None:
    assert client.post("/api/sim/start").status_code == 200
    t = time.time()
    while client.get("/api/sim/status").json()["ticks"] < 2:
        assert time.time() - t < 30
        time.sleep(0.05)
    client.__exit__(None, None, None)                    # runs the app lifespan shutdown
    eng = simulation.STATE["engine"]
    assert eng.status == "stopped" and simulation.STATE["task"] is None
    from src.cryptography.audit_log import AuditLog
    last = [r for r in AuditLog(db.DB_PATH).records() if r["event_type"] == "simulation_stopped"][-1]
    assert last["details"]["reason"] == "server shutdown"
