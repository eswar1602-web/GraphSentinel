"""REST and WebSocket API of the live network simulation (mounted under /api/sim by src/api/main.py).

All traffic is synthetic (src/simulation). No endpoint captures packets, opens connections or blocks traffic:
incident status changes are analyst bookkeeping only.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import re
from datetime import datetime, timezone
from typing import Any, Literal

from fastapi import APIRouter, HTTPException, Query, WebSocket, WebSocketDisconnect
from pydantic import BaseModel, ConfigDict, Field
from pydantic import ValidationError as PydanticValidationError

from src.api import db
from src.cryptography.audit_log import AuditLog
from src.simulation.config import load_config
from src.simulation.engine import Event, SimulationEngine, SimulationError
from src.simulation.incidents import STATUSES
from src.simulation.ml import MLDetector
from src.simulation.scenarios import CATALOG
from src.simulation.store import SimStore

log = logging.getLogger("graphsentinel.api.simulation")
router = APIRouter(prefix="/api/sim", tags=["simulation"])

TOPICS = ("status", "flows", "graph_update", "detection", "incident", "scenario")
DEVICE_ID = r"^[a-z]{2,4}-\d{2,3}$"
STATE: dict[str, Any] = {}


class Hub:
    """Fan-out of engine events to WebSocket clients. Each client has a bounded queue; when a slow client's queue
    is full its oldest message is dropped (and counted), so memory stays bounded."""

    def __init__(self, queue_size: int) -> None:
        self.queue_size = queue_size
        self.clients: dict[int, tuple[asyncio.Queue, set[str]]] = {}
        self.n = 0
        self.sent = 0
        self.dropped = 0

    def add(self, topics: set[str]) -> tuple[int, asyncio.Queue]:
        self.n += 1
        q: asyncio.Queue = asyncio.Queue(maxsize=self.queue_size)
        self.clients[self.n] = (q, topics)
        return self.n, q

    def remove(self, cid: int) -> None:
        self.clients.pop(cid, None)

    def publish(self, events: list[Event]) -> None:
        """Must be called from the event-loop thread."""
        ts = datetime.now(timezone.utc).isoformat(timespec="milliseconds")
        for typ, data in events:
            msg = {"type": typ, "ts": ts, "data": data}
            for q, topics in list(self.clients.values()):
                if typ not in topics:
                    continue
                if q.full():
                    q.get_nowait()
                    self.dropped += 1
                q.put_nowait(msg)
                self.sent += 1


def engine() -> SimulationEngine:
    if "engine" not in STATE:
        cfg = load_config(os.environ.get("GRAPHSENTINEL_SIM_CONFIG"))
        STATE["engine"] = SimulationEngine(cfg, SimStore(), lambda: AuditLog(db.DB_PATH),
                                           MLDetector(cfg.ml.min_confidence))
        STATE["hub"] = Hub(cfg.limits.ws_queue)
        STATE["task"] = None
    return STATE["engine"]


def hub() -> Hub:
    engine()
    return STATE["hub"]


async def _stop_loop(reason: str = "requested") -> None:
    eng = engine()
    if eng.status == "running":
        eng.stop(reason)
    task = STATE.get("task")
    if task is not None and not task.done():
        try:
            await asyncio.wait_for(task, timeout=30)
        except asyncio.TimeoutError:
            task.cancel()
    STATE["task"] = None


async def shutdown() -> None:
    """Called from the app lifespan: stop a running simulation cleanly (audited as a stop)."""
    if "engine" in STATE:
        await _stop_loop("server shutdown")


def _err(exc: Exception) -> HTTPException:
    if isinstance(exc, SimulationError):
        return HTTPException(409, str(exc))
    if isinstance(exc, KeyError):
        return HTTPException(404, f"not found: {exc.args[0] if exc.args else exc}")
    if isinstance(exc, PydanticValidationError):
        return HTTPException(422, exc.errors(include_url=False, include_context=False))
    if isinstance(exc, ValueError):
        return HTTPException(422, str(exc))
    log.error("unexpected simulation error", exc_info=exc)
    return HTTPException(500, "internal simulation error (see server log)")


# --------------------------------------------------------------------------- request bodies
class _Body(BaseModel):
    model_config = ConfigDict(extra="forbid")


class StartRequest(_Body):
    speed: float | None = Field(None, gt=0, le=100, description="simulated seconds per wall second")
    tick_interval_s: float | None = Field(None, ge=0.02, le=10)
    duration_s: float | None = Field(None, gt=0, le=7 * 24 * 3600, description="simulated seconds")


class ResetRequest(_Body):
    seed: int | None = Field(None, ge=0, le=2**32 - 1)
    start_time: datetime | None = None
    network: dict[str, int] | None = None
    traffic: dict[str, float | bool | int] | None = None
    detection: dict[str, Any] | None = None


class StepRequest(_Body):
    seconds: float = Field(5.0, gt=0, le=600)


class ScenarioRequest(_Body):
    name: Literal["normal", "port_scan", "dos", "lateral_movement", "brute_force", "suspicious_outbound"]
    attacker: str | None = Field(None, pattern=DEVICE_ID)
    targets: list[str] | None = Field(None, max_length=20)
    duration_s: float | None = Field(None, gt=0, le=86_400)
    intensity: float = Field(1.0, ge=0.1, le=10)


class IncidentUpdate(_Body):
    status: Literal["open", "acknowledged", "investigating", "resolved", "false_positive"]
    note: str | None = Field(None, max_length=500)


# --------------------------------------------------------------------------- lifecycle
@router.get("/status")
def status() -> dict[str, Any]:
    return {**engine().status_dict(), "websocket_clients": len(hub().clients)}


@router.post("/start")
async def start(body: StartRequest | None = None) -> dict[str, Any]:
    eng, h = engine(), hub()
    b = body or StartRequest()
    try:
        st = eng.start(b.speed, b.tick_interval_s, b.duration_s)
    except Exception as exc:  # noqa: BLE001
        raise _err(exc) from exc
    STATE["task"] = asyncio.create_task(eng.run_loop(h.publish))
    h.publish([("status", st)])
    return st


@router.post("/stop")
async def stop() -> dict[str, Any]:
    eng = engine()
    if eng.status != "running":
        raise HTTPException(409, f"the simulation is not running (status: {eng.status})")
    await _stop_loop()
    st = eng.status_dict()
    hub().publish([("status", st)])
    return st


@router.post("/reset")
async def reset(body: ResetRequest | None = None) -> dict[str, Any]:
    eng = engine()
    b = body or ResetRequest()
    await _stop_loop("reset")
    over = {k: v for k, v in (("network", b.network), ("traffic", b.traffic), ("detection", b.detection)) if v}
    if b.start_time is not None:
        over["start_time"] = b.start_time
    try:
        st = await asyncio.to_thread(eng.reset, b.seed, over)
    except Exception as exc:  # noqa: BLE001
        raise _err(exc) from exc
    hub().publish([("status", st), ("graph_update", {"reset": True, **eng.topology()})])
    return st


@router.post("/step")
async def step(body: StepRequest) -> dict[str, Any]:
    """Advance a stopped/idle simulation by ``seconds`` of simulated time (deterministic, for demos and tests)."""
    eng = engine()
    try:
        events = await asyncio.to_thread(eng.step, body.seconds)
    except Exception as exc:  # noqa: BLE001
        raise _err(exc) from exc
    hub().publish(events)
    return {"status": eng.status_dict(),
            "flows": next((d["count"] for t, d in events if t == "flows"), 0),
            "detections": [{"id": d["id"], "event": d["event"], "rule": d["rule"], "severity": d["severity"]}
                           for t, d in events if t == "detection"],
            "incidents": [{"id": d["id"], "event": d["event"], "severity": d["severity"], "title": d["title"]}
                          for t, d in events if t == "incident"]}


# --------------------------------------------------------------------------- scenarios
@router.get("/scenarios")
def scenarios() -> dict[str, Any]:
    return engine().scenarios_dict()


@router.post("/scenarios")
async def launch(body: ScenarioRequest) -> dict[str, Any]:
    if body.targets and any(not re.fullmatch(DEVICE_ID, t) for t in body.targets):
        raise HTTPException(422, "invalid target device id")
    try:
        res = engine().launch_scenario(body.name, body.attacker, body.targets, body.duration_s, body.intensity)
    except Exception as exc:  # noqa: BLE001
        raise _err(exc) from exc
    hub().publish([("scenario", {"event": "selected" if body.name == "normal" else "started", **res})])
    return res


@router.delete("/scenarios/{instance_id}")
async def stop_scenario(instance_id: str) -> dict[str, Any]:
    try:
        res = engine().stop_scenario(instance_id)
    except Exception as exc:  # noqa: BLE001
        raise _err(exc) from exc
    hub().publish([("scenario", {"event": "stopped", **res})])
    return res


# --------------------------------------------------------------------------- graph, flows, stats
@router.get("/topology")
def topology(active_only: bool = False, suspicious_only: bool = False) -> dict[str, Any]:
    return engine().topology(active_only, suspicious_only)


@router.get("/flows")
def flows(limit: int = Query(100, ge=1, le=1000), src: str | None = Query(None, pattern=DEVICE_ID),
          dst: str | None = Query(None, pattern=DEVICE_ID), suspicious_only: bool = False,
          scenario: Literal["normal", "port_scan", "dos", "lateral_movement", "brute_force", "suspicious_outbound"] | None = None
          ) -> dict[str, Any]:
    return engine().flow_list(limit, src, dst, suspicious_only, scenario)


@router.get("/flows/{flow_id}")
def flow(flow_id: str) -> dict[str, Any]:
    f = engine().flow(flow_id)
    if f is None:
        raise HTTPException(404, "flow not in the in-memory buffer (unknown or evicted)")
    return f


@router.get("/stats")
def stats() -> dict[str, Any]:
    h = hub()
    return {**engine().stats(), "websocket": {"clients": len(h.clients), "messages_sent": h.sent,
                                              "messages_dropped": h.dropped, "queue_size": h.queue_size}}


@router.get("/ml")
def ml() -> dict[str, Any]:
    eng = engine()
    return eng.ml.report if eng.ml else {"available": False, "reason": "ML detector not configured"}


@router.get("/runs")
def runs(limit: int = Query(20, ge=1, le=200)) -> list[dict[str, Any]]:
    return engine().store.runs(limit)


# --------------------------------------------------------------------------- detections and incidents
def _run(run_id: str | None) -> str | None:
    return None if run_id == "all" else (run_id or engine().run_id)


@router.get("/detections")
def detections(run_id: str | None = Query(None, max_length=16, description="default: current run; 'all' for every run"),
               severity: Literal["low", "medium", "high", "critical"] | None = None,
               rule: str | None = Query(None, max_length=40), incident_id: str | None = Query(None, max_length=40),
               limit: int = Query(100, ge=1, le=1000), offset: int = Query(0, ge=0)) -> list[dict[str, Any]]:
    return engine().store.alerts(_run(run_id), severity, rule, incident_id, limit, offset)


@router.get("/detections/{alert_id}")
def detection(alert_id: str) -> dict[str, Any]:
    a = engine().store.alert(alert_id)
    if a is None:
        raise HTTPException(404, "detection not found")
    return a


@router.get("/incidents")
def incidents(run_id: str | None = Query(None, max_length=16, description="default: current run; 'all' for every run"),
              status: Literal["open", "acknowledged", "investigating", "resolved", "false_positive"] | None = None,
              limit: int = Query(100, ge=1, le=1000), offset: int = Query(0, ge=0)) -> list[dict[str, Any]]:
    return engine().store.incidents(_run(run_id), status, limit, offset)


@router.get("/incidents/{incident_id}")
def incident(incident_id: str) -> dict[str, Any]:
    inc = engine().store.incident(incident_id)
    if inc is None:
        raise HTTPException(404, "incident not found")
    inc["detections"] = engine().store.alerts(None, incident_id=incident_id, limit=1000)
    return inc


@router.patch("/incidents/{incident_id}")
async def update_incident(incident_id: str, body: IncidentUpdate) -> dict[str, Any]:
    try:
        inc = engine().update_incident(incident_id, body.status, body.note)
    except Exception as exc:  # noqa: BLE001
        raise _err(exc) from exc
    hub().publish([("incident", {"event": "status_changed", **inc})])
    return inc


# --------------------------------------------------------------------------- streaming
@router.websocket("/ws")
async def ws(websocket: WebSocket, topics: str | None = None) -> None:
    """Server push of simulation events. Query ``topics`` (comma separated, default all) filters message types:
    status, flows, graph_update, detection, incident, scenario. Client messages (JSON):
    {"action": "subscribe", "topics": [...]}, {"action": "snapshot"}, {"action": "ping"}."""
    want = set(TOPICS) if not topics else {t.strip() for t in topics.split(",")}
    if not want <= set(TOPICS):
        await websocket.close(code=1008, reason=f"unknown topics: {sorted(want - set(TOPICS))}")
        return
    await websocket.accept()
    eng, h = engine(), hub()
    cid, q = h.add(want)
    await websocket.send_json({"type": "hello", "data": {"client_id": cid, "topics": sorted(want),
                                                         "status": eng.status_dict(), "scenarios": list(CATALOG),
                                                         "incident_statuses": list(STATUSES)}})

    async def sender() -> None:
        while True:
            await websocket.send_json(await q.get())

    async def receiver() -> None:
        while True:
            try:
                msg = json.loads(await websocket.receive_text())
            except json.JSONDecodeError:
                await websocket.send_json({"type": "error", "data": {"message": "messages must be JSON"}})
                continue
            act = msg.get("action") if isinstance(msg, dict) else None
            if act == "ping":
                await websocket.send_json({"type": "pong", "data": {}})
            elif act == "snapshot":
                await websocket.send_json({"type": "snapshot", "data": {"status": eng.status_dict(), "topology": eng.topology()}})
            elif act == "subscribe" and isinstance(msg.get("topics"), list) and set(msg["topics"]) <= set(TOPICS):
                h.clients[cid] = (q, set(msg["topics"]))
                await websocket.send_json({"type": "subscribed", "data": {"topics": sorted(msg["topics"])}})
            else:
                await websocket.send_json({"type": "error", "data": {"message": "unknown action"}})

    tasks = [asyncio.create_task(sender()), asyncio.create_task(receiver())]
    try:
        done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for t in pending:
            t.cancel()
        for t in done:
            exc = t.exception()
            if exc is not None and not isinstance(exc, (WebSocketDisconnect, RuntimeError)):
                log.warning("websocket client %d ended with %r", cid, exc)
    finally:
        h.remove(cid)
