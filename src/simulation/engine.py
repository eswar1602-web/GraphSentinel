"""Simulation engine: clock, traffic generation, validation, graph updates, hybrid detection, incidents,
persistence, audit events and event streaming.

One ``step(dt)`` advances simulated time by ``dt`` seconds and runs the whole pipeline on the flows generated in
that interval. ``run_loop`` calls ``step(speed * tick_interval_s)`` every ``tick_interval_s`` wall seconds, so a
run is deterministic for a seed and a sequence of commands regardless of machine speed.
All state is bounded (see ``limits`` in configs/simulation.yaml); alerts and incidents are persisted in SQLite.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import secrets
import threading
import time
from collections import Counter, deque
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

import numpy as np

from src.cryptography.audit_log import AuditLog
from src.simulation.config import SimConfig, deep_merge
from src.simulation.flows import PROTOCOL_NAMES, Flow, FlowValidationError, validate_flow
from src.simulation.graph import LiveGraph
from src.simulation.incidents import CLOSED, AlertManager, IncidentManager, check_transition, now_iso
from src.simulation.ml import MLDetector
from src.simulation.network import Network
from src.simulation.rules import BehaviouralDetector
from src.simulation.scenarios import (CATALOG, FlowFactory, NormalTraffic, Scenario, default_participants,
                                      validate_participants)
from src.simulation.store import SimStore

log = logging.getLogger("graphsentinel.simulation")

Event = tuple[str, dict[str, Any]]
MAX_ACTIVE_SCENARIOS = 10
AUDIT_SEVERITIES = ("high", "critical")


class SimulationError(RuntimeError):
    """A command that is not valid in the current state (reported as HTTP 409)."""


def evidence_digest(flow_ids: list[str]) -> str:
    """SHA-256 over the canonical JSON list of supporting flow IDs; binds audit records to the evidence."""
    return hashlib.sha256(json.dumps(flow_ids, separators=(",", ":")).encode("utf-8")).hexdigest()


class SimulationEngine:
    def __init__(self, config: SimConfig, store: SimStore | None = None,
                 audit: Callable[[], AuditLog] | None = None, ml: MLDetector | None = None) -> None:
        self.base_config = config
        self.store = store
        self._audit_factory = audit
        self.ml = ml
        self._lock = threading.RLock()
        self.task: asyncio.Task | None = None
        self.audit_failures = 0
        if self.ml is not None and config.ml.enabled:
            self.ml.load()
        self._init_run(config, audited=False)

    # ------------------------------------------------------------------ lifecycle
    def _init_run(self, cfg: SimConfig, audited: bool = True) -> None:
        self.cfg = cfg
        self.run_id = secrets.token_hex(4)
        self.t_origin = cfg.start_time or datetime.now(timezone.utc).replace(microsecond=0)
        self.net = Network(cfg.network, cfg.seed)
        self.ss = np.random.SeedSequence(cfg.seed)
        self.rng = np.random.default_rng(self.ss.spawn(1)[0])
        self.factory = FlowFactory(self.run_id, self.t_origin)
        self.normal = NormalTraffic(self.net, cfg.traffic)
        self.scenarios: list[Scenario] = []
        self.finished_scenarios: deque[Scenario] = deque(maxlen=50)
        self.n_scenarios = 0
        self.graph = LiveGraph(self.net)
        self.rules = BehaviouralDetector(self.net, cfg.detection, cfg.limits.evidence_flow_ids)
        self.alerts = AlertManager(self.run_id, self.t_origin, cfg.detection.alert_merge_s, cfg.limits.alert_buffer,
                                   cfg.limits.evidence_flow_ids)
        self.incidents = IncidentManager(self.run_id, self.t_origin, cfg.incidents.correlation_window_s,
                                         cfg.ml.create_incidents, cfg.limits.incident_buffer, cfg.limits.evidence_flow_ids,
                                         cfg.incidents.min_severity_to_open)
        self.flows: deque[Flow] = deque(maxlen=cfg.limits.flow_buffer)
        self.flow_index: dict[str, Flow] = {}
        self.status = "idle"
        self.sim_t = 0.0
        self.ticks = 0
        self.created_at = now_iso()
        self.started_at: str | None = None
        self.stopped_at: str | None = None
        self.counters: Counter = Counter()
        self.protocols: Counter = Counter()
        self.truth: Counter = Counter()
        self.ml_pred: Counter = Counter()
        self.ml_confusion: Counter = Counter()           # (ground truth attack?, predicted attack?) for scored flows
        self.alert_eval: Counter = Counter()
        self.first_detection: dict[str, dict[str, Any]] = {}
        self.last_tick_ms = 0.0
        self._save_run()
        if audited:
            self._audit("simulation_reset", {"run_id": self.run_id, "seed": cfg.seed,
                                             "devices": len(self.net.devices)})

    def reset(self, seed: int | None = None, overrides: dict[str, Any] | None = None) -> dict[str, Any]:
        with self._lock:
            if self.status == "running":
                raise SimulationError("stop the simulation before resetting it")
            data = deep_merge(self.base_config.model_dump(), overrides or {})
            if seed is not None:
                data["seed"] = seed
            cfg = SimConfig.model_validate(data)
            old = self.run_id
            self._init_run(cfg, audited=False)
            self._audit("simulation_reset", {"previous_run_id": old, "run_id": self.run_id, "seed": cfg.seed,
                                             "devices": len(self.net.devices)})
            return self.status_dict()

    def start(self, speed: float | None = None, tick_interval_s: float | None = None,
              duration_s: float | None = None) -> dict[str, Any]:
        with self._lock:
            if self.status == "running":
                raise SimulationError("the simulation is already running")
            if self.status == "completed":
                raise SimulationError("the run has completed; reset it to start a new run")
            clock = self.cfg.clock.model_dump()
            for k, v in (("speed", speed), ("tick_interval_s", tick_interval_s), ("duration_s", duration_s)):
                if v is not None:
                    clock[k] = v
            self.cfg = self.cfg.model_copy(update={"clock": type(self.cfg.clock).model_validate(clock)})
            if self.cfg.clock.duration_s is not None and self.sim_t >= self.cfg.clock.duration_s:
                raise SimulationError("duration_s is already reached; use a larger duration or reset")
            self.status = "running"
            self.started_at = self.started_at or now_iso()
            self.stopped_at = None
            self._save_run()
            self._audit("simulation_start", {"run_id": self.run_id, "seed": self.cfg.seed, **self.cfg.clock.model_dump(),
                                             "sim_elapsed_s": round(self.sim_t, 3)})
            return self.status_dict()

    def stop(self, reason: str = "requested") -> dict[str, Any]:
        with self._lock:
            if self.status != "running":
                raise SimulationError(f"the simulation is not running (status: {self.status})")
            self._finish("stopped", reason)
            return self.status_dict()

    def _finish(self, status: str, reason: str) -> None:
        self.status = status
        self.stopped_at = now_iso()
        self._save_run()
        self._audit(f"simulation_{status}", {"run_id": self.run_id, "reason": reason, "sim_elapsed_s": round(self.sim_t, 3),
                                             "flows": self.counters["flows"], "alerts": self.alerts.n,
                                             "incidents": self.incidents.n})

    async def run_loop(self, publish: Callable[[list[Event]], None]) -> None:
        """Tick until stopped or completed. Each step runs in a worker thread so the event loop stays responsive."""
        try:
            while self.status == "running":
                t0 = time.perf_counter()
                dt = self.cfg.clock.speed * self.cfg.clock.tick_interval_s
                events = await asyncio.to_thread(self.step, dt, True)
                publish(events)
                await asyncio.sleep(max(0.0, self.cfg.clock.tick_interval_s - (time.perf_counter() - t0)))
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 - surface the failure instead of dying silently
            log.exception("simulation loop failed")
            with self._lock:
                self.status = "error"
                self.counters["loop_errors"] += 1
                self._audit("simulation_error", {"run_id": self.run_id, "error": str(exc)[:500]})
            publish([("status", self.status_dict())])

    # ------------------------------------------------------------------ scenarios
    def launch_scenario(self, name: str, attacker: str | None = None, targets: list[str] | None = None,
                        duration_s: float | None = None, intensity: float = 1.0) -> dict[str, Any]:
        with self._lock:
            if name not in CATALOG:
                raise ValueError(f"unknown scenario '{name}' (choose from {', '.join(CATALOG)})")
            if self.status == "completed":
                raise SimulationError("the run has completed; reset it first")
            if name == "normal":
                stopped = [s.id for s in self.scenarios]
                for s in self.scenarios:
                    s.end_t = self.sim_t
                    self.finished_scenarios.append(s)
                self.scenarios = []
                self._audit("scenario_selected", {"run_id": self.run_id, "scenario": "normal",
                                                  "stopped_instances": stopped, "sim_t": round(self.sim_t, 3)})
                return {"scenario": "normal", "stopped_instances": stopped}
            if len(self.scenarios) >= MAX_ACTIVE_SCENARIOS:
                raise SimulationError(f"at most {MAX_ACTIVE_SCENARIOS} scenarios can be active")
            self.n_scenarios += 1
            rng = np.random.default_rng(self.ss.spawn(1)[0])
            d_att, d_tg = default_participants(name, self.net, rng)
            att = self.net.get(attacker) if attacker else d_att
            tgs = [self.net.get(t) for t in targets] if targets else d_tg
            validate_participants(name, att, tgs)
            s = Scenario(f"SC-{self.run_id}-{self.n_scenarios:03d}", name, att, tgs, self.sim_t,
                         None if duration_s is None else self.sim_t + duration_s, intensity, rng)
            self.scenarios.append(s)
            self._audit("scenario_started", {"run_id": self.run_id, **s.to_dict()})
            log.info("scenario %s started: %s -> %s", name, att.id, [t.id for t in tgs])
            return s.to_dict()

    def stop_scenario(self, instance_id: str) -> dict[str, Any]:
        with self._lock:
            s = next((x for x in self.scenarios if x.id == instance_id), None)
            if s is None:
                raise KeyError(instance_id)
            s.end_t = self.sim_t
            self.scenarios.remove(s)
            self.finished_scenarios.append(s)
            self._audit("scenario_stopped", {"run_id": self.run_id, "instance": s.id, "scenario": s.name,
                                             "flows_generated": s.flows})
            return s.to_dict()

    # ------------------------------------------------------------------ the pipeline
    def step(self, dt: float, from_loop: bool = False) -> list[Event]:
        if not 0 < dt <= 3600:
            raise ValueError("dt must be in (0, 3600] seconds")
        t_wall = time.perf_counter()
        with self._lock:
            if from_loop and self.status != "running":
                return []
            if not from_loop and self.status in ("running", "completed"):
                raise SimulationError(f"manual steps are not allowed while the simulation is {self.status}")
            t0 = self.sim_t
            if self.cfg.clock.duration_s is not None:
                dt = min(dt, self.cfg.clock.duration_s - t0)
                if dt <= 0:
                    raise SimulationError("duration_s is reached; reset the simulation or start it with a larger duration")
            t1 = t0 + dt
            raw: list[Flow] = self.normal.generate(self.rng, t0, dt, self.factory) if self.cfg.traffic.normal_enabled else []
            for s in list(self.scenarios):
                raw.extend(s.generate(t0, dt, self.factory))
                if s.end_t is not None and s.end_t <= t1:
                    self.scenarios.remove(s)
                    self.finished_scenarios.append(s)
            raw.sort(key=lambda f: f.sim_t)
            cap = self.cfg.traffic.max_flows_per_tick
            if len(raw) > cap:
                self.counters["dropped"] += len(raw) - cap
                log.warning("tick generated %d flows; keeping the first %d (max_flows_per_tick)", len(raw), cap)
                raw = raw[:cap]
            flows: list[Flow] = []
            for f in raw:
                try:
                    validate_flow(f, self.net.by_ip)
                    flows.append(f)
                except FlowValidationError as exc:
                    self.counters["invalid"] += 1
                    log.warning("rejected simulated flow: %s", exc)
            cn, ce = self.graph.add_flows(flows)
            if self.ml is not None and self.cfg.ml.enabled and self.ml.ready and flows:
                self.ml.score(flows)
                n2, e2 = self.graph.mark_ml(flows)
                cn |= n2
                ce |= e2
            for f in flows:
                self._remember(f)
            findings = self.rules.process(flows, t1)
            if self.ml is not None and self.ml.ready:
                findings += self.ml.findings(flows, t1, self.cfg.limits.evidence_flow_ids)
            new_a, upd_a = self.alerts.ingest(findings)
            for a in new_a + upd_a:
                for fid in a["flow_ids"]:
                    f = self.flow_index.get(fid)
                    if f is not None and a["id"] not in f.alert_ids:
                        f.alert_ids.append(a["id"])
                n2, e2 = self.graph.mark_alert(a)
                cn |= n2
                ce |= e2
            for a in new_a:
                self._evaluate_alert(a)
            new_i, upd_i, esc = self.incidents.ingest(new_a + upd_a, self.alerts.alerts)
            for inc in new_i + upd_i:
                cn |= self.graph.mark_incident(inc)
            self.sim_t = t1
            self.ticks += 1
            if self.ticks % 30 == 0:
                self.rules.sweep_idle(t1)
            if self.store is not None:
                try:
                    self.store.save(new_a + upd_a, new_i + upd_i)
                except Exception:  # noqa: BLE001 - keep simulating; the failure is counted and logged
                    self.counters["store_errors"] += 1
                    log.exception("could not persist alerts/incidents")
            for a in new_a:
                if a["severity"] in AUDIT_SEVERITIES:
                    self._audit("detection_alert", {"run_id": self.run_id, "alert_id": a["id"], "rule": a["rule"],
                                                    "severity": a["severity"], "src": a["src"], "dst": a["dst_devices"],
                                                    "flow_ids": len(a["flow_ids"]),
                                                    "evidence_sha256": evidence_digest(a["flow_ids"])})
            for inc in new_i:
                self._audit("incident_created", {"run_id": self.run_id, "incident_id": inc["id"], "severity": inc["severity"],
                                                 "actor": inc["actor"], "rules": inc["rules"], "alert_ids": inc["alert_ids"],
                                                 "evidence_sha256": evidence_digest(inc["flow_ids"])})
            for inc, prev in esc:
                self._audit("incident_escalated", {"run_id": self.run_id, "incident_id": inc["id"], "from": prev,
                                                   "to": inc["severity"], "rules": inc["rules"]})
            if self.cfg.clock.duration_s is not None and self.sim_t >= self.cfg.clock.duration_s - 1e-9 \
                    and self.status == "running":
                self._finish("completed", "duration reached")
            elif self.ticks % 10 == 0:
                self._save_run()
            self.last_tick_ms = (time.perf_counter() - t_wall) * 1000
            return self._events(flows, cn, ce, new_a, upd_a, new_i, upd_i)

    def _remember(self, f: Flow) -> None:
        if len(self.flows) == self.flows.maxlen:
            old = self.flows[0]
            self.flow_index.pop(old.flow_id, None)
        self.flows.append(f)
        self.flow_index[f.flow_id] = f
        self.counters["flows"] += 1
        self.counters["packets"] += f.packets
        self.counters["bytes"] += f.total_bytes
        self.protocols[PROTOCOL_NAMES.get(f.protocol, str(f.protocol))] += 1
        self.truth[f.scenario] += 1
        if f.ml_family is not None:
            self.ml_pred[f.ml_family] += 1
            self.ml_confusion[(f.scenario != "normal", f.ml_family != "Benign")] += 1

    def _evaluate_alert(self, a: dict[str, Any]) -> None:
        """Compare an alert's supporting flows with the simulator ground truth (evaluation only)."""
        fs = [self.flow_index[i] for i in a["flow_ids"] if i in self.flow_index]
        if not fs:
            self.alert_eval["unknown"] += 1
            return
        attack = [f for f in fs if f.scenario != "normal"]
        self.alert_eval["true_positive" if len(attack) * 2 >= len(fs) else "false_positive"] += 1
        for f in attack:
            inst = f.scenario_instance
            if inst and inst not in self.first_detection:
                sc = next((s for s in [*self.scenarios, *self.finished_scenarios] if s.id == inst), None)
                self.first_detection[inst] = {"scenario": f.scenario, "alert_id": a["id"], "rule": a["rule"],
                                              "latency_sim_s": None if sc is None else round(a["first_seen"] - sc.start_t, 3)}

    def _events(self, flows: list[Flow], cn: set[str], ce: set[tuple[str, str]], new_a: list, upd_a: list,
                new_i: list, upd_i: list) -> list[Event]:
        k = self.cfg.limits.ws_flows_per_message
        ev: list[Event] = [("flows", {"run_id": self.run_id, "sim_t": round(self.sim_t, 3), "count": len(flows),
                                      "flows": [f.to_dict() for f in flows[-k:]], "truncated": len(flows) > k})]
        if cn or ce:
            ev.append(("graph_update", {"run_id": self.run_id, **self.graph.delta(cn, ce)}))
        ev += [("detection", {"event": "created", **a}) for a in new_a]
        ev += [("detection", {"event": "updated", **a}) for a in upd_a]
        ev += [("incident", {"event": "created", **i}) for i in new_i]
        ev += [("incident", {"event": "updated", **i}) for i in upd_i]
        ev.append(("status", self.status_dict()))
        return ev

    # ------------------------------------------------------------------ incidents
    def update_incident(self, inc_id: str, status: str, note: str | None = None, by: str = "analyst") -> dict[str, Any]:
        with self._lock:
            if inc_id in self.incidents.incidents:
                prev = self.incidents.incidents[inc_id]["status"]
                inc = self.incidents.set_status(inc_id, status, note, by)
            else:
                if self.store is None:
                    raise KeyError(inc_id)
                inc = self.store.incident(inc_id)
                if inc is None:
                    raise KeyError(inc_id)
                prev = inc["status"]
                check_transition(prev, status)
                ts = now_iso()
                inc["status"], inc["updated_at"] = status, ts
                inc["history"] = (inc["history"] + [{"at": ts, "status": status, "note": note, "by": by}])[-50:]
            if self.store is not None:
                self.store.save([], [inc])
            self._audit("incident_status_changed", {"incident_id": inc_id, "from": prev, "to": status,
                                                    "note": (note or "")[:500], "by": by})
            return dict(inc)

    # ------------------------------------------------------------------ views
    def _at(self, t: float) -> str:
        return (self.t_origin + timedelta(seconds=t)).isoformat(timespec="seconds")

    def status_dict(self) -> dict[str, Any]:
        with self._lock:
            return {"run_id": self.run_id, "status": self.status, "seed": self.cfg.seed, "sim_start": self._at(0),
                    "sim_time": self._at(self.sim_t), "sim_elapsed_s": round(self.sim_t, 3), "ticks": self.ticks,
                    "clock": self.cfg.clock.model_dump(), "normal_traffic": self.cfg.traffic.normal_enabled,
                    "flows_generated": self.counters["flows"], "flows_invalid": self.counters["invalid"],
                    "flows_dropped": self.counters["dropped"], "alerts": self.alerts.n, "incidents": self.incidents.n,
                    "open_incidents": sum(1 for i in self.incidents.incidents.values() if i["status"] not in CLOSED),
                    "active_scenarios": [s.to_dict() for s in self.scenarios],
                    "baseline_learned": self.rules.baseline_frozen, "devices": len(self.net.devices),
                    "ml": {k: self.ml.report.get(k) for k in ("available", "compatible", "reason")} if self.ml else
                    {"available": False, "compatible": False, "reason": "ML detector not configured"},
                    "started_at": self.started_at, "stopped_at": self.stopped_at, "last_tick_ms": round(self.last_tick_ms, 2)}

    def scenarios_dict(self) -> dict[str, Any]:
        with self._lock:
            return {"catalog": [{"name": k, **v} for k, v in CATALOG.items()],
                    "active": [s.to_dict() for s in self.scenarios],
                    "finished": [s.to_dict() for s in self.finished_scenarios]}

    def topology(self, active_only: bool = False, suspicious_only: bool = False) -> dict[str, Any]:
        with self._lock:
            return {"run_id": self.run_id, "sim_time": self._at(self.sim_t), **self.net.to_dict(),
                    **self.graph.snapshot(active_only, suspicious_only)}

    def flow_list(self, limit: int = 100, src: str | None = None, dst: str | None = None,
                  suspicious_only: bool = False, scenario: str | None = None) -> dict[str, Any]:
        with self._lock:
            out = []
            for f in reversed(self.flows):
                if (src and f.src != src) or (dst and f.dst != dst) or (scenario and f.scenario != scenario):
                    continue
                if suspicious_only and not (f.alert_ids or (f.ml_family not in (None, "Benign"))):
                    continue
                out.append(f.to_dict())
                if len(out) >= limit:
                    break
            return {"run_id": self.run_id, "buffered": len(self.flows), "buffer_limit": self.flows.maxlen,
                    "returned": len(out), "flows": out}

    def flow(self, flow_id: str) -> dict[str, Any] | None:
        with self._lock:
            f = self.flow_index.get(flow_id)
            return None if f is None else f.to_dict(features=True)

    def alert_list(self, limit: int = 100) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(a) for a in list(self.alerts.alerts.values())[::-1][:limit]]

    def incident_list(self) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(i) for i in list(self.incidents.incidents.values())[::-1]]

    def stats(self) -> dict[str, Any]:
        with self._lock:
            recent = list(self.flows)
            horizon = 60.0
            last = [f for f in recent if f.sim_t >= self.sim_t - horizon]
            span = min(horizon, self.sim_t) or 1.0
            tp, fp = self.ml_confusion[(True, True)], self.ml_confusion[(False, True)]
            fn, tn = self.ml_confusion[(True, False)], self.ml_confusion[(False, False)]
            sev = Counter(a["severity"] for a in self.alerts.alerts.values())
            return {
                "run_id": self.run_id, "status": self.status, "sim_elapsed_s": round(self.sim_t, 3),
                "totals": {"flows": self.counters["flows"], "packets": self.counters["packets"],
                           "bytes": self.counters["bytes"], "invalid_flows": self.counters["invalid"],
                           "dropped_flows": self.counters["dropped"], "alerts": self.alerts.n,
                           "incidents": self.incidents.n},
                "rates_last_60s": {"flows_per_s": round(len(last) / span, 3),
                                   "bytes_per_s": round(sum(f.total_bytes for f in last) / span, 1)},
                "protocols": dict(self.protocols),
                "alerts_by_rule": dict(self.alerts.counts), "alerts_by_severity_buffered": dict(sev),
                "incidents_by_status": dict(Counter(i["status"] for i in self.incidents.incidents.values())),
                "graph": {"devices": len(self.net.devices), "active_devices": sum(1 for n in self.graph.nodes.values() if n.last_seen is not None),
                          "edges": len(self.graph.edges),
                          "suspicious_devices": sum(1 for n in self.graph.nodes.values() if n.rules or n.ml_attack_flows),
                          "suspicious_edges": sum(1 for e in self.graph.edges.values() if e.rules or e.ml_attack_flows),
                          "structure_recent": self.graph.structure(recent)},
                "ml": {**(self.ml.report if self.ml else {"available": False}),
                       "scored_flows": sum(self.ml_pred.values()),             # this run (the detector is shared by runs)
                       "failed_batches_since_start": self.ml.failed_batches if self.ml else 0,
                       "predicted_family_counts": dict(self.ml_pred)},
                "evaluation_against_ground_truth": {
                    "note": "Uses the simulator's scenario labels, which no detector reads.",
                    "flows_by_scenario": dict(self.truth),
                    "ml_attack_vs_benign": {"tp": tp, "fp": fp, "fn": fn, "tn": tn,
                                            "precision": round(tp / (tp + fp), 4) if tp + fp else None,
                                            "recall": round(tp / (tp + fn), 4) if tp + fn else None,
                                            "false_positive_rate": round(fp / (fp + tn), 4) if fp + tn else None},
                    "alerts": dict(self.alert_eval),
                    "first_detection_by_scenario_instance": dict(self.first_detection)},
                "memory": {"flow_buffer": len(self.flows), "flow_buffer_limit": self.flows.maxlen,
                           "alerts_in_memory": len(self.alerts.alerts), "incidents_in_memory": len(self.incidents.incidents),
                           **self.rules.memory()},
                "performance": {"last_tick_ms": round(self.last_tick_ms, 2), "ticks": self.ticks},
                "audit_failures": self.audit_failures}

    # ------------------------------------------------------------------ persistence and audit
    def _save_run(self) -> None:
        if self.store is None:
            return
        try:
            self.store.save_run({"run_id": self.run_id, "created_at": self.created_at, "seed": self.cfg.seed,
                                 "config": json.loads(self.cfg.model_dump_json()), "status": self.status,
                                 "started_at": self.started_at, "stopped_at": self.stopped_at, "sim_start": self._at(0),
                                 "sim_elapsed_s": self.sim_t, "flows_generated": self.counters["flows"],
                                 "flows_invalid": self.counters["invalid"], "updated_at": now_iso()})
        except Exception:  # noqa: BLE001
            self.counters["store_errors"] += 1
            log.exception("could not persist the run record")

    def _audit(self, event_type: str, details: dict[str, Any]) -> None:
        if self._audit_factory is None:
            return
        try:
            self._audit_factory().append(event_type, details)
        except Exception:  # noqa: BLE001 - an audit failure is counted, logged and reported in /stats
            self.audit_failures += 1
            log.exception("audit append failed for %s", event_type)
