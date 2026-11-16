"""Alerts (merged rule findings) and incidents (alerts correlated by the acting device).

Alert: one rule firing for one (source, destination group); repeats within ``alert_merge_s`` update the alert
(occurrences, latest evidence, supporting flow IDs) instead of creating a new one.

Incident: alerts whose acting device is the same, or whose acting device was a target of an open incident
(possible pivot), within ``correlation_window_s``. Only alerts of at least ``min_severity_to_open`` (and, unless
configured, not ML-only alerts) open a new incident; others join an existing one when they correlate. Severity = highest alert severity, raised one level when three
or more different behavioural rules agree. Status is changed by analysts only (no automatic response or blocking).
"""
from __future__ import annotations

from collections import OrderedDict
from datetime import datetime, timedelta, timezone
from typing import Any

from src.simulation.rules import SEVERITIES

STATUSES = ("open", "acknowledged", "investigating", "resolved", "false_positive")
CLOSED = ("resolved", "false_positive")
TRANSITIONS = {"open": {"acknowledged", "investigating", "resolved", "false_positive"},
               "acknowledged": {"investigating", "resolved", "false_positive"},
               "investigating": {"resolved", "false_positive"},
               "resolved": {"open"}, "false_positive": {"open"}}
RULE_LABELS = {"port_scan": "Port scan", "host_sweep": "Host sweep", "connection_rate": "Connection flood",
               "traffic_volume": "Unusual data volume", "brute_force": "Brute-force attempts",
               "unexpected_communication": "Unexpected communication"}


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def check_transition(cur: str, new: str) -> None:
    if new not in STATUSES:
        raise ValueError(f"unknown status '{new}' (allowed: {', '.join(STATUSES)})")
    if new not in TRANSITIONS[cur]:
        raise ValueError(f"cannot change status from '{cur}' to '{new}'")


def _max_sev(a: str, b: str) -> str:
    return a if SEVERITIES.index(a) >= SEVERITIES.index(b) else b


def _merge_ids(old: list[str], new: list[str], k: int) -> list[str]:
    seen = set(old)
    out = list(old) + [x for x in new if x not in seen and not seen.add(x)]
    return out[-k:]


class AlertManager:
    def __init__(self, run_id: str, start: datetime, merge_s: float, buffer: int, k: int) -> None:
        self.run_id, self.start, self.merge_s, self.buffer, self.k = run_id, start, merge_s, buffer, k
        self.alerts: OrderedDict[str, dict[str, Any]] = OrderedDict()
        self.by_key: dict[tuple, str] = {}
        self.n = 0
        self.counts: dict[str, int] = {}

    def _at(self, t: float) -> str:
        return (self.start + timedelta(seconds=t)).isoformat(timespec="milliseconds")

    def ingest(self, findings: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        new, updated = {}, {}
        for f in findings:
            key = (f["rule"], f["src"], f.get("group") or ",".join(f["dst_devices"]))
            aid = self.by_key.get(key)
            a = self.alerts.get(aid) if aid else None
            if a is not None and f["t"] - a["last_seen"] <= self.merge_s:
                before = (a["severity"], len(a["flow_ids"]), a["flow_ids"][-1:] if a["flow_ids"] else None, len(a["dst_devices"]))
                a["severity"] = _max_sev(a["severity"], f["severity"])
                a["last_seen"] = max(a["last_seen"], f["t"])
                a["last_seen_at"] = self._at(a["last_seen"])
                a["occurrences"] += 1
                a["evidence"], a["explanation"], a["title"] = f["evidence"], f["explanation"], f["title"]
                a["flow_ids"] = _merge_ids(a["flow_ids"], f["flow_ids"], self.k)
                a["dst_devices"] = sorted(set(a["dst_devices"]) | set(f["dst_devices"]))
                a["updated_at"] = now_iso()
                after = (a["severity"], len(a["flow_ids"]), a["flow_ids"][-1:] if a["flow_ids"] else None, len(a["dst_devices"]))
                if before != after and a["id"] not in new:
                    updated[a["id"]] = a
                continue
            self.n += 1
            a = {"id": f"AL-{self.run_id}-{self.n:05d}", "run_id": self.run_id, "rule": f["rule"],
                 "source": f.get("source", "behavioural"), "severity": f["severity"], "title": f["title"],
                 "explanation": f["explanation"], "src": f["src"], "dst_devices": sorted(set(f["dst_devices"])),
                 "first_seen": f["t"], "last_seen": f["t"], "first_seen_at": self._at(f["t"]),
                 "last_seen_at": self._at(f["t"]), "occurrences": 1, "evidence": f["evidence"],
                 "flow_ids": list(dict.fromkeys(f["flow_ids"]))[-self.k:], "incident_id": None,
                 "created_at": now_iso(), "updated_at": now_iso()}
            self.alerts[a["id"]] = a
            self.by_key[key] = a["id"]
            self.counts[a["rule"]] = self.counts.get(a["rule"], 0) + 1
            new[a["id"]] = a
            while len(self.alerts) > self.buffer:          # bounded memory (all alerts are persisted in SQLite)
                old_id, _ = self.alerts.popitem(last=False)
                for k in [k for k, v in self.by_key.items() if v == old_id]:
                    del self.by_key[k]
        return list(new.values()), [a for a in updated.values() if a["id"] not in new]


class IncidentManager:
    def __init__(self, run_id: str, start: datetime, window_s: float, ml_opens: bool, buffer: int, k: int,
                 min_severity: str = "medium") -> None:
        self.run_id, self.start, self.window_s, self.ml_opens, self.buffer, self.k = run_id, start, window_s, ml_opens, buffer, k
        self.min_severity = min_severity
        self.incidents: OrderedDict[str, dict[str, Any]] = OrderedDict()
        self.n = 0

    def _at(self, t: float) -> str:
        return (self.start + timedelta(seconds=t)).isoformat(timespec="milliseconds")

    def _find(self, a: dict[str, Any]) -> dict[str, Any] | None:
        best = None
        for inc in reversed(self.incidents.values()):
            if inc["status"] in CLOSED or a["last_seen"] - inc["last_seen"] > self.window_s:
                continue
            if inc["actor"] == a["src"]:
                return inc
            if best is None and a["src"] in inc["targets"]:
                best = inc                      # the acting device was a target of this incident: possible pivot
        return best

    def ingest(self, alerts: list[dict[str, Any]], alert_index: dict[str, dict[str, Any]]
               ) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[tuple[dict[str, Any], str]]]:
        """Returns (new incidents, updated incidents, escalations as (incident, previous severity))."""
        new, updated, esc = {}, {}, []
        for a in alerts:
            inc = self.incidents.get(a["incident_id"]) if a["incident_id"] else None
            if inc is None:
                inc = self._find(a)
                if inc is None:
                    if (a["source"] == "ml" and not self.ml_opens) or                             SEVERITIES.index(a["severity"]) < SEVERITIES.index(self.min_severity):
                        continue
                    inc = self._create(a)
                    new[inc["id"]] = inc
                elif inc["actor"] != a["src"] and a["src"] not in inc["pivots"]:
                    inc["pivots"].append(a["src"])
                a["incident_id"] = inc["id"]
            prev = inc["severity"]
            self._absorb(inc, a, alert_index)
            if SEVERITIES.index(inc["severity"]) > SEVERITIES.index(prev) and inc["id"] not in new:
                esc.append((inc, prev))
            if inc["id"] not in new:
                updated[inc["id"]] = inc
        return list(new.values()), list(updated.values()), esc

    def _create(self, a: dict[str, Any]) -> dict[str, Any]:
        self.n += 1
        ts = now_iso()
        inc = {"id": f"INC-{self.run_id}-{self.n:04d}", "run_id": self.run_id, "status": "open",
               "severity": a["severity"], "title": "", "summary": "", "actor": a["src"], "targets": [], "pivots": [],
               "devices": [a["src"]], "rules": [], "alert_ids": [], "flow_ids": [], "first_seen": a["first_seen"],
               "last_seen": a["last_seen"], "first_seen_at": self._at(a["first_seen"]),
               "last_seen_at": self._at(a["last_seen"]), "created_at": ts, "updated_at": ts,
               "history": [{"at": ts, "status": "open", "note": "created by correlation", "by": "system"}]}
        self.incidents[inc["id"]] = inc
        while len(self.incidents) > self.buffer:
            self.incidents.popitem(last=False)
        return inc

    def _absorb(self, inc: dict[str, Any], a: dict[str, Any], alert_index: dict[str, dict[str, Any]]) -> None:
        if a["id"] not in inc["alert_ids"]:
            inc["alert_ids"].append(a["id"])
        if a["rule"] not in inc["rules"]:
            inc["rules"].append(a["rule"])
        for d in a["dst_devices"]:
            if d not in inc["targets"] and d != inc["actor"]:
                inc["targets"].append(d)
        inc["devices"] = list(dict.fromkeys([inc["actor"], *inc["pivots"], *inc["targets"]]))
        inc["flow_ids"] = _merge_ids(inc["flow_ids"], a["flow_ids"], self.k * 4)
        inc["first_seen"] = min(inc["first_seen"], a["first_seen"])
        inc["last_seen"] = max(inc["last_seen"], a["last_seen"])
        inc["first_seen_at"], inc["last_seen_at"] = self._at(inc["first_seen"]), self._at(inc["last_seen"])
        sevs = [alert_index[i]["severity"] for i in inc["alert_ids"] if i in alert_index] + [a["severity"]]
        sev = sevs[0]
        for s in sevs:
            sev = _max_sev(sev, s)
        if len({r for r in inc["rules"] if not r.startswith("ml_")}) >= 3:
            sev = SEVERITIES[min(SEVERITIES.index(sev) + 1, len(SEVERITIES) - 1)]
        inc["severity"] = _max_sev(inc["severity"], sev)
        labels = [RULE_LABELS.get(r, r.replace("_", " ")) for r in inc["rules"]]
        tgt = ", ".join(inc["targets"][:3]) + (f" and {len(inc['targets']) - 3} more" if len(inc["targets"]) > 3 else "")
        inc["title"] = f"{labels[0]} from {inc['actor']}" + (f" (+{len(labels) - 1} more indicator types)" if len(labels) > 1 else "")
        inc["summary"] = (f"{inc['actor']} is the acting device of {len(inc['alert_ids'])} alert(s): {', '.join(labels)}. "
                          f"Targets: {tgt or 'none'}." + (f" Also acting: {', '.join(inc['pivots'])} (were targets; possible pivot)."
                                                          if inc["pivots"] else ""))
        inc["updated_at"] = now_iso()

    def set_status(self, inc_id: str, status: str, note: str | None, by: str) -> dict[str, Any]:
        inc = self.incidents[inc_id]
        check_transition(inc["status"], status)
        ts = now_iso()
        inc["status"] = status
        inc["updated_at"] = ts
        inc["history"].append({"at": ts, "status": status, "note": note, "by": by})
        del inc["history"][:-50]
        return inc
