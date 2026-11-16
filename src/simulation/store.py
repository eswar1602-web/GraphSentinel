"""SQLite persistence of simulation runs, alerts and incidents (tables created by ``src.api.db.init``)."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from src.api import db

ALERT_COLS = ("id", "run_id", "rule", "source", "severity", "title", "explanation", "src", "dst_devices", "first_seen",
              "last_seen", "first_seen_at", "last_seen_at", "occurrences", "evidence", "flow_ids", "incident_id",
              "created_at", "updated_at")
INCIDENT_COLS = ("id", "run_id", "status", "severity", "title", "summary", "actor", "targets", "pivots", "devices",
                 "rules", "alert_ids", "flow_ids", "first_seen", "last_seen", "first_seen_at", "last_seen_at",
                 "created_at", "updated_at", "history")
JSON_COLS = {"dst_devices", "evidence", "flow_ids", "targets", "pivots", "devices", "rules", "alert_ids", "history", "config"}


def _enc(row: dict[str, Any], cols: tuple[str, ...]) -> tuple:
    return tuple(json.dumps(row[c], sort_keys=True) if c in JSON_COLS else row[c] for c in cols)


def _dec(r: Any) -> dict[str, Any]:
    d = dict(r)
    for c in JSON_COLS & d.keys():
        if d[c] is not None:
            d[c] = json.loads(d[c])
    return d


class SimStore:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path
        db.init(path)

    def save_run(self, run: dict[str, Any]) -> None:
        cols = ("run_id", "created_at", "seed", "config", "status", "started_at", "stopped_at", "sim_start",
                "sim_elapsed_s", "flows_generated", "flows_invalid", "updated_at")
        with db.connect(self.path) as c:
            c.execute(f"INSERT OR REPLACE INTO sim_runs ({','.join(cols)}) VALUES ({','.join('?' * len(cols))})",
                      _enc(run, cols))

    def save(self, alerts: list[dict[str, Any]], incidents: list[dict[str, Any]]) -> None:
        """Upsert alerts and incidents in one transaction."""
        if not alerts and not incidents:
            return
        with db.connect(self.path) as c:
            c.executemany(f"INSERT OR REPLACE INTO sim_alerts ({','.join(ALERT_COLS)}) VALUES ({','.join('?' * len(ALERT_COLS))})",
                          [_enc(a, ALERT_COLS) for a in alerts])
            c.executemany(f"INSERT OR REPLACE INTO sim_incidents ({','.join(INCIDENT_COLS)}) "
                          f"VALUES ({','.join('?' * len(INCIDENT_COLS))})", [_enc(i, INCIDENT_COLS) for i in incidents])

    def runs(self, limit: int = 20) -> list[dict[str, Any]]:
        with db.connect(self.path) as c:
            return [_dec(r) for r in c.execute("SELECT * FROM sim_runs ORDER BY created_at DESC LIMIT ?", (int(limit),))]

    def alerts(self, run_id: str | None = None, severity: str | None = None, rule: str | None = None,
               incident_id: str | None = None, limit: int = 100, offset: int = 0) -> list[dict[str, Any]]:
        q, args = "SELECT * FROM sim_alerts WHERE 1=1", []
        for col, v in (("run_id", run_id), ("severity", severity), ("rule", rule), ("incident_id", incident_id)):
            if v is not None:
                q += f" AND {col} = ?"
                args.append(v)
        q += " ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?"
        with db.connect(self.path) as c:
            return [_dec(r) for r in c.execute(q, (*args, int(limit), int(offset)))]

    def alert(self, alert_id: str) -> dict[str, Any] | None:
        with db.connect(self.path) as c:
            r = c.execute("SELECT * FROM sim_alerts WHERE id = ?", (alert_id,)).fetchone()
        return _dec(r) if r else None

    def incidents(self, run_id: str | None = None, status: str | None = None, limit: int = 100,
                  offset: int = 0) -> list[dict[str, Any]]:
        q, args = "SELECT * FROM sim_incidents WHERE 1=1", []
        for col, v in (("run_id", run_id), ("status", status)):
            if v is not None:
                q += f" AND {col} = ?"
                args.append(v)
        q += " ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?"
        with db.connect(self.path) as c:
            return [_dec(r) for r in c.execute(q, (*args, int(limit), int(offset)))]

    def incident(self, inc_id: str) -> dict[str, Any] | None:
        with db.connect(self.path) as c:
            r = c.execute("SELECT * FROM sim_incidents WHERE id = ?", (inc_id,)).fetchone()
        return _dec(r) if r else None

    def counts(self, run_id: str) -> dict[str, Any]:
        with db.connect(self.path) as c:
            a = {r[0]: r[1] for r in c.execute("SELECT severity, COUNT(*) FROM sim_alerts WHERE run_id=? GROUP BY severity", (run_id,))}
            i = {r[0]: r[1] for r in c.execute("SELECT status, COUNT(*) FROM sim_incidents WHERE run_id=? GROUP BY status", (run_id,))}
        return {"alerts_by_severity": a, "incidents_by_status": i}
