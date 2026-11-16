"""SQLite storage for the backend: experiment index, detection history, config. The audit log lives in the same
database (table audit_log, see src/cryptography/audit_log.py). No raw traffic is stored."""
from __future__ import annotations

import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from src.api import results

DB_PATH = Path(os.environ.get("GRAPHSENTINEL_DB", "experiments/graphsentinel.sqlite"))

SCHEMA = [
    """CREATE TABLE IF NOT EXISTS experiments (
        id TEXT PRIMARY KEY, family TEXT, experiment TEXT, model TEXT, scheme TEXT, target TEXT, feature_set TEXT,
        identity_free INTEGER, aggregation_aware TEXT, file TEXT, file_sha256 TEXT, n_seeds INTEGER,
        macro_f1 REAL, macro_f1_std REAL, fpr REAL, off_pair_macro_f1 REAL, ingested_at TEXT)""",
    """CREATE TABLE IF NOT EXISTS detections (
        id INTEGER PRIMARY KEY AUTOINCREMENT, created_at TEXT, filename TEXT, file_sha256 TEXT, n_flows INTEGER,
        n_scored INTEGER, n_alerts INTEGER, model TEXT, summary TEXT)""",
    """CREATE TABLE IF NOT EXISTS config (key TEXT PRIMARY KEY, value TEXT)""",
    # Live simulation (src/simulation): runs, alerts and incidents. Simulated flows stay in a bounded in-memory
    # buffer; alerts and incidents keep only the IDs of their supporting flows.
    """CREATE TABLE IF NOT EXISTS sim_runs (
        run_id TEXT PRIMARY KEY, created_at TEXT, seed INTEGER, config TEXT, status TEXT, started_at TEXT,
        stopped_at TEXT, sim_start TEXT, sim_elapsed_s REAL, flows_generated INTEGER, flows_invalid INTEGER,
        updated_at TEXT)""",
    """CREATE TABLE IF NOT EXISTS sim_alerts (
        id TEXT PRIMARY KEY, run_id TEXT, rule TEXT, source TEXT, severity TEXT, title TEXT, explanation TEXT,
        src TEXT, dst_devices TEXT, first_seen REAL, last_seen REAL, first_seen_at TEXT, last_seen_at TEXT,
        occurrences INTEGER, evidence TEXT, flow_ids TEXT, incident_id TEXT, created_at TEXT, updated_at TEXT)""",
    """CREATE TABLE IF NOT EXISTS sim_incidents (
        id TEXT PRIMARY KEY, run_id TEXT, status TEXT, severity TEXT, title TEXT, summary TEXT, actor TEXT,
        targets TEXT, pivots TEXT, devices TEXT, rules TEXT, alert_ids TEXT, flow_ids TEXT, first_seen REAL,
        last_seen REAL, first_seen_at TEXT, last_seen_at TEXT, created_at TEXT, updated_at TEXT, history TEXT)""",
    "CREATE INDEX IF NOT EXISTS ix_sim_alerts_run ON sim_alerts (run_id, last_seen)",
    "CREATE INDEX IF NOT EXISTS ix_sim_incidents_run ON sim_incidents (run_id, status)",
]


@contextmanager
def connect(path: Path | None = None) -> Iterator[sqlite3.Connection]:
    p = Path(path or DB_PATH)
    p.parent.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(p, timeout=30)
    c.row_factory = sqlite3.Row
    try:
        yield c
        c.commit()
    finally:
        c.close()


def init(path: Path | None = None) -> None:
    with connect(path) as c:
        for s in SCHEMA:
            c.execute(s)


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def ingest_results(root: Path | None = None, path: Path | None = None) -> int:
    """(Re)index every result JSON. Returns number of indexed files."""
    root = root or results.RESULTS
    files = results.result_files(root)
    with connect(path) as c:
        c.execute("DELETE FROM experiments")
        for f in files:
            d = results.describe(f, root)
            c.execute("""INSERT INTO experiments VALUES (:id,:family,:experiment,:model,:scheme,:target,:feature_set,
                         :identity_free,:aggregation_aware,:file,:sha,:n_seeds,:macro_f1,:macro_f1_std,:fpr,
                         :off_pair_macro_f1,:ts)""",
                      {**d, "identity_free": None if d["identity_free"] is None else int(bool(d["identity_free"])),
                       "aggregation_aware": json.dumps(d["aggregation_aware"]) if d["aggregation_aware"] else None,
                       "sha": results.sha256(f), "ts": now()})
    return len(files)


def list_experiments(path: Path | None = None) -> list[dict[str, Any]]:
    with connect(path) as c:
        return [dict(r) for r in c.execute("SELECT * FROM experiments ORDER BY family, experiment, model")]


def add_detection(rec: dict[str, Any], path: Path | None = None) -> int:
    with connect(path) as c:
        cur = c.execute("INSERT INTO detections (created_at, filename, file_sha256, n_flows, n_scored, n_alerts, model, summary) "
                        "VALUES (?,?,?,?,?,?,?,?)",
                        (now(), rec["filename"], rec["file_sha256"], rec["n_flows"], rec["n_scored"], rec["n_alerts"],
                         rec["model"], json.dumps({k: rec[k] for k in ("predicted_family_counts", "n_invalid_negative_duration",
                                                                       "value_corrections") if k in rec}
                                                  | ({"ground_truth_macro_f1": rec["ground_truth_evaluation"]["overall"]["macro_f1"]}
                                                     if "ground_truth_evaluation" in rec else {}))))
        return int(cur.lastrowid)


def list_detections(limit: int = 50, path: Path | None = None) -> list[dict[str, Any]]:
    with connect(path) as c:
        rows = [dict(r) for r in c.execute("SELECT * FROM detections ORDER BY id DESC LIMIT ?", (int(limit),))]
    for r in rows:
        r["summary"] = json.loads(r["summary"])
    return rows


def set_config(key: str, value: Any, path: Path | None = None) -> None:
    with connect(path) as c:
        c.execute("INSERT OR REPLACE INTO config VALUES (?, ?)", (key, json.dumps(value)))


def get_config(key: str, default: Any = None, path: Path | None = None) -> Any:
    with connect(path) as c:
        r = c.execute("SELECT value FROM config WHERE key = ?", (key,)).fetchone()
    return json.loads(r["value"]) if r else default
