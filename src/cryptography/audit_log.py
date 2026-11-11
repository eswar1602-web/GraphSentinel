"""Tamper-evident audit log: SHA-256 hash chain + HMAC-SHA256 (Milestone 8).

Record i (stored in SQLite table ``audit_log``):
    event_id   consecutive integer starting at 1
    timestamp  ISO-8601 UTC string
    event_type short string
    details    JSON object
    prev_hash  H_{i-1} (hex), H_0 = 64 zeros
    hash       H_i = SHA256( bytes(H_{i-1}) || CanonicalRecord_i )
    hmac       HMAC-SHA256( key, bytes(H_i) )
CanonicalRecord_i = UTF-8 bytes of json.dumps({event_id, timestamp, event_type, details}, sort_keys=True,
                    separators=(",", ":"), ensure_ascii=False). Deterministic for equal content.

Key management: the HMAC key is read from env ``GRAPHSENTINEL_HMAC_KEY`` (hex) or from the file named by
``GRAPHSENTINEL_HMAC_KEY_FILE`` (default ``keys/hmac.key``, git-ignored, created with 32 random bytes if missing).
It is never stored in source code or in the database.

Limitations (see docs/audit_log.md): SHA-256 alone does not authenticate (anyone can recompute a chain); HMAC
authenticates only against parties without the key; whoever controls the storage can delete the newest records
(truncation) unless the verifier holds a trusted checkpoint of the head hash; the key on the same host as the log
gives no protection against an attacker who compromises that host.

Demo:
    python -m src.cryptography.audit_log demo
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import tempfile
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

GENESIS = "0" * 64
KEY_ENV, KEY_FILE_ENV = "GRAPHSENTINEL_HMAC_KEY", "GRAPHSENTINEL_HMAC_KEY_FILE"
DEFAULT_KEY_FILE = Path("keys/hmac.key")

SCHEMA = """CREATE TABLE IF NOT EXISTS audit_log (
    event_id INTEGER PRIMARY KEY, timestamp TEXT NOT NULL, event_type TEXT NOT NULL, details TEXT NOT NULL,
    prev_hash TEXT NOT NULL, hash TEXT NOT NULL, hmac TEXT NOT NULL)"""


def load_key(create: bool = True) -> bytes:
    """HMAC key from env (hex) or key file (raw bytes). Creates a random key file if allowed and missing."""
    if os.environ.get(KEY_ENV):
        key = bytes.fromhex(os.environ[KEY_ENV])
    else:
        path = Path(os.environ.get(KEY_FILE_ENV, DEFAULT_KEY_FILE))
        if not path.exists():
            if not create:
                raise FileNotFoundError(f"HMAC key file {path} not found and {KEY_ENV} not set")
            path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as fh:
                fh.write(secrets.token_bytes(32))
        key = path.read_bytes()
    if len(key) < 32:
        raise ValueError("HMAC key must be at least 32 bytes")
    return key


def canonical(event_id: int, timestamp: str, event_type: str, details: dict[str, Any]) -> bytes:
    return json.dumps({"event_id": event_id, "timestamp": timestamp, "event_type": event_type, "details": details},
                      sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def chain_hash(prev_hash: str, canon: bytes) -> str:
    return hashlib.sha256(bytes.fromhex(prev_hash) + canon).hexdigest()


def record_mac(key: bytes, h: str) -> str:
    return hmac.new(key, bytes.fromhex(h), hashlib.sha256).hexdigest()


class AuditLog:
    def __init__(self, db_path: str | Path, key: bytes | None = None) -> None:
        self.db_path = str(db_path)
        self.key = key if key is not None else load_key()
        with self._conn() as c:
            c.execute(SCHEMA)

    @contextmanager
    def _conn(self):
        """Autocommit connection that is always closed (Windows keeps unclosed SQLite files locked)."""
        c = sqlite3.connect(self.db_path, timeout=30, isolation_level=None)
        c.row_factory = sqlite3.Row
        try:
            yield c
        finally:
            c.close()

    def head(self) -> dict[str, Any] | None:
        with self._conn() as c:
            r = c.execute("SELECT * FROM audit_log ORDER BY event_id DESC LIMIT 1").fetchone()
        return dict(r) if r else None

    def append(self, event_type: str, details: dict[str, Any]) -> dict[str, Any]:
        with self._conn() as c:
            c.execute("BEGIN IMMEDIATE")              # serialize writers so the chain cannot fork
            last = c.execute("SELECT event_id, hash FROM audit_log ORDER BY event_id DESC LIMIT 1").fetchone()
            eid = (last["event_id"] + 1) if last else 1
            prev = last["hash"] if last else GENESIS
            ts = datetime.now(timezone.utc).isoformat(timespec="microseconds")
            canon = canonical(eid, ts, event_type, details)
            h = chain_hash(prev, canon)
            rec = {"event_id": eid, "timestamp": ts, "event_type": event_type,
                   "details": json.dumps(details, sort_keys=True, ensure_ascii=False),
                   "prev_hash": prev, "hash": h, "hmac": record_mac(self.key, h)}
            c.execute("INSERT INTO audit_log VALUES (:event_id,:timestamp,:event_type,:details,:prev_hash,:hash,:hmac)", rec)
            c.execute("COMMIT")
        return {**rec, "details": details}

    def records(self, limit: int | None = None, offset: int = 0) -> list[dict[str, Any]]:
        q = "SELECT * FROM audit_log ORDER BY event_id"
        if limit is not None:
            q += f" LIMIT {int(limit)} OFFSET {int(offset)}"
        with self._conn() as c:
            rows = [dict(r) for r in c.execute(q)]
        for r in rows:
            r["details"] = json.loads(r["details"])
        return rows

    def checkpoint(self) -> dict[str, Any]:
        """Trusted checkpoint (store it somewhere the log owner cannot modify) for truncation detection."""
        h = self.head()
        return {"event_id": h["event_id"], "hash": h["hash"]} if h else {"event_id": 0, "hash": GENESIS}

    def verify(self, checkpoint: dict[str, Any] | None = None) -> dict[str, Any]:
        """Recompute the chain and every HMAC. Reports every problem with the event_id where it occurs."""
        errors: list[dict[str, Any]] = []
        prev, expected_id = GENESIS, 1
        rows = self.records()
        for r in rows:
            eid = r["event_id"]
            if eid != expected_id:
                errors.append({"event_id": eid, "error": f"sequence gap: expected event_id {expected_id}"})
            if r["prev_hash"] != prev:
                errors.append({"event_id": eid, "error": "prev_hash does not match previous record hash"})
            h = chain_hash(r["prev_hash"], canonical(eid, r["timestamp"], r["event_type"], r["details"]))
            if h != r["hash"]:
                errors.append({"event_id": eid, "error": "hash mismatch: record content was modified"})
            if not hmac.compare_digest(record_mac(self.key, r["hash"]), r["hmac"]):
                errors.append({"event_id": eid, "error": "HMAC invalid: record not authenticated by the key holder"})
            prev, expected_id = r["hash"], eid + 1
        if checkpoint is not None:
            cp = next((r for r in rows if r["event_id"] == checkpoint["event_id"]), None)
            if checkpoint["event_id"] > 0 and (cp is None or cp["hash"] != checkpoint["hash"]):
                errors.append({"event_id": checkpoint["event_id"],
                               "error": "checkpoint mismatch: log truncated or rewritten since checkpoint"})
        return {"valid": not errors, "records": len(rows), "head_hash": prev, "errors": errors,
                "first_invalid_event_id": min((e["event_id"] for e in errors), default=None),
                "checkpoint_checked": checkpoint is not None}


@contextmanager
def _raw(db: Path):
    """Direct, attacker-style DB access used by the demo; commits and always closes."""
    c = sqlite3.connect(db)
    try:
        yield c
        c.commit()
    finally:
        c.close()


def demo() -> dict[str, Any]:
    """Create -> verify -> tamper (3 ways) -> detect. Uses a temporary DB and a temporary random key."""
    out: dict[str, Any] = {}
    with tempfile.TemporaryDirectory() as tmp:
        db = Path(tmp) / "demo.sqlite"
        log = AuditLog(db, key=secrets.token_bytes(32))
        for i in range(5):
            log.append("detection", {"batch": i, "flows": 100 + i, "alerts": i})
        cp = log.checkpoint()
        out["1_clean"] = log.verify(cp)
        with _raw(db) as c:   # attacker edits a record's details
            c.execute("UPDATE audit_log SET details = ? WHERE event_id = 3", (json.dumps({"batch": 2, "flows": 102, "alerts": 0}),))
        out["2_modified_details"] = log.verify(cp)
        with _raw(db) as c:   # attacker without key recomputes the SHA-256 chain from record 3 on
            rows = c.execute("SELECT * FROM audit_log ORDER BY event_id").fetchall()
            prev = rows[1][5]
            for r in rows[2:]:
                h = chain_hash(prev, canonical(r[0], r[1], r[2], json.loads(r[3])))
                c.execute("UPDATE audit_log SET prev_hash=?, hash=? WHERE event_id=?", (prev, h, r[0]))
                prev = h
        out["3_rechained_without_key"] = log.verify(cp)
        log2 = AuditLog(Path(tmp) / "demo2.sqlite", key=log.key)
        for i in range(5):
            log2.append("detection", {"batch": i})
        cp2 = log2.checkpoint()
        with _raw(Path(tmp) / "demo2.sqlite") as c:   # storage owner deletes the newest record
            c.execute("DELETE FROM audit_log WHERE event_id = 5")
        out["4_truncated_no_checkpoint"] = log2.verify()
        out["5_truncated_with_checkpoint"] = log2.verify(cp2)
    return out


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("command", choices=["demo", "verify"])
    ap.add_argument("--db", default="experiments/graphsentinel.sqlite")
    a = ap.parse_args(argv)
    if a.command == "demo":
        for k, v in demo().items():
            print(f"{k}: valid={v['valid']} first_invalid={v['first_invalid_event_id']} "
                  f"errors={[e['error'] for e in v['errors']][:3]}")
    else:
        print(json.dumps(AuditLog(a.db, load_key(create=False)).verify(), indent=1))


if __name__ == "__main__":
    main()
