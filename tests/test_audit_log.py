"""Tests for the SHA-256 hash chain + HMAC-SHA256 audit log."""
from __future__ import annotations

import json
import secrets
import sqlite3
from pathlib import Path

import pytest

from src.cryptography import audit_log as al

KEY = secrets.token_bytes(32)


def _log(tmp_path: Path, n: int = 4) -> al.AuditLog:
    log = al.AuditLog(tmp_path / "a.sqlite", key=KEY)
    for i in range(n):
        log.append("event", {"i": i, "msg": "Ã¼nÃ¯code ok"})
    return log


def test_create_and_verify(tmp_path: Path) -> None:
    log = _log(tmp_path)
    recs = log.records()
    assert [r["event_id"] for r in recs] == [1, 2, 3, 4]
    assert recs[0]["prev_hash"] == al.GENESIS and recs[1]["prev_hash"] == recs[0]["hash"]
    v = log.verify(log.checkpoint())
    assert v["valid"] and v["records"] == 4 and v["head_hash"] == recs[-1]["hash"]


def test_hash_definition(tmp_path: Path) -> None:
    r = _log(tmp_path, 1).records()[0]
    canon = al.canonical(r["event_id"], r["timestamp"], r["event_type"], r["details"])
    import hashlib, hmac
    assert r["hash"] == hashlib.sha256(bytes.fromhex(al.GENESIS) + canon).hexdigest()
    assert r["hmac"] == hmac.new(KEY, bytes.fromhex(r["hash"]), hashlib.sha256).hexdigest()


def test_canonical_is_deterministic() -> None:
    assert al.canonical(1, "t", "e", {"b": 1, "a": [1, 2]}) == al.canonical(1, "t", "e", {"a": [1, 2], "b": 1})


def test_detects_modified_details(tmp_path: Path) -> None:
    log = _log(tmp_path)
    with al._raw(log.db_path) as c:
        c.execute("UPDATE audit_log SET details=? WHERE event_id=2", (json.dumps({"i": 99}),))
    v = log.verify()
    assert not v["valid"] and v["first_invalid_event_id"] == 2
    assert any("hash mismatch" in e["error"] for e in v["errors"])


def test_rechain_without_key_fails_hmac(tmp_path: Path) -> None:
    log = _log(tmp_path)
    with al._raw(log.db_path) as c:
        rows = c.execute("SELECT * FROM audit_log ORDER BY event_id").fetchall()
        c.execute("UPDATE audit_log SET details=? WHERE event_id=2", (json.dumps({"i": 99}),))
        prev = rows[0][5]
        for r in rows[1:]:
            det = {"i": 99} if r[0] == 2 else json.loads(r[3])
            h = al.chain_hash(prev, al.canonical(r[0], r[1], r[2], det))
            c.execute("UPDATE audit_log SET prev_hash=?, hash=? WHERE event_id=?", (prev, h, r[0]))
            prev = h
    v = log.verify()
    assert not v["valid"] and all("HMAC invalid" in e["error"] for e in v["errors"])
    assert {e["event_id"] for e in v["errors"]} == {2, 3, 4}


def test_deletion_and_truncation(tmp_path: Path) -> None:
    log = _log(tmp_path)
    cp = log.checkpoint()
    with al._raw(log.db_path) as c:
        c.execute("DELETE FROM audit_log WHERE event_id=4")
    assert log.verify()["valid"]                      # documented limitation: truncation invisible without checkpoint
    v = log.verify(cp)
    assert not v["valid"] and "checkpoint mismatch" in v["errors"][0]["error"]
    with al._raw(log.db_path) as c:
        c.execute("DELETE FROM audit_log WHERE event_id=2")
    v = log.verify()
    assert not v["valid"] and any("sequence gap" in e["error"] for e in v["errors"])


def test_wrong_key_rejected(tmp_path: Path) -> None:
    _log(tmp_path)
    v = al.AuditLog(tmp_path / "a.sqlite", key=secrets.token_bytes(32)).verify()
    assert not v["valid"] and len(v["errors"]) == 4


def test_key_loading(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(al.KEY_ENV, raising=False)
    kf = tmp_path / "k" / "hmac.key"
    monkeypatch.setenv(al.KEY_FILE_ENV, str(kf))
    k1 = al.load_key()
    assert kf.exists() and len(k1) == 32 and al.load_key() == k1
    monkeypatch.setenv(al.KEY_ENV, "ab" * 32)
    assert al.load_key() == bytes.fromhex("ab" * 32)
    monkeypatch.setenv(al.KEY_ENV, "ab" * 8)
    with pytest.raises(ValueError):
        al.load_key()
    src = Path("src/cryptography/audit_log.py").read_text(encoding="utf-8")
    assert k1.hex() not in src


def test_demo_detects_every_tampering() -> None:
    r = al.demo()
    assert r["1_clean"]["valid"]
    assert not r["2_modified_details"]["valid"]
    assert not r["3_rechained_without_key"]["valid"]
    assert r["4_truncated_no_checkpoint"]["valid"]          # limitation, explicitly demonstrated
    assert not r["5_truncated_with_checkpoint"]["valid"]
