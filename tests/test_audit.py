"""Tests for the read-only raw-data audit."""
from __future__ import annotations

from pathlib import Path

import pytest

from src.preprocessing.audit import audit_directory, detect_encoding, detect_encoding_details, to_markdown


def _by_file(audit: dict, prefix: str) -> dict:
    return next(r for r in audit["files_report"] if r["file"].startswith(prefix))


def test_detects_encodings(synthetic_raw_dir: Path) -> None:
    assert detect_encoding(synthetic_raw_dir / "Monday-WorkingHours.pcap_ISCX.csv")[0] == "utf-8-sig"
    thu = synthetic_raw_dir / "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv"
    enc, _, failures = detect_encoding_details(thu)
    assert enc == "cp1252"
    # utf-8 failure is recorded with the offending cp1252 en-dash byte, not silently replaced
    assert failures[0]["encoding"] == "utf-8-sig" and failures[0]["bad_bytes"] == "96"
    assert "Web Attack" in failures[0]["context"]


def test_reports_literal_replacement_char(tmp_path: Path) -> None:
    from tests.conftest import HEADER, _row, _write

    d = tmp_path / "raw"
    d.mkdir()
    rows = [_row("a-b-1-80-6", "a", 1, "b", 80, "3/7/2017 9:00", 5, "1", "1", 20, 1, "Web Attack � XSS")]
    _write(d / "f.csv", rows, "utf-8")
    rep = audit_directory(d)["files_report"][0]
    assert rep["labels_containing_U+FFFD"] == {"Web Attack � XSS": 1}
    assert len(HEADER) == len(rows[0])


def test_audit_finds_documented_quirks(synthetic_raw_dir: Path) -> None:
    audit = audit_directory(synthetic_raw_dir)
    mon, thu = _by_file(audit, "Monday"), _by_file(audit, "Thursday")

    assert mon["duplicate_column_names_after_strip"] == ["Fwd Header Length"]
    assert "Fwd Header Length.1" in mon["pandas_column_names"]
    assert len(mon["columns_with_surrounding_whitespace"]) > 0
    assert mon["duplicate_rows_all_columns"] == 1
    assert mon["numeric_column_issues"]["Flow Bytes/s"]["+inf"] == 1
    assert mon["numeric_column_issues"]["Flow Bytes/s"]["nan"] == 1
    assert mon["numeric_column_issues"]["Flow Duration"]["negative"] == 1
    assert "Bwd PSH Flags" in mon["constant_columns"]

    assert thu["fully_empty_rows"] == 3
    assert thu["n_rows_non_empty"] == 3
    assert "'Web Attack – Brute Force'" in thu["labels"]
    assert thu["labels_with_non_ascii"] == {"Web Attack – Brute Force": ["U+2013"]}
    assert thu["rows_in_conflicting_label_groups"] == 2

    # timestamp shape is reported, not silently parsed
    assert "9/9/9999 9:99" in mon["timestamp"]["shape_patterns"]
    assert "99/99/9999 99:99:99" in thu["timestamp"]["shape_patterns"]
    assert mon["timestamp"]["hour_histogram"][1] == 1  # the ambiguous 12-hour afternoon case

    assert audit["header_consistent_across_files"]
    assert audit["distinct_content_rows_shared_across_files"] == 1
    assert audit["totals"]["rows_non_empty"] == 7
    assert "CICIDS2017 raw data audit" in to_markdown(audit)


def test_missing_dir_raises(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        audit_directory(tmp_path)
