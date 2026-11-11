"""Shared pytest fixtures.

`synthetic_raw_dir` writes small CSVs that reproduce the *documented* CICIDS2017 quirks
(whitespace-padded headers, duplicated 'Fwd Header Length', 'Infinity'/'NaN' tokens,
cp1252 en-dash in Web Attack labels, trailing all-comma rows, exact duplicates,
conflicting labels, timestamps with/without seconds). It is a test double, not real data.
"""
from __future__ import annotations

from pathlib import Path

import pytest

HEADER = ["Flow ID", " Source IP", " Source Port", " Destination IP", " Destination Port", " Protocol",
          " Timestamp", " Flow Duration", "Flow Bytes/s", " Flow Packets/s", " Fwd Header Length",
          " Bwd Header Length", " Fwd Header Length", "Init_Win_bytes_forward", " Bwd PSH Flags", " Label"]


def _row(fid: str, src: str, sport: int, dst: str, dport: int, ts: str, dur: int, fbs: str, fps: str,
         fwh: int, iw: int, label: str) -> list[str]:
    return [fid, src, str(sport), dst, str(dport), "6", ts, str(dur), fbs, fps, str(fwh), "20", str(fwh),
            str(iw), "0", label]


def _write(path: Path, rows: list[list[str]], encoding: str, trailing_empty: int = 0) -> None:
    lines = [",".join(HEADER)] + [",".join(r) for r in rows] + ["," * (len(HEADER) - 1)] * trailing_empty
    path.write_bytes(("\r\n".join(lines) + "\r\n").encode(encoding))


@pytest.fixture()
def synthetic_raw_dir(tmp_path: Path) -> Path:
    d = tmp_path / "TrafficLabelling"
    d.mkdir()
    mon = [
        _row("10.0.0.1-10.0.0.2-1000-80-6", "10.0.0.1", 1000, "10.0.0.2", 80, "3/7/2017 8:55", 100, "1000.5", "20",
             32, 8192, "BENIGN"),
        _row("10.0.0.1-10.0.0.2-1000-80-6", "10.0.0.1", 1000, "10.0.0.2", 80, "3/7/2017 8:55", 100, "1000.5", "20",
             32, 8192, "BENIGN"),  # exact duplicate
        _row("10.0.0.3-10.0.0.2-1001-80-6", "10.0.0.3", 1001, "10.0.0.2", 80, "3/7/2017 9:01", 0, "Infinity",
             "Infinity", 32, -1, "BENIGN"),
        _row("10.0.0.4-10.0.0.2-1002-80-6", "10.0.0.4", 1002, "10.0.0.2", 80, "3/7/2017 1:30", -1, "NaN", "-2",
             20, 255, "BENIGN"),
    ]
    thu = [
        _row("10.0.0.9-10.0.0.2-2000-80-6", "10.0.0.9", 2000, "10.0.0.2", 80, "06/07/2017 09:20:11", 50, "10",
             "5", 40, 29200, "Web Attack – Brute Force"),
        _row("10.0.0.8-10.0.0.2-2001-80-6", "10.0.0.8", 2001, "10.0.0.2", 80, "06/07/2017 09:21:00", 50, "10",
             "5", 40, 29200, "BENIGN"),  # same features as previous row, different label -> conflict
        _row("10.0.0.1-10.0.0.2-1000-80-6", "10.0.0.1", 1000, "10.0.0.2", 80, "06/07/2017 09:30:00", 100,
             "1000.5", "20", 32, 8192, "BENIGN"),  # content duplicate of a Monday row (cross-file)
    ]
    _write(d / "Monday-WorkingHours.pcap_ISCX.csv", mon, "utf-8")
    _write(d / "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv", thu, "cp1252", trailing_empty=3)
    return d
