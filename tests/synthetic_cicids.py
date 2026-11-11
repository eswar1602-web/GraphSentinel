"""Deterministic synthetic CICIDS2017-format raw CSVs for end-to-end pipeline tests.

Uses the exact 85-column raw header (leading spaces, duplicated 'Fwd Header Length') and injects
every anomaly the real audit found: comma-only trailing rows, an exact duplicate, a negative
duration, zero-duration rows with NaN/Infinity rates, negative IAT jitter, overflowed and small
negative header lengths, cp1252 en-dash labels, 12-hour timestamps without AM/PM, a
conflicting-label feature vector, an attack outside its published window, and a small (<100) group.
It is a test double, not real data.
"""
from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

import numpy as np
import yaml

RAW_HEADER = ["Flow ID", " Source IP", " Source Port", " Destination IP", " Destination Port", " Protocol", " Timestamp", " Flow Duration", " Total Fwd Packets", " Total Backward Packets", "Total Length of Fwd Packets", " Total Length of Bwd Packets", " Fwd Packet Length Max", " Fwd Packet Length Min", " Fwd Packet Length Mean", " Fwd Packet Length Std", "Bwd Packet Length Max", " Bwd Packet Length Min", " Bwd Packet Length Mean", " Bwd Packet Length Std", "Flow Bytes/s", " Flow Packets/s", " Flow IAT Mean", " Flow IAT Std", " Flow IAT Max", " Flow IAT Min", "Fwd IAT Total", " Fwd IAT Mean", " Fwd IAT Std", " Fwd IAT Max", " Fwd IAT Min", "Bwd IAT Total", " Bwd IAT Mean", " Bwd IAT Std", " Bwd IAT Max", " Bwd IAT Min", "Fwd PSH Flags", " Bwd PSH Flags", " Fwd URG Flags", " Bwd URG Flags", " Fwd Header Length", " Bwd Header Length", "Fwd Packets/s", " Bwd Packets/s", " Min Packet Length", " Max Packet Length", " Packet Length Mean", " Packet Length Std", " Packet Length Variance", "FIN Flag Count", " SYN Flag Count", " RST Flag Count", " PSH Flag Count", " ACK Flag Count", " URG Flag Count", " CWE Flag Count", " ECE Flag Count", " Down/Up Ratio", " Average Packet Size", " Avg Fwd Segment Size", " Avg Bwd Segment Size", " Fwd Header Length", "Fwd Avg Bytes/Bulk", " Fwd Avg Packets/Bulk", " Fwd Avg Bulk Rate", " Bwd Avg Bytes/Bulk", " Bwd Avg Packets/Bulk", "Bwd Avg Bulk Rate", "Subflow Fwd Packets", " Subflow Fwd Bytes", " Subflow Bwd Packets", " Subflow Bwd Bytes", "Init_Win_bytes_forward", " Init_Win_bytes_backward", " act_data_pkt_fwd", " min_seg_size_forward", "Active Mean", " Active Std", " Active Max", " Active Min", "Idle Mean", " Idle Std", " Idle Max", " Idle Min", " Label"]  # noqa: E501
NAMES = [h.strip() for h in RAW_HEADER]
FHL_IDX = [i for i, n in enumerate(NAMES) if n == "Fwd Header Length"]
CONSTANT = {"Bwd PSH Flags", "Fwd URG Flags", "Bwd URG Flags", "CWE Flag Count", "Fwd Avg Bytes/Bulk",
            "Fwd Avg Packets/Bulk", "Fwd Avg Bulk Rate", "Bwd Avg Bytes/Bulk", "Bwd Avg Packets/Bulk", "Bwd Avg Bulk Rate"}
ATTACKER, VICTIM = "172.16.0.1", "192.168.10.50"


def _clock12(minutes: int) -> tuple[int, int]:
    h, m = divmod(minutes, 60)
    return (h - 12 if h > 12 else h), m


def _ts(date: tuple[int, int, int], minutes: int, seconds: int | None) -> str:
    d, mo, y = date
    h, m = _clock12(minutes)
    if seconds is None:
        return f"{d}/{mo}/{y} {h}:{m:02d}"
    return f"{d:02d}/{mo:02d}/{y} {h:02d}:{m:02d}:{seconds:02d}"


def make_row(rng: np.random.Generator, src: str, dst: str, dport: int, ts: str, label: str, **over: Any) -> list[str]:
    sport = int(rng.integers(1024, 65000))
    dur = int(over.pop("dur", rng.integers(100, 2_000_000)))
    fp, bp = int(rng.integers(1, 30)), int(rng.integers(0, 30))
    fl, bl = int(rng.integers(0, 5000)), int(rng.integers(0, 50000))
    v: dict[str, Any] = {n: (0 if n in CONSTANT else round(float(rng.random() * 100), 3)) for n in NAMES}
    v.update({"Flow ID": f"{src}-{dst}-{sport}-{dport}-6", "Source IP": src, "Source Port": sport,
              "Destination IP": dst, "Destination Port": dport, "Protocol": 6, "Timestamp": ts, "Label": label,
              "Flow Duration": dur, "Total Fwd Packets": fp, "Total Backward Packets": bp,
              "Total Length of Fwd Packets": fl, "Total Length of Bwd Packets": bl,
              "Flow IAT Min": int(rng.integers(0, 1000)), "Fwd IAT Min": int(rng.integers(0, 1000)),
              "Fwd Header Length": 20 * fp, "Bwd Header Length": 20 * bp, "min_seg_size_forward": 20,
              "Init_Win_bytes_forward": int(rng.choice([-1, 8192, 29200])),
              "Init_Win_bytes_backward": int(rng.choice([-1, 229, 65535]))})
    if dur:
        v["Flow Bytes/s"] = (fl + bl) / (dur / 1e6)
        v["Flow Packets/s"] = (fp + bp) / (dur / 1e6)
    v.update(over)
    row = [str(v[n]) for n in NAMES]
    row[FHL_IDX[1]] = row[FHL_IDX[0]]
    return row


def _write(path: Path, rows: list[list[str]], encoding: str, trailing_empty: int = 0) -> None:
    lines = [",".join(RAW_HEADER)] + [",".join(r) for r in rows] + ["," * (len(RAW_HEADER) - 1)] * trailing_empty
    path.write_bytes(("\r\n".join(lines) + "\r\n").encode(encoding))


def _spread(rng: np.random.Generator, n: int, start: int, end: int) -> list[int]:
    return sorted(int(x) for x in rng.integers(start, end + 1, n))


def build_raw_dir(root: Path, seed: int = 0) -> Path:
    rng = np.random.default_rng(seed)
    d = root / "raw"
    d.mkdir(parents=True)
    benign = lambda i: (f"192.168.10.{i % 20 + 1}", f"8.8.{i % 7}.{i % 5}")  # noqa: E731

    # Monday: benign only, second-resolution timestamps, file order shuffled (not chronological)
    mon = [make_row(rng, *benign(i), 443, _ts((3, 7, 2017), m, int(rng.integers(0, 60))), "BENIGN")
           for i, m in enumerate(_spread(rng, 300, 8 * 60 + 55, 17 * 60))]
    order = rng.permutation(len(mon))
    mon = [mon[i] for i in order]
    t = _ts((3, 7, 2017), 10 * 60, 0)
    mon.insert(1, list(mon[0]))                                                 # exact duplicate
    mon.append(make_row(rng, *benign(1), 443, t, "BENIGN", dur=-1, **{"Flow Bytes/s": -12000000.0,
               "Flow Packets/s": -2000000.0, "Flow IAT Mean": -1, "Flow IAT Max": -1, "Flow IAT Min": -1}))
    mon.append(make_row(rng, *benign(2), 443, t, "BENIGN", **{"Fwd Header Length": -83885125, "Bwd Header Length": -83885181,
               "min_seg_size_forward": -83885313}))                             # overflow
    mon.append(make_row(rng, *benign(3), 443, t, "BENIGN", **{"Fwd Header Length": -11, "min_seg_size_forward": -1}))
    mon.append(make_row(rng, *benign(4), 53, t, "BENIGN", dur=0, **{"Total Length of Fwd Packets": 0,
               "Total Length of Bwd Packets": 0, "Flow Bytes/s": "NaN", "Flow Packets/s": "Infinity"}))
    mon.append(make_row(rng, *benign(5), 53, t, "BENIGN", dur=0, **{"Flow Bytes/s": "Infinity", "Flow Packets/s": "Infinity"}))
    mon.append(make_row(rng, *benign(6), 443, t, "BENIGN", **{"Flow IAT Min": -1, "Fwd IAT Min": -12}))
    _write(d / "Monday-WorkingHours.pcap_ISCX.csv", mon, "utf-8")

    # Tuesday: benign + FTP-Patator (>=100, purge) + SSH-Patator (<100, no purge) + conflict + outlier
    tue = [make_row(rng, *benign(i), 443, _ts((4, 7, 2017), m, None), "BENIGN")
           for i, m in enumerate(_spread(rng, 300, 8 * 60 + 54, 17 * 60))]
    ftp = [make_row(rng, ATTACKER, VICTIM, 21, _ts((4, 7, 2017), m, None), "FTP-Patator")
           for m in _spread(rng, 150, 9 * 60 + 20, 10 * 60 + 20)]
    ssh = [make_row(rng, ATTACKER, VICTIM, 22, _ts((4, 7, 2017), m, None), "SSH-Patator")
           for m in _spread(rng, 40, 14 * 60, 15 * 60)]
    twin = list(ftp[5])
    twin[0], twin[1], twin[3] = "192.168.10.9-1.2.3.4-5555-21-6", "192.168.10.9", "1.2.3.4"
    twin[NAMES.index("Label")] = "BENIGN"                                     # same features, other label
    outlier = make_row(rng, ATTACKER, VICTIM, 21, _ts((4, 7, 2017), 11 * 60 + 30, None), "FTP-Patator")
    _write(d / "Tuesday-WorkingHours.pcap_ISCX.csv", tue + ftp + ssh + [twin, outlier], "utf-8")

    # Thursday morning: cp1252 en-dash labels, trailing comma-only rows
    thu = [make_row(rng, *benign(i), 80, _ts((6, 7, 2017), m, None), "BENIGN")
           for i, m in enumerate(_spread(rng, 200, 8 * 60 + 59, 12 * 60 + 59))]
    thu += [make_row(rng, ATTACKER, VICTIM, 80, _ts((6, 7, 2017), m, None), "Web Attack – Brute Force")
            for m in _spread(rng, 120, 9 * 60 + 20, 10 * 60)]
    thu += [make_row(rng, ATTACKER, VICTIM, 80, _ts((6, 7, 2017), m, None), "Web Attack – Sql Injection")
            for m in _spread(rng, 12, 10 * 60 + 40, 10 * 60 + 42)]
    # Dense minute-resolution burst (like PortScan 14:55): 100 of 150 XSS flows share 10:20, and ranks 125-129
    # fall in 10:21, so the rank-cut purge empties val -> whole-minute-boundary fallback (decision D1).
    xss_minutes = (_spread(rng, 25, 10 * 60 + 15, 10 * 60 + 19) + [10 * 60 + 20] * 100 + [10 * 60 + 21] * 5
                   + _spread(rng, 20, 10 * 60 + 22, 10 * 60 + 35))
    thu += [make_row(rng, ATTACKER, VICTIM, 80, _ts((6, 7, 2017), m, None), "Web Attack – XSS") for m in xss_minutes]
    _write(d / "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv", thu, "cp1252", trailing_empty=5)
    return d


EXPECTED = {"comma_only_rows": 5, "exact_duplicate_rows": 1, "negative_duration_rows": 1,
            "final_rows": (300 + 5) + (300 + 150 + 40 + 2) + (200 + 120 + 12 + 150)}  # Monday: 6 specials, 1 removed


def synthetic_config(root: Path, raw_dir: Path) -> dict[str, Any]:
    cfg = yaml.safe_load(Path("configs/preprocessing.yaml").read_text(encoding="utf-8"))
    cfg = copy.deepcopy(cfg)
    cfg["paths"] = {"raw_dir": str(raw_dir), "manifest": None, "out_dir": str(root / "processed"),
                    "report_dir": str(root / "reports")}
    cfg["files"] = {"Monday-WorkingHours.pcap_ISCX.csv": "2017-07-03", "Tuesday-WorkingHours.pcap_ISCX.csv": "2017-07-04",
                    "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv": "2017-07-06"}
    cfg["splits"]["dayholdout"]["train_days"] = ["2017-07-03", "2017-07-04"]
    cfg["splits"]["dayholdout"]["test_days"] = ["2017-07-06"]
    cfg["expect"] = dict(EXPECTED)
    return cfg
