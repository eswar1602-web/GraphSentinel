"""Tests for audit-resolution logic (synthetic data) plus real-data checks (skipped if CSVs absent)."""
from __future__ import annotations

from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from src.preprocessing import audit_resolution as ar
from tests.conftest import HEADER, _row, _write

REAL = Path("data/raw/CICIDS2017/TrafficLabelling")


def test_scan_finds_contiguous_comma_only_block(synthetic_raw_dir: Path) -> None:
    s = ar.scan_raw_lines(synthetic_raw_dir / "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv")
    assert s["comma_only_lines"] == 3
    assert s["comma_only_runs"] == [[5, 7]]  # header=1, 3 records, then 3 empty lines
    assert s["comma_count_distribution"] == {len(HEADER) - 1: 7}
    assert s["crlf_lines"] == 7 and s["quote_chars"] == 0
    assert s["transitions"][0]["first_empty"][0] == 5
    assert s["transitions"][0]["before"][-1][0] == 4
    eq = s["fwd_header_length_raw_equality"]
    assert eq["compared"] == 3 and eq["equal"] == 3


def test_scan_reports_header_duplicate_mismatch(tmp_path: Path) -> None:
    r = _row("a-b-1-80-6", "a", 1, "b", 80, "3/7/2017 9:00", 5, "1", "1", 20, 1, "BENIGN")
    r[12] = "999"  # second 'Fwd Header Length' differs
    _write(tmp_path / "x.csv", [r], "utf-8")
    eq = ar.scan_raw_lines(tmp_path / "x.csv")["fwd_header_length_raw_equality"]
    assert eq["equal"] == 0 and eq["mismatch_examples"][0]["b"] == "999"


def _neg_frame() -> tuple[pd.DataFrame, pd.DataFrame]:
    num = pd.DataFrame({c: [0.0, 0.0] for c in ar.NEG_CONTEXT_COLS}, index=[7, 9])
    num.loc[9, ["Flow Duration", "Total Fwd Packets", "Total Backward Packets"]] = [-1.0, 1.0, 1.0]
    num.loc[9, ["Flow Packets/s", "Flow Bytes/s", "Flow IAT Min", "Flow IAT Max", "Flow IAT Mean"]] = [-2e6, -1.2e7, -1, -1, -1]
    df = pd.DataFrame({"Flow ID": ["f7", "f9"], "Timestamp": ["t7", "t9"], "Label": ["BENIGN", "BENIGN"]}, index=[7, 9])
    return df, num


def test_negative_duration_records_keep_raw_row_identity() -> None:
    df, num = _neg_frame()
    out = ar.negative_duration_records(df, num, "Mon")
    assert out["flow_uid"].tolist() == ["Mon:9"] and out["file_line"].tolist() == [11]
    assert bool(out["rate_negative"].iloc[0]) and bool(out["iat_negative"].iloc[0])
    assert out["packets_per_s_recomputed"].iloc[0] == pytest.approx(-2e6)


def test_conflicting_groups() -> None:
    feats = pd.DataFrame({"Destination Port": [80, 80, 80, 443], "Protocol": [6, 6, 6, 6], "Flow Duration": [0, 0, 0, 5]})
    lab = pd.Series(["DoS Hulk", "DoS Hulk", "BENIGN", "BENIGN"])
    extra = pd.DataFrame({"Timestamp": ["a", "b", "c", "d"], "Source IP": ["x", "x", "y", "y"],
                          "Destination IP": ["v", "v", "w", "w"]}).join(feats.astype(float))
    c = ar.conflicting_groups(ar.row_hash(feats.astype(float)), lab, extra)
    assert c["groups"] == 1 and c["rows"] == 3
    assert c["largest_groups"][0]["labels"] == {"DoS Hulk": 2, "BENIGN": 1}
    assert c["rows_by_label"] == {"DoS Hulk": 2, "BENIGN": 1}


def test_timestamp_parts_and_candidate_correction() -> None:
    ts = pd.Series(["3/7/2017 8:55", "03/07/2017 12:59:30", "3/7/2017 1:00", "3/7/2017 5:04"])
    p = ar.parse_timestamp_parts(ts)
    assert p["hour"].tolist() == [8, 12, 1, 5]
    assert p["has_seconds"].tolist() == [False, True, False, False]
    raw, cor = ar.corrected_minutes(p)
    assert cor.tolist() == [8 * 60 + 55, 12 * 60 + 59.5, 13 * 60, 17 * 60 + 4]  # 12 stays noon
    assert ar.backward_jump_fraction(raw) == pytest.approx(1 / 3)
    assert ar.backward_jump_fraction(cor) == 0.0


def test_timestamp_evidence_against_schedule() -> None:
    df = pd.DataFrame({"Timestamp": ["7/7/2017 3:56", "7/7/2017 4:10", "7/7/2017 3:30"],
                       "Label": ["DDoS", "DDoS", "BENIGN"]})
    ev = ar.timestamp_evidence(df)
    w = ev["label_windows"]["DDoS"]
    assert w["corrected"] == ["15:56", "16:10"] and w["corrected_rows_within_published_pm5min"] == 1.0
    assert w["raw_rows_within_published_pm5min"] == 0.0 and w["day_matches"]
    assert not ev["any_hour_13_to_23"]


def test_flow_id_analysis() -> None:
    df = pd.DataFrame({"Flow ID": ["a-b-1-2-6", "a-b-1-2-6", "c-d-3-4-6"], "Source IP": ["a", "b", "c"],
                       "Timestamp": ["t", "t", "u"], "Label": ["BENIGN", "DDoS", "BENIGN"]})
    f = ar.flow_id_analysis(df)
    assert f["rows_with_repeated_flow_id"] == 2 and f["rows_src_not_first_ip_in_flow_id"] == 1
    assert f["flow_ids_seen_in_both_directions"] == 1 and f["flow_ids_with_multiple_labels"] == 1
    assert f["rows_sharing_flow_id_and_timestamp"] == 2


def test_exact_duplicate_summary() -> None:
    df = pd.DataFrame({"Flow ID": ["a", "a", "b", "a"], "Timestamp": ["t"] * 4, "Label": ["BENIGN"] * 4, "x": [1, 1, 2, 1]})
    e = ar.exact_duplicate_summary(df, "S")
    assert e["extra_copies"] == 2 and e["rows_involved"] == 3 and e["adjacent_to_identical_row"] == 1
    assert e["examples"][0]["flow_uid"] == "S:1"


# ------------------------------------------------------------------ real data (skipped when absent)
realdata = pytest.mark.skipif(not REAL.exists() or not any(REAL.glob("*.csv")), reason="real CICIDS2017 CSVs not present")


@pytest.mark.realdata
@realdata
def test_real_webattacks_trailing_block_is_comma_only() -> None:
    s = ar.scan_raw_lines(REAL / "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv")
    assert s["comma_only_runs"] == [[170368, 458969]] and s["comma_only_lines"] == 288602
    assert s["comma_count_distribution"] == {84: 458969} and s["quote_chars"] == 0
    assert s["fwd_header_length_raw_equality"]["equal"] == s["fwd_header_length_raw_equality"]["compared"] == 170366


@pytest.mark.realdata
@realdata
def test_real_labels_all_map() -> None:
    from src.preprocessing.labels import map_label

    df = ar.load_csv(REAL / "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv").dropna(how="all")
    assert {map_label(x)[1] for x in df["Label"].unique()} == {"Benign", "WebAttack"}
    assert np.isin(["Web Attack – Sql Injection"], df["Label"].unique()).all()
