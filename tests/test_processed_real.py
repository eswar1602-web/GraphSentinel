"""Checks on the real processed dataset (skipped unless data/processed/v1 and the raw CSVs exist)."""
from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from src.preprocessing.raw_manifest import verify_manifest

OUT = Path("data/processed/v1")
RAW = Path("data/raw/CICIDS2017/TrafficLabelling")
pytestmark = [pytest.mark.realdata,
              pytest.mark.skipif(not (OUT / "metadata.parquet").exists() or not RAW.exists(),
                                 reason="real processed data not present")]


@pytest.fixture(scope="module")
def meta() -> pd.DataFrame:
    return pd.read_parquet(OUT / "metadata.parquet")


def test_raw_unchanged() -> None:
    verify_manifest(RAW, Path("configs/raw_manifest_cicids2017.json"))


def test_counts_match_contract(meta: pd.DataFrame) -> None:
    md = json.loads((OUT / "preprocessing_metadata.json").read_text(encoding="utf-8"))
    for name, c in md["expected_count_checks"].items():
        assert c["observed"] == c["expected"], name
    assert len(meta) == 2_830_425 and meta["flow_uid"].is_unique
    assert int(meta["timestamp_corrected"].sum()) == 1_471_487
    removed = pd.read_parquet(OUT / "removed_rows.parquet")
    assert removed["reason"].value_counts().to_dict() == {"comma_only_row": 288602, "exact_duplicate": 203,
                                                          "negative_flow_duration": 115}
    assert set(removed["flow_uid"]).isdisjoint(set(meta["flow_uid"]))


def test_labels_and_rare_classes_kept(meta: pd.DataFrame) -> None:
    fine = meta["label_fine"].value_counts()
    assert len(fine) == 15 and fine["Heartbleed"] == 11 and fine["Infiltration"] == 36
    assert fine["Web Attack - SQL Injection"] == 21
    tab = pd.crosstab(meta["label_fine"], meta["split_primary"])
    assert (tab[["train", "val", "test"]] > 0).all().all()  # every class in every primary split


def test_small_groups_flagged(meta: pd.DataFrame) -> None:
    for lab in ("Heartbleed", "Infiltration", "Web Attack - SQL Injection"):
        assert (meta.loc[meta.label_fine == lab, "purge_status_primary"] == "no_purge_gap").all()


@pytest.mark.parametrize("label", ["PortScan", "DoS GoldenEye"])
def test_dense_bursts_split_on_whole_minutes(meta: pd.DataFrame, label: str) -> None:
    g = meta[meta.label_fine == label]
    assert set(g["purge_status_primary"]) == {"minute_boundary", "boundary_minute_dropped"}
    mins = {s: set(g.loc[g.split_primary == s, "timestamp"].dt.floor("min")) for s in ("train", "val", "test", "purged")}
    assert all(mins[s] for s in ("train", "val", "test"))
    assert max(mins["train"]) < min(mins["val"]) and max(mins["val"]) < min(mins["test"])
    for a, b in (("train", "val"), ("train", "test"), ("val", "test")):
        assert mins[a].isdisjoint(mins[b])
    assert len(mins["purged"]) == 2
    assert g[g.timestamp.dt.floor("min").isin(mins["purged"])]["split_primary"].eq("purged").all()


def test_no_rank_only_fallback_left(meta: pd.DataFrame) -> None:
    assert not meta["purge_status_primary"].eq("purge_infeasible").any()
    assert not meta["purge_status_dayholdout"].eq("purge_infeasible").any()


def test_dominant_pair(meta: pd.DataFrame) -> None:
    atk = meta["label_binary"] == 1
    assert meta.loc[atk, "dominant_pair_directed"].mean() == pytest.approx(0.9964, abs=5e-4)


def test_flows_aligned_and_clean() -> None:
    m = pd.read_parquet(OUT / "metadata.parquet", columns=["flow_uid"])
    f = pd.read_parquet(OUT / "flows.parquet")
    assert (f["flow_uid"].to_numpy() == m["flow_uid"].to_numpy()).all()
    X = f.drop(columns="flow_uid")
    assert "Fwd Header Length.1" not in X and not np.isinf(X.to_numpy()).any()
    neg = (X < 0).any()
    assert set(neg[neg].index) == {"Init_Win_bytes_forward", "Init_Win_bytes_backward"}
