"""End-to-end and unit tests for Milestone 1 preprocessing (synthetic raw data)."""
from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from src.preprocessing.dataset import load_split
from src.preprocessing.features import FeatureTransform
from src.preprocessing.labels import UnknownLabelError
from src.preprocessing.pipeline import run
from src.preprocessing.raw_manifest import RawDataChangedError, compute_manifest, verify_manifest
from src.preprocessing.splits import rank_boundaries, split_group
from src.preprocessing.timestamps import TimestampError, parse_and_correct
from tests.synthetic_cicids import EXPECTED, build_raw_dir, synthetic_config


@pytest.fixture(scope="module")
def processed(tmp_path_factory: pytest.TempPathFactory) -> dict:
    root = tmp_path_factory.mktemp("pipe")
    raw = build_raw_dir(root)
    before = compute_manifest(raw)
    cfg = synthetic_config(root, raw)
    res = run(cfg)
    out = Path(cfg["paths"]["out_dir"])
    return {"root": root, "raw": raw, "before": before, "cfg": cfg, "res": res, "out": out,
            "meta": pd.read_parquet(out / "metadata.parquet"), "flows": pd.read_parquet(out / "flows.parquet"),
            "removed": pd.read_parquet(out / "removed_rows.parquet"),
            "corr": pd.read_parquet(out / "corrections.parquet")}


# ---------------------------------------------------------------- row identity / removals / raw integrity
def test_raw_files_unchanged(processed: dict) -> None:
    assert compute_manifest(processed["raw"]) == processed["before"]


def test_expected_counts_and_removals(processed: dict) -> None:
    checks = processed["res"]["metadata"]["expected_count_checks"]
    for k, v in EXPECTED.items():
        assert checks[k]["observed"] == v
    r = processed["removed"]
    assert set(r["reason"]) == {"comma_only_row", "exact_duplicate", "negative_flow_duration"}
    assert r.loc[r.reason == "exact_duplicate", "flow_uid"].tolist() == ["Monday-WorkingHours:1"]
    # trailing comma-only rows are the last 5 raw rows of the Thursday file (482 records -> rows 482..486)
    assert sorted(r.loc[r.reason == "comma_only_row", "flow_uid"]) == [
        f"Thursday-WorkingHours-Morning-WebAttacks:{i}" for i in range(482, 487)]


def test_flow_uid_traceability(processed: dict) -> None:
    m, f = processed["meta"], processed["flows"]
    assert m["flow_uid"].is_unique
    assert (m["flow_uid"] == m["source_file"] + ":" + m["raw_row"].astype(str)).all()
    assert (f["flow_uid"].to_numpy() == m["flow_uid"].to_numpy()).all()
    removed = set(processed["removed"]["flow_uid"])
    assert removed.isdisjoint(set(m["flow_uid"]))
    # kept + removed == every raw data row
    raw_rows = {"Monday-WorkingHours": 307, "Tuesday-WorkingHours": 492, "Thursday-WorkingHours-Morning-WebAttacks": 487}
    for stem, n in raw_rows.items():
        uids = {u for u in set(m["flow_uid"]) | removed if u.startswith(stem + ":")}
        assert uids == {f"{stem}:{i}" for i in range(n)}


def test_raw_label_and_timestamp_preserved(processed: dict) -> None:
    m = processed["meta"]
    assert "Web Attack – Sql Injection" in set(m["label_raw"])
    assert (m.loc[m.label_raw == "Web Attack – Sql Injection", "label_fine"] == "Web Attack - SQL Injection").all()
    assert set(m["label_family"]) == {"Benign", "BruteForce", "WebAttack"}
    assert ((m["label_family"] == "Benign") == (m["label_binary"] == 0)).all()
    pm = m[m.timestamp_corrected]
    assert (pm["timestamp"].dt.hour.between(13, 17)).all()
    assert (m.loc[~m.timestamp_corrected, "timestamp"].dt.hour.between(8, 12)).all()
    # raw string kept verbatim and still shows the 12-hour value
    assert (pm["timestamp_raw"].str.extract(r" (\d{1,2}):")[0].astype(int) + 12 == pm["timestamp"].dt.hour).all()


# ---------------------------------------------------------------- feature corrections
def test_corrections_logged_with_raw_values(processed: dict) -> None:
    c = processed["corr"]
    rules = set(zip(c["rule"], c["column"]))
    assert ("clip_negative_iat_to_zero", "Flow IAT Min") in rules and ("clip_negative_iat_to_zero", "Fwd IAT Min") in rules
    assert ("overflow_to_missing", "Fwd Header Length") in rules
    assert ("overflow_to_missing", "min_seg_size_forward") in rules
    assert ("invalid_negative_to_missing", "Fwd Header Length") in rules
    assert ("nonfinite_rate_to_missing", "Flow Packets/s") in rules
    ov = c[(c.rule == "overflow_to_missing") & (c.column == "Fwd Header Length")]
    assert ov["raw_value"].tolist() == ["-83885125.0"]
    assert set(c.loc[c.rule == "nonfinite_rate_to_missing", "raw_value"]) <= {"inf", "nan"}


def test_feature_invariants(processed: dict) -> None:
    f = processed["flows"].drop(columns="flow_uid")
    assert "Fwd Header Length.1" not in f.columns
    assert not np.isinf(f.to_numpy()).any()
    neg = (f < 0).any()
    assert set(neg[neg].index) <= {"Init_Win_bytes_forward", "Init_Win_bytes_backward"}
    assert ((f["Init_Win_bytes_forward"] < 0) <= (f["Init_Win_bytes_forward"] == -1)).all()   # sentinel kept
    m = processed["meta"]
    zero = f["flow_duration_zero"] == 1
    assert zero.sum() == 2 and f.loc[zero, "Flow Packets/s"].isna().all()
    assert f["header_len_invalid"].sum() == 2 and f["iat_negative_clipped"].sum() == 1
    assert len(f) == len(m)


# ---------------------------------------------------------------- splits
def test_primary_purge_guarantee_and_small_groups(processed: dict) -> None:
    m = processed["meta"]
    gap = np.timedelta64(60, "s")
    for (day, lab), g in m.groupby(["day", "label_fine"]):
        st = set(g["purge_status_primary"])
        if len(g) >= 100:
            assert st <= {"gap_applied", "purged"} or st <= {"minute_boundary", "boundary_minute_dropped"}, (day, lab, st)
            tr, va, te = (g.loc[g.split_primary == s, "timestamp"] for s in ("train", "val", "test"))
            assert va.min() - tr.max() > gap and te.min() - va.max() > gap
        else:
            assert st == {"no_purge_gap"}, (day, lab, st)
            assert set(g["split_primary"]) == {"train", "val", "test"}
    small = m[m.label_fine.isin(["SSH-Patator", "Web Attack - SQL Injection"])]
    assert (small["purge_status_primary"] == "no_purge_gap").all()


def test_dense_burst_uses_minute_boundaries(processed: dict) -> None:
    m = processed["meta"]
    g = m[m.label_fine == "Web Attack - XSS"]
    assert set(g["purge_status_primary"]) == {"minute_boundary", "boundary_minute_dropped"}
    minutes = {s: set(g.loc[g.split_primary == s, "timestamp"].dt.floor("min")) for s in ("train", "val", "test", "purged")}
    assert all(minutes[s] for s in ("train", "val", "test"))
    for a, b in (("train", "val"), ("train", "test"), ("val", "test")):
        assert minutes[a].isdisjoint(minutes[b])           # no recorded minute shared across splits
    assert max(minutes["train"]) < min(minutes["val"]) and max(minutes["val"]) < min(minutes["test"])
    dropped = g[g.split_primary == "purged"]
    assert (dropped["purge_status_primary"] == "boundary_minute_dropped").all()
    assert len(minutes["purged"]) == 2                      # exactly one whole boundary minute per cut
    # whole minutes are dropped: every row of a dropped minute is dropped
    assert g[g.timestamp.dt.floor("min").isin(minutes["purged"])]["split_primary"].eq("purged").all()
    rep = {(r["day"], r["label_fine"]): r for r in
           json.loads((processed["out"] / "schemes" / "primary" / "split_stats.json").read_text())["group_splits"]}
    r = rep[("2017-07-06", "Web Attack - XSS")]
    assert r["method"] == "minute_boundary" and r["train"] + r["val"] + r["test"] + r["dropped"] == r["n"] == 150


def test_minute_boundary_unit() -> None:
    from src.preprocessing.splits import minute_boundary_split

    base = np.datetime64("2017-07-07T14:00", "s")
    mins = [0] * 10 + [1] * 10 + [2] * 3 + [3] * 3 + [4] * 2 + [5] * 2 + [6] * 1  # 31 rows, 7 minutes
    ts = base + np.array(mins) * np.timedelta64(60, "s")
    s = minute_boundary_split(ts, [0.7, 0.15, 0.15])
    assert s is not None
    mi = np.array(mins)
    for j in (0, 1, 2):
        assert (s == j).any()
    for x in set(mins):                                     # each minute wholly in one split (or dropped)
        assert len(set(s[mi == x])) == 1
    assert (np.diff(s[s >= 0]) >= 0).all()                  # chronological
    assert minute_boundary_split(base + np.array([0, 0, 1, 1]) * np.timedelta64(60, "s"), [0.7, 0.15, 0.15]) is None


def test_feature_collision_reports(processed: dict) -> None:
    st = json.loads((processed["out"] / "dataset_stats.json").read_text())["label_collisions"]
    assert st["default"]["groups"] >= 1 and "BENIGN | FTP-Patator" in st["default"]["group_label_combinations"]
    c = json.loads((processed["out"] / "schemes" / "primary" / "feature_collisions.json").read_text())
    assert set(c) == {"default", "dstport"} and set(c["default"]) == {"val", "test"}


def test_every_class_in_every_primary_split(processed: dict) -> None:
    m = processed["meta"]
    tab = pd.crosstab(m["label_fine"], m["split_primary"])
    assert (tab[["train", "val", "test"]] > 0).all().all()


def test_dayholdout(processed: dict) -> None:
    m = processed["meta"]
    assert (m.loc[m.day == "2017-07-06", "split_dayholdout"] == "test").all()
    assert set(m.loc[m.day != "2017-07-06", "split_dayholdout"]) <= {"train", "val", "purged"}


def test_split_unit_rules() -> None:
    assert rank_boundaries(11, [0.7, 0.15, 0.15]) == [7, 9]
    assert rank_boundaries(3, [0.7, 0.15, 0.15]) == [1, 2]
    ts = np.array(["2017-07-04T10:00", "2017-07-04T10:00", "2017-07-04T10:00"], dtype="datetime64[s]")
    s, st = split_group(ts, [0.7, 0.15, 0.15], np.timedelta64(60, "s"), min_n=2)
    assert set(st) == {"purge_infeasible"} and sorted(s.tolist()) == [0, 1, 2]


# ---------------------------------------------------------------- transforms (train-only)
def test_transforms_fit_on_train_only(processed: dict) -> None:
    out, m, f = processed["out"], processed["meta"], processed["flows"]
    for sc in ("primary", "dayholdout"):
        tf = FeatureTransform.from_json(out / "schemes" / sc / "transforms.json")
        tr = f[(m[f"split_{sc}"] == "train").to_numpy()]
        assert tf.n_train_rows == len(tr)
        for c in ("Flow Duration", "Flow Packets/s", "Total Fwd Packets"):
            assert tf.medians[c] == pytest.approx(float(tr[c].median()))
        assert "Bwd PSH Flags" in tf.dropped_constant


def test_feature_transform_ignores_test_distribution() -> None:
    tr = pd.DataFrame({"a": [1.0, 2.0, 3.0, np.nan], "b": [5.0, 5.0, 5.0, 5.0]})
    te = pd.DataFrame({"a": [np.nan, 1e9]})
    tf = FeatureTransform.fit(tr)
    assert tf.columns == ["a"] and tf.dropped_constant == {"b": 5.0} and tf.medians["a"] == 2.0
    assert tf.transform(te, ["a"], "raw")[0, 0] == 2.0


def test_schemas_and_dstport_ablation(processed: dict) -> None:
    sdir = processed["out"] / "schemes" / "primary"
    d = json.loads((sdir / "feature_schema_default.json").read_text())
    p = json.loads((sdir / "feature_schema_dstport.json").read_text())
    assert "Destination Port" not in d["columns"] and "Destination Port" in p["columns"]
    assert set(p["columns"]) - set(d["columns"]) == {"Destination Port"}
    forbidden = {"Flow ID", "Source IP", "Source Port", "Destination IP", "Timestamp", "Label", "flow_uid"}
    assert forbidden.isdisjoint(d["columns"]) and forbidden <= set(d["excluded_columns"]) | {"flow_uid"}
    shapes = set()
    for part in ("train", "val", "test"):
        for rep in ("raw", "scaled"):
            sd = load_split(processed["out"], "primary", part, "default", rep, "family")
            assert np.isfinite(sd.X).all() and sd.X.dtype == np.float32
            assert sd.columns == d["columns"] and len(sd.flow_uid) == len(sd.y) == sd.X.shape[0]
            shapes.add(sd.X.shape[1])
    assert shapes == {d["n_features"]}


def test_label_map_from_train(processed: dict) -> None:
    lm = json.loads((processed["out"] / "schemes" / "dayholdout" / "label_map.json").read_text())
    assert "WebAttack" not in lm["family"] and "WebAttack" in lm["absent_from_train"]["family"]
    with pytest.raises(KeyError, match="absent from train"):
        load_split(processed["out"], "dayholdout", "test", target="family")
    sd = load_split(processed["out"], "dayholdout", "test", target="binary")
    assert set(np.unique(sd.y)) == {0, 1}


# ---------------------------------------------------------------- diagnostics
def test_diagnostic_flags(processed: dict) -> None:
    m = processed["meta"]
    assert (m.loc[m.label_binary == 1, "dominant_pair_directed"]).all()
    assert not m.loc[m.label_binary == 0, "dominant_pair_directed"].any()
    out = m[m.outside_published_window.fillna(False)]
    assert out["label_fine"].tolist() == ["FTP-Patator"] and out["timestamp"].dt.strftime("%H:%M").tolist() == ["11:30"]
    assert m.loc[m.label_binary == 0, "outside_published_window"].isna().all()
    grp = m[m.conflict_group_default >= 0]
    assert len(grp) == 2 and set(grp["label_fine"]) == {"BENIGN", "FTP-Patator"}
    stats = json.loads((processed["out"] / "schemes" / "primary" / "split_stats.json").read_text())
    assert "2017-07-04 | SSH-Patator" in stats["groups_without_purge_gap"]
    assert "counts_label_family" in stats and "low_support_label_fine" in stats


# ---------------------------------------------------------------- failure modes
def test_unknown_label_aborts(tmp_path: Path) -> None:
    raw = build_raw_dir(tmp_path)
    p = raw / "Tuesday-WorkingHours.pcap_ISCX.csv"
    p.write_bytes(p.read_bytes().replace(b"SSH-Patator", b"SSH Mystery"))
    with pytest.raises(UnknownLabelError):
        run(synthetic_config(tmp_path, raw))


def test_manifest_detects_change(tmp_path: Path) -> None:
    raw = build_raw_dir(tmp_path)
    man = tmp_path / "m.json"
    man.write_text(json.dumps(compute_manifest(raw)))
    verify_manifest(raw, man)
    p = raw / "Monday-WorkingHours.pcap_ISCX.csv"
    p.write_bytes(p.read_bytes() + b"\n")
    with pytest.raises(RawDataChangedError, match="changed"):
        verify_manifest(raw, man)


def test_timestamp_rule_rejects_unvalidated_hours() -> None:
    ts, corr = parse_and_correct(pd.Series(["5/7/2017 3:12", "5/7/2017 12:30", "03/07/2017 08:55:58"]))
    assert corr.tolist() == [True, False, False]
    assert ts.dt.strftime("%H:%M:%S").tolist() == ["15:12:00", "12:30:00", "08:55:58"]
    for bad in ("5/7/2017 7:00", "5/7/2017 13:00", "5/7/2017 0:10", "2017-07-05 10:00"):
        with pytest.raises(TimestampError):
            parse_and_correct(pd.Series([bad]))
