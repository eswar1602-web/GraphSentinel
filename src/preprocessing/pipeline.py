"""Milestone 1 preprocessing pipeline: raw CICIDS2017 CSVs -> versioned, auditable processed dataset.

Usage:
    python -m src.preprocessing.pipeline --config configs/preprocessing.yaml

Outputs (contract §8), under paths.out_dir:
  flows.parquet            flow_uid + corrected (not yet imputed/scaled) numeric features + indicator columns
  metadata.parquet         flow_uid, identities, timestamps (raw + corrected), labels (4 levels), split tags, flags
  removed_rows.parquet     flow_uid + reason for every removed raw row
  corrections.parquet      every corrected cell: flow_uid, column, raw value, new value, rule
  schemes/<scheme>/        transforms.json (train-only fit), feature_schema_<set>.json, label_map.json, split_stats.json
  preprocessing_metadata.json, dataset_stats.json
"""
from __future__ import annotations

import argparse
import hashlib
import json
import platform
import sys
import time
from importlib import metadata as im
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
import yaml

from src.preprocessing import diagnostics as dg
from src.preprocessing.cleaning import IDENTITY_COLUMNS, apply_feature_corrections, process_file
from src.preprocessing.features import FeatureTransform, build_schema
from src.preprocessing.labels import FAMILIES, FINE_LABELS
from src.preprocessing.raw_manifest import compute_manifest, verify_manifest
from src.preprocessing.splits import dayholdout_split, primary_split

SCHEMES = ("primary", "dayholdout")


def load_config(path: Path) -> dict[str, Any]:
    return yaml.safe_load(Path(path).read_text(encoding="utf-8"))


def _sha256_text(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def _code_fingerprint() -> dict[str, str]:
    root = Path(__file__).parent
    return {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(root.glob("*.py"))}


def _check(name: str, observed: int, expect: dict[str, Any], checks: dict[str, Any]) -> None:
    exp = (expect or {}).get(name)
    checks[name] = {"observed": observed, "expected": exp}
    if exp is not None and observed != exp:
        raise AssertionError(f"{name}: observed {observed:,} but contract expects {exp:,}")


def _label_map(train_meta: pd.DataFrame) -> dict[str, Any]:
    present_fam = [f for f in FAMILIES if f in set(train_meta["label_family"])]
    present_fine = [f for f in FINE_LABELS if f in set(train_meta["label_fine"])]
    return {"derived_from": "train split only",
            "family": {f: i for i, f in enumerate(present_fam)},
            "fine": {f: i for i, f in enumerate(present_fine)},
            "binary": {"benign": 0, "attack": 1},
            "absent_from_train": {"family": [f for f in FAMILIES if f not in present_fam],
                                  "fine": [f for f in FINE_LABELS if f not in present_fine]}}


def run(cfg: dict[str, Any]) -> dict[str, Any]:
    t0 = time.time()
    raw_dir, out_dir = Path(cfg["paths"]["raw_dir"]), Path(cfg["paths"]["out_dir"])
    expect = cfg.get("expect") or {}
    checks: dict[str, Any] = {}

    # ---- 0. raw integrity (before and after)
    manifest_path = cfg["paths"].get("manifest")
    raw_before = verify_manifest(raw_dir, Path(manifest_path)) if manifest_path else compute_manifest(raw_dir)

    # ---- 1. per-file load, removals, timestamps, labels
    metas, nums, removed, file_info = [], [], [], {}
    present = {p.name for p in raw_dir.glob("*.csv")}
    if set(cfg["files"]) != present:
        raise ValueError(f"config files {sorted(cfg['files'])} != files on disk {sorted(present)}")
    for name, date in cfg["files"].items():
        print(f"[1/6] {name}", flush=True)
        r = process_file(raw_dir / name, date, cfg)
        if nums and list(r.num.columns) != list(nums[0].columns):
            raise AssertionError(f"{name}: feature columns differ from {list(cfg['files'])[0]}")
        metas.append(r.meta), nums.append(r.num), removed.append(r.removed)
        file_info[name] = r.info
    meta = pd.concat(metas, ignore_index=True)
    num = pd.concat(nums, ignore_index=True)
    removed_df = pd.concat(removed, ignore_index=True)
    del metas, nums
    if not meta["flow_uid"].is_unique:
        raise AssertionError("flow_uid not unique")
    if num.isna().all(axis=0).any():
        raise AssertionError(f"columns entirely missing: {list(num.columns[num.isna().all(axis=0)])}")
    rc = removed_df["reason"].value_counts()
    _check("comma_only_rows", int(rc.get("comma_only_row", 0)), expect, checks)
    _check("exact_duplicate_rows", int(rc.get("exact_duplicate", 0)), expect, checks)
    _check("negative_duration_rows", int(rc.get("negative_flow_duration", 0)), expect, checks)
    _check("final_rows", int(len(meta)), expect, checks)
    _check("timestamp_corrected_rows", int(meta["timestamp_corrected"].sum()), expect, checks)

    # ---- 2. value corrections (logged per cell)
    print("[2/6] feature corrections", flush=True)
    num, corrections, corr_summary = apply_feature_corrections(num, meta["flow_uid"], cfg["features"])

    # ---- 3. diagnostics flags (metadata only)
    print("[3/6] diagnostics", flush=True)
    dcfg = cfg["diagnostics"]
    meta["dominant_pair_directed"], meta["dominant_pair_undirected"] = dg.dominant_pair_flags(
        meta, dcfg["dominant_pair"]["src"], dcfg["dominant_pair"]["dst"])
    meta["outside_published_window"] = dg.outside_published_window(meta, dcfg["schedule_tolerance_minutes"])
    default_cols = [c for c in num.columns if c != "Destination Port"]
    h_default, h_dstport = dg.row_hash(num[default_cols]), dg.row_hash(num)
    meta["conflict_group_default"] = dg.conflict_group_ids(h_default, meta["label_fine"])
    meta["conflict_group_dstport"] = dg.conflict_group_ids(h_dstport, meta["label_fine"])

    # ---- 4. splits
    print("[4/6] splits", flush=True)
    meta["split_primary"], meta["purge_status_primary"] = primary_split(meta, cfg["splits"]["primary"])
    meta["split_dayholdout"], meta["purge_status_dayholdout"] = dayholdout_split(meta, cfg["splits"]["dayholdout"])
    for sc in SCHEMES:
        meta[f"train_dup_{sc}"] = dg.train_duplicate_flags(h_default, meta[f"split_{sc}"])

    # ---- 5. train-only transforms, schemas, label maps, stats
    print("[5/6] train-only transforms", flush=True)
    out_dir.mkdir(parents=True, exist_ok=True)
    excluded = {c: "identity/metadata column (never a feature)" for c in IDENTITY_COLUMNS}
    excluded["Label"] = "target"
    excluded[cfg["features"]["duplicate_header_drop"]["drop"]] = (
        f"verified identical to '{cfg['features']['duplicate_header_drop']['must_equal']}' on every kept row")
    scheme_info = {}
    for sc in SCHEMES:
        sdir = out_dir / "schemes" / sc
        sdir.mkdir(parents=True, exist_ok=True)
        train_mask = (meta[f"split_{sc}"] == "train").to_numpy()
        tf = FeatureTransform.fit(num.loc[train_mask])
        tf.to_json(sdir / "transforms.json")
        for fs, fsc in cfg["features"]["feature_sets"].items():
            schema = build_schema(tf, fs, fsc["include_destination_port"], excluded)
            (sdir / f"feature_schema_{fs}.json").write_text(json.dumps(schema, indent=1), encoding="utf-8")
            # every partition must transform cleanly against the same schema
            for part in ("train", "val", "test"):
                m = (meta[f"split_{sc}"] == part).to_numpy()
                if m.any():
                    X = tf.transform(num.loc[m].head(200_000), schema["columns"], "scaled")
                    assert X.shape[1] == schema["n_features"]
        lm = _label_map(meta.loc[train_mask])
        (sdir / "label_map.json").write_text(json.dumps(lm, indent=1), encoding="utf-8")
        st = dg.split_statistics(meta, sc, dcfg["low_support_threshold"])
        st["dominant_pair_share_of_train_attacks"] = float(
            meta.loc[train_mask & (meta["label_binary"] == 1).to_numpy(), "dominant_pair_directed"].mean())
        (sdir / "split_stats.json").write_text(json.dumps(st, indent=1, default=str), encoding="utf-8")
        coll = {fs: dg.train_eval_collisions(hh, meta["label_fine"], meta[f"split_{sc}"])
                for fs, hh in (("default", h_default), ("dstport", h_dstport))}
        (sdir / "feature_collisions.json").write_text(json.dumps(coll, indent=1, default=str), encoding="utf-8")
        scheme_info[sc] = {"train_rows": int(train_mask.sum()), "constant_dropped": list(tf.dropped_constant),
                           "n_features": {fs: len(build_schema(tf, fs, f["include_destination_port"], excluded)["columns"])
                                          for fs, f in cfg["features"]["feature_sets"].items()}}

    # ---- 6. write data + metadata
    print("[6/6] writing outputs", flush=True)
    flows = num.copy()
    flows.insert(0, "flow_uid", meta["flow_uid"].to_numpy())
    flows.to_parquet(out_dir / "flows.parquet", index=False)
    meta.to_parquet(out_dir / "metadata.parquet", index=False)
    removed_df.to_parquet(out_dir / "removed_rows.parquet", index=False)
    corrections.to_parquet(out_dir / "corrections.parquet", index=False)

    raw_after = compute_manifest(raw_dir)
    if raw_after != {"files": raw_before["files"]}:
        raise AssertionError("raw files changed during preprocessing")

    stats = {
        "rows": int(len(meta)), "rows_by_file": meta["source_file"].value_counts().to_dict(),
        "label_fine": meta["label_fine"].value_counts().to_dict(),
        "label_family": meta["label_family"].value_counts().to_dict(),
        "label_binary": meta["label_binary"].value_counts().to_dict(),
        "unique_endpoints": int(pd.concat([meta["src_ip"], meta["dst_ip"]]).nunique()),
        "dominant_pair": {
            "directed_rows": int(meta["dominant_pair_directed"].sum()),
            "attack_rows_on_pair": int((meta["dominant_pair_directed"] & (meta["label_binary"] == 1)).sum()),
            "attack_rows_total": int((meta["label_binary"] == 1).sum()),
            "attack_share_on_pair": float(meta.loc[meta["label_binary"] == 1, "dominant_pair_directed"].mean()),
            "attack_fraction_within_pair": float(meta.loc[meta["dominant_pair_directed"], "label_binary"].mean()),
            "by_family_on_pair": meta[meta["dominant_pair_directed"]]["label_family"].value_counts().to_dict()},
        "outside_published_window_by_label": meta[meta["outside_published_window"].fillna(False)]["label_fine"].value_counts().to_dict(),
        "conflict_groups": {"default": int(meta["conflict_group_default"].max() + 1),
                            "default_rows": int((meta["conflict_group_default"] >= 0).sum()),
                            "dstport": int(meta["conflict_group_dstport"].max() + 1),
                            "dstport_rows": int((meta["conflict_group_dstport"] >= 0).sum())},
        "label_collisions": {"note": "exact identity on corrected, pre-imputation feature values of each feature set",
                             "default": dg.label_collisions(h_default, meta["label_fine"]),
                             "dstport": dg.label_collisions(h_dstport, meta["label_fine"])},
    }
    (out_dir / "dataset_stats.json").write_text(json.dumps(stats, indent=1, default=str), encoding="utf-8")

    cfg_text = yaml.safe_dump(cfg, sort_keys=True)
    md = {
        "contract_version": cfg.get("contract_version"), "data_version": cfg.get("data_version"), "seed": cfg.get("seed"),
        "config": cfg, "config_sha256": _sha256_text(cfg_text), "code_sha256": _code_fingerprint(),
        "raw_manifest_verified": bool(manifest_path), "raw_files": raw_before["files"],
        "file_info": file_info, "expected_count_checks": checks,
        "removed_rows_by_reason": rc.to_dict(),
        "removed_rows_by_file_and_reason": removed_df.assign(f=removed_df.flow_uid.str.split(":").str[0])
            .groupby(["f", "reason"]).size().rename("rows").reset_index().to_dict("records"),
        "timestamp_correction": {
            "rule": f"hour in {cfg['timestamps']['pm_hours']} -> hour + 12 (12-hour clock without AM/PM)",
            "evidence": "docs/dataset_contract.md §3; reports/data_audit/audit_resolution.json",
            "rows_corrected_by_file": {k: v["timestamp_corrected_rows"] for k, v in file_info.items()}},
        "feature_corrections": corr_summary,
        "schemes": scheme_info,
        "versions": {"python": sys.version, "platform": platform.platform(),
                     **{p: im.version(p) for p in ("numpy", "pandas", "pyarrow", "scikit-learn", "pyyaml")}},
        "runtime_seconds": round(time.time() - t0, 1),
    }
    (out_dir / "preprocessing_metadata.json").write_text(json.dumps(md, indent=1, default=str), encoding="utf-8")
    return {"metadata": md, "stats": stats}


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--config", type=Path, default=Path("configs/preprocessing.yaml"))
    a = ap.parse_args(argv)
    res = run(load_config(a.config))
    print(json.dumps({"rows": res["stats"]["rows"], "checks": res["metadata"]["expected_count_checks"],
                      "runtime_s": res["metadata"]["runtime_seconds"]}, indent=1))


if __name__ == "__main__":
    main()
