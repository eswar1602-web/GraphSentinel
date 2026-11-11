"""Raw-file loading, row removals and feature-value corrections (contract §1, §4).

Every removal and every corrected value is logged against ``flow_uid`` so each transformation
is auditable. Raw CSVs are only ever opened for reading.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

from src.preprocessing.audit import detect_encoding
from src.preprocessing.labels import map_labels
from src.preprocessing.timestamps import parse_and_correct

IDENTITY_COLUMNS = ("Flow ID", "Source IP", "Source Port", "Destination IP", "Timestamp")
LABEL_COLUMN = "Label"


def file_stem(name: str) -> str:
    return name.replace(".pcap_ISCX.csv", "").replace(".csv", "")


@dataclass
class FileResult:
    meta: pd.DataFrame
    num: pd.DataFrame
    removed: pd.DataFrame
    info: dict[str, Any] = field(default_factory=dict)


def load_raw(path: Path) -> tuple[pd.DataFrame, str]:
    """Read one raw CSV (read-only). Columns stripped; index = 0-based raw data-row number."""
    enc, newlines = detect_encoding(path)
    df = pd.read_csv(path, encoding=enc, low_memory=False)
    df.columns = [c.strip() for c in df.columns]
    if len(df) != newlines - 1:
        raise AssertionError(f"{path.name}: {len(df)} parsed rows but {newlines - 1} data lines; row numbers unreliable")
    return df, enc


def _removed(stem: str, idx: pd.Index, reason: str) -> pd.DataFrame:
    return pd.DataFrame({"flow_uid": [f"{stem}:{i}" for i in idx], "reason": reason})


def process_file(path: Path, expected_date: str, cfg: dict[str, Any]) -> FileResult:
    """Load one file, remove invalid rows, build metadata (identities, timestamps, labels) and numeric features."""
    stem = file_stem(path.name)
    df, enc = load_raw(path)
    raw_cols = list(df.columns)
    removed = []

    empty = df[raw_cols].isna().all(axis=1)
    removed.append(_removed(stem, df.index[empty], "comma_only_row"))
    df = df.loc[~empty]

    dup = df.duplicated(subset=raw_cols, keep="first")
    removed.append(_removed(stem, df.index[dup], "exact_duplicate"))
    df = df.loc[~dup]

    feat_cols = [c for c in raw_cols if c not in IDENTITY_COLUMNS and c != LABEL_COLUMN]
    num = pd.DataFrame({c: pd.to_numeric(df[c], errors="raise").astype("float64") for c in feat_cols}, index=df.index)

    neg = num["Flow Duration"] < 0
    removed.append(_removed(stem, df.index[neg], "negative_flow_duration"))
    df, num = df.loc[~neg], num.loc[~neg]

    dh = cfg["features"]["duplicate_header_drop"]
    a, b = num[dh["must_equal"]], num[dh["drop"]]
    if not ((a == b) | (a.isna() & b.isna())).all():
        raise AssertionError(f"{path.name}: '{dh['drop']}' differs from '{dh['must_equal']}'; contract says drop only if identical")
    num = num.drop(columns=[dh["drop"]])

    ts, corrected = parse_and_correct(df["Timestamp"], tuple(cfg["timestamps"]["pm_hours"]),
                                      tuple(cfg["timestamps"]["allowed_hours"]))
    ts.index = corrected.index = df.index
    if not (ts.dt.normalize() == pd.Timestamp(expected_date)).all():
        raise AssertionError(f"{path.name}: timestamps not all on expected date {expected_date}")

    labels = map_labels(df[LABEL_COLUMN].astype(str))
    meta = pd.DataFrame({
        "flow_uid": [f"{stem}:{i}" for i in df.index],
        "source_file": stem,
        "raw_row": df.index.to_numpy(dtype="int64"),
        "day": expected_date,
        "flow_id": df["Flow ID"].astype(str).to_numpy(),
        "src_ip": df["Source IP"].astype(str).str.strip().to_numpy(),
        "src_port": df["Source Port"].astype("int64").to_numpy(),
        "dst_ip": df["Destination IP"].astype(str).str.strip().to_numpy(),
        "dst_port": num["Destination Port"].astype("int64").to_numpy(),
        "protocol": num["Protocol"].astype("int64").to_numpy(),
        "timestamp_raw": df["Timestamp"].astype(str).to_numpy(),
        "timestamp": ts.to_numpy(),
        "timestamp_corrected": corrected.to_numpy(),
    }, index=df.index)
    meta = meta.join(labels)
    info = {"encoding": enc, "rows_raw": int(len(empty)), "rows_kept": int(len(meta)),
            "timestamp_corrected_rows": int(corrected.sum()),
            "timestamp_resolution": "second" if df["Timestamp"].astype(str).str.count(":").max() == 2 else "minute"}
    return FileResult(meta=meta.reset_index(drop=True), num=num.reset_index(drop=True),
                      removed=pd.concat(removed, ignore_index=True), info=info)


def apply_feature_corrections(num: pd.DataFrame, flow_uid: pd.Series, fcfg: dict[str, Any]
                              ) -> tuple[pd.DataFrame, pd.DataFrame, dict[str, Any]]:
    """Apply the approved value corrections. Returns (corrected copy, correction log, summary).

    Adds indicator columns: ``flow_duration_zero``, ``iat_negative_clipped``, ``header_len_invalid``.
    The log keeps the original raw value of every changed cell.
    """
    num = num.copy()
    logs = []

    def log(mask: pd.Series, col: str, rule: str, new: float) -> None:
        if mask.any():
            logs.append(pd.DataFrame({"flow_uid": flow_uid[mask].to_numpy(), "column": col,
                                      "raw_value": num.loc[mask, col].astype(str).to_numpy(),
                                      "new_value": new, "rule": rule}))

    # 1. non-finite rates -> missing (they occur exactly when Flow Duration == 0)
    nonfinite_any = pd.Series(False, index=num.index)
    for c in fcfg["nonfinite_rate_columns"]:
        m = ~np.isfinite(num[c])
        nonfinite_any |= m
        log(m, c, "nonfinite_rate_to_missing", np.nan)
        num.loc[m, c] = np.nan
    zero_dur = num["Flow Duration"] == 0
    if fcfg.get("assert_nonfinite_equals_zero_duration") and not nonfinite_any.equals(zero_dur):
        raise AssertionError(f"non-finite rates ({int(nonfinite_any.sum())}) != zero-duration rows ({int(zero_dur.sum())})")

    # 2. negative IAT jitter -> 0
    clipped = pd.Series(False, index=num.index)
    for c in fcfg["clip_negative_to_zero"]:
        m = num[c] < 0
        clipped |= m
        log(m, c, "clip_negative_iat_to_zero", 0.0)
        num.loc[m, c] = 0.0

    # 3. impossible negative header lengths -> missing (overflow vs small invalid negative)
    invalid = pd.Series(False, index=num.index)
    thr = fcfg["overflow_threshold"]
    for c in fcfg["invalid_negative_to_missing"]:
        m = num[c] < 0
        invalid |= m
        log(m & (num[c] <= thr), c, "overflow_to_missing", np.nan)
        log(m & (num[c] > thr), c, "invalid_negative_to_missing", np.nan)
        num.loc[m, c] = np.nan

    num["flow_duration_zero"] = zero_dur.astype("float64")
    num["iat_negative_clipped"] = clipped.astype("float64")
    num["header_len_invalid"] = invalid.astype("float64")

    # Invariants: no infinities; only approved sentinels may remain negative.
    if np.isinf(num.to_numpy(dtype="float64")).any():
        raise AssertionError("infinite values remain after corrections")
    sentinels = fcfg["sentinel_columns"]
    for c in num.columns:
        neg = num[c] < 0
        if neg.any():
            if c not in sentinels or not (num.loc[neg, c] == sentinels[c]).all():
                raise AssertionError(f"unexpected negative values remain in '{c}': {num.loc[neg, c].unique()[:5]}")
    log_df = (pd.concat(logs, ignore_index=True) if logs
              else pd.DataFrame(columns=["flow_uid", "column", "raw_value", "new_value", "rule"]))
    summary = {"by_rule_and_column": log_df.groupby(["rule", "column"]).size().rename("cells").reset_index().to_dict("records"),
               "rows_flow_duration_zero": int(zero_dur.sum()), "rows_iat_negative_clipped": int(clipped.sum()),
               "rows_header_len_invalid": int(invalid.sum()),
               "sentinel_counts": {c: int((num[c] == v).sum()) for c, v in sentinels.items()}}
    return num, log_df, summary
