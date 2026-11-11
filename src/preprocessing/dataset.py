"""Load a processed split as model-ready arrays, with row-level traceability via flow_uid.

Example:
    from src.preprocessing.dataset import load_split
    d = load_split("data/processed/v1", scheme="primary", split="train", feature_set="default",
                   representation="raw", target="family")
    d.X, d.y, d.flow_uid, d.meta

Memory: flows.parquet is streamed in record batches. Each batch is transformed in float64, exactly as
FeatureTransform.transform does, and only the requested split's rows are kept, as float32. Only the needed
metadata columns are read. Peak memory stays near the size of the returned split.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

import numpy as np
import pandas as pd
import pyarrow.parquet as pq

from src.preprocessing.features import FeatureTransform

TARGETS = {"family": "label_family", "fine": "label_fine", "binary": "label_binary"}
DEFAULT_META_COLUMNS = ("flow_uid", "source_file", "day", "src_ip", "dst_ip", "timestamp", "label_raw", "label_fine",
                        "label_family", "label_binary", "dominant_pair_directed", "dominant_pair_undirected",
                        "outside_published_window", "conflict_group_default", "conflict_group_dstport")


@dataclass
class SplitData:
    X: np.ndarray
    y: np.ndarray
    flow_uid: np.ndarray
    columns: list[str]
    meta: pd.DataFrame


def split_mask(processed_dir: str | Path, scheme: str, split: str | list[str]) -> np.ndarray:
    col = pq.read_table(Path(processed_dir) / "metadata.parquet", columns=[f"split_{scheme}"]).column(0).to_numpy()
    wanted = [split] if isinstance(split, str) else list(split)
    return np.isin(col.astype(object), wanted)


def read_transformed(processed_dir: str | Path, tf: FeatureTransform, columns: list[str], mask: np.ndarray,
                     representation: str, batch_rows: int = 262_144) -> np.ndarray:
    """Stream flows.parquet, transform each batch in float64 exactly as FeatureTransform.transform, keep float32."""
    pf = pq.ParquetFile(Path(processed_dir) / "flows.parquet")
    out = np.empty((int(mask.sum()), len(columns)), dtype="float32")
    start = pos = 0
    for batch in pf.iter_batches(batch_size=batch_rows, columns=list(columns)):
        n = batch.num_rows
        m = mask[start:start + n]
        start += n
        k = int(m.sum())
        if k:
            out[pos:pos + k] = tf.transform(batch.to_pandas().loc[m], columns, representation)
            pos += k
    if start != len(mask):
        raise AssertionError("mask length does not match flows.parquet")
    return out


def load_split(processed_dir: str | Path, scheme: str, split: str, feature_set: str = "default",
               representation: str = "scaled", target: str = "family",
               meta_columns: tuple[str, ...] = DEFAULT_META_COLUMNS, row_filter: np.ndarray | None = None) -> SplitData:
    """Model-ready split. ``row_filter`` (bool over all rows) further restricts rows, e.g. for the dominant-pair ablation."""
    d = Path(processed_dir)
    sdir = d / "schemes" / scheme
    schema = json.loads((sdir / f"feature_schema_{feature_set}.json").read_text(encoding="utf-8"))
    label_map = json.loads((sdir / "label_map.json").read_text(encoding="utf-8"))
    tf = FeatureTransform.from_json(sdir / "transforms.json")
    mask = split_mask(d, scheme, split)
    if row_filter is not None:
        mask &= row_filter
    cols = list(dict.fromkeys(["flow_uid", *meta_columns]))
    meta = pq.read_table(d / "metadata.parquet", columns=cols).to_pandas()
    meta = meta.loc[mask].reset_index(drop=True)
    uid = pq.read_table(d / "flows.parquet", columns=["flow_uid"]).column(0).to_numpy()[mask]
    if not (uid == meta["flow_uid"].to_numpy()).all():
        raise AssertionError("flows.parquet and metadata.parquet are not row-aligned")
    X = read_transformed(d, tf, schema["columns"], mask, representation)
    if target == "binary":
        y = meta["label_binary"].to_numpy(dtype="int64")
    else:
        lm = label_map[target]
        lab = meta[TARGETS[target]]
        missing = sorted(set(lab) - set(lm))
        if missing:
            raise KeyError(f"labels absent from train label map ({scheme}/{split}): {missing}; "
                           f"use target='binary' or handle unseen classes explicitly")
        y = lab.map(lm).to_numpy(dtype="int64")
    return SplitData(X=X, y=y, flow_uid=meta["flow_uid"].to_numpy(), columns=schema["columns"], meta=meta)
