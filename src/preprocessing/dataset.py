"""Load a processed split as model-ready arrays, with row-level traceability via flow_uid.

Example:
    from src.preprocessing.dataset import load_split
    d = load_split("data/processed/v1", scheme="primary", split="train", feature_set="default",
                   representation="raw", target="family")
    d.X, d.y, d.flow_uid, d.meta
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

import numpy as np
import pandas as pd

from src.preprocessing.features import FeatureTransform

TARGETS = {"family": "label_family", "fine": "label_fine", "binary": "label_binary"}


@dataclass
class SplitData:
    X: np.ndarray
    y: np.ndarray
    flow_uid: np.ndarray
    columns: list[str]
    meta: pd.DataFrame


def load_split(processed_dir: str | Path, scheme: str, split: str, feature_set: str = "default",
               representation: str = "scaled", target: str = "family") -> SplitData:
    d = Path(processed_dir)
    sdir = d / "schemes" / scheme
    schema = json.loads((sdir / f"feature_schema_{feature_set}.json").read_text(encoding="utf-8"))
    label_map = json.loads((sdir / "label_map.json").read_text(encoding="utf-8"))
    tf = FeatureTransform.from_json(sdir / "transforms.json")
    meta = pd.read_parquet(d / "metadata.parquet")
    mask = (meta[f"split_{scheme}"] == split).to_numpy()
    flows = pd.read_parquet(d / "flows.parquet", columns=["flow_uid", *schema["columns"]])
    if not (flows["flow_uid"].to_numpy() == meta["flow_uid"].to_numpy()).all():
        raise AssertionError("flows.parquet and metadata.parquet are not row-aligned")
    flows, meta = flows.loc[mask].reset_index(drop=True), meta.loc[mask].reset_index(drop=True)
    X = tf.transform(flows, schema["columns"], representation)
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
