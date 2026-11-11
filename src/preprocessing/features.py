"""Train-only fitted feature transforms and the feature schema (contract §4).

Fitted on the train split only:
  1. constant-column filter (nunique of non-missing values <= 1 in train)
  2. median imputation of missing values (train medians)
  3. 'scaled' representation: signed log1p, then standardization with train mean/std

Representations:
  raw     imputed values (float32): for tree models
  scaled  imputed -> sign(x)*log1p(|x|) -> (x - mean)/std (float32): for neural models

Parameters are stored as JSON (no pickles), so transforms are inspectable and loading is safe.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

INDICATOR_COLUMNS = {
    "flow_duration_zero": "1 if Flow Duration == 0 (Flow Bytes/s and Flow Packets/s were non-finite and are imputed)",
    "iat_negative_clipped": "1 if a negative Flow/Fwd IAT Min was clipped to 0",
    "header_len_invalid": "1 if a negative Fwd/Bwd Header Length or min_seg_size_forward was set to missing",
}


def signed_log1p(x: np.ndarray) -> np.ndarray:
    return np.sign(x) * np.log1p(np.abs(x))


@dataclass
class FeatureTransform:
    columns: list[str]                       # fitted (non-constant) candidate columns, in order
    dropped_constant: dict[str, float | None]
    medians: dict[str, float]
    log_mean: dict[str, float]
    log_std: dict[str, float]
    n_train_rows: int

    @classmethod
    def fit(cls, X_train: pd.DataFrame) -> "FeatureTransform":
        if len(X_train) == 0:
            raise ValueError("cannot fit on an empty train split")
        dropped, keep = {}, []
        for c in X_train.columns:
            vals = X_train[c].dropna()
            if vals.nunique() <= 1:
                dropped[c] = None if vals.empty else float(vals.iloc[0])
            else:
                keep.append(c)
        med = X_train[keep].median(skipna=True)
        imputed = X_train[keep].fillna(med).to_numpy(dtype="float64")
        lg = signed_log1p(imputed)
        mean, std = lg.mean(axis=0), lg.std(axis=0)
        std = np.where(std > 0, std, 1.0)
        return cls(columns=keep, dropped_constant=dropped, medians={c: float(med[c]) for c in keep},
                   log_mean=dict(zip(keep, map(float, mean))), log_std=dict(zip(keep, map(float, std))),
                   n_train_rows=int(len(X_train)))

    def transform(self, X: pd.DataFrame, columns: list[str], representation: str = "scaled") -> np.ndarray:
        unknown = [c for c in columns if c not in self.medians]
        if unknown:
            raise KeyError(f"columns not fitted: {unknown}")
        A = X[columns].to_numpy(dtype="float64", copy=True)
        med = np.array([self.medians[c] for c in columns])
        miss = np.isnan(A)
        A[miss] = np.take(med, np.nonzero(miss)[1])
        if representation == "scaled":
            A = (signed_log1p(A) - np.array([self.log_mean[c] for c in columns])) / np.array([self.log_std[c] for c in columns])
        elif representation != "raw":
            raise ValueError("representation must be 'raw' or 'scaled'")
        out = A.astype("float32")
        if not np.isfinite(out).all():
            raise AssertionError("non-finite values after transform")
        return out

    def to_json(self, path: Path) -> None:
        Path(path).write_text(json.dumps(asdict(self), indent=1), encoding="utf-8")

    @classmethod
    def from_json(cls, path: Path) -> "FeatureTransform":
        return cls(**json.loads(Path(path).read_text(encoding="utf-8")))


def build_schema(tf: FeatureTransform, feature_set: str, include_destination_port: bool,
                 excluded: dict[str, str]) -> dict[str, Any]:
    """Ordered feature list + per-feature provenance/parameters + every excluded column with its reason."""
    cols = [c for c in tf.columns if include_destination_port or c != "Destination Port"]
    feats = [{"name": c, "dtype": "float32",
              "source": "indicator: " + INDICATOR_COLUMNS[c] if c in INDICATOR_COLUMNS else f"raw column '{c}'",
              "impute_median": tf.medians[c], "log_mean": tf.log_mean[c], "log_std": tf.log_std[c]} for c in cols]
    dropped = dict(excluded)
    dropped.update({c: f"constant in train (value {v})" for c, v in tf.dropped_constant.items()})
    if not include_destination_port and "Destination Port" in tf.columns:
        dropped["Destination Port"] = "excluded from default feature set (shortcut risk); see 'dstport' ablation"
    return {"feature_set": feature_set, "n_features": len(cols), "columns": cols, "features": feats,
            "excluded_columns": dropped,
            "representations": {"raw": "train-median imputed", "scaled": "imputed -> signed log1p -> train standardization"}}
