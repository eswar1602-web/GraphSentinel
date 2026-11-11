"""Helpers shared by all trainers: run metadata, sampling, class weights, JSON output."""
from __future__ import annotations

import hashlib
import json
import platform
import sys
import time
from importlib import metadata as im
from pathlib import Path
from typing import Any

import numpy as np

PACKAGES = ("numpy", "pandas", "scikit-learn", "xgboost", "torch", "torch_geometric")


def run_metadata(processed_dir: str | Path, config: dict[str, Any]) -> dict[str, Any]:
    pm = json.loads((Path(processed_dir) / "preprocessing_metadata.json").read_text(encoding="utf-8"))
    code = {str(p.relative_to(Path("src"))): hashlib.sha256(p.read_bytes()).hexdigest()[:16]
            for p in sorted(Path("src").rglob("*.py"))}
    versions = {}
    for p in PACKAGES:
        try:
            versions[p] = im.version(p)
        except im.PackageNotFoundError:
            versions[p] = None
    return {"created_unix": int(time.time()), "data_version": pm.get("data_version"),
            "contract_version": pm.get("contract_version"), "preprocessing_config_sha256": pm.get("config_sha256"),
            "config": config, "config_sha256": hashlib.sha256(json.dumps(config, sort_keys=True).encode()).hexdigest(),
            "code_sha256_16": code, "python": sys.version.split()[0], "platform": platform.platform(),
            "versions": versions}


def capped_sample(labels: np.ndarray, cap: int, seed: int) -> np.ndarray:
    """Deterministic class-capped subsample: indices (sorted) keeping at most ``cap`` rows per label value."""
    rng = np.random.default_rng(seed)
    keep = []
    for v in np.unique(labels):
        idx = np.flatnonzero(labels == v)
        if len(idx) > cap:
            idx = rng.choice(idx, cap, replace=False)
        keep.append(idx)
    return np.sort(np.concatenate(keep))


def sqrt_balanced_weights(y: np.ndarray, n_classes: int) -> np.ndarray:
    """Per-class weights w_c = sqrt(n_max / n_c) (0 for absent classes)."""
    counts = np.bincount(y, minlength=n_classes).astype(float)
    w = np.zeros(n_classes)
    nz = counts > 0
    w[nz] = np.sqrt(counts[nz].max() / counts[nz])
    return w


def write_json(path: str | Path, obj: Any) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(obj, indent=1, default=_default), encoding="utf-8")


def _default(o: Any) -> Any:
    if isinstance(o, (np.integer,)):
        return int(o)
    if isinstance(o, (np.floating,)):
        return float(o)
    if isinstance(o, np.ndarray):
        return o.tolist()
    return str(o)
