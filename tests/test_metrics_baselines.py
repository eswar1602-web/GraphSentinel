"""Tests for shared metrics, the streamed loader and the RF/XGBoost baseline trainer (synthetic data)."""
from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from src.evaluation.metrics import evaluate, summarize_seeds
from src.preprocessing.dataset import load_split
from src.preprocessing.features import FeatureTransform
from src.preprocessing.pipeline import run
from src.training.common import capped_sample, sqrt_balanced_weights
from tests.synthetic_cicids import build_raw_dir, synthetic_config


@pytest.fixture(scope="module")
def synth(tmp_path_factory: pytest.TempPathFactory) -> Path:
    root = tmp_path_factory.mktemp("mb")
    cfg = synthetic_config(root, build_raw_dir(root))
    run(cfg)
    return Path(cfg["paths"]["out_dir"])


def test_streamed_loader_equals_full_transform(synth: Path) -> None:
    sd = load_split(synth, "primary", "test", "default", "scaled", "family", row_filter=None)
    meta = pd.read_parquet(synth / "metadata.parquet")
    flows = pd.read_parquet(synth / "flows.parquet")
    tf = FeatureTransform.from_json(synth / "schemes" / "primary" / "transforms.json")
    m = (meta["split_primary"] == "test").to_numpy()
    ref = tf.transform(flows.loc[m], sd.columns, "scaled")
    assert np.array_equal(sd.X, ref)
    assert (sd.flow_uid == meta.loc[m, "flow_uid"].to_numpy()).all()


def test_row_filter_restricts_rows(synth: Path) -> None:
    meta = pd.read_parquet(synth / "metadata.parquet", columns=["dominant_pair_undirected"])
    keep = ~meta["dominant_pair_undirected"].to_numpy()
    sd = load_split(synth, "primary", "train", target="binary", row_filter=keep)
    assert not sd.meta["dominant_pair_directed"].any() and (sd.y == 0).all()


def test_evaluate_views_and_fpr() -> None:
    classes = ["Benign", "DoS", "PortScan"]
    y = np.array([0, 0, 0, 0, 1, 1, 2, 2])
    p = np.array([0, 1, 0, 0, 1, 0, 2, 2])
    dom = np.array([False, False, False, False, True, False, True, True])
    ev = evaluate(y, p, classes, dom)
    assert ev["overall"]["fpr"] == pytest.approx(0.25)
    assert ev["per_class"]["DoS"]["recall"] == pytest.approx(0.5)
    assert ev["confusion_matrix"][0] == [3, 1, 0]
    off = ev["view_off_dominant_pair"]
    assert off["per_attack_recall"]["DoS"] == {"recall": 0.0, "support": 1, "low_support": True}
    assert off["attack_classes_without_off_pair_support"] == ["PortScan"]
    assert ev["view_dominant_vs_non_dominant"]["dominant_pair"]["overall"]["n"] == 3
    s = summarize_seeds([ev, ev])
    assert s["macro_f1"]["std"] == 0.0 and s["macro_f1"]["n"] == 2
    empty = evaluate(y, p, classes, np.zeros(8, dtype=bool))["view_dominant_vs_non_dominant"]["dominant_pair"]
    assert empty["overall"]["n"] == 0 and empty["overall"]["macro_f1"] is None


def test_capped_sample_and_weights() -> None:
    lab = np.array(["a"] * 100 + ["b"] * 5)
    idx = capped_sample(lab, 10, 0)
    assert (lab[idx] == "a").sum() == 10 and (lab[idx] == "b").sum() == 5
    assert np.array_equal(idx, capped_sample(lab, 10, 0))
    w = sqrt_balanced_weights(np.array([0] * 100 + [1] * 25), 3)
    assert w.tolist() == [1.0, 2.0, 0.0]


def test_baselines_end_to_end(synth: Path, tmp_path: Path) -> None:
    pytest.importorskip("xgboost")
    from src.training.baselines import run_experiment

    cfg = {"processed_dir": str(synth), "results_dir": str(tmp_path / "res"), "models_dir": str(tmp_path / "models"),
           "seeds": [0, 1], "train_sample": {"cap_per_fine_label": 1000},
           "models": {"random_forest": {"grid": [{"n_estimators": 10, "max_depth": 5}]},
                      "xgboost": {"grid": [{"n_estimators": 20, "max_depth": 3}], "early_stopping_rounds": 5,
                                  "device": "cpu"}}}
    exp = {"name": "t", "scheme": "primary", "target": "family", "feature_set": "default"}
    run_experiment(exp, cfg, ["xgboost", "random_forest"])
    for kind in ("xgboost", "random_forest"):
        r = json.loads((tmp_path / "res" / "t" / f"{kind}.json").read_text())
        assert len(r["seeds"]) == 2 and "view_off_dominant_pair" in r["seeds"][0]
        # reported metrics must be reproducible from the saved predictions (no fabricated numbers)
        pr = pd.read_parquet(tmp_path / "models" / "t" / f"{kind}_test_predictions_seed0.parquet")
        ev = evaluate(pr["y_true"].to_numpy(), pr["y_pred"].to_numpy(), r["classes"])
        assert ev["overall"]["macro_f1"] == pytest.approx(r["seeds"][0]["overall"]["macro_f1"])
        assert Path(r["model_file"]).exists()
