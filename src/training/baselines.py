"""Milestone 2: Random Forest and XGBoost baselines on the processed CICIDS2017 dataset.

Protocol (configs/baselines.yaml):
  * fit on a deterministic, seeded, class-capped subsample of TRAIN (cap per fine label)
  * sqrt-balanced class weights; hyper-parameters selected on VAL macro-F1 (seed = seeds[0])
  * selected config refit for every seed; evaluated once on the full TEST split
  * every evaluation includes the contract §6.5 views (off-dominant-pair, dominant vs non-dominant) and
    a de-duplicated-test view; primary and day-holdout experiments are written to separate files

Usage:
    python -m src.training.baselines --config configs/baselines.yaml [--only primary_family_default] [--models xgboost]
"""
from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
import pyarrow.parquet as pq
import yaml
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import f1_score

from src.evaluation.metrics import evaluate, summarize_seeds
from src.preprocessing.dataset import load_split
from src.training.common import capped_sample, run_metadata, sqrt_balanced_weights, write_json

META_COLS = ("flow_uid", "label_fine", "label_family", "label_binary", "dominant_pair_directed")


def class_names(processed_dir: Path, scheme: str, target: str) -> list[str]:
    if target == "binary":
        return ["Benign", "Attack"]
    lm = json.loads((processed_dir / "schemes" / scheme / "label_map.json").read_text(encoding="utf-8"))[target]
    return [k for k, _ in sorted(lm.items(), key=lambda kv: kv[1])]


def xgb_device(pref: str) -> str:
    if pref != "auto":
        return pref
    try:
        import xgboost as xgb
        xgb.XGBClassifier(n_estimators=1, device="cuda", tree_method="hist").fit(np.zeros((8, 2)), np.arange(8) % 2)
        return "cuda"
    except Exception:  # noqa: BLE001 - any CUDA failure falls back to CPU
        return "cpu"


def make_model(kind: str, params: dict[str, Any], n_classes: int, class_w: np.ndarray, seed: int, device: str,
               early_stopping: int | None) -> Any:
    if kind == "random_forest":
        cw = {i: float(w) for i, w in enumerate(class_w) if w > 0}
        return RandomForestClassifier(**params, class_weight=cw, n_jobs=-1, random_state=seed)
    import xgboost as xgb
    common = dict(tree_method="hist", device=device, random_state=seed, n_jobs=-1, max_bin=256,
                  early_stopping_rounds=early_stopping)
    if n_classes == 2:
        return xgb.XGBClassifier(**params, objective="binary:logistic", eval_metric="logloss", **common)
    return xgb.XGBClassifier(**params, objective="multi:softprob", num_class=n_classes, eval_metric="mlogloss", **common)


def full_proba(model: Any, X: np.ndarray, n_classes: int) -> np.ndarray:
    """predict_proba with columns for every class (RF omits classes absent from its fitting data)."""
    pr = model.predict_proba(X)
    if pr.ndim == 1:
        pr = np.stack([1 - pr, pr], 1)
    cls = getattr(model, "gs_classes", getattr(model, "classes_", np.arange(pr.shape[1])))
    out = np.zeros((len(X), n_classes), dtype="float32")
    out[:, np.asarray(cls, dtype=int)] = pr
    return out


def fit(kind: str, params: dict[str, Any], Xs: np.ndarray, ys: np.ndarray, class_w: np.ndarray, n_classes: int,
        seed: int, device: str, es: int | None, val: tuple[np.ndarray, np.ndarray] | None) -> tuple[Any, float]:
    t0 = time.time()
    if kind == "xgboost":
        # XGBoost needs contiguous labels 0..n-1: encode the classes present in the fitting sample (e.g. the
        # dominant-pair ablation removes DDoS/PortScan) and remember them for full_proba.
        present = np.unique(ys)
        enc = np.full(n_classes, -1)
        enc[present] = np.arange(len(present))
        m = make_model(kind, params, len(present), class_w, seed, device, es)
        ev = None
        if val is not None:
            keep = np.isin(val[1], present)
            ev = [(val[0][keep], enc[val[1][keep]])]
        m.fit(Xs, enc[ys], sample_weight=class_w[ys], eval_set=ev, verbose=False)
        m.gs_classes = present
    else:
        m = make_model(kind, params, n_classes, class_w, seed, device, None)
        m.fit(Xs, ys)
    return m, time.time() - t0


def run_experiment(exp: dict[str, Any], cfg: dict[str, Any], kinds: list[str]) -> None:
    d = Path(cfg["processed_dir"])
    scheme, target, fs = exp["scheme"], exp["target"], exp["feature_set"]
    seeds = exp.get("seeds", cfg["seeds"])
    row_filter = None
    if exp.get("exclude_dominant_pair"):
        row_filter = ~pq.read_table(d / "metadata.parquet", columns=["dominant_pair_undirected"]).column(0).to_numpy()
    mc = (*META_COLS, f"train_dup_{scheme}")
    print(f"== {exp['name']}: loading", flush=True)
    tr = load_split(d, scheme, "train", fs, "raw", target, mc, row_filter)
    va = load_split(d, scheme, "val", fs, "raw", target, mc, row_filter)
    te = load_split(d, scheme, "test", fs, "raw", target, mc, row_filter)
    classes = class_names(d, scheme, target)
    K = len(classes)
    tr_fine, tr_X, tr_y = tr.meta["label_fine"].to_numpy(), tr.X, tr.y
    n_train_full = len(tr_y)
    del tr
    device = xgb_device(cfg["models"]["xgboost"].get("device", "auto"))
    out_dir = Path(cfg["results_dir"]) / exp["name"]
    pred_dir = Path(cfg["models_dir"]) / exp["name"]
    pred_dir.mkdir(parents=True, exist_ok=True)

    def sample(seed: int) -> tuple[np.ndarray, np.ndarray, dict[str, int]]:
        idx = capped_sample(tr_fine, cfg["train_sample"]["cap_per_fine_label"], seed)
        return tr_X[idx], tr_y[idx], pd.Series(tr_fine[idx]).value_counts().to_dict()

    for kind in kinds:
        mcfg = cfg["models"][kind]
        es = mcfg.get("early_stopping_rounds")
        Xs, ys, counts = sample(seeds[0])
        cw = sqrt_balanced_weights(ys, K)
        tuning = []
        best = None
        for params in mcfg["grid"]:
            m, secs = fit(kind, params, Xs, ys, cw, K, seeds[0], device, es, (va.X, va.y))
            vpred = full_proba(m, va.X, K).argmax(1)
            f1 = float(f1_score(va.y, vpred, labels=np.unique(va.y), average="macro", zero_division=0))
            tuning.append({"params": params, "val_macro_f1": f1, "fit_seconds": round(secs, 1),
                           "best_iteration": getattr(m, "best_iteration", None)})
            print(f"   {kind} {params} val macro-F1={f1:.4f} ({secs:.0f}s)", flush=True)
            if best is None or f1 > best[0]:
                best = (f1, params, m, secs)
        _, params, best_model, best_secs = best
        seed_results, fits = [], []
        for s in seeds:
            if s == seeds[0]:
                m, secs = best_model, best_secs
                samp_counts = counts
            else:
                Xs_s, ys_s, samp_counts = sample(s)
                m, secs = fit(kind, params, Xs_s, ys_s, sqrt_balanced_weights(ys_s, K), K, s, device, es, (va.X, va.y))
            t0 = time.time()
            proba = full_proba(m, te.X, K)
            lat = (time.time() - t0) / max(len(te.y), 1) * 1000 * 1000
            pred = proba.argmax(1)
            ev = evaluate(te.y, pred, classes, te.meta["dominant_pair_directed"].to_numpy(), proba,
                          dedup_mask=~te.meta[f"train_dup_{scheme}"].to_numpy())
            ev.update({"seed": s, "fit_seconds": round(secs, 1), "predict_ms_per_1k_flows": round(lat, 3),
                       "train_sample_counts": samp_counts})
            seed_results.append(ev)
            fits.append(m)
            print(f"   {kind} seed {s}: test macro-F1={ev['overall']['macro_f1']:.4f} "
                  f"FPR={ev['overall'].get('fpr')} off-pair macro-F1={ev['view_off_dominant_pair']['overall']['macro_f1']:.4f}",
                  flush=True)
            if s == seeds[0]:
                pd.DataFrame({"flow_uid": te.flow_uid, "y_true": te.y, "y_pred": pred,
                              "p_max": proba.max(1)}).to_parquet(pred_dir / f"{kind}_test_predictions_seed{s}.parquet",
                                                                  index=False)
        mpath = pred_dir / (f"{kind}_seed{seeds[0]}.json" if kind == "xgboost" else f"{kind}_seed{seeds[0]}.joblib")
        if kind == "xgboost":
            fits[0].save_model(mpath)
        else:
            joblib.dump(fits[0], mpath, compress=3)
        write_json(out_dir / f"{kind}.json", {
            "experiment": exp, "model": kind, "classes": classes, "selected_params": params, "tuning": tuning,
            "xgboost_device": device if kind == "xgboost" else None,
            "n_train_full": n_train_full, "n_val": int(len(va.y)), "n_test": int(len(te.y)),
            "model_file": str(mpath), "model_bytes": mpath.stat().st_size,
            "seeds": seed_results, "summary": summarize_seeds(seed_results),
            "run": run_metadata(d, {"baselines": cfg, "experiment": exp})})
        del fits, best_model


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--config", type=Path, default=Path("configs/baselines.yaml"))
    ap.add_argument("--only", nargs="*", default=None)
    ap.add_argument("--models", nargs="*", default=["xgboost", "random_forest"])
    a = ap.parse_args(argv)
    cfg = yaml.safe_load(a.config.read_text(encoding="utf-8"))
    for exp in cfg["experiments"]:
        if a.only and exp["name"] not in a.only:
            continue
        run_experiment(exp, cfg, a.models)


if __name__ == "__main__":
    main()
