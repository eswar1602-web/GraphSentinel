"""Shared evaluation for every model (contract v1.1 §6.5, §7).

``evaluate`` returns one JSON-serializable dict with:
  overall               accuracy, macro precision/recall/F1, weighted F1, FPR, macro PR-AUC
  per_class             precision / recall / F1 / support / low_support
  confusion_matrix      rows = true, cols = predicted, in class order
  view_off_dominant_pair       per-attack recall + macro-F1 on flows NOT on the dominant NAT pair
  view_dominant_vs_non_dominant  separate overall metrics on and off the dominant pair
  dedup_test            metrics on rows whose feature vector does not occur in train (if flag provided)
FPR = benign flows predicted as any attack / benign flows (the operational false-alarm rate).
"""
from __future__ import annotations

from typing import Any

import numpy as np
from sklearn.metrics import (accuracy_score, average_precision_score, confusion_matrix,
                             precision_recall_fscore_support)

LOW_SUPPORT = 30


def _overall(y: np.ndarray, p: np.ndarray, classes: list[str], benign: int | None,
             proba: np.ndarray | None = None) -> dict[str, Any]:
    if len(y) == 0:   # e.g. the dominant-pair view after the dominant-pair ablation: nothing to evaluate
        return {"n": 0, "accuracy": None, "macro_precision": None, "macro_recall": None, "macro_f1": None,
                "weighted_f1": None, "classes_present": [], "fpr": None, "attack_detection_rate": None,
                "note": "no flows in this view"}
    present = np.unique(y)
    pr, rc, f1, _ = precision_recall_fscore_support(y, p, labels=present, average="macro", zero_division=0)
    wf1 = precision_recall_fscore_support(y, p, labels=present, average="weighted", zero_division=0)[2]
    out: dict[str, Any] = {"n": int(len(y)), "accuracy": float(accuracy_score(y, p)) if len(y) else None,
                           "macro_precision": float(pr), "macro_recall": float(rc), "macro_f1": float(f1),
                           "weighted_f1": float(wf1), "classes_present": [classes[i] for i in present]}
    if benign is not None:
        b = y == benign
        out["fpr"] = float((p[b] != benign).mean()) if b.any() else None
        a = ~b
        out["attack_detection_rate"] = float((p[a] != benign).mean()) if a.any() else None
    if proba is not None and len(y):
        aps = []
        for c in present:
            yc = (y == c).astype(int)
            if 0 < yc.sum() < len(yc):
                aps.append(average_precision_score(yc, proba[:, c]))
        out["macro_pr_auc"] = float(np.mean(aps)) if aps else None
    return out


def _per_class(y: np.ndarray, p: np.ndarray, classes: list[str]) -> dict[str, Any]:
    labels = np.arange(len(classes))
    if len(y) == 0:
        return {c: {"precision": None, "recall": None, "f1": None, "support": 0, "low_support": True} for c in classes}
    pr, rc, f1, sup = precision_recall_fscore_support(y, p, labels=labels, zero_division=0)
    return {c: {"precision": float(pr[i]), "recall": float(rc[i]), "f1": float(f1[i]), "support": int(sup[i]),
                "low_support": bool(sup[i] < LOW_SUPPORT)} for i, c in enumerate(classes)}


def evaluate(y: np.ndarray, pred: np.ndarray, classes: list[str], dominant_pair: np.ndarray | None = None,
             proba: np.ndarray | None = None, benign_label: str = "Benign",
             dedup_mask: np.ndarray | None = None) -> dict[str, Any]:
    """Full evaluation incl. the mandatory NAT-shortcut views. ``classes`` maps integer label -> name."""
    benign = classes.index(benign_label) if benign_label in classes else None
    res: dict[str, Any] = {"classes": classes,
                           "overall": _overall(y, pred, classes, benign, proba),
                           "per_class": _per_class(y, pred, classes),
                           "confusion_matrix": confusion_matrix(y, pred, labels=np.arange(len(classes))).tolist()}
    if dominant_pair is not None:
        off = ~dominant_pair
        pc_off = _per_class(y[off], pred[off], classes)
        res["view_off_dominant_pair"] = {
            "overall": _overall(y[off], pred[off], classes, benign, proba[off] if proba is not None else None),
            "per_attack_recall": {c: {"recall": v["recall"], "support": v["support"], "low_support": v["low_support"]}
                                  for c, v in pc_off.items() if c != benign_label and v["support"] > 0},
            "attack_classes_without_off_pair_support": [c for c, v in pc_off.items()
                                                        if c != benign_label and v["support"] == 0]}
        on = dominant_pair
        res["view_dominant_vs_non_dominant"] = {
            "dominant_pair": {"overall": _overall(y[on], pred[on], classes, benign), "per_class": _per_class(y[on], pred[on], classes)},
            "non_dominant_pair": {"overall": res["view_off_dominant_pair"]["overall"], "per_class": pc_off}}
    if dedup_mask is not None:
        res["dedup_test"] = {"overall": _overall(y[dedup_mask], pred[dedup_mask], classes, benign),
                             "per_class": _per_class(y[dedup_mask], pred[dedup_mask], classes)}
    return res


def summarize_seeds(results: list[dict[str, Any]]) -> dict[str, Any]:
    """mean ± std over seeds for the headline numbers."""
    def stat(get):
        vals = [get(r) for r in results]
        vals = [v for v in vals if v is not None]
        return {"mean": float(np.mean(vals)), "std": float(np.std(vals)), "n": len(vals)} if vals else None
    out = {k: stat(lambda r, k=k: r["overall"].get(k)) for k in ("macro_f1", "macro_recall", "macro_precision",
                                                                 "accuracy", "fpr", "macro_pr_auc")}
    classes = results[0]["classes"]
    out["per_class_recall"] = {c: stat(lambda r, c=c: r["per_class"][c]["recall"]) for c in classes}
    out["per_class_f1"] = {c: stat(lambda r, c=c: r["per_class"][c]["f1"]) for c in classes}
    if "view_off_dominant_pair" in results[0]:
        out["off_pair_macro_f1"] = stat(lambda r: r["view_off_dominant_pair"]["overall"]["macro_f1"])
        out["off_pair_per_attack_recall"] = {
            c: stat(lambda r, c=c: r["view_off_dominant_pair"]["per_attack_recall"].get(c, {}).get("recall"))
            for c in results[0]["view_off_dominant_pair"]["per_attack_recall"]}
    return out
