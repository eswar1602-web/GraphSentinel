"""Read real experiment result files (experiments/results/**) and build API views. Nothing here invents numbers:
every value is taken from a result JSON written by a training/evaluation run."""
from __future__ import annotations

import hashlib
import json
from functools import lru_cache
from pathlib import Path
from typing import Any

RESULTS = Path("experiments/results")


def _load(path: Path) -> dict[str, Any]:
    return _load_cached(str(path), path.stat().st_mtime)


@lru_cache(maxsize=256)
def _load_cached(path: str, mtime: float) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def result_files(root: Path | None = None) -> list[Path]:
    root = root or RESULTS
    return sorted(p for p in root.glob("**/*.json") if p.parent.name != "aggregation")


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def describe(path: Path, root: Path | None = None) -> dict[str, Any]:
    """Index entry for one result file."""
    root = root or RESULTS
    r = _load(path)
    rel = path.relative_to(root).as_posix()
    family = rel.split("/")[0]
    exp = r.get("experiment", {})
    if family == "baselines":
        model, s = r["model"], r["summary"]
        headline = s
    else:
        model = ("graphsage_" + r["variant"]) if not r.get("aggregation_aware") else f"aggaware_{r['aggregation_aware']['name']}"
        headline = r["summary"]["native_modes"]["cumulative"]
    return {"id": rel.removesuffix(".json"), "family": family, "experiment": exp.get("name"), "model": model,
            "scheme": exp.get("scheme"), "target": exp.get("target"), "feature_set": exp.get("feature_set"),
            "identity_free": r.get("identity_free"), "aggregation_aware": r.get("aggregation_aware"),
            "file": rel, "n_seeds": len(r.get("seeds", [])),
            "macro_f1": (headline.get("macro_f1") or {}).get("mean"), "macro_f1_std": (headline.get("macro_f1") or {}).get("std"),
            "fpr": (headline.get("fpr") or {}).get("mean"),
            "off_pair_macro_f1": (headline.get("off_pair_macro_f1") or {}).get("mean")}


def _model_entries(experiment: str, root: Path | None = None) -> list[tuple[str, dict[str, Any], str]]:
    root = root or RESULTS
    out = []
    for p in sorted((root / "baselines" / experiment).glob("*.json")):
        out.append((_load(p)["model"], _load(p), "baselines"))
    for p in sorted((root / "gnn" / experiment).glob("*.json")):
        r = _load(p)
        out.append(("graphsage_" + r["variant"], r, "gnn"))
    return out


def _headline(r: dict[str, Any], family: str) -> tuple[dict[str, Any], dict[str, Any]]:
    """(summary over seeds, first-seed evaluation) for the standard test evaluation."""
    if family == "baselines":
        return r["summary"], r["seeds"][0]
    return r["summary"]["native_modes"]["cumulative"], r["seeds"][0]["native_modes"]["cumulative"]


def comparison(experiment: str, root: Path | None = None) -> dict[str, Any]:
    root = root or RESULTS
    models = []
    for name, r, fam in _model_entries(experiment, root):
        s, first = _headline(r, fam)
        models.append({
            "model": name, "family": fam, "identity_free": r.get("identity_free", True if fam == "baselines" else None),
            "classes": r["classes"], "n_seeds": len(r["seeds"]),
            "macro_f1": s.get("macro_f1"), "macro_precision": s.get("macro_precision"), "macro_recall": s.get("macro_recall"),
            "accuracy": s.get("accuracy"), "fpr": s.get("fpr"), "macro_pr_auc": s.get("macro_pr_auc"),
            "off_pair_macro_f1": s.get("off_pair_macro_f1"), "per_class_recall": s.get("per_class_recall"),
            "per_class_f1": s.get("per_class_f1"), "off_pair_per_attack_recall": s.get("off_pair_per_attack_recall"),
            "confusion_matrix_seed0": first["confusion_matrix"],
            "dominant_vs_non_dominant_seed0": {k: v["overall"] for k, v in first.get("view_dominant_vs_non_dominant", {}).items()},
            "dedup_test_seed0": first.get("dedup_test", {}).get("overall"),
            "predict_ms_per_1k_flows": first.get("predict_ms_per_1k_flows"),
            "per_class_support_seed0": {c: v["support"] for c, v in first["per_class"].items()},
        })
    return {"experiment": experiment, "models": models}


def robustness(experiment: str = "primary_family_default", root: Path | None = None) -> dict[str, Any]:
    root = root or RESULTS
    rows = []
    levels: list[str] = []
    for name, r, fam in _model_entries(experiment, root):
        if fam == "gnn":
            lv = r["summary"]["robustness"]
            levels = levels or list(lv)
            rows.append({"model": name, "invariant_by_construction": False, "levels": {
                k: {"macro_f1": v.get("macro_f1"), "fpr": v.get("fpr"), "off_pair_macro_f1": v.get("off_pair_macro_f1"),
                    "per_class_recall": v.get("per_class_recall")} for k, v in lv.items()}})
    for p in sorted((root / "gnn" / "aggregation_aware").glob("*.json")):
        r = _load(p)
        if r["experiment"]["name"] != experiment:
            continue
        lv = r["summary"]["robustness"]
        rows.append({"model": f"aggaware_{r['aggregation_aware']['name']}", "invariant_by_construction": False,
                     "aggregation_aware": r["aggregation_aware"], "levels": {
                         k: {"macro_f1": v.get("macro_f1"), "fpr": v.get("fpr"), "off_pair_macro_f1": v.get("off_pair_macro_f1"),
                             "per_class_recall": v.get("per_class_recall")} for k, v in lv.items()}})
    for name, r, fam in _model_entries(experiment, root):
        if fam == "baselines":
            s = r["summary"]
            same = {"macro_f1": s.get("macro_f1"), "fpr": s.get("fpr"), "off_pair_macro_f1": s.get("off_pair_macro_f1"),
                    "per_class_recall": s.get("per_class_recall")}
            rows.append({"model": name, "invariant_by_construction": True,
                         "note": "uses no endpoint identity; inputs are identical at every aggregation level",
                         "levels": {k: same for k in levels} if levels else {"native_identity_baseline": same}})
    return {"experiment": experiment, "levels": levels, "models": rows,
            "note": "native_identity_baseline = merge factor 1 (already NAT-aggregated); higher = synthetic aggregation"}


def native_modes(experiment: str = "primary_family_default", root: Path | None = None) -> dict[str, Any]:
    root = root or RESULTS
    out = []
    for name, r, fam in _model_entries(experiment, root):
        if fam == "gnn":
            out.append({"model": name, "modes": {m: {"macro_f1": v.get("macro_f1"), "fpr": v.get("fpr"),
                                                     "off_pair_macro_f1": v.get("off_pair_macro_f1")}
                                                 for m, v in r["summary"]["native_modes"].items()}})
    return {"experiment": experiment, "models": out}


def eps1(root: Path | None = None, processed: Path | None = None) -> dict[str, Any]:
    """Headline E-PS1: PortScan with vs without Destination Port, plus exact collision counts."""
    root = root or RESULTS
    processed = processed or Path("data/processed/v1")
    rows = []
    for fs, exp in (("default", "primary_family_default"), ("dstport", "primary_family_dstport")):
        for name, r, fam in _model_entries(exp, root):
            s, first = _headline(r, fam)
            pc = first["per_class"].get("PortScan", {})
            rows.append({"feature_set": fs, "model": name,
                         "portscan_recall": (s.get("per_class_recall") or {}).get("PortScan"),
                         "portscan_f1": (s.get("per_class_f1") or {}).get("PortScan"),
                         "portscan_precision_seed0": pc.get("precision"), "portscan_support": pc.get("support"),
                         "macro_f1": s.get("macro_f1"), "fpr": s.get("fpr"),
                         "off_pair_portscan_recall": (s.get("off_pair_per_attack_recall") or {}).get("PortScan")})
    coll = {}
    stats = processed / "dataset_stats.json"
    if stats.exists():
        lc = json.loads(stats.read_text(encoding="utf-8")).get("label_collisions", {})
        coll = {fs: {k: lc[fs][k] for k in ("groups", "rows", "portscan_rows_total", "portscan_rows_colliding",
                                             "portscan_rows_colliding_with_benign")} for fs in ("default", "dstport") if fs in lc}
    fc = processed / "schemes" / "primary" / "feature_collisions.json"
    tt = {}
    if fc.exists():
        c = json.loads(fc.read_text(encoding="utf-8"))
        tt = {fs: c[fs]["test"]["rows_vector_in_train_with_other_label_by_label"].get("PortScan", 0) for fs in c}
    return {"rows": rows, "collisions": coll, "test_portscan_rows_with_train_twin_of_other_label": tt,
            "interpretation": "Destination Port is legitimate but may encode dataset-specific attack signatures; "
                              "a higher with-port score is not evidence of better generalization by itself."}
