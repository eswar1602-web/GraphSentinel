"""Build reports/results/RESULTS.md and figures from the experiment result files (nothing typed in by hand).

Usage:
    python -m src.evaluation.report
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402

RES = Path("experiments/results")
OUT = Path("reports/results")
LEVELS = ["native_identity_baseline", "merge_factor_2", "merge_factor_4", "merge_factor_8", "merge_factor_16", "merge_factor_32"]
LV_X = [1, 2, 4, 8, 16, 32]


def load(p: Path) -> dict[str, Any]:
    return json.loads(p.read_text(encoding="utf-8"))


def models(exp: str) -> list[tuple[str, dict[str, Any], dict[str, Any], dict[str, Any]]]:
    """(name, file, summary-over-seeds, seed-0 evaluation) for the standard test evaluation."""
    out = []
    for p in sorted((RES / "baselines" / exp).glob("*.json")):
        r = load(p)
        out.append((r["model"], r, r["summary"], r["seeds"][0]))
    for p in sorted((RES / "gnn" / exp).glob("*.json")):
        r = load(p)
        out.append(("graphsage_" + r["variant"], r, r["summary"]["native_modes"]["cumulative"], r["seeds"][0]["native_modes"]["cumulative"]))
    return out


def ms(s: dict[str, Any] | None, d: int = 3, pct: bool = False) -> str:
    if not s:
        return "—"
    f = (lambda v: f"{100 * v:.{max(d - 1, 1)}f}%") if pct else (lambda v: f"{v:.{d}f}")
    return f"{f(s['mean'])}" if s.get("n", 0) == 1 else f"{f(s['mean'])} ± {f(s['std'])}"


def table(header: list[str], rows: list[list[str]]) -> str:
    return "\n".join(["| " + " | ".join(header) + " |", "|" + "|".join("---" for _ in header) + "|"]
                     + ["| " + " | ".join(map(str, r)) + " |" for r in rows])


def main_table(exp: str) -> str:
    rows = []
    for name, r, s, first in models(exp):
        dom = first.get("view_dominant_vs_non_dominant", {})
        rows.append([name, len(r["seeds"]), ms(s.get("macro_f1")), ms(s.get("fpr"), 3, True), ms(s.get("macro_pr_auc")),
                     ms(s.get("off_pair_macro_f1")),
                     f"{first['dedup_test']['overall']['macro_f1']:.3f}" if first.get("dedup_test") else "—",
                     f"{100 * dom['dominant_pair']['overall']['fpr']:.1f}%" if dom.get("dominant_pair", {}).get("overall", {}).get("fpr") is not None else "—",
                     f"{first.get('predict_ms_per_1k_flows', 0):.1f}"])
    return table(["model", "seeds", "macro-F1", "FPR", "macro PR-AUC", "off-pair macro-F1", "dedup-test macro-F1 (s0)",
                  "FPR on dominant pair (s0)", "ms/1k flows"], rows)


def per_class_table(exp: str) -> str:
    ms_ = models(exp)
    classes = ms_[0][1]["classes"]
    rows = []
    for c in classes:
        sup = ms_[0][3]["per_class"][c]["support"]
        rows.append([c, f"{sup:,}"] + [ms((s.get("per_class_recall") or {}).get(c)) for _, _, s, _ in ms_])
    return table(["class", "test support"] + [m[0] + " recall" for m in ms_], rows)


def robustness_rows(exp: str = "primary_family_default") -> list[tuple[str, list[dict | None], list[dict | None], list[dict | None]]]:
    out = []
    for name, r, s, _ in models(exp):
        if "robustness" in r.get("summary", {}):
            lv = r["summary"]["robustness"]
            out.append((name, [lv[l].get("macro_f1") for l in LEVELS], [lv[l].get("fpr") for l in LEVELS],
                        [lv[l].get("off_pair_macro_f1") for l in LEVELS]))
        else:
            out.append((name + " (invariant)", [s.get("macro_f1")] * 6, [s.get("fpr")] * 6, [s.get("off_pair_macro_f1")] * 6))
    for p in sorted((RES / "gnn" / "aggregation_aware").glob("*.json")):
        r = load(p)
        lv = r["summary"]["robustness"]
        out.append(("aggaware_" + r["aggregation_aware"]["name"], [lv[l].get("macro_f1") for l in LEVELS],
                    [lv[l].get("fpr") for l in LEVELS], [lv[l].get("off_pair_macro_f1") for l in LEVELS]))
    return out


def fig_severity(rows, idx: int, ylabel: str, fname: str) -> None:
    fig, ax = plt.subplots(figsize=(8, 4.8))
    for name, *vals in rows:
        v = vals[idx]
        y = np.array([x["mean"] if x else np.nan for x in v])
        e = np.array([x["std"] if x else 0 for x in v])
        ax.errorbar(LV_X, y, yerr=e, marker="o", capsize=3, label=name, linestyle=":" if "invariant" in name else "-")
    ax.axvspan(12, 40, color="red", alpha=0.06, label="unseen by aggregation-aware training")
    ax.set_xscale("log", base=2)
    ax.set_xticks(LV_X, ["1\nnative", "2", "4", "8", "16", "32"])
    ax.set_xlabel("merge factor (1 = native_identity_baseline)")
    ax.set_ylabel(ylabel)
    ax.legend(fontsize=7, loc="best")
    ax.grid(alpha=0.3)
    fig.tight_layout()
    fig.savefig(OUT / fname, dpi=130)
    plt.close(fig)


def fig_models(exp: str, fname: str) -> None:
    ms_ = models(exp)
    fig, axes = plt.subplots(1, 2, figsize=(11, 4))
    names = [m[0] for m in ms_]
    for ax, key, lab in ((axes[0], "macro_f1", "test macro-F1"), (axes[1], "off_pair_macro_f1", "off-dominant-pair macro-F1")):
        y = [m[2][key]["mean"] for m in ms_]
        e = [m[2][key]["std"] for m in ms_]
        ax.bar(names, y, yerr=e, capsize=4, color=plt.cm.tab10(np.arange(len(names))))
        ax.set_ylim(0, 1)
        ax.set_title(lab)
        ax.tick_params(axis="x", rotation=20)
    fig.suptitle(exp)
    fig.tight_layout()
    fig.savefig(OUT / fname, dpi=130)
    plt.close(fig)


def fig_per_class(exp: str, fname: str) -> None:
    ms_ = models(exp)
    classes = ms_[0][1]["classes"]
    w = 0.8 / len(ms_)
    fig, ax = plt.subplots(figsize=(11, 4))
    for i, (name, _, s, _) in enumerate(ms_):
        y = [(s.get("per_class_f1") or {}).get(c, {}).get("mean", np.nan) for c in classes]
        ax.bar(np.arange(len(classes)) + i * w, y, w, label=name)
    ax.set_xticks(np.arange(len(classes)) + 0.4 - w / 2, classes, rotation=20)
    ax.set_ylabel("F1 (mean over seeds)")
    ax.set_ylim(0, 1.05)
    ax.legend(fontsize=8)
    fig.tight_layout()
    fig.savefig(OUT / fname, dpi=130)
    plt.close(fig)


def fig_confusions(exp: str, fname: str) -> None:
    ms_ = models(exp)
    fig, axes = plt.subplots(1, len(ms_), figsize=(4.6 * len(ms_), 4.4))
    for ax, (name, r, _, first) in zip(np.atleast_1d(axes), ms_):
        cm = np.array(first["confusion_matrix"], dtype=float)
        norm = cm / np.maximum(cm.sum(1, keepdims=True), 1)
        ax.imshow(norm, cmap="Blues", vmin=0, vmax=1)
        ax.set_xticks(range(len(r["classes"])), r["classes"], rotation=90, fontsize=7)
        ax.set_yticks(range(len(r["classes"])), r["classes"], fontsize=7)
        ax.set_title(f"{name} (seed 0, row-normalized)", fontsize=8)
    fig.tight_layout()
    fig.savefig(OUT / fname, dpi=130)
    plt.close(fig)


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    md = ["# GraphSentinel results", "",
          "Generated by `python -m src.evaluation.report` from `experiments/results/**`. All numbers are test-set results of",
          "real runs on CICIDS2017 (processed v1, contract v1.1); mean ± std over seeds unless a single seed is noted.",
          "Primary-split and day-holdout results are separate experiments and are never pooled.", ""]
    md += ["## 1. Primary split, attack family, default features (no Destination Port)", "", main_table("primary_family_default"), "",
           "![](model_comparison_primary.png)", "", "### Per-class recall", "", per_class_table("primary_family_default"), "",
           "![](per_class_f1_primary.png)", "", "![](confusion_primary.png)", ""]
    fig_models("primary_family_default", "model_comparison_primary.png")
    fig_per_class("primary_family_default", "per_class_f1_primary.png")
    fig_confusions("primary_family_default", "confusion_primary.png")

    md += ["## 2. GraphSAGE context modes (contract §6.3, native identities)", ""]
    rows = []
    for name, r, _, _ in models("primary_family_default"):
        if "native_modes" in r.get("summary", {}):
            for mode, s in r["summary"]["native_modes"].items():
                rows.append([name, mode, ms(s.get("macro_f1")), ms(s.get("fpr"), 3, True), ms(s.get("off_pair_macro_f1"))])
    md += [table(["model", "mode", "macro-F1", "FPR", "off-pair macro-F1"], rows), ""]

    rob = robustness_rows()
    md += ["## 3. Robustness across identity aggregation (primary split)", "",
           "Merge factor 1 = `native_identity_baseline` (already NAT-aggregated). Higher = synthetic aggregation (one seeded",
           "mapping per level). Aggregation-aware models were trained with factors 2/4/8; 16 and 32 are unseen.", "",
           table(["model"] + ["×1 native", "×2", "×4", "×8", "×16 (unseen)", "×32 (unseen)"], [[n] + [ms(x) for x in f1] for n, f1, _, _ in rob]),
           "", "FPR:", "", table(["model"] + ["×1", "×2", "×4", "×8", "×16", "×32"], [[n] + [ms(x, 3, True) for x in fp] for n, _, fp, _ in rob]),
           "", "Off-dominant-pair macro-F1:", "",
           table(["model"] + ["×1", "×2", "×4", "×8", "×16", "×32"], [[n] + [ms(x) for x in op] for n, _, _, op in rob]), "",
           "![](severity_macro_f1.png)", "", "![](severity_fpr.png)", "", "![](severity_off_pair.png)", ""]
    fig_severity(rob, 0, "test macro-F1", "severity_macro_f1.png")
    fig_severity(rob, 1, "FPR", "severity_fpr.png")
    fig_severity(rob, 2, "off-dominant-pair macro-F1", "severity_off_pair.png")

    md += ["## 4. E-PS1: PortScan with vs without Destination Port", ""]
    rows = []
    for fs, exp in (("default", "primary_family_default"), ("dstport", "primary_family_dstport")):
        for name, _, s, first in models(exp):
            rows.append([fs, name, ms((s.get("per_class_recall") or {}).get("PortScan")), ms((s.get("per_class_f1") or {}).get("PortScan")),
                         f"{first['per_class']['PortScan']['precision']:.3f}", ms(s.get("macro_f1")), ms(s.get("fpr"), 3, True)])
    md += [table(["features", "model", "PortScan recall", "PortScan F1", "PortScan precision (s0)", "macro-F1", "FPR"], rows), ""]
    st = load(Path("data/processed/v1/dataset_stats.json"))["label_collisions"]
    fc = load(Path("data/processed/v1/schemes/primary/feature_collisions.json"))
    md += [table(["features", "collision groups", "rows in groups", "PortScan rows identical to a BENIGN flow",
                  "test PortScan rows with a train twin of another label"],
                 [[k, st[k]["groups"], f"{st[k]['rows']:,}", f"{st[k]['portscan_rows_colliding_with_benign']:,} / {st[k]['portscan_rows_total']:,}",
                   f"{fc[k]['test']['rows_vector_in_train_with_other_label_by_label'].get('PortScan', 0):,}"] for k in ("default", "dstport")]), "",
           "Destination Port is a legitimate feature but may encode dataset-specific attack signatures; a higher with-port",
           "score is not evidence of better generalization by itself.", ""]

    md += ["## 5. Day-holdout generalization (binary; train Mon–Wed, test Thu–Fri)", ""]
    for exp in ("dayholdout_binary_default", "dayholdout_binary_dstport"):
        if models(exp):
            md += [f"### {exp}", "", main_table(exp), ""]
            ms_ = models(exp)
            md += [table(["model", "attack recall (mean)", "benign recall (mean)"],
                         [[n, ms((s.get("per_class_recall") or {}).get("Attack")), ms((s.get("per_class_recall") or {}).get("Benign"))]
                          for n, _, s, _ in ms_]), ""]

    md += ["## 6. Dominant-pair ablation (all 172.16.0.1 ↔ 192.168.10.50 flows removed; contract §6.5 view 4)", "",
           main_table("primary_family_default_dominant_pair_ablation"), ""]
    ms_ = models("primary_family_default_dominant_pair_ablation")
    if ms_:
        classes = ms_[0][1]["classes"]
        md += [table(["class", "test support"] + [m[0] + " recall" for m in ms_],
                     [[c, ms_[0][3]["per_class"][c]["support"]] + [f"{m[3]['per_class'][c]['recall']:.3f}" if m[3]["per_class"][c]["support"] else "not evaluable"
                                                                   for m in ms_] for c in classes]), ""]

    s = load(RES / "aggregation" / "structure.json")
    md += ["## 7. Graph structure under aggregation (all flows)", "",
           table(["level", "buckets", "unique pairs", "avg degree", "density", "self-loop flows", "mean nbr Jaccard", "dominant bucket pair attack fraction"],
                 [[k, f"{v['buckets']:,}", f"{v['all_flows']['unique_directed_pairs']:,}", f"{v['all_flows']['avg_degree_distinct_pairs']:.1f}",
                   f"{v['all_flows']['density']:.2e}", f"{v['all_flows']['self_loop_flows']:,}", f"{v['neighbourhood_change']['mean_jaccard']:.3f}",
                   f"{100 * v['dominant_pair']['attack_fraction_on_bucket_pair']:.2f}%"] for k, v in s["levels"].items()]), ""]
    (OUT / "RESULTS.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    print(f"wrote {OUT / 'RESULTS.md'} and figures")


if __name__ == "__main__":
    main()
