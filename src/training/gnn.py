"""GraphSAGE training and evaluation (Milestones 4, 6, 7).

* Training: M = train edges. Seeded, disjoint target batches B (class-capped per epoch); context C = M \\ B
  (exact exclusion, graph_builder.Context). Early stopping on VAL macro-F1 at native_identity_baseline (cumulative).
* Test evaluation, model frozen:
    - native_identity_baseline in the three context modes cumulative / period_only / prior_only (contract §6.3)
    - robustness: every aggregation level (merge factors 1, 2, 4, 8, 16, 32) in cumulative mode, with ONE shared
      seeded mapping per level applied to all splits
    - each evaluation includes the §6.5 views (off-dominant-pair, dominant vs non-dominant) and dedup test
* Aggregation-aware training (Milestone 7): each batch is also classified in a paired aggregated view (merge factor
  drawn from train_levels, same mapping policy), with
      L_total = L_cls(native) + lambda1 * L_consistency + lambda2 * L_robustness
  where L_consistency = symmetric KL between the two views' predictive distributions and L_robustness = CE on the
  aggregated view. Labels are never inputs. unseen_levels are never used in training.

Usage:
    python -m src.training.gnn --config configs/gnn.yaml [--only primary_family_default] [--variants identity_free]
    python -m src.training.gnn --config configs/gnn.yaml --aggregation-aware [--settings consistency_only]
"""
from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
import pyarrow.parquet as pq
import torch
import torch.nn.functional as F
import yaml
from sklearn.metrics import f1_score

from src.augmentation.aggregation import bucket_mapping, level_name
from src.evaluation.metrics import evaluate, summarize_seeds
from src.graph_builder.graph import Context, EdgeSet, build_node_index, load_edges
from src.training.baselines import class_names
from src.training.common import capped_sample, run_metadata, sqrt_balanced_weights, write_json
from src.training.gnn_model import EdgeGraphSAGE

MODES = {  # target split -> mode -> context splits (contract §6.3)
    "val": {"cumulative": ("train", "val"), "period_only": ("val",), "prior_only": ("train",)},
    "test": {"cumulative": ("train", "val", "test"), "period_only": ("test",), "prior_only": ("train", "val")},
}


def pick_device(pref: str) -> torch.device:
    if pref == "auto":
        return torch.device("cuda" if torch.cuda.is_available() else "cpu")
    return torch.device(pref)


class GraphData:
    """Edges of all splits + cached contexts per (context splits, merge factor)."""

    def __init__(self, cfg: dict[str, Any], exp: dict[str, Any], device: torch.device) -> None:
        self.cfg, self.exp, self.device = cfg, exp, device
        d = Path(cfg["processed_dir"])
        self.names = build_node_index(d)
        self.N = len(self.names)
        row_filter = None
        if exp.get("exclude_dominant_pair"):
            row_filter = ~pq.read_table(d / "metadata.parquet", columns=["dominant_pair_undirected"]).column(0).to_numpy()
        extra = (f"train_dup_{exp['scheme']}",)
        self.edges: dict[str, EdgeSet] = {s: load_edges(d, exp["scheme"], s, self.names, exp["feature_set"],
                                                        exp["target"], row_filter, extra) for s in ("train", "val", "test")}
        self.classes = class_names(d, exp["scheme"], exp["target"])
        self.agg_seed = cfg["aggregation"]["seed"]
        self._ctx: dict[tuple, Context] = {}
        self._maps: dict[int, tuple[torch.Tensor, int]] = {}

    def mapping(self, k: int) -> tuple[torch.Tensor, int]:
        if k not in self._maps:
            m = bucket_mapping(self.N, k, self.agg_seed)
            self._maps[k] = (torch.from_numpy(m).to(self.device), int(m.max()) + 1)
        return self._maps[k]

    def context(self, splits: tuple[str, ...], k: int = 1) -> Context:
        key = (splits, k)
        if key not in self._ctx:
            m, nb = self.mapping(k)
            self._ctx[key] = Context([self.edges[s] for s in splits], nb, self.device, None if k == 1 else m)
        return self._ctx[key]

    def drop_contexts(self, keep_train: bool = True) -> None:
        self._ctx = {k: v for k, v in self._ctx.items() if keep_train and k[0] == ("train",)}
        torch.cuda.empty_cache()


def sym_kl(logits_a: torch.Tensor, logits_b: torch.Tensor) -> torch.Tensor:
    la, lb = F.log_softmax(logits_a, 1), F.log_softmax(logits_b, 1)
    return 0.5 * (F.kl_div(la, lb, log_target=True, reduction="batchmean") +
                  F.kl_div(lb, la, log_target=True, reduction="batchmean"))


@torch.no_grad()
def predict(model: EdgeGraphSAGE, gd: GraphData, target: str, ctx_splits: tuple[str, ...], k: int,
            batch_size: int, seed: int) -> np.ndarray:
    """Class probabilities for every flow of `target`, with seeded disjoint batches and C = M \\ B."""
    model.eval()
    E = gd.edges[target]
    ctx = gd.context(ctx_splits, k)
    exclude = target in ctx_splits
    m, nb = gd.mapping(k)
    emb_table = model.bucket_embeddings(m, nb) if (not model.identity_free and k > 1) else None
    order = np.random.default_rng(seed).permutation(len(E))
    out = np.empty((len(E), len(gd.classes)), dtype="float32")
    for i in range(0, len(E), batch_size):
        b = torch.from_numpy(order[i:i + batch_size])
        s, d, x = E.src[b].to(gd.device), E.dst[b].to(gd.device), E.x[b].to(gd.device)
        h0, ei = ctx.node_inputs(s, d, x, exclude)
        logits = model(h0, ei, m[s], m[d], x, emb_table)
        out[order[i:i + batch_size]] = torch.softmax(logits, 1).cpu().numpy()
    return out


def evaluate_split(model: EdgeGraphSAGE, gd: GraphData, target: str, ctx_splits: tuple[str, ...], k: int,
                   bs: int, seed: int) -> tuple[dict[str, Any], np.ndarray]:
    t0 = time.time()
    proba = predict(model, gd, target, ctx_splits, k, bs, seed)
    secs = time.time() - t0
    E = gd.edges[target]
    dup_col = f"train_dup_{gd.exp['scheme']}"
    ev = evaluate(E.y.numpy(), proba.argmax(1), gd.classes, E.meta["dominant_pair_directed"].to_numpy(), proba,
                  dedup_mask=~E.meta[dup_col].to_numpy() if dup_col in E.meta else None)
    ev["predict_ms_per_1k_flows"] = round(secs / max(len(E), 1) * 1e6, 3)
    return ev, proba


def train_model(gd: GraphData, variant: str, seed: int, agg: dict[str, Any] | None = None
                ) -> tuple[EdgeGraphSAGE, list[dict[str, Any]], float]:
    cfg, tc, mc = gd.cfg, gd.cfg["train"], gd.cfg["model"]
    torch.manual_seed(seed)
    rng = np.random.default_rng(seed)
    tr = gd.edges["train"]
    K = len(gd.classes)
    ctx_tr = gd.context(("train",), 1)
    model = EdgeGraphSAGE(ctx_tr.node_dim, tr.x.shape[1], K, mc["hidden"], mc["layers"], mc["dropout"],
                          num_nodes=gd.N if variant == "standard" else None, emb_dim=mc["emb_dim"]).to(gd.device)
    opt = torch.optim.AdamW(model.parameters(), lr=tc["lr"], weight_decay=tc["weight_decay"])
    fine = tr.meta["label_fine"].to_numpy()
    y_np = tr.y.numpy()
    w = torch.tensor(sqrt_balanced_weights(y_np[capped_sample(fine, tc["cap_per_fine_label_per_epoch"], seed)], K),
                     dtype=torch.float32, device=gd.device)
    agg_ctx = {k: gd.context(("train",), k) for k in (agg["train_levels"] if agg else [])}
    best, best_state, bad, hist = -1.0, None, 0, []
    t_start = time.time()
    for ep in range(tc["max_epochs"]):
        model.train()
        t0 = time.time()
        idx = capped_sample(fine, tc["cap_per_fine_label_per_epoch"], seed * 1000 + ep)
        rng.shuffle(idx)
        tot = {"loss": 0.0, "cls": 0.0, "cons": 0.0, "rob": 0.0}
        nb = 0
        for i in range(0, len(idx), tc["batch_size"]):
            b = torch.from_numpy(idx[i:i + tc["batch_size"]])
            s, d, x, y = (tr.src[b].to(gd.device), tr.dst[b].to(gd.device), tr.x[b].to(gd.device), tr.y[b].to(gd.device))
            h0, ei = ctx_tr.node_inputs(s, d, x, exclude=True)
            logits = model(h0, ei, s, d, x)
            l_cls = F.cross_entropy(logits, y, weight=w)
            loss = l_cls
            if agg:
                k = int(rng.choice(agg["train_levels"]))
                m, nbk = gd.mapping(k)
                h0k, eik = agg_ctx[k].node_inputs(s, d, x, exclude=True)
                emb = model.bucket_embeddings(m, nbk) if not model.identity_free else None
                la = model(h0k, eik, m[s], m[d], x, emb)
                l_rob = F.cross_entropy(la, y, weight=w)
                l_cons = sym_kl(logits, la)
                loss = l_cls + agg["lambda1"] * l_cons + agg["lambda2"] * l_rob
                tot["cons"] += l_cons.detach().item()
                tot["rob"] += l_rob.detach().item()
            opt.zero_grad(set_to_none=True)
            loss.backward()
            opt.step()
            tot["loss"] += loss.detach().item()
            tot["cls"] += l_cls.detach().item()
            nb += 1
        proba = predict(model, gd, "val", MODES["val"]["cumulative"], 1, tc["eval_batch_size"], seed)
        yv = gd.edges["val"].y.numpy()
        f1 = float(f1_score(yv, proba.argmax(1), labels=np.unique(yv), average="macro", zero_division=0))
        rec = {"epoch": ep, "val_macro_f1": f1, "seconds": round(time.time() - t0, 1), **{k: v / nb for k, v in tot.items()}}
        hist.append(rec)
        print(f"     ep {ep}: loss={rec['loss']:.4f} val macro-F1={f1:.4f} ({rec['seconds']}s)", flush=True)
        if f1 > best + 1e-4:
            best, bad = f1, 0
            best_state = {k: v.detach().clone() for k, v in model.state_dict().items()}
        else:
            bad += 1
            if bad >= tc["patience"]:
                break
    model.load_state_dict(best_state)
    return model, hist, time.time() - t_start


def run_variant(gd: GraphData, variant: str, seeds: list[int], out_file: Path, model_dir: Path,
                agg: dict[str, Any] | None = None, tag: str | None = None) -> dict[str, Any]:
    cfg = gd.cfg
    bs = cfg["train"]["eval_batch_size"]
    levels = cfg["aggregation"]["levels"]
    results = []
    for seed in seeds:
        print(f"   [{tag or variant}] seed {seed}", flush=True)
        model, hist, secs = train_model(gd, variant, seed, agg)
        res: dict[str, Any] = {"seed": seed, "train_seconds": round(secs, 1), "epochs_trained": len(hist),
                               "best_val_macro_f1": max(h["val_macro_f1"] for h in hist), "history": hist,
                               "native_modes": {}, "robustness": {}}
        for mode, ctx_splits in MODES["test"].items():
            ev, proba = evaluate_split(model, gd, "test", ctx_splits, 1, bs, seed)
            res["native_modes"][mode] = ev
            if mode == "cumulative" and seed == seeds[0]:
                E = gd.edges["test"]
                model_dir.mkdir(parents=True, exist_ok=True)
                pd.DataFrame({"flow_uid": E.flow_uid, "y_true": E.y.numpy(), "y_pred": proba.argmax(1),
                              "p_max": proba.max(1)}).to_parquet(model_dir / f"{tag or variant}_test_predictions_seed{seed}.parquet",
                                                                  index=False)
        for k in levels:
            ev = res["native_modes"]["cumulative"] if k == 1 else evaluate_split(
                model, gd, "test", MODES["test"]["cumulative"], k, bs, seed)[0]
            res["robustness"][level_name(k)] = ev
            print(f"     {level_name(k)}: macro-F1={ev['overall']['macro_f1']:.4f} FPR={ev['overall'].get('fpr')}", flush=True)
        if seed == seeds[0]:
            model_dir.mkdir(parents=True, exist_ok=True)
            torch.save({"state_dict": model.state_dict(), "variant": variant, "classes": gd.classes,
                        "node_dim": gd.context(("train",), 1).node_dim, "edge_dim": gd.edges["train"].x.shape[1],
                        "num_nodes": gd.N, "model_cfg": cfg["model"]}, model_dir / f"{tag or variant}_seed{seed}.pt")
        results.append(res)
        gd.drop_contexts(keep_train=True)
        del model
        torch.cuda.empty_cache()
    summary = {"native_modes": {m: summarize_seeds([r["native_modes"][m] for r in results]) for m in MODES["test"]},
               "robustness": {level_name(k): summarize_seeds([r["robustness"][level_name(k)] for r in results]) for k in levels}}
    payload = {"experiment": gd.exp, "variant": variant, "identity_free": variant != "standard", "classes": gd.classes,
               "aggregation_aware": agg, "seeds": results, "summary": summary,
               "graph": {"num_nodes": gd.N, "edges": {s: len(e) for s, e in gd.edges.items()},
                         "train_context_unique_pairs": int(len(gd.context(("train",), 1).pair_key)),
                         "aggregation_seed": cfg["aggregation"]["seed"]},
               "run": run_metadata(cfg["processed_dir"], {"gnn": cfg, "experiment": gd.exp, "variant": variant, "agg": agg})}
    write_json(out_file, payload)
    return payload


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--config", type=Path, default=Path("configs/gnn.yaml"))
    ap.add_argument("--only", nargs="*", default=None)
    ap.add_argument("--variants", nargs="*", default=None)
    ap.add_argument("--seeds", nargs="*", type=int, default=None)
    ap.add_argument("--aggregation-aware", action="store_true")
    ap.add_argument("--settings", nargs="*", default=None)
    a = ap.parse_args(argv)
    cfg = yaml.safe_load(a.config.read_text(encoding="utf-8"))
    device = pick_device(cfg.get("device", "auto"))
    print(f"device: {device}", flush=True)
    res_dir, mdl_dir = Path(cfg["results_dir"]), Path(cfg["models_dir"])
    if a.aggregation_aware:
        ac = cfg["aggregation_aware"]
        exp = next(e for e in cfg["experiments"] if e["name"] == ac["base_experiment"])
        gd = GraphData(cfg, exp, device)
        for st in ac["settings"]:
            if a.settings and st["name"] not in a.settings:
                continue
            agg = {**st, "train_levels": ac["train_levels"], "unseen_levels": ac["unseen_levels"]}
            run_variant(gd, ac["variant"], a.seeds or cfg["seeds"], res_dir / "aggregation_aware" / f"{st['name']}.json",
                        mdl_dir / "aggregation_aware", agg, tag=f"aggaware_{st['name']}")
        return
    for exp in cfg["experiments"]:
        if a.only and exp["name"] not in a.only:
            continue
        print(f"== {exp['name']}", flush=True)
        gd = GraphData(cfg, exp, device)
        for v in exp["variants"]:
            if a.variants and v not in a.variants:
                continue
            run_variant(gd, v, a.seeds or exp.get("seeds", cfg["seeds"]), res_dir / exp["name"] / f"graphsage_{v}.json",
                        mdl_dir / exp["name"], tag=f"graphsage_{v}")
        del gd
        torch.cuda.empty_cache()


if __name__ == "__main__":
    main()
