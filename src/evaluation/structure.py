"""Milestone 5: structural effect of identity aggregation on the CICIDS2017 flow graph.

For every aggregation level (merge factor 1 = native_identity_baseline, then synthetic levels) computes the
structural metrics of the full graph (all kept flows of the primary scheme) and of the train context, plus
neighbourhood change and what happens to the dominant NAT pair. Uses only endpoint identities (no labels as inputs;
labels only to report how many attack flows share a pair with benign flows after aggregation).

Usage:
    python -m src.evaluation.structure --config configs/gnn.yaml
"""
from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
import pyarrow.parquet as pq
import yaml

from src.augmentation.aggregation import bucket_mapping, level_name, neighborhood_change, structural_metrics
from src.training.common import write_json


def label_mixing(src: np.ndarray, dst: np.ndarray, attack: np.ndarray, n: int) -> dict[str, Any]:
    """How many attack flows lie on a (src,dst) pair that also carries benign flows (a structural confusion proxy)."""
    key = src.astype(np.int64) * n + dst
    df = pd.DataFrame({"k": key, "a": attack})
    g = df.groupby("k")["a"].agg(["min", "max"])
    mixed = g.index[(g["min"] == 0) & (g["max"] == 1)]
    on_mixed = df["k"].isin(mixed).to_numpy()
    return {"pairs_with_both_benign_and_attack": int(len(mixed)),
            "attack_flows_on_mixed_pairs": int((on_mixed & attack.astype(bool)).sum()),
            "benign_flows_on_mixed_pairs": int((on_mixed & ~attack.astype(bool)).sum())}


def analyse(cfg: dict[str, Any]) -> dict[str, Any]:
    d = Path(cfg["processed_dir"])
    t = pq.read_table(d / "metadata.parquet", columns=["src_ip", "dst_ip", "label_binary", "split_primary",
                                                      "dominant_pair_directed"]).to_pandas()
    names = np.unique(np.concatenate([t["src_ip"].to_numpy().astype(str), t["dst_ip"].to_numpy().astype(str)]))
    cat = pd.CategoricalDtype(names, ordered=True)
    src = t["src_ip"].astype(str).astype(cat).cat.codes.to_numpy().astype(np.int64)
    dst = t["dst_ip"].astype(str).astype(cat).cat.codes.to_numpy().astype(np.int64)
    attack = t["label_binary"].to_numpy()
    train = (t["split_primary"] == "train").to_numpy()
    dom = t["dominant_pair_directed"].to_numpy()
    N = len(names)
    seed = cfg["aggregation"]["seed"]
    out: dict[str, Any] = {"num_endpoints": int(N), "aggregation_seed": seed, "levels": {},
                           "note": "merge_factor 1 = native_identity_baseline (already contains NAT aggregation); "
                                   "higher levels add synthetic identity collisions (stress test, not a NAT emulator)"}
    dom_src = int(np.searchsorted(names, cfg.get("dominant_src", "172.16.0.1")))
    dom_dst = int(np.searchsorted(names, cfg.get("dominant_dst", "192.168.10.50")))
    for k in cfg["aggregation"]["levels"]:
        m = bucket_mapping(N, k, seed)
        nb = int(m.max()) + 1
        ms, md = m[src], m[dst]
        bs, bd = m[dom_src], m[dom_dst]
        on_dom_bucket_pair = (ms == bs) & (md == bd)
        out["levels"][level_name(k)] = {
            "merge_factor": k, "buckets": nb,
            "all_flows": structural_metrics(ms, md, nb),
            "train_context": structural_metrics(ms[train], md[train], nb),
            "neighbourhood_change": neighborhood_change(src, dst, m, N) if k > 1 else {"mean_jaccard": 1.0,
                                                                                   "fraction_unchanged": 1.0},
            "label_mixing_all_flows": label_mixing(ms, md, attack, nb),
            "dominant_pair": {"bucket_pair_flows": int(on_dom_bucket_pair.sum()),
                              "attack_fraction_on_bucket_pair": float(attack[on_dom_bucket_pair].mean()),
                              "original_dominant_flows": int(dom.sum()),
                              "endpoints_sharing_attacker_bucket": int((m == bs).sum()),
                              "endpoints_sharing_victim_bucket": int((m == bd).sum())},
        }
        print(f"{level_name(k)}: buckets={nb} pairs={out['levels'][level_name(k)]['all_flows']['unique_directed_pairs']}",
              flush=True)
    return out


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--config", type=Path, default=Path("configs/gnn.yaml"))
    ap.add_argument("--out", type=Path, default=Path("experiments/results/aggregation/structure.json"))
    a = ap.parse_args(argv)
    cfg = yaml.safe_load(a.config.read_text(encoding="utf-8"))
    write_json(a.out, analyse(cfg))
    print(f"wrote {a.out}")


if __name__ == "__main__":
    main()
