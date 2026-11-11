"""Identity aggregation simulator (Milestone 5).

A controlled identity-collision stress test, NOT a NAT emulator. merge_factor = 1 is the
``native_identity_baseline``: the original data already contains real NAT aggregation (contract §6.5).
merge_factor = k > 1 adds *synthetic* aggregation on top of it.

Mapping policy (one shared policy for every split and for both paired views; never independent mappings):
  rng = default_rng(seed); perm = rng.permutation(num_nodes); bucket[perm[i]] = i // k
  -> ceil(N / k) buckets of exactly k endpoints (the last may be smaller). Deterministic for (N, k, seed).
Flows keep their features, labels and flow_uid; only endpoint ids change. Collisions create self-loops
(both endpoints in one bucket) and merge parallel edges at the pair level; both are kept and counted.
"""
from __future__ import annotations

from typing import Any

import numpy as np
import scipy.sparse as sp
from scipy.sparse.csgraph import connected_components

NATIVE = "native_identity_baseline"


def level_name(k: int) -> str:
    return NATIVE if k == 1 else f"merge_factor_{k}"


def bucket_mapping(num_nodes: int, merge_factor: int, seed: int) -> np.ndarray:
    if merge_factor < 1:
        raise ValueError("merge_factor must be >= 1")
    if merge_factor == 1:
        return np.arange(num_nodes, dtype=np.int64)
    perm = np.random.default_rng(seed).permutation(num_nodes)
    mapping = np.empty(num_nodes, dtype=np.int64)
    mapping[perm] = np.arange(num_nodes) // merge_factor
    return mapping


def structural_metrics(src: np.ndarray, dst: np.ndarray, num_nodes: int) -> dict[str, Any]:
    """Structure of a flow multigraph (nodes that carry at least one flow are counted as active)."""
    pairs = np.unique(src.astype(np.int64) * num_nodes + dst)
    ps, pd_ = pairs // num_nodes, pairs % num_nodes
    active = np.unique(np.concatenate([src, dst]))
    n = len(active)
    deg = np.bincount(np.concatenate([ps, pd_]), minlength=num_nodes)[active]   # distinct-pair degree
    a = sp.coo_matrix((np.ones(len(ps)), (ps, pd_)), shape=(num_nodes, num_nodes)).tocsr()
    ncomp, lab = connected_components(a, directed=True, connection="weak")
    comp_sizes = np.bincount(lab[active])
    comp_sizes = comp_sizes[comp_sizes > 0]
    return {"active_nodes": int(n), "flows": int(len(src)), "unique_directed_pairs": int(len(pairs)),
            "self_loop_flows": int((src == dst).sum()), "self_loop_pairs": int((ps == pd_).sum()),
            "avg_degree_distinct_pairs": float(deg.mean()) if n else 0.0,
            "avg_flows_per_node": float(2 * len(src) / n) if n else 0.0,
            "density": float(len(pairs) / (n * (n - 1))) if n > 1 else 0.0,
            "weakly_connected_components": int(len(comp_sizes)),
            "largest_component_fraction": float(comp_sizes.max() / n) if n else 0.0,
            "degree_quantiles": {str(q): float(np.quantile(deg, q)) for q in (0.5, 0.9, 0.99, 1.0)} if n else {},
            "degree_histogram_log2": np.bincount(np.floor(np.log2(np.maximum(deg, 1))).astype(int)).tolist() if n else []}


def neighborhood_change(src: np.ndarray, dst: np.ndarray, mapping: np.ndarray, num_nodes: int,
                        max_nodes: int = 20000, seed: int = 0) -> dict[str, float]:
    """Mean Jaccard similarity between each endpoint's (mapped) original neighbour set and its bucket's
    neighbour set (undirected). 1.0 = neighbourhood unchanged; lower = more identity confusion."""
    und_s = np.concatenate([src, dst]).astype(np.int64)
    und_d = np.concatenate([dst, src]).astype(np.int64)
    orig = np.unique(und_s * num_nodes + und_d)
    o_s, o_d = orig // num_nodes, orig % num_nodes
    nodes = np.unique(o_s)
    if len(nodes) > max_nodes:
        nodes = np.sort(np.random.default_rng(seed).choice(nodes, max_nodes, replace=False))
    # mapped original neighbourhoods: {b(w) : w in N(u)}
    mo = np.unique(o_s * num_nodes + mapping[o_d])
    agg = np.unique(mapping[und_s] * num_nodes + mapping[und_d])
    mo_s, mo_n = mo // num_nodes, mo % num_nodes
    ag_s, ag_n = agg // num_nodes, agg % num_nodes
    from collections import defaultdict

    a_sets: dict[int, set] = defaultdict(set)
    for b, n in zip(ag_s.tolist(), ag_n.tolist()):
        a_sets[b].add(n)
    o_sets: dict[int, set] = defaultdict(set)
    sel = set(nodes.tolist())
    for u, n in zip(mo_s.tolist(), mo_n.tolist()):
        if u in sel:
            o_sets[u].add(n)
    js = []
    for u in nodes.tolist():
        A, B = o_sets[u], a_sets[int(mapping[u])]
        js.append(len(A & B) / len(A | B) if (A or B) else 1.0)
    js = np.asarray(js)
    return {"nodes_evaluated": int(len(js)), "mean_jaccard": float(js.mean()), "median_jaccard": float(np.median(js)),
            "fraction_unchanged": float((js == 1.0).mean())}
