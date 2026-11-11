"""Tests: graph construction/alignment, exact target-edge exclusion, aggregation simulator, GraphSAGE variants."""
from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pandas as pd
import pytest
import torch

from src.augmentation.aggregation import bucket_mapping, level_name, neighborhood_change, structural_metrics
from src.graph_builder.graph import Context, EdgeSet, build_node_index, load_edges
from src.preprocessing.dataset import load_split
from src.preprocessing.pipeline import run
from src.training.gnn_model import EdgeGraphSAGE
from tests.synthetic_cicids import build_raw_dir, synthetic_config

CPU = torch.device("cpu")


@pytest.fixture(scope="module")
def synth(tmp_path_factory: pytest.TempPathFactory) -> Path:
    root = tmp_path_factory.mktemp("g")
    cfg = synthetic_config(root, build_raw_dir(root))
    run(cfg)
    return Path(cfg["paths"]["out_dir"])


def _toy_edges(n_nodes: int = 12, n_edges: int = 200, F: int = 5, seed: int = 0) -> EdgeSet:
    g = torch.Generator().manual_seed(seed)
    src = torch.randint(0, n_nodes, (n_edges,), generator=g)
    dst = torch.randint(0, n_nodes, (n_edges,), generator=g)
    x = torch.randn(n_edges, F, generator=g)
    y = torch.randint(0, 3, (n_edges,), generator=g)
    return EdgeSet("train", src, dst, x, y, np.arange(n_edges).astype(str), pd.DataFrame(index=range(n_edges)))


# ------------------------------------------------------------------ graph construction / alignment
def test_edges_align_with_processed_rows(synth: Path) -> None:
    names = build_node_index(synth)
    e = load_edges(synth, "primary", "test", names)
    sd = load_split(synth, "primary", "test")
    assert (e.flow_uid == sd.flow_uid).all() and torch.equal(e.y, torch.from_numpy(sd.y))
    assert np.array_equal(e.x.numpy(), sd.X)
    assert (names[e.src.numpy()] == sd.meta["src_ip"].to_numpy()).all()
    assert (names[e.dst.numpy()] == sd.meta["dst_ip"].to_numpy()).all()
    assert len(names) == len(set(names))


def test_exclusion_is_exact() -> None:
    E = _toy_edges()
    ctx = Context([E], 12, CPU)
    B = torch.arange(0, 200, 7)
    h0, ei = ctx.node_inputs(E.src[B], E.dst[B], E.x[B], exclude=True)
    keep = torch.ones(200, dtype=torch.bool)
    keep[B] = False
    ref_ctx = Context([EdgeSet("train", E.src[keep], E.dst[keep], E.x[keep], E.y[keep], E.flow_uid[keep.numpy()],
                               E.meta)], 12, CPU)
    h_ref, ei_ref = ref_ctx.node_inputs(exclude=False)
    assert torch.allclose(h0, h_ref, atol=1e-6)
    as_set = lambda t: set(map(tuple, t.T.tolist()))  # noqa: E731
    assert as_set(ei) == as_set(ei_ref)


def test_target_not_in_context_raises() -> None:
    src, dst = torch.tensor([0, 1, 2]), torch.tensor([1, 2, 0])
    E = EdgeSet("train", src, dst, torch.randn(3, 5), torch.zeros(3, dtype=torch.long), np.array(["a", "b", "c"]),
                pd.DataFrame(index=range(3)))
    ctx = Context([E], 4, CPU)
    with pytest.raises(AssertionError, match="not part of the context"):   # pair 3 -> 3 does not exist in M
        ctx.node_inputs(torch.tensor([3]), torch.tensor([3]), torch.zeros(1, 5), exclude=True)


# ------------------------------------------------------------------ aggregation simulator
def test_bucket_mapping_policy() -> None:
    m1 = bucket_mapping(10, 1, 7)
    assert m1.tolist() == list(range(10))
    m4 = bucket_mapping(10, 4, 7)
    assert np.array_equal(m4, bucket_mapping(10, 4, 7))          # deterministic, shared
    assert sorted(np.bincount(m4).tolist()) == [2, 4, 4] and m4.max() == 2
    assert not np.array_equal(m4, bucket_mapping(10, 4, 8))
    assert level_name(1) == "native_identity_baseline" and level_name(8) == "merge_factor_8"


def test_structure_and_neighbourhood_metrics() -> None:
    src, dst = np.array([0, 0, 1, 2, 3]), np.array([1, 1, 2, 3, 0])
    s = structural_metrics(src, dst, 4)
    assert s["active_nodes"] == 4 and s["unique_directed_pairs"] == 4 and s["self_loop_flows"] == 0
    assert s["weakly_connected_components"] == 1
    mp = np.array([0, 0, 1, 1])
    a = structural_metrics(mp[src], mp[dst], 2)
    assert a["self_loop_flows"] == 3 and a["active_nodes"] == 2
    assert neighborhood_change(src, dst, np.arange(4), 4)["mean_jaccard"] == 1.0
    # bucket-mates 0 and 2 have different neighbours: node 0's mapped neighbourhood {1} vs bucket's {1, 2}
    s6, d6 = np.array([0, 2, 4]), np.array([1, 3, 5])
    nc = neighborhood_change(s6, d6, np.array([0, 1, 0, 2, 3, 4]), 6)
    assert 0 < nc["mean_jaccard"] < 1.0 and nc["fraction_unchanged"] < 1.0


# ------------------------------------------------------------------ GraphSAGE variants
def test_identity_free_is_permutation_invariant() -> None:
    torch.manual_seed(0)
    E = _toy_edges()
    model = EdgeGraphSAGE(4 + 10, 5, 3, hidden=16, layers=2, dropout=0.0).eval()
    perm = torch.randperm(12)
    out = []
    for mapping in (None, perm):
        ctx = Context([E], 12, CPU, mapping)
        s = E.src if mapping is None else perm[E.src]
        d = E.dst if mapping is None else perm[E.dst]
        h0, ei = ctx.node_inputs(E.src[:20], E.dst[:20], E.x[:20], exclude=True)
        out.append(model(h0, ei, s[:20], d[:20], E.x[:20]))
    assert torch.allclose(out[0], out[1], atol=1e-5)


def test_standard_variant_has_identity_parameters() -> None:
    std = EdgeGraphSAGE(14, 5, 3, num_nodes=12, emb_dim=4)
    free = EdgeGraphSAGE(14, 5, 3)
    assert not std.identity_free and free.identity_free
    assert not any("emb" in n for n, _ in free.named_parameters())
    b = std.bucket_embeddings(torch.tensor([0, 0, 1] * 4), 2)
    assert torch.allclose(b[0], std.emb.weight[torch.tensor([0, 1, 3, 4, 6, 7, 9, 10])].mean(0))


def test_gnn_end_to_end(synth: Path, tmp_path: Path) -> None:
    from src.training.gnn import GraphData, run_variant

    cfg = {"processed_dir": str(synth), "model": {"hidden": 16, "layers": 2, "dropout": 0.1, "emb_dim": 4},
           "train": {"max_epochs": 2, "patience": 1, "batch_size": 128, "cap_per_fine_label_per_epoch": 200,
                     "lr": 0.01, "weight_decay": 0.0, "eval_batch_size": 64},
           "aggregation": {"seed": 1, "levels": [1, 2, 4]}}
    exp = {"name": "t", "scheme": "primary", "target": "family", "feature_set": "default"}
    gd = GraphData(cfg, exp, CPU)
    for variant, agg in (("identity_free", None), ("standard", None),
                         ("identity_free", {"lambda1": 1.0, "lambda2": 1.0, "train_levels": [2], "unseen_levels": [4]})):
        out = tmp_path / f"{variant}_{bool(agg)}.json"
        r = run_variant(gd, variant, [0], out, tmp_path / "m", agg, tag=f"{variant}_{bool(agg)}")
        assert set(r["seeds"][0]["robustness"]) == {"native_identity_baseline", "merge_factor_2", "merge_factor_4"}
        assert set(r["seeds"][0]["native_modes"]) == {"cumulative", "period_only", "prior_only"}
        assert json.loads(out.read_text())["identity_free"] == (variant == "identity_free")
        pr = pd.read_parquet(tmp_path / "m" / f"{variant}_{bool(agg)}_test_predictions_seed0.parquet")
        from src.evaluation.metrics import evaluate
        ev = evaluate(pr["y_true"].to_numpy(), pr["y_pred"].to_numpy(), r["classes"])
        assert ev["overall"]["macro_f1"] == pytest.approx(r["seeds"][0]["native_modes"]["cumulative"]["overall"]["macro_f1"])
