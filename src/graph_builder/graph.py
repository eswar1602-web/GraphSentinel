"""Split-aware flow graph construction (contract v1.1 §6).

Nodes are endpoints (IP strings), mapped to ids from identity strings only (no labels, no features).
Each flow is a directed edge src -> dst carrying its flow_uid, its scaled feature vector x_e and its labels.

Context graph and target-edge exclusion (§6.2):
  A ``Context`` holds the message-passing edge set M of one phase/mode as *sufficient statistics*:
  per-node sums and counts of incident edge features (in/out) and per-(src,dst)-pair multiplicities.
  For a target batch B, ``Context.node_inputs(B)`` returns node inputs and a message-passing graph computed
  from C = M \\ B exactly, by subtracting B's contributions (only if the batch belongs to M). So a target
  flow never contributes its own features, existence or degree to the embeddings used to predict it.

Node input features (a function of C only; identity-free by construction, §6.5 (c)):
  [log1p out-degree, log1p in-degree, log1p distinct out-neighbours, log1p distinct in-neighbours,
   mean outgoing edge features (F), mean incoming edge features (F)]
Message-passing graph: every (src,dst) pair with multiplicity > 0 in C, in both directions.
Labels are never used as inputs.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import numpy as np
import pandas as pd
import pyarrow.parquet as pq
import torch

from src.preprocessing.dataset import load_split

META_COLS = ("flow_uid", "src_ip", "dst_ip", "timestamp", "label_fine", "label_family", "label_binary",
             "dominant_pair_directed", "dominant_pair_undirected")


def build_node_index(processed_dir: str | Path) -> np.ndarray:
    """Sorted unique endpoint strings over all kept flows. Node id = position. Uses identity strings only."""
    t = pq.read_table(Path(processed_dir) / "metadata.parquet", columns=["src_ip", "dst_ip"])
    names = np.unique(np.concatenate([t.column(0).to_numpy().astype(str), t.column(1).to_numpy().astype(str)]))
    return names


@dataclass
class EdgeSet:
    """Flows of one split as graph edges (row order identical to load_split, i.e. to metadata order)."""
    split: str
    src: torch.Tensor          # int64 node ids
    dst: torch.Tensor
    x: torch.Tensor            # float32 [n, F] (CPU)
    y: torch.Tensor            # int64 labels for the chosen target
    flow_uid: np.ndarray
    meta: pd.DataFrame
    columns: list[str] = field(default_factory=list)

    def __len__(self) -> int:
        return int(self.src.shape[0])

    def subset(self, mask: np.ndarray) -> "EdgeSet":
        m = torch.from_numpy(mask)
        return EdgeSet(self.split, self.src[m], self.dst[m], self.x[m], self.y[m], self.flow_uid[mask],
                       self.meta.loc[mask].reset_index(drop=True), self.columns)


def load_edges(processed_dir: str | Path, scheme: str, split: str, node_names: np.ndarray, feature_set: str = "default",
               target: str = "family", row_filter: np.ndarray | None = None,
               extra_meta: tuple[str, ...] = ()) -> EdgeSet:
    sd = load_split(processed_dir, scheme, split, feature_set, "scaled", target,
                    tuple(dict.fromkeys((*META_COLS, *extra_meta))), row_filter)
    cat = pd.CategoricalDtype(categories=node_names, ordered=True)
    src = pd.Series(sd.meta["src_ip"].astype(str)).astype(cat).cat.codes.to_numpy()
    dst = pd.Series(sd.meta["dst_ip"].astype(str)).astype(cat).cat.codes.to_numpy()
    if (src < 0).any() or (dst < 0).any():
        raise AssertionError("endpoint missing from node index")
    return EdgeSet(split, torch.from_numpy(src.astype("int64")), torch.from_numpy(dst.astype("int64")),
                   torch.from_numpy(sd.X), torch.from_numpy(sd.y), sd.flow_uid, sd.meta, sd.columns)


class Context:
    """Sufficient statistics of a message-passing edge set M (optionally in an aggregated node space)."""

    def __init__(self, parts: list[EdgeSet], num_nodes: int, device: torch.device,
                 mapping: torch.Tensor | None = None, chunk: int = 262_144) -> None:
        self.num_nodes, self.device = num_nodes, device
        self.mapping = mapping.to(device) if mapping is not None else None
        self.splits = {p.split for p in parts}
        F = parts[0].x.shape[1]
        N = num_nodes
        self.out_sum = torch.zeros(N, F, device=device, dtype=torch.float64)
        self.in_sum = torch.zeros(N, F, device=device, dtype=torch.float64)
        self.out_cnt = torch.zeros(N, device=device, dtype=torch.float64)
        self.in_cnt = torch.zeros(N, device=device, dtype=torch.float64)
        keys = []
        for p in parts:
            for s in range(0, len(p), chunk):
                src, dst = self.map(p.src[s:s + chunk].to(device)), self.map(p.dst[s:s + chunk].to(device))
                x = p.x[s:s + chunk].to(device, dtype=torch.float64)
                self.out_sum.index_add_(0, src, x)
                self.in_sum.index_add_(0, dst, x)
                one = torch.ones_like(src, dtype=torch.float64)
                self.out_cnt.index_add_(0, src, one)
                self.in_cnt.index_add_(0, dst, one)
                keys.append(src * N + dst)
        k = torch.cat(keys)
        self.pair_key, self.pair_cnt = torch.unique(k, return_counts=True)   # sorted keys
        self.pair_src, self.pair_dst = self.pair_key // N, self.pair_key % N
        self.n_edges = int(k.numel())

    def map(self, ids: torch.Tensor) -> torch.Tensor:
        return self.mapping[ids] if self.mapping is not None else ids

    def node_inputs(self, src: torch.Tensor | None = None, dst: torch.Tensor | None = None,
                    x: torch.Tensor | None = None, exclude: bool = True) -> tuple[torch.Tensor, torch.Tensor]:
        """Node inputs h0 [N, 4+2F] and edge_index [2, E] of C = M \\ B (B = given batch; subtracted iff exclude)."""
        out_sum, in_sum, out_cnt, in_cnt, pair_cnt = self.out_sum, self.in_sum, self.out_cnt, self.in_cnt, self.pair_cnt
        if exclude and src is not None and len(src):
            s, d = self.map(src.to(self.device)), self.map(dst.to(self.device))
            xb = x.to(self.device, dtype=torch.float64)
            one = torch.ones_like(s, dtype=torch.float64)
            out_sum = out_sum.index_add(0, s, -xb)
            in_sum = in_sum.index_add(0, d, -xb)
            out_cnt = out_cnt.index_add(0, s, -one)
            in_cnt = in_cnt.index_add(0, d, -one)
            key = s * self.num_nodes + d
            pos = torch.searchsorted(self.pair_key, key)
            pos = pos.clamp(max=len(self.pair_key) - 1)
            if not bool((self.pair_key[pos] == key).all()):
                raise AssertionError("excluded target edge is not part of the context edge set M")
            pair_cnt = pair_cnt.index_add(0, pos, -torch.ones_like(pos))
        out_cnt, in_cnt = out_cnt.clamp(min=0), in_cnt.clamp(min=0)   # guard tiny float error
        active = pair_cnt > 0
        ps, pd_ = self.pair_src[active], self.pair_dst[active]
        N = self.num_nodes
        d_out = torch.zeros(N, device=self.device, dtype=torch.float64).index_add_(0, ps, torch.ones_like(ps, dtype=torch.float64))
        d_in = torch.zeros(N, device=self.device, dtype=torch.float64).index_add_(0, pd_, torch.ones_like(pd_, dtype=torch.float64))
        out_mean = out_sum / out_cnt.clamp(min=1).unsqueeze(1)
        in_mean = in_sum / in_cnt.clamp(min=1).unsqueeze(1)
        out_mean[out_cnt < 0.5] = 0
        in_mean[in_cnt < 0.5] = 0
        h0 = torch.cat([torch.log1p(out_cnt).unsqueeze(1), torch.log1p(in_cnt).unsqueeze(1),
                        torch.log1p(d_out).unsqueeze(1), torch.log1p(d_in).unsqueeze(1), out_mean, in_mean], 1).float()
        ei = torch.stack([torch.cat([ps, pd_]), torch.cat([pd_, ps])])
        return h0, ei

    @property
    def node_dim(self) -> int:
        return 4 + 2 * self.out_sum.shape[1]


def to_pyg(context: Context):
    """PyG export of a context graph (node inputs + message-passing edges), e.g. for inspection or other GNNs."""
    from torch_geometric.data import Data

    h0, ei = context.node_inputs(exclude=False)
    return Data(x=h0, edge_index=ei, num_nodes=context.num_nodes)


def time_window_snapshots(timestamps: pd.Series, window: str = "5min") -> pd.Series:
    """Snapshot id per flow for fixed time windows (used for visualization / windowed analysis)."""
    t = pd.to_datetime(timestamps)
    return t.dt.floor(window).rank(method="dense").astype("int64") - 1
