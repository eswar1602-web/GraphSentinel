"""GraphSAGE edge classifier (Milestone 4). GraphSAGE itself is not claimed as novel.

edge representation = [h_src, h_dst, x_e] -> MLP -> class logits, where h = SAGEConv stack over the
context graph (graph_builder.Context) and x_e is the target flow's own feature vector.

Variants (contract §6.5):
  identity_free  node inputs = Context.node_inputs only; no IP-derived inputs, no per-node parameters.
                 Predictions are invariant to node-id permutations (tested).
  standard       additionally concatenates a learned per-endpoint embedding nn.Embedding(num_nodes, emb_dim).
                 Under synthetic aggregation a bucket's embedding is the mean of its members' embeddings.
"""
from __future__ import annotations

import torch
from torch import nn
from torch_geometric.nn import SAGEConv


class EdgeGraphSAGE(nn.Module):
    def __init__(self, node_in: int, edge_in: int, n_classes: int, hidden: int = 64, layers: int = 2,
                 dropout: float = 0.2, num_nodes: int | None = None, emb_dim: int = 32) -> None:
        super().__init__()
        self.emb = nn.Embedding(num_nodes, emb_dim) if num_nodes else None
        d = node_in + (emb_dim if self.emb is not None else 0)
        self.norm = nn.LayerNorm(d)
        self.inp = nn.Linear(d, hidden)          # project first so messages are `hidden`-wide (VRAM)
        self.convs = nn.ModuleList([SAGEConv(hidden, hidden, aggr="mean") for _ in range(layers)])
        self.drop = nn.Dropout(dropout)
        self.head = nn.Sequential(nn.Linear(2 * hidden + edge_in, hidden), nn.ReLU(), nn.Dropout(dropout),
                                  nn.Linear(hidden, n_classes))

    @property
    def identity_free(self) -> bool:
        return self.emb is None

    def bucket_embeddings(self, mapping: torch.Tensor, n_buckets: int) -> torch.Tensor:
        """Mean of member-node embeddings per bucket (standard variant under synthetic aggregation)."""
        assert self.emb is not None
        w = self.emb.weight
        s = torch.zeros(n_buckets, w.shape[1], device=w.device).index_add_(0, mapping, w)
        c = torch.zeros(n_buckets, device=w.device).index_add_(0, mapping, torch.ones_like(mapping, dtype=w.dtype))
        return s / c.clamp(min=1).unsqueeze(1)

    def node_states(self, h0: torch.Tensor, edge_index: torch.Tensor, emb_table: torch.Tensor | None = None) -> torch.Tensor:
        if self.emb is not None:
            h0 = torch.cat([h0, self.emb.weight if emb_table is None else emb_table], 1)
        h = torch.relu(self.inp(self.norm(h0)))
        for conv in self.convs:
            h = self.drop(torch.relu(conv(h, edge_index)))
        return h

    def forward(self, h0: torch.Tensor, edge_index: torch.Tensor, src: torch.Tensor, dst: torch.Tensor,
                x_e: torch.Tensor, emb_table: torch.Tensor | None = None) -> torch.Tensor:
        h = self.node_states(h0, edge_index, emb_table)
        return self.head(torch.cat([h[src], h[dst], x_e], 1))
