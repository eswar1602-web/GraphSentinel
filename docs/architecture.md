# GraphSentinel architecture

```
 raw CICIDS2017 CSVs (read-only, SHA-256 manifest)
        │  src/preprocessing  (Milestone 1, contract v1.1)
        ▼
 data/processed/v1: flows.parquet · metadata.parquet · schemes/{primary,dayholdout}/(transforms, schemas, label maps)
        │                                   │
        │ src/preprocessing/dataset.py      │ src/graph_builder/graph.py
        ▼                                   ▼
 RF / XGBoost (src/training/baselines.py)   endpoint graph + split-aware Context (C = M \ B)
        │                                   │ src/augmentation/aggregation.py (merge factors, one seeded mapping)
        │                                   ▼
        │                          GraphSAGE identity-free / standard, aggregation-aware (src/training/gnn*.py)
        ▼                                   ▼
 src/evaluation/metrics.py  (same metrics + §6.5 views for every model)
        ▼
 experiments/results/**.json  ──► src/evaluation/report.py ──► reports/results/RESULTS.md + figures
        │
        ▼
 FastAPI (src/api) + SQLite (experiment index, detections, audit_log) ◄── HMAC hash chain (src/cryptography)
        ▼
 React dashboard (frontend/, Vite + Plotly + Cytoscape.js), served by FastAPI from frontend/dist
```

## Modules
| path | milestone | role |
|---|---|---|
| `src/preprocessing/` | 1 | audit, cleaning, labels, timestamps, splits, train-only transforms, streamed loader |
| `src/training/baselines.py` | 2 | RF and XGBoost: class-capped sample, sqrt-balanced weights, val-tuned grid, 3 seeds |
| `src/graph_builder/graph.py` | 3 | node index from identity strings, `EdgeSet`, `Context` (exact target-edge exclusion), PyG export |
| `src/training/gnn_model.py`, `gnn.py` | 4, 6, 7 | GraphSAGE edge classifier, training, context modes, robustness sweep, multi-view loss |
| `src/augmentation/aggregation.py` | 5 | bucket mapping policy, structural metrics, neighbourhood change |
| `src/evaluation/` | 5–7, 10 | shared metrics, structure analysis, results report |
| `src/cryptography/audit_log.py` | 8 | SHA-256 chain and HMAC-SHA256, verify, tamper demo |
| `src/api/` | 9 | FastAPI routes, detection service, SQLite, results views, sample builder |
| `frontend/` | 9 | dashboard with 8 sections; every value is fetched from the API |

## Design decisions made during implementation
- **Graph size.** The CICIDS2017 graph has 19,129 endpoint nodes but 2.8M flow edges. GraphSAGE runs on the node-level
  pair graph (113,769 unique directed pairs), with node inputs built from sufficient statistics of the context edges:
  degree, distinct neighbours, and mean incoming and outgoing edge features. Target-edge exclusion subtracts each batch's
  contributions exactly. A test checks the result against rebuilding the context without those edges.
- **Memory.** About 4 GB of RAM was free during development, so `load_split` streams parquet record batches. Each
  batch is transformed in float64 exactly as before, and only the requested split's rows are kept, as float32. A test
  checks that the results are identical to the original loader.
- **Standard vs identity-free GraphSAGE.** The standard variant adds `nn.Embedding(num_nodes, 32)`. Under synthetic
  aggregation, a bucket's embedding is the mean of its members' embeddings. The identity-free variant satisfies
  contract §6.5 (a)–(d), and a test checks that its predictions are invariant to node-id permutation.
- **Aggregation-aware training.** The loss is L = CE(native) + λ1·symKL(native, aggregated) + λ2·CE(aggregated).
  The aggregated view uses a merge factor drawn from {2, 4, 8} per batch. 16 and 32 are never used in training.
- **Tabular models and aggregation.** RF and XGBoost use no endpoint identity, so their inputs are identical at every
  aggregation level. They are reported as invariant by construction, not re-run.
- **Detection endpoint.** It uses the saved XGBoost model of `primary_family_default` (no Destination Port) and the
  Milestone 1 correction code. Negative-duration records are reported as `invalid_record` and not scored.
