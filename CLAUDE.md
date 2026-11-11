# GraphSentinel — Project Brief for Claude Code

> Place this file as `CLAUDE.md` in the repo root. Claude Code reads it automatically every session.

## Role

Act as a senior ML engineer, graph-learning researcher, cybersecurity engineer and software architect. Build GraphSentinel as a complete, reproducible 5th-semester end-term project for **Network Security and Cryptography** (B.Tech CSE AI/ML). Environment: Windows, PowerShell, VS Code, Git. There is NO existing starter code: build from scratch.

## Project

**Title:** Graph-Based Network Intrusion Detection and Identity-Aggregation Robustness Analysis
**Dataset:** CICIDS2017 (https://www.unb.ca/cic/datasets/ids-2017.html). Inspect real columns and labels; never assume them.
**Core idea:** Flows are directed edges between endpoint nodes (src IP -> dst IP) with flow features as edge features and a label per edge. Simulate controlled *identity aggregation* (many original identities mapped to fewer pseudonymous buckets, merge\_factor in {1,2,4,8,16,32}) and measure how graph structure and detection performance degrade. Then test whether multi-view, aggregation-aware training helps.
**Caveat to preserve everywhere:** the aggregation simulator is a controlled identity-collision stress test, NOT a faithful NAT emulator.
**Terminology (contract v1.0 §6.5):** the original CICIDS2017 data already contains real NAT-based aggregation (external attackers appear as 172.16.0.1; 99.64% of attack flows lie on 172.16.0.1 → 192.168.10.50). `merge_factor=1` is named **`native_identity_baseline`**, never "unaggregated"; merge factors > 1 are *additional synthetic* identity aggregation. The NAT endpoint concentration is a central threat to validity: every evaluation must include the four mandatory diagnostic views in `docs/dataset_contract.md` §6.5 (overall, off-dominant-pair per-attack recall, identity-free GNN, dominant vs non-dominant pair + dominant-pair ablation).

**Main research question:** Can a graph-based NIDS learn attack-discriminative representations that stay reliable when identities become less distinguishable?
**Supporting questions:** (1) effect of aggregation on graph structure; (2) effect on RF/XGBoost vs GraphSAGE; (3) does GraphSAGE behave differently; (4) do multiple graph views improve prediction consistency; (5) generalization to unseen aggregation levels.

## Pipeline phases

1. **Preprocessing** (pandas, numpy, sklearn): CSV ingestion, column-name normalization (CICIDS2017 has leading spaces and a duplicated "Fwd Header Length"), duplicate checks, NaN/inf handling (Flow Bytes/s, Flow Packets/s), label normalization (non-ASCII dash in Web Attack labels), timestamp parsing (mixed formats), src/dst identity extraction, feature-schema validation, label mapping derived from training data only, chronological and day-aware train/val/test split. Fit scalers/encoders on train only. Audit for duplicate flows, overlapping captures, temporal and identity leakage. Never use IP, Flow ID, row index or timestamp as accidental features. Document every removed feature and the split strategy with its limitations. Outputs: cleaned data, label map, feature schema, dataset stats, preprocessing metadata. Note: the "MachineLearningCVE" CSVs have no IPs; the "TrafficLabelling / GeneratedLabelledFlows" version has Flow ID, IPs and Timestamp and is required for graphs.
2. **Baselines:** Random Forest and XGBoost; tune on train/val, evaluate on held-out test, confusion matrices, per-class metrics, saved models and configs. Do not assume the GNN will win.
3. **Graph construction** (NetworkX, PyTorch Geometric): directed graphs, time-window snapshots, edge-to-flow ID preservation, label correspondence, consistent node mapping and feature dimensions, PyG export, no unnecessary global nodes, documented train/test leakage policy. Supports original and aggregated views.
4. **GraphSAGE edge classifier** (PyTorch, PyG, CUDA if verified): node embeddings via SAGEConv layers; edge representation = \[src\_emb, dst\_emb, edge\_features]; classification head; class-imbalance-aware loss, optimizer, validation, early stopping. Compare vs RF/XGBoost. Do not claim GraphSAGE alone is novel.
5. **Identity aggregation simulator:** deterministic, seeded mapping of unique endpoints to buckets; transform nodes/edges; keep flow features, labels and flow IDs; handle self-loops and duplicate edges; one shared documented mapping policy for paired views (never independent mappings); export aggregated graphs and metadata. Structural metrics: original vs aggregated node count, edge count, avg degree, degree distribution, self-loops, connected components, density, neighborhood change.
6. **Aggregation-aware learning (Level 2 research):** paired original/aggregated views, aligned via flow IDs. `L\_total = L\_cls + λ1·L\_consistency + λ2·L\_robustness`. Standard GraphSAGE baseline first; test multiple λ; ablations; evaluate on unseen aggregation levels; labels never used as inputs. This is a hypothesis: report negative results honestly and make no novelty/robustness claims without evidence.
7. **Robustness evaluation:** RF, XGBoost, standard GraphSAGE, aggregation-aware GraphSAGE across original, mild, moderate, severe and unseen aggregation. Metrics: accuracy, precision, recall, macro-F1, per-attack recall, PR-AUC, FPR, confusion matrix, inference latency, memory where feasible. Prioritize macro-F1, per-attack recall, FPR. Multiple seeds, report mean ± std. Charts: model comparison, severity vs macro-F1, severity vs FPR, per-class, confusion matrices, ablations.
8. **Cryptographic audit log** (hashlib, hmac): records = event ID, timestamp, event type, details, prev hash, current hash. `H\_i = SHA256(H\_{i-1} || CanonicalRecord\_i)` with canonical deterministic serialization and specified encoding; HMAC-SHA256 with a protected secret key (from env var / key file outside git, never in source). Demo: create, tamper, verify, detect. Document limitations: SHA-256 alone doesn't authenticate; a chain without a trusted checkpoint can be rewritten by whoever controls storage; key management caveats.
9. **Backend/Frontend:** FastAPI + SQLite (experiment metadata, results, detection history, audit records, config; no raw traffic in DB); React + Plotly + Cytoscape.js with sections: Overview, Dataset, Detection, Graph visualization, Aggregation simulator, Model comparison, Robustness, Audit verification. Dashboard is a real interface to the pipeline: NO fake or hardcoded results.

## Priorities

* **Level 1 (mandatory):** preprocessing, RF, XGBoost, graph construction, GraphSAGE edge classification, aggregation simulator, performance comparison, robustness reporting.
* **Level 2:** multi-view learning, consistency training, unseen-severity evaluation, SHA-256 audit chain, HMAC authentication.
* **Level 3 (optional, only after the rest):** live capture (Scapy), real-time detection, deployment, cross-dataset generalization, user management.

## Milestones (do ONE at a time, in order)

1. Project scaffold + reliable CICIDS2017 preprocessing and dataset contract
2. RF and XGBoost baselines with reproducible reports
3. Graph construction with validated node/edge/feature/label alignment
4. Standard GraphSAGE edge classification
5. Identity aggregation + structural analysis
6. Robustness experiments across all baseline models
7. Multi-view aggregation-aware training with consistency loss
8. Hash-chain + HMAC audit logging
9. FastAPI backend + React dashboard
10. Integration, tests, docs, end-term demo prep

For every milestone: inspect existing code; state exact requirements; explain the design BEFORE major architectural choices; implement only that milestone; run tests; fix failures before moving on; document changes; give exact commands to run and verify. Never assume code works because it was generated. Stop at the end of each milestone and wait for my go-ahead.

## Structure (improve if needed, keep modular)

```
GraphSentinel/
  configs/  data/{raw,processed,graphs}/  models/{traditional,graph,checkpoints}/
  src/{preprocessing,graph\_builder,augmentation,training,evaluation,cryptography,api}/
  frontend/  experiments/  reports/  tests/
  README.md  requirements.txt  .gitignore  CLAUDE.md
```

## Engineering standards

* Modular code, type hints, docstrings on important functions, config-driven experiments (YAML), minimal dependencies.
* Pytest unit tests for: preprocessing, identity mapping, graph construction, label alignment, model I/O shapes, aggregation transforms, audit-log creation, hash verification, HMAC verification. Integration test for the full detection pipeline.
* Reproducibility: fixed seeds, saved configs and checkpoints, dataset/preprocessing versions, recorded metrics, hardware/software versions (verify CUDA and PyTorch/PyG compatibility before using GPU).
* Security: validate uploads, never execute uploaded content, safe file handling, protect keys, commit no secrets or data (`.gitignore` data/, models, keys, .env).
* Research integrity: never invent or hardcode results, never claim a model is better without comparable evaluation, never claim novelty without evidence, document limitations, report negative results.
* Provide PowerShell commands where applicable. Don't build the frontend or GraphSAGE until data and graph foundations are validated on the real dataset.

\---

