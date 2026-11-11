# Experiments

Specifications and configs live here and in `configs/`. Results are produced only by running them; `results/` holds
the JSON written by the runs, and [reports/results/RESULTS.md](../reports/results/RESULTS.md) is generated from it.

| id | config | status | question |
|---|---|---|---|
| primary_family_default | `configs/baselines.yaml`, `configs/gnn.yaml` | done (RF, XGB, GraphSAGE ×2, 3 seeds) | known-attack detection, primary split |
| E-PS1 / primary_family_dstport | [portscan_dstport.yaml](portscan_dstport.yaml) | done (RF, XGB, GraphSAGE ×2, 3 seeds) | PortScan with vs without Destination Port |
| dayholdout_binary_default | `configs/baselines.yaml`, `configs/gnn.yaml` | done (RF, XGB, GraphSAGE ×2, 3 seeds) | generalization to unseen days and attack types |
| dayholdout_binary_dstport | `configs/baselines.yaml` | done (RF, XGB, 3 seeds) | same, with Destination Port |
| dominant-pair ablation | both configs | done (1 seed, by design) | performance without the NAT shortcut (contract §6.5 view 4) |
| robustness sweep | `configs/gnn.yaml` | done (merge factors 1–32) | effect of identity aggregation |
| aggregation-aware | `configs/gnn.yaml` → `aggregation_aware` | done (4 λ settings, 3 seeds) | does multi-view consistency training help? |

## Rules (from `docs/dataset_contract.md` v1.1)
- **Reporting separation:** identity-aggregation robustness (primary split) and day-holdout generalization are reported separately.
- **Aggregation naming:** `merge_factor = 1` is the **`native_identity_baseline`**. The original data already contains NAT
  aggregation (172.16.0.1). Higher merge factors are additional *synthetic* aggregation, a controlled
  identity-collision stress test and not a NAT emulator.
- **Mandatory views:** every evaluation includes the four views of §6.5:
  1. overall
  2. per-attack recall off the dominant pair
  3. the identity-free GNN
  4. dominant vs non-dominant pair, plus the dominant-pair ablation
- **Low-support classes:** rare classes (Heartbleed, Infiltration, SQL Injection) and groups with weaker temporal
  protection (`no_purge_gap`) are flagged in every table.
