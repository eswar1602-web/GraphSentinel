# Experiments

Specifications live here. Results are produced only by running them; nothing in this folder is a result.

| id | spec | status | question |
|---|---|---|---|
| E-PS1 | [portscan_dstport.yaml](portscan_dstport.yaml) | specified (runs from Milestone 2) | PortScan detection with vs without Destination Port, for RF, XGBoost and GraphSAGE, and under aggregation |

## Rules (from `docs/dataset_contract.md` v1.0)
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
