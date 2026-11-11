# Findings, threats to validity and limitations

The numbers come from [reports/results/RESULTS.md](../reports/results/RESULTS.md). That file is generated from
`experiments/results/**` and reports test sets as mean ± std over 3 seeds unless noted. Primary-split and day-holdout
results are separate experiments.

## 1. Primary split (known attack types; attack family; no Destination Port)
| model | macro-F1 | FPR | off-pair macro-F1 |
|---|---|---|---|
| Random Forest | 0.773 ± 0.008 | 2.53% | 0.587 ± 0.019 |
| XGBoost | 0.766 ± 0.010 | 3.15% | 0.555 ± 0.035 |
| GraphSAGE identity-free | 0.808 ± 0.038 | 0.10% | 0.639 ± 0.097 |
| GraphSAGE standard | 0.816 ± 0.048 | 0.93% | 0.670 ± 0.107 |

GraphSAGE has higher mean macro-F1 and a much lower overall FPR. Its seed variance is about 5× larger, and with 3 seeds
the macro-F1 difference is within roughly one standard deviation, so **no significant superiority is claimed**.
Bot is the clearest per-class difference: RF and XGBoost recall 0.000, GraphSAGE recall 0.52 ± 0.41 (highly seed-dependent).

## 2. The NAT shortcut dominates the graph results (central threat to validity)
- **Dominant pair:** on the dominant pair 172.16.0.1 → 192.168.10.50, both GraphSAGE variants classify **all** benign test flows as
  attacks (FPR 100% on that pair, 54 flows, seed 0). RF has 0% FPR there.
- **Day holdout (binary, train Mon–Wed, test Thu–Fri):** standard GraphSAGE reaches macro-F1 0.997, against
  RF 0.664 and XGBoost 0.452. But its off-dominant-pair macro-F1 is 0.499, which means no attack detected off the pair,
  and its FPR on the pair is 100%. The unseen Thursday/Friday attacks (PortScan, DDoS, WebAttack) use the same NAT pair
  as the training attacks, and the per-endpoint embedding detects that pair, not the attacks. **This is a shortcut, not
  generalization.**
- **Dominant-pair ablation (1 seed):** when every 172.16.0.1 ↔ 192.168.10.50 flow is removed, identity-free GraphSAGE
  falls to macro-F1 0.250 (it predicts everything Benign). Standard GraphSAGE reaches 0.515, while RF and XGBoost reach
  0.617. Without the shortcut, the graph models are **worse** than the tabular baselines on the remaining rare attacks
  (Bot, Infiltration, Heartbleed).

## 3. Context modes (contract §6.3)
| identity-free GraphSAGE mode | macro-F1 |
|---|---|
| cumulative | 0.808 |
| prior_only | 0.783 |
| period_only | 0.142 |

When the context contains only the test-period flows, the node statistics differ strongly from training and the
model collapses. Graph-context features are therefore sensitive to which traffic the detector has observed.

## 4. Robustness to synthetic identity aggregation (primary split)
- **Tabular models:** RF and XGBoost use no endpoint identity, so they are invariant by construction (0.773 and 0.766 at
  every level).
- **Identity-free GraphSAGE:** degrades from 0.808 (native) to 0.765 (×32); its FPR rises from 0.10% to 2.6%.
- **Standard GraphSAGE:** degrades more, from 0.816 to 0.711. Averaged bucket embeddings lose identity information.
- **Structure:** at ×32 there are 598 buckets, mean neighbourhood Jaccard is 0.277, and the dominant bucket pair is
  still 99.98% attack. Synthetic collisions barely dilute the NAT pair, because its bucket-mates rarely talk to each other.

## 5. Aggregation-aware multi-view training (Level 2 hypothesis)
| λ setting | native | ×16 (unseen) | ×32 (unseen) | off-pair ×32 |
|---|---|---|---|---|
| baseline identity-free | 0.808 ± 0.038 | 0.771 | 0.765 | 0.562 |
| consistency only (λ1=1, λ2=0) | 0.807 ± 0.043 | 0.759 | 0.769 | 0.545 |
| robustness only (λ1=0, λ2=1) | 0.885 ± 0.052 | 0.827 | 0.829 | 0.691 |
| consistency + robustness (1, 1) | 0.889 ± 0.051 | 0.833 | 0.834 | 0.699 |
| strong consistency (3, 1) | 0.862 ± 0.004 | 0.831 | 0.826 | 0.669 |

- **Consistency alone gives no measurable gain.** The improvement comes from the cross-entropy term on the
  aggregated view (λ2).
- **That term also raises native performance** by a similar margin, so it most likely acts as structural data
  augmentation and regularization rather than specifically buying robustness.
- **The aggregation-aware models see two forward passes per batch**, which is more gradient signal per epoch than the
  baseline gets. This compute difference was not equalized.
- **Validation macro-F1 oscillated between epochs** (for example 0.96 ↔ 0.83). Early stopping keeps the best checkpoint.
- **Scope:** it was evaluated on the primary split only, not on the day holdout or the ablation. None of this addresses
  the NAT shortcut in §2.

## 6. E-PS1: Destination Port
| model | PortScan recall, without port | PortScan recall, with port | PortScan precision without port | PortScan precision with port |
|---|---|---|---|---|
| RF / XGBoost | 0.997 | 0.996–0.997 | 0.888 / 0.949 | 0.872 / 0.911 |
| GraphSAGE | 0.991–0.992 | 0.991–0.992 | 0.997 | 0.999 |

- **PortScan itself barely changes.** RF and XGBoost precision drops slightly *with* the port.
- **XGBoost overall macro-F1 rises with the port** (0.766 → 0.813 ± 0.044), but with large seed variance.
- **Collision counts:** without the port, 76,322 PortScan flows have an exact BENIGN twin; with it, 1,053. Even so,
  PortScan recall stays at 0.997 because the colliding vectors are dominated by PortScan rows.
- **The with-port gain is not presented as better generalization.**

## 7. Limitations
- **Dataset scope:** one dataset (CICIDS2017) with known label noise (Engelen et al., 2021). There is no cross-dataset
  validation and no live capture (Level 3 was not implemented).
- **Seeds and support:** 3 seeds; the dominant-pair ablation uses 1 seed. Rare classes have tiny test support
  (Heartbleed 2, Infiltration 6, SQL Injection inside WebAttack), so their per-class numbers are anecdotal.
- **Primary split:** not globally chronological. The `cumulative` mode allows mild unlabeled look-ahead; `prior_only`
  results are reported alongside.
- **Baseline protocol:** fitted on a class-capped subsample (≤ 150k per fine label) for the 16 GB RAM budget, with a
  small two-point hyperparameter grid per model.
- **GraphSAGE design:** GraphSAGE is not novel. The node-input design (context sufficient statistics) is one reasonable
  choice and was not ablated against alternatives.
- **Aggregation simulator:** a controlled stress test, not a NAT emulator. It uses one mapping seed (2017) and random
  uniform buckets; real NAT groups are not random.
- **Detection endpoint:** scores uploaded CICIDS-format flow CSVs offline. It is not a real-time sensor.
- **Audit log:** the HMAC key lives on the same host, there is no key rotation, and truncation detection requires an
  external checkpoint (see docs/audit_log.md).
