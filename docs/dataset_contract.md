# GraphSentinel Dataset Contract: v1.1 (APPROVED)

v1.1 (2026-11-11) adds decisions D1 (whole-minute-boundary splitting) and D2 (Destination Port headline
experiment). It also corrects the expected timestamp-correction count (1,471,487 kept rows).

History:
- v0.2 approved 2026-11-11.
- v0.3 added target-edge exclusion and split interpretation.
- v0.4 settled every audit item from the real data.
- **v1.0 (2026-11-11)** records the decisions on Q1–Q4, the identity-free model definition and the `native_identity_baseline` terminology.

Implemented by `src/preprocessing/` with `configs/preprocessing.yaml`.

Evidence:
- `reports/data_audit/audit_traffic_labelling.*`
- `reports/data_audit/audit_resolution.*`
- `data/processed/v1/preprocessing_metadata.json`

Source: CICIDS2017 `GeneratedLabelledFlows` → `TrafficLabelling/`, 8 CSVs, 85 columns, 3,119,345 parsed rows.

**Raw integrity:** SHA-256 and size of every raw CSV are recorded in `configs/raw_manifest_cicids2017.json`.
- The pipeline verifies them before running.
- It recomputes them after writing outputs and aborts if anything changed.
- Raw files are only ever opened for reading.

## 1. Row identity and removals
- `flow_uid = "<file_stem>:<raw_row>"`. `raw_row` is the 0-based data-row index in the raw CSV; file line = raw_row + 2.
  - Verified: pandas row count = data-line count in every file.
  - Every processed row, removed row and corrected cell is traceable by `flow_uid`.
  - `Flow ID` is not an identifier (§1.4).
- Removals are written to `removed_rows.parquet` (`flow_uid`, reason). The pipeline asserts each count:

| reason | rows | evidence |
|---|---:|---|
| `comma_only_row` | 288,602 | Thursday-WebAttacks: one contiguous block, file lines 170,368–EOF. Each line is byte-identical, 84 commas + CRLF. Every line in the file has 84 delimiters and the file has no quote characters, so this is not a parser artefact. The count equals the Infilteration file's row count (observation only). |
| `exact_duplicate` | 203 | Identical on all raw columns including Flow ID, IPs and Timestamp. 202 BENIGN, 1 DoS Hulk. The first copy is kept. |
| `negative_flow_duration` | 115 | All BENIGN, −1 to −13 µs. In all 115, the rates and Flow IAT Mean/Max/Min are also negative and are derived from the bad duration (recomputed packets/s matches 115/115). The whole record is invalid. |

- **Final row count: 2,830,425** (asserted).
- No other row is ever deleted for a feature anomaly (§4.2).

### 1.2 Conflicting labels
- Identical feature vectors with different labels, by feature set:

Global counts over all kept rows, from `dataset_stats.json`:

| feature set | groups | rows in groups | rows by label |
|---|---:|---:|---|
| `dstport` (with Destination Port) | 697 | 7,018 | DoS Hulk 5,223 · PortScan 1,053 · BENIGN 735 · DDoS 6 · slowloris 1 |
| `default` (no Destination Port) | 271 | **82,868** | **PortScan 76,322** · DoS Hulk 5,233 · BENIGN 1,183 · Bot 122 · DDoS 6 · slowloris 2 |

**Finding:** once Destination Port is removed, 76,322 of 158,930 PortScan flows (48%) have a feature vector identical
to at least one BENIGN flow. Port-scan probes are tiny flows that differ from routine benign flows mainly by port.
The default (no-port) feature set therefore has a much higher irreducible error floor for PortScan. Every
Destination Port ablation must be read with this in mind.

- The typical case is a large DoS Hulk cluster from 172.16.0.1 → 192.168.10.50 plus one BENIGN twin from another host.
  These are SYN-only/half-open flows.
- Across files, 663 vectors conflict.
- **No deletion, no relabeling.** `conflict_group_default` / `conflict_group_dstport` are stored in metadata (−1 = none).
  Reports describe these rows as an error floor for feature-only classifiers.

### 1.3 Identity-ignored and cross-file duplicates
- 33,548 vectors (139,720 rows) recur across files.
  - All are BENIGN and small (median 4 packets), mostly DNS.
  - They have different Flow IDs and timestamps.
- Kept. Per scheme, `train_dup_<scheme>` flags val/test rows whose default-set vector occurs in train.
- Reports include a de-duplicated test evaluation.

### 1.4 Flow ID
- Flow ID is not unique:
  - Both directions share one Flow ID.
  - IDs are reused within and across files (150,961 appear in more than one file).
  - 35,778 (summed over files) carry more than one label.
- Kept as metadata only. Never a key or a feature.

## 2. Labels
| column | content |
|---|---|
| `label_raw` | exact decoded string, never modified |
| `label_fine` | explicit table, `src/preprocessing/labels.py` |
| `label_family` | **primary multiclass target** |
| `label_binary` | 0 benign / 1 attack |

- **Families:** Benign, DoS, DDoS, PortScan, Bot, WebAttack, BruteForce, Infiltration, Heartbleed. All 15 raw labels are mapped.
- **Encoding:** Thursday-WebAttacks is cp1252. Its byte 0x96 is U+2013 (en dash), and UTF-8 decoding fails at byte 5,003,134.
  The other files decode as UTF-8. **No U+FFFD exists anywhere.**
- **Lookup key** folds only whitespace, dash variants and letter case.
  - U+FFFD is never folded.
  - Any unmapped label raises `UnknownLabelError` and aborts the run.
- **Label maps** are derived from each scheme's train split only. Classes absent from train are listed, never dropped.
- **Rare classes are never discarded:** Heartbleed 11, SQL Injection 21, Infiltration 36.

## 3. Timestamps
- `timestamp_raw` is preserved verbatim. `timestamp` is the parsed value; `timestamp_corrected` is a bool per row.
- **Format:** d/m/Y. Monday includes seconds; the other seven files have minute resolution.
- **12-hour clock without AM/PM; correction hours 1–5 → +12.** Evidence:
  1. No hour 0, 6, 7 or 13–23 exists anywhere. "Afternoon" files contain only hours 1–5.
  2. Afternoon attacks match the published UNB schedule only after correction:

| attack | +12h | published |
|---|---|---|
| DDoS | 15:56–16:16 | 15:56–16:16 |
| Heartbleed | 15:12–15:32 | 15:12–15:32 |
| Infiltration | 14:19–15:45 | 14:19–15:45 |

     Raw times: 0% inside the published windows.
  3. Morning attacks match without correction.
  4. Corrected day ranges are 08:42–17:10.
- **Expected corrections: 1,471,487 kept rows** (asserted). Over all 2,830,743 non-empty rows the figure is 1,471,716;
  229 of the 318 removed rows (§1) were in hours 1–5, verified per file. Per-file counts and the rule are recorded in metadata.
- Any unparseable timestamp, unexpected hour, or date not matching the file's configured day aborts the run.
- File order is not chronological. All time operations sort by (timestamp, source_file, raw_row).
- **Published-schedule discrepancies (Q4, approved):**
  - Attack rows outside their published window ±5 min get `outside_published_window = True`. The column is `<NA>` for benign rows.
  - Counts per class are reported.
  - **Labels are never changed** on the basis of the schedule.

## 4. Features
### 4.1 Columns
- **Never features:** Flow ID, Source IP, Source Port, Destination IP, Timestamp, Label, `flow_uid`, row index, file/day.
- **`Fwd Header Length.1` is dropped**, verified identical to `Fwd Header Length` on every row of every file.
  The pipeline re-checks this per file and aborts on any difference.
- **`Destination Port`** is excluded from the `default` feature set and included in the `dstport` ablation set.
  - Both sets share splits, transforms and `flow_uid`.
  - Selection is a config flag (`features.feature_sets`).
- `Protocol` is kept.
- **Constant columns** are those constant in each scheme's train split. They are dropped and recorded in `feature_schema_*.json`.

### 4.2 Value corrections (Q2, approved)
Every changed cell is logged to `corrections.parquet` (flow_uid, column, **raw value**, new value, rule). Rows are never
deleted for these anomalies.

| rule | columns | treatment | indicator feature |
|---|---|---|---|
| `nonfinite_rate_to_missing` | Flow Bytes/s, Flow Packets/s | NaN/±inf → missing | `flow_duration_zero` |
| `clip_negative_iat_to_zero` | Flow IAT Min, Fwd IAT Min | negative → 0 | `iat_negative_clipped` |
| `overflow_to_missing` | Fwd/Bwd Header Length, min_seg_size_forward | values ≤ −65,536 → missing | `header_len_invalid` |
| `invalid_negative_to_missing` | same columns | negatives above −65,536 → missing | `header_len_invalid` |

- **Non-finite rates:** verified that they occur exactly on the 2,867 rows with Flow Duration = 0, and asserted.
- **IAT clipping:** jitter of −1 to −13 µs. Fwd IAT Min (17 rows) is included under the approved "IAT-type negatives" rule.
- **Header overflow:** e.g. −83,885,125 and −32,212,234,632.
- **Small invalid negatives:** for example the single Wednesday row with Fwd Header Length −11 and min_seg_size_forward −1.
  These are impossible values, but not overflow-sized.
- **`Init_Win_bytes_forward/backward = −1` is preserved as a sentinel.**
- **Post-correction invariant (asserted):** no infinities, and no negative value anywhere except the −1 sentinels.
- Missing values are imputed with **train medians only**, at load time, via `transforms.json`.

### 4.3 Train-only transforms
Each scheme fits `transforms.json` on its train split only. The fitted parameters are:
- the constant filter
- medians
- train mean and standard deviation of signed-log1p values

Two representations:
- `raw`: imputed, float32, for tree models
- `scaled`: imputed → sign(x)·log1p(|x|) → standardized, float32

Parameters are stored as JSON, not pickles. Every partition is validated against the same ordered schema: same columns, same
order, float32, all finite.

## 5. Splits
### 5.1 Primary `split_primary` (Q1, approved)
- **Assignment:** within each (day, `label_fine`) group, rows are sorted by time and cut by rank 70/15/15 into
  train/val/test. Every split of every group gets at least one row.
- **Purge gap:** applies to groups with ≥ 100 eligible flows.
  - At each cut, `t_cut` is the timestamp of the first row of the later split. Earlier-split rows with
    timestamp ≥ `t_cut` − 60 s get split `purged`.
  - Guarantee (tested): min(later) − max(earlier) > 60 s at the recorded resolution.
  - Purged rows stay in metadata and are excluded from all splits.
- **Groups below 100 flows** get no purge gap and `purge_status = no_purge_gap`. This means **weaker temporal
  protection** for rare classes: adjacent flows of one short attack burst can fall on both sides of a cut. Reports state this.
- **Whole-minute-boundary fallback (decision D1, approved).** This applies when purging would empty a split. On the
  real data that happens for dense bursts recorded at minute resolution: PortScan (44,410 flows at 14:55) and DoS GoldenEye.
  - Each split consists of whole timestamp minutes in chronological order.
  - At each cut, **one entire boundary minute is dropped**: split `purged`, status `boundary_minute_dropped`.
  - No recorded minute is shared between train, val and test, and min(later) − max(earlier) > 60 s.
  - Boundary minutes come from an exhaustive, deterministic search minimizing Σⱼ |nⱼ/n − fⱼ| + n_dropped/n (ties go to the
    earliest). **Exact 70/15/15 ratios are not forced.**
  - Realized ratios and dropped counts are written per group to `split_stats.json → group_splits`. Tests check minute
    disjointness for these groups on both synthetic and real data.
  - Only if fewer than 2k − 1 distinct minutes exist does a group fall back to a rank-only cut (`purge_infeasible`).
    No real group needs this.
- Per-class split counts, purge status and time ranges are in `schemes/primary/split_stats.json`.
- **Interpretation:**
  - It is chronological **within** groups, **not globally across classes or days**.
  - It measures in-distribution detection of known attack types, not forecasting and not zero-day detection.

### 5.2 Secondary `split_dayholdout` (binary)
- Train/val come from Monday–Wednesday: time-ordered 85/15 within (day, label_fine), same purge rule.
- Test is all of Thursday and Friday.
- It is globally chronological between train and test, and its test attack types are unseen in train.
- It is a generalization experiment and is **reported independently** of the primary split, never pooled.

### 5.3 Leakage reporting (both schemes)
- `train_dup_<scheme>` (exact default-set vector seen in train)
- counts of val/test rows whose endpoint was unseen in train
- dominant-pair counts per split (§6.5)

## 6. Graph leakage policy (implemented from Milestone 3)
### 6.1 Target-edge features vs graph-context features
- Input for a target flow `e = (u → v)`: `[h_u, h_v, x_e]`.
- `x_e` is exactly the per-flow feature vector that RF and XGBoost receive.
- `h_u` and `h_v` come from message passing over a context set `C(e)` of **other** flows.

### 6.2 Target-edge exclusion (all phases and modes)
- `e ∉ C(e)`. Targets are processed in disjoint, seeded batches `B`, with context `C = M \ B`.
- Node statistics are computed on `C`.
- Labels are never message-passing inputs.
- Ablation `exclude_same_flow_id` also removes context edges that share the target's Flow ID.

### 6.3 Modes
| mode | val context `M` | test context `M` | intent |
|---|---|---|---|
| `cumulative` (default) | train ∪ val | train ∪ val ∪ test | detector has seen all unlabeled traffic so far |
| `period_only` (stricter) | val | test | no cross-split context |
| `prior_only` (strictly causal) | train | train ∪ val | no same-split context |

- Training always uses `M = train` with exclusion. Weights are frozen for val and test. Test never affects early stopping
  or tuning.
- `cumulative` relies on these assumptions: unlabeled traffic in the period was passively observed; val/test labels are never
  used; and, under the primary split, mild unlabeled look-ahead is possible (§5.1). Results are reported in all three modes.

### 6.4 Nodes
- The endpoint→id map is built from identity strings only.
- Endpoints first seen in val/test are kept and reported.
- Self-loops and parallel edges are kept, one edge per flow.

### 6.5 NAT endpoint concentration: central threat to validity (Q3, approved)
**Evidence:**
- 172.16.0.1 is the firewall's NAT address for the external attackers (published attackers 205.174.165.73 and DDoS .69/.70/.71).
- **99.64% of all attack flows lie on the directed pair 172.16.0.1 → 192.168.10.50, and 99.98% of the 555,764 flows on
  that pair are attacks.**
- Endpoint context alone therefore nearly determines the label. A high score on the original graph can come from an
  identity or topology shortcut rather than learned attack behaviour.
- The data is **not** modified.

Metadata flags: `dominant_pair_directed` and `dominant_pair_undirected`. The pair is configured in `diagnostics.dominant_pair`,
and its train attack share is recomputed and recorded per scheme.

**Mandatory diagnostic views** for every model (RF, XGBoost, GraphSAGE, aggregation-aware), in every robustness and
day-holdout report:
1. **Standard overall evaluation.**
2. **Per-attack recall on flows outside the dominant pair** (`dominant_pair_directed == False`).
   Classes with too little off-pair support are flagged low-support.
3. **Identity-free GNN** (definition below), reported alongside the standard GNN.
4. **Dominant-pair vs non-dominant-pair evaluation**, as separate metric tables on the same test set.
   - **Dominant-pair ablation:** retrain and evaluate with all `dominant_pair_undirected` flows removed from train, val
     and test, as message-passing context and as targets.
   - Splits are unchanged otherwise.
   - Results are reported as a separate experiment with its own class counts. Families with no remaining support
     (e.g. DDoS, PortScan) are listed as "not evaluable", not silently dropped.

**Identity-free GNN definition.** A model is identity-free if and only if:
- (a) Node input features contain no information derived from IP strings: no octets, subnet bits, hashes, one-hot
  ids or "is internal" flags.
- (b) There are no endpoint-specific learned parameters: no `nn.Embedding(num_nodes, ·)`, no learnable per-node vectors,
  no node-id positional encodings.
- (c) Initial node features are a constant vector or a function of the context graph `C` only (e.g. in/out degree,
  number of distinct neighbours, aggregates of incident edge features), computed under target-edge exclusion (§6.2).
- (d) Node ids are used only as indices for adjacency.
- **Test:** predictions are invariant, up to floating-point tolerance, to a random permutation of node ids.

Legitimate graph topology and all flow features are kept. Identity-free does **not** remove structure, so the dominant
node's structural fingerprint (for example its extreme degree) can still act as a shortcut. That is why views 2 and 4 are
mandatory in addition to view 3.

**`native_identity_baseline`.** The original dataset already contains real NAT-based identity aggregation. The
aggregation level `merge_factor = 1` is therefore named **`native_identity_baseline`** in every config, table and
figure. Merge factors > 1 add **synthetic** identity aggregation on top of it. merge_factor = 1 must never be described
as an un-aggregated network. The simulator remains a controlled identity-collision stress test, not a NAT emulator.

## 7. Evaluation reporting rules
- **Kept separate:** identity-aggregation robustness (primary split, `native_identity_baseline` vs synthetic merge
  factors) and day-holdout generalization.
- **Every result reports:**
  - the four §6.5 views
  - per-split class distribution
  - the train imbalance ratio
  - per-class support with low-support flags (< 30 per split)
  - groups without a purge gap
- **Recorded with every experiment:** seeds, configs (with hash), raw-file SHA-256, `data_version`, code hashes and package versions.

## 8. Outputs (`data/processed/v1/`)
| file | content |
|---|---|
| `flows.parquet` | `flow_uid` + corrected, not yet imputed, numeric features + 3 indicators |
| `metadata.parquet` | `flow_uid`, source_file, raw_row, day, identities, `timestamp_raw` / `timestamp` / `timestamp_corrected`, 4 label levels, dominant-pair flags, `outside_published_window`, conflict groups, `split_*`, `purge_status_*`, `train_dup_*` |
| `removed_rows.parquet`, `corrections.parquet` | row-level audit trail |
| `schemes/{primary,dayholdout}/` | `transforms.json`, `feature_schema_{default,dstport}.json`, `label_map.json`, `split_stats.json` |
| `dataset_stats.json`, `preprocessing_metadata.json` | config + hash, code hashes, raw hashes, count checks, timestamp-correction record, correction summary, versions |

Model-ready arrays are loaded with `src.preprocessing.dataset.load_split(...)`, which returns X, y, flow_uid and metadata.

## 9. Decisions D1 and D2 (approved 2026-11-11)
- **D1:** whole-minute-boundary splitting for purge-infeasible bursts (§5.1).
- **D2: Destination Port comparison promoted to the headline experiment E-PS1** (`experiments/portscan_dstport.yaml`).
  - Destination Port **stays excluded from the default feature set**.
  - E-PS1 reports PortScan, and every class, with and without the port:
    - per-class precision, recall and F1
    - macro-F1, FPR and confusion matrices
    - RF, XGBoost and GraphSAGE (standard and identity-free)
    - `native_identity_baseline` and synthetic merge factors
    - the §6.5 views
  - Exact cross-label feature-collision counts for both configurations are produced by preprocessing:
    `dataset_stats.json → label_collisions` (global) and `schemes/<scheme>/feature_collisions.json` (val/test vectors that
    occur in train with another label).
  - **Interpretation:** Destination Port is a legitimate flow feature, but in CICIDS2017 it may encode dataset-specific
    attack signatures, such as the fixed scanner and victim ports of one attacker setup. A better with-port score
    must **not** be presented as better generalization unless it holds off the dominant pair, under the day-holdout split
    and under aggregation.
