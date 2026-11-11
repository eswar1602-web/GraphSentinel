# GraphSentinel

Graph-based network intrusion detection on CICIDS2017 and an identity-aggregation robustness study.
The aggregation simulator is a **controlled identity-collision stress test, not a NAT emulator**.

Status: **Milestones 1–10 are implemented and evaluated on the real dataset.**
- Preprocessing follows [the dataset contract v1.1](docs/dataset_contract.md).
- Models: RF and XGBoost baselines, standard and identity-free GraphSAGE, and aggregation-aware multi-view GraphSAGE.
- Robustness is evaluated across aggregation levels.
- A SHA-256 + HMAC audit log, a FastAPI backend and a React dashboard are included.
- **Results:** [reports/results/RESULTS.md](reports/results/RESULTS.md), generated from the result files.
- **Architecture:** [docs/architecture.md](docs/architecture.md). **Audit log:** [docs/audit_log.md](docs/audit_log.md).

Experiment specifications are in [experiments/](experiments/README.md). The headline experiment E-PS1 compares PortScan
detection with and without Destination Port; the port is excluded by default.

> **Threat to validity: NAT endpoint concentration.** In the original data, external attackers appear behind the
> firewall NAT address 172.16.0.1. 99.64% of all attack flows lie on the single pair 172.16.0.1 → 192.168.10.50.
> The original data is therefore the **`native_identity_baseline`** (merge_factor = 1), not an un-aggregated network.
> Higher merge factors add *synthetic* aggregation on top of it. Every evaluation reports the four diagnostic views in
> contract §6.5.

## 1. Environment (Windows PowerShell)

```powershell
cd C:\Users\eswar\Music\GraphSentinel
powershell -ExecutionPolicy Bypass -File scripts\setup_env.ps1   # creates .venv (Python 3.12), installs, freezes lock file
.venv\Scripts\Activate.ps1
python -m pytest -q
```

The venv uses Python 3.12, not the system 3.14, because PyTorch and PyG wheels are more reliably available for it.
Exact versions are in `requirements-lock.txt`, and hardware/software info is in `reports/environment.json`.

## 2. Get CICIDS2017

1. Open https://www.unb.ca/cic/datasets/ids-2017.html and click **Download this dataset**. UNB asks for a short registration form and then shows the download index.
2. From the `CSVs/` folder, download:
   - **`GeneratedLabelledFlows.zip`** (required): extracts to `TrafficLabelling/` and has `Flow ID`, `Source IP`, `Destination IP`, `Timestamp`. Graphs need these columns.
   - `MachineLearningCSV.zip` (optional): extracts to `MachineLearningCVE/`. It has no identities and is used only for cross-checking.
3. Extract so the layout is:

```
data/raw/CICIDS2017/
  TrafficLabelling/
    Monday-WorkingHours.pcap_ISCX.csv
    Tuesday-WorkingHours.pcap_ISCX.csv
    Wednesday-workingHours.pcap_ISCX.csv
    Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv
    Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv
    Friday-WorkingHours-Morning.pcap_ISCX.csv
    Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv
    Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv
  MachineLearningCVE/          (optional)
```

```powershell
New-Item -ItemType Directory -Force data\raw\CICIDS2017 | Out-Null
Expand-Archive "$env:USERPROFILE\Downloads\GeneratedLabelledFlows.zip" -DestinationPath data\raw\CICIDS2017
Expand-Archive "$env:USERPROFILE\Downloads\MachineLearningCSV.zip"     -DestinationPath data\raw\CICIDS2017   # optional
Get-ChildItem -Recurse data\raw\CICIDS2017 -Filter *.csv | Select-Object FullName, @{n='MB';e={[math]::Round($_.Length/1MB,1)}}
```

If the zip extracts to an extra nested folder, move the CSVs so they match the layout above. `data/` is git-ignored.

## 3. Audit the raw data (read-only)

```powershell
python -m src.preprocessing.audit --raw-dir data\raw\CICIDS2017\TrafficLabelling --name traffic_labelling
python -m src.preprocessing.audit --raw-dir data\raw\CICIDS2017\MachineLearningCVE --name ml_cve   # optional
```

Then run the focused audit-resolution pass (about 5 minutes, read-only):

```powershell
python -m src.preprocessing.audit_resolution --raw-dir data\raw\CICIDS2017\TrafficLabelling
python -m pytest -q          # unit tests plus real-data checks (real-data tests skip if the CSVs are absent)
```

Reports are written to `reports/data_audit/audit_<name>.{md,json}` and `audit_resolution.{md,json}`.
The dataset contract is in `docs/dataset_contract.md`. The audit records exact headers, encodings, raw label strings with
non-ASCII code points, empty rows, NaN/inf and non-numeric tokens, negative values, constant columns, exact,
identity-ignored and cross-file duplicates, conflicting-label feature vectors, Flow ID repeats, IP cardinalities, and
timestamp shapes, dates and hour histograms. It does not parse timestamps or clean anything.

## 4. Preprocessing (Milestone 1)

```powershell
python -m src.preprocessing.raw_manifest --raw-dir data\raw\CICIDS2017\TrafficLabelling --verify   # raw CSVs unchanged?
python -m src.preprocessing.pipeline --config configs\preprocessing.yaml                           # writes data\processed\v1
python -m pytest -q                                                                                # unit, synthetic end-to-end, real-data checks
```

Load model-ready arrays:

```python
from src.preprocessing.dataset import load_split
d = load_split("data/processed/v1", scheme="primary", split="train", feature_set="default",
               representation="raw", target="family")   # d.X, d.y, d.flow_uid, d.meta
```

## 5. Baselines, GraphSAGE, aggregation (Milestones 2–7)

```powershell
python -m src.training.baselines --config configs\baselines.yaml           # RF + XGBoost, 5 experiments (~10 min)
python -m src.evaluation.structure --config configs\gnn.yaml                # graph structure per merge factor (~1 min)
python -m src.training.gnn --config configs\gnn.yaml                        # GraphSAGE identity-free + standard (~25 min, GPU)
python -m src.training.gnn --config configs\gnn.yaml --aggregation-aware    # multi-view consistency training (~15 min, GPU)
python -m src.evaluation.report                                             # reports\results\RESULTS.md + figures
```

Results are written to `experiments/results/{baselines,gnn,aggregation}/` as JSON. Each file includes per-seed
evaluations, the mean ± std summary, configs, data and code hashes, and package versions. Models are saved under
`models/` (git-ignored). Runtimes were measured on an RTX 3050 4 GB with 16 GB RAM.

## 6. Audit log, backend and dashboard (Milestones 8–9)

```powershell
python -m src.cryptography.audit_log demo                 # create -> tamper -> detect, on a temporary log
cd frontend; npm install; npm run build; cd ..           # builds frontend\dist (Node.js 20+)
python -m uvicorn src.api.main:app --host 127.0.0.1 --port 8000
# open http://127.0.0.1:8000  (API docs: http://127.0.0.1:8000/docs)
```

**Frontend development with hot reload:** keep uvicorn running, then run `cd frontend; npm run dev` and open
http://localhost:5173. Vite proxies `/api` to port 8000.

**Making a real upload for the Detection page:** run `python -m src.api.make_sample --file Wednesday-workingHours.pcap_ISCX.csv --n 3000`.
It copies raw test-split rows into `data\samples\` (git-ignored).

**HMAC key:** set `GRAPHSENTINEL_HMAC_KEY` (hex, ≥ 32 bytes) or `GRAPHSENTINEL_HMAC_KEY_FILE`. Otherwise
`keys\hmac.key` is created automatically and is git-ignored. The backend database is `experiments\graphsentinel.sqlite`
(git-ignored); it stores no raw traffic.

## 7. Tests

```powershell
python -m pytest -q -W error::DeprecationWarning
```

The suite covers:
- unit tests for preprocessing, labels, timestamps, splits, metrics, graph construction, exact target-edge exclusion,
  aggregation mapping and metrics, GraphSAGE variants (including identity-free permutation invariance), the audit chain
  and HMAC
- a synthetic end-to-end pipeline
- baseline and GNN trainers on synthetic data
- FastAPI integration covering upload validation, detection, audit and graph endpoints
- checks on the real processed data, which skip when the data is absent

## Layout

```
configs/      preprocessing.yaml, baselines.yaml, gnn.yaml, raw_manifest_cicids2017.json
data/         raw/ (read-only), processed/v1/, samples/                 (git-ignored)
models/       traditional/, graph/                                      (git-ignored)
src/          preprocessing, training, graph_builder, augmentation, evaluation, cryptography, api, utils
frontend/     React + Vite + Plotly + Cytoscape.js dashboard
experiments/  specs, results/ (JSON, committed), logs/ (ignored)
reports/      data_audit/, results/RESULTS.md + figures, environment.json
docs/         dataset_contract.md, architecture.md, audit_log.md
tests/        pytest suite
```
