# GraphSentinel

Graph-based network intrusion detection on CICIDS2017 and an identity-aggregation robustness study.
The aggregation simulator (a later milestone) is a **controlled identity-collision stress test, not a NAT emulator**.

Status: **Milestone 1 (preprocessing) is complete**, following [the dataset contract v1.1](docs/dataset_contract.md).
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

## Layout

```
configs/  data/{raw,processed,graphs}/  models/{traditional,graph,checkpoints}/
src/{preprocessing,graph_builder,augmentation,training,evaluation,cryptography,api,utils}/
frontend/  experiments/  reports/  scripts/  tests/
```
