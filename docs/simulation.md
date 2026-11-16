# Live network simulation and hybrid threat detection

GraphSentinel's backend can run a **simulated enterprise network**:
- It generates flow records for routine traffic and for five attack-like scenarios.
- It maintains a live communication graph.
- It detects threats with behavioural rules plus the existing XGBoost model, and correlates alerts into incidents.
- It stores alerts and incidents in SQLite, records security events in the tamper-evident audit log, and streams
  everything over a WebSocket.

> **Safety.** Everything is synthetic and in-process. No packets are captured, sent or received, no sockets are opened
> to simulated hosts, and nothing is ever blocked automatically. External endpoints use the RFC 5737 documentation
> ranges (198.51.100.0/24, 203.0.113.0/24), which are never routed. "Attacker" and "target" are labels on simulated
> records.

The React dashboard is unchanged; this is a backend and API feature.

## Pipeline

Each `step(dt)` advances simulated time by `dt` seconds and runs:

```
NormalTraffic + active Scenario generators     (src/simulation/scenarios.py, seeded numpy Generators)
   │  synthetic packets per flow -> CICFlowMeter-style features   (packets.py)
   ▼
validate_flow   ── invalid records are counted and dropped, never scored          (flows.py)
   ▼
LiveGraph.add_flows   ── devices = nodes, (src, dst) = directed edges with running stats   (graph.py)
   ▼
MLDetector.score   ── existing XGBoost via services.score_numeric (only if the features are compatible)   (ml.py)
BehaviouralDetector.process   ── sliding-window rules                              (rules.py)
   ▼
AlertManager (merge repeats) -> IncidentManager (correlate by acting device)    (incidents.py)
   ▼
SimStore (SQLite) · AuditLog (SHA-256 chain + HMAC) · WebSocket events             (store.py, engine.py, api/simulation.py)
```

- **Running mode:** `run_loop` calls `step(speed × tick_interval_s)` every `tick_interval_s` wall-clock seconds. The
  simulated step is fixed, not measured, so a seed plus the same sequence of commands reproduces the same flows on any
  machine.
- **Idle or stopped:** `POST /api/sim/step` advances the clock by a chosen amount, which is useful for demos and tests.

## Network model (`network.py`, `configs/simulation.yaml` → `network`)

| role | default count | address range | services (ports) |
|---|---|---|---|
| router | 1 | 10.10.0.0/24 | 22, 161 |
| workstation | 12 | 10.10.1.0/24 | 135, 139, 445, 3389 |
| laptop | 6 | 10.10.2.0/24 | 135, 139, 445 |
| application server | 2 | 10.10.10.0/24 | 22, 80, 443, 8080 |
| database server | 1 | 10.10.10.0/24 | 22, 5432 |
| DNS server | 1 | 10.10.10.0/24 | 22, 53 |
| external endpoint | 8 | RFC 5737 | 53, 80, 123, 443 |

- The topology is deterministic for a seed.
- The first workstation is the admin workstation.
- Routine traffic uses all external endpoints except two; the scenarios use those two as rarely contacted destinations.
  No detector reads this split. The baseline is learned from traffic.

## Traffic and scenarios (`scenarios.py`)

Normal traffic is always on unless `traffic.normal_enabled` is false. It consists of:
- client DNS lookups followed by external HTTPS;
- internal web on 80, 443 and 8080;
- app-server-to-database queries on 5432;
- DNS forwarding;
- router NTP;
- rare admin SSH sessions.

Event times are Poisson-distributed at the configured rates.

| scenario (`name`) | what is generated | default participants |
|---|---|---|
| `normal` | routine traffic only. Selecting it stops every active attack. | — |
| `port_scan` | SYN probes to ports 1–1024 of one host, about 40/s × intensity. Open ports answer SYN/ACK; closed ports answer RST. | client → app server |
| `dos` | about 60/s × intensity short HTTP connections, 40% of them unanswered SYN retransmissions | client → app server |
| `lateral_movement` | about 1.5/s × intensity connections from one workstation to five clients on 445, 3389, 135 and 5985 | client → 5 clients |
| `brute_force` | about 1.5/s × intensity short SSH sessions that end after a failed login | rare external → app server |
| `suspicious_outbound` | beacons and 2–8 MB uploads (about 0.3/s × intensity) on port 4444, 8443 or 9001 | client → rare external |

`POST /api/sim/scenarios` accepts optional `attacker`, `targets`, `duration_s` (simulated seconds) and `intensity`
(0.1–10). Invalid combinations are rejected with a 422, for example a lateral movement whose target is a server.

## Flow records and features (`packets.py`, `flows.py`)

Each flow is generated as a sequence of synthetic packets. A packet has:
- a time in µs;
- a direction;
- a payload length;
- a header length;
- TCP flags;
- a TCP window.

All 69 raw CICIDS2017 feature columns the detector needs are **computed** from these packets, following CICFlowMeter
definitions:
- sample standard deviations;
- rates of +inf for zero-duration flows, which the shared Milestone 1 corrections turn into missing values;
- `Init_Win_bytes_*` = -1 when there is no packet in that direction;
- a 5 s activity timeout for the Active and Idle features.

This is an approximation of CICFlowMeter. It does not re-implement it. A flow record also carries:
- its addresses, ports, protocol, timestamp and flow ID;
- packet and byte counters;
- the simulator's ground truth (`ground_truth_scenario`), used only for evaluation and display.

`validate_flow` rejects a flow when:
- an IP address is invalid, or does not belong to the named device;
- source and destination are the same device;
- a port is out of range;
- the protocol is not TCP or UDP;
- the timestamp has no timezone;
- a counter is negative, or the packet and byte counters disagree with the features;
- a feature is missing or NaN;
- a feature is infinite, except the documented zero-duration rates;
- a value is negative, except the CICIDS2017 `Init_Win` sentinel -1.

Rejected flows are counted (`flows_invalid`) and never reach the graph or the detectors.

## Graph engine (`graph.py`)

- **Nodes** are the topology's devices, so the node count is bounded. Each records:
  - flows and bytes in and out;
  - in-degree and out-degree;
  - last seen;
  - ML attack predictions;
  - alert IDs;
  - rule indicators;
  - incident IDs;
  - maximum severity.
- **Edges** are directed (source device → destination device) pairs, with:
  - flows, packets, and bytes in each direction;
  - first and last seen;
  - destination-port counts, with at most 64 ports tracked plus an overflow count;
  - protocols;
  - ML family counts;
  - alert IDs and rules.
- Every step returns only the nodes and edges that changed. The WebSocket streams that delta as `graph_update`.
- `structure_recent` in `/api/sim/stats` reuses `src.augmentation.aggregation.structural_metrics`, the code that
  measures the CICIDS2017 graphs, on the in-memory flow window.

## Detection

### Behavioural rules (`rules.py`, `configs/simulation.yaml` → `detection`)

All rules use a 60 s sliding window with incremental counters, so the cost per flow is O(1).

| rule | fires when (default threshold) | base severity |
|---|---|---|
| `port_scan` | one source reaches ≥ 20 distinct ports of one host | medium |
| `host_sweep` | one source reaches ≥ 8 distinct internal hosts on one port | high |
| `connection_rate` | ≥ 15 flows/s from one source to one destination service | high |
| `traffic_volume` | ≥ 20 MB sent from one source to one destination, with sent/received ≥ 5 | high |
| `brute_force` | ≥ 12 TCP sessions of ≤ 5 s to one authentication service (21, 22, 23, 3389, 5900, 5985) | high |
| `unexpected_communication` | a (source, destination, port) not seen during the 120 s baseline **and** breaking the role policy. The policy cases are listed below. | per case |

Policy cases for `unexpected_communication`:
- client-to-client traffic: high on admin ports, medium otherwise;
- an external endpoint initiating a connection: medium;
- outbound on a port outside 53, 80, 123 and 443: high;
- a new admin-port connection to a server: low.

Severity rises one level when the observed value is at least 4× the threshold.

Every alert includes:
- a plain-language explanation;
- the evidence values;
- the window length;
- up to 50 supporting flow IDs.

### ML detection (`ml.py`)

The adapter loads the existing detector, `services.Detector`, which is the primary_family_default XGBoost model
without Destination Port. **Before any scoring** it checks `required_raw_columns()` against the 69 computed columns.

- **Model files missing, or a required feature absent:** ML is reported as unavailable or incompatible (`GET /api/sim/ml`)
  and **no prediction is made**. Flows keep `ml: null`.
- **Compatible:** scoring calls `services.score_numeric`, the same corrections and transform as the CSV upload
  detector. That code was factored out of `services.detect` and is shared.
- **Alerts:** confident non-benign predictions (confidence ≥ 0.9 by default) are grouped per (source, destination,
  family) into `ml_<family>` alerts.

**Caveat:** the model learned CICIDS2017 traffic; simulated flows are out of distribution. Its outputs are model
predictions, not validated detections. By default, ML-only alerts join existing incidents but do not open new ones
(`ml.create_incidents: false`).

### Alerts and incidents (`incidents.py`)

- **Alert merging:** a repeat of an open alert (same rule, source and destination group) within 120 s updates that
  alert. Its occurrences, latest evidence and merged flow IDs change; no new alert is created.
- **Correlation:** alerts are grouped by acting device into incidents within 600 s. An alert whose source was a
  *target* of an open incident joins it as a possible **pivot**.
- **Opening incidents:** only alerts of severity ≥ medium open a new incident (`incidents.min_severity_to_open`).
- **Severity:** incident severity is the maximum of its alerts, raised one level when three different behavioural rules
  agree.
- **Status changes (analyst actions):** open → acknowledged → investigating → resolved or false_positive, and
  resolved or false_positive → open. Every change is kept in `history` and audited. No status triggers any automated
  response.

## Persistence and audit

SQLite: `db.init` creates the tables `sim_runs`, `sim_alerts` and `sim_incidents` in the existing database
(`experiments/graphsentinel.sqlite`, or the path in `GRAPHSENTINEL_DB`).
- Alerts and incidents are upserted on every change.
- Simulated flows are not stored. They live in a bounded in-memory buffer of 5,000 flows, and alerts and incidents
  keep the IDs of their supporting flows.

Audit events are appended to the existing SHA-256 + HMAC chain (`src/cryptography/audit_log.py`):

| event | when | key details |
|---|---|---|
| `simulation_reset` / `simulation_start` / `simulation_stopped` / `simulation_completed` / `simulation_error` | lifecycle | run ID, seed, clock, flow, alert and incident counts, reason |
| `scenario_started` / `scenario_stopped` / `scenario_selected` | scenario control | instance, attacker, targets, intensity |
| `detection_alert` | a new alert of severity high or critical | alert ID, rule, devices, `evidence_sha256` |
| `incident_created` / `incident_escalated` | correlation | incident ID, severity, rules, alert IDs, `evidence_sha256` |
| `incident_status_changed` | analyst update | from, to, note |

`evidence_sha256` is the SHA-256 of the canonical JSON list of supporting flow IDs, which binds the audit record to its
evidence. `GET /api/audit/verify` verifies the whole chain, as before.

## API

The API lives under `/api/sim`. Interactive docs are at http://127.0.0.1:8000/docs.

| method and path | purpose |
|---|---|
| `GET /status` | run ID, state (idle, running, stopped, completed, error), simulated clock, counters, active scenarios, ML status |
| `POST /start` `{speed?, tick_interval_s?, duration_s?}` | start or resume the clock (409 if already running) |
| `POST /stop` | stop cleanly (409 if not running) |
| `POST /reset` `{seed?, start_time?, network?, traffic?, detection?}` | new run, with optional overrides (stops first if running) |
| `POST /step` `{seconds}` | advance a stopped or idle simulation manually |
| `GET /scenarios` · `POST /scenarios` `{name, attacker?, targets?, duration_s?, intensity?}` · `DELETE /scenarios/{id}` | catalog, launch, stop |
| `GET /topology?active_only&suspicious_only` | devices, edges, indicators |
| `GET /flows?limit&src&dst&suspicious_only&scenario` · `GET /flows/{flow_id}` | recent flows; one flow with all 69 features |
| `GET /detections?run_id&severity&rule&incident_id&limit&offset` · `GET /detections/{id}` | persisted alerts (default: current run; `run_id=all` for every run) |
| `GET /incidents?run_id&status&limit&offset` · `GET /incidents/{id}` | persisted incidents (the single-incident view includes its detections) |
| `PATCH /incidents/{id}` `{status, note?}` | analyst status change (422 for an invalid transition) |
| `GET /stats` | totals, rates, rules, graph structure, ML, ground-truth evaluation, memory, WebSocket counters |
| `GET /ml` · `GET /runs` | ML compatibility report; persisted runs |
| `WS /ws?topics=status,flows,graph_update,detection,incident,scenario` | event stream |

### PowerShell examples

```powershell
$api = "http://127.0.0.1:8000/api/sim"
Invoke-RestMethod -Method Post "$api/reset" -ContentType application/json -Body '{"seed": 2017}'
Invoke-RestMethod -Method Post "$api/start" -ContentType application/json -Body '{"speed": 20, "tick_interval_s": 0.5}'
Start-Sleep 10    # let the 120 s baseline be learned (10 wall s x 20 = 200 simulated s)
Invoke-RestMethod -Method Post "$api/scenarios" -ContentType application/json -Body '{"name": "port_scan", "attacker": "ws-04", "targets": ["app-01"]}'
Start-Sleep 3
Invoke-RestMethod "$api/detections?rule=port_scan" | Select-Object id, severity, explanation
$inc = (Invoke-RestMethod "$api/incidents")[0]; $inc | Select-Object id, severity, title, flow_ids
Invoke-RestMethod -Method Patch "$api/incidents/$($inc.id)" -ContentType application/json -Body '{"status": "investigating", "note": "checking ws-04"}'
Invoke-RestMethod "$api/stats" | ConvertTo-Json -Depth 4
Invoke-RestMethod -Method Post "$api/stop"
Invoke-RestMethod "http://127.0.0.1:8000/api/audit/verify"
```

### WebSocket messages

Every message has the shape `{"type": ..., "ts": ISO-8601, "data": {...}}`.

| type | data |
|---|---|
| `hello` | sent on connect: client ID, topics, current status |
| `flows` | each tick: count, up to 200 flow summaries, `truncated` |
| `graph_update` | each tick: changed nodes and edges, with full attributes |
| `detection` | created or updated alert |
| `incident` | created, updated or status-changed incident |
| `scenario` | started, stopped or selected |
| `status` | each tick and on lifecycle changes |

Clients may send:
- `{"action":"ping"}`, answered with `pong`;
- `{"action":"snapshot"}`, answered with the status and full topology;
- `{"action":"subscribe","topics":[...]}`, to change topics.

Each client has a bounded queue of 500 messages. When a slow client's queue is full, its oldest messages are dropped and
counted in `/stats`.

## Running

```powershell
# 1. backend (the trained model from Milestone 2 is used if present; otherwise ML is reported unavailable)
python -m uvicorn src.api.main:app --host 127.0.0.1 --port 8000

# 2. end-to-end demo: REST + WebSocket, the 10 acceptance steps (second terminal)
python -m src.simulation.demo --url http://127.0.0.1:8000

# 3. reproducible headless evaluation (no server): writes experiments/results/simulation/evaluation.json
python -m src.simulation.evaluate --seeds 2017 2018 2019

# tests
python -m pytest -q tests/test_simulation.py tests/test_simulation_api.py
```

- **Configuration:** `configs/simulation.yaml`, or set `GRAPHSENTINEL_SIM_CONFIG` to another file. Pydantic validates
  the config and rejects unknown keys.
- **Database and key:** `GRAPHSENTINEL_DB` and `GRAPHSENTINEL_HMAC_KEY_FILE` select the database and the HMAC key, as
  for the rest of the backend.

## Measured behaviour

These figures come from `python -m src.simulation.evaluate` with seeds 2017–2019 and the trained CICIDS2017 model; the
results file is `experiments/results/simulation/evaluation.json`.

| check | result |
|---|---|
| 20 simulated minutes of normal traffic | about 7,900 flows per seed and **0 incidents**. Seeds 2017 and 2019 each produced 7 **low-severity** `unexpected_communication` alerts: admin-workstation SSH to servers it had not used during the 120 s baseline. Seed 2018 produced none. |
| ML on normal traffic | every flow predicted Benign (23,777 of 23,777 across the three seeds) |
| each of the 5 attack scenarios × 3 seeds | **detected in 15 of 15 runs**, with an incident opened in every run |
| ML on attack scenarios | predicts `DoS` for about 26% of DoS-scenario flows. It predicts Benign for essentially all port-scan, lateral-movement, brute-force and outbound flows (one `Infiltration` prediction in one run). Detection of these scenarios comes from the behavioural rules. |
| memory soak (one-off development run, not part of `evaluate.py`; seed 5, all five attacks running continuously, ML on) | over 1.1 M flows (2.8 simulated h): flow buffer constant at 5,000, rule-window state about 2,500 keys and 21,600 entries, 0 invalid and 0 dropped flows. A separate 1.25 h run measured process RSS at 321 MB at 82 k flows and 323 MB at 496 k flows. |
| step cost (same run, Windows laptop, CPU) | about 300 ms per 5 s step at about 550 flows per step (≈ 0.55 ms per flow, including XGBoost scoring). Keep `speed × tick_interval_s × flow rate` well below `max_flows_per_tick`; excess flows are dropped and counted. |

Two caveats apply to these figures:
- **Detection latency:** the evaluation steps the clock 5 s at a time, and window rules evaluate at the end of each step.
  A reported "5.0 s" therefore means "within the first step". Per-flow policy alerts carry the flow's own time.
- **ML counts:** scenario flow counts for the ML rows come from the bounded flow buffer of the 5,000 most recent flows.

## Limitations

- **Synthetic traffic.** Rates, sizes and timings are plausible but simple distributions. The thresholds were chosen
  for this simulator; they are not validated on real networks.
- **Approximate features.** The CICFlowMeter-style features approximate CICFlowMeter. The ML model is applied out of
  distribution, and its behaviour above (strong only on DoS-like floods) is a finding, not a tuning target.
- **Baseline learning.** The 120 s baseline is short. Rare legitimate pairs, such as admin SSH, appear as low-severity
  alerts after warm-up. Pairs observed during warm-up, including any attack launched during warm-up, are treated as
  normal.
- **Ground truth.** It is available only because the traffic is simulated. It is reported separately
  (`evaluation_against_ground_truth`) and never used by a detector.
- **No NAT or routing.** Internal hosts talk to external endpoints directly, without the CICIDS2017 NAT effect
  described in the dataset contract.
- **Bounded history.** Flows older than the 5,000-flow buffer cannot be fetched by ID; their IDs remain in persisted
  alerts and incidents. Alerts and incidents beyond the in-memory limits remain in SQLite.
