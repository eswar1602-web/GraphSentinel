"""Reproducible headless evaluation of the hybrid detector on simulated traffic.

    python -m src.simulation.evaluate                      # seeds 2017 2018 2019, writes the JSON below
    python -m src.simulation.evaluate --seeds 1 2 --no-ml

For each seed: (a) 20 simulated minutes of normal traffic only (false alerts and incidents), and (b) for each attack
scenario a fresh run with 150 s of normal traffic, then the scenario for 120 s alongside normal traffic (time to first
alert, rules fired, incident opened, ML predictions on the scenario's flows). Ground truth is the simulator's
scenario label, used only here. Output: experiments/results/simulation/evaluation.json.
"""
from __future__ import annotations

import argparse
import json
import platform
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np

from src.simulation.config import load_config
from src.simulation.engine import SimulationEngine
from src.simulation.ml import MLDetector
from src.simulation.scenarios import CATALOG

OUT = Path("experiments/results/simulation/evaluation.json")
STEP = 5.0


def _engine(seed: int, ml: MLDetector | None) -> SimulationEngine:
    return SimulationEngine(load_config(overrides={"seed": seed, "start_time": "2026-01-05T09:00:00Z"}), ml=ml)


def normal_run(seed: int, ml: MLDetector | None, minutes: float = 20.0) -> dict[str, Any]:
    e = _engine(seed, ml)
    for _ in range(int(minutes * 60 / STEP)):
        e.step(STEP)
    sev = Counter(a["severity"] for a in e.alerts.alerts.values())
    return {"sim_minutes": minutes, "flows": e.counters["flows"], "alerts_by_rule": dict(e.alerts.counts),
            "alerts_by_severity": dict(sev), "incidents": e.incidents.n,
            "ml_predicted": dict(e.ml_pred), "invalid_flows": e.counters["invalid"]}


def scenario_run(seed: int, name: str, ml: MLDetector | None) -> dict[str, Any]:
    e = _engine(seed, ml)
    for _ in range(int(150 / STEP)):
        e.step(STEP)
    sc = e.launch_scenario(name, duration_s=120.0)
    for _ in range(int(150 / STEP)):
        e.step(STEP)
    ids = sc["id"]
    mine = [a for a in e.alerts.alerts.values() if any(
        e.flow_index[f].scenario_instance == ids for f in a["flow_ids"] if f in e.flow_index)]
    att = [f for f in e.flows if f.scenario_instance == ids]
    inc = [i for i in e.incidents.incidents.values() if i["actor"] == sc["attacker"]]
    first = min(mine, key=lambda a: a["first_seen"]) if mine else None
    return {"attacker": sc["attacker"], "targets": sc["targets"], "scenario_flows": sum(1 for f in att),
            "detected": bool(mine), "first_alert_rule": first["rule"] if first else None,
            "time_to_first_alert_s": round(first["first_seen"] - sc["start_t"], 3) if first else None,
            "rules_fired": sorted({a["rule"] for a in mine}),
            "incident_opened": bool(inc), "incident_severity": inc[0]["severity"] if inc else None,
            "ml_predicted_on_scenario_flows": dict(Counter(f.ml_family for f in att if f.ml_family is not None)),
            "note_buffer": "scenario flows counted from the in-memory flow buffer (5,000 most recent flows)"}


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--seeds", type=int, nargs="+", default=[2017, 2018, 2019])
    ap.add_argument("--no-ml", action="store_true")
    ap.add_argument("--out", type=Path, default=OUT)
    a = ap.parse_args(argv)
    ml = None
    if not a.no_ml:
        ml = MLDetector(load_config().ml.min_confidence)
        ml.load()
    res: dict[str, Any] = {"created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"), "seeds": a.seeds,
                           "ml": None if ml is None else {k: ml.report.get(k) for k in ("available", "compatible", "model", "reason", "caveat")},
                           "python": platform.python_version(), "numpy": np.__version__, "normal": {}, "scenarios": {}}
    for seed in a.seeds:
        res["normal"][str(seed)] = normal_run(seed, ml)
        n = res["normal"][str(seed)]
        print(f"seed {seed} normal 20 min: {n['flows']} flows, alerts {n['alerts_by_rule']}, incidents {n['incidents']}, "
              f"ML {n['ml_predicted']}", flush=True)
        for name in CATALOG:
            if name == "normal":
                continue
            r = scenario_run(seed, name, ml)
            res["scenarios"].setdefault(name, {})[str(seed)] = r
            print(f"  {name:20s} detected={r['detected']} first={r['first_alert_rule']} after {r['time_to_first_alert_s']} s; "
                  f"rules={r['rules_fired']}; incident={r['incident_severity']}; ML={r['ml_predicted_on_scenario_flows']}",
                  flush=True)
    a.out.parent.mkdir(parents=True, exist_ok=True)
    a.out.write_text(json.dumps(res, indent=1), encoding="utf-8")
    print(f"wrote {a.out}")


if __name__ == "__main__":
    main()
