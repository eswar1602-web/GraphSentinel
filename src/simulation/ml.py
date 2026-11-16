"""ML detection for simulated flows with the existing XGBoost detector (experiment primary_family_default).

Before any scoring the adapter verifies feature compatibility: every raw column the detector requires
(``services.Detector.required_raw_columns``) must be produced by ``packets.cic_features``. If the model, its
transforms or a required feature is missing, ML detection is reported as unavailable and no prediction is made
(nothing is filled in or guessed). Scoring then uses ``services.score_numeric``: the same Milestone 1 value
corrections and train-fitted transform as the upload detector.

Caveat (reported by the API): the model was trained on CICIDS2017 traffic; simulated flows are synthetic and
out-of-distribution, so its outputs are model predictions, not validated detections.
"""
from __future__ import annotations

import logging
from typing import Any, Callable

import numpy as np
import pandas as pd

from src.api import services
from src.simulation.flows import Flow
from src.simulation.packets import FEATURE_COLUMNS

log = logging.getLogger("graphsentinel.simulation.ml")

CAVEAT = ("XGBoost model trained on CICIDS2017 (experiment primary_family_default, no Destination Port). Simulated "
          "flows are synthetic and out-of-distribution: predictions are model outputs, not validated detections.")


class MLDetector:
    def __init__(self, min_confidence: float = 0.9, loader: Callable[[], services.Detector] | None = None) -> None:
        self.min_confidence = min_confidence
        self._loader = loader or services.Detector.load
        self.det: services.Detector | None = None
        self.report: dict[str, Any] = {"available": False, "compatible": False, "reason": "not loaded"}
        self.scored = 0
        self.failed_batches = 0
        self.last_error: str | None = None

    def load(self) -> dict[str, Any]:
        """Load the detector and check feature compatibility. Never raises; the report says what happened."""
        try:
            det = self._loader()
        except FileNotFoundError as exc:
            self.det, self.report = None, {"available": False, "compatible": False, "reason": str(exc)}
            return self.report
        except Exception as exc:  # noqa: BLE001 - a broken artefact disables ML, it must not stop the simulation
            log.exception("could not load the ML detector")
            self.det, self.report = None, {"available": False, "compatible": False, "reason": f"load failed: {exc}"}
            return self.report
        required = det.required_raw_columns()
        missing = sorted(set(required) - set(FEATURE_COLUMNS))
        unused = sorted(set(FEATURE_COLUMNS) - set(required))
        ok = not missing and "Benign" in det.classes
        self.report = {"available": True, "compatible": ok, "model": det.model_file, "classes": det.classes,
                       "model_inputs": len(det.columns), "required_raw_columns": len(required),
                       "computed_columns": len(FEATURE_COLUMNS), "missing_features": missing,
                       "unused_computed_features": unused, "destination_port_used": "Destination Port" in det.columns,
                       "min_confidence": self.min_confidence, "caveat": CAVEAT,
                       "reason": None if ok else ("missing features: " + ", ".join(missing) if missing
                                                  else "model has no Benign class")}
        self.det = det if ok else None
        if not ok:
            log.warning("ML detection disabled: %s", self.report["reason"])
        return self.report

    @property
    def ready(self) -> bool:
        return self.det is not None

    def score(self, flows: list[Flow]) -> int:
        """Set ``ml_family``/``ml_confidence`` on every flow of the batch. Returns the number scored (0 on failure:
        the flows then stay unscored, ``ml_family is None``)."""
        if not self.ready or not flows:
            return 0
        det = self.det
        assert det is not None
        cols = det.required_raw_columns()
        num = pd.DataFrame([[f.features[c] for c in cols] for f in flows], columns=cols, dtype="float64")
        try:
            proba, _ = services.score_numeric(det, num, pd.Series([f.flow_id for f in flows]))
        except (AssertionError, ValueError) as exc:
            self.failed_batches += 1
            self.last_error = str(exc)
            log.warning("ML scoring failed for a batch of %d flows: %s", len(flows), exc)
            return 0
        pred = proba.argmax(1)
        conf = proba.max(1)
        names = np.array(det.classes, dtype=object)
        for f, p, c in zip(flows, pred, conf):
            f.ml_family, f.ml_confidence = str(names[p]), float(c)
        self.scored += len(flows)
        return len(flows)

    def findings(self, flows: list[Flow], now: float, k: int = 50) -> list[dict[str, Any]]:
        """Group confident non-benign predictions by (source, destination, family) into alert findings."""
        groups: dict[tuple[str, str, str], list[Flow]] = {}
        for f in flows:
            if f.ml_family and f.ml_family != "Benign" and (f.ml_confidence or 0) >= self.min_confidence:
                groups.setdefault((f.src, f.dst, f.ml_family), []).append(f)
        out = []
        for (src, dst, fam), fs in groups.items():
            mc = float(np.mean([f.ml_confidence for f in fs]))
            out.append({"rule": f"ml_{fam.lower()}", "severity": "high" if mc >= 0.99 and len(fs) >= 10 else "medium",
                        "src": src, "dst_devices": [dst], "t": now, "source": "ml",
                        "title": f"ML classifier: {fam} predicted for {src} -> {dst}",
                        "explanation": f"The XGBoost flow classifier predicted '{fam}' for {len(fs)} flow(s) from {src} "
                                       f"to {dst} in this interval (mean confidence {mc:.3f}, minimum "
                                       f"{self.min_confidence:g}). {CAVEAT}",
                        "evidence": {"family": fam, "flows": len(fs), "mean_confidence": round(mc, 4),
                                     "ports": sorted({f.dst_port for f in fs})[:20]},
                        "flow_ids": [f.flow_id for f in fs][-k:]})
        return out
