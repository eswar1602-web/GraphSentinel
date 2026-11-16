"""Simulated flow records and their validation.

A flow record carries identity fields (addresses, ports, timestamp, flow ID), summary counters, the computed
CICFlowMeter-style feature vector, and the simulator's ground truth (``scenario``). The ground truth is kept only
for evaluation and display; no detector reads it.
"""
from __future__ import annotations

import ipaddress
import math
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from src.simulation.packets import FEATURE_COLUMNS, TCP, UDP, Packet, cic_features

PROTOCOL_NAMES = {TCP: "TCP", UDP: "UDP"}
SENTINEL_COLUMNS = {"Init_Win_bytes_forward": -1.0, "Init_Win_bytes_backward": -1.0}
INF_ALLOWED = {"Flow Bytes/s", "Flow Packets/s"}     # +inf only for zero-duration flows (CICIDS2017 behaviour)


class FlowValidationError(ValueError):
    """A simulated flow record violates the flow schema."""


@dataclass(slots=True)
class Flow:
    flow_id: str
    ts: datetime                 # start time (UTC, simulated clock)
    sim_t: float                 # seconds since the simulation started
    src: str                     # device ids
    dst: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int
    duration_s: float
    fwd_packets: int
    bwd_packets: int
    fwd_bytes: int
    bwd_bytes: int
    tcp_flags: str
    features: dict[str, float]
    scenario: str = "normal"                 # ground truth, evaluation only
    scenario_instance: str | None = None
    ml_family: str | None = None             # filled by the ML detector (None = not scored)
    ml_confidence: float | None = None
    alert_ids: list[str] = field(default_factory=list)

    @property
    def total_bytes(self) -> int:
        return self.fwd_bytes + self.bwd_bytes

    @property
    def packets(self) -> int:
        return self.fwd_packets + self.bwd_packets

    def to_dict(self, features: bool = False) -> dict[str, Any]:
        d = {"flow_id": self.flow_id, "timestamp": self.ts.isoformat(timespec="milliseconds"), "sim_t": round(self.sim_t, 3),
             "src": self.src, "dst": self.dst, "src_ip": self.src_ip, "dst_ip": self.dst_ip, "src_port": self.src_port,
             "dst_port": self.dst_port, "protocol": PROTOCOL_NAMES.get(self.protocol, str(self.protocol)),
             "duration_s": round(self.duration_s, 6), "fwd_packets": self.fwd_packets, "bwd_packets": self.bwd_packets,
             "fwd_bytes": self.fwd_bytes, "bwd_bytes": self.bwd_bytes, "tcp_flags": self.tcp_flags,
             "ground_truth_scenario": self.scenario, "scenario_instance": self.scenario_instance,
             "ml": None if self.ml_family is None else {"family": self.ml_family, "confidence": round(self.ml_confidence or 0.0, 4)},
             "alert_ids": list(self.alert_ids)}
        if features:
            d["features"] = {k: (None if not math.isfinite(v) else v) for k, v in self.features.items()}
        return d


def make_flow(flow_id: str, start: datetime, sim_t: float, src: Any, dst: Any, src_port: int, dst_port: int,
              protocol: int, pkts: list[Packet], scenario: str = "normal", instance: str | None = None) -> Flow:
    """Build a flow record from simulated packets (src/dst are network.Device objects)."""
    feats = cic_features(pkts, protocol)
    fl = "".join(sorted({c for p in pkts for c in p.flags}))
    sim_t = float(sim_t)
    return Flow(flow_id, start + timedelta(seconds=sim_t), sim_t, src.id, dst.id, src.ip, dst.ip, int(src_port),
                int(dst_port), protocol, feats["Flow Duration"] / 1e6, int(feats["Total Fwd Packets"]),
                int(feats["Total Backward Packets"]), int(feats["Total Length of Fwd Packets"]),
                int(feats["Total Length of Bwd Packets"]), fl, feats, scenario, instance)


def validate_flow(f: Flow, known_ips: dict[str, Any] | None = None) -> None:
    """Raise FlowValidationError on any schema or consistency violation."""
    try:
        ipaddress.ip_address(f.src_ip)
        ipaddress.ip_address(f.dst_ip)
    except ValueError as exc:
        raise FlowValidationError(f"{f.flow_id}: invalid IP address ({exc})") from exc
    if known_ips is not None:
        for ip, dev in ((f.src_ip, f.src), (f.dst_ip, f.dst)):
            if ip not in known_ips or known_ips[ip].id != dev:
                raise FlowValidationError(f"{f.flow_id}: address {ip} does not belong to device {dev}")
    if f.src == f.dst:
        raise FlowValidationError(f"{f.flow_id}: source and destination are the same device")
    if not (0 <= f.src_port <= 65535 and 0 <= f.dst_port <= 65535):
        raise FlowValidationError(f"{f.flow_id}: port out of range")
    if f.protocol not in PROTOCOL_NAMES:
        raise FlowValidationError(f"{f.flow_id}: unsupported protocol {f.protocol}")
    if f.ts.tzinfo is None:
        raise FlowValidationError(f"{f.flow_id}: timestamp without timezone")
    if f.duration_s < 0 or not math.isfinite(f.duration_s) or f.sim_t < 0:
        raise FlowValidationError(f"{f.flow_id}: negative or non-finite duration/time")
    if f.fwd_packets < 1 or f.bwd_packets < 0 or f.fwd_bytes < 0 or f.bwd_bytes < 0:
        raise FlowValidationError(f"{f.flow_id}: invalid packet/byte counters")
    missing = [c for c in FEATURE_COLUMNS if c not in f.features]
    if missing:
        raise FlowValidationError(f"{f.flow_id}: missing features {missing[:5]}")
    for c in FEATURE_COLUMNS:
        v = f.features[c]
        if not isinstance(v, float) or math.isnan(v):
            raise FlowValidationError(f"{f.flow_id}: feature '{c}' is not a number")
        if math.isinf(v) and not (c in INF_ALLOWED and v > 0 and f.features["Flow Duration"] == 0):
            raise FlowValidationError(f"{f.flow_id}: feature '{c}' is infinite")
        if v < 0 and SENTINEL_COLUMNS.get(c) != v:
            raise FlowValidationError(f"{f.flow_id}: feature '{c}' is negative")
    checks = {"Total Fwd Packets": f.fwd_packets, "Total Backward Packets": f.bwd_packets,
              "Total Length of Fwd Packets": f.fwd_bytes, "Total Length of Bwd Packets": f.bwd_bytes,
              "Protocol": f.protocol}
    for c, v in checks.items():
        if f.features[c] != float(v):
            raise FlowValidationError(f"{f.flow_id}: '{c}' disagrees with the record counters")
