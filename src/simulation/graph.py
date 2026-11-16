"""Incrementally updated directed communication graph of the simulated network.

Nodes are the topology's devices, so memory is bounded by the topology size; edges are (src device, dst device)
pairs with running traffic statistics. Detection indicators (alerts, ML predictions, incidents) are attached to
nodes and edges as they arrive. Structural metrics reuse ``src.augmentation.aggregation.structural_metrics``
(the same code that measures the CICIDS2017 graphs).
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Iterable

import numpy as np

from src.augmentation.aggregation import structural_metrics
from src.simulation.flows import PROTOCOL_NAMES, Flow
from src.simulation.network import Network

SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}
MAX_PORTS_PER_EDGE = 64
MAX_IDS = 20


@dataclass
class EdgeStats:
    src: str
    dst: str
    flows: int = 0
    packets: int = 0
    bytes_fwd: int = 0
    bytes_bwd: int = 0
    first_seen: float = 0.0
    last_seen: float = 0.0
    ports: Counter = field(default_factory=Counter)
    ports_overflow: int = 0
    protocols: Counter = field(default_factory=Counter)
    ml_attack_flows: int = 0
    ml_families: Counter = field(default_factory=Counter)
    alert_ids: list[str] = field(default_factory=list)
    rules: set[str] = field(default_factory=set)
    max_severity: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {"id": f"{self.src}->{self.dst}", "source": self.src, "target": self.dst, "flows": self.flows,
                "packets": self.packets, "bytes_fwd": self.bytes_fwd, "bytes_bwd": self.bytes_bwd,
                "first_seen": round(self.first_seen, 3), "last_seen": round(self.last_seen, 3),
                "distinct_ports": len(self.ports) + self.ports_overflow,
                "top_ports": [p for p, _ in self.ports.most_common(5)],
                "protocols": {PROTOCOL_NAMES.get(k, str(k)): v for k, v in self.protocols.items()},
                "ml_attack_flows": self.ml_attack_flows, "ml_families": dict(self.ml_families),
                "suspicious": bool(self.rules or self.ml_attack_flows), "indicators": sorted(self.rules),
                "alert_ids": list(self.alert_ids), "max_severity": self.max_severity}


@dataclass
class NodeStats:
    flows_out: int = 0
    flows_in: int = 0
    bytes_out: int = 0
    bytes_in: int = 0
    peers_out: set[str] = field(default_factory=set)
    peers_in: set[str] = field(default_factory=set)
    last_seen: float | None = None
    ml_attack_flows: int = 0
    alert_ids: list[str] = field(default_factory=list)
    rules: set[str] = field(default_factory=set)
    incident_ids: list[str] = field(default_factory=list)
    max_severity: str | None = None


def _bump(cur: str | None, new: str) -> str:
    return new if cur is None or SEVERITY_RANK[new] > SEVERITY_RANK[cur] else cur


def _push(xs: list[str], v: str) -> None:
    if v not in xs:
        xs.append(v)
        del xs[:-MAX_IDS]


class LiveGraph:
    def __init__(self, net: Network) -> None:
        self.net = net
        self.nodes: dict[str, NodeStats] = {d: NodeStats() for d in net.devices}
        self.edges: dict[tuple[str, str], EdgeStats] = {}
        self.index = {d: i for i, d in enumerate(net.devices)}
        self.flows_total = 0

    def add_flows(self, flows: Iterable[Flow]) -> tuple[set[str], set[tuple[str, str]]]:
        """Add flows; returns the ids of changed nodes and edges (for incremental streaming)."""
        cn: set[str] = set()
        ce: set[tuple[str, str]] = set()
        for f in flows:
            if f.src not in self.nodes or f.dst not in self.nodes:
                raise KeyError(f"flow {f.flow_id} references a device outside the topology")
            k = (f.src, f.dst)
            e = self.edges.get(k)
            if e is None:
                e = self.edges[k] = EdgeStats(f.src, f.dst, first_seen=f.sim_t)
            e.flows += 1
            e.packets += f.packets
            e.bytes_fwd += f.fwd_bytes
            e.bytes_bwd += f.bwd_bytes
            e.last_seen = max(e.last_seen, f.sim_t)
            if f.dst_port in e.ports or len(e.ports) < MAX_PORTS_PER_EDGE:
                e.ports[f.dst_port] += 1
            else:
                e.ports_overflow += 1
            e.protocols[f.protocol] += 1
            s, d = self.nodes[f.src], self.nodes[f.dst]
            s.flows_out += 1
            s.bytes_out += f.fwd_bytes
            s.bytes_in += f.bwd_bytes
            d.flows_in += 1
            d.bytes_in += f.fwd_bytes
            d.bytes_out += f.bwd_bytes
            s.peers_out.add(f.dst)
            d.peers_in.add(f.src)
            s.last_seen = d.last_seen = f.sim_t
            self.flows_total += 1
            cn.update(k)
            ce.add(k)
        return cn, ce

    def mark_ml(self, flows: Iterable[Flow], benign: str = "Benign") -> tuple[set[str], set[tuple[str, str]]]:
        cn: set[str] = set()
        ce: set[tuple[str, str]] = set()
        for f in flows:
            if f.ml_family is None or f.ml_family == benign:
                continue
            e = self.edges[(f.src, f.dst)]
            e.ml_attack_flows += 1
            e.ml_families[f.ml_family] += 1
            self.nodes[f.src].ml_attack_flows += 1
            cn.update((f.src, f.dst))
            ce.add((f.src, f.dst))
        return cn, ce

    def mark_alert(self, alert: dict[str, Any]) -> tuple[set[str], set[tuple[str, str]]]:
        rule, sev, aid = alert["rule"], alert["severity"], alert["id"]
        cn, ce = set(), set()
        for dev in [alert["src"], *alert.get("dst_devices", [])]:
            if dev in self.nodes:
                n = self.nodes[dev]
                _push(n.alert_ids, aid)
                n.rules.add(rule)
                n.max_severity = _bump(n.max_severity, sev)
                cn.add(dev)
        for dst in alert.get("dst_devices", []):
            e = self.edges.get((alert["src"], dst))
            if e is not None:
                _push(e.alert_ids, aid)
                e.rules.add(rule)
                e.max_severity = _bump(e.max_severity, sev)
                ce.add((alert["src"], dst))
        return cn, ce

    def mark_incident(self, incident: dict[str, Any]) -> set[str]:
        changed = set()
        for dev in incident["devices"]:
            if dev in self.nodes:
                _push(self.nodes[dev].incident_ids, incident["id"])
                changed.add(dev)
        return changed

    def node_dict(self, dev_id: str) -> dict[str, Any]:
        d, n = self.net.devices[dev_id], self.nodes[dev_id]
        return {**d.to_dict(), "label": d.hostname.split(".")[0], "flows_out": n.flows_out, "flows_in": n.flows_in,
                "bytes_out": n.bytes_out, "bytes_in": n.bytes_in, "out_degree": len(n.peers_out),
                "in_degree": len(n.peers_in), "last_seen": n.last_seen, "active": n.last_seen is not None,
                "ml_attack_flows": n.ml_attack_flows, "suspicious": bool(n.rules or n.ml_attack_flows),
                "indicators": sorted(n.rules), "alert_ids": list(n.alert_ids), "incident_ids": list(n.incident_ids),
                "max_severity": n.max_severity}

    def delta(self, nodes: set[str], edges: set[tuple[str, str]]) -> dict[str, Any]:
        return {"nodes": [self.node_dict(n) for n in sorted(nodes)],
                "edges": [self.edges[e].to_dict() for e in sorted(edges) if e in self.edges]}

    def snapshot(self, active_only: bool = False, suspicious_only: bool = False) -> dict[str, Any]:
        nodes = [self.node_dict(n) for n in self.nodes]
        edges = [e.to_dict() for e in self.edges.values()]
        if suspicious_only:
            edges = [e for e in edges if e["suspicious"]]
            keep = {e["source"] for e in edges} | {e["target"] for e in edges}
            nodes = [n for n in nodes if n["suspicious"] or n["id"] in keep]
        elif active_only:
            nodes = [n for n in nodes if n["active"]]
        return {"nodes": nodes, "edges": edges, "flows_total": self.flows_total}

    def structure(self, recent: list[Flow]) -> dict[str, Any]:
        """Structural metrics of the recent-flow window (``structural_metrics`` from the aggregation module)."""
        if not recent:
            return {"window_flows": 0}
        s = np.fromiter((self.index[f.src] for f in recent), dtype=np.int64, count=len(recent))
        d = np.fromiter((self.index[f.dst] for f in recent), dtype=np.int64, count=len(recent))
        return {"window_flows": len(recent), **structural_metrics(s, d, len(self.index))}
