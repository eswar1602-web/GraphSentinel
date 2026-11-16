"""Traffic generators: routine (normal) traffic and five attack-like scenarios.

All output is synthetic flow records built in memory. No packet is sent, no socket is opened and no host is
contacted; "attacker" and "target" are devices of the simulated topology.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable

import numpy as np

from src.simulation.config import TrafficConfig
from src.simulation.flows import Flow, make_flow
from src.simulation.network import CLIENT_ROLES, Device, Network
from src.simulation.packets import (TCP, UDP, Packet, tcp_probe, tcp_session, tcp_unanswered, udp_exchange)


class FlowFactory:
    """Assigns flow IDs and ephemeral ports and turns packet sequences into flow records."""

    def __init__(self, run_id: str, start: datetime) -> None:
        self.run_id, self.start, self.seq = run_id, start, 0

    def make(self, rng: np.random.Generator, t: float, src: Device, dst: Device, dport: int, proto: int,
             pkts: list[Packet], scenario: str = "normal", instance: str | None = None,
             sport: int | None = None) -> Flow:
        self.seq += 1
        sp = int(sport if sport is not None else rng.integers(49152, 65536))
        return make_flow(f"{self.run_id}-{self.seq:08d}", self.start, t, src, dst, sp, dport, proto, pkts,
                         scenario, instance)


def _times(rng: np.random.Generator, rate: float, t0: float, dt: float) -> np.ndarray:
    n = int(rng.poisson(max(rate, 0.0) * dt))
    return np.sort(rng.uniform(t0, t0 + dt, n))


def _web(rng: np.random.Generator, internal: bool) -> list[Packet]:
    k = int(rng.integers(1, 6))
    ex = [(int(rng.integers(200, 1500)), int(rng.lognormal(9.0 if internal else 9.8, 1.0))) for _ in range(k)]
    return tcp_session(rng, ex, rtt_us=300 if internal else 25_000, think_us=float(rng.uniform(1e3, 4e5)))


class NormalTraffic:
    """Routine enterprise traffic: DNS, web (internal and external), app->DB queries, DNS forwarding, NTP,
    and the admin workstation's SSH sessions."""

    def __init__(self, net: Network, cfg: TrafficConfig) -> None:
        self.net, self.cfg = net, cfg

    def generate(self, rng: np.random.Generator, t0: float, dt: float, fac: FlowFactory) -> list[Flow]:
        n, c, out = self.net, self.cfg, []
        dns, apps, dbs = n.role("dns_server"), n.role("app_server"), n.role("db_server")
        for cl in n.clients():
            for t in _times(rng, c.client_sessions_per_s, t0, dt):
                kind = rng.choice(4, p=[0.45, 0.30, 0.15, 0.10])
                d = dns[int(rng.integers(len(dns)))]
                if kind in (0, 2):        # name lookup (followed by external browsing for kind 0)
                    out.append(fac.make(rng, t, cl, d, 53, UDP, udp_exchange(rng, int(rng.integers(30, 70)),
                                                                                int(rng.integers(60, 300)))))
                if kind == 0:
                    ext = n.common_external[int(rng.integers(len(n.common_external)))]
                    out.append(fac.make(rng, t + 0.02, cl, ext, 443, TCP, _web(rng, False)))
                elif kind == 1:
                    a = apps[int(rng.integers(len(apps)))]
                    out.append(fac.make(rng, t, cl, a, int(rng.choice([443, 8080])), TCP, _web(rng, True)))
                elif kind == 3:           # plain-HTTP internal page
                    a = apps[int(rng.integers(len(apps)))]
                    out.append(fac.make(rng, t, cl, a, 80, TCP, _web(rng, True)))
        for a in apps:
            for t in _times(rng, c.app_to_db_queries_per_s, t0, dt):
                db = dbs[int(rng.integers(len(dbs)))]
                ex = [(int(rng.integers(80, 700)), int(rng.lognormal(7.5, 1.2))) for _ in range(int(rng.integers(1, 4)))]
                out.append(fac.make(rng, t, a, db, 5432, TCP, tcp_session(rng, ex, rtt_us=200, think_us=500)))
            if rng.random() < 0.05 * dt:     # app server calls an external API
                ext = n.common_external[int(rng.integers(len(n.common_external)))]
                out.append(fac.make(rng, t0 + rng.uniform(0, dt), a, ext, 443, TCP, _web(rng, False)))
        for d in dns:
            for t in _times(rng, c.dns_forward_per_s, t0, dt):
                ext = n.common_external[int(rng.integers(len(n.common_external)))]
                out.append(fac.make(rng, t, d, ext, 53, UDP, udp_exchange(rng, int(rng.integers(30, 70)),
                                                                          int(rng.integers(60, 500)), rtt_us=20_000)))
        for r in n.role("router"):
            for t in _times(rng, c.router_ntp_per_s, t0, dt):
                ext = n.common_external[0]
                out.append(fac.make(rng, t, r, ext, 123, UDP, udp_exchange(rng, 48, 48, rtt_us=30_000), sport=123))
        servers = apps + dbs + dns
        for t in _times(rng, c.admin_ssh_per_s, t0, dt):
            s = servers[int(rng.integers(len(servers)))]
            ex = [(int(rng.integers(40, 400)), int(rng.integers(40, 4000))) for _ in range(int(rng.integers(10, 40)))]
            out.append(fac.make(rng, t, n.admin_workstation, s, 22, TCP,
                                tcp_session(rng, ex, rtt_us=300, think_us=float(rng.uniform(5e5, 8e6)))))
        return out


@dataclass
class Scenario:
    """One running instance of an attack-like scenario."""
    id: str
    name: str
    attacker: Device
    targets: list[Device]
    start_t: float
    end_t: float | None
    intensity: float
    rng: np.random.Generator
    state: dict[str, Any] = field(default_factory=dict)
    flows: int = 0

    def active(self, t: float) -> bool:
        return t >= self.start_t and (self.end_t is None or t < self.end_t)

    def generate(self, t0: float, dt: float, fac: FlowFactory) -> list[Flow]:
        lo, hi = max(t0, self.start_t), t0 + dt if self.end_t is None else min(t0 + dt, self.end_t)
        if hi <= lo:
            return []
        out = GENERATORS[self.name](self, lo, hi - lo, fac)
        self.flows += len(out)
        return out

    def to_dict(self) -> dict[str, Any]:
        return {"id": self.id, "name": self.name, "attacker": self.attacker.id, "targets": [d.id for d in self.targets],
                "start_t": round(self.start_t, 3), "end_t": None if self.end_t is None else round(self.end_t, 3),
                "intensity": self.intensity, "flows_generated": self.flows}


def _port_scan(s: Scenario, t0: float, dt: float, fac: FlowFactory) -> list[Flow]:
    order = s.state.setdefault("ports", [int(p) for p in s.rng.permutation(np.arange(1, 1025))])
    tgt = s.targets[0]
    out = []
    for t in _times(s.rng, 40.0 * s.intensity, t0, dt):
        i = s.state.get("i", 0)
        port = order[i % len(order)]
        s.state["i"] = i + 1
        out.append(fac.make(s.rng, t, s.attacker, tgt, port, TCP, tcp_probe(s.rng, port in tgt.services),
                            scenario=s.name, instance=s.id))
    return out


def _dos(s: Scenario, t0: float, dt: float, fac: FlowFactory) -> list[Flow]:
    tgt, out = s.targets[0], []
    port = 80 if 80 in tgt.services else tgt.services[0]
    for t in _times(s.rng, 60.0 * s.intensity, t0, dt):
        if s.rng.random() < 0.4:      # the service no longer answers: retransmitted SYNs
            pk = tcp_unanswered(s.rng, 0, retries=int(s.rng.integers(0, 3)))
        else:                         # tiny request, tiny or truncated response, immediate teardown
            pk = tcp_session(s.rng, [(int(s.rng.integers(60, 200)), int(s.rng.integers(0, 300)))], rtt_us=2_000,
                             think_us=100)
        out.append(fac.make(s.rng, t, s.attacker, tgt, port, TCP, pk, scenario=s.name, instance=s.id))
    return out


def _lateral(s: Scenario, t0: float, dt: float, fac: FlowFactory) -> list[Flow]:
    out = []
    for t in _times(s.rng, 1.5 * s.intensity, t0, dt):
        tgt = s.targets[int(s.rng.integers(len(s.targets)))]
        port = int(s.rng.choice([445, 3389, 135, 5985]))
        if port in tgt.services and s.rng.random() < 0.7:
            ex = [(int(s.rng.integers(100, 3000)), int(s.rng.integers(100, 30_000))) for _ in range(int(s.rng.integers(2, 8)))]
            pk = tcp_session(s.rng, ex, rtt_us=300, think_us=20_000)
        else:
            pk = tcp_probe(s.rng, False)
        out.append(fac.make(s.rng, t, s.attacker, tgt, port, TCP, pk, scenario=s.name, instance=s.id))
    return out


def _brute_force(s: Scenario, t0: float, dt: float, fac: FlowFactory) -> list[Flow]:
    tgt, out = s.targets[0], []
    for t in _times(s.rng, 1.5 * s.intensity, t0, dt):
        # SSH banner + key exchange + one failed password attempt, then the server closes.
        ex = [(int(s.rng.integers(20, 45)), int(s.rng.integers(20, 45))), (int(s.rng.integers(1000, 1600)), int(s.rng.integers(700, 1100))),
              (int(s.rng.integers(40, 120)), int(s.rng.integers(200, 600))), (int(s.rng.integers(60, 140)), int(s.rng.integers(30, 90)))]
        out.append(fac.make(s.rng, t, s.attacker, tgt, 22, TCP,
                            tcp_session(s.rng, ex, rtt_us=20_000 if not s.attacker.internal else 300,
                                        think_us=float(s.rng.uniform(5e4, 3e5))),
                            scenario=s.name, instance=s.id))
    return out


def _exfiltration(s: Scenario, t0: float, dt: float, fac: FlowFactory) -> list[Flow]:
    tgt, out = s.targets[0], []
    port = s.state.setdefault("port", int(s.rng.choice([4444, 8443, 9001])))
    for t in _times(s.rng, 0.1, t0, dt):              # command-and-control style beacon
        out.append(fac.make(s.rng, t, s.attacker, tgt, port, TCP,
                            tcp_session(s.rng, [(int(s.rng.integers(100, 400)), int(s.rng.integers(50, 300)))],
                                        rtt_us=40_000), scenario=s.name, instance=s.id))
    for t in _times(s.rng, 0.3 * s.intensity, t0, dt):  # bulk upload: much more sent than received
        up = int(s.rng.integers(2_000_000, 8_000_000))
        out.append(fac.make(s.rng, t, s.attacker, tgt, port, TCP,
                            tcp_session(s.rng, [(up, int(s.rng.integers(100, 2000)))], rtt_us=40_000, think_us=10_000),
                            scenario=s.name, instance=s.id))
    return out


GENERATORS: dict[str, Callable[[Scenario, float, float, FlowFactory], list[Flow]]] = {
    "port_scan": _port_scan, "dos": _dos, "lateral_movement": _lateral, "brute_force": _brute_force,
    "suspicious_outbound": _exfiltration}

CATALOG: dict[str, dict[str, Any]] = {
    "normal": {"description": "Routine traffic only: DNS, internal and external web, app-to-database queries, DNS "
                              "forwarding, NTP and admin SSH. Selecting it stops every active attack scenario.",
               "default_attacker": None, "default_target": None},
    "port_scan": {"description": "One host sends SYN probes to the first 1,024 TCP ports of a server (about 40 probes/s "
                                 "at intensity 1); open ports answer SYN/ACK, closed ones RST.",
                  "default_attacker": "a workstation or laptop", "default_target": "an application server"},
    "dos": {"description": "One host opens short HTTP connections to a server at about 60/s; 40% of them are "
                           "unanswered SYN retransmissions, as from an overwhelmed service.",
            "default_attacker": "a workstation or laptop", "default_target": "an application server"},
    "lateral_movement": {"description": "A workstation contacts other workstations and laptops on administrative ports "
                                        "(SMB 445, RDP 3389, RPC 135, WinRM 5985), about 1.5 attempts/s.",
                         "default_attacker": "a workstation other than the admin workstation",
                         "default_target": "five other workstations or laptops"},
    "brute_force": {"description": "An external endpoint opens short SSH sessions, each ending after a failed login, "
                                   "about 1.5 attempts/s.",
                    "default_attacker": "a rarely contacted external endpoint", "default_target": "an application server"},
    "suspicious_outbound": {"description": "An internal host beacons to a rarely contacted external endpoint on a "
                                           "non-standard port and uploads 2-8 MB per transfer (about 0.3/s).",
                            "default_attacker": "a workstation or laptop",
                            "default_target": "a rarely contacted external endpoint"},
}


def default_participants(name: str, net: Network, rng: np.random.Generator) -> tuple[Device, list[Device]]:
    clients = [d for d in net.clients() if d.id != net.admin_workstation.id]
    pick = lambda xs: xs[int(rng.integers(len(xs)))]  # noqa: E731
    if name in ("port_scan", "dos"):
        return pick(clients), [pick(net.role("app_server"))]
    if name == "lateral_movement":
        a = pick(clients)
        others = [d for d in net.clients() if d.id != a.id]
        k = min(5, len(others))
        return a, [others[int(i)] for i in rng.choice(len(others), k, replace=False)]
    if name == "brute_force":
        return pick(net.rare_external), [pick(net.role("app_server"))]
    if name == "suspicious_outbound":
        return pick(clients), [pick(net.rare_external)]
    raise KeyError(name)


def validate_participants(name: str, attacker: Device, targets: list[Device]) -> None:
    """Reject combinations the generator cannot model (e.g. a target that is the attacker)."""
    if any(t.id == attacker.id for t in targets):
        raise ValueError("the attacker cannot be its own target")
    if not targets:
        raise ValueError("at least one target is required")
    if name == "lateral_movement" and (not attacker.internal or any(t.role not in CLIENT_ROLES for t in targets)):
        raise ValueError("lateral movement needs an internal attacker and workstation/laptop targets")
    if name == "suspicious_outbound" and (not attacker.internal or targets[0].internal):
        raise ValueError("suspicious outbound needs an internal source and an external destination")
    if name in ("port_scan", "dos") and not targets[0].services:
        raise ValueError("the target offers no service")
