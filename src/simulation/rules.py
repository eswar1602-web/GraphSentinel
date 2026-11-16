"""Behavioural detection: explainable threshold rules over sliding time windows of simulated flows.

Rules (thresholds in configs/simulation.yaml, section ``detection``):

* ``port_scan``         unusual port diversity: one source reaches >= N distinct destination ports of one host.
* ``host_sweep``        one source reaches >= N distinct internal hosts on the same port.
* ``connection_rate``   connection frequency: flows/s from one source to one destination service >= threshold.
* ``traffic_volume``    bytes sent from one source to one destination >= threshold and sent/received >= ratio.
* ``brute_force``       repeated short sessions to one authentication service (SSH, RDP, ...) >= N.
* ``unexpected_communication``  a (source, destination, port) never seen during the baseline warm-up that also
  breaks the network's role policy: client-to-client traffic, an external endpoint initiating a connection,
  outbound traffic on a non-allowed port, or a new administrative-port connection to a server.

Only flow fields and the asset inventory (device roles) are used: never the simulator's ground truth.
Every window keeps incremental counters, so evaluation is O(1) per flow and memory is bounded per key.
"""
from __future__ import annotations

from collections import Counter, deque
from typing import Any, Iterable

from src.simulation.config import DetectionConfig
from src.simulation.flows import Flow
from src.simulation.network import CLIENT_ROLES, Network

MAX_WINDOW_ENTRIES = 20_000
SEVERITIES = ("low", "medium", "high", "critical")


def escalate(base: str, ratio: float) -> str:
    """Raise severity by one level when the observed value is at least 4x the threshold."""
    i = SEVERITIES.index(base)
    return SEVERITIES[min(i + (1 if ratio >= 4 else 0), len(SEVERITIES) - 1)]


class Window:
    """Time-ordered entries with a distinct-item counter and two running sums."""
    __slots__ = ("q", "items", "sum_a", "sum_b", "capped")

    def __init__(self) -> None:
        self.q: deque[tuple[float, str, Any, int, int]] = deque()
        self.items: Counter = Counter()
        self.sum_a = 0
        self.sum_b = 0
        self.capped = False

    def add(self, t: float, fid: str, item: Any = None, a: int = 0, b: int = 0) -> None:
        if len(self.q) >= MAX_WINDOW_ENTRIES:
            self._pop()
            self.capped = True
        self.q.append((t, fid, item, a, b))
        self.items[item] += 1
        self.sum_a += a
        self.sum_b += b

    def _pop(self) -> None:
        _, _, item, a, b = self.q.popleft()
        self.items[item] -= 1
        if self.items[item] <= 0:
            del self.items[item]
        self.sum_a -= a
        self.sum_b -= b

    def evict(self, cutoff: float) -> None:
        while self.q and self.q[0][0] < cutoff:
            self._pop()

    def __len__(self) -> int:
        return len(self.q)

    def flow_ids(self, n: int) -> list[str]:
        return [e[1] for e in list(self.q)[-n:]]


class BehaviouralDetector:
    def __init__(self, net: Network, cfg: DetectionConfig, evidence_ids: int = 50) -> None:
        self.net, self.cfg, self.k = net, cfg, evidence_ids
        self.pair: dict[tuple[str, str], Window] = {}           # item = dst_port, a = fwd bytes, b = bwd bytes
        self.service: dict[tuple[str, str, int], Window] = {}   # all flows to one service
        self.short_auth: dict[tuple[str, str, int], Window] = {}
        self.sweep: dict[tuple[str, int], Window] = {}          # item = internal dst device
        self.baseline: set[tuple[str, str, int]] = set()
        self.baseline_frozen = False
        self.auth, self.admin = set(cfg.auth_ports), set(cfg.admin_ports)
        self.allowed_out = set(cfg.allowed_outbound_ports)
        self.unexpected_seen: dict[tuple[str, str, int], list[str]] = {}

    def memory(self) -> dict[str, int]:
        return {"windows": len(self.pair) + len(self.service) + len(self.short_auth) + len(self.sweep),
                "window_entries": sum(len(w) for d in (self.pair, self.service, self.short_auth, self.sweep) for w in d.values()),
                "baseline_pairs": len(self.baseline)}

    def _w(self, d: dict, key: Any) -> Window:
        w = d.get(key)
        if w is None:
            w = d[key] = Window()
        return w

    def process(self, flows: Iterable[Flow], now: float) -> list[dict[str, Any]]:
        """Add a batch of flows (sorted by time) and return findings for the keys they touched."""
        c = self.cfg
        dev = self.net.devices
        touched_pair, touched_service, touched_auth, touched_sweep = set(), set(), set(), set()
        findings: list[dict[str, Any]] = []
        for f in flows:
            kp, ks = (f.src, f.dst), (f.src, f.dst, f.dst_port)
            self._w(self.pair, kp).add(f.sim_t, f.flow_id, f.dst_port, f.fwd_bytes, f.bwd_bytes)
            self._w(self.service, ks).add(f.sim_t, f.flow_id)
            touched_pair.add(kp)
            touched_service.add(ks)
            if f.dst_port in self.auth and f.protocol == 6 and f.duration_s <= c.brute_force_max_duration_s:
                self._w(self.short_auth, ks).add(f.sim_t, f.flow_id)
                touched_auth.add(ks)
            if dev[f.dst].internal:
                self._w(self.sweep, (f.src, f.dst_port)).add(f.sim_t, f.flow_id, f.dst)
                touched_sweep.add((f.src, f.dst_port))
            u = self._unexpected(f)
            if u:
                findings.append(u)
        cutoff = now - c.window_s
        for kp in touched_pair:
            w = self.pair[kp]
            w.evict(cutoff)
            src, dst = kp
            if len(w.items) >= c.port_scan_distinct_ports:
                ports = sorted(p for p in w.items)
                failed = sum(1 for e in w.q if e[4] == 0)
                findings.append(self._finding(
                    "port_scan", escalate("medium", len(ports) / c.port_scan_distinct_ports), src, [dst], now,
                    f"Port scan suspected: {src} -> {dst}",
                    f"{src} contacted {len(ports)} distinct ports on {dst} within {c.window_s:g} s "
                    f"(threshold {c.port_scan_distinct_ports}); {failed} of {len(w)} connections received no reply payload.",
                    {"distinct_ports": len(ports), "ports_sample": ports[:25], "connections": len(w),
                     "no_reply_payload": failed, "threshold": c.port_scan_distinct_ports}, w))
            ratio = w.sum_a / max(w.sum_b, 1)
            if w.sum_a >= c.volume_bytes and ratio >= c.volume_upload_ratio:
                findings.append(self._finding(
                    "traffic_volume", escalate("high", w.sum_a / c.volume_bytes), src, [dst], now,
                    f"Unusual data volume: {src} -> {dst}",
                    f"{src} sent {w.sum_a / 1e6:.1f} MB to {dst} within {c.window_s:g} s "
                    f"(threshold {c.volume_bytes / 1e6:.1f} MB) while receiving {w.sum_b / 1e3:.1f} kB "
                    f"(sent/received {ratio:.0f}x, threshold {c.volume_upload_ratio:g}x).",
                    {"bytes_sent": w.sum_a, "bytes_received": w.sum_b, "upload_ratio": round(ratio, 2),
                     "threshold_bytes": c.volume_bytes, "connections": len(w),
                     "destination_role": dev[dst].role}, w))
        for ks in touched_service:
            w = self.service[ks]
            w.evict(cutoff)
            rate = len(w) / c.window_s
            if rate >= c.conn_rate_per_s:
                src, dst, port = ks
                findings.append(self._finding(
                    "connection_rate", escalate("high", rate / c.conn_rate_per_s), src, [dst], now,
                    f"High connection rate: {src} -> {dst}:{port}",
                    f"{src} opened {len(w)} connections to {dst} port {port} within {c.window_s:g} s "
                    f"({rate:.1f}/s, threshold {c.conn_rate_per_s:g}/s).",
                    {"connections": len(w), "rate_per_s": round(rate, 2), "port": port,
                     "threshold_per_s": c.conn_rate_per_s, "window_capped": w.capped}, w))
        for ks in touched_auth:
            w = self.short_auth[ks]
            w.evict(cutoff)
            if len(w) >= c.brute_force_attempts:
                src, dst, port = ks
                findings.append(self._finding(
                    "brute_force", escalate("high", len(w) / c.brute_force_attempts), src, [dst], now,
                    f"Repeated authentication attempts: {src} -> {dst}:{port}",
                    f"{src} opened {len(w)} short sessions (each <= {c.brute_force_max_duration_s:g} s) to the "
                    f"authentication service on {dst} port {port} within {c.window_s:g} s "
                    f"(threshold {c.brute_force_attempts}).",
                    {"short_sessions": len(w), "port": port, "threshold": c.brute_force_attempts,
                     "max_session_s": c.brute_force_max_duration_s}, w))
        for kw in touched_sweep:
            w = self.sweep[kw]
            w.evict(cutoff)
            if len(w.items) >= c.host_sweep_distinct_hosts:
                src, port = kw
                hosts = sorted(w.items)
                findings.append(self._finding(
                    "host_sweep", escalate("high", len(hosts) / c.host_sweep_distinct_hosts), src, hosts, now,
                    f"Host sweep on port {port} from {src}",
                    f"{src} contacted {len(hosts)} distinct internal hosts on port {port} within {c.window_s:g} s "
                    f"(threshold {c.host_sweep_distinct_hosts}).",
                    {"distinct_hosts": len(hosts), "port": port, "threshold": c.host_sweep_distinct_hosts}, w)
                    | {"group": f"port:{port}"})
        if not self.baseline_frozen and now >= c.baseline_warmup_s:
            self.baseline_frozen = True
        return findings

    def _unexpected(self, f: Flow) -> dict[str, Any] | None:
        key = (f.src, f.dst, f.dst_port)
        if not self.baseline_frozen:
            if f.sim_t < self.cfg.baseline_warmup_s:
                self.baseline.add(key)
                return None
            self.baseline_frozen = True
        if key in self.baseline:
            return None
        s, d = self.net.devices[f.src], self.net.devices[f.dst]
        if s.role in CLIENT_ROLES and d.role in CLIENT_ROLES:
            why, sev = "client-to-client connection (workstations and laptops do not serve each other)", \
                "high" if f.dst_port in self.admin else "medium"
        elif not s.internal and d.internal:
            why, sev = "an external endpoint initiated a connection to an internal device", "medium"
        elif s.internal and not d.internal and f.dst_port not in self.allowed_out:
            why, sev = f"outbound connection on non-allowed port {f.dst_port} (allowed: {sorted(self.allowed_out)})", "high"
        elif d.internal and d.role not in CLIENT_ROLES and f.dst_port in self.admin:
            why, sev = f"new administrative-port ({f.dst_port}) connection to a server", "low"
        else:
            return None
        ids = self.unexpected_seen.setdefault(key, [])
        ids.append(f.flow_id)
        del ids[:-self.k]
        if len(self.unexpected_seen) > 5000:            # bounded: forget the oldest keys
            for k in list(self.unexpected_seen)[:1000]:
                del self.unexpected_seen[k]
        return {"rule": "unexpected_communication", "severity": sev, "src": f.src, "dst_devices": [f.dst],
                "t": f.sim_t, "title": f"Unexpected communication: {f.src} -> {f.dst}:{f.dst_port}",
                "explanation": f"{f.src} ({s.role}) -> {f.dst} ({d.role}) port {f.dst_port} was not seen during the "
                               f"{self.cfg.baseline_warmup_s:g} s baseline and breaks the role policy: {why}.",
                "evidence": {"port": f.dst_port, "src_role": s.role, "dst_role": d.role, "policy": why,
                             "connections_seen": len(ids)},
                "flow_ids": list(ids)}

    def _finding(self, rule: str, sev: str, src: str, dsts: list[str], now: float, title: str, explanation: str,
                 evidence: dict[str, Any], w: Window) -> dict[str, Any]:
        return {"rule": rule, "severity": sev, "src": src, "dst_devices": dsts, "t": now, "title": title,
                "explanation": explanation, "evidence": {**evidence, "window_s": self.cfg.window_s},
                "flow_ids": w.flow_ids(self.k)}

    def sweep_idle(self, now: float) -> None:
        """Drop windows that hold no entry inside the current window (bounds memory for idle keys)."""
        cutoff = now - self.cfg.window_s
        for d in (self.pair, self.service, self.short_auth, self.sweep):
            for k in [k for k, w in d.items() if not w.q or w.q[-1][0] < cutoff]:
                del d[k]
