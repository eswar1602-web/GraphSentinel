"""Packet-level synthesis of one simulated flow and CICFlowMeter-style feature extraction.

The XGBoost detector was trained on the CICIDS2017 flow features produced by CICFlowMeter. To score simulated
flows without inventing feature values, each simulated flow is first generated as a sequence of synthetic packets
(time, direction, payload length, transport-header length, TCP flags, TCP window) and every feature is then
*computed* from that sequence, following the CICFlowMeter definitions:

* times in microseconds; Flow Duration = last - first packet time;
* lengths are payload (segment) lengths; header lengths are transport-header bytes;
* standard deviations are sample standard deviations (n - 1), 0 for fewer than two values;
* rates divide by the duration in seconds and are +inf for zero-duration flows (the shared Milestone 1 value
  corrections turn them into missing values, exactly as for real CICIDS2017 rows);
* Init_Win_bytes_* is the TCP window of the first packet in that direction, -1 if there is none (CICIDS2017 sentinel);
* Active/Idle periods split the flow at gaps larger than 5 s (CICFlowMeter activity timeout);
* one subflow per flow (Subflow * = totals).

This is an approximation of CICFlowMeter, not a re-implementation: bulk features are absent from the model's
feature set, and real network effects (retransmissions, MSS, options) are only roughly modelled. Predictions on
simulated flows are therefore out-of-distribution model outputs and are reported as such.
"""
from __future__ import annotations

import math
from dataclasses import dataclass

import numpy as np

ACTIVITY_TIMEOUT_US = 5_000_000.0
TCP, UDP = 6, 17
TCP_HDR, UDP_HDR = 32, 8

# The 69 raw CICIDS2017 columns this module computes (the model's 72 inputs minus 3 indicator columns that the
# shared value corrections derive). ml.py checks this list against the model's feature schema before any scoring.
FEATURE_COLUMNS: tuple[str, ...] = (
    "Protocol", "Flow Duration", "Total Fwd Packets", "Total Backward Packets", "Total Length of Fwd Packets",
    "Total Length of Bwd Packets", "Fwd Packet Length Max", "Fwd Packet Length Min", "Fwd Packet Length Mean",
    "Fwd Packet Length Std", "Bwd Packet Length Max", "Bwd Packet Length Min", "Bwd Packet Length Mean",
    "Bwd Packet Length Std", "Flow Bytes/s", "Flow Packets/s", "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max",
    "Flow IAT Min", "Fwd IAT Total", "Fwd IAT Mean", "Fwd IAT Std", "Fwd IAT Max", "Fwd IAT Min", "Bwd IAT Total",
    "Bwd IAT Mean", "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min", "Fwd PSH Flags", "Fwd URG Flags",
    "Fwd Header Length", "Bwd Header Length", "Fwd Packets/s", "Bwd Packets/s", "Min Packet Length",
    "Max Packet Length", "Packet Length Mean", "Packet Length Std", "Packet Length Variance", "FIN Flag Count",
    "SYN Flag Count", "RST Flag Count", "PSH Flag Count", "ACK Flag Count", "URG Flag Count", "CWE Flag Count",
    "ECE Flag Count", "Down/Up Ratio", "Average Packet Size", "Avg Fwd Segment Size", "Avg Bwd Segment Size",
    "Subflow Fwd Packets", "Subflow Fwd Bytes", "Subflow Bwd Packets", "Subflow Bwd Bytes", "Init_Win_bytes_forward",
    "Init_Win_bytes_backward", "act_data_pkt_fwd", "min_seg_size_forward", "Active Mean", "Active Std", "Active Max",
    "Active Min", "Idle Mean", "Idle Std", "Idle Max", "Idle Min")


@dataclass(frozen=True, slots=True)
class Packet:
    t_us: float          # microseconds since flow start
    fwd: bool            # True: initiator -> responder
    payload: int         # bytes
    header: int          # transport header bytes
    flags: str = ""      # subset of "FSRPAUCE" (FIN SYN RST PSH ACK URG CWE ECE)
    window: int = 0      # TCP window (0 for UDP)


class PacketBuilder:
    """Appends packets with increasing timestamps."""

    def __init__(self, protocol: int, rng: np.random.Generator) -> None:
        self.protocol, self.rng, self.t, self.pkts = protocol, rng, 0.0, []
        self.hdr = TCP_HDR if protocol == TCP else UDP_HDR

    def add(self, fwd: bool, payload: int, flags: str = "", window: int = 0, gap_us: float = 0.0) -> None:
        if self.pkts:
            self.t += max(gap_us, 1.0)
        self.pkts.append(Packet(self.t, fwd, max(int(payload), 0), self.hdr, flags if self.protocol == TCP else "",
                                window if self.protocol == TCP else 0))

    def rtt(self, base_us: float) -> float:
        return float(self.rng.gamma(4.0, base_us / 4.0))


def tcp_session(rng: np.random.Generator, exchanges: list[tuple[int, int]], rtt_us: float = 400.0,
                think_us: float = 2_000.0, close: bool = True, win_fwd: int = 29200, win_bwd: int = 28960,
                mss: int = 1460) -> list[Packet]:
    """Complete TCP connection: handshake, request/response exchanges (bytes each way), FIN teardown."""
    b = PacketBuilder(TCP, rng)
    b.add(True, 0, "S", win_fwd)
    b.add(False, 0, "SA", win_bwd, b.rtt(rtt_us))
    b.add(True, 0, "A", win_fwd, 40)
    for req, resp in exchanges:
        for i, seg in enumerate(_segments(req, mss)):
            b.add(True, seg, "PA", win_fwd, b.rtt(think_us) if i == 0 else 30)
        for i, seg in enumerate(_segments(resp, mss)):
            b.add(False, seg, "PA" if i == 0 else "A", win_bwd, b.rtt(rtt_us) if i == 0 else 15)
        if resp:
            b.add(True, 0, "A", win_fwd, 40)
    if close:
        b.add(True, 0, "FA", win_fwd, b.rtt(think_us))
        b.add(False, 0, "FA", win_bwd, b.rtt(rtt_us))
        b.add(True, 0, "A", win_fwd, 40)
    return b.pkts


def tcp_probe(rng: np.random.Generator, open_port: bool, rtt_us: float = 300.0) -> list[Packet]:
    """SYN probe: closed port -> RST/ACK; open port -> SYN/ACK then the prober resets (half-open scan)."""
    b = PacketBuilder(TCP, rng)
    b.add(True, 0, "S", 1024)
    if open_port:
        b.add(False, 0, "SA", 28960, b.rtt(rtt_us))
        b.add(True, 0, "R", 0, 20)
    else:
        b.add(False, 0, "RA", 0, b.rtt(rtt_us))
    return b.pkts


def tcp_unanswered(rng: np.random.Generator, payload: int, retries: int = 1, rto_us: float = 1_000_000.0) -> list[Packet]:
    """Connection attempt to an overwhelmed service: SYN retransmissions without an answer (DoS symptom)."""
    b = PacketBuilder(TCP, rng)
    for i in range(1 + retries):
        b.add(True, 0, "S", 29200, rto_us * (2 ** (i - 1)) if i else 0)
    if payload:
        b.add(True, payload, "PA", 29200, 50)
    return b.pkts


def udp_exchange(rng: np.random.Generator, req: int, resp: int, rtt_us: float = 800.0, repeats: int = 1) -> list[Packet]:
    b = PacketBuilder(UDP, rng)
    for i in range(repeats):
        b.add(True, req, gap_us=b.rtt(50_000) if i else 0)
        if resp:
            b.add(False, resp, gap_us=b.rtt(rtt_us))
    return b.pkts


def _segments(n: int, mss: int) -> list[int]:
    if n <= 0:
        return []
    full, rest = divmod(int(n), mss)
    return [mss] * full + ([rest] if rest else [])


def _stats(v: np.ndarray) -> tuple[float, float, float, float]:
    """mean, sample std, max, min (zeros for an empty array; std 0 for one value)."""
    if v.size == 0:
        return 0.0, 0.0, 0.0, 0.0
    return float(v.mean()), float(v.std(ddof=1)) if v.size > 1 else 0.0, float(v.max()), float(v.min())


def cic_features(pkts: list[Packet], protocol: int) -> dict[str, float]:
    """All FEATURE_COLUMNS for one flow, computed from its packets."""
    if not pkts:
        raise ValueError("a flow needs at least one packet")
    if not pkts[0].fwd:
        raise ValueError("the first packet of a flow must come from the initiator")
    t = np.array([p.t_us for p in pkts], dtype="float64")
    if np.any(np.diff(t) < 0):
        raise ValueError("packet timestamps must be non-decreasing")
    fwd = np.array([p.fwd for p in pkts])
    ln = np.array([p.payload for p in pkts], dtype="float64")
    hdr = np.array([p.header for p in pkts], dtype="float64")
    fl, bl = ln[fwd], ln[~fwd]
    dur = float(t[-1] - t[0])
    secs = dur / 1e6
    nf, nb = int(fwd.sum()), int((~fwd).sum())
    tot_f, tot_b = float(fl.sum()), float(bl.sum())
    f: dict[str, float] = {"Protocol": float(protocol), "Flow Duration": dur, "Total Fwd Packets": float(nf),
                           "Total Backward Packets": float(nb), "Total Length of Fwd Packets": tot_f,
                           "Total Length of Bwd Packets": tot_b}
    fm, fs, fx, fn = _stats(fl)
    bm, bs, bx, bn = _stats(bl)
    f.update({"Fwd Packet Length Max": fx, "Fwd Packet Length Min": fn, "Fwd Packet Length Mean": fm,
              "Fwd Packet Length Std": fs, "Bwd Packet Length Max": bx, "Bwd Packet Length Min": bn,
              "Bwd Packet Length Mean": bm, "Bwd Packet Length Std": bs})
    f["Flow Bytes/s"] = (tot_f + tot_b) / secs if secs > 0 else math.inf
    f["Flow Packets/s"] = len(pkts) / secs if secs > 0 else math.inf
    m, s, x, n = _stats(np.diff(t))
    f.update({"Flow IAT Mean": m, "Flow IAT Std": s, "Flow IAT Max": x, "Flow IAT Min": n})
    for name, mask in (("Fwd", fwd), ("Bwd", ~fwd)):
        d = np.diff(t[mask])
        m, s, x, n = _stats(d)
        f.update({f"{name} IAT Total": float(d.sum()), f"{name} IAT Mean": m, f"{name} IAT Std": s,
                  f"{name} IAT Max": x, f"{name} IAT Min": n})
    flags = [p.flags for p in pkts]
    f["Fwd PSH Flags"] = float(sum("P" in p.flags for p in pkts if p.fwd))
    f["Fwd URG Flags"] = float(sum("U" in p.flags for p in pkts if p.fwd))
    f["Fwd Header Length"], f["Bwd Header Length"] = float(hdr[fwd].sum()), float(hdr[~fwd].sum())
    f["Fwd Packets/s"] = nf / secs if secs > 0 else 0.0
    f["Bwd Packets/s"] = nb / secs if secs > 0 else 0.0
    m, s, x, n = _stats(ln)
    f.update({"Min Packet Length": n, "Max Packet Length": x, "Packet Length Mean": m, "Packet Length Std": s,
              "Packet Length Variance": s * s})
    for col, ch in (("FIN", "F"), ("SYN", "S"), ("RST", "R"), ("PSH", "P"), ("ACK", "A"), ("URG", "U"),
                    ("CWE", "C"), ("ECE", "E")):
        f[f"{col} Flag Count"] = float(sum(ch in fl_ for fl_ in flags))
    f["Down/Up Ratio"] = float(nb // nf) if nf else 0.0
    f["Average Packet Size"] = float(ln.sum() / len(pkts))
    f["Avg Fwd Segment Size"], f["Avg Bwd Segment Size"] = fm, bm
    f.update({"Subflow Fwd Packets": float(nf), "Subflow Fwd Bytes": tot_f, "Subflow Bwd Packets": float(nb),
              "Subflow Bwd Bytes": tot_b})
    first_f = next((p for p in pkts if p.fwd), None)
    first_b = next((p for p in pkts if not p.fwd), None)
    tcp = protocol == TCP
    f["Init_Win_bytes_forward"] = float(first_f.window) if tcp and first_f else -1.0
    f["Init_Win_bytes_backward"] = float(first_b.window) if tcp and first_b else -1.0
    f["act_data_pkt_fwd"] = float((fl >= 1).sum())
    f["min_seg_size_forward"] = float(hdr[fwd].min()) if nf else 0.0
    active, idle, start, last = [], [], t[0], t[0]
    for ti in t[1:]:
        if ti - last > ACTIVITY_TIMEOUT_US:
            if last - start > 0:
                active.append(last - start)
            idle.append(ti - last)
            start = ti
        last = ti
    if idle and last - start > 0:
        active.append(last - start)
    for name, v in (("Active", active), ("Idle", idle)):
        m, s, x, n = _stats(np.array(v, dtype="float64"))
        f.update({f"{name} Mean": m, f"{name} Std": s, f"{name} Max": x, f"{name} Min": n})
    missing = set(FEATURE_COLUMNS) - f.keys()
    if missing:
        raise AssertionError(f"feature extractor did not produce {sorted(missing)}")
    return {c: f[c] for c in FEATURE_COLUMNS}
