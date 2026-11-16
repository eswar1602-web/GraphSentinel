"""Unit and pipeline tests of the live network simulation (src/simulation)."""
from __future__ import annotations

import dataclasses
import ipaddress
import math
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pytest
from pydantic import ValidationError

from src.cryptography.audit_log import AuditLog
from src.simulation.config import SimConfig, load_config
from src.simulation.engine import SimulationEngine, SimulationError, evidence_digest
from src.simulation.flows import Flow, FlowValidationError, make_flow, validate_flow
from src.simulation.graph import MAX_PORTS_PER_EDGE, LiveGraph
from src.simulation.incidents import AlertManager, IncidentManager, check_transition
from src.simulation.ml import MLDetector
from src.simulation.network import EXTERNAL_NETS, Network
from src.simulation.packets import (FEATURE_COLUMNS, TCP, UDP, Packet, cic_features, tcp_probe, tcp_session,
                                    udp_exchange)
from src.simulation.rules import BehaviouralDetector, Window
from src.simulation.scenarios import CATALOG, FlowFactory, NormalTraffic, Scenario, default_participants
from src.simulation.store import SimStore

T0 = datetime(2026, 1, 5, 9, 0, tzinfo=timezone.utc)


def cfg(**over) -> SimConfig:
    return load_config(overrides={"start_time": T0, **over})


@pytest.fixture()
def net() -> Network:
    return Network(SimConfig().network, 11)


def flow(net: Network, src: str, dst: str, dport: int, t: float, pkts: list[Packet] | None = None, proto: int = TCP,
         fid: list[int] = [0]) -> Flow:  # noqa: B006 - deliberate shared counter for unique ids
    fid[0] += 1
    rng = np.random.default_rng(fid[0])
    return make_flow(f"t-{fid[0]:06d}", T0, t, net.get(src), net.get(dst), 50000, dport, proto,
                     pkts or tcp_session(rng, [(100, 1000)]))


# --------------------------------------------------------------------------- config and topology
def test_config_validation(tmp_path: Path) -> None:
    c = load_config()
    assert c.network.workstations >= 2 and c.clock.speed > 0
    with pytest.raises(ValidationError):
        load_config(overrides={"clock": {"speed": -1}})
    with pytest.raises(ValidationError):
        load_config(overrides={"unknown_section": 1})
    with pytest.raises(ValidationError):
        load_config(overrides={"start_time": datetime(2026, 1, 1)})          # naive timestamp
    assert load_config(tmp_path / "absent.yaml").seed == SimConfig().seed


def test_topology_deterministic_and_safe(net: Network) -> None:
    again = Network(SimConfig().network, 11)
    assert [d.ip for d in net.devices.values()] == [d.ip for d in again.devices.values()]
    assert len({d.ip for d in net.devices.values()}) == len(net.devices)
    for d in net.devices.values():
        ip = ipaddress.ip_address(d.ip)
        if d.internal:
            assert ip in ipaddress.ip_network("10.10.0.0/16")
        else:   # RFC 5737 documentation ranges only: never routed, nothing real is ever addressed
            assert any(ip in n for n in EXTERNAL_NETS)
    c = net.to_dict()["counts"]
    assert c["workstation"] == 12 and c["external"] == 8 and c["router"] == 1
    assert set(net.rare_external).isdisjoint(net.common_external)


# --------------------------------------------------------------------------- packets and features
def test_cic_features_hand_computed() -> None:
    pk = [Packet(0, True, 0, 32, "S", 1000), Packet(100, False, 0, 32, "SA", 2000), Packet(150, True, 10, 32, "PA", 1000),
          Packet(450, False, 30, 32, "PA", 2000), Packet(1150, True, 0, 32, "FA", 1000)]
    f = cic_features(pk, TCP)
    assert list(f) == list(FEATURE_COLUMNS) and len(FEATURE_COLUMNS) == 69
    assert f["Flow Duration"] == 1150 and f["Total Fwd Packets"] == 3 and f["Total Backward Packets"] == 2
    assert f["Total Length of Fwd Packets"] == 10 and f["Total Length of Bwd Packets"] == 30
    assert f["Flow IAT Max"] == 700 and f["Flow IAT Min"] == 50 and f["Flow IAT Mean"] == pytest.approx(1150 / 4)
    assert f["Fwd IAT Total"] == 1150 and f["Bwd IAT Total"] == 350
    assert f["Fwd Packet Length Std"] == pytest.approx(np.std([0, 10, 0], ddof=1))
    assert f["Flow Bytes/s"] == pytest.approx(40 / 1150e-6)
    assert f["SYN Flag Count"] == 2 and f["ACK Flag Count"] == 4 and f["FIN Flag Count"] == 1 and f["PSH Flag Count"] == 2
    assert f["Fwd PSH Flags"] == 1 and f["Down/Up Ratio"] == 0
    assert f["Init_Win_bytes_forward"] == 1000 and f["Init_Win_bytes_backward"] == 2000
    assert f["Fwd Header Length"] == 96 and f["min_seg_size_forward"] == 32 and f["act_data_pkt_fwd"] == 1
    assert f["Average Packet Size"] == pytest.approx(40 / 5) and f["Packet Length Variance"] == pytest.approx(np.var([0, 0, 10, 30, 0], ddof=1))


def test_cic_features_edge_cases() -> None:
    one = cic_features([Packet(0, True, 40, 8)], UDP)
    assert one["Flow Duration"] == 0 and math.isinf(one["Flow Bytes/s"]) and one["Flow IAT Std"] == 0
    assert one["Init_Win_bytes_forward"] == -1 and one["Init_Win_bytes_backward"] == -1   # CICIDS2017 sentinels
    idle = cic_features([Packet(0, True, 1, 32, "A", 5), Packet(1e6, True, 1, 32, "A", 5), Packet(8e6, True, 1, 32, "A", 5),
                         Packet(9e6, True, 1, 32, "A", 5)], TCP)
    assert idle["Idle Max"] == 7e6 and idle["Active Mean"] == pytest.approx(1e6)
    with pytest.raises(ValueError):
        cic_features([], TCP)
    with pytest.raises(ValueError):
        cic_features([Packet(0, False, 1, 32)], TCP)
    with pytest.raises(ValueError):
        cic_features([Packet(5, True, 1, 32), Packet(1, False, 1, 32)], TCP)


# --------------------------------------------------------------------------- flow validation
def test_flow_validation(net: Network) -> None:
    f = flow(net, "ws-01", "app-01", 443, 1.0)
    validate_flow(f, net.by_ip)
    bad = [dataclasses.replace(f, src_ip="999.1.1.1"), dataclasses.replace(f, dst_port=70000),
           dataclasses.replace(f, protocol=1), dataclasses.replace(f, ts=f.ts.replace(tzinfo=None)),
           dataclasses.replace(f, dst="ws-02"), dataclasses.replace(f, fwd_packets=0),
           dataclasses.replace(f, fwd_bytes=f.fwd_bytes + 1), dataclasses.replace(f, dst=f.src, dst_ip=f.src_ip),
           dataclasses.replace(f, features={**f.features, "Flow IAT Min": -3.0}),
           dataclasses.replace(f, features={**f.features, "Flow IAT Mean": float("nan")}),
           dataclasses.replace(f, features={**f.features, "Flow Bytes/s": float("inf")}),
           dataclasses.replace(f, features={k: v for k, v in f.features.items() if k != "Protocol"})]
    for b in bad:
        with pytest.raises(FlowValidationError):
            validate_flow(b, net.by_ip)


# --------------------------------------------------------------------------- traffic generation
def test_normal_traffic_and_scenarios(net: Network) -> None:
    fac = FlowFactory("t", T0)
    rng = np.random.default_rng(0)
    normal = NormalTraffic(net, SimConfig().traffic).generate(rng, 0.0, 120.0, fac)
    assert len(normal) > 200 and {f.scenario for f in normal} == {"normal"}
    assert {f.dst_port for f in normal} <= {53, 80, 123, 443, 8080, 5432, 22}
    for f in normal:
        validate_flow(f, net.by_ip)
        assert 0 <= f.sim_t < 120.0 + 1
    for name in CATALOG:
        if name == "normal":
            continue
        att, tg = default_participants(name, net, rng)
        s = Scenario(f"SC-{name}", name, att, tg, 10.0, 70.0, 1.0, np.random.default_rng(1))
        assert s.generate(0.0, 10.0, fac) == []                                   # not started yet
        fs = s.generate(10.0, 60.0, fac) + s.generate(70.0, 30.0, fac)           # second call is after the end
        assert fs and all(f.scenario == name and f.scenario_instance == s.id and 10 <= f.sim_t < 70 for f in fs)
        assert {f.src for f in fs} == {att.id} and {f.dst for f in fs} <= {t.id for t in tg}
        for f in fs:
            validate_flow(f, net.by_ip)
    att, tg = default_participants("port_scan", net, rng)
    scan = Scenario("s", "port_scan", att, tg, 0.0, None, 1.0, np.random.default_rng(2)).generate(0.0, 20.0, fac)
    assert len({f.dst_port for f in scan}) == len(scan) > 500                     # each probe a new port
    att, tg = default_participants("suspicious_outbound", net, rng)
    out = Scenario("o", "suspicious_outbound", att, tg, 0.0, None, 1.0, np.random.default_rng(3)).generate(0.0, 60.0, fac)
    assert not tg[0].internal and sum(f.fwd_bytes for f in out) > 10 * sum(f.bwd_bytes for f in out)


def test_simulation_is_deterministic() -> None:
    def run() -> list[tuple]:
        e = SimulationEngine(cfg(seed=5))
        e.step(30.0)
        e.launch_scenario("port_scan")
        e.step(30.0)
        return [(f.src, f.dst, f.dst_port, f.features["Flow Duration"]) for f in e.flows]
    assert run() == run()


# --------------------------------------------------------------------------- graph
def test_graph_incremental_updates(net: Network) -> None:
    g = LiveGraph(net)
    f1, f2 = flow(net, "ws-01", "app-01", 443, 1.0), flow(net, "ws-01", "app-01", 8080, 2.0)
    cn, ce = g.add_flows([f1, f2])
    assert cn == {"ws-01", "app-01"} and ce == {("ws-01", "app-01")}
    e = g.edges[("ws-01", "app-01")].to_dict()
    assert e["flows"] == 2 and e["bytes_fwd"] == f1.fwd_bytes + f2.fwd_bytes and e["distinct_ports"] == 2
    cn, ce = g.add_flows([flow(net, "lt-01", "dns-01", 53, 3.0, udp_exchange(np.random.default_rng(0), 40, 90), UDP)])
    assert ce == {("lt-01", "dns-01")} and g.edges[("ws-01", "app-01")].flows == 2       # untouched edge unchanged
    n = g.node_dict("ws-01")
    assert n["flows_out"] == 2 and n["out_degree"] == 1 and not n["suspicious"]
    g.mark_alert({"id": "AL-1", "rule": "port_scan", "severity": "high", "src": "ws-01", "dst_devices": ["app-01"]})
    assert g.node_dict("app-01")["suspicious"] and g.edges[("ws-01", "app-01")].to_dict()["indicators"] == ["port_scan"]
    many = [flow(net, "ws-02", "app-02", p, 4.0, tcp_probe(np.random.default_rng(p), False)) for p in range(1, 101)]
    g.add_flows(many)
    e = g.edges[("ws-02", "app-02")]
    assert len(e.ports) == MAX_PORTS_PER_EDGE and e.to_dict()["distinct_ports"] == 100            # bounded memory
    s = g.structure([f1, f2, *many])
    assert s["window_flows"] == 102 and s["unique_directed_pairs"] == 2 and s["active_nodes"] == 4
    assert len(g.snapshot(suspicious_only=True)["edges"]) == 1
    with pytest.raises(KeyError):
        g.add_flows([dataclasses.replace(f1, dst="nope-01")])


# --------------------------------------------------------------------------- behavioural rules
def detector(net: Network, **over) -> BehaviouralDetector:
    return BehaviouralDetector(net, SimConfig().detection.model_copy(update={"baseline_warmup_s": 0.0, **over}))


def test_window_counters() -> None:
    w = Window()
    for i, p in enumerate([80, 80, 443, 22]):
        w.add(float(i), f"f{i}", p, 10, 1)
    assert len(w) == 4 and len(w.items) == 3 and w.sum_a == 40
    w.evict(2.0)
    assert len(w) == 2 and set(w.items) == {443, 22} and w.sum_b == 2 and w.flow_ids(5) == ["f2", "f3"]


def test_port_scan_rule(net: Network) -> None:
    d = detector(net)
    probes = [flow(net, "ws-03", "app-01", p, 1 + p * 0.01, tcp_probe(np.random.default_rng(p), False)) for p in range(1, 31)]
    found = [x for x in d.process(probes[:10], 2.0) if x["rule"] == "port_scan"]
    assert not found                                                                     # 10 ports < 20
    found = [x for x in d.process(probes[10:], 2.0) if x["rule"] == "port_scan"]
    assert len(found) == 1
    f = found[0]
    assert f["src"] == "ws-03" and f["dst_devices"] == ["app-01"] and f["evidence"]["distinct_ports"] == 30
    assert f["evidence"]["no_reply_payload"] == 30 and set(f["flow_ids"]) <= {p.flow_id for p in probes}
    assert "30 distinct ports" in f["explanation"]
    assert not [x for x in d.process([], 200.0) if x["rule"] == "port_scan"]          # window expired


def test_rate_volume_bruteforce_sweep_rules(net: Network) -> None:
    d = detector(net, conn_rate_per_s=1.0, volume_bytes=1_000_000)
    rng = np.random.default_rng(0)
    flood = [flow(net, "ws-04", "app-01", 80, i * 0.5) for i in range(70)]
    assert {x["rule"] for x in d.process(flood, 35.0)} >= {"connection_rate"}
    up = [flow(net, "ws-05", "ext-08", 443, 40.0 + i, tcp_session(rng, [(600_000, 200)])) for i in range(3)]
    vol = [x for x in d.process(up, 45.0) if x["rule"] == "traffic_volume"]
    assert vol and vol[0]["evidence"]["bytes_sent"] == 1_800_000
    ssh = [flow(net, "ext-07", "app-02", 22, 50.0 + i, tcp_session(rng, [(40, 40), (1200, 900)], think_us=1e4)) for i in range(12)]
    assert "brute_force" in {x["rule"] for x in d.process(ssh, 62.0)}
    sweep = [flow(net, "ws-06", t.id, 445, 70.0 + i, tcp_probe(rng, False)) for i, t in enumerate(net.clients()[:9])
             if t.id != "ws-06"]
    hs = [x for x in d.process(sweep, 80.0) if x["rule"] == "host_sweep"]
    assert hs and hs[0]["evidence"]["distinct_hosts"] >= 8 and hs[0]["group"] == "port:445"


def test_unexpected_communication_uses_baseline_and_policy(net: Network) -> None:
    d = BehaviouralDetector(net, SimConfig().detection.model_copy(update={"baseline_warmup_s": 100.0}))
    assert d.process([flow(net, "ws-01", "ws-02", 445, 10.0)], 11.0) == []          # warm-up: learned, not flagged
    out = d.process([flow(net, "ws-01", "ws-02", 445, 150.0), flow(net, "ws-03", "ws-04", 445, 150.0),
                     flow(net, "ws-03", "ext-01", 4444, 151.0), flow(net, "ws-03", "ext-01", 443, 151.0),
                     flow(net, "ext-02", "app-01", 22, 152.0)], 153.0)
    got = {(x["src"], x["dst_devices"][0], x["evidence"]["port"]): x["severity"] for x in out if x["rule"] == "unexpected_communication"}
    assert got == {("ws-03", "ws-04", 445): "high", ("ws-03", "ext-01", 4444): "high", ("ext-02", "app-01", 22): "medium"}


# --------------------------------------------------------------------------- alerts and incidents
def finding(rule: str, src: str, dst: str, t: float, sev: str = "high", ids: tuple = ("f1",), source: str = "behavioural") -> dict:
    return {"rule": rule, "severity": sev, "src": src, "dst_devices": [dst], "t": t, "title": rule, "explanation": "x",
            "evidence": {}, "flow_ids": list(ids), "source": source}


def test_alert_merge_and_incident_correlation() -> None:
    am = AlertManager("r", T0, merge_s=60, buffer=100, k=5)
    im = IncidentManager("r", T0, window_s=600, ml_opens=False, buffer=100, k=5)
    new, upd = am.ingest([finding("port_scan", "ws-01", "app-01", 10.0, "medium")])
    assert len(new) == 1 and not upd
    new2, upd2 = am.ingest([finding("port_scan", "ws-01", "app-01", 20.0, "high", ("f2",))])
    assert not new2 and upd2[0]["occurrences"] == 2 and upd2[0]["severity"] == "high" and upd2[0]["flow_ids"] == ["f1", "f2"]
    incs, _, _ = im.ingest(new + upd2, am.alerts)
    assert len(incs) == 1 and incs[0]["actor"] == "ws-01" and incs[0]["targets"] == ["app-01"]
    a3, _ = am.ingest([finding("brute_force", "ws-01", "db-01", 30.0), finding("traffic_volume", "ws-01", "ext-08", 31.0)])
    _, upd_i, esc = im.ingest(a3, am.alerts)
    inc = upd_i[0]
    assert inc["rules"] == ["port_scan", "brute_force", "traffic_volume"] and inc["severity"] == "critical" and esc
    a4, _ = am.ingest([finding("unexpected_communication", "app-01", "db-01", 40.0, "medium")])   # target now acting
    _, upd_i, _ = im.ingest(a4, am.alerts)
    assert upd_i[0]["id"] == inc["id"] and upd_i[0]["pivots"] == ["app-01"]
    low, _ = am.ingest([finding("unexpected_communication", "lt-02", "app-01", 50.0, "low")])
    ml, _ = am.ingest([finding("ml_dos", "lt-03", "app-01", 50.0, "high", source="ml")])
    new_i, _, _ = im.ingest(low + ml, am.alerts)
    assert new_i == [] and low[0]["incident_id"] is None                                  # gates: low and ML-only
    new3, _ = am.ingest([finding("port_scan", "ws-01", "app-01", 500.0)])                 # after merge window
    assert new3 and new3[0]["id"] != new[0]["id"]


def test_incident_status_transitions() -> None:
    im = IncidentManager("r", T0, 600, False, 10, 5)
    am = AlertManager("r", T0, 60, 10, 5)
    a, _ = am.ingest([finding("port_scan", "ws-01", "app-01", 1.0)])
    inc, _, _ = im.ingest(a, am.alerts)
    iid = inc[0]["id"]
    for s in ("acknowledged", "investigating", "resolved", "open"):
        im.set_status(iid, s, "note", "tester")
    assert [h["status"] for h in im.incidents[iid]["history"]] == ["open", "acknowledged", "investigating", "resolved", "open"]
    with pytest.raises(ValueError):
        check_transition("resolved", "investigating")
    with pytest.raises(ValueError):
        check_transition("open", "deleted")


# --------------------------------------------------------------------------- engine pipeline
@pytest.fixture()
def store(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> SimStore:
    monkeypatch.setenv("GRAPHSENTINEL_HMAC_KEY_FILE", str(tmp_path / "hmac.key"))
    monkeypatch.delenv("GRAPHSENTINEL_HMAC_KEY", raising=False)
    return SimStore(tmp_path / "sim.sqlite")


def test_normal_traffic_opens_no_incident() -> None:
    e = SimulationEngine(cfg(seed=2017))
    for _ in range(120):                                        # 10 simulated minutes of routine traffic
        e.step(5.0)
    assert e.counters["flows"] > 3000 and e.counters["invalid"] == 0
    assert e.incidents.n == 0
    assert all(a["rule"] == "unexpected_communication" and a["severity"] == "low" for a in e.alerts.alerts.values())


def test_port_scan_end_to_end(store: SimStore, tmp_path: Path) -> None:
    audit = AuditLog(tmp_path / "sim.sqlite")
    e = SimulationEngine(cfg(seed=3), store, lambda: audit)
    e.start(speed=10)                                           # running: only the loop may step
    with pytest.raises(SimulationError):
        e.step(5.0)
    e.stop()
    for _ in range(30):
        e.step(5.0)                                             # normal traffic, baseline learned
    sc = e.launch_scenario("port_scan", attacker="ws-05", targets=["app-02"])
    events = []
    for _ in range(6):
        events += e.step(5.0)
    scan_alerts = [a for a in e.alerts.alerts.values() if a["rule"] == "port_scan"]
    assert len(scan_alerts) == 1
    a = scan_alerts[0]
    assert a["src"] == "ws-05" and a["dst_devices"] == ["app-02"] and a["incident_id"]
    assert all(e.flow_index[i].scenario == "port_scan" for i in a["flow_ids"] if i in e.flow_index)
    inc = e.incidents.incidents[a["incident_id"]]
    assert inc["actor"] == "ws-05" and "port_scan" in inc["rules"] and inc["flow_ids"]
    assert sc["id"] in e.first_detection          # earliest alert may be a policy alert on a probed admin port
    types = Counter(t for t, _ in events)
    assert types["flows"] == 6 and types["graph_update"] == 6 and types["detection"] >= 1 and types["incident"] >= 1
    node = e.topology()["nodes"]
    assert next(n for n in node if n["id"] == "ws-05")["suspicious"]
    # persisted
    db_alert = store.alert(a["id"])
    assert db_alert["flow_ids"] == a["flow_ids"] and db_alert["incident_id"] == inc["id"]
    assert store.incident(inc["id"])["alert_ids"] == inc["alert_ids"]
    assert store.runs()[0]["run_id"] == e.run_id
    # audit: lifecycle, scenario, alert, incident, all verifiable
    upd = e.update_incident(inc["id"], "investigating", "checking ws-05")
    assert upd["status"] == "investigating" and store.incident(inc["id"])["status"] == "investigating"
    recs = audit.records()
    kinds = [r["event_type"] for r in recs]
    for k in ("simulation_start", "simulation_stopped", "scenario_started", "detection_alert", "incident_created",
              "incident_status_changed"):
        assert k in kinds
    created = next(r for r in recs if r["event_type"] == "incident_created" and r["details"]["incident_id"] == inc["id"])
    at_creation = next(d for t, d in events if t == "incident" and d["event"] == "created" and d["id"] == inc["id"])
    assert created["details"]["evidence_sha256"] == evidence_digest(at_creation["flow_ids"])
    assert audit.verify()["valid"]


def test_all_scenarios_detected_and_bounded_memory() -> None:
    e = SimulationEngine(cfg(seed=9, limits={"flow_buffer": 500, "alert_buffer": 50}))
    for _ in range(26):
        e.step(5.0)
    ids = {n: e.launch_scenario(n)["id"] for n in CATALOG if n != "normal"}
    for _ in range(18):
        e.step(5.0)
    det = e.first_detection
    assert set(det) == set(ids.values()), det
    assert len(e.flows) == 500 and len(e.flow_index) == 500 and len(e.alerts.alerts) <= 50
    assert e.alert_eval["true_positive"] > 0
    st = e.stats()
    assert st["totals"]["flows"] > 500 and st["memory"]["flow_buffer"] == 500
    e.launch_scenario("normal")
    assert e.scenarios == [] and len(e.finished_scenarios) == 5


def test_duration_reset_and_errors(store: SimStore) -> None:
    e = SimulationEngine(cfg(seed=1, clock={"duration_s": 12.0}), store)
    e.start()
    e.step(5.0, from_loop=True)
    e.step(5.0, from_loop=True)
    e.step(5.0, from_loop=True)                                 # clipped to the remaining 2 s
    assert e.status == "completed" and e.sim_t == pytest.approx(12.0)
    with pytest.raises(SimulationError):
        e.start()
    with pytest.raises(SimulationError):
        e.launch_scenario("port_scan")
    old = e.run_id
    e.reset(seed=4)
    assert e.run_id != old and e.status == "idle" and e.sim_t == 0 and e.counters["flows"] == 0
    with pytest.raises(ValueError):
        e.launch_scenario("teleport")
    with pytest.raises(KeyError):
        e.launch_scenario("port_scan", attacker="ws-99")
    with pytest.raises(ValueError):
        e.launch_scenario("suspicious_outbound", attacker="ws-01", targets=["app-01"])
    with pytest.raises(SimulationError):
        e.stop()
    with pytest.raises(KeyError):
        e.update_incident("INC-none", "resolved")


def test_invalid_flows_are_rejected_not_processed(monkeypatch: pytest.MonkeyPatch) -> None:
    e = SimulationEngine(cfg(seed=2))
    orig = e.normal.generate

    def corrupt(*a, **k):
        fs = orig(*a, **k)
        fs[0] = dataclasses.replace(fs[0], dst_port=99999)
        return fs
    monkeypatch.setattr(e.normal, "generate", corrupt)
    e.step(10.0)
    assert e.counters["invalid"] == 1 and e.graph.flows_total == e.counters["flows"]


# --------------------------------------------------------------------------- ML compatibility
def test_ml_unavailable_and_incompatible_never_predict(net: Network) -> None:
    def missing():
        raise FileNotFoundError("model missing")
    m = MLDetector(loader=missing)
    assert m.load()["available"] is False and not m.ready

    class Fake:
        classes, model_file, columns = ["Benign", "DoS"], "fake.json", ["Protocol", "Bwd Avg Bulk Rate"]

        def required_raw_columns(self) -> list[str]:
            return ["Protocol", "Bwd Avg Bulk Rate"]
    m2 = MLDetector(loader=lambda: Fake())
    r = m2.load()
    assert r["available"] and not r["compatible"] and r["missing_features"] == ["Bwd Avg Bulk Rate"]
    fs = [flow(net, "ws-01", "app-01", 443, 1.0)]
    assert m2.score(fs) == 0 and fs[0].ml_family is None                      # nothing is guessed


def test_ml_scores_with_trained_detector(trained_detector: dict, monkeypatch: pytest.MonkeyPatch, net: Network) -> None:
    from src.api import services
    monkeypatch.setattr(services, "PROCESSED", trained_detector["processed"])
    monkeypatch.setattr(services, "DETECTOR_MODEL", trained_detector["model"])
    services.Detector.load.__func__.cache_clear()
    try:
        m = MLDetector(min_confidence=0.0)
        r = m.load()
        assert r["compatible"], r
        det = services.Detector.load()
        assert set(det.required_raw_columns()) <= set(FEATURE_COLUMNS)
        fac = FlowFactory("t", T0)
        fs = NormalTraffic(net, SimConfig().traffic).generate(np.random.default_rng(0), 0.0, 30.0, fac)
        assert m.score(fs) == len(fs)
        # the adapter's output equals the model's own prediction on the same corrected feature matrix
        import pandas as pd
        cols = det.required_raw_columns()
        num = pd.DataFrame([[f.features[c] for c in cols] for f in fs], columns=cols)
        proba, _ = services.score_numeric(det, num, pd.Series([f.flow_id for f in fs]))
        assert [f.ml_family for f in fs] == [det.classes[i] for i in proba.argmax(1)]
        assert all(0 <= f.ml_confidence <= 1 for f in fs)
        e = SimulationEngine(cfg(seed=3), ml=MLDetector(0.9))
        e.step(10.0)
        assert e.ml.scored == e.counters["flows"] > 0 and sum(e.ml_pred.values()) == e.counters["flows"]
    finally:
        services.Detector.load.__func__.cache_clear()


def test_simulation_evaluation_file_is_not_indexed_as_model_result(tmp_path: Path) -> None:
    """Regression: experiments/results/simulation/evaluation.json once crashed backend startup (db.ingest_results)."""
    from src.api import results
    (tmp_path / "simulation").mkdir()
    (tmp_path / "simulation" / "evaluation.json").write_text('{"seeds": [1]}', encoding="utf-8")
    assert results.result_files(tmp_path) == []


def test_ml_scored_count_is_per_run(trained_detector: dict, monkeypatch: pytest.MonkeyPatch) -> None:
    """Regression: /stats reported the detector's process-wide counter, which kept growing across resets."""
    from src.api import services
    monkeypatch.setattr(services, "PROCESSED", trained_detector["processed"])
    monkeypatch.setattr(services, "DETECTOR_MODEL", trained_detector["model"])
    services.Detector.load.__func__.cache_clear()
    try:
        e = SimulationEngine(cfg(seed=3), ml=MLDetector(0.9))
        e.step(20.0)
        e.reset()
        e.step(10.0)
        st = e.stats()
        assert st["ml"]["scored_flows"] == e.counters["flows"] == sum(st["ml"]["predicted_family_counts"].values())
    finally:
        services.Detector.load.__func__.cache_clear()
