"""Integration tests for the FastAPI backend on synthetic data (real pipeline -> real model -> API)."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("xgboost")
from fastapi.testclient import TestClient  # noqa: E402

from src.api import db, results, services  # noqa: E402
from src.preprocessing.pipeline import run  # noqa: E402
from src.training.baselines import run_experiment  # noqa: E402
from tests.synthetic_cicids import build_raw_dir, synthetic_config  # noqa: E402


@pytest.fixture(scope="module")
def env(tmp_path_factory: pytest.TempPathFactory) -> dict:
    root = tmp_path_factory.mktemp("api")
    raw = build_raw_dir(root)
    cfg = synthetic_config(root, raw)
    run(cfg)
    processed = Path(cfg["paths"]["out_dir"])
    bcfg = {"processed_dir": str(processed), "results_dir": str(root / "results" / "baselines"),
            "models_dir": str(root / "models" / "traditional"), "seeds": [0], "train_sample": {"cap_per_fine_label": 1000},
            "models": {"xgboost": {"grid": [{"n_estimators": 30, "max_depth": 3}], "early_stopping_rounds": 5, "device": "cpu"}}}
    run_experiment({"name": "primary_family_default", "scheme": "primary", "target": "family", "feature_set": "default"},
                   bcfg, ["xgboost"])
    return {"root": root, "raw": raw, "processed": processed}


@pytest.fixture()
def client(env: dict, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    root = env["root"]
    monkeypatch.setattr(services, "PROCESSED", env["processed"])
    monkeypatch.setattr(services, "DETECTOR_MODEL", root / "models" / "traditional" / "primary_family_default" / "xgboost_seed0.json")
    monkeypatch.setattr(results, "RESULTS", root / "results")
    monkeypatch.setattr(db, "DB_PATH", root / "test.sqlite")
    monkeypatch.setenv("GRAPHSENTINEL_HMAC_KEY_FILE", str(root / "keys" / "hmac.key"))
    monkeypatch.delenv("GRAPHSENTINEL_HMAC_KEY", raising=False)
    services.graph_table.cache_clear()
    services.Detector.load.__func__.cache_clear()
    from src.api.main import app
    with TestClient(app) as c:
        yield c


def test_health_and_overview(client: TestClient, env: dict) -> None:
    h = client.get("/api/health").json()
    assert h["processed_data"] and h["detector_model"]
    o = client.get("/api/overview").json()
    stats = json.loads((env["processed"] / "dataset_stats.json").read_text())
    assert o["rows"] == stats["rows"] and o["audit"]["valid"]
    assert o["best_by_experiment"]["primary_family_default"]["model"] == "xgboost"


def test_results_come_from_files(client: TestClient, env: dict) -> None:
    c = client.get("/api/results/comparison", params={"experiment": "primary_family_default"}).json()
    f = json.loads((env["root"] / "results" / "baselines" / "primary_family_default" / "xgboost.json").read_text())
    m = next(x for x in c["models"] if x["model"] == "xgboost")
    assert m["macro_f1"] == f["summary"]["macro_f1"] and m["confusion_matrix_seed0"] == f["seeds"][0]["confusion_matrix"]
    assert client.get("/api/results/comparison", params={"experiment": "nope"}).status_code == 404
    r = client.get("/api/results/robustness").json()
    assert r["models"][0]["invariant_by_construction"] is True
    assert client.get("/api/experiments").json()[0]["model"] == "xgboost"
    assert "collisions" in client.get("/api/results/eps1").json()


def test_detection_upload_and_audit(client: TestClient, env: dict) -> None:
    data = (env["raw"] / "Tuesday-WorkingHours.pcap_ISCX.csv").read_bytes()
    r = client.post("/api/detect", files={"file": ("tuesday.csv", data, "text/csv")})
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["n_flows"] == 492 and d["n_scored"] == 492 and not d["destination_port_used"]
    assert sum(d["predicted_family_counts"].values()) == 492
    assert d["ground_truth_evaluation"]["n"] == 492
    hist = client.get("/api/detections").json()
    assert hist[0]["id"] == d["detection_id"] and hist[0]["n_alerts"] == d["n_alerts"]
    recs = client.get("/api/audit/records").json()["records"]
    assert any(x["event_type"] == "detection" and x["details"]["detection_id"] == d["detection_id"] for x in recs)
    assert client.get("/api/audit/verify").json()["valid"]


def test_detection_handles_invalid_records(client: TestClient, env: dict) -> None:
    data = (env["raw"] / "Monday-WorkingHours.pcap_ISCX.csv").read_bytes()   # contains a negative-duration row
    d = client.post("/api/detect", files={"file": ("monday.csv", data, "text/csv")}).json()
    assert d["n_invalid_negative_duration"] == 1 and d["n_scored"] == d["n_flows"] - 1
    assert d["predicted_family_counts"]["invalid_record"] == 1


def test_upload_validation(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    assert client.post("/api/detect", files={"file": ("x.txt", b"a,b\n1,2\n", "text/plain")}).status_code == 400
    r = client.post("/api/detect", files={"file": ("x.csv", b"a,b\n1,2\n", "text/csv")})
    assert r.status_code == 400 and "missing required" in r.json()["detail"]
    assert client.post("/api/detect", files={"file": ("x.csv", b"\x00\x01binary", "text/csv")}).status_code == 400
    monkeypatch.setattr(services, "MAX_UPLOAD_BYTES", 10)
    assert client.post("/api/detect", files={"file": ("x.csv", b"a,b\n1,2\n3,4\n", "text/csv")}).status_code == 413


def test_graph_and_aggregation(client: TestClient) -> None:
    g = client.get("/api/graph", params={"day": "2017-07-04", "start": "09:20", "minutes": 30}).json()
    assert g["nodes"] and g["edges"] and g["flows"] > 0
    assert any(n["label"] == "172.16.0.1" for n in g["nodes"])
    g2 = client.get("/api/graph", params={"day": "2017-07-04", "start": "09:20", "minutes": 30, "merge_factor": 4}).json()
    assert g2["nodes"][0]["label"].startswith("bucket")
    assert client.get("/api/graph", params={"day": "2018-01-01"}).status_code == 422
    s = client.get("/api/aggregation/simulate", params={"merge_factor": 4}).json()
    assert s["buckets"] < client.get("/api/aggregation/simulate", params={"merge_factor": 1}).json()["buckets"]


def test_audit_demo_endpoint(client: TestClient) -> None:
    r = client.post("/api/audit/demo").json()
    assert r["1_clean"]["valid"] and not r["3_rechained_without_key"]["valid"]
