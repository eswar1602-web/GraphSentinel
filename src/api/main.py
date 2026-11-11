"""GraphSentinel FastAPI backend (Milestone 9).

Run:
    python -m uvicorn src.api.main:app --host 127.0.0.1 --port 8000
Serves the JSON API under /api and, if built, the React dashboard (frontend/dist) at /.
All numbers come from real result files, the processed dataset, or live computation; nothing is hard-coded.
"""
from __future__ import annotations

import hashlib
import os
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI, File, HTTPException, Query, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from src.api import db, results, services
from src.cryptography.audit_log import AuditLog, demo as audit_demo

FRONTEND = Path("frontend/dist")
EXPERIMENTS = ["primary_family_default", "primary_family_dstport", "dayholdout_binary_default",
               "dayholdout_binary_dstport", "primary_family_default_dominant_pair_ablation"]


def audit() -> AuditLog:
    return AuditLog(db.DB_PATH)


@asynccontextmanager
async def lifespan(app: FastAPI):
    db.init()
    n = db.ingest_results()
    audit().append("server_start", {"result_files_indexed": n})
    yield


app = FastAPI(title="GraphSentinel API", version="1.0", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=[o for o in os.environ.get(
    "GRAPHSENTINEL_CORS", "http://localhost:5173,http://127.0.0.1:5173").split(",") if o],
    allow_methods=["GET", "POST"], allow_headers=["*"])


@app.get("/api/health")
def health() -> dict[str, Any]:
    return {"status": "ok", "processed_data": (services.PROCESSED / "metadata.parquet").exists(),
            "detector_model": services.DETECTOR_MODEL.exists(), "frontend_built": (FRONTEND / "index.html").exists()}


@app.get("/api/overview")
def overview() -> dict[str, Any]:
    info = services.dataset_info()
    exps = db.list_experiments()
    best = {}
    for e in exps:
        if e["macro_f1"] is not None and not e["aggregation_aware"]:
            k = e["experiment"]
            if k not in best or e["macro_f1"] > best[k]["macro_f1"]:
                best[k] = {"model": e["model"], "macro_f1": e["macro_f1"], "macro_f1_std": e["macro_f1_std"],
                           "fpr": e["fpr"], "n_seeds": e["n_seeds"]}
    v = audit().verify()
    return {"rows": info["dataset_stats"]["rows"], "label_family": info["dataset_stats"]["label_family"],
            "contract_version": info["preprocessing"].get("contract_version"),
            "data_version": info["preprocessing"].get("data_version"),
            "dominant_pair": info["dataset_stats"]["dominant_pair"], "result_files": len(exps),
            "best_by_experiment": best, "detections": len(db.list_detections(1000)),
            "audit": {"valid": v["valid"], "records": v["records"]}}


@app.get("/api/dataset")
def dataset() -> dict[str, Any]:
    return services.dataset_info()


@app.get("/api/experiments")
def experiments() -> list[dict[str, Any]]:
    return db.list_experiments()


@app.get("/api/results/comparison")
def comparison(experiment: str = Query("primary_family_default")) -> dict[str, Any]:
    if experiment not in EXPERIMENTS:
        raise HTTPException(404, "unknown experiment")
    return results.comparison(experiment)


@app.get("/api/results/robustness")
def robustness(experiment: str = Query("primary_family_default")) -> dict[str, Any]:
    if experiment not in EXPERIMENTS:
        raise HTTPException(404, "unknown experiment")
    return results.robustness(experiment)


@app.get("/api/results/modes")
def modes(experiment: str = Query("primary_family_default")) -> dict[str, Any]:
    if experiment not in EXPERIMENTS:
        raise HTTPException(404, "unknown experiment")
    return results.native_modes(experiment)


@app.get("/api/results/eps1")
def eps1() -> dict[str, Any]:
    return results.eps1()


@app.get("/api/aggregation/structure")
def aggregation_structure() -> dict[str, Any]:
    p = results.RESULTS / "aggregation" / "structure.json"
    if not p.exists():
        raise HTTPException(404, "run python -m src.evaluation.structure first")
    return results._load(p)


@app.get("/api/aggregation/simulate")
def aggregation_simulate(merge_factor: int = Query(4, ge=1, le=1024), seed: int = Query(2017, ge=0, le=2**31)) -> dict[str, Any]:
    return services.simulate_aggregation(merge_factor, seed)


@app.get("/api/graph")
def graph(day: str = Query("2017-07-05", pattern=r"^2017-07-0[3-7]$"), start: str = Query("10:40", pattern=r"^\d{2}:\d{2}$"),
          minutes: int = Query(5, ge=1, le=60), max_nodes: int = Query(60, ge=5, le=300),
          merge_factor: int = Query(1, ge=1, le=1024)) -> dict[str, Any]:
    return services.graph_view(day, start, minutes, max_nodes, merge_factor)


@app.post("/api/detect")
async def detect(file: UploadFile = File(...)) -> dict[str, Any]:
    data = await file.read(services.MAX_UPLOAD_BYTES + 1)
    if len(data) > services.MAX_UPLOAD_BYTES:
        raise HTTPException(413, "file too large")
    name = Path(file.filename or "upload.csv").name
    try:
        res = services.detect(data, name)
    except services.UploadError as exc:
        raise HTTPException(400, str(exc)) from exc
    except FileNotFoundError as exc:
        raise HTTPException(503, str(exc)) from exc
    res["file_sha256"] = hashlib.sha256(data).hexdigest()
    res["detection_id"] = db.add_detection(res)
    rec = audit().append("detection", {"detection_id": res["detection_id"], "filename": name,
                                       "file_sha256": res["file_sha256"], "n_flows": res["n_flows"],
                                       "n_alerts": res["n_alerts"], "model": res["model"]})
    res["audit_event_id"] = rec["event_id"]
    return res


@app.get("/api/detections")
def detections(limit: int = Query(50, ge=1, le=500)) -> list[dict[str, Any]]:
    return db.list_detections(limit)


@app.get("/api/audit/records")
def audit_records(limit: int = Query(100, ge=1, le=1000), offset: int = Query(0, ge=0)) -> dict[str, Any]:
    a = audit()
    return {"records": a.records(limit, offset), "head": a.checkpoint()}


@app.get("/api/audit/verify")
def audit_verify(checkpoint_event_id: int | None = None, checkpoint_hash: str | None = None) -> dict[str, Any]:
    cp = None
    if checkpoint_event_id is not None and checkpoint_hash:
        cp = {"event_id": checkpoint_event_id, "hash": checkpoint_hash}
    return audit().verify(cp)


@app.post("/api/audit/demo")
def audit_demo_endpoint() -> dict[str, Any]:
    """Tamper demonstration on a temporary copy-free log (never touches the real audit log)."""
    return audit_demo()


if (FRONTEND / "index.html").exists():
    app.mount("/assets", StaticFiles(directory=FRONTEND / "assets"), name="assets")

    @app.get("/{path:path}", include_in_schema=False)
    def spa(path: str) -> FileResponse:
        f = FRONTEND / path
        if path and f.is_file() and FRONTEND.resolve() in f.resolve().parents:
            return FileResponse(f)
        return FileResponse(FRONTEND / "index.html")
