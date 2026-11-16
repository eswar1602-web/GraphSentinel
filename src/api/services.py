"""Backend services: flow detection on uploaded CSVs, graph views, aggregation simulation, dataset info.

Detection uses the saved XGBoost model of experiment primary_family_default (default feature set, no Destination
Port) and exactly the preprocessing code of Milestone 1 (cleaning.apply_feature_corrections + train-only
transforms of the primary scheme). Uploaded content is parsed as CSV data only and never executed.
"""
from __future__ import annotations

import io
import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
import pyarrow.parquet as pq

from src.augmentation.aggregation import bucket_mapping, structural_metrics
from src.evaluation.metrics import evaluate
from src.preprocessing.cleaning import IDENTITY_COLUMNS, apply_feature_corrections
from src.preprocessing.features import FeatureTransform
from src.preprocessing.labels import UnknownLabelError, map_label

PROCESSED = Path("data/processed/v1")
DETECTOR_MODEL = Path("models/traditional/primary_family_default/xgboost_seed0.json")
MAX_UPLOAD_BYTES = 25 * 1024 * 1024
MAX_ROWS = 200_000
FEATURE_CFG = {"nonfinite_rate_columns": ["Flow Bytes/s", "Flow Packets/s"], "assert_nonfinite_equals_zero_duration": False,
               "clip_negative_to_zero": ["Flow IAT Min", "Fwd IAT Min"],
               "invalid_negative_to_missing": ["Fwd Header Length", "Bwd Header Length", "min_seg_size_forward"],
               "overflow_threshold": -65536,
               "sentinel_columns": {"Init_Win_bytes_forward": -1, "Init_Win_bytes_backward": -1}}


class UploadError(ValueError):
    """Invalid upload (reported to the client as HTTP 400/413)."""


@dataclass
class Detector:
    model: Any
    tf: FeatureTransform
    columns: list[str]
    classes: list[str]
    model_file: str

    @classmethod
    @lru_cache(maxsize=1)
    def load(cls) -> "Detector":
        import xgboost as xgb

        if not DETECTOR_MODEL.exists():
            raise FileNotFoundError(f"{DETECTOR_MODEL} missing: run python -m src.training.baselines first")
        sdir = PROCESSED / "schemes" / "primary"
        schema = json.loads((sdir / "feature_schema_default.json").read_text(encoding="utf-8"))
        lm = json.loads((sdir / "label_map.json").read_text(encoding="utf-8"))["family"]
        m = xgb.XGBClassifier()
        m.load_model(DETECTOR_MODEL)
        m.set_params(device="cpu")
        return cls(m, FeatureTransform.from_json(sdir / "transforms.json"), schema["columns"],
                   [k for k, _ in sorted(lm.items(), key=lambda kv: kv[1])], Path(DETECTOR_MODEL).as_posix())

    def required_raw_columns(self) -> list[str]:
        indicators = {"flow_duration_zero", "iat_negative_clipped", "header_len_invalid"}
        raw = [c for c in self.columns if c not in indicators]
        need = set(raw) | set(FEATURE_CFG["nonfinite_rate_columns"]) | set(FEATURE_CFG["clip_negative_to_zero"]) \
            | set(FEATURE_CFG["invalid_negative_to_missing"]) | {"Flow Duration"}
        return sorted(need)


def parse_upload(data: bytes, filename: str) -> pd.DataFrame:
    if not filename.lower().endswith(".csv"):
        raise UploadError("only .csv files are accepted")
    if len(data) > MAX_UPLOAD_BYTES:
        raise UploadError(f"file larger than {MAX_UPLOAD_BYTES // (1024 * 1024)} MB")
    if b"\x00" in data[:4096]:
        raise UploadError("binary content is not accepted")
    for enc in ("utf-8-sig", "cp1252"):
        try:
            text = data.decode(enc)
            break
        except UnicodeDecodeError:
            continue
    else:
        raise UploadError("file is neither UTF-8 nor cp1252 text")
    try:
        df = pd.read_csv(io.StringIO(text), low_memory=False, nrows=MAX_ROWS + 1)
    except Exception as exc:  # noqa: BLE001 - any parse error is a client error
        raise UploadError(f"could not parse CSV: {exc}") from exc
    if len(df) > MAX_ROWS:
        raise UploadError(f"more than {MAX_ROWS} rows")
    df.columns = [str(c).strip() for c in df.columns]
    df = df.loc[~df.isna().all(axis=1)].reset_index(drop=True)
    if df.empty:
        raise UploadError("no data rows")
    return df


def score_numeric(det: Detector, num: pd.DataFrame, uid: pd.Series) -> tuple[np.ndarray, pd.DataFrame]:
    """Class probabilities for flows whose raw CICIDS2017 feature columns are in ``num`` (float64, no negative
    Flow Duration). Applies exactly the Milestone 1 value corrections and the train-fitted transform.
    Raises AssertionError if values fall outside the validated domain. Shared by upload and live-simulation scoring."""
    num_c, corrections, _ = apply_feature_corrections(num.reset_index(drop=True), uid.reset_index(drop=True), FEATURE_CFG)
    X = det.tf.transform(num_c, det.columns, "raw")
    pr = det.model.predict_proba(X)
    if pr.ndim == 1:
        pr = np.stack([1 - pr, pr], 1)
    full = np.zeros((len(X), len(det.classes)), dtype="float32")
    full[:, np.asarray(getattr(det.model, "gs_classes", np.arange(pr.shape[1])), dtype=int)] = pr
    return full, corrections


def detect(data: bytes, filename: str, detector: Detector | None = None, preview: int = 200) -> dict[str, Any]:
    det = detector or Detector.load()
    df = parse_upload(data, filename)
    missing = [c for c in det.required_raw_columns() if c not in df.columns]
    if missing:
        raise UploadError(f"missing required CICIDS2017 feature columns: {missing[:10]}{' ...' if len(missing) > 10 else ''}")
    feat_src = [c for c in det.required_raw_columns()]
    num = pd.DataFrame(index=df.index)
    for c in feat_src:
        v = pd.to_numeric(df[c], errors="coerce")
        bad = v.isna() & df[c].notna() & ~df[c].astype(str).str.strip().str.lower().isin(["nan", "infinity", "-infinity", "inf"])
        if bad.any():
            raise UploadError(f"non-numeric values in column '{c}'")
        num[c] = v.astype("float64")
    invalid = (num["Flow Duration"] < 0).to_numpy()            # contract Â§1: invalid records are not scored
    ok = ~invalid
    proba = np.zeros((len(df), len(det.classes)), dtype="float32")
    corrections = pd.DataFrame()
    if ok.any():
        sub = num.loc[ok].reset_index(drop=True)
        uid = pd.Series([f"upload:{i}" for i in np.flatnonzero(ok)])
        try:
            proba[ok], corrections = score_numeric(det, sub, uid)
        except AssertionError as exc:
            raise UploadError(f"feature values outside the validated CICIDS2017 domain: {exc}") from exc
    pred = proba.argmax(1)
    names = np.array(det.classes, dtype=object)[pred]   # object dtype: fixed-width str would truncate labels
    names[invalid] = "invalid_record"
    benign = det.classes.index("Benign")
    alerts = ok & (pred != benign)
    result: dict[str, Any] = {
        "filename": filename, "model": det.model_file, "n_flows": int(len(df)), "n_scored": int(ok.sum()),
        "n_invalid_negative_duration": int(invalid.sum()), "n_alerts": int(alerts.sum()),
        "predicted_family_counts": pd.Series(names).value_counts().to_dict(),
        "value_corrections": int(len(corrections)),
        "features_used": len(det.columns), "destination_port_used": "Destination Port" in det.columns,
    }
    cols = {c: df[c].astype(str).tolist() for c in ("Source IP", "Destination IP", "Timestamp") if c in df.columns}
    result["preview"] = [{"row": int(i), **{k: v[i] for k, v in cols.items()}, "predicted": str(names[i]),
                          "confidence": float(proba[i].max()) if ok[i] else None} for i in range(min(preview, len(df)))]
    if "Label" in df.columns:          # ground truth is used ONLY for reporting, never as an input
        fam = []
        for lab in df["Label"].astype(str):
            try:
                fam.append(map_label(lab)[1])
            except UnknownLabelError:
                fam.append(None)
        fam = np.array(fam, dtype=object)
        known = ok & np.array([f in det.classes for f in fam])
        if known.any():
            y = np.array([det.classes.index(f) for f in fam[known]])
            ev = evaluate(y, pred[known], det.classes)
            result["ground_truth_evaluation"] = {"n": int(known.sum()), "overall": ev["overall"],
                                                 "per_class": ev["per_class"], "confusion_matrix": ev["confusion_matrix"],
                                                 "classes": det.classes}
    return result


@lru_cache(maxsize=1)
def graph_table() -> tuple[pd.DataFrame, np.ndarray]:
    """Minimal per-flow table for graph views (endpoint codes, time, family, split)."""
    t = pq.read_table(PROCESSED / "metadata.parquet", columns=["src_ip", "dst_ip", "timestamp", "day", "label_family",
                                                               "split_primary", "dominant_pair_directed"]).to_pandas()
    names = np.unique(np.concatenate([t["src_ip"].to_numpy().astype(str), t["dst_ip"].to_numpy().astype(str)]))
    cat = pd.CategoricalDtype(names, ordered=True)
    df = pd.DataFrame({"s": t["src_ip"].astype(str).astype(cat).cat.codes.astype("int32"),
                       "d": t["dst_ip"].astype(str).astype(cat).cat.codes.astype("int32"),
                       "t": t["timestamp"], "day": t["day"].astype("category"),
                       "fam": t["label_family"].astype("category"), "split": t["split_primary"].astype("category"),
                       "dom": t["dominant_pair_directed"]})
    return df, names


def graph_view(day: str, start: str, minutes: int = 5, max_nodes: int = 60, merge_factor: int = 1,
               seed: int = 2017) -> dict[str, Any]:
    df, names = graph_table()
    t0 = np.datetime64(f"{day}T{start}", "s")
    t1 = t0 + np.timedelta64(int(minutes) * 60, "s")      # explicit unit (pandas/NumPy generic-unit deprecation)
    tv = df["t"].to_numpy().astype("datetime64[s]")
    w = df[(tv >= t0) & (tv < t1)]
    if w.empty:
        return {"nodes": [], "edges": [], "window": [str(t0), str(t1)], "flows": 0}
    m = bucket_mapping(len(names), merge_factor, seed)
    s, d = m[w["s"].to_numpy()], m[w["d"].to_numpy()]
    atk = (w["fam"] != "Benign").to_numpy()
    e = pd.DataFrame({"s": s, "d": d, "a": atk, "fam": w["fam"].astype(str).to_numpy()})
    deg = pd.concat([e.groupby("s").size(), e.groupby("d").size()], axis=1).fillna(0).sum(axis=1).sort_values(ascending=False)
    keep = set(deg.index[:max_nodes].tolist())
    sub = e[e["s"].isin(keep) & e["d"].isin(keep)]
    pairs = sub.groupby(["s", "d"]).agg(flows=("a", "size"), attacks=("a", "sum"),
                                        top_family=("fam", lambda x: x.value_counts().index[0])).reset_index()
    members: dict[int, list[str]] = {}
    if merge_factor > 1:
        for node, b in enumerate(m):
            if b in keep:
                members.setdefault(int(b), []).append(str(names[node]))
    node_flows = pd.concat([sub.groupby("s").size(), sub.groupby("d").size()], axis=1).fillna(0).sum(axis=1)
    node_atk = pd.concat([sub[sub.a].groupby("s").size(), sub[sub.a].groupby("d").size()], axis=1).fillna(0).sum(axis=1)
    nodes = [{"id": str(int(n)), "label": (str(names[n]) if merge_factor == 1 else f"bucket {int(n)} ({len(members.get(int(n), []))} endpoints)"),
              "flows": int(node_flows.get(n, 0)), "attack_flows": int(node_atk.get(n, 0)),
              "members_sample": members.get(int(n), [])[:5]} for n in keep]
    edges = [{"id": f"{int(r.s)}-{int(r.d)}", "source": str(int(r.s)), "target": str(int(r.d)), "flows": int(r.flows),
              "attack_fraction": float(r.attacks / r.flows), "top_family": r.top_family} for r in pairs.itertuples()]
    return {"window": [str(t0), str(t1)], "flows": int(len(w)),
            "flows_shown": int(len(sub)), "merge_factor": merge_factor, "nodes": nodes, "edges": edges,
            "family_counts": w["fam"].astype(str).value_counts().to_dict()}


def simulate_aggregation(merge_factor: int, seed: int) -> dict[str, Any]:
    df, names = graph_table()
    m = bucket_mapping(len(names), merge_factor, seed)
    s, d = m[df["s"].to_numpy()], m[df["d"].to_numpy()]
    return {"merge_factor": merge_factor, "seed": seed, "buckets": int(m.max()) + 1,
            "structure": structural_metrics(s, d, int(m.max()) + 1)}


def dataset_info() -> dict[str, Any]:
    out = {"dataset_stats": json.loads((PROCESSED / "dataset_stats.json").read_text(encoding="utf-8"))}
    pm = json.loads((PROCESSED / "preprocessing_metadata.json").read_text(encoding="utf-8"))
    out["preprocessing"] = {k: pm[k] for k in ("contract_version", "data_version", "expected_count_checks",
                                               "removed_rows_by_reason", "timestamp_correction", "feature_corrections",
                                               "schemes") if k in pm}
    for sc in ("primary", "dayholdout"):
        st = json.loads((PROCESSED / "schemes" / sc / "split_stats.json").read_text(encoding="utf-8"))
        out[f"split_{sc}"] = {k: st[k] for k in ("rows_by_split", "counts_label_family", "low_support_label_fine",
                                                 "groups_without_purge_gap", "groups_minute_boundary") if k in st}
    out["identity_columns_never_features"] = list(IDENTITY_COLUMNS)
    return out
