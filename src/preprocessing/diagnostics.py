"""Row-level diagnostic flags and split statistics (contract §1.2, §3, §5, §6.5, §7).

Flags are metadata for evaluation/reporting only; none of them is a model feature.
"""
from __future__ import annotations

from typing import Any

import numpy as np
import pandas as pd

from src.preprocessing.audit_resolution import PUBLISHED_SCHEDULE


def row_hash(X: pd.DataFrame) -> np.ndarray:
    return pd.util.hash_pandas_object(X, index=False).to_numpy()


def conflict_group_ids(feature_hash: np.ndarray, labels: pd.Series) -> np.ndarray:
    """Dense id for each identical-feature group carrying >1 label; -1 otherwise."""
    df = pd.DataFrame({"h": feature_hash, "y": labels.to_numpy()})
    nun = df.groupby("h")["y"].nunique()
    bad = nun[nun > 1].index
    ids = pd.Series(np.arange(len(bad)), index=np.sort(bad))
    return df["h"].map(ids).fillna(-1).astype("int64").to_numpy()


def dominant_pair_flags(meta: pd.DataFrame, src: str, dst: str) -> tuple[np.ndarray, np.ndarray]:
    directed = (meta["src_ip"] == src) & (meta["dst_ip"] == dst)
    undirected = directed | ((meta["src_ip"] == dst) & (meta["dst_ip"] == src))
    return directed.to_numpy(), undirected.to_numpy()


def outside_published_window(meta: pd.DataFrame, tol_min: int) -> pd.Series:
    """True/False for attack rows with a published window (± tol); <NA> for benign or unscheduled labels."""
    out = pd.Series(pd.NA, index=meta.index, dtype="boolean")
    minute = meta["timestamp"].dt.hour * 60 + meta["timestamp"].dt.minute
    for raw, (day, s, e) in PUBLISHED_SCHEDULE.items():
        m = meta["label_raw"] == raw
        if not m.any():
            continue
        lo = int(s[:2]) * 60 + int(s[3:]) - tol_min
        hi = int(e[:2]) * 60 + int(e[3:]) + tol_min
        right_day = meta.loc[m, "timestamp"].dt.day == day
        out.loc[m] = ~(minute[m].between(lo, hi) & right_day)
    return out


def train_duplicate_flags(feature_hash: np.ndarray, split: pd.Series) -> np.ndarray:
    """True for non-train rows whose (default-set) feature vector also occurs in train."""
    train_h = np.unique(feature_hash[(split == "train").to_numpy()])
    return np.isin(feature_hash, train_h) & (split != "train").to_numpy()


def group_split_report(meta: pd.DataFrame, scheme: str) -> list[dict[str, Any]]:
    """Per (day, label_fine) group: realized split counts and ratios, dropped rows and split method."""
    rows = []
    s, st = f"split_{scheme}", f"purge_status_{scheme}"
    for (day, lab), g in meta.groupby(["day", "label_fine"], sort=True):
        n = len(g)
        cnt = g[s].value_counts().to_dict()
        status = sorted(set(g[st]))
        method = ("holdout" if status == ["holdout"] else
                  "minute_boundary" if "minute_boundary" in status else
                  "purge_gap" if "gap_applied" in status else status[0])
        kept = {k: int(cnt.get(k, 0)) for k in ("train", "val", "test")}
        rows.append({"day": day, "label_fine": lab, "n": n, "method": method, **kept,
                     "dropped": int(cnt.get("purged", 0)),
                     "ratio_of_group": {k: round(v / n, 4) for k, v in {**kept, "dropped": cnt.get("purged", 0)}.items()},
                     "time_ranges": {k: [str(x.min()), str(x.max())] for k, x in g.groupby(s)["timestamp"]
                                     if k in ("train", "val", "test")}})
    return rows


def label_collisions(h: np.ndarray, labels: pd.Series) -> dict[str, Any]:
    """Global exact cross-label feature collisions: identical vectors carrying different labels."""
    df = pd.DataFrame({"h": h, "y": labels.to_numpy()})
    per = df.groupby("h")["y"].agg(["nunique"])
    bad = per[per["nunique"] > 1].index
    sub = df[df["h"].isin(bad)]
    combos = sub.groupby("h")["y"].agg(lambda x: " | ".join(sorted(set(x)))).value_counts()
    ps = sub[sub["y"] == "PortScan"]
    ps_with_benign = sub[sub["h"].isin(ps["h"])].groupby("h")["y"].agg(lambda x: "BENIGN" in set(x))
    return {"groups": int(len(bad)), "rows": int(len(sub)), "rows_by_label": sub["y"].value_counts().to_dict(),
            "group_label_combinations": combos.to_dict(),
            "portscan_rows_total": int((df["y"] == "PortScan").sum()),
            "portscan_rows_colliding": int(len(ps)),
            "portscan_rows_colliding_with_benign": int(ps["h"].isin(ps_with_benign[ps_with_benign].index).sum())}


def train_eval_collisions(h: np.ndarray, labels: pd.Series, split: pd.Series) -> dict[str, Any]:
    """For val/test rows: does the exact vector occur in train with a *different* label (or the same label)?"""
    y = labels.to_numpy()
    tr = (split == "train").to_numpy()
    g = pd.DataFrame({"h": h[tr], "y": y[tr]}).drop_duplicates().groupby("h")["y"].agg(["nunique", "first"])
    out = {}
    for part in ("val", "test"):
        m = (split == part).to_numpy()
        hh, yy = pd.Series(h[m]), pd.Series(y[m])
        nun, first = hh.map(g["nunique"]), hh.map(g["first"])
        in_train = nun.notna()
        other = in_train & ((nun > 1) | (first != yy))
        same_only = in_train & ~other
        out[part] = {"rows": int(m.sum()),
                     "rows_vector_in_train_with_other_label_by_label": yy[other].value_counts().to_dict(),
                     "rows_vector_in_train_same_label_only_by_label": yy[same_only].value_counts().to_dict()}
    return out


def split_statistics(meta: pd.DataFrame, scheme: str, low_support: int) -> dict[str, Any]:
    s, st = meta[f"split_{scheme}"], meta[f"purge_status_{scheme}"]
    out: dict[str, Any] = {"rows_by_split": s.value_counts().to_dict()}
    for level in ("label_fine", "label_family", "label_binary"):
        tab = pd.crosstab(meta[level], s)
        out[f"counts_{level}"] = {str(k): {c: int(v) for c, v in row.items()} for k, row in tab.iterrows()}
        flags = {}
        for k, row in tab.iterrows():
            low = [c for c in ("train", "val", "test") if c in row and row[c] < low_support]
            if low:
                flags[str(k)] = low
        out[f"low_support_{level}"] = flags
        kept = tab[[c for c in ("train", "val", "test") if c in tab.columns]]
        if "train" in kept:
            nz = kept["train"][kept["train"] > 0]
            out[f"imbalance_ratio_train_{level}"] = float(nz.max() / nz.min()) if len(nz) else None
    out["purge_status_by_fine_label"] = {str(k): {c: int(v) for c, v in row.items() if v}
                                        for k, row in pd.crosstab(meta["label_fine"], st).iterrows()}
    out["groups_without_purge_gap"] = sorted({f"{d} | {l}" for d, l, x in
                                              meta[["day", "label_fine", f"purge_status_{scheme}"]].itertuples(index=False)
                                              if x in ("no_purge_gap", "purge_infeasible", "too_small")})
    out["groups_minute_boundary"] = sorted({f"{d} | {l}" for d, l, x in
                                            meta[["day", "label_fine", f"purge_status_{scheme}"]].itertuples(index=False)
                                            if x in ("minute_boundary", "boundary_minute_dropped")})
    out["group_splits"] = group_split_report(meta, scheme)
    tr = meta[s == "train"]
    seen = set(tr["src_ip"]) | set(tr["dst_ip"])
    for name in ("val", "test"):
        part = meta[s == name]
        if len(part):
            unseen = ~part["src_ip"].isin(seen) | ~part["dst_ip"].isin(seen)
            out[f"{name}_rows_with_endpoint_unseen_in_train"] = int(unseen.sum())
            out[f"{name}_rows_feature_vector_seen_in_train"] = int(part[f"train_dup_{scheme}"].sum())
            out[f"{name}_dominant_pair_rows_by_family"] = part[part["dominant_pair_directed"]]["label_family"].value_counts().to_dict()
    ranges = {}
    for (lab, sp), g in meta[s.isin(["train", "val", "test"])].groupby(["label_fine", f"split_{scheme}"]):
        ranges.setdefault(str(lab), {})[sp] = [str(g["timestamp"].min()), str(g["timestamp"].max())]
    out["time_ranges_by_fine_label"] = ranges
    return out
