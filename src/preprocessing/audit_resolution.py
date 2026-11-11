"""Audit-resolution pass: focused, read-only investigations of the first audit's findings.

Covers: empty-row structure, conflicting-label groups, duplicated header equality, negative
durations and related fields, timestamp interpretation evidence, label mapping coverage,
exact / cross-file duplicates and Flow ID reuse. Never modifies raw files and never decides
anything silently: every function returns evidence for the dataset contract.

Usage:
    python -m src.preprocessing.audit_resolution --raw-dir data/raw/CICIDS2017/TrafficLabelling
"""
from __future__ import annotations

import argparse
import json
import re
from collections import Counter, deque
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

from src.preprocessing.audit import detect_encoding
from src.preprocessing.labels import UnknownLabelError, map_label

IDENTITY = ("Flow ID", "Source IP", "Source Port", "Destination IP", "Timestamp")
LABEL = "Label"
TS_RE = r"^(\d{1,2})/(\d{1,2})/(\d{4}) (\d{1,2}):(\d{2})(?::(\d{2}))?$"
KEY_COLS = ["Destination Port", "Protocol", "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
            "Total Length of Fwd Packets", "Total Length of Bwd Packets", "Init_Win_bytes_forward",
            "Init_Win_bytes_backward"]
NEG_CONTEXT_COLS = ["Flow Duration", "Total Fwd Packets", "Total Backward Packets", "Total Length of Fwd Packets",
                    "Total Length of Bwd Packets", "Flow Bytes/s", "Flow Packets/s", "Flow IAT Mean", "Flow IAT Max",
                    "Flow IAT Min", "Fwd IAT Total", "Bwd IAT Total"]

# Published schedule (local time, 24h) from https://www.unb.ca/cic/datasets/ids-2017.html, fetched 2026-11-11.
# Capture: 09:00 Mon 3 Jul 2017 to 17:00 Fri 7 Jul 2017. Keys are raw labels as observed.
PUBLISHED_SCHEDULE: dict[str, tuple[int, str, str]] = {  # label -> (day of July, start, end)
    "FTP-Patator": (4, "09:20", "10:20"), "SSH-Patator": (4, "14:00", "15:00"),
    "DoS slowloris": (5, "09:47", "10:10"), "DoS Slowhttptest": (5, "10:14", "10:35"),
    "DoS Hulk": (5, "10:43", "11:00"), "DoS GoldenEye": (5, "11:10", "11:23"),
    "Heartbleed": (5, "15:12", "15:32"),
    "Web Attack – Brute Force": (6, "09:20", "10:00"), "Web Attack – XSS": (6, "10:15", "10:35"),
    "Web Attack – Sql Injection": (6, "10:40", "10:42"), "Infiltration": (6, "14:19", "15:45"),
    "Bot": (7, "10:02", "11:02"), "PortScan": (7, "13:55", "15:29"), "DDoS": (7, "15:56", "16:16"),
}


# --------------------------------------------------------------------------- raw text scan
def scan_raw_lines(path: Path, context: int = 3) -> dict[str, Any]:
    """Byte-level pass: delimiter counts, line endings, quotes, comma-only blocks, header-duplicate equality,
    exact raw label byte strings. CICIDS2017 has no quoted fields; that is verified here (quote count)."""
    n = crlf = quotes = 0
    comma_counts: Counter = Counter()
    runs: list[list[int]] = []
    empty_forms: Counter = Counter()
    label_bytes: Counter = Counter()
    prev: deque = deque(maxlen=context)
    transitions: list[dict[str, Any]] = []
    pending_after = 0
    dup_idx: tuple[int, int] | None = None
    dup = {"compared": 0, "equal": 0, "both_empty": 0, "mismatch_examples": []}
    with open(path, "rb") as fh:
        for lineno, raw in enumerate(fh, start=1):
            n += 1
            crlf += raw.endswith(b"\r\n")
            body = raw.rstrip(b"\r\n")
            quotes += body.count(b'"')
            comma_counts[body.count(b",")] += 1
            text = body[:160].decode("latin-1")
            if lineno == 1:
                names = [h.strip() for h in body.decode("utf-8-sig", errors="replace").split(",")]
                idx = [i for i, h in enumerate(names) if h == "Fwd Header Length"]
                dup_idx = (idx[0], idx[1]) if len(idx) == 2 else None
                prev.append((lineno, text))
                continue
            is_empty = body.strip(b", \t") == b""
            if pending_after:
                transitions[-1]["after"].append((lineno, text))
                pending_after -= 1
            if is_empty:
                empty_forms[body] += 1
                if runs and runs[-1][1] == lineno - 1:
                    runs[-1][1] = lineno
                else:
                    runs.append([lineno, lineno])
                    if len(transitions) < 5:
                        transitions.append({"before": list(prev), "first_empty": (lineno, text), "after": []})
                        pending_after = context - 1
            else:
                f = body.split(b",")
                label_bytes[f[-1]] += 1
                if dup_idx and len(f) > max(dup_idx):
                    a, b = f[dup_idx[0]], f[dup_idx[1]]
                    dup["compared"] += 1
                    if a == b:
                        dup["equal"] += 1
                        dup["both_empty"] += a.strip() == b""
                    elif len(dup["mismatch_examples"]) < 5:
                        dup["mismatch_examples"].append({"line": lineno, "a": a.decode("latin-1"), "b": b.decode("latin-1")})
            prev.append((lineno, text))
    return {
        "lines_total": n, "crlf_lines": crlf, "quote_chars": quotes,
        "comma_count_distribution": dict(comma_counts),
        "comma_only_runs": runs, "comma_only_lines": sum(e - s + 1 for s, e in runs),
        "comma_only_distinct_forms": {k.decode("latin-1")[:20] + f"... (len {len(k)})": v for k, v in empty_forms.items()},
        "transitions": transitions,
        "fwd_header_length_columns": dup_idx,
        "fwd_header_length_raw_equality": dup,
        "raw_label_bytes": {k.hex(" ") if any(c > 127 for c in k) else k.decode("ascii"): v for k, v in label_bytes.items()},
    }


# --------------------------------------------------------------------------- loading helpers
def load_csv(path: Path) -> pd.DataFrame:
    """Load one raw CSV with stripped column names; index = 0-based raw data-row number."""
    enc, _ = detect_encoding(path)
    df = pd.read_csv(path, encoding=enc, low_memory=False)
    df.columns = [c.strip() for c in df.columns]
    return df


def numeric_features(df: pd.DataFrame) -> pd.DataFrame:
    """All non-identity, non-label columns as float64 (same normalization as the audit)."""
    cols = [c for c in df.columns if c not in IDENTITY and c != LABEL]
    return pd.DataFrame({c: pd.to_numeric(df[c], errors="coerce").astype("float64") for c in cols}, index=df.index)


def row_hash(frame: pd.DataFrame) -> np.ndarray:
    return pd.util.hash_pandas_object(frame, index=False).to_numpy()


# --------------------------------------------------------------------------- analyses
def negative_duration_records(df: pd.DataFrame, num: pd.DataFrame, stem: str) -> pd.DataFrame:
    """Every row with Flow Duration < 0, plus related rate/IAT fields and validity checks."""
    m = num["Flow Duration"] < 0
    cols = [c for c in NEG_CONTEXT_COLS if c in num.columns]
    out = num.loc[m, cols].copy()
    out.insert(0, "flow_uid", [f"{stem}:{i}" for i in out.index])
    out.insert(1, "file_line", out.index + 2)
    for c in ("Flow ID", "Timestamp", LABEL):
        out[c] = df.loc[m, c].values
    pk = out["Total Fwd Packets"] + out["Total Backward Packets"]
    out["packets_per_s_recomputed"] = pk / (out["Flow Duration"] / 1e6)
    out["rate_negative"] = (out["Flow Packets/s"] < 0) | (out["Flow Bytes/s"] < 0)
    out["iat_negative"] = (out["Flow IAT Min"] < 0) | (out["Flow IAT Max"] < 0) | (out["Flow IAT Mean"] < 0)
    return out


def other_negative_summary(num: pd.DataFrame) -> dict[str, Any]:
    """Negatives outside Flow Duration, split by whether duration itself is non-negative."""
    ok_dur = num["Flow Duration"] >= 0
    res = {}
    for c in num.columns:
        if c in ("Flow Duration", "Init_Win_bytes_forward", "Init_Win_bytes_backward"):
            continue
        neg = num[c] < 0
        if neg.any():
            vals = num.loc[neg, c]
            res[c] = {"rows": int(neg.sum()), "rows_with_nonneg_duration": int((neg & ok_dur).sum()),
                      "distinct_values_top": {str(k): int(v) for k, v in vals.value_counts().head(5).items()}}
    for c in ("Init_Win_bytes_forward", "Init_Win_bytes_backward"):
        if c in num.columns:
            vals = num.loc[num[c] < 0, c]
            res[c] = {"rows": int(vals.size), "distinct_values": {str(k): int(v) for k, v in vals.value_counts().items()}}
    return res


def conflicting_groups(feat_hash: np.ndarray, labels: pd.Series, extra: pd.DataFrame, top: int = 25) -> dict[str, Any]:
    """Groups of identical feature vectors carrying >1 label. `extra` supplies context columns (same index)."""
    g = pd.DataFrame({"h": feat_hash, "y": labels.values}, index=labels.index)
    nun = g.groupby("h")["y"].nunique()
    bad = nun[nun > 1].index
    sub = g[g["h"].isin(bad)]
    groups = []
    for h, part in sub.groupby("h"):
        ctx = extra.loc[part.index]
        groups.append({
            "hash": f"{np.uint64(h):016x}", "rows": int(len(part)),
            "labels": part["y"].value_counts().to_dict(),
            "feature_values": {c: (None if pd.isna(v) else float(v)) for c, v in ctx[[c for c in KEY_COLS if c in ctx]].iloc[0].items()},
            "timestamps": sorted(ctx["Timestamp"].astype(str).unique().tolist())[:6] if "Timestamp" in ctx else None,
            "src_dst_top": (ctx["Source IP"].astype(str) + " -> " + ctx["Destination IP"].astype(str)).value_counts().head(3).to_dict(),
            "flow_uids_sample": [str(i) for i in part.index[:5]],
        })
    groups.sort(key=lambda d: -d["rows"])
    return {"groups": int(len(bad)), "rows": int(len(sub)),
            "rows_by_label": sub["y"].value_counts().to_dict(),
            "label_combinations": Counter(" | ".join(sorted(d["labels"])) for d in groups).most_common(),
            "largest_groups": groups[:top]}


def parse_timestamp_parts(ts: pd.Series) -> pd.DataFrame:
    """Parse d/m/Y H:M[:S] strings into integer parts without choosing a correction."""
    p = ts.astype(str).str.strip().str.extract(TS_RE)
    p.columns = ["day", "month", "year", "hour", "minute", "second"]
    out = p.apply(pd.to_numeric, errors="coerce")
    out["has_seconds"] = p["second"].notna()
    out["second"] = out["second"].fillna(0)
    return out


def corrected_minutes(parts: pd.DataFrame, pm_max_hour: int = 7) -> tuple[pd.Series, pd.Series]:
    """Minutes since midnight, raw and with the candidate +12h rule (hours 1..pm_max_hour -> +12)."""
    raw = parts["hour"] * 60 + parts["minute"] + parts["second"] / 60
    corr_hour = parts["hour"].where(~parts["hour"].between(1, pm_max_hour), parts["hour"] + 12)
    return raw, corr_hour * 60 + parts["minute"] + parts["second"] / 60


def backward_jump_fraction(minutes: pd.Series, tol: float = 1.0) -> float:
    """Fraction of consecutive rows (file order) whose time goes back by more than `tol` minutes."""
    d = minutes.diff().dropna()
    return float((d < -tol).mean()) if len(d) else 0.0


def _hhmm(m: float) -> str:
    return f"{int(m // 60):02d}:{int(m % 60):02d}"


def timestamp_evidence(df: pd.DataFrame) -> dict[str, Any]:
    """Raw samples by position, hour set, file-order backward jumps raw vs corrected, label windows vs schedule."""
    ts = df["Timestamp"].astype(str)
    parts = parse_timestamp_parts(ts)
    raw_m, cor_m = corrected_minutes(parts)
    pos = sorted({int(round(q * (len(ts) - 1))) for q in (0, .1, .25, .5, .75, .9, 1)})
    hours = sorted(parts["hour"].dropna().astype(int).unique().tolist())
    windows = {}
    for lab, idx in df.groupby(LABEL).groups.items():
        r, c = raw_m.loc[idx], cor_m.loc[idx]
        w = {"rows": int(len(idx)), "raw": [_hhmm(r.min()), _hhmm(r.max())], "corrected": [_hhmm(c.min()), _hhmm(c.max())]}
        if lab in PUBLISHED_SCHEDULE:
            day, s, e = PUBLISHED_SCHEDULE[lab]
            w["published"] = [s, e]
            to_m = lambda t: int(t[:2]) * 60 + int(t[3:])  # noqa: E731
            ps, pe = to_m(s), to_m(e)
            w["corrected_rows_within_published_pm5min"] = float(c.between(ps - 5, pe + 5).mean())
            w["raw_rows_within_published_pm5min"] = float(r.between(ps - 5, pe + 5).mean())
            w["day_matches"] = bool((parts.loc[idx, "day"] == day).all())
        windows[str(lab)] = w
    return {
        "unparsed_rows": int(parts["hour"].isna().sum()),
        "with_seconds_fraction": float(parts["has_seconds"].mean()),
        "date_values": parts[["day", "month", "year"]].drop_duplicates().astype(int).values.tolist(),
        "hours_present": hours,
        "any_hour_13_to_23": any(h >= 13 for h in hours), "any_hour_6_or_7": any(h in (6, 7) for h in hours),
        "raw_samples_by_position": {int(p): ts.iloc[p] for p in pos},
        "raw_range": [_hhmm(raw_m.min()), _hhmm(raw_m.max())],
        "corrected_range": [_hhmm(cor_m.min()), _hhmm(cor_m.max())],
        "backward_jump_fraction_raw": backward_jump_fraction(raw_m),
        "backward_jump_fraction_corrected": backward_jump_fraction(cor_m),
        "label_windows": windows,
    }


def flow_id_analysis(df: pd.DataFrame) -> dict[str, Any]:
    """Explain repeated Flow IDs: direction reversals, same-timestamp repeats, multi-label Flow IDs."""
    fid = df["Flow ID"].astype(str)
    first_ip = fid.str.split("-", n=1).str[0]
    reversed_dir = df["Source IP"].astype(str) != first_ip
    rep = fid.duplicated(keep=False)
    per = df.assign(_fid=fid, _rev=reversed_dir).groupby("_fid")
    sizes = per.size()
    multi_label = per[LABEL].nunique()
    both_dirs = per["_rev"].nunique()
    same_ts = df.assign(_fid=fid).duplicated(["_fid", "Timestamp"], keep=False)
    return {
        "rows": int(len(df)), "unique_flow_ids": int(sizes.size),
        "rows_with_repeated_flow_id": int(rep.sum()),
        "flow_ids_repeated": int((sizes > 1).sum()),
        "max_rows_per_flow_id": int(sizes.max()),
        "rows_src_not_first_ip_in_flow_id": int(reversed_dir.sum()),
        "flow_ids_seen_in_both_directions": int((both_dirs > 1).sum()),
        "rows_sharing_flow_id_and_timestamp": int(same_ts.sum()),
        "flow_ids_with_multiple_labels": int((multi_label > 1).sum()),
        "multi_label_flow_id_label_combos": Counter(
            " | ".join(sorted(map(str, v))) for v in per[LABEL].unique()[multi_label > 1]).most_common(10),
    }


def exact_duplicate_summary(df: pd.DataFrame, stem: str) -> dict[str, Any]:
    """Rows identical on every raw column (incl. Flow ID, IPs, Timestamp)."""
    extra = df.duplicated(keep="first")
    allm = df.duplicated(keep=False)
    idx = df.index[extra]
    # adjacency: is the duplicate right after an identical row?
    adjacent = int(sum(1 for i in idx if i - 1 in df.index and df.loc[i - 1].equals(df.loc[i])))
    return {"extra_copies": int(extra.sum()), "rows_involved": int(allm.sum()),
            "by_label": df.loc[extra, LABEL].value_counts().to_dict(), "adjacent_to_identical_row": adjacent,
            "examples": [{"flow_uid": f"{stem}:{i}", "flow_id": df.at[i, "Flow ID"], "timestamp": df.at[i, "Timestamp"],
                          "label": df.at[i, LABEL]} for i in idx[:5]]}


# --------------------------------------------------------------------------- driver
def resolve(raw_dir: Path) -> dict[str, Any]:
    files = sorted(raw_dir.glob("*.csv"))
    if not files:
        raise FileNotFoundError(f"No CSV files in {raw_dir}")
    out: dict[str, Any] = {"raw_dir": str(raw_dir), "files": {}}
    cross_parts, neg_all, all_labels = [], [], Counter()
    for p in files:
        print(f"resolving {p.name} ...", flush=True)
        stem = p.name.replace(".pcap_ISCX.csv", "")
        scan = scan_raw_lines(p)
        df = load_csv(p)
        if len(df) != scan["lines_total"] - 1:
            raise AssertionError(f"{p.name}: pandas rows {len(df)} != data lines {scan['lines_total'] - 1}")
        empty = df.isna().all(axis=1)
        df = df.loc[~empty]
        num = numeric_features(df)
        fh_all = row_hash(num)
        fh_noport = row_hash(num.drop(columns=["Destination Port"]))
        lab = df[LABEL].astype(str)
        all_labels.update(lab.value_counts().to_dict())
        a, b = "Fwd Header Length", "Fwd Header Length.1"
        num_eq = (num[a] == num[b]) | (num[a].isna() & num[b].isna())
        neg = negative_duration_records(df, num, stem)
        neg_all.append(neg)
        out["files"][p.name] = {
            "raw_scan": scan,
            "pandas_rows_including_empty": int(len(empty)), "pandas_empty_rows": int(empty.sum()),
            "fwd_header_length_numeric_equal_all_rows": bool(num_eq.all()),
            "fwd_header_length_numeric_mismatches": int((~num_eq).sum()),
            "negative_flow_duration_rows": int(len(neg)),
            "other_negatives": other_negative_summary(num),
            "conflicts_with_dst_port": conflicting_groups(fh_all, lab, df[["Timestamp", "Source IP", "Destination IP"]].join(num)),
            "conflicts_without_dst_port": {k: v for k, v in conflicting_groups(
                fh_noport, lab, df[["Timestamp", "Source IP", "Destination IP"]].join(num), top=5).items()},
            "exact_duplicates": exact_duplicate_summary(df, stem),
            "flow_id": flow_id_analysis(df),
            "timestamp": timestamp_evidence(df),
        }
        lab_h = pd.util.hash_pandas_object(lab, index=False).to_numpy()
        cross_parts.append(pd.DataFrame({
            "file": stem, "row": df.index.values, "feat_h": fh_all,
            "content_h": pd.util.hash_array(fh_all ^ (lab_h * np.uint64(31))), "label": lab.values,
            "flow_id": df["Flow ID"].astype(str).values,
            "packets": (num["Total Fwd Packets"] + num["Total Backward Packets"]).values,
            "duration": num["Flow Duration"].values, "dst_port": num["Destination Port"].values}))
        del df, num

    cross = pd.concat(cross_parts, ignore_index=True)
    nf = cross.groupby("content_h")["file"].nunique()
    shared = nf[nf > 1].index
    sh = cross[cross["content_h"].isin(shared)]
    pair_counts = Counter()
    for _, files_ in sh.groupby("content_h")["file"].unique().items():
        pair_counts[" & ".join(sorted(files_))] += 1
    fl = cross.groupby("feat_h").agg(nfile=("file", "nunique"), nlab=("label", "nunique"))
    cross_conf = fl[(fl.nfile > 1) & (fl.nlab > 1)].index
    fid_files = cross.groupby("flow_id")["file"].nunique()
    out["cross_file"] = {
        "distinct_content_rows_shared": int(len(shared)), "rows_involved": int(len(sh)),
        "rows_involved_by_label": sh["label"].value_counts().to_dict(),
        "file_combinations_top": pair_counts.most_common(10),
        "shared_rows_packets_quantiles": sh["packets"].quantile([.5, .9, .99]).to_dict(),
        "shared_rows_duration_us_quantiles": sh["duration"].quantile([.5, .9, .99]).to_dict(),
        "shared_rows_top_dst_ports": sh["dst_port"].value_counts().head(5).to_dict(),
        "feature_vectors_with_conflicting_labels_across_files": int(len(cross_conf)),
        "flow_ids_in_multiple_files": int((fid_files > 1).sum()),
    }
    neg_df = pd.concat(neg_all)
    out["negative_flow_duration"] = {
        "rows": int(len(neg_df)), "by_label": neg_df[LABEL].value_counts().to_dict(),
        "duration_values": neg_df["Flow Duration"].value_counts().to_dict(),
        "rows_with_negative_rate": int(neg_df["rate_negative"].sum()),
        "rows_with_negative_iat": int(neg_df["iat_negative"].sum()),
        "records": json.loads(neg_df.to_json(orient="records")),
    }
    mapping, errors = {}, {}
    for raw, cnt in all_labels.items():
        try:
            mapping[raw] = {"rows": cnt, "map": map_label(raw)}
        except UnknownLabelError as e:
            errors[raw] = str(e)
    out["label_mapping"] = {"mapped": mapping, "errors": errors}
    return out


def to_markdown(r: dict[str, Any]) -> str:
    L = [f"# Audit resolution — `{r['raw_dir']}`", ""]
    L += ["## Per-file structure", "", "| file | lines | CRLF | quotes | commas/line | comma-only lines | runs | FHL raw equal | FHL numeric equal |",
          "|---|---:|---:|---:|---|---:|---|---|---|"]
    for f, d in r["files"].items():
        s = d["raw_scan"]
        eq = s["fwd_header_length_raw_equality"]
        L.append(f"| {f} | {s['lines_total']:,} | {s['crlf_lines']:,} | {s['quote_chars']} | {s['comma_count_distribution']} | "
                 f"{s['comma_only_lines']:,} | {s['comma_only_runs']} | {eq['equal']:,}/{eq['compared']:,} | "
                 f"{d['fwd_header_length_numeric_equal_all_rows']} |")
    L += ["", "## Timestamps", "", "| file | dates | hours | secs | raw range | corrected range | back-jumps raw | back-jumps corr |",
          "|---|---|---|---:|---|---|---:|---:|"]
    for f, d in r["files"].items():
        t = d["timestamp"]
        L.append(f"| {f} | {t['date_values']} | {t['hours_present']} | {t['with_seconds_fraction']:.2f} | {t['raw_range']} | "
                 f"{t['corrected_range']} | {t['backward_jump_fraction_raw']:.4f} | {t['backward_jump_fraction_corrected']:.4f} |")
    L += ["", "| label | file | rows | raw window | corrected window | published | corr in pub±5m | raw in pub±5m |", "|---|---|---:|---|---|---|---:|---:|"]
    for f, d in r["files"].items():
        for lab, w in d["timestamp"]["label_windows"].items():
            if "published" in w:
                L.append(f"| {lab} | {f.split('.')[0]} | {w['rows']:,} | {w['raw']} | {w['corrected']} | {w['published']} | "
                         f"{w['corrected_rows_within_published_pm5min']:.3f} | {w['raw_rows_within_published_pm5min']:.3f} |")
    L += ["", "## Conflicting labels (features incl. Destination Port; identity excluded)", ""]
    for f, d in r["files"].items():
        c, c2 = d["conflicts_with_dst_port"], d["conflicts_without_dst_port"]
        if c["groups"] or c2["groups"]:
            L.append(f"- **{f}**: {c['groups']} groups / {c['rows']} rows {c['rows_by_label']}; combos {c['label_combinations']}. "
                     f"Without Destination Port: {c2['groups']} groups / {c2['rows']} rows {c2['rows_by_label']}")
            for g in c["largest_groups"][:8]:
                L.append(f"  - {g['rows']} rows {g['labels']} | {g['feature_values']} | ts {g['timestamps'][:3]} | {g['src_dst_top']}")
    n = r["negative_flow_duration"]
    L += ["", "## Negative Flow Duration", "", f"- Rows: {n['rows']}; by label {n['by_label']}; values {n['duration_values']}",
          f"- With negative rate: {n['rows_with_negative_rate']}; with negative IAT: {n['rows_with_negative_iat']}", ""]
    L += ["## Exact duplicates and Flow IDs", "", "| file | extra copies | adjacent | by label | rows w/ repeated FlowID | FlowIDs both dirs | same FlowID+ts rows | multi-label FlowIDs |",
          "|---|---:|---:|---|---:|---:|---:|---:|"]
    for f, d in r["files"].items():
        e, fi = d["exact_duplicates"], d["flow_id"]
        L.append(f"| {f} | {e['extra_copies']} | {e['adjacent_to_identical_row']} | {e['by_label']} | {fi['rows_with_repeated_flow_id']:,} | "
                 f"{fi['flow_ids_seen_in_both_directions']:,} | {fi['rows_sharing_flow_id_and_timestamp']:,} | {fi['flow_ids_with_multiple_labels']:,} |")
    cf = r["cross_file"]
    L += ["", "## Cross-file", "", f"```\n{json.dumps(cf, indent=1, default=str)}\n```", "",
          "## Label mapping", "", "| raw (repr) | rows | fine | family | binary |", "|---|---:|---|---|---:|"]
    for raw, m in r["label_mapping"]["mapped"].items():
        L.append(f"| {raw!r} | {m['rows']:,} | {m['map'][0]} | {m['map'][1]} | {m['map'][2]} |")
    L.append(f"\nErrors: {r['label_mapping']['errors'] or 'none'}")
    return "\n".join(L) + "\n"


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--raw-dir", type=Path, required=True)
    ap.add_argument("--out-dir", type=Path, default=Path("reports/data_audit"))
    args = ap.parse_args(argv)
    r = resolve(args.raw_dir)
    args.out_dir.mkdir(parents=True, exist_ok=True)
    (args.out_dir / "audit_resolution.json").write_text(json.dumps(r, indent=2, default=str), encoding="utf-8")
    md = to_markdown(r)
    (args.out_dir / "audit_resolution.md").write_text(md, encoding="utf-8")
    print(md)


if __name__ == "__main__":
    main()
