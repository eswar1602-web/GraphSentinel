"""Read-only audit of raw CICIDS2017 CSV files.

Reports what is *actually* in the files (headers exactly as written, encodings, labels,
row counts, blank rows, NaN/inf, non-numeric tokens, duplicates, timestamp formats,
identity cardinalities) so the preprocessing contract is based on evidence, not assumptions.
Nothing here modifies or cleans data.

Usage:
    python -m src.preprocessing.audit --raw-dir data/raw/CICIDS2017/TrafficLabelling --name traffic_labelling
"""
from __future__ import annotations

import argparse
import codecs
import csv
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

DEFAULT_ENCODINGS = ("utf-8-sig", "cp1252")
DEFAULT_IDENTITY = ("Flow ID", "Source IP", "Source Port", "Destination IP", "Timestamp")
DEFAULT_LABEL = "Label"
_CHUNK = 1 << 24  # 16 MiB


def detect_encoding_details(
    path: Path, encodings: tuple[str, ...] = DEFAULT_ENCODINGS
) -> tuple[str, int, list[dict[str, Any]]]:
    """Return (first encoding that decodes the whole file, newline count, failed attempts).

    Each failed attempt records the absolute byte offset, the offending bytes and surrounding
    context so decoding problems can be investigated instead of silently replaced.
    Streams the file so large CSVs are not loaded into memory.
    """
    failures: list[dict[str, Any]] = []
    for enc in encodings:
        decoder = codecs.getincrementaldecoder(enc)()
        newlines, offset = 0, 0
        try:
            with open(path, "rb") as fh:
                while chunk := fh.read(_CHUNK):
                    try:
                        decoder.decode(chunk)
                    except UnicodeDecodeError as exc:
                        lo, hi = max(exc.start - 40, 0), min(exc.end + 40, len(chunk))
                        failures.append({
                            "encoding": enc,
                            "byte_offset": offset + exc.start,
                            "bad_bytes": chunk[exc.start:exc.end].hex(" "),
                            "context": chunk[lo:hi].decode("latin-1"),
                            "reason": exc.reason,
                        })
                        raise
                    newlines += chunk.count(b"\n")
                    offset += len(chunk)
                decoder.decode(b"", final=True)
            return enc, newlines, failures
        except UnicodeDecodeError:
            continue
    raise ValueError(f"{path}: none of {encodings} could decode the file; failures={failures}")


def detect_encoding(path: Path, encodings: tuple[str, ...] = DEFAULT_ENCODINGS) -> tuple[str, int]:
    """Return the first encoding that decodes the whole file, and the file's newline count."""
    enc, newlines, _ = detect_encoding_details(path, encodings)
    return enc, newlines


def read_raw_header(path: Path, encoding: str) -> list[str]:
    """Header fields exactly as written (leading/trailing spaces preserved)."""
    with open(path, encoding=encoding, newline="") as fh:
        return next(csv.reader(fh))


def _non_ascii(values: list[str]) -> dict[str, list[str]]:
    return {v: [f"U+{ord(c):04X}" for c in v if ord(c) > 127] for v in values if any(ord(c) > 127 for c in v)}


def timestamp_profile(ts: pd.Series, top_k: int) -> dict[str, Any]:
    """Describe timestamp strings without choosing a parse format: shape patterns, date parts, hours."""
    s = ts.dropna().astype(str).str.strip()
    shapes = s.str.replace(r"\d", "9", regex=True)
    date_part = s.str.split(" ", n=1).str[0]
    hour = pd.to_numeric(s.str.extract(r"\s(\d{1,2}):", expand=False), errors="coerce")
    return {
        "n_non_null": int(s.size),
        "shape_patterns": shapes.value_counts().head(top_k).to_dict(),
        "date_parts": date_part.value_counts().head(top_k).to_dict(),
        "hour_histogram": {int(k): int(v) for k, v in hour.value_counts().sort_index().items()},
        "first_values": s.head(3).tolist(),
        "last_values": s.tail(3).tolist(),
        "is_monotonic_non_decreasing_as_text": bool(s.is_monotonic_increasing),
    }


def audit_file(
    path: Path,
    encodings: tuple[str, ...] = DEFAULT_ENCODINGS,
    identity_cols: tuple[str, ...] = DEFAULT_IDENTITY,
    label_col: str = DEFAULT_LABEL,
    top_k: int = 15,
) -> tuple[dict[str, Any], pd.Series]:
    """Audit one CSV. Returns (report dict, per-row content hash over feature+label columns)."""
    enc, newlines, decode_failures = detect_encoding_details(path, encodings)
    raw_header = read_raw_header(path, enc)
    stripped = [h.strip() for h in raw_header]
    dup_names = [n for n, c in Counter(stripped).items() if c > 1]

    df = pd.read_csv(path, encoding=enc, low_memory=False, skipinitialspace=False)
    df.columns = [c.strip() for c in df.columns]  # pandas already mangled duplicates as "X.1"

    rep: dict[str, Any] = {
        "file": path.name,
        "size_mb": round(path.stat().st_size / 2**20, 2),
        "encoding": enc,
        "decode_failures_before_success": decode_failures,
        "newline_count": newlines,
        "n_rows_parsed": int(len(df)),
        "n_columns": len(raw_header),
        "columns_with_surrounding_whitespace": [repr(h) for h in raw_header if h != h.strip()],
        "duplicate_column_names_after_strip": dup_names,
        "pandas_column_names": list(df.columns),
    }

    all_nan = df.isna().all(axis=1)
    rep["fully_empty_rows"] = int(all_nan.sum())
    if all_nan.any():
        rep["fully_empty_row_index_range"] = [int(df.index[all_nan].min()), int(df.index[all_nan].max())]
    df = df.loc[~all_nan]
    rep["n_rows_non_empty"] = int(len(df))

    present_id = [c for c in identity_cols if c in df.columns]
    rep["identity_columns_present"] = present_id
    rep["identity_columns_missing"] = [c for c in identity_cols if c not in df.columns]

    # ---- Labels
    if label_col in df.columns:
        lab = df[label_col].astype("string")
        counts = lab.value_counts(dropna=False)
        rep["labels"] = {repr(k): int(v) for k, v in counts.items()}
        rep["labels_with_non_ascii"] = _non_ascii([str(k) for k in counts.index if pd.notna(k)])
        rep["labels_containing_U+FFFD"] = {str(k): int(v) for k, v in counts.items()
                                           if pd.notna(k) and "�" in str(k)}
        rep["labels_with_surrounding_whitespace"] = [repr(k) for k in counts.index if pd.notna(k) and k != k.strip()]
    else:
        rep["labels"] = None

    # ---- Numeric columns
    non_numeric_cols = set(present_id) | {label_col}
    num_cols = [c for c in df.columns if c not in non_numeric_cols]
    issues: dict[str, dict[str, Any]] = {}
    numeric = {}
    for c in num_cols:
        col = df[c]
        entry: dict[str, Any] = {}
        if col.dtype == object:
            conv = pd.to_numeric(col, errors="coerce")
            bad = col.notna() & conv.isna()
            if bad.any():
                entry["non_numeric_tokens"] = col[bad].astype(str).value_counts().head(5).to_dict()
            col = conv
        col = col.astype("float64")
        numeric[c] = col
        n_nan, n_pinf, n_ninf = int(col.isna().sum()), int(np.isposinf(col).sum()), int(np.isneginf(col).sum())
        n_neg = int((col < 0).sum())
        if n_nan:
            entry["nan"] = n_nan
        if n_pinf:
            entry["+inf"] = n_pinf
        if n_ninf:
            entry["-inf"] = n_ninf
        if n_neg:
            entry["negative"] = n_neg
            entry["min"] = float(col[np.isfinite(col)].min())
        if col.nunique(dropna=True) <= 1:
            entry["constant_value"] = None if col.dropna().empty else float(col.dropna().iloc[0])
        if entry:
            issues[c] = entry
    rep["numeric_columns"] = len(num_cols)
    rep["numeric_column_issues"] = issues
    rep["constant_columns"] = [c for c, e in issues.items() if "constant_value" in e]

    # ---- Duplicates
    rep["duplicate_rows_all_columns"] = int(df.duplicated().sum())
    # Hash dtype-normalized values (float64 features, string label) so equal rows hash equally
    # even when pandas inferred int64 in one file and float64 in another.
    feat_frame = pd.DataFrame(numeric, index=df.index)
    h_feat = pd.util.hash_pandas_object(feat_frame, index=False)
    if label_col in df.columns:
        h_lab = pd.util.hash_pandas_object(df[label_col].astype(str), index=False)
        h_content = pd.Series(pd.util.hash_array((h_feat.values ^ (h_lab.values * np.uint64(31)))), index=df.index)
    else:
        h_content = h_feat
    rep["duplicate_rows_features_plus_label_ignoring_identity"] = int(h_content.duplicated().sum())
    rep["duplicate_rows_features_only"] = int(h_feat.duplicated().sum())
    if label_col in df.columns:
        g = pd.DataFrame({"h": h_feat.values, "y": df[label_col].values}).groupby("h")["y"].nunique()
        conflict_hashes = g[g > 1].index
        rep["feature_vectors_with_conflicting_labels"] = int(len(conflict_hashes))
        mask = h_feat.isin(conflict_hashes).values
        rep["rows_in_conflicting_label_groups"] = int(mask.sum())
        rep["conflicting_label_rows_by_label"] = df.loc[mask, label_col].value_counts().head(top_k).to_dict()
    if "Flow ID" in df.columns:
        fid = df["Flow ID"]
        rep["flow_id_unique"] = int(fid.nunique())
        rep["flow_id_repeated_rows"] = int(fid.duplicated().sum())

    # ---- Identities
    if "Source IP" in df.columns and "Destination IP" in df.columns:
        src, dst = df["Source IP"].astype(str), df["Destination IP"].astype(str)
        rep["unique_source_ips"] = int(src.nunique())
        rep["unique_destination_ips"] = int(dst.nunique())
        rep["unique_endpoints_union"] = int(pd.concat([src, dst]).nunique())
        rep["top_source_ips"] = src.value_counts().head(5).to_dict()
        rep["top_destination_ips"] = dst.value_counts().head(5).to_dict()
        if label_col in df.columns:
            atk = df[label_col].astype(str).str.upper() != "BENIGN"
            rep["attack_top_source_ips"] = src[atk].value_counts().head(5).to_dict()
            rep["attack_top_destination_ips"] = dst[atk].value_counts().head(5).to_dict()
    if "Timestamp" in df.columns:
        rep["timestamp"] = timestamp_profile(df["Timestamp"], top_k)

    return rep, h_content


def audit_directory(raw_dir: Path, **kw: Any) -> dict[str, Any]:
    """Audit every CSV in raw_dir; also checks header consistency and cross-file duplicate rows."""
    files = sorted(p for p in raw_dir.glob("*.csv"))
    if not files:
        raise FileNotFoundError(f"No CSV files found in {raw_dir}")
    reports, hashes = [], []
    for p in files:
        print(f"auditing {p.name} ...", flush=True)
        r, h = audit_file(p, **kw)
        reports.append(r)
        hashes.append(pd.Series(h.values, name=p.name))

    ref = reports[0]["pandas_column_names"]
    header_diff = {r["file"]: sorted(set(r["pandas_column_names"]) ^ set(ref))
                   for r in reports if r["pandas_column_names"] != ref}

    # Rows (features+label, identity ignored) that appear in more than one file.
    file_sets = [set(np.unique(h.values)) for h in hashes]
    seen: Counter = Counter()
    for s in file_sets:
        seen.update(s)
    cross = {h for h, c in seen.items() if c > 1}
    cross_by_file = {hashes[i].name: int(np.isin(hashes[i].values, list(cross)).sum()) for i in range(len(hashes))}

    total = {
        "files": len(files),
        "rows_parsed": sum(r["n_rows_parsed"] for r in reports),
        "rows_non_empty": sum(r["n_rows_non_empty"] for r in reports),
        "fully_empty_rows": sum(r["fully_empty_rows"] for r in reports),
        "duplicate_rows_all_columns_within_files": sum(r["duplicate_rows_all_columns"] for r in reports),
    }
    labels: Counter = Counter()
    for r in reports:
        if r["labels"]:
            labels.update(r["labels"])
    total["labels"] = dict(labels.most_common())
    return {
        "raw_dir": str(raw_dir),
        "totals": total,
        "header_consistent_across_files": not header_diff,
        "header_differences_vs_first_file": header_diff,
        "distinct_content_rows_shared_across_files": len(cross),
        "rows_shared_with_other_files_by_file": cross_by_file,
        "files_report": reports,
    }


def to_markdown(audit: dict[str, Any]) -> str:
    """Human-readable summary of the audit."""
    t = audit["totals"]
    L = [f"# CICIDS2017 raw data audit — `{audit['raw_dir']}`", "",
         f"- Files: {t['files']}  |  rows parsed: {t['rows_parsed']:,}  |  non-empty: {t['rows_non_empty']:,}"
         f"  |  fully-empty rows: {t['fully_empty_rows']:,}",
         f"- Exact duplicate rows (within files, all columns): {t['duplicate_rows_all_columns_within_files']:,}",
         f"- Header consistent across files: {audit['header_consistent_across_files']}",
         f"- Distinct content rows (identity ignored) shared across files: {audit['distinct_content_rows_shared_across_files']:,}",
         "", "## Label totals (raw strings, repr)", "", "| label | rows |", "|---|---:|"]
    L += [f"| {k} | {v:,} |" for k, v in t["labels"].items()]
    L += ["", "## Per file", "",
          "| file | enc | rows | empty | dup(all) | dup(feat+label) | conflicting-label rows | src IPs | dst IPs |",
          "|---|---|---:|---:|---:|---:|---:|---:|---:|"]
    for r in audit["files_report"]:
        L.append(f"| {r['file']} | {r['encoding']} | {r['n_rows_non_empty']:,} | {r['fully_empty_rows']:,} | "
                 f"{r['duplicate_rows_all_columns']:,} | {r['duplicate_rows_features_plus_label_ignoring_identity']:,} | "
                 f"{r.get('rows_in_conflicting_label_groups', 'n/a')} | {r.get('unique_source_ips', 'n/a')} | "
                 f"{r.get('unique_destination_ips', 'n/a')} |")
    for r in audit["files_report"]:
        L += ["", f"### {r['file']}", "",
              f"- Columns: {r['n_columns']}; whitespace-padded headers: {len(r['columns_with_surrounding_whitespace'])}; "
              f"duplicate names after strip: {r['duplicate_column_names_after_strip']}",
              f"- Identity columns present: {r['identity_columns_present']}; missing: {r['identity_columns_missing']}",
              f"- Encoding: {r['encoding']}; failed attempts: "
              f"{[(f['encoding'], f['byte_offset'], f['bad_bytes'], f['context']) for f in r['decode_failures_before_success']] or 'none'}",
              f"- Labels with non-ASCII chars: {r.get('labels_with_non_ascii')}; containing U+FFFD: "
              f"{r.get('labels_containing_U+FFFD') or 'none'}",
              f"- Constant columns: {r['constant_columns']}"]
        nan_inf = {c: {k: v for k, v in e.items() if k in ('nan', '+inf', '-inf', 'non_numeric_tokens')}
                   for c, e in r["numeric_column_issues"].items()}
        nan_inf = {c: e for c, e in nan_inf.items() if e}
        L.append(f"- NaN/inf/non-numeric: {nan_inf or 'none'}")
        neg = {c: e['negative'] for c, e in r['numeric_column_issues'].items() if 'negative' in e}
        L.append(f"- Columns with negative values (count): {neg or 'none'}")
        if "timestamp" in r:
            ts = r["timestamp"]
            L.append(f"- Timestamp shapes: {ts['shape_patterns']}")
            L.append(f"- Timestamp date parts: {ts['date_parts']}")
            L.append(f"- Timestamp hour histogram: {ts['hour_histogram']}")
            L.append(f"- First/last: {ts['first_values']} … {ts['last_values']}")
        if "flow_id_repeated_rows" in r:
            L.append(f"- Flow ID: {r['flow_id_unique']:,} unique, {r['flow_id_repeated_rows']:,} repeated rows")
    return "\n".join(L) + "\n"


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--raw-dir", type=Path, required=True)
    ap.add_argument("--name", default="traffic_labelling", help="report file stem")
    ap.add_argument("--out-dir", type=Path, default=Path("reports/data_audit"))
    args = ap.parse_args(argv)
    audit = audit_directory(args.raw_dir)
    args.out_dir.mkdir(parents=True, exist_ok=True)
    (args.out_dir / f"audit_{args.name}.json").write_text(json.dumps(audit, indent=2, default=str), encoding="utf-8")
    md = to_markdown(audit)
    (args.out_dir / f"audit_{args.name}.md").write_text(md, encoding="utf-8")
    print(md)
    print(f"Wrote {args.out_dir / f'audit_{args.name}.json'} and .md")


if __name__ == "__main__":
    main()
