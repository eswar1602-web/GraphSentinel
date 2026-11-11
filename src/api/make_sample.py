"""Write a real sample upload for the Detection page: raw CICIDS2017 rows (original header, incl. Label for
ground-truth reporting) of flows that belong to the primary TEST split, drawn with a fixed seed.

Raw files are only read. Output goes to data/samples/ (git-ignored).

Usage:
    python -m src.api.make_sample --file Wednesday-workingHours.pcap_ISCX.csv --n 3000
"""
from __future__ import annotations

import argparse
from pathlib import Path

import numpy as np
import pyarrow.parquet as pq

from src.preprocessing.audit import detect_encoding
from src.preprocessing.cleaning import file_stem


def make_sample(raw_dir: Path, name: str, n: int, seed: int, out: Path, processed: Path) -> Path:
    t = pq.read_table(processed / "metadata.parquet", columns=["source_file", "raw_row", "split_primary"]).to_pandas()
    rows = t.loc[(t.source_file == file_stem(name)) & (t.split_primary == "test"), "raw_row"].to_numpy()
    pick = set(np.random.default_rng(seed).choice(rows, min(n, len(rows)), replace=False).tolist())
    enc, _ = detect_encoding(raw_dir / name)
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(raw_dir / name, encoding=enc, newline="") as src, open(out, "w", encoding="utf-8", newline="") as dst:
        dst.write(src.readline())                     # original header
        for i, line in enumerate(src):
            if i in pick:
                dst.write(line)
    return out


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--raw-dir", type=Path, default=Path("data/raw/CICIDS2017/TrafficLabelling"))
    ap.add_argument("--file", default="Wednesday-workingHours.pcap_ISCX.csv")
    ap.add_argument("--n", type=int, default=3000)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--processed", type=Path, default=Path("data/processed/v1"))
    ap.add_argument("--out", type=Path, default=None)
    a = ap.parse_args(argv)
    out = a.out or Path("data/samples") / f"sample_{file_stem(a.file)}_test_{a.n}.csv"
    print(make_sample(a.raw_dir, a.file, a.n, a.seed, out, a.processed))


if __name__ == "__main__":
    main()
