"""SHA-256 manifest of the raw CSVs, so any modification of raw data is detected.

Usage:
    python -m src.preprocessing.raw_manifest --raw-dir data/raw/CICIDS2017/TrafficLabelling --create
    python -m src.preprocessing.raw_manifest --raw-dir data/raw/CICIDS2017/TrafficLabelling --verify
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

DEFAULT_MANIFEST = Path("configs/raw_manifest_cicids2017.json")


class RawDataChangedError(RuntimeError):
    """Raised when raw files differ from the recorded manifest."""


def sha256_file(path: Path, chunk: int = 1 << 24) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while b := fh.read(chunk):
            h.update(b)
    return h.hexdigest()


def compute_manifest(raw_dir: Path) -> dict[str, Any]:
    files = sorted(raw_dir.glob("*.csv"))
    if not files:
        raise FileNotFoundError(f"No CSV files in {raw_dir}")
    return {"files": {p.name: {"sha256": sha256_file(p), "bytes": p.stat().st_size} for p in files}}


def verify_manifest(raw_dir: Path, manifest_path: Path = DEFAULT_MANIFEST) -> dict[str, Any]:
    """Recompute hashes and compare; raises RawDataChangedError on any difference. Returns the current manifest."""
    expected = json.loads(Path(manifest_path).read_text(encoding="utf-8"))["files"]
    current = compute_manifest(raw_dir)["files"]
    problems = []
    for name in sorted(set(expected) | set(current)):
        if name not in current:
            problems.append(f"missing: {name}")
        elif name not in expected:
            problems.append(f"unexpected file: {name}")
        elif current[name] != expected[name]:
            problems.append(f"changed: {name}")
    if problems:
        raise RawDataChangedError("; ".join(problems))
    return {"files": current}


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--raw-dir", type=Path, required=True)
    ap.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--create", action="store_true")
    g.add_argument("--verify", action="store_true")
    a = ap.parse_args(argv)
    if a.create:
        if a.manifest.exists():
            raise SystemExit(f"{a.manifest} exists; refusing to overwrite (delete it deliberately to re-create)")
        m = compute_manifest(a.raw_dir)
        a.manifest.write_text(json.dumps(m, indent=2), encoding="utf-8")
        print(f"wrote {a.manifest} ({len(m['files'])} files)")
    else:
        verify_manifest(a.raw_dir, a.manifest)
        print("raw files match manifest")


if __name__ == "__main__":
    main()
