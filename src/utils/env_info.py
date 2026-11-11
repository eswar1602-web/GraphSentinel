"""Record hardware/software versions for reproducibility (writes reports/environment.json)."""
from __future__ import annotations

import json
import platform
import shutil
import subprocess
import sys
from importlib import metadata
from pathlib import Path

PACKAGES = ("numpy", "pandas", "pyarrow", "scikit-learn", "pyyaml", "pytest",
            "xgboost", "torch", "torch_geometric", "networkx", "fastapi")


def collect() -> dict:
    """Collect Python, OS, package and GPU information without importing heavy libs unless present."""
    info: dict = {
        "python": sys.version,
        "executable": sys.executable,
        "platform": platform.platform(),
        "processor": platform.processor(),
        "packages": {},
    }
    for pkg in PACKAGES:
        try:
            info["packages"][pkg] = metadata.version(pkg)
        except metadata.PackageNotFoundError:
            info["packages"][pkg] = None
    if shutil.which("nvidia-smi"):
        try:
            out = subprocess.run(
                ["nvidia-smi", "--query-gpu=name,driver_version,memory.total", "--format=csv,noheader"],
                capture_output=True, text=True, timeout=15, check=True,
            ).stdout.strip()
            info["gpu_nvidia_smi"] = out
        except (subprocess.SubprocessError, OSError) as exc:
            info["gpu_nvidia_smi"] = f"error: {exc}"
    if info["packages"].get("torch"):
        import torch  # noqa: PLC0415

        info["torch_cuda_available"] = torch.cuda.is_available()
        info["torch_cuda_version"] = torch.version.cuda
    return info


def main() -> None:
    info = collect()
    out = Path("reports") / "environment.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(info, indent=2), encoding="utf-8")
    print(json.dumps(info, indent=2))
    print(f"\nWrote {out}")


if __name__ == "__main__":
    main()
