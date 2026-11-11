# GraphSentinel environment setup (Windows PowerShell).
# Usage (from repo root):  powershell -ExecutionPolicy Bypass -File scripts\setup_env.ps1
# Creates .venv on Python 3.12 (better PyTorch/PyG wheel coverage than 3.14), installs
# requirements.txt and freezes exact versions to requirements-lock.txt.

$ErrorActionPreference = "Stop"
$PyVersion = "3.12"

if (Get-Command uv -ErrorAction SilentlyContinue) {
    Write-Host "Using uv to create .venv with Python $PyVersion"
    uv python install $PyVersion
    uv venv .venv --python $PyVersion
    uv pip install --python .venv\Scripts\python.exe -r requirements.txt
    uv pip freeze --python .venv\Scripts\python.exe | Out-File -Encoding utf8 requirements-lock.txt
}
else {
    Write-Host "uv not found; falling back to the py launcher (needs Python $PyVersion installed)"
    py -$PyVersion -m venv .venv
    .venv\Scripts\python.exe -m pip install --upgrade pip
    .venv\Scripts\python.exe -m pip install -r requirements.txt
    .venv\Scripts\python.exe -m pip freeze | Out-File -Encoding utf8 requirements-lock.txt
}

.venv\Scripts\python.exe -m src.utils.env_info
Write-Host "Done. Activate with:  .venv\Scripts\Activate.ps1"
