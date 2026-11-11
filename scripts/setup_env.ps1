# GraphSentinel environment setup (Windows PowerShell).
# Usage (from repo root):  powershell -ExecutionPolicy Bypass -File scripts\setup_env.ps1 [-Cpu]
# Creates .venv on Python 3.12, installs PyTorch (CUDA 12.6 wheels unless -Cpu), then requirements.txt,
# freezes exact versions to requirements-lock.txt, and installs the frontend's npm packages if npm exists.
param([switch]$Cpu)
$ErrorActionPreference = "Stop"
$PyVersion = "3.12"
$Py = ".venv\Scripts\python.exe"

if (-not (Get-Command uv -ErrorAction SilentlyContinue)) {
    throw "uv not found. Install it (https://docs.astral.sh/uv/) or create .venv with Python $PyVersion manually."
}
uv python install $PyVersion
if (-not (Test-Path $Py)) { uv venv .venv --python $PyVersion }
if ($Cpu) { uv pip install --python $Py torch }
else { uv pip install --python $Py torch --index-url https://download.pytorch.org/whl/cu126 }
uv pip install --python $Py -r requirements.txt
uv pip freeze --python $Py | Out-File -Encoding utf8 requirements-lock.txt

& $Py -c "import torch; print('torch', torch.__version__, 'CUDA available:', torch.cuda.is_available())"
& $Py -m src.utils.env_info | Out-Null

if (Get-Command npm -ErrorAction SilentlyContinue) {
    Push-Location frontend; npm install --no-audit --no-fund; Pop-Location
} else { Write-Host "npm not found: install Node.js 20+ to build the dashboard" }
Write-Host "Done. Activate with:  .venv\Scripts\Activate.ps1"
