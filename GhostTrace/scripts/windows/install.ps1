# GhostTrace — instalador Windows
# Uso: .\scripts\windows\install.ps1

$ErrorActionPreference = "Stop"
. "$PSScriptRoot\_lib.ps1"

Write-Host ""
Write-Host "  ghosttrace — instalador (Windows)" -ForegroundColor Cyan
Write-Host ""

Set-Location $GhostRoot
Ensure-GhostEnv

function Require-Cmd($name, $hint) {
  if (-not (Get-Command $name -ErrorAction SilentlyContinue)) {
    Write-GhostErr "'$name' nao encontrado. $hint"
    exit 1
  }
}

Require-Cmd "node" "Instale Node.js 18+ de https://nodejs.org/"
Require-Cmd "npm" ""
Require-Cmd "python" "Instale Python 3.10+ de https://python.org/"

Write-Host "  [..] npm install..." -ForegroundColor Cyan
npm install

Write-Host "  [..] pip install (backend)..." -ForegroundColor Cyan
python -m pip install --upgrade pip -q
python -m pip install -r (Join-Path $GhostRoot "backend\requirements.txt") -q
if ($LASTEXITCODE -ne 0) { exit 1 }

Write-Host ""
Write-GhostLog "Instalacao concluida."
Write-Host "  Subir (janelas):     .\scripts\windows\start.ps1"
Write-Host "  Subir (background):  .\scripts\windows\start-daemon.ps1"
Write-Host "  Parar:               .\scripts\windows\stop.ps1"
Write-Host ""
