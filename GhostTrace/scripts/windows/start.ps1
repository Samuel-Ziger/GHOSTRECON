# GhostTrace — arranque com janelas visíveis (Windows)
# Uso: .\scripts\windows\start.ps1

$ErrorActionPreference = "Stop"
. "$PSScriptRoot\_lib.ps1"

Ensure-GhostEnv

$owner = Get-PortOwnerPid -Port ([int]$GhostApiPort)
if ($owner) {
  Write-GhostWarn "Porta $GhostApiPort em uso (PID $owner)."
  $kill = Read-Host "Encerrar e continuar? (s/N)"
  if ($kill -match '^[sS]') { Stop-Process -Id $owner -Force -ErrorAction SilentlyContinue; Start-Sleep 1 }
  else { exit 1 }
}

if (-not (Test-Path (Join-Path $GhostRoot "node_modules"))) {
  Write-Host "  [..] npm install..." -ForegroundColor Cyan
  npm install
}

python -m pip install -r (Join-Path $GhostRoot "backend\requirements.txt") -q 2>$null

$backendDir = Join-Path $GhostRoot "backend"
$apiCmd = "Set-Location '$backendDir'; Write-Host 'GhostTrace API' -ForegroundColor Green; python -m uvicorn app.main:app --reload --host 127.0.0.1 --port $GhostApiPort"
$webCmd = "Set-Location '$GhostRoot'; Write-Host 'GhostTrace Web' -ForegroundColor Green; npm run dev"

Write-Host "  [..] Abrindo API..." -ForegroundColor Cyan
Start-Process powershell -ArgumentList "-NoExit", "-NoLogo", "-Command", $apiCmd | Out-Null

if (Wait-GhostApi) { Write-GhostLog "API online" } else { Write-GhostWarn "API lenta — veja a janela da API" }

Write-Host "  [..] Abrindo frontend..." -ForegroundColor Cyan
Start-Process powershell -ArgumentList "-NoExit", "-NoLogo", "-Command", $webCmd | Out-Null

Start-Sleep 2
Write-Host ""
Write-GhostLog "Pronto — feche as janelas PowerShell para parar."
Write-Host "  Web: $GhostWebUrl"
Write-Host "  API: $GhostApiUrl/health"
Write-Host ""

Start-Process $GhostWebUrl | Out-Null
