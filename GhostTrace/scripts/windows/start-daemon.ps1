# GhostTrace — arranque em background (Windows) — continua rodando
# Uso: .\scripts\windows\start-daemon.ps1

$ErrorActionPreference = "Stop"
. "$PSScriptRoot\_lib.ps1"

Ensure-GhostEnv

$apiPidFile = Join-Path $GhostRunDir "api.pid"
$webPidFile = Join-Path $GhostRunDir "web.pid"
$apiLog = Join-Path $GhostLogDir "api.log"
$webLog = Join-Path $GhostLogDir "web.log"

if ((Test-Path $apiPidFile) -and (Get-Process -Id (Get-Content $apiPidFile) -ErrorAction SilentlyContinue)) {
  Write-GhostWarn "API ja rodando. Use .\scripts\windows\stop.ps1"
  exit 1
}

$owner = Get-PortOwnerPid -Port ([int]$GhostApiPort)
if ($owner) {
  Write-GhostWarn "Liberando porta $GhostApiPort (PID $owner)..."
  Stop-Process -Id $owner -Force -ErrorAction SilentlyContinue
  Start-Sleep -Seconds 1
}

$backendDir = Join-Path $GhostRoot "backend"

Write-Host "  [..] API em background..." -ForegroundColor Cyan
$apiProc = Start-Process -FilePath "python" `
  -ArgumentList "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", $GhostApiPort `
  -WorkingDirectory $backendDir `
  -WindowStyle Hidden `
  -RedirectStandardOutput $apiLog `
  -RedirectStandardError $apiLog `
  -PassThru
$apiProc.Id | Set-Content $apiPidFile

if (-not (Wait-GhostApi)) {
  Write-GhostErr "API nao subiu. Ver: $apiLog"
  exit 1
}
Write-GhostLog "API online ($GhostApiUrl)"

Write-Host "  [..] Frontend em background..." -ForegroundColor Cyan
$webProc = Start-Process -FilePath "cmd.exe" `
  -ArgumentList "/c", "npm run dev > `"$webLog`" 2>&1" `
  -WorkingDirectory $GhostRoot `
  -WindowStyle Hidden `
  -PassThru
$webProc.Id | Set-Content $webPidFile

Start-Sleep -Seconds 5

Write-Host ""
Write-GhostLog "GhostTrace rodando em background"
Write-Host "  Web:  $GhostWebUrl"
Write-Host "  API:  $GhostApiUrl/health"
Write-Host "  Logs: $GhostLogDir"
Write-Host "  Parar: .\scripts\windows\stop.ps1"
Write-Host ""

Start-Process $GhostWebUrl | Out-Null
