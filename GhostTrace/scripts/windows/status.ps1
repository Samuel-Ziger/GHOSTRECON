# GhostTrace — status (Windows)
. "$PSScriptRoot\_lib.ps1"
Initialize-GhostTraceDirs

function Show-Service($name, $pidFile, $url) {
  if ((Test-Path $pidFile) -and (Get-Process -Id (Get-Content $pidFile) -ErrorAction SilentlyContinue)) {
    Write-Host "  $name`: RODANDO (PID $(Get-Content $pidFile))" -ForegroundColor Green
    try {
      if ($url) { Invoke-RestMethod $url -TimeoutSec 2 | Out-Null; Write-Host "         HTTP OK — $url" }
    } catch {}
  } else {
    Write-Host "  $name`: PARADO" -ForegroundColor DarkGray
  }
}

Write-Host ""
Write-Host "  ghosttrace — status"
Show-Service "API" (Join-Path $GhostRunDir "api.pid") "$GhostApiUrl/health"
Show-Service "Web" (Join-Path $GhostRunDir "web.pid") $GhostWebUrl
Write-Host ""
