# GhostTrace — parar serviços (Windows)
. "$PSScriptRoot\_lib.ps1"
Initialize-GhostTraceDirs

Stop-GhostPidFile "API" (Join-Path $GhostRunDir "api.pid")
Stop-GhostPidFile "Web" (Join-Path $GhostRunDir "web.pid")

Get-NetTCPConnection -LocalPort ([int]$GhostApiPort) -State Listen -ErrorAction SilentlyContinue |
  ForEach-Object { Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue }

Get-NetTCPConnection -LocalPort ([int]$GhostWebPort) -State Listen -ErrorAction SilentlyContinue |
  ForEach-Object { Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue }

Write-GhostLog "Servicos encerrados."
