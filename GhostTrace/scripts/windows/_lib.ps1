# Funções partilhadas — scripts Windows

$script:GhostRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$script:GhostRunDir = Join-Path $GhostRoot ".ghosttrace\run"
$script:GhostLogDir = Join-Path $GhostRoot ".ghosttrace\logs"
$script:GhostApiPort = if ($env:GHOSTTRACE_API_PORT) { $env:GHOSTTRACE_API_PORT } else { "8787" }
$script:GhostWebPort = if ($env:GHOSTTRACE_WEB_PORT) { $env:GHOSTTRACE_WEB_PORT } else { "3000" }
$script:GhostApiUrl = "http://127.0.0.1:$GhostApiPort"
$script:GhostWebUrl = "http://localhost:$GhostWebPort"

function Initialize-GhostTraceDirs {
  New-Item -ItemType Directory -Force -Path $GhostRunDir, $GhostLogDir | Out-Null
}

function Write-GhostLog { param([string]$Message) Write-Host "[ghosttrace] $Message" -ForegroundColor Green }
function Write-GhostWarn { param([string]$Message) Write-Host "[ghosttrace] $Message" -ForegroundColor Yellow }
function Write-GhostErr { param([string]$Message) Write-Host "[ghosttrace] $Message" -ForegroundColor Red }

function Ensure-GhostEnv {
  Initialize-GhostTraceDirs
  Set-Location $GhostRoot
  $envFile = Join-Path $GhostRoot ".env.local"
  $envExample = Join-Path $GhostRoot ".env.example"
  if (-not (Test-Path $envFile)) {
    if (Test-Path $envExample) { Copy-Item $envExample $envFile }
    else {
      @"
NEXT_PUBLIC_APP_NAME=GhostTrace
NEXT_PUBLIC_APP_VERSION=0.1.0
NEXT_PUBLIC_API_URL=$GhostApiUrl
"@ | Set-Content -Path $envFile -Encoding UTF8
    }
    Write-GhostWarn ".env.local criado"
  }
  $content = Get-Content $envFile -Raw -ErrorAction SilentlyContinue
  if ($content -match "NEXT_PUBLIC_API_URL=http://localhost:8000") {
    (Get-Content $envFile) -replace "http://localhost:8000", $GhostApiUrl | Set-Content $envFile
  }
}

function Wait-GhostApi {
  for ($i = 0; $i -lt 40; $i++) {
    try {
      $r = Invoke-RestMethod -Uri "$GhostApiUrl/health" -TimeoutSec 2
      if ($r.status -eq "ok") { return $true }
    } catch { Start-Sleep -Milliseconds 500 }
  }
  return $false
}

function Get-PortOwnerPid {
  param([int]$Port)
  $c = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1
  if ($c) { return $c.OwningProcess }
  return $null
}

function Stop-GhostPidFile {
  param([string]$Name, [string]$PidFile)
  if (Test-Path $PidFile) {
    $procId = Get-Content $PidFile -Raw
    $procId = $procId.Trim()
    if ($procId -match '^\d+$') {
      Stop-Process -Id ([int]$procId) -Force -ErrorAction SilentlyContinue
      Write-GhostLog "$Name parado (PID $procId)"
    }
    Remove-Item $PidFile -Force -ErrorAction SilentlyContinue
  }
}
