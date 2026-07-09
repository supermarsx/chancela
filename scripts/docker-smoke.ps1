param(
  [string]$Image = "chancela-server:local"
)

$ErrorActionPreference = "Stop"

$DataDir = Join-Path ([System.IO.Path]::GetTempPath()) ("chancela-docker-smoke-" + [System.Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $DataDir | Out-Null
$Container = $null

try {
  $Container = docker run -d `
    -p "127.0.0.1::8080" `
    -e "CHANCELA_DATA_DIR=/data" `
    -v "${DataDir}:/data" `
    $Image

  $Mapped = docker port $Container "8080/tcp"
  $HealthUrl = "http://$Mapped/health"
  $Body = $null

  for ($i = 0; $i -lt 60; $i++) {
    try {
      $Body = Invoke-RestMethod -Uri $HealthUrl -TimeoutSec 3
      break
    } catch {
      Start-Sleep -Seconds 1
    }
  }

  if ($null -eq $Body) {
    throw "server did not become healthy at $HealthUrl"
  }

  $Body | ConvertTo-Json -Compress

  $Failures = @()
  if ($Body.status -ne "ok") { $Failures += "status" }
  if ($Body.persistent -ne $true) { $Failures += "persistent" }
  if ($Body.ledger_verified -ne $true) { $Failures += "ledger_verified" }
  if ($Body.store_schema_version -isnot [int] -and $Body.store_schema_version -isnot [long]) {
    $Failures += "store_schema_version"
  }
  if ($Failures.Count -gt 0) {
    throw "health smoke failed $($Failures -join ', '): $($Body | ConvertTo-Json -Compress)"
  }
} finally {
  if ($Container) {
    docker rm -f $Container | Out-Null
  }
  Remove-Item -LiteralPath $DataDir -Recurse -Force -ErrorAction SilentlyContinue
}
