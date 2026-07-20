param(
  [string]$Image = "chancela-server:local",
  [switch]$ComposeProfile,
  [switch]$Help
)

$ErrorActionPreference = "Stop"

function Show-Usage {
  Write-Output @"
Usage: powershell -NoProfile -File scripts/docker-smoke.ps1 [-Image <image>] [-ComposeProfile]

Runs the Docker health/persistence smoke against the selected image.
With -ComposeProfile, starts the single-node Compose profile and also inspects
the Compose-created server container for the expected runtime hardening posture.
"@
}

if ($Help) {
  Show-Usage
  return
}

function Test-NonRootUser {
  param([AllowNull()][string]$User)

  if ([string]::IsNullOrWhiteSpace($User)) {
    return $false
  }

  $Parts = $User.Trim().Split(":")
  if ($Parts[0] -eq "0" -or $Parts[0] -eq "root") {
    return $false
  }
  if ($Parts.Count -gt 1 -and ($Parts[1] -eq "0" -or $Parts[1] -eq "root")) {
    return $false
  }

  return $true
}

function Test-ComposeHardening {
  param([string]$Service)

  $ContainerIdOutput = docker compose -f $ComposeFile -p $Project ps -q $Service
  if ($LASTEXITCODE -ne 0) {
    throw "docker compose ps failed for service $Service"
  }
  $ContainerId = ""
  if ($null -ne $ContainerIdOutput) {
    $ContainerId = (@($ContainerIdOutput)[0]).Trim()
  }
  if ([string]::IsNullOrWhiteSpace($ContainerId)) {
    throw "compose service $Service did not produce a container"
  }

  $InspectJson = docker inspect $ContainerId
  if ($LASTEXITCODE -ne 0) {
    throw "docker inspect failed for compose service $Service"
  }
  $Inspect = $InspectJson | ConvertFrom-Json
  $ContainerInfo = @($Inspect)[0]
  $HostConfig = $ContainerInfo.HostConfig
  $Config = $ContainerInfo.Config

  $Failures = @()
  if ($HostConfig.ReadonlyRootfs -ne $true) {
    $Failures += "read-only rootfs"
  }
  if (@($HostConfig.CapDrop) -notcontains "ALL") {
    $Failures += "cap_drop ALL"
  }
  if (@($HostConfig.SecurityOpt) -notcontains "no-new-privileges:true") {
    $Failures += "no-new-privileges"
  }
  if (-not (Test-NonRootUser -User $Config.User)) {
    $Failures += "non-root user"
  }

  $TmpfsNames = @()
  if ($null -ne $HostConfig.Tmpfs) {
    $TmpfsNames = @($HostConfig.Tmpfs.PSObject.Properties.Name)
  }
  if ($TmpfsNames -notcontains "/tmp") {
    $Failures += "/tmp tmpfs"
  }

  $PersistentDataMount = @($ContainerInfo.Mounts) | Where-Object {
    $_.Destination -eq "/var/lib/chancela" -and ($_.Type -eq "volume" -or $_.Type -eq "bind")
  } | Select-Object -First 1
  if (-not $PersistentDataMount) {
    $Failures += "/var/lib/chancela persistent data mount"
  }

  if ($Failures.Count -gt 0) {
    throw "compose hardening smoke failed for ${Service}: missing $($Failures -join ', ')"
  }

  Write-Output "compose hardening smoke passed for ${Service}: read-only rootfs, cap_drop ALL, no-new-privileges, user $($Config.User), /tmp tmpfs, /var/lib/chancela persistent mount"
}

$DataDir = Join-Path ([System.IO.Path]::GetTempPath()) ("chancela-docker-smoke-" + [System.Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $DataDir | Out-Null
$Container = $null
$Project = "chancela-smoke-" + [System.Guid]::NewGuid().ToString("N")
$ScriptDir = Split-Path -Parent $PSCommandPath
$RepoRoot = Resolve-Path (Join-Path $ScriptDir "..")
$ComposeFile = Join-Path $RepoRoot "docker\docker-compose.yml"
$OldImage = $env:CHANCELA_SERVER_IMAGE
$OldPort = $env:CHANCELA_HOST_PORT

try {
  if ($ComposeProfile) {
    $env:CHANCELA_SERVER_IMAGE = $Image
    $env:CHANCELA_HOST_PORT = "0"
    docker compose -f $ComposeFile --profile single-node -p $Project up -d --no-build server | Out-Null
    if ($LASTEXITCODE -ne 0) {
      throw "docker compose up failed for the single-node profile"
    }
    Test-ComposeHardening -Service "server"
    $MappedOutput = docker compose -f $ComposeFile -p $Project port server 8080
    if ($LASTEXITCODE -ne 0) {
      throw "docker compose port failed for server"
    }
    $Mapped = ""
    if ($null -ne $MappedOutput) {
      $Mapped = (@($MappedOutput)[0]).Trim()
    }
    if ([string]::IsNullOrWhiteSpace($Mapped)) {
      throw "docker compose port did not report a server port"
    }
  } else {
    $Container = docker run -d `
      -p "127.0.0.1::8080" `
      -e "CHANCELA_DATA_DIR=/data" `
      -v "${DataDir}:/data" `
      $Image

    if ($LASTEXITCODE -ne 0) {
      throw "docker run failed for image $Image"
    }
    $MappedOutput = docker port $Container "8080/tcp"
    if ($LASTEXITCODE -ne 0) {
      throw "docker port failed for container $Container"
    }
    $Mapped = ""
    if ($null -ne $MappedOutput) {
      $Mapped = (@($MappedOutput)[0]).Trim()
    }
    if ([string]::IsNullOrWhiteSpace($Mapped)) {
      throw "docker port did not report a server port"
    }
  }
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
  if ($ComposeProfile) {
    docker compose -f $ComposeFile -p $Project down -v --remove-orphans | Out-Null
    if ($null -eq $OldImage) {
      Remove-Item Env:CHANCELA_SERVER_IMAGE -ErrorAction SilentlyContinue
    } else {
      $env:CHANCELA_SERVER_IMAGE = $OldImage
    }
    if ($null -eq $OldPort) {
      Remove-Item Env:CHANCELA_HOST_PORT -ErrorAction SilentlyContinue
    } else {
      $env:CHANCELA_HOST_PORT = $OldPort
    }
  }
  if ($Container) {
    docker rm -f $Container | Out-Null
  }
  Remove-Item -LiteralPath $DataDir -Recurse -Force -ErrorAction SilentlyContinue
}
