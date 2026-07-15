# Chancela PostgreSQL restore helper (Windows / PowerShell).
#
# Restores a scripts\pg-backup.ps1 archive (a pg_dump custom-format .dump) into a
# target database with pg_restore, SAFELY:
#   1. Refuses to run while a server is alive at -BaseUrl (probes GET /health), so
#      it never restores under an app holding the ledger's single-writer connection
#      or serving from the database being replaced.
#   2. Restores with pg_restore --clean --if-exists into the target DATABASE_URL.
#   3. Verifies: polls the app's /health after you start it against the restored
#      database and asserts "ledger_verified": true.
#
# Usage:
#   $env:DATABASE_URL = 'postgres://chancela:...@host:5432/chancela'
#   scripts\pg-restore.ps1 -DumpFile C:\backups\chancela-pg-backup-...dump
#   scripts\pg-restore.ps1 <dump> -BaseUrl http://127.0.0.1:8080
#
# Environment:
#   DATABASE_URL   libpq connection string for the TARGET database (required). To
#                  rehearse without risk, point it at a throwaway database.
#   PGPASSWORD     password, OR a pgpass.conf entry (preferred).
#   PG_RESTORE     override the pg_restore binary.
#
# Works on Windows PowerShell 5.1 and PowerShell 7+.

param(
    [Parameter(Mandatory = $true, Position = 0)][string]$DumpFile,
    [string]$BaseUrl = 'http://127.0.0.1:8080',
    [int]$VerifyTimeout = 180
)

$ErrorActionPreference = 'Stop'

$pgRestore = if ($env:PG_RESTORE) { $env:PG_RESTORE } else { 'pg_restore' }

if ($BaseUrl -notmatch '^[a-zA-Z][a-zA-Z0-9+.-]*://') { $BaseUrl = "http://$BaseUrl" }
$BaseUrl = $BaseUrl.TrimEnd('/')

if (-not $env:DATABASE_URL) {
    Write-Host 'DATABASE_URL is not set. Set the target libpq connection string.'
    Write-Host '  To rehearse safely, point it at a throwaway database first.'
    exit 1
}
if (-not (Test-Path -LiteralPath $DumpFile -PathType Leaf)) {
    Write-Host "Backup archive not found: $DumpFile"
    exit 1
}
if (-not (Get-Command $pgRestore -ErrorAction SilentlyContinue)) {
    Write-Host "Could not find '$pgRestore' (install postgresql-client or set PG_RESTORE)."
    exit 1
}

Write-Host "Chancela PostgreSQL restore`n"
Write-Host "  archive   $DumpFile"
Write-Host "  target    (DATABASE_URL)"
Write-Host "  probing   $BaseUrl/health`n"

# 1. Refuse if a server is alive at the probe URL.
$alive = $false
try {
    $resp = Invoke-WebRequest -Uri "$BaseUrl/health" -TimeoutSec 3 -UseBasicParsing
    if ($resp.StatusCode -ge 200 -and $resp.StatusCode -lt 500) { $alive = $true }
} catch {
    if ($_.Exception.Response) { $alive = $true }
}
if ($alive) {
    Write-Host "A server is responding at $BaseUrl - refusing to restore under a live app."
    Write-Host "  Stop chancela-server first, then re-run."
    Write-Host "  (If that URL is some OTHER service, pass -BaseUrl for the real one.)"
    exit 1
}

# 2. Restore. --clean --if-exists makes a re-restore idempotent; --exit-on-error
#    fails closed on the first problem.
Write-Host "Restoring with pg_restore (this drops + recreates the app objects) ..."
& $pgRestore --clean --if-exists --no-owner --no-privileges --exit-on-error `
    --dbname="$env:DATABASE_URL" "$DumpFile"
if ($LASTEXITCODE -ne 0) {
    Write-Host "`npg_restore reported an error. The target database may be partially restored;"
    Write-Host "do NOT start the app against it until you have re-run a clean restore."
    exit 1
}
Write-Host "Restore complete.`n"

# 3. Verify via /health ledger_verified.
Write-Host "Now start the server against the restored database, e.g.:"
Write-Host "  `$env:CHANCELA_DB_BACKEND = 'postgres'; cargo run -p chancela-server"
Write-Host "`nWaiting up to ${VerifyTimeout}s for $BaseUrl/health ..."

$deadline = (Get-Date).AddSeconds($VerifyTimeout)
$body = $null
while ((Get-Date) -lt $deadline) {
    try {
        $resp = Invoke-WebRequest -Uri "$BaseUrl/health" -TimeoutSec 5 -UseBasicParsing
        if ($resp.Content) { $body = $resp.Content; break }
    } catch {
        Start-Sleep -Seconds 3
    }
}

if (-not $body) {
    Write-Host "`nTimed out waiting for $BaseUrl/health. Once the app is up, confirm by hand that"
    Write-Host '  "ledger_verified": true'
    Write-Host "before trusting the restored database."
    exit 2
}

$verified = $null
try {
    $json = $body | ConvertFrom-Json
    if ($null -ne $json.ledger_verified) { $verified = [bool]$json.ledger_verified }
    elseif ($json.persistence -and $null -ne $json.persistence.ledger_verified) { $verified = [bool]$json.persistence.ledger_verified }
} catch {
    if ($body -match '"ledger_verified"\s*:\s*true') { $verified = $true }
    elseif ($body -match '"ledger_verified"\s*:\s*false') { $verified = $false }
}

if ($verified -eq $true) {
    Write-Host "`nOK: GET /health reports `"ledger_verified`": true - the restored chain re-verified."
    exit 0
}

Write-Host "`nWARNING: /health did NOT report ledger_verified == true (got: $verified)."
Write-Host "The restored database failed the durable integrity check. Investigate before"
Write-Host "relying on it; do not put it into service."
exit 3
