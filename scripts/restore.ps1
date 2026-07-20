# Chancela restore helper (Windows / PowerShell).
#
# Automates the documented manual restore (t30 §D6) SAFELY:
#   1. Refuses to run while a server is alive at -BaseUrl (probes GET /health),
#      so it never overwrites a data dir an app has open.
#   2. Renames any existing target data dir to "<dir>.pre-restore-<stamp>" so the
#      current state is never destroyed, only set aside.
#   3. Unpacks the named backup .zip (a scripts\backup.ps1 / POST /v1/backup
#      archive, or a cold copy zipped up) into a fresh target data dir.
#   4. Prints how to start against it and verify the chain (GET /health
#      ledger_verified).
#
# Usage:
#   scripts\restore.ps1 -BackupZip C:\backups\chancela-backup-20260707T120000Z.zip `
#                       -DataDir  C:\chancela\data
#   scripts\restore.ps1 <zip> <dataDir>            # positional also works
#   scripts\restore.ps1 <zip> <dataDir> -BaseUrl 127.0.0.1:9000
#
# Works on Windows PowerShell 5.1 and PowerShell 7+.

param(
    [Parameter(Mandatory = $true, Position = 0)][string]$BackupZip,
    [Parameter(Mandatory = $true, Position = 1)][string]$DataDir,
    [string]$BaseUrl = 'http://127.0.0.1:8080'
)

$ErrorActionPreference = 'Stop'

if ($BaseUrl -notmatch '^[a-zA-Z][a-zA-Z0-9+.-]*://') { $BaseUrl = "http://$BaseUrl" }
$BaseUrl = $BaseUrl.TrimEnd('/')

if (-not (Test-Path -LiteralPath $BackupZip -PathType Leaf)) {
    Write-Host "Backup archive not found: $BackupZip"
    exit 1
}

Write-Host "Chancela restore`n"
Write-Host "  archive   $BackupZip"
Write-Host "  data dir  $DataDir"
Write-Host "  probing   $BaseUrl/health`n"

# 1. Refuse if a server is alive at the probe URL: restoring under a running app
#    would fight its open SQLite handles and could corrupt the result.
$alive = $false
try {
    $resp = Invoke-WebRequest -Uri "$BaseUrl/health" -TimeoutSec 3 -UseBasicParsing
    if ($resp.StatusCode -ge 200 -and $resp.StatusCode -lt 500) { $alive = $true }
} catch {
    # A refused/timed-out connection is the good case: nothing is listening.
    if ($_.Exception.Response) { $alive = $true }
}
if ($alive) {
    Write-Host "A server is responding at $BaseUrl - refusing to restore under a live app."
    Write-Host "  Stop chancela-server / close the desktop app first, then re-run."
    Write-Host "  (If that URL is some OTHER service, pass -BaseUrl for the real one.)"
    exit 1
}

# 2. Set aside any existing data dir (never destroy it).
if (Test-Path -LiteralPath $DataDir) {
    $stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
    $aside = "$($DataDir.TrimEnd('\','/')).pre-restore-$stamp"
    Write-Host "Existing data dir found; moving it aside:"
    Write-Host "  $DataDir"
    Write-Host "    -> $aside"
    try {
        Move-Item -LiteralPath $DataDir -Destination $aside
    } catch {
        Write-Host "`nCould not move the existing data dir aside: $($_.Exception.Message)"
        Write-Host "  A file may still be locked by a running app. Stop it and retry."
        exit 1
    }
}

# 3. Unpack the archive into a fresh data dir. The archive holds chancela.db plus
#    the sidecars (settings.json/users.json/cae-catalog.json/laws/) and a
#    manifest.json at its root - exactly the data-dir layout.
New-Item -ItemType Directory -Path $DataDir -Force | Out-Null
Write-Host "`nUnpacking archive into $DataDir ..."
try {
    Expand-Archive -LiteralPath $BackupZip -DestinationPath $DataDir -Force
} catch {
    Write-Host "`nFailed to unpack the archive: $($_.Exception.Message)"
    exit 1
}

$db = Join-Path $DataDir 'chancela.db'
if (-not (Test-Path -LiteralPath $db -PathType Leaf)) {
    Write-Host "`nWARNING: the unpacked archive has no chancela.db at its root."
    Write-Host "  It may not be a Chancela backup, or it wrapped the files in a subfolder."
    Write-Host "  Inspect $DataDir; the server needs chancela.db directly inside the data dir."
    exit 1
}

Write-Host "`nRestore staged. Next steps:"
Write-Host "  1. Start the server against the restored data dir, e.g.:"
Write-Host "       `$env:CHANCELA_DATA_DIR = '$DataDir'; cargo run -p chancela-server"
Write-Host "     (or point the desktop app at it the same way)."
Write-Host "  2. Confirm the chain verified on boot:"
Write-Host "       the startup banner shows 'Ledger  <N> events on disk - chain verified',"
Write-Host "       and GET $BaseUrl/health reports \"ledger_verified\": true."
Write-Host "  If anything looks wrong, your previous data dir is preserved next to it as"
Write-Host "  the .pre-restore-<stamp> folder."
exit 0
