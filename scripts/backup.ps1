# Chancela hot-backup helper (Windows / PowerShell).
#
# Calls `POST /v1/backup` on a RUNNING chancela-server and prints the returned
# manifest: the on-disk archive path, its size, the ledger length + boot-verify
# status, and the per-file SHA-256 digest table. The server takes the snapshot
# with SQLite `VACUUM INTO` (transactionally consistent, no downtime), so this is
# safe to run against a live instance.
#
# Usage:
#   scripts\backup.ps1                         # default http://127.0.0.1:8080
#   scripts\backup.ps1 -BaseUrl 127.0.0.1:9000 # a different host:port
#   scripts\backup.ps1 http://host:8080        # positional base URL also works
#
# If the server is in-memory (no CHANCELA_DATA_DIR) it returns 422 and there is
# nothing to back up online; if it is unreachable this prints a clear message.
# Either way it points at the COLD-COPY alternative (stop the app, copy the data
# dir) documented in the README.
#
# Works on Windows PowerShell 5.1 and PowerShell 7+.

param(
    [string]$BaseUrl = 'http://127.0.0.1:8080'
)

$ErrorActionPreference = 'Stop'

# Accept a bare host:port (prepend http://) and trim a trailing slash so
# "$BaseUrl/v1/backup" is always well formed.
if ($BaseUrl -notmatch '^[a-zA-Z][a-zA-Z0-9+.-]*://') { $BaseUrl = "http://$BaseUrl" }
$BaseUrl = $BaseUrl.TrimEnd('/')
$backupUrl = "$BaseUrl/v1/backup"

# Human-readable byte size (IEC units), e.g. 12345 -> "12.06 KiB".
function Format-Bytes {
    param([long]$Bytes)
    $units = @('B', 'KiB', 'MiB', 'GiB', 'TiB')
    $size = [double]$Bytes
    $i = 0
    while ($size -ge 1024 -and $i -lt $units.Length - 1) {
        $size /= 1024
        $i++
    }
    if ($i -eq 0) { return "$Bytes B" }
    return ('{0:N2} {1}' -f $size, $units[$i])
}

# The cold-copy fallback, printed whenever the online backup cannot be taken.
function Write-ColdCopyHint {
    Write-Host ""
    Write-Host "Cold-copy alternative (works with the app stopped):"
    Write-Host "  1. Stop chancela-server / close the desktop app."
    Write-Host "  2. Copy the whole data directory (the folder holding chancela.db,"
    Write-Host "     settings.json, users.json, cae-catalog.json and laws/) somewhere safe."
    Write-Host "     Its location is the CHANCELA_DATA_DIR you started the server with,"
    Write-Host "     or the per-app data dir the desktop app logs at startup."
    Write-Host "  Restore either kind of copy with scripts\restore.ps1."
}

Write-Host "Chancela backup - POST $backupUrl`n"

try {
    $manifest = Invoke-RestMethod -Method Post -Uri $backupUrl -TimeoutSec 300
} catch {
    $status = $null
    if ($_.Exception.Response) {
        try { $status = [int]$_.Exception.Response.StatusCode } catch { }
    }

    if ($status -eq 422) {
        # In-memory server: nothing durable to snapshot (frozen §3.2 body).
        $message = 'backup requires on-disk persistence; set CHANCELA_DATA_DIR'
        if ($_.ErrorDetails.Message) {
            try { $message = (ConvertFrom-Json $_.ErrorDetails.Message).error } catch { }
        }
        Write-Host "The server is running IN-MEMORY, so there is nothing to back up online."
        Write-Host "  server said: $message"
        Write-Host "  Start it with CHANCELA_DATA_DIR set to enable POST /v1/backup."
        Write-ColdCopyHint
        exit 2
    }

    if ($null -ne $status) {
        Write-Host "The server rejected the backup (HTTP $status)."
        if ($_.ErrorDetails.Message) { Write-Host "  server said: $($_.ErrorDetails.Message)" }
        Write-ColdCopyHint
        exit 1
    }

    Write-Host "Could not reach a chancela-server at $BaseUrl."
    Write-Host "  $($_.Exception.Message)"
    Write-Host "  Is the server running? Pass -BaseUrl if it listens elsewhere."
    Write-ColdCopyHint
    exit 1
}

# Success: render the manifest.
Write-Host "Backup written:"
Write-Host "  path            $($manifest.path)"
Write-Host "  size            $(Format-Bytes ([long]$manifest.bytes))  ($($manifest.bytes) bytes)"
Write-Host "  created_at      $($manifest.created_at)"
Write-Host "  app_version     $($manifest.app_version)"
Write-Host "  schema_version  $($manifest.store_schema_version)"
Write-Host "  ledger_length   $($manifest.ledger_length)"
$verified = if ($manifest.ledger_verified) { 'true (chain verified)' } else { 'FALSE - chain integrity failure' }
Write-Host "  ledger_verified $verified"

Write-Host "`nArchived files:"
Write-Host ("  {0,-22} {1,12}  {2}" -f 'name', 'bytes', 'sha256')
Write-Host ("  {0,-22} {1,12}  {2}" -f ('-' * 22), ('-' * 12), ('-' * 64))
foreach ($file in $manifest.files) {
    Write-Host ("  {0,-22} {1,12}  {2}" -f $file.name, $file.bytes, $file.sha256)
}

if (-not $manifest.ledger_verified) {
    Write-Host "`nWARNING: the durable chain did NOT verify at backup time. The archive still"
    Write-Host "captures the current bytes, but investigate the integrity failure before relying"
    Write-Host "on it (see the server banner / GET /health ledger_verified)."
    exit 3
}

Write-Host "`nDone. Copy the archive above to your off-box backup location."
exit 0
