# Chancela PostgreSQL backup helper (Windows / PowerShell).
#
# For the self-hosted server edition on the optional Postgres backend
# (CHANCELA_DB_BACKEND=postgres). Takes a transactionally-consistent logical dump
# of the whole database with pg_dump into a timestamped custom-format archive, then
# prints how to verify it via a restore drill + GET /health ledger_verified.
#
# pg_dump runs inside a single repeatable-read snapshot, so the archive is a
# consistent point-in-time image even while the server keeps serving.
#
# Usage:
#   $env:DATABASE_URL = 'postgres://chancela:...@host:5432/chancela'
#   scripts\pg-backup.ps1 [-OutDir .\backups]
#
# Environment:
#   DATABASE_URL   libpq connection string / URI (required). The SAME value the
#                  server uses. TLS params (sslmode=verify-full, sslrootcert=...)
#                  are honored by pg_dump exactly as by the app.
#   PGPASSWORD     password, OR a %APPDATA%\postgresql\pgpass.conf entry (preferred).
#   PG_DUMP        override the pg_dump binary.
#
# Works on Windows PowerShell 5.1 and PowerShell 7+.

param(
    [string]$OutDir = '.\backups'
)

$ErrorActionPreference = 'Stop'

$pgDump = if ($env:PG_DUMP) { $env:PG_DUMP } else { 'pg_dump' }

if (-not $env:DATABASE_URL) {
    Write-Host 'DATABASE_URL is not set. Set the same libpq connection string the server uses, e.g.:'
    Write-Host "  `$env:DATABASE_URL = 'postgres://chancela:***@host:5432/chancela'"
    exit 1
}
if (-not (Get-Command $pgDump -ErrorAction SilentlyContinue)) {
    Write-Host "Could not find '$pgDump'. Install the PostgreSQL client tools or set PG_DUMP to its full path."
    exit 1
}

New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
$stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
$outFile = Join-Path $OutDir "chancela-pg-backup-$stamp.dump"

Write-Host "Chancela PostgreSQL backup`n"
Write-Host "  target    $outFile"
Write-Host "  dumping   (consistent snapshot via pg_dump)`n"

# --format=custom       compressed, selective, restorable with pg_restore
# --no-owner/--no-acl   portable across roles
& $pgDump --format=custom --no-owner --no-privileges --file="$outFile" "$env:DATABASE_URL"
if ($LASTEXITCODE -ne 0) {
    Write-Host "`npg_dump failed; removing the incomplete archive."
    Remove-Item -LiteralPath $outFile -Force -ErrorAction SilentlyContinue
    exit 1
}

$size = (Get-Item -LiteralPath $outFile).Length
Write-Host "Backup written:"
Write-Host "  path   $outFile"
Write-Host "  bytes  $size`n"

Write-Host "Next steps:"
Write-Host "  1. Copy this archive to your off-box, encrypted-at-rest backup location."
Write-Host "  2. VERIFY it is restorable (regularly, not only in a real incident):"
Write-Host "       - restore into a THROWAWAY database + data dir with"
Write-Host "           scripts\pg-restore.ps1 -DumpFile `"$outFile`""
Write-Host "         (see that script's help for the scratch-DATABASE_URL flow), then"
Write-Host "       - start the server against the restored database and confirm the chain"
Write-Host "         re-verified on boot: GET /health reports `"ledger_verified`": true."
Write-Host "  A backup you have never restored is not a backup you can rely on."
exit 0
