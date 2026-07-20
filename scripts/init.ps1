# Chancela one-shot developer bootstrap (Windows / PowerShell).
#
# Verifies the required toolchain is present (cargo, rustup, node, npm),
# reports the detected versions, enforces Node >= 20, installs the npm
# workspace dependencies, and prints the next steps. It never mutates the
# Rust toolchain (no rustup install/update) — it only reports what is there.
#
# Works on Windows PowerShell 5.1 and PowerShell 7+. Invoked via `npm run init`.

$ErrorActionPreference = 'Stop'

$MinNodeMajor = 20

# Return the trimmed first line of a tool's output, or $null if the tool is
# missing or fails. Must never throw — a missing tool is an expected outcome.
# Relax $ErrorActionPreference locally: some tools (e.g. `rustup --version`)
# print an info banner to stderr, which under the script-level 'Stop' would be
# raised as a terminating NativeCommandError and misreported as "not found".
function Get-ToolVersion {
    param(
        [string]$Command,
        [string[]]$Arguments
    )
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'SilentlyContinue'
    try {
        $out = & $Command @Arguments 2>$null
        if ($LASTEXITCODE -ne 0 -or $null -eq $out) {
            return $null
        }
        return (@($out)[0]).ToString().Trim()
    } catch {
        return $null
    } finally {
        $ErrorActionPreference = $previous
    }
}

Write-Host "Chancela - environment check`n"

$checks = @(
    [pscustomobject]@{ Name = 'cargo';  Version = (Get-ToolVersion 'cargo'  @('--version')) }
    [pscustomobject]@{ Name = 'rustup'; Version = (Get-ToolVersion 'rustup' @('--version')) }
    [pscustomobject]@{ Name = 'node';   Version = (Get-ToolVersion 'node'   @('--version')) }
    [pscustomobject]@{ Name = 'npm';    Version = (Get-ToolVersion 'npm'    @('--version')) }
)

$missing = $false
foreach ($check in $checks) {
    if ($check.Version) {
        Write-Host ("  ok    {0} {1}" -f $check.Name.PadRight(7), $check.Version)
    } else {
        Write-Host ("  MISS  {0} not found on PATH" -f $check.Name.PadRight(7))
        $missing = $true
    }
}

# Node engine gate (mirrors package.json "engines": { "node": ">=20" }).
$nodeVersion = ($checks | Where-Object { $_.Name -eq 'node' }).Version
if ($nodeVersion) {
    $match = [regex]::Match($nodeVersion, '(\d+)')
    if ($match.Success -and [int]$match.Groups[1].Value -lt $MinNodeMajor) {
        Write-Host ""
        Write-Host "Node $nodeVersion is too old - Chancela requires Node >= $MinNodeMajor."
        $missing = $true
    }
}

if ($missing) {
    Write-Host ""
    Write-Host "Install the missing tools, then re-run 'npm run init'."
    Write-Host "  Rust (cargo + rustup): https://rustup.rs"
    Write-Host "  Node.js (node + npm):  https://nodejs.org  (>= 20)"
    exit 1
}

Write-Host "`nInstalling web workspace dependencies (npm install)...`n"
npm install
if ($LASTEXITCODE -ne 0) {
    Write-Host "`n[chancela] npm install failed ($LASTEXITCODE)"
    exit $LASTEXITCODE
}

Write-Host "`nSetup complete. Next steps:"
Write-Host "  npm run dev      # run the API server + web dev server together"
Write-Host "  npm run test     # cargo + vitest test suites"
Write-Host "  npm run build    # release build of server and web bundle"
Write-Host "  npm run package  # assemble a distributable tarball"
