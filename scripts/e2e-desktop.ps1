<#
.SYNOPSIS
    End-to-end smoke test for the Chancela desktop app's embedded server.

.DESCRIPTION
    Launches the packaged desktop binary with a fresh CHANCELA_DATA_DIR, discovers
    the loopback port its embedded HTTP server binds (by walking the launched process
    tree and scanning listening TCP sockets), then drives a real HTTP round-trip
    against that server and asserts the composed system behaves:

      * GET  /health              -> 200 JSON  {status:"ok"}
      * GET  /                    -> 200 HTML shell when a web dist resolves, otherwise
                                     200 text/plain API-only landing
      * GET  /v1/session/roster   -> 200 JSON, onboarding required for the fresh data dir
      * GET  /v1/session/password-policy -> 200 JSON
      * POST /v1/users            -> bootstrap first profile with mandatory password
      * POST /v1/session          -> password-backed bootstrap session token
      * POST /v1/users/{id}/recovery -> mandatory recovery phrase, with the session header
      * POST /v1/entities         -> 201 JSON, with the session header
      * GET  /v1/entities         -> the created entity is listed, with the session header
      * GET  /v1/dashboard        -> 200 JSON, with the session header
      * ledger actor attribution  -> the entity.created event's actor == the session user
      * GET  /v1/ledger/verify    -> the hash chain is valid, with the session header
      * CHANCELA_DATA_DIR          -> a durable chancela.db was created there
      * GET  /v1/<unknown>        -> 404 JSON  {error:...}  (NOT the HTML shell)

    The last check is the regression guard for the bug this whole test program exists
    to catch: an unknown /v1 path must return a JSON 404, never the single-page-app
    index.html (which broke JSON.parse in the client with "Unexpected token '<'").

    Every JSON-due response is parsed and asserted to actually be JSON, so a server
    that regresses to serving HTML for an API route fails the relevant check.

    On any failure the script prints a PASS/FAIL table and exits non-zero. It always
    kills the process tree it launched (even on a mid-run error) so no orphan exe or
    WebView2 process survives.

.PARAMETER ExePath
    Path to the desktop binary. Defaults to the repo's release build
    (apps/desktop/src-tauri/target/release/chancela-desktop.exe). MUST be a *release*
    build: a debug build reports tauri::is_dev()==true and skips the embedded server,
    so no port is ever bound (the script detects this and says so).

.PARAMETER StartTimeoutSeconds
    How long to wait for the embedded server to bind and answer /health. Default 40.

.PARAMETER DataDir
    Empty or absent data directory to pass to the launched app as CHANCELA_DATA_DIR.
    Defaults to a fresh temp directory, removed at the end of the run. An explicit
    DataDir is created if absent, must be empty if present, and is left on disk.

.PARAMETER MovedLooseBinary
    Copy ExePath to a fresh temp directory and launch that copy with its working
    directory set there. This exercises the "loose --no-bundle binary moved away
    from the repo" path. A loose moved no-bundle binary may legitimately be
    API-only unless -WebDist is provided.

.PARAMETER WebDist
    Optional web build directory to pass to the launched app as CHANCELA_WEB_DIST.
    When provided it must contain index.html, and the smoke expects GET / to serve
    the SPA shell.

.PARAMETER KillOwnedProcesses
    Before launching, terminate only stale processes that are explicitly marked as
    desktop smoke processes (the smoke command-line marker or temp WebView2 profile).
    Generic Chancela desktop/WebView2 instances remain blockers and are never killed
    by this option.

.NOTES
    Honest boundary: this drives the embedded-server composition only. It does NOT
    interact with the native window (drag/click/paint) -- headed Tauri automation is
    inconclusive on this dev box (disconnected RDP). Human headed checks stay manual.

    Compatible with Windows PowerShell 5.1 and PowerShell 7+. Uses System.Net.Http
    directly (not Invoke-WebRequest) so non-2xx responses are inspected uniformly
    across both editions without the throw-on-error / body-extraction differences.

    By default, pre-existing Chancela desktop/WebView2 processes are reported as
    blockers and left running. Pass -KillOwnedProcesses only to clear stale processes
    that a previous smoke run marked with its session/temp-profile marker.
#>

[CmdletBinding()]
param(
    [string]$ExePath,
    [string]$DataDir,
    [switch]$MovedLooseBinary,
    [string]$WebDist,
    [switch]$KillOwnedProcesses,
    [int]$StartTimeoutSeconds = 40
)

$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot
if (-not $ExePath) {
    $ExePath = [System.IO.Path]::Combine(
        $repoRoot, 'apps', 'desktop', 'src-tauri', 'target', 'release', 'chancela-desktop.exe')
}

if (-not (Test-Path -LiteralPath $ExePath)) {
    Write-Host "Desktop binary not found: $ExePath"
    Write-Host "Build it first, e.g.:  cd apps/desktop; npm run build:no-bundle"
    exit 1
}
$ExePath = (Resolve-Path -LiteralPath $ExePath).Path

function New-OwnedTempDir {
    param([Parameter(Mandatory = $true)][string]$Prefix)

    $name = "{0}-{1}-{2}" -f $Prefix, $PID, ([Guid]::NewGuid().ToString('N').Substring(0, 8))
    $path = Join-Path ([System.IO.Path]::GetTempPath()) $name
    New-Item -ItemType Directory -Path $path -Force | Out-Null
    return [System.IO.Path]::GetFullPath($path)
}

function Remove-OwnedTempDir {
    param(
        [string]$Path,
        [Parameter(Mandatory = $true)][string]$Prefix
    )

    if ([string]::IsNullOrWhiteSpace($Path)) { return }
    try {
        $full = [System.IO.Path]::GetFullPath($Path).TrimEnd('\', '/')
        $temp = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath()).TrimEnd('\', '/')
        $tempWithSep = $temp + [System.IO.Path]::DirectorySeparatorChar
        $leaf = Split-Path -Leaf $full
        $comparison = [StringComparison]::OrdinalIgnoreCase
        if ($full.StartsWith($tempWithSep, $comparison) -and
            $leaf.StartsWith($Prefix, $comparison) -and
            (Test-Path -LiteralPath $full)) {
            Remove-Item -LiteralPath $full -Recurse -Force -ErrorAction SilentlyContinue
        }
    } catch { }
}

$SMOKE_PROCESS_MARKER = 'chancela-desktop-smoke'
$SmokeSessionId = "{0}-{1}-{2}" -f $SMOKE_PROCESS_MARKER, $PID, ([Guid]::NewGuid().ToString('N').Substring(0, 12))
$webViewDataDir = $null

$removeDataDirOnExit = $false
if ([string]::IsNullOrWhiteSpace($DataDir)) {
    $DataDir = New-OwnedTempDir -Prefix 'chancela-desktop-smoke-data'
    $removeDataDirOnExit = $true
} else {
    $DataDir = [System.IO.Path]::GetFullPath($DataDir)
    if (Test-Path -LiteralPath $DataDir) {
        $item = Get-Item -LiteralPath $DataDir
        if (-not $item.PSIsContainer) {
            Write-Host "DataDir exists but is not a directory: $DataDir"
            exit 1
        }
        $entries = @(Get-ChildItem -LiteralPath $DataDir -Force -ErrorAction Stop | Select-Object -First 1)
        if ($entries.Count -gt 0) {
            Write-Host "DataDir must be empty for a hermetic smoke run: $DataDir"
            exit 1
        }
    } else {
        New-Item -ItemType Directory -Path $DataDir -Force | Out-Null
    }
}

$webDistForLaunch = $null
if (-not [string]::IsNullOrWhiteSpace($WebDist)) {
    $webDistForLaunch = [System.IO.Path]::GetFullPath($WebDist)
}
if ($webDistForLaunch) {
    $indexPath = Join-Path $webDistForLaunch 'index.html'
    if (-not (Test-Path -LiteralPath $indexPath)) {
        Write-Host "WebDist must contain index.html: $webDistForLaunch"
        Write-Host "Build it first, e.g.:  npm run build --workspace apps/web"
        if ($removeDataDirOnExit) {
            Remove-OwnedTempDir -Path $DataDir -Prefix 'chancela-desktop-smoke-data'
        }
        exit 1
    }
}

$launchExePath = $ExePath
$launchWorkingDir = Split-Path -Parent $launchExePath
$looseRunDir = $null
if ($MovedLooseBinary) {
    try {
        $looseRunDir = New-OwnedTempDir -Prefix 'chancela-desktop-smoke-loose'
        $launchExePath = Join-Path $looseRunDir (Split-Path -Leaf $ExePath)
        Copy-Item -LiteralPath $ExePath -Destination $launchExePath -Force
        $launchWorkingDir = $looseRunDir
    } catch {
        if ($looseRunDir) {
            Remove-OwnedTempDir -Path $looseRunDir -Prefix 'chancela-desktop-smoke-loose'
        }
        if ($removeDataDirOnExit) {
            Remove-OwnedTempDir -Path $DataDir -Prefix 'chancela-desktop-smoke-data'
        }
        throw
    }
}

$webViewDataDir = New-OwnedTempDir -Prefix 'chancela-desktop-smoke-webview'

# --- HTTP plumbing -------------------------------------------------------------------------
# HttpClient never throws on non-2xx, so status + body + content-type read the same way for a
# 200 and a 404. That is exactly what the JSON-vs-HTML assertions need.
Add-Type -AssemblyName System.Net.Http -ErrorAction SilentlyContinue
$script:Http = [System.Net.Http.HttpClient]::new()
$script:Http.Timeout = [TimeSpan]::FromSeconds(15)

function Invoke-Probe {
    param(
        [string]$Method = 'GET',
        [Parameter(Mandatory)][string]$Url,
        [string]$Body,
        [hashtable]$Headers
    )
    $req = [System.Net.Http.HttpRequestMessage]::new(
        [System.Net.Http.HttpMethod]::new($Method), $Url)
    try {
        if ($PSBoundParameters.ContainsKey('Body') -and $null -ne $Body) {
            $req.Content = [System.Net.Http.StringContent]::new(
                $Body, [System.Text.Encoding]::UTF8, 'application/json')
        }
        if ($Headers) {
            foreach ($k in $Headers.Keys) {
                [void]$req.Headers.TryAddWithoutValidation($k, [string]$Headers[$k])
            }
        }
        try {
            $resp = $script:Http.SendAsync($req).GetAwaiter().GetResult()
            $text = $resp.Content.ReadAsStringAsync().GetAwaiter().GetResult()
            $ct = if ($resp.Content.Headers.ContentType) {
                $resp.Content.Headers.ContentType.MediaType
            } else { '' }
            return [pscustomobject]@{
                Status = [int]$resp.StatusCode; Body = $text; ContentType = $ct; Failed = $false
            }
        } catch {
            return [pscustomobject]@{
                Status = 0; Body = ''; ContentType = ''; Failed = $true; Error = $_.Exception.Message
            }
        }
    } finally {
        $req.Dispose()
    }
}

function ConvertFrom-JsonSafe {
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
    try { return $Text | ConvertFrom-Json -ErrorAction Stop } catch { return $null }
}

# --- process helpers -----------------------------------------------------------------------
# WebView2 helpers can outlive or reparent away from the desktop launcher. The safe rule here is:
# default runs never kill pre-existing Chancela processes, and cleanup only kills the launcher we
# started plus descendants/session-marked WebView2 helpers. -KillOwnedProcesses extends that to
# stale smoke-marked processes from earlier runs, but still never kills generic user instances.
$WEBVIEW_PROFILE_MARKER = 'pt.chancela.desktop'   # Tauri bundle id -> %LOCALAPPDATA%\<id>\EBWebView
$DesktopExeName = [System.IO.Path]::GetFileName($launchExePath)
$ApiExeNames = @('chancela-server.exe')
$script:OwnedProcessIds = @{}

function Test-TextContains {
    param([string]$Text, [string]$Needle)
    if ([string]::IsNullOrEmpty($Text) -or [string]::IsNullOrEmpty($Needle)) { return $false }
    return ($Text.IndexOf($Needle, [StringComparison]::OrdinalIgnoreCase) -ge 0)
}

function Add-ProcessInfo {
    param(
        [Parameter(Mandatory = $true)][hashtable]$Map,
        [Parameter(Mandatory = $true)]$Process,
        [Parameter(Mandatory = $true)][string]$Reason
    )

    $id = [int]$Process.ProcessId
    if ($Map.ContainsKey($id)) {
        if (-not (Test-TextContains -Text $Map[$id].Reason -Needle $Reason)) {
            $Map[$id].Reason = "$($Map[$id].Reason); $Reason"
        }
        return
    }

    $Map[$id] = [pscustomobject]@{
        ProcessId = $id
        Name = [string]$Process.Name
        ExecutablePath = [string]$Process.ExecutablePath
        CommandLine = [string]$Process.CommandLine
        Reason = $Reason
    }
}

function Get-ChancelaProcesses {
    $processes = @{}

    Get-CimInstance Win32_Process -Filter "Name='$DesktopExeName'" -ErrorAction SilentlyContinue |
        ForEach-Object { Add-ProcessInfo -Map $processes -Process $_ -Reason 'desktop executable name' }

    foreach ($apiName in $ApiExeNames) {
        Get-CimInstance Win32_Process -Filter "Name='$apiName'" -ErrorAction SilentlyContinue |
            Where-Object { Test-TextContains -Text $_.CommandLine -Needle $SMOKE_PROCESS_MARKER } |
            ForEach-Object { Add-ProcessInfo -Map $processes -Process $_ -Reason 'smoke-marked API process' }
    }

    Get-CimInstance Win32_Process -Filter "Name='msedgewebview2.exe'" -ErrorAction SilentlyContinue |
        Where-Object {
            (Test-TextContains -Text $_.CommandLine -Needle $WEBVIEW_PROFILE_MARKER) -or
            (Test-TextContains -Text $_.CommandLine -Needle $SMOKE_PROCESS_MARKER)
        } |
        ForEach-Object {
            $reason = if (Test-TextContains -Text $_.CommandLine -Needle $SMOKE_PROCESS_MARKER) {
                'smoke-marked WebView2 helper'
            } else {
                'desktop WebView2 profile'
            }
            Add-ProcessInfo -Map $processes -Process $_ -Reason $reason
        }

    return @($processes.Values | Sort-Object ProcessId)
}

function Test-SmokeOwnedProcess {
    param([Parameter(Mandatory = $true)]$Process)

    $name = [string]$Process.Name
    $cmd = [string]$Process.CommandLine
    $exe = [string]$Process.ExecutablePath
    if ($name -ieq $DesktopExeName) {
        return ((Test-TextContains -Text $cmd -Needle $SMOKE_PROCESS_MARKER) -or
            (Test-TextContains -Text $exe -Needle $SMOKE_PROCESS_MARKER))
    }
    if ($name -ieq 'msedgewebview2.exe') {
        return (Test-TextContains -Text $cmd -Needle $SMOKE_PROCESS_MARKER)
    }
    foreach ($apiName in $ApiExeNames) {
        if ($name -ieq $apiName) {
            return (Test-TextContains -Text $cmd -Needle $SMOKE_PROCESS_MARKER)
        }
    }
    return $false
}

function Test-CurrentSmokeProcess {
    param([Parameter(Mandatory = $true)]$Process)

    $cmd = [string]$Process.CommandLine
    $exe = [string]$Process.ExecutablePath
    if ((Test-TextContains -Text $cmd -Needle $SmokeSessionId) -or
        (Test-TextContains -Text $cmd -Needle $webViewDataDir) -or
        (Test-TextContains -Text $exe -Needle $SmokeSessionId) -or
        (Test-TextContains -Text $exe -Needle $webViewDataDir)) {
        return $true
    }
    if ($looseRunDir -and
        ((Test-TextContains -Text $cmd -Needle $looseRunDir) -or
         (Test-TextContains -Text $exe -Needle $looseRunDir))) {
        return $true
    }
    return $false
}

function Get-SmokeOwnedProcesses {
    $processes = @{}
    $candidateNames = @($DesktopExeName, 'msedgewebview2.exe') + $ApiExeNames |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
        Select-Object -Unique

    foreach ($name in $candidateNames) {
        Get-CimInstance Win32_Process -Filter "Name='$name'" -ErrorAction SilentlyContinue |
            Where-Object { Test-SmokeOwnedProcess -Process $_ } |
            ForEach-Object { Add-ProcessInfo -Map $processes -Process $_ -Reason 'smoke-owned marker' }
    }

    return @($processes.Values | Sort-Object ProcessId)
}

function Get-CurrentSmokeProcesses {
    $processes = @{}
    $candidateNames = @($DesktopExeName, 'msedgewebview2.exe') + $ApiExeNames |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
        Select-Object -Unique

    foreach ($name in $candidateNames) {
        Get-CimInstance Win32_Process -Filter "Name='$name'" -ErrorAction SilentlyContinue |
            Where-Object { Test-CurrentSmokeProcess -Process $_ } |
            ForEach-Object { Add-ProcessInfo -Map $processes -Process $_ -Reason 'current smoke session marker' }
    }

    return @($processes.Values | Sort-Object ProcessId)
}

function Format-ProcessList {
    param([object[]]$Processes)

    $lines = @()
    foreach ($p in @($Processes | Sort-Object ProcessId)) {
        $path = if ([string]::IsNullOrWhiteSpace($p.ExecutablePath)) { '(unknown path)' } else { $p.ExecutablePath }
        $cmd = if ([string]::IsNullOrWhiteSpace($p.CommandLine)) { '' } else { $p.CommandLine }
        if ($cmd.Length -gt 260) { $cmd = $cmd.Substring(0, 257) + '...' }
        $lines += ("  PID {0}: {1} - {2}; path={3}; cmd={4}" -f $p.ProcessId, $p.Name, $p.Reason, $path, $cmd)
    }
    return ($lines -join [Environment]::NewLine)
}

function Stop-ProcessIds {
    param([int[]]$ProcessIds)

    foreach ($id in @($ProcessIds | Where-Object { $_ -gt 0 } | Select-Object -Unique)) {
        Stop-Process -Id $id -Force -ErrorAction SilentlyContinue
    }
}

function Get-LiveProcessIds {
    param([int[]]$ProcessIds)

    $live = @()
    foreach ($id in @($ProcessIds | Where-Object { $_ -gt 0 } | Select-Object -Unique)) {
        if (Get-Process -Id $id -ErrorAction SilentlyContinue) { $live += [int]$id }
    }
    return @($live)
}

function Add-OwnedProcessId {
    param([int]$ProcessId)
    if ($ProcessId -gt 0) { $script:OwnedProcessIds[[int]$ProcessId] = $true }
}

function Get-DescendantProcessIds {
    param([int]$RootPid)

    $ids = @()
    Get-CimInstance Win32_Process -Filter "ParentProcessId=$RootPid" -ErrorAction SilentlyContinue |
        ForEach-Object {
            $child = [int]$_.ProcessId
            $ids += $child
            $ids += Get-DescendantProcessIds -RootPid $child
        }
    return @($ids)
}

function Update-OwnedProcessIds {
    param([int]$RootPid)

    Add-OwnedProcessId -ProcessId $RootPid
    Get-DescendantProcessIds -RootPid $RootPid | ForEach-Object { Add-OwnedProcessId -ProcessId $_ }
    Get-CurrentSmokeProcesses | ForEach-Object { Add-OwnedProcessId -ProcessId $_.ProcessId }
}

function Get-CurrentOwnedProcessIds {
    param([int]$RootPid)

    Update-OwnedProcessIds -RootPid $RootPid
    return @(($script:OwnedProcessIds.Keys | ForEach-Object { [int]$_ }) |
        Where-Object { $_ -gt 0 } |
        Select-Object -Unique)
}

# Tauri spawns WebView2 grandchildren; a plain Stop-Process on the launcher would orphan them.
# Recurse via CIM (portable across PS 5.1 and 7, no taskkill shell-out) -- same idiom as dev.ps1.
function Stop-Tree {
    param([int]$RootPid)
    Get-CimInstance Win32_Process -Filter "ParentProcessId=$RootPid" -ErrorAction SilentlyContinue |
        ForEach-Object { Stop-Tree -RootPid $_.ProcessId }
    Stop-Process -Id $RootPid -Force -ErrorAction SilentlyContinue
}

# --- results table -------------------------------------------------------------------------
$script:Results = New-Object System.Collections.ArrayList
function Add-Result {
    param([string]$Check, [bool]$Pass, [string]$Detail)
    [void]$script:Results.Add([pscustomobject]@{
        Check = $Check; Result = $(if ($Pass) { 'PASS' } else { 'FAIL' }); Detail = $Detail
    })
    $tag = if ($Pass) { 'PASS' } else { 'FAIL' }
    Write-Host ("  [{0}] {1} - {2}" -f $tag, $Check, $Detail)
}

$script:LaunchEnvBackup = @{}
function Set-LaunchEnvVar {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Value
    )
    if (-not $script:LaunchEnvBackup.ContainsKey($Name)) {
        $script:LaunchEnvBackup[$Name] =
            [Environment]::GetEnvironmentVariable($Name, 'Process')
    }
    [Environment]::SetEnvironmentVariable($Name, $Value, 'Process')
}

function Restore-LaunchEnvVars {
    foreach ($name in @($script:LaunchEnvBackup.Keys)) {
        $value = $script:LaunchEnvBackup[$name]
        if ($null -eq $value) {
            [Environment]::SetEnvironmentVariable($name, $null, 'Process')
        } else {
            [Environment]::SetEnvironmentVariable($name, [string]$value, 'Process')
        }
    }
    $script:LaunchEnvBackup.Clear()
}

Write-Host "Chancela desktop smoke - $launchExePath"
if ($MovedLooseBinary) { Write-Host "  original exe  $ExePath" }
Write-Host "  working dir   $launchWorkingDir"
Write-Host "  data dir      $DataDir"
Write-Host "  session       $SmokeSessionId"
Write-Host "  webview data  $webViewDataDir"
if ($webDistForLaunch) { Write-Host "  web dist      $webDistForLaunch" }
if ($KillOwnedProcesses) { Write-Host "  cleanup       stale smoke-owned processes only" }
Write-Host ''

$proc = $null
$aborted = $false
$abortMsg = ''
try {
    Write-Host "Launching desktop binary..."
    if ($KillOwnedProcesses) {
        $staleOwned = @(Get-SmokeOwnedProcesses)
        if ($staleOwned.Count -gt 0) {
            Write-Host "Stopping stale smoke-owned process(es) before launch:"
            Write-Host (Format-ProcessList -Processes $staleOwned)
            Stop-ProcessIds -ProcessIds @($staleOwned | ForEach-Object { [int]$_.ProcessId })
            Start-Sleep -Milliseconds 500
        }
    }

    # Any remaining Chancela desktop/WebView2 process is a blocker. Default behavior is
    # conservative: report it and leave it running so we cannot stop a user's app instance.
    $preExisting = @(Get-ChancelaProcesses)
    if ($preExisting.Count -gt 0) {
        $details = Format-ProcessList -Processes $preExisting
        $ownedRemaining = @($preExisting | Where-Object { Test-SmokeOwnedProcess -Process $_ })
        $hint = if ($ownedRemaining.Count -gt 0 -and -not $KillOwnedProcesses) {
            "Rerun with -KillOwnedProcesses to clear only the smoke-marked process(es), or close the listed processes yourself."
        } else {
            "Close the listed process(es) before running the hermetic desktop smoke."
        }
        throw "pre-existing Chancela desktop/WebView2 process(es) detected before launch:`n$details`n$hint"
    }
    Set-LaunchEnvVar -Name 'CHANCELA_DATA_DIR' -Value $DataDir
    if ($webDistForLaunch) {
        Set-LaunchEnvVar -Name 'CHANCELA_WEB_DIST' -Value $webDistForLaunch
    }
    Set-LaunchEnvVar -Name 'WEBVIEW2_USER_DATA_FOLDER' -Value $webViewDataDir
    $smokeArg = "--chancela-smoke-session=$SmokeSessionId"
    $webViewArgs = $smokeArg
    $existingWebViewArgs = [Environment]::GetEnvironmentVariable('WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS', 'Process')
    if (-not [string]::IsNullOrWhiteSpace($existingWebViewArgs)) {
        $webViewArgs = "$existingWebViewArgs $webViewArgs"
    }
    Set-LaunchEnvVar -Name 'WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS' -Value $webViewArgs
    try {
        $proc = Start-Process `
            -FilePath $launchExePath `
            -WorkingDirectory $launchWorkingDir `
            -ArgumentList @($smokeArg) `
            -PassThru
    } finally {
        Restore-LaunchEnvVars
    }
    Add-OwnedProcessId -ProcessId $proc.Id
    Write-Host "  launched pid $($proc.Id)"

    # --- discover the embedded server port -------------------------------------------------
    # The server runs in-process on the main binary; the port is not printed to stdout (it is
    # only used internally to navigate the WebView). Scan listening sockets owned by the
    # launched process tree and confirm the one that answers /health with {status:"ok"}.
    Write-Host "Discovering embedded server port (up to ${StartTimeoutSeconds}s)..."
    $deadline = (Get-Date).AddSeconds($StartTimeoutSeconds)
    $port = 0
    while ((Get-Date) -lt $deadline -and $port -eq 0) {
        if ($proc.HasExited) {
            throw "the desktop binary exited during startup (exit code $($proc.ExitCode)). " +
                  "Is this a RELEASE build? A debug build skips the embedded server."
        }
        # The embedded server binds in the main launched process; scan only the process IDs known
        # to belong to this smoke session so a concurrently-open app cannot be mistaken for ours.
        $scanPids = Get-CurrentOwnedProcessIds -RootPid $proc.Id
        $listen = foreach ($p in $scanPids) {
            Get-NetTCPConnection -OwningProcess $p -State Listen -ErrorAction SilentlyContinue
        }
        $candidates = $listen |
            Where-Object { $_.LocalAddress -in @('127.0.0.1', '::1', '0.0.0.0', '::') } |
            Select-Object -ExpandProperty LocalPort -Unique
        foreach ($cand in $candidates) {
            $r = Invoke-Probe -Method GET -Url "http://127.0.0.1:$cand/health"
            if ($r.Status -eq 200) {
                $parsed = ConvertFrom-JsonSafe $r.Body
                if ($parsed -and $parsed.status -eq 'ok') { $port = $cand; break }
            }
        }
        if ($port -eq 0) { Start-Sleep -Milliseconds 400 }
    }
    if ($port -eq 0) {
        throw "could not discover the embedded server port within ${StartTimeoutSeconds}s. " +
              "The exe launched but no loopback socket answered /health -- confirm it is a " +
              "RELEASE build (a debug build has tauri::is_dev()==true and never starts the server)."
    }
    Write-Host "  embedded server on 127.0.0.1:$port`n"

    $base = "http://127.0.0.1:$port"
    $unique = [Guid]::NewGuid().ToString('N').Substring(0, 8)

    Write-Host "Running probes:"

    # 1. /health -> JSON {status:ok, version}
    $r = Invoke-Probe -Method GET -Url "$base/health"
    $j = ConvertFrom-JsonSafe $r.Body
    Add-Result 'GET /health -> JSON ok' `
        (($r.Status -eq 200) -and ($null -ne $j) -and ($j.status -eq 'ok')) `
        "status=$($r.Status) body=$(if ($j) { "ok, version=$($j.version)" } else { 'NOT JSON' })"

    # 2. / -> either the SPA shell (when a web dist/resource resolves) or the API-only landing.
    # A moved loose --no-bundle binary is not self-contained and, without -WebDist, cannot walk
    # from its temp run dir back to apps/web/dist. That is a valid embedded-server mode.
    $r = Invoke-Probe -Method GET -Url "$base/"
    $looksHtml = ($r.Body -match '(?i)<!doctype html|<html')
    $looksApiLanding = (($r.ContentType -eq 'text/plain') -and
        ($r.Body -match 'Chancela API is running \(web UI not built\)'))
    $isJson = $null -ne (ConvertFrom-JsonSafe $r.Body)
    $rootOk = (($r.Status -eq 200) -and (-not $isJson) -and
        $(if ($webDistForLaunch) { $looksHtml } else { $looksHtml -or $looksApiLanding }))
    Add-Result 'GET / -> shell or API-only landing' `
        $rootOk `
        "status=$($r.Status) content-type=$($r.ContentType) mode=$(if ($looksHtml) { 'html' } elseif ($looksApiLanding) { 'api-only' } else { 'unexpected' }) expectedHtml=$([bool]$webDistForLaunch)"

    # 3. Fresh hermetic data dir starts in onboarding mode.
    $r = Invoke-Probe -Method GET -Url "$base/v1/session/roster"
    $j = ConvertFrom-JsonSafe $r.Body
    $onboardingRequired = ($null -ne $j) -and ($j.onboarding_required -eq $true)
    $rosterKeys = if ($null -ne $j) { @($j.PSObject.Properties.Name) } else { @() }
    $rosterIsMinimal = (($rosterKeys.Count -eq 1) -and ($rosterKeys -contains 'onboarding_required'))
    Add-Result 'GET /v1/session/roster -> onboarding required' `
        (($r.Status -eq 200) -and $onboardingRequired -and $rosterIsMinimal) `
        "status=$($r.Status) onboarding_required=$(if ($j) { $j.onboarding_required } else { '?' }) properties=$($rosterKeys -join ',')"
    if (-not ($onboardingRequired -and $rosterIsMinimal)) {
        throw "fresh DataDir did not report the minimal onboarding_required=true roster; refusing to smoke against a non-hermetic, enumerable, or already-onboarded instance"
    }

    # 4. Password policy is public so onboarding can render before a session exists.
    $r = Invoke-Probe -Method GET -Url "$base/v1/session/password-policy"
    $j = ConvertFrom-JsonSafe $r.Body
    Add-Result 'GET /v1/session/password-policy -> JSON' `
        (($r.Status -eq 200) -and ($null -ne $j) -and ($j.min_length -ge 1) -and ($null -ne $j.rules)) `
        "status=$($r.Status) min_length=$(if ($j) { $j.min_length } else { '?' }) rules=$(if ($j -and $j.rules) { @($j.rules).Count } else { '?' })"

    # 5. Bootstrap the first user. This is the only unauthenticated user create, and it requires a password.
    $username = "smoke-$unique"
    $password = 'N0tary!Vault7'
    $body = @{ username = $username; display_name = 'Smoke Test'; password = $password } | ConvertTo-Json -Compress
    $r = Invoke-Probe -Method POST -Url "$base/v1/users" -Body $body
    $j = ConvertFrom-JsonSafe $r.Body
    $userId = if ($j) { $j.id } else { $null }
    Add-Result 'POST /v1/users -> profile' `
        (($r.Status -in 200, 201) -and ($null -ne $userId) -and ($j.has_secret -eq $true)) `
        "status=$($r.Status) username=$username id=$userId has_secret=$(if ($j) { $j.has_secret } else { '?' })"
    if (-not $userId) { throw "cannot continue the round-trip without a created user" }

    # 6. Open a password-backed bootstrap session. Later onboarding steps are auth-gated.
    $body = @{ user_id = $userId; password = $password } | ConvertTo-Json -Compress
    $r = Invoke-Probe -Method POST -Url "$base/v1/session" -Body $body
    $j = ConvertFrom-JsonSafe $r.Body
    $token = if ($j) { $j.token } else { $null }
    Add-Result 'POST /v1/session with password -> token' `
        (($r.Status -eq 200) -and (-not [string]::IsNullOrWhiteSpace($token))) `
        "status=$($r.Status) user=$(if ($j) { $j.user.username } else { '?' }) token=$(if ($token) { 'yes' } else { 'no' })"
    if (-not $token) { throw "cannot continue the round-trip without a session token" }
    $sessionHeader = @{ 'X-Chancela-Session' = $token }

    # 7. Current onboarding requires a one-time recovery phrase.
    $body = @{ current_password = $password } | ConvertTo-Json -Compress
    $r = Invoke-Probe -Method POST -Url "$base/v1/users/$userId/recovery" -Body $body -Headers $sessionHeader
    $j = ConvertFrom-JsonSafe $r.Body
    Add-Result 'POST /v1/users/{id}/recovery -> phrase issued' `
        (($r.Status -eq 200) -and ($null -ne $j) -and ($j.has_recovery_phrase -eq $true) -and
            (-not [string]::IsNullOrWhiteSpace($j.recovery_phrase))) `
        "status=$($r.Status) has_recovery_phrase=$(if ($j) { $j.has_recovery_phrase } else { '?' }) phrase=$(if ($j -and $j.recovery_phrase) { 'yes' } else { 'no' })"

    # 8. Create an entity, attributed to the session user.
    $body = @{
        name = 'Encosto Estrategico Lda'
        nipc = '503004642'
        seat = 'Lisboa'
        kind = 'SociedadePorQuotas'
    } | ConvertTo-Json -Compress
    $r = Invoke-Probe -Method POST -Url "$base/v1/entities" -Body $body -Headers $sessionHeader
    $j = ConvertFrom-JsonSafe $r.Body
    $entityId = if ($j) { $j.id } else { $null }
    Add-Result 'POST /v1/entities -> 201 JSON' `
        (($r.Status -eq 201) -and ($null -ne $entityId)) `
        "status=$($r.Status) id=$entityId"
    if (-not $entityId) { throw "cannot continue the round-trip without a created entity" }

    # 9. The entity is listed by an authenticated read.
    $r = Invoke-Probe -Method GET -Url "$base/v1/entities" -Headers $sessionHeader
    $j = ConvertFrom-JsonSafe $r.Body
    $listed = ($null -ne $j) -and (@($j | Where-Object { $_.id -eq $entityId }).Count -gt 0)
    Add-Result 'GET /v1/entities -> lists it' `
        (($r.Status -eq 200) -and $listed) `
        "status=$($r.Status) count=$(if ($j) { @($j).Count } else { 0 }) found=$listed"

    # 10. /v1/dashboard is auth-gated; exercise it with the session token.
    $r = Invoke-Probe -Method GET -Url "$base/v1/dashboard" -Headers $sessionHeader
    $j = ConvertFrom-JsonSafe $r.Body
    Add-Result 'GET /v1/dashboard -> JSON with session' `
        (($r.Status -eq 200) -and ($null -ne $j) -and ($j.entities -ge 1)) `
        "status=$($r.Status) content-type=$($r.ContentType) json=$($null -ne $j) entities=$(if ($j) { $j.entities } else { '?' })"

    # 11. Ledger attribution: the entity.created event's actor is the session user. Assign the
    # filtered result with a direct @() (NOT via an if/else block): assigning the output of an
    # `if` statement enumerates the pipeline and would unroll a single-element array back to a
    # scalar, whose `.Count` is $null under Windows PowerShell 5.1. @($null | ...) is already [].
    $r = Invoke-Probe -Method GET -Url "$base/v1/ledger/events?scope=$entityId" -Headers $sessionHeader
    $j = ConvertFrom-JsonSafe $r.Body
    $created = @($j | Where-Object { $_.kind -eq 'entity.created' })
    $actorOk = ($created.Count -gt 0) -and ($created[0].actor -eq $username)
    Add-Result 'ledger actor = session user' `
        (($r.Status -eq 200) -and $actorOk) `
        "status=$($r.Status) actor=$(if ($created.Count) { $created[0].actor } else { '(no event)' }) expected=$username"

    # 13. Ledger chain verifies.
    $r = Invoke-Probe -Method GET -Url "$base/v1/ledger/verify" -Headers $sessionHeader
    $j = ConvertFrom-JsonSafe $r.Body
    Add-Result 'GET /v1/ledger/verify -> valid' `
        (($r.Status -eq 200) -and ($null -ne $j) -and ($j.valid -eq $true)) `
        "status=$($r.Status) valid=$(if ($j) { $j.valid } else { '?' }) length=$(if ($j) { $j.length } else { '?' })"

    # 14. The app honoured the hermetic CHANCELA_DATA_DIR instead of falling back to
    # the user's normal per-app desktop data directory or in-memory state.
    $dbPath = Join-Path $DataDir 'chancela.db'
    $dbExists = Test-Path -LiteralPath $dbPath
    Add-Result 'CHANCELA_DATA_DIR -> durable store' `
        $dbExists `
        "path=$dbPath exists=$dbExists"

    # 15. THE REGRESSION GUARD: an unknown /v1 path is a JSON 404, never the HTML shell.
    $r = Invoke-Probe -Method GET -Url "$base/v1/does-not-exist-$unique"
    $j = ConvertFrom-JsonSafe $r.Body
    $looksHtml = ($r.Body -match '(?i)<!doctype html|<html')
    Add-Result 'unknown /v1 -> JSON 404 (not HTML)' `
        (($r.Status -eq 404) -and ($null -ne $j) -and ($null -ne $j.error) -and (-not $looksHtml)) `
        "status=$($r.Status) content-type=$($r.ContentType) json=$($null -ne $j) html=$looksHtml"
}
catch {
    # A critical prerequisite failed (no port, or the round-trip could not proceed because a
    # user/session/entity was not created -- e.g. a stale binary that 405s on a route the current
    # source serves). Record it and fall through to the summary + non-zero exit, rather than
    # letting the raw exception escape past the PASS/FAIL table.
    $aborted = $true
    $abortMsg = $_.Exception.Message
}
finally {
    if ($proc) {
        Write-Host "`nStopping smoke-owned desktop process(es) (launcher pid $($proc.Id))..."
        try { Update-OwnedProcessIds -RootPid $proc.Id } catch { }
        try { if (-not $proc.HasExited) { Stop-Tree -RootPid $proc.Id } } catch { }
        Start-Sleep -Milliseconds 300
        $remainingOwned = Get-LiveProcessIds -ProcessIds (Get-CurrentOwnedProcessIds -RootPid $proc.Id)
        if ($remainingOwned.Count -gt 0) {
            Stop-ProcessIds -ProcessIds $remainingOwned
            Write-Host "  stopped $($remainingOwned.Count) current smoke-owned helper process(es)"
        }
    }
    if ($script:Http) { $script:Http.Dispose() }
    if ($looseRunDir) {
        Remove-OwnedTempDir -Path $looseRunDir -Prefix 'chancela-desktop-smoke-loose'
    }
    if ($webViewDataDir) {
        Remove-OwnedTempDir -Path $webViewDataDir -Prefix 'chancela-desktop-smoke-webview'
    }
    if ($removeDataDirOnExit) {
        Remove-OwnedTempDir -Path $DataDir -Prefix 'chancela-desktop-smoke-data'
    }
}

# --- summary -------------------------------------------------------------------------------
Write-Host "`nResults:"
$script:Results | Format-Table -AutoSize Check, Result, Detail | Out-String | Write-Host

if ($aborted) {
    Write-Host "Aborted before all checks ran: $abortMsg"
    Write-Host "(remaining checks were skipped)`n"
}

$failed = @($script:Results | Where-Object { $_.Result -eq 'FAIL' })
$total = $script:Results.Count
if ($aborted -or $failed.Count -gt 0) {
    Write-Host ("SMOKE FAILED: {0} of {1} checks failed{2}." -f `
        $failed.Count, $total, $(if ($aborted) { ', run aborted early' } else { '' }))
    exit 1
}
Write-Host ("SMOKE PASSED: all {0} checks green." -f $total)
exit 0
