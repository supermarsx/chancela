<#
.SYNOPSIS
    End-to-end smoke test for the Chancela desktop app's embedded server.

.DESCRIPTION
    Launches the packaged desktop binary, discovers the loopback port its embedded
    HTTP server binds (by walking the launched process tree and scanning listening
    TCP sockets), then drives a real HTTP round-trip against that server and asserts
    the composed system behaves:

      * GET  /health              -> 200 JSON  {status:"ok"}
      * GET  /                    -> 200 HTML   (the SPA shell, NOT JSON)
      * GET  /v1/dashboard        -> 200 JSON
      * POST /v1/users            -> a profile (actor for the ledger)
      * POST /v1/session          -> a session token
      * POST /v1/entities         -> 201 JSON, with the session header
      * GET  /v1/entities         -> the created entity is listed
      * ledger actor attribution  -> the entity.created event's actor == the session user
      * GET  /v1/ledger/verify    -> the hash chain is valid
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

.NOTES
    Honest boundary: this drives the embedded-server composition only. It does NOT
    interact with the native window (drag/click/paint) -- headed Tauri automation is
    inconclusive on this dev box (disconnected RDP). Human headed checks stay manual.

    Compatible with Windows PowerShell 5.1 and PowerShell 7+. Uses System.Net.Http
    directly (not Invoke-WebRequest) so non-2xx responses are inspected uniformly
    across both editions without the throw-on-error / body-extraction differences.

    Do NOT run this while another Chancela desktop instance is open: cleanup reaps every
    chancela-scoped process (the exe + its WebView2 helpers, matched by the app's WebView2
    profile dir) that appeared during the run, which would also stop a concurrent instance.
    The WebView2 EBWebView profile is single-instance locked, so two instances cannot run
    against it at once regardless.
#>

[CmdletBinding()]
param(
    [string]$ExePath,
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
    Write-Host "Build it first, e.g.:  cd apps/desktop; npm run tauri -- build --no-bundle"
    exit 1
}
$ExePath = (Resolve-Path -LiteralPath $ExePath).Path

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
# Killing this run's process family is the tricky part. The desktop exe spawns msedgewebview2.exe
# children (the WebView2 runtime) plus renderer/GPU grandchildren; these reparent when an
# intermediate exits, so a point-in-time tree walk can miss them -- and a leaked WebView2 process
# holds the EBWebView user-data-dir lock, which makes the *next* launch hang (the embedded server
# never starts). A Windows Job Object would be the textbook fix, but a KILL_ON_JOB_CLOSE job
# breaks WebView2: its helper processes need job breakaway, which a plain kill-on-close job denies,
# so WebView2 init fails and no port is ever bound. WebView2 is also shared with the user's Edge,
# so we cannot bulk-kill msedgewebview2 either.
#
# The working, precisely-scoped approach: match by identity, not tree position. The desktop's
# WebView2 profile lives under a fixed, app-specific dir (the bundle id), so its helpers are
# distinguishable from the user's Edge on the msedgewebview2 command line. We snapshot the
# chancela-scoped PIDs *before* launch and, on cleanup, reap the launched tree plus any
# chancela-scoped process that appeared *during* this run. (The EBWebView dir is single-instance
# locked, so two chancela desktop instances cannot run at once anyway; do not run this script while
# another chancela desktop instance is open -- the reap would also stop that one.)
$WEBVIEW_PROFILE_MARKER = 'pt.chancela.desktop'   # Tauri bundle id -> %LOCALAPPDATA%\<id>\EBWebView
$DesktopExeName = [System.IO.Path]::GetFileName($ExePath)

# PIDs of every process belonging to this app right now: the desktop exe (by its own basename) and
# any msedgewebview2 whose --user-data-dir is this app's WebView2 profile (never the user's Edge).
function Get-ChancelaProcessIds {
    $ids = @()
    Get-CimInstance Win32_Process -Filter "Name='$DesktopExeName'" -ErrorAction SilentlyContinue |
        ForEach-Object { $ids += [int]$_.ProcessId }
    Get-CimInstance Win32_Process -Filter "Name='msedgewebview2.exe'" -ErrorAction SilentlyContinue |
        Where-Object { $_.CommandLine -like "*$WEBVIEW_PROFILE_MARKER*" } |
        ForEach-Object { $ids += [int]$_.ProcessId }
    return @($ids)
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

Write-Host "Chancela desktop smoke - $ExePath`n"

$proc = $null
$preExistingPids = @()
$aborted = $false
$abortMsg = ''
try {
    Write-Host "Launching desktop binary..."
    # Snapshot any chancela processes that already exist so cleanup only reaps what THIS run spawns.
    $preExistingPids = Get-ChancelaProcessIds
    $proc = Start-Process -FilePath $ExePath -PassThru
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
        # The embedded server binds in the main launched process; scan its sockets plus this app's
        # other processes (belt-and-suspenders against any reparented socket owner).
        $scanPids = @($proc.Id) + (Get-ChancelaProcessIds) | Select-Object -Unique
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

    # 2. / -> the SPA shell (HTML, explicitly not JSON)
    $r = Invoke-Probe -Method GET -Url "$base/"
    $looksHtml = ($r.Body -match '(?i)<!doctype html|<html')
    $isJson = $null -ne (ConvertFrom-JsonSafe $r.Body)
    Add-Result 'GET / -> HTML shell' `
        (($r.Status -eq 200) -and $looksHtml -and (-not $isJson)) `
        "status=$($r.Status) content-type=$($r.ContentType) html=$looksHtml"

    # 3. /v1/dashboard -> JSON (guard against HTML-instead-of-JSON)
    $r = Invoke-Probe -Method GET -Url "$base/v1/dashboard"
    $j = ConvertFrom-JsonSafe $r.Body
    Add-Result 'GET /v1/dashboard -> JSON' `
        (($r.Status -eq 200) -and ($null -ne $j)) `
        "status=$($r.Status) content-type=$($r.ContentType) json=$($null -ne $j)"

    # 4. Create a user (the actor recorded on the ledger).
    $username = "smoke-$unique"
    $body = @{ username = $username; display_name = 'Smoke Test' } | ConvertTo-Json -Compress
    $r = Invoke-Probe -Method POST -Url "$base/v1/users" -Body $body
    $j = ConvertFrom-JsonSafe $r.Body
    $userId = if ($j) { $j.id } else { $null }
    Add-Result 'POST /v1/users -> profile' `
        (($r.Status -in 200, 201) -and ($null -ne $userId)) `
        "status=$($r.Status) username=$username id=$userId"
    if (-not $userId) { throw "cannot continue the round-trip without a created user" }

    # 5. Open a session for that user -> token.
    $body = @{ user_id = $userId } | ConvertTo-Json -Compress
    $r = Invoke-Probe -Method POST -Url "$base/v1/session" -Body $body
    $j = ConvertFrom-JsonSafe $r.Body
    $token = if ($j) { $j.token } else { $null }
    Add-Result 'POST /v1/session -> token' `
        (($r.Status -eq 200) -and (-not [string]::IsNullOrWhiteSpace($token))) `
        "status=$($r.Status) user=$(if ($j) { $j.user.username } else { '?' }) token=$(if ($token) { 'yes' } else { 'no' })"
    if (-not $token) { throw "cannot continue the round-trip without a session token" }
    $sessionHeader = @{ 'X-Chancela-Session' = $token }

    # 6. Create an entity, attributed to the session user.
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

    # 7. The entity is listed.
    $r = Invoke-Probe -Method GET -Url "$base/v1/entities"
    $j = ConvertFrom-JsonSafe $r.Body
    $listed = ($null -ne $j) -and (@($j | Where-Object { $_.id -eq $entityId }).Count -gt 0)
    Add-Result 'GET /v1/entities -> lists it' `
        (($r.Status -eq 200) -and $listed) `
        "status=$($r.Status) count=$(if ($j) { @($j).Count } else { 0 }) found=$listed"

    # 8. Ledger attribution: the entity.created event's actor is the session user. Assign the
    # filtered result with a direct @() (NOT via an if/else block): assigning the output of an
    # `if` statement enumerates the pipeline and would unroll a single-element array back to a
    # scalar, whose `.Count` is $null under Windows PowerShell 5.1. @($null | ...) is already [].
    $r = Invoke-Probe -Method GET -Url "$base/v1/ledger/events?scope=$entityId"
    $j = ConvertFrom-JsonSafe $r.Body
    $created = @($j | Where-Object { $_.kind -eq 'entity.created' })
    $actorOk = ($created.Count -gt 0) -and ($created[0].actor -eq $username)
    Add-Result 'ledger actor = session user' `
        (($r.Status -eq 200) -and $actorOk) `
        "status=$($r.Status) actor=$(if ($created.Count) { $created[0].actor } else { '(no event)' }) expected=$username"

    # 9. Ledger chain verifies.
    $r = Invoke-Probe -Method GET -Url "$base/v1/ledger/verify"
    $j = ConvertFrom-JsonSafe $r.Body
    Add-Result 'GET /v1/ledger/verify -> valid' `
        (($r.Status -eq 200) -and ($null -ne $j) -and ($j.valid -eq $true)) `
        "status=$($r.Status) valid=$(if ($j) { $j.valid } else { '?' }) length=$(if ($j) { $j.length } else { '?' })"

    # 10. THE REGRESSION GUARD: an unknown /v1 path is a JSON 404, never the HTML shell.
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
        Write-Host "`nStopping desktop process tree (pid $($proc.Id))..."
        # 1. Kill the launched tree (fast path for the live parent + current descendants).
        try { if (-not $proc.HasExited) { Stop-Tree -RootPid $proc.Id } } catch { }
        # 2. Reap any chancela-scoped process that appeared during this run (its own exe + this
        #    app's WebView2 helpers) but did not exist before launch -- this catches reparented /
        #    orphaned WebView2 processes the tree walk missed, without touching the user's Edge.
        Start-Sleep -Milliseconds 300
        $leaked = @(Get-ChancelaProcessIds | Where-Object { $preExistingPids -notcontains $_ })
        foreach ($lpid in $leaked) { Stop-Process -Id $lpid -Force -ErrorAction SilentlyContinue }
        if ($leaked.Count -gt 0) { Write-Host "  reaped $($leaked.Count) orphaned WebView2/app process(es)" }
    }
    if ($script:Http) { $script:Http.Dispose() }
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
