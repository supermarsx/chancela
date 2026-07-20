# Chancela dev runner (Windows / PowerShell).
#
# Runs `cargo run -p chancela-server` and `npm run dev --workspace apps/web`
# concurrently with prefixed, interleaved output. Ctrl+C — or either child
# exiting — tears both down cleanly so no orphan processes survive.
#
# Each child is launched through cmd.exe (so `cargo`/`npm` resolve from PATH,
# npm's .cmd shim included) with its output redirected to temp files; the main
# loop tails those files and prints prefixed lines. Doing the printing on the
# main thread — rather than from Register-ObjectEvent handlers — is what makes
# the output show up reliably even when stdout is a pipe (npm, CI) and not a tty.
#
# Works on Windows PowerShell 5.1 and PowerShell 7+. Invoked via `npm run dev`.

$ErrorActionPreference = 'Stop'

# Kill a process and all of its descendants. cargo/npm each spawn grandchildren
# (the server binary, the Vite node process), so a plain Stop-Process on the
# launcher would orphan them. Recurse via CIM — portable across 5.1 and 7 and
# without shelling out to taskkill.
function Stop-Tree {
    param([int]$ProcessId)
    Get-CimInstance Win32_Process -Filter "ParentProcessId=$ProcessId" -ErrorAction SilentlyContinue |
        ForEach-Object { Stop-Tree -ProcessId $_.ProcessId }
    Stop-Process -Id $ProcessId -Force -ErrorAction SilentlyContinue
}

$logDir = Join-Path ([System.IO.Path]::GetTempPath()) "chancela-dev-$PID"
New-Item -ItemType Directory -Path $logDir -Force | Out-Null

function Start-Labeled {
    param(
        [string]$Label,
        [string]$CommandLine
    )
    $out = Join-Path $logDir "$Label.out"
    $err = Join-Path $logDir "$Label.err"
    New-Item -ItemType File -Path $out -Force | Out-Null
    New-Item -ItemType File -Path $err -Force | Out-Null

    $proc = Start-Process -FilePath $env:ComSpec `
        -ArgumentList '/d', '/s', '/c', $CommandLine `
        -WorkingDirectory (Get-Location).Path `
        -WindowStyle Hidden -PassThru `
        -RedirectStandardOutput $out -RedirectStandardError $err

    return [pscustomobject]@{
        Label = $Label
        Proc  = $proc
        Streams = @(
            [pscustomobject]@{ Path = $out; Pos = [long]0; Buffer = '' }
            [pscustomobject]@{ Path = $err; Pos = [long]0; Buffer = '' }
        )
    }
}

# Print any newly appended complete lines from one redirect file, prefixed by
# [label]. A trailing partial line is held back until its newline arrives.
function Write-Delta {
    param(
        [pscustomobject]$Stream,
        [string]$Label
    )
    $fs = $null
    try {
        $fs = [System.IO.File]::Open($Stream.Path, 'Open', 'Read', 'ReadWrite')
    } catch {
        return
    }
    try {
        if ($fs.Length -le $Stream.Pos) { return }
        [void]$fs.Seek($Stream.Pos, 'Begin')
        $reader = New-Object System.IO.StreamReader($fs)
        $text = $reader.ReadToEnd()
        $Stream.Pos = $fs.Length
    } finally {
        if ($null -ne $fs) { $fs.Dispose() }
    }

    $parts = ($Stream.Buffer + $text) -split "`r`n|`n|`r", -1
    $Stream.Buffer = $parts[-1]
    for ($i = 0; $i -lt $parts.Length - 1; $i++) {
        if ($parts[$i].Length -gt 0) {
            [Console]::Out.WriteLine("[$Label] " + $parts[$i])
        }
    }
}

Write-Host "Chancela dev - starting server + web (Ctrl+C to stop)`n"

$children = @()
$exitCode = 0
$stopped = $false

try {
    $children = @(
        (Start-Labeled 'server' 'cargo run -p chancela-server')
        (Start-Labeled 'web'    'npm run dev --workspace apps/web')
    )

    # Pump output until any child exits (or Ctrl+C interrupts the sleep). A
    # process from Start-Process -PassThru does not reliably expose ExitCode, so
    # a dedicated boolean (not the code) drives loop termination.
    while (-not $stopped) {
        foreach ($child in $children) {
            foreach ($stream in $child.Streams) { Write-Delta $stream $child.Label }
        }
        foreach ($child in $children) {
            if ($child.Proc.HasExited) {
                foreach ($stream in $child.Streams) { Write-Delta $stream $child.Label }
                $code = try { $child.Proc.ExitCode } catch { $null }
                if ($null -eq $code) { $code = 1 }
                Write-Host "`n[dev] $($child.Label) exited (code $code) - shutting down the other process."
                $exitCode = $code
                $stopped = $true
                break
            }
        }
        if (-not $stopped) { Start-Sleep -Milliseconds 250 }
    }
} finally {
    foreach ($child in $children) {
        try {
            if (-not $child.Proc.HasExited) { Stop-Tree -ProcessId $child.Proc.Id }
        } catch { }
    }
    # Final drain of any buffered output, then discard the temp logs.
    Start-Sleep -Milliseconds 200
    foreach ($child in $children) {
        foreach ($stream in $child.Streams) { try { Write-Delta $stream $child.Label } catch { } }
    }
    Remove-Item $logDir -Recurse -Force -ErrorAction SilentlyContinue
}

exit $exitCode
