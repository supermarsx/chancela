# Chancela release packager (Windows / PowerShell).
#
# 1. Runs the full release build (`npm run build`: cargo release + web bundle).
# 2. Stages the server binary, the web dist, README and license into dist/<stem>/.
# 3. Compresses that directory into dist/<stem>.tar.gz with the system `tar`.
#
# <stem> = chancela-<version>-<platform>-<arch>. Version is read from
# package.json; platform is `windows` here; arch is x64 / arm64.
#
# Works on Windows PowerShell 5.1 and PowerShell 7+. Invoked via `npm run package`.

$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot

$platform = 'windows'
switch ($env:PROCESSOR_ARCHITECTURE) {
    'AMD64' { $arch = 'x64' }
    'ARM64' { $arch = 'arm64' }
    'x86'   { $arch = 'ia32' }
    default { $arch = $env:PROCESSOR_ARCHITECTURE.ToLower() }
}

$pkg = Get-Content ([System.IO.Path]::Combine($repoRoot, 'package.json')) -Raw | ConvertFrom-Json
$version = if ($pkg.version) { $pkg.version } else { '0.0.0' }

$stem = "chancela-$version-$platform-$arch"
$distDir = [System.IO.Path]::Combine($repoRoot, 'dist')
$stageDir = [System.IO.Path]::Combine($distDir, $stem)
$tarball = [System.IO.Path]::Combine($distDir, "$stem.tar.gz")

Write-Host "Chancela package - $stem`n"

# 1. Build.
Write-Host "Building release artifacts (npm run build)...`n"
npm run build
if ($LASTEXITCODE -ne 0) {
    Write-Host "`n[chancela] npm run build failed ($LASTEXITCODE)"
    exit $LASTEXITCODE
}

# 2. Stage.
Write-Host "`nStaging into dist/$stem/ ..."
if (Test-Path $stageDir) { Remove-Item $stageDir -Recurse -Force }
New-Item -ItemType Directory -Path $stageDir -Force | Out-Null

$binaryName = 'chancela-server.exe'
$binarySrc = [System.IO.Path]::Combine($repoRoot, 'target', 'release', $binaryName)
if (-not (Test-Path $binarySrc)) {
    Write-Host "`nExpected server binary not found: $binarySrc"
    Write-Host "Did the release build succeed?"
    exit 1
}
Copy-Item $binarySrc ([System.IO.Path]::Combine($stageDir, $binaryName))

$webDist = [System.IO.Path]::Combine($repoRoot, 'apps', 'web', 'dist')
if (Test-Path $webDist) {
    Copy-Item $webDist ([System.IO.Path]::Combine($stageDir, 'web')) -Recurse
} else {
    Write-Host "`nWarning: web bundle not found at $webDist - packaging server only."
}

foreach ($doc in @('readme.md', 'license.md')) {
    $src = [System.IO.Path]::Combine($repoRoot, $doc)
    if (Test-Path $src) { Copy-Item $src ([System.IO.Path]::Combine($stageDir, $doc)) }
}

# 3. Compress via system tar. Run *inside* dist/ with relative names so the
# archive holds a single top dir (<stem>/) and — critically on Windows — no
# argument contains a drive-letter colon. GNU tar treats `F:\...` as a remote
# `host:path` (bsdtar does not); relative names keep both implementations happy.
if (Test-Path $tarball) { Remove-Item $tarball -Force }
Write-Host "Compressing -> dist/$stem.tar.gz ..."
Push-Location $distDir
try {
    & tar -czf "$stem.tar.gz" $stem
    $tarExit = $LASTEXITCODE
} finally {
    Pop-Location
}
if ($tarExit -ne 0) {
    Write-Host "`ntar failed (exit $tarExit). Is 'tar' on PATH? (Windows 10+/macOS/Linux ship it.)"
    exit $tarExit
}

$sizeMb = "{0:N2}" -f ((Get-Item $tarball).Length / 1MB)
Write-Host "`nArtifact ready:"
Write-Host "  $tarball  ($sizeMb MiB)"
Write-Host "`nInspect it with:  tar -tzf `"$tarball`""
