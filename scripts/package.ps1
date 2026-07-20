# Chancela release packager (Windows / PowerShell).
#
# 1. Runs the full release build (`npm run build`: cargo release + web bundle).
# 2. Stages binaries, the web dist, operator scripts, README and license into dist/<stem>/.
# 3. Writes manifest.json and SHA256SUMS into the staged package.
# 4. Compresses that directory into dist/<stem>.tar.gz with the system `tar`.
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

$cliName = 'chancela.exe'
$cliSrc = [System.IO.Path]::Combine($repoRoot, 'target', 'release', $cliName)
if (Test-Path $cliSrc) {
    Copy-Item $cliSrc ([System.IO.Path]::Combine($stageDir, $cliName))
} else {
    Write-Host "`nWarning: host ops CLI binary not found at $cliSrc - packaging without chancela."
}

$scriptNames = @(
    'backup.ps1', 'backup.sh',
    'restore.ps1', 'restore.sh',
    'init.ps1', 'init.sh',
    'dev.ps1', 'dev.sh',
    'package.ps1', 'package.sh'
)
$scriptStageDir = [System.IO.Path]::Combine($stageDir, 'scripts')
foreach ($scriptName in $scriptNames) {
    $src = [System.IO.Path]::Combine($repoRoot, 'scripts', $scriptName)
    if (Test-Path $src) {
        if (-not (Test-Path $scriptStageDir)) {
            New-Item -ItemType Directory -Path $scriptStageDir -Force | Out-Null
        }
        Copy-Item $src ([System.IO.Path]::Combine($scriptStageDir, $scriptName))
    }
}

function Get-RelativePackagePath {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string]$Path
    )

    $rootFull = [System.IO.Path]::GetFullPath($Root).TrimEnd([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar) + [System.IO.Path]::DirectorySeparatorChar
    $pathFull = [System.IO.Path]::GetFullPath($Path)
    $rootUri = New-Object System.Uri($rootFull)
    $pathUri = New-Object System.Uri($pathFull)
    [System.Uri]::UnescapeDataString($rootUri.MakeRelativeUri($pathUri).ToString()).Replace('\', '/')
}

function Get-PackageFileKind {
    param([Parameter(Mandatory = $true)][string]$RelativePath)

    $name = [System.IO.Path]::GetFileName($RelativePath)
    if ($name -in @('chancela-server.exe', 'chancela.exe')) { return 'binary' }
    if ($RelativePath -like 'web/*') { return 'asset' }
    if ($RelativePath -like 'scripts/*') { return 'script' }
    if ($name -in @('readme.md', 'license.md')) { return 'document' }
    return 'asset'
}

function Get-Sha256File {
    param([Parameter(Mandatory = $true)][string]$Path)

    $stream = [System.IO.File]::OpenRead($Path)
    try {
        $sha256 = [System.Security.Cryptography.SHA256]::Create()
        try {
            $hashBytes = $sha256.ComputeHash($stream)
            -join ($hashBytes | ForEach-Object { $_.ToString('x2') })
        } finally {
            $sha256.Dispose()
        }
    } finally {
        $stream.Dispose()
    }
}

$gitCommit = $null
try {
    $gitCommitCandidate = (& git -C $repoRoot rev-parse HEAD 2>$null)
    if ($LASTEXITCODE -eq 0 -and $gitCommitCandidate) {
        $gitCommit = ($gitCommitCandidate | Select-Object -First 1).Trim()
    }
} catch {
    $gitCommit = $null
}

$sourceTreeState = 'unknown'
try {
    $gitStatus = (& git -C $repoRoot status --porcelain --untracked-files=all 2>$null)
    if ($LASTEXITCODE -eq 0) {
        if ($gitStatus) {
            $sourceTreeState = 'dirty'
        } else {
            $sourceTreeState = 'clean'
        }
    }
} catch {
    $sourceTreeState = 'unknown'
}

$includedFiles = Get-ChildItem -Path $stageDir -Recurse -File |
    Where-Object { $_.Name -notin @('manifest.json', 'SHA256SUMS') } |
    Sort-Object FullName |
    ForEach-Object {
        $relativePath = Get-RelativePackagePath -Root $stageDir -Path $_.FullName
        [pscustomobject][ordered]@{
            path = $relativePath
            kind = Get-PackageFileKind -RelativePath $relativePath
            size = $_.Length
            sha256 = Get-Sha256File -Path $_.FullName
        }
    }

$notarizationStatus = if ($platform -eq 'macos') { 'not_notarized' } else { 'not_applicable' }
$notarizationReason = if ($platform -eq 'macos') {
    'The local package script does not submit artifacts for notarization.'
} else {
    'Notarization applies to macOS release artifacts only.'
}

$manifest = [pscustomobject][ordered]@{
    version = $version
    platform = $platform
    arch = $arch
    gitCommit = $gitCommit
    generatedAt = (Get-Date).ToUniversalTime().ToString('o')
    sourceProvenance = [pscustomobject][ordered]@{
        commitSha = $gitCommit
        sourceTreeState = $sourceTreeState
        buildMode = 'release'
    }
    releaseIntegrity = [pscustomobject][ordered]@{
        codeSigning = [pscustomobject][ordered]@{
            status = 'unsigned'
            reason = 'The local package script stages unsigned binaries; signed release artifacts must update this status with signer evidence.'
        }
        notarization = [pscustomobject][ordered]@{
            status = $notarizationStatus
            reason = $notarizationReason
        }
    }
    included = $includedFiles
    checksums = [pscustomobject][ordered]@{
        algorithm = 'SHA-256'
        files = $includedFiles
    }
}

$manifestPath = [System.IO.Path]::Combine($stageDir, 'manifest.json')
$manifest | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $manifestPath -Encoding UTF8

$sumPath = [System.IO.Path]::Combine($stageDir, 'SHA256SUMS')
$sumLines = Get-ChildItem -Path $stageDir -Recurse -File |
    Where-Object { $_.Name -ne 'SHA256SUMS' } |
    Sort-Object FullName |
    ForEach-Object {
        $relativePath = Get-RelativePackagePath -Root $stageDir -Path $_.FullName
        "{0}  *{1}" -f (Get-Sha256File -Path $_.FullName), $relativePath
    }
$sumLines | Set-Content -LiteralPath $sumPath -Encoding ASCII

# 4. Compress via system tar. Run *inside* dist/ with relative names so the
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
