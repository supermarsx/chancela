#!/usr/bin/env bash
# Chancela release packager (POSIX / bash).
#
# 1. Runs the full release build (`npm run build`: cargo release + web bundle).
# 2. Stages binaries, the web dist, operator scripts, README and license into dist/<stem>/.
# 3. Writes manifest.json and SHA256SUMS into the staged package.
# 4. Compresses that directory into dist/<stem>.tar.gz with the system `tar`.
#
# <stem> = chancela-<version>-<platform>-<arch>. Version is read from
# package.json; platform maps linux/macos/windows; arch is x64 / arm64.
#
# Invoked via `npm run package` (or `bash scripts/package.sh` directly).

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"

case "$(uname -s)" in
    Linux*)               platform='linux' ;;
    Darwin*)              platform='macos' ;;
    MINGW*|MSYS*|CYGWIN*) platform='windows' ;;
    *)                    platform="$(uname -s | tr '[:upper:]' '[:lower:]')" ;;
esac

case "$(uname -m)" in
    x86_64|amd64)  arch='x64' ;;
    arm64|aarch64) arch='arm64' ;;
    *)             arch="$(uname -m)" ;;
esac

# Read the version straight out of package.json (avoids handing a path to node,
# which sidesteps MSYS/native-path issues when this script is run under Git Bash).
version="$(sed -n 's/.*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$repo_root/package.json" | head -n 1)"
version="${version:-0.0.0}"

binary_name='chancela-server'
[ "$platform" = 'windows' ] && binary_name='chancela-server.exe'

stem="chancela-${version}-${platform}-${arch}"
dist_dir="$repo_root/dist"
stage_dir="$dist_dir/$stem"
tarball="$dist_dir/$stem.tar.gz"

printf 'Chancela package - %s\n\n' "$stem"

# 1. Build.
printf 'Building release artifacts (npm run build)...\n\n'
npm run build

# 2. Stage.
printf '\nStaging into dist/%s/ ...\n' "$stem"
rm -rf "$stage_dir"
mkdir -p "$stage_dir"

binary_src="$repo_root/target/release/$binary_name"
if [ ! -f "$binary_src" ]; then
    printf '\nExpected server binary not found: %s\n' "$binary_src" >&2
    printf 'Did the release build succeed?\n' >&2
    exit 1
fi
cp "$binary_src" "$stage_dir/$binary_name"

web_dist="$repo_root/apps/web/dist"
if [ -d "$web_dist" ]; then
    cp -R "$web_dist" "$stage_dir/web"
else
    printf '\nWarning: web bundle not found at %s - packaging server only.\n' "$web_dist" >&2
fi

for doc in readme.md license.md; do
    if [ -f "$repo_root/$doc" ]; then
        cp "$repo_root/$doc" "$stage_dir/$doc"
    fi
done

cli_name='chancela'
[ "$platform" = 'windows' ] && cli_name='chancela.exe'
cli_src="$repo_root/target/release/$cli_name"
if [ -f "$cli_src" ]; then
    cp "$cli_src" "$stage_dir/$cli_name"
else
    printf '\nWarning: host ops CLI binary not found at %s - packaging without chancela.\n' "$cli_src" >&2
fi

script_stage_dir="$stage_dir/scripts"
for script_name in \
    backup.ps1 backup.sh \
    restore.ps1 restore.sh \
    init.ps1 init.sh \
    dev.ps1 dev.sh \
    package.ps1 package.sh
do
    if [ -f "$repo_root/scripts/$script_name" ]; then
        mkdir -p "$script_stage_dir"
        cp "$repo_root/scripts/$script_name" "$script_stage_dir/$script_name"
    fi
done

git_commit=''
if git_commit_candidate="$(git -C "$repo_root" rev-parse HEAD 2>/dev/null)"; then
    git_commit="$git_commit_candidate"
fi

source_tree_state='unknown'
if git_status="$(git -C "$repo_root" status --porcelain --untracked-files=all 2>/dev/null)"; then
    if [ -n "$git_status" ]; then
        source_tree_state='dirty'
    else
        source_tree_state='clean'
    fi
fi

node - "$stage_dir" "$version" "$platform" "$arch" "$git_commit" "$source_tree_state" <<'NODE'
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const [stageDir, version, platform, arch, gitCommit, sourceTreeState] = process.argv.slice(2);

function walk(dir) {
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const fullPath = path.join(dir, entry.name);
    return entry.isDirectory() ? walk(fullPath) : [fullPath];
  });
}

function relativePackagePath(filePath) {
  return path.relative(stageDir, filePath).split(path.sep).join('/');
}

function fileKind(relativePath) {
  const name = path.basename(relativePath);
  if (['chancela-server', 'chancela-server.exe', 'chancela', 'chancela.exe'].includes(name)) {
    return 'binary';
  }
  if (relativePath.startsWith('web/')) return 'asset';
  if (relativePath.startsWith('scripts/')) return 'script';
  if (['readme.md', 'license.md'].includes(name)) return 'document';
  return 'asset';
}

function sha256(filePath) {
  return crypto.createHash('sha256').update(fs.readFileSync(filePath)).digest('hex');
}

const included = walk(stageDir)
  .map((filePath) => ({ filePath, relativePath: relativePackagePath(filePath) }))
  .filter(({ relativePath }) => !['manifest.json', 'SHA256SUMS'].includes(relativePath))
  .sort((a, b) => a.relativePath.localeCompare(b.relativePath))
  .map(({ filePath, relativePath }) => ({
    path: relativePath,
    kind: fileKind(relativePath),
    size: fs.statSync(filePath).size,
    sha256: sha256(filePath),
  }));

const manifest = {
  version,
  platform,
  arch,
  gitCommit: gitCommit || null,
  generatedAt: new Date().toISOString(),
  sourceProvenance: {
    commitSha: gitCommit || null,
    sourceTreeState,
    buildMode: 'release',
  },
  releaseIntegrity: {
    codeSigning: {
      status: 'unsigned',
      reason: 'The local package script stages unsigned binaries; signed release artifacts must update this status with signer evidence.',
    },
    notarization: {
      status: platform === 'macos' ? 'not_notarized' : 'not_applicable',
      reason: platform === 'macos'
        ? 'The local package script does not submit artifacts for notarization.'
        : 'Notarization applies to macOS release artifacts only.',
    },
  },
  included,
  checksums: {
    algorithm: 'SHA-256',
    files: included,
  },
};

fs.writeFileSync(path.join(stageDir, 'manifest.json'), `${JSON.stringify(manifest, null, 2)}\n`);

const sums = walk(stageDir)
  .map((filePath) => ({ filePath, relativePath: relativePackagePath(filePath) }))
  .filter(({ relativePath }) => relativePath !== 'SHA256SUMS')
  .sort((a, b) => a.relativePath.localeCompare(b.relativePath))
  .map(({ filePath, relativePath }) => `${sha256(filePath)}  *${relativePath}`)
  .join('\n');

fs.writeFileSync(path.join(stageDir, 'SHA256SUMS'), `${sums}\n`);
NODE

# 4. Compress via system tar. Run *inside* dist/ with relative names so the
# archive holds a single top dir (<stem>/) and no argument is an absolute path.
rm -f "$tarball"
printf 'Compressing -> dist/%s.tar.gz ...\n' "$stem"
( cd "$dist_dir" && tar -czf "$stem.tar.gz" "$stem" )

bytes=$(wc -c < "$tarball")
size_mb=$(awk "BEGIN { printf \"%.2f\", $bytes / 1048576 }")
printf '\nArtifact ready:\n'
printf '  %s  (%s MiB)\n' "$tarball" "$size_mb"
printf '\nInspect it with:  tar -tzf "%s"\n' "$tarball"
