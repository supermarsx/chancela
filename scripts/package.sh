#!/usr/bin/env bash
# Chancela release packager (POSIX / bash).
#
# 1. Runs the full release build (`npm run build`: cargo release + web bundle).
# 2. Stages the server binary, the web dist, README and license into dist/<stem>/.
# 3. Compresses that directory into dist/<stem>.tar.gz with the system `tar`.
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

# 3. Compress via system tar. Run *inside* dist/ with relative names so the
# archive holds a single top dir (<stem>/) and no argument is an absolute path.
rm -f "$tarball"
printf 'Compressing -> dist/%s.tar.gz ...\n' "$stem"
( cd "$dist_dir" && tar -czf "$stem.tar.gz" "$stem" )

bytes=$(wc -c < "$tarball")
size_mb=$(awk "BEGIN { printf \"%.2f\", $bytes / 1048576 }")
printf '\nArtifact ready:\n'
printf '  %s  (%s MiB)\n' "$tarball" "$size_mb"
printf '\nInspect it with:  tar -tzf "%s"\n' "$tarball"
