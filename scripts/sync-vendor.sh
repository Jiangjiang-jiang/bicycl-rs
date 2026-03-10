#!/usr/bin/env bash
# sync-vendor.sh
#
# Synchronize vendored BICYCL sources from upstream.
#
# Defaults (repo URL and commit ref) are read from:
#   bicycl-rs-sys/vendor/bicycl-upstream.toml
#
# Override with positional arguments:
#   ./scripts/sync-vendor.sh [repo-url] [git-ref]
#
# After running, bicycl-upstream.toml is updated with the resolved commit hash.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
vendor_root="$repo_root/bicycl-rs-sys/vendor"
vendor_dir="$vendor_root/bicycl"
meta_file="$vendor_root/bicycl-upstream.toml"

default_repo="$(sed -n 's/^repo = "\(.*\)"$/\1/p' "$meta_file")"
default_ref="$(sed -n 's/^ref = "\(.*\)"$/\1/p' "$meta_file")"

upstream_repo="${1:-$default_repo}"
upstream_ref="${2:-$default_ref}"

if [[ -z "$upstream_repo" || -z "$upstream_ref" ]]; then
  echo "usage: $0 [upstream-repo] [upstream-ref]" >&2
  exit 1
fi

tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/bicycl-upstream.XXXXXX")"
cleanup() {
  rm -rf "$tmp_dir"
}
trap cleanup EXIT

git clone --depth 1 --branch "$upstream_ref" "$upstream_repo" "$tmp_dir/repo" 2>/dev/null || {
  git clone "$upstream_repo" "$tmp_dir/repo"
  git -C "$tmp_dir/repo" checkout "$upstream_ref"
}

resolved_ref="$(git -C "$tmp_dir/repo" rev-parse HEAD)"

rm -rf "$vendor_dir"
mkdir -p "$vendor_dir"
cp -R "$tmp_dir/repo/AUTHORS" "$vendor_dir/AUTHORS"
cp -R "$tmp_dir/repo/LICENSE" "$vendor_dir/LICENSE"
cp -R "$tmp_dir/repo/src" "$vendor_dir/src"

cat > "$meta_file" <<EOF
repo = "$upstream_repo"
ref = "$resolved_ref"
sync_paths = ["AUTHORS", "LICENSE", "src"]
EOF

echo "synced vendor/bicycl from $upstream_repo@$resolved_ref"
