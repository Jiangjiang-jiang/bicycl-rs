#!/usr/bin/env bash
# test-system-from-vendored.sh
#
# Integration test for the "system" feature flag.  Since CI runners don't have
# libbicycl_capi installed system-wide, this script:
#   1. Builds bicycl-rs-sys in vendored (default) mode to produce libbicycl_capi.a
#   2. Locates the resulting static library and sets BICYCL_CAPI_LIB_DIR
#   3. Runs `cargo test -p bicycl-rs --features system` against that library
#
# This validates the system-mode link path without requiring a real system install.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
vendored_target_dir="$(mktemp -d "${TMPDIR:-/tmp}/bicycl-rs-vendored-system.XXXXXX")"
system_target_dir="$(mktemp -d "${TMPDIR:-/tmp}/bicycl-rs-system-check.XXXXXX")"

cleanup() {
  rm -rf "$vendored_target_dir" "$system_target_dir"
}
trap cleanup EXIT

cd "$repo_root"

cargo build -p bicycl-rs-sys --target-dir "$vendored_target_dir"

capi_lib_path="$(
  find "$vendored_target_dir"/debug/build -path '*/out/lib/libbicycl_capi.a' \
    | head -n 1
)"

capi_lib_dir=""
if [[ -n "$capi_lib_path" ]]; then
  capi_lib_dir="$(dirname "$capi_lib_path")"
fi

if [[ -z "$capi_lib_dir" ]]; then
  echo "failed to locate libbicycl_capi.a in $vendored_target_dir" >&2
  exit 1
fi

dep_lib_dirs="${BICYCL_DEP_LIB_DIR:-}"

if [[ -n "$dep_lib_dirs" ]]; then
  export BICYCL_DEP_LIB_DIR="$dep_lib_dirs"
fi

export BICYCL_CAPI_LIB_DIR="$capi_lib_dir"

cargo test -p bicycl-rs --no-default-features --features system --target-dir "$system_target_dir"
