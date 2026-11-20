#!/usr/bin/env bash
# Build the `ap` CLI and the browser native messaging host, and stage them at
# stable paths for strudel to copy into the bundle (see [[build.copy]] in
# strudel.toml).
#
# Env:
#   PROFILE=debug|release  (default: debug)
#
# Outputs:
#   target/dist/ap
#   target/dist/AxoPassBrowserHost
set -euo pipefail

PROFILE="${PROFILE:-debug}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BINS=(ap AxoPassBrowserHost)

cargo_flags=(-p axo-pass-cli)
for bin in "${BINS[@]}"; do
  cargo_flags+=(--bin "$bin")
done
if [[ "$PROFILE" == "release" ]]; then
  cargo_flags+=(--release)
fi

echo "==> building ${BINS[*]} ($PROFILE)"
# Match the platform in app/Package.swift so binaries run on the minimum macOS.
export MACOSX_DEPLOYMENT_TARGET="${MACOSX_DEPLOYMENT_TARGET:-15.0}"
cargo build "${cargo_flags[@]}"

DIST_DIR="$ROOT/target/dist"
mkdir -p "$DIST_DIR"
for bin in "${BINS[@]}"; do
  src="$ROOT/target/$PROFILE/$bin"
  if [[ ! -f "$src" ]]; then
    echo "missing $src" >&2
    exit 1
  fi
  cp "$src" "$DIST_DIR/$bin"
  chmod +x "$DIST_DIR/$bin"
  echo "==> ok ($DIST_DIR/$bin)"
done
