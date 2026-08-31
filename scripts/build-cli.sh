#!/usr/bin/env bash
# Build the `ap` CLI binary and stage it at a stable path for strudel to
# pick up as a bundle resource (see [build.resources] in strudel.toml).
#
# Env:
#   PROFILE=debug|release  (default: debug)
#
# Outputs:
#   target/dist/ap
set -euo pipefail

PROFILE="${PROFILE:-debug}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

cargo_flags=(-p axo-pass-cli --bin ap)
if [[ "$PROFILE" == "release" ]]; then
  cargo_flags+=(--release)
fi

echo "==> building ap ($PROFILE)"
cargo build "${cargo_flags[@]}"

BIN="$ROOT/target/$PROFILE/ap"
if [[ ! -f "$BIN" ]]; then
  echo "missing $BIN" >&2
  exit 1
fi

DIST_DIR="$ROOT/target/dist"
mkdir -p "$DIST_DIR"
cp "$BIN" "$DIST_DIR/ap"
chmod +x "$DIST_DIR/ap"

echo "==> ok ($DIST_DIR/ap)"
