#!/usr/bin/env bash
# Build the axo-pass FFI static library and generate Swift bindings for the
# SwiftPM package at ./app.
#
# Env:
#   PROFILE=debug|release  (default: debug)
#
# Outputs:
#   target/<profile>/libaxo_pass_ffi.a
#   target/swift-lib -> target/<profile>   (symlink used by Package.swift)
#   app/Sources/axo_pass_ffiFFI/{axo_pass_ffiFFI.h,module.modulemap}
#   app/Sources/AxoPassFFI/axo_pass_ffi.swift
set -euo pipefail

PROFILE="${PROFILE:-debug}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

cargo_flags=(-p axo-pass-ffi)
if [[ "$PROFILE" == "release" ]]; then
  cargo_flags+=(--release)
fi

echo "==> building axo-pass-ffi ($PROFILE)"
cargo build "${cargo_flags[@]}"

LIB="$ROOT/target/$PROFILE/libaxo_pass_ffi.a"
if [[ ! -f "$LIB" ]]; then
  echo "missing $LIB" >&2
  exit 1
fi

# Keep a stable symlink so Package.swift doesn't need to know the profile.
ln -sfn "$ROOT/target/$PROFILE" "$ROOT/target/swift-lib"

echo "==> generating Swift bindings"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
cargo run --quiet "${cargo_flags[@]}" --bin uniffi-bindgen -- \
  generate --language swift --out-dir "$TMP" "$LIB"

FFI_C_DIR="$ROOT/app/Sources/axo_pass_ffiFFI"
FFI_SWIFT_DIR="$ROOT/app/Sources/AxoPassFFI"
mkdir -p "$FFI_C_DIR" "$FFI_SWIFT_DIR"

cp "$TMP/axo_pass_ffiFFI.h"        "$FFI_C_DIR/axo_pass_ffiFFI.h"
cp "$TMP/axo_pass_ffiFFI.modulemap" "$FFI_C_DIR/module.modulemap"
cp "$TMP/axo_pass_ffi.swift"        "$FFI_SWIFT_DIR/axo_pass_ffi.swift"

echo "==> ok"
