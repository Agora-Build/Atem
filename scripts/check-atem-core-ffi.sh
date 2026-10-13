#!/usr/bin/env bash
# Builds libatem_core_ffi.a and drives it from C (and Swift on macOS).
set -euo pipefail
cd "$(dirname "$0")/.."

cargo build -p atem-core-ffi --release
# The system libraries a Rust static library needs on this platform.
LIBS=$(cargo rustc -p atem-core-ffi --release --lib --crate-type staticlib -- --print native-static-libs 2>&1 \
  | sed -n 's/.*native-static-libs: //p' | tail -1)
LIB=target/release/libatem_core_ffi.a
INCLUDE=crates/atem-core-ffi/include
OUT=target/atem-core-ffi-check
mkdir -p "$OUT"

cc -std=c11 -Wall -Wextra -Werror -I "$INCLUDE" crates/atem-core-ffi/tests/c/consumer.c "$LIB" $LIBS -o "$OUT/consumer"
"$OUT/consumer"

if [ "$(uname)" = "Darwin" ]; then
  swiftc -import-objc-header "$INCLUDE/atem_core.h" crates/atem-core-ffi/tests/swift/main.swift \
    -Xlinker "$LIB" $LIBS -o "$OUT/swift_consumer"
  "$OUT/swift_consumer"
fi
