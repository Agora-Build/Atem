#!/usr/bin/env bash
# Usage: scripts/package-atem-core-macos.sh <version> <output-dir>
# Universal (arm64 + x86_64) static library + header → AtemCore.xcframework,
# zipped, with the header and SHA-256 sums alongside. macOS only.
set -euo pipefail
VERSION="$1"
OUT="$2"
cd "$(dirname "$0")/.."
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"

for target in aarch64-apple-darwin x86_64-apple-darwin; do
  cargo build -p atem-core-ffi --release --target "$target"
done

WORK="$(mktemp -d)"
lipo -create \
  target/aarch64-apple-darwin/release/libatem_core_ffi.a \
  target/x86_64-apple-darwin/release/libatem_core_ffi.a \
  -output "$WORK/libatem_core_ffi.a"
mkdir -p "$WORK/include"
cp crates/atem-core-ffi/include/atem_core.h crates/atem-core-ffi/include/module.modulemap "$WORK/include/"
xcodebuild -create-xcframework -library "$WORK/libatem_core_ffi.a" -headers "$WORK/include" \
  -output "$WORK/AtemCore.xcframework"

ZIP="atem-core-${VERSION}-macos-xcframework.zip"
(cd "$WORK" && ditto -c -k --keepParent AtemCore.xcframework "$ZIP")
mv "$WORK/$ZIP" "$OUT/"
cp crates/atem-core-ffi/include/atem_core.h "$OUT/atem-core-${VERSION}-atem_core.h"
(cd "$OUT" && shasum -a 256 "$ZIP" "atem-core-${VERSION}-atem_core.h" > "atem-core-${VERSION}-SHA256SUMS.txt")
echo "Packaged into $OUT:"
ls -l "$OUT"
