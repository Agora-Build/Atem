#!/usr/bin/env bash
# Usage: scripts/package-atem-client-bindings.sh <version> <output-dir> [wasm] [kotlin]
#        (no kind: both)
#
# The production atem-client binding packages for Astation (no test
# features: `software-keys`, `test-vectors` and `host` are never in them),
# each with a source pin and SHA-256 sums:
#
#   wasm    atem-client-<version>-wasm.tar.gz: the release wasm-bindgen
#           build (feature `wasm` only) for `web/`, `nodejs/` and `bundler/`
#           (atem_client_ffi.js, atem_client_ffi_bg.wasm, .d.ts)
#   kotlin  atem-client-<version>-kotlin-jvm-<platform>.tar.gz: the
#           UniFFI-generated Kotlin (src/uniffi/atem_client_ffi/
#           atem_client_ffi.kt), the release JNA library for this machine
#           (<platform>/libatem_client_ffi.so|.dylib, platform as JNA names
#           it), and atem-client-ffi-<version>.jar (the compiled bindings with
#           the library inside, when KOTLINC and JNA_JAR are given)
#
# Next to them: atem-client-<version>-SOURCE.json (commit, crate versions,
# features, toolchains; scripts/atem-client-source-pin.sh) and
# atem-client-<version>-SHA256SUMS.txt over every file. Archives are
# deterministic (sorted, mtime 0, numeric owner 0, gzip -n).
# The Apple package is scripts/package-atem-client-apple.sh (macOS). This
# script needs GNU tar and coreutils (Linux; CI runs it on ubuntu-latest).
#
# Toolchains are passed in, as for the conformance script:
#   WASM_BINDGEN  wasm-bindgen CLI, exactly the version the crate pins
#   KOTLINC, JNA_JAR  optional: the jar is built only with both
set -euo pipefail
VERSION="$1"
OUT="$2"
shift 2
kinds=("$@")
[ ${#kinds[@]} -eq 0 ] && kinds=(wasm kotlin)
want() { local k; for k in "${kinds[@]}"; do [ "$k" = "$1" ] && return 0; done; return 1; }
cd "$(dirname "$0")/.."
ROOT=$(pwd)
TARGET=${CARGO_TARGET_DIR:-$ROOT/target}
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
FILES=()
TOOLS=()
FEATURES=()

archive() { # archive <name.tar.gz> <dir> <entry>
  tar --sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner -C "$2" -cf - "$3" \
    | gzip -n -9 >"$OUT/$1"
  FILES+=("$1")
}

if want wasm; then
  : "${WASM_BINDGEN:?set WASM_BINDGEN to the wasm-bindgen CLI (0.2.101)}"
  PINNED=$(sed -n 's/^wasm-bindgen = { version = "=\([0-9.]*\)".*/\1/p' crates/atem-client-ffi/Cargo.toml)
  GOT=$("$WASM_BINDGEN" --version | awk '{print $2}')
  [ "$GOT" = "$PINNED" ] || { echo "wasm-bindgen CLI $GOT, the crate pins $PINNED" >&2; exit 1; }
  cargo build -p atem-client-ffi --target wasm32-unknown-unknown --release \
    --no-default-features --features wasm
  WASM="$TARGET/wasm32-unknown-unknown/release/atem_client_ffi.wasm"
  PKG="$WORK/atem-client-wasm"
  for t in web nodejs bundler; do
    "$WASM_BINDGEN" --target "$t" --out-dir "$PKG/$t" "$WASM"
  done
  archive "atem-client-${VERSION}-wasm.tar.gz" "$WORK" atem-client-wasm
  TOOLS+=("wasm-bindgen-cli=$GOT")
  FEATURES+=("wasm: --no-default-features --features wasm")
fi

if want kotlin; then
  HOST=$(rustc -vV | sed -n 's/^host: //p')
  case "$HOST" in
    x86_64-unknown-linux-gnu) PLATFORM=linux-x86-64; LIB=libatem_client_ffi.so ;;
    aarch64-unknown-linux-gnu) PLATFORM=linux-aarch64; LIB=libatem_client_ffi.so ;;
    aarch64-apple-darwin) PLATFORM=darwin-aarch64; LIB=libatem_client_ffi.dylib ;;
    x86_64-apple-darwin) PLATFORM=darwin-x86-64; LIB=libatem_client_ffi.dylib ;;
    *) echo "kotlin: no JNA platform for $HOST" >&2; exit 1 ;;
  esac
  # Kotlin is generated from a build with the shipped exports (`bindgen`
  # adds only the generator); the library is the release build.
  cargo build -p atem-client-ffi --features bindgen
  cargo build -p atem-client-ffi --release
  PKG="$WORK/atem-client-kotlin-jvm"
  mkdir -p "$PKG/src" "$PKG/$PLATFORM"
  "$TARGET/debug/uniffi-bindgen" generate --no-format --library "$TARGET/debug/$LIB" \
    --language kotlin --out-dir "$PKG/src"
  cp "$TARGET/release/$LIB" "$PKG/$PLATFORM/"
  if [ -n "${KOTLINC:-}" ] && [ -n "${JNA_JAR:-}" ]; then
    mkdir -p "$WORK/classes"
    "$KOTLINC" -nowarn -cp "$JNA_JAR" -d "$WORK/classes" \
      "$PKG/src/uniffi/atem_client_ffi/atem_client_ffi.kt"
    mkdir -p "$WORK/classes/$PLATFORM"
    cp "$TARGET/release/$LIB" "$WORK/classes/$PLATFORM/"
    # Deterministic jar: sorted entries, fixed times.
    (cd "$WORK/classes" && find . -type f | LC_ALL=C sort | sed 's|^\./||' >"$WORK/entries" \
      && touch -d @0 $(cat "$WORK/entries") \
      && rm -f "$PKG/atem-client-ffi-${VERSION}.jar" \
      && zip -q -X -D "$PKG/atem-client-ffi-${VERSION}.jar" -@ <"$WORK/entries")
    TOOLS+=("kotlinc=$("$KOTLINC" -version 2>&1 | sed -n 's/.*kotlinc-jvm \([^ ]*\).*/\1/p')")
    TOOLS+=("jna=$(basename "$JNA_JAR" .jar | sed 's/^jna-//')")
  fi
  FEATURES+=("kotlin: default (uniffi)")
  archive "atem-client-${VERSION}-kotlin-jvm-${PLATFORM}.tar.gz" "$WORK" atem-client-kotlin-jvm
fi

PIN="atem-client-${VERSION}-SOURCE.json"
./scripts/atem-client-source-pin.sh "$OUT/$PIN" "$(IFS=,; echo "${kinds[*]}")" \
  "$(printf '%s\n' "${FEATURES[@]}" | paste -sd ';' - | sed 's/;/; /g')" \
  ${TOOLS[@]+"${TOOLS[@]}"}
FILES+=("$PIN")
SUMS="atem-client-${VERSION}-SHA256SUMS.txt"
(cd "$OUT" && sha256sum "${FILES[@]}" >"$SUMS")
echo "Packaged into $OUT:"
(cd "$OUT" && ls -l "${FILES[@]}" "$SUMS")
