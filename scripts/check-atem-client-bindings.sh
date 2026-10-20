#!/usr/bin/env bash
# Builds atem-client-ffi and runs the binding conformance suites over the
# shared r9 vectors (designs/protocol/fixtures/r9-vectors-*.json):
#
#   kotlin  UniFFI-generated Kotlin + JNA on the JVM (Linux, macOS)
#   wasm    the wasm-bindgen build under Node (vectors, then the stateful flows)
#   swift   the UniFFI-generated Swift package (macOS only: swift test)
#   e2e     the binding end-to-end test: a Kotlin phone and a Node/WASM
#           browser against a test host over loopback TCP (needs kotlin+wasm)
#
# Usage: scripts/check-atem-client-bindings.sh [kotlin] [wasm] [swift] [e2e]
#        (no argument: kotlin wasm e2e, plus swift on macOS)
#
# Toolchains are not downloaded here: pass them in (CI fetches and verifies
# them into their own directories; see designs/protocol/atem-client-bindings.md):
#   KOTLINC       kotlinc of the Kotlin compiler release (its lib/ has kotlin-stdlib.jar)
#   JNA_JAR       jna-<version>.jar
#   JAVA          java (default: java on PATH; JDK 17+)
#   NODE          node (default: node on PATH; Node 20+)
#   WASM_BINDGEN  wasm-bindgen CLI, the exact version the crate pins (0.2.101)
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT=$(pwd)

steps=("$@")
if [ ${#steps[@]} -eq 0 ]; then
  steps=(kotlin wasm e2e)
  [ "$(uname)" = "Darwin" ] && steps+=(swift)
fi
want() { local s; for s in "${steps[@]}"; do [ "$s" = "$1" ] && return 0; done; return 1; }

TARGET=${CARGO_TARGET_DIR:-$ROOT/target}
OUT=$TARGET/atem-client-bindings
FIXTURES=$ROOT/designs/protocol/fixtures
BINDINGS=$ROOT/crates/atem-client-ffi/bindings
FEATURES=software-keys,test-vectors,host
JAVA=${JAVA:-java}
NODE=${NODE:-node}
case "$(uname)" in
  Darwin) DYLIB=libatem_client_ffi.dylib ;;
  *) DYLIB=libatem_client_ffi.so ;;
esac
mkdir -p "$OUT"

kotlin_cp=""
if want kotlin || want e2e; then
  : "${KOTLINC:?set KOTLINC to kotlinc of the Kotlin compiler}"
  : "${JNA_JAR:?set JNA_JAR to jna-<version>.jar}"
  cargo build -p atem-client-ffi --features "bindgen,$FEATURES"
  rm -rf "$OUT/kotlin-gen" "$OUT/kotlin-classes"
  "$TARGET/debug/uniffi-bindgen" generate --no-format --library "$TARGET/debug/$DYLIB" \
    --language kotlin --out-dir "$OUT/kotlin-gen"
  "$KOTLINC" -nowarn -cp "$JNA_JAR" -d "$OUT/kotlin-classes" \
    "$OUT/kotlin-gen/uniffi/atem_client_ffi/atem_client_ffi.kt" "$BINDINGS"/kotlin/*.kt
  STDLIB=$(cd "$(dirname "$KOTLINC")/../lib" && pwd)/kotlin-stdlib.jar
  kotlin_cp="$OUT/kotlin-classes:$JNA_JAR:$STDLIB"
fi

if want kotlin; then
  "$JAVA" -Djna.library.path="$TARGET/debug" -cp "$kotlin_cp" atem.bindings.test.ConformanceKt "$FIXTURES"
fi

if want wasm || want e2e; then
  : "${WASM_BINDGEN:?set WASM_BINDGEN to the wasm-bindgen CLI (0.2.101)}"
  cargo build -p atem-client-ffi --target wasm32-unknown-unknown --release \
    --no-default-features --features "wasm,$FEATURES"
  rm -rf "$OUT/wasm-node"
  "$WASM_BINDGEN" --target nodejs --out-dir "$OUT/wasm-node" \
    "$TARGET/wasm32-unknown-unknown/release/atem_client_ffi.wasm"
fi

if want wasm; then
  "$NODE" "$BINDINGS/js/conformance.mjs" "$OUT/wasm-node" "$FIXTURES"
  "$NODE" "$BINDINGS/js/flows.mjs" "$OUT/wasm-node" "$FIXTURES"
fi

if want e2e; then
  ATEM_E2E_JAVA=$(command -v "$JAVA") ATEM_E2E_KOTLIN_CP="$kotlin_cp" \
    ATEM_E2E_JNA_PATH="$TARGET/debug" ATEM_E2E_NODE=$(command -v "$NODE") \
    ATEM_E2E_WASM_PKG="$OUT/wasm-node" \
    cargo test -p atem-client-ffi --test e2e_bindings -- --ignored --nocapture
fi

if want swift; then
  [ "$(uname)" = "Darwin" ] || { echo "swift: macOS only" >&2; exit 1; }
  ./scripts/package-atem-client-apple.sh dev "$OUT/apple" --conformance
  (cd "$OUT/apple/AtemClient" && ATEM_FIXTURES="$FIXTURES" swift test)
fi
echo "atem-client bindings: ${steps[*]} ok"
