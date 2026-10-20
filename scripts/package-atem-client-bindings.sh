#!/usr/bin/env bash
# Usage: scripts/package-atem-client-bindings.sh <version> <output-dir> [wasm] [kotlin] [android]
#        (no kind: wasm and kotlin)
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
#   android atem-client-<version>-android.zip: atem-client-android/
#           jniLibs/<abi>/libatem_client_ffi.so for arm64-v8a, armeabi-v7a
#           and x86_64 (release cdylib, default features, linked by the
#           NDK's clang for API level ANDROID_API, 16 KB LOAD alignment),
#           kotlin/uniffi/atem_client_ffi/atem_client_ffi.kt (the same
#           UniFFI Kotlin as the JVM package; it loads the library through
#           JNA, so the app adds net.java.dev.jna:jna:<v>@aar) and
#           README.txt. Each library's ELF class, machine and LOAD alignment
#           are checked before it is packaged.
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
#   ANDROID_NDK_HOME  android: the NDK; EXPECT_NDK (optional): the
#                     Pkg.Revision it must have (CI pins it)
#   ANDROID_API       android: the minimum API level (default 24)
#   JNA_VERSION       android: the JNA version README.txt names (optional)
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

if want android; then
  : "${ANDROID_NDK_HOME:?set ANDROID_NDK_HOME to the Android NDK}"
  API=${ANDROID_API:-24}
  NDK_REV=$(sed -n 's/^Pkg.Revision *= *//p' "$ANDROID_NDK_HOME/source.properties")
  [ -n "$NDK_REV" ] || { echo "android: no Pkg.Revision in $ANDROID_NDK_HOME/source.properties" >&2; exit 1; }
  if [ -n "${EXPECT_NDK:-}" ] && [ "$NDK_REV" != "$EXPECT_NDK" ]; then
    echo "android: NDK $NDK_REV, expected $EXPECT_NDK" >&2
    exit 1
  fi
  [ "$(uname -s)-$(uname -m)" = Linux-x86_64 ] \
    || { echo "android: packaged on Linux x86_64 only" >&2; exit 1; }
  TC="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin"
  READELF="$TC/llvm-readelf"
  # The Kotlin is generated from the host build, as for the JVM package.
  cargo build -p atem-client-ffi --features bindgen
  PKG="$WORK/atem-client-android"
  mkdir -p "$PKG/kotlin"
  "$TARGET/debug/uniffi-bindgen" generate --no-format --library "$TARGET/debug/libatem_client_ffi.so" \
    --language kotlin --out-dir "$PKG/kotlin"
  # abi, Rust target, NDK clang prefix, ELF class, ELF machine (readelf -h)
  while read -r ABI TRIPLE CLANG CLASS MACHINE; do
    T_UP=$(echo "$TRIPLE" | tr 'a-z-' 'A-Z_')
    T_LO=$(echo "$TRIPLE" | tr '-' '_')
    export "CARGO_TARGET_${T_UP}_LINKER=$TC/${CLANG}${API}-clang"
    export "CC_${T_LO}=$TC/${CLANG}${API}-clang" "AR_${T_LO}=$TC/llvm-ar"
    # Only the cdylib, its LOAD segments 16 KB aligned (Google Play requires
    # it for 64-bit libraries; it also loads on 4 KB devices).
    cargo rustc -p atem-client-ffi --lib --release --target "$TRIPLE" --crate-type cdylib \
      -- -C link-arg=-Wl,-z,max-page-size=16384
    SO="$TARGET/$TRIPLE/release/libatem_client_ffi.so"
    HDR=$("$READELF" -hW "$SO")
    echo "$HDR" | grep -Eq "^ *Class: +$CLASS\$" \
      || { echo "android $ABI: not $CLASS" >&2; echo "$HDR" >&2; exit 1; }
    echo "$HDR" | grep -Eq "^ *Machine: +$MACHINE\$" \
      || { echo "android $ABI: not $MACHINE" >&2; echo "$HDR" >&2; exit 1; }
    ALIGNS=$("$READELF" -lW "$SO" | awk '$1 == "LOAD" {print $NF}' | sort -u)
    [ "$ALIGNS" = 0x4000 ] \
      || { echo "android $ABI: LOAD alignment '$ALIGNS', need 0x4000 (16 KB)" >&2; exit 1; }
    mkdir -p "$PKG/jniLibs/$ABI"
    cp "$SO" "$PKG/jniLibs/$ABI/"
  done <<'ABIS'
arm64-v8a aarch64-linux-android aarch64-linux-android ELF64 AArch64
armeabi-v7a armv7-linux-androideabi armv7a-linux-androideabi ELF32 ARM
x86_64 x86_64-linux-android x86_64-linux-android ELF64 Advanced.Micro.Devices.X86-64
ABIS
  cat >"$PKG/README.txt" <<README
atem-client ${VERSION} for Android (the atem-session r9 client core).
jniLibs/  libatem_client_ffi.so for arm64-v8a, armeabi-v7a and x86_64
          (minSdk ${API}, LOAD segments 16 KB aligned): src/main/jniLibs/.
kotlin/   the UniFFI Kotlin bindings (package uniffi.atem_client_ffi), added
          to the app's sources. They load the library through JNA:
          implementation("net.java.dev.jna:jna:${JNA_VERSION:-<version>}@aar")
Check this archive against atem-client-${VERSION}-SHA256SUMS.txt and the
source pin atem-client-${VERSION}-SOURCE.json.
README
  # Deterministic zip: sorted entries, one fixed time, no extra attributes.
  (cd "$WORK" && find atem-client-android -type f | LC_ALL=C sort >"$WORK/android-entries" \
    && TZ=UTC touch -d '1980-01-01 00:00:00' $(cat "$WORK/android-entries") \
    && rm -f "$OUT/atem-client-${VERSION}-android.zip" \
    && TZ=UTC zip -q -X -D "$OUT/atem-client-${VERSION}-android.zip" -@ <"$WORK/android-entries")
  FILES+=("atem-client-${VERSION}-android.zip")
  TOOLS+=("android-ndk=$NDK_REV")
  FEATURES+=("android: default (uniffi), cdylib, minSdk $API, -z max-page-size=16384")
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
