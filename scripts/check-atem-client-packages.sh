#!/usr/bin/env bash
# Usage: scripts/check-atem-client-packages.sh <version> <dir>
#
# Checks what scripts/package-atem-client-bindings.sh put in <dir>, the way
# Astation should after downloading it (designs/protocol/atem-client-bindings.md
# §7): the SHA-256 sums, the source pin, the shared host-work vectors listed in
# the sums (requests, prompt framing, framing size), no test-only or host-role
# export in the shipped bindings (the framing's vectors-only rendering
# included), and each package used once: the Node build of the WASM package
# runs the packaged framing vectors (escaping, Unicode version, the preflight
# size check) and, with the JVM jar (through JNA), reads the r9 pairing
# vectors' verifyCommit messages with the shared parser. The Android zip:
# each ABI's ELF class, machine, 16 KB LOAD alignment and exports (READELF,
# default readelf).
#   EXPECT_COMMIT  the full SHA the packages must pin (with a clean tree)
#   NODE  node (default: node on PATH)
#   JAVA, JAVAC  java and javac (default: on PATH), and JNA_JAR: the jar check
set -euo pipefail
VERSION="$1"
DIR="$(cd "$2" && pwd)"
cd "$(dirname "$0")/.."
ROOT=$(pwd)
NODE=${NODE:-node}
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
VECTORS="$ROOT/designs/protocol/fixtures/r9-vectors-pairing.json"

(cd "$DIR" && sha256sum -c "atem-client-${VERSION}-SHA256SUMS.txt")
# The shared host-work and r9 vectors ship beside the packages, each listed in
# the sums (sha256sum -c above checked what is listed, not that it is listed)
# and the same bytes as the repository's.
for vector in \
  host-work/requests-v1.json:host-work-requests-v1.json \
  host-work/prompt-framing-v1.json:host-work-prompt-framing-v1.json \
  host-work/framing-size-v1.json:host-work-framing-size-v1.json \
  r9-vectors-host-work-control.json:r9-vectors-host-work-control.json \
  r9-vectors-host-envelope.json:r9-vectors-host-envelope.json; do
  source="$ROOT/designs/protocol/fixtures/${vector%%:*}"
  shipped="atem-client-${VERSION}-${vector#*:}"
  test -s "$DIR/$shipped" || { echo "$shipped: missing from the package directory" >&2; exit 1; }
  awk -v f="$shipped" '$2 == f {found = 1} END {exit !found}' "$DIR/atem-client-${VERSION}-SHA256SUMS.txt" \
    || { echo "$shipped: not listed in the sums" >&2; exit 1; }
  cmp -s "$source" "$DIR/$shipped" ||
    { echo "vectors: $shipped differs from ${vector%%:*}" >&2; exit 1; }
done
echo "vectors: 5 files shipped, listed and unchanged"
FRAMING_VECTORS="$DIR/atem-client-${VERSION}-host-work-prompt-framing-v1.json"
FRAMING_SIZE_VECTORS="$DIR/atem-client-${VERSION}-host-work-framing-size-v1.json"
python3 - "$DIR/atem-client-${VERSION}-SOURCE.json" "${EXPECT_COMMIT:-}" <<'EOF'
import json, re, sys
pin = json.load(open(sys.argv[1]))
assert re.fullmatch(r"[0-9a-f]{40}", pin["commit"]), pin
expect = sys.argv[2]
if expect:
    # The build you asked for: that exact commit, from a clean tree.
    assert pin["commit"] == expect, ("pin names", pin["commit"], "expected", expect)
    assert pin["tree_dirty"] is False, pin
for crate in ("atem-client", "atem-client-ffi", "uniffi", "wasm-bindgen"):
    assert pin["crates"].get(crate), (crate, pin)
assert pin["toolchain"].get("rustc"), pin
print("source pin:", pin["commit"], "dirty" if pin["tree_dirty"] else "clean")
EOF
# No test-only or host-role export ships.
FORBIDDEN='SoftwareKeyStore|signSeen|sign_seen|admitCarrier|admit_carrier|AdmissionInfo|framingRenderForVectors|framing_render_for_vectors|sealEnvelope|seal_envelope|openEnvelope|open_envelope|sealResult|seal_result|acceptResult|accept_result|MailFieldsData'

WASM="$DIR/atem-client-${VERSION}-wasm.tar.gz"
if [ -f "$WASM" ]; then
  tar xzf "$WASM" -C "$WORK"
  if grep -RqE "$FORBIDDEN" "$WORK/atem-client-wasm"; then
    echo "wasm: a test-only or host-role export is in the package" >&2
    exit 1
  fi
  "$NODE" -e '
    const ffi = require(process.argv[1]);
    const v = require(process.argv[2]).verify_commit;
    for (const c of v.valid) {
      const got = ffi.verifyCommitHostTrustGen(c.raw);
      if (got !== c.host_trust_gen) throw new Error(`${c.case}: ${got}`);
    }
    for (const c of v.invalid) {
      let threw = false;
      try { ffi.verifyCommitHostTrustGen(c.raw); } catch (e) { threw = true; }
      if (!threw) throw new Error(`${c.case}: accepted`);
    }
    console.log(`wasm (nodejs): ${v.valid.length + v.invalid.length} verifyCommit vectors`);
  ' "$WORK/atem-client-wasm/nodejs/atem_client_ffi.js" "$VECTORS"
  # The packaged framing exports against the packaged vectors: the escaping,
  # the pinned Unicode version and every size case with its complete inputs.
  # Rendering is vectors-only: a shipped build must not have it.
  "$NODE" -e '
    const ffi = require(process.argv[1]);
    const framing = require(process.argv[2]);
    const sizes = require(process.argv[3]);
    if (ffi.framingRenderForVectors !== undefined) throw new Error("framingRenderForVectors is exported");
    if (ffi.framingUnicodeVersion() !== framing.unicode_version) throw new Error("Unicode version");
    if (framing.escape.length < 1 || sizes.cases.length < 1) throw new Error("no framing vectors");
    for (const c of framing.escape) {
      const r = ffi.framingEscape(c.text);
      if (r.escaped !== c.escaped || r.barsAdded !== c.bars_added) throw new Error(`escape: ${c.name}`);
    }
    for (const c of sizes.cases) {
      const mark = c.mark === undefined ? undefined : JSON.stringify(c.mark);
      const got = ffi.framingCheckedLen(c.text, mark, JSON.stringify(c.context));
      if (got !== c.checked_len) throw new Error(`size: ${c.name}: ${got}`);
    }
    console.log(`wasm (nodejs): ${framing.escape.length} framing escape and ${sizes.cases.length} size vectors`);
  ' "$WORK/atem-client-wasm/nodejs/atem_client_ffi.js" "$FRAMING_VECTORS" "$FRAMING_SIZE_VECTORS"
  for t in web bundler; do
    test -s "$WORK/atem-client-wasm/$t/atem_client_ffi_bg.wasm"
    test -s "$WORK/atem-client-wasm/$t/atem_client_ffi.d.ts"
  done
fi

for KOTLIN in "$DIR"/atem-client-"${VERSION}"-kotlin-jvm-*.tar.gz; do
  [ -f "$KOTLIN" ] || continue
  mkdir -p "$WORK/k"
  tar xzf "$KOTLIN" -C "$WORK/k"
  PKG="$WORK/k/atem-client-kotlin-jvm"
  if grep -RqE "$FORBIDDEN" "$PKG/src"; then
    echo "kotlin: a test-only or host-role export is in the package" >&2
    exit 1
  fi
  JAR="$PKG/atem-client-ffi-${VERSION}.jar"
  if [ -f "$JAR" ] && [ -n "${JNA_JAR:-}" ]; then
    mkdir -p "$WORK/java"
    cat >"$WORK/java/Smoke.java" <<'EOF'
import java.nio.file.*;
public class Smoke {
  public static void main(String[] a) throws Exception {
    String text = new String(Files.readAllBytes(Paths.get(a[0])));
    // The two valid cases' raw messages and values (no JSON library).
    String[] raws = {
      "{\"type\":\"verifyCommit\",\"data\":{\"device_id\":\"host-a\",\"commitment\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\",\"host_trust_gen\":3}}",
      "{\"type\":\"verifyCommit\",\"data\":{\"device_id\":\"host-a\",\"commitment\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\",\"host_trust_gen\":9007199254740991}}"
    };
    long[] want = {3L, 9007199254740991L};
    for (int i = 0; i < raws.length; i++) {
      if (!text.contains(raws[i].replace("\"", "\\\""))) throw new Exception("not a vector: " + i);
      // ULong is a Kotlin inline class: on the JVM it is a long.
      java.lang.reflect.Method m = null;
      for (java.lang.reflect.Method c :
           Class.forName("uniffi.atem_client_ffi.Atem_client_ffiKt").getMethods()) {
        if (c.getName().startsWith("verifyCommitHostTrustGen")) m = c;
      }
      long got = (long) m.invoke(null, raws[i]);
      if (got != want[i]) throw new Exception("case " + i + ": " + got);
    }
    System.out.println("kotlin (jvm jar via JNA): 2 verifyCommit vectors");
  }
}
EOF
    "${JAVAC:-javac}" -d "$WORK/java" "$WORK/java/Smoke.java"
    STDLIB=""
    [ -n "${KOTLIN_STDLIB:-}" ] && STDLIB=":$KOTLIN_STDLIB"
    "${JAVA:-java}" -cp "$WORK/java:$JAR:$JNA_JAR$STDLIB" Smoke "$VECTORS"
  fi
done
ANDROID="$DIR/atem-client-${VERSION}-android.zip"
if [ -f "$ANDROID" ]; then
  mkdir -p "$WORK/a"
  unzip -q "$ANDROID" -d "$WORK/a"
  PKG="$WORK/a/atem-client-android"
  if grep -RqE "$FORBIDDEN" "$PKG/kotlin"; then
    echo "android: a test-only or host-role export is in the package" >&2
    exit 1
  fi
  READELF=${READELF:-readelf}
  for spec in "arm64-v8a ELF64 AArch64" "armeabi-v7a ELF32 ARM" \
    "x86_64 ELF64 Advanced.Micro.Devices.X86-64"; do
    read -r ABI CLASS MACHINE <<<"$spec"
    SO="$PKG/jniLibs/$ABI/libatem_client_ffi.so"
    test -s "$SO" || { echo "android: no $ABI library" >&2; exit 1; }
    # readelf's output is captured whole before any grep: a `grep -q` in a
    # pipe exits at its first match, readelf then dies of SIGPIPE and, under
    # pipefail, the match would read as a failure (and the check fail open).
    HDR=$("$READELF" -hW "$SO")
    grep -Eq "^ *Class: +$CLASS\$" <<<"$HDR" || { echo "android $ABI: not $CLASS" >&2; exit 1; }
    grep -Eq "^ *Machine: +$MACHINE\$" <<<"$HDR" || { echo "android $ABI: not $MACHINE" >&2; exit 1; }
    PHDRS=$("$READELF" -lW "$SO")
    ALIGNS=$(awk '$1 == "LOAD" {print $NF}' <<<"$PHDRS" | sort -u)
    [ "$ALIGNS" = 0x4000 ] || { echo "android $ABI: LOAD alignment '$ALIGNS', need 0x4000" >&2; exit 1; }
    SYMS=$("$READELF" --dyn-syms -W "$SO")
    [ -n "$SYMS" ] || { echo "android $ABI: no dynamic symbols read" >&2; exit 1; }
    if grep -qiE 'sign_seen|admit_carrier|software_?key|framing_render_for_vectors|seal_envelope|open_envelope|seal_result|accept_result' <<<"$SYMS"; then
      echo "android $ABI: a test-only or host-role symbol is exported" >&2
      exit 1
    fi
    grep -q 'uniffi_atem_client_ffi_fn_func_verify_commit_host_trust_gen' <<<"$SYMS" \
      || { echo "android $ABI: the UniFFI exports are missing" >&2; exit 1; }
    echo "android $ABI: $CLASS $MACHINE, LOAD aligned 16 KB"
  done
fi

echo "atem-client packages ${VERSION}: ok"
