#!/usr/bin/env bash
# Usage: scripts/package-atem-r9-harness.sh <version> <output-dir>
#
# NON-PRODUCTION TEST TOOLING. Packages the headless r9 multi-device
# harness (tests/r9_harness.rs) for Astation, who can't build Atem from
# source: the prebuilt test binary, the atem binary it drives and the fake
# Claude Code it launches, with a run script, so `run-harness.sh` works on a
# Linux x86_64 machine with python3 and nothing else from this repository.
#
#   atem-r9-harness-NONPRODUCTION-<version>-linux-x86_64.tar.gz
#     atem-r9-harness-NONPRODUCTION/
#       bin/r9_harness     the harness (a Rust test binary, release build)
#       bin/atem           the atem it runs as the host (release build of the
#                          same commit; for this harness only, never install it)
#       fake-agent.py      the fake Claude Code (python3)
#       run-harness.sh     runs it (ATEM_HARNESS_PHONES/BOTS/BROWSERS,
#                          ATEM_HARNESS_OUT are passed through)
#       README.txt
#   atem-r9-harness-NONPRODUCTION-<version>-sample-transcript.jsonl
#     a run of the packaged harness, unpacked into an empty directory the
#     way a consumer runs it (default counts: 2 phones, 1 bot, 1 browser)
#   atem-r9-harness-NONPRODUCTION-<version>-SOURCE.json
#   atem-r9-harness-NONPRODUCTION-<version>-SHA256SUMS.txt
#
# The flow is fixed and the routing is fake: the harness's own fake
# Astation plays the router and the relay. Linux x86_64 only: the
# harness's sandbox finds and cleans up its processes through /proc (on
# macOS the test target compiles to nothing). Needs GNU tar, coreutils.
set -euo pipefail
VERSION="$1"
OUT="$2"
cd "$(dirname "$0")/.."
ROOT=$(pwd)
[ "$(uname -s)-$(uname -m)" = Linux-x86_64 ] || { echo "the r9 harness is packaged on Linux x86_64 only" >&2; exit 1; }
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
NAME="atem-r9-harness-NONPRODUCTION"
PREFIX="${NAME}-${VERSION}"

# The test binary and the atem binary of the same release build.
cargo build --release --bin atem
HARNESS=$(cargo test --release --test r9_harness --no-run --message-format=json \
  | python3 -c 'import json,sys
for line in sys.stdin:
    m = json.loads(line)
    if m.get("reason") == "compiler-artifact" and m["target"]["name"] == "r9_harness" and m.get("executable"):
        print(m["executable"])')
[ -x "$HARNESS" ] || { echo "no r9_harness test binary" >&2; exit 1; }
TARGET=${CARGO_TARGET_DIR:-$ROOT/target}

PKG="$WORK/$NAME"
mkdir -p "$PKG/bin"
cp "$HARNESS" "$PKG/bin/r9_harness"
cp "$TARGET/release/atem" "$PKG/bin/atem"
cp tests/fixtures/approvals/fake-agent.py "$PKG/fake-agent.py"
chmod 0755 "$PKG/bin/r9_harness" "$PKG/bin/atem" "$PKG/fake-agent.py"
cat >"$PKG/run-harness.sh" <<'RUN'
#!/usr/bin/env bash
# NON-PRODUCTION TEST TOOLING: runs the headless r9 multi-device harness
# against the packaged atem (a temp profile under /tmp; nothing of the
# user's profile, runtime or cred agent is touched).
#   ATEM_HARNESS_PHONES (default 2), ATEM_HARNESS_BOTS (1),
#   ATEM_HARNESS_BROWSERS (1), ATEM_HARNESS_OUT=<file> (JSON lines).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
export ATEM_HARNESS_ATEM_BIN="$HERE/bin/atem"
export ATEM_HARNESS_FAKE_AGENT="$HERE/fake-agent.py"
exec "$HERE/bin/r9_harness" --exact harness --nocapture --test-threads=1 "$@"
RUN
chmod 0755 "$PKG/run-harness.sh"
cat >"$PKG/README.txt" <<README
atem r9 harness ${VERSION} -- NON-PRODUCTION TEST TOOLING.

Not a release of Atem: bin/atem is a build of the commit named in
${PREFIX}-SOURCE.json for this harness only. Do not install it or use it
with a real profile.

What it does: one real \`atem runtime\` host on a temp profile (a verified
pairing and a pinned device list signed with deterministic test keys, a
fake Claude Code session) and N simulated r9 clients (phones, bots,
browsers) that are the shared core atem-client, carried in the channel
envelope (atem-session-v1.md §R9.7a) on the runtime's link to a fake
Astation that also plays the relay. It walks them through admission, the
registry, a lease, a prompt to its turn's end, an approval with sealed push
hints verified and opened per device, a seen and a lease-free answer, and
prints a transcript.

Run (Linux x86_64, python3 on /usr/bin):
  ./run-harness.sh
  ATEM_HARNESS_PHONES=3 ATEM_HARNESS_BOTS=2 ATEM_HARNESS_BROWSERS=2 \\
    ATEM_HARNESS_OUT=transcript.jsonl ./run-harness.sh

Limits: a fixed flow; fake routing (no entry point for Astation's router
or relay yet); the fake Claude Code only; Linux x86_64 only (the sandbox
cleans up through /proc). See designs/protocol/atem-host-handoff.md.
README

tar --sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner -C "$WORK" -cf - "$NAME" \
  | gzip -n -9 >"$OUT/${PREFIX}-linux-x86_64.tar.gz"
FILES=("${PREFIX}-linux-x86_64.tar.gz")

# The sample transcript: the archive unpacked into an empty directory and
# run the way a consumer runs it.
RUNDIR="$WORK/consumer"
mkdir -p "$RUNDIR"
tar xzf "$OUT/${PREFIX}-linux-x86_64.tar.gz" -C "$RUNDIR"
(cd "$RUNDIR" && ATEM_HARNESS_OUT="$OUT/${PREFIX}-sample-transcript.jsonl" \
  "$RUNDIR/$NAME/run-harness.sh" >"$WORK/run.log" 2>&1) \
  || { cat "$WORK/run.log" >&2; echo "the packaged harness failed" >&2; exit 1; }
grep -q 'test result: ok. 1 passed' "$WORK/run.log" \
  || { cat "$WORK/run.log" >&2; echo "the packaged harness didn't pass" >&2; exit 1; }
test -s "$OUT/${PREFIX}-sample-transcript.jsonl"
python3 -c 'import json,sys; [json.loads(l) for l in open(sys.argv[1])]' "$OUT/${PREFIX}-sample-transcript.jsonl"
FILES+=("${PREFIX}-sample-transcript.jsonl")

PIN="${PREFIX}-SOURCE.json"
./scripts/atem-client-source-pin.sh "$OUT/$PIN" "r9-harness (non-production)" \
  "r9_harness test binary and atem, release profile, default features" \
  "python3=$(python3 -V 2>&1 | awk '{print $2}')"
FILES+=("$PIN")
SUMS="${PREFIX}-SHA256SUMS.txt"
(cd "$OUT" && sha256sum "${FILES[@]}" >"$SUMS")
echo "Packaged into $OUT:"
(cd "$OUT" && ls -l "${FILES[@]}" "$SUMS")
