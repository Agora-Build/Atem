#!/usr/bin/env bash
# Usage: scripts/test-check-atem-client-packages.sh <version> <dir>
#
# Negative tests of scripts/check-atem-client-packages.sh on a built Android
# package in <dir>: the check must pass on it as built, and must fail when
# readelf (a wrapper around the real one) shows
#   - a host-role symbol (`…sign_seen`) early in the dynamic symbol table
#     (early, so a `| grep -q` under pipefail would have failed open),
#   - no `verify_commit_host_trust_gen` export,
#   - a 4 KB LOAD alignment.
#   READELF  the real readelf (default: readelf)
set -euo pipefail
VERSION="$1"
DIR="$(cd "$2" && pwd)"
cd "$(dirname "$0")/.."
REAL=$(command -v "${READELF:-readelf}")
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

wrapper() { # wrapper <name> <filter for --dyn-syms> <filter for -lW>
  cat >"$WORK/$1" <<EOF
#!/usr/bin/env bash
set -euo pipefail
case " \$* " in
  *" --dyn-syms "*) "$REAL" "\$@" | $2 ;;
  *" -lW "*) "$REAL" "\$@" | $3 ;;
  *) exec "$REAL" "\$@" ;;
esac
EOF
  chmod +x "$WORK/$1"
}
# The injected symbol goes right after the table's header (line 4).
wrapper inject "awk 'NR == 4 {print \"    52: 0000000000001000   10 FUNC    GLOBAL DEFAULT   12 uniffi_atem_client_ffi_fn_func_sign_seen\"} {print}'" cat
wrapper drop "grep -v verify_commit_host_trust_gen" cat
wrapper align cat "sed 's/0x4000\$/0x1000/'"

expect() { # expect <ok|fail> <readelf> <message>
  local out status=0
  out=$(READELF="$2" ./scripts/check-atem-client-packages.sh "$VERSION" "$DIR" 2>&1) || status=$?
  if [ "$1" = ok ]; then
    [ "$status" = 0 ] || { echo "$out" >&2; echo "FAIL: the unmodified package was refused" >&2; exit 1; }
  else
    [ "$status" != 0 ] || { echo "$out" >&2; echo "FAIL: accepted although: $3" >&2; exit 1; }
    grep -qF "$3" <<<"$out" || { echo "$out" >&2; echo "FAIL: refused, but not for: $3" >&2; exit 1; }
  fi
  echo "ok: ${3:-as built}"
}
expect ok "$REAL" ""
expect fail "$WORK/inject" "a test-only or host-role symbol is exported"
expect fail "$WORK/drop" "the UniFFI exports are missing"
expect fail "$WORK/align" "need 0x4000"
echo "check-atem-client-packages negative tests: ok"
