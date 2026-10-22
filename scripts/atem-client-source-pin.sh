#!/usr/bin/env bash
# Usage: scripts/atem-client-source-pin.sh <out.json> <artifact kind> <features> [tool=version ...]
#
# The source pin of a packaged atem-client binding: the commit it was built
# from (and whether the tree had changes), the crate versions (atem-client,
# atem-client-ffi, and uniffi / wasm-bindgen from Cargo.lock), the cargo
# features of the shipped build, and the toolchain versions (rustc, cargo,
# plus the tools the caller names, e.g. wasm-bindgen-cli=0.2.101).
# No secrets, no paths of the build machine.
set -euo pipefail
OUT="$1"
KIND="$2"
FEATURES="$3"
shift 3
cd "$(dirname "$0")/.."
COMMIT=$(git rev-parse HEAD)
DIRTY=false
[ -n "$(git status --porcelain --untracked-files=no)" ] && DIRTY=true
RUSTC=$(rustc -V)
CARGO=$(cargo -V)
cargo metadata --format-version 1 --no-deps >"$OUT.metadata"
python3 - "$OUT" "$KIND" "$FEATURES" "$COMMIT" "$DIRTY" "$RUSTC" "$CARGO" "$@" <<'EOF'
import json, sys
out, kind, features, commit, dirty, rustc, cargo = sys.argv[1:8]
tools = sys.argv[8:]
meta = json.load(open(out + ".metadata"))
crates = {p["name"]: p["version"] for p in meta["packages"]
          if p["name"] in ("atem-client", "atem-client-ffi")}
lock = open("Cargo.lock").read().split("[[package]]")
for block in lock:
    fields = dict(
        line.split(" = ", 1) for line in block.strip().splitlines() if " = " in line
    )
    name = fields.get("name", "").strip('"')
    if name in ("uniffi", "wasm-bindgen"):
        crates[name] = fields["version"].strip('"')
toolchain = {"rustc": rustc, "cargo": cargo}
for t in tools:
    k, v = t.split("=", 1)
    toolchain[k] = v
pin = {
    "artifact": kind,
    "commit": commit,
    "tree_dirty": dirty == "true",
    "crates": dict(sorted(crates.items())),
    "features": features,
    "toolchain": toolchain,
}
with open(out, "w") as f:
    json.dump(pin, f, indent=2, sort_keys=True)
    f.write("\n")
EOF
rm -f "$OUT.metadata"
