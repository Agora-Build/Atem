#!/usr/bin/env bash
# Verify the downloaded production Apple package, then call its selected-
# Station helpers through Swift using the packaged independent vectors.
# Usage: EXPECT_COMMIT=<sha> scripts/check-atem-client-apple.sh <version> <dir>
set -euo pipefail
VERSION="$1"
OUT="$(cd "$2" && pwd)"
: "${EXPECT_COMMIT:?set EXPECT_COMMIT to the immutable source commit}"
[ "$(uname -s)" = Darwin ] || { echo "the Apple package check requires macOS" >&2; exit 1; }
cd "$(dirname "$0")/.."
ROOT=$(pwd)
PREFIX="atem-client-${VERSION}"
(cd "$OUT" && shasum -a 256 -c "${PREFIX}-SHA256SUMS.txt")
python3 - "$OUT/${PREFIX}-SOURCE.json" "$EXPECT_COMMIT" <<'PY'
import json, sys
p = json.load(open(sys.argv[1]))
assert p['commit'] == sys.argv[2] and p['tree_dirty'] is False, p
assert p['artifact'] == 'apple-swiftpm' and p['features'] == 'default (uniffi)', p
PY
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
unzip -q "$OUT/${PREFIX}-apple-swiftpm.zip" -d "$WORK"
SWIFT="$WORK/AtemClient/Sources/AtemClient/atem_client_ffi.swift"
grep -q 'public func stationRouteOffer' "$SWIFT"
grep -q 'public func stationRouteVerifyAccepted' "$SWIFT"
if grep -qE 'SoftwareKeyStore|signSeen|admitCarrier|AdmissionInfo|framingRenderForVectors' "$SWIFT"; then
  echo "a test-only or host-role export is in the package" >&2
  exit 1
fi
mkdir -p "$WORK/consumer/Tests/StationRoutePackageTests" "$WORK/fixtures/station-route"
cp "$OUT/${PREFIX}-station-route-v1.json" "$WORK/fixtures/station-route/v1.json"
cp "$ROOT/crates/atem-client-ffi/bindings/swift/Tests/AtemClientTests/StationRouteTests.swift" \
  "$WORK/consumer/Tests/StationRoutePackageTests/"
cat >"$WORK/consumer/Package.swift" <<'SWIFT'
// swift-tools-version:5.9
import PackageDescription
let package = Package(
    name: "StationRoutePackageCheck",
    platforms: [.macOS(.v14)],
    dependencies: [.package(name: "AtemClient", path: "../AtemClient")],
    targets: [.testTarget(name: "StationRoutePackageTests",
        dependencies: [.product(name: "AtemClient", package: "AtemClient")])]
)
SWIFT
ATEM_FIXTURES="$WORK/fixtures" swift test --package-path "$WORK/consumer"
