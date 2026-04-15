#!/usr/bin/env bash
# Fetch the upstream Conversational-AI-Demo toolkit, compile to a single
# browser bundle, and write to assets/convo/. Idempotent.
#
# Usage:
#   ./scripts/update-convoai-toolkit.sh           # fetch main @ HEAD
#   ./scripts/update-convoai-toolkit.sh <commit>  # pin a specific SHA
#
# Requires: git + npx (esbuild pulled transitively).
set -euo pipefail

REPO="https://github.com/AgoraIO-Community/Conversational-AI-Demo.git"
SUBDIR="Web/Scenes/VoiceAgent/src/conversational-ai-api"
REF="${1:-main}"
OUT_DIR="assets/convo"
OUT_FILE="$OUT_DIR/conversational-ai-api.js"
VERSION_FILE="$OUT_DIR/VERSION"

mkdir -p "$OUT_DIR"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

git clone --depth 50 "$REPO" "$TMP"
git -C "$TMP" checkout "$REF" 2>/dev/null || true
SHA="$(git -C "$TMP" rev-parse HEAD)"
SRC="$TMP/$SUBDIR"
[[ -d "$SRC" ]] || { echo "Source dir missing: $SRC"; exit 1; }

# Find the entry point — typical locations.
ENTRY=""
for candidate in "$SRC/index.ts" "$SRC/index.tsx" "$SRC/api.ts"; do
    if [[ -f "$candidate" ]]; then ENTRY="$candidate"; break; fi
done
[[ -n "$ENTRY" ]] || { echo "No entry file found under $SRC"; ls -la "$SRC"; exit 1; }

# Install upstream deps so transitive @/* path-alias imports resolve.
npm install --prefix "$TMP/Web/Scenes/VoiceAgent" --legacy-peer-deps --silent

npx --yes esbuild "$ENTRY" \
    --bundle --format=iife --global-name=ConversationalAIAPI \
    --target=es2020 --minify \
    --alias:@="$TMP/Web/Scenes/VoiceAgent/src" \
    --external:agora-rtc-sdk-ng \
    --outfile="$OUT_FILE"

{
    echo "upstream: $REPO"
    echo "ref:      $REF"
    echo "sha:      $SHA"
    echo "entry:    ${ENTRY#$TMP/}"
    echo "built:    $(date -u +%Y-%m-%dT%H:%M:%SZ)"
} > "$VERSION_FILE"

echo "Wrote $OUT_FILE ($(wc -c < "$OUT_FILE") bytes) from $SHA"
