#!/usr/bin/env bash
# Fetch the upstream Conversational-AI-Demo toolkit, compile to a single
# browser bundle, and write to assets/convo/. Idempotent.
#
# Usage:
#   ./scripts/update-convoai-toolkit.sh           # rebuild from the pinned SHA
#   ./scripts/update-convoai-toolkit.sh <commit>  # build from another commit
#
# The source is pinned: upstream moved the in-repo toolkit to the published
# npm package `agora-agent-client-toolkit` in commit 8b41d4b ("adopt published
# agent toolkits for 2.3.1"), so its main branch no longer has this source.
# PINNED_SHA is the last commit we vendor from; the release check rebuilds it
# and fails if assets/convo/ doesn't match. Moving to the npm package is a
# separate migration.
#
# Requires: git + npx (esbuild pulled transitively).
set -euo pipefail

REPO="https://github.com/AgoraIO-Community/Conversational-AI-Demo.git"
SUBDIR="Web/Scenes/VoiceAgent/src/conversational-ai-api"
PINNED_SHA="761875f240ce08f418293d22331229c6f975240a"
REF="${1:-$PINNED_SHA}"
OUT_DIR="assets/convo"
OUT_FILE="$OUT_DIR/conversational-ai-api.js"
VERSION_FILE="$OUT_DIR/VERSION"

mkdir -p "$OUT_DIR"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# Blobless clone: full history (so any commit can be checked out) without
# downloading every file version.
git clone --quiet --filter=blob:none "$REPO" "$TMP"
git -C "$TMP" checkout --quiet "$REF" || { echo "Cannot check out $REF in $REPO"; exit 1; }
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
