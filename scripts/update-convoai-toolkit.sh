#!/usr/bin/env bash
# Fetch the upstream Conversational-AI-Demo toolkit, compile to a single
# browser bundle, and write to assets/convo/. Idempotent.
#
# Usage:
#   ./scripts/update-convoai-toolkit.sh                         # rebuild from the pinned SHA
#   UPDATE_LOCK=1 ./scripts/update-convoai-toolkit.sh [<commit>] # re-resolve dependencies
#
# The build is reproducible: upstream ships no lockfile, so ours lives in
# scripts/convoai-toolkit/package-lock.json and is installed with `npm ci`,
# and esbuild is pinned. Without that, `npm install` picked up the newest
# dependency releases on every run and the release check failed whenever any
# dependency published, with the source unchanged. Updating dependencies is a
# deliberate step: run with UPDATE_LOCK=1, review the lockfile diff, commit.
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
ESBUILD_VERSION="0.28.2"
LOCKFILE="scripts/convoai-toolkit/package-lock.json"
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

# Install upstream deps (so transitive @/* path-alias imports resolve) from
# our lockfile; UPDATE_LOCK=1 re-resolves them and saves the new lockfile.
APP="$TMP/Web/Scenes/VoiceAgent"
if [[ "${UPDATE_LOCK:-}" == "1" ]]; then
    npm install --prefix "$APP" --legacy-peer-deps --silent
    mkdir -p "$(dirname "$LOCKFILE")"
    cp "$APP/package-lock.json" "$LOCKFILE"
    echo "Updated $LOCKFILE: review its diff before committing."
else
    [[ -f "$LOCKFILE" ]] || { echo "Missing $LOCKFILE; run with UPDATE_LOCK=1 to create it."; exit 1; }
    cp "$LOCKFILE" "$APP/package-lock.json"
    npm ci --prefix "$APP" --legacy-peer-deps --silent \
        || { echo "$LOCKFILE doesn't match upstream's package.json at $REF; run with UPDATE_LOCK=1."; exit 1; }
fi

npx --yes "esbuild@$ESBUILD_VERSION" "$ENTRY" \
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
