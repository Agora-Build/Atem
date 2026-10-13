# ConvoAI Toolkit (vendored)

Pre-compiled browser bundle of the upstream [Conversational-AI-Demo][repo] toolkit.
The page served by `atem serv convo` loads this at `/vendor/conversational-ai-api.js`.

**Do not edit** `conversational-ai-api.js` by hand. To refresh:

```bash
./scripts/update-convoai-toolkit.sh                          # rebuild from the pinned commit (PINNED_SHA)
UPDATE_LOCK=1 ./scripts/update-convoai-toolkit.sh [<commit>] # re-resolve dependencies, then review and commit
```

The build is reproducible: upstream has no lockfile, so atem keeps one in
`scripts/convoai-toolkit/package-lock.json` (installed with `npm ci`), and
esbuild is pinned in the script. Two runs give the same bytes, so the release
check only fails when the pinned source or a committed dependency changes.

Commit the regenerated `conversational-ai-api.js` and `VERSION` (and the lockfile
if it changed). The release check rebuilds from the pinned commit and fails if
the committed bundle differs.

[repo]: https://github.com/AgoraIO-Community/Conversational-AI-Demo
