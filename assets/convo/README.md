# ConvoAI Toolkit (vendored)

Pre-compiled browser bundle of the upstream [Conversational-AI-Demo][repo] toolkit.
The page served by `atem serv convo` loads this at `/vendor/conversational-ai-api.js`.

**Do not edit** `conversational-ai-api.js` by hand. To refresh:

```bash
./scripts/update-convoai-toolkit.sh           # fetch main @ HEAD
./scripts/update-convoai-toolkit.sh <commit>  # pin a specific SHA
```

Commit the regenerated `conversational-ai-api.js` and `VERSION`. CI enforces
that the committed bundle matches upstream HEAD at release time.

[repo]: https://github.com/AgoraIO-Community/Conversational-AI-Demo
