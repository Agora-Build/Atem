# Build by Talk: get the whole project clear by talking

Talking is the fastest way to get a whole project clear. Build by Talk is a
voice conversation that brings you, the project's knowledge and its coding agents
together: grounded in the project's own context, with tool calls that ask
the coding agents in Atem for more information or hand them work. It replaces the earlier voice-coding
pipeline (`voice-coding-stages.md`, removed).

Status: planned (user, 2026-10-31): it will be built; the build starts later
(not started). Design decisions by the user, 2026-10-17. Its prerequisites
(chat-v1, the Codex adapter, approvals, r9 remote access) are released in
Atem v0.8.0 (2026-10-31).

## Goal

Talk to your project by voice from the phone or the Mac: ask what's going on,
brainstorm, and steer the coding agents ("build function A instead of B",
"draw a diagram of the auth flow"). The voice agent answers simple questions
from the project's context and hands real work to the coding agent running in
Atem.

This is an **Astation** feature. It is not `atem serv convo`, which is a test
page for ConvoAI demos.

## Shape

```
Phone / Mac (Astation)                 Relay                        Coding machine (Atem)
┌────────────────────────┐   ┌───────────────────────────┐   ┌──────────────────────────────┐
│ voice UI               │   │ per-project knowledge     │◄──│ atem agent launch sessions   │
│ ConvoAI session (cloud)│──►│ store (retrieval)         │   │ curate + upload (opt-in)     │
│ tool orchestration     │   └───────────────────────────┘   │                              │
│ read-back, approvals   │──── authenticated link ──────────►│ live state, chat-v1 submit,  │
└────────────────────────┘    (session-v1 / chat-v1)         │ receipts, approvals, artifacts│
                                                             └──────────────────────────────┘
```

- **Astation** (phone/Mac) owns the voice UI, the cloud ConvoAI session
  (ASR/LLM/TTS or an MLLM), the tool calls, read-back confirmation, approval
  taps and announcing completions.
- **The relay** hosts one knowledge store per project with retrieval for the
  voice agent.
- **Atem** is the source: every session started with `atem agent launch` in a
  project feeds that project's knowledge, and Atem serves live state and
  actions over the existing authenticated link.

## Project and scope

- A project is the normalized git remote (the key Atem Memory already uses),
  so sessions of the same repo on different machines share one knowledge
  store.
- **Enabled per project, opt-in.** Nothing is uploaded until the user enables
  voice context for that project. Astation shows what has been uploaded and
  can delete it (all of it, or per item).

## What Atem uploads — only what is necessary

From sessions launched by `atem agent launch` in an enabled project:

- per-turn or per-session summaries (prompt intent, outcome), decisions
- docs the agents created or changed under allowlisted paths (e.g. `designs/`,
  `docs/`, plans), as text
- commit messages of the project
- the session's summary (`summary.md`)

Not uploaded: raw tool output, full transcripts, terminal recordings, source
files outside the allowlist, environment, credentials. Everything passes the
credential redactor (as chat output does) before upload; anything the
redactor flags is dropped, not masked and sent.

Uploads are incremental with an offline queue (like Atem Memory's), keyed by
project; deleting the project's voice context on Astation removes it from the
relay and stops uploads until re-enabled.

## Encryption boundary

- The **knowledge store is readable by the relay and the voice LLM**, which
  must read the text to retrieve and answer. That is why it is opt-in per
  project and limited to the curated content above.
- **Memory, vault and credentials stay end-to-end encrypted** and are never
  part of the knowledge store.

## Live state and actions — tools, not RAG

RAG answers "what did we decide / what has been done". Anything about *now*
or anything that changes code goes through Astation → Atem over the
authenticated link, with the existing protocol:

| Voice intent | Path |
|---|---|
| "What's Claude doing?" | session-v1 registry: activity, pending approvals |
| "What did it just say?" | chat-v1 history of the session |
| "Build A instead of B" | read-back confirmation, then a chat-v1 `submit` (lease, receipt; never resent); the reply and `complete` are announced when they arrive |
| "Draw a diagram of …" | an ask to the coding agent; the result is shown in Astation (artifact read) |
| Approvals | stay taps on the card or notification; not by voice |

Coding turns take minutes: the voice agent never blocks on them. It says
"I've asked Claude" and announces the completion later from the chat events.

## Work split

- **Astation:** voice UI (push-to-talk/continuous), ConvoAI session, tool
  definitions and orchestration, read-back, completion announcements, the
  per-project enable/inspect/delete UI.
- **Relay:** per-project knowledge store, retrieval API for the voice agent
  (scoped to the account and project), deletion.
- **Atem:** per-project opt-in state, collection and curation from launched
  sessions, redaction and allowlist, incremental upload with queue; an
  `artifact` read for generated files. Live state, history, submit, receipts
  and approvals already exist.

## Open questions

- Retrieval: relay-hosted service called by the voice agent as a tool, or a
  custom-LLM endpoint that adds retrieved context — or ConvoAI's own knowledge
  base if it has one that fits.
- Summaries: generated by Atem (which model, where it runs, cost), or taken
  from the agent's own turn text.
- Default allowlist of doc paths per project, and how the user edits it.
- Which sessions the voice agent may drive: the project's sessions on all
  machines needs account trust (`designs/account-trust.md`) first.
