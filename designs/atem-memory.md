# Atem Memory — shared memory and skills for AI coding agents

Status: built. MVP: Atem #23, #24; relay Astation #19. Phase 1.1 (**Fact
validity**, **Search**, **Skill history and restore**): relay side (migrations
0004/0005) merged and deployed (Astation PR #22); atem `feat/memory-1.1`.
Spans two repos: **Atem** (CLI, local store, adapters, sync client) and
**Astation** (relay-server `/api/memory`, `/api/skills` + Postgres).

## Goal

Make Atem a portable knowledge layer that works across coding agents and
machines, not a copier of `~/.claude` or `~/.codex`. What one agent learns on
one machine should reach a different agent on another machine:

```
Claude@A ──learns──▶ Atem ──sync──▶ Codex@B ──learns──▶ Atem ──sync──▶ Claude@C
```

It carries two kinds of knowledge:

- **Memory:** short facts, such as "DialF uses TCP 8765".
- **Skills:** Agent Skills directories (`SKILL.md` plus supporting files).

Machines may be anywhere on the Internet. They need no public IP, no SSH or
shared LAN, and no overlap in when they're online. They sync through the
relay-server, and each keeps a local copy so it works offline.

## Non-goals

- **Credential values.** Memory and skills never carry API keys, tokens, or
  passwords. They may **name** a credential and tell the agent to fetch it
  from `atem vault` (see "Credential references"). Credential management is
  a separate feature, to be built on the vault later (see "Relationship to
  vault"). Atem blocks anything that looks like a secret value before it's
  stored (see "Security").
- `atemd` daemon, agent hooks, and an `atem mcp` server: Phase 2.
- Distilling session transcripts with an LLM, and merging or synthesizing
  memories: Phase 3. The MVP only dedupes.
- Editing a memory in place. To change a memory, replace it: the new fact is
  added and the old one is marked invalid (see "Fact validity").
- Syncing settings, MCP config, or hooks: Phase 4.

## Relationship to vault

This work does not modify `atem vault`. Memory reuses the vault's code and
patterns: the pure request-builder client module, the relay handler shape,
Postgres migrations, and the `seq` sync cursor.

In the long run the vault is where credentials are managed, as its own
feature with its own design. The two features stay separate, and they're
connected only by **reference**:

- Memory and skills can say which vault credential to use, and the agent
  fetches the value from the vault when it needs it.
- When Phase 4 syncs settings or MCP definitions, it syncs them **without**
  credential values. Those fields become references that the credential
  feature resolves.

## Scopes

| Scope | Meaning | Example | Injected into |
|---|---|---|---|
| `global` | Useful everywhere | "Run tests before committing" | Global agent files, every machine |
| `project` | One project | "DialF uses TCP 8765" | That project's files, every machine |
| `machine` | One machine | "nixps runs NixOS + Niri" | Global agent files, **that machine only** |

`machine` is keyed by `atem_id` and keeps machine-specific facts from leaking
into other machines' context. Skills use `global` and `project` only.

### Project identity

The project key is the **normalized git `origin` URL**, so two repos that
share a folder name don't collide:

- `git@github.com:Agora-Build/Atem.git` and
  `https://github.com/Agora-Build/Atem` both become
  `github.com/agora-build/atem`.
- Normalization strips the scheme, any `user@`, and `.git`, turns `:` into
  `/`, and lowercases the whole string.

If there's no remote, the key is `local:<git top-level dir name>`. If there's
no git, it's `local:<cwd name>`. `--project <key>` overrides.

The key is lowercased only for **matching**, so clones whose remotes differ
in case (`agora-build/atem` vs `Agora-Build/Atem`) still share one project.
What atem **shows** keeps the remote's own spelling:
`Project: github.com/Agora-Build/Atem` in `memory status`, and the short name
`project:Atem` in `memory list`, `search`, history and `skill list`. A project
other than the one you're in has no remote to read, so it shows its stored
(lowercase) key's last segment.

## Identity & auth

**Astation is the control plane.** Atem Memory works only on machines paired
with, and approved by, your Astation.

- The account is the paired Astation. Every machine paired with the same
  Astation shares memory and skills.
- Pair once per machine with `atem pair`. An unpaired machine can't read,
  write, or sync.
- Pairing bindings are durable and survive relay restarts — they're stored
  in Postgres, not held in memory.
- The verified Astation pushes bindings to the relay (`relaySessions` full
  resync plus `relayBind`/`relayUnbind` as sessions come and go), including
  local-only pairings; removing the session in Astation revokes the binding
  immediately.
- This requires an Astation version with relay identity (a P-256 key
  verified to the relay). Older Astations keep relaying chat and remote
  control but can't grant memory or vault access.
- Login-based accounts are a possible future follow-up.
- atem sends `Authorization: session <session_id>` (the pairing session for
  the configured Astation, from `SessionManager::load()`) plus
  `?id=<instance_id>`. Wire JSON is otherwise unchanged.

## Capture: how agents learn from each other

| Source | Mechanism |
|---|---|
| **Claude** | **Harvest.** Claude Code already saves facts on its own. On `atem sync`, atem reads them into the store |
| **Codex** | **Instruction.** The managed block in Codex's `AGENTS.md` includes one line: *"To save a durable fact for future sessions, run `atem memory add --agent codex "<fact>"`."* A second line tells Codex to run `atem memory replace <id> "<new fact>"` when a saved fact is outdated; the block shows each fact's short id (see "Fact validity"). |
| **Any user** | `atem memory add`, `atem skill add` |

Claude does the learning and Atem moves it around. No LLM is involved in the
MVP.

### Harvesting Claude's memory

- **Where it reads from:** `~/.claude/projects/<encoded>/memory/*.md`,
  skipping the `MEMORY.md` index. `<encoded>` is the project's absolute path
  with non-alphanumeric characters replaced by `-`; for example
  `/home/u/Dev/Agora.Build/Atem` becomes `-home-u-Dev-Agora-Build-Atem`.
  Decoding is ambiguous, so atem computes the encoded path from the current
  repo and never decodes. Harvesting therefore runs for the repo you're in
  when you run `atem sync`.
- **What a file contains:** frontmatter with `name` and `description`, plus a
  type under `metadata.type` or a top-level `type`. The memory's `content` is
  the file body.
- **Scope:** type `user` or `feedback` becomes `global`; `project` or
  `reference` becomes `project` for the current repo.
- **Edits and deletes:** a local `harvest_map` maps
  `origin = <atem_id>:<file path>` to a memory id, a content hash, and a
  status (`synced`, `held_back`, or `excluded`). If the file's content
  changes, atem **replaces** the old memory: it adds the new one and
  invalidates the old one with `superseded_by` pointing at it. If the file
  is deleted, atem **invalidates** its memory. Either way the history is
  kept (see "Fact validity"). A memory is only invalidated this way when
  Claude on this machine created it and no other harvested file links to
  it; otherwise the file is just unlinked. An edit that now looks like a
  credential is held back, and the old memory is invalidated with no
  successor.
- **Held back and excluded:** a file that fails the secret check is
  recorded as `held_back` and isn't synced. A memory the relay refuses is
  also recorded as `held_back`. A purged memory's file is recorded as
  `excluded`, so it isn't harvested again. Either status is cleared, and
  the file checked again, only when its content changes.
- **No echo:** when atem applies memory to Claude on a machine, it skips
  project-scope memories that Claude on that same machine produced. Those
  are already in Claude's native memory for that project, so Claude doesn't
  see them twice; global and machine memories it produced are still written
  to `~/.claude/CLAUDE.md`, because the native memory is per project.
- **On by default,** with a config switch `[memory] harvest_claude = false`
  to turn it off and a `--no-harvest` flag. Every sync prints what it
  harvested.

## Data model

### Server (Postgres, relay-server)

Every insert or tombstone takes a fresh value from a global sequence, and
that value is the sync cursor. This matches the deployed migration
`relay-server/migrations/0002_knowledge.sql`, as changed by `0004_memory_validity.sql` and `0005_skill_purged.sql`. Times are unix seconds.

```sql
CREATE SEQUENCE knowledge_seq;

CREATE TABLE memories (
    id             TEXT PRIMARY KEY,         -- mem_<uuid v4, no dashes>, generated by the client
    account_id     TEXT NOT NULL,
    scope          TEXT NOT NULL,            -- global | project | machine
    project        TEXT NOT NULL DEFAULT '', -- '' unless scope = project
    machine        TEXT NOT NULL DEFAULT '', -- '' unless scope = machine (atem_id)
    content        TEXT NOT NULL,
    content_hash   TEXT NOT NULL,            -- sha256 of normalized content
    confidence     TEXT NOT NULL DEFAULT 'medium',  -- high | medium | low
    source_agent   TEXT NOT NULL,            -- claude | codex | cli
    source_machine TEXT NOT NULL,            -- atem_id
    created_at     BIGINT NOT NULL,
    seq            BIGINT NOT NULL DEFAULT nextval('knowledge_seq'),
    -- added by 0004 (see "Fact validity"); the `deleted` boolean was dropped:
    deleted_at     BIGINT,                   -- tombstone time; NULL = not deleted
    valid_at       BIGINT,                   -- when the fact became true; NULL = created_at
    invalid_at     BIGINT,                   -- when it stopped being true; NULL = still valid
    superseded_by  TEXT                      -- id of the memory that replaced it
);
CREATE INDEX memories_account_seq ON memories (account_id, seq);
CREATE UNIQUE INDEX memories_dedup ON memories
    (account_id, scope, project, machine, content_hash)
    WHERE deleted_at IS NULL AND invalid_at IS NULL;

CREATE TABLE skill_versions (
    account_id     TEXT NOT NULL,
    scope          TEXT NOT NULL,            -- global | project
    project        TEXT NOT NULL DEFAULT '',
    name           TEXT NOT NULL,            -- directory name
    version        BIGINT NOT NULL,          -- 1, 2, 3 …; the latest live version wins
    files          JSONB NOT NULL,           -- {"SKILL.md": "<b64>", "scripts/x.sh": "<b64>"}
    content_hash   TEXT NOT NULL,            -- over sorted (path, bytes)
    source_agent   TEXT NOT NULL,
    source_machine TEXT NOT NULL,
    created_at     BIGINT NOT NULL,
    deleted        BOOLEAN NOT NULL DEFAULT false,  -- a tombstone is a version too
    seq            BIGINT NOT NULL DEFAULT nextval('knowledge_seq'),
    purged         BOOLEAN NOT NULL DEFAULT false,  -- added by 0005: files erased by purge
    PRIMARY KEY (account_id, scope, project, name, version)
);
CREATE INDEX skill_versions_account_seq ON skill_versions (account_id, seq);
```

- `project` and `machine` store `''` instead of NULL so the dedup index
  compares them normally.
- **Deleting a memory clears its text.** The tombstone sets `deleted_at = <now>`,
  blanks `content` and `content_hash`, and takes a new `seq`, so the text
  doesn't stay on the server. Deleted memories keep no history; invalidated
  ones do (see "Fact validity").
- **Memory `content_hash`:** trim, collapse runs of whitespace, lowercase.
  The original `content` is stored unchanged.
- **Skills** are edited, unlike memories. Each push adds a version, and older
  versions are kept so nothing is lost, unless they're purged (see "Removing
  a credential that slipped through"). If two machines push the same skill
  concurrently, the one with the higher `seq` wins. A skill is limited to
  1 MB total.
- **Skills are text-only.** Every file must be UTF-8 text. Files are
  base64-encoded in the JSON, but only so the wire format is uniform; no
  binary file ever reaches it, because the secret check can't scan binary
  and refuses it (see "Security").

### Local (SQLite, each machine)

`~/.config/atem/knowledge.db`, using `rusqlite` like `diagram_server.rs`,
file mode 0600. The file is created with mode 0600 before it's opened, so
there's no window where it's readable by others:

- `memories` and `skills`: mirrors of the server rows (latest skill version
  only). `memories` has the same `deleted_at` and validity columns, plus the
  `memories_fts` search index (see "Search"). Opening an older
  `knowledge.db` migrates it in place (`deleted` → `deleted_at`).
- `replacements`: a local-only record of which memory this machine wrote
  to replace which (see "Two replacements of the same fact").
- `pending_ops`: an outbound queue of `add`/`delete`/`invalidate` memory and
  `push`/`delete`/`purge` skill, applied locally first.
- `sync_state`: the last pulled `seq`, per account (paired Astation id), and
  the last clean sync time.
- `harvest_map`: see above.
- Drift is detected with the hash stored in each skill's `.atem-skill`
  marker.

## Relay API (Astation repo)

| Method & path | Purpose |
|---|---|
| `POST /api/memory/batch` | Push memory ops (`add`, `delete`, `invalidate`). Returns per-op results. |
| `GET /api/memory?since=<seq>&limit=<n>` | Pull memory rows (tombstones and invalidations included, with the validity fields) with `seq > since`. |
| `POST /api/skills/batch` | Push skill ops (`push`, `delete`, `purge`). |
| `GET /api/skills?since=<seq>&limit=<n>` | Pull skill versions with `seq > since`. |
| `GET /api/skills/versions`, `GET /api/skills/version` | Skill history and one old version's files (see "Skill history and restore"). |

Rules:

- **Memory add is idempotent by `id`.** If a live row with the same dedup key
  already exists under another id, the server returns
  `{sent_id, canonical_id}` and the client rewrites its local row. This is how
  two machines that added the same fact offline end up with one memory.
  Within one batch, a later `delete`/`invalidate` that names the
  deduplicated id (as `id` or `superseded_by`) is rewritten to the
  `canonical_id`; atem rewrites its still-queued ops the same way.
- **Skill pushes carry the client's `base_version`.** The server always
  appends the push as the next version. If `base_version` is behind the
  latest version, the response flags `superseded_concurrent: true` and the
  CLI reports it; nothing is dropped.
- **Skill `purge`** erases the files of the chosen versions: `files` becomes
  `{}`, `content_hash` becomes `''`, and each row takes a new `seq` so every
  machine sees the change. Purging the latest version also deletes the skill.
- Every endpoint is limited to the caller's `account_id` and runs the secret
  check again on the server.
- Deleting an unknown or already-deleted memory id returns ok (idempotent),
  so a delete retried after a crash is harmless.

## Adapters

There's no per-agent trait object. `enum Agent { Claude, Codex }` carries
everything that differs between agents as data — `global_memory_file`,
`project_memory_file`, `skills_root` (per scope), and `instructions` (the
credential line for both, plus the Codex capture line for Codex) — and one
shared `apply_memory`/`apply_skills` code path does the discovery, writing,
and safety checks for every agent.

### Memory targets (managed block)

| Memory | Claude | Codex |
|---|---|---|
| `global` + this machine's `machine` | `~/.claude/CLAUDE.md` | `~/.codex/AGENTS.md` |
| `project` (current repo) | `<repo>/CLAUDE.local.md` | `<repo>/AGENTS.md`, only if not tracked by git |

```markdown
<!-- atem:memory:begin (managed by atem — edits here are overwritten) -->
- DialF advertises _dialfd._tcp and listens on TCP 8765.
- DialF's OpenAI key is the vault credential `dialf/openai`.

Credentials are never stored in memory. When you need one, fetch it with
`atem vault get <name>` at the moment you use it. Never paste a credential
value into memory, skills, or instruction files.
<!-- atem:memory:end -->
```

Every block ends with this standing instruction for Claude and Codex, so a
credential named in memory is always fetched from the vault, never copied.

- Nothing outside the markers is ever changed. If the markers are missing,
  the block is appended. If the file doesn't exist, it's created.
- **Marker integrity:** if the file has a begin marker without an end marker,
  duplicate markers, or a marker nested inside another, atem refuses to
  write that file and reports it. If the reserved `atem:memory:` token
  appears in memory content, the content is rejected.
- Applying the same set twice produces identical output, and the file isn't
  rewritten when nothing changed.
- **Size cap:** at most 50 entries and 4 KB of entries per block (the
  markers, instruction lines and the "N more facts" line are not counted).
  Sort by confidence, then newest first. Only valid facts are written. When
  facts are left out, the block's last line says how many and points the
  agent to `atem memory search "<query>"` (see "Search").
- For Codex, each entry starts with the fact's short id (the first 8
  characters after `mem_`, e.g. `- [1a2b3c4d] DialF uses TCP 8765`), and
  the block also includes the capture and replace instruction lines
  described earlier, placed just before the credential instruction.

### Skill targets

| Skill scope | Claude | Codex |
|---|---|---|
| `global` | `~/.claude/skills/<name>/` | `~/.agents/skills/<name>/` |
| `project` | `<repo>/.claude/skills/<name>/` | `<repo>/.agents/skills/<name>/` |

- Every directory atem writes gets a `.atem-skill` marker file (name,
  version, hash). atem **never overwrites a skill directory it didn't
  create.** A name clash with an unmanaged skill is reported as skipped.
- **Drift:** if a managed skill on disk no longer matches the hash atem
  last wrote there, someone edited it locally. atem won't overwrite it. The
  report says so and suggests `atem skill add <dir>` to push the edit.
- Skills are written atomically: files go into a sibling temp directory,
  then swap in with a rename-aside. The 1 MB cap applies on write as well
  as on read.

### Rules for writing into repos

- **Never write into a file tracked by git.** Project `CLAUDE.md` and
  `AGENTS.md` are often committed, and this repo commits `CLAUDE.md`. Before
  every write into a repo, atem runs `git ls-files --error-unmatch` and skips
  tracked paths with a warning. Passing `--allow-tracked` overrides this.
- When atem creates a file or directory in a repo, it adds the path to
  `.git/info/exclude`. That is a local-only ignore; atem never edits a
  committed `.gitignore`.
- **Worktrees:** a new worktree doesn't contain these local files until
  `atem sync` (or `atem memory apply`) runs in it. Phase 2's session-start
  hook fixes this.

### Apply report

Every apply prints one line per target:

```
✓ ~/.claude/CLAUDE.md             12 memories
✓ ~/.codex/AGENTS.md              12 memories
◐ <repo>/AGENTS.md                skipped: tracked by git
✓ ~/.agents/skills/deploy-check   v3
✗ ~/.claude/skills/review         skipped: unmanaged skill with same name
```

✓ means applied, ◐ means skipped for a safety reason, and ✗ means a clash.

### Verify in plan task 1

Verified 2026-09-24 on this machine. All targets assumed by the spec and by
the `Agent::*` path functions in Task 10 are confirmed correct; no path
changes needed.

**Claude (tested live, `claude -p`, in a scratch `mktemp -d` git repo, deleted
after):**

- Auto-memory path encoding — `ls ~/.claude/projects/`: confirmed every
  non-alphanumeric character (`/`, `.`, and also `_`) is replaced with `-`.
  Ran an extra check the spec didn't cover: created a repo under a path
  containing `_` (`my_under_score`) and ran `claude -p` in it; the resulting
  directory was `-tmp-tmp-<rand>-my-under-score` — underscore is *not*
  preserved, it's replaced like every other non-alphanumeric character. No
  exception found to the stated rule.
- Frontmatter — `head -8 ~/.claude/projects/*/memory/*.md`: every file has a
  `---` block with top-level `name:`, `description:`, `type:` (no
  `metadata:` nesting seen). Observed `type` values in this store:
  `feedback`, `project`, `reference` (matches the spec's `user|feedback|
  project|reference` set; `user` not observed but the field is free-form
  top-level so it's expected to work the same way).
- `CLAUDE.local.md` + project skills — wrote `CLAUDE.local.md` with a canary
  word and `.claude/skills/canary/SKILL.md` in a scratch repo, ran
  `claude -p "What is the canary word? Also list your available skills."`:
  response contained `PERSIMMON` and listed `canary` among available skills.
  Confirms `project_memory_file` = `<repo>/CLAUDE.local.md` and project
  `skills_root` = `<repo>/.claude/skills/`.
- Global memory/skills (inspected, not modified) — `~/.claude/CLAUDE.md`
  exists (it's this machine's real global instructions file) and
  `~/.claude/skills/` exists and contains a real skill (`visual-explainer`).
  Confirms global `global_memory_file` = `~/.claude/CLAUDE.md` and global
  `skills_root` = `~/.claude/skills/`.

**Codex (doc-verified per controller ruling — `~/.codex/` was not modified;
`codex --help`/`codex exec --help` inspected, plus official docs, since a
live `codex exec` canary test would have required editing the user's real
`~/.codex/AGENTS.md`):**

- Global instructions file: `~/.codex/AGENTS.md` (confirmed by
  [OpenAI's AGENTS.md guide](https://learn.chatgpt.com/docs/agent-configuration/agents-md),
  the current redirect target of `developers.openai.com/codex/guides/
  agents-md`). Codex home is `~/.codex` unless `CODEX_HOME` is set; within
  it, Codex reads `AGENTS.override.md` if present, else `AGENTS.md` — only
  one file at this level, "first non-empty file."
- Repo-level `AGENTS.md`: yes. Per the same doc, Codex starts at the project
  root (typically the git root) and walks down directory-by-directory to the
  cwd, checking `AGENTS.override.md` then `AGENTS.md` (then any
  `project_doc_fallback_filenames`) in each directory, concatenating them
  global-first, cwd-last (closer to cwd = higher precedence). Confirms
  `project_memory_file` = `<repo>/AGENTS.md`.
- Skills directories: per
  [OpenAI's skills guide](https://learn.chatgpt.com/docs/build-skills) (the
  redirect target of `developers.openai.com/codex/skills`), the personal/
  user-level directory is `~/.agents/skills` and the project-level directory
  is `.agents/skills`, scanned from cwd up through parent directories to the
  repo root. Confirms Codex `skills_root` = `~/.agents/skills` (global) and
  `<repo>/.agents/skills` (project) — matching the spec and Task 10 exactly.
  `SKILL.md` requires `name` and `description` frontmatter, same as Claude's
  skill format; no feature flag needed (skills are on by default).
- Local-install observation (not a contradiction, just noted): this
  machine's real `~/.codex/` has no `AGENTS.md` yet (user hasn't created
  one), and ships OpenAI's own bundled system skills under
  `~/.codex/skills/.system/*` — a separate, Codex-managed location for
  first-party skills, distinct from the user-authored `~/.agents/skills`
  path above. `codex --version` on this machine: `codex-cli 0.155.0`
  (`@openai/codex`).

No `Agent::*` path function in Task 10 needs to change:
`global_memory_file`/`project_memory_file`/`skills_root` for both `Claude`
and `Codex` already match verified reality.

## CLI

```
atem sync [--no-harvest]            # harvest → push → pull → apply (memory + skills)

atem memory add "<content>" [--scope global|project|machine] [--project <key>]
                            [--confidence high|medium|low] [--valid-at <date>]
atem memory replace <id> "<new>" [--valid-at <date>]   # add new, invalidate old
atem memory invalidate <id> [--at <date>]
atem memory list   [--scope …] [--project <key>] [--all] [--history [<id>]] [--full]
atem memory search "<query>" [--scope …] [--project <key>] [--history] [--limit <n>] [--full]
                                    # FTS5 + BM25, trigram (works for CJK)
atem memory rm <id>

atem memory apply                   # rewrite the managed blocks from the local store

atem skill add <dir> [--scope global|project] [--name <n>]
atem skill list
atem skill rm <name> [--scope …]
atem skill history <name> [--scope …]              # every version (asks the relay)
atem skill restore <name> --version <n> [--scope …]  # re-push version n as a new version

atem memory purge <id>              # remove a leaked credential (see Security)
atem skill purge <name> [--version <n> | --all-versions]

atem memory status                  # account, machine, pending ops, last sync, targets,
                                    # held-back memories, credential findings,
                                    # facts with more than one valid successor
```

- `<date>` is `YYYY-MM-DD` (midnight UTC) or unix seconds. `<id>` for `replace`, `invalidate`, `rm`, `purge` and `list --history` is a full id or a unique prefix, with or without `mem_` (the Codex block's short id works), or the listing form `<head>…<tail>` (`..` works in place of `…`).
- `list` and `search` show one row per memory: the id abbreviated to the short id plus its last 4 characters (`8245ecf6…e6fe`), and the content cut to fit. `--all` widens *which* memories are shown; `--full` shows *everything* about each one, one field per line: the whole id, status (`valid` / `replaced` / `invalidated`), where, confidence, source agent @ machine, `created_at`, `valid_at`, `invalid_at`, `replaced_by`, the relay `seq`, and the content with its line breaks.

- `memory add` defaults to `--scope project` inside a git repo and
  `--scope global` outside one.
- Commands that change something write locally, queue the change, then try a
  best-effort sync. That sync fails silently when offline and is retried on
  the next command.
- `sync` and `apply` always handle global targets, and project targets when
  the current directory is in a repo.
- Every command refuses to run without an active Astation pairing, and says
  so plainly.

## Sync algorithm

1. **Harvest** Claude's memory for the current repo, unless disabled.
2. **Push** `pending_ops` for memories, then skills (at most 50 memory ops
   and 8 skill ops per request). Apply `canonical_id` rewrites and remove the
   ops the server answered. A per-op refusal is permanent and is removed
   (with a note); a failed request (network error, any HTTP error) leaves
   the ops queued and stops that group, keeping queue order:
   - 401: the relay didn't recognize the Astation session (see Identity &
     auth) — reconnect atem to the Astation, then sync again.
   - 503: the relay is temporarily unavailable (e.g. its database).
   - 413 on a chunk: its ops are retried one at a time. A single op that is
     still too large stays queued with a note and is never acked.
3. **Pull** memories and skills since `cursor`, page by page. Upsert rows and
   apply tombstones locally. Advance `cursor` after each page. Cursors are
   kept per account (`memory_cursor:<astation_id>`,
   `skill_cursor:<astation_id>`), so pairing with a different Astation
   pulls that account from 0; the legacy unkeyed cursor is ignored.
   "Last sync" is recorded only when push and pull both finish with no
   network or HTTP error. Pulled invalidations set `invalid_at` and
   `superseded_by` locally (a local invalidation not yet on the relay is
   kept); the search index follows through triggers.
4. **Apply** memory blocks and skills to every discovered agent, and print
   the report. Invalid facts are skipped.

## Security

- **No credentials.** The secret check runs on `memory add`, `skill add`,
  harvested Claude memories, and every file in a skill. It looks for common
  key prefixes (`sk-`, `AKIA`, `ghp_`, `xox`), JWT and PEM blocks, and long
  high-entropy tokens. An assignment like `KEY=VALUE` is split so the value
  is checked on its own. Path- and URL-like tokens (containing `://` or
  starting with `/`, `./`, `~/`) skip only the high-entropy check; the
  prefix checks still apply to them.
  - A match is **refused**. Harvested memories are skipped and listed in the
    sync output.
  - If the check itself fails, the item is treated as a match and refused.
  - **Binary files can't be checked, so they're refused.** A skill file
    that isn't valid UTF-8 (an image, archive, compiled binary, `.pyc`) is
    reported as `unreadable (binary)`, and the whole skill is refused. Both
    atem (`check_bytes`) and the relay apply this rule.
  - `--force` overrides the check for manual `add` only, never for
    harvesting. A forced memory is stored locally only: it is never queued
    for sync, so it never leaves the machine.
- The relay runs the same check server-side.
- `knowledge.db` is 0600 plaintext, like `config.toml`. It holds no secrets
  by construction.

### When credentials are found

The fixed rule: **a credential value never leaves the machine.** What atem
does depends on where it finds one.

| Where | What atem does |
|---|---|
| `atem memory add` | Refuses, shows the match masked (`sk-…a41f`), and suggests naming the vault credential instead |
| Harvested Claude memory | Holds the memory back: it isn't synced and Claude's file isn't changed. It's listed in the sync output and in `atem memory status` ("1 held back"), and checked again only when the file changes |
| `atem skill add` | Refuses the whole skill and shows `file:line` with the value masked. Syncing part of a skill would be worse than syncing none of it |
| Settings and MCP config (Phase 4) | Keeps syncing, with the value stripped automatically and replaced by a vault reference |
| Keys already in files atem reads or writes (the memory targets, skill directories, and Claude's memory directory) | Never uploads them and never edits the file without asking. `atem memory status` reports each one as a credential finding |

atem holds the whole item back rather than stripping out just the matched
text. If the detector matches only part of a key, stripping would upload the
rest of it. The original stays on disk, so nothing is lost.

### Removing a credential that slipped through

If the detector misses a credential and it syncs:

- `atem memory purge <id>` deletes the memory, which also clears its text on
  the server. Other machines drop it and rewrite their managed blocks on
  their next sync. If the memory was harvested, its Claude file is marked
  `excluded`, so it isn't harvested again unless the file changes.
- `atem skill purge <name> --version <n>` (or `--all-versions`) erases the
  files of those versions on the server. Other machines delete the skill
  directory on their next sync, unless it was edited locally; in that case
  they report the directory instead of deleting it.
- Both commands end with a warning: **rotate the credential.** It may already
  have been copied to other machines' disks or backups, so treat it as
  exposed.

### Moving credentials to the vault (after the credential feature ships)

Once the vault manages credentials, atem will offer to move a detected value
into the vault and replace it with a reference such as `dialf/openai`,
asking you to confirm first. Until then, atem only reports findings and
tells you what to do.

### Credential references

Memory and skills refer to a credential by its **vault name**. The value
stays in the vault and is fetched at use time.

- **In memory:**
  ```
  atem memory add "DialF's OpenAI key is the vault credential dialf/openai"
  ```
- **In a skill:** scripts read the value at run time; the key never
  appears in the file.
  ```sh
  OPENAI_API_KEY="$(atem vault get dialf/openai)" ./deploy.sh
  ```
- **The secret check looks for values, not names.** A vault name like
  `dialf/openai`, or the `atem vault get …` command, passes the check. A
  pasted key like `sk-…` is still refused.
- **Values never flow back into the store.** If an agent fetches a
  credential and later writes it into Claude's memory or a skill file, the
  secret check blocks it on the next harvest or `skill add`.

**Dependency:** `atem vault get <name>` is a placeholder. The real command
comes from the credential feature's design. Until that ships, a name in
memory is just text that tells the user and agent where the credential
lives.

## Testing

- **Pure units:** project-key normalization, scope defaults, content
  normalization and hashing, frontmatter parsing, type-to-scope mapping,
  managed-block splice (idempotent, never changes text outside the markers,
  refuses broken markers), size-cap ordering, secret detection (including
  fail-closed), skill hashing.
- **Local store:** `pending_ops`, cursor handling, `canonical_id` rewrite,
  `harvest_map` edit and delete handling, the `held_back` and `excluded`
  states (and clearing them when the file changes), `applied` drift
  detection.
- **Relay (Astation):** idempotent add, dedup to `canonical_id`, a
  tombstone that clears the text, `since` paging, skill versioning and
  `superseded_concurrent`, skill purge (files erased, latest-version purge
  deletes the skill, new `seq`), account isolation, server-side secret
  rejection, auth rejection.
- **Credentials:** masked output, the whole skill refused, a held-back
  memory never pushed, a purge that reaches a second machine, and a purge on
  a locally edited skill that reports instead of deleting.
- **Adapters:** a temp HOME and a temp git repo. Tracked-file refusal,
  `.git/info/exclude` entries, unmanaged-skill clash, drift detection, and
  no echo to the machine that produced a memory.
- **E2E (headline):** two isolated atem configs, A and B, on one account
  against a relay.
  1. Claude on A saves a project memory.
  2. A runs `atem sync`.
  3. B runs `atem sync` in the same project's checkout.
  4. The fact appears in B's `CLAUDE.local.md` and in B's Codex target.
  5. A skill pushed from B appears under A's `~/.claude/skills/`.
- Phase 1.1 (Fact validity, Search, Skill history):
  - **Pure/local:** `replace` queues add then invalidate; invalidation is
    final (a second invalidate changes nothing); invalid facts are left out
    of the block but shown by `--history`; re-adding a previously invalid
    fact creates a new memory; harvest turns an edit into `replace` and a
    delete into `invalidate`; FTS5 BM25 ranking, CJK trigram matches,
    the substring fallback under 3 characters, and the "N more facts"
    line in the block.
  - **Relay:** the `invalidate` op (unknown id ok, content unchanged, new
    `seq`, account isolation) and the dedup index ignoring invalid rows.
    Skill `versions` and `version`: newest first, no files in the list,
    404 unknown, 410 purged, another account's skill invisible.
  - **Skill restore:** creates a new version with the old files, keeps
    the history, refuses purged versions, re-runs the secret check, and
    reports when offline.
  - **E2E:** A replaces a fact, B syncs, and the old fact leaves B's
    `CLAUDE.md` but is still in B's `memory list --history`.

## Fact validity

Status: built (phase 1.1). Borrowed from Graphiti's temporal model (see
"Prior art"). It uses only the time fields, not the graph or the LLM.

Facts go stale. "DialF listens on TCP 8765" was true until the port moved,
and a stale fact misleads every agent it's injected into. Delete is the
wrong tool for that: the fact *was* true, and the history is useful. So a
memory can be **invalidated**: it stops being injected, but it's kept.

| | Delete | Invalidate |
|---|---|---|
| Use for | Facts that were never true (mistakes), and leaked credentials (`purge`) | Facts that were true and changed |
| Text on the server | Cleared | Kept |
| Injected into agent files | No | No |
| Shown by `memory list --history` | No | Yes |

### Fields

Added to `memories` on both the server and the local store:

| Field | Meaning |
|---|---|
| `valid_at` | When the fact became true. Defaults to `created_at`. |
| `invalid_at` | When it stopped being true. `NULL` means still valid. |
| `superseded_by` | The id of the memory that replaced it, if any |

`created_at` and `seq` already record when atem learned each thing, so
these three fields give the useful half of a bi-temporal model without
four timestamps per row.

The same migration replaces the `deleted` boolean with a `deleted_at`
timestamp. It says both *that* and *when* a memory was deleted, which
matters because a deletion clears the text, so the time is all that's left.
It also matches `invalid_at`, so both ways a fact ends are recorded the same
way.

```sql
-- relay-server migration (next number after 0003)
ALTER TABLE memories ADD COLUMN deleted_at    BIGINT;
UPDATE memories SET deleted_at = extract(epoch FROM now())::bigint
    WHERE deleted;                                              -- real time unknown
ALTER TABLE memories ADD COLUMN valid_at      BIGINT;          -- NULL means created_at
ALTER TABLE memories ADD COLUMN invalid_at    BIGINT;
ALTER TABLE memories ADD COLUMN superseded_by TEXT;
DROP INDEX memories_dedup;
CREATE UNIQUE INDEX memories_dedup ON memories
    (account_id, scope, project, machine, content_hash)
    WHERE deleted_at IS NULL AND invalid_at IS NULL;
ALTER TABLE memories DROP COLUMN deleted;
```

- The dedup index only covers valid facts, so a fact that becomes true
  again (the port moves back) can be added again as a new memory.
- Rows deleted before this migration get the migration time as
  `deleted_at`; the real time was never stored.
- The wire format keeps `deleted: true|false`, computed from `deleted_at`,
  and adds `deleted_at`, so older atems keep working.
- The local store makes the same change.
- Skills keep their `deleted` boolean: a skill tombstone is its own version
  row, so its `created_at` already is the deletion time.

### Operations

- `atem memory replace <id> "<new fact>"` adds the new fact and invalidates
  the old one, with `superseded_by` pointing at the new id. Both ops go into
  the queue together, add first, and are sent in the same batch.
- `atem memory invalidate <id> [--at <date>]` invalidates without a
  replacement.
- `atem memory add … --valid-at <date>` and `replace … --valid-at <date>`
  set `valid_at` when the fact became true before it was recorded.
- `atem memory list --history [<id>]` includes invalid facts and shows each
  replacement chain, oldest first.

New wire op for `POST /api/memory/batch`:

```json
{"op": "invalidate", "id": "mem_…", "invalid_at": 1790000000, "superseded_by": "mem_…"}
```

Memory rows returned by `GET /api/memory` gain `valid_at`, `invalid_at` and
`superseded_by`. An invalidation takes a new `seq`, so every machine pulls
it.

### Rules

- **Invalidation is final.** Once `invalid_at` is set it never changes, and
  a later invalidate of the same id returns ok without changing anything.
  Two machines can't disagree about it, so sync needs no conflict handling.
  To bring a fact back, add it again.
- **Invalidating an unknown or deleted id returns ok,** the same as delete,
  so a retry after a crash is harmless.
- **Two replacements of the same fact** (two machines, both offline) leave
  two valid successors. Both survive. Because invalidation is final, the
  relay keeps only the first `superseded_by`; the machine whose replacement
  came second still knows its link from its local `replacements` table.
  `atem memory status` lists facts with more than one valid successor (from
  `superseded_by` plus that local table), so an agent or the user can
  replace one of them. Only that machine sees the fork.
- The server runs the same scope and account checks as for delete. An
  invalidate never changes `content`.

### Who decides a fact is outdated

The agents, as they already decide what to remember. atem still runs no
LLM.

- **Claude:** harvest turns Claude's edits into replacements.
  - An edited memory file → `replace` (it used to be delete plus add).
  - A deleted memory file → `invalidate`. Claude usually deletes a memory
    because it's outdated, and keeping the history is the safe default.
- **Codex:** the capture line in `AGENTS.md` gains: *"If a saved fact is
  outdated, run `atem memory replace <id> "<new fact>"`."* The managed block
  shows each fact's short id so Codex can do this.
- **You:** `replace` and `invalidate`.

### Compatibility

- The production relay is updated (Astation PR #22). A self-hosted relay
  older than that rejects the unknown `invalidate` op with 400: that batch
  and every memory change queued after the first invalidate wait, and sync
  says "This relay doesn't support outdating facts yet — update the relay
  (Astation)". Nothing is lost; it all goes out once the relay is updated.
- An older atem's delete of a fact that newer atems invalidated erases
  that fact's history text on the relay (the delete wins). Update every
  machine.
- An older atem ignores the new fields, so on that machine an invalid fact
  still looks valid until it's updated. Nothing breaks, but the
  release notes should say to update every machine.
- After this version migrates `knowledge.db`, an older atem can't read
  memories from it (the `deleted` column is gone). Update atem on every
  machine; there's no downgrade.

## Search

Status: built (phase 1.1).

Every paired machine already keeps a full copy of its account's memories in
`knowledge.db`, so search runs **locally**. It works offline, costs nothing,
and sends nothing to the relay.

- **Index:** an SQLite FTS5 table over `content`, kept in step with
  `memories` by triggers:

  ```sql
  CREATE VIRTUAL TABLE memories_fts USING fts5(
      content, content='memories', content_rowid='rowid', tokenize='trigram');
  ```

  The bundled SQLite in `rusqlite` already includes FTS5, so this adds no
  dependency.
- The index uses `memories`' implicit rowid, so `knowledge.db` is never `VACUUM`ed without an FTS `'rebuild'` afterwards.
- **Ranking:** BM25, via FTS5's built-in `bm25()`.
- **Why `trigram`:** Chinese, Japanese and Korean text has no spaces
  between words, so word tokenizers can't split it. Trigram matching works
  for any language. Postgres's built-in full-text search has the same
  problem and would need `zhparser` or `pg_jieba`, another reason search
  stays local.
- **Short queries:** trigram needs at least 3 characters. Shorter queries,
  such as a 2-character Chinese word, fall back to a substring match.
- `atem memory search "<query>" [--scope …] [--project <key>] [--history]
  [--limit <n>]`. Valid facts only unless `--history`.

### Search and the injection cap

Today each managed block holds at most 50 entries and 4 KB, and any extra
facts are dropped silently. With search:

- The block still holds the top facts, by confidence and then newest.
- When facts are left out, the block ends with a line saying how many and
  telling the agent to run `atem memory search "<query>"` for the rest.
- Phase 2's `atem mcp` exposes the same search as a `memory_search` tool.

## Skill history and restore

Status: built (phase 1.1).

When two machines push the same skill at once, the later push becomes the
latest version. The other version is kept on the relay, but there's no way
to see or get it back. These two commands fix that.

```
atem skill history <name> [--scope …]            # list every version
atem skill restore <name> --version <n> [--scope …]
```

`history` prints one line per version, newest first (times in UTC; the relay doesn't record which pushes were concurrent):

```
v5  latest   2026-10-02 14:10  mac-mini    claude   4 files
v4           2026-10-02 14:09  genie       codex    1 file
v3           2026-09-28 09:31  genie       cli      3 files
v2  deleted  2026-09-20 17:02  mac-mini    cli
v1  purged   2026-09-18 11:45  genie       claude
```

`restore` pushes the files of version *n* as a **new** version, based on the
current latest. It's an ordinary push, so:

- History is never rewritten. Restoring v4 over v5 creates v6 with v4's
  files, and v5 stays in the history.
- It syncs to every machine like any other push, and it takes part in the
  usual concurrency and drift rules.
- Restoring a deleted skill's earlier version brings the skill back.
- A **purged** version can't be restored: its files were erased. A
  **deleted** marker has no files to restore.
- The files are secret-checked again before the push, like `skill add`.

Where the data comes from: the local store keeps only the latest version of
each skill, so both commands ask the relay. They need a connection and say
so plainly when offline.

New relay endpoints, with the same auth and account isolation as the other
skill routes:

| Method & path | Returns |
|---|---|
| `GET /api/skills/versions?scope=&project=&name=` | `{"versions":[{version, created_at, source_agent, source_machine, file_count, deleted, purged}]}`, newest first. No file contents. |
| `GET /api/skills/version?scope=&project=&name=&version=<n>` | `{"skill": <skill row with files>}`. 404 for an unknown version; 410 for a purged one. |

`purged` comes from `skill_versions.purged` (migration 0005), set by
`purge`. A purged version and a delete marker are otherwise stored the same
way (`deleted = true`, `files = {}`, `content_hash = ''`), so versions purged
before 0005 report as `deleted`. `version` returns a delete marker with
`deleted: true` and no files; `restore` refuses it.

The concurrent-push note has a pointer (with `--scope project` for project skills): *"… both versions are kept and v5
is now the latest. See them with `atem skill history <name>`."*

## Future: binary files in skills

Not planned. Skills stay text-only until a real skill needs an image or
other binary file. If that happens:

- **Allowlist, checked by file signature** (not just the extension): for
  example `png`, `jpg`, `gif`, `pdf`. Executables and archives stay
  refused, because they can hide anything, including credentials.
- **Visible:** `skill add` lists every binary file it accepted without a
  secret scan, so you see exactly what went through.
- **Stored once by hash:** today every version stores every file again.
  Binary files would go into a content-addressed store (a separate Postgres
  table, or object storage behind the relay), keyed by SHA-256. A version
  refers to them by hash, so an unchanged image isn't copied into each new
  version.
- The 1 MB-per-skill cap stays, or gets its own separate limit for binary
  files.

## Future: semantic search and relationships

Not planned. Build these only if an evaluation shows keyword search isn't
enough.

- **Where:** on the Astation side, in Astation or the relay server. atem
  stays a client: it would call a search endpoint and would not run
  embeddings or a graph itself.
- **Semantic (vector) search:** for example `pgvector` on the relay's
  Postgres, combined with keyword search and merged with reciprocal rank
  fusion. Choose between a cloud embedding API (costs money and sends
  memory content to a provider, so it must be opt-in per account) and a
  local model.
- **Relationships:** only if we need questions like "what depends on the
  auth service?" Start with an edges table in Postgres, or the Apache AGE
  extension, before considering a separate graph database such as Neo4j.
  The relay's Postgres stays the source of truth either way; any index is
  rebuilt from it.
- **Graphiti as an optional backend:** the same rule applies. It would be
  an index fed from Postgres, not a replacement.

### Evaluation before building any of it

Measure on real data before adding anything:

1. Take the memories from real projects and write about 50 questions whose
   answers are in them. Include questions about facts that changed.
2. Compare:
   - inject-all (the managed block);
   - local FTS5 search;
   - relay hybrid search (keyword plus `pgvector`);
   - Graphiti, fed the same facts through `add_triplet`.
3. Measure answer accuracy with the same agent and model, latency, cost per
   write and per query, and what leaves the machine.

Adopt a new backend only if it beats local FTS5 by a clear margin on this
test.

## Phasing

| Phase | Scope |
|---|---|
| **1 (MVP)** | Everything in this doc except the 1.1 items and the Future sections. Built |
| **1.1** | Fact validity, local Search, and Skill history and restore. Built |
| 2 | `atemd` plus session-start hooks (sync and apply automatically, which also fixes worktrees). An `atem mcp` server with `memory_add` and `memory_search` tools, so agents save and search memory directly; this matters most for Codex, whose hooks are weaker |
| 3 | A guarded nightly clean-up pass: back up first, run the LLM, sanity-check the result, restore the backup on failure. It merges duplicates, promotes project facts that apply everywhere to global, and flags contradictions. Also harvest session transcripts into searchable history before Claude deletes them (30 days by default), and distill them into memory |
| 4 | Settings, MCP definitions, and hooks, with portable and machine-local fields separated and credential values replaced by references to the credential feature. Gemini and OpenCode adapters |

Credential management is a separate feature on the vault, with its own
design. It isn't a phase of this one.

## Prior art

- **hierrr/agent-sync.** Useful ideas: harvesting Claude's native
  auto-memory, the guarded nightly curation pass, and never silently
  dropping a conflict. Avoided: its LAN-only Syncthing, symlinked `~/.claude`,
  and keying projects by folder name.
- **spxrogers/agentsync.** Useful ideas: the per-target apply report,
  marker integrity rules, copying skills verbatim to `~/.agents/skills`,
  drift detection by hash, and fail-closed secret checks. Avoided: owning the
  whole file, and having no sync.
- **Memorix.** The closest design found: a Postgres relay, global and
  project scopes, personal records kept local, and turning memories into
  skills. Worth reviewing before Phase 3.
- **Graphiti (Zep).** An open-source temporal knowledge graph (Apache-2.0)
  on Neo4j, FalkorDB or Neptune. It uses an LLM to extract entities and
  facts from raw text, keeps each fact's validity window, and combines BM25,
  vector and graph search. In the Zep paper (arXiv 2501.13956), on
  LongMemEval against a full 115k-token history, accuracy rose from 60.2%
  to 71.2% (gpt-4o) and latency fell from 28.9 s to 2.58 s. Recall of what
  the assistant itself said dropped from 94.6% to 80.4%. The comparison is
  against pasting raw chat history, not against curated facts like ours.
  Useful idea: invalidating facts instead of deleting them ("Fact
  validity"). Avoided for now: LLM extraction on every write (our agents
  already curate facts), and running a second database.
- **Others surveyed:** rulesync, ruler, basic-memory, ai-memory,
  agentmemory, mem0/OpenMemory, the Anthropic memory MCP server, and
  Claude-only sync tools. None combines account-scoped relay sync, offline
  copies on each machine, memory plus skills, and a machine scope.
