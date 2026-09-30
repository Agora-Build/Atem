# Atem Memory — shared memory and skills for AI coding agents

Status: design (MVP). Spans two repos: **Atem** (CLI, local store, adapters,
sync client) and **Astation** (relay-server `/api/memory`, `/api/skills` +
Postgres).

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
- Editing a memory in place. To change a memory, remove it and add a new one.
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
no git, it's `local:<cwd name>`. `--project <key>` overrides. The display
name is the last path segment, for example `atem`.

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
| **Codex** | **Instruction.** The managed block in Codex's `AGENTS.md` includes one line: *"To save a durable fact for future sessions, run `atem memory add --agent codex "<fact>"`."* |
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
  changes, atem removes the old memory and adds a new one. If the file is
  deleted, atem removes its memory. A memory is only removed this way when
  Claude on this machine created it and no other harvested file links to
  it; otherwise the file is just unlinked.
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
that value is the sync cursor.

```sql
CREATE SEQUENCE knowledge_seq;

CREATE TABLE memories (
    id             TEXT PRIMARY KEY,         -- mem_<ulid>, generated by the client
    account_id     TEXT NOT NULL,
    scope          TEXT NOT NULL,            -- global | project | machine
    project        TEXT NOT NULL DEFAULT '', -- '' unless scope = project
    machine        TEXT NOT NULL DEFAULT '', -- '' unless scope = machine (atem_id)
    content        TEXT NOT NULL,
    content_hash   TEXT NOT NULL,            -- sha256 of normalized content
    confidence     TEXT NOT NULL DEFAULT 'medium',  -- high | medium | low
    source_agent   TEXT NOT NULL,            -- claude | codex | cli
    source_machine TEXT NOT NULL,            -- atem_id
    created_at     TIMESTAMPTZ NOT NULL,
    deleted_at     TIMESTAMPTZ,              -- tombstone; syncs like any other change
    seq            BIGINT NOT NULL DEFAULT nextval('knowledge_seq')
);
CREATE INDEX memories_account_seq ON memories (account_id, seq);
CREATE UNIQUE INDEX memories_dedup ON memories
    (account_id, scope, project, machine, content_hash) WHERE deleted_at IS NULL;

CREATE TABLE skill_versions (
    account_id     TEXT NOT NULL,
    scope          TEXT NOT NULL,            -- global | project
    project        TEXT NOT NULL DEFAULT '',
    name           TEXT NOT NULL,            -- directory name
    version        INT  NOT NULL,            -- 1, 2, 3 …; the latest live version wins
    files          JSONB NOT NULL,           -- {"SKILL.md": "<b64>", "scripts/x.sh": "<b64>"}
    content_hash   TEXT NOT NULL,            -- over sorted (path, bytes)
    source_agent   TEXT NOT NULL,
    source_machine TEXT NOT NULL,
    created_at     TIMESTAMPTZ NOT NULL,
    deleted        BOOLEAN NOT NULL DEFAULT false,  -- a tombstone is a version too
    seq            BIGINT NOT NULL DEFAULT nextval('knowledge_seq'),
    PRIMARY KEY (account_id, scope, project, name, version)
);
CREATE INDEX skill_versions_account_seq ON skill_versions (account_id, seq);
```

- `project` and `machine` store `''` instead of NULL so the dedup index
  compares them normally.
- **Deleting a memory clears its text.** The tombstone sets `deleted_at`,
  blanks `content` and `content_hash`, and takes a new `seq`, so the text
  doesn't stay on the server. Memories keep no history.
- **Memory `content_hash`:** trim, collapse runs of whitespace, lowercase.
  The original `content` is stored unchanged.
- **Skills** are edited, unlike memories. Each push adds a version, and older
  versions are kept so nothing is lost, unless they're purged (see "Removing
  a credential that slipped through"). If two machines push the same skill
  concurrently, the one with the higher `seq` wins. A skill is limited to
  1 MB total.

### Local (SQLite, each machine)

`~/.config/atem/knowledge.db`, using `rusqlite` like `diagram_server.rs`,
file mode 0600. The file is created with mode 0600 before it's opened, so
there's no window where it's readable by others:

- `memories` and `skills`: mirrors of the server rows (latest skill version
  only).
- `pending_ops`: an outbound queue of `add`/`delete` memory and `push`/`delete`
  skill, applied locally first.
- `sync_state`: the last pulled `seq`, per account (paired Astation id), and
  the last clean sync time.
- `harvest_map`: see above.
- Drift is detected with the hash stored in each skill's `.atem-skill`
  marker.

## Relay API (Astation repo)

| Method & path | Purpose |
|---|---|
| `POST /api/memory/batch` | Push memory ops (`add`, `delete`). Returns per-op results. |
| `GET /api/memory?since=<seq>&limit=<n>` | Pull memory rows (tombstones included) with `seq > since`. |
| `POST /api/skills/batch` | Push skill ops (`push`, `delete`, `purge`). |
| `GET /api/skills?since=<seq>&limit=<n>` | Pull skill versions with `seq > since`. |

Rules:

- **Memory add is idempotent by `id`.** If a live row with the same dedup key
  already exists under another id, the server returns
  `{sent_id, canonical_id}` and the client rewrites its local row. This is how
  two machines that added the same fact offline end up with one memory.
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
- **Size cap:** at most 50 entries and 4 KB per block. Sort by confidence,
  then newest first.
- For Codex, the block also includes the capture instruction line described
  earlier, placed just before the credential instruction.

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
                            [--confidence high|medium|low]
atem memory list   [--scope …] [--project <key>] [--all]
atem memory search "<text>"         # local substring search
atem memory rm <id>
atem memory apply                   # rewrite the managed blocks from the local store

atem skill add <dir> [--scope global|project] [--name <n>]
atem skill list
atem skill rm <name> [--scope …]

atem memory purge <id>              # remove a leaked credential (see Security)
atem skill purge <name> [--version <n> | --all-versions]

atem memory status                  # account, machine, pending ops, last sync, targets,
                                    # held-back memories, credential findings
```

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
   network or HTTP error.
4. **Apply** memory blocks and skills to every discovered agent, and print
   the report.

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

## Phasing

| Phase | Scope |
|---|---|
| **1 (MVP)** | Everything in this doc |
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
- **Others surveyed:** rulesync, ruler, basic-memory, ai-memory,
  agentmemory, mem0/OpenMemory, the Anthropic memory MCP server, and
  Claude-only sync tools. None combines account-scoped relay sync, offline
  copies on each machine, memory plus skills, and a machine scope.
