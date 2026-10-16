# Runtime host integration (atem-session r6.2 in the real runtime) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development.

**Goal:** Run the accepted atem-session protocol (r6.2) in Atem's real runtime: one broker per profile that owns the Astation connection and the session authority, one `atem worker` per agent session that survives the broker, local frontends through the broker, pairing/unlock through the broker, durable receipts on disk, and the shared host fixtures passing against the real processes.

**Architecture:** `atem runtime` (broker) holds `SessionHost` (src/session_protocol/host.rs), a `FileJournal`, the Astation connection(s) and local IPC. Each session's agent runs in an `atem worker` that owns the PTY, canonical screen, chat adapter and output; the broker is the only writer authority — every write reaches the worker tagged with the input epoch the broker granted, and the worker drops bytes whose epoch is older than its current one (epoch updates and writes travel in order on one stream). A new broker adopts surviving workers after validating session id, process generation and process-start metadata.

**Tech Stack:** Rust 2024 (`atem` bin), tokio, Unix sockets (src/daemon.rs helpers), portable-pty, serde_json lines.

**Spec:** `designs/protocol/atem-session-v1.md` (r6.2), `designs/session-multiplexing.md`, `designs/agent-runtime.md` (with its "Alignment" section), Astation handoff https://truck.netbird.cloud:58310/protocol/atem-implementation-handoff.md ("Next work with the Atem owner" 1–4).

## Global Constraints

- Branch `feat/runtime` (= feat/agent-runtime + feat/status-pair-verify + feat/session-protocol). Commits end with a blank line and `🤖 Built with SMT <smt@agora.build>`. Never push without the user asking.
- **No backward compatibility** (user direction): remove legacy paths instead of gating them — `agentInput`, `agentPrompt`, `voiceCommand`/`voiceToggle`/`voiceRequest` prompts, `userCommand`, terminal-v1 `control`/`list`/`lease_id`, provider-name terminal ids, unbound chat submit. No aliases, no compatibility shims.
- One authority: every remote mutation goes through `SessionHost` with a binding and the current lease; local frontend input goes through the broker, which revokes any remote lease before the bytes are written; the worker's write boundary drops bytes with a stale epoch.
- Welcome uses the authenticated account/device identity and the durable `pairing.json` host trust generation; §9 features (resume, browser grants, account-wide access, relay confidentiality) stay refused.
- Never rustfmt `src/app.rs`, `src/main.rs`, `src/cli.rs`, `src/websocket_client.rs`, `src/memory/{mod,crypto,secrets}.rs`; new files may be formatted; check others with `--check` first. Never project-wide `cargo fmt`.
- Never run the installed `atem`; never touch the real `~/.config/atem`, `$XDG_RUNTIME_DIR/atem`, the user's running atem/agents or key agent; tests use temp HOME/XDG dirs, fake agents, and only signal processes they started.
- Every task: full `cargo test` reading every `test result` line (unit + all `tests/*` binaries), session_protocol tests ×3, clippy not above the branch baseline.

## Tasks

### Task 1: Remove the legacy remote paths from the App

Remove the r6 "removed ops" from `src/app.rs`, `src/app/terminal.rs`, `src/app/chat.rs`, `src/websocket_client.rs`, `src/terminal_share.rs` (handlers, message types, routing helpers, `ActiveCli` leftovers, `default_session` legacy routing, draft-check for legacy text, `terminal_ids:"session"` marker, provider aliases in `Sessions::resolve`), and their tests. terminal-v1 streams and chat-v1 become session-bound only (binding checked by `SessionHost`; until Task 4 wires the host, remote terminal/chat mutations are refused). Mark tasks stay, as **local-origin work**: dispatched to the Claude session whose cwd holds the task only when that session has no remote lease holder and is ready; they wait otherwise. Docs: AGENTS.md sections that describe removed messages.

### Task 2: FileJournal

`src/session_protocol/file_journal.rs`: append-only per-session receipt log under the broker's state dir (0700/0600, O_NOFOLLOW), fsync per transition, halt admission after an fsync error, compaction (rewrite live receipts + lease floor atomically; drop evicted/expired), lease-epoch floor; implements `Journal`. Receipts indexed by session in `SessionHost` (wiring note). Tests: crash points (truncate mid-record), compaction atomicity, reload equals in-memory state, fsync failure halts.

### Task 3: `atem worker` and adoption

`src/runtime/worker.rs` (+ protocol): `atem worker --state <dir>` (hidden) spawned detached by the broker per session; owns the agent PTY (`pty_session`), canonical screen (`terminal_share` frames), Claude chat adapter, output buffer; serves one broker connection on `<runtime dir>/atem/workers/<session_id>.sock` (same-UID); messages: hello{session_id, process_gen, start_time}, write{bytes, input_epoch}, set_input_epoch, resize, stop, output/frame, chat events, activity, exited. Writes with an epoch older than the current one are dropped and counted. Records `{session_id, process_gen, pid, start_time}` in its state dir. Broker adoption on start: scan worker records, connect, verify session_id + process_gen + the process start time from the OS (Linux `/proc/<pid>/stat` field 22, macOS `proc_pidinfo`), then `restore_session`; unverifiable → `recovery_required`. Tests: worker survives broker kill (binary test), adoption validates start time (pid reuse rejected), stale-epoch writes dropped.

### Task 4: Broker host wiring

In `src/runtime/`: the broker owns the Astation connection(s) (local :8080 and relay through the existing client) and drives `SessionHost`: session-v1 hello/welcome (identity from the authenticated socket + `pairing_binding` trust gen), registry from workers, leases, receipts via FileJournal, terminal-v1 frames/input bound to sessions (write effects → worker `write` with epoch; `admit_write` semantics), chat-v1 submit → receipt → paste through the worker, `set_activity` from chat status, `replace_process`/exit from workers, periodic `advance` (100 ms), dedup of identical requests arriving on direct and relay (by message id within a window, and by request_id for submits). Remote connection loss → leases stop renewing; registry per attachment. Tests: in-process broker with fake workers + fake Astation peer.

### Task 5: Local frontends through the broker

`atem agent launch|attach|list|stop` as broker clients (the earlier step-1 Task 5 design): local input and resize travel to the broker, which revokes remote leases and forwards to the worker; detach keeps the session. Bare `atem` menu launches/attaches through the broker. Binary tests (launch, detach, attach restore, stop, two sessions, broker restart with a surviving worker).

### Task 6: Pairing and unlock through the broker

`atem pair` (first pairing), `atem pair verify`, `atem cred unlock|projects`, and paired-token refresh run inside the broker on its connection; the CLI is the UI (`print`/`ask`/`answer`/`done` over local IPC); one operation at a time; handshake replies routed to the active operation only and dropped after it ends; no fallback to a separate socket. Tests per `designs/agent-runtime.md` testing section.

### Task 7: Shared fixtures against the real runtime; docs and handoff

An integration harness that runs every host-side fixture in `designs/protocol/fixtures/` against a real broker + real workers (fake agent binary) over a real socket; AGENTS.md/README/design docs; a handoff note for Astation (what's live, how to run the host, which fixtures pass).

## Runtime wiring notes (from the protocol core)

See `designs/plans/2026-10-16-session-protocol-core.md` "Runtime wiring notes".
