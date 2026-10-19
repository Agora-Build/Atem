# Atem runtime, step 1 (runtime and sessions) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move agent sessions and the Astation connection out of the TUI into one background `atem runtime` per profile that hosts any number of Claude/Codex sessions, with `atem agent launch|attach|list|stop` as local frontends.

**Architecture:** First turn `App`'s two fixed agent slots into a map of sessions inside today's process (Tasks 1–2), so all host logic is session-keyed and tested before anything moves. Then extract the cred agent's daemon plumbing (Task 3), run the host loop headless behind a same-user Unix socket (Task 4), and make the terminal UI a client of it (Task 5). Step 2 (pair/cred through the runtime) and step 3 (cleanup) get their own plans; the three ship in one release.

**Tech Stack:** Rust 2024 bin crate `atem`; tokio (UnixListener/UnixStream, signal), serde_json lines, portable-pty, vt100, ratatui/crossterm, libc (flock, SO_PEERCRED/getpeereid, setsid).

**Spec:** `designs/agent-runtime.md` (binding). Code map of today's coupling: `.superpowers/runtime-code-map.md` (local, gitignored; regenerate with the Explore prompt in the ledger if missing).

## Global Constraints

- Branch `feat/agent-runtime` from `main` (after `docs/agent-runtime` is merged or rebased in). Commits end with a blank line and `🤖 Built with SMT <smt@agora.build>`. Never push without the user asking.
- Behaviour visible to Astation must stay compatible: agent-list bytes for an entry without capabilities unchanged (pinned test); terminal ids `claude`/`codex` keep working as aliases for the most recently used live session of that provider; chat-v1 unchanged.
- `session_id` = `ses-` + 12 lowercase base32 chars (`[a-z2-7]`), random; used as registry id, terminal-v1 `terminal_id` and chat-v1 `agentId`. At most 16 live sessions.
- Launch environment bounds: ≤ 512 entries, ≤ 256 KiB total; never logged, listed or kept after spawn.
- Runtime files: `runtime.lock` (flock + pid) and `runtime.socket` (recorded path) and `runtime.log` in the config dir; socket `$XDG_RUNTIME_DIR/atem/runtime.sock` else `<config>/runtime.sock`; dir 0700, socket 0600, same-UID peers only. Must not collide with the cred agent's `agent.sock`/`agent.lock`/`cred_agent.lock`.
- Idle exit: 10 min with no sessions (live or exited), no clients and no operation; exited sessions removed 10 min after exit.
- Local protocol v1 per the spec table (JSON lines, `{"v":1,"op":…}`, base64 bytes); output backlog per client ≤ 256 KiB then drop + fresh restore; stop reading a client while the target PTY input queue is full.
- Never rustfmt `src/app.rs`, `src/main.rs`, `src/cli.rs`, `src/websocket_client.rs`, `src/memory/crypto.rs`, `src/memory/mod.rs`, `src/memory/secrets.rs`; new files may use `rustfmt --edition 2024`; check others with `--check` first. Never project-wide `cargo fmt`.
- Never run the installed `atem`; never touch the real `~/.config/atem`, `$XDG_RUNTIME_DIR/atem`, the user's running atem/claude/codex processes or cred agent; tests use temp `HOME`/`XDG_RUNTIME_DIR` and fake agent binaries. No signals to processes a test didn't start.
- Every task: full `cargo test` reading EVERY `test result` line (unit + `tests/*` binaries), `cargo test --bin atem chat` 3× (flake check), `cargo clippy --all-targets` not above baseline (82 bin / 83 test).

## File Structure

| File | Responsibility |
|---|---|
| `src/session.rs` (new) | `SessionId`, `Provider`, `Session` (all per-agent state), `Sessions` (ordered map + aliases + limits) |
| `src/app.rs`, `src/app/terminal.rs`, `src/app/chat.rs`, `src/app/reauth.rs` | host logic rewritten over `Sessions` |
| `src/pty_session.rs` | spawn with explicit cwd and env |
| `src/terminal_share.rs` | `SharedTerminal::new(id, provider)`; `sessions` gains `terminal_ids` |
| `src/daemon.rs` (new) | generic socket path/dir/peer/lock/spawn helpers extracted from `memory/agent_socket.rs` |
| `src/runtime/mod.rs`, `src/runtime/protocol.rs`, `src/runtime/server.rs`, `src/runtime/client.rs` (new) | `atem runtime`: host loop, local protocol, server, async client |
| `src/tui/*` | TUI as a runtime client for agent terminals |
| `src/cli.rs` | `agent launch|attach|list|stop`, hidden `runtime` |
| `tests/runtime_binary.rs` (new) | binary tests of the runtime |

---

### Task 1: Sessions inside App (no behaviour change)

**Files:** Create `src/session.rs`; modify `src/app.rs`, `src/app/terminal.rs`, `src/app/chat.rs`, `src/app/reauth.rs`, `src/tui/mod.rs`, `src/tui/draw.rs`, the test modules listed in the code map §6, `src/main.rs` (`mod session;`).

**Interfaces — produces:**

```rust
// src/session.rs
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SessionId(String);            // "ses-" + 12 base32; Display; as_str()
impl SessionId { pub fn new() -> Self; pub fn parse(s: &str) -> Option<Self>; }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Provider { Claude, Codex }      // as_str(): "claude" | "codex"; kind() -> AgentKind

pub struct Session {
    pub id: SessionId,
    pub provider: Provider,
    pub cwd: PathBuf,
    pub created_at: SystemTime,
    pub last_used: Instant,               // bumped by local/remote input and launch
    pub input: Option<PtyInput>,
    pub events: Option<mpsc::Receiver<PtyEvent>>,
    pub handle: Option<PtyHandle>,
    pub terminal: VtParser,
    pub share: SharedTerminal,
    pub raw_log: String, pub raw_log_start: usize,
    pub output_log: String,
    pub user_actions: Vec<String>,
    pub log_file: Option<PathBuf>, pub summary_file: Option<PathBuf>,
    pub waiting_exit: bool,
    pub view: (u16, u16),                 // local viewport size, (0,0) = unset
    pub chat: Option<chat::AgentChat>,    // Claude only
    pub exited_at: Option<Instant>,
}

pub struct Sessions { /* BTreeMap<SessionId, Session> + insertion order */ }
impl Sessions {
    pub const MAX_LIVE: usize = 16;
    pub fn insert(&mut self, s: Session) -> anyhow::Result<&mut Session>; // refuses > MAX_LIVE live
    pub fn get(&self, id: &SessionId) -> Option<&Session>;
    pub fn get_mut(&mut self, id: &SessionId) -> Option<&mut Session>;
    pub fn remove(&mut self, id: &SessionId) -> Option<Session>;
    pub fn iter(&self) -> impl Iterator<Item = &Session>;          // creation order
    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut Session>;
    /// "claude"/"codex" alias or a session id → the live session it names
    /// (alias = the most recently used live session of that provider).
    pub fn resolve(&self, id_or_alias: &str) -> Option<SessionId>;
    pub fn latest(&self, provider: Provider) -> Option<SessionId>;
}
```

`App` loses every `claude_*`/`codex_*` per-agent field and `claude_chat` and gains `sessions: Sessions` and `focused: Option<SessionId>` (the session the TUI shows; replaces `AppMode::{ClaudeChat,CodexChat}` → a single `AppMode::Terminal`). `ClaudeClient`/`CodexClient` stay on `App` as launch configuration. `ActiveCli`/`pinned_cli` are removed (pinned_cli is dead; routing uses ids from Task 2). In this task `ensure_claude_session`/`ensure_codex_session` keep their "one per provider" behaviour by reusing `sessions.latest(provider)` if live, else creating one — Task 2 adds multiple sessions.

Mechanical rules: every `self.claude_X` becomes access through the focused or addressed `Session`; helper `fn session_for(&self, provider) -> Option<&Session>` may be used in this task only where the old code was provider-fixed (voice, mark tasks, legacy routing), each marked `// Task 2: route by id`. Registry ids stay `claude-pty-<uuid>`/`codex-pty-<uuid>` in this task (Task 2 switches to session ids). Test helpers `app_with_cat`, `share_codex_with_remote_controller`, chat `Harness::start` are rewritten over `Sessions` once, and tests keep asserting the same behaviour.

- [ ] Step 1: write `src/session.rs` with unit tests (id format/parse, insert limit, resolve aliases by `last_used`, iteration order).
- [ ] Step 2: migrate `App` and all users; update test helpers; no test changes their assertions except field access.
- [ ] Step 3: full verification (constraints); commit `refactor(app): agent sessions as a session map`.

### Task 2: Many sessions, session ids, explicit cwd/env, addressed routing

**Files:** `src/session.rs`, `src/app.rs`, `src/app/terminal.rs`, `src/app/chat.rs`, `src/pty_session.rs`, `src/claude_client.rs`, `src/codex_client.rs`, `src/terminal_share.rs`, `src/agent_registry.rs`, `src/agent_client.rs` (only if needed), tests.

**Interfaces — consumes** Task 1. **Produces:**

```rust
// pty_session.rs
pub struct SpawnSpec { pub binary: String, pub args: Vec<String>, pub cwd: PathBuf,
                       pub env: Option<Vec<(OsString, OsString)>>, pub rows: u16, pub cols: u16 }
pub fn spawn_spec(spec: SpawnSpec) -> Result<PtySession>;   // env None = inherit (today)

// session.rs
pub struct LaunchRequest { pub provider: Provider, pub args: Vec<String>, pub cwd: PathBuf,
                           pub env: Option<Vec<(OsString, OsString)>>, pub rows: u16, pub cols: u16 }
pub fn check_env(env: &[(OsString, OsString)]) -> Result<(), &'static str>; // ≤512 entries, ≤256 KiB

// app.rs
impl App {
    /// Start a new session (Claude gets its chat adapter as today). Registers it
    /// (id = session id, name = provider), sends the agent list when connected.
    pub async fn launch_session(&mut self, req: LaunchRequest) -> Result<SessionId>;
    pub fn stop_session(&mut self, id: &SessionId);       // PTY stop; exit handled as today
    pub fn reap_exited_sessions(&mut self, now: Instant); // remove 10 min after exit (+ registry entry)
}
// terminal_share.rs
SharedTerminal::new(id: &str, provider: &str)            // id = session id
// `sessions` message gains `terminal_ids: "session"`
```

Behaviour:
- `ensure_claude_session`/`ensure_codex_session` become `launch_session` with the process cwd and inherited env (TUI menu keeps working). `CLAUDE_CLI_*`/`CODEX_CLI_*` are read from the request env when given, else the process env.
- Registry: one entry per session, `id` = session id; removed when the session is reaped; `all()` sorted by creation. The agent list is sent on launch, exit and reap when connected.
- terminal-v1: `list` returns every live session (`terminal_id` = session id, `provider`); requests accept a session id or the `claude`/`codex` alias (resolved per request; the reply uses the real session id); unknown → `Error "Unknown terminal"`.
- `AgentInput`/`AgentPrompt`/voice/`UserCommand`: route by `agent_id` when present (unknown id → error/status message); without one → `sessions.latest(Claude)` (or Codex for codex-specific actions), subject to chat-v1's draft rule when that session has chat (refuse with a status message when it has unsent input); with none → refuse ("no Claude session; run `atem agent launch claude`"). No implicit spawning for voice/AgentPrompt.
- Mark tasks: pick a live Claude session whose `cwd.join(".chisel/tasks/<id>.json")` exists (most recently used first); read the task from there; none → `MarkTaskResult{success:false, "no Claude session for this project; run atem agent launch claude there"}`. `try_dispatch_main` no longer calls ensure; the dispatcher's main queue targets that session; background `claude -p` runs with `current_dir(session.cwd)`.
- Logs: `<cwd>/claude_logs/` → `<config>/logs/<session_id>/` (session-unique names).
- `PendingAstationCommand`/`pending_voice_request` hold a `SessionId` instead of `ActiveCli`.

Tests (write first): two Claude sessions + one Codex in one App: all three in the agent list (sorted, distinct ids); terminal-v1 subscribe by id and by alias (alias → most recently used); AgentPrompt to each id reaches the right PTY (test channels); AgentInput without id → latest Claude, refused with unsent input; mark task routed by cwd (temp dirs) and refused with none; 17th launch refused; env over limit refused; exited session reaped after 10 min (inject time); registry entry removed; logs path per session.

- [ ] tests → implement → verify → commit `feat(session): several sessions with ids, cwd/env and addressed routing`.

### Task 3: Daemon plumbing shared with the cred agent

**Files:** create `src/daemon.rs`; modify `src/memory/agent_socket.rs` to use it (no behaviour change).

**Produces:**

```rust
pub struct DaemonFiles { pub socket: PathBuf, pub lock: PathBuf, pub record: PathBuf, pub log: PathBuf }
impl DaemonFiles { pub fn for_name(config_dir: &Path, runtime_dir: Option<OsString>, name: &str) -> Self; }
// name "runtime" → runtime.sock / runtime.lock / runtime.socket / runtime.log
pub fn prepare_socket_dir(dir: &Path, uid: u32) -> io::Result<()>;
pub fn check_parent_dir(dir: &Path, uid: u32) -> io::Result<()>;
pub fn peer_uid(stream: &std::os::unix::net::UnixStream) -> io::Result<u32>;
pub struct HeldLock { /* fd */ }
pub fn lock_exclusive_with_pid(path: &Path) -> io::Result<Option<HeldLock>>; // None = held elsewhere
pub fn read_lock_pid(path: &Path) -> Option<u32>;
pub fn confirmed_atem_pid(pid: u32, subcommand: &str) -> bool;   // same uid + cmdline matches
pub fn spawn_detached(exe: &Path, subcommand: &str, log: &Path, envs: &[(OsString, OsString)]) -> io::Result<u32>; // setsid, chdir, null stdin, 0600 log
pub fn bind_socket(files: &DaemonFiles, uid: u32) -> io::Result<tokio::net::UnixListener>; // replaces a dead socket, chmod 0600, records path
```

The cred agent keeps its file names (`agent.sock`, `agent.lock`, `cred_agent.lock`, `agent.socket`, `cred-agent.log`) by passing them explicitly; `spawn_detached(.., "cred-agent", ..)` replaces `spawn_agent`'s hard-coded argument.

- [ ] Move with tests (copy the relevant agent_socket tests to daemon.rs: dir checks, peer uid, lock held/free, pid read, short socket dirs); all cred-agent tests and `tests/cred_agent_binary.rs` pass unchanged → commit `refactor(daemon): socket, lock and spawn helpers shared with the cred agent`.

### Task 4: `atem runtime` — headless host and local protocol

**Files:** create `src/runtime/{mod.rs,protocol.rs,server.rs,client.rs}`; modify `src/cli.rs` (hidden `Runtime` subcommand), `src/main.rs`, `src/app.rs` (extract the host tick), `src/tui/mod.rs` (call the extracted tick).

**Produces:**

```rust
// app.rs — the host part of today's TUI loop (steps 3–7, 9–13 in the code map §2)
impl App { pub async fn tick_host(&mut self); }

// runtime/protocol.rs — v1, exactly the spec table
pub const PROTOCOL: u32 = 1;
#[serde(tag = "op", rename_all = "snake_case")]
pub enum ClientMsg { Hello{protocol, build}, Launch{provider, args, cwd, env, rows, cols},
  Attach{session_id, rows, cols}, Detach{session_id}, Input{session_id, bytes /*b64*/},
  Resize{session_id, rows, cols}, List, Stop{session_id}, Reload }
pub enum RuntimeMsg { Welcome{protocol, build, pid}, Launched{session}, Attached{session, restore /*b64 ANSI*/},
  Output{session_id, bytes, offset}, Exited{session_id, generation, status}, Sessions{sessions},
  Detached{session_id, reason}, Notice{text}, Error{text, op?} }
pub struct SessionSummary { id, provider, cwd, created_at_ms, status, attached, remote_controlled, exited }

// runtime/mod.rs
pub async fn run_runtime(config_dir: PathBuf) -> Result<()>;  // `atem runtime` (hidden)
// runtime/client.rs
pub struct RuntimeClient { /* tokio UnixStream lines */ }
impl RuntimeClient {
    pub async fn connect_or_start() -> Result<Self>;   // start detached via daemon::spawn_detached, wait ≤ 5 s
    pub async fn existing() -> Result<Option<Self>>;
    pub async fn send(&mut self, m: &ClientMsg) -> Result<()>;
    pub async fn recv(&mut self) -> Result<Option<RuntimeMsg>>;
}
```

Behaviour: one runtime per config dir (`lock_exclusive_with_pid`; loser exits 0); `chdir($HOME)`; logs to `runtime.log`; the runtime owns an `App` with no TUI and runs `tick_host()` on a 16 ms interval plus socket events; same-UID check on accept; `hello` first or the client is dropped; protocol mismatch → `Error` then close (restart allowed only when no live sessions, per spec); `launch` validates env and limit and replies `Launched`; one local frontend per session (a second `attach` sends `Detached{reason:"attached elsewhere"}` to the first); `attach` replies with a restore snapshot built from the session's canonical screen (`terminal_share` frame builder) then streams `Output` from the PTY reader; per-client backlog ≤ 256 KiB → drop + new `Attached` restore; stop reading a client while its target session's input queue is full; `Exited` to the attached client; idle exit and exited-session reaping per spec (test-only env `ATEM_RUNTIME_IDLE_SECS` to shorten); each client handler and each session pump runs in its own task with panics caught (`tokio::task::JoinError::is_panic` → log + end that client/session). Local input marks the session used and counts as terminal input (PtyInput::send) for chat-v1. The TUI process keeps working unchanged in this task (it calls `tick_host()` itself).

Tests: protocol encode/decode round-trips and bounds; in-process server+client over a temp socket: hello, launch two fake agents, attach → restore then output, input reaches the PTY, resize, second attach moves the session, list, stop → exited, backlog overflow → restore, wrong uid can't be faked (skip), protocol mismatch; idle exit with the shortened timeout; `tests/runtime_binary.rs`: the real binary `atem runtime` with temp HOME/XDG_RUNTIME_DIR starts, a second instance exits, `runtime.lock` holds its pid, socket is 0600.

- [ ] tests → implement → verify → commit `feat(runtime): atem runtime hosts sessions behind a local socket`.

### Task 5: Terminal frontends through the runtime

**Files:** `src/cli.rs` (`agent launch|attach|list|stop`), `src/tui/mod.rs`, `src/tui/draw.rs`, `src/tui/terminal_view.rs`, `tests/agent_launch_binary.rs`, `tests/terminal_ui_binary.rs`, `tests/runtime_binary.rs`, AGENTS.md (short section; full docs in step 3).

**Produces:** `tui::run_frontend(client: RuntimeClient, session: SessionId) -> Result<FrontendExit>` — full-screen view of one session: local `VtParser` fed by `Attached.restore` + `Output`, keys/paste/resize sent as `Input`/`Resize`, status row from session summary + `Notice`, prefix keys unchanged (`h`/`m` = detach, `x` = `Stop`, `g` = reclaim via existing terminal-v1 rules on the runtime side — add `ClientMsg::Reclaim{session_id}` if needed and note it in the spec), `[`/`c` history and copy from the local parser. On detach/quit: print one line `Session ses-… is still running. Reattach: atem agent attach ses-… · Stop: atem agent stop ses-…`.

CLI: `atem agent launch <claude|claude-code|codex> [args…]` = `connect_or_start` + `Launch{cwd: current_dir, env: std::env::vars_os(), rows, cols}` + frontend; `attach <id>`; `list` prints `ID  PROVIDER  STATUS  ATTACHED  CWD` plus the runtime's build and protocol; `stop <id>`. Bare `atem` (menu TUI) is unchanged in this step (it still hosts in-process; step 3 moves it) — but it must not open an Astation connection when a runtime is running: if `RuntimeClient::existing()` finds one, the menu TUI runs without Astation and shows a notice (keeps the race out until step 3).

Binary tests updated: launch with a fixture agent starts the runtime; quitting the frontend leaves the session (`atem agent list` shows it); `attach` restores the screen; `stop` ends it and removes Claude's chat dir; argv forwarding and chat hook args as before; `terminal_ui_binary` (control keys, paste, resize, copy) runs through the frontend.

- [ ] tests → implement → verify (+ `./scripts/run-local-dev-tests.sh`, report only the known `atem list` failures) → commit `feat(agent): launch, attach, list and stop through the runtime`.

---

## Self-review notes

- Spec coverage for step 1: runtime process (T4), sessions/ids/limits/env (T1–T2), local frontends and detach (T5), lifetime and isolation (T4), Astation-visible changes for sessions, aliases, routing and mark tasks (T2). Astation operations through the runtime and the replaced-connection backoff are step 2; bare `atem` through the runtime and docs are step 3.
- Risk: Task 1 is a large mechanical refactor; it must not change assertions. Task 2 changes Astation-visible ids (aliases keep old Astation working) — Astation is told in step 3's handoff, and before release.
