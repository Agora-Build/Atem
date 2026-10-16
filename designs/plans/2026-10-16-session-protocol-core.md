# atem-session v1 core and shared fixture runner Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development.

**Goal:** Implement the accepted atem-session v1 contract (r5) as a transport-free Rust core — wire types, canonical digest, client state machines and the host authority (registry, leases, receipts) — and run every shared fixture in `designs/protocol/fixtures/` against it.

**Architecture:** `src/session_protocol/` is pure logic with injected time, journal and PTY/dispatch effects, so the fixtures drive it deterministically. The runtime (later plan) wires it to real PTYs, workers and connections; nothing here touches sockets or files except the journal implementation.

**Spec:** `designs/protocol/atem-session-v1.md` (r5, accepted for compatibility mode) and `designs/protocol/fixtures/schema.md`. Product context: `designs/session-multiplexing.md`.

## Global Constraints

- Branch `feat/session-protocol` (from `main` + the accepted protocol). Commits end with a blank line and `🤖 Built with SMT <smt@agora.build>`. Never push.
- Compatibility mode only: no resume, no browser clients, no account-wide access, no relay-confidentiality claim; §9 inputs (`resume_proof`, freshness) are refused (`unauthorized`/`forbidden`), never stubbed as trusted.
- Representation rules of §1 exactly (UUID v4 lowercase, `ses-`+12 `[a-z2-7]`, opaque ids 1–128 `[A-Za-z0-9._:-]`, counters 0..=2^53−1 rejecting overflow, ms times, lowercase hex SHA-256, size bounds checked before allocation, duplicate keys rejected at any depth).
- Digest = SHA-256 of RFC 8785 JCS over the supported domain; must pass every `digest-vectors.json` vector and reject every `must_reject` input.
- Expiry is `now >= deadline`; authority uses an injected monotonic clock only.
- Every fixture file runs in `cargo test` through a data-driven harness that reads the JSON at test time (all files in the directory; a new fixture needs no Rust change). Wire messages are decoded with the real wire types (strict).
- Never rustfmt `src/app.rs`, `src/main.rs`, `src/cli.rs`, `src/websocket_client.rs`, `src/memory/{mod,crypto,secrets}.rs`; new files may be formatted. Never project-wide `cargo fmt`. No new dependencies unless unavoidable (serde_json with `preserve_order` off is fine; implement JCS and duplicate-key detection in-crate).
- Full `cargo test` reading every `test result` line; clippy not above main's count.

### Task 1: wire types, strict decoding, canonical digest

Files: `src/session_protocol/{mod.rs,wire.rs,canonical.rs}`, `src/main.rs` (`mod session_protocol;`), tests.

- `wire.rs`: serde types for every op in §3–§7 (`hello`, `challenge`, `resume_proof`, `welcome`, `list`, `sessions`, `session_changed`, `acquire`, `renew`, `release`, `lease`, `lease_released`, `lease_changed`, `submit`, `receipt`, `receipt_query`, `receipts`, `error`), the `binding`/`target` objects, descriptors (all fields required), receipt states/kinds, error codes; the terminal-v1/chat-v1 `data.binding` field shape. `decode(bytes) -> Result<Envelope, DecodeError>`: size bound, strict JSON (duplicate keys at any depth, non-integers/exponents where integers are required, unsafe integers, lone surrogates, invalid UTF-8 → errors), field validation per §1. `encode(&Envelope) -> Vec<u8>`.
- `canonical.rs`: `jcs(&Value) -> Result<String>` (UTF-16 key order, ES string escaping, safe integers only, no floats) and `payload_digest(&Value) -> String`; a strict parser front end used by both.
- Tests: every `digest-vectors.json` vector (canonical + sha256) and `must_reject` entry; every wire message appearing in any fixture's `json` decodes and re-encodes to an equal JSON value; targeted negative cases per §1 row.
- Commit `feat(session-protocol): wire types, strict decoding and canonical digest`.

### Task 2: client state machines + client-side fixtures

Files: `src/session_protocol/client.rs`, `src/session_protocol/fixtures.rs` (harness), tests.

- `LeaseClient` (§5 reply-correlation rules 1–5, deadline = send time + `ms_left` capped, repeat-acquire min rule, `now >= deadline` expiry, `controls()`, `input_enabled()`), `RegistryClient` (§4 runtime-epoch fencing, per-attachment `seq`, gap → `list`, resync discard, duplicates ignored, removal without resurrection, fixed `runtime_gen` per epoch).
- Harness: loads all `fixtures/*.json`, runs `side:"client"` scenarios against these machines (`deliver_to_client`, `send` records outgoing requests and their send times, `advance_ms`, `assert_client`), and host scenarios via Task 3 (until then they're listed and skipped with a visible count).
- Commit `feat(session-protocol): lease and registry client state machines with shared fixtures`.

### Task 3: host authority + host-side fixtures

Files: `src/session_protocol/host.rs`, `src/session_protocol/journal.rs`, harness, tests.

- `SessionHost` (pure): host context (account, device, trust gen, runtime gen/epoch), attachments with permissions and `upgraded`, sessions (id, process_gen, descriptor fields, managed flag), the lease authority per session (§5: 15 s, takeover, repeat acquire, local input revocation with input-epoch bump, release, expiry on `now >= deadline`), legacy mapping (§0: terminal-v1 subscribe/control/resize/stop/input with stream and generation checks; unscoped legacy mutations refused for managed sessions), registry snapshot/changes with per-attachment `seq` and `removed`, submissions and receipts (§6: immutable request binding, host-computed digest, admission checks, state transitions incl. dispatch-failure rules, `receipt_query` scoping, retention bounds), errors (§7, no disclosure).
- Effects are returned as values (`Effect::PtyWrite{session, bytes, input_epoch}`, `Resize`, `Stop`, `Dispatch`, `Send{attachment, msg}`), so the harness counts them and the runtime will execute them. The PTY write boundary re-checks the input epoch (`apply_write(session, epoch)`).
- `Journal` trait (append receipt transition, fsync point, load on restart) + `MemJournal` with failure injection (`fail_next_fsync`); restart reloads receipts and applies the §6 crash rules.
- Harness runs every `side:"host"` scenario (all actions in schema.md incl. hold/deliver, crash, restart, reconnect, failure injection) asserting messages and counters.
- Commit `feat(session-protocol): host authority — registry, leases and durable receipts — with shared fixtures`.
