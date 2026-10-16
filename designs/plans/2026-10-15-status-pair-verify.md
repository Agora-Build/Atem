# atem status, pair, pair verify, cred (Atem CLI workflow) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development.

**Goal:** Implement the approved CLI workflow from `designs/session-multiplexing.md` §1 that needs no new wire contract: `atem status` (+ `atem cred status` alias), `atem pair` as a no-op when paired, `atem pair verify`, and `atem cred unlock` that never starts pairing/verification.

**Spec:** `designs/session-multiplexing.md` §1 and §11 rows 2–5 (copy on branch `feat/agent-runtime`; hosted at https://truck.netbird.cloud:58310/session-multiplexing.md). Authoritative wording is quoted in Task 1.

## Global Constraints

- Branch `feat/status-pair-verify` from `main`. Commits end with a blank line and `🤖 Built with SMT <smt@agora.build>`. Never push.
- `atem status` is read-only and works offline: no network, no Astation connection, never starts the key agent (query only a running one), never writes files. Cached remote information is marked stale. User-facing label `Credentials`, never `Keys`.
- `atem pair` on an already paired profile (any paired credential entry or saved Astation session) prints the status plus `Already paired. Verify this device: atem pair verify · Replace the pairing: atem unpair, then atem pair` and exits 0 without connecting, changing identity, trust, keys, sessions or files. Applies also when verification is incomplete.
- `atem pair verify` requires an existing pairing (else: `Not paired. Run atem pair first.`, exit 1). Already validly verified with the paired Astation → `Already verified (safety code …).`, no connection, exit 0. Revoked by that Astation → no verification; message: `This device was revoked by Astation <id>. Run atem unpair, then atem pair, to set it up again.` exit 1 — verification never moves keys aside or replaces trusted keys. Otherwise run the existing verification ceremony (`src/pair_verify.rs` + the verification half of `run_pair`) on a connection authenticated with the saved session (no pairing code, `allow_pairing = false`); cancellation/interruption keeps the pairing.
- `atem pair` (not yet paired) keeps today's pairing flow, then runs verification as today (first-time setup stays one command); the revoked-keys-moved-aside branch is removed from `atem pair` (now only reachable after `atem unpair`, where the device has no pin for that Astation).
- `atem cred unlock` on an unverified profile: `This device isn't verified. Run atem pair verify first.` exit 1, no connection. `atem cred lock` unchanged (offline, always allowed). Neither starts pairing or verification.
- `atem cred status` prints exactly what `atem status` prints (one implementation).
- Never rustfmt `src/cli.rs`, `src/main.rs`, `src/websocket_client.rs`, `src/memory/mod.rs`, `src/memory/crypto.rs`, `src/memory/secrets.rs`; check others with `--check` first. Never project-wide `cargo fmt`.
- Never run the installed `atem`, never touch the real `~/.config/atem`, the user's key agent or running atem processes; tests use temp config dirs (existing patterns in src/memory tests and `cli.rs` tests).
- Full `cargo test` reading every `test result` line; clippy not above `main`'s count (measure first).

### Task 1: status, pair no-op, pair verify, cred gating

Files: `src/cli.rs` (commands, `run_pair`, new `run_status`, `PairCommands::Verify`), new `src/status.rs` (state gathering + rendering, pure and testable), `src/memory/unlock.rs` (cred status → status; unlock gate), `src/pair_verify.rs` (verification entry usable without pairing), tests; AGENTS.md / README.md / npm/README.md command lists.

`src/status.rs` interface:

```rust
pub struct StatusReport {
    pub account: Line,        // "signed in" (SSO or paired credentials present and not expired) | "signed in (expired)" | "signed out"
    pub pairing: Line,        // "paired (<astation id>)" | "not paired"
    pub verification: Line,   // "verified (safety code …)" | "not verified" | "revoked by <id>" | "—" when not paired
    pub credentials: Line,    // "unlocked" | "locked" | "no key agent running" (=locked) | "not set up"
    pub authorization: Line,  // "unknown (stale)" until the freshness contract lands — never "fresh" without proof
    pub relay: Line,          // "unknown (offline check)" — status never connects
    pub local_agents: Line,   // "unknown" until the runtime lands (feat/agent-runtime) — or a count if a runtime answers without starting it
}
pub struct Line { pub value: String, pub stale: bool }
pub fn gather(config_dir: &Path) -> StatusReport;   // reads files + a running key agent only
pub fn render(r: &StatusReport) -> String;          // the aligned block from the spec, "(stale)" suffix when stale
```

Output format (labels exactly):

```text
Account:        signed in
Pairing:        paired (astation-…)
Verification:   verified (safety code MN3H-A74N-FJE4)
Credentials:    locked
Authorization:  unknown (stale)
Relay:          unknown (stale)
Local agents:   unknown
```

Tests (first): render labels/alignment; gather on temp config dirs: nothing → signed out / not paired / — / not set up; paired+unverified; paired+verified; revoked; `atem pair` when paired makes no connection (point ASTATION_WS at a closed port and assert it never dials, e.g. via a listener that must not get a connection) and leaves files unchanged (hash the config dir before/after); `pair verify` already verified → no connection; not paired → error text; revoked → error text, no files changed; `cred unlock` unverified → error text, no connection; `cred status` output == `status` output; CLI parsing for `status`, `pair verify`.

- [ ] tests → implement → verify → commit `feat(cli): atem status, pair verify, and pair/unlock that never re-pair`.
