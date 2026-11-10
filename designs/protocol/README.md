# Atem protocols

Status: current (Atem v0.8.3, 2026-11-04).

This page lists the protocols Atem speaks, says how the remote protocol
(atem-session) evolved, and where the shared fixtures run. It gives no wire
details: follow the links. [atem-session-v1.md](atem-session-v1.md) is the
contract for everything remote. [AGENTS.md](../../AGENTS.md) describes the
current behavior in detail.

## The protocols

Everything remote travels on Atem's one outbound WebSocket link, either to
Astation on the same machine (`:8080`) or to the relay. Atem opens no port.
The local protocols run over same-user Unix sockets.

| Protocol | Between | Version today | Specified in |
|---|---|---|---|
| atem-session (`session` messages) | Astation, phones, bots (services) and browsers ↔ the Atem host (`atem runtime`): session list, control leases, prompts, receipts, approvals | v1, revision **r9**; **r8** on a host without a device list (**Planned (owner decision 2026-11-08), not implemented:** r9 only) | [atem-session-v1.md](atem-session-v1.md) |
| chat-v1 (`agentChat` messages) | the same clients ↔ an agent's chat; bound to atem-session sessions and leases | v1 | atem-session-v1.md, [../agent-chat-host.md](../agent-chat-host.md) |
| terminal-v1 (`terminal` messages) | the same clients ↔ an agent's shared terminal: screen frames, input, resize | v1 | atem-session-v1.md, [../shared-terminal.md](../shared-terminal.md) |
| atem-ch1 | one remote client ↔ the host: r9's end-to-end encrypted channel; atem-session runs inside it. The router (the relay or Astation's `:8080`) carries its frames in a `channel` envelope | 1 (in the name) | atem-session-v1.md §R9.7, §R9.7a; clients use atem-client ([atem-client-bindings.md](atem-client-bindings.md)) |
| Host work (`host.launch`, `host.work`, `host.messages`, `host.attachments`; stage 1, unreleased: `host.reply`) | the same clients ↔ the host, inside r9 channels: remote launch from approved profiles, directed work, messages and notices, PNG screenshots and Chisel/mark | features of r9 (v0.8.2) | [atem-host-work-v1.md](atem-host-work-v1.md); [../agent-hosting.md](../agent-hosting.md) |
| Selected Station (`stationRoute` messages) | Astation ↔ Atem on the paired link: which Station (relay) Atem connects to | v1 (v0.8.2) | [station-route-v1.md](station-route-v1.md); [../astation-connection.md](../astation-connection.md#station-selection) |
| Relay messages (`relay`) | the host ↔ the relay: host route proof (`host_challenge`, `host_route`), sealed push hints and seen (`push_hint`, `push_seen`, `push_ack`) | part of r9 | atem-session-v1.md §R9.7b, §R9.9 |
| Pairing v1 (`pairing`) | Atem ↔ Astation during `atem pair`: the token-free pairing bootstrap (`hello`, `introduction`, `error`) | v1 | Astation's `designs/protocol/pairing-and-service-authorization.md`; Atem's strict reader is `src/pairing_wire.rs` |
| Local protocol ("local v1") | `atem` commands and the terminal frontend ↔ the background `atem runtime` | v1 | [../agent-runtime.md](../agent-runtime.md) "Local protocol (v1)"; `src/runtime/protocol.rs` |
| Worker protocol | the runtime (the broker) ↔ each `atem worker` (one per agent session) | v1 | `src/runtime/worker_protocol.rs`; ../agent-runtime.md |
| Cred agent socket | `atem` commands ↔ `atem cred-agent`, which holds the unlocked keys | v2 | [../e2e-encryption.md](../e2e-encryption.md) "Keys on disk (atem)"; `src/memory/agent_socket.rs` |

An r8 host has no device list, so it sends no sealed hints: it sends
`push_approval` and `push_resolved` relay messages instead. **Planned (owner
decision 2026-11-08), not implemented:** with r8 admission removed, those two
messages go too. The other
messages on the Astation link (authentication, `credentialSync`, device
verification, key grants, unlock) carry no version number; they
are listed in AGENTS.md ("WebSocket messages") and ../e2e-encryption.md.

## What "v1" means

- **atem-session v1, chat-v1, terminal-v1.** v1 is the message format:
  every message carries `"v": 1` inside its `data`. It has not changed.
  "atem-session v1" is the name of the protocol, not its current version.
- **rN** is the revision of the atem-session contract: its rules and the
  messages it allows. r1 to r7 were revisions of the document only. Since
  r8 the client names the revision in `hello.revision`, and the host
  refuses any other.
- **local v1** is the local protocol's own number. A client and the runtime
  exchange it in `hello`/`welcome`. `atem agent list` shows it as
  `protocol 1`, and `atem --version` showed it as `local v1`. A runtime
  that speaks another local protocol and has no live sessions is restarted
  for the client.
- The **worker protocol** has its own number too (`welcome.worker_protocol`).
  A new build replaces a running runtime only when their worker protocols
  match, so live sessions are never left without a broker that can adopt
  them.
- Pairing v1 and the cred agent's v2 are numbered separately again. Each of
  these numbers changes on its own; none follows the atem-session revision.

## How atem-session evolved

The contract is one document, revised in place. Its base text is r7.3;
appendix "r8" and appendix "r9" replace it where they differ. Older texts
are in git history.

- **r1 to r5 (to 2026-10-15).** The contract was drafted with Astation for
  the session multiplexing design: identities and the binding of a message
  to a session, the session registry, control leases, submissions with
  durable receipts, terminal-v1 and chat-v1 bound to sessions, and the
  shared fixtures. Astation reviewed each draft and accepted r5 on
  2026-10-15. It ran in "compatibility mode": inside the authenticated
  socket of the one paired Astation, with no resume, no browsers and no
  end-to-end encryption (all left to the contract's §9 gate).
- **r6 (2026-10-16).** One session authority, no legacy paths. Every
  remote change to a session is an atem-session message with a binding and
  the lease. The old ops (`agentInput`, `agentPrompt`, voice commands,
  `userCommand`, terminal-v1 `control` and `list`) were removed; they are
  answered `unsupported_version` with no effect. Atem's runtime (the
  `atem runtime` broker, one `atem worker` per session, a durable journal)
  became the host.
- **r7 (2026-10-16 to 2026-10-17).** Approvals: an agent's permission
  prompts reach devices with `control`, which answer them remotely, bound
  to the exact prompt. r7.1: a second `hello` replaces the attachment (a
  client reset after sleep). r7.2: Atem session rules, "always allow this
  command" for Codex, kept by the worker. r7.3: revoking a rule needs
  `control`, not the lease.
- **r8 (drafted 2026-10-17, implemented 2026-10-18).** Revision admission
  (`hello.revision: 8` and `welcome.features`; r7 peers are refused). Chat
  history pages in the conversation's ordered stream, with coverage and
  holes. `receipt.result` (a prompt's turn and reply ids). Chat Send that
  takes the lease with the prompt. Lease-free approval answers (`control`
  is enough; the first answer wins). Submitter principals with a durable
  control fence. One persistence rule: a request is accepted only once its
  record is durable. First released in v0.7.0 (2026-10-19).
- **r9 (signed off 2026-10-19, implemented 2026-10-20, released in v0.8.0
  on 2026-10-31).** Remote clients that reach Atem without the Mac: a
  signed device list pinned at pairing (see
  [../account-trust.md](../account-trust.md)); the end-to-end channel
  `atem-ch1`, routed by the relay or Astation's `:8080`; native members
  (Mac, iPhone, iPad, Android), scoped services (bots) and short browser
  grants; sealed push hints and `seen`; recovery with a 24 h wait. Added
  within r9: the host route proof (the relay holds a proved host's route
  with no Mac online), "relay only" (feature `host.policy`) and, in v0.8.2,
  host work (features `host.launch`, `host.work`, `host.messages`,
  `host.attachments`). r8's
  operations run unchanged inside the channel. A host with a device list
  refuses r8. Atem and Astation passed joint live tests before the release.
  **Planned (owner decision 2026-11-08), not implemented:** every host
  refuses r8, so Atem serves remote sessions only over r9; a host without a
  pinned device list serves none until `atem pair verify` pins one.

Rules:

- A new revision changes the wire contract. Atem, Astation and Astation's
  apps update together.
- No backward compatibility. A host answers a `hello` of any other
  revision with `unsupported_version` and does nothing else. A client
  refuses a host whose `welcome` doesn't carry its revision.
- An addition that changes nothing else is a feature, not a revision. The
  host lists its features in `welcome.features` (r8's nine; r9 adds six). A
  client uses only features the host offered, and a host offers one only
  once its fixtures pass. `host.policy` was added to r9 this way.
- From r8 on, Astation signs off each revision and its fixtures before
  Atem implements it. A correction that changes no wire, fixture or
  behavior is noted in the contract's header, without a new revision.

## Shared fixtures and tests

The shared fixtures are in [fixtures/](fixtures/), one scenario per JSON
file; the format is in [fixtures/schema.md](fixtures/schema.md). Files
without a prefix are the base (r7.x) scenarios, `r8-*` files carry
`"requires": "r8"`, and `r9-*` files carry `"requires": "r9"` (known-answer
vectors, and host, client and relay scenarios). `digest-vectors.json` holds
the canonical-digest vectors. Atem and Astation share the fixtures, so a
change needs both sides. When code and a fixture disagree, the fixture
wins, unless it contradicts the contract text: then stop and report.

| Runner | What it runs | Command |
|---|---|---|
| Core runner (`src/session_protocol/fixtures.rs`) | every base and `r8-*` scenario: host ones against `SessionHost` in a fake runtime (with the memory journal and with the `FileJournal`), client ones against the client machines; reports `r9-*` as not run | `cargo test --bin atem session_protocol::fixtures` |
| atem-client (`crates/atem-client/tests/`) | the r9 vectors, client and relay scenarios (against a reference relay), and host scenarios against a test host | `cargo test -p atem-client -p atem-client-ffi` |
| r9 engine (`src/session_protocol/r9/fixtures_tests.rs`) | the `r9-envelope-*` fixtures in process | `cargo test --bin atem session_protocol::r9::fixtures_tests` |
| Real runtime, r8 (`tests/runtime_fixtures_binary.rs`) | host scenarios against the `atem runtime` binary, real `atem worker`s running a fake Claude Code, and a fake Astation playing the client | `cargo test --test runtime_fixtures_binary` (`ATEM_FIXTURE=<name>` runs one) |
| Real runtime, r9 (`tests/r9_runner/`) | every r9 host scenario: a device list pinned as `atem pair` writes it, clients that speak `atem-ch1` in the envelope, a fake Astation that also plays the relay | `cargo test --test runtime_fixtures_binary r9_fixtures -- --nocapture` (`ATEM_FIXTURE=<name>[,…]`; `ATEM_R9_PARALLEL` runtimes at once, default 6) |
| Bindings | Swift, Kotlin and WASM conformance over the r9 vectors | `./scripts/check-atem-client-bindings.sh [kotlin] [wasm] [swift] [e2e]` |

Notes:

- The real-runtime runners need a debug build on Linux: they drive the
  runtime through debug-only hooks in `src/runtime/test_hooks.rs` (clock
  files, PTY and device-list faults, a state dump). Release builds ignore
  them. CI runs them on every pull request (`.github/workflows/test.yml`,
  the debug-hook step).
- What the real runtime can't express is printed with its reason and runs
  in the core runner or atem-client's tests instead. For r8 that is mostly
  scenarios with more than one attachment (the runtime holds one Astation
  link), journal faults and history eviction; an r8 scenario on that list
  that starts passing fails the test until it is taken off. For r9 it is a
  few items (fixed handshake bytes, a stalled link writer, a host outside
  the vectors).
- **Planned (owner decision 2026-11-08), not implemented:** with r8 admission
  removed, the real-runtime r8 runner (a fake Astation sending a clear `hello`
  on the link of a host with no device list) has no host to talk to; its
  scenarios run inside r9 channels, as the r9 runner's do.
- More r9 behavior in the real runtime, beyond the fixtures:
  `tests/r9_*_binary.rs` (admission, several devices, push, services,
  two enrolled hosts, revoked grants, host route proof) and
  `tests/membership_binary.rs`. `tests/approvals_real_agents.rs` answers
  approvals with the real Claude Code and Codex
  (`ATEM_REAL_AGENTS=1 cargo test --test approvals_real_agents -- --ignored --nocapture --test-threads=1`;
  real API calls).
- Conformance of Astation's own Swift client is Astation's. Its apps link
  atem-client through the bindings.

### The r9 multi-device harness

`tests/r9_harness.rs` runs one real host and simulated phones, bots and
browsers, all through atem-client. Each client goes through admission, the
session list, a lease, a prompt to its turn's end, an approval with sealed
push hints opened per device, a `seen` and a lease-free answer. The run
prints a transcript.

```bash
cargo test --test r9_harness -- --nocapture
# client counts (defaults 2, 1, 1) and a JSON-lines copy of the transcript
ATEM_HARNESS_PHONES=3 ATEM_HARNESS_BOTS=2 ATEM_HARNESS_BROWSERS=2 \
  ATEM_HARNESS_OUT=/tmp/r9-harness.jsonl cargo test --test r9_harness -- --nocapture
```

It is a test target only, never in a release build. Limits: Linux only,
the fake Claude Code only (no fake Codex), a fixed flow, and no entry point
for Astation's own router or relay (its fake Astation plays both).

For Astation, who doesn't build Atem, `.github/workflows/r9-harness.yml`
packages a prebuilt copy with `./scripts/package-atem-r9-harness.sh <ver>
<out>` on pushes to `main` and on pull requests that touch the sources. The
workflow artifact `atem-r9-harness-NONPRODUCTION-<version>-linux-x86_64`
holds the harness binary, an `atem` built for the harness only (never
install it), the fake agent and `run-harness.sh`, plus a sample transcript,
a `SOURCE.json` pin and `SHA256SUMS`. It is non-production test tooling.
Check the sums and the pin, then run `./run-harness.sh` on Linux x86_64
with python3 (the same `ATEM_HARNESS_*` variables apply). There is no macOS
build.
