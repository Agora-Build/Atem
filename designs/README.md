# Atem designs

Design only: how Atem works today, and what is planned. Implementation plans,
review replies and handoffs were removed once their work shipped; they are in
git history. AGENTS.md at the repository root describes the current behaviour
in detail and wins where a design differs.

A design that also describes work not built yet marks it: a sentence or
bullet starts with **Not implemented:**, a heading ends with "(not
implemented)", and a design with nothing built says so in its status line.

## Current design

| Document | What it covers |
|---|---|
| [protocol/README.md](protocol/README.md) | The protocols Atem speaks, how atem-session evolved (r8, r9), where the shared fixtures run |
| [protocol/atem-session-v1.md](protocol/atem-session-v1.md) | The atem-session wire contract (the r9 appendix is authoritative on a host with a device list) |
| [protocol/atem-client-bindings.md](protocol/atem-client-bindings.md) | atem-client, the shared client core, and its Swift, Kotlin and WASM bindings |
| [protocol/atem-host-work-v1.md](protocol/atem-host-work-v1.md) | Host work in r9 channels: remote launch, directed work, messages, screenshots and Chisel/mark |
| [protocol/station-route-v1.md](protocol/station-route-v1.md) | How Astation tells Atem which Station (relay) to use |
| [agent-runtime.md](agent-runtime.md) | `atem runtime` and its `atem worker`s: sessions, leases, receipts, the local protocol, Astation operations |
| [shared-terminal.md](shared-terminal.md) | The shared terminal (terminal-v1): canonical-screen frames, credit, keys |
| [agent-chat-host.md](agent-chat-host.md) | Agent chat (chat-v1) on the host: Claude and Codex adapters, status, approvals |
| [agent-chat-api.md](agent-chat-api.md) | Developer guide for chat clients |
| [agent-hosting.md](agent-hosting.md) | Remote launch from `runtime.toml` profiles, messages, notices, directed work and Chisel/mark on the host |
| [agent-collaboration.md](agent-collaboration.md) | Stage 1: local selectors and tags, durable messages, verified context, correlated results and optional launch on message (unreleased) |
| [astation-connection.md](astation-connection.md) | How Atem reaches Astation: local then relay, authentication, pairing, relay only, Stations |
| [account-trust.md](account-trust.md) | Account trust for r9: the signed device list, recovery, the Recovery Kit |
| [e2e-encryption.md](e2e-encryption.md) | End-to-end encryption of memory, skills and vault; credentials (`atem cred get`, planned) |
| [atem-memory.md](atem-memory.md) | Atem Memory: facts and skills shared across agents and machines |
| [vault.md](vault.md) | The shared, versioned context store for handing work between agents |
| [atem-identity.md](atem-identity.md) | `instance_id` and the relay `atem_id` |
| [atem-core.md](atem-core.md) | The atem-core token library and its C ABI |
| [convo.md](convo.md) | ConvoAI: `atem serv convo` and the `atem config convo` wizard |

## Planned

| Document | What it covers |
|---|---|
| [agent-hosting.md](agent-hosting.md) | OS service and boot startup, remote launch when work arrives, durable delivery through the Station (outbox, replay, offline senders) |
| [delegated-host-work.md](delegated-host-work.md) | Agreed 2026-11-08, nothing built: delegated host work (Atem owns accepted tasks of covered integrations, native members and host senders: control records, the revocation gate, attempts and recovery, unknown-outcome alerts) and stages 2-3 of agent collaboration, host-to-host senders (signed projects, Revoke/Readmit, host encryption keys, the sealed Station mailbox), plus prompt framing for every rendered prompt; diagram: [delegated-host-work-flows.html](delegated-host-work-flows.html) |
| [agent-collaboration.md](agent-collaboration.md) | Parts of local collaboration not built: launch on message for Codex, atomic write-and-notify in the Station, a sandbox for agents (stages 2-3 are in delegated-host-work.md) |
| [build-by-talk.md](build-by-talk.md) | Build by Talk: get the whole project clear by talking, with tool calls to the coding agents (Astation and Atem; nothing built) |
| [e2e-encryption.md](e2e-encryption.md) | Credentials (`atem cred get` and the rest), device-signed writes, the recovery secret, auto-unlock |
| [agora-account-grouping.md](agora-account-grouping.md) | Proposed: merge Astations under one Agora login (opt-in) |

## Test data

[fixtures/](fixtures/) holds agent hook fixtures, and
[protocol/fixtures/](protocol/fixtures/) the shared protocol fixtures. Tests
read both, so they stay with the designs they check.
