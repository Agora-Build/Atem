# Atem Sessions, Multiplexing, and Device Trust

Date: 2026-10-15

Status: product decisions and all six initial defaults approved by the user on
2026-10-15. The consolidated CLI workflow below is also approved. Architecture
recommendations and remaining engineering specifications are identified below.
This approval recorded the design (2026-10-15); it has since been
implemented (the runtime broker and workers, leases and receipts,
`atem pair verify`, `atem status`) and released in Atem v0.8.0 (2026-10-31); AGENTS.md describes the
current behaviour.

## 1. Product decisions

Enroll Atem once per machine, OS user, and account profile. Further launches and
reconnects reuse that approved identity through automatic authentication.
Account login, device verification, and key unlock are separate states; a locked
cred agent or expired login must not automatically mean "pair again."

`atem pair` is a no-op for an already paired profile: report its current
pairing/verification status without changing identity, trust bindings, keys, or
sessions, and without starting another pairing or verification exchange.
Changing or replacing a pairing requires explicit `atem unpair` first.
`atem pair verify` completes or retries verification of the existing binding
without re-pairing. Unpairing preserves account data and running agents while
invalidating the old host authorization as specified in the recovery lifecycle
below.

Approved CLI workflow to implement:

| Command | Purpose |
| --- | --- |
| `atem status` | Unified account, pairing, verification, credential availability, authorization freshness, connectivity, and local-agent status. |
| `atem pair` | Establish a pairing; report status without changes when already paired. |
| `atem pair verify` | Explicit safety-code verification of the existing binding with native approval. |
| `atem cred unlock` | Unlock protected keys using existing verified trust; native Touch ID or password approval may be required. |
| `atem cred lock` | Clear unlocked key material locally, including offline, without requiring verification or native approval. |
| `atem unpair` | Explicitly remove the binding and invalidate its authorization, preserving account data and running agents. |

`atem status` is read-only, works offline, and marks cached remote information
as stale. Use the user-facing label `Credentials`, not `Keys`:

```text
Account:        signed in
Pairing:        paired
Verification:   verified
Credentials:    locked
Authorization:  fresh
Relay:          connected
Local agents:   2 running
```

Credential availability is separate from pairing and verification. Locking clears
unlocked key material; it does not delete saved credential records. Keep
`atem cred status` as a compatibility alias to the unified status implementation;
do not add a separate `atem pair status` command.

`atem pair verify` requires an existing pairing and is a no-op for a currently
valid verified binding. Cancellation or interruption preserves pairing and
allows an explicit safe retry. Revocation or changed identities require the
applicable recovery flow; verification cannot silently replace trusted keys.
Neither `atem cred unlock` nor `atem cred lock` starts pairing or safety-code
verification. Unlock on an unverified profile stops with an instruction to run
`atem pair verify`.

Local `atem agent launch` remains usable without Astation pairing/verification.
Remote viewing/control requires verified, fresh authorization and its applicable
permissions/lease. Memory/vault access additionally requires its grants and,
for encrypted content, available unlocked keys. Verification does not itself
turn account encryption on; the signed migration lifecycle remains separate.

The design supports:

- Multiple independent Codex/Claude sessions, including several of one provider,
  with their original processes, projects, conversations, and unfinished input.
- Multiple trusted native Astation clients viewing the same Atem session and
  switching between sessions without re-pairing. Native iOS/Android clients can
  participate alongside Macs.
- Any authorized, verified native Astation can access enrolled Atem hosts under
  the same account's trust, subject to host/session permissions. Enroll each
  native device and host once; do not pair every Astation-Atem combination or
  each independent agent process.
- A web companion authorized by a trusted native Astation scanning its QR code.
  Web is not a standalone Astation or a permanent trusted device.
- Account recovery followed by explicit local Atem unpairing, pairing, and fresh
  verification when no trusted native device remains.
- Manual device removal in Settings. Recovery never automatically removes an
  Astation ID. Account data and surviving encryption material remain intact.
- Keep Astation's authenticated direct WebSocket connection on port 8080,
  alongside relay connections, including for Atem and Astation on the same host.
  Multiplexing does not require relay-only connectivity.

Approved initial control policy: multiple viewers, one active controller per
agent session. The accepted defaults cover enrollment authority, control transfer,
browser independence and lifetimes, retention, and offline authorization.

`atem pair` currently establishes a relationship with an Astation through the
relay. The relay provides discovery and routing; it does not approve device
keys. Account login alone must not authorize an existing host or release its
keys.

Direct and relay connections are transports for the same identity, session
registry, permissions, control leases, and request receipts. Keep their adapters
thin; do not introduce separate pairing, session, or control implementations for
each path. A direct connection does not grant trust or bypass authorization,
revocation, or confidentiality requirements.

Same-host direct connections can remain usable during relay/internet outages
while locally validated authorization remains valid under the agreed freshness
policy. A connection switch authenticates the new transport and resynchronizes
the original session without re-pairing, reclaiming expired control, or replaying
input. Simultaneous direct/relay delivery uses the same submission deduplication.
Runtime-to-worker local IPC is separate from Astation's port-8080 listener.

## 2. Identity and authorization

| Identity or generation | Purpose |
| --- | --- |
| Account ID | Stable data ownership, independent of email, device removal, or relay routing. |
| Atem device/profile ID and keys | Persist across launches for one OS user/account profile. |
| Astation device ID and keys | Separate protected identity for each native installation. |
| Host trust generation | Changes durably on authorized unpair/rebind; invalidates old remote grants. |
| Agent session ID and process generation | Address one original session and distinguish a replacement process. |
| Runtime and transport generations | Distinguish broker restarts and socket replacements from device trust. |
| Controller session and lease epoch | Identify the attachment currently allowed to operate a session. |
| Browser grant and ephemeral key | Bind one limited companion authorization to one browser session. |

Commands target the exact account, Atem device, host trust generation, agent
session, and process generation. Conversation and request IDs stay explicit.
Never route a delayed command to whichever agent happens to be selected.

Only trusted native Astations explicitly authorized to manage devices may
approve new native controllers. Enrollment requires fresh Touch ID or password
approval. Browser companions and Atem sessions cannot enroll controllers.
Recovering an existing Atem host still requires local unpair, pair, and verify.

Recommended enrollment mechanism: an authorized native device approves another
native device's actual keys and issues account-bound, scoped authorization.
Atem validates that authorization against retained trust and authenticates each
connection. This avoids pairing every controller with every agent session.
Each native device keeps its own private keys; devices do not clone one identity.
Safety codes are derived locally from the verification transcript and actual
endpoint keys. A relay-supplied code or approval cannot establish trust.

The cryptographic trust anchor, membership/certificate format, and mechanism for
assigning management authority remain engineering specifications. View/control
permission does not imply enrollment authority. Existing pairwise pins cannot
silently become account-wide authority. A host must explicitly accept the
account's enrollment authority before account-wide native access applies;
matching relay account IDs alone is insufficient. Approved native clients should
reach Atem without the original approving Mac acting as a permanent forwarding
process.

## 3. Runtime and process recovery

Recommended architecture: one shared runtime per OS user/account profile owns
connection management, device/cred-agent access, and the session registry.
Individual `atem` launches attach through owner-restricted local IPC.
Concurrent launches must elect one owner without displacing a live runtime.
Pairing, unlock, sync, and short-lived commands use that shared ownership.

Each independent session worker owns its original agent process, PTY, output
collection, and submission journal. An existing Atem host can become a worker
without replacing its agent. A broker crash or frontend exit must not terminate
those workers or close their PTYs. OS users and account profiles remain isolated.

| Failure | Recovery behavior |
| --- | --- |
| Connection loss | Authenticate a new connection and resynchronize the existing session. |
| Shared runtime crash | Surviving workers re-register through authenticated local IPC; preserve their original processes. |
| Worker/agent crash or machine reboot | Show Interrupted or Recovery Required. Offer an explicit provider-supported resume when available. |

Worker recovery validates session identity, process generation, and process-start
metadata; a PID alone is insufficient. A registry file or saved history cannot
prove that an agent is alive. Provider resume creates a new process generation
and invalidates old leases/actions. Never replay a transcript into a new process
and present it as the original live session.

Platform supervision and worker adoption mechanisms remain implementation choices.

## 4. Viewing and control

The Atem host enforces a renewable control lease per agent session, expiring
after 15 seconds without renewal or earlier when its authorization expires.
Multiple authorized clients can read output, history, and activity, but only the
current controller may submit prompts or terminal input. Interrupts, restarts,
and provider approvals also require their applicable permissions. Holding a
lease never automatically approves a provider permission request.

Different clients may control different sessions on the same machine. A Mac
could operate Codex while a phone operates Claude, with both viewing both.

Lease acquisition, transfer, expiry, and revocation serialize at the host. Every
mutation path, including chat, terminal, and future APIs, checks the same target,
controller identity, lease epoch, and permissions. Terminal resize follows the
shared terminal policy. Delayed input from an old owner or process is rejected.

Take Control explicitly transfers ownership and leaves the previous controller
as a viewer. Local terminal input takes priority and transfers control locally,
invalidating the previous remote lease before accepting conflicting input.
Disconnects expire control within the 15-second renewal window while agents
continue running. Reconnect does not replay input or reclaim an expired lease
automatically. Lease transfer never restarts an agent or resubmits accepted work.

Renewal scheduling and the UI presentation of ownership changes remain engineering
details within these approved rules.

## 5. Command receipts and retained history

A session worker durably records a high-level submission before acknowledging
acceptance. Its request ID binds the exact target and payload digest; duplicates
return the recorded outcome or are rejected. The same ID with different content
is rejected. Broker/socket delivery alone is not durable acceptance.

Accepted, executing, completed, rejected, and outcome-unknown are distinct.
If dispatch occurs before a crash and the outcome cannot be recovered from the
original worker/provider, report uncertainty without resubmitting. Exactly-once
external effects cannot be guaranteed across arbitrary process crashes.
An admitted task may continue after controller disconnection or lease expiry;
future mutations and cancellation require current authorization.

Raw terminal keystrokes are a live stream, not a durable task queue. Never replay
uncertain input after reconnect. Reattachment queries session state, history,
and request outcomes rather than starting another conversation.

Approved retention defaults:

| Data | Retention |
| --- | --- |
| Request IDs, payload digests, and command outcomes | Entire active session lifetime, then seven days after closure. |
| Atem-owned structured conversation history | Thirty days after closure, with configurable disk limits and export/delete controls. |
| Raw PTY output | Bounded scrollback with visible truncation. |

Do not evict deduplication receipts while a session accepts submissions. Refuse
new admission explicitly if its receipt limit is reached. Closed/expired
sessions reject later submissions, including after old receipts are deleted.

Protect persisted records with owner-only access and encrypt sensitive content
under the approved local key policy. Unavailable keys do not permit plaintext
fallback. Retention controls apply to Atem-owned records, not silent deletion of
provider transcripts. Keep structured user/agent/tool messages separate from
terminal repaint output. Memory, skills, vaults, and saved credentials retain
their separate preservation rules. Storage engine and disk budgets remain
engineering specifications; the retention durations above are approved.

## 6. Web companion: native-scanned QR authorization

1. The browser tab generates a fresh ephemeral key and a short-lived pending
   request, then displays its QR code.
2. A trusted native Astation scans and validates the request. Scanning does not
   automatically open arbitrary URLs or grant access.
3. Native Astation shows the request and lets the user select an authenticated
   Atem host, exact agent session, permissions, and duration. Browser labels and
   requested targets are untrusted hints. The user explicitly approves, using
   local device authentication where required.
4. The native client authorizes the exact browser key, request/challenge,
   account, host trust generation, agent/process, scope, and expiry. The browser
   proves possession of its key through an authenticated bootstrap. The
   receiving trusted endpoint validates the issuer and grant; relay approval
   alone is insufficient.

Approved default: view access. Operation additionally requires explicit
control permission and the current session lease. Grants do not enroll devices,
release vault keys, administer encryption, or expand to other agents. Selecting
another target requires new native authorization, not new Atem enrollment.
Remote control still permits actions within the controlled agent's authority;
a scoped grant is not a sandbox around arbitrary shell commands.

QR requests expire two minutes after creation; approved browser grants expire
one hour after issuance, or earlier on revocation or loss of underlying
authorization. Requests and grants have separate lifetimes. Requests are consumed
atomically. Retries or repeated scans cannot mint extra grants. Changed keys/targets/accounts,
cancellation, expiry, or revocation invalidate pending approval, including late
local-authentication callbacks. Native Astation lists active companion grants
and offers revoke/disconnect.

The reviewed bootstrap must authenticate both directions. Public request IDs
and keys alone do not authenticate the return approval. QR payloads must not
contain account credentials, long-term keys, recovery material, or usable access
grants. Any one-time out-of-band bootstrap secret belongs only in the reviewed
handshake and must stay out of relay traffic, URLs, logs, and stored history.

Approved initial storage is tab memory only: reload/close requires a new QR
authorization. A short reconnect within the same tab may resume a still-valid
grant with fresh connection authentication, without replaying submissions.

After approval, the browser connects through the relay using its scoped grant;
the approving native Astation need not remain online or forward traffic. Closing
that native app does not itself revoke the grant. Atem validates the grant and
its issuer, permissions, expiry, revocation state, and any current control lease.

QR authorization limits browser authority; it does not prove that delivered
JavaScript is trustworthy. A compromised page could substitute another browser's
QR or misuse its grant. Passkeys do not fix that code-delivery boundary.

## 7. Account recovery and data preservation

When no trusted native device remains:

1. Recover login to the same account and set up a new native Astation. Login
   recovery does not approve that device on existing Atem hosts.
2. Use independent local OS access to each host to unpair the Atem profile.
   Commit a new host trust generation and invalidate old controller sessions,
   browser grants, leases, pending approvals, and input/output routes.
3. Pair the host with the new native Astation, compare safety codes, and complete
   explicit approval and cryptographic verification. Remote viewing/control stay
   disabled until verification is durably committed.
4. Reauthorize other native clients and companions under the new trust binding.

This is once per host/profile, not per agent process. Interrupted recovery stays
unpaired/unverified across restart. Without independent host access, the recovered
account has no takeover path through relay administration or a browser QR.

| Preserve | Invalidate |
| --- | --- |
| Memory, skills, vault entries, and their histories | Old host pairing/session authentication tokens |
| Saved provider/API/SSO service credentials, subject to provider expiry/revocation | Old controller memberships and leases on that host |
| Surviving account/storage keys, encrypted key blobs, and recovery metadata | Browser grants and pending remote approvals |
| Existing account ID, local agents, history, and command receipts | Old trust-bound routes and stale queued remote input |

Unpair/re-pair must not create an empty data account, move records to a new
namespace, overwrite data, or change signed encryption state. Retain historical
signature metadata needed to validate old records without authorizing new actions.
Local agent work can continue independently of remote trust reset.

Retained encrypted data requires its original available/unlocked keys or
cryptographic recovery material. Login recovery and fresh verification do not
reconstruct lost keys. Preserve ciphertext and report missing keys explicitly.

## 8. Manual device management

Recommended location: Settings > Security > Devices, linked by Manage Devices
from Accounts. Show device name, exact Astation ID, platform, current-device
badge, and last-seen/connection status. Presence is informational, not proof of
cryptographic trust.

Provide Remove from Account for an individually selected device. Confirmation
names the device/ID and explains that service access is revoked while memory,
vault data, and saved credentials remain. Cancellation changes nothing. Require
authorized account-owner access and fresh authentication where policy requires;
no approval from a lost device is needed.

Removal is optional and manual, during ordinary account management or after
recovery. Account recovery, login, re-pairing, and time offline never remove an
Astation ID automatically. Device removal is not a prerequisite for local host
trust repair.

Revoke the selected registration, service routes, and associated companion
sessions. Keep a durable revocation record so deleting a registration cannot
reopen automatic first-use trust. Preserve the stable account and all data;
re-adding a device requires explicit authorization.

This service-side operation does not replace local host unpairing or new-device
verification, including for direct connections outside relay control.

## 9. Security boundaries

The relay transports messages and enforces service access; endpoints authorize
device trust, control, encryption state, and key use. Relay-supplied identities,
labels, presence, counters, and acknowledgments cannot create that authority.

Live terminal output, prompts, replies, and control messages require reviewed,
authenticated end-to-end encryption before claiming relay confidentiality.
Storage E2EE, HMAC message authentication, and relay-terminated HTTPS/WSS do not
provide that guarantee. Bind handshakes and messages to endpoint keys, account,
roles, permissions, fresh context, and exact target/generations; reject tampering,
replay, substitution, and downgrade.

Approved offline authorization window: at most 24 hours after the last validated
trust/revocation update. During this window, direct access still requires valid
endpoint authentication, membership, permissions, and any applicable grant or
lease. Shorter authorization expiries and known revocations take effect sooner.
At the freshness deadline, pause further Astation viewing and control until a
valid refresh; keep agents and the local terminal running. A reconnect, relay
presence report, or replayed trust snapshot cannot extend the window.

Signed membership needs bounded freshness and revocation rules. A valid old
signature does not prove no newer revocation exists. Persist version high-water
marks and freshness deadlines across restarts, and reject stale/unknown
authority for both viewing and mutation. The protocol must define an authenticated
freshness proof and conservative handling of clock changes; the relay cannot
renew authority on its own. Account recovery cannot
instantly change trust on an offline host or through a relay withholding updates;
local unpair is the definite host-side cutoff. Revocation also cannot erase
plaintext, credentials, or keys already copied to a removed device. Protecting
future data after key exposure requires a separate rotation/rekey policy.

Multiple controllers do not automatically become enrollment or encryption-state
authorities. Initially preserve the existing approved encryption authority,
signed-state checks, and durable/idempotent migration completion lifecycle.
Authority transfer and encrypted-data recovery require separate specifications.
An accepted migration report must not depend on its sender staying connected.

Native mobile clients protect their own keys using platform-secured storage and
hardware protection where supported. Local biometrics/device authentication
approve local key use; the enrollment protocol establishes remote endpoint trust.

## 10. Ownership and remaining engineering specifications

| Area | Owner |
| --- | --- |
| Shared runtime, session workers, receipts, and host control enforcement | Atem |
| Native trust approval, session/control UI, and manual device management | Astation |
| Distinct controller routing, fanout, and replica consistency | Relay |
| QR requests, scanning, and scoped companion authorization | Astation and webapp |
| Trust, revocation, encryption, and recovery wire contracts | Joint protocol design |

All six product defaults are accepted. No product confirmation remains for the
choices recorded in this document. Before implementation, specify:

- Cryptographic trust anchor, initial enrollment/bootstrap, management-authority
  assignment, membership format, and durable host unpair/rebind protocol.
- Authenticated freshness proofs, clock/restart handling for the approved
  24-hour window, encrypted transport, and separate key recovery/rotation protocols.
- QR bootstrap and validation of scoped grants without an online native bridge,
  using the approved two-minute request and one-hour grant limits.
- Platform supervision, worker recovery, journal encryption, and disk budgets
  under the approved retention policy.
- Lease renewal and atomic local/remote arbitration under the approved
  15-second expiry, explicit takeover, and local-input priority rules.

Define versioned contracts and cross-client fixtures before implementing either
side. Preserve existing identities and keys during migration; expanding old
pairwise trust requires explicit validation and approval. Unsupported clients
must fail clearly rather than downgrade security.

## 11. Acceptance criteria

These are requirements for future implementation, not completed test results.

| Scenario | Required result |
| --- | --- |
| Concurrent launches and pair/unlock/sync with existing agents | One profile identity and runtime owner; preserve processes, drafts, and separately addressed sessions. |
| Repeat `atem pair` on an already paired profile, including incomplete verification | Report current status without starting pairing/verification or changing identity, keys, trust, or sessions; require explicit unpair before replacing the binding. |
| Explicit `atem pair verify`, cancellation, retry, and already-valid verification | Verify only the existing binding; preserve pairing on interruption; do nothing when already validly verified; never silently replace trusted keys. |
| `atem status`, its `atem cred status` alias, and offline execution | Use one read-only implementation with a `Credentials` label, distinct verification/lock state, and visibly stale cached remote information. |
| Credential unlock/lock on an unverified profile | Unlock instructs the user to run `atem pair verify`; lock can clear local keys offline; neither command initiates verification. |
| Same-host direct access during a relay outage, connection switching, and simultaneous direct/relay delivery | Honor valid local authorization; preserve the same sessions, leases, and receipts; authenticate replacement connections and reject duplicate submissions or stale input. |
| Runtime crash, worker failure, PID reuse, and agent restart | Reattach only to authenticated surviving workers; show interrupted sessions honestly; reject old process generations. |
| Several viewers and competing remote/local controllers | One lease holder per session; independent sessions remain independently controllable. |
| Explicit takeover, local terminal input, and missed renewals | Previous controller becomes a viewer; local input wins atomically; remote control expires after 15 seconds without renewal while agents continue. |
| Delayed input after lease transfer, revocation, or account change | Reject stale epochs and cross-account/target commands. |
| Immediate disconnect, delayed dispatch, duplicates, and crash after dispatch | Preserve accepted work and deduplicate; show unresolved outcomes without automatic replay. |
| Receipt/history limits and closed-session expiry | Preserve active deduplication; reject late submissions to closed sessions; identify truncation. |
| Closed-session retention deadlines | Retain receipts for seven days and conversation history for thirty days after closure; preserve memory, skills, vaults, and saved credentials. |
| QR approval, repeated/expired scans, target/key substitution, and late callbacks | One scoped grant for the captured request; no stale approval or secret disclosure. |
| Two-minute QR expiry, one-hour browser expiry, and approving native disconnect | Reject expired requests/grants; an approved browser remains usable within its valid authority when the native app closes. |
| Companion reload, expiry, revocation, or view-only control attempt | Require valid native authorization and control permission; never gain permanent trust or replay input. |
| Enrollment by a viewer, browser, Atem session, or native without fresh authentication | Reject enrollment; require an explicitly authorized native management device and fresh Touch ID or password approval. |
| Account recovery and interrupted host re-enrollment | No automatic host access or device removal; restart stays unverified until new approval commits. |
| Cancel/confirm manual removal of one Astation ID | Cancellation changes nothing; confirmation revokes only that device's service authority, preserving data and blocking silent re-registration. |
| Unpair/re-pair with existing memory, vaults, credentials, and missing keys | Preserve records, identities, and surviving keys; invalidate old access; report unavailable keys without resetting encryption. |
| Malicious relay alters traffic or withholds newer revocation state | Cryptographic validation and the defined freshness policy prevent forged or stale authority. |
| Offline freshness deadline, restart, clock change, or replayed trust update | Enforce the 24-hour maximum without extending stale authority; pause Astation viewing/control on expiry while agents and local terminal continue. |

## References

- [Atem device verification](https://github.com/Agora-Build/Astation/blob/main/docs/atem-device-verification.md)
- [Encryption migration lifecycle](https://github.com/Agora-Build/Astation/blob/main/designs/e2e-encryption.md)
- [Unified agora.build identity](https://github.com/Agora-Build/Astation/blob/main/docs/specs/2026-10-10-unified-agora-build-identity.md)
