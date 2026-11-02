# Selected Station Handoff v1

Status: Atem receiver, shared Rust codec and native UniFFI sender helper
implemented on `fix/selected-relay`. Native integration and live joint
verification remain required. This is a proposed concrete contract for
[Atem #112](https://github.com/Agora-Build/Atem/issues/112), not a claim that
native already sends it. Use the shared helper and vectors rather than
independently inventing authentication bytes in Swift.

## Purpose and authority

Atem follows its paired Astation's effective `stationRelayUrl`, including
`https://station-dev.agora.build` and custom Station origins. This transport
handoff works with an existing paired session even if R9 membership cannot
open. It cannot enroll a host, change account trust, revive membership,
unlock credentials, acquire control or submit a prompt. Agent operations
retain all existing current R9 authorization requirements.

The paired session already has a secret known to the host and native's
protected session store. A fresh host challenge and a separate HMAC domain
authenticate the selected endpoint. Neither the session token nor any account
key is sent to the new endpoint. Another controller, service or browser does
not become the routing controller by sharing an account or having `manage`.

## Exact Wire

Only the current shared station-route protocol, v1, is supported. Atem
closes a routing exchange with a missing or different version, reports an
explicit upgrade requirement, and backs off for 30 seconds. It does not
translate older messages or fall back to an older protocol. Atem and
Astation application build numbers need not match; their shared protocol
must match. The published native v1 helpers remain the wire contract.

The host sends on its authenticated Astation WebSocket:

```json
{"type":"stationRoute","data":{"v":1,"op":"request","request":{"id":"aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee","context":{"astation_id":"astation-test","atem_id":"atem-test","binding_id":"binding-test","host_trust_gen":15,"session_id":"session-test","host_device_id":"host-test","account_id":"account-test","genesis_hash":"1212121212121212121212121212121212121212121212121212121212121212"},"route_revision":7,"policy_revision":3}}}
```

`id` is a random UUID v4, single use, valid for 30 seconds on the host's
monotonic clock and only on this authenticated link generation. The three
membership fields (`account_id`, `genesis_hash`, `host_device_id`) are all
null before a device list is pinned. They provide context, not membership
proof. `binding_id` is the host's opaque pairing fence; echo it exactly.
`policy_revision` is the current R9 policy revision (initially zero);
`route_revision` is the host's current selection revision (initially zero).

Native replies on that exact authenticated host socket:

```json
{"type":"stationRoute","data":{"v":1,"op":"offer","offer":{"request":{"id":"aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee","context":{"astation_id":"astation-test","atem_id":"atem-test","binding_id":"binding-test","host_trust_gen":15,"session_id":"session-test","host_device_id":"host-test","account_id":"account-test","genesis_hash":"1212121212121212121212121212121212121212121212121212121212121212"},"route_revision":7,"policy_revision":3},"relay_url":"https://station-dev.agora.build","relay_only":true,"proof":"BASE64URL_HMAC_SHA256"}}}
```

The MAC key is the UTF-8 bytes of the existing saved session token. The
input is exactly:

```text
enc([UTF8("atem-station-route-v1"), UTF8(JCS({request, relay_url, relay_only}))])
```

`enc` prefixes each field with its four-byte unsigned big-endian length.
JCS is the existing shared canonicalizer. The body excludes `proof`.
`proof` is HMAC-SHA256 encoded as base64url without padding.
Use `atem_client::station_route::Offer::sign`, or UniFFI
`stationRouteOffer(requestJson:relayUrl:relayOnly:sessionToken:)`. The binding
normalizes the URL and returns the complete envelope. It performs no I/O and
does not validate native app state. Keep session secrets in the existing
protected store and out of logs.

Native must validate the transport's authenticated host/session, Astation
identity, host routing ID, session ID and any established account, enrolled
host and trust generation. Capture current account, effective selected
Station, host session and connection generation before asynchronous work;
recheck immediately before signing and before sending. Sign only the app's
effective selection, never an endpoint supplied by the peer. Account changes
and replacement connections invalidate queued work.

After durably saving an offer, Atem replies on the same socket:

```json
{"type":"stationRoute","data":{"v":1,"op":"accepted","accepted":{"offer":"EXACT_OFFER_OBJECT","route_revision":8,"direct_blocked":true,"proof":"BASE64URL_HMAC_SHA256"}}}
```

`offer` is the exact offer object, including its proof, rather than the
placeholder string shown here. `route_revision` must equal the offer's
request revision plus one. `direct_blocked` reports the saved routing
restriction; the R9 policy can independently prohibit direct transport.
The acknowledgment uses the same paired session key with a separate input:

```text
enc([UTF8("atem-station-route-accepted-v1"), UTF8(JCS({offer, route_revision, direct_blocked}))])
```

Use shared `Accepted::verify` or UniFFI
`stationRouteVerifyAccepted(offerJson:acceptedJson:sessionToken:)` against
the exact pending offer. It returns the accepted route revision. Native
also rechecks its captured account, Station, session and socket generation
before applying the acknowledgment. An old or forged acknowledgment cannot
complete a newer handoff. This confirms durable routing metadata only;
R9 policy readiness still requires its existing bound policy result.

A Station change deliberately sends its **new current selection** over the
retained old authenticated socket before retiring it. Keep that socket
available for this handoff. A remote host cannot discover an arbitrary new
endpoint after every old route has already been closed.

Native can ask for a new challenge with this untrusted wake hint:

```json
{"type":"stationRoute","data":{"v":1,"op":"changed"}}
```

It carries no endpoint and changes no saved state. The host bounds fresh
challenges to one per two seconds; ordinary refresh is every 30 seconds.
An offer without a pending challenge, after expiry, on another generation,
or after its nonce was spent is ignored. Re-authentication discards pending
challenges. Invalid MACs do not spend a valid nonce.

Envelopes are at most 4096 bytes. The shared parser refuses duplicate keys,
extra fields, unsafe/noninteger numbers, unknown versions and malformed
identifiers. Identifiers are 1-128 ASCII bytes from `[A-Za-z0-9._:-]`;
`atem_id` also preserves non-ASCII hostname characters within 128 UTF-8 bytes.
generations/revisions are safe JSON integers and generation is positive.
Genesis hashes are 32 bytes of lowercase hex. Relay origins are at most
1024 ASCII bytes: HTTPS, or HTTP on an explicit loopback IP for development.
Credentials, paths, queries, fragments, whitespace, backslashes and other
schemes are refused. Normalize before signing; normalized origins omit `/`.
The WebSocket connector does not follow HTTP redirects.

## Storage And Switching

Under its pairing lock, Atem verifies the MAC, exact pending request,
current pairing/session, account/genesis/host context, policy revision and
selection revision. It atomically writes and fsyncs
`pairing/station_route.json` before scheduling migration. This 0600 file
contains the authenticated offer and a `direct_blocked` bit, never a secret.
Each accepted offer increments the selection revision. Competing/replayed
offers meet a spent nonce or revision conflict. Unpair deletes the selection;
old binding/account/session context cannot redirect a replacement. Damaged
current routing state fails closed. A retained selection can still route R9
host proofs after legacy session expiry; expired sessions cannot make new
offers or obtain authorization from routing metadata.

`relay_only:true` immediately restricts direct transport and persists across
reconnects, even without usable R9 membership. It does not fabricate an R9
policy acknowledgment. A later offer with `relay_only:false` cannot clear
that restriction. Only an admitted native manager's explicit durable
`host_policy_set{relay_only:false}` at a revision **newer than the selection's
policy revision** can clear it. Older unchanged/committed retries cannot undo
a newer routing restriction. A get, non-manager, failed write or routing hint
cannot clear it. If earlier preparation could not open R9,
native must first align the R9 policy to true on the relay, then commit false
to enable direct routing. These are internal protocol operations, with no new
enrollment or owner prompt. The existing R9 policy independently can still
prohibit direct transport.

For a direct-to-relay handoff, native stages the endpoint **before** committing
R9 relay-only: answer a current request with the selected URL and
`relay_only:false`, verify its `accepted` acknowledgment, then send the
existing `host_policy_set{relay_only:true}`. Staging leaves an allowed direct
socket open; the policy's flushed result closes it and reconnect uses the
already saved selection. If R9 preparation is unavailable, native instead
requests a fresh challenge and offers `relay_only:true`. That restricts and
migrates transport without claiming R9 readiness. For relay-to-relay changes,
native offers the new selection directly and verifies its acknowledgment.

Migration waits for any running pairing/unlock operation and the queued
routing acknowledgment to flush (bounded to five seconds once the operation
finishes), then replaces only the transport. A newly blocked direct link is
fenced from R9 traffic during that wait. An allow-direct transition flushes its policy result before
attempting direct again, with a five-second bound once no operation runs.
An unchanged allow-direct set only triggers reconnect if it actually cleared
a routing restriction, avoiding a reconnect loop when no local socket exists.

The runtime, workers, agent PTYs, session IDs, process generations and
durable receipts continue. Old attachments/leases are fenced as on a normal
disconnect. Clients open fresh encrypted channels and recover with receipt
and history queries; neither endpoint replays a prompt. Native observes the
new connection after the authenticated routing acknowledgment.

Reconnect prefers the saved selection over config and compiled defaults.
Blocked direct links are skipped. Unavailable selected relays have no
production or direct fallback; failed connections retry every 30 seconds.
Links closing within ten seconds of authentication also back off 30 seconds
to prevent flicker. Established links retry immediately on a later drop;
deliberate migrations reconnect immediately.

This change selects runtime WebSocket transport. Memory/vault HTTP endpoints
remain separately configured: changing their authorization or token audience
needs a separate contract, not forwarding existing credentials.

## Shared Evidence And Native Handoff

- Shared codec: `crates/atem-client/src/station_route.rs`.
- Native binding: `crates/atem-client-ffi/src/station_route.rs`.
- Exact envelopes and independent Python offer/acknowledgment HMAC vectors:
  `designs/protocol/fixtures/station-route/v1.json` (synthetic key only).
- Shared/native tests check the vectors, altered sender/endpoint/context,
  acknowledgment tampering and stale pending offers,
  strict shapes and origin validation.
- Host tests check freshness, link/session/pairing replacement, CAS/replay,
  durable selection, write failures and manager-only direct re-enable.
- Binary tests exercise the real runtime and worker with isolated peers,
  an encrypted R9 prompt/receipt, migration and an unavailable relay.

The native sender uses the shared helpers with its effective
`stationRelayUrl`. Live verification of the provisioned app on dev/custom
relays, rapid changes, re-authentication, unavailable relays and direct
re-enable still requires a paired route-capable host. Fixture success does
not prove a live switch. Preserve the retained Genie runtime, active
integration and healthy station-dev replicas. No deployed service or user
agent is restarted by this implementation or its tests.

The prebuilt Apple artifact includes `atem-client-<version>-station-route-v1.json`
in its SHA-256 manifest alongside the SwiftPM zip, C header and source pin.
On macOS, `EXPECT_COMMIT=<sha> scripts/check-atem-client-apple.sh <version> <dir>`
verifies the download and runs the independent vectors through the shipped
production Swift helpers. CI runs this check before uploading the artifact.
