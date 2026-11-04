# Selected Station Handoff v1

Status: implemented and released (Atem v0.8.2).

How Astation tells Atem which Station to use. This file is the wire contract and Atem's receiver rules. How the selection fits the connection order is in [astation-connection.md](../astation-connection.md#station-selection).

Code:

- `crates/atem-client/src/station_route.rs`: the shared codec (messages, limits, origin normalization, both MACs).
- `crates/atem-client-ffi/src/station_route.rs`: the UniFFI helpers for Astation's native sender.
- `src/station_route.rs`: the stored selection (`pairing/station_route.json`).
- `src/app/station_route.rs`: the exchange and the transport switch inside `atem runtime`.

## Purpose and authority

Atem follows its paired Astation's effective `stationRelayUrl`, including `https://station-dev.agora.build` and custom Station origins. The handoff works on an existing paired session even when R9 membership cannot open. It cannot enroll a host, change account trust, unlock credentials, acquire control or submit a prompt. Agent operations keep every R9 authorization requirement.

The saved session token is a secret that Atem and native's protected session store both hold. A fresh host challenge and a separate HMAC domain authenticate the selected endpoint. The token and every account key stay off the new endpoint. A controller, service or browser does not become the routing controller by sharing the account or holding `manage`.

## Exact wire

Only station-route v1 is supported. Atem does not translate older messages and does not fall back to an older protocol. A `stationRoute` message of at most 4096 bytes with a missing or different `v` makes Atem drop the Astation link with `station-route v1 is required; upgrade Atem and Astation to the current shared protocol`. It logs that line and retries after 30 seconds. Application build numbers need not match; the protocol version must.

Atem (the host) sends `request` and `accepted`. Astation's native app sends `offer` and `changed`. Atem ignores any other op it receives.

### Request

Atem sends this on its authenticated Astation WebSocket:

```json
{"type":"stationRoute","data":{"v":1,"op":"request","request":{"id":"aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee","context":{"astation_id":"astation-test","atem_id":"atem-test","binding_id":"binding-test","host_trust_gen":15,"session_id":"session-test","host_device_id":"host-test","account_id":"account-test","genesis_hash":"1212121212121212121212121212121212121212121212121212121212121212"},"route_revision":7,"policy_revision":3}}}
```

- `id` is a random UUID v4. It is single use, valid for 30 seconds on Atem's monotonic clock, and only on this link generation.
- `account_id`, `genesis_hash` and `host_device_id` are all null before a device list is pinned, and all set after. They give context, not membership proof.
- `binding_id` is the host's opaque pairing fence. Echo it exactly.
- `policy_revision` is the current R9 host-policy revision (zero before any).
- `route_revision` is the current selection revision (zero before any).

Atem sends a request right after it authenticates the link, then every 30 seconds, and again after a `changed` hint. A new request replaces the pending one. It sends none on a routed link (no Astation), without a usable saved session, or while re-authenticating, and re-authentication discards the pending challenge.

### Offer

Native replies on that exact authenticated host socket:

```json
{"type":"stationRoute","data":{"v":1,"op":"offer","offer":{"request":{"id":"aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee","context":{"astation_id":"astation-test","atem_id":"atem-test","binding_id":"binding-test","host_trust_gen":15,"session_id":"session-test","host_device_id":"host-test","account_id":"account-test","genesis_hash":"1212121212121212121212121212121212121212121212121212121212121212"},"route_revision":7,"policy_revision":3},"relay_url":"https://station-dev.agora.build","relay_only":true,"proof":"BASE64URL_HMAC_SHA256"}}}
```

The MAC key is the UTF-8 bytes of the saved session token. The input is exactly:

```text
enc([UTF8("atem-station-route-v1"), UTF8(JCS({request, relay_url, relay_only}))])
```

- `enc` prefixes each field with its four-byte unsigned big-endian length.
- JCS is the existing shared canonicalizer. The body excludes `proof`.
- `proof` is HMAC-SHA256 as base64url without padding.

Sign with `atem_client::station_route::Offer::sign`, or the UniFFI `stationRouteOffer(requestJson:relayUrl:relayOnly:sessionToken:)`. The binding normalizes the URL and returns the whole envelope. It does no I/O and does not check native app state. Do not rebuild these bytes by hand in Swift. Keep the session token in the protected store and out of logs.

Sender rules for native:

- Check the transport's authenticated host and session, the Astation identity, the host routing id, the session id, and any established account, enrolled host and trust generation.
- Capture the current account, effective selected Station, host session and connection generation before asynchronous work. Recheck them just before signing and again before sending.
- Sign only the app's own effective selection, never an endpoint the peer supplied.
- An account change or a replacement connection invalidates queued work.

### Accepted

After Atem durably saves an offer, it replies on the same socket:

```json
{"type":"stationRoute","data":{"v":1,"op":"accepted","accepted":{"offer":"EXACT_OFFER_OBJECT","route_revision":8,"direct_blocked":true,"proof":"BASE64URL_HMAC_SHA256"}}}
```

- `offer` is the exact offer object with its proof, not the placeholder shown.
- `route_revision` is the offer's request revision plus one.
- `direct_blocked` is the saved routing restriction. The R9 policy can also forbid direct transport on its own.
- The acknowledgment uses the same session key and a separate input:

```text
enc([UTF8("atem-station-route-accepted-v1"), UTF8(JCS({offer, route_revision, direct_blocked}))])
```

Native checks it with `Accepted::verify`, or UniFFI `stationRouteVerifyAccepted(offerJson:acceptedJson:sessionToken:)`, against the exact pending offer. It returns the accepted revision. Native also rechecks its captured account, Station, session and socket generation before it applies the acknowledgment. An old or forged acknowledgment cannot complete a newer handoff.

`accepted` confirms durable routing metadata only. R9 policy readiness still needs its own bound policy result.

### Station change and wake hint

A Station change sends the new current selection over the retained old authenticated socket before native retires it. Native must keep that socket for the handoff: a remote host cannot find a new endpoint after every old route is closed.

Native can ask for a fresh challenge with this untrusted wake hint:

```json
{"type":"stationRoute","data":{"v":1,"op":"changed"}}
```

It carries no endpoint and changes no saved state. Atem answers with a new request, at most one per two seconds.

Atem ignores an offer when there is no pending challenge, when the challenge expired, on another link generation, or after the nonce was spent. An invalid MAC does not spend a valid nonce.

### Limits

- An envelope is at most 4096 bytes. Atem's reader drops a longer `stationRoute` message.
- The parser refuses duplicate keys, extra fields, unsafe or non-integer numbers, unknown versions and malformed identifiers.
- Identifiers are 1 to 128 ASCII bytes from `[A-Za-z0-9._:-]`. `atem_id` also keeps non-ASCII hostname characters, within 128 UTF-8 bytes.
- Generations and revisions are safe JSON integers. The trust generation is positive.
- A genesis hash is 32 bytes of lowercase hex.
- A relay origin is at most 1024 ASCII bytes: HTTPS, or HTTP on an explicit loopback IP for development. Credentials, paths, queries, fragments, whitespace, backslashes and other schemes are refused. Normalize before signing; a normalized origin has no trailing `/`.
- The WebSocket connection does not follow HTTP redirects.

## Storage and switching

Atem applies an offer under the pairing lock, and only when all of these hold:

- the offer carries the exact pending request, unchanged, within its 30 seconds;
- the MAC verifies under the saved session token;
- the request context equals the current pairing context (Astation, `atem_id`, binding, host trust generation, session id, and the pinned account, genesis and host id);
- `policy_revision` equals the current R9 policy revision;
- `route_revision` equals the saved selection revision (compare and set).

It then writes `pairing/station_route.json` atomically and fsyncs it, before it acknowledges or migrates. The file is 0600 and holds the authenticated offer and a `direct_blocked` bit, never a secret. Each accepted offer raises the selection revision by one. A replayed or competing offer meets a spent nonce or a revision conflict.

- `atem unpair` deletes the selection.
- A selection saved under another context (a new binding, trust generation or session id) is ignored. It cannot redirect the replacement.
- A damaged file, or one that no longer verifies under the saved session token, fails closed: no connect, no fallback.
- An expired legacy session cannot make new offers or give authorization. A retained selection still routes R9 host proofs.

`relay_only:true` blocks direct transport at once and persists across reconnects, even without usable R9 membership. It does not fake an R9 policy acknowledgment. An offer with `relay_only:false` never clears the block. Only an admitted native manager's durable `host_policy_set{relay_only:false}` at a revision newer than the selection's `policy_revision` clears it. These cannot clear it: an older unchanged or committed retry, a `host_policy_get`, a non-manager, a failed write or a routing hint. If earlier preparation could not open R9, native first sets the R9 policy to true on the relay, then commits false to allow direct again. No new enrollment is involved.

Direct to relay: native stages the endpoint before it commits R9 relay only.

1. Answer a current request with the selected URL and `relay_only:false`, and verify the `accepted` reply.
2. Send `host_policy_set{relay_only:true}`.

Staging leaves an allowed direct socket open. The policy's flushed result closes it, and the reconnect uses the saved selection. If R9 preparation is unavailable, native instead asks for a fresh challenge and offers `relay_only:true`, which restricts and migrates the transport without claiming R9 readiness. Relay to relay: native offers the new selection and verifies its acknowledgment.

Migration:

- It waits for a running pairing or unlock operation, and for the queued `accepted` frame to flush (at most five seconds once the operation ends). Then it replaces only the transport.
- A newly blocked direct link is fenced from R9 traffic during that wait.
- An allow-direct change flushes its policy result first, with the same five-second bound, then tries direct again. An unchanged allow-direct set reconnects only when it actually cleared a restriction, so no reconnect loop forms when no local socket exists.
- The runtime, workers, agent PTYs, session ids, process generations and durable receipts continue. Old attachments and leases are fenced as on any disconnect. Clients open fresh encrypted channels and recover through receipt and history queries. Nobody replays a prompt.

Reconnect uses the saved selection ahead of config and compiled defaults. A blocked direct link is skipped. A selected Station that is down never falls back to the production Station; the 30-second retry goes on. A link that closes within ten seconds of authenticating also waits 30 seconds, so a flapping Station does not loop. An established link retries at once after a later drop, and so does a deliberate migration.

## Scope

This selects the runtime's WebSocket transport. Memory, skills and vault HTTP calls, and the first relay registration of `atem pair`, still use the Station from `ASTATION_RELAY_URL`, then `astation_relay_url`, then the compiled default.

**Not implemented:** following the selected Station for those HTTP calls. It needs its own authorization and token-audience contract. Atem does not forward the existing credentials to the selected endpoint.

## Evidence

- Vectors: `designs/protocol/fixtures/station-route/v1.json` (exact envelopes; offer and acknowledgment HMACs generated independently in Python with a synthetic key).
- Shared and binding tests: `crates/atem-client/tests/station_route.rs`, `crates/atem-client-ffi/tests/station_route.rs`, and the Swift `StationRouteTests`. They check the vectors, altered sender, endpoint or context, acknowledgment tampering, stale pending offers, strict shapes, origin validation and the version requirement.
- Host tests (`src/station_route.rs`, `src/app/station_route.rs`): nonce freshness, link, session and pairing replacement, compare and set and replay, durable selection, write failures, manager-only direct re-enable, session expiry.
- Real runtime and worker (`tests/station_route_binary.rs`): isolated peers, an encrypted R9 prompt and receipt across a migration, and an unavailable selected relay with no direct or default fallback.
- The prebuilt Apple package lists `atem-client-<version>-station-route-v1.json` in its SHA-256 manifest next to the SwiftPM zip, the C header and the source pin. On macOS, `EXPECT_COMMIT=<sha> scripts/check-atem-client-apple.sh <version> <dir>` verifies the download and runs the vectors through the shipped Swift helpers. CI runs it before the artifact is uploaded.
