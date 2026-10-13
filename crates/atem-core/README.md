# atem-core

Rust library for atem, built to be shared with Astation. It builds, decodes and verifies
Agora AccessToken2 tokens (version `007`) for RTC and RTM. It has no I/O, keeps
no state and never logs. See [`designs/atem-core.md`](../../designs/atem-core.md)
for the design. C and Swift callers use the `atem-core-ffi` crate
([`crates/atem-core-ffi/README.md`](../atem-core-ffi/README.md)).

atem's own CLI keeps its conventions on top of this library (the `s/` prefix
for string accounts, an empty certificate meaning "no token"). They live in
`src/token.rs`, not here.

## Build an RTC token

The App ID and certificate below are Agora's public test values, not real
credentials.

```rust,ignore
use atem_core::{build_rtc_token, Issue, RtcIdentity, RtcPrivileges, RtcTokenRequest};

let token = build_rtc_token(
    &RtcTokenRequest {
        app_id: "970CA35de60c44645bbae8a215061b33",
        app_certificate: "5CFd2fd1755d40ecb72977518be15d3b",
        channel: "demo",
        identity: RtcIdentity::Uid(1234),
        privileges: RtcPrivileges::Publisher { expire: 3600 },
        token_expire: 3600,
        rtm: None,
    },
    Issue::now(),
)?;
```

`RtcIdentity::Uid(0)` means any user. `RtcIdentity::UserAccount(&str)` is a
string account; numbers and strings are never converted into each other.
`RtcPrivileges` is `Publisher { expire }` (join and publish audio, video and
data), `Subscriber { expire }` (join only) or `Explicit { join, publish_audio,
publish_video, publish_data }`. Set `rtm: Some(RtmLogin { user_id, expire })` to
add an RTM login to the same token (`user_id: None` reuses the RTC account).

`Issue::now()` uses the system clock and a random salt. `Issue::at(unix_secs)`
takes your own clock. A fixed `Issue { issued_at, salt }` makes a token
reproducible (tests).

## Build an RTM token

```rust,ignore
use atem_core::{build_rtm_token, Issue, RtmTokenRequest};

let token = build_rtm_token(
    &RtmTokenRequest {
        app_id: "970CA35de60c44645bbae8a215061b33",
        app_certificate: "5CFd2fd1755d40ecb72977518be15d3b",
        user_id: "alice",
        expire: 3600,
    },
    Issue::now(),
)?;
```

## Decode and verify

```rust,ignore
use atem_core::{decode_token, verify_token_signature};

let decoded = decode_token(&token)?;           // app_id, issued_at, expire, services
let signed_by_us = verify_token_signature(&token, "5CFd2fd1755d40ecb72977518be15d3b")?;
```

Decoding does not verify; use `verify_token_signature`.
`verify_token_signature` returns `Ok(false)` for a well-formed token signed with
another certificate. `DecodedToken::expires_at()` gives the expiry in unix
seconds.

The optional `serde` feature derives `Serialize` for the decoded types (the FFI
crate uses it for its JSON output).

## Validation

Failures are a `TokenError`. Messages name the field and the rule, never the
App Certificate or the token.

| Input | Rule | Error |
|---|---|---|
| App ID | 32 hex characters | `InvalidAppId` |
| App Certificate | 32 hex characters | `InvalidAppCertificate` |
| Channel | 1-64 bytes | `InvalidChannel` |
| RTC user account | 1-255 bytes | `InvalidUserAccount` |
| RTM user id | 1-64 bytes | `InvalidRtmUserId` |
| Expiries | at least 1 second, relative seconds | `InvalidExpiry` |
| Token to decode | starts with `007` | `UnsupportedVersion` |
| Token to decode | well-formed | `Malformed` |

Agora caps privileges at 24 hours on its servers; atem-core does not.

## Compatibility with Agora

`tests/upstream_compat.rs` pins Agora's own `agora_token` crate (a git
dependency at a fixed revision) as a dev-dependency. Upstream picks the issue
time and salt itself, so each test decodes upstream's token, rebuilds it with
atem-core from the same issue time and salt, and requires the same string. It
covers uid and user-account RTC tokens, publisher, subscriber and explicit
privileges, RTC tokens with an RTM login, and RTM tokens. The published test vector is also checked byte for byte from the C
and Swift callers.

```bash
cargo test -p atem-core
```
