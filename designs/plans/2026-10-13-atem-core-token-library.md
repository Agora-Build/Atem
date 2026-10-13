# atem-core Token Library Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move Agora RTC/RTM token generation and inspection out of the `atem` binary into a reusable Rust library (`atem-core`) with a versioned C ABI (`atem-core-ffi`) that Astation can link statically, while `atem`'s CLI and servers keep their behaviour.

**Architecture:** A Cargo workspace: the `atem` binary stays at the repo root; `crates/atem-core` owns a safe implementation of Agora's AccessToken2 format (proven byte-identical to Agora's `agora_token` crate by tests) behind a typed API; `crates/atem-core-ffi` wraps it in a small C ABI with a hand-written header. CI tests both crates on Linux, macOS and Windows and drives the C ABI from C and Swift; each release attaches a macOS xcframework.

**Tech Stack:** Rust 2024 edition, `hmac` 0.12 + `sha2` 0.10, `flate2` 1, `base64` 0.22, `getrandom` 0.2, `serde`/`serde_json` (FFI JSON only), `agora_token` (dev-dependency, pinned git rev) for compatibility tests; GitHub Actions; `cc`/`swiftc`/`lipo`/`xcodebuild` for the native checks and packaging.

**Spec:** `designs/atem-core.md` (written from the Astation agent's "Shared-library handoff" memories in project github.com/agora-build/atem).

## Global Constraints

- Every commit message ends with the line `🤖 Built with SMT <smt@agora.build>`.
- Work on branch `feat/atem-core` (create it from `main` in Task 1). Do not push; the controller pushes and opens the PR.
- New crates use `edition = "2024"`, `publish = false`, version `0.1.0`.
- `cargo fmt` is never run project-wide. New files under `crates/` and `src/token.rs` may be formatted with `rustfmt --edition 2024 <file>`. Never rustfmt `src/cli.rs`, `src/websocket_client.rs`, `src/main.rs`, `src/app.rs`, `src/memory/crypto.rs`, `src/memory/mod.rs`.
- Library code never prints, reads stdin, reads files, environment variables or atem config. No `unwrap`/`expect` on caller data in library code.
- Error messages never contain the App Certificate or a token string (they may name the field and its length).
- App ID and App Certificate: exactly 32 ASCII hex characters. Channel: 1–64 bytes. RTC user account: 1–255 bytes. RTM user id: 1–64 bytes. Every expiry: ≥ 1 second. Decode input ≤ 16 KiB, decompressed ≤ 64 KiB.
- `atem token rtc|rtm create|decode`, `/api/token` and the ConvoAI server keep their documented behaviour (the `s/` prefix, int-uid vs string-account detection, empty certificate → no token).
- Tests: `cargo test -p atem-core -p atem-core-ffi`; the `atem` package with `cargo test -- --test-threads=1` and plain `cargo test` (CI runs tests in parallel). `cargo clippy --all-targets` (workspace) adds no warnings to existing files and none in new crates.
- Don't touch a running `atem key-agent`, `~/.config/atem`, or run `atem pair`/`atem cred`/`atem sync`.
- Pinned upstream: `agora_token` git `https://github.com/AgoraIO/Tools.git`, rev `374cd21f5220d2c921ec903c1eae2ee1464be651`, subdirectory `DynamicKey/AgoraDynamicKey/rust`.

## File Structure

| File | Responsibility |
|---|---|
| `Cargo.toml` (root) | Adds `[workspace]`; `atem` depends on `atem-core`; `agora_token` removed (Task 3) |
| `crates/atem-core/Cargo.toml` | Library manifest |
| `crates/atem-core/src/lib.rs` | Crate docs, `pub mod token`, `pub use` of the public API |
| `crates/atem-core/src/error.rs` | `TokenError` |
| `crates/atem-core/src/wire.rs` | AccessToken2 packing, signing, compression, parsing (crate-private) |
| `crates/atem-core/src/token.rs` | Public types, validation, builders, decode, verify |
| `crates/atem-core/tests/upstream_compat.rs` | Byte-for-byte compatibility with `agora_token` |
| `src/token.rs` (atem) | CLI glue: `RtcAccount` parsing, `Role`, empty-certificate rule, `TokenInfo` display |
| `crates/atem-core-ffi/Cargo.toml` | staticlib + cdylib + rlib manifest |
| `crates/atem-core-ffi/src/lib.rs` | `extern "C"` functions, params structs, status codes |
| `crates/atem-core-ffi/include/atem_core.h` | The public C header |
| `crates/atem-core-ffi/include/module.modulemap` | Swift module `AtemCore` |
| `crates/atem-core-ffi/tests/abi.rs` | ABI behaviour from Rust (ownership, errors, nulls) |
| `crates/atem-core-ffi/tests/c/consumer.c` | Minimal native consumer |
| `crates/atem-core-ffi/tests/swift/main.swift` | Swift caller (macOS) |
| `scripts/check-atem-core-ffi.sh` | Builds the static lib, compiles and runs the C (and on macOS Swift) consumers |
| `scripts/package-atem-core-macos.sh` | Universal static lib → xcframework zip + header + SHA256SUMS |
| `.github/workflows/atem-core.yml` | CI: tests on Linux/macOS/Windows, native consumers, package dry run |
| `.github/workflows/release.yml` | Release job attaching the macOS artifacts |
| `crates/atem-core/README.md`, `crates/atem-core-ffi/README.md` | API overview; build/link/Swift instructions |

---

### Task 1: Workspace and the AccessToken2 codec in `atem-core`

**Files:**
- Modify: `Cargo.toml` (root: add `[workspace]`)
- Create: `crates/atem-core/Cargo.toml`, `crates/atem-core/src/lib.rs`, `crates/atem-core/src/error.rs`, `crates/atem-core/src/wire.rs`, `crates/atem-core/src/token.rs` (types only in this task)

**Interfaces:**
- Produces (crate-private, used by Task 2): `wire::Content { app_id: String, issue_ts: u32, expire: u32, salt: u32, services: Vec<wire::Service> }`, `wire::Service { privileges: BTreeMap<u16, u32>, details: ServiceDetails }`, `wire::encode(&Content, app_certificate: &str) -> Result<String, TokenError>`, `wire::parse(token: &str) -> Result<wire::Parsed, TokenError>` with `Parsed { signature: Vec<u8>, body: Vec<u8>, content: Content }`, `wire::signature_matches(&Parsed, app_certificate: &str) -> bool`.
- Produces (public): `TokenError` (all variants below), `ServiceDetails`, the `SERVICE_*` and `PRIVILEGE_*` constants.

- [ ] **Step 1: Create the branch and the workspace**

```bash
git checkout -b feat/atem-core main
```

Append to the root `Cargo.toml` (after `[build-dependencies]` and its entries, at the end of the file):

```toml
[workspace]
members = ["crates/atem-core", "crates/atem-core-ffi"]
resolver = "3"
```

Create `crates/atem-core/Cargo.toml`:

```toml
[package]
name = "atem-core"
version = "0.1.0"
edition = "2024"
description = "Agora AccessToken2 (RTC/RTM) generation and inspection shared by atem and Astation"
publish = false

[dependencies]
base64 = "0.22"
flate2 = "1.0"
hmac = "0.12"
sha2 = "0.10"
getrandom = "0.2"
serde = { version = "1.0", features = ["derive"], optional = true }

[features]
serde = ["dep:serde"]

[dev-dependencies]
agora_token = { git = "https://github.com/AgoraIO/Tools.git", rev = "374cd21f5220d2c921ec903c1eae2ee1464be651", subdirectory = "DynamicKey/AgoraDynamicKey/rust" }
```

`crates/atem-core-ffi` doesn't exist until Task 4, so for now set `members = ["crates/atem-core"]`; Task 4 adds the second member.

- [ ] **Step 2: Write `error.rs` and the public data types**

`crates/atem-core/src/error.rs`:

```rust
//! Why a token could not be built, decoded or verified.

use std::fmt;

/// Every failure in atem-core. Messages name the field and the rule, never
/// the App Certificate or the token text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenError {
    /// The App ID isn't 32 hexadecimal characters.
    InvalidAppId,
    /// The App Certificate isn't 32 hexadecimal characters.
    InvalidAppCertificate,
    InvalidChannel(String),
    InvalidUserAccount(String),
    InvalidRtmUserId(String),
    InvalidExpiry(String),
    /// The token doesn't start with the AccessToken2 version "007".
    UnsupportedVersion,
    Malformed(String),
}

impl fmt::Display for TokenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TokenError::InvalidAppId => write!(f, "App ID must be 32 hexadecimal characters"),
            TokenError::InvalidAppCertificate => {
                write!(f, "App Certificate must be 32 hexadecimal characters")
            }
            TokenError::InvalidChannel(why) => write!(f, "invalid channel name: {why}"),
            TokenError::InvalidUserAccount(why) => write!(f, "invalid RTC user account: {why}"),
            TokenError::InvalidRtmUserId(why) => write!(f, "invalid RTM user id: {why}"),
            TokenError::InvalidExpiry(why) => write!(f, "invalid expiry: {why}"),
            TokenError::UnsupportedVersion => {
                write!(f, "unsupported token version (expected an AccessToken2 starting with \"007\")")
            }
            TokenError::Malformed(why) => write!(f, "malformed token: {why}"),
        }
    }
}

impl std::error::Error for TokenError {}
```

`crates/atem-core/src/token.rs` (types only; Task 2 adds the functions):

```rust
//! Agora AccessToken2 (version "007") for RTC and RTM. See designs/atem-core.md.

use std::collections::BTreeMap;

pub use crate::error::TokenError;

/// Service types inside a token.
pub const SERVICE_RTC: u16 = 1;
pub const SERVICE_RTM: u16 = 2;
pub const SERVICE_FPA: u16 = 4;
pub const SERVICE_CHAT: u16 = 5;
pub const SERVICE_APAAS: u16 = 7;

/// RTC privileges.
pub const PRIVILEGE_JOIN_CHANNEL: u16 = 1;
pub const PRIVILEGE_PUBLISH_AUDIO_STREAM: u16 = 2;
pub const PRIVILEGE_PUBLISH_VIDEO_STREAM: u16 = 3;
pub const PRIVILEGE_PUBLISH_DATA_STREAM: u16 = 4;
/// RTM privilege.
pub const PRIVILEGE_RTM_LOGIN: u16 = 1;

/// The service-specific fields of one service in a token.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", serde(tag = "kind", rename_all = "snake_case"))]
pub enum ServiceDetails {
    /// `account` is the user account, or the decimal uid; empty means uid 0 (any user).
    Rtc { channel: String, account: String },
    Rtm { user_id: String },
    Fpa,
    Chat { user_id: String },
    Apaas { room_uuid: String, user_uuid: String, role: i16 },
}

impl ServiceDetails {
    pub fn service_type(&self) -> u16 {
        match self {
            ServiceDetails::Rtc { .. } => SERVICE_RTC,
            ServiceDetails::Rtm { .. } => SERVICE_RTM,
            ServiceDetails::Fpa => SERVICE_FPA,
            ServiceDetails::Chat { .. } => SERVICE_CHAT,
            ServiceDetails::Apaas { .. } => SERVICE_APAAS,
        }
    }
}

/// One service as read from a token: its privileges (privilege → expiry in
/// seconds after the issue time) and fields.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct DecodedService {
    pub service_type: u16,
    pub privileges: BTreeMap<u16, u32>,
    pub details: ServiceDetails,
}

/// What a token says about itself. Reading these fields does **not**
/// establish that the token is authentic: use `verify_token_signature`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct DecodedToken {
    pub version: String,
    pub app_id: String,
    /// Unix seconds.
    pub issued_at: u32,
    /// Seconds after `issued_at`.
    pub expire: u32,
    pub salt: u32,
    pub services: Vec<DecodedService>,
}

impl DecodedToken {
    /// Unix seconds at which the token itself expires.
    pub fn expires_at(&self) -> u64 {
        self.issued_at as u64 + self.expire as u64
    }
}
```

`crates/atem-core/src/lib.rs`:

```rust
//! Shared library for atem and Astation, starting with Agora RTC/RTM tokens.
//! The Rust API is `token`; C callers use the `atem-core-ffi` crate.
//! See designs/atem-core.md.

mod error;
pub mod token;
mod wire;

pub use error::TokenError;
```

- [ ] **Step 3: Write the failing codec tests**

Create `crates/atem-core/src/wire.rs` with only the test module first (the functions are `todo!()` stubs so it compiles):

```rust
//! AccessToken2 wire format: packing, signing, zlib, base64, and parsing.
//! Crate-private; `token` validates inputs before anything reaches here.

use std::collections::BTreeMap;

use crate::error::TokenError;
use crate::token::ServiceDetails;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Service {
    pub privileges: BTreeMap<u16, u32>,
    pub details: ServiceDetails,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Content {
    pub app_id: String,
    pub issue_ts: u32,
    pub expire: u32,
    pub salt: u32,
    /// At most one service per type.
    pub services: Vec<Service>,
}

#[derive(Debug)]
pub(crate) struct Parsed {
    pub signature: Vec<u8>,
    /// The signed bytes: everything after the signature.
    pub body: Vec<u8>,
    pub content: Content,
}

pub(crate) fn encode(_content: &Content, _app_certificate: &str) -> Result<String, TokenError> {
    todo!()
}

pub(crate) fn parse(_token: &str) -> Result<Parsed, TokenError> {
    todo!()
}

pub(crate) fn signature_matches(_parsed: &Parsed, _app_certificate: &str) -> bool {
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;
    use std::io::Write as _;

    const APP_ID: &str = "970CA35de60c44645bbae8a215061b33";
    const APP_CERT: &str = "5CFd2fd1755d40ecb72977518be15d3b";
    // Upstream's published vector (agora_token access_token.rs test_service_rtc).
    const VECTOR: &str = "007eJwBigB1/yAAFqC4TFpegsv3T7gT0J9ZxUvaycBhIFgFOayXV46VixogADk3MENBMzVkZTYwYzQ0NjQ1YmJhZThhMjE1MDYxYjMzR/QQAFgCAAABAAAAAQABAAEAAQBYAgAAIAA3ZDcyMzY1ZWI5ODM0ODUzOTdlM2UzZjlkNDYwYmRkYQoAMjg4MjM0MTI3M8JqJOM=";

    fn vector_content() -> Content {
        Content {
            app_id: APP_ID.into(),
            issue_ts: 1111111,
            expire: 600,
            salt: 1,
            services: vec![Service {
                privileges: BTreeMap::from([(1, 600)]),
                details: ServiceDetails::Rtc {
                    channel: "7d72365eb983485397e3e3f9d460bdda".into(),
                    account: "2882341273".into(),
                },
            }],
        }
    }

    /// `007` + base64(zlib(bytes)), for hand-made malformed tokens.
    fn wrap(bytes: &[u8]) -> String {
        let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        z.write_all(bytes).unwrap();
        format!("007{}", base64::engine::general_purpose::STANDARD.encode(z.finish().unwrap()))
    }

    #[test]
    fn encodes_upstreams_published_vector_byte_for_byte() {
        assert_eq!(encode(&vector_content(), APP_CERT).unwrap(), VECTOR);
    }

    #[test]
    fn parses_the_vector_back() {
        let parsed = parse(VECTOR).unwrap();
        assert_eq!(parsed.content, vector_content());
        assert_eq!(parsed.signature.len(), 32);
    }

    #[test]
    fn signature_matches_only_with_the_right_certificate() {
        let parsed = parse(VECTOR).unwrap();
        assert!(signature_matches(&parsed, APP_CERT));
        assert!(!signature_matches(&parsed, "00000000000000000000000000000000"));
    }

    #[test]
    fn round_trips_every_service_kind_in_type_order() {
        let mut content = vector_content();
        content.services = vec![
            Service {
                privileges: BTreeMap::from([(1, 60), (2, 60), (3, 60), (4, 60)]),
                details: ServiceDetails::Rtc { channel: "c".into(), account: "".into() },
            },
            Service {
                privileges: BTreeMap::from([(1, 30)]),
                details: ServiceDetails::Rtm { user_id: "bob".into() },
            },
            Service { privileges: BTreeMap::from([(1, 10)]), details: ServiceDetails::Fpa },
            Service {
                privileges: BTreeMap::from([(1, 10), (2, 20)]),
                details: ServiceDetails::Chat { user_id: "u".into() },
            },
            Service {
                privileges: BTreeMap::from([(1, 5)]),
                details: ServiceDetails::Apaas {
                    room_uuid: "r".into(),
                    user_uuid: "u".into(),
                    role: -1,
                },
            },
        ];
        let token = encode(&content, APP_CERT).unwrap();
        assert_eq!(parse(&token).unwrap().content, content);
    }

    #[test]
    fn accepts_unpadded_base64() {
        let unpadded = VECTOR.trim_end_matches('=');
        assert_eq!(parse(unpadded).unwrap().content, vector_content());
    }

    #[test]
    fn rejects_other_versions() {
        assert_eq!(parse("").unwrap_err(), TokenError::UnsupportedVersion);
        assert_eq!(parse("006abc").unwrap_err(), TokenError::UnsupportedVersion);
    }

    #[test]
    fn rejects_malformed_tokens_without_echoing_them() {
        let cases = [
            "007!!!not-base64".to_string(),
            format!("007{}", base64::engine::general_purpose::STANDARD.encode(b"not zlib")),
            wrap(&[1, 0]),                          // signature length 1, then nothing
            wrap(&[0, 0, 3, 0, b'a']),              // app id cut short
        ];
        for token in cases {
            match parse(&token) {
                Err(TokenError::Malformed(why)) => assert!(!why.contains(&token[3..]), "{why}"),
                other => panic!("{token}: {other:?}"),
            }
        }
    }

    #[test]
    fn rejects_trailing_bytes_and_unknown_services() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&[0, 0]); // empty signature
        bytes.extend_from_slice(&[1, 0, b'a']); // app id "a"
        bytes.extend_from_slice(&[0; 12]); // issue_ts, expire, salt
        bytes.extend_from_slice(&[1, 0, 9, 0, 0, 0]); // one service of type 9, no privileges
        assert!(matches!(parse(&wrap(&bytes)), Err(TokenError::Malformed(why)) if why.contains("unknown service type 9")));

        let mut ok = Vec::new();
        ok.extend_from_slice(&[0, 0, 1, 0, b'a']);
        ok.extend_from_slice(&[0; 12]);
        ok.extend_from_slice(&[0, 0]); // no services
        assert!(parse(&wrap(&ok)).is_ok());
        ok.push(7);
        assert!(matches!(parse(&wrap(&ok)), Err(TokenError::Malformed(why)) if why.contains("trailing")));
    }

    #[test]
    fn rejects_oversized_input_and_decompression_bombs() {
        let long = format!("007{}", "A".repeat(16 * 1024));
        assert!(matches!(parse(&long), Err(TokenError::Malformed(why)) if why.contains("16 KiB")));
        let bomb = wrap(&vec![0u8; 100 * 1024]);
        assert!(bomb.len() < 16 * 1024);
        assert!(matches!(parse(&bomb), Err(TokenError::Malformed(why)) if why.contains("64 KiB")));
    }

    #[test]
    fn refuses_fields_longer_than_the_format_allows() {
        let mut content = vector_content();
        content.app_id = "x".repeat(70_000);
        assert!(matches!(encode(&content, APP_CERT), Err(TokenError::Malformed(_))));
    }
}
```

- [ ] **Step 4: Run them to see them fail**

Run: `cargo test -p atem-core`
Expected: the tests compile and FAIL (panics at `not yet implemented`).

- [ ] **Step 5: Implement the codec**

Replace the three `todo!()` functions in `wire.rs` (keep the structs and tests) with:

```rust
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
use flate2::Compression;
use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::io::{Read, Write};

pub(crate) const VERSION: &str = "007";
const MAX_TOKEN_LEN: usize = 16 * 1024;
const MAX_DECOMPRESSED: usize = 64 * 1024;

type HmacSha256 = Hmac<Sha256>;

fn put_u16(buf: &mut Vec<u8>, v: u16) {
    buf.extend_from_slice(&v.to_le_bytes());
}

fn put_u32(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_le_bytes());
}

/// `u16` length + bytes; longer fields don't fit the format.
fn put_bytes(buf: &mut Vec<u8>, field: &str, bytes: &[u8]) -> Result<(), TokenError> {
    let len = u16::try_from(bytes.len()).map_err(|_| {
        TokenError::Malformed(format!("{field} is {} bytes, more than a token can hold", bytes.len()))
    })?;
    put_u16(buf, len);
    buf.extend_from_slice(bytes);
    Ok(())
}

impl Content {
    fn pack(&self) -> Result<Vec<u8>, TokenError> {
        let mut buf = Vec::new();
        put_bytes(&mut buf, "app id", self.app_id.as_bytes())?;
        put_u32(&mut buf, self.issue_ts);
        put_u32(&mut buf, self.expire);
        put_u32(&mut buf, self.salt);
        let mut services: Vec<&Service> = self.services.iter().collect();
        services.sort_by_key(|s| s.details.service_type());
        put_u16(&mut buf, services.len() as u16);
        for service in services {
            put_u16(&mut buf, service.details.service_type());
            put_u16(&mut buf, service.privileges.len() as u16);
            for (privilege, expire) in &service.privileges {
                put_u16(&mut buf, *privilege);
                put_u32(&mut buf, *expire);
            }
            match &service.details {
                ServiceDetails::Rtc { channel, account } => {
                    put_bytes(&mut buf, "channel", channel.as_bytes())?;
                    put_bytes(&mut buf, "account", account.as_bytes())?;
                }
                ServiceDetails::Rtm { user_id } | ServiceDetails::Chat { user_id } => {
                    put_bytes(&mut buf, "user id", user_id.as_bytes())?;
                }
                ServiceDetails::Fpa => {}
                ServiceDetails::Apaas { room_uuid, user_uuid, role } => {
                    put_bytes(&mut buf, "room uuid", room_uuid.as_bytes())?;
                    put_bytes(&mut buf, "user uuid", user_uuid.as_bytes())?;
                    buf.extend_from_slice(&role.to_le_bytes());
                }
            }
        }
        Ok(buf)
    }
}

/// HMAC(key = salt, HMAC(key = issue_ts, certificate)), as Agora defines it.
fn sign_key(app_certificate: &str, issue_ts: u32, salt: u32) -> [u8; 32] {
    let mut h = HmacSha256::new_from_slice(&issue_ts.to_le_bytes()).expect("HMAC takes any key length");
    h.update(app_certificate.as_bytes());
    let inner = h.finalize().into_bytes();
    let mut h = HmacSha256::new_from_slice(&salt.to_le_bytes()).expect("HMAC takes any key length");
    h.update(&inner);
    h.finalize().into_bytes().into()
}

fn signer(content_issue_ts: u32, salt: u32, app_certificate: &str) -> HmacSha256 {
    HmacSha256::new_from_slice(&sign_key(app_certificate, content_issue_ts, salt))
        .expect("HMAC takes any key length")
}

pub(crate) fn encode(content: &Content, app_certificate: &str) -> Result<String, TokenError> {
    let body = content.pack()?;
    let mut mac = signer(content.issue_ts, content.salt, app_certificate);
    mac.update(&body);
    let signature = mac.finalize().into_bytes();

    let mut plain = Vec::with_capacity(2 + signature.len() + body.len());
    put_bytes(&mut plain, "signature", &signature)?;
    plain.extend_from_slice(&body);

    let mut zlib = ZlibEncoder::new(Vec::new(), Compression::default());
    zlib.write_all(&plain)
        .and_then(|_| zlib.finish())
        .map(|compressed| format!("{VERSION}{}", STANDARD.encode(compressed)))
        .map_err(|_| TokenError::Malformed("compression failed".into()))
}

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], TokenError> {
        let end = self.pos.checked_add(n).filter(|end| *end <= self.data.len());
        let end = end.ok_or_else(|| TokenError::Malformed("token data ends early".into()))?;
        let slice = &self.data[self.pos..end];
        self.pos = end;
        Ok(slice)
    }
    fn u16(&mut self) -> Result<u16, TokenError> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().expect("2 bytes")))
    }
    fn u32(&mut self) -> Result<u32, TokenError> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().expect("4 bytes")))
    }
    fn i16(&mut self) -> Result<i16, TokenError> {
        Ok(i16::from_le_bytes(self.take(2)?.try_into().expect("2 bytes")))
    }
    fn bytes(&mut self) -> Result<&'a [u8], TokenError> {
        let len = self.u16()? as usize;
        self.take(len)
    }
    fn string(&mut self) -> Result<String, TokenError> {
        String::from_utf8(self.bytes()?.to_vec())
            .map_err(|_| TokenError::Malformed("a text field is not UTF-8".into()))
    }
}

pub(crate) fn parse(token: &str) -> Result<Parsed, TokenError> {
    if token.len() > MAX_TOKEN_LEN {
        return Err(TokenError::Malformed("token is longer than 16 KiB".into()));
    }
    let encoded = token.strip_prefix(VERSION).ok_or(TokenError::UnsupportedVersion)?;
    let compressed = STANDARD
        .decode(encoded)
        .or_else(|_| STANDARD_NO_PAD.decode(encoded))
        .map_err(|_| TokenError::Malformed("not base64".into()))?;
    let mut data = Vec::new();
    ZlibDecoder::new(compressed.as_slice())
        .take(MAX_DECOMPRESSED as u64 + 1)
        .read_to_end(&mut data)
        .map_err(|_| TokenError::Malformed("not zlib data".into()))?;
    if data.len() > MAX_DECOMPRESSED {
        return Err(TokenError::Malformed("decompressed token is larger than 64 KiB".into()));
    }

    let mut r = Reader { data: &data, pos: 0 };
    let signature = r.bytes()?.to_vec();
    let body_start = r.pos;
    let app_id = r.string()?;
    let issue_ts = r.u32()?;
    let expire = r.u32()?;
    let salt = r.u32()?;
    let count = r.u16()?;
    let mut services = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let service_type = r.u16()?;
        let n = r.u16()?;
        let mut privileges = BTreeMap::new();
        for _ in 0..n {
            let privilege = r.u16()?;
            privileges.insert(privilege, r.u32()?);
        }
        let details = match service_type {
            1 => ServiceDetails::Rtc { channel: r.string()?, account: r.string()? },
            2 => ServiceDetails::Rtm { user_id: r.string()? },
            4 => ServiceDetails::Fpa,
            5 => ServiceDetails::Chat { user_id: r.string()? },
            7 => ServiceDetails::Apaas { room_uuid: r.string()?, user_uuid: r.string()?, role: r.i16()? },
            other => return Err(TokenError::Malformed(format!("unknown service type {other}"))),
        };
        services.push(Service { privileges, details });
    }
    if r.pos != data.len() {
        return Err(TokenError::Malformed("trailing bytes after the last service".into()));
    }
    Ok(Parsed {
        signature,
        body: data[body_start..].to_vec(),
        content: Content { app_id, issue_ts, expire, salt, services },
    })
}

/// Recomputes the signature over the signed bytes (constant-time compare).
pub(crate) fn signature_matches(parsed: &Parsed, app_certificate: &str) -> bool {
    let mut mac = signer(parsed.content.issue_ts, parsed.content.salt, app_certificate);
    mac.update(&parsed.body);
    mac.verify_slice(&parsed.signature).is_ok()
}
```

The `expect` calls are on HMAC key construction (any key length is valid for HMAC) and on fixed-size slices produced by `take(n)`; none depends on caller data.

- [ ] **Step 6: Run the tests**

Run: `cargo test -p atem-core`
Expected: all 10 tests PASS. If `encodes_upstreams_published_vector_byte_for_byte` fails, the packing order or zlib level differs from upstream: fix `wire.rs`, never the vector.

- [ ] **Step 7: Format, lint, commit**

```bash
rustfmt --edition 2024 crates/atem-core/src/*.rs
cargo clippy -p atem-core --all-targets -- -D warnings
cargo test -- --test-threads=1   # the atem package still builds and passes
git add Cargo.toml Cargo.lock crates/atem-core designs/atem-core.md designs/plans/2026-10-13-atem-core-token-library.md
git commit -m "feat(atem-core): workspace and AccessToken2 codec (byte-identical to Agora's vector)

🤖 Built with SMT <smt@agora.build>"
```

---

### Task 2: Typed builders, decode and verify, proven against `agora_token`

**Files:**
- Modify: `crates/atem-core/src/token.rs` (add the API below), `crates/atem-core/src/lib.rs` (re-exports)
- Create: `crates/atem-core/tests/upstream_compat.rs`

**Interfaces:**
- Consumes: `wire::{Content, Service, encode, parse, signature_matches}` from Task 1.
- Produces (used by Tasks 3 and 4), all in `atem_core::token`:
  - `enum RtcIdentity<'a> { Uid(u32), UserAccount(&'a str) }` with `fn token_account(&self) -> String`
  - `enum RtcPrivileges { Publisher { expire: u32 }, Subscriber { expire: u32 }, Explicit { join: u32, publish_audio: u32, publish_video: u32, publish_data: u32 } }`
  - `struct RtmLogin<'a> { pub user_id: Option<&'a str>, pub expire: u32 }`
  - `struct RtcTokenRequest<'a> { pub app_id: &'a str, pub app_certificate: &'a str, pub channel: &'a str, pub identity: RtcIdentity<'a>, pub privileges: RtcPrivileges, pub token_expire: u32, pub rtm: Option<RtmLogin<'a>> }`
  - `struct RtmTokenRequest<'a> { pub app_id: &'a str, pub app_certificate: &'a str, pub user_id: &'a str, pub expire: u32 }`
  - `struct Issue { pub issued_at: u32, pub salt: u32 }` with `Issue::now() -> Issue` and `Issue::at(issued_at: u32) -> Issue`
  - `fn build_rtc_token(&RtcTokenRequest, Issue) -> Result<String, TokenError>`
  - `fn build_rtm_token(&RtmTokenRequest, Issue) -> Result<String, TokenError>`
  - `fn decode_token(&str) -> Result<DecodedToken, TokenError>`
  - `fn verify_token_signature(token: &str, app_certificate: &str) -> Result<bool, TokenError>`

- [ ] **Step 1: Write the failing tests**

Create `crates/atem-core/tests/upstream_compat.rs`:

```rust
//! atem-core must produce exactly what Agora's own crate produces. Upstream
//! picks the issue time and salt itself, so each test decodes upstream's
//! token, rebuilds it with atem-core from the same issue time and salt, and
//! requires the same string.

use agora_token::{rtc_token_builder as rtc, rtm_token_builder as rtm};
use atem_core::token::*;

const APP_ID: &str = "970CA35de60c44645bbae8a215061b33";
const CERT: &str = "5CFd2fd1755d40ecb72977518be15d3b";
const CHANNEL: &str = "7d72365eb983485397e3e3f9d460bdda";

fn same_issue(upstream: &str) -> Issue {
    let d = decode_token(upstream).unwrap();
    Issue { issued_at: d.issued_at, salt: d.salt }
}

fn rtc_request<'a>(identity: RtcIdentity<'a>, privileges: RtcPrivileges, token_expire: u32) -> RtcTokenRequest<'a> {
    RtcTokenRequest { app_id: APP_ID, app_certificate: CERT, channel: CHANNEL, identity, privileges, token_expire, rtm: None }
}

#[test]
fn rtc_uid_publisher_and_subscriber_match_upstream() {
    for (role, privileges) in [
        (rtc::ROLE_PUBLISHER, RtcPrivileges::Publisher { expire: 1800 }),
        (rtc::ROLE_SUBSCRIBER, RtcPrivileges::Subscriber { expire: 1800 }),
    ] {
        let upstream = rtc::build_token_with_uid(APP_ID, CERT, CHANNEL, 2882341273, role, 3600, 1800).unwrap();
        let ours = build_rtc_token(&rtc_request(RtcIdentity::Uid(2882341273), privileges, 3600), same_issue(&upstream)).unwrap();
        assert_eq!(ours, upstream);
    }
}

#[test]
fn rtc_uid_zero_is_the_empty_account_like_upstream() {
    let upstream = rtc::build_token_with_uid(APP_ID, CERT, CHANNEL, 0, rtc::ROLE_PUBLISHER, 600, 600).unwrap();
    let ours = build_rtc_token(&rtc_request(RtcIdentity::Uid(0), RtcPrivileges::Publisher { expire: 600 }, 600), same_issue(&upstream)).unwrap();
    assert_eq!(ours, upstream);
}

#[test]
fn rtc_user_account_matches_upstream() {
    let upstream = rtc::build_token_with_user_account(APP_ID, CERT, CHANNEL, "alice", rtc::ROLE_PUBLISHER, 3600, 3600).unwrap();
    let ours = build_rtc_token(&rtc_request(RtcIdentity::UserAccount("alice"), RtcPrivileges::Publisher { expire: 3600 }, 3600), same_issue(&upstream)).unwrap();
    assert_eq!(ours, upstream);
}

#[test]
fn rtc_explicit_privileges_match_upstream() {
    let upstream = rtc::build_token_with_uid_and_privilege(APP_ID, CERT, CHANNEL, 42, 3600, 3000, 2000, 1000, 500).unwrap();
    let privileges = RtcPrivileges::Explicit { join: 3000, publish_audio: 2000, publish_video: 1000, publish_data: 500 };
    let ours = build_rtc_token(&rtc_request(RtcIdentity::Uid(42), privileges, 3600), same_issue(&upstream)).unwrap();
    assert_eq!(ours, upstream);
}

#[test]
fn rtc_with_rtm_same_account_matches_upstream() {
    let upstream = rtc::build_token_with_rtm(APP_ID, CERT, CHANNEL, "alice", rtc::ROLE_PUBLISHER, 3600, 1800).unwrap();
    let mut request = rtc_request(RtcIdentity::UserAccount("alice"), RtcPrivileges::Publisher { expire: 1800 }, 3600);
    request.rtm = Some(RtmLogin { user_id: None, expire: 3600 });
    assert_eq!(build_rtc_token(&request, same_issue(&upstream)).unwrap(), upstream);
}

#[test]
fn rtc_with_rtm_separate_account_matches_upstream() {
    let upstream = rtc::build_token_with_rtm2(APP_ID, CERT, CHANNEL, "alice", rtc::ROLE_SUBSCRIBER, 3600, 1800, 1800, 1800, 1800, "bob", 900).unwrap();
    let mut request = rtc_request(RtcIdentity::UserAccount("alice"), RtcPrivileges::Subscriber { expire: 1800 }, 3600);
    request.rtm = Some(RtmLogin { user_id: Some("bob"), expire: 900 });
    assert_eq!(build_rtc_token(&request, same_issue(&upstream)).unwrap(), upstream);
}

#[test]
fn rtm_matches_upstream() {
    let upstream = rtm::build_token(APP_ID, CERT, "atem01", 3600).unwrap();
    let request = RtmTokenRequest { app_id: APP_ID, app_certificate: CERT, user_id: "atem01", expire: 3600 };
    assert_eq!(build_rtm_token(&request, same_issue(&upstream)).unwrap(), upstream);
}

#[test]
fn upstream_tokens_verify_and_decode() {
    let upstream = rtc::build_token_with_rtm2(APP_ID, CERT, CHANNEL, "alice", rtc::ROLE_PUBLISHER, 3600, 1800, 1700, 1600, 1500, "bob", 900).unwrap();
    assert!(verify_token_signature(&upstream, CERT).unwrap());
    assert!(!verify_token_signature(&upstream, "00000000000000000000000000000000").unwrap());
    let d = decode_token(&upstream).unwrap();
    assert_eq!(d.app_id, APP_ID);
    assert_eq!(d.expire, 3600);
    assert_eq!(d.services.len(), 2);
    assert_eq!(d.services[0].details, ServiceDetails::Rtc { channel: CHANNEL.into(), account: "alice".into() });
    assert_eq!(d.services[0].privileges.get(&PRIVILEGE_PUBLISH_DATA_STREAM), Some(&1500));
    assert_eq!(d.services[1].details, ServiceDetails::Rtm { user_id: "bob".into() });
    assert_eq!(d.services[1].privileges.get(&PRIVILEGE_RTM_LOGIN), Some(&900));
}
```

Add a unit-test module at the bottom of `crates/atem-core/src/token.rs` for validation:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    const APP_ID: &str = "970CA35de60c44645bbae8a215061b33";
    const CERT: &str = "5CFd2fd1755d40ecb72977518be15d3b";
    const FIXED: Issue = Issue { issued_at: 1_700_000_000, salt: 7 };

    fn request() -> RtcTokenRequest<'static> {
        RtcTokenRequest {
            app_id: APP_ID,
            app_certificate: CERT,
            channel: "test-channel",
            identity: RtcIdentity::Uid(1),
            privileges: RtcPrivileges::Publisher { expire: 600 },
            token_expire: 600,
            rtm: None,
        }
    }

    #[test]
    fn credentials_must_be_32_hex_characters() {
        for bad in ["", "abc", "970CA35de60c44645bbae8a215061b3Z", "970CA35de60c44645bbae8a215061b333"] {
            let mut r = request();
            r.app_id = bad;
            assert_eq!(build_rtc_token(&r, FIXED).unwrap_err(), TokenError::InvalidAppId);
            let mut r = request();
            r.app_certificate = bad;
            assert_eq!(build_rtc_token(&r, FIXED).unwrap_err(), TokenError::InvalidAppCertificate);
        }
    }

    #[test]
    fn channel_must_be_1_to_64_bytes() {
        let long = "c".repeat(65);
        for bad in ["", long.as_str()] {
            let mut r = request();
            r.channel = bad;
            assert!(matches!(build_rtc_token(&r, FIXED), Err(TokenError::InvalidChannel(_))));
        }
        let max = "c".repeat(64);
        let mut r = request();
        r.channel = &max;
        assert!(build_rtc_token(&r, FIXED).is_ok());
    }

    #[test]
    fn user_account_must_be_1_to_255_bytes_and_uids_cover_the_whole_u32_range() {
        let long = "a".repeat(256);
        for bad in ["", long.as_str()] {
            let mut r = request();
            r.identity = RtcIdentity::UserAccount(bad);
            assert!(matches!(build_rtc_token(&r, FIXED), Err(TokenError::InvalidUserAccount(_))));
        }
        let max = "a".repeat(255);
        let mut r = request();
        r.identity = RtcIdentity::UserAccount(&max);
        assert!(build_rtc_token(&r, FIXED).is_ok());
        for uid in [0, 1, u32::MAX] {
            let mut r = request();
            r.identity = RtcIdentity::Uid(uid);
            let d = decode_token(&build_rtc_token(&r, FIXED).unwrap()).unwrap();
            let expected = if uid == 0 { String::new() } else { uid.to_string() };
            assert_eq!(d.services[0].details, ServiceDetails::Rtc { channel: "test-channel".into(), account: expected });
        }
    }

    #[test]
    fn every_expiry_must_be_at_least_one_second() {
        let mut r = request();
        r.token_expire = 0;
        assert!(matches!(build_rtc_token(&r, FIXED), Err(TokenError::InvalidExpiry(_))));
        for privileges in [
            RtcPrivileges::Publisher { expire: 0 },
            RtcPrivileges::Subscriber { expire: 0 },
            RtcPrivileges::Explicit { join: 1, publish_audio: 0, publish_video: 1, publish_data: 1 },
        ] {
            let mut r = request();
            r.privileges = privileges;
            assert!(matches!(build_rtc_token(&r, FIXED), Err(TokenError::InvalidExpiry(_))));
        }
        let mut r = request();
        r.rtm = Some(RtmLogin { user_id: Some("bob"), expire: 0 });
        assert!(matches!(build_rtc_token(&r, FIXED), Err(TokenError::InvalidExpiry(_))));
        let rtm = RtmTokenRequest { app_id: APP_ID, app_certificate: CERT, user_id: "bob", expire: 0 };
        assert!(matches!(build_rtm_token(&rtm, FIXED), Err(TokenError::InvalidExpiry(_))));
        let mut r = request();
        r.token_expire = u32::MAX;
        assert!(build_rtc_token(&r, FIXED).is_ok());
    }

    #[test]
    fn rtm_user_id_must_be_1_to_64_bytes_including_a_reused_rtc_account() {
        let long = "u".repeat(65);
        for bad in ["", long.as_str()] {
            let rtm = RtmTokenRequest { app_id: APP_ID, app_certificate: CERT, user_id: bad, expire: 60 };
            assert!(matches!(build_rtm_token(&rtm, FIXED), Err(TokenError::InvalidRtmUserId(_))));
        }
        // Uid 0 is the empty account: there is no RTM user to reuse.
        let mut r = request();
        r.identity = RtcIdentity::Uid(0);
        r.rtm = Some(RtmLogin { user_id: None, expire: 60 });
        assert!(matches!(build_rtc_token(&r, FIXED), Err(TokenError::InvalidRtmUserId(_))));
    }

    #[test]
    fn the_same_issue_gives_the_same_token_and_now_differs() {
        assert_eq!(build_rtc_token(&request(), FIXED).unwrap(), build_rtc_token(&request(), FIXED).unwrap());
        let a = Issue::now();
        assert!(a.salt >= 1 && a.salt < 99_999_999);
        assert!(a.issued_at > 1_700_000_000);
        assert_eq!(Issue::at(5).issued_at, 5);
    }

    #[test]
    fn errors_never_contain_the_certificate_or_the_token() {
        let token = build_rtc_token(&request(), FIXED).unwrap();
        let mut r = request();
        r.channel = "";
        let messages = [
            build_rtc_token(&r, FIXED).unwrap_err().to_string(),
            decode_token(&format!("{}!", &token[..token.len() - 1])).unwrap_err().to_string(),
            verify_token_signature("007garbage", CERT).unwrap_err().to_string(),
        ];
        for m in messages {
            assert!(!m.contains(CERT) && !m.contains(&token[3..20]), "{m}");
        }
    }
}
```

- [ ] **Step 2: Run them to see them fail**

Run: `cargo test -p atem-core`
Expected: compile errors (`build_rtc_token`, `RtcIdentity`, … not found). That is the failing state.

- [ ] **Step 3: Implement the API in `token.rs`** (above the test module, after the data types)

```rust
use crate::wire;

/// Who the RTC token is for. `Uid(0)` means any user (stored as an empty
/// account, as Agora does). Strings and numbers are never converted into
/// each other: a numeric user account is still a user account.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RtcIdentity<'a> {
    Uid(u32),
    UserAccount(&'a str),
}

impl RtcIdentity<'_> {
    /// The account string stored in the token.
    pub fn token_account(&self) -> String {
        match self {
            RtcIdentity::Uid(0) => String::new(),
            RtcIdentity::Uid(uid) => uid.to_string(),
            RtcIdentity::UserAccount(account) => (*account).to_string(),
        }
    }
}

/// RTC privileges, each valid for `expire` seconds after the issue time.
/// `Publisher` = join + publish audio, video and data; `Subscriber` = join.
/// Publish privileges only matter when co-host authentication is enabled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RtcPrivileges {
    Publisher { expire: u32 },
    Subscriber { expire: u32 },
    Explicit { join: u32, publish_audio: u32, publish_video: u32, publish_data: u32 },
}

/// Adds an RTM login to an RTC token. `user_id: None` reuses the RTC account.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RtmLogin<'a> {
    pub user_id: Option<&'a str>,
    pub expire: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RtcTokenRequest<'a> {
    pub app_id: &'a str,
    pub app_certificate: &'a str,
    pub channel: &'a str,
    pub identity: RtcIdentity<'a>,
    pub privileges: RtcPrivileges,
    /// Seconds after the issue time.
    pub token_expire: u32,
    pub rtm: Option<RtmLogin<'a>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RtmTokenRequest<'a> {
    pub app_id: &'a str,
    pub app_certificate: &'a str,
    pub user_id: &'a str,
    /// Seconds after the issue time (token and login privilege).
    pub expire: u32,
}

/// When the token is issued (unix seconds) and its random salt. Fixed values
/// make tokens reproducible (tests); `now()` is what callers normally use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Issue {
    pub issued_at: u32,
    pub salt: u32,
}

impl Issue {
    /// The system clock and a random salt.
    ///
    /// Panics if the operating system's random source is unavailable.
    pub fn now() -> Issue {
        let issued_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as u32)
            .unwrap_or(0);
        Issue::at(issued_at)
    }

    /// A caller-supplied issue time (e.g. from a synced clock) and a random salt.
    pub fn at(issued_at: u32) -> Issue {
        let mut bytes = [0u8; 4];
        getrandom::getrandom(&mut bytes).expect("operating system random source");
        // 1..99_999_999, the range Agora's own builders use.
        Issue { issued_at, salt: 1 + u32::from_le_bytes(bytes) % 99_999_998 }
    }
}

fn is_hex32(s: &str) -> bool {
    s.len() == 32 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

fn check_credentials(app_id: &str, app_certificate: &str) -> Result<(), TokenError> {
    if !is_hex32(app_id) {
        return Err(TokenError::InvalidAppId);
    }
    if !is_hex32(app_certificate) {
        return Err(TokenError::InvalidAppCertificate);
    }
    Ok(())
}

fn check_len(value: &str, max: usize) -> Result<(), String> {
    match value.len() {
        0 => Err("must not be empty".into()),
        n if n > max => Err(format!("must be at most {max} bytes, got {n}")),
        _ => Ok(()),
    }
}

fn check_expiry(what: &str, seconds: u32) -> Result<(), TokenError> {
    if seconds == 0 {
        return Err(TokenError::InvalidExpiry(format!("{what} must be at least 1 second")));
    }
    Ok(())
}

/// Builds an RTC token (optionally with an RTM login).
pub fn build_rtc_token(request: &RtcTokenRequest, issue: Issue) -> Result<String, TokenError> {
    check_credentials(request.app_id, request.app_certificate)?;
    check_len(request.channel, 64).map_err(TokenError::InvalidChannel)?;
    if let RtcIdentity::UserAccount(account) = request.identity {
        check_len(account, 255).map_err(TokenError::InvalidUserAccount)?;
    }
    check_expiry("token expiry", request.token_expire)?;

    let mut privileges = std::collections::BTreeMap::new();
    match request.privileges {
        RtcPrivileges::Publisher { expire } => {
            check_expiry("privilege expiry", expire)?;
            for p in [
                PRIVILEGE_JOIN_CHANNEL,
                PRIVILEGE_PUBLISH_AUDIO_STREAM,
                PRIVILEGE_PUBLISH_VIDEO_STREAM,
                PRIVILEGE_PUBLISH_DATA_STREAM,
            ] {
                privileges.insert(p, expire);
            }
        }
        RtcPrivileges::Subscriber { expire } => {
            check_expiry("privilege expiry", expire)?;
            privileges.insert(PRIVILEGE_JOIN_CHANNEL, expire);
        }
        RtcPrivileges::Explicit { join, publish_audio, publish_video, publish_data } => {
            for (what, privilege, expire) in [
                ("join channel expiry", PRIVILEGE_JOIN_CHANNEL, join),
                ("publish audio expiry", PRIVILEGE_PUBLISH_AUDIO_STREAM, publish_audio),
                ("publish video expiry", PRIVILEGE_PUBLISH_VIDEO_STREAM, publish_video),
                ("publish data expiry", PRIVILEGE_PUBLISH_DATA_STREAM, publish_data),
            ] {
                check_expiry(what, expire)?;
                privileges.insert(privilege, expire);
            }
        }
    }

    let account = request.identity.token_account();
    let mut services = vec![wire::Service {
        privileges,
        details: ServiceDetails::Rtc { channel: request.channel.to_string(), account: account.clone() },
    }];
    if let Some(rtm) = request.rtm {
        check_expiry("RTM login expiry", rtm.expire)?;
        let user_id = rtm.user_id.map(str::to_string).unwrap_or(account);
        check_len(&user_id, 64).map_err(TokenError::InvalidRtmUserId)?;
        services.push(wire::Service {
            privileges: std::collections::BTreeMap::from([(PRIVILEGE_RTM_LOGIN, rtm.expire)]),
            details: ServiceDetails::Rtm { user_id },
        });
    }
    wire::encode(
        &wire::Content {
            app_id: request.app_id.to_string(),
            issue_ts: issue.issued_at,
            expire: request.token_expire,
            salt: issue.salt,
            services,
        },
        request.app_certificate,
    )
}

/// Builds an RTM token (login privilege for `expire` seconds).
pub fn build_rtm_token(request: &RtmTokenRequest, issue: Issue) -> Result<String, TokenError> {
    check_credentials(request.app_id, request.app_certificate)?;
    check_len(request.user_id, 64).map_err(TokenError::InvalidRtmUserId)?;
    check_expiry("expiry", request.expire)?;
    wire::encode(
        &wire::Content {
            app_id: request.app_id.to_string(),
            issue_ts: issue.issued_at,
            expire: request.expire,
            salt: issue.salt,
            services: vec![wire::Service {
                privileges: std::collections::BTreeMap::from([(PRIVILEGE_RTM_LOGIN, request.expire)]),
                details: ServiceDetails::Rtm { user_id: request.user_id.to_string() },
            }],
        },
        request.app_certificate,
    )
}

/// Reads a token's fields. This does **not** establish that the token is
/// authentic; use `verify_token_signature` for that.
pub fn decode_token(token: &str) -> Result<DecodedToken, TokenError> {
    let parsed = wire::parse(token.trim())?;
    let content = parsed.content;
    Ok(DecodedToken {
        version: wire::VERSION.to_string(),
        app_id: content.app_id,
        issued_at: content.issue_ts,
        expire: content.expire,
        salt: content.salt,
        services: content
            .services
            .into_iter()
            .map(|s| DecodedService { service_type: s.details.service_type(), privileges: s.privileges, details: s.details })
            .collect(),
    })
}

/// Whether `token` was signed with `app_certificate`. `Ok(false)` for a
/// well-formed token signed with another certificate.
pub fn verify_token_signature(token: &str, app_certificate: &str) -> Result<bool, TokenError> {
    if !is_hex32(app_certificate) {
        return Err(TokenError::InvalidAppCertificate);
    }
    Ok(wire::signature_matches(&wire::parse(token.trim())?, app_certificate))
}
```

`decode_token` trims surrounding whitespace (pasted tokens often carry a newline); `atem`'s CLI passes the raw argument.

Update `crates/atem-core/src/lib.rs`'s last line to:

```rust
pub use error::TokenError;
pub use token::{
    DecodedService, DecodedToken, Issue, RtcIdentity, RtcPrivileges, RtcTokenRequest, RtmLogin,
    RtmTokenRequest, ServiceDetails, build_rtc_token, build_rtm_token, decode_token,
    verify_token_signature,
};
```

- [ ] **Step 4: Run the tests**

Run: `cargo test -p atem-core`
Expected: all unit and `upstream_compat` tests PASS. A mismatch with upstream means `build_rtc_token` builds different privileges or service fields than the corresponding upstream builder (compare with `~/.cargo/git/checkouts/tools-*/374cd21/DynamicKey/AgoraDynamicKey/rust/src/rtc_token_builder.rs`); fix atem-core, not the test.

- [ ] **Step 5: Format, lint, commit**

```bash
rustfmt --edition 2024 crates/atem-core/src/*.rs crates/atem-core/tests/*.rs
cargo clippy -p atem-core --all-targets -- -D warnings
git add crates/atem-core
git commit -m "feat(atem-core): typed RTC/RTM builders, decode and explicit signature check

🤖 Built with SMT <smt@agora.build>"
```

---

### Task 3: `atem` uses `atem-core`

**Files:**
- Modify: root `Cargo.toml` (add `atem-core = { path = "crates/atem-core" }`, remove the `agora_token` line), `src/token.rs`
- Unchanged callers (they keep calling `crate::token::…`): `src/cli.rs:657-800`, `src/web_server/token_endpoint.rs`, `src/convo_test_server.rs`

**Interfaces:**
- Consumes: everything Task 2 produces.
- Produces: the same `crate::token` items the callers use today, with the same signatures: `Role`, `RtcAccount::{parse, as_str, mode_label}`, `build_token_rtc(app_id, app_certificate, channel, account: RtcAccount, role: Role, expire_secs: u32, issued_at: u32) -> anyhow::Result<String>`, `build_token_rtc_with_rtm(app_id, app_certificate, channel, rtc_account, role, token_expire_secs, privilege_expire_secs, rtm_user_id: Option<&str>) -> anyhow::Result<String>`, `build_token_rtm(app_id, app_certificate, user_id, expire_secs, issued_at) -> anyhow::Result<String>`, `decode_token(&str) -> anyhow::Result<TokenInfo>`, `TokenInfo`/`ServiceInfo` and their display methods, `SERVICE_TYPE_RTC`/`SERVICE_TYPE_RTM`.

Behaviour kept exactly (these rules live in atem, not the library):
- An empty App Certificate returns `Ok(String::new())` (the test servers rely on it for projects without a certificate).
- `RtcAccount::parse` (`s/` prefix, digits → uid, overflow → string) is unchanged.
- `RtcAccount::Str("")` (an empty `s/`) is sent as `RtcIdentity::Uid(0)`, the empty account it always produced.
- The RTC+RTM builder stores the RTC account as a string (`rtc_account.as_str()`, so uid 0 is `"0"`), and the RTM login lasts `token_expire_secs`, as before.

Behaviour that changes (and is intended):
- `issued_at` is now honoured. It was ignored before, so the CLI's time-synced clock (`TimeSync`) now really sets the issue time. `0` means the system clock.
- An RTC+RTM token whose RTM user would be empty now fails with "invalid RTM user id: must not be empty" instead of producing an unusable token.

- [ ] **Step 1: Check the existing tests are the safety net**

Run: `cargo test token:: -- --test-threads=1`
Expected: PASS (about 47 tests in `src/token.rs`). They must still pass after Step 3, unchanged, except tests that assert one of the two intended changes above. If one does, change it to assert the new behaviour and say so in the commit message.

- [ ] **Step 2: Add one failing test for the honoured issue time**

In `src/token.rs`'s test module add:

```rust
    #[test]
    fn issued_at_is_honoured() {
        let t = build_token_rtc(
            "970CA35de60c44645bbae8a215061b33",
            "5CFd2fd1755d40ecb72977518be15d3b",
            "c",
            RtcAccount::Int(1),
            Role::Publisher,
            600,
            1_700_000_000,
        )
        .unwrap();
        assert_eq!(decode_token(&t).unwrap().issue_ts, 1_700_000_000);
    }
```

Run: `cargo test token::tests::issued_at_is_honoured`
Expected: FAIL (the current code ignores `_issued_at`).

- [ ] **Step 3: Replace the generation and decode internals**

In `Cargo.toml` replace the `agora_token = { git = … }` line with `atem-core = { path = "crates/atem-core" }`.

In `src/token.rs`:
1. Replace the `use agora_token::…` lines and the `SERVICE_TYPE_*` constants with:

```rust
use anyhow::Result;
use atem_core::token as core;
use std::collections::HashMap;

pub const SERVICE_TYPE_RTC: u16 = core::SERVICE_RTC;
pub const SERVICE_TYPE_RTM: u16 = core::SERVICE_RTM;
```

   Keep any other `use` lines that the display code still needs. Remove `base64`, `flate2` and `IoRead` imports only if the compiler reports them unused.

2. Add the glue helpers and replace the bodies of `build_token_rtc`, `build_token_rtc_with_rtm`, `build_token_rtm` and `decode_token` (signatures unchanged):

```rust
/// atem's identity rules on top of the library: `RtcAccount::parse` decides
/// int uid vs string account; an empty string account is uid 0.
fn identity<'a>(account: &RtcAccount<'a>) -> core::RtcIdentity<'a> {
    match *account {
        RtcAccount::Int(uid) => core::RtcIdentity::Uid(uid),
        RtcAccount::Str("") => core::RtcIdentity::Uid(0),
        RtcAccount::Str(account) => core::RtcIdentity::UserAccount(account),
    }
}

fn privileges(role: Role, expire: u32) -> core::RtcPrivileges {
    match role {
        Role::Publisher => core::RtcPrivileges::Publisher { expire },
        Role::Subscriber => core::RtcPrivileges::Subscriber { expire },
    }
}

/// `issued_at` from a synced clock, or the system clock when 0.
fn issue(issued_at: u32) -> core::Issue {
    if issued_at == 0 { core::Issue::now() } else { core::Issue::at(issued_at) }
}

/// Build an Agora AccessToken2 for RTC. Auto-selects int-uid vs string-account path.
/// An empty certificate means the project has none: no token, not an error.
pub fn build_token_rtc(
    app_id: &str,
    app_certificate: &str,
    channel: &str,
    account: RtcAccount<'_>,
    role: Role,
    expire_secs: u32,
    issued_at: u32,
) -> Result<String> {
    if app_certificate.is_empty() {
        return Ok(String::new());
    }
    let request = core::RtcTokenRequest {
        app_id,
        app_certificate,
        channel,
        identity: identity(&account),
        privileges: privileges(role, expire_secs),
        token_expire: expire_secs,
        rtm: None,
    };
    Ok(core::build_rtc_token(&request, issue(issued_at))?)
}

/// Build a combined RTC + RTM AccessToken2 (`BuildTokenWithRtm`). The RTC
/// account is stored as a string (uid 0 → "0"), and `rtm_user_id: None`
/// reuses it for RTM; the RTM login lasts `token_expire_secs`.
pub fn build_token_rtc_with_rtm(
    app_id: &str,
    app_certificate: &str,
    channel: &str,
    rtc_account: RtcAccount<'_>,
    role: Role,
    token_expire_secs: u32,
    privilege_expire_secs: u32,
    rtm_user_id: Option<&str>,
) -> Result<String> {
    if app_certificate.is_empty() {
        return Ok(String::new());
    }
    let account = rtc_account.as_str();
    let request = core::RtcTokenRequest {
        app_id,
        app_certificate,
        channel,
        identity: if account.is_empty() {
            core::RtcIdentity::Uid(0)
        } else {
            core::RtcIdentity::UserAccount(&account)
        },
        privileges: privileges(role, privilege_expire_secs),
        token_expire: token_expire_secs,
        rtm: Some(core::RtmLogin { user_id: rtm_user_id, expire: token_expire_secs }),
    };
    Ok(core::build_rtc_token(&request, core::Issue::now())?)
}

/// Build an Agora AccessToken2 for RTM.
pub fn build_token_rtm(
    app_id: &str,
    app_certificate: &str,
    user_id: &str,
    expire_secs: u32,
    issued_at: u32,
) -> Result<String> {
    if app_certificate.is_empty() {
        return Ok(String::new());
    }
    let request = core::RtmTokenRequest { app_id, app_certificate, user_id, expire: expire_secs };
    Ok(core::build_rtm_token(&request, issue(issued_at))?)
}

/// Decode a token to inspect its fields (for diagnostics). Does not verify
/// the signature.
pub fn decode_token(token: &str) -> Result<TokenInfo> {
    let d = core::decode_token(token)?;
    Ok(TokenInfo {
        version: d.version,
        app_id: d.app_id,
        issue_ts: d.issued_at,
        expire: d.expire,
        salt: d.salt,
        services: d
            .services
            .into_iter()
            .map(|s| {
                let (channel, rtc_user_id, rtm_user_id) = match s.details {
                    core::ServiceDetails::Rtc { channel, account } => (Some(channel), Some(account), None),
                    core::ServiceDetails::Rtm { user_id } => (None, None, Some(user_id)),
                    _ => (None, None, None),
                };
                ServiceInfo {
                    service_type: s.service_type,
                    privileges: s.privileges.into_iter().collect::<HashMap<_, _>>(),
                    channel,
                    rtc_user_id,
                    rtm_user_id,
                }
            })
            .collect(),
    })
}
```

3. Delete the now-unused private helpers (`zlib_decompress`, `read_uint16`, `read_uint32`, `read_string`, and anything else the compiler reports as dead after the change). Keep `TokenInfo`, `ServiceInfo`, `display`, `display_at` and the formatting helpers.

- [ ] **Step 4: Run all atem tests**

Run: `cargo test -- --test-threads=1`, then `cargo test` (parallel) twice.
Expected: PASS, including `issued_at_is_honoured` and every pre-existing token test (except any you changed under Step 1's rule).

Also check the CLI by hand (no credentials needed for decode):

```bash
cargo run -q -- token rtc decode "007eJwBigB1/yAAFqC4TFpegsv3T7gT0J9ZxUvaycBhIFgFOayXV46VixogADk3MENBMzVkZTYwYzQ0NjQ1YmJhZThhMjE1MDYxYjMzR/QQAFgCAAABAAAAAQABAAEAAQBYAgAAIAA3ZDcyMzY1ZWI5ODM0ODUzOTdlM2UzZjlkNDYwYmRkYQoAMjg4MjM0MTI3M8JqJOM="
```

Expected: the decoded fields (App ID `970CA35d…`, channel `7d72365e…`, user `2882341273`, join channel privilege), formatted as before.

- [ ] **Step 5: Format, lint, commit**

```bash
rustfmt --edition 2024 src/token.rs
cargo clippy --all-targets 2>&1 | grep -c "^warning"   # not higher than on main
git add Cargo.toml Cargo.lock src/token.rs
git commit -m "refactor(token): atem builds and decodes tokens through atem-core

The CLI's issue time (synced clock) is now honoured; agora_token is no
longer a dependency of the binary.

🤖 Built with SMT <smt@agora.build>"
```

---

### Task 4: The C ABI (`atem-core-ffi`)

**Files:**
- Modify: root `Cargo.toml` (`members = ["crates/atem-core", "crates/atem-core-ffi"]`)
- Create: `crates/atem-core-ffi/Cargo.toml`, `crates/atem-core-ffi/src/lib.rs`, `crates/atem-core-ffi/include/atem_core.h`, `crates/atem-core-ffi/include/module.modulemap`, `crates/atem-core-ffi/tests/abi.rs`

**Interfaces:**
- Consumes: `atem_core::token::*` (Task 2) with the `serde` feature.
- Produces (C symbols, used by Task 5's consumers and Astation): `atem_core_abi_version`, `atem_core_version`, `atem_core_build_rtc_token`, `atem_core_build_rtm_token`, `atem_core_decode_token`, `atem_core_verify_token_signature`, `atem_core_string_free`; structs `AtemCoreRtcTokenParams`, `AtemCoreRtmTokenParams`; the `ATEM_CORE_*` constants — exactly as in the header below.

- [ ] **Step 1: Manifest and header**

`crates/atem-core-ffi/Cargo.toml`:

```toml
[package]
name = "atem-core-ffi"
version = "0.1.0"
edition = "2024"
description = "C ABI for atem-core (Agora RTC/RTM tokens), for Swift and other native hosts"
publish = false

[lib]
name = "atem_core_ffi"
crate-type = ["staticlib", "cdylib", "rlib"]

[dependencies]
atem-core = { path = "../atem-core", features = ["serde"] }
serde_json = "1.0"
```

`crates/atem-core-ffi/include/atem_core.h`:

```c
/*
 * atem_core.h — C ABI for atem-core: Agora AccessToken2 (RTC/RTM) tokens.
 * ABI version 1. See crates/atem-core-ffi/README.md and designs/atem-core.md.
 *
 * Rules for every function:
 *  - Strings are NUL-terminated UTF-8.
 *  - Returns ATEM_CORE_OK (0) or an error code below. On success the output
 *    string is set and *out_error is NULL; on failure outputs are NULL and,
 *    if out_error is not NULL, *out_error holds a message.
 *  - Every string returned through an out-parameter is owned by the caller
 *    and must be freed exactly once with atem_core_string_free (NULL is ok).
 *  - Functions are thread-safe and keep no state. Nothing is logged; error
 *    messages never contain the App Certificate or a token.
 */
#ifndef ATEM_CORE_H
#define ATEM_CORE_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ATEM_CORE_ABI_VERSION 1u

/* Status codes. */
#define ATEM_CORE_OK                           0
#define ATEM_CORE_ERR_NULL_ARGUMENT            1
#define ATEM_CORE_ERR_INVALID_UTF8             2
#define ATEM_CORE_ERR_STRUCT_SIZE              3
#define ATEM_CORE_ERR_INVALID_ARGUMENT         4
#define ATEM_CORE_ERR_INVALID_APP_ID          10
#define ATEM_CORE_ERR_INVALID_APP_CERTIFICATE 11
#define ATEM_CORE_ERR_INVALID_CHANNEL         12
#define ATEM_CORE_ERR_INVALID_USER_ACCOUNT    13
#define ATEM_CORE_ERR_INVALID_RTM_USER_ID     14
#define ATEM_CORE_ERR_INVALID_EXPIRY          15
#define ATEM_CORE_ERR_UNSUPPORTED_VERSION     20
#define ATEM_CORE_ERR_MALFORMED_TOKEN         21
#define ATEM_CORE_ERR_INTERNAL                99

/* AtemCoreRtcTokenParams.role */
#define ATEM_CORE_ROLE_EXPLICIT   0u /* use the four *_expire privilege fields */
#define ATEM_CORE_ROLE_PUBLISHER  1u /* join + publish audio/video/data, privilege_expire */
#define ATEM_CORE_ROLE_SUBSCRIBER 2u /* join only, privilege_expire */

/* All expiries are seconds after the issue time and must be >= 1. */
typedef struct AtemCoreRtcTokenParams {
    uint32_t struct_size;          /* sizeof(AtemCoreRtcTokenParams) */
    const char *app_id;            /* 32 hex characters */
    const char *app_certificate;   /* 32 hex characters */
    const char *channel;           /* 1-64 bytes */
    uint32_t uid;                  /* used when user_account is NULL; 0 = any user */
    const char *user_account;      /* NULL, or a 1-255 byte user account (then uid is ignored) */
    uint32_t role;                 /* ATEM_CORE_ROLE_* */
    uint32_t token_expire;
    uint32_t privilege_expire;     /* PUBLISHER / SUBSCRIBER */
    uint32_t join_channel_expire;  /* EXPLICIT */
    uint32_t publish_audio_expire; /* EXPLICIT */
    uint32_t publish_video_expire; /* EXPLICIT */
    uint32_t publish_data_expire;  /* EXPLICIT */
    uint32_t with_rtm;             /* 0 or 1: also grant RTM login */
    const char *rtm_user_id;       /* NULL = reuse the RTC account; else 1-64 bytes */
    uint32_t rtm_expire;           /* when with_rtm = 1 */
    uint32_t issued_at;            /* unix seconds; 0 = now */
    uint32_t salt;                 /* 0 = random (normal use); fixed only for tests */
} AtemCoreRtcTokenParams;

typedef struct AtemCoreRtmTokenParams {
    uint32_t struct_size;          /* sizeof(AtemCoreRtmTokenParams) */
    const char *app_id;
    const char *app_certificate;
    const char *user_id;           /* 1-64 bytes */
    uint32_t expire;
    uint32_t issued_at;            /* 0 = now */
    uint32_t salt;                 /* 0 = random */
} AtemCoreRtmTokenParams;

/* ATEM_CORE_ABI_VERSION of the linked library. */
uint32_t atem_core_abi_version(void);

/* atem-core's version, e.g. "0.1.0". Static: never free it. */
const char *atem_core_version(void);

int32_t atem_core_build_rtc_token(const AtemCoreRtcTokenParams *params,
                                  char **out_token, char **out_error);

int32_t atem_core_build_rtm_token(const AtemCoreRtmTokenParams *params,
                                  char **out_token, char **out_error);

/*
 * Reads a token's fields into JSON. Does NOT establish authenticity; use
 * atem_core_verify_token_signature. JSON shape:
 * {"version":"007","app_id":"...","issued_at":1700000000,"expire":3600,
 *  "salt":123,"services":[{"service_type":1,"privileges":{"1":3600,...},
 *  "details":{"kind":"rtc","channel":"...","account":"..."}},
 *  {"service_type":2,...,"details":{"kind":"rtm","user_id":"..."}}]}
 * Other kinds: "fpa", "chat" (user_id), "apaas" (room_uuid, user_uuid, role).
 */
int32_t atem_core_decode_token(const char *token, char **out_json, char **out_error);

/* *out_valid = 1 if token was signed with app_certificate, else 0. */
int32_t atem_core_verify_token_signature(const char *token, const char *app_certificate,
                                         int32_t *out_valid, char **out_error);

/* Frees a string returned by this library. NULL is ignored. */
void atem_core_string_free(char *s);

#ifdef __cplusplus
}
#endif

#endif /* ATEM_CORE_H */
```

`crates/atem-core-ffi/include/module.modulemap`:

```
module AtemCore {
    header "atem_core.h"
    export *
}
```

Add `"crates/atem-core-ffi"` to the workspace `members` in the root `Cargo.toml`.

- [ ] **Step 2: Write the failing ABI tests**

`crates/atem-core-ffi/tests/abi.rs`:

```rust
//! The C ABI as a C caller sees it: status codes, ownership, nulls, sizes.

use atem_core_ffi::*;
use std::ffi::{CStr, CString, c_char};
use std::ptr::{null, null_mut};

const APP_ID: &str = "970CA35de60c44645bbae8a215061b33";
const CERT: &str = "5CFd2fd1755d40ecb72977518be15d3b";
const VECTOR: &str = "007eJwBigB1/yAAFqC4TFpegsv3T7gT0J9ZxUvaycBhIFgFOayXV46VixogADk3MENBMzVkZTYwYzQ0NjQ1YmJhZThhMjE1MDYxYjMzR/QQAFgCAAABAAAAAQABAAEAAQBYAgAAIAA3ZDcyMzY1ZWI5ODM0ODUzOTdlM2UzZjlkNDYwYmRkYQoAMjg4MjM0MTI3M8JqJOM=";

struct Strings(Vec<CString>);
impl Strings {
    fn c(&mut self, s: &str) -> *const c_char {
        self.0.push(CString::new(s).unwrap());
        self.0.last().unwrap().as_ptr()
    }
}

/// Takes ownership of a returned string (frees it through the ABI).
fn take(p: *mut c_char) -> Option<String> {
    if p.is_null() {
        return None;
    }
    let s = unsafe { CStr::from_ptr(p) }.to_str().unwrap().to_string();
    unsafe { atem_core_string_free(p) };
    Some(s)
}

/// The published vector's inputs: uid 2882341273, join only, 600 s.
fn vector_params(s: &mut Strings) -> AtemCoreRtcTokenParams {
    AtemCoreRtcTokenParams {
        struct_size: std::mem::size_of::<AtemCoreRtcTokenParams>() as u32,
        app_id: s.c(APP_ID),
        app_certificate: s.c(CERT),
        channel: s.c("7d72365eb983485397e3e3f9d460bdda"),
        uid: 2882341273,
        user_account: null(),
        role: ATEM_CORE_ROLE_SUBSCRIBER,
        token_expire: 600,
        privilege_expire: 600,
        join_channel_expire: 0,
        publish_audio_expire: 0,
        publish_video_expire: 0,
        publish_data_expire: 0,
        with_rtm: 0,
        rtm_user_id: null(),
        rtm_expire: 0,
        issued_at: 1111111,
        salt: 1,
    }
}

fn build(params: &AtemCoreRtcTokenParams) -> (i32, Option<String>, Option<String>) {
    let (mut token, mut error) = (null_mut(), null_mut());
    let status = unsafe { atem_core_build_rtc_token(params, &mut token, &mut error) };
    (status, take(token), take(error))
}

#[test]
fn reports_its_abi_and_version() {
    assert_eq!(atem_core_abi_version(), 1);
    let v = unsafe { CStr::from_ptr(atem_core_version()) }.to_str().unwrap();
    assert_eq!(v, env!("CARGO_PKG_VERSION"));
}

#[test]
fn builds_the_published_vector_through_the_abi() {
    let mut s = Strings(vec![]);
    let (status, token, error) = build(&vector_params(&mut s));
    assert_eq!((status, token.as_deref(), error), (ATEM_CORE_OK, Some(VECTOR), None));
}

#[test]
fn explicit_publisher_rtm_and_user_account_variants_build() {
    let mut s = Strings(vec![]);
    let mut p = vector_params(&mut s);
    p.user_account = s.c("alice");
    p.role = ATEM_CORE_ROLE_EXPLICIT;
    p.join_channel_expire = 300;
    p.publish_audio_expire = 200;
    p.publish_video_expire = 100;
    p.publish_data_expire = 50;
    p.with_rtm = 1;
    p.rtm_user_id = s.c("bob");
    p.rtm_expire = 60;
    let (status, token, _) = build(&p);
    assert_eq!(status, ATEM_CORE_OK);
    let d = atem_core::decode_token(&token.unwrap()).unwrap();
    assert_eq!(d.services.len(), 2);
    assert_eq!(d.services[0].privileges.get(&4), Some(&50));
}

#[test]
fn validation_errors_map_to_codes_and_messages_without_secrets() {
    let mut s = Strings(vec![]);
    let cases: Vec<(Box<dyn Fn(&mut AtemCoreRtcTokenParams, &mut Strings)>, i32)> = vec![
        (Box::new(|p, s| p.app_id = s.c("nothex")), ATEM_CORE_ERR_INVALID_APP_ID),
        (Box::new(|p, s| p.app_certificate = s.c("nothex")), ATEM_CORE_ERR_INVALID_APP_CERTIFICATE),
        (Box::new(|p, s| p.channel = s.c("")), ATEM_CORE_ERR_INVALID_CHANNEL),
        (Box::new(|p, s| p.user_account = s.c("")), ATEM_CORE_ERR_INVALID_USER_ACCOUNT),
        (Box::new(|p, _| p.token_expire = 0), ATEM_CORE_ERR_INVALID_EXPIRY),
        (Box::new(|p, _| { p.with_rtm = 1; p.rtm_expire = 60; p.uid = 0 }), ATEM_CORE_ERR_INVALID_RTM_USER_ID),
        (Box::new(|p, _| p.role = 7), ATEM_CORE_ERR_INVALID_ARGUMENT),
        (Box::new(|p, _| p.with_rtm = 2), ATEM_CORE_ERR_INVALID_ARGUMENT),
    ];
    for (edit, code) in cases {
        let mut p = vector_params(&mut s);
        edit(&mut p, &mut s);
        let (status, token, error) = build(&p);
        assert_eq!(status, code);
        assert!(token.is_none());
        let error = error.expect("an error message");
        assert!(!error.contains(CERT), "{error}");
    }
}

#[test]
fn null_and_bad_utf8_arguments_are_errors_not_crashes() {
    let mut s = Strings(vec![]);
    let (mut token, mut error) = (null_mut(), null_mut());
    assert_eq!(unsafe { atem_core_build_rtc_token(null(), &mut token, &mut error) }, ATEM_CORE_ERR_NULL_ARGUMENT);
    assert!(token.is_null());
    take(error);

    let p = vector_params(&mut s);
    assert_eq!(unsafe { atem_core_build_rtc_token(&p, null_mut(), null_mut()) }, ATEM_CORE_ERR_NULL_ARGUMENT);

    let mut p = vector_params(&mut s);
    p.channel = null();
    assert_eq!(build(&p).0, ATEM_CORE_ERR_NULL_ARGUMENT);

    let bad = [0xff_u8, 0xfe, 0];
    let mut p = vector_params(&mut s);
    p.channel = bad.as_ptr().cast();
    assert_eq!(build(&p).0, ATEM_CORE_ERR_INVALID_UTF8);

    // A NULL out_error is allowed: the status still says what failed.
    let mut p = vector_params(&mut s);
    p.token_expire = 0;
    let mut token = null_mut();
    assert_eq!(unsafe { atem_core_build_rtc_token(&p, &mut token, null_mut()) }, ATEM_CORE_ERR_INVALID_EXPIRY);
    assert!(token.is_null());
}

#[test]
fn an_unknown_struct_size_is_rejected() {
    let mut s = Strings(vec![]);
    let mut p = vector_params(&mut s);
    p.struct_size -= 4;
    assert_eq!(build(&p).0, ATEM_CORE_ERR_STRUCT_SIZE);
}

#[test]
fn rtm_tokens_build() {
    let mut s = Strings(vec![]);
    let p = AtemCoreRtmTokenParams {
        struct_size: std::mem::size_of::<AtemCoreRtmTokenParams>() as u32,
        app_id: s.c(APP_ID),
        app_certificate: s.c(CERT),
        user_id: s.c("atem01"),
        expire: 3600,
        issued_at: 0,
        salt: 0,
    };
    let (mut token, mut error) = (null_mut(), null_mut());
    assert_eq!(unsafe { atem_core_build_rtm_token(&p, &mut token, &mut error) }, ATEM_CORE_OK);
    assert!(take(error).is_none());
    let d = atem_core::decode_token(&take(token).unwrap()).unwrap();
    assert_eq!(d.services[0].details, atem_core::ServiceDetails::Rtm { user_id: "atem01".into() });
}

#[test]
fn decode_returns_json_and_errors_on_garbage() {
    let mut s = Strings(vec![]);
    let (mut json, mut error) = (null_mut(), null_mut());
    assert_eq!(unsafe { atem_core_decode_token(s.c(VECTOR), &mut json, &mut error) }, ATEM_CORE_OK);
    let v: serde_json::Value = serde_json::from_str(&take(json).unwrap()).unwrap();
    assert_eq!(v["app_id"], APP_ID);
    assert_eq!(v["issued_at"], 1111111);
    assert_eq!(v["services"][0]["details"]["kind"], "rtc");
    assert_eq!(v["services"][0]["details"]["account"], "2882341273");
    assert_eq!(v["services"][0]["privileges"]["1"], 600);

    let (mut json, mut error2) = (null_mut(), null_mut());
    assert_eq!(unsafe { atem_core_decode_token(s.c("006xyz"), &mut json, &mut error2) }, ATEM_CORE_ERR_UNSUPPORTED_VERSION);
    assert!(json.is_null());
    take(error2);
    let (mut json, mut error3) = (null_mut(), null_mut());
    assert_eq!(unsafe { atem_core_decode_token(s.c("007!!"), &mut json, &mut error3) }, ATEM_CORE_ERR_MALFORMED_TOKEN);
    take(error3);
    take(error);
}

#[test]
fn verify_reports_validity_through_out_valid() {
    let mut s = Strings(vec![]);
    let mut valid = -1;
    let mut error = null_mut();
    assert_eq!(unsafe { atem_core_verify_token_signature(s.c(VECTOR), s.c(CERT), &mut valid, &mut error) }, ATEM_CORE_OK);
    assert_eq!(valid, 1);
    assert_eq!(
        unsafe { atem_core_verify_token_signature(s.c(VECTOR), s.c("00000000000000000000000000000000"), &mut valid, &mut error) },
        ATEM_CORE_OK
    );
    assert_eq!(valid, 0);
    assert_eq!(
        unsafe { atem_core_verify_token_signature(s.c(VECTOR), s.c(CERT), null_mut(), &mut error) },
        ATEM_CORE_ERR_NULL_ARGUMENT
    );
    take(error);
}

#[test]
fn freeing_null_is_a_no_op() {
    unsafe { atem_core_string_free(null_mut()) };
}

#[test]
fn rust_struct_sizes_match_the_c_layout() {
    // 5 pointers + 13 u32 fields on 64-bit targets, padded to pointer alignment.
    #[cfg(target_pointer_width = "64")]
    {
        assert_eq!(std::mem::size_of::<AtemCoreRtcTokenParams>(), 104);
        assert_eq!(std::mem::size_of::<AtemCoreRtmTokenParams>(), 48);
    }
}
```

Run: `cargo test -p atem-core-ffi`
Expected: compile errors (functions not defined yet).

- [ ] **Step 3: Implement `crates/atem-core-ffi/src/lib.rs`**

```rust
//! C ABI for atem-core. The header is include/atem_core.h; keep the two in
//! step (the C consumer in CI and tests/abi.rs check the shared rules).

use std::ffi::{CStr, CString, c_char};
use std::panic::{AssertUnwindSafe, catch_unwind};

use atem_core::token::{
    Issue, RtcIdentity, RtcPrivileges, RtcTokenRequest, RtmLogin, RtmTokenRequest, TokenError,
};

pub const ATEM_CORE_ABI_VERSION: u32 = 1;

pub const ATEM_CORE_OK: i32 = 0;
pub const ATEM_CORE_ERR_NULL_ARGUMENT: i32 = 1;
pub const ATEM_CORE_ERR_INVALID_UTF8: i32 = 2;
pub const ATEM_CORE_ERR_STRUCT_SIZE: i32 = 3;
pub const ATEM_CORE_ERR_INVALID_ARGUMENT: i32 = 4;
pub const ATEM_CORE_ERR_INVALID_APP_ID: i32 = 10;
pub const ATEM_CORE_ERR_INVALID_APP_CERTIFICATE: i32 = 11;
pub const ATEM_CORE_ERR_INVALID_CHANNEL: i32 = 12;
pub const ATEM_CORE_ERR_INVALID_USER_ACCOUNT: i32 = 13;
pub const ATEM_CORE_ERR_INVALID_RTM_USER_ID: i32 = 14;
pub const ATEM_CORE_ERR_INVALID_EXPIRY: i32 = 15;
pub const ATEM_CORE_ERR_UNSUPPORTED_VERSION: i32 = 20;
pub const ATEM_CORE_ERR_MALFORMED_TOKEN: i32 = 21;
pub const ATEM_CORE_ERR_INTERNAL: i32 = 99;

pub const ATEM_CORE_ROLE_EXPLICIT: u32 = 0;
pub const ATEM_CORE_ROLE_PUBLISHER: u32 = 1;
pub const ATEM_CORE_ROLE_SUBSCRIBER: u32 = 2;

#[repr(C)]
pub struct AtemCoreRtcTokenParams {
    pub struct_size: u32,
    pub app_id: *const c_char,
    pub app_certificate: *const c_char,
    pub channel: *const c_char,
    pub uid: u32,
    pub user_account: *const c_char,
    pub role: u32,
    pub token_expire: u32,
    pub privilege_expire: u32,
    pub join_channel_expire: u32,
    pub publish_audio_expire: u32,
    pub publish_video_expire: u32,
    pub publish_data_expire: u32,
    pub with_rtm: u32,
    pub rtm_user_id: *const c_char,
    pub rtm_expire: u32,
    pub issued_at: u32,
    pub salt: u32,
}

#[repr(C)]
pub struct AtemCoreRtmTokenParams {
    pub struct_size: u32,
    pub app_id: *const c_char,
    pub app_certificate: *const c_char,
    pub user_id: *const c_char,
    pub expire: u32,
    pub issued_at: u32,
    pub salt: u32,
}

struct Failure {
    code: i32,
    message: String,
}

impl Failure {
    fn new(code: i32, message: impl Into<String>) -> Failure {
        Failure { code, message: message.into() }
    }
}

impl From<TokenError> for Failure {
    fn from(error: TokenError) -> Failure {
        let code = match &error {
            TokenError::InvalidAppId => ATEM_CORE_ERR_INVALID_APP_ID,
            TokenError::InvalidAppCertificate => ATEM_CORE_ERR_INVALID_APP_CERTIFICATE,
            TokenError::InvalidChannel(_) => ATEM_CORE_ERR_INVALID_CHANNEL,
            TokenError::InvalidUserAccount(_) => ATEM_CORE_ERR_INVALID_USER_ACCOUNT,
            TokenError::InvalidRtmUserId(_) => ATEM_CORE_ERR_INVALID_RTM_USER_ID,
            TokenError::InvalidExpiry(_) => ATEM_CORE_ERR_INVALID_EXPIRY,
            TokenError::UnsupportedVersion => ATEM_CORE_ERR_UNSUPPORTED_VERSION,
            TokenError::Malformed(_) => ATEM_CORE_ERR_MALFORMED_TOKEN,
        };
        Failure::new(code, error.to_string())
    }
}

/// A required string argument.
///
/// # Safety
/// `p` is NULL or points to a NUL-terminated string valid for `'a`.
unsafe fn arg<'a>(p: *const c_char, name: &str) -> Result<&'a str, Failure> {
    if p.is_null() {
        return Err(Failure::new(ATEM_CORE_ERR_NULL_ARGUMENT, format!("{name} is NULL")));
    }
    unsafe { CStr::from_ptr(p) }
        .to_str()
        .map_err(|_| Failure::new(ATEM_CORE_ERR_INVALID_UTF8, format!("{name} is not UTF-8")))
}

/// An optional string argument (NULL = absent).
///
/// # Safety
/// As for `arg`.
unsafe fn opt_arg<'a>(p: *const c_char, name: &str) -> Result<Option<&'a str>, Failure> {
    if p.is_null() { Ok(None) } else { unsafe { arg(p, name) }.map(Some) }
}

fn issue(issued_at: u32, salt: u32) -> Issue {
    let base = if issued_at == 0 { Issue::now() } else { Issue::at(issued_at) };
    if salt == 0 { base } else { Issue { issued_at: base.issued_at, salt } }
}

/// Runs `body` with panics caught, then writes the result to the caller's
/// pointers. Outputs are cleared first, so they are NULL on every failure.
///
/// # Safety
/// `out` and `out_error` are NULL or valid for writing one pointer.
unsafe fn deliver(
    out: *mut *mut c_char,
    out_error: *mut *mut c_char,
    body: impl FnOnce() -> Result<String, Failure>,
) -> i32 {
    if !out_error.is_null() {
        unsafe { *out_error = std::ptr::null_mut() };
    }
    let result = if out.is_null() {
        Err(Failure::new(ATEM_CORE_ERR_NULL_ARGUMENT, "the output pointer is NULL"))
    } else {
        unsafe { *out = std::ptr::null_mut() };
        catch_unwind(AssertUnwindSafe(body))
            .unwrap_or_else(|_| Err(Failure::new(ATEM_CORE_ERR_INTERNAL, "internal error in atem-core")))
    };
    let result = result.and_then(|value| {
        CString::new(value).map_err(|_| Failure::new(ATEM_CORE_ERR_INTERNAL, "result contains NUL"))
    });
    match result {
        Ok(value) => {
            unsafe { *out = value.into_raw() };
            ATEM_CORE_OK
        }
        Err(failure) => {
            if !out_error.is_null() {
                let message = CString::new(failure.message.replace('\0', ""))
                    .unwrap_or_else(|_| CString::new("error").expect("no NUL"));
                unsafe { *out_error = message.into_raw() };
            }
            failure.code
        }
    }
}

/// Checks `struct_size` before reading any other field.
///
/// # Safety
/// `params` is NULL or points to at least a `u32`.
unsafe fn params<'a, T>(params: *const T, name: &str) -> Result<&'a T, Failure> {
    if params.is_null() {
        return Err(Failure::new(ATEM_CORE_ERR_NULL_ARGUMENT, format!("{name} is NULL")));
    }
    let size = unsafe { *(params as *const u32) } as usize;
    if size != std::mem::size_of::<T>() {
        return Err(Failure::new(
            ATEM_CORE_ERR_STRUCT_SIZE,
            format!("{name}.struct_size is {size}, this library expects {}", std::mem::size_of::<T>()),
        ));
    }
    Ok(unsafe { &*params })
}

#[unsafe(no_mangle)]
pub extern "C" fn atem_core_abi_version() -> u32 {
    ATEM_CORE_ABI_VERSION
}

#[unsafe(no_mangle)]
pub extern "C" fn atem_core_version() -> *const c_char {
    concat!(env!("CARGO_PKG_VERSION"), "\0").as_ptr().cast()
}

/// # Safety
/// See include/atem_core.h.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn atem_core_build_rtc_token(
    params_ptr: *const AtemCoreRtcTokenParams,
    out_token: *mut *mut c_char,
    out_error: *mut *mut c_char,
) -> i32 {
    unsafe {
        deliver(out_token, out_error, || {
            let p = params(params_ptr, "params")?;
            let identity = match opt_arg(p.user_account, "user_account")? {
                Some(account) => RtcIdentity::UserAccount(account),
                None => RtcIdentity::Uid(p.uid),
            };
            let privileges = match p.role {
                ATEM_CORE_ROLE_PUBLISHER => RtcPrivileges::Publisher { expire: p.privilege_expire },
                ATEM_CORE_ROLE_SUBSCRIBER => RtcPrivileges::Subscriber { expire: p.privilege_expire },
                ATEM_CORE_ROLE_EXPLICIT => RtcPrivileges::Explicit {
                    join: p.join_channel_expire,
                    publish_audio: p.publish_audio_expire,
                    publish_video: p.publish_video_expire,
                    publish_data: p.publish_data_expire,
                },
                other => return Err(Failure::new(ATEM_CORE_ERR_INVALID_ARGUMENT, format!("role {other} is not 0, 1 or 2"))),
            };
            let rtm = match p.with_rtm {
                0 => None,
                1 => Some(RtmLogin { user_id: opt_arg(p.rtm_user_id, "rtm_user_id")?, expire: p.rtm_expire }),
                other => return Err(Failure::new(ATEM_CORE_ERR_INVALID_ARGUMENT, format!("with_rtm {other} is not 0 or 1"))),
            };
            let request = RtcTokenRequest {
                app_id: arg(p.app_id, "app_id")?,
                app_certificate: arg(p.app_certificate, "app_certificate")?,
                channel: arg(p.channel, "channel")?,
                identity,
                privileges,
                token_expire: p.token_expire,
                rtm,
            };
            Ok(atem_core::build_rtc_token(&request, issue(p.issued_at, p.salt))?)
        })
    }
}

/// # Safety
/// See include/atem_core.h.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn atem_core_build_rtm_token(
    params_ptr: *const AtemCoreRtmTokenParams,
    out_token: *mut *mut c_char,
    out_error: *mut *mut c_char,
) -> i32 {
    unsafe {
        deliver(out_token, out_error, || {
            let p = params(params_ptr, "params")?;
            let request = RtmTokenRequest {
                app_id: arg(p.app_id, "app_id")?,
                app_certificate: arg(p.app_certificate, "app_certificate")?,
                user_id: arg(p.user_id, "user_id")?,
                expire: p.expire,
            };
            Ok(atem_core::build_rtm_token(&request, issue(p.issued_at, p.salt))?)
        })
    }
}

/// # Safety
/// See include/atem_core.h.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn atem_core_decode_token(
    token: *const c_char,
    out_json: *mut *mut c_char,
    out_error: *mut *mut c_char,
) -> i32 {
    unsafe {
        deliver(out_json, out_error, || {
            let decoded = atem_core::decode_token(arg(token, "token")?)?;
            serde_json::to_string(&decoded)
                .map_err(|_| Failure::new(ATEM_CORE_ERR_INTERNAL, "could not encode JSON"))
        })
    }
}

/// # Safety
/// See include/atem_core.h.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn atem_core_verify_token_signature(
    token: *const c_char,
    app_certificate: *const c_char,
    out_valid: *mut i32,
    out_error: *mut *mut c_char,
) -> i32 {
    // Reuse `deliver` for panics, error strings and clearing; the "value" is
    // discarded and out_valid carries the answer.
    let mut scratch: *mut c_char = std::ptr::null_mut();
    let status = unsafe {
        deliver(&mut scratch, out_error, || {
            if out_valid.is_null() {
                return Err(Failure::new(ATEM_CORE_ERR_NULL_ARGUMENT, "out_valid is NULL"));
            }
            *out_valid = 0;
            let valid = atem_core::verify_token_signature(arg(token, "token")?, arg(app_certificate, "app_certificate")?)?;
            *out_valid = i32::from(valid);
            Ok(String::new())
        })
    };
    if !scratch.is_null() {
        drop(unsafe { CString::from_raw(scratch) });
    }
    status
}

/// # Safety
/// `s` is NULL or a string returned by this library, not yet freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn atem_core_string_free(s: *mut c_char) {
    if !s.is_null() {
        let _ = catch_unwind(AssertUnwindSafe(|| drop(unsafe { CString::from_raw(s) })));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_panic_inside_becomes_internal_not_an_unwind() {
        let mut out: *mut c_char = std::ptr::null_mut();
        let mut error: *mut c_char = std::ptr::null_mut();
        let status = unsafe { deliver(&mut out, &mut error, || panic!("boom")) };
        assert_eq!(status, ATEM_CORE_ERR_INTERNAL);
        assert!(out.is_null());
        let message = unsafe { CString::from_raw(error) }.into_string().unwrap();
        assert_eq!(message, "internal error in atem-core");
    }
}
```

Make `atem_core_abi_version` and `atem_core_version` reachable from the integration tests: they are `pub` already; the test file imports `atem_core_ffi::*`.

- [ ] **Step 4: Run the tests**

Run: `cargo test -p atem-core-ffi` (twice, and once with `-- --test-threads=1`)
Expected: PASS. If `rust_struct_sizes_match_the_c_layout` fails, the Rust struct's field order or types differ from the header; fix the Rust struct to match the header.

- [ ] **Step 5: Format, lint, commit**

```bash
rustfmt --edition 2024 crates/atem-core-ffi/src/lib.rs crates/atem-core-ffi/tests/abi.rs
cargo clippy -p atem-core-ffi --all-targets -- -D warnings
git add Cargo.toml Cargo.lock crates/atem-core-ffi
git commit -m "feat(atem-core-ffi): versioned C ABI for token build/decode/verify

🤖 Built with SMT <smt@agora.build>"
```

---

### Task 5: Native consumers (C, Swift) and CI on Linux, macOS, Windows

**Files:**
- Create: `crates/atem-core-ffi/tests/c/consumer.c`, `crates/atem-core-ffi/tests/swift/main.swift`, `scripts/check-atem-core-ffi.sh` (executable), `.github/workflows/atem-core.yml`

**Interfaces:**
- Consumes: the header and static library from Task 4.
- Produces: `scripts/check-atem-core-ffi.sh` (used by CI and by Task 6's dry run).

- [ ] **Step 1: The C consumer**

`crates/atem-core-ffi/tests/c/consumer.c`:

```c
/* Minimal native consumer of atem_core.h: builds the published vector,
 * decodes it, verifies it, and checks error and ownership rules. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "atem_core.h"

#define APP_ID "970CA35de60c44645bbae8a215061b33"
#define CERT "5CFd2fd1755d40ecb72977518be15d3b"
#define VECTOR "007eJwBigB1/yAAFqC4TFpegsv3T7gT0J9ZxUvaycBhIFgFOayXV46VixogADk3MENBMzVkZTYwYzQ0NjQ1YmJhZThhMjE1MDYxYjMzR/QQAFgCAAABAAAAAQABAAEAAQBYAgAAIAA3ZDcyMzY1ZWI5ODM0ODUzOTdlM2UzZjlkNDYwYmRkYQoAMjg4MjM0MTI3M8JqJOM="

static int failures = 0;
#define CHECK(cond) do { if (!(cond)) { fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); failures++; } } while (0)

int main(void) {
    CHECK(atem_core_abi_version() == ATEM_CORE_ABI_VERSION);
    CHECK(strlen(atem_core_version()) > 0);

    AtemCoreRtcTokenParams p;
    memset(&p, 0, sizeof p);
    p.struct_size = sizeof p;
    p.app_id = APP_ID;
    p.app_certificate = CERT;
    p.channel = "7d72365eb983485397e3e3f9d460bdda";
    p.uid = 2882341273u;
    p.role = ATEM_CORE_ROLE_SUBSCRIBER;
    p.token_expire = 600;
    p.privilege_expire = 600;
    p.issued_at = 1111111;
    p.salt = 1;

    char *token = NULL, *error = NULL;
    CHECK(atem_core_build_rtc_token(&p, &token, &error) == ATEM_CORE_OK);
    CHECK(error == NULL);
    CHECK(token != NULL && strcmp(token, VECTOR) == 0);

    char *json = NULL;
    CHECK(atem_core_decode_token(token, &json, &error) == ATEM_CORE_OK);
    CHECK(json != NULL && strstr(json, "\"app_id\":\"" APP_ID "\"") != NULL);

    int32_t valid = -1;
    CHECK(atem_core_verify_token_signature(token, CERT, &valid, &error) == ATEM_CORE_OK);
    CHECK(valid == 1);
    atem_core_string_free(json);
    atem_core_string_free(token);

    /* An error: outputs NULL, message set, no certificate in it. */
    p.app_id = "not-hex";
    token = NULL;
    CHECK(atem_core_build_rtc_token(&p, &token, &error) == ATEM_CORE_ERR_INVALID_APP_ID);
    CHECK(token == NULL);
    CHECK(error != NULL && strstr(error, CERT) == NULL);
    atem_core_string_free(error);

    /* Wrong struct size, NULL arguments. */
    p.app_id = APP_ID;
    p.struct_size = sizeof p - 4;
    CHECK(atem_core_build_rtc_token(&p, &token, NULL) == ATEM_CORE_ERR_STRUCT_SIZE);
    CHECK(atem_core_decode_token(NULL, &json, NULL) == ATEM_CORE_ERR_NULL_ARGUMENT);
    atem_core_string_free(NULL);

    AtemCoreRtmTokenParams r;
    memset(&r, 0, sizeof r);
    r.struct_size = sizeof r;
    r.app_id = APP_ID;
    r.app_certificate = CERT;
    r.user_id = "atem01";
    r.expire = 3600;
    CHECK(atem_core_build_rtm_token(&r, &token, &error) == ATEM_CORE_OK);
    CHECK(token != NULL && strncmp(token, "007", 3) == 0);
    atem_core_string_free(token);

    if (failures) return 1;
    printf("atem_core C consumer: ok (abi %u, %s)\n", atem_core_abi_version(), atem_core_version());
    return 0;
}
```

- [ ] **Step 2: The Swift caller**

`crates/atem-core-ffi/tests/swift/main.swift` (compiled with `-import-objc-header atem_core.h`):

```swift
import Foundation

let appID = "970CA35de60c44645bbae8a215061b33"
let cert = "5CFd2fd1755d40ecb72977518be15d3b"
let vector = "007eJwBigB1/yAAFqC4TFpegsv3T7gT0J9ZxUvaycBhIFgFOayXV46VixogADk3MENBMzVkZTYwYzQ0NjQ1YmJhZThhMjE1MDYxYjMzR/QQAFgCAAABAAAAAQABAAEAAQBYAgAAIAA3ZDcyMzY1ZWI5ODM0ODUzOTdlM2UzZjlkNDYwYmRkYQoAMjg4MjM0MTI3M8JqJOM="

func fail(_ message: String) -> Never {
    FileHandle.standardError.write(("FAIL: " + message + "\n").data(using: .utf8)!)
    exit(1)
}

/// Takes ownership of a string returned by atem-core.
func take(_ p: UnsafeMutablePointer<CChar>?) -> String? {
    guard let p else { return nil }
    defer { atem_core_string_free(p) }
    return String(cString: p)
}

guard atem_core_abi_version() == ATEM_CORE_ABI_VERSION else { fail("abi version") }

let token: String = appID.withCString { app in
    cert.withCString { certificate in
        "7d72365eb983485397e3e3f9d460bdda".withCString { channel in
            var p = AtemCoreRtcTokenParams()
            p.struct_size = UInt32(MemoryLayout<AtemCoreRtcTokenParams>.size)
            p.app_id = app
            p.app_certificate = certificate
            p.channel = channel
            p.uid = 2882341273
            p.role = ATEM_CORE_ROLE_SUBSCRIBER
            p.token_expire = 600
            p.privilege_expire = 600
            p.issued_at = 1111111
            p.salt = 1
            var out: UnsafeMutablePointer<CChar>? = nil
            var error: UnsafeMutablePointer<CChar>? = nil
            let status = atem_core_build_rtc_token(&p, &out, &error)
            if status != ATEM_CORE_OK { fail("build status \(status): \(take(error) ?? "")") }
            return take(out) ?? fail("no token")
        }
    }
}
guard token == vector else { fail("token differs from the published vector") }

var json: UnsafeMutablePointer<CChar>? = nil
var error: UnsafeMutablePointer<CChar>? = nil
guard atem_core_decode_token(token, &json, &error) == ATEM_CORE_OK, let text = take(json),
      let object = try? JSONSerialization.jsonObject(with: Data(text.utf8)) as? [String: Any],
      object["app_id"] as? String == appID
else { fail("decode") }

var valid: Int32 = -1
guard atem_core_verify_token_signature(token, cert, &valid, &error) == ATEM_CORE_OK, valid == 1 else { fail("verify") }

print("atem_core Swift caller: ok")
```

- [ ] **Step 3: The check script**

`scripts/check-atem-core-ffi.sh`:

```bash
#!/usr/bin/env bash
# Builds libatem_core_ffi.a and drives it from C (and Swift on macOS).
set -euo pipefail
cd "$(dirname "$0")/.."

cargo build -p atem-core-ffi --release
# The system libraries a Rust static library needs on this platform.
LIBS=$(cargo rustc -p atem-core-ffi --release --lib --crate-type staticlib -- --print native-static-libs 2>&1 \
  | sed -n 's/.*native-static-libs: //p' | tail -1)
LIB=target/release/libatem_core_ffi.a
INCLUDE=crates/atem-core-ffi/include
OUT=target/atem-core-ffi-check
mkdir -p "$OUT"

cc -std=c11 -Wall -Wextra -Werror -I "$INCLUDE" crates/atem-core-ffi/tests/c/consumer.c "$LIB" $LIBS -o "$OUT/consumer"
"$OUT/consumer"

if [ "$(uname)" = "Darwin" ]; then
  swiftc -import-objc-header "$INCLUDE/atem_core.h" crates/atem-core-ffi/tests/swift/main.swift \
    -Xlinker "$LIB" -o "$OUT/swift_consumer"
  "$OUT/swift_consumer"
fi
```

`chmod +x scripts/check-atem-core-ffi.sh`, then run it locally (Linux): `./scripts/check-atem-core-ffi.sh`
Expected: `atem_core C consumer: ok (abi 1, 0.1.0)`.

- [ ] **Step 4: The CI workflow**

`.github/workflows/atem-core.yml`:

```yaml
name: atem-core

on:
  push:
    branches: [main]
    paths:
      - "crates/**"
      - "Cargo.toml"
      - "Cargo.lock"
      - "scripts/check-atem-core-ffi.sh"
      - "scripts/package-atem-core-macos.sh"
      - ".github/workflows/atem-core.yml"
  pull_request:
    paths:
      - "crates/**"
      - "Cargo.toml"
      - "Cargo.lock"
      - "scripts/check-atem-core-ffi.sh"
      - "scripts/package-atem-core-macos.sh"
      - ".github/workflows/atem-core.yml"

jobs:
  test:
    name: test (${{ matrix.os }})
    strategy:
      fail-fast: false
      matrix:
        os: [ubuntu-latest, macos-latest, windows-latest]
    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - name: Test atem-core and atem-core-ffi
        run: cargo test -p atem-core -p atem-core-ffi
      - name: Build the C library
        run: cargo build -p atem-core-ffi --release
      - name: C consumer (and Swift on macOS)
        if: runner.os != 'Windows'
        run: ./scripts/check-atem-core-ffi.sh
```

(Task 6 adds the packaging dry run to this workflow.)

- [ ] **Step 5: Commit**

```bash
git add crates/atem-core-ffi/tests scripts/check-atem-core-ffi.sh .github/workflows/atem-core.yml
git commit -m "ci(atem-core): test on Linux, macOS and Windows; drive the C ABI from C and Swift

🤖 Built with SMT <smt@agora.build>"
```

The Swift and Windows legs run for the first time on the PR; the controller checks them there.

---

### Task 6: macOS release artifacts

**Files:**
- Create: `scripts/package-atem-core-macos.sh` (executable)
- Modify: `.github/workflows/release.yml` (new job; `release.needs`), `.github/workflows/atem-core.yml` (dry-run step)

**Interfaces:**
- Consumes: `crates/atem-core-ffi/include/{atem_core.h,module.modulemap}`.
- Produces: release assets `atem-core-<version>-macos-xcframework.zip`, `atem-core-<version>-atem_core.h`, `atem-core-<version>-SHA256SUMS.txt`.

- [ ] **Step 1: The packaging script**

`scripts/package-atem-core-macos.sh`:

```bash
#!/usr/bin/env bash
# Usage: scripts/package-atem-core-macos.sh <version> <output-dir>
# Universal (arm64 + x86_64) static library + header → AtemCore.xcframework,
# zipped, with the header and SHA-256 sums alongside. macOS only.
set -euo pipefail
VERSION="$1"
OUT="$2"
cd "$(dirname "$0")/.."
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"

for target in aarch64-apple-darwin x86_64-apple-darwin; do
  cargo build -p atem-core-ffi --release --target "$target"
done

WORK="$(mktemp -d)"
lipo -create \
  target/aarch64-apple-darwin/release/libatem_core_ffi.a \
  target/x86_64-apple-darwin/release/libatem_core_ffi.a \
  -output "$WORK/libatem_core_ffi.a"
mkdir -p "$WORK/include"
cp crates/atem-core-ffi/include/atem_core.h crates/atem-core-ffi/include/module.modulemap "$WORK/include/"
xcodebuild -create-xcframework -library "$WORK/libatem_core_ffi.a" -headers "$WORK/include" \
  -output "$WORK/AtemCore.xcframework"

ZIP="atem-core-${VERSION}-macos-xcframework.zip"
(cd "$WORK" && ditto -c -k --keepParent AtemCore.xcframework "$ZIP")
mv "$WORK/$ZIP" "$OUT/"
cp crates/atem-core-ffi/include/atem_core.h "$OUT/atem-core-${VERSION}-atem_core.h"
(cd "$OUT" && shasum -a 256 "$ZIP" "atem-core-${VERSION}-atem_core.h" > "atem-core-${VERSION}-SHA256SUMS.txt")
echo "Packaged into $OUT:"
ls -l "$OUT"
```

`chmod +x scripts/package-atem-core-macos.sh`. It can't run on Linux; the CI dry run in Step 3 is its test.

- [ ] **Step 2: The release job**

In `.github/workflows/release.yml`, add this job after the `build` job:

```yaml
  atem-core-macos:
    name: atem-core (macOS xcframework)
    runs-on: macos-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with:
          targets: aarch64-apple-darwin,x86_64-apple-darwin
      - name: Package
        run: ./scripts/package-atem-core-macos.sh "${GITHUB_REF_NAME#v}" dist
      - uses: actions/upload-artifact@v4
        with:
          name: atem-core-macos
          path: dist/*
```

and change the `release` job's `needs: build` to `needs: [build, atem-core-macos]`. The existing `files: dist/atem-*` pattern already matches the three new assets; the R2 mirror only copies `dist/atem-*.tar.gz`, so it is unaffected.

- [ ] **Step 3: Dry run in CI**

Append to the `test` job in `.github/workflows/atem-core.yml`:

```yaml
      - name: Package dry run (macOS)
        if: runner.os == 'macOS'
        run: |
          rustup target add aarch64-apple-darwin x86_64-apple-darwin
          ./scripts/package-atem-core-macos.sh dev target/atem-core-package
          test -s target/atem-core-package/atem-core-dev-macos-xcframework.zip
          (cd target/atem-core-package && shasum -a 256 -c atem-core-dev-SHA256SUMS.txt)
```

- [ ] **Step 4: Commit**

```bash
git add scripts/package-atem-core-macos.sh .github/workflows/release.yml .github/workflows/atem-core.yml
git commit -m "ci(release): attach the atem-core macOS xcframework, header and SHA-256 sums

🤖 Built with SMT <smt@agora.build>"
```

---

### Task 7: Documentation

**Files:**
- Create: `crates/atem-core/README.md`, `crates/atem-core-ffi/README.md`
- Modify: `AGENTS.md` (source structure: workspace and both crates; Development Commands: `cargo test -p atem-core -p atem-core-ffi`, `./scripts/check-atem-core-ffi.sh`; Release Process: the three atem-core assets; `designs/atem-core.md` in the designs list), `README.md` (Development: one paragraph pointing to `crates/atem-core-ffi/README.md`)

- [ ] **Step 1: `crates/atem-core/README.md`**

Contents (write it out, short):
- What it is (one paragraph, link to `designs/atem-core.md`).
- A Rust example building an RTC token for uid 1234 with publisher privileges for 3600 s via `build_rtc_token(&RtcTokenRequest{…}, Issue::now())`, an RTM example, `decode_token` with the sentence "decoding does not verify; use `verify_token_signature`".
- The validation table (App ID/certificate 32 hex; channel 1–64 bytes; account 1–255; RTM user 1–64; expiries ≥ 1 s, relative seconds; Agora caps privileges at 24 h server-side).
- How compatibility with Agora is tested (`tests/upstream_compat.rs`, the published vector).

- [ ] **Step 2: `crates/atem-core-ffi/README.md`**

Contents:
- The ABI rules (copy the header's top comment), ABI version 1, the `struct_size` rule, the status-code table.
- **Using the release artifacts (macOS):** download `atem-core-<version>-macos-xcframework.zip` and `atem-core-<version>-SHA256SUMS.txt` from the Atem release, check with `shasum -a 256 -c atem-core-<version>-SHA256SUMS.txt`, add `AtemCore.xcframework` to the Xcode target (Frameworks, Libraries; "Do Not Embed": it is static), then `import AtemCore` in Swift. A Swift snippet equal to the core of `tests/swift/main.swift` (build, take/free, decode).
- **Building from source:** `cargo build -p atem-core-ffi --release` → `target/release/libatem_core_ffi.a` (Linux, macOS) or `target/release/atem_core_ffi.lib` (Windows MSVC); link flags from `cargo rustc -p atem-core-ffi --release --lib --crate-type staticlib -- --print native-static-libs`; the C example compile line from `scripts/check-atem-core-ffi.sh`.
- Thread-safety, ownership, and "no secrets in errors or logs".

- [ ] **Step 3: AGENTS.md and README.md**

Make the edits listed under **Files** above. Keep the existing style (dense, factual).

- [ ] **Step 4: Commit**

```bash
git add crates/atem-core/README.md crates/atem-core-ffi/README.md AGENTS.md README.md
git commit -m "docs(atem-core): API, C ABI, build and Swift integration

🤖 Built with SMT <smt@agora.build>"
```

---

### Task 8 (controller, after merge and release): Return the handoff

Not an implementer task: the controller does it once the PR is merged and a release carrying the artifacts is published.

- [ ] Confirm the release has `atem-core-<version>-macos-xcframework.zip`, `atem-core-<version>-atem_core.h`, `atem-core-<version>-SHA256SUMS.txt`, and record the SHA-256 values.
- [ ] Add an atem memory in project `github.com/agora-build/astation` (run from the Astation checkout) and replace the Atem-side handoff memories (`becd6fb6`, `b99862c9`, `ce5bb36d`, `1e21ee42`) with a "delivered" note. Content: release version and tag commit; asset names and SHA-256 values; header path and ABI version 1; `import AtemCore` integration steps (crates/atem-core-ffi/README.md); test evidence (published-vector KAT, upstream byte-for-byte rebuilds for every builder, ABI tests, C consumer on Linux/macOS, Swift caller on macOS, Windows test run); remaining gaps (Astation integration and the Token Tools UI not done; Linux/Windows artifacts not published; no FPA/Chat/aPaaS builders).
- [ ] `atem sync`.
