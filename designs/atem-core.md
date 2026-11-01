# atem-core: shared token library (Rust API + C ABI)

Status: built and released (since Atem v0.6.15: the xcframework, header and
SHA-256 sums are attached to every release); the Astation integration is a
follow-up. Approved 2026-10-12/13 (handoff from the Astation agent, saved as the
"Shared-library handoff" memories in project github.com/agora-build/atem;
layout and distribution chosen by the user on 2026-10-13). This document is the
spec the implementation plan argues from.

## Why

Astation (macOS, later Linux/Windows) needs Agora RTC/RTM token generation and
inspection without an installed or running atem, SSH or relay. Today it has
its own C++ (`core/src/astation_token.cpp`), and atem has `src/token.rs` on top
of Agora's `agora_token` crate. One maintained implementation should serve both:
the Rust CLI directly, Swift and other hosts through a C ABI.

## Layout

A Cargo workspace in the Atem repository. The `atem` binary stays at the root.

| Crate | Path | Kind | Contents |
|---|---|---|---|
| `atem-core` | `crates/atem-core` | `rlib` | Typed Rust API, no unsafe, no I/O |
| `atem-core-ffi` | `crates/atem-core-ffi` | `staticlib` + `cdylib` + `rlib` | Versioned C ABI over `atem-core`; hand-written `include/atem_core.h` |

`atem` depends on `atem-core` (path dependency) and no longer on `agora_token`.

## The token format (AccessToken2, version "007")

`atem-core` implements the format itself instead of wrapping `agora_token`:
upstream's API cannot fix the salt or issue time (no known-answer tests), it
builds a `String` from raw signature bytes with `unsafe`, panics on unknown
service types, and truncates lengths with `as u16`. The format is small:

- content = `pack_string(app_id)`, `u32 issue_ts`, `u32 expire`, `u32 salt`,
  `u16 service_count`, then each service in type order (RTC 1, RTM 2, FPA 4,
  CHAT 5, APAAS 7): `u16 type`, `u16 n` + `n × (u16 privilege, u32 expire)`
  sorted by privilege, then the service fields (RTC: channel, account
  strings; RTM: user id string). Integers little-endian; strings are
  `u16 length` + bytes.
- sign key = HMAC-SHA256(key = `u32 salt` LE, msg = HMAC-SHA256(key = `u32
  issue_ts` LE, msg = app certificate bytes)).
- signature = HMAC-SHA256(sign key, content).
- token = `"007"` + base64(STANDARD, padded)(zlib(default level)(
  `pack_string(signature)` + content)).

Compatibility is proven by tests, not assumed: upstream's published vector is
reproduced byte for byte, and for every upstream builder the token it produces
is decoded and rebuilt by `atem-core` from the same issue time and salt, and
must match exactly. `agora_token` stays as a dev-dependency for those tests.

## Rust API (`atem_core::token`)

- `RtcIdentity::Uid(u32)` (0 = any user, stored as an empty string, as
  upstream) or `RtcIdentity::UserAccount(&str)` (1–255 bytes). No silent
  conversion between the two.
- `RtcPrivileges::Publisher { expire }` (join + publish audio/video/data),
  `Subscriber { expire }` (join only), or `Explicit { join, publish_audio,
  publish_video, publish_data }`.
- `RtcTokenRequest { app_id, app_certificate, channel, identity, privileges,
  token_expire, rtm: Option<RtmLogin { user_id: Option<&str>, expire }> }`;
  `rtm.user_id = None` reuses the RTC account string.
- `RtmTokenRequest { app_id, app_certificate, user_id, expire }`.
- `Issue { issued_at: u32, salt: u32 }`; `Issue::now()` uses the system clock
  and a random salt in `1..99_999_999` (as upstream). Callers with a better
  clock (atem's HTTP time sync) pass their own `issued_at`.
- `build_rtc_token(&RtcTokenRequest, Issue) -> Result<String, TokenError>`,
  `build_rtm_token(&RtmTokenRequest, Issue) -> Result<String, TokenError>`.
- `decode_token(&str) -> Result<DecodedToken, TokenError>`: reads the fields
  only and **does not establish authenticity**.
- `verify_token_signature(&str, app_certificate) -> Result<bool, TokenError>`:
  the explicit signature check.
- Validation (typed `TokenError`, never coercion): App ID and certificate are
  32 hex characters; channel 1–64 bytes; RTC user account 1–255 bytes; RTM
  user id 1–64 bytes; every expiry ≥ 1 second (relative seconds, as Agora;
  Agora caps privileges at 24 h server-side, atem-core does not). Decode
  accepts at most 16 KiB of token text and 64 KiB decompressed.
- No printing, stdin, files, environment or config in the library.

## C ABI (`atem_core.h`, ABI version 1)

- `uint32_t atem_core_abi_version(void)`, `const char *atem_core_version(void)`
  (static string, never freed).
- `int32_t atem_core_build_rtc_token(const AtemCoreRtcTokenParams *, char
  **out_token, char **out_error)`, `atem_core_build_rtm_token(...)`,
  `atem_core_decode_token(const char *token, char **out_json, char
  **out_error)` (JSON, see the header), `atem_core_verify_token_signature(const
  char *token, const char *app_certificate, int32_t *out_valid, char
  **out_error)`.
- Return value: `ATEM_CORE_OK` (0) or an `AtemCoreStatus` error code. On
  success `*out_*` holds a new string and `*out_error` is NULL; on failure
  `*out_error` holds a message (when `out_error` is non-NULL) and outputs are
  NULL. Every returned string is freed with `atem_core_string_free`, exactly
  once; NULL is accepted.
- Params structs begin with `uint32_t struct_size` (set to
  `sizeof(the struct)`); a size the library doesn't know is rejected
  (`ATEM_CORE_ERR_STRUCT_SIZE`), so fields can be added later without breaking
  callers.
- Strings are NUL-terminated UTF-8; NULL where a string is required is
  `ATEM_CORE_ERR_NULL_ARGUMENT`, invalid UTF-8 `ATEM_CORE_ERR_INVALID_UTF8`.
- No panic crosses the boundary (`catch_unwind` on every entry point →
  `ATEM_CORE_ERR_INTERNAL`). Functions are thread-safe and keep no state.
- Error messages never contain the App Certificate or a token; nothing is
  logged.

## Distribution

Each Atem release attaches `atem-core-<version>-macos-xcframework.zip`
(universal arm64 + x86_64 static library + header), `atem-core-<version>-
atem_core.h` and `atem-core-<version>-SHA256SUMS.txt`. Astation pins a
version. Linux and Windows are built and tested in CI from source; their
artifacts can be added later.

## Out of scope (follow-ups)

Astation integration (replacing `astation_token.cpp`, a Tools > Token Tools
Generate/Inspect UI), other Agora services (FPA, Chat, aPaaS builders),
Linux/Windows artifacts.
