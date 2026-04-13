# SSO Auth + Project Listing via BFF API

**Date:** 2026-03-30
**Status:** Approved

## Overview

Replace Atem's current Basic-auth credential system (customer_id / customer_secret) with Agora Console SSO (OAuth 2.0 + PKCE). Project listing switches from the legacy REST API to the BFF API used by agora-cli. All credential storage, encryption, and Astation credential-sync logic is removed in this change. Astation pairing (`atem pair`) is preserved as-is for later integration.

## Command Surface

| Command | Behaviour |
|---|---|
| `atem login` | OAuth 2.0 + PKCE browser flow; stores SSO session |
| `atem logout` | Deletes SSO session file; prints confirmation |
| `atem list project` | Fetches projects via BFF API using Bearer token |
| `atem project use <id\|index>` | Unchanged UX; uses Bearer token when fetching by App ID |
| `atem config show` | Now includes SSO login state and token expiry |

`atem auth` is removed entirely. No `atem auth status` — auth state is visible via `atem config show`.

## New File: `src/sso_auth.rs`

Owns the complete OAuth lifecycle.

### Data structure

```rust
pub struct SsoSession {
    access_token: String,
    refresh_token: String,
    expires_at: u64,   // Unix seconds
}
```

Stored at `~/.config/atem/sso_session.json` with file mode 0600.

### Public API

```rust
impl SsoSession {
    pub fn load() -> Option<Self>
    pub fn save(&self) -> Result<()>
    pub fn delete() -> Result<()>
    /// Loads session, refreshes token if expires_at < now + 60s, returns access_token.
    /// Returns error if no session exists (caller prints login hint).
    pub async fn valid_token() -> Result<String>
}

/// Full browser-based login flow.
pub async fn run_login_flow(sso_url: &str) -> Result<SsoSession>
```

### Login flow steps

1. Generate PKCE: 32-byte random `code_verifier` → SHA-256 → base64url `code_challenge`
2. Generate random `state` token (CSRF protection)
3. Bind `TcpListener` on `127.0.0.1:0` (OS picks port)
4. Build authorize URL: `{sso_url}/api/v0/oauth/authorize?response_type=code&client_id=agora_web_cli&redirect_uri=http://127.0.0.1:{port}/oauth/callback&scope=basic_info,console&state={state}&code_challenge={challenge}&code_challenge_method=S256`
5. Try `open_browser(url)` (reuse existing `rtc_test_server::open_browser`); always also print the URL as fallback
6. Accept one HTTP connection on loopback; parse `?code=&state=`; validate state matches; send a minimal HTML "Login successful, return to terminal" response
7. `POST {sso_url}/api/v0/oauth/token` with `grant_type=authorization_code`, `client_id`, `code`, `code_verifier`, `redirect_uri`
8. Parse response into `SsoSession`; call `session.save()`

### Token refresh

`valid_token()` checks `expires_at < now + 60`. If true, calls `POST /api/v0/oauth/token` with `grant_type=refresh_token`. On 401 from any API call, caller should retry once after refresh; if second attempt fails, return error with hint to `atem login`.

### OAuth endpoints

| | Staging | Production |
|---|---|---|
| Authorize | `https://staging-sso.agora.io/api/v0/oauth/authorize` | `https://sso.agora.io/api/v0/oauth/authorize` |
| Token | `https://staging-sso.agora.io/api/v0/oauth/token` | `https://sso.agora.io/api/v0/oauth/token` |

Default: production. Override via `sso_url` in `config.toml` or env var `ATEM_SSO_URL`.

## `src/agora_api.rs` — Full Replacement

### New project model

```rust
pub struct BffProject {
    pub project_id: String,
    pub name: String,
    pub app_id: String,           // replaces vendor_key
    pub sign_key: Option<String>, // app certificate; None if not set
    pub status: String,           // "active" | "suspended"
    pub created_at: String,       // ISO 8601 datetime string
}
```

### New API function

```rust
pub async fn fetch_projects(access_token: &str, bff_url: &str) -> Result<Vec<BffProject>>
```

- `GET {bff_url}/api/cli/v1/projects`
- Header: `Authorization: Bearer {access_token}`
- On HTTP 401: return `Err("Session expired — run 'atem login'")`
- Supports pagination query params `page` and `pageSize` (use defaults for now)

### BFF endpoints

| | Staging | Production |
|---|---|---|
| BFF base | `https://agora-cli-bff.staging.la3.agoralab.co` | `https://agora-cli.agora.io` |

Default: staging (`https://agora-cli-bff.staging.la3.agoralab.co`) until the production URL is confirmed. Override via `bff_url` in `config.toml` or env var `ATEM_BFF_URL`.

### Kept from old file

- `format_projects()` — adapted for `BffProject` fields
- `format_unix_timestamp()` / `is_leap_year()` — kept as-is (still useful)
- Existing unit tests for formatting — updated to new model

### Removed from old file

- `AgoraApiResponse`, `AgoraApiProject`
- `fetch_agora_projects()`, `fetch_agora_projects_with_credentials()`
- All Basic-auth logic

## `src/config.rs` — Removals + Additions

### Remove — no fallback, no legacy path

- `customer_id: Option<String>`
- `customer_secret: Option<String>`
- `CredentialSource` enum and all variants (`ConfigFile`, `EnvVar`, `Astation`)
- `CredentialStore` struct and all methods
- `credentials.enc` file (no migration — users re-authenticate via `atem login`)
- Env vars `AGORA_CUSTOMER_ID` and `AGORA_CUSTOMER_SECRET` — no longer read or documented
- Basic-auth path in `agora_api.rs` — gone entirely, no fallback

### Add to `AtemConfig`

```rust
pub bff_url: Option<String>,   // config key: bff_url
pub sso_url: Option<String>,   // config key: sso_url
```

Resolved via (lowest → highest): `config.toml` → env var (`ATEM_BFF_URL`, `ATEM_SSO_URL`).

Helper methods on `AtemConfig`:
```rust
pub fn effective_bff_url(&self) -> &str   // returns bff_url or "https://agora-cli.agora.io"
pub fn effective_sso_url(&self) -> &str   // returns sso_url or "https://sso.agora.io"
```

### Unchanged

`astation_ws`, `astation_relay_url`, `astation_relay_code`, `diagram_server_url`, `ActiveProject`, `ProjectCache` — all kept as-is.

## `src/cli.rs` — Changes

### Add top-level commands

```rust
Commands::Login  // atem login  → run_login_flow()
Commands::Logout // atem logout → SsoSession::delete()
```

### Remove

- `Commands::Pair` — removed (astation pairing preserved but decoupled from credential sync; can be re-added later)
- `Commands::Auth` and `AuthCommands` enum
- `resolve_credentials()` function
- All credential-sync logic (the `connect_with_pairing` + save-to-config flow)

### Update `atem list project`

```rust
let token = SsoSession::valid_token().await
    .map_err(|_| anyhow!("Not logged in. Run 'atem login' first."))?;
let projects = fetch_projects(&token, &config.effective_bff_url()).await?;
```

### Update `atem project use <id>`

Same pattern: get token, fetch projects if resolving by App ID (index lookup uses `ProjectCache`, no network call needed).

### Update `atem config show`

Add SSO section:
```
SSO:    logged in  (expires 2026-04-01 08:30 UTC)
  — or —
SSO:    not logged in  (run 'atem login')
```

## `src/repl.rs` — Minor Update

Add `login` and `logout` to `KNOWN_COMMANDS`. Remove `auth` entries if any exist.

## Error Handling

| Situation | User-facing message |
|---|---|
| No SSO session | `Not logged in. Run 'atem login' first.` |
| Token refresh fails | `Session expired. Run 'atem login' to re-authenticate.` |
| BFF returns 401 | `Session expired. Run 'atem login' to re-authenticate.` |
| BFF returns other error | `API error {status}: {body}` |
| Login flow: browser timeout | Print URL, wait for manual redirect |
| Login flow: state mismatch | `OAuth state mismatch — possible CSRF. Try 'atem login' again.` |

## Files Changed

| File | Change |
|---|---|
| `src/sso_auth.rs` | **New** |
| `src/agora_api.rs` | **Replace** |
| `src/config.rs` | Remove credential fields/types; add bff_url/sso_url |
| `src/cli.rs` | Add Login/Logout; remove Pair/Auth/resolve_credentials |
| `src/repl.rs` | Update KNOWN_COMMANDS |

## Out of Scope

- Astation credential sync (preserved structurally via `atem pair`, not wired to project listing)
- UAP / RTM2 endpoints (future)
- Pagination UI for project list (use BFF defaults)
