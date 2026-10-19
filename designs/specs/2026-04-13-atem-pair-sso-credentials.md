# Atem Pair + SSO Credentials Design

> **Storage superseded (2026-10-19):** the user's login is `~/.config/atem/login.enc` and the one pairing is `~/.config/atem/pairing/` (`pairing.enc`, `trust_gen`); see AGENTS.md "Configuration & Storage". This document is kept as history.

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Replace `sso_session.json` with a unified machine-bound encrypted `credentials.enc` that holds both own-SSO and Astation-paired credentials; re-introduce `atem pair` so pairing with Astation distributes SSO tokens to Atem.

**Architecture:** Single encrypted file stores an array of credential entries (own SSO + paired per Astation). Astation adds SSO2 login and pushes tokens to paired Atems over WebSocket. Credential resolution prioritises the active Astation connection, falls back to own SSO.

**Tech Stack:** Rust (Atem), Swift/SwiftNIO (Astation), AES-256-GCM machine-bound encryption, OAuth 2.0 + PKCE (SSO2), existing OTP-based pairing protocol.

---

## 1. Storage: `credentials.enc`

**Path:** `~/.config/atem/credentials.enc`

**Encryption:** AES-256-GCM, key derived via HMAC-SHA256 from machine identity (`/etc/machine-id` on Linux, `IOPlatformUUID` on macOS) — same derivation used for `active_project.json`. File cannot be decrypted on another machine.

**Plaintext payload:** JSON array of `CredentialEntry` objects.

```json
[
  {
    "access_token": "eyJ...",
    "refresh_token": "dGt...",
    "expires_at": 1776081626,
    "login_id": "<login_id>",
    "source": "sso",
    "save_credentials": true,
    "astation_id": null,
    "paired_at": null,
    "disconnected_at": null
  },
  {
    "access_token": "eyJ...",
    "refresh_token": "dGt...",
    "expires_at": 1776081626,
    "login_id": "<login_id>",
    "source": "astation_paired",
    "save_credentials": false,
    "astation_id": "astation-550e8400-e29b-41d4-a716-446655440000",
    "paired_at": 1776000000,
    "disconnected_at": null
  }
]
```

**Field semantics:**

| Field | `sso` | `astation_paired` |
|---|---|---|
| `source` | `"sso"` | `"astation_paired"` |
| `save_credentials` | always `true` | user choice during `atem pair` |
| `astation_id` | `null` | Astation instance UUID |
| `paired_at` | `null` | Unix timestamp of successful pair |
| `disconnected_at` | `null` | Unix timestamp when Astation last disconnected (null if connected) |

**Migration:** Old `sso_session.json` is ignored — no migration. User re-runs `atem login`.

---

## 2. Credential Resolution Priority

Called by `valid_token()` on every API call:

```
1. Astation paired entry where astation_id == currently connected Astation
   AND (connected OR save_credentials == true OR within grace period)
   → use paired access_token, auto-refresh if needed

2. Own SSO entry (source == "sso")
   → use own access_token, auto-refresh if needed

3. Astation paired entry where save_credentials == true AND disconnected
   (not currently connected but saved)
   → use paired access_token, auto-refresh if needed

4. Error: "Not logged in. Run 'atem login' or 'atem pair'."
```

**Grace period:** 5 minutes after `disconnected_at`. During grace period, `save_credentials: false` paired tokens remain usable. After expiry they are frozen (not deleted) until Astation reconnects.

**Freeze vs delete:** Frozen entries stay in `credentials.enc` so reconnecting Astation can resume without re-pairing. Astation sends a fresh `SsoTokenSync` on reconnect which overwrites the entry.

---

## 3. WebSocket Protocol — New Messages

### `SsoTokenSync` (Astation → Atem)

Sent by Astation immediately after Atem successfully authenticates, and again whenever Astation refreshes its own SSO tokens.

```json
{
  "type": "SsoTokenSync",
  "access_token": "eyJ...",
  "refresh_token": "dGt...",
  "expires_at": 1776081626,
  "login_id": "<login_id>",
  "astation_id": "astation-550e8400-e29b-41d4-a716-446655440000",
  "save_credentials": false
}
```

`save_credentials` is included by Astation based on what Atem indicated during pairing (see `PairSavePreference` below).

### `PairSavePreference` (Atem → Astation)

Sent by Atem after the OTP pairing succeeds but before `SsoTokenSync` is received, to communicate the user's save preference.

```json
{
  "type": "PairSavePreference",
  "save_credentials": true
}
```

---

## 4. Atem Changes

### `credentials.enc` replaces `sso_session.json`

- New struct `CredentialEntry` (serialisable, mirrors the JSON above)
- New struct `CredentialStore` wraps `Vec<CredentialEntry>`, handles load/save/encrypt/decrypt
- `CredentialStore::load()` → reads `credentials.enc`, decrypts, parses
- `CredentialStore::save()` → serialises, encrypts, writes atomically
- `CredentialStore::upsert(entry)` → insert or replace by `(source, astation_id)` key
- `CredentialStore::remove_sso()` → removes `source == "sso"` entry
- `CredentialStore::remove_paired(astation_id)` → removes matched paired entry

### `valid_token()` updated

```rust
pub async fn valid_token(connected_astation_id: Option<&str>, sso_url: &str) -> Result<String>
```

Applies the 4-step priority chain from Section 2. Auto-refreshes whichever entry it selects.

### Commands

**`atem login`**
- Runs OAuth + PKCE flow (unchanged logic)
- Writes/overwrites `source: "sso"` entry in `credentials.enc`
- Prints: `Logged in. (SSO: <login_id>)`

**`atem logout`**
- Removes `source: "sso"` entry from `credentials.enc`
- Prints: `Logged out.`

**`atem pair`**
- Runs existing OTP pairing flow from `auth.rs` (deep link → web fallback → polling)
- After OTP approval, prompts: `Save credentials? Keeps working when Astation disconnects [y/N]:`
- Sends `PairSavePreference` to Astation
- Waits for `SsoTokenSync` (timeout 30s)
- Writes `source: "astation_paired"` entry to `credentials.enc`
- Prints: `Paired with Astation. (SSO: <login_id>)`
- If `save_credentials: true`: prints `Credentials saved — will work offline.`

**`atem unpair`**
- Removes paired entry for currently connected Astation from `credentials.enc`
- Prints: `Unpaired from Astation.`

### Disconnect lifecycle (in `app.rs` / `websocket_client.rs`)

When Astation WebSocket disconnects:
1. Find paired entry for that `astation_id` in `CredentialStore`
2. Set `disconnected_at` to current Unix timestamp
3. Save `credentials.enc`
4. If `save_credentials: false`: start in-memory 5-minute grace timer
5. Grace timer expiry: set in-memory `frozen` flag (no file change needed)

When Astation reconnects and sends `SsoTokenSync`:
1. Upsert entry (clears `disconnected_at`, updates tokens)
2. Clear grace timer and frozen flag

### `atem config show` updates

```
Credentials:
  SSO:     logged in  (52a4f560...)
  Paired:  astation-550e8400  (SSO: 52a4f560...)  [save: yes]  ← active
```

### TUI updates

- `🔑 Logged in (SSO: <login_id>)` when own SSO active
- `🔗 Paired (SSO: <login_id>)` when paired Astation is active source
- `⚠️  Not logged in — run 'atem login' or 'atem pair'` when neither

---

## 5. Astation Changes (Swift)

### Remove customer credentials
- Delete `customer_id` / `customer_secret` from `AppSettings` / `UserDefaults`
- Remove any UI for entering/storing them
- Remove any API calls that used them

### Add SSO2 login
- New `SSOAuthManager` class (mirrors `sso_auth.rs` logic in Swift):
  - `generatePKCE() -> (verifier: String, challenge: String)`
  - `generateState() -> String`
  - `runLoginFlow(ssoURL: String) async throws -> SSOSession`
    - Opens browser to auth URL
    - Starts local loopback server on random port
    - 15s timeout → shows paste-URL fallback in a dialog
    - Exchanges code for tokens
    - Returns `SSOSession`
  - `refreshToken(session: SSOSession) async throws -> SSOSession`
- New `SSOSession` struct: `accessToken`, `refreshToken`, `expiresAt`, `loginId`
- Persisted to `~/Library/Application Support/Astation/sso_session.json` (local, chmod 0600)
- Menu item: "Login with Agora Console..." / "Logout" in menubar

### Push tokens to paired Atems

In `AstationWebSocketServer.swift`, after an Atem client authenticates:
```swift
func sendSsoTokenSync(to clientId: String, saveCredentials: Bool) {
    guard let session = SSOAuthManager.shared.currentSession else { return }
    let msg = SsoTokenSync(
        accessToken: session.accessToken,
        refreshToken: session.refreshToken,
        expiresAt: session.expiresAt,
        loginId: session.loginId,
        astationId: AstationIdentity.shared.id,
        saveCredentials: saveCredentials
    )
    send(msg, to: clientId)
}
```

Called:
1. When Atem sends `PairSavePreference` (use `saveCredentials` from that message)
2. When `SSOAuthManager` refreshes tokens → broadcast to all authenticated clients

---

## 6. Error Cases

| Situation | Behaviour |
|---|---|
| `atem pair` but Astation has no SSO session | Astation sends error: `"Astation not logged in. Login from Astation menu first."` |
| `SsoTokenSync` timeout (30s) during pair | `atem pair` fails: `"Pairing timed out waiting for credentials."` |
| Grace period expired, no own SSO | `valid_token()` returns: `"Credentials inactive. Reconnect Astation or run 'atem login'."` |
| Refresh fails on saved paired credentials | Error: `"Session expired. Re-pair with Astation or run 'atem login'."` |

---

## 7. Scope

**In scope:**
- `credentials.enc` storage layer replacing `sso_session.json`
- `atem login` / `atem logout` using new store
- `atem pair` / `atem unpair` commands
- `SsoTokenSync` + `PairSavePreference` WebSocket messages (Atem side)
- Astation SSO2 login + token push (Swift)
- Disconnect grace period lifecycle

**Out of scope:**
- Multi-account (multiple own SSO logins) — one own SSO entry maximum
- Astation-side `atem unpair` notification
- Token revocation from Console (handled naturally by refresh failure)
