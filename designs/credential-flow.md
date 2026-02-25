# Credential Flow Architecture

## Overview

Atem uses Agora customer credentials (`customer_id`, `customer_secret`) for API access, token generation, and ConvoAI agent management. Credentials can arrive through three independent paths, with a clear priority chain.

## Priority Chain

```
Astation sync (live)  >  env vars  >  config.toml
    overwrites all       bootstrap     base defaults
```

| Source | Lifetime | Persisted? | When used |
|--------|----------|------------|-----------|
| Astation sync | Until Atem exits (or saved) | In-memory; optionally to config.toml via y/n prompt | Always wins when Astation is connected |
| `AGORA_CUSTOMER_ID` / `AGORA_CUSTOMER_SECRET` env vars | Shell session | No | Before Astation connects, or standalone CLI usage |
| `~/.config/atem/config.toml` | Permanent | Yes | Fallback when neither sync nor env vars are set |

## Credential Sources

### 1. config.toml (lowest priority)

```
~/.config/atem/config.toml
```

```toml
customer_id = "abc123..."
customer_secret = "def456..."
```

Written by:
- `atem config set` (interactive)
- y/n save prompt after Astation sync
- `atem login` save prompt

Loaded at startup by `AtemConfig::load()` in `config.rs`.

### 2. Environment Variables (middle priority)

```bash
export AGORA_CUSTOMER_ID="abc123..."
export AGORA_CUSTOMER_SECRET="def456..."
```

Applied during `AtemConfig::load()` — env vars override config.toml values in the loaded struct. Used for CI, scripting, or quick override without editing config.

### 3. Astation Sync (highest priority)

Astation pushes a `credentialSync` WebSocket message immediately when an Atem instance connects. The credentials originate from Astation's encrypted keychain (`CredentialManager` using AES-GCM).

This is the **live source of truth** and overwrites whatever was loaded from env/config.

## Data Flow

```
                      Astation (macOS)
                      CredentialManager
                      (AES-GCM encrypted)
                            |
                            | credentialSync (WebSocket)
                            v
    +----------------------------------------------------+
    |                    Atem                             |
    |                                                    |
    |  config.toml ──load──> AtemConfig                  |
    |       ^                    ^                       |
    |       |                    |                       |
    |  env vars ──override──>    |                       |
    |                            |                       |
    |  credentialSync ──overwrite─┘                      |
    |       |                                            |
    |       v                                            |
    |  [y/n prompt] ──y──> save to config.toml           |
    |               ──n──> session-only (in-memory)      |
    +----------------------------------------------------+
```

## Entry Points

### TUI mode (`app.rs`)

```
Startup:
  AtemConfig::load()
    ← reads config.toml
    ← env vars override

WebSocket connected:
  CredentialSync { customer_id, customer_secret }
    → self.synced_customer_id = Some(...)       # reference copy
    → self.config.customer_id = Some(...)       # active copy (overwrites all)
    → if config.toml has credentials:
        status: "Credentials synced from Astation"
    → else:
        pending_credential_save = Some(...)
        status: "Press 'y' to save, 'n' for session only"

Key 'y':
  → save to config.toml via AtemConfig::save_to_disk()
  → clear synced_customer_id (now "from config")

Key 'n':
  → session-only, lost on exit
```

### CLI mode (`cli.rs`)

Two paths trigger credential sync:

**`atem login` (explicit sync step):**
```
atem login
  → authenticate with Astation
  → "Sync Agora credentials from Astation? [Y/n]"
  → wait for credentialSync message
  → "Save credentials (xxxx...) to config? [Y/n]"
    y → save to config.toml
    n → session-only
```

**`ensure_credentials_from_astation()` (fallback for CLI commands):**
```
atem list project  (no local credentials)
  → connect to Astation WS
  → wait for credentialSync
  → "Save credentials (xxxx...) to config? [Y/n]"
    y → save to config.toml
    n → return credentials for this invocation only
```

## Credential Usage

Once in `self.config`, credentials are consumed by:

| Consumer | File | How |
|----------|------|-----|
| Agora REST API (project listing) | `agora_api.rs` | `std::env::var("AGORA_CUSTOMER_ID")` or `fetch_agora_projects_with_credentials()` |
| RTC token generation | `token.rs` | Via project's `vendorKey` + `signKey` (fetched using credentials) |
| ConvoAI agent creation | Astation's `ConvoAIClient.swift` | `credentialManager.load()` (Astation-side, not Atem) |

Note: Atem uses credentials primarily for listing projects and generating tokens. The ConvoAI agent is created by Astation directly, which has its own encrypted credential store.

## TUI Status Banner

The TUI main menu shows the credential source via `CredentialSource` enum (`config.rs`):

```
CredentialSource::Astation   →  "🔑 Credentials: from Astation"
CredentialSource::EnvVar     →  "🔑 Credentials: from ENV"
CredentialSource::ConfigFile →  "🔑 Credentials: from config file"
CredentialSource::None       →  "⚠️  No credentials — run `atem login` or set AGORA_CUSTOMER_ID"
```

The source is tracked through the full lifecycle:
- `AtemConfig::load()` sets `ConfigFile` or `EnvVar` based on where credentials came from
- `CredentialSync` handler sets `Astation`
- Pressing 'y' to save resets to `ConfigFile`

## Encrypted Credential Storage

Credentials are stored encrypted at `~/.config/atem/credentials.enc`, matching Astation's approach.

```
~/.config/atem/
├── config.toml          # Non-sensitive settings (plaintext TOML)
├── credentials.enc      # Encrypted credentials (AES-256-GCM binary)
├── active_project.json  # Selected project state
├── project_cache.json   # Cached project list (sign_keys encrypted)
└── session.json         # Auth session
```

**Encryption details:**

| Property | Value |
|----------|-------|
| Cipher | AES-256-GCM (authenticated encryption) |
| Key derivation | HMAC-SHA256(salt=`"atem-credentials-v1"`, machine_id) |
| Machine ID | Linux: `/etc/machine-id`, macOS: `IOPlatformUUID`, fallback: hostname |
| Nonce | Random 96-bit (12 bytes), generated per save |
| File format | nonce (12 bytes) ‖ ciphertext ‖ auth tag (16 bytes) |
| Plaintext | JSON: `{"customer_id":"...","customer_secret":"..."}` |

**Machine-bound**: credentials cannot be transferred between machines — the AES key is derived from the hardware identity.

**Migration**: if `config.toml` contains plaintext `customer_id`/`customer_secret`, they are read on load but `save_to_disk()` moves them to `credentials.enc` and removes them from `config.toml`.

### Comparison with Astation

| | Astation (Swift) | Atem (Rust) |
|---|---|---|
| Cipher | AES-GCM (CryptoKit) | AES-256-GCM (`aes-gcm` crate) |
| Key derivation | HKDF-SHA256 from hardware UUID | HMAC-SHA256 from machine ID |
| Salt | `"com.agora.astation"` | `"atem-credentials-v1"` |
| Storage | `~/Library/Application Support/Astation/credentials.enc` | `~/.config/atem/credentials.enc` |
| Tamper detection | AES-GCM auth tag | AES-GCM auth tag |

## Security

| Concern | Mitigation |
|---------|------------|
| Credentials on disk | AES-256-GCM encrypted in `credentials.enc` |
| Credentials in transit | WebSocket uses WSS (TLS) when connecting to Astation relay |
| Astation storage | AES-GCM encryption with hardware-bound key derivation |
| Machine binding | Key derived from hardware UUID/machine-id — not portable |
| Tamper detection | AES-GCM authentication tag rejects modified files |
| Prompt before saving | y/n prompt in all paths prevents accidental persistence |
| Env var exposure | Standard risk; env vars visible to same-user processes |
