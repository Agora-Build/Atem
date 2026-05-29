# Vault (atem-side) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add the `atem vault` CLI — a client for the relay-hosted shared context store defined in [vault.md](vault.md) — so agents on different atems can read/write a common, versioned, append-only context store.

**Architecture:** atem talks to the relay-server's `/api/vault` HTTP endpoints. All request building (URL, body, method) and output rendering are **pure functions**, unit-tested offline (mirroring how `convo_config.rs` builds the ConvoAI `/join` body without a live server). A thin `VaultClient` executes the requests via `reqwest`, adding session auth. Identity comes from [atem-identity.md](atem-identity.md): `client_id` = the persistent `instance_id`.

**Tech Stack:** Rust, clap (derive), reqwest (0.11), serde / serde_json, anyhow, urlencoding, tokio.

---

## Scope

The vault spans **two subsystems** (per the writing-plans scope rule):

1. **relay-server (Astation repo)** — Postgres schema + `/api/vault` endpoints + authz + (v1.5) `vault-updated` broadcast. **This is a prerequisite for end-to-end testing and gets its own plan in the Astation repo.** Its contract is fully specified in [vault.md](vault.md) §"Server endpoints" / §"Data model" / §"Auth model". See "Prerequisite" below.
2. **atem (this repo)** — the `atem vault` CLI + client. **This plan.** Pure builders/renderers are testable now; the HTTP handlers become end-to-end testable once subsystem 1 exists.

This plan delivers vault **v1**: `new`, `list`, `read`, `write`, `set-summary`. `watch` (relay `vault-updated` subscription) is **v1.5** and deferred to a follow-up plan.

## Prerequisite (relay-server, Astation repo — NOT this plan)

A separate plan in the Astation repo must deliver, per [vault.md](vault.md):

- Postgres migration: `vaults` + `vault_entries` tables (schema in vault.md §Data model).
- Endpoints: `POST /api/vault`, `GET /api/vault`, `GET /api/vault/<id>` (`?since=&history=`), `POST /api/vault/<id>`, `POST /api/vault/<id>/summary`.
- Auth: validate `Authorization: session <id>` → resolve `work_session_id`; read `id=<client_id>` query; enforce `can_read` / `can_write` (vault.md §Auth model).
- `writer_list` maintenance on content writes.
- Relay `atem_id` sanitizer must percent-decode the query param and keep non-ASCII (atem-identity.md §"Relay-side requirement").

The atem side codes against this contract. If the relay's request/response JSON differs, adjust the types in Task 1/2.

## Wire contract (atem-side view)

```
Auth header (all requests):  Authorization: session <session_id>
Query (all requests):        ?id=<client_id>            (instance_id)

POST /api/vault                 {summary}                       → {vault_id}
GET  /api/vault                                                 → [{vault_id, summary}]
GET  /api/vault/<id>            [?since=<seq>&history=true]      → [VaultEntry]
POST /api/vault/<id>           {text, entry_id?}                → {entry_no, version, seq}
POST /api/vault/<id>/summary   {text}                           → {} (200 OK)

VaultEntry = {seq, entry_no, version, kind, writer_id, content, created_at}
```

## File Structure

| File | Responsibility |
|------|----------------|
| Create: `src/vault_client.rs` | Pure request builders (`VaultRequest`), response types, output renderers, and the thin `VaultClient` reqwest executor. |
| Modify: `src/cli.rs` | Add `Commands::Vault` + `VaultCommands` subcommands; dispatch arm in `handle_cli_command`. |
| Modify: `src/main.rs` | `mod vault_client;` declaration (if modules are declared there). |

Identity/session/relay-url come from existing APIs:
- `crate::config::AtemConfig::ensure_instance_id()` → `client_id`.
- `crate::config::AtemConfig::load()?.astation_relay_url` (default `https://station.agora.build`) → base URL.
- `crate::auth::SessionManager::load()?.get(&astation_relay_code)` → `AuthSession.session_id`.

---

## Task 1: `vault_client.rs` — request builders + response types

**Files:**
- Create: `src/vault_client.rs`
- Modify: `src/main.rs` (add `mod vault_client;`)

- [ ] **Step 1: Write the failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn create_request_shape() {
        let r = create_vault_request("https://relay.example/", "inst-1", "my summary");
        assert_eq!(r.method, "POST");
        assert_eq!(r.url, "https://relay.example/api/vault?id=inst-1");
        assert_eq!(r.body, Some(json!({"summary": "my summary"})));
    }

    #[test]
    fn read_request_with_since_and_history() {
        let r = read_vault_request("https://relay.example", "inst-1", "v-7Kf3qD", Some(42), true);
        assert_eq!(r.method, "GET");
        assert_eq!(
            r.url,
            "https://relay.example/api/vault/v-7Kf3qD?id=inst-1&since=42&history=true"
        );
        assert!(r.body.is_none());
    }

    #[test]
    fn read_request_current_view() {
        let r = read_vault_request("https://relay.example", "inst-1", "v-7Kf3qD", None, false);
        assert_eq!(r.url, "https://relay.example/api/vault/v-7Kf3qD?id=inst-1");
    }

    #[test]
    fn write_request_append_omits_entry_id() {
        let r = write_vault_request("https://relay.example", "inst-1", "v-1", "hello", None);
        assert_eq!(r.method, "POST");
        assert_eq!(r.url, "https://relay.example/api/vault/v-1?id=inst-1");
        assert_eq!(r.body, Some(json!({"text": "hello"})));
    }

    #[test]
    fn write_request_override_includes_entry_id() {
        let r = write_vault_request("https://relay.example", "inst-1", "v-1", "edit", Some(3));
        assert_eq!(r.body, Some(json!({"text": "edit", "entry_id": 3})));
    }

    #[test]
    fn set_summary_request_shape() {
        let r = set_summary_request("https://relay.example", "inst-1", "v-1", "new sum");
        assert_eq!(r.method, "POST");
        assert_eq!(r.url, "https://relay.example/api/vault/v-1/summary?id=inst-1");
        assert_eq!(r.body, Some(json!({"text": "new sum"})));
    }

    #[test]
    fn client_id_is_percent_encoded() {
        let r = list_vaults_request("https://relay.example", "a b/c");
        assert_eq!(r.url, "https://relay.example/api/vault?id=a%20b%2Fc");
    }
}
```

- [ ] **Step 2: Run tests, verify they fail**

Run: `cargo test vault_client::tests:: 2>&1 | tail`
Expected: compile error / FAIL (functions not defined).

- [ ] **Step 3: Implement the builders + types**

```rust
use anyhow::{anyhow, Result};
use serde::Deserialize;
use serde_json::{json, Value};

/// A vault HTTP request, fully built but not yet sent. Pure + testable.
#[derive(Debug, Clone, PartialEq)]
pub struct VaultRequest {
    pub method: &'static str, // "GET" | "POST"
    pub url: String,
    pub body: Option<Value>,
}

/// One entry row as returned by the relay (see vault.md §Data model).
#[derive(Debug, Clone, Deserialize)]
pub struct VaultEntry {
    pub seq: u64,
    pub entry_no: u32,
    pub version: u32,
    pub kind: String,
    pub writer_id: String,
    pub content: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CreatedVault {
    pub vault_id: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct VaultListItem {
    pub vault_id: String,
    pub summary: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct WriteResult {
    pub entry_no: u32,
    pub version: u32,
    pub seq: u64,
}

fn enc(s: &str) -> String {
    urlencoding::encode(s).into_owned()
}

fn base_trim(base: &str) -> &str {
    base.trim_end_matches('/')
}

pub fn create_vault_request(base: &str, client_id: &str, summary: &str) -> VaultRequest {
    VaultRequest {
        method: "POST",
        url: format!("{}/api/vault?id={}", base_trim(base), enc(client_id)),
        body: Some(json!({ "summary": summary })),
    }
}

pub fn list_vaults_request(base: &str, client_id: &str) -> VaultRequest {
    VaultRequest {
        method: "GET",
        url: format!("{}/api/vault?id={}", base_trim(base), enc(client_id)),
        body: None,
    }
}

pub fn read_vault_request(
    base: &str,
    client_id: &str,
    vault_id: &str,
    since: Option<u64>,
    history: bool,
) -> VaultRequest {
    let mut url = format!(
        "{}/api/vault/{}?id={}",
        base_trim(base),
        enc(vault_id),
        enc(client_id)
    );
    if let Some(s) = since {
        url.push_str(&format!("&since={}", s));
    }
    if history {
        url.push_str("&history=true");
    }
    VaultRequest { method: "GET", url, body: None }
}

pub fn write_vault_request(
    base: &str,
    client_id: &str,
    vault_id: &str,
    text: &str,
    entry_id: Option<u32>,
) -> VaultRequest {
    let mut body = json!({ "text": text });
    if let Some(e) = entry_id {
        body["entry_id"] = json!(e);
    }
    VaultRequest {
        method: "POST",
        url: format!("{}/api/vault/{}?id={}", base_trim(base), enc(vault_id), enc(client_id)),
        body: Some(body),
    }
}

pub fn set_summary_request(base: &str, client_id: &str, vault_id: &str, text: &str) -> VaultRequest {
    VaultRequest {
        method: "POST",
        url: format!(
            "{}/api/vault/{}/summary?id={}",
            base_trim(base),
            enc(vault_id),
            enc(client_id)
        ),
        body: Some(json!({ "text": text })),
    }
}
```

Add `mod vault_client;` to `src/main.rs` near the other `mod` declarations.

- [ ] **Step 4: Run tests, verify they pass**

Run: `cargo test vault_client::tests:: 2>&1 | tail`
Expected: PASS (7 tests).

- [ ] **Step 5: Commit**

```bash
git add src/vault_client.rs src/main.rs
git commit -m "feat(vault): request builders + response types for the vault client

🤖 Built with SMT <smt@agora.build>"
```

---

## Task 2: `vault_client.rs` — output renderers

**Files:**
- Modify: `src/vault_client.rs`

- [ ] **Step 1: Write the failing tests**

```rust
#[test]
fn parse_format_defaults_to_human() {
    assert!(matches!(parse_format("human"), OutFormat::Human));
    assert!(matches!(parse_format("plain"), OutFormat::Plain));
    assert!(matches!(parse_format("anything-else"), OutFormat::Human));
}

#[test]
fn render_current_human_shows_summary_and_entries() {
    let entries = vec![
        VaultEntry { seq: 1, entry_no: 1, version: 1, kind: "content".into(),
            writer_id: "a".into(), content: "first".into(), created_at: "t1".into() },
        VaultEntry { seq: 3, entry_no: 2, version: 2, kind: "content".into(),
            writer_id: "b".into(), content: "second-edited".into(), created_at: "t3".into() },
    ];
    let out = render_current("the summary", &entries, OutFormat::Human);
    assert!(out.contains("the summary"));
    assert!(out.contains("e1"));
    assert!(out.contains("first"));
    assert!(out.contains("e2"));
    assert!(out.contains("second-edited"));
}

#[test]
fn render_plain_is_bare_content_only() {
    let entries = vec![VaultEntry { seq: 1, entry_no: 1, version: 1, kind: "content".into(),
        writer_id: "a".into(), content: "just text".into(), created_at: "t1".into() }];
    let out = render_current("sum", &entries, OutFormat::Plain);
    assert!(out.contains("just text"));
    assert!(!out.contains("e1")); // plain = pipe-friendly, no decoration
}

#[test]
fn render_history_labels_versions() {
    let entries = vec![
        VaultEntry { seq: 1, entry_no: 1, version: 1, kind: "content".into(),
            writer_id: "a".into(), content: "v1 text".into(), created_at: "t1".into() },
        VaultEntry { seq: 2, entry_no: 1, version: 2, kind: "content".into(),
            writer_id: "b".into(), content: "v2 text".into(), created_at: "t2".into() },
    ];
    let out = render_history(&entries, OutFormat::Human);
    assert!(out.contains("e1 v1"));
    assert!(out.contains("e1 v2"));
}
```

- [ ] **Step 2: Run tests, verify they fail**

Run: `cargo test vault_client::tests::render 2>&1 | tail`
Expected: FAIL (functions not defined).

- [ ] **Step 3: Implement the renderers**

```rust
#[derive(Debug, Clone, Copy)]
pub enum OutFormat {
    Human,
    Plain,
}

pub fn parse_format(s: &str) -> OutFormat {
    match s {
        "plain" => OutFormat::Plain,
        _ => OutFormat::Human,
    }
}

/// Current view: summary header + one line per entry (server already collapsed
/// to the latest version per entry_no, ordered by entry_no).
pub fn render_current(summary: &str, entries: &[VaultEntry], fmt: OutFormat) -> String {
    match fmt {
        OutFormat::Plain => entries
            .iter()
            .map(|e| e.content.as_str())
            .collect::<Vec<_>>()
            .join("\n"),
        OutFormat::Human => {
            let mut out = String::new();
            out.push_str(&format!("summary: {}\n", summary));
            for e in entries {
                out.push_str(&format!("  e{}: {}\n", e.entry_no, e.content));
            }
            out
        }
    }
}

/// History: every row by seq, labeled `eN vM`.
pub fn render_history(entries: &[VaultEntry], fmt: OutFormat) -> String {
    match fmt {
        OutFormat::Plain => entries
            .iter()
            .map(|e| e.content.as_str())
            .collect::<Vec<_>>()
            .join("\n"),
        OutFormat::Human => {
            let mut out = String::new();
            for e in entries {
                out.push_str(&format!(
                    "  e{} v{} [{}] {}\n",
                    e.entry_no, e.version, e.writer_id, e.content
                ));
            }
            out
        }
    }
}
```

- [ ] **Step 4: Run tests, verify they pass**

Run: `cargo test vault_client::tests::render 2>&1 | tail`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/vault_client.rs
git commit -m "feat(vault): human/plain renderers for current view + history

🤖 Built with SMT <smt@agora.build>"
```

---

## Task 3: `vault_client.rs` — `VaultClient` executor

**Files:**
- Modify: `src/vault_client.rs`

No unit tests (network I/O); correctness is covered by the request-builder tests in Task 1 plus the manual smoke test in Verification. Keep this layer thin.

- [ ] **Step 1: Implement the executor**

```rust
pub struct VaultClient {
    base: String,
    client_id: String,
    session_id: String,
    http: reqwest::Client,
}

impl VaultClient {
    pub fn new(base: String, client_id: String, session_id: String) -> Self {
        Self {
            base,
            client_id,
            session_id,
            http: reqwest::Client::new(),
        }
    }

    async fn send(&self, req: VaultRequest) -> Result<reqwest::Response> {
        let mut rb = match req.method {
            "POST" => self.http.post(&req.url),
            _ => self.http.get(&req.url),
        };
        rb = rb.header("Authorization", format!("session {}", self.session_id));
        if let Some(body) = req.body {
            rb = rb.json(&body);
        }
        let resp = rb.send().await.map_err(|e| anyhow!("vault request failed: {}", e))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(anyhow!("vault returned {}: {}", status, text));
        }
        Ok(resp)
    }

    pub async fn create(&self, summary: &str) -> Result<CreatedVault> {
        let req = create_vault_request(&self.base, &self.client_id, summary);
        Ok(self.send(req).await?.json().await?)
    }

    pub async fn list(&self) -> Result<Vec<VaultListItem>> {
        let req = list_vaults_request(&self.base, &self.client_id);
        Ok(self.send(req).await?.json().await?)
    }

    pub async fn read(&self, vault_id: &str, since: Option<u64>, history: bool) -> Result<Vec<VaultEntry>> {
        let req = read_vault_request(&self.base, &self.client_id, vault_id, since, history);
        Ok(self.send(req).await?.json().await?)
    }

    pub async fn write(&self, vault_id: &str, text: &str, entry_id: Option<u32>) -> Result<WriteResult> {
        let req = write_vault_request(&self.base, &self.client_id, vault_id, text, entry_id);
        Ok(self.send(req).await?.json().await?)
    }

    pub async fn set_summary(&self, vault_id: &str, text: &str) -> Result<()> {
        let req = set_summary_request(&self.base, &self.client_id, vault_id, text);
        self.send(req).await?;
        Ok(())
    }
}
```

- [ ] **Step 2: Type-check**

Run: `cargo check 2>&1 | tail`
Expected: no errors.

- [ ] **Step 3: Commit**

```bash
git add src/vault_client.rs
git commit -m "feat(vault): VaultClient reqwest executor with session auth

🤖 Built with SMT <smt@agora.build>"
```

---

## Task 4: `cli.rs` — `vault` command definitions

**Files:**
- Modify: `src/cli.rs`

- [ ] **Step 1: Write the failing parse tests**

Add to `cli.rs` tests (follow the existing test style there):

```rust
#[test]
fn cli_vault_new_parses() {
    let cli = Cli::try_parse_from(["atem", "vault", "new", "--summary", "ctx"]).unwrap();
    match cli.command {
        Some(Commands::Vault { command: VaultCommands::New { summary } }) => {
            assert_eq!(summary, "ctx");
        }
        _ => panic!("expected vault new"),
    }
}

#[test]
fn cli_vault_write_with_entry_id_parses() {
    let cli = Cli::try_parse_from([
        "atem", "vault", "write", "--vault-id", "v-1", "--entry-id", "3", "--text", "edit",
    ])
    .unwrap();
    match cli.command {
        Some(Commands::Vault {
            command: VaultCommands::Write { vault_id, entry_id, text },
        }) => {
            assert_eq!(vault_id, "v-1");
            assert_eq!(entry_id, Some(3));
            assert_eq!(text, "edit");
        }
        _ => panic!("expected vault write"),
    }
}

#[test]
fn cli_vault_read_history_flag_parses() {
    let cli = Cli::try_parse_from([
        "atem", "vault", "read", "--vault-id", "v-1", "--history",
    ])
    .unwrap();
    match cli.command {
        Some(Commands::Vault { command: VaultCommands::Read { vault_id, history, .. } }) => {
            assert_eq!(vault_id, "v-1");
            assert!(history);
        }
        _ => panic!("expected vault read"),
    }
}
```

- [ ] **Step 2: Run tests, verify they fail**

Run: `cargo test cli::tests::cli_vault 2>&1 | tail`
Expected: compile error (`Commands::Vault` / `VaultCommands` not defined).

- [ ] **Step 3: Add the command definitions**

In the `Commands` enum (`src/cli.rs`), add:

```rust
    /// Shared cross-agent context store (see designs/vault.md)
    Vault {
        #[command(subcommand)]
        command: VaultCommands,
    },
```

Add the subcommand enum near the other `*Commands` enums:

```rust
#[derive(clap::Subcommand, Debug)]
pub enum VaultCommands {
    /// Create a new vault in the current work session
    New {
        #[arg(long)]
        summary: String,
    },
    /// List vaults you can read
    List,
    /// Read a vault's current contents (or history)
    Read {
        #[arg(long = "vault-id")]
        vault_id: String,
        #[arg(long)]
        since: Option<u64>,
        #[arg(long)]
        history: bool,
        #[arg(long, default_value = "human")]
        format: String,
    },
    /// Append an entry, or override one with --entry-id
    Write {
        #[arg(long = "vault-id")]
        vault_id: String,
        #[arg(long = "entry-id")]
        entry_id: Option<u32>,
        #[arg(long)]
        text: String,
    },
    /// Update the mutable summary
    SetSummary {
        #[arg(long = "vault-id")]
        vault_id: String,
        #[arg(long)]
        text: String,
    },
}
```

- [ ] **Step 4: Run tests, verify they pass**

Run: `cargo test cli::tests::cli_vault 2>&1 | tail`
Expected: PASS (3 tests). (The dispatch arm is added in Task 5; until then `handle_cli_command` won't compile if it's exhaustive — add a temporary `Commands::Vault { .. } => unimplemented!()` arm if needed, replaced in Task 5.)

- [ ] **Step 5: Commit**

```bash
git add src/cli.rs
git commit -m "feat(vault): add 'atem vault' command definitions

🤖 Built with SMT <smt@agora.build>"
```

---

## Task 5: `cli.rs` — `vault` handlers (orchestration)

**Files:**
- Modify: `src/cli.rs`

No unit tests (resolves real config/session + network). Covered by the Verification smoke test.

- [ ] **Step 1: Implement the dispatch + handler**

In `handle_cli_command`, add the arm:

```rust
        Commands::Vault { command } => handle_vault_command(command).await,
```

Add the handler function (in `cli.rs`):

```rust
async fn handle_vault_command(command: crate::cli::VaultCommands) -> Result<()> {
    use crate::cli::VaultCommands;
    use crate::vault_client::{self, VaultClient, OutFormat};

    // Resolve relay base, client id, and session.
    let config = crate::config::AtemConfig::load()?;
    let base = config
        .astation_relay_url
        .clone()
        .unwrap_or_else(|| "https://station.agora.build".to_string());
    let astation_id = config
        .astation_relay_code
        .clone()
        .ok_or_else(|| anyhow::anyhow!("No relay configured. Set astation_relay_code in config.toml."))?;
    let client_id = crate::config::AtemConfig::ensure_instance_id();
    let session_id = crate::auth::SessionManager::load()?
        .get(&astation_id)
        .map(|s| s.session_id.clone())
        .ok_or_else(|| anyhow::anyhow!("No session for {}. Run 'atem pair' first.", astation_id))?;

    let client = VaultClient::new(base, client_id, session_id);

    match command {
        VaultCommands::New { summary } => {
            let v = client.create(&summary).await?;
            println!("Created vault {}", v.vault_id);
        }
        VaultCommands::List => {
            for item in client.list().await? {
                println!("{}  {}", item.vault_id, item.summary);
            }
        }
        VaultCommands::Read { vault_id, since, history, format } => {
            let entries = client.read(&vault_id, since, history).await?;
            let fmt = vault_client::parse_format(&format);
            let out = if history {
                vault_client::render_history(&entries, fmt)
            } else {
                // Summary is not in the entries list; fetch via list or a future
                // dedicated endpoint. v1: show entries only, summary header empty.
                vault_client::render_current("", &entries, fmt)
            };
            print!("{}", out);
        }
        VaultCommands::Write { vault_id, entry_id, text } => {
            let r = client.write(&vault_id, &text, entry_id).await?;
            println!("Wrote e{} v{} (seq {})", r.entry_no, r.version, r.seq);
        }
        VaultCommands::SetSummary { vault_id, text } => {
            client.set_summary(&vault_id, &text).await?;
            println!("Summary updated.");
        }
    }
    Ok(())
}
```

> **Note on the `Read` summary header:** the current-view summary lives on the
> `vaults` row, not in the entry list. v1 renders an empty summary header for
> `read`; a follow-up can have `GET /api/vault/<id>` include the summary (adjust
> `read` to return `{summary, entries}` and thread it through). Flag this when
> the relay response shape is finalized.

- [ ] **Step 2: Build + full test suite**

Run: `cargo build && cargo test 2>&1 | grep "test result"`
Expected: build ok; all tests pass.

- [ ] **Step 3: Commit**

```bash
git add src/cli.rs
git commit -m "feat(vault): wire 'atem vault' handlers to VaultClient

🤖 Built with SMT <smt@agora.build>"
```

---

## Verification

**Offline (no relay needed):**

```bash
cargo test vault_client
cargo test cli::tests::cli_vault
cargo build
```

**End-to-end (requires the relay-server vault API from the Prerequisite plan):**

```bash
# Two atems paired to the same Astation/work session:
atem vault new --summary "auth refactor context"      # → prints v-XXXX
atem vault write --vault-id v-XXXX --text "decided: JWT in httpOnly cookie"
atem vault read  --vault-id v-XXXX                     # second atem sees the entry
atem vault write --vault-id v-XXXX --entry-id 1 --text "decided: JWT, 15m expiry"
atem vault read  --vault-id v-XXXX --history           # shows e1 v1 + e1 v2
atem vault set-summary --vault-id v-XXXX --text "auth refactor — settled"
```

Negative: an atem **not** in the work session and **not** in `writer_list` gets a 403 on `read`; an out-of-session past-writer can `read` but a `write` is rejected.

## Notes for the implementer

- DRY: all URLs/bodies go through the Task 1 builders — handlers never format URLs inline.
- YAGNI: do **not** build `watch` here (v1.5). Do not add caching or retries.
- The session/auth coupling depends on the relay's session validation (vault.md open-question #6). If the relay uses a different auth header/scheme than `Authorization: session <id>`, change it in `VaultClient::send` only.
