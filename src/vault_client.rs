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

/// One entry row as returned by the relay (see designs/vault.md §Data model).
#[derive(Debug, Clone, Deserialize)]
pub struct VaultEntry {
    /// Global write order; becomes the `--since` cursor when `watch` (v1.5) lands.
    #[allow(dead_code)]
    pub seq: u64,
    pub entry_no: u32,
    pub version: u32,
    /// 'content' | 'summary' — kept for wire-contract completeness.
    #[allow(dead_code)]
    pub kind: String,
    pub writer_id: String,
    pub content: String,
    /// ISO-8601 timestamp — kept for wire-contract completeness.
    #[allow(dead_code)]
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
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .unwrap_or_else(|_| reqwest::Client::new()),
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

    #[test]
    fn render_current_human_exact_output() {
        let entries = vec![
            VaultEntry { seq: 1, entry_no: 1, version: 1, kind: "content".into(),
                writer_id: "a".into(), content: "first".into(), created_at: "t1".into() },
            VaultEntry { seq: 3, entry_no: 2, version: 2, kind: "content".into(),
                writer_id: "b".into(), content: "second".into(), created_at: "t3".into() },
        ];
        let out = render_current("the summary", &entries, OutFormat::Human);
        assert_eq!(out, "summary: the summary\n  e1: first\n  e2: second\n");
    }

    #[test]
    fn render_history_human_exact_output_includes_writer() {
        let entries = vec![
            VaultEntry { seq: 1, entry_no: 1, version: 1, kind: "content".into(),
                writer_id: "alice".into(), content: "v1 text".into(), created_at: "t1".into() },
            VaultEntry { seq: 2, entry_no: 1, version: 2, kind: "content".into(),
                writer_id: "bob".into(), content: "v2 text".into(), created_at: "t2".into() },
        ];
        let out = render_history(&entries, OutFormat::Human);
        assert_eq!(out, "  e1 v1 [alice] v1 text\n  e1 v2 [bob] v2 text\n");
    }

    #[test]
    fn render_empty_entries_is_stable() {
        let none: Vec<VaultEntry> = vec![];
        assert_eq!(render_current("s", &none, OutFormat::Human), "summary: s\n");
        assert_eq!(render_current("s", &none, OutFormat::Plain), "");
        assert_eq!(render_history(&none, OutFormat::Human), "");
        assert_eq!(render_history(&none, OutFormat::Plain), "");
    }
}
