//! Relay client for /api/memory and /api/skills. Request building is pure
//! (unit-tested); `KnowledgeClient` only sends. Auth = the SSO token from
//! `atem login`, so any logged-in machine on any network can sync.
use serde::Deserialize;
use serde_json::{json, Value};
use crate::memory::model::{Memory, Skill};
use crate::memory::store::PendingOp;

pub const PULL_LIMIT: u32 = 200;

#[derive(Debug, Clone, PartialEq)]
pub struct ApiRequest {
    pub method: &'static str,
    pub url: String,
    pub body: Option<Value>,
}

fn base_trim(b: &str) -> &str {
    b.trim_end_matches('/')
}

fn enc(s: &str) -> String {
    urlencoding::encode(s).into_owned()
}

pub fn op_to_wire(op: &PendingOp) -> Value {
    match op {
        PendingOp::AddMemory { memory } => json!({"op": "add", "memory": memory}),
        PendingOp::DeleteMemory { id } => json!({"op": "delete", "id": id}),
        PendingOp::PushSkill { skill, base_version } => json!({"op": "push", "skill": skill, "base_version": base_version}),
        PendingOp::DeleteSkill { scope, project, name } => json!({"op": "delete", "scope": scope, "project": project, "name": name}),
        PendingOp::PurgeSkill { scope, project, name, versions } => json!({"op": "purge", "scope": scope, "project": project, "name": name, "versions": versions}),
    }
}

fn batch(base: &str, client_id: &str, kind: &str, ops: &[&PendingOp]) -> ApiRequest {
    ApiRequest {
        method: "POST",
        url: format!("{}/api/{}/batch?id={}", base_trim(base), kind, enc(client_id)),
        body: Some(json!({"ops": ops.iter().map(|o| op_to_wire(o)).collect::<Vec<_>>()})),
    }
}

fn pull(base: &str, client_id: &str, kind: &str, since: i64, limit: u32) -> ApiRequest {
    ApiRequest {
        method: "GET",
        url: format!("{}/api/{}?id={}&since={}&limit={}", base_trim(base), kind, enc(client_id), since, limit),
        body: None,
    }
}

pub fn memory_batch_request(base: &str, client_id: &str, ops: &[&PendingOp]) -> ApiRequest {
    batch(base, client_id, "memory", ops)
}
pub fn skills_batch_request(base: &str, client_id: &str, ops: &[&PendingOp]) -> ApiRequest {
    batch(base, client_id, "skills", ops)
}
pub fn memory_pull_request(base: &str, client_id: &str, since: i64, limit: u32) -> ApiRequest {
    pull(base, client_id, "memory", since, limit)
}
pub fn skills_pull_request(base: &str, client_id: &str, since: i64, limit: u32) -> ApiRequest {
    pull(base, client_id, "skills", since, limit)
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
pub struct OpResult {
    pub ok: bool,
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub canonical_id: Option<String>,
    #[serde(default)]
    pub seq: Option<i64>,
    #[serde(default)]
    pub version: Option<i64>,
    #[serde(default)]
    pub superseded_concurrent: bool,
    #[serde(default)]
    pub error: Option<String>,
}

#[derive(Deserialize)]
struct BatchResponse {
    results: Vec<OpResult>,
}
#[derive(Deserialize)]
struct MemoryPage {
    memories: Vec<Memory>,
}
#[derive(Deserialize)]
struct SkillPage {
    skills: Vec<Skill>,
}

#[derive(Debug)]
pub enum ApiError {
    /// Network failure: changes stay queued and sync next time.
    Offline(String),
    Http(u16, String),
    Decode(String),
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ApiError::Offline(e) => write!(f, "relay unreachable: {}", e),
            ApiError::Http(code, body) => write!(f, "relay returned {}: {}", code, body),
            ApiError::Decode(e) => write!(f, "unexpected relay response: {}", e),
        }
    }
}

impl std::error::Error for ApiError {}

pub struct KnowledgeClient {
    base: String,
    client_id: String,
    token: String,
    http: reqwest::Client,
}

impl KnowledgeClient {
    pub fn new(base: String, client_id: String, token: String) -> Self {
        Self {
            base,
            client_id,
            token,
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .unwrap_or_else(|_| reqwest::Client::new()),
        }
    }

    async fn send(&self, req: ApiRequest) -> Result<reqwest::Response, ApiError> {
        let mut rb = match req.method {
            "POST" => self.http.post(&req.url),
            _ => self.http.get(&req.url),
        };
        rb = rb.header("Authorization", format!("Bearer {}", self.token));
        if let Some(b) = req.body {
            rb = rb.json(&b);
        }
        let resp = rb.send().await.map_err(|e| ApiError::Offline(e.to_string()))?;
        if !resp.status().is_success() {
            let code = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(ApiError::Http(code, body));
        }
        Ok(resp)
    }

    pub async fn push(&self, ops: &[&PendingOp], memory: bool) -> Result<Vec<OpResult>, ApiError> {
        let req = if memory {
            memory_batch_request(&self.base, &self.client_id, ops)
        } else {
            skills_batch_request(&self.base, &self.client_id, ops)
        };
        let resp: BatchResponse = self.send(req).await?.json().await.map_err(|e| ApiError::Decode(e.to_string()))?;
        Ok(resp.results)
    }

    pub async fn pull_memories(&self, since: i64) -> Result<Vec<Memory>, ApiError> {
        let req = memory_pull_request(&self.base, &self.client_id, since, PULL_LIMIT);
        let page: MemoryPage = self.send(req).await?.json().await.map_err(|e| ApiError::Decode(e.to_string()))?;
        Ok(page.memories)
    }

    pub async fn pull_skills(&self, since: i64) -> Result<Vec<Skill>, ApiError> {
        let req = skills_pull_request(&self.base, &self.client_id, since, PULL_LIMIT);
        let page: SkillPage = self.send(req).await?.json().await.map_err(|e| ApiError::Decode(e.to_string()))?;
        Ok(page.skills)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::model::{content_hash, skill_hash, Scope};
    use serde_json::json;
    use std::collections::BTreeMap;

    fn sample() -> Memory {
        Memory {
            id: "mem_1".into(), scope: Scope::Project, project: "github.com/acme/dialf".into(), machine: String::new(),
            content: "DialF uses TCP 8765".into(), content_hash: content_hash("DialF uses TCP 8765"),
            confidence: "high".into(), source_agent: "claude".into(), source_machine: "nixps-0001".into(),
            created_at: 1700000000, deleted: false, seq: 0,
        }
    }

    #[test]
    fn pull_request_urls() {
        let r = memory_pull_request("https://relay.example/", "inst 1", 42, 200);
        assert_eq!(r.method, "GET");
        assert_eq!(r.url, "https://relay.example/api/memory?id=inst%201&since=42&limit=200");
        assert!(r.body.is_none());
        assert_eq!(skills_pull_request("https://relay.example", "i", 0, 5).url, "https://relay.example/api/skills?id=i&since=0&limit=5");
    }

    #[test]
    fn memory_batch_body() {
        let add = PendingOp::AddMemory { memory: sample() };
        let del = PendingOp::DeleteMemory { id: "mem_x".into() };
        let r = memory_batch_request("https://relay.example", "inst", &[&add, &del]);
        assert_eq!(r.method, "POST");
        assert_eq!(r.url, "https://relay.example/api/memory/batch?id=inst");
        let body = r.body.unwrap();
        assert_eq!(body["ops"][0]["op"], "add");
        assert_eq!(body["ops"][0]["memory"]["id"], "mem_1");
        assert_eq!(body["ops"][0]["memory"]["scope"], "project");
        assert_eq!(body["ops"][1], json!({"op": "delete", "id": "mem_x"}));
    }

    #[test]
    fn skill_ops_wire() {
        let mut files = BTreeMap::new();
        files.insert("SKILL.md".to_string(), b"hello".to_vec());
        let skill = Skill {
            scope: Scope::Global, project: String::new(), name: "demo".into(), version: 2,
            content_hash: skill_hash(&files), files,
            source_agent: "cli".into(), source_machine: "m".into(), created_at: 1, deleted: false, seq: 0,
        };
        let push = op_to_wire(&PendingOp::PushSkill { skill, base_version: 1 });
        assert_eq!(push["op"], "push");
        assert_eq!(push["base_version"], 1);
        assert_eq!(push["skill"]["files"]["SKILL.md"], "aGVsbG8=");
        let del = op_to_wire(&PendingOp::DeleteSkill { scope: Scope::Global, project: String::new(), name: "demo".into() });
        assert_eq!(del, json!({"op": "delete", "scope": "global", "project": "", "name": "demo"}));
        let purge_all = op_to_wire(&PendingOp::PurgeSkill { scope: Scope::Global, project: String::new(), name: "demo".into(), versions: None });
        assert_eq!(purge_all["versions"], serde_json::Value::Null);
        let purge_one = op_to_wire(&PendingOp::PurgeSkill { scope: Scope::Global, project: String::new(), name: "demo".into(), versions: Some(vec![2]) });
        assert_eq!(purge_one["versions"], json!([2]));
    }

    #[test]
    fn op_result_defaults() {
        let r: OpResult = serde_json::from_value(json!({"ok": true})).unwrap();
        assert!(r.ok && r.canonical_id.is_none() && !r.superseded_concurrent);
    }

    #[test]
    fn api_error_display() {
        assert!(ApiError::Offline("x".into()).to_string().contains("unreachable"));
        assert!(ApiError::Http(403, "no".into()).to_string().contains("403"));
    }
}
