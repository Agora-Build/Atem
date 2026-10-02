//! Relay client for /api/memory and /api/skills. Request building is pure
//! (unit-tested); `KnowledgeClient` only sends. Auth = the Astation pairing
//! session: the paired Astation is the account, so any machine paired with
//! it (and approved by it) can sync.
use serde::Deserialize;
use serde_json::{json, Value};
use crate::memory::model::{Memory, Scope, Skill};
use crate::memory::store::PendingOp;
use crate::memory::crypto::EncryptionContext;

pub const PULL_LIMIT: u32 = 200;
const MEMORY_MIGRATION_CHUNK: usize = 64;
const SKILL_MIGRATION_CHUNK: usize = 16;

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
        PendingOp::InvalidateMemory { id, invalid_at, superseded_by } => json!({"op": "invalidate", "id": id, "invalid_at": invalid_at, "superseded_by": superseded_by}),
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

fn skill_key_query(scope: Scope, project: &str, name: &str) -> String {
    format!("scope={}&project={}&name={}", scope.as_str(), enc(project), enc(name))
}

pub fn skill_versions_request(base: &str, client_id: &str, scope: Scope, project: &str, name: &str) -> ApiRequest {
    ApiRequest {
        method: "GET",
        url: format!("{}/api/skills/versions?id={}&{}", base_trim(base), enc(client_id), skill_key_query(scope, project, name)),
        body: None,
    }
}

pub fn skill_version_request(base: &str, client_id: &str, scope: Scope, project: &str, name: &str, version: i64) -> ApiRequest {
    ApiRequest {
        method: "GET",
        url: format!("{}/api/skills/version?id={}&{}&version={}", base_trim(base), enc(client_id), skill_key_query(scope, project, name), version),
        body: None,
    }
}

/// One entry of `GET /api/skills/versions` (no files).
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct SkillVersionInfo {
    pub version: i64,
    pub created_at: i64,
    #[serde(default)]
    pub source_agent: String,
    #[serde(default)]
    pub source_machine: String,
    #[serde(default)]
    pub file_count: i64,
    #[serde(default)]
    pub deleted: bool,
    #[serde(default)]
    pub purged: bool,
}

#[derive(Deserialize)]
struct VersionsPage {
    versions: Vec<SkillVersionInfo>,
}
#[derive(Deserialize)]
struct VersionPage {
    skill: Skill,
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
    Encryption(String),
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ApiError::Offline(e) => write!(f, "relay unreachable: {}", e),
            ApiError::Http(code, body) => write!(f, "relay returned {}: {}", code, body),
            ApiError::Decode(e) => write!(f, "unexpected relay response: {}", e),
            ApiError::Encryption(e) => write!(f, "end-to-end encryption: {}", e),
        }
    }
}

impl std::error::Error for ApiError {}

impl From<anyhow::Error> for ApiError {
    fn from(error: anyhow::Error) -> Self {
        Self::Encryption(error.to_string())
    }
}

/// The `Authorization` header value for a pairing session. Pure so it can be
/// unit-tested without a live `KnowledgeClient`.
pub fn auth_header(session_id: &str) -> String {
    format!("session {}", session_id)
}

pub struct KnowledgeClient {
    base: String,
    client_id: String,
    session_id: String,
    /// The paired Astation id — the relay account this client syncs with.
    astation_id: String,
    http: reqwest::Client,
}

impl KnowledgeClient {
    pub fn new(base: String, client_id: String, session_id: String, astation_id: String) -> Self {
        Self {
            base,
            client_id,
            session_id,
            astation_id,
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .unwrap_or_else(|_| reqwest::Client::new()),
        }
    }

    /// The account this client syncs with (the paired Astation id). Pull
    /// cursors are kept per account.
    pub fn account(&self) -> &str {
        &self.astation_id
    }

    async fn send(&self, req: ApiRequest) -> Result<reqwest::Response, ApiError> {
        let mut rb = match req.method {
            "POST" => self.http.post(&req.url),
            _ => self.http.get(&req.url),
        };
        rb = rb.header("Authorization", auth_header(&self.session_id));
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

    fn encryption(&self) -> Result<EncryptionContext, ApiError> {
        EncryptionContext::for_astation(&self.astation_id)
            .map_err(|error| ApiError::Encryption(error.to_string()))
    }

    fn encrypted_op(&self, op: &PendingOp, encryption: &EncryptionContext) -> Result<Value, ApiError> {
        let value = match op {
            PendingOp::AddMemory { memory } => json!({
                "op": "add",
                "memory": encryption.encrypt_memory(memory.clone())
                    .map_err(|error| ApiError::Encryption(error.to_string()))?,
            }),
            PendingOp::PushSkill { skill, base_version } => json!({
                "op": "push",
                "skill": encryption.encrypt_skill(skill.clone())
                    .map_err(|error| ApiError::Encryption(error.to_string()))?,
                "base_version": base_version,
            }),
            PendingOp::DeleteSkill { scope, project, name } => json!({
                "op": "delete", "scope": scope,
                "project": encryption.wire_project(project)
                    .map_err(|error| ApiError::Encryption(error.to_string()))?,
                "name": name,
            }),
            PendingOp::PurgeSkill { scope, project, name, versions } => json!({
                "op": "purge", "scope": scope,
                "project": encryption.wire_project(project)
                    .map_err(|error| ApiError::Encryption(error.to_string()))?,
                "name": name, "versions": versions,
            }),
            _ => op_to_wire(op),
        };
        Ok(value)
    }

    pub async fn push(&self, ops: &[&PendingOp], memory: bool) -> Result<Vec<OpResult>, ApiError> {
        let encryption = self.encryption()?;
        let kind = if memory { "memory" } else { "skills" };
        let wire = ops.iter()
            .map(|op| self.encrypted_op(op, &encryption))
            .collect::<Result<Vec<_>, _>>()?;
        let req = ApiRequest {
            method: "POST",
            url: format!("{}/api/{kind}/batch?id={}", base_trim(&self.base), enc(&self.client_id)),
            body: Some(json!({"ops": wire})),
        };
        let resp: BatchResponse = self.send(req).await?.json().await.map_err(|e| ApiError::Decode(e.to_string()))?;
        Ok(resp.results)
    }

    pub async fn pull_memories(&self, since: i64) -> Result<Vec<Memory>, ApiError> {
        let req = memory_pull_request(&self.base, &self.client_id, since, PULL_LIMIT);
        let page: MemoryPage = self.send(req).await?.json().await.map_err(|e| ApiError::Decode(e.to_string()))?;
        let encryption = self.encryption()?;
        page.memories.into_iter()
            .map(|memory| encryption.decrypt_memory(memory)
                .map_err(|error| ApiError::Encryption(error.to_string())))
            .collect()
    }

    pub async fn pull_skills(&self, since: i64) -> Result<Vec<Skill>, ApiError> {
        let req = skills_pull_request(&self.base, &self.client_id, since, PULL_LIMIT);
        let page: SkillPage = self.send(req).await?.json().await.map_err(|e| ApiError::Decode(e.to_string()))?;
        let encryption = self.encryption()?;
        page.skills.into_iter()
            .map(|skill| encryption.decrypt_skill(skill)
                .map_err(|error| ApiError::Encryption(error.to_string())))
            .collect()
    }

    /// A skill's history, newest first (no files).
    pub async fn skill_versions(&self, scope: Scope, project: &str, name: &str) -> Result<Vec<SkillVersionInfo>, ApiError> {
        let project = self.encryption()?.wire_project(project)
            .map_err(|error| ApiError::Encryption(error.to_string()))?;
        let req = skill_versions_request(&self.base, &self.client_id, scope, &project, name);
        let page: VersionsPage = self.send(req).await?.json().await.map_err(|e| ApiError::Decode(e.to_string()))?;
        Ok(page.versions)
    }

    /// One version with its files. 404 unknown, 410 purged (as `ApiError::Http`).
    pub async fn skill_version(&self, scope: Scope, project: &str, name: &str, version: i64) -> Result<Skill, ApiError> {
        let encryption = self.encryption()?;
        let project = encryption.wire_project(project)
            .map_err(|error| ApiError::Encryption(error.to_string()))?;
        let req = skill_version_request(&self.base, &self.client_id, scope, &project, name, version);
        let page: VersionPage = self.send(req).await?.json().await.map_err(|e| ApiError::Decode(e.to_string()))?;
        encryption.decrypt_skill(page.skill)
            .map_err(|error| ApiError::Encryption(error.to_string()))
    }

    /// Snapshot every historical row before rewriting any of them. Rewrites
    /// allocate fresh sequence values, so interleaving pull and rewrite could
    /// otherwise keep rediscovering our own migration writes.
    pub async fn migrate_encryption(&self) -> Result<(), ApiError> {
        use crate::memory::crypto::EncryptionMode;
        let encryption = self.encryption()?;
        if !matches!(encryption.mode, EncryptionMode::Enabling | EncryptionMode::Disabling) {
            return Ok(());
        }

        let mut memories = Vec::new();
        let mut since = 0;
        loop {
            let request = memory_pull_request(&self.base, &self.client_id, since, PULL_LIMIT);
            let page: MemoryPage = self.send(request).await?.json().await
                .map_err(|error| ApiError::Decode(error.to_string()))?;
            if page.memories.is_empty() { break; }
            since = page.memories.iter().map(|row| row.seq).max().unwrap_or(since);
            let count = page.memories.len();
            memories.extend(page.memories);
            if count < PULL_LIMIT as usize { break; }
        }

        let mut skills = Vec::new();
        since = 0;
        loop {
            let request = skills_pull_request(&self.base, &self.client_id, since, PULL_LIMIT);
            let page: SkillPage = self.send(request).await?.json().await
                .map_err(|error| ApiError::Decode(error.to_string()))?;
            if page.skills.is_empty() { break; }
            since = page.skills.iter().map(|row| row.seq).max().unwrap_or(since);
            let count = page.skills.len();
            skills.extend(page.skills);
            if count < PULL_LIMIT as usize { break; }
        }

        for chunk in memories.chunks(MEMORY_MIGRATION_CHUNK) {
            let mut ops = Vec::with_capacity(chunk.len());
            for raw in chunk {
                let old = raw.clone();
                let plain = encryption.decrypt_memory(raw.clone())?;
                let desired = if encryption.mode == EncryptionMode::Enabling {
                    encryption.encrypt_memory(plain)?
                } else {
                    plain
                };
                ops.push(json!({
                    "op": "rewrite",
                    "id": old.id,
                    "project": desired.project,
                    "content": desired.content,
                    "content_hash": desired.content_hash,
                }));
            }
            let response: BatchResponse = self.send(ApiRequest {
                method: "POST",
                url: format!("{}/api/memory/batch?id={}", base_trim(&self.base), enc(&self.client_id)),
                body: Some(json!({"ops": ops})),
            }).await?.json().await.map_err(|error| ApiError::Decode(error.to_string()))?;
            if response.results.len() != ops.len() || response.results.iter().any(|result| !result.ok) {
                return Err(ApiError::Encryption("relay refused a memory encryption rewrite".into()));
            }
        }

        for chunk in skills.chunks(SKILL_MIGRATION_CHUNK) {
            let mut ops = Vec::with_capacity(chunk.len());
            for raw in chunk {
                let old_project = raw.project.clone();
                let plain = encryption.decrypt_skill(raw.clone())?;
                let desired = if encryption.mode == EncryptionMode::Enabling {
                    encryption.encrypt_skill(plain)?
                } else {
                    plain
                };
                ops.push(json!({
                    "op": "rewrite",
                    "scope": desired.scope,
                    "old_project": old_project,
                    "name": desired.name,
                    "version": desired.version,
                    "project": desired.project,
                    "files": desired.files,
                    "content_hash": desired.content_hash,
                }));
            }
            let response: BatchResponse = self.send(ApiRequest {
                method: "POST",
                url: format!("{}/api/skills/batch?id={}", base_trim(&self.base), enc(&self.client_id)),
                body: Some(json!({"ops": ops})),
            }).await?.json().await.map_err(|error| ApiError::Decode(error.to_string()))?;
            if response.results.len() != ops.len() || response.results.iter().any(|result| !result.ok) {
                return Err(ApiError::Encryption("relay refused a skill encryption rewrite".into()));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::model::{content_hash, skill_hash, Scope};
    use serde_json::json;
    use std::collections::BTreeMap;

    #[test]
    fn invalidate_wire() {
        let op = PendingOp::InvalidateMemory { id: "mem_old".into(), invalid_at: 1790000000, superseded_by: Some("mem_new".into()) };
        assert_eq!(op_to_wire(&op), json!({"op": "invalidate", "id": "mem_old", "invalid_at": 1790000000, "superseded_by": "mem_new"}));
        let bare = PendingOp::InvalidateMemory { id: "mem_old".into(), invalid_at: 5, superseded_by: None };
        assert_eq!(op_to_wire(&bare)["superseded_by"], serde_json::Value::Null);
        // A replace's add carries valid_at to the relay.
        let mut m = sample();
        m.valid_at = Some(1690000000);
        assert_eq!(op_to_wire(&PendingOp::AddMemory { memory: m })["memory"]["valid_at"], 1690000000);
    }

    fn sample() -> Memory {
        Memory {
            id: "mem_1".into(), scope: Scope::Project, project: "github.com/acme/dialf".into(), machine: String::new(),
            content: "DialF uses TCP 8765".into(), content_hash: content_hash("DialF uses TCP 8765"),
            confidence: "high".into(), source_agent: "claude".into(), source_machine: "nixps-0001".into(),
            created_at: 1700000000, seq: 0, ..Default::default()
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
    fn sends_session_authorization() {
        assert_eq!(auth_header("sess_abc123"), "session sess_abc123");
    }

    #[test]
    fn api_error_display() {
        assert!(ApiError::Offline("x".into()).to_string().contains("unreachable"));
        assert!(ApiError::Http(403, "no".into()).to_string().contains("403"));
    }

    #[test]
    fn skill_history_request_urls() {
        let r = skill_versions_request("https://relay.example/", "inst 1", Scope::Project, "github.com/a/b", "deploy check");
        assert_eq!(r.method, "GET");
        assert_eq!(r.url, "https://relay.example/api/skills/versions?id=inst%201&scope=project&project=github.com%2Fa%2Fb&name=deploy%20check");
        assert!(r.body.is_none());
        assert_eq!(
            skill_version_request("https://relay.example", "i", Scope::Global, "", "demo", 4).url,
            "https://relay.example/api/skills/version?id=i&scope=global&project=&name=demo&version=4"
        );
        let info: SkillVersionInfo = serde_json::from_value(json!({"version": 2, "created_at": 5})).unwrap();
        assert_eq!((info.file_count, info.deleted, info.purged, info.source_agent.as_str()), (0, false, false, ""));
    }
}
