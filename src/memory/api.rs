//! Relay client for /api/memory and /api/skills. Request building is pure
//! (unit-tested); `KnowledgeClient` only sends. Auth = the Astation pairing
//! session: the paired Astation is the account, so any machine paired with
//! it (and approved by it) can sync.
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::VecDeque;
use std::future::Future;
use crate::memory::model::{Memory, Scope, Skill};
use crate::memory::store::PendingOp;
use crate::memory::crypto::{
    memory_open_cost, memory_seal_cost, plan_groups, project_hash_cost, skill_open_cost, skill_seal_cost, Cost,
    EncryptionContext, EncryptionMode, ProjectNaming, Steps,
};

pub const PULL_LIMIT: u32 = 200;

/// What an encryption migration rewrites on the relay, per batch POST.
#[derive(Clone, Copy)]
enum Rewrite {
    Memory,
    Skills,
}

impl Rewrite {
    fn kind(self) -> &'static str {
        match self { Self::Memory => "memory", Self::Skills => "skills" }
    }

    /// Rows per POST.
    fn chunk(self) -> usize {
        match self { Self::Memory => 64, Self::Skills => 16 }
    }

    fn refused(self) -> &'static str {
        match self {
            Self::Memory => "relay refused a memory encryption rewrite",
            Self::Skills => "relay refused a skill encryption rewrite",
        }
    }
}

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

fn pull(base: &str, client_id: &str, kind: &str, since: i64, limit: u32) -> ApiRequest {
    ApiRequest {
        method: "GET",
        url: format!("{}/api/{}?id={}&since={}&limit={}", base_trim(base), kind, enc(client_id), since, limit),
        body: None,
    }
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
        // The whole chain: the cause (a locked agent, a hang-up) is the useful part.
        Self::Encryption(format!("{error:#}"))
    }
}

/// The `Authorization` header value for a pairing session. Pure so it can be
/// unit-tested without a live `KnowledgeClient`.
pub fn auth_header(session_id: &str) -> String {
    format!("session {}", session_id)
}

/// Cheap to clone (the HTTP client is shared): a pull fetches its next page
/// on a task of its own.
#[derive(Clone)]
pub struct KnowledgeClient {
    base: String,
    client_id: String,
    session_id: String,
    /// The paired Astation id — the relay account this client syncs with.
    astation_id: String,
    http: reqwest::Client,
    encryption_with: Option<(crate::paths::CredPaths, std::sync::Arc<dyn crate::memory::cred_agent::CredAgentApi>)>,
}

/// `ops` with every project pulled as a hash this Atem has named since put
/// back under its name (`EncryptionContext::name_hashes`): a replacement
/// queued while its fact was unresolved goes out like any other once the
/// name is known, never with a stale hash. What `seal_ops` seals, and what
/// an op sealed ahead is compared with before its POST (`seal_state`).
fn named_ops(encryption: &EncryptionContext, mut ops: Vec<PendingOp>) -> anyhow::Result<Vec<PendingOp>> {
    encryption.name_hashes(ops.iter_mut().filter_map(|op| match op {
        PendingOp::AddMemory { memory } => Some(&mut memory.project),
        PendingOp::PushSkill { skill, .. } => Some(&mut skill.project),
        PendingOp::DeleteSkill { project, .. } | PendingOp::PurgeSkill { project, .. } => Some(project),
        PendingOp::DeleteMemory { .. } | PendingOp::InvalidateMemory { .. } => None,
    }))?;
    Ok(ops)
}

/// The wire form of `ops` (as `named_ops` made them), encrypted when the
/// account is: every memory, skill and project hash of the batch in a few
/// cred-agent round trips.
fn encrypted_ops(encryption: &EncryptionContext, ops: &[PendingOp]) -> anyhow::Result<Vec<Value>> {
    if !encryption.should_encrypt() {
        return Ok(ops.iter().map(op_to_wire).collect());
    }
    let memories = encryption.encrypt_memories(ops.iter().filter_map(|op| match op {
        PendingOp::AddMemory { memory } => Some(memory.clone()),
        _ => None,
    }).collect())?;
    // Deleted and purged skills' project hashes ride in the pushed skills'
    // first request.
    let (skills, projects) = encryption.encrypt_skills_with_projects(ops.iter().filter_map(|op| match op {
        PendingOp::PushSkill { skill, .. } => Some(skill.clone()),
        _ => None,
    }).collect(), &ops.iter().filter_map(|op| match op {
        PendingOp::DeleteSkill { project, .. } | PendingOp::PurgeSkill { project, .. } => Some(project.clone()),
        _ => None,
    }).collect::<Vec<_>>())?;
    let (mut memories, mut skills, mut projects) = (memories.into_iter(), skills.into_iter(), projects.into_iter());
    let missing = || anyhow::anyhow!("an encrypted field of the batch is missing");
    ops.iter().map(|op| Ok(match op {
        PendingOp::AddMemory { .. } => json!({"op": "add", "memory": memories.next().ok_or_else(missing)?}),
        PendingOp::PushSkill { base_version, .. } => json!({"op": "push", "skill": skills.next().ok_or_else(missing)?, "base_version": base_version}),
        PendingOp::DeleteSkill { scope, name, .. } => json!({"op": "delete", "scope": scope, "project": projects.next().ok_or_else(missing)?, "name": name}),
        PendingOp::PurgeSkill { scope, name, versions, .. } => json!({"op": "purge", "scope": scope, "project": projects.next().ok_or_else(missing)?, "name": name, "versions": versions}),
        // Listed, not a catch-all: a new op with a secret field must be
        // encrypted above, never sent as it is by default.
        PendingOp::DeleteMemory { .. } | PendingOp::InvalidateMemory { .. } => op_to_wire(op),
    })).collect()
}

/// What `encrypted_ops` asks the cred agent for `op`, per dependent step
/// (memory: one; skills: paths and hashes, then files), for `Planner`. A
/// project this Atem can't name costs nothing (it goes out as it came);
/// `Planner` prices ops as queued, so one named since (`named_ops`) costs a
/// keyed hash more when sealed: an estimate, never a result (`Cost`).
pub(crate) fn seal_cost(op: &PendingOp) -> Steps {
    let none = Cost::default();
    match op {
        PendingOp::AddMemory { memory } => [memory_seal_cost(memory), none, none],
        PendingOp::PushSkill { skill, .. } => {
            let [paths, files] = skill_seal_cost(skill);
            [paths, files, none]
        }
        PendingOp::DeleteSkill { project, .. } | PendingOp::PurgeSkill { project, .. } => [project_hash_cost(project), none, none],
        PendingOp::DeleteMemory { .. } | PendingOp::InvalidateMemory { .. } => [none; 3],
    }
}

/// The account state a batch was sealed under (mode, key, data account).
/// An op sealed ahead of its POST is sent as sealed only while the state is
/// still this one: after a mode or key change it is sealed again, as if it
/// had been sealed just before its POST.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealState {
    mode: EncryptionMode,
    kid: Option<String>,
    data_account: String,
}

impl SealState {
    fn of(encryption: &EncryptionContext) -> Self {
        Self { mode: encryption.mode, kid: encryption.kid.clone(), data_account: encryption.data_account.clone() }
    }

    /// Whether ops are sealed under this state (the account encrypts): only
    /// then does sealing an op with a protected field ask the cred agent.
    pub fn encrypts(&self) -> bool {
        matches!(self.mode, EncryptionMode::Enabling | EncryptionMode::On)
    }
}

/// The body of a batch POST, serialized from borrowed ops.
#[derive(Serialize)]
struct Batch<'a> {
    ops: &'a [Value],
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
            encryption_with: None,
        }
    }

    
    pub(crate) fn with_encryption(mut self, paths: crate::paths::CredPaths, agent: std::sync::Arc<dyn crate::memory::cred_agent::CredAgentApi>) -> Self {
        self.encryption_with = Some((paths, agent));
        self
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
        if let Some(b) = req.body {
            rb = rb.json(&b);
        }
        self.finish(rb).await
    }

    async fn finish(&self, rb: reqwest::RequestBuilder) -> Result<reqwest::Response, ApiError> {
        let rb = rb.header("Authorization", auth_header(&self.session_id));
        let resp = rb.send().await.map_err(|e| ApiError::Offline(e.to_string()))?;
        if !resp.status().is_success() {
            let code = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(ApiError::Http(code, body));
        }
        Ok(resp)
    }

    fn encryption(&self) -> Result<EncryptionContext, ApiError> {
        if let Some((paths, agent)) = &self.encryption_with {
            return EncryptionContext::for_astation_with(&self.astation_id, paths, agent.clone())
                .map_err(ApiError::from);
        }
        EncryptionContext::for_astation(&self.astation_id)
            .map_err(ApiError::from)
    }

    /// The state ops sealed now would be sealed under, and `ops` as they
    /// would be sealed now (`named_ops`; project_names.json is read only
    /// when some op has a project pulled as a hash). An op sealed earlier
    /// goes out as sealed only while both are unchanged (`sync::reusable`).
    pub fn seal_state(&self, ops: Vec<PendingOp>) -> Result<(SealState, Vec<PendingOp>), ApiError> {
        let encryption = self.encryption()?;
        let named = named_ops(&encryption, ops)?;
        Ok((SealState::of(&encryption), named))
    }

    /// `ops` in their wire form, sealed while the account is encrypted, and
    /// the state they were sealed under; each wire beside the op it was
    /// sealed from (`named_ops`: a project hash named since under its name).
    /// Ops planned with `seal_cost` to fit one batch are one `Crypt` request
    /// per step.
    pub async fn seal_ops(&self, ops: Vec<PendingOp>) -> Result<(SealState, Vec<(PendingOp, Value)>), ApiError> {
        let encryption = self.encryption()?;
        let state = SealState::of(&encryption);
        let sealed = encryption.blocking(move |encryption| {
            let ops = named_ops(encryption, ops)?;
            let wire = encrypted_ops(encryption, &ops)?;
            Ok(ops.into_iter().zip(wire).collect::<Vec<_>>())
        }).await?;
        Ok((state, sealed))
    }

    /// Before ops sealed by an earlier request are sent: the cred agent is
    /// still unlocked (a status on the shared connection), so a lock stops a
    /// push within one POST, as when each chunk was sealed just before its
    /// POST. Nothing to confirm while the account isn't encrypting.
    pub async fn confirm_unlocked(&self) -> Result<(), ApiError> {
        let encryption = self.encryption()?;
        if !encryption.should_encrypt() {
            return Ok(());
        }
        encryption.blocking(|encryption| encryption.confirm_unlocked()).await.map_err(ApiError::from)
    }

    /// POSTs ops in their wire form (`seal_ops`) as one batch.
    pub async fn post_ops(&self, wire: &[Value], memory: bool) -> Result<Vec<OpResult>, ApiError> {
        self.post_batch(if memory { "memory" } else { "skills" }, wire).await
    }

    async fn post_batch(&self, kind: &str, ops: &[Value]) -> Result<Vec<OpResult>, ApiError> {
        let url = format!("{}/api/{kind}/batch?id={}", base_trim(&self.base), enc(&self.client_id));
        let resp: BatchResponse = self.finish(self.http.post(&url).json(&Batch { ops })).await?
            .json().await.map_err(|e| ApiError::Decode(e.to_string()))?;
        Ok(resp.results)
    }

    /// Seals `ops` and POSTs them as one batch.
    #[cfg(test)]
    pub async fn push(&self, ops: &[&PendingOp], memory: bool) -> Result<Vec<OpResult>, ApiError> {
        let (_, sealed) = self.seal_ops(ops.iter().map(|op| (*op).clone()).collect()).await?;
        let wire: Vec<Value> = sealed.into_iter().map(|(_, wire)| wire).collect();
        self.post_ops(&wire, memory).await
    }

    /// The page of memory rows after `since`, as the relay sent it.
    pub async fn fetch_memories(&self, since: i64) -> Result<Vec<Memory>, ApiError> {
        let req = memory_pull_request(&self.base, &self.client_id, since, PULL_LIMIT);
        let page: MemoryPage = self.send(req).await?.json().await.map_err(|e| ApiError::Decode(e.to_string()))?;
        Ok(page.memories)
    }

    /// A pulled page's memory rows opened (`decrypt_pulled_memories`):
    /// plain text is refused while encryption is on, and a well-formed
    /// project hash this Atem can't name stays as it is (unresolved).
    pub async fn open_memories(&self, rows: Vec<Memory>) -> Result<Vec<Memory>, ApiError> {
        let encryption = self.encryption()?;
        encryption.blocking(move |encryption| encryption.decrypt_pulled_memories(rows)).await.map_err(ApiError::from)
    }

    #[cfg(test)]
    pub async fn pull_memories(&self, since: i64) -> Result<Vec<Memory>, ApiError> {
        let rows = self.fetch_memories(since).await?;
        self.open_memories(rows).await
    }

    /// The page of skill rows after `since`, as the relay sent it.
    pub async fn fetch_skills(&self, since: i64) -> Result<Vec<Skill>, ApiError> {
        let req = skills_pull_request(&self.base, &self.client_id, since, PULL_LIMIT);
        let page: SkillPage = self.send(req).await?.json().await.map_err(|e| ApiError::Decode(e.to_string()))?;
        Ok(page.skills)
    }

    /// A pulled page's skill rows opened (`decrypt_pulled_skills`): as
    /// `open_memories`.
    pub async fn open_skills(&self, rows: Vec<Skill>) -> Result<Vec<Skill>, ApiError> {
        let encryption = self.encryption()?;
        encryption.blocking(move |encryption| encryption.decrypt_pulled_skills(rows)).await.map_err(ApiError::from)
    }

    #[cfg(test)]
    pub async fn pull_skills(&self, since: i64) -> Result<Vec<Skill>, ApiError> {
        let rows = self.fetch_skills(since).await?;
        self.open_skills(rows).await
    }

    /// Names what it can of the pulled project hashes `hashes`, hashing and
    /// recording `current` (the checkout a sync runs in) and the projects it
    /// knows first. See `EncryptionContext::learn_project_names`.
    pub async fn learn_project_names(&self, hashes: Vec<String>, current: Option<String>) -> Result<ProjectNaming, ApiError> {
        let encryption = self.encryption()?;
        encryption.blocking(move |encryption| encryption.learn_project_names(&hashes, current.as_deref())).await.map_err(ApiError::from)
    }

    /// A skill's history, newest first (no files).
    pub async fn skill_versions(&self, scope: Scope, project: &str, name: &str) -> Result<Vec<SkillVersionInfo>, ApiError> {
        let encryption = self.encryption()?;
        let project = project.to_string();
        let project = encryption.blocking(move |encryption| encryption.wire_project(&project)).await.map_err(ApiError::from)?;
        let req = skill_versions_request(&self.base, &self.client_id, scope, &project, name);
        let page: VersionsPage = self.send(req).await?.json().await.map_err(|e| ApiError::Decode(e.to_string()))?;
        Ok(page.versions)
    }

    /// One version with its files. 404 unknown, 410 purged (as `ApiError::Http`).
    pub async fn skill_version(&self, scope: Scope, project: &str, name: &str, version: i64) -> Result<Skill, ApiError> {
        let encryption = self.encryption()?;
        let project = project.to_string();
        let project = encryption.blocking(move |encryption| encryption.wire_project(&project)).await.map_err(ApiError::from)?;
        let req = skill_version_request(&self.base, &self.client_id, scope, &project, name, version);
        let page: VersionPage = self.send(req).await?.json().await.map_err(|e| ApiError::Decode(e.to_string()))?;
        encryption.blocking(move |encryption| encryption.decrypt_skill(page.skill)).await.map_err(ApiError::from)
    }

    /// Read every returned historical row back and authenticate its migrated
    /// fields, page by page, each page checked while the next one is fetched.
    pub async fn verify_encryption_migration(&self) -> Result<(), ApiError> {
        let encryption = self.encryption()?;
        let kid = encryption.kid.clone().ok_or_else(|| ApiError::Encryption("migration key is missing".into()))?;
        let encryption = &encryption;
        self.read_back(|since| self.fetch_memories(since), |row: &Memory| row.seq, |page: Vec<Memory>| {
            let kid = kid.clone();
            encryption.blocking(move |context| {
                for row in &page {
                    for (value, prefix) in [(&row.content, "e1"), (&row.project, "h1"), (&row.content_hash, "h1")] {
                        crate::memory::migration::verify_field(value, prefix, context.mode, &kid)?;
                    }
                }
                context.decrypt_memories(page)?;
                Ok(())
            })
        }).await?;
        self.read_back(|since| self.fetch_skills(since), |row: &Skill| row.seq, |page: Vec<Skill>| {
            let kid = kid.clone();
            encryption.blocking(move |context| {
                for row in &page {
                    for value in [&row.project, &row.content_hash] {
                        crate::memory::migration::verify_field(value, "h1", context.mode, &kid)?;
                    }
                    for (path, content) in &row.files {
                        crate::memory::migration::verify_field(path, "e1", context.mode, &kid)?;
                        if context.mode == EncryptionMode::Enabling {
                            crate::memory::migration::verify_field(std::str::from_utf8(content)?, "e1", context.mode, &kid)?;
                        } else if let Ok(content) = std::str::from_utf8(content) {
                            crate::memory::migration::verify_field(content, "e1", context.mode, &kid)?;
                        }
                    }
                }
                context.decrypt_skills(page)?;
                Ok(())
            })
        }).await
    }

    /// Reads one kind back from the start, checking each page (`check`)
    /// while the next one is fetched (F2); a failed check or request stops
    /// it, and a page that doesn't move the cursor is an error.
    async fn read_back<R, F, FF, C, CF>(&self, fetch: F, seq: fn(&R) -> i64, check: C) -> Result<(), ApiError>
    where
        F: Fn(i64) -> FF,
        FF: Future<Output = Result<Vec<R>, ApiError>>,
        C: Fn(Vec<R>) -> CF,
        CF: Future<Output = anyhow::Result<()>>,
    {
        let mut since = 0;
        let mut page = fetch(since).await?;
        loop {
            let count = page.len();
            let next = page.iter().map(seq).max().unwrap_or(since);
            if count < PULL_LIMIT as usize {
                return Ok(check(page).await?);
            }
            if next <= since {
                check(page).await?;
                return Err(ApiError::Encryption("migration verification cursor did not advance".into()));
            }
            let (checked, fetched) = tokio::join!(check(page), fetch(next));
            checked?;
            page = fetched?;
            since = next;
        }
    }

    /// Snapshot every historical row before rewriting any of them. Rewrites
    /// allocate fresh sequence values, so interleaving pull and rewrite could
    /// otherwise keep rediscovering our own migration writes.
    pub async fn migrate_encryption(&self) -> Result<(), ApiError> {
        let encryption = self.encryption()?;
        if !matches!(encryption.mode, EncryptionMode::Enabling | EncryptionMode::Disabling) {
            return Ok(());
        }

        let mut memories = Vec::new();
        let mut since = 0;
        loop {
            let page = self.fetch_memories(since).await?;
            if page.is_empty() { break; }
            since = page.iter().map(|row| row.seq).max().unwrap_or(since);
            let count = page.len();
            memories.extend(page);
            if count < PULL_LIMIT as usize { break; }
        }

        let mut skills = Vec::new();
        since = 0;
        loop {
            let page = self.fetch_skills(since).await?;
            if page.is_empty() { break; }
            since = page.iter().map(|row| row.seq).max().unwrap_or(since);
            let count = page.len();
            skills.extend(page);
            if count < PULL_LIMIT as usize { break; }
        }

        let enabling = encryption.mode == EncryptionMode::Enabling;
        let none = Cost::default();
        self.rewrite_all(&encryption, memories, Rewrite::Memory,
            |row| [memory_open_cost(row), if enabling { memory_seal_cost(row) } else { none }, none],
            rewritten_memories).await?;
        self.rewrite_all(&encryption, skills, Rewrite::Skills,
            |row| {
                let [paths, files] = if enabling { skill_seal_cost(row) } else { [none; 2] };
                [skill_open_cost(row), paths, files]
            },
            rewritten_skills).await
    }

    /// Rewrites `rows` on the relay, `kind.chunk()` rows per POST, in order.
    /// The rows are opened and sealed again (`prepare`) in groups of whole
    /// POSTs (`plan_groups`), the next group while the POST before it is in
    /// flight (F2). A POST of rows prepared by an earlier request first
    /// confirms the cred agent is still unlocked, so a lock stops the
    /// migration within one POST, as when each POST was prepared just before
    /// it. Nothing is recorded locally: a failure stops the migration, which
    /// runs again from a new snapshot, and only the read-back says it is done.
    async fn rewrite_all<R: Clone + Send + 'static>(
        &self,
        encryption: &EncryptionContext,
        rows: Vec<R>,
        kind: Rewrite,
        cost: impl Fn(&R) -> Steps,
        prepare: fn(&EncryptionContext, Vec<R>) -> anyhow::Result<Vec<Value>>,
    ) -> Result<(), ApiError> {
        let chunk = kind.chunk();
        let mut groups = plan_groups(&rows, chunk, cost).into_iter();
        let seal = |range: std::ops::Range<usize>| {
            let rows = rows[range].to_vec();
            encryption.blocking(move |encryption| prepare(encryption, rows))
        };
        let mut ready: VecDeque<Value> = VecDeque::new();
        let mut sent = 0;
        while sent < rows.len() {
            let end = (sent + chunk).min(rows.len());
            // The first chunk, or the read-ahead fell behind: this POST's rows first.
            let mut prepared_now = false;
            while sent + ready.len() < end {
                let Some(range) = groups.next() else { break };
                ready.extend(seal(range).await?);
                prepared_now = true;
            }
            if sent + ready.len() < end {
                return Err(ApiError::Encryption("a migration batch lost rows".into()));
            }
            if !prepared_now {
                encryption.blocking(|encryption| encryption.confirm_unlocked()).await?;
            }
            let ops: Vec<Value> = ready.drain(..end - sent).collect();
            // Prepare the next group while this POST is in flight, once what is
            // ready no longer covers the next POST.
            let next = if ready.len() < chunk { groups.next() } else { None };
            let (posted, prepared) = match next {
                Some(range) => {
                    let (posted, prepared) = tokio::join!(self.post_batch(kind.kind(), &ops), seal(range));
                    (posted, Some(prepared))
                }
                None => (self.post_batch(kind.kind(), &ops).await, None),
            };
            let results = posted?;
            if results.len() != ops.len() || results.iter().any(|result| !result.ok) {
                return Err(ApiError::Encryption(kind.refused().into()));
            }
            if let Some(prepared) = prepared {
                ready.extend(prepared?);
            }
            sent = end;
        }
        Ok(())
    }
}

/// The migration's rewrite ops for memory rows: opened, then sealed again
/// while enabling.
fn rewritten_memories(encryption: &EncryptionContext, raw: Vec<Memory>) -> anyhow::Result<Vec<Value>> {
    let plain = encryption.decrypt_memories(raw.clone())?;
    let desired = if encryption.mode == EncryptionMode::Enabling { encryption.encrypt_memories(plain)? } else { plain };
    Ok(raw.iter().zip(desired).map(|(old, desired)| json!({
        "op": "rewrite",
        "id": old.id,
        "project": desired.project,
        "content": desired.content,
        "content_hash": desired.content_hash,
    })).collect())
}

/// The migration's rewrite ops for skill rows: opened, then sealed again
/// while enabling.
fn rewritten_skills(encryption: &EncryptionContext, raw: Vec<Skill>) -> anyhow::Result<Vec<Value>> {
    let plain = encryption.decrypt_skills(raw.clone())?;
    let desired = if encryption.mode == EncryptionMode::Enabling { encryption.encrypt_skills(plain)? } else { plain };
    Ok(raw.iter().zip(desired).map(|(old, desired)| json!({
        "op": "rewrite",
        "scope": desired.scope,
        "old_project": old.project,
        "name": desired.name,
        "version": desired.version,
        "project": desired.project,
        "files": desired.files,
        "content_hash": desired.content_hash,
    })).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::model::{content_hash, skill_hash, Scope};
    use serde_json::json;
    use std::collections::BTreeMap;

    #[test]
    fn an_encryption_error_keeps_its_cause() {
        let error = anyhow::anyhow!("the cred agent closed the connection").context("sealing a memory");
        assert_eq!(
            ApiError::from(error).to_string(),
            "end-to-end encryption: sealing a memory: the cred agent closed the connection"
        );
    }

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
    fn memory_ops_wire() {
        let add = op_to_wire(&PendingOp::AddMemory { memory: sample() });
        assert_eq!(add["op"], "add");
        assert_eq!(add["memory"]["id"], "mem_1");
        assert_eq!(add["memory"]["scope"], "project");
        let del = op_to_wire(&PendingOp::DeleteMemory { id: "mem_x".into() });
        assert_eq!(del, json!({"op": "delete", "id": "mem_x"}));
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
