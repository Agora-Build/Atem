use crate::memory::adapters::Ctx;
use crate::memory::api::KnowledgeClient;
use crate::memory::account_keys::CryptOp;
use crate::memory::crypto::{EncryptionContext, EncryptionMode};
use crate::memory::fake_astation::UnlockedDevice;
use crate::memory::fake_station_skills;
use crate::memory::cred_agent::{CredAgent, CredAgentApi, Reply, Request, error_of, test_agent};
use crate::paths::CredPaths;
use std::sync::atomic::{AtomicUsize, Ordering};
use crate::memory::model::{Memory, Scope, Skill, content_hash, skill_hash};
use crate::memory::store::{PendingOp, Store};
use crate::memory::sync::{SyncOptions, run_sync};
use crate::vault_client::VaultClient;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

const ASTATION: &str = "astation-1";
const OLD_KID: &str = "0123abcd";
const NEW_KID: &str = "89abcdef";

#[derive(Clone)]
pub(crate) struct RelayState {
    memories: Vec<Memory>,
    skills: Vec<Skill>,
    vault_summary: String,
    vault_entries: Vec<Value>,
    next_seq: i64,
}

impl RelayState {
    /// A relay that stores nothing yet.
    pub(crate) fn empty() -> Self {
        Self { memories: Vec::new(), skills: Vec::new(), vault_summary: String::new(), vault_entries: Vec::new(), next_seq: 1 }
    }

    pub(crate) fn seeded() -> Self {
        let memory = Memory {
            id: "mem-seed".into(),
            scope: Scope::Project,
            project: "github.com/agora/atem".into(),
            content: "relay starts as plaintext".into(),
            content_hash: content_hash("relay starts as plaintext"),
            confidence: "high".into(),
            source_agent: "test".into(),
            source_machine: "mac".into(),
            created_at: 1,
            seq: 1,
            ..Memory::default()
        };
        let skill = |version: i64, body: &str, seq: i64| {
            let files = BTreeMap::from([
                ("SKILL.md".to_string(), body.as_bytes().to_vec()),
                ("asset.bin".to_string(), vec![0, 159, 146, version as u8]),
            ]);
            Skill {
                scope: Scope::Project,
                project: "github.com/agora/atem".into(),
                name: "deploy".into(),
                version,
                content_hash: skill_hash(&files),
                files,
                source_agent: "test".into(),
                source_machine: "mac".into(),
                created_at: version,
                deleted: false,
                seq,
            }
        };
        Self {
            memories: vec![memory],
            skills: vec![skill(1, "# deploy v1", 2), skill(2, "# deploy v2", 3)],
            vault_summary: "production access".into(),
            vault_entries: vec![
                vault_entry(4, 1, 1, "first secret"),
                vault_entry(5, 1, 2, "rotated secret"),
                vault_entry(6, 2, 1, "recovery note"),
            ],
            next_seq: 7,
        }
    }
}

fn vault_entry(seq: u64, entry_no: u32, version: u32, content: &str) -> Value {
    json!({
        "seq": seq,
        "entry_no": entry_no,
        "version": version,
        "kind": "content",
        "writer_id": "seed",
        "content": content,
        "created_at": "2026-10-02T00:00:00Z",
    })
}

fn clients(base: &str, device: &UnlockedDevice) -> (KnowledgeClient, VaultClient) {
    (
        KnowledgeClient::new(
            base.into(),
            "atem-1".into(),
            "session-1".into(),
            ASTATION.into(),
        )
        .with_encryption(device.paths.clone(), device.agent.clone()),
        VaultClient::new(
            base.into(),
            "atem-1".into(),
            "session-1".into(),
            ASTATION.into(),
        )
        .with_encryption(device.paths.clone(), device.agent.clone()),
    )
}

pub(crate) fn assert_all_encrypted_with(state: &RelayState, kid: &str) {
    let envelope = format!("e1.{kid}.");
    let hash = format!("h1.{kid}.");
    assert!(state.memories.iter().all(|memory| {
        memory.content.starts_with(&envelope)
            && memory.content_hash.starts_with(&hash)
            && memory.project.starts_with(&hash)
    }));
    assert!(state.skills.iter().all(|skill| {
        skill.project.starts_with(&hash)
            && skill.content_hash.starts_with(&hash)
            && skill.files.iter().all(|(path, content)| {
                path.starts_with(&envelope)
                    && std::str::from_utf8(content).is_ok_and(|text| text.starts_with(&envelope))
            })
    }));
    assert!(state.vault_summary.starts_with(&envelope));
    assert!(state.vault_entries.iter().all(|entry| {
        entry["content"]
            .as_str()
            .is_some_and(|content| content.starts_with(&envelope))
    }));
}

pub(crate) async fn stub_relay(state: Arc<Mutex<RelayState>>) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            let state = state.clone();
            tokio::spawn(async move {
                let mut request = Vec::new();
                let mut chunk = [0_u8; 65_536];
                let header_end = loop {
                    let count = socket.read(&mut chunk).await.unwrap_or(0);
                    if count == 0 {
                        return;
                    }
                    request.extend_from_slice(&chunk[..count]);
                    if let Some(index) = request.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
                        break index + 4;
                    }
                };
                let header = String::from_utf8_lossy(&request[..header_end]);
                let mut lines = header.lines();
                let mut request_line = lines.next().unwrap_or("").split(' ');
                let method = request_line.next().unwrap_or("").to_string();
                let path = request_line.next().unwrap_or("").to_string();
                let content_length = lines
                    .filter_map(|line| line.split_once(':'))
                    .find(|(name, _)| name.trim().eq_ignore_ascii_case("content-length"))
                    .and_then(|(_, value)| value.trim().parse::<usize>().ok())
                    .unwrap_or(0);
                while request.len() < header_end + content_length {
                    let count = socket.read(&mut chunk).await.unwrap_or(0);
                    if count == 0 {
                        break;
                    }
                    request.extend_from_slice(&chunk[..count]);
                }
                let body = serde_json::from_slice(&request[header_end..]).unwrap_or(Value::Null);
                let response = handle_request(&state, &method, &path, &body);
                let text = response.to_string();
                let wire = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                    text.len(),
                    text
                );
                socket.write_all(wire.as_bytes()).await.unwrap();
                socket.shutdown().await.unwrap();
            });
        }
    });
    base
}

/// The `since` cursor of a pull request (0 without one).
fn since(path: &str) -> i64 {
    path.split(['?', '&'])
        .find_map(|pair| pair.strip_prefix("since="))
        .and_then(|value| value.parse().ok())
        .unwrap_or(0)
}

fn handle_request(state: &Arc<Mutex<RelayState>>, method: &str, path: &str, body: &Value) -> Value {
    let mut state = state.lock().unwrap();
    if method == "GET" && path.starts_with("/api/memory?") {
        let since = since(path);
        let page: Vec<&Memory> = state.memories.iter().filter(|row| row.seq > since).collect();
        return json!({"memories": page});
    }
    // Skills as the Station's skill file transport serves
    // them (`fake_station_skills`), the rows kept in their stored form.
    if method == "GET" && path.starts_with("/api/skills?") {
        let since = since(path);
        return fake_station_skills::page(state.skills.iter().filter(|row| row.seq > since));
    }
    if method == "POST" && path.starts_with("/api/memory/batch?") {
        let mut results = Vec::new();
        for op in body["ops"].as_array().unwrap() {
            let mut canonical_id = None;
            let mut seq = state.next_seq;
            match op["op"].as_str().unwrap() {
                // A rewrite takes a fresh seq, as on the relay.
                "rewrite" => {
                    state.next_seq += 1;
                    let id = op["id"].as_str().unwrap();
                    let memory = state.memories.iter_mut().find(|row| row.id == id).unwrap();
                    memory.project = op["project"].as_str().unwrap().into();
                    memory.content = op["content"].as_str().unwrap().into();
                    memory.content_hash = op["content_hash"].as_str().unwrap().into();
                    memory.seq = seq;
                }
                "add" => {
                    let mut memory: Memory = serde_json::from_value(op["memory"].clone()).unwrap();
                    if let Some(existing) = state.memories.iter().find(|m| m.id == memory.id ||
                        (m.content_hash == memory.content_hash && m.scope == memory.scope && m.project == memory.project && m.machine == memory.machine)) {
                        seq = existing.seq;
                        canonical_id = Some(existing.id.clone());
                    } else {
                        memory.seq = seq;
                        state.next_seq += 1;
                        state.memories.push(memory);
                    }
                }
                "invalidate" => {
                    state.next_seq += 1;
                    let id = op["id"].as_str().unwrap();
                    let memory = state.memories.iter_mut().find(|row| row.id == id).unwrap();
                    memory.invalid_at = op["invalid_at"].as_i64();
                    memory.superseded_by = op["superseded_by"].as_str().map(str::to_string);
                    memory.seq = seq;
                }
                other => panic!("unexpected memory operation {other}"),
            }
            results.push(json!({"ok": true, "seq": seq, "canonical_id": canonical_id}));
        }
        return json!({"results": results});
    }
    if method == "POST" && path.starts_with("/api/skills/batch?") {
        let state = &mut *state;
        return fake_station_skills::batch_ok(body, |op| {
            assert_eq!(op["op"], "rewrite");
            let seq = state.next_seq;
            state.next_seq += 1;
            let version = op["version"].as_i64().unwrap();
            let name = op["name"].as_str().unwrap();
            let skill = state
                .skills
                .iter_mut()
                .find(|row| row.name == name && row.version == version)
                .unwrap();
            skill.project = op["project"].as_str().unwrap().into();
            skill.files = crate::memory::model::b64map::deserialize(&op["files"]).unwrap();
            skill.content_hash = op["content_hash"].as_str().unwrap().into();
            skill.seq = seq;
            json!({"ok": true, "version": version, "seq": state.next_seq})
        });
    }
    if method == "GET" && path.starts_with("/api/vault?") {
        return json!([{"vault_id": "v-test", "summary": state.vault_summary}]);
    }
    if method == "GET" && path.starts_with("/api/vault/v-test?") {
        return Value::Array(state.vault_entries.clone());
    }
    if method == "POST" && path.starts_with("/api/vault/v-test/encryption?") {
        state.vault_summary = body["summary"].as_str().unwrap().into();
        for replacement in body["entries"].as_array().unwrap() {
            let entry = state
                .vault_entries
                .iter_mut()
                .find(|entry| {
                    entry["entry_no"] == replacement["entry_no"]
                        && entry["version"] == replacement["version"]
                })
                .unwrap();
            entry["content"] = replacement["content"].clone();
        }
        return json!({"ok": true});
    }
    panic!("unexpected relay request: {method} {path} {body}");
}

#[tokio::test]
async fn real_clients_migrate_upload_pull_and_rotate_every_history_row() {
    let directory = tempfile::tempdir().unwrap();
    let mut device = UnlockedDevice::new(directory.path());
    let relay_state = Arc::new(Mutex::new(RelayState::seeded()));
    let base = stub_relay(relay_state.clone()).await;
    let (knowledge, vault) = clients(&base, &device);

    {
        let state = relay_state.lock().unwrap();
        assert_eq!(state.memories[0].content, "relay starts as plaintext");
        assert_eq!(state.skills.len(), 2);
        assert_eq!(state.vault_entries.len(), 3);
    }

    device.set_key(EncryptionMode::Enabling, OLD_KID, [7; 32]);
    knowledge.migrate_encryption().await.unwrap();
    vault.migrate_encryption().await.unwrap();
    assert_all_encrypted_with(&relay_state.lock().unwrap(), OLD_KID);
    knowledge.verify_encryption_migration().await.unwrap();
    vault.verify_encryption_migration().await.unwrap();

    let upload = Memory {
        id: "mem-upload".into(),
        scope: Scope::Project,
        project: "github.com/agora/atem".into(),
        content: "new encrypted upload".into(),
        content_hash: content_hash("new encrypted upload"),
        confidence: "high".into(),
        source_agent: "test".into(),
        source_machine: "mac".into(),
        created_at: 7,
        ..Memory::default()
    };
    let operation = PendingOp::AddMemory {
        memory: upload.clone(),
    };
    let results = knowledge.push(&[&operation], true).await.unwrap();
    assert_eq!(results.len(), 1);
    assert_all_encrypted_with(&relay_state.lock().unwrap(), OLD_KID);

    let memories = knowledge.pull_memories(0).await.unwrap();
    assert!(memories.iter().any(|memory| {
        memory.id == upload.id
            && memory.project == upload.project
            && memory.content == upload.content
            && memory.content_hash == upload.content_hash
    }));
    let skills = knowledge.pull_skills(0).await.unwrap();
    assert_eq!(skills.len(), 2);
    assert_eq!(skills[0].files["SKILL.md"], b"# deploy v1");
    assert_eq!(skills[1].files["SKILL.md"], b"# deploy v2");
    assert_eq!(vault.list().await.unwrap()[0].summary, "production access");
    let entries = vault.read("v-test", None, true).await.unwrap();
    assert_eq!(
        entries
            .iter()
            .map(|entry| entry.content.as_str())
            .collect::<Vec<_>>(),
        vec!["first secret", "rotated secret", "recovery note"]
    );

    device.set_key(EncryptionMode::Enabling, NEW_KID, [8; 32]);
    assert!(knowledge.verify_encryption_migration().await.is_err());
    assert!(vault.verify_encryption_migration().await.is_err());
    assert_eq!(
        knowledge.pull_memories(0).await.unwrap()[0].content,
        "relay starts as plaintext"
    );
    knowledge.migrate_encryption().await.unwrap();
    vault.migrate_encryption().await.unwrap();
    assert_all_encrypted_with(&relay_state.lock().unwrap(), NEW_KID);
    knowledge.verify_encryption_migration().await.unwrap();
    vault.verify_encryption_migration().await.unwrap();

    device.state(EncryptionMode::On, Some(NEW_KID));
    assert!(
        knowledge
            .pull_memories(0)
            .await
            .unwrap()
            .iter()
            .any(|memory| memory.content == "new encrypted upload")
    );
    assert_eq!(vault.read("v-test", None, true).await.unwrap().len(), 3);
}

/// The vault client collaboration reads context with (`encryption_on_only`)
/// reads only while the account's signed mode is on: off or migrating it
/// refuses; on, it opens the sealed entries and refuses one the relay sent in
/// the clear.
#[tokio::test]
async fn a_context_vault_client_reads_only_with_encryption_on() {
    use crate::runtime::collab_context::VAULT_NEEDS_E2E;
    let directory = tempfile::tempdir().unwrap();
    let mut device = UnlockedDevice::new(directory.path());
    let relay_state = Arc::new(Mutex::new(RelayState::seeded()));
    let base = stub_relay(relay_state.clone()).await;
    let (_, vault) = clients(&base, &device);
    let context = clients(&base, &device).1.encryption_on_only();
    device.state(EncryptionMode::Off, None);
    assert_eq!(vault.read("v-test", None, true).await.unwrap().len(), 3);
    assert_eq!(context.read("v-test", None, true).await.unwrap_err().to_string(), VAULT_NEEDS_E2E);
    assert_eq!(context.read_back("v-test", 1, 1, 4).await.unwrap_err().to_string(), VAULT_NEEDS_E2E);
    device.set_key(EncryptionMode::Enabling, OLD_KID, [7; 32]);
    vault.migrate_encryption().await.unwrap();
    assert_eq!(context.read("v-test", None, true).await.unwrap_err().to_string(), VAULT_NEEDS_E2E);
    device.state(EncryptionMode::On, Some(OLD_KID));
    let entries = context.read("v-test", None, true).await.unwrap();
    assert_eq!(
        entries.iter().map(|entry| entry.content.as_str()).collect::<Vec<_>>(),
        vec!["first secret", "rotated secret", "recovery note"]
    );
    assert_eq!(context.read_back("v-test", 1, 2, 5).await.unwrap(), "rotated secret");
    relay_state.lock().unwrap().vault_entries[1]["content"] = json!("written by the relay");
    let error = context.read("v-test", None, true).await.unwrap_err();
    assert!(format!("{error:#}").contains("plain-text vault entry"), "{error:#}");
}

#[tokio::test]
async fn repeated_signed_pending_states_resume_interrupted_migrations_with_a_loaded_key() {
    use crate::memory::cred_agent::CredAgentApi;
    use crate::memory::trust::TrustStore;
    use crate::memory::verification::{Applied, apply_account_state};

    let directory = tempfile::tempdir().unwrap();
    let mut device = UnlockedDevice::new(directory.path());
    device.set_key(EncryptionMode::Enabling, OLD_KID, [7; 32]);
    let state = Arc::new(Mutex::new(RelayState::seeded()));
    let base = stub_relay(state.clone()).await;

    for (mode, target) in [(EncryptionMode::Enabling, "on"), (EncryptionMode::Disabling, "off")] {
        if mode == EncryptionMode::Disabling {
            device.state(mode, Some(OLD_KID));
        }
        let (knowledge, vault) = clients(&base, &device);
        knowledge.migrate_encryption().await.unwrap();
        assert!(vault.verify_encryption_migration().await.is_err());
        // The command exits after rewriting knowledge, before rewriting vault history.
        drop((knowledge, vault));

        let trust = TrustStore::load_from(&device.paths.trust).unwrap();
        let entry = trust.verified(ASTATION).unwrap();
        let pending = entry.account_state.clone().unwrap();
        let epoch = entry.account_epoch;
        assert!(device.agent.held_kid(ASTATION).unwrap().is_some());
        let Applied::MigrationPending(retry) = apply_account_state(&device.paths, ASTATION, Some(&pending)).unwrap() else {
            panic!("a repeated signed pending state must trigger another migration pass");
        };
        assert_eq!(retry.mode, mode);
        assert_eq!(retry.epoch, epoch);
        assert!(apply_account_state(&device.paths, ASTATION, None).is_ok_and(|applied| matches!(applied, Applied::Ignored(_))));
        let mut tampered = pending.clone();
        tampered.signature = "AA==".into();
        assert!(apply_account_state(&device.paths, ASTATION, Some(&tampered)).is_err());

        let (knowledge, vault) = clients(&base, &device);
        knowledge.migrate_encryption().await.unwrap();
        vault.migrate_encryption().await.unwrap();
        knowledge.verify_encryption_migration().await.unwrap();
        vault.verify_encryption_migration().await.unwrap();
        let first = device.agent.migration_completion(ASTATION, epoch, target, OLD_KID).unwrap();
        let duplicate = device.agent.migration_completion(ASTATION, epoch, target, OLD_KID).unwrap();
        assert_eq!(first.statement, duplicate.statement);
        assert_eq!(first.signature, duplicate.signature);
        assert_eq!(TrustStore::load_from(&device.paths.trust).unwrap().verified(ASTATION).unwrap().account_epoch, epoch);
    }

    device.state(EncryptionMode::Off, None);
    let trust = TrustStore::load_from(&device.paths.trust).unwrap();
    let final_state = trust.verified(ASTATION).unwrap().account_state.as_ref().unwrap();
    assert!(matches!(apply_account_state(&device.paths, ASTATION, Some(final_state)).unwrap(), Applied::Unchanged));
    assert!(device.agent.migration_completion(ASTATION, 2, "on", OLD_KID).is_err());
}

#[tokio::test]
async fn migration_verification_checks_readback_and_every_vault_history_version() {
    let directory = tempfile::tempdir().unwrap();
    let mut device = UnlockedDevice::new(directory.path());
    device.set_key(EncryptionMode::Enabling, OLD_KID, [7; 32]);
    let state = Arc::new(Mutex::new(RelayState::seeded()));
    let base = stub_relay(state.clone()).await;
    let (knowledge, vault) = clients(&base, &device);
    assert!(knowledge.verify_encryption_migration().await.is_err());
    assert!(vault.verify_encryption_migration().await.is_err());
    knowledge.migrate_encryption().await.unwrap();
    vault.migrate_encryption().await.unwrap();
    let migrated = state.lock().unwrap().clone();
    state.lock().unwrap().memories[0].content = format!("e1.{OLD_KID}.AA==");
    assert!(knowledge.verify_encryption_migration().await.is_err());
    *state.lock().unwrap() = migrated.clone();
    state.lock().unwrap().vault_entries[0]["content"] = json!("unmigrated historical version");
    assert!(vault.verify_encryption_migration().await.is_err());
    *state.lock().unwrap() = migrated;
    device.state(EncryptionMode::Disabling, Some(OLD_KID));
    assert!(knowledge.verify_encryption_migration().await.is_err());
    assert!(vault.verify_encryption_migration().await.is_err());
    knowledge.migrate_encryption().await.unwrap();
    vault.migrate_encryption().await.unwrap();
    knowledge.verify_encryption_migration().await.unwrap();
    vault.verify_encryption_migration().await.unwrap();
}

#[tokio::test]
async fn missing_encryption_key_keeps_sync_operations_queued() {
    let directory = tempfile::tempdir().unwrap();
    let mut device = UnlockedDevice::new(directory.path());
    // On, but no grant yet: the agent holds no K.
    device.state(EncryptionMode::On, Some(OLD_KID));
    let relay_state = Arc::new(Mutex::new(RelayState::seeded()));
    let base = stub_relay(relay_state).await;
    let (knowledge, _) = clients(&base, &device);
    let store = Store::open_in_memory().unwrap();
    let memory = Memory {
        id: "mem-queued".into(),
        scope: Scope::Global,
        content: "must remain queued".into(),
        content_hash: content_hash("must remain queued"),
        confidence: "high".into(),
        source_agent: "test".into(),
        source_machine: "mac".into(),
        created_at: 1,
        ..Memory::default()
    };
    store.upsert_memory(&memory).unwrap();
    store.enqueue(&PendingOp::AddMemory { memory }).unwrap();
    let context = Ctx {
        home: directory.path().into(),
        repo: None,
        atem_id: "atem-1".into(),
        allow_tracked: false,
    };
    let options = SyncOptions { harvest: false };

    let outcome = run_sync(&store, Some(&knowledge), &context, &options).await.unwrap();
    assert!(outcome.relay_error);
    assert!(outcome.notes.iter().any(|note| note.contains("requires encryption")), "{:?}", outcome.notes);
    assert_eq!(store.pending_count().unwrap(), 1);

    // A locked agent takes the same path: queued, with the way out.
    device.agent.lock_keys().unwrap();
    let outcome = run_sync(&store, Some(&knowledge), &context, &options).await.unwrap();
    assert!(outcome.relay_error);
    assert!(outcome.notes.iter().any(|note| note.contains("atem cred unlock")), "{:?}", outcome.notes);
    assert_eq!(store.pending_count().unwrap(), 1);
}

#[tokio::test]
async fn relay_injected_plain_text_is_rejected_while_on() {
    let dir = tempfile::tempdir().unwrap();
    let mut device = UnlockedDevice::new(dir.path());
    device.set_key(EncryptionMode::On, OLD_KID, [7; 32]);
    let state = Arc::new(Mutex::new(RelayState::seeded()));
    let base = stub_relay(state.clone()).await;
    let (knowledge, vault) = clients(&base, &device);

    let error = knowledge.pull_memories(0).await.unwrap_err().to_string();
    assert!(error.contains("plain-text"), "{error}");

    let vault_error = vault.list().await.unwrap_err().to_string();
    assert!(vault_error.contains("plain-text"), "{vault_error}");
}

const ATEM_PROJECT: &str = "github.com/agora/atem";
const ELSEWHERE: &str = "github.com/agora/elsewhere";

fn fact(id: &str, scope: Scope, project: &str, content: &str, seq: i64) -> Memory {
    Memory {
        id: id.into(),
        scope,
        project: project.into(),
        content: content.into(),
        content_hash: content_hash(content),
        confidence: "high".into(),
        source_agent: "test".into(),
        source_machine: "other-mac".into(),
        created_at: seq,
        seq,
        ..Memory::default()
    }
}

fn skill_row(name: &str, scope: Scope, project: &str, body: &str, seq: i64) -> Skill {
    let files = BTreeMap::from([("SKILL.md".to_string(), body.as_bytes().to_vec())]);
    Skill {
        scope,
        project: project.into(),
        name: name.into(),
        version: 1,
        content_hash: skill_hash(&files),
        files,
        source_agent: "test".into(),
        source_machine: "other-mac".into(),
        created_at: seq,
        deleted: false,
        seq,
    }
}

/// Two devices of one account (encryption on, the same `K`) and a relay
/// holding what `other` sealed: a global fact, a fact for ATEM_PROJECT, one
/// for ELSEWHERE, a global skill, a skill for ELSEWHERE, then a global fact
/// and a global skill that carry ELSEWHERE as their project (only the
/// unresolved filter keeps those out of the global targets). This device
/// used ATEM_PROJECT only, so it can't name ELSEWHERE's hash. Claude and
/// Codex are both installed.
struct Elsewhere {
    dir: tempfile::TempDir,
    device: UnlockedDevice,
    other: UnlockedDevice,
    relay: Arc<Mutex<RelayState>>,
    base: String,
    knowledge: KnowledgeClient,
    store: Store,
}

impl Elsewhere {
    async fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let base_dir = dir.path().canonicalize().unwrap();
        let mut other = UnlockedDevice::new(&base_dir.join("other"));
        other.set_key(EncryptionMode::On, OLD_KID, [7; 32]);
        let mut device = UnlockedDevice::new(&base_dir.join("this"));
        device.set_key(EncryptionMode::On, OLD_KID, [7; 32]);
        EncryptionContext::for_astation_with(ASTATION, &device.paths, device.agent.clone())
            .unwrap()
            .wire_project(ATEM_PROJECT)
            .unwrap();
        let sealer = EncryptionContext::for_astation_with(ASTATION, &other.paths, other.agent.clone()).unwrap();
        let memories = sealer
            .encrypt_memories(vec![
                fact("mem-global", Scope::Global, "", "run the tests before committing", 1),
                fact("mem-atem", Scope::Project, ATEM_PROJECT, "atem listens on port 27183", 2),
                fact("mem-elsewhere", Scope::Project, ELSEWHERE, "elsewhere deploys on fridays", 3),
                fact("mem-stray", Scope::Global, ELSEWHERE, "a stray global fact", 6),
            ])
            .unwrap();
        let skills = sealer
            .encrypt_skills(vec![
                skill_row("lint", Scope::Global, "", "# lint everything", 4),
                skill_row("ship", Scope::Project, ELSEWHERE, "# ship elsewhere", 5),
                skill_row("stray", Scope::Global, ELSEWHERE, "# a stray global skill", 7),
            ])
            .unwrap();
        let relay = Arc::new(Mutex::new(RelayState {
            memories,
            skills,
            vault_summary: String::new(),
            vault_entries: Vec::new(),
            next_seq: 8,
        }));
        let base = stub_relay(relay.clone()).await;
        let (knowledge, _) = clients(&base, &device);
        std::fs::create_dir_all(base_dir.join("home/.claude")).unwrap();
        std::fs::create_dir_all(base_dir.join("home/.codex")).unwrap();
        Self { dir, device, other, relay, base, knowledge, store: Store::open_in_memory().unwrap() }
    }

    fn path(&self, rel: &str) -> std::path::PathBuf {
        self.dir.path().canonicalize().unwrap().join(rel)
    }

    /// A git checkout of `project` (created the first time).
    fn checkout(&self, project: &str) -> crate::memory::project::RepoInfo {
        let root = self.path(project.rsplit('/').next().unwrap());
        if !root.exists() {
            std::fs::create_dir_all(&root).unwrap();
            let init = std::process::Command::new("git").arg("-C").arg(&root).args(["init", "-q"]).status();
            assert!(init.unwrap().success());
        }
        crate::memory::project::RepoInfo { root, key: project.into(), label: project.into() }
    }

    /// One `atem sync`, from `repo` (or outside any checkout).
    async fn sync(&self, repo: Option<crate::memory::project::RepoInfo>) -> crate::memory::sync::SyncOutcome {
        let ctx = Ctx { home: self.path("home"), repo, atem_id: "this-mac".into(), allow_tracked: false };
        run_sync(&self.store, Some(&self.knowledge), &ctx, &SyncOptions { harvest: false }).await.unwrap()
    }

    /// One `atem sync` from `project`'s checkout.
    async fn sync_in(&self, project: &str) -> crate::memory::sync::SyncOutcome {
        self.sync(Some(self.checkout(project))).await
    }

    fn read(&self, path: std::path::PathBuf) -> String {
        std::fs::read_to_string(path).unwrap_or_default()
    }

    /// Every managed block Claude and Codex read in `project`'s checkout,
    /// global ones included, joined.
    fn applied(&self, project: &str) -> String {
        let root = self.checkout(project).root;
        [self.path("home/.claude/CLAUDE.md"), self.path("home/.codex/AGENTS.md"), root.join("CLAUDE.local.md"), root.join("AGENTS.md")]
            .into_iter()
            .map(|file| self.read(file))
            .collect()
    }

    /// The skill directories Claude and Codex have in `project`'s checkout,
    /// global ones included.
    fn installed(&self, project: &str) -> Vec<String> {
        let root = self.checkout(project).root;
        let mut names = Vec::new();
        for dir in [self.path("home/.claude/skills"), self.path("home/.agents/skills"), root.join(".claude/skills"), root.join(".agents/skills")] {
            if let Ok(entries) = std::fs::read_dir(dir) {
                names.extend(entries.flatten().map(|entry| entry.file_name().to_string_lossy().into_owned()));
            }
        }
        names.sort();
        names
    }

    fn project_file(&self, project: &str) -> String {
        self.read(self.checkout(project).root.join("CLAUDE.local.md"))
    }

    fn context(&self, device: &UnlockedDevice) -> EncryptionContext {
        EncryptionContext::for_astation_with(ASTATION, &device.paths, device.agent.clone()).unwrap()
    }

    /// `other` seals and publishes one more row.
    fn publish(&self, memory: Memory) {
        let mut sealed = self.context(&self.other).encrypt_memories(vec![memory]).unwrap().remove(0);
        let mut relay = self.relay.lock().unwrap();
        sealed.seq = relay.next_seq;
        relay.next_seq += 1;
        relay.memories.push(sealed);
    }

    /// A key rotation: both devices get `K` = [8; 32] (NEW_KID), `other`
    /// migrates every relay row to it (each takes a fresh seq), then the
    /// account is on with it.
    async fn rotate(&mut self) {
        self.other.set_key(EncryptionMode::Enabling, NEW_KID, [8; 32]);
        self.device.set_key(EncryptionMode::Enabling, NEW_KID, [8; 32]);
        let (theirs, _) = clients(&self.base, &self.other);
        theirs.migrate_encryption().await.unwrap();
        theirs.verify_encryption_migration().await.unwrap();
        self.other.state(EncryptionMode::On, Some(NEW_KID));
        self.device.state(EncryptionMode::On, Some(NEW_KID));
    }

    /// Encryption turned off: `other` migrates every relay row to plain text
    /// (each takes a fresh seq), then the account is off.
    async fn turn_off(&mut self) {
        self.other.state(EncryptionMode::Disabling, Some(OLD_KID));
        self.device.state(EncryptionMode::Disabling, Some(OLD_KID));
        let (theirs, _) = clients(&self.base, &self.other);
        theirs.migrate_encryption().await.unwrap();
        theirs.verify_encryption_migration().await.unwrap();
        self.other.state(EncryptionMode::Off, None);
        self.device.state(EncryptionMode::Off, None);
    }

    fn skills_named(&self, name: &str) -> Vec<Skill> {
        self.store.all_skills().unwrap().into_iter().filter(|skill| skill.name == name).collect()
    }
}

/// A fact for a project this device can't name doesn't stop the pull: the
/// rest of the page applies, the fact is kept under its hash and never
/// applied (not even the stray global rows), both cursors move, and later
/// syncs go on.
#[tokio::test]
async fn a_fact_for_a_project_this_device_cannot_name_is_kept_and_the_pull_goes_on() {
    use crate::memory::store::{memory_cursor_key, skill_cursor_key};
    let world = Elsewhere::new().await;
    let outcome = world.sync_in(ATEM_PROJECT).await;
    assert!(!outcome.relay_error && !outcome.offline, "{:?}", outcome.notes);
    assert_eq!(outcome.pulled, 7, "four facts and three skills");
    let hash = world.relay.lock().unwrap().memories[2].project.clone();
    let kept = world.store.get_memory("mem-elsewhere").unwrap().expect("the fact is kept");
    assert_eq!(kept.project, hash, "under the relay's hash: unresolved");
    assert!(kept.has_unresolved_project());
    assert_eq!(kept.content, "elsewhere deploys on fridays");
    assert_eq!(world.store.get_memory("mem-atem").unwrap().unwrap().project, ATEM_PROJECT);
    assert_eq!(world.store.get_state(&memory_cursor_key(ASTATION)).unwrap(), 6);
    assert_eq!(world.store.get_state(&skill_cursor_key(ASTATION)).unwrap(), 7, "skills are pulled after memories");
    let applied = world.applied(ATEM_PROJECT);
    assert!(applied.contains("run the tests before committing"), "{applied}");
    assert!(applied.contains("atem listens on port 27183"), "{applied}");
    assert!(!applied.contains("fridays") && !applied.contains("stray"), "an unresolved fact is never applied: {applied}");
    let installed = world.installed(ATEM_PROJECT);
    assert_eq!(installed, ["lint", "lint"], "Claude's and Codex's global skill, nothing unresolved");

    // The next sync doesn't stop on that page: a later fact arrives.
    world.publish(fact("mem-later", Scope::Global, "", "a later fact", 0));
    let again = world.sync_in(ATEM_PROJECT).await;
    assert!(!again.relay_error, "{:?}", again.notes);
    assert_eq!(world.store.get_state(&memory_cursor_key(ASTATION)).unwrap(), 8);
    assert!(world.applied(ATEM_PROJECT).contains("a later fact"));
    assert!(world.store.get_memory("mem-elsewhere").unwrap().unwrap().has_unresolved_project());
}

/// Once this device records the project's name (as a push or a skill
/// history there would), the fact resolves and is applied for that project
/// only.
#[tokio::test]
async fn an_unresolved_fact_resolves_once_this_device_records_its_project() {
    let world = Elsewhere::new().await;
    world.sync_in(ATEM_PROJECT).await;
    assert!(world.store.get_memory("mem-elsewhere").unwrap().expect("kept").has_unresolved_project());
    world.context(&world.device).wire_project(ELSEWHERE).unwrap();
    let outcome = world.sync_in(ATEM_PROJECT).await;
    assert!(!outcome.relay_error, "{:?}", outcome.notes);
    assert_eq!(world.store.get_memory("mem-elsewhere").unwrap().unwrap().project, ELSEWHERE);
    assert!(!world.project_file(ATEM_PROJECT).contains("fridays"), "only for its own project");
    world.sync_in(ELSEWHERE).await;
    assert!(world.project_file(ELSEWHERE).contains("elsewhere deploys on fridays"));
}

/// A skill for a project this device can't name is kept the same way:
/// never installed, the skills cursor moves on. A sync from that project's
/// checkout names the project: the skill is installed there, and the fact
/// applied.
#[tokio::test]
async fn a_skill_for_a_project_this_device_cannot_name_is_kept_until_it_is_named() {
    use crate::memory::store::skill_cursor_key;
    let world = Elsewhere::new().await;
    let outcome = world.sync_in(ATEM_PROJECT).await;
    assert!(!outcome.relay_error, "{:?}", outcome.notes);
    let hash = world.relay.lock().unwrap().skills[1].project.clone();
    let kept = world.store.get_skill(Scope::Project, &hash, "ship").unwrap().expect("the skill is kept under its hash");
    assert_eq!(kept.files["SKILL.md"], b"# ship elsewhere");
    assert!(kept.has_unresolved_project());
    assert_eq!(world.store.get_state(&skill_cursor_key(ASTATION)).unwrap(), 7);
    assert_eq!(world.installed(ATEM_PROJECT), ["lint", "lint"], "never installed");

    let outcome = world.sync_in(ELSEWHERE).await;
    assert!(!outcome.relay_error, "{:?}", outcome.notes);
    assert!(world.store.get_skill(Scope::Project, &hash, "ship").unwrap().is_none());
    assert_eq!(world.store.get_skill(Scope::Project, ELSEWHERE, "ship").unwrap().unwrap().version, 1);
    assert_eq!(world.read(world.checkout(ELSEWHERE).root.join(".claude/skills/ship/SKILL.md")), "# ship elsewhere");
    assert_eq!(world.read(world.checkout(ELSEWHERE).root.join(".agents/skills/ship/SKILL.md")), "# ship elsewhere");
    assert_eq!(world.store.get_memory("mem-elsewhere").unwrap().unwrap().project, ELSEWHERE);
    assert!(world.project_file(ELSEWHERE).contains("elsewhere deploys on fridays"));
    assert!(world.store.unresolved_projects().unwrap().is_empty());
}

/// A purge rewrites a skill's version in place with a new seq. Pulled
/// under its name (the name was recorded first), it wins over the older
/// unresolved copy: the skill stays purged and is never installed.
#[tokio::test]
async fn a_purge_pulled_under_the_name_wins_over_the_unresolved_copy() {
    let world = Elsewhere::new().await;
    world.sync_in(ATEM_PROJECT).await;
    {
        let mut relay = world.relay.lock().unwrap();
        let seq = relay.next_seq;
        relay.next_seq += 1;
        let row = &mut relay.skills[1];
        row.files.clear();
        row.content_hash.clear();
        row.deleted = true;
        row.seq = seq;
    }
    world.context(&world.device).wire_project(ELSEWHERE).unwrap();
    let outcome = world.sync_in(ELSEWHERE).await;
    assert!(!outcome.relay_error, "{:?}", outcome.notes);
    let stored = world.skills_named("ship");
    assert_eq!(stored.len(), 1, "{stored:?}");
    assert!(stored[0].deleted && stored[0].files.is_empty() && stored[0].project == ELSEWHERE, "{stored:?}");
    assert!(!world.installed(ELSEWHERE).contains(&"ship".to_string()));
}

/// After a key rotation the relay delivers every row again under the new
/// key. Skills still stored under the old key's hash, which this device can
/// never name, are dropped; projects it already knew are hashed under the
/// new key, so their facts resolve without a sync in their checkout.
#[tokio::test]
async fn after_a_rotation_old_key_rows_go_and_known_projects_resolve() {
    let mut world = Elsewhere::new().await;
    world.sync_in(ATEM_PROJECT).await;
    let old_hash = world.relay.lock().unwrap().skills[1].project.clone();
    assert!(world.store.unresolved_projects().unwrap().contains(&old_hash));
    world.rotate().await;
    let new_hash = world.relay.lock().unwrap().skills[1].project.clone();
    assert!(new_hash.starts_with(&format!("h1.{NEW_KID}.")) && new_hash != old_hash);

    let outcome = world.sync(None).await;
    assert!(!outcome.relay_error, "{:?}", outcome.notes);
    assert_eq!(world.store.unresolved_projects().unwrap(), std::slice::from_ref(&new_hash), "nothing under the old key is left");
    assert_eq!(world.skills_named("ship").len(), 1);
    assert_eq!(world.store.get_memory("mem-elsewhere").unwrap().unwrap().project, new_hash);
    assert_eq!(world.store.get_memory("mem-atem").unwrap().unwrap().project, ATEM_PROJECT, "a known project is hashed again");

    world.sync_in(ELSEWHERE).await;
    assert!(world.store.unresolved_projects().unwrap().is_empty());
    assert_eq!(world.read(world.checkout(ELSEWHERE).root.join(".claude/skills/ship/SKILL.md")), "# ship elsewhere");
    assert!(world.project_file(ELSEWHERE).contains("elsewhere deploys on fridays"));
}

/// Turning encryption off delivers every row again in plain text. Skills
/// stored under a hash this device couldn't name are dropped: an off
/// device never names a hash.
#[tokio::test]
async fn turning_encryption_off_drops_skill_rows_under_an_unnamed_hash() {
    let mut world = Elsewhere::new().await;
    world.sync_in(ATEM_PROJECT).await;
    world.turn_off().await;
    let outcome = world.sync_in(ATEM_PROJECT).await;
    assert!(!outcome.relay_error, "{:?}", outcome.notes);
    assert!(world.store.unresolved_projects().unwrap().is_empty());
    let ship = world.skills_named("ship");
    assert_eq!((ship.len(), ship[0].project.as_str()), (1, ELSEWHERE));
    assert_eq!(world.store.get_memory("mem-elsewhere").unwrap().unwrap().project, ELSEWHERE);
    assert!(!world.installed(ATEM_PROJECT).contains(&"ship".to_string()));
    assert!(!world.applied(ATEM_PROJECT).contains("fridays"));
}

/// Replacing an unresolved fact pushes its successor with the project hash
/// it came with, never hashed again: the device that knows the project
/// reads it under its name.
#[tokio::test]
async fn a_push_after_pulling_an_unresolved_fact_keeps_its_project_hash() {
    let world = Elsewhere::new().await;
    world.sync_in(ATEM_PROJECT).await;
    let old = world.store.get_memory("mem-elsewhere").unwrap().expect("kept");
    let hash = old.project.clone();
    let new_id = crate::memory::sync::replace_memory(&world.store, &old, "elsewhere deploys on mondays", None, "cli", "this-mac").unwrap();
    let outcome = world.sync_in(ATEM_PROJECT).await;
    assert!(!outcome.relay_error, "{:?}", outcome.notes);
    assert_eq!(outcome.pushed, 2, "the successor and the invalidation");
    {
        let relay = world.relay.lock().unwrap();
        let added = relay.memories.iter().find(|row| row.id == new_id).unwrap();
        assert_eq!(added.project, hash, "the hash goes back as it came");
        let replaced = relay.memories.iter().find(|row| row.id == "mem-elsewhere").unwrap();
        assert_eq!(replaced.project, hash);
        assert_eq!(replaced.superseded_by.as_deref(), Some(new_id.as_str()));
    }
    let (theirs, _) = clients(&world.base, &world.other);
    let pulled = theirs.pull_memories(0).await.unwrap();
    let new = pulled.iter().find(|row| row.id == new_id).unwrap();
    assert_eq!((new.project.as_str(), new.content.as_str()), (ELSEWHERE, "elsewhere deploys on mondays"));
    assert!(world.store.get_memory(&new_id).unwrap().unwrap().has_unresolved_project(), "still unresolved here");
    assert!(!world.applied(ATEM_PROJECT).contains("mondays"));
}

/// A replacement queued while its fact was unresolved goes out under the
/// name this device learned since: here plain, after encryption was turned
/// off, never as a hash nobody off can name.
#[tokio::test]
async fn a_replacement_queued_while_unresolved_goes_out_under_the_name_learned_since() {
    let mut world = Elsewhere::new().await;
    world.sync_in(ATEM_PROJECT).await;
    let old = world.store.get_memory("mem-elsewhere").unwrap().expect("kept");
    let new_id = crate::memory::sync::replace_memory(&world.store, &old, "elsewhere deploys on mondays", None, "cli", "this-mac").unwrap();
    world.context(&world.device).wire_project(ELSEWHERE).unwrap();
    world.turn_off().await;
    let outcome = world.sync_in(ATEM_PROJECT).await;
    assert!(!outcome.relay_error, "{:?}", outcome.notes);
    let added = world.relay.lock().unwrap().memories.iter().find(|row| row.id == new_id).cloned().unwrap();
    assert_eq!((added.project.as_str(), added.content.as_str()), (ELSEWHERE, "elsewhere deploys on mondays"));
    assert_eq!(world.store.get_memory(&new_id).unwrap().unwrap().project, ELSEWHERE);
}

/// Counts the `Crypt` requests that reach the agent.
struct CountingAgent {
    inner: Arc<Mutex<CredAgent>>,
    crypts: AtomicUsize,
}

impl CredAgentApi for CountingAgent {
    fn call(&self, request: Request) -> anyhow::Result<Reply> {
        if matches!(request, Request::Crypt { .. }) {
            self.crypts.fetch_add(1, Ordering::SeqCst);
        }
        self.inner.call(request)
    }
}

fn numbered(n: usize) -> Memory {
    let content = format!("fact number {n}");
    Memory {
        id: format!("mem-{n}"),
        scope: Scope::Project,
        project: "github.com/agora/atem".into(),
        content_hash: content_hash(&content),
        content,
        confidence: "high".into(),
        source_agent: "test".into(),
        source_machine: "mac".into(),
        created_at: 1,
        seq: n as i64 + 1,
        ..Memory::default()
    }
}

#[tokio::test]
async fn a_full_pull_and_push_are_one_agent_round_trip_each() {
    let directory = tempfile::tempdir().unwrap();
    let mut device = UnlockedDevice::new(directory.path());
    device.set_key(EncryptionMode::On, OLD_KID, [7; 32]);
    let counting = Arc::new(CountingAgent { inner: device.agent.clone(), crypts: AtomicUsize::new(0) });
    let context = EncryptionContext::for_astation_with(ASTATION, &device.paths, counting.clone()).unwrap();
    let plain: Vec<Memory> = (0..200).map(numbered).collect();
    let sealed = context.encrypt_memories(plain.clone()).unwrap();
    assert_eq!(counting.crypts.load(Ordering::SeqCst), 1, "200 memories encrypt in one request");

    let mut relay = RelayState::seeded();
    relay.memories = sealed;
    let base = stub_relay(Arc::new(Mutex::new(relay))).await;
    let knowledge = KnowledgeClient::new(base, "atem-1".into(), "session-1".into(), ASTATION.into())
        .with_encryption(device.paths.clone(), counting.clone());
    counting.crypts.store(0, Ordering::SeqCst);
    let pulled = knowledge.pull_memories(0).await.unwrap();
    assert_eq!(
        pulled.iter().map(|memory| memory.content.as_str()).collect::<Vec<_>>(),
        plain.iter().map(|memory| memory.content.as_str()).collect::<Vec<_>>()
    );
    assert!(pulled.iter().all(|memory| memory.project == "github.com/agora/atem"));
    assert_eq!(counting.crypts.load(Ordering::SeqCst), 1, "a 200-memory page opens in one request");

    counting.crypts.store(0, Ordering::SeqCst);
    let ops: Vec<PendingOp> = plain.into_iter().map(|memory| PendingOp::AddMemory { memory }).collect();
    let refs: Vec<&PendingOp> = ops.iter().collect();
    assert_eq!(knowledge.push(&refs, true).await.unwrap().len(), 200);
    assert_eq!(counting.crypts.load(Ordering::SeqCst), 1, "a 200-op push seals in one request");
}

#[test]
fn a_copied_config_directory_yields_no_k() {
    let directory = tempfile::tempdir().unwrap();
    let mut device = UnlockedDevice::new(directory.path());
    device.set_key(EncryptionMode::On, OLD_KID, [42; 32]);
    EncryptionContext::for_astation_with(ASTATION, &device.paths, device.agent.clone())
        .unwrap()
        .wire_project("github.com/agora/atem")
        .unwrap();
    let copy = tempfile::tempdir().unwrap();
    let paths = CredPaths::in_dir(copy.path());
    crate::paths::create_private_dir(&paths.dir).unwrap();
    for entry in std::fs::read_dir(&device.paths.dir).unwrap() {
        let entry = entry.unwrap();
        if entry.file_type().unwrap().is_file() {
            std::fs::copy(entry.path(), paths.dir.join(entry.file_name())).unwrap();
        }
    }
    assert!(paths.device_keys_sealed.exists() && paths.project_names.exists() && paths.trust.exists());
    assert!(!paths.device_keys.exists());
    // No file holds K in any encoding.
    let k = [42u8; 32];
    let encoded = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, k);
    let hex: String = k.iter().map(|byte| format!("{byte:02x}")).collect();
    for entry in std::fs::read_dir(&paths.dir).unwrap() {
        let bytes = std::fs::read(entry.unwrap().path()).unwrap();
        let text = String::from_utf8_lossy(&bytes);
        assert!(!bytes.windows(32).any(|window| window == k));
        assert!(!text.contains(&encoded) && !text.contains(&hex));
    }
    // An agent over the copy starts locked: nothing can be sealed or opened.
    let agent = Arc::new(test_agent(&paths));
    assert!(!agent.status().unwrap().unlocked);
    let context = EncryptionContext::for_astation_with(ASTATION, &paths, agent.clone()).unwrap();
    assert_eq!(context.mode, EncryptionMode::On);
    assert!(format!("{:#}", context.seal("mem", "content", b"x").unwrap_err()).contains("atem cred unlock"));
    assert!(error_of(agent.crypt(ASTATION, vec![CryptOp::keyed_hash(b"x")])).contains("atem cred unlock"));
}

#[test]
fn big_batches_split_and_keep_their_order() {
    let directory = tempfile::tempdir().unwrap();
    let mut device = UnlockedDevice::new(directory.path());
    device.set_key(EncryptionMode::On, OLD_KID, [7; 32]);
    let counting = Arc::new(CountingAgent { inner: device.agent.clone(), crypts: AtomicUsize::new(0) });
    let context = EncryptionContext::for_astation_with(ASTATION, &device.paths, counting.clone()).unwrap();
    // Over the operation budget: 1500 fields go in two requests.
    let plain: Vec<Vec<u8>> = (0..1500).map(|n| format!("field {n}").into_bytes()).collect();
    let items: Vec<(&str, &str, &[u8])> = plain.iter().map(|bytes| ("v", "content", bytes.as_slice())).collect();
    let sealed = context.seal_many(&items).unwrap();
    assert_eq!(counting.crypts.load(Ordering::SeqCst), 2);
    // Over the byte budget: three fields of 900 KiB go one per request.
    counting.crypts.store(0, Ordering::SeqCst);
    let big: Vec<Vec<u8>> = (0..3u8).map(|n| vec![n; 900 << 10]).collect();
    let items: Vec<(&str, &str, &[u8])> = big.iter().map(|bytes| ("v", "content", bytes.as_slice())).collect();
    let sealed_big = context.seal_many(&items).unwrap();
    assert_eq!(counting.crypts.load(Ordering::SeqCst), 3);
    let opened = context.open_many(&sealed.iter().map(|value| ("v", "content", value.as_str())).collect::<Vec<_>>()).unwrap();
    assert_eq!(opened, plain);
    let opened = context.open_many(&sealed_big.iter().map(|value| ("v", "content", value.as_str())).collect::<Vec<_>>()).unwrap();
    assert_eq!(opened, big);
}

#[test]
fn a_field_too_big_for_one_agent_request_fails_before_any_request() {
    let directory = tempfile::tempdir().unwrap();
    let mut device = UnlockedDevice::new(directory.path());
    device.set_key(EncryptionMode::On, OLD_KID, [7; 32]);
    let counting = Arc::new(CountingAgent { inner: device.agent.clone(), crypts: AtomicUsize::new(0) });
    let context = EncryptionContext::for_astation_with(ASTATION, &device.paths, counting.clone()).unwrap();
    let huge = vec![1u8; 5 << 20];
    let small = b"small".to_vec();
    let Err(error) = context.seal_many(&[("v", "content", small.as_slice()), ("v", "content", huge.as_slice())]) else {
        panic!("a 5 MiB field must be refused");
    };
    let error = format!("{error:#}");
    assert!(error.contains(&format!("a field is too large to encrypt ({} bytes)", huge.len())), "{error}");
    assert_eq!(counting.crypts.load(Ordering::SeqCst), 0, "nothing is sent");
    // The largest skill still fits in one request.
    let skill = vec![2u8; crate::memory::skills_fs::MAX_SKILL_BYTES];
    assert_eq!(context.seal_many(&[("v", "content", skill.as_slice())]).unwrap().len(), 1);
}

#[tokio::test]
async fn a_pushed_memory_reads_back_by_its_seq() {
    use crate::memory::sync::push_memory_and_read_back;
    let directory = tempfile::tempdir().unwrap();
    let mut device = UnlockedDevice::new(directory.path());
    device.state(EncryptionMode::Off, None);
    let relay = Arc::new(Mutex::new(RelayState::seeded()));
    let base = stub_relay(relay.clone()).await;
    for encrypted in [false, true] {
        if encrypted {
            device.set_key(EncryptionMode::Enabling, OLD_KID, [7; 32]);
            clients(&base, &device).0.migrate_encryption().await.unwrap();
        }
        let (client, _) = clients(&base, &device);
        let memory = Memory { id: format!("mem_{}", if encrypted { "12345678" } else { "f00dbabe" }),
            content: format!("Exact  bytes with a newline\n{encrypted}"), scope: Scope::Global,
            content_hash: content_hash(&format!("Exact  bytes with a newline\n{encrypted}")), ..Default::default() };
        let snapshot = push_memory_and_read_back(&client, &memory).await.unwrap();
        assert_eq!(snapshot.text, memory.content);
        assert_eq!(snapshot.digest, atem_client::session::host_work::digest(memory.content.as_bytes()));
        let mut alias = memory.clone();
        alias.id.push_str("abcd");
        let canonical = push_memory_and_read_back(&client, &alias).await.unwrap();
        assert_eq!(canonical.id, memory.id);
        assert_eq!(canonical.version, snapshot.version);
    }
}
