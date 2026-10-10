use crate::memory::adapters::Ctx;
use crate::memory::api::KnowledgeClient;
use crate::memory::account_keys::CryptOp;
use crate::memory::crypto::{EncryptionContext, EncryptionMode};
use crate::memory::fake_astation::UnlockedDevice;
use crate::memory::key_agent::{KeyAgent, KeyAgentApi, Reply, Request, error_of, test_agent};
use crate::memory::verification::KeyPaths;
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
struct RelayState {
    memories: Vec<Memory>,
    skills: Vec<Skill>,
    vault_summary: String,
    vault_entries: Vec<Value>,
    next_seq: i64,
}

impl RelayState {
    fn seeded() -> Self {
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

fn assert_all_encrypted_with(state: &RelayState, kid: &str) {
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

async fn stub_relay(state: Arc<Mutex<RelayState>>) -> String {
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

fn handle_request(state: &Arc<Mutex<RelayState>>, method: &str, path: &str, body: &Value) -> Value {
    let mut state = state.lock().unwrap();
    if method == "GET" && path.starts_with("/api/memory?") {
        return json!({"memories": state.memories});
    }
    if method == "GET" && path.starts_with("/api/skills?") {
        return json!({"skills": state.skills});
    }
    if method == "POST" && path.starts_with("/api/memory/batch?") {
        let mut results = Vec::new();
        for op in body["ops"].as_array().unwrap() {
            match op["op"].as_str().unwrap() {
                "rewrite" => {
                    let id = op["id"].as_str().unwrap();
                    let memory = state.memories.iter_mut().find(|row| row.id == id).unwrap();
                    memory.project = op["project"].as_str().unwrap().into();
                    memory.content = op["content"].as_str().unwrap().into();
                    memory.content_hash = op["content_hash"].as_str().unwrap().into();
                }
                "add" => {
                    let mut memory: Memory = serde_json::from_value(op["memory"].clone()).unwrap();
                    memory.seq = state.next_seq;
                    state.next_seq += 1;
                    state.memories.push(memory);
                }
                other => panic!("unexpected memory operation {other}"),
            }
            results.push(json!({"ok": true, "seq": state.next_seq}));
        }
        return json!({"results": results});
    }
    if method == "POST" && path.starts_with("/api/skills/batch?") {
        let mut results = Vec::new();
        for op in body["ops"].as_array().unwrap() {
            assert_eq!(op["op"], "rewrite");
            let version = op["version"].as_i64().unwrap();
            let name = op["name"].as_str().unwrap();
            let skill = state
                .skills
                .iter_mut()
                .find(|row| row.name == name && row.version == version)
                .unwrap();
            skill.project = op["project"].as_str().unwrap().into();
            skill.files = serde_json::from_value(op["files"].clone()).unwrap();
            skill.content_hash = op["content_hash"].as_str().unwrap().into();
            results.push(json!({"ok": true, "version": version, "seq": state.next_seq}));
        }
        return json!({"results": results});
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
    assert_eq!(
        knowledge.pull_memories(0).await.unwrap()[0].content,
        "relay starts as plaintext"
    );
    knowledge.migrate_encryption().await.unwrap();
    vault.migrate_encryption().await.unwrap();
    assert_all_encrypted_with(&relay_state.lock().unwrap(), NEW_KID);

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

/// Counts the `Crypt` requests that reach the agent.
struct CountingAgent {
    inner: Arc<Mutex<KeyAgent>>,
    crypts: AtomicUsize,
}

impl KeyAgentApi for CountingAgent {
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
    for entry in std::fs::read_dir(directory.path()).unwrap() {
        let entry = entry.unwrap();
        if entry.file_type().unwrap().is_file() {
            std::fs::copy(entry.path(), copy.path().join(entry.file_name())).unwrap();
        }
    }
    let paths = KeyPaths::in_dir(copy.path());
    assert!(paths.device_keys_sealed.exists() && paths.project_names.exists() && paths.trust.exists());
    assert!(!paths.data_keys.exists() && !paths.device_keys.exists());
    // No file holds K in any encoding.
    let k = [42u8; 32];
    let encoded = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, k);
    let hex: String = k.iter().map(|byte| format!("{byte:02x}")).collect();
    for entry in std::fs::read_dir(copy.path()).unwrap() {
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
    assert!(error.contains("a field is too large to encrypt ("), "{error}");
    assert_eq!(counting.crypts.load(Ordering::SeqCst), 0, "nothing is sent");
    // The largest skill still fits in one request.
    let skill = vec![2u8; crate::memory::skills_fs::MAX_SKILL_BYTES];
    assert_eq!(context.seal_many(&[("v", "content", skill.as_slice())]).unwrap().len(), 1);
}
