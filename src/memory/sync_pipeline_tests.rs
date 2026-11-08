//! Full-size, overlapped batches (designs/e2e-encryption.md "Performance",
//! F2): the `Crypt` requests each phase makes, ops sealed ahead against an
//! earlier chunk's rewrites, the prefetched page against a failure or a
//! crash, a lock while a POST is in flight, and the order of commits.
use super::tests::{
    KeepingRelay, NO_HARVEST, keeping_relay, posted_ops, stub_relay, test_ctx, valid,
};
use super::*;
use crate::memory::account_keys::CryptOp;
use crate::memory::cred_agent::{CredAgent, CredAgentApi, Reply, Request};
use crate::memory::crypto::{
    CRYPT_BATCH_BYTES, CRYPT_BATCH_OPS, EncryptionContext, EncryptionMode,
};
use crate::memory::fake_astation::{ASTATION_ID, UnlockedDevice, unlock_with};
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const KID: &str = "0123abcd";
const PROJECT: &str = "github.com/agora/atem";

type Log = Arc<Mutex<Vec<(String, String, serde_json::Value)>>>;

/// One `Crypt` request as the agent saw it.
#[derive(Debug, Clone, Copy)]
struct Call {
    ops: usize,
    bytes: usize,
    opens: bool,
    ok: bool,
}

type Hook = Box<dyn Fn(usize, &[CryptOp], &Mutex<CredAgent>) + Send + Sync>;

/// The in-process agent, recording every `Crypt` request. `hook` runs
/// before a request reaches the agent, with its index (from 0) and its ops.
struct Recorder {
    inner: Arc<Mutex<CredAgent>>,
    started: AtomicUsize,
    calls: Mutex<Vec<Call>>,
    hook: Hook,
}

impl Recorder {
    fn new(inner: Arc<Mutex<CredAgent>>) -> Arc<Self> {
        Self::with_hook(inner, Box::new(|_, _, _| {}))
    }

    fn with_hook(inner: Arc<Mutex<CredAgent>>, hook: Hook) -> Arc<Self> {
        Arc::new(Self {
            inner,
            started: AtomicUsize::new(0),
            calls: Mutex::new(Vec::new()),
            hook,
        })
    }

    fn calls(&self) -> Vec<Call> {
        self.calls.lock().unwrap().clone()
    }

    /// Requests that seal or hash (a push, a rewrite), and those that open.
    fn seals_and_opens(&self) -> (Vec<Call>, Vec<Call>) {
        self.calls().into_iter().partition(|call| !call.opens)
    }
}

impl CredAgentApi for Recorder {
    fn call(&self, request: Request) -> anyhow::Result<Reply> {
        let Request::Crypt { ops, .. } = &request else {
            return self.inner.call(request);
        };
        let seen = Call {
            ops: ops.len(),
            bytes: ops.iter().map(CryptOp::wire_len).sum(),
            opens: ops.iter().any(|op| matches!(op, CryptOp::Open { .. })),
            ok: false,
        };
        (self.hook)(
            self.started.fetch_add(1, Ordering::SeqCst),
            ops,
            &self.inner,
        );
        let reply = self.inner.call(request);
        self.calls.lock().unwrap().push(Call {
            ok: reply.is_ok(),
            ..seen
        });
        reply
    }
}

/// A verified, unlocked device with `K` in `mode`.
fn device(dir: &Path, mode: EncryptionMode) -> UnlockedDevice {
    let mut device = UnlockedDevice::new(dir);
    device.set_key(mode, KID, [7; 32]);
    device
}

fn client_with(
    base: &str,
    device: &UnlockedDevice,
    agent: Arc<dyn CredAgentApi>,
) -> KnowledgeClient {
    KnowledgeClient::new(
        base.into(),
        "inst".into(),
        "sess".into(),
        ASTATION_ID.into(),
    )
    .with_encryption(device.paths.clone(), agent)
}

/// The device's own context, unrecorded (to seal seed rows, open sent ones).
fn context(device: &UnlockedDevice) -> EncryptionContext {
    EncryptionContext::for_astation_with(ASTATION_ID, &device.paths, device.agent.clone()).unwrap()
}

/// Fact `i`, project-scoped when `project` (3 `Crypt` ops to push, else 2).
fn fact(i: usize, project: bool) -> Memory {
    let mut m = valid(
        &format!("mem_{i:04}"),
        &format!("fact {i}: staging listens on port {}", 8000 + i),
    );
    if project {
        m.scope = Scope::Project;
        m.project = PROJECT.into();
    }
    m
}

fn queue(s: &Store, memories: impl IntoIterator<Item = Memory>) {
    for m in memories {
        s.upsert_memory(&m).unwrap();
        s.enqueue(&PendingOp::AddMemory { memory: m }).unwrap();
    }
}

/// `n` facts from another device, sealed, on the relay as seq 1..=n.
fn seed_sealed(relay: &Mutex<KeepingRelay>, device: &UnlockedDevice, n: usize) {
    let sealed = context(device)
        .encrypt_memories(
            (1..=n)
                .map(|i| {
                    let mut m = fact(i, i % 2 == 0);
                    m.id = format!("mem_r{i:04}");
                    m.content = format!("remote {}", m.content);
                    m.content_hash = content_hash(&m.content);
                    m.source_machine = "m2".into();
                    m
                })
                .collect(),
        )
        .unwrap();
    let mut r = relay.lock().unwrap();
    for m in sealed {
        r.put(m);
    }
}

fn memory_gets(log: &Log) -> Vec<i64> {
    log.lock()
        .unwrap()
        .iter()
        .filter(|(m, p, _)| m == "GET" && p.starts_with("/api/memory?"))
        .map(|(_, p, _)| since(p))
        .collect()
}

fn since(path: &str) -> i64 {
    path.split(['?', '&'])
        .find_map(|kv| kv.strip_prefix("since="))
        .unwrap()
        .parse()
        .unwrap()
}

/// Whether `ops` open a field of record `id`.
fn opens(ops: &[CryptOp], id: &str) -> bool {
    ops.iter()
        .any(|op| matches!(op, CryptOp::Open { record, .. } if record == id))
}

/// Waits up to `limit` for `done`.
fn wait_for(limit: Duration, done: impl Fn() -> bool) -> bool {
    let start = Instant::now();
    while start.elapsed() < limit {
        if done() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    done()
}

// ─────────────── ruling 6: Crypt requests per phase ───────────────

#[tokio::test]
async fn a_push_seals_full_groups_and_a_pull_opens_page_by_page() {
    let dir = tempfile::tempdir().unwrap();
    let device = device(dir.path(), EncryptionMode::On);
    let recorder = Recorder::new(device.agent.clone());
    let relay = Arc::new(Mutex::new(KeepingRelay::default()));
    let (base, log) = stub_relay(keeping_relay(relay.clone())).await;
    let s = Store::open_in_memory().unwrap();
    // Half project-scoped: 2,500 Crypt ops to push.
    queue(&s, (0..1000).map(|i| fact(i, i % 2 == 0)));
    let (_home, ctx) = test_ctx();
    let out = run_sync(
        &s,
        Some(&client_with(&base, &device, recorder.clone())),
        &ctx,
        &NO_HARVEST,
    )
    .await
    .unwrap();
    assert!(
        out.notes.is_empty() && !out.relay_error && !out.offline,
        "{:?}",
        out.notes
    );
    assert_eq!((out.pushed, out.pulled), (1000, 1000));
    // The relay's chunks are unchanged.
    assert_eq!(
        posted_ops(&log).iter().map(Vec::len).collect::<Vec<_>>(),
        vec![50; 20]
    );
    let (seals, opens) = recorder.seals_and_opens();
    // Every op sealed once, in one request per 1,024 ops / 2 MiB.
    assert_eq!(seals.iter().map(|c| c.ops).sum::<usize>(), 2500);
    assert_eq!(
        seals.len(),
        2500usize.div_ceil(CRYPT_BATCH_OPS),
        "{seals:?}"
    );
    assert!(
        seals
            .iter()
            .all(|c| c.ops <= CRYPT_BATCH_OPS && c.bytes <= CRYPT_BATCH_BYTES),
        "{seals:?}"
    );
    // One request per pulled page.
    assert_eq!(
        opens.iter().map(|c| c.ops).collect::<Vec<_>>(),
        vec![200; 5]
    );
    assert_eq!(s.pending_count().unwrap(), 0);
}

#[tokio::test]
async fn a_skill_group_seals_in_two_requests_with_its_deletes_and_purges() {
    let dir = tempfile::tempdir().unwrap();
    let device = device(dir.path(), EncryptionMode::On);
    let recorder = Recorder::new(device.agent.clone());
    let relay = Arc::new(Mutex::new(KeepingRelay::default()));
    let (base, log) = stub_relay(keeping_relay(relay.clone())).await;
    let s = Store::open_in_memory().unwrap();
    for i in 0..10 {
        let mut skill = super::tests::skill_v1(&format!("skill{i}"), &format!("# skill {i}"), "m1");
        skill.files.insert(
            "reference/notes.md".into(),
            format!("notes for skill {i}").into_bytes(),
        );
        skill.scope = Scope::Project;
        skill.project = PROJECT.into();
        skill.content_hash = skill_hash(&skill.files);
        s.put_skill(&skill).unwrap();
        s.enqueue(&PendingOp::PushSkill {
            skill,
            base_version: 0,
        })
        .unwrap();
    }
    s.enqueue(&PendingOp::DeleteSkill {
        scope: Scope::Project,
        project: PROJECT.into(),
        name: "old".into(),
    })
    .unwrap();
    s.enqueue(&PendingOp::PurgeSkill {
        scope: Scope::Project,
        project: "github.com/agora/other".into(),
        name: "gone".into(),
        versions: None,
    })
    .unwrap();
    let (_home, ctx) = test_ctx();
    let out = run_sync(
        &s,
        Some(&client_with(&base, &device, recorder.clone())),
        &ctx,
        &NO_HARVEST,
    )
    .await
    .unwrap();
    assert!(!out.relay_error && !out.offline, "{:?}", out.notes);
    assert_eq!(out.pushed, 12);
    assert_eq!(
        posted_ops(&log).iter().map(Vec::len).collect::<Vec<_>>(),
        vec![8, 4]
    );
    let (seals, opens) = recorder.seals_and_opens();
    // Paths, hashes and the deleted and purged projects' hashes, then the
    // file contents (sealed under their sealed paths): two requests.
    assert_eq!(
        seals.iter().map(|c| c.ops).collect::<Vec<_>>(),
        vec![10 * 2 + 10 * 2 + 2, 10 * 2],
        "{seals:?}"
    );
    assert_eq!(opens.len(), 1);
    let r = relay.lock().unwrap();
    assert!(
        r.skills
            .values()
            .all(|k| k.project.starts_with("h1.") && k.files.keys().all(|p| p.starts_with("e1.")))
    );
}

// ─────────────── ruling 2: rewrites after sealing ───────────────

#[tokio::test]
async fn a_canonical_rewrite_of_an_op_sealed_ahead_is_sent_rewritten() {
    let dir = tempfile::tempdir().unwrap();
    let device = device(dir.path(), EncryptionMode::On);
    let recorder = Recorder::new(device.agent.clone());
    let relay = Arc::new(Mutex::new(KeepingRelay::default()));
    // Another machine added "beta" first: the relay dedups ours onto it.
    relay.lock().unwrap().put(
        context(&device)
            .encrypt_memories(vec![valid("mem_canon", "beta")])
            .unwrap()
            .remove(0),
    );
    let (base, log) = stub_relay(keeping_relay(relay.clone())).await;
    let s = Store::open_in_memory().unwrap();
    // Chunk 1: beta and 49 more. Chunk 2: x replaces beta. Both chunks are
    // one group, sealed before chunk 1 is sent.
    queue(&s, [valid("mem_beta", "beta")]);
    queue(&s, (0..49).map(|i| fact(i, false)));
    queue(&s, [valid("mem_x", "x")]);
    assert!(invalidate_and_queue(&s, "mem_beta", T0, Some("mem_x")).unwrap());
    let (_home, ctx) = test_ctx();
    let out = run_sync(
        &s,
        Some(&client_with(&base, &device, recorder.clone())),
        &ctx,
        &NO_HARVEST,
    )
    .await
    .unwrap();
    assert!(out.notes.is_empty() && !out.relay_error, "{:?}", out.notes);
    let posts = posted_ops(&log);
    assert_eq!(posts.iter().map(Vec::len).collect::<Vec<_>>(), vec![50, 2]);
    // Chunk 1's result renamed beta to the relay's id; chunk 2 says so.
    assert_eq!(posts[1][1]["op"], "invalidate");
    assert_eq!(posts[1][1]["id"], "mem_canon");
    assert_eq!(
        relay.lock().unwrap().rows["mem_canon"]
            .superseded_by
            .as_deref(),
        Some("mem_x")
    );
    let canon = s.get_memory("mem_canon").unwrap().unwrap();
    assert_eq!(
        (canon.invalid_at, canon.superseded_by.as_deref()),
        (Some(T0), Some("mem_x"))
    );
    assert!(s.get_memory("mem_beta").unwrap().is_none());
    // One group: the rewritten invalidation carries no sealed field, so
    // sending it again sealed nothing more.
    let (seals, _) = recorder.seals_and_opens();
    assert_eq!(
        seals.iter().map(|c| c.ops).collect::<Vec<_>>(),
        vec![51 * 2]
    );
}

const T0: i64 = 1_790_000_000;

#[tokio::test]
async fn an_op_changed_or_acked_after_it_was_sealed_is_sealed_again_or_dropped() {
    let td = tempfile::tempdir().unwrap();
    let db = td.path().join("knowledge.db");
    let device = device(td.path(), EncryptionMode::On);
    let recorder = Recorder::new(device.agent.clone());
    let s = Store::open(&db).unwrap();
    queue(&s, (0..60).map(|i| fact(i, false)));
    let queued = s.pending().unwrap();
    let (changed, acked) = (queued[52].0, queued[55].0);
    let relay = Arc::new(Mutex::new(KeepingRelay::default()));
    let keeping = keeping_relay(relay.clone());
    let first = AtomicBool::new(true);
    let other_writer = db.clone();
    // While chunk 1 is in flight (both chunks already sealed), another
    // writer changes one queued op of chunk 2 and acks another.
    let (base, log) = stub_relay(Box::new(move |m, p, body| {
        if m == "POST" && first.swap(false, Ordering::SeqCst) {
            let other = Store::open(&other_writer).unwrap();
            let mut op = fact(52, false);
            op.content = "changed after it was sealed".into();
            op.content_hash = content_hash(&op.content);
            other
                .replace_pending(changed, &PendingOp::AddMemory { memory: op })
                .unwrap();
            other.ack(acked).unwrap();
        }
        keeping(m, p, body)
    }))
    .await;
    let (_home, ctx) = test_ctx();
    let out = run_sync(
        &s,
        Some(&client_with(&base, &device, recorder.clone())),
        &ctx,
        &NO_HARVEST,
    )
    .await
    .unwrap();
    assert!(out.notes.is_empty() && !out.relay_error, "{:?}", out.notes);
    let posts = posted_ops(&log);
    assert_eq!(posts.iter().map(Vec::len).collect::<Vec<_>>(), vec![50, 9]);
    let ids: Vec<&str> = posts[1]
        .iter()
        .map(|o| o["memory"]["id"].as_str().unwrap())
        .collect();
    assert!(!ids.contains(&"mem_0055"), "{ids:?}");
    let sent = posts[1]
        .iter()
        .find(|o| o["memory"]["id"] == "mem_0052")
        .unwrap();
    let opened = context(&device)
        .open(
            "mem_0052",
            "content",
            sent["memory"]["content"].as_str().unwrap(),
        )
        .unwrap();
    assert_eq!(opened, b"changed after it was sealed");
    // One group for both chunks, then the changed op alone.
    let (seals, _) = recorder.seals_and_opens();
    assert_eq!(
        seals.iter().map(|c| c.ops).collect::<Vec<_>>(),
        vec![60 * 2, 2]
    );
    assert_eq!(s.pending_count().unwrap(), 0);
}

/// The account's mode changes while chunk 1 is in flight, after both
/// chunks were sealed (or left plain) under the old one: chunk 2 goes out as
/// the new mode says, as it did when each chunk was sealed just before its
/// POST.
#[tokio::test]
async fn a_mode_change_after_sealing_seals_again_under_the_new_mode() {
    for (from, to) in [
        (EncryptionMode::Off, EncryptionMode::On),
        (EncryptionMode::On, EncryptionMode::Off),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let mut device = device(dir.path(), EncryptionMode::On);
        if from == EncryptionMode::Off {
            device.state(EncryptionMode::Off, None);
        }
        let device = Arc::new(Mutex::new(device));
        let relay = Arc::new(Mutex::new(KeepingRelay::default()));
        let keeping = keeping_relay(relay.clone());
        let (switch, first) = (device.clone(), AtomicBool::new(true));
        let (base, log) = stub_relay(Box::new(move |m, p, body| {
            if m == "POST" && first.swap(false, Ordering::SeqCst) {
                let kid = (to == EncryptionMode::On).then_some(KID);
                switch.lock().unwrap().state(to, kid);
            }
            keeping(m, p, body)
        }))
        .await;
        let s = Store::open_in_memory().unwrap();
        queue(&s, (0..60).map(|i| fact(i, true)));
        let (_home, ctx) = test_ctx();
        let client = {
            let device = device.lock().unwrap();
            client_with(&base, &device, device.agent.clone())
        };
        let out = run_sync(&s, Some(&client), &ctx, &NO_HARVEST)
            .await
            .unwrap();
        assert_eq!(out.pushed, 60, "{from:?} → {to:?}: {:?}", out.notes);
        let posts = posted_ops(&log);
        assert_eq!(posts.iter().map(Vec::len).collect::<Vec<_>>(), vec![50, 10]);
        let sealed =
            |op: &serde_json::Value| op["memory"]["content"].as_str().unwrap().starts_with("e1.");
        assert!(
            posts[0]
                .iter()
                .all(|op| sealed(op) == (from == EncryptionMode::On)),
            "{from:?} → {to:?}"
        );
        assert!(
            posts[1]
                .iter()
                .all(|op| sealed(op) == (to == EncryptionMode::On)),
            "{from:?} → {to:?}"
        );
    }
}

// ─────────────── the overlap itself ───────────────

#[tokio::test]
async fn the_next_group_is_sealed_while_a_chunk_is_posted() {
    let dir = tempfile::tempdir().unwrap();
    let device = device(dir.path(), EncryptionMode::On);
    let in_flight = Arc::new(AtomicBool::new(false));
    let overlapped = Arc::new(AtomicBool::new(false));
    let (flag, seen) = (in_flight.clone(), overlapped.clone());
    // The second request is the next group's: is a POST in flight then?
    let recorder = Recorder::with_hook(
        device.agent.clone(),
        Box::new(move |index, _, _| {
            if index == 1 {
                seen.store(
                    wait_for(Duration::from_secs(2), || flag.load(Ordering::SeqCst)),
                    Ordering::SeqCst,
                );
            }
        }),
    );
    let relay = Arc::new(Mutex::new(KeepingRelay::default()));
    let keeping = keeping_relay(relay.clone());
    let flag = in_flight.clone();
    let (base, _log) = stub_relay(Box::new(move |m, p, body| {
        if m != "POST" {
            return keeping(m, p, body);
        }
        flag.store(true, Ordering::SeqCst);
        std::thread::sleep(Duration::from_millis(100));
        let answer = keeping(m, p, body);
        flag.store(false, Ordering::SeqCst);
        answer
    }))
    .await;
    let s = Store::open_in_memory().unwrap();
    // 1,200 Crypt ops: two groups.
    queue(&s, (0..400).map(|i| fact(i, true)));
    let (_home, ctx) = test_ctx();
    let out = run_sync(
        &s,
        Some(&client_with(&base, &device, recorder.clone())),
        &ctx,
        &NO_HARVEST,
    )
    .await
    .unwrap();
    assert!(out.notes.is_empty() && !out.relay_error, "{:?}", out.notes);
    assert_eq!(out.pushed, 400);
    assert!(
        overlapped.load(Ordering::SeqCst),
        "the next group was sealed between POSTs"
    );
}

#[tokio::test]
async fn a_page_is_opened_while_the_next_one_is_fetched() {
    let dir = tempfile::tempdir().unwrap();
    let device = device(dir.path(), EncryptionMode::On);
    let relay = Arc::new(Mutex::new(KeepingRelay::default()));
    seed_sealed(&relay, &device, 450);
    let (base, log) = stub_relay(keeping_relay(relay.clone())).await;
    let overlapped = Arc::new(AtomicBool::new(false));
    let (seen, gets) = (overlapped.clone(), log.clone());
    // While page 1 is opened: has the relay been asked for page 2?
    let recorder = Recorder::with_hook(
        device.agent.clone(),
        Box::new(move |_, ops, _| {
            if opens(ops, "mem_r0001") {
                seen.store(
                    wait_for(Duration::from_secs(2), || memory_gets(&gets).contains(&200)),
                    Ordering::SeqCst,
                );
            }
        }),
    );
    let s = Store::open_in_memory().unwrap();
    let (_home, ctx) = test_ctx();
    let out = run_sync(
        &s,
        Some(&client_with(&base, &device, recorder.clone())),
        &ctx,
        &NO_HARVEST,
    )
    .await
    .unwrap();
    assert!(out.notes.is_empty() && !out.relay_error, "{:?}", out.notes);
    assert_eq!(out.pulled, 450);
    assert!(
        overlapped.load(Ordering::SeqCst),
        "page 2 was fetched only after page 1 was opened"
    );
    assert_eq!(memory_gets(&log), vec![0, 200, 400]);
}

/// Page 2 is opened while page 1's transaction runs: page 1's last insert
/// waits (bounded) for page 2's open to reach the agent.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_page_is_opened_while_the_one_before_is_applied() {
    use rusqlite::functions::FunctionFlags;
    let dir = tempfile::tempdir().unwrap();
    let device = device(dir.path(), EncryptionMode::On);
    let relay = Arc::new(Mutex::new(KeepingRelay::default()));
    seed_sealed(&relay, &device, 450);
    let (base, _log) = stub_relay(keeping_relay(relay.clone())).await;
    let page_two_opening = Arc::new(AtomicBool::new(false));
    let opening = page_two_opening.clone();
    let recorder = Recorder::with_hook(
        device.agent.clone(),
        Box::new(move |_, ops, _| {
            if opens(ops, "mem_r0201") {
                opening.store(true, Ordering::SeqCst);
            }
        }),
    );
    let s = Store::open_in_memory().unwrap();
    let overlapped = Arc::new(AtomicBool::new(false));
    let (seen, opening) = (overlapped.clone(), page_two_opening.clone());
    s.test_conn()
        .create_scalar_function(
            "wait_for_page_two",
            0,
            FunctionFlags::SQLITE_UTF8,
            move |_| {
                seen.store(
                    wait_for(Duration::from_secs(2), || opening.load(Ordering::SeqCst)),
                    Ordering::SeqCst,
                );
                Ok(0i64)
            },
        )
        .unwrap();
    s.test_conn()
        .execute_batch(
            "CREATE TEMP TRIGGER page_one_last BEFORE INSERT ON memories WHEN new.id = 'mem_r0200' BEGIN SELECT wait_for_page_two(); END;",
        )
        .unwrap();
    let (_home, ctx) = test_ctx();
    let out = run_sync(
        &s,
        Some(&client_with(&base, &device, recorder.clone())),
        &ctx,
        &NO_HARVEST,
    )
    .await
    .unwrap();
    assert!(out.notes.is_empty() && !out.relay_error, "{:?}", out.notes);
    assert_eq!(out.pulled, 450);
    assert!(
        overlapped.load(Ordering::SeqCst),
        "page 2 was opened only after page 1 was applied"
    );
}

// ─────────────── ruling 3: the prefetched page ───────────────

/// Page 2's open fails (its ciphertext was tampered with) after page 3 came
/// back: page 3 is dropped unapplied, and the next sync starts from page 1's
/// cursor.
#[tokio::test]
async fn a_page_that_fails_to_open_drops_the_page_fetched_meanwhile() {
    let dir = tempfile::tempdir().unwrap();
    let device = device(dir.path(), EncryptionMode::On);
    let relay = Arc::new(Mutex::new(KeepingRelay::default()));
    seed_sealed(&relay, &device, 600);
    let sealed_300 = {
        let mut r = relay.lock().unwrap();
        let row = r.rows.get_mut("mem_r0300").unwrap();
        let mut tampered = row.content.clone().into_bytes();
        let last = tampered.len() - 3;
        tampered[last] = if tampered[last] == b'A' { b'B' } else { b'A' };
        std::mem::replace(&mut row.content, String::from_utf8(tampered).unwrap())
    };
    let (base, log) = stub_relay(keeping_relay(relay.clone())).await;
    let gets = log.clone();
    // Page 2's open waits until page 3 came back.
    let recorder = Recorder::with_hook(
        device.agent.clone(),
        Box::new(move |_, ops, _| {
            if opens(ops, "mem_r0300") {
                assert!(wait_for(Duration::from_secs(2), || memory_gets(&gets).contains(&400)));
            }
        }),
    );
    let s = Store::open_in_memory().unwrap();
    let (_home, ctx) = test_ctx();
    let out = run_sync(
        &s,
        Some(&client_with(&base, &device, recorder.clone())),
        &ctx,
        &NO_HARVEST,
    )
    .await
    .unwrap();
    assert!(out.relay_error, "{:?}", out.notes);
    assert!(
        out.notes
            .iter()
            .any(|n| n.contains("end-to-end encryption")),
        "{:?}",
        out.notes
    );
    assert_eq!(memory_gets(&log), vec![0, 200, 400]);
    assert_eq!(s.get_state(&memory_cursor_key(ASTATION_ID)).unwrap(), 200);
    assert_eq!(s.history_memories().unwrap().len(), 200);
    assert!(s.history_memories().unwrap().iter().all(|m| m.seq <= 200));
    assert_eq!(s.get_state(LAST_SYNC_AT).unwrap(), 0);
    // The pull stopped there: no skill page.
    assert!(
        !log.lock()
            .unwrap()
            .iter()
            .any(|(_, p, _)| p.starts_with("/api/skills?"))
    );

    // The next sync starts from the committed cursor.
    relay
        .lock()
        .unwrap()
        .rows
        .get_mut("mem_r0300")
        .unwrap()
        .content = sealed_300;
    log.lock().unwrap().clear();
    let out = run_sync(
        &s,
        Some(&client_with(&base, &device, device.agent.clone())),
        &ctx,
        &NO_HARVEST,
    )
    .await
    .unwrap();
    assert!(out.notes.is_empty() && !out.relay_error, "{:?}", out.notes);
    assert_eq!(out.pulled, 400);
    assert_eq!(memory_gets(&log), vec![200, 400, 600]);
    assert_eq!(s.get_state(&memory_cursor_key(ASTATION_ID)).unwrap(), 600);
    assert_eq!(s.history_memories().unwrap().len(), 600);
}

/// A stop inside page 2's transaction while page 3's request is in flight
/// (the relay has it and holds its answer until the stop).
#[derive(Default)]
struct InFlight {
    received: AtomicBool,
    released: AtomicBool,
    answered: AtomicBool,
    seen: AtomicBool,
}

/// The relay, holding its answer to GET `since` until `flags.released`.
fn holding(
    relay: Arc<Mutex<KeepingRelay>>,
    since_held: i64,
    flags: Arc<InFlight>,
) -> Box<super::tests::Handler> {
    let keeping = keeping_relay(relay);
    Box::new(move |m, p, body| {
        if m == "GET" && p.starts_with("/api/memory?") && since(p) == since_held {
            flags.received.store(true, Ordering::SeqCst);
            wait_for(Duration::from_secs(2), || {
                flags.released.load(Ordering::SeqCst)
            });
            flags.answered.store(true, Ordering::SeqCst);
        }
        keeping(m, p, body)
    })
}

/// Arms a stop in the store's next transaction, at the insert of row `id`:
/// it waits until the relay holds the next page's request, records that,
/// copies the store as a process killed then leaves it (with `image`), lets
/// the relay answer and fails the statement.
fn arm_stop_in_flight(s: &Store, db: &Path, image: Option<&Path>, id: &str, flags: Arc<InFlight>) {
    use rusqlite::functions::FunctionFlags;
    let (db, image) = (db.to_path_buf(), image.map(Path::to_path_buf));
    s.test_conn()
        .create_scalar_function(
            "stop_in_flight",
            0,
            FunctionFlags::SQLITE_UTF8,
            move |_| -> rusqlite::Result<i64> {
                let received = wait_for(Duration::from_secs(2), || {
                    flags.received.load(Ordering::SeqCst)
                });
                flags.seen.store(
                    received && !flags.answered.load(Ordering::SeqCst),
                    Ordering::SeqCst,
                );
                if let Some(image) = &image {
                    std::fs::create_dir_all(image.parent().unwrap()).unwrap();
                    for suffix in ["", "-journal"] {
                        let (mut from, mut to) =
                            (db.clone().into_os_string(), image.clone().into_os_string());
                        from.push(suffix);
                        to.push(suffix);
                        if Path::new(&from).exists() {
                            std::fs::copy(&from, &to).unwrap();
                        }
                    }
                }
                flags.released.store(true, Ordering::SeqCst);
                Err(rusqlite::Error::UserFunctionError("injected stop".into()))
            },
        )
        .unwrap();
    s.test_conn().execute_batch(&format!(
        "CREATE TEMP TRIGGER stop_mid_page BEFORE INSERT ON memories WHEN new.id = '{id}' BEGIN SELECT stop_in_flight(); END;"
    )).unwrap();
}

/// Page 2's transaction fails (an error, then a crash) while page 3's
/// request is in flight: page 3 is never applied, the cursor stays at the end
/// of page 1, and the next sync resumes there and completes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_page_that_fails_or_crashes_while_the_next_is_in_flight_keeps_the_cursor() {
    for crash in [false, true] {
        let td = tempfile::tempdir().unwrap();
        let (db, image) = (
            td.path().join("knowledge.db"),
            td.path().join("crash/knowledge.db"),
        );
        let device = device(td.path(), EncryptionMode::On);
        let relay = Arc::new(Mutex::new(KeepingRelay::default()));
        seed_sealed(&relay, &device, 450);
        let flags = Arc::new(InFlight::default());
        let s = Store::open(&db).unwrap();
        // Half way through page 2.
        arm_stop_in_flight(
            &s,
            &db,
            crash.then_some(image.as_path()),
            "mem_r0300",
            flags.clone(),
        );
        let (base, log) = stub_relay(holding(relay.clone(), 400, flags.clone())).await;
        let (_home, ctx) = test_ctx();
        let client = client_with(&base, &device, device.agent.clone());
        let err = run_sync(&s, Some(&client), &ctx, &NO_HARVEST)
            .await
            .unwrap_err();
        assert!(format!("{err:#}").contains("injected stop"), "{err:#}");
        assert!(
            flags.seen.load(Ordering::SeqCst),
            "page 3's request wasn't in flight during page 2's transaction"
        );

        let page_one_only = |s: &Store| {
            assert_eq!(s.get_state(&memory_cursor_key(ASTATION_ID)).unwrap(), 200);
            let rows = s.history_memories().unwrap();
            assert_eq!(rows.len(), 200);
            assert!(rows.iter().all(|m| m.seq <= 200));
            assert_eq!(s.get_state(LAST_SYNC_AT).unwrap(), 0);
        };
        page_one_only(&s);
        let s = if crash {
            drop(s);
            page_one_only(&Store::open(&db).unwrap());
            Store::open(&image).unwrap()
        } else {
            s.test_conn()
                .execute_batch("DROP TRIGGER stop_mid_page;")
                .unwrap();
            s
        };
        page_one_only(&s);

        // The next sync resumes at page 2 and completes.
        log.lock().unwrap().clear();
        let out = run_sync(&s, Some(&client), &ctx, &NO_HARVEST)
            .await
            .unwrap();
        assert!(out.notes.is_empty() && !out.relay_error, "{:?}", out.notes);
        assert_eq!(out.pulled, 250);
        assert_eq!(memory_gets(&log), vec![200, 400]);
        assert_eq!(s.get_state(&memory_cursor_key(ASTATION_ID)).unwrap(), 450);
        let opened = context(&device)
            .decrypt_memories(relay.lock().unwrap().rows.values().cloned().collect())
            .unwrap();
        assert_eq!(s.history_memories().unwrap().len(), 450);
        for row in opened {
            assert_eq!(
                s.get_memory(&row.id).unwrap().as_ref(),
                Some(&row),
                "{}",
                row.id
            );
        }
    }
}

// ─────────────── ruling 5: a lock while a POST is in flight ───────────────

#[tokio::test]
async fn a_lock_while_the_next_group_is_sealed_stops_the_push_cleanly() {
    let dir = tempfile::tempdir().unwrap();
    let device = device(dir.path(), EncryptionMode::On);
    // `atem cred lock` lands just as the next group is sealed, while chunk 6
    // (the last whole chunk of group 1) is in flight.
    let recorder = Recorder::with_hook(
        device.agent.clone(),
        Box::new(|index, _, agent| {
            if index == 1 {
                agent.lock_keys().unwrap();
            }
        }),
    );
    let relay = Arc::new(Mutex::new(KeepingRelay::default()));
    let (base, log) = stub_relay(keeping_relay(relay.clone())).await;
    let s = Store::open_in_memory().unwrap();
    // 341 facts of 3 ops fill group 1.
    queue(&s, (0..400).map(|i| fact(i, true)));
    let queued = s.pending().unwrap();
    let (_home, ctx) = test_ctx();
    let client = client_with(&base, &device, recorder.clone());
    let out = run_sync(&s, Some(&client), &ctx, &NO_HARVEST)
        .await
        .unwrap();
    assert!(out.relay_error, "{:?}", out.notes);
    assert!(
        out.notes.iter().any(|n| n.contains("atem cred unlock")),
        "{:?}",
        out.notes
    );
    // Chunks 1 to 6 went out, sealed before the lock; nothing after it.
    assert_eq!(out.pushed, 300);
    assert_eq!(
        posted_ops(&log).iter().map(Vec::len).collect::<Vec<_>>(),
        vec![50; 6]
    );
    assert_eq!(s.pending().unwrap(), queued[300..].to_vec());
    let calls = recorder.calls();
    assert!(calls[0].ok && calls[1..].iter().all(|c| !c.ok), "{calls:?}");
    {
        let r = relay.lock().unwrap();
        assert_eq!(r.rows.len(), 300);
        assert!(
            r.rows
                .values()
                .all(|m| m.content.starts_with("e1.") && m.project.starts_with("h1."))
        );
    }
    // The pull couldn't open its page: nothing applied, no cursor.
    assert_eq!(s.get_state(&memory_cursor_key(ASTATION_ID)).unwrap(), 0);
    assert_eq!(s.get_state(LAST_SYNC_AT).unwrap(), 0);

    // Unlocked again, the next sync sends the rest once.
    unlock_with(device.agent.as_ref(), &device.server, &device.paths).unwrap();
    let out = run_sync(
        &s,
        Some(&client_with(&base, &device, device.agent.clone())),
        &ctx,
        &NO_HARVEST,
    )
    .await
    .unwrap();
    assert!(out.notes.is_empty() && !out.relay_error, "{:?}", out.notes);
    assert_eq!((out.pushed, out.pulled), (100, 400));
    assert_eq!(s.pending_count().unwrap(), 0);
    let r = relay.lock().unwrap();
    assert_eq!((r.rows.len(), r.ops_received), (400, 400));
}

/// An op that can't be sealed (a field over the agent's limit) is a group of
/// its own (over the budget) and fails it, while chunk 2 is in flight; from
/// then on the push seals chunk by chunk, so it stops at that op's own chunk,
/// as before read-ahead.
#[tokio::test]
async fn an_op_that_cannot_be_sealed_stops_the_push_at_its_own_chunk() {
    let dir = tempfile::tempdir().unwrap();
    let device = device(dir.path(), EncryptionMode::On);
    let recorder = Recorder::new(device.agent.clone());
    let relay = Arc::new(Mutex::new(KeepingRelay::default()));
    let (base, log) = stub_relay(keeping_relay(relay.clone())).await;
    let s = Store::open_in_memory().unwrap();
    queue(&s, (0..120).map(|i| fact(i, false)));
    queue(&s, [valid("mem_huge", &"x".repeat(3 << 20))]);
    queue(&s, (120..150).map(|i| fact(i, false)));
    let (_home, ctx) = test_ctx();
    let out = run_sync(
        &s,
        Some(&client_with(&base, &device, recorder.clone())),
        &ctx,
        &NO_HARVEST,
    )
    .await
    .unwrap();
    assert!(out.relay_error);
    assert!(
        out.notes.iter().any(|n| n.contains("too large to encrypt")),
        "{:?}",
        out.notes
    );
    assert_eq!(out.pushed, 100);
    assert_eq!(
        posted_ops(&log).iter().map(Vec::len).collect::<Vec<_>>(),
        vec![50, 50]
    );
    assert_eq!(s.pending_count().unwrap(), 51);
    // The 120 facts before it in one request; nothing reached the agent for
    // the failed group or chunk.
    let (seals, _) = recorder.seals_and_opens();
    assert_eq!(seals.iter().map(|c| c.ops).collect::<Vec<_>>(), vec![240]);
}

// ─────────────── ruling 1: the order of commits ───────────────

/// What another connection to the store sees when a request reaches the
/// relay: the queued ops and the memory cursor, and whether every relay row
/// at or below that cursor is stored.
#[derive(Debug)]
struct Seen {
    method: String,
    since: Option<i64>,
    queued: Vec<i64>,
    cursor: i64,
    below_cursor_stored: bool,
}

#[tokio::test]
async fn commits_and_acks_keep_their_order() {
    let td = tempfile::tempdir().unwrap();
    let db = td.path().join("knowledge.db");
    let device = device(td.path(), EncryptionMode::On);
    let relay = Arc::new(Mutex::new(KeepingRelay::default()));
    seed_sealed(&relay, &device, 400);
    let s = Store::open(&db).unwrap();
    queue(&s, (0..120).map(|i| fact(i, i % 3 == 0)));
    let queued: Vec<i64> = s.pending().unwrap().iter().map(|(n, _)| *n).collect();
    let seen = Arc::new(Mutex::new(Vec::<Seen>::new()));
    let keeping = keeping_relay(relay.clone());
    let (observer, rows, record) = (db.clone(), relay.clone(), seen.clone());
    let (base, _log) = stub_relay(Box::new(move |m, p, body| {
        let other = Store::open(&observer).unwrap();
        let cursor = other.get_state(&memory_cursor_key(ASTATION_ID)).unwrap();
        let ids: Vec<String> = rows
            .lock()
            .unwrap()
            .rows
            .values()
            .filter(|r| r.seq <= cursor)
            .map(|r| r.id.clone())
            .collect();
        record.lock().unwrap().push(Seen {
            method: m.into(),
            since: p.starts_with("/api/memory?").then(|| since(p)),
            queued: other.pending().unwrap().iter().map(|(n, _)| *n).collect(),
            cursor,
            below_cursor_stored: ids.iter().all(|id| other.get_memory(id).unwrap().is_some()),
        });
        keeping(m, p, body)
    }))
    .await;
    let (_home, ctx) = test_ctx();
    let out = run_sync(
        &s,
        Some(&client_with(&base, &device, device.agent.clone())),
        &ctx,
        &NO_HARVEST,
    )
    .await
    .unwrap();
    assert!(out.notes.is_empty() && !out.relay_error, "{:?}", out.notes);
    assert_eq!((out.pushed, out.pulled), (120, 520));
    let seen = seen.lock().unwrap();
    // Each POST goes out once the chunks before it are acked, and none of
    // its own or later ops is.
    let posts: Vec<&Seen> = seen.iter().filter(|x| x.method == "POST").collect();
    assert_eq!(posts.len(), 3);
    for (k, post) in posts.iter().enumerate() {
        assert_eq!(post.queued, queued[k * 50..].to_vec(), "POST {k}");
    }
    // The cursor only ever names whole stored pages, and a page is asked
    // for from the end of the page before it, at most one page ahead of
    // what is committed.
    let gets: Vec<&Seen> = seen.iter().filter(|x| x.since.is_some()).collect();
    assert_eq!(
        gets.iter().map(|x| x.since.unwrap()).collect::<Vec<_>>(),
        vec![0, 200, 400]
    );
    for get in &gets {
        let since = get.since.unwrap();
        assert!(get.below_cursor_stored, "{get:?}");
        assert!(
            get.cursor <= since && (since == 0 || get.cursor >= since - 200),
            "{get:?}"
        );
        assert!(get.queued.is_empty(), "{get:?}");
    }
    assert_eq!(s.get_state(&memory_cursor_key(ASTATION_ID)).unwrap(), 520);
}

// ─────────────── migration and read-back ───────────────

/// A relay with `n` plain facts (half project-scoped) and `skills` plain
/// skills of three files.
fn plain_relay(n: usize, skills: usize) -> Arc<Mutex<KeepingRelay>> {
    let relay = Arc::new(Mutex::new(KeepingRelay::default()));
    {
        let mut r = relay.lock().unwrap();
        for i in 0..n {
            r.put(fact(i, i % 2 == 0));
        }
        for i in 0..skills {
            let mut skill =
                super::tests::skill_v1(&format!("skill{i:02}"), &format!("# skill {i}"), "m2");
            skill.files.insert("a.md".into(), b"a".to_vec());
            skill.files.insert("b.md".into(), b"b".to_vec());
            skill.content_hash = skill_hash(&skill.files);
            r.put_skill(skill);
        }
    }
    relay
}

#[tokio::test]
async fn a_migration_seals_full_groups_and_reads_back_page_by_page() {
    let dir = tempfile::tempdir().unwrap();
    let device = device(dir.path(), EncryptionMode::Enabling);
    let recorder = Recorder::new(device.agent.clone());
    let relay = plain_relay(1000, 20);
    let (base, log) = stub_relay(keeping_relay(relay.clone())).await;
    let client = client_with(&base, &device, recorder.clone());
    client.migrate_encryption().await.unwrap();
    // The relay's chunks are unchanged: 64 facts, 16 skills per POST.
    let posts = posted_ops(&log);
    assert_eq!(
        posts.iter().map(Vec::len).collect::<Vec<_>>(),
        [vec![64; 15], vec![40, 16, 4]].concat()
    );
    let (seals, opens) = recorder.seals_and_opens();
    assert!(opens.is_empty());
    // Facts: 2,500 ops in 3 requests. Skills: paths and hashes, then files.
    assert_eq!(
        seals.iter().map(|c| c.ops).sum::<usize>(),
        2500 + 20 * 4 + 20 * 3
    );
    assert_eq!(
        seals.len(),
        2500usize.div_ceil(CRYPT_BATCH_OPS) + 2,
        "{seals:?}"
    );
    assert!(
        seals
            .iter()
            .all(|c| c.ops <= CRYPT_BATCH_OPS && c.bytes <= CRYPT_BATCH_BYTES),
        "{seals:?}"
    );
    let (envelope, hash) = (format!("e1.{KID}."), format!("h1.{KID}."));
    assert!(
        relay
            .lock()
            .unwrap()
            .rows
            .values()
            .all(|m| m.content.starts_with(&envelope)
                && m.content_hash.starts_with(&hash)
                && (m.project.is_empty() || m.project.starts_with(&hash)))
    );

    // The read-back: one request per page of 200.
    let before = recorder.calls().len();
    client.verify_encryption_migration().await.unwrap();
    let read_back: Vec<usize> = recorder.calls()[before..].iter().map(|c| c.ops).collect();
    assert_eq!(read_back, vec![200, 200, 200, 200, 200, 20 * 3 * 2]);
}

#[tokio::test]
async fn the_read_back_checks_every_page_while_the_next_one_is_fetched() {
    let dir = tempfile::tempdir().unwrap();
    let device = device(dir.path(), EncryptionMode::Enabling);
    let relay = plain_relay(450, 0);
    let (base, log) = stub_relay(keeping_relay(relay.clone())).await;
    let overlapped = Arc::new(AtomicBool::new(false));
    let mark = Arc::new(AtomicUsize::new(usize::MAX));
    let (seen, gets, from) = (overlapped.clone(), log.clone(), mark.clone());
    let opened = AtomicBool::new(false);
    // A migration over plain rows opens nothing: the first open is the
    // read-back's, of page 1. Is page 2 being fetched meanwhile?
    let recorder = Recorder::with_hook(
        device.agent.clone(),
        Box::new(move |_, ops, _| {
            let opening = ops.iter().any(|op| matches!(op, CryptOp::Open { .. }));
            if opening && !opened.swap(true, Ordering::SeqCst) {
                let read_back_gets = || {
                    let log = gets.lock().unwrap();
                    log[from.load(Ordering::SeqCst).min(log.len())..]
                        .iter()
                        .filter(|(m, p, _)| m == "GET" && p.starts_with("/api/memory?"))
                        .count()
                };
                seen.store(
                    wait_for(Duration::from_secs(2), || read_back_gets() == 2),
                    Ordering::SeqCst,
                );
            }
        }),
    );
    let client = client_with(&base, &device, recorder.clone());
    client.migrate_encryption().await.unwrap();
    mark.store(log.lock().unwrap().len(), Ordering::SeqCst);
    client.verify_encryption_migration().await.unwrap();
    assert!(
        overlapped.load(Ordering::SeqCst),
        "page 2 was fetched only after page 1 was checked"
    );

    // An unmigrated row anywhere fails the read-back: the first page, the last.
    for id in ["mem_0003", "mem_0440"] {
        let original = relay.lock().unwrap().rows[id].content.clone();
        relay.lock().unwrap().rows.get_mut(id).unwrap().content = "left in plain text".into();
        let err = client.verify_encryption_migration().await.unwrap_err();
        assert!(err.to_string().contains("unmigrated field"), "{id}: {err}");
        relay.lock().unwrap().rows.get_mut(id).unwrap().content = original;
    }
    client.verify_encryption_migration().await.unwrap();
}

/// Vaults `v-1`..`v-n` of plain entries, as the relay keeps them.
type Vaults = Arc<Mutex<BTreeMap<String, (String, Vec<serde_json::Value>)>>>;

fn vault_relay(vaults: Vaults, in_flight: Arc<AtomicBool>) -> Box<super::tests::Handler> {
    Box::new(move |m, p, body| {
        let path = p.split_once('?').map_or(p, |(path, _)| path);
        if m == "GET" && path == "/api/vault" {
            let list: Vec<_> = vaults
                .lock()
                .unwrap()
                .iter()
                .map(|(id, (summary, _))| serde_json::json!({"vault_id": id, "summary": summary}))
                .collect();
            return (200, serde_json::Value::Array(list));
        }
        let rest = path.strip_prefix("/api/vault/").unwrap();
        if m == "GET" {
            return (
                200,
                serde_json::Value::Array(vaults.lock().unwrap()[rest].1.clone()),
            );
        }
        let id = rest.strip_suffix("/encryption").unwrap();
        in_flight.store(true, Ordering::SeqCst);
        std::thread::sleep(Duration::from_millis(100));
        {
            let mut vaults = vaults.lock().unwrap();
            let (summary, entries) = vaults.get_mut(id).unwrap();
            *summary = body["summary"].as_str().unwrap().into();
            for replacement in body["entries"].as_array().unwrap() {
                let entry = entries
                    .iter_mut()
                    .find(|e| {
                        e["entry_no"] == replacement["entry_no"]
                            && e["version"] == replacement["version"]
                    })
                    .unwrap();
                entry["content"] = replacement["content"].clone();
            }
        }
        in_flight.store(false, Ordering::SeqCst);
        (200, serde_json::json!({"ok": true}))
    })
}

#[tokio::test]
async fn vaults_are_sealed_while_the_one_before_is_posted_and_all_read_back() {
    let dir = tempfile::tempdir().unwrap();
    let device = device(dir.path(), EncryptionMode::Enabling);
    let vaults: Vaults = Arc::new(Mutex::new(BTreeMap::new()));
    for v in 1..=3 {
        let entries = (1..=3).map(|e| serde_json::json!({"seq": v * 10 + e, "entry_no": e, "version": 1, "kind": "content",
            "writer_id": "seed", "content": format!("vault {v} entry {e}"), "created_at": "2026-11-08T00:00:00Z"})).collect();
        vaults
            .lock()
            .unwrap()
            .insert(format!("v-{v}"), (format!("vault {v}"), entries));
    }
    let in_flight = Arc::new(AtomicBool::new(false));
    let overlapped = Arc::new(AtomicBool::new(false));
    let (flag, seen) = (in_flight.clone(), overlapped.clone());
    // The second request seals vault 2: is vault 1's POST in flight then?
    let recorder = Recorder::with_hook(
        device.agent.clone(),
        Box::new(move |index, _, _| {
            if index == 1 {
                seen.store(
                    wait_for(Duration::from_secs(2), || flag.load(Ordering::SeqCst)),
                    Ordering::SeqCst,
                );
            }
        }),
    );
    let (base, _log) = stub_relay(vault_relay(vaults.clone(), in_flight)).await;
    let vault = crate::vault_client::VaultClient::new(
        base,
        "inst".into(),
        "sess".into(),
        ASTATION_ID.into(),
    )
    .with_encryption(device.paths.clone(), recorder.clone());
    vault.migrate_encryption().await.unwrap();
    assert!(
        overlapped.load(Ordering::SeqCst),
        "vault 2 was sealed only after vault 1 was posted"
    );
    let envelope = format!("e1.{KID}.");
    assert!(vaults.lock().unwrap().values().all(|(summary, entries)| {
        summary.starts_with(&envelope)
            && entries
                .iter()
                .all(|e| e["content"].as_str().unwrap().starts_with(&envelope))
    }));
    vault.verify_encryption_migration().await.unwrap();
    // An unmigrated version in the last vault fails the read-back.
    vaults.lock().unwrap().get_mut("v-3").unwrap().1[2]["content"] = "left in plain text".into();
    let err = vault.verify_encryption_migration().await.unwrap_err();
    assert!(err.to_string().contains("unmigrated field"), "{err}");
}
