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
/// Project facts (3 `Crypt` ops each) whose push is two groups: chunk 1
/// alone (`GROUP_ONE_CHUNKS`, sealed in `GROUP_ONE_REQUESTS` request), then
/// the other seven chunks (1,050 ops), sealed while chunk 1 is in flight.
const TWO_GROUPS: usize = 400;
const GROUP_ONE_CHUNKS: usize = 1;
const GROUP_ONE_REQUESTS: usize = 1;
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

/// The in-process agent, recording every `Crypt` request and counting every
/// request of any kind (in production the first request starts the agent).
/// `hook` runs before a `Crypt` request reaches the agent, with its index
/// (from 0) and its ops.
struct Recorder {
    inner: Arc<Mutex<CredAgent>>,
    started: AtomicUsize,
    calls: Mutex<Vec<Call>>,
    requests: AtomicUsize,
    statuses: AtomicUsize,
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
            requests: AtomicUsize::new(0),
            statuses: AtomicUsize::new(0),
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

    /// Every request that reached the agent, of any kind.
    fn requests(&self) -> usize {
        self.requests.load(Ordering::SeqCst)
    }

    /// The status requests (the unlocked check before a POST).
    fn statuses(&self) -> usize {
        self.statuses.load(Ordering::SeqCst)
    }
}

impl CredAgentApi for Recorder {
    fn call(&self, request: Request) -> anyhow::Result<Reply> {
        self.requests.fetch_add(1, Ordering::SeqCst);
        if matches!(request, Request::Status) {
            self.statuses.fetch_add(1, Ordering::SeqCst);
        }
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
    // Every op sealed once: chunk 1 alone (so the first POST starts at
    // once), then the rest in one request per 1,024 ops / 2 MiB.
    assert_eq!(seals.iter().map(|c| c.ops).sum::<usize>(), 2500);
    assert_eq!(seals[0].ops, 125);
    assert_eq!(
        seals.len(),
        2375usize.div_ceil(CRYPT_BATCH_OPS) + 1,
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
    // Per group (chunk 1, then chunk 2 with the delete and the purge): paths,
    // hashes and the deleted and purged projects' hashes, then the file
    // contents sealed under their sealed paths. Two requests per group, the
    // purge's and delete's hashes riding along (five before F2).
    assert_eq!(
        seals.iter().map(|c| c.ops).collect::<Vec<_>>(),
        vec![8 * 4, 8 * 2, 2 * 4 + 2, 2 * 2],
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

/// The first group is chunk 1 alone, so the first POST starts as soon as one
/// request is answered; the rest go in full groups, and the push never takes
/// more requests than sealing chunk by chunk did (one per chunk here).
#[tokio::test]
async fn the_first_group_is_one_chunk_and_no_more_requests_than_chunk_by_chunk() {
    let dir = tempfile::tempdir().unwrap();
    let device = device(dir.path(), EncryptionMode::On);
    let posted_after_first = Arc::new(AtomicBool::new(false));
    let chunk_one_arrived = Arc::new(AtomicBool::new(false));
    // The next group's first request waits (bounded) for chunk 1 to reach
    // the relay: if chunk 1 needed more than its own request, it never does.
    let arrived = chunk_one_arrived.clone();
    let recorder = Recorder::with_hook(
        device.agent.clone(),
        Box::new(move |index, _, _| {
            if index == 1 {
                wait_for(Duration::from_secs(2), || arrived.load(Ordering::SeqCst));
            }
        }),
    );
    let relay = Arc::new(Mutex::new(KeepingRelay::default()));
    let keeping = keeping_relay(relay.clone());
    let (seen, sealed, first) = (
        posted_after_first.clone(),
        recorder.clone(),
        AtomicBool::new(true),
    );
    let (base, log) = stub_relay(Box::new(move |m, p, body| {
        if m == "POST" && first.swap(false, Ordering::SeqCst) {
            seen.store(sealed.calls().len() == 1, Ordering::SeqCst);
            chunk_one_arrived.store(true, Ordering::SeqCst);
        }
        keeping(m, p, body)
    }))
    .await;
    let s = Store::open_in_memory().unwrap();
    // 1,000 project facts: 20 chunks of 150 ops.
    queue(&s, (0..1000).map(|i| fact(i, true)));
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
    assert_eq!(out.pushed, 1000);
    assert_eq!(
        posted_ops(&log).iter().map(Vec::len).collect::<Vec<_>>(),
        vec![50; 20]
    );
    assert!(
        posted_after_first.load(Ordering::SeqCst),
        "chunk 1 waited for more than its own request"
    );
    let (seals, _) = recorder.seals_and_opens();
    assert_eq!(
        seals.iter().map(|c| c.ops).collect::<Vec<_>>(),
        vec![150, 1024, 1024, 802]
    );
    // Sealing chunk by chunk took one request per chunk: 20.
    assert!(seals.len() <= 20);
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
        vec![50 * 2, 2]
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
        vec![50 * 2, 10 * 2, 2]
    );
    // Sealing the changed op again, just before chunk 2's POST, showed the
    // agent unlocked: no status check for the ops sealed ahead beside it.
    assert_eq!(recorder.statuses(), 0);
    assert_eq!(s.pending_count().unwrap(), 0);
}

/// The account's mode changes while chunk 1 is in flight, once chunk 2 (the
/// next group) was sealed, or left plain, under the old one: chunk 2 goes out
/// as the new mode says, sealed again, as it did when each chunk was sealed
/// just before its POST.
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
        let recorder = Recorder::new(device.agent.clone());
        let device = Arc::new(Mutex::new(device));
        let relay = Arc::new(Mutex::new(KeepingRelay::default()));
        let keeping = keeping_relay(relay.clone());
        let (switch, sealed, first) = (device.clone(), recorder.clone(), AtomicBool::new(true));
        let (base, log) = stub_relay(Box::new(move |m, p, body| {
            if m == "POST" && first.swap(false, Ordering::SeqCst) {
                // Chunk 2 is sealed first: under on, its request has come
                // back; under off it was left plain without the agent, in the
                // same poll that sent chunk 1, before this relay could run.
                if from == EncryptionMode::On {
                    assert!(wait_for(Duration::from_secs(2), || sealed.calls().len() == 2));
                }
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
            client_with(&base, &device, recorder.clone())
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
        // The push's requests: under on, both groups (chunk 2's ciphertext is
        // dropped for its plain form); under off, none until chunk 2 is
        // sealed again under on.
        let pushed: Vec<usize> = recorder.seals_and_opens().0.iter().map(|c| c.ops).collect();
        let want = if from == EncryptionMode::On {
            vec![150, 30]
        } else {
            vec![30]
        };
        assert_eq!(pushed, want, "{from:?} → {to:?}");
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
    // Group 1 (chunk 1) is one request; the second is the next group's: is
    // a POST in flight then?
    let recorder = Recorder::with_hook(
        device.agent.clone(),
        Box::new(move |index, _, _| {
            if index == GROUP_ONE_REQUESTS {
                seen.store(
                    wait_for(Duration::from_secs(2), || flag.load(Ordering::SeqCst)),
                    Ordering::SeqCst,
                );
            }
        }),
    );
    let relay = Arc::new(Mutex::new(KeepingRelay::default()));
    let keeping = keeping_relay(relay.clone());
    let (flag, posts) = (in_flight.clone(), AtomicUsize::new(0));
    let (base, _log) = stub_relay(Box::new(move |m, p, body| {
        // Chunk 1 (all of group 1) is held a while.
        if m != "POST" || posts.fetch_add(1, Ordering::SeqCst) + 1 != GROUP_ONE_CHUNKS {
            return keeping(m, p, body);
        }
        flag.store(true, Ordering::SeqCst);
        std::thread::sleep(Duration::from_millis(300));
        let answer = keeping(m, p, body);
        flag.store(false, Ordering::SeqCst);
        answer
    }))
    .await;
    let s = Store::open_in_memory().unwrap();
    queue(&s, (0..TWO_GROUPS).map(|i| fact(i, true)));
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
    assert_eq!(out.pushed, TWO_GROUPS);
    assert!(
        overlapped.load(Ordering::SeqCst),
        "the next group was sealed between POSTs"
    );
    let (seals, _) = recorder.seals_and_opens();
    assert_eq!(
        seals.iter().map(|c| c.ops).collect::<Vec<_>>(),
        vec![150, 1024, 26]
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

        // The stopped sync's page-3 request is answered, and logged, only
        // after that sync returned: wait for it, so it isn't counted as the
        // resumed sync's.
        assert!(
            wait_for(Duration::from_secs(5), || memory_gets(&log).contains(&400)),
            "the stopped sync's page-3 request was never answered"
        );

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

/// Page 2's transaction fails after page 3 was already opened: page 3 is
/// dropped unapplied, the cursor stays at page 1, and the next sync resumes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_page_that_fails_to_apply_after_the_next_was_opened_keeps_the_cursor() {
    use rusqlite::functions::FunctionFlags;
    let dir = tempfile::tempdir().unwrap();
    let device = device(dir.path(), EncryptionMode::On);
    let recorder = Recorder::new(device.agent.clone());
    let relay = Arc::new(Mutex::new(KeepingRelay::default()));
    seed_sealed(&relay, &device, 600);
    let (base, log) = stub_relay(keeping_relay(relay.clone())).await;
    let s = Store::open_in_memory().unwrap();
    let opened_three = Arc::new(AtomicBool::new(false));
    let (seen, opens) = (opened_three.clone(), recorder.clone());
    s.test_conn()
        .create_scalar_function(
            "stop_after_page_three",
            0,
            FunctionFlags::SQLITE_UTF8,
            move |_| -> rusqlite::Result<i64> {
                seen.store(
                    wait_for(Duration::from_secs(2), || opens.calls().len() >= 3),
                    Ordering::SeqCst,
                );
                Err(rusqlite::Error::UserFunctionError("injected stop".into()))
            },
        )
        .unwrap();
    s.test_conn()
        .execute_batch("CREATE TEMP TRIGGER stop_mid_page BEFORE INSERT ON memories WHEN new.id = 'mem_r0300' BEGIN SELECT stop_after_page_three(); END;")
        .unwrap();
    let (_home, ctx) = test_ctx();
    let client = client_with(&base, &device, recorder.clone());
    let err = run_sync(&s, Some(&client), &ctx, &NO_HARVEST)
        .await
        .unwrap_err();
    assert!(format!("{err:#}").contains("injected stop"), "{err:#}");
    assert!(
        opened_three.load(Ordering::SeqCst),
        "page 3 wasn't opened during page 2's transaction"
    );
    assert_eq!(s.get_state(&memory_cursor_key(ASTATION_ID)).unwrap(), 200);
    assert_eq!(s.history_memories().unwrap().len(), 200);
    assert!(s.history_memories().unwrap().iter().all(|m| m.seq <= 200));

    s.test_conn()
        .execute_batch("DROP TRIGGER stop_mid_page;")
        .unwrap();
    log.lock().unwrap().clear();
    let out = run_sync(&s, Some(&client), &ctx, &NO_HARVEST)
        .await
        .unwrap();
    assert!(out.notes.is_empty() && !out.relay_error, "{:?}", out.notes);
    assert_eq!(out.pulled, 400);
    assert_eq!(memory_gets(&log), vec![200, 400, 600]);
    assert_eq!(s.get_state(&memory_cursor_key(ASTATION_ID)).unwrap(), 600);
    assert_eq!(s.history_memories().unwrap().len(), 600);
}

/// Another writer moves the cursor past page 2 as page 1 commits: the page 2
/// fetched meanwhile (from page 1's end) is dropped, and the pull starts again
/// from the committed cursor.
#[tokio::test]
async fn a_cursor_moved_by_another_writer_restarts_the_pull_from_it() {
    let dir = tempfile::tempdir().unwrap();
    let device = device(dir.path(), EncryptionMode::On);
    let relay = Arc::new(Mutex::new(KeepingRelay::default()));
    seed_sealed(&relay, &device, 600);
    let (base, log) = stub_relay(keeping_relay(relay.clone())).await;
    let s = Store::open_in_memory().unwrap();
    let key = memory_cursor_key(ASTATION_ID);
    s.test_conn()
        .execute_batch(&format!(
            "CREATE TEMP TRIGGER other_writer AFTER INSERT ON sync_state WHEN new.key = '{key}' AND new.value = 200 \
             BEGIN UPDATE sync_state SET value = 400 WHERE key = new.key; END;"
        ))
        .unwrap();
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
    assert_eq!(out.pulled, 400);
    assert_eq!(s.get_state(&key).unwrap(), 600);
    let rows = s.history_memories().unwrap();
    assert_eq!(rows.len(), 400);
    assert!(
        rows.iter().all(|m| m.seq <= 200 || m.seq > 400),
        "page 2 was applied"
    );
    let gets = memory_gets(&log);
    assert!(
        gets.contains(&200) && gets.ends_with(&[400, 600]),
        "{gets:?}"
    );
}

// ─────────────── ruling 5: a lock while a POST is in flight ───────────────

#[tokio::test]
async fn a_lock_while_the_next_group_is_sealed_stops_the_push_cleanly() {
    let dir = tempfile::tempdir().unwrap();
    let device = device(dir.path(), EncryptionMode::On);
    // `atem cred lock` lands just as the next group is sealed, while chunk 1
    // (all of group 1) is in flight.
    let recorder = Recorder::with_hook(
        device.agent.clone(),
        Box::new(|index, _, agent| {
            if index == GROUP_ONE_REQUESTS {
                agent.lock_keys().unwrap();
            }
        }),
    );
    let relay = Arc::new(Mutex::new(KeepingRelay::default()));
    let (base, log) = stub_relay(keeping_relay(relay.clone())).await;
    let s = Store::open_in_memory().unwrap();
    queue(&s, (0..TWO_GROUPS).map(|i| fact(i, true)));
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
    // Group 1's chunks went out, sealed before the lock; the failed group
    // stopped the push at once (one refused request, never retried), and the
    // pull's open was refused too.
    let sent = GROUP_ONE_CHUNKS * 50;
    assert_eq!(out.pushed, sent);
    assert_eq!(
        posted_ops(&log).iter().map(Vec::len).collect::<Vec<_>>(),
        vec![50; GROUP_ONE_CHUNKS]
    );
    assert_eq!(s.pending().unwrap(), queued[sent..].to_vec());
    let calls = recorder.calls();
    assert_eq!(calls.len(), GROUP_ONE_REQUESTS + 2, "{calls:?}");
    assert!(
        calls[..GROUP_ONE_REQUESTS].iter().all(|c| c.ok),
        "{calls:?}"
    );
    assert!(
        calls[GROUP_ONE_REQUESTS..].iter().all(|c| !c.ok),
        "{calls:?}"
    );
    {
        let r = relay.lock().unwrap();
        assert_eq!(r.rows.len(), sent);
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
    assert_eq!((out.pushed, out.pulled), (TWO_GROUPS - sent, TWO_GROUPS));
    assert_eq!(s.pending_count().unwrap(), 0);
    let r = relay.lock().unwrap();
    assert_eq!((r.rows.len(), r.ops_received), (TWO_GROUPS, TWO_GROUPS));
}

/// A chunk with an op that can't be sealed (a field over the agent's limit)
/// is a group of its own, sealed while chunk 2 is in flight; its failure
/// stops the push at that chunk, as before read-ahead.
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
    // Chunks 1 and 2 in one request; nothing reached the agent for the
    // failed chunk.
    let (seals, _) = recorder.seals_and_opens();
    assert_eq!(
        seals.iter().map(|c| c.ops).collect::<Vec<_>>(),
        vec![100, 100]
    );
}

/// `atem cred lock` lands after the whole group was sealed, while chunk 1 is
/// in flight: chunk 2 (sealed before the lock) is not sent, as when each
/// chunk was sealed just before its POST.
#[tokio::test]
async fn a_lock_between_two_seals_stops_the_push_within_one_post() {
    let dir = tempfile::tempdir().unwrap();
    let device = device(dir.path(), EncryptionMode::On);
    let recorder = Recorder::new(device.agent.clone());
    let relay = Arc::new(Mutex::new(KeepingRelay::default()));
    let keeping = keeping_relay(relay.clone());
    let (agent, sealed, first) = (
        device.agent.clone(),
        recorder.clone(),
        AtomicBool::new(true),
    );
    let (base, log) = stub_relay(Box::new(move |m, p, body| {
        // Chunk 1 is in flight: once the next group (chunks 2 to 8) is
        // sealed, the agent is locked.
        if m == "POST" && first.swap(false, Ordering::SeqCst) {
            assert!(wait_for(Duration::from_secs(2), || sealed.calls().len() == 3));
            agent.lock_keys().unwrap();
        }
        keeping(m, p, body)
    }))
    .await;
    let s = Store::open_in_memory().unwrap();
    // Chunk 1 alone, then chunks 2 to 8 (1,050 ops) in two requests.
    queue(&s, (0..400).map(|i| fact(i, true)));
    let queued = s.pending().unwrap();
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
        out.notes.iter().any(|n| n.contains("atem cred unlock")),
        "{:?}",
        out.notes
    );
    assert_eq!(out.pushed, 50);
    assert_eq!(
        posted_ops(&log).iter().map(Vec::len).collect::<Vec<_>>(),
        vec![50]
    );
    assert_eq!(s.pending().unwrap(), queued[50..].to_vec());
    // Both groups' requests, then only the pull's refused open.
    let calls = recorder.calls();
    assert_eq!(
        calls.iter().map(|c| (c.ops, c.ok)).collect::<Vec<_>>(),
        vec![(150, true), (1024, true), (26, true), (50, false)]
    );
}

/// A locked agent refuses the push's first seal once: the refusal is the
/// note, and nothing is asked again.
#[tokio::test]
async fn a_locked_agent_refuses_a_push_once() {
    let dir = tempfile::tempdir().unwrap();
    let device = device(dir.path(), EncryptionMode::On);
    device.agent.lock_keys().unwrap();
    let recorder = Recorder::new(device.agent.clone());
    let relay = Arc::new(Mutex::new(KeepingRelay::default()));
    let (base, log) = stub_relay(keeping_relay(relay.clone())).await;
    let s = Store::open_in_memory().unwrap();
    queue(&s, (0..60).map(|i| fact(i, false)));
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
        out.notes.iter().any(|n| n.contains("atem cred unlock")),
        "{:?}",
        out.notes
    );
    assert_eq!(out.pushed, 0);
    assert!(posted_ops(&log).is_empty());
    assert_eq!(s.pending_count().unwrap(), 60);
    let calls = recorder.calls();
    assert_eq!(
        calls.iter().map(|c| (c.ops, c.ok)).collect::<Vec<_>>(),
        vec![(100, false)]
    );
}

/// The key rotates while chunk 1 is in flight, once chunk 2 (the next
/// group) was sealed under the old kid: chunk 2 is sealed again and goes out
/// under the new kid, never the old one.
#[tokio::test]
async fn a_key_rotation_after_sealing_seals_again_under_the_new_kid() {
    let dir = tempfile::tempdir().unwrap();
    let device = device(dir.path(), EncryptionMode::On);
    let recorder = Recorder::new(device.agent.clone());
    let device = Arc::new(Mutex::new(device));
    let relay = Arc::new(Mutex::new(KeepingRelay::default()));
    let keeping = keeping_relay(relay.clone());
    let (rotate, sealed, first) = (device.clone(), recorder.clone(), AtomicBool::new(true));
    let (base, log) = stub_relay(Box::new(move |m, p, body| {
        if m == "POST" && first.swap(false, Ordering::SeqCst) {
            // Chunk 2's request (under the old kid) has come back first.
            assert!(wait_for(Duration::from_secs(2), || sealed.calls().len() == 2));
            rotate
                .lock()
                .unwrap()
                .set_key(EncryptionMode::On, "89abcdef", [8; 32]);
        }
        keeping(m, p, body)
    }))
    .await;
    let s = Store::open_in_memory().unwrap();
    queue(&s, (0..60).map(|i| fact(i, true)));
    let (_home, ctx) = test_ctx();
    let client = {
        let device = device.lock().unwrap();
        client_with(&base, &device, recorder.clone())
    };
    let out = run_sync(&s, Some(&client), &ctx, &NO_HARVEST)
        .await
        .unwrap();
    assert_eq!(out.pushed, 60, "{:?}", out.notes);
    let posts = posted_ops(&log);
    assert_eq!(posts.iter().map(Vec::len).collect::<Vec<_>>(), vec![50, 10]);
    let under = |op: &serde_json::Value, kid: &str| {
        op["memory"]["content"]
            .as_str()
            .unwrap()
            .starts_with(&format!("e1.{kid}."))
            && op["memory"]["content_hash"]
                .as_str()
                .unwrap()
                .starts_with(&format!("h1.{kid}."))
            && op["memory"]["project"]
                .as_str()
                .unwrap()
                .starts_with(&format!("h1.{kid}."))
    };
    assert!(posts[0].iter().all(|op| under(op, KID)));
    assert!(posts[1].iter().all(|op| under(op, "89abcdef")));
    // Chunk 1, chunk 2 under the old kid (dropped), chunk 2 again.
    let pushed: Vec<usize> = recorder.seals_and_opens().0.iter().map(|c| c.ops).collect();
    assert_eq!(pushed, vec![150, 30, 30]);
}

/// Skills whose files fill more than half a request each take exactly the
/// requests sealing their chunk alone did (paths and hashes, then the files
/// packed into as few requests as fit), never a pair per skill.
#[tokio::test]
async fn large_skills_never_take_more_requests_than_sealing_chunk_by_chunk() {
    let dir = tempfile::tempdir().unwrap();
    let device = device(dir.path(), EncryptionMode::On);
    let recorder = Recorder::new(device.agent.clone());
    let relay = Arc::new(Mutex::new(KeepingRelay::default()));
    let (base, log) = stub_relay(keeping_relay(relay.clone())).await;
    let s = Store::open_in_memory().unwrap();
    for i in 0..3u8 {
        let files: std::collections::BTreeMap<String, Vec<u8>> = (0..6)
            .map(|f| (format!("part-{f}.md"), vec![b'a' + (i + f) % 26; 100 << 10]))
            .collect();
        let skill = Skill {
            scope: Scope::Global,
            project: String::new(),
            name: format!("big{i:02}"),
            version: 1,
            content_hash: skill_hash(&files),
            files,
            source_agent: "cli".into(),
            source_machine: "m1".into(),
            created_at: 1,
            deleted: false,
            seq: 0,
        };
        s.put_skill(&skill).unwrap();
        s.enqueue(&PendingOp::PushSkill {
            skill,
            base_version: 0,
        })
        .unwrap();
    }
    let (_home, ctx) = test_ctx();
    let out = run_sync(
        &s,
        Some(&client_with(&base, &device, recorder.clone())),
        &ctx,
        &NO_HARVEST,
    )
    .await
    .unwrap();
    assert!(!out.relay_error, "{:?}", out.notes);
    assert_eq!(out.pushed, 3);
    assert_eq!(
        posted_ops(&log).iter().map(Vec::len).collect::<Vec<_>>(),
        vec![3]
    );
    let (seals, _) = recorder.seals_and_opens();
    // 3 × (6 paths + 1 hash), then 18 files at 7 per request: as sealing
    // the chunk alone did, not two requests per skill.
    assert_eq!(
        seals.iter().map(|c| c.ops).collect::<Vec<_>>(),
        vec![21, 7, 7, 4]
    );
    assert!(
        seals.iter().all(|c| c.bytes <= CRYPT_BATCH_BYTES),
        "{seals:?}"
    );
}

/// Another writer acks ten ops of chunk 2 and queues ten invalidations, then
/// the agent is locked, all while chunk 1 is in flight: chunk 2 is now forty
/// ops sealed ahead plus a group of invalidations, which seals without asking
/// the agent. That proves nothing about the lock, so chunk 2 is checked and
/// stopped like any chunk sealed ahead.
#[tokio::test]
async fn a_group_of_free_ops_does_not_stand_in_for_the_unlocked_check() {
    let td = tempfile::tempdir().unwrap();
    let db = td.path().join("knowledge.db");
    let device = device(td.path(), EncryptionMode::On);
    let recorder = Recorder::new(device.agent.clone());
    let s = Store::open(&db).unwrap();
    queue(&s, (0..100).map(|i| fact(i, false)));
    let gone: Vec<i64> = s.pending().unwrap()[50..60]
        .iter()
        .map(|(n, _)| *n)
        .collect();
    let relay = Arc::new(Mutex::new(KeepingRelay::default()));
    let keeping = keeping_relay(relay.clone());
    let (agent, sealed, other_writer, first) = (
        device.agent.clone(),
        recorder.clone(),
        db.clone(),
        AtomicBool::new(true),
    );
    let (base, log) = stub_relay(Box::new(move |m, p, body| {
        if m == "POST" && first.swap(false, Ordering::SeqCst) {
            assert!(wait_for(Duration::from_secs(2), || sealed.calls().len() == 2));
            let other = Store::open(&other_writer).unwrap();
            for (i, n) in gone.iter().enumerate() {
                other.ack(*n).unwrap();
                other
                    .enqueue(&PendingOp::InvalidateMemory {
                        id: format!("mem_gone_{i}"),
                        invalid_at: T0,
                        superseded_by: None,
                    })
                    .unwrap();
            }
            agent.lock_keys().unwrap();
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
    assert!(out.relay_error, "{:?}", out.notes);
    assert!(
        out.notes.iter().any(|n| n.contains("atem cred unlock")),
        "{:?}",
        out.notes
    );
    assert_eq!(out.pushed, 50);
    assert_eq!(
        posted_ops(&log).iter().map(Vec::len).collect::<Vec<_>>(),
        vec![50]
    );
    assert_eq!(s.pending_count().unwrap(), 50);
    let calls = recorder.calls();
    assert_eq!(
        calls.iter().map(|c| (c.ops, c.ok)).collect::<Vec<_>>(),
        vec![(100, true), (100, true), (50, false)]
    );
}

/// Deletes and invalidations carry no sealed field: sealing them never asks
/// the cred agent, so they are never "sealed by an earlier request". A push
/// of only those goes out while the agent is locked, as before read-ahead,
/// and never contacts the agent (in production, a request would start it).
#[tokio::test]
async fn deletes_and_invalidations_alone_are_pushed_while_the_agent_is_locked() {
    let dir = tempfile::tempdir().unwrap();
    let device = device(dir.path(), EncryptionMode::On);
    device.agent.lock_keys().unwrap();
    let recorder = Recorder::new(device.agent.clone());
    let relay = Arc::new(Mutex::new(KeepingRelay::default()));
    let (base, log) = stub_relay(keeping_relay(relay.clone())).await;
    let s = Store::open_in_memory().unwrap();
    // Two chunks: chunk 1 sealed alone, chunk 2 sealed ahead of its POST.
    for i in 0..60 {
        s.enqueue(&if i % 3 == 0 {
            PendingOp::DeleteMemory {
                id: format!("mem_deleted_{i}"),
            }
        } else {
            PendingOp::InvalidateMemory {
                id: format!("mem_outdated_{i}"),
                invalid_at: T0,
                superseded_by: None,
            }
        })
        .unwrap();
    }
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
    assert_eq!(out.pushed, 60);
    assert_eq!(
        posted_ops(&log).iter().map(Vec::len).collect::<Vec<_>>(),
        vec![50, 10]
    );
    assert_eq!(s.pending_count().unwrap(), 0);
    assert_eq!(recorder.requests(), 0);
}

/// A global skill's purge (erasing its files on the relay, e.g. a leaked
/// value) and delete carry no project hash: they go out while the agent is
/// locked, without contacting it.
#[tokio::test]
async fn a_global_skill_purge_is_pushed_while_the_agent_is_locked() {
    let dir = tempfile::tempdir().unwrap();
    let device = device(dir.path(), EncryptionMode::On);
    device.agent.lock_keys().unwrap();
    let recorder = Recorder::new(device.agent.clone());
    let relay = Arc::new(Mutex::new(KeepingRelay::default()));
    let (base, log) = stub_relay(keeping_relay(relay.clone())).await;
    let s = Store::open_in_memory().unwrap();
    s.enqueue(&PendingOp::PurgeSkill {
        scope: Scope::Global,
        project: String::new(),
        name: "leaked".into(),
        versions: None,
    })
    .unwrap();
    s.enqueue(&PendingOp::DeleteSkill {
        scope: Scope::Global,
        project: String::new(),
        name: "old".into(),
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
    assert!(out.notes.is_empty() && !out.relay_error, "{:?}", out.notes);
    assert_eq!(out.pushed, 2);
    let posts = posted_ops(&log);
    assert_eq!(
        posts[0]
            .iter()
            .map(|op| op["op"].as_str().unwrap())
            .collect::<Vec<_>>(),
        vec!["purge", "delete"]
    );
    assert_eq!(posts.len(), 1);
    assert_eq!(s.pending_count().unwrap(), 0);
    assert_eq!(recorder.requests(), 0);
}

/// `atem cred lock` lands while chunk 1 is in flight, after the next group
/// (chunks 2 and 3) was sealed: chunk 2, only invalidations, needs no agent
/// and still goes out; chunk 3, facts sealed before the lock, is checked and
/// stopped.
#[tokio::test]
async fn after_a_lock_free_ops_go_and_ops_sealed_ahead_stop() {
    let dir = tempfile::tempdir().unwrap();
    let device = device(dir.path(), EncryptionMode::On);
    let recorder = Recorder::new(device.agent.clone());
    let relay = Arc::new(Mutex::new(KeepingRelay::default()));
    let keeping = keeping_relay(relay.clone());
    let (agent, sealed, first) = (
        device.agent.clone(),
        recorder.clone(),
        AtomicBool::new(true),
    );
    let (base, log) = stub_relay(Box::new(move |m, p, body| {
        if m == "POST" && first.swap(false, Ordering::SeqCst) {
            assert!(wait_for(Duration::from_secs(2), || sealed.calls().len() == 2));
            agent.lock_keys().unwrap();
        }
        keeping(m, p, body)
    }))
    .await;
    let s = Store::open_in_memory().unwrap();
    queue(&s, (0..50).map(|i| fact(i, false)));
    for i in 0..50 {
        s.enqueue(&PendingOp::InvalidateMemory {
            id: format!("mem_outdated_{i}"),
            invalid_at: T0,
            superseded_by: None,
        })
        .unwrap();
    }
    queue(&s, (50..100).map(|i| fact(i, false)));
    let queued = s.pending().unwrap();
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
        out.notes.iter().any(|n| n.contains("atem cred unlock")),
        "{:?}",
        out.notes
    );
    assert_eq!(out.pushed, 100);
    let posts = posted_ops(&log);
    assert_eq!(posts.iter().map(Vec::len).collect::<Vec<_>>(), vec![50, 50]);
    assert!(posts[1].iter().all(|op| op["op"] == "invalidate"));
    assert_eq!(s.pending().unwrap(), queued[100..].to_vec());
    // Chunk 1, then chunks 2 and 3 in one request; the check before chunk 3
    // only, then the pull's refused open.
    assert_eq!(recorder.statuses(), 1);
    assert_eq!(
        recorder
            .calls()
            .iter()
            .map(|c| (c.ops, c.ok))
            .collect::<Vec<_>>(),
        vec![(100, true), (100, true), (50, false)]
    );
}

/// A chunk refused as too large (413) is sent again one op at a time. A lock
/// while it was in flight stops the first op the agent sealed; the free ops
/// before it still go.
#[tokio::test]
async fn a_chunk_refused_as_too_large_sends_its_free_ops_after_a_lock() {
    let dir = tempfile::tempdir().unwrap();
    let device = device(dir.path(), EncryptionMode::On);
    let recorder = Recorder::new(device.agent.clone());
    let relay = Arc::new(Mutex::new(KeepingRelay::default()));
    let keeping = keeping_relay(relay.clone());
    let (agent, first) = (device.agent.clone(), AtomicBool::new(true));
    let (base, log) = stub_relay(Box::new(move |m, p, body| {
        if m != "POST" {
            return keeping(m, p, body);
        }
        if first.swap(false, Ordering::SeqCst) {
            agent.lock_keys().unwrap();
        }
        if body["ops"].as_array().unwrap().len() > 1 {
            return (413, serde_json::json!({"error": "request body too large"}));
        }
        keeping(m, p, body)
    }))
    .await;
    let s = Store::open_in_memory().unwrap();
    for i in 0..2 {
        s.enqueue(&PendingOp::InvalidateMemory {
            id: format!("mem_outdated_{i}"),
            invalid_at: T0,
            superseded_by: None,
        })
        .unwrap();
    }
    queue(&s, [fact(0, false)]);
    let queued = s.pending().unwrap();
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
        out.notes.iter().any(|n| n.contains("atem cred unlock")),
        "{:?}",
        out.notes
    );
    assert_eq!(out.pushed, 2);
    assert_eq!(
        posted_ops(&log).iter().map(Vec::len).collect::<Vec<_>>(),
        vec![3, 1, 1]
    );
    assert_eq!(s.pending().unwrap(), queued[2..].to_vec());
    assert_eq!(recorder.statuses(), 1);
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
    // Every field sealed once.
    assert_eq!(
        seals.iter().map(|c| c.ops).sum::<usize>(),
        2500 + 20 * 4 + 20 * 3
    );
    assert_eq!(
        seals.len(),
        // Facts: chunk 1 alone, then 2,340 ops; skills: two chunks of two requests.
        2340usize.div_ceil(CRYPT_BATCH_OPS) + 1 + 2 * 2,
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

// ─────────────── projects not known here yet (#132) in the pipeline ───────────────

/// A project this device never used: it has no name for its hash.
const ELSEWHERE: &str = "github.com/agora/elsewhere";

/// `ELSEWHERE`'s hash under this device's key, recorded nowhere.
fn unnamed(device: &UnlockedDevice) -> String {
    context(device).keyed_hash(ELSEWHERE.as_bytes()).unwrap()
}

/// The relay's rows `ids` moved to the project `hash`.
fn move_to(relay: &Mutex<KeepingRelay>, ids: &[&str], hash: &str) {
    let mut r = relay.lock().unwrap();
    for id in ids {
        let row = r.rows.get_mut(*id).unwrap();
        row.scope = Scope::Project;
        row.project = hash.into();
    }
}

/// Records every row a pulled page applies, in a temp table the page's own
/// transaction writes: a page rolled back leaves nothing there.
fn count_applied(s: &Store) {
    s.test_conn()
        .execute_batch(
            "CREATE TEMP TABLE applied (id TEXT NOT NULL);
             CREATE TEMP TRIGGER count_applied BEFORE INSERT ON memories BEGIN INSERT INTO applied VALUES (new.id); END;",
        )
        .unwrap();
}

/// Rows applied by committed pages, and how many of them are distinct.
fn applied(s: &Store) -> (i64, i64) {
    s.test_conn()
        .query_row(
            "SELECT COUNT(*), COUNT(DISTINCT id) FROM applied",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap()
}

/// A recorder that also collects the records every `Crypt` request opens.
fn recording_opens(device: &UnlockedDevice) -> (Arc<Recorder>, Arc<Mutex<Vec<String>>>) {
    let opened: Arc<Mutex<Vec<String>>> = Default::default();
    let seen = opened.clone();
    let recorder = Recorder::with_hook(
        device.agent.clone(),
        Box::new(move |_, ops, _| {
            seen.lock()
                .unwrap()
                .extend(ops.iter().filter_map(|op| match op {
                    CryptOp::Open { record, .. } => Some(record.clone()),
                    _ => None,
                }));
        }),
    );
    (recorder, opened)
}

/// Pages 2 and 3 carry rows of a project this device can't name, and each is
/// opened while the page before it is applied: those rows are kept as they
/// came (unresolved, content opened), committed with their page and its
/// cursor; no page is fetched again, and every row is applied once.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unresolved_rows_on_a_page_opened_ahead_commit_with_their_page() {
    use rusqlite::functions::FunctionFlags;
    let dir = tempfile::tempdir().unwrap();
    let device = device(dir.path(), EncryptionMode::On);
    let relay = Arc::new(Mutex::new(KeepingRelay::default()));
    seed_sealed(&relay, &device, 450);
    let hash = unnamed(&device);
    // The first and last rows of page 2, and the first of page 3.
    let moved = ["mem_r0201", "mem_r0400", "mem_r0401"];
    move_to(&relay, &moved, &hash);
    let (base, log) = stub_relay(keeping_relay(relay.clone())).await;
    let (recorder, opened) = recording_opens(&device);
    let s = Store::open_in_memory().unwrap();
    count_applied(&s);
    // The last insert of pages 1 and 2 waits (bounded) for the next page's
    // open to reach the agent.
    let overlaps = Arc::new(AtomicUsize::new(0));
    let (counted, opens) = (overlaps.clone(), opened.clone());
    s.test_conn()
        .create_scalar_function("wait_for_open", 1, FunctionFlags::SQLITE_UTF8, move |f| {
            let id: String = f.get(0)?;
            if wait_for(Duration::from_secs(2), || {
                opens.lock().unwrap().contains(&id)
            }) {
                counted.fetch_add(1, Ordering::SeqCst);
            }
            Ok(0i64)
        })
        .unwrap();
    s.test_conn()
        .execute_batch(
            "CREATE TEMP TRIGGER page_one_last BEFORE INSERT ON memories WHEN new.id = 'mem_r0200' BEGIN SELECT wait_for_open('mem_r0201'); END;
             CREATE TEMP TRIGGER page_two_last BEFORE INSERT ON memories WHEN new.id = 'mem_r0400' BEGIN SELECT wait_for_open('mem_r0401'); END;",
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
    assert_eq!(
        overlaps.load(Ordering::SeqCst),
        2,
        "pages 2 and 3 weren't opened while the page before them was applied"
    );
    assert_eq!(out.pulled, 450);
    assert_eq!(memory_gets(&log), vec![0, 200, 400]);
    assert_eq!(s.get_state(&memory_cursor_key(ASTATION_ID)).unwrap(), 450);
    assert_eq!(
        applied(&s),
        (450, 450),
        "a row applied twice, or not at all"
    );
    // Every row as a pull opens it: the moved ones under the hash.
    let want = context(&device)
        .decrypt_pulled_memories(relay.lock().unwrap().rows.values().cloned().collect())
        .unwrap();
    assert_eq!(s.history_memories().unwrap().len(), 450);
    for row in want {
        assert_eq!(
            s.get_memory(&row.id).unwrap().as_ref(),
            Some(&row),
            "{}",
            row.id
        );
    }
    for id in moved {
        let kept = s.get_memory(id).unwrap().unwrap();
        assert!(
            kept.has_unresolved_project() && kept.project == hash,
            "{id}"
        );
        assert!(kept.content.starts_with("remote fact"), "{id}");
    }
    // Still unresolved after the sync's resolve step: one open per page,
    // nothing else asked of the agent.
    assert_eq!(s.unresolved_projects().unwrap(), vec![hash]);
    let (seals, page_opens) = recorder.seals_and_opens();
    assert!(seals.is_empty(), "{seals:?}");
    assert_eq!(page_opens.len(), 3);
}

/// Page 2's transaction fails after page 3, which carries rows of a project
/// this device can't name, was opened: page 3 is dropped unapplied (none of
/// its rows stored, unresolved or not), the cursor stays at page 1, and the
/// next sync applies pages 2 and 3 once, the rows kept unresolved.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_page_that_fails_after_the_next_with_unresolved_rows_was_opened_drops_it() {
    use rusqlite::functions::FunctionFlags;
    let dir = tempfile::tempdir().unwrap();
    let device = device(dir.path(), EncryptionMode::On);
    let relay = Arc::new(Mutex::new(KeepingRelay::default()));
    seed_sealed(&relay, &device, 600);
    let hash = unnamed(&device);
    let moved = ["mem_r0401", "mem_r0450", "mem_r0600"];
    move_to(&relay, &moved, &hash);
    let (base, log) = stub_relay(keeping_relay(relay.clone())).await;
    let (recorder, opened) = recording_opens(&device);
    let s = Store::open_in_memory().unwrap();
    count_applied(&s);
    let opened_three = Arc::new(AtomicBool::new(false));
    let (seen, calls) = (opened_three.clone(), recorder.clone());
    s.test_conn()
        .create_scalar_function(
            "stop_after_page_three",
            0,
            FunctionFlags::SQLITE_UTF8,
            move |_| -> rusqlite::Result<i64> {
                seen.store(
                    wait_for(Duration::from_secs(2), || calls.calls().len() >= 3),
                    Ordering::SeqCst,
                );
                Err(rusqlite::Error::UserFunctionError("injected stop".into()))
            },
        )
        .unwrap();
    s.test_conn()
        .execute_batch("CREATE TEMP TRIGGER stop_mid_page BEFORE INSERT ON memories WHEN new.id = 'mem_r0300' BEGIN SELECT stop_after_page_three(); END;")
        .unwrap();
    let (_home, ctx) = test_ctx();
    let client = client_with(&base, &device, recorder.clone());
    let err = run_sync(&s, Some(&client), &ctx, &NO_HARVEST)
        .await
        .unwrap_err();
    assert!(format!("{err:#}").contains("injected stop"), "{err:#}");
    assert!(
        opened_three.load(Ordering::SeqCst)
            && opened.lock().unwrap().iter().any(|id| id == "mem_r0401"),
        "page 3 wasn't opened during page 2's transaction"
    );
    assert_eq!(s.get_state(&memory_cursor_key(ASTATION_ID)).unwrap(), 200);
    assert_eq!(s.history_memories().unwrap().len(), 200);
    assert!(s.history_memories().unwrap().iter().all(|m| m.seq <= 200));
    assert!(
        s.unresolved_projects().unwrap().is_empty(),
        "page 3 left a row"
    );
    assert_eq!(applied(&s), (200, 200));

    s.test_conn()
        .execute_batch("DROP TRIGGER stop_mid_page;")
        .unwrap();
    log.lock().unwrap().clear();
    let out = run_sync(&s, Some(&client), &ctx, &NO_HARVEST)
        .await
        .unwrap();
    assert!(out.notes.is_empty() && !out.relay_error, "{:?}", out.notes);
    assert_eq!(out.pulled, 400);
    assert_eq!(memory_gets(&log), vec![200, 400, 600]);
    assert_eq!(s.get_state(&memory_cursor_key(ASTATION_ID)).unwrap(), 600);
    assert_eq!(s.history_memories().unwrap().len(), 600);
    assert_eq!(
        applied(&s),
        (600, 600),
        "a row applied twice, or not at all"
    );
    for id in moved {
        let kept = s.get_memory(id).unwrap().unwrap();
        assert!(
            kept.has_unresolved_project() && kept.project == hash,
            "{id}"
        );
    }
    assert_eq!(s.unresolved_projects().unwrap(), vec![hash]);
}

/// A fact queued under a project hash this device couldn't name (a
/// replacement of an unresolved fact) is sealed ahead as it came. While the
/// chunk before it is in flight, resolution names that hash (the name
/// recorded, the row moved to it by another writer): the fact is sealed again
/// under its name, never sent under the hash it was sealed with. Under on the
/// queued hash is an earlier key's and the name is hashed under the current
/// key; under off the name goes plain. A fact under a hash still unknown is
/// sent as sealed ahead, exactly as it came.
#[tokio::test]
async fn an_op_whose_project_hash_is_named_after_it_was_sealed_is_sealed_again() {
    let named = format!("h1.89abcdef.{}", "cd".repeat(32));
    let unknown = format!("h1.89abcdef.{}", "ef".repeat(32));
    for mode in [EncryptionMode::On, EncryptionMode::Off] {
        let td = tempfile::tempdir().unwrap();
        let db = td.path().join("knowledge.db");
        let mut device = device(td.path(), EncryptionMode::On);
        if mode == EncryptionMode::Off {
            device.state(EncryptionMode::Off, None);
        }
        let recorder = Recorder::new(device.agent.clone());
        let s = Store::open(&db).unwrap();
        // Chunk 1: 50 facts. Chunk 2: 8 facts, then one fact under each hash.
        queue(&s, (0..58).map(|i| fact(i, false)));
        let under = |id: &str, project: &str| {
            let mut m = valid(id, &format!("{id} deploys on mondays"));
            m.scope = Scope::Project;
            m.project = project.into();
            m
        };
        queue(
            &s,
            [under("mem_named", &named), under("mem_unknown", &unknown)],
        );
        let relay = Arc::new(Mutex::new(KeepingRelay::default()));
        let keeping = keeping_relay(relay.clone());
        let (sealed, names, account) = (
            recorder.clone(),
            device.paths.project_names.clone(),
            context(&device).data_account,
        );
        let (other_writer, hash, first) = (db.clone(), named.clone(), AtomicBool::new(true));
        let (base, log) = stub_relay(Box::new(move |m, p, body| {
            if m == "POST" && first.swap(false, Ordering::SeqCst) {
                // Chunk 2 is sealed first: under on, its request has come
                // back; under off it needed no agent and was sealed in the
                // same poll that sent chunk 1.
                if mode == EncryptionMode::On {
                    assert!(wait_for(Duration::from_secs(2), || sealed.calls().len() == 2));
                }
                let resolved = [(hash.clone(), ELSEWHERE.to_string())];
                crate::memory::project_names::remember(&names, &account, resolved.clone()).unwrap();
                Store::open(&other_writer)
                    .unwrap()
                    .resolve_projects(&resolved, &[])
                    .unwrap();
            }
            keeping(m, p, body)
        }))
        .await;
        let (_home, ctx) = test_ctx();
        let client = client_with(&base, &device, recorder.clone());
        let out = run_sync(&s, Some(&client), &ctx, &NO_HARVEST)
            .await
            .unwrap();
        assert_eq!(out.pushed, 60, "{mode:?}: {:?}", out.notes);
        let posts = posted_ops(&log);
        assert_eq!(
            posts.iter().map(Vec::len).collect::<Vec<_>>(),
            vec![50, 10],
            "{mode:?}"
        );
        let sent = |id: &str| {
            posts[1].iter().find(|op| op["memory"]["id"] == id).unwrap()["memory"]["project"]
                .as_str()
                .unwrap()
                .to_string()
        };
        let want = if mode == EncryptionMode::On {
            context(&device).wire_project(ELSEWHERE).unwrap()
        } else {
            ELSEWHERE.to_string()
        };
        assert_eq!(sent("mem_named"), want, "{mode:?}");
        assert_eq!(
            sent("mem_unknown"),
            unknown,
            "{mode:?}: an unknown hash goes as it came"
        );
        assert!(
            !serde_json::to_string(&posts).unwrap().contains(&named),
            "{mode:?}: sent under the hash it was sealed with"
        );
        if mode == EncryptionMode::On {
            // Chunk 1, chunk 2 ahead (no project hashed), then the named fact
            // alone again (its project, content hash and content); the
            // others of chunk 2 went as sealed ahead, its seal showing the
            // agent unlocked.
            let seals: Vec<usize> = recorder.seals_and_opens().0.iter().map(|c| c.ops).collect();
            assert_eq!(seals, vec![100, 20, 3]);
            assert_eq!(recorder.statuses(), 0);
        } else {
            assert_eq!(recorder.requests(), 0, "off never asks the agent");
        }
        assert_eq!(s.pending_count().unwrap(), 0);
    }
}

// ─────────────── skill files on the wire (F8) ───────────────

/// A skill with `SKILL.md` and an empty `.gitkeep`.
fn skill_with_an_empty_file(machine: &str) -> Skill {
    let mut skill = super::tests::skill_v1("deploy", "# deploy steps", machine);
    skill.files.insert(".gitkeep".into(), Vec::new());
    skill.content_hash = skill_hash(&skill.files);
    skill
}

/// The skill requests of `log`, as (method, path without the query).
fn skill_requests(log: &Log) -> Vec<(String, String)> {
    log.lock()
        .unwrap()
        .iter()
        .filter(|(_, p, _)| p.starts_with("/api/skills"))
        .map(|(m, p, _)| (m.clone(), p.split('?').next().unwrap().to_string()))
        .collect()
}

/// A sealed skill goes out as `e1-text`: each file's `e1.` text as it is
/// (encoded once), an empty file as `""` (never sealed). The Station stores
/// it as the old wire did, and another machine pulls it back whole.
#[tokio::test]
async fn a_skill_with_an_empty_file_travels_as_e1_text_and_comes_back_whole() {
    let dir = tempfile::tempdir().unwrap();
    let device = device(dir.path(), EncryptionMode::On);
    let relay = Arc::new(Mutex::new(KeepingRelay::default()));
    let (base, log) = stub_relay(keeping_relay(relay.clone())).await;
    let s = Store::open_in_memory().unwrap();
    let skill = skill_with_an_empty_file("m1");
    s.put_skill(&skill).unwrap();
    s.enqueue(&PendingOp::PushSkill {
        skill: skill.clone(),
        base_version: 0,
    })
    .unwrap();
    let client = client_with(&base, &device, device.agent.clone());
    let (_home, ctx) = test_ctx();
    let out = run_sync(&s, Some(&client), &ctx, &NO_HARVEST)
        .await
        .unwrap();
    assert!(out.notes.is_empty() && !out.relay_error, "{:?}", out.notes);
    assert_eq!(out.pushed, 1);
    let posts = posted_ops(&log);
    let sent = &posts[0][0]["skill"];
    assert_eq!(sent["files_encoding"], "e1-text");
    let envelope = format!("e1.{KID}.");
    let files = sent["files"].as_object().unwrap();
    assert_eq!(files.len(), 2);
    assert!(files.keys().all(|path| path.starts_with(&envelope)));
    let mut values: Vec<&str> = files.values().map(|v| v.as_str().unwrap()).collect();
    values.sort();
    assert!(values[0].is_empty() && values[1].starts_with(&envelope));
    // Stored as the old wire stored it: the same e1 text, "" for the empty
    // file (base64 of nothing is nothing).
    let stored = relay
        .lock()
        .unwrap()
        .skills
        .values()
        .next()
        .unwrap()
        .clone();
    assert_eq!(stored.files.len(), 2);
    for (path, value) in files {
        assert_eq!(stored.files[path], value.as_str().unwrap().as_bytes());
    }
    assert_eq!(
        crate::memory::fake_station_skills::row(&stored)["files_encoding"],
        "e1-text"
    );

    // Another machine pulls it back whole: the same files and hash.
    let other = Store::open_in_memory().unwrap();
    let (_home, ctx) = test_ctx();
    let out = run_sync(&other, Some(&client), &ctx, &NO_HARVEST)
        .await
        .unwrap();
    assert!(out.notes.is_empty() && !out.relay_error, "{:?}", out.notes);
    let pulled = other
        .get_skill(Scope::Global, "", "deploy")
        .unwrap()
        .unwrap();
    assert_eq!(pulled.files, skill.files);
    assert_eq!(pulled.content_hash, skill_hash(&skill.files));
    assert!(
        skill_requests(&log)
            .iter()
            .all(|(_, p)| p.starts_with("/api/skills"))
    );
}

/// A sealed skill with an empty file in a `base64` row (the stored form;
/// the Station serves such a row as `e1-text`, but a `base64` row of any
/// bytes is valid): the client reads it as the same bytes and opens it
/// whole.
#[tokio::test]
async fn a_sealed_skill_with_an_empty_file_served_as_base64_opens_whole() {
    let dir = tempfile::tempdir().unwrap();
    let device = device(dir.path(), EncryptionMode::On);
    let skill = skill_with_an_empty_file("m2");
    let mut sealed = context(&device).encrypt_skill(skill.clone()).unwrap();
    sealed.seq = 5;
    assert!(sealed.files.values().any(Vec::is_empty));
    let mut row = serde_json::to_value(&sealed).unwrap();
    row["files_encoding"] = serde_json::json!("base64");
    let relay = Arc::new(Mutex::new(KeepingRelay::default()));
    let keeping = keeping_relay(relay);
    let (base, _log) = stub_relay(Box::new(move |m, p, body| {
        if m == "GET" && p.starts_with("/api/skills?") {
            let rows = if since(p) < 5 {
                vec![row.clone()]
            } else {
                Vec::new()
            };
            return (200, serde_json::json!({"skills": rows}));
        }
        keeping(m, p, body)
    }))
    .await;
    let s = Store::open_in_memory().unwrap();
    let (_home, ctx) = test_ctx();
    let client = client_with(&base, &device, device.agent.clone());
    let out = run_sync(&s, Some(&client), &ctx, &NO_HARVEST)
        .await
        .unwrap();
    assert!(out.notes.is_empty() && !out.relay_error, "{:?}", out.notes);
    assert_eq!(out.pulled, 1);
    let pulled = s.get_skill(Scope::Global, "", "deploy").unwrap().unwrap();
    assert_eq!(pulled.files, skill.files);
    assert_eq!(pulled.content_hash, skill_hash(&skill.files));
}

/// A skill push whose outcome is unknown (the connection closed with no
/// answer) stays queued and goes again by the same route in the same
/// format: never in another format.
///
/// Here the Station hadn't applied the first POST. A known pre-existing
/// bug (not F8's; the legacy wire had it too) makes the other
/// case unreadable: the Station stores every push as `max(version) + 1`,
/// but a sealed skill's associated data names the version it was sealed
/// under (`scope:name:version`). A sealed push the Station had already
/// applied is stored again under a version its envelopes don't name, and
/// every reader's skill pull then fails ("encrypted field authentication
/// failed"); a concurrent push from another machine does the same. The
/// owner decided the fix on Atem #130 (comment 6726291208): the Station
/// stores the version the push was sealed under, or answers
/// `version_conflict`.
#[tokio::test]
async fn an_uncertain_skill_push_goes_again_in_the_same_format() {
    let dir = tempfile::tempdir().unwrap();
    let device = device(dir.path(), EncryptionMode::On);
    let relay = Arc::new(Mutex::new(KeepingRelay::default()));
    let keeping = keeping_relay(relay.clone());
    let first = AtomicBool::new(true);
    let (base, log) = stub_relay(Box::new(move |m, p, body| {
        if m == "POST" && first.swap(false, Ordering::SeqCst) {
            return (0, serde_json::Value::Null);
        }
        keeping(m, p, body)
    }))
    .await;
    let s = Store::open_in_memory().unwrap();
    let skill = skill_with_an_empty_file("m1");
    s.put_skill(&skill).unwrap();
    s.enqueue(&PendingOp::PushSkill {
        skill,
        base_version: 0,
    })
    .unwrap();
    let client = client_with(&base, &device, device.agent.clone());
    let (_home, ctx) = test_ctx();
    let out = run_sync(&s, Some(&client), &ctx, &NO_HARVEST)
        .await
        .unwrap();
    assert!(out.offline, "{:?}", out.notes);
    assert_eq!(s.pending_count().unwrap(), 1);
    let out = run_sync(&s, Some(&client), &ctx, &NO_HARVEST)
        .await
        .unwrap();
    assert!(!out.offline && !out.relay_error, "{:?}", out.notes);
    assert_eq!(s.pending_count().unwrap(), 0);
    assert_eq!(relay.lock().unwrap().skills.len(), 1);
    let posts = posted_ops(&log);
    assert_eq!(posts.len(), 2);
    for post in &posts {
        assert_eq!(post[0]["skill"]["files_encoding"], "e1-text");
    }
    let requests = skill_requests(&log);
    assert!(
        requests.iter().all(|(_, p)| p.starts_with("/api/skills")),
        "{requests:?}"
    );
    assert_eq!(
        requests.iter().filter(|(m, _)| m == "POST").count(),
        2,
        "{requests:?}"
    );
}

/// A migration rewrites a skill with an empty file as `e1-text` (the empty
/// file `""`) while enabling, and back as `base64` while disabling: the
/// stored row ends as it started, and both read-backs pass.
#[tokio::test]
async fn a_migration_rewrites_an_empty_skill_file_as_e1_text_and_back_as_base64() {
    let dir = tempfile::tempdir().unwrap();
    let mut device = device(dir.path(), EncryptionMode::Enabling);
    let relay = Arc::new(Mutex::new(KeepingRelay::default()));
    let skill = skill_with_an_empty_file("m2");
    relay.lock().unwrap().put_skill(skill.clone());
    let (base, log) = stub_relay(keeping_relay(relay.clone())).await;
    let client = client_with(&base, &device, device.agent.clone());
    client.migrate_encryption().await.unwrap();
    let rewrite = posted_ops(&log)[0][0].clone();
    assert_eq!(rewrite["op"], "rewrite");
    assert_eq!(rewrite["files_encoding"], "e1-text");
    let envelope = format!("e1.{KID}.");
    let mut values: Vec<&str> = rewrite["files"]
        .as_object()
        .unwrap()
        .values()
        .map(|v| v.as_str().unwrap())
        .collect();
    values.sort();
    assert!(values[0].is_empty() && values[1].starts_with(&envelope));
    client.verify_encryption_migration().await.unwrap();
    let sealed = relay
        .lock()
        .unwrap()
        .skills
        .values()
        .next()
        .unwrap()
        .clone();
    assert!(sealed.files.values().any(Vec::is_empty));

    device.state(EncryptionMode::Disabling, Some(KID));
    client.migrate_encryption().await.unwrap();
    let posts = posted_ops(&log);
    let rewrite = &posts.last().unwrap()[0];
    assert_eq!(rewrite["files_encoding"], "base64");
    client.verify_encryption_migration().await.unwrap();
    let plain = relay
        .lock()
        .unwrap()
        .skills
        .values()
        .next()
        .unwrap()
        .clone();
    assert_eq!(
        Skill {
            seq: skill.seq,
            ..plain
        },
        Skill {
            seq: skill.seq,
            ..skill
        }
    );
    assert!(
        skill_requests(&log)
            .iter()
            .all(|(_, p)| p.starts_with("/api/skills"))
    );
}

// ─────────────── skill versions: compare-and-set, holds ───────────────

use crate::memory::fake_station_skills::Versioning;

/// Queues a push of `skill` on `base_version` (as `atem skill add` does).
fn queue_skill(s: &Store, skill: Skill, base_version: i64) {
    s.put_skill(&skill).unwrap();
    s.enqueue(&PendingOp::PushSkill {
        skill,
        base_version,
    })
    .unwrap();
}

fn a_relay(versioning: Versioning) -> Arc<Mutex<KeepingRelay>> {
    Arc::new(Mutex::new(KeepingRelay::with(versioning)))
}

fn versions(relay: &Mutex<KeepingRelay>, name: &str) -> Vec<i64> {
    let r = relay.lock().unwrap();
    let mut versions: Vec<i64> = r
        .skills
        .values()
        .filter(|k| k.name == name)
        .map(|k| k.version)
        .collect();
    versions.sort();
    versions
}

fn clean(out: &SyncOutcome) {
    assert!(
        out.notes.is_empty() && !out.relay_error && !out.offline,
        "{:?}",
        out.notes
    );
}

const CONCURRENT: &str = "another machine pushed an edit at the same time";

/// A push the Station applied but whose answer was lost goes again at the
/// same version: the Station answers `version_conflict`, Atem reads that
/// version, finds its own write (the same content hash and metadata; the
/// files differ only in their nonces) and acks it. One row, readable.
#[tokio::test]
async fn an_applied_push_whose_answer_was_lost_is_acked_once_its_conflict_is_checked() {
    let dir = tempfile::tempdir().unwrap();
    let device = device(dir.path(), EncryptionMode::On);
    let relay = a_relay(Versioning::Kept);
    let keeping = keeping_relay(relay.clone());
    let first = AtomicBool::new(true);
    let (base, log) = stub_relay(Box::new(move |m, p, body| {
        let answer = keeping(m, p, body);
        if m == "POST" && first.swap(false, Ordering::SeqCst) {
            // Applied, never answered.
            return (0, serde_json::Value::Null);
        }
        answer
    }))
    .await;
    let s = Store::open_in_memory().unwrap();
    let skill = skill_with_an_empty_file("m1");
    queue_skill(&s, skill.clone(), 0);
    let client = client_with(&base, &device, device.agent.clone());
    let (_home, ctx) = test_ctx();
    let out = run_sync(&s, Some(&client), &ctx, &NO_HARVEST)
        .await
        .unwrap();
    assert!(out.offline, "{:?}", out.notes);
    assert_eq!(s.pending_count().unwrap(), 1);
    let out = run_sync(&s, Some(&client), &ctx, &NO_HARVEST)
        .await
        .unwrap();
    clean(&out);
    assert_eq!(s.pending_count().unwrap(), 0);
    assert_eq!(versions(&relay, "deploy"), vec![1]);
    assert_eq!(
        skill_requests(&log),
        [
            ("POST", "/api/skills/batch"),
            ("POST", "/api/skills/batch"),
            ("GET", "/api/skills/version"),
            ("GET", "/api/skills"),
        ]
        .map(|(m, p)| (m.to_string(), p.to_string()))
    );
    let local = s.get_skill(Scope::Global, "", "deploy").unwrap().unwrap();
    assert_eq!(
        (local.version, local.files.clone()),
        (1, skill.files.clone())
    );

    // Another machine reads it whole.
    let other = Store::open_in_memory().unwrap();
    let (_home, ctx) = test_ctx();
    clean(
        &run_sync(&other, Some(&client), &ctx, &NO_HARVEST)
            .await
            .unwrap(),
    );
    let pulled = other
        .get_skill(Scope::Global, "", "deploy")
        .unwrap()
        .unwrap();
    assert_eq!(pulled.files, skill.files);
}

/// Two machines push the same skill at the same version: the first is
/// stored; the second meets `version_conflict`, finds another machine's
/// edit there, re-bases onto the next version (sealed again at the next
/// sync) and lands. Every device reads both versions.
#[tokio::test]
async fn two_machines_pushing_the_same_skill_keep_both_versions_readable() {
    let dir = tempfile::tempdir().unwrap();
    let device = device(dir.path(), EncryptionMode::On);
    let relay = a_relay(Versioning::Kept);
    let (base, _log) = stub_relay(keeping_relay(relay.clone())).await;
    let client = client_with(&base, &device, device.agent.clone());
    let (a, b) = (
        Store::open_in_memory().unwrap(),
        Store::open_in_memory().unwrap(),
    );
    let edit_a = super::tests::skill_v1("deploy", "# deploy, as machine a has it", "m1");
    let edit_b = super::tests::skill_v1("deploy", "# deploy, as machine b has it", "m2");
    queue_skill(&a, edit_a.clone(), 0);
    queue_skill(&b, edit_b.clone(), 0);
    let ((_ha, ctx_a), (_hb, ctx_b)) = (test_ctx(), test_ctx());
    clean(
        &run_sync(&a, Some(&client), &ctx_a, &NO_HARVEST)
            .await
            .unwrap(),
    );

    let out = run_sync(&b, Some(&client), &ctx_b, &NO_HARVEST)
        .await
        .unwrap();
    // What is true now: A's v1 is the latest; B's edit goes on top next.
    assert_eq!(
        out.notes,
        vec![format!(
            "skill deploy: {CONCURRENT}; its v1 is the latest for now, and this machine's edit will be pushed on top as v2 at the next sync. Both versions are kept: see them with `atem skill history deploy`."
        )]
    );
    assert!(!out.relay_error && !out.offline);
    // The conflicted push wasn't acked: not counted as pushed.
    assert_eq!((out.pushed, out.rebased), (0, 1));
    let queued = b.pending().unwrap();
    assert_eq!(queued.len(), 1);
    match &queued[0].1 {
        PendingOp::PushSkill {
            skill,
            base_version,
        } => {
            assert_eq!((skill.version, *base_version), (2, 1));
            assert_eq!(skill.files, edit_b.files);
        }
        other => panic!("{other:?}"),
    }
    // The local edit moved with it: A's pulled v1 doesn't replace it.
    let local = b.get_skill(Scope::Global, "", "deploy").unwrap().unwrap();
    assert_eq!((local.version, local.files), (2, edit_b.files.clone()));

    clean(
        &run_sync(&b, Some(&client), &ctx_b, &NO_HARVEST)
            .await
            .unwrap(),
    );
    assert_eq!(b.pending_count().unwrap(), 0);
    assert_eq!(versions(&relay, "deploy"), vec![1, 2]);
    clean(
        &run_sync(&a, Some(&client), &ctx_a, &NO_HARVEST)
            .await
            .unwrap(),
    );
    let latest = a.get_skill(Scope::Global, "", "deploy").unwrap().unwrap();
    assert_eq!((latest.version, latest.files), (2, edit_b.files.clone()));
    for (version, edit) in [(1, &edit_a), (2, &edit_b)] {
        let opened = client
            .skill_version(Scope::Global, "", "deploy", version)
            .await
            .unwrap();
        assert_eq!(opened.files, edit.files, "v{version}");
    }
}

/// Two queued pushes of one skill in one batch: the first meets another
/// machine's version, the second lands on top of it. The first is acked,
/// never pushed again: the newer edit already went out.
#[tokio::test]
async fn a_conflicted_push_superseded_by_a_later_one_in_the_batch_is_acked() {
    let dir = tempfile::tempdir().unwrap();
    let device = device(dir.path(), EncryptionMode::On);
    let relay = a_relay(Versioning::Kept);
    let theirs = super::tests::skill_v1("deploy", "# deploy from m2", "m2");
    relay
        .lock()
        .unwrap()
        .put_skill(context(&device).encrypt_skill(theirs).unwrap());
    let (base, log) = stub_relay(keeping_relay(relay.clone())).await;
    let s = Store::open_in_memory().unwrap();
    let first = super::tests::skill_v1("deploy", "# first edit", "m1");
    let mut second = super::tests::skill_v1("deploy", "# second edit", "m1");
    second.version = 2;
    second.content_hash = skill_hash(&second.files);
    queue_skill(&s, first, 0);
    queue_skill(&s, second.clone(), 1);
    let client = client_with(&base, &device, device.agent.clone());
    let (_home, ctx) = test_ctx();
    let out = run_sync(&s, Some(&client), &ctx, &NO_HARVEST)
        .await
        .unwrap();
    assert!(!out.relay_error && !out.offline, "{:?}", out.notes);
    assert_eq!(out.notes.len(), 1, "{:?}", out.notes);
    assert!(out.notes[0].contains(CONCURRENT), "{:?}", out.notes);
    assert_eq!(s.pending_count().unwrap(), 0);
    assert_eq!(posted_ops(&log).len(), 1);
    assert_eq!(versions(&relay, "deploy"), vec![1, 2]);
    let local = s.get_skill(Scope::Global, "", "deploy").unwrap().unwrap();
    assert_eq!((local.version, local.files), (2, second.files));
}

/// A conflict in chunk 1 coalesces the skill's queued pushes into its
/// newest edit, re-based past the Station's version, and holds the skill
/// back for the rest of the sync: chunk 2's push of it isn't sent (nor
/// sealed again), so the Station never has a gap a third machine could
/// fill. A third machine pushing in between meets no gap; the newest edit
/// is re-based again past it and lands last; the older edit never becomes
/// a version.
#[tokio::test]
async fn a_conflict_holds_the_skill_back_and_coalesces_its_pushes() {
    let dir = tempfile::tempdir().unwrap();
    let device = device(dir.path(), EncryptionMode::On);
    let recorder = Recorder::new(device.agent.clone());
    let relay = a_relay(Versioning::Kept);
    let theirs = super::tests::skill_v1("deploy", "# deploy from m2", "m2");
    relay
        .lock()
        .unwrap()
        .put_skill(context(&device).encrypt_skill(theirs).unwrap());
    let (base, log) = stub_relay(keeping_relay(relay.clone())).await;
    let s = Store::open_in_memory().unwrap();
    // Chunk 1: deploy's first edit and seven others; chunk 2: deploy's
    // second edit and one other.
    queue_skill(
        &s,
        super::tests::skill_v1("deploy", "# first edit", "m1"),
        0,
    );
    for i in 0..7 {
        queue_skill(
            &s,
            super::tests::skill_v1(&format!("other{i}"), "# other", "m1"),
            0,
        );
    }
    let mut second = super::tests::skill_v1("deploy", "# second edit", "m1");
    second.version = 2;
    second.content_hash = skill_hash(&second.files);
    queue_skill(&s, second.clone(), 1);
    queue_skill(&s, super::tests::skill_v1("last", "# last", "m1"), 0);
    let client = client_with(&base, &device, recorder.clone());
    let (_home, ctx) = test_ctx();
    let out = run_sync(&s, Some(&client), &ctx, &NO_HARVEST)
        .await
        .unwrap();
    assert!(!out.relay_error && !out.offline, "{:?}", out.notes);
    assert_eq!(
        out.notes,
        vec![format!(
            "skill deploy: {CONCURRENT}; its v1 is the latest for now, and this machine's edit will be pushed on top as v2 at the next sync. Both versions are kept: see them with `atem skill history deploy`."
        )]
    );
    // Seven of chunk 1 and `last` were acked; deploy's two pushes wait as one.
    assert_eq!((out.pushed, out.rebased), (8, 1));
    // Chunk 1 (8 skills: 8 paths and 8 hashes, then 8 files), chunk 2
    // sealed ahead (2 and 2, then 2); nothing sealed again.
    let (seals, _) = recorder.seals_and_opens();
    assert_eq!(
        seals.iter().map(|c| c.ops).collect::<Vec<_>>(),
        vec![16, 8, 4, 2],
        "{seals:?}"
    );
    // Chunk 2 carried only `last`; deploy has no gap.
    let posts = posted_ops(&log);
    assert_eq!(posts.iter().map(Vec::len).collect::<Vec<_>>(), vec![8, 1]);
    assert_eq!(versions(&relay, "deploy"), vec![1]);
    assert_eq!(versions(&relay, "last"), vec![1]);
    let queued = s.pending().unwrap();
    assert_eq!(queued.len(), 1);
    assert!(
        matches!(&queued[0].1, PendingOp::PushSkill { skill, base_version: 1 } if skill.version == 2 && skill.files == second.files),
        "{queued:?}"
    );

    // A third machine pushes v2 meanwhile, into no gap.
    let third = Store::open_in_memory().unwrap();
    let (_home3, ctx3) = test_ctx();
    clean(
        &run_sync(&third, Some(&client), &ctx3, &NO_HARVEST)
            .await
            .unwrap(),
    );
    let mut theirs = super::tests::skill_v1("deploy", "# deploy from m3", "m3");
    theirs.version = 2;
    theirs.content_hash = skill_hash(&theirs.files);
    queue_skill(&third, theirs, 1);
    clean(
        &run_sync(&third, Some(&client), &ctx3, &NO_HARVEST)
            .await
            .unwrap(),
    );
    assert_eq!(versions(&relay, "deploy"), vec![1, 2]);

    // Our newest edit meets it, is re-based past it, and lands last.
    let out = run_sync(&s, Some(&client), &ctx, &NO_HARVEST)
        .await
        .unwrap();
    assert!(
        out.notes.iter().any(|n| n.contains(CONCURRENT)),
        "{:?}",
        out.notes
    );
    clean(
        &run_sync(&s, Some(&client), &ctx, &NO_HARVEST)
            .await
            .unwrap(),
    );
    assert_eq!(versions(&relay, "deploy"), vec![1, 2, 3]);
    let local = s.get_skill(Scope::Global, "", "deploy").unwrap().unwrap();
    assert_eq!((local.version, local.files), (3, second.files.clone()));
    // Every version opens, and the first edit is none of them.
    for version in 1..=3 {
        let opened = client
            .skill_version(Scope::Global, "", "deploy", version)
            .await
            .unwrap();
        assert_ne!(
            opened.files["SKILL.md"],
            b"# first edit".to_vec(),
            "v{version}"
        );
    }
}

/// The reviewer's case: a push whose conflict couldn't be checked stays
/// queued while the pull brings another machine's row of the same version.
/// The local edit stays (a note says so), so the next edit, a full
/// snapshot, carries it; the next sync acks the old push as superseded and
/// lands the new one. No edit is lost.
#[tokio::test]
async fn an_unpushed_edit_is_kept_over_a_pulled_version_and_lands_later() {
    let dir = tempfile::tempdir().unwrap();
    let device = device(dir.path(), EncryptionMode::On);
    let relay = a_relay(Versioning::Kept);
    let theirs = super::tests::skill_v1("deploy", "# deploy from a", "m1");
    relay
        .lock()
        .unwrap()
        .put_skill(context(&device).encrypt_skill(theirs).unwrap());
    let keeping = keeping_relay(relay.clone());
    let first_get = AtomicBool::new(true);
    let (base, _log) = stub_relay(Box::new(move |m, p, body| {
        if m == "GET"
            && p.starts_with("/api/skills/version?")
            && first_get.swap(false, Ordering::SeqCst)
        {
            return (503, serde_json::json!({"error": "temporarily unavailable"}));
        }
        keeping(m, p, body)
    }))
    .await;
    let b = Store::open_in_memory().unwrap();
    let mine = super::tests::skill_v1("deploy", "# deploy from b", "m2");
    queue_skill(&b, mine.clone(), 0);
    let client = client_with(&base, &device, device.agent.clone());
    let (home, ctx) = test_ctx();
    // Claude is installed here, so apply writes skill directories.
    std::fs::create_dir_all(home.path().join(".claude")).unwrap();
    let out = run_sync(&b, Some(&client), &ctx, &NO_HARVEST)
        .await
        .unwrap();
    // The conflict couldn't be checked; the pull still brought A's v1.
    assert!(out.relay_error, "{:?}", out.notes);
    assert!(
        out.notes
            .iter()
            .any(|n| n.contains("reading v1 to check it failed")),
        "{:?}",
        out.notes
    );
    assert!(
        out.notes.iter().any(|n| n.contains(
            "another machine pushed an edit (v1) while this machine's edit waits to sync"
        )),
        "{:?}",
        out.notes
    );
    let local = b.get_skill(Scope::Global, "", "deploy").unwrap().unwrap();
    assert_eq!(local.files, mine.files);
    let installed = home.path().join(".claude/skills/deploy/SKILL.md");
    assert_eq!(std::fs::read(&installed).unwrap(), b"# deploy from b");

    // The user edits again: a full snapshot of the local skill.
    let mut again = local.clone();
    again
        .files
        .insert("SKILL.md".into(), b"# deploy from b, and more".to_vec());
    again.version = 2;
    again.content_hash = skill_hash(&again.files);
    queue_skill(&b, again.clone(), 1);
    let out = run_sync(&b, Some(&client), &ctx, &NO_HARVEST)
        .await
        .unwrap();
    assert!(!out.relay_error, "{:?}", out.notes);
    assert_eq!(b.pending_count().unwrap(), 0);
    assert_eq!(versions(&relay, "deploy"), vec![1, 2]);
    let latest = client
        .skill_version(Scope::Global, "", "deploy", 2)
        .await
        .unwrap();
    assert_eq!(latest.files, again.files);
}

/// A skill row under a key id this device doesn't hold (it hasn't received
/// a rotation) stops the pull with the way to get the key: nothing is
/// held, nothing applied, the cursor stays. So does a locked agent on a
/// page that also has a row that would be held.
#[tokio::test]
async fn a_key_not_held_or_a_locked_agent_stops_the_pull_without_holding() {
    let dir = tempfile::tempdir().unwrap();
    let device = device(dir.path(), EncryptionMode::On);
    let other_dir = tempfile::tempdir().unwrap();
    let mut rotated = UnlockedDevice::new(other_dir.path());
    rotated.set_key(EncryptionMode::On, "89abcdef", [8; 32]);
    let rotated_context =
        EncryptionContext::for_astation_with(ASTATION_ID, &rotated.paths, rotated.agent.clone())
            .unwrap();
    for case in ["key not held", "locked agent"] {
        let relay = a_relay(Versioning::Kept);
        {
            let mut r = relay.lock().unwrap();
            r.put_skill(
                context(&device)
                    .encrypt_skill(super::tests::skill_v1("ok", "# ok", "m2"))
                    .unwrap(),
            );
            // A row sealed under v1 but stored as v2: it would be held.
            let mut bad = context(&device)
                .encrypt_skill(super::tests::skill_v1("bad", "# bad", "m2"))
                .unwrap();
            bad.version = 2;
            r.put_skill(bad);
            if case == "key not held" {
                r.put_skill(
                    rotated_context
                        .encrypt_skill(super::tests::skill_v1("rotated", "# rotated", "m3"))
                        .unwrap(),
                );
            }
        }
        if case == "locked agent" {
            device.agent.lock_keys().unwrap();
        }
        let (base, _log) = stub_relay(keeping_relay(relay.clone())).await;
        let s = Store::open_in_memory().unwrap();
        let (_home, ctx) = test_ctx();
        let client = client_with(&base, &device, device.agent.clone());
        let out = run_sync(&s, Some(&client), &ctx, &NO_HARVEST)
            .await
            .unwrap();
        assert!(out.relay_error, "{case}: {:?}", out.notes);
        if case == "key not held" {
            assert!(
                out.notes
                    .iter()
                    .any(|n| n.contains(crate::memory::crypto::KEY_NOT_HELD)),
                "{case}: {:?}",
                out.notes
            );
        }
        assert!(s.held_skills().unwrap().is_empty(), "{case}");
        assert!(s.all_skills().unwrap().is_empty(), "{case}");
        assert_eq!(
            s.get_state(&skill_cursor_key(ASTATION_ID)).unwrap(),
            0,
            "{case}"
        );
    }
}

/// A crash inside the commit of a page with a held row leaves neither the
/// hold nor the page's rows nor the cursor; the next sync pulls the page
/// again whole and holds the row once.
#[tokio::test]
async fn a_crash_while_a_page_with_a_held_row_commits_leaves_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let device = device(dir.path(), EncryptionMode::On);
    let relay = a_relay(Versioning::Kept);
    {
        let mut r = relay.lock().unwrap();
        r.put_skill(
            context(&device)
                .encrypt_skill(super::tests::skill_v1("ok", "# ok", "m2"))
                .unwrap(),
        );
        let mut bad = context(&device)
            .encrypt_skill(super::tests::skill_v1("bad", "# bad", "m2"))
            .unwrap();
        bad.version = 2;
        r.put_skill(bad);
    }
    let (base, _log) = stub_relay(keeping_relay(relay.clone())).await;
    let td = tempfile::tempdir().unwrap();
    let (db, image) = (
        td.path().join("knowledge.db"),
        td.path().join("crash/knowledge.db"),
    );
    let s = Store::open(&db).unwrap();
    super::tests::arm_crash(
        &s,
        &db,
        &image,
        "CREATE TEMP TRIGGER crash_in_held_page BEFORE INSERT ON held_skills BEGIN SELECT crash(); END;",
    );
    let client = client_with(&base, &device, device.agent.clone());
    let (_home, ctx) = test_ctx();
    let err = run_sync(&s, Some(&client), &ctx, &NO_HARVEST)
        .await
        .unwrap_err();
    assert!(format!("{err:#}").contains("injected crash"), "{err:#}");
    drop(s);
    for s in [Store::open(&db).unwrap(), Store::open(&image).unwrap()] {
        assert!(s.held_skills().unwrap().is_empty());
        assert!(s.all_skills().unwrap().is_empty());
        assert_eq!(s.get_state(&skill_cursor_key(ASTATION_ID)).unwrap(), 0);
    }
    let s = Store::open(&image).unwrap();
    let out = run_sync(&s, Some(&client), &ctx, &NO_HARVEST)
        .await
        .unwrap();
    assert!(!out.relay_error, "{:?}", out.notes);
    assert_eq!(s.held_skills().unwrap().len(), 1);
    assert!(s.get_skill(Scope::Global, "", "ok").unwrap().is_some());
    let last = relay.lock().unwrap().skills.keys().max().copied().unwrap();
    assert_eq!(s.get_state(&skill_cursor_key(ASTATION_ID)).unwrap(), last);
}

/// A Station that renumbers pushes (before Astation PR #76) stores a concurrent push under
/// a version its envelopes don't name. Every device holds that row (never
/// applied, reported once) and the pull goes on: later skills apply and the
/// cursor moves. Once the Station keeps versions, the next edit is re-based
/// past it, lands readable, and the hold clears.
#[tokio::test]
async fn a_skill_row_that_cannot_open_is_held_and_cleared_by_a_later_version() {
    let dir = tempfile::tempdir().unwrap();
    let device = device(dir.path(), EncryptionMode::On);
    let relay = a_relay(Versioning::Renumbered);
    let (base, _log) = stub_relay(keeping_relay(relay.clone())).await;
    let client = client_with(&base, &device, device.agent.clone());
    let (a, b, c) = (
        Store::open_in_memory().unwrap(),
        Store::open_in_memory().unwrap(),
        Store::open_in_memory().unwrap(),
    );
    let ((_ha, ctx_a), (_hb, ctx_b), (_hc, ctx_c)) = (test_ctx(), test_ctx(), test_ctx());
    let edit_a = super::tests::skill_v1("deploy", "# deploy from a", "m1");
    queue_skill(&a, edit_a.clone(), 0);
    clean(
        &run_sync(&a, Some(&client), &ctx_a, &NO_HARVEST)
            .await
            .unwrap(),
    );
    // B's push of the same version is renumbered to v2 (sealed under v1).
    queue_skill(
        &b,
        super::tests::skill_v1("deploy", "# deploy from b", "m2"),
        0,
    );
    run_sync(&b, Some(&client), &ctx_b, &NO_HARVEST)
        .await
        .unwrap();
    assert_eq!(versions(&relay, "deploy"), vec![1, 2]);
    queue_skill(&a, super::tests::skill_v1("lint", "# lint", "m1"), 0);
    let out = run_sync(&a, Some(&client), &ctx_a, &NO_HARVEST)
        .await
        .unwrap();
    assert!(!out.relay_error, "{:?}", out.notes);

    // C reads everything else: deploy v1, then lint after the held row.
    let out = run_sync(&c, Some(&client), &ctx_c, &NO_HARVEST)
        .await
        .unwrap();
    assert!(!out.relay_error && !out.offline, "{:?}", out.notes);
    assert_eq!(out.notes.len(), 1, "{:?}", out.notes);
    assert!(
        out.notes[0].contains("deploy v2") && out.notes[0].contains("can't open"),
        "{:?}",
        out.notes
    );
    let held = c.held_skills().unwrap();
    assert_eq!(held.len(), 1, "{held:?}");
    assert_eq!(
        (
            held[0].scope,
            held[0].project.as_str(),
            held[0].name.as_str(),
            held[0].version
        ),
        (Scope::Global, "", "deploy", 2)
    );
    assert!(held[0].reason.contains("authentication failed"), "{held:?}");
    let deploy = c.get_skill(Scope::Global, "", "deploy").unwrap().unwrap();
    assert_eq!((deploy.version, deploy.files), (1, edit_a.files.clone()));
    assert!(c.get_skill(Scope::Global, "", "lint").unwrap().is_some());
    let last_seq = relay.lock().unwrap().skills.keys().max().copied().unwrap();
    assert_eq!(
        c.get_state(&skill_cursor_key(ASTATION_ID)).unwrap(),
        last_seq
    );
    // Reported once; still held.
    clean(
        &run_sync(&c, Some(&client), &ctx_c, &NO_HARVEST)
            .await
            .unwrap(),
    );
    assert_eq!(c.held_skills().unwrap().len(), 1);

    // The Station keeps versions: A's next edit (on its v1) meets B's v2, is
    // re-based onto v3, sealed again there, and lands readable.
    relay.lock().unwrap().versioning = Versioning::Kept;
    let mut again = super::tests::skill_v1("deploy", "# deploy from a, again", "m1");
    again.version = 2;
    again.content_hash = skill_hash(&again.files);
    queue_skill(&a, again.clone(), 1);
    let out = run_sync(&a, Some(&client), &ctx_a, &NO_HARVEST)
        .await
        .unwrap();
    assert!(
        out.notes.iter().any(|n| n.contains(CONCURRENT)),
        "{:?}",
        out.notes
    );
    clean(
        &run_sync(&a, Some(&client), &ctx_a, &NO_HARVEST)
            .await
            .unwrap(),
    );
    assert_eq!(versions(&relay, "deploy"), vec![1, 2, 3]);
    clean(
        &run_sync(&c, Some(&client), &ctx_c, &NO_HARVEST)
            .await
            .unwrap(),
    );
    assert!(c.held_skills().unwrap().is_empty());
    let deploy = c.get_skill(Scope::Global, "", "deploy").unwrap().unwrap();
    assert_eq!((deploy.version, deploy.files), (3, again.files));
}

/// A row that breaks skill wire v2's rules still refuses its page while
/// encryption is on: holding is only for well-formed rows that don't open.
#[tokio::test]
async fn a_malformed_skill_row_still_refuses_the_page() {
    let dir = tempfile::tempdir().unwrap();
    let device = device(dir.path(), EncryptionMode::On);
    let sealed = context(&device)
        .encrypt_skill(super::tests::skill_v1("deploy", "# deploy", "m2"))
        .unwrap();
    let mut good = crate::memory::fake_station_skills::row(&Skill {
        seq: 1,
        ..sealed.clone()
    });
    good["seq"] = serde_json::json!(1);
    let mut bad = crate::memory::fake_station_skills::row(&Skill {
        name: "lint".into(),
        seq: 2,
        ..sealed
    });
    let path = bad["files"]
        .as_object()
        .unwrap()
        .keys()
        .next()
        .unwrap()
        .clone();
    bad["files"][path] = serde_json::json!("plaintext");
    let relay = Arc::new(Mutex::new(KeepingRelay::default()));
    let keeping = keeping_relay(relay);
    let (base, _log) = stub_relay(Box::new(move |m, p, body| {
        if m == "GET" && p.starts_with("/api/skills?") {
            let rows = if since(p) < 2 {
                vec![good.clone(), bad.clone()]
            } else {
                Vec::new()
            };
            return (200, serde_json::json!({"skills": rows}));
        }
        keeping(m, p, body)
    }))
    .await;
    let s = Store::open_in_memory().unwrap();
    let (_home, ctx) = test_ctx();
    let client = client_with(&base, &device, device.agent.clone());
    let out = run_sync(&s, Some(&client), &ctx, &NO_HARVEST)
        .await
        .unwrap();
    assert!(out.relay_error, "{:?}", out.notes);
    assert!(
        out.notes
            .iter()
            .any(|n| n.contains("unexpected relay response")),
        "{:?}",
        out.notes
    );
    assert!(s.all_skills().unwrap().is_empty());
    assert!(s.held_skills().unwrap().is_empty());
    assert_eq!(s.get_state(&skill_cursor_key(ASTATION_ID)).unwrap(), 0);
}

/// The Station's compare-and-set counts tombstones: a push's base is the
/// skill's latest version, a tombstone included. After a delete here (its
/// tombstone at the next version, as the Station appends it) and after one
/// pulled from another machine, the next push builds on the tombstone and
/// lands with no conflict.
#[tokio::test]
async fn a_push_after_a_delete_builds_on_the_tombstone() {
    let dir = tempfile::tempdir().unwrap();
    let device = device(dir.path(), EncryptionMode::On);
    let relay = a_relay(Versioning::Kept);
    let (base, _log) = stub_relay(keeping_relay(relay.clone())).await;
    let client = client_with(&base, &device, device.agent.clone());
    let (a, b) = (
        Store::open_in_memory().unwrap(),
        Store::open_in_memory().unwrap(),
    );
    let ((_ha, ctx_a), (_hb, ctx_b)) = (test_ctx(), test_ctx());
    queue_skill(&a, super::tests::skill_v1("deploy", "# deploy", "m1"), 0);
    clean(
        &run_sync(&a, Some(&client), &ctx_a, &NO_HARVEST)
            .await
            .unwrap(),
    );
    clean(
        &run_sync(&b, Some(&client), &ctx_b, &NO_HARVEST)
            .await
            .unwrap(),
    );
    // A removes it (as `atem skill rm`) and adds it again (as `atem skill
    // add`, on the local tombstone's version).
    let mut tombstone = a.get_skill(Scope::Global, "", "deploy").unwrap().unwrap();
    tombstone.version += 1;
    tombstone.deleted = true;
    tombstone.files.clear();
    tombstone.content_hash.clear();
    a.put_skill(&tombstone).unwrap();
    a.enqueue(&PendingOp::DeleteSkill {
        scope: Scope::Global,
        project: String::new(),
        name: "deploy".into(),
    })
    .unwrap();
    let mut again = super::tests::skill_v1("deploy", "# deploy again", "m1");
    again.version = 3;
    again.content_hash = skill_hash(&again.files);
    queue_skill(&a, again.clone(), 2);
    clean(
        &run_sync(&a, Some(&client), &ctx_a, &NO_HARVEST)
            .await
            .unwrap(),
    );
    assert_eq!(versions(&relay, "deploy"), vec![1, 2, 3]);
    // B pulls the tombstone and the new version; its next edit builds on v3.
    clean(
        &run_sync(&b, Some(&client), &ctx_b, &NO_HARVEST)
            .await
            .unwrap(),
    );
    let local = b.get_skill(Scope::Global, "", "deploy").unwrap().unwrap();
    assert_eq!((local.version, local.files), (3, again.files));
    // A removes it again; B pulls only that tombstone and adds on it.
    let mut tombstone = a.get_skill(Scope::Global, "", "deploy").unwrap().unwrap();
    tombstone.version += 1;
    tombstone.deleted = true;
    tombstone.files.clear();
    tombstone.content_hash.clear();
    a.put_skill(&tombstone).unwrap();
    a.enqueue(&PendingOp::DeleteSkill {
        scope: Scope::Global,
        project: String::new(),
        name: "deploy".into(),
    })
    .unwrap();
    clean(
        &run_sync(&a, Some(&client), &ctx_a, &NO_HARVEST)
            .await
            .unwrap(),
    );
    clean(
        &run_sync(&b, Some(&client), &ctx_b, &NO_HARVEST)
            .await
            .unwrap(),
    );
    let base_version = b
        .get_skill(Scope::Global, "", "deploy")
        .unwrap()
        .unwrap()
        .version;
    assert_eq!(base_version, 4);
    let mut from_b = super::tests::skill_v1("deploy", "# deploy from b", "m2");
    from_b.version = base_version + 1;
    from_b.content_hash = skill_hash(&from_b.files);
    queue_skill(&b, from_b, base_version);
    clean(
        &run_sync(&b, Some(&client), &ctx_b, &NO_HARVEST)
            .await
            .unwrap(),
    );
    assert_eq!(versions(&relay, "deploy"), vec![1, 2, 3, 4, 5]);
}

/// A migration (and its read-back) that meets a skill row which doesn't
/// open names it and the way to remove it; once that version is purged, it
/// finishes. Its completion rules are unchanged.
#[tokio::test]
async fn a_migration_names_a_skill_row_that_cannot_open_and_how_to_remove_it() {
    let dir = tempfile::tempdir().unwrap();
    let device = device(dir.path(), EncryptionMode::Enabling);
    let relay = a_relay(Versioning::Kept);
    {
        // Both already sealed under the key (so the read-back's field checks
        // pass); one stored under a version it wasn't sealed under.
        let mut r = relay.lock().unwrap();
        r.put_skill(
            context(&device)
                .encrypt_skill(super::tests::skill_v1("ok", "# ok", "m2"))
                .unwrap(),
        );
        let mut bad = context(&device)
            .encrypt_skill(super::tests::skill_v1("bad", "# bad", "m2"))
            .unwrap();
        bad.version = 2;
        r.put_skill(bad);
    }
    let (base, _log) = stub_relay(keeping_relay(relay.clone())).await;
    let client = client_with(&base, &device, device.agent.clone());
    let want = "skill bad v2 (global) can't be opened on this device (encrypted field authentication failed), so this can't finish. Remove that version with `atem skill purge bad --version 2`, then try again.";
    let error = client.migrate_encryption().await.unwrap_err().to_string();
    assert!(error.contains(want), "{error}");
    let error = client
        .verify_encryption_migration()
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains(want), "{error}");

    // The purge (as `atem skill purge bad --version 2` queues it) blanks it.
    let s = Store::open_in_memory().unwrap();
    s.enqueue(&PendingOp::PurgeSkill {
        scope: Scope::Global,
        project: String::new(),
        name: "bad".into(),
        versions: Some(vec![2]),
    })
    .unwrap();
    let (_home, ctx) = test_ctx();
    run_sync(&s, Some(&client), &ctx, &NO_HARVEST)
        .await
        .unwrap();
    client.migrate_encryption().await.unwrap();
    client.verify_encryption_migration().await.unwrap();
}
