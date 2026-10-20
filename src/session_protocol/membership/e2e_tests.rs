//! Local end-to-end tests of the device list as the runtime uses it: the
//! real store on a temp profile (real files, fsyncs and directory fsyncs,
//! injected faults at each step) driving the real session host over a real
//! `FileJournal`, whose fake PTY checks every queued remote byte at the
//! write boundary (`admit_write`), as the worker does. Restarts reopen the
//! journal and the device list from disk.
use super::store::{DlFile, Injected, Step};
use super::tests::{Rig, WALL0, clock, vectors};
use super::*;
use crate::session_protocol::fake_runtime::FakeRuntime;
use crate::session_protocol::file_journal::FileJournal;
use crate::session_protocol::fixtures::{HostEvent, HostUnderTest};
use crate::session_protocol::host::{DETAIL_CONTROL_REVOKED, DETAIL_HISTORY_UNKNOWN, HostConfig};
use crate::session_protocol::wire::ReceiptState;

const SID: &str = "ses-aaaaaaaaaaaa";
const PGEN: &str = "22222222-2222-4222-8222-222222222222";
const SVC: &str = "service:svc-discord";
const PHONE: &str = "member:dev-phone";
const SVC_GEN: &str = "33333333-3333-4333-8333-000000000001";
const PHONE_GEN: &str = "33333333-3333-4333-8333-000000000002";
const LOG6: [&str; 6] = ["E1", "E2", "E3", "E4", "E5", "E6"];

/// A runtime's host side: the session host over its journal and the device
/// list, both on `rig`'s files.
struct Runtime {
    rig: Rig,
    rt: FakeRuntime<FileJournal>,
    m: MembershipHost,
    now: HostNow,
    epoch: u64,
}

fn binding(rt: &FakeRuntime<FileJournal>, client: &str, lease: bool) -> Value {
    let mut b = json!({"target": serde_json::to_value(rt.target(SID)).unwrap(),
                       "attachment_gen": rt.attachment(client)});
    if lease {
        b["lease_epoch"] = json!(rt.host.lease_epoch(SID).unwrap());
    }
    b
}

impl Runtime {
    /// Pinned at E6; the bot (`svc`) holds the session's lease, the phone
    /// watches; accepted work stays queued.
    fn start() -> Runtime {
        let rig = Rig::new();
        rig.pin(&LOG6);
        let setup = json!({
            "host": {"account_id": "acct-test-1", "atem_device_id": "host-a", "host_trust_gen": 1,
                     "runtime_gen": "11111111-1111-4111-8111-111111111111", "runtime_epoch": 1},
            "sessions": [{"session_id": SID, "process_gen": PGEN, "chat": true}],
            "clients": [
                {"name": SVC, "attachment_gen": SVC_GEN, "permissions": ["view", "control"],
                 "client_kind": "native", "holds_lease_epoch": 1},
                {"name": PHONE, "attachment_gen": PHONE_GEN, "permissions": ["view", "control"],
                 "client_kind": "native"},
            ],
        });
        let journal = FileJournal::open(&rig.journal).unwrap();
        let mut rt = FakeRuntime::from_json_with(setup, HostConfig::default(), journal);
        rt.host.hold_dispatch(true);
        let now = clock(WALL0, 1_000, "boot-1");
        let mut fences = HostFences::new(&mut rt.host);
        let (m, _) = rig.open(1, &now, &mut fences).unwrap();
        Runtime {
            rig,
            rt,
            m,
            now,
            epoch: 1,
        }
    }

    /// The bot queues a prompt (accepted, not executing) and remote terminal
    /// bytes (held at the writer).
    fn queue_work(&mut self) {
        let submit = json!({"type": "session", "data": {"v": 1, "op": "submit",
            "id": "aaaaaaaa-0000-4000-8000-000000000001",
            "binding": binding(&self.rt, SVC, true), "kind": "prompt",
            "request_id": "bbbbbbbb-0000-4000-8000-000000000001",
            "payload": {"text": "run the tests"}}});
        self.rt.send(SVC, &submit);
        let replies = self.rt.take(SVC);
        assert!(
            replies
                .iter()
                .any(|m| m["data"]["op"] == "receipt" && m["data"]["state"] == "accepted"),
            "{replies:?}"
        );
        self.rt
            .event(&HostEvent::HoldPtyWrites, self.rt.now())
            .unwrap();
        let subscribe = json!({"type": "terminal", "data": {"v": 1, "op": "subscribe",
            "terminal_id": SID, "generation": PGEN, "binding": binding(&self.rt, SVC, false)}});
        self.rt.send(SVC, &subscribe);
        let stream = self
            .rt
            .take(SVC)
            .into_iter()
            .find(|m| m["data"]["op"] == "attached")
            .unwrap()["data"]["stream_id"]
            .clone();
        let input = json!({"type": "terminal", "data": {"v": 1, "op": "input",
            "terminal_id": SID, "generation": PGEN, "stream_id": stream, "sequence": 0,
            "bytes": "eA==", "binding": binding(&self.rt, SVC, true)}});
        self.rt.send(SVC, &input);
        self.rt.take(SVC);
        self.rt.take(PHONE);
    }

    fn carry(&mut self, labels: &[&str]) -> CarriageResult {
        let carried = vectors().carry(labels);
        let mut fences = HostFences::new(&mut self.rt.host);
        let result = self.m.apply_carriage(&carried, &self.now, &mut fences);
        let effects = fences.effects;
        self.rt.apply(effects);
        result
    }

    fn counter(&self, key: &str) -> Value {
        self.rt.counter(key).unwrap()
    }

    fn flush(&mut self) {
        self.rt
            .event(&HostEvent::FlushPtyWrites, self.rt.now())
            .unwrap();
    }

    fn receipt(&self) -> (ReceiptState, Option<String>) {
        let r = self
            .rt
            .host
            .receipt("bbbbbbbb-0000-4000-8000-000000000001")
            .unwrap();
        (r.state, r.detail)
    }

    /// Stops (orderly, or killed) and starts again from the disk.
    fn restart(mut self, orderly: bool) -> Runtime {
        if orderly {
            self.m.close(&self.now);
        }
        let Runtime {
            rig,
            mut rt,
            m,
            now,
            epoch,
        } = self;
        drop(m);
        let epoch = epoch + 1;
        let runtime_gen = format!("44444444-4444-4444-8444-{epoch:012}");
        let event = if orderly {
            HostEvent::RestartRuntime {
                runtime_gen,
                runtime_epoch: epoch,
            }
        } else {
            HostEvent::CrashRuntime {
                runtime_gen,
                runtime_epoch: epoch,
            }
        };
        rt.event(&event, rt.now()).unwrap();
        let mut fences = HostFences::new(&mut rt.host);
        let (m, _) = rig.open(epoch, &now, &mut fences).unwrap();
        let effects = fences.effects;
        rt.apply(effects);
        Runtime {
            rig,
            rt,
            m,
            now,
            epoch,
        }
    }

    /// The durable principals file, as the next run reads it.
    fn durable_control_gen(&self, principal: &str) -> u64 {
        // `<len> <crc32> <json>\n` (file_journal.rs).
        let bytes = std::fs::read(self.rig.journal.join("principals")).unwrap();
        let text = String::from_utf8(bytes).unwrap();
        let json = text.splitn(3, ' ').nth(2).unwrap().trim_end();
        let file: Value = serde_json::from_str(json).unwrap();
        file["principals"][principal]["control_gen"]
            .as_u64()
            .unwrap_or(1)
    }
}

/// A removal arrives while the removed bot holds the lease with a prompt
/// queued and terminal bytes waiting at the writer: in one step the fence
/// is durable, the lease revoked (the viewer hears it), the queued prompt
/// rejected `control revoked` durably, and the queued bytes dropped at the
/// write boundary. A restart finds the same.
#[test]
fn a_removal_revokes_the_lease_and_rejects_queued_work_through_the_fence() {
    let mut r = Runtime::start();
    r.queue_work();
    let result = r.carry(&["E7"]);
    assert_eq!(result.carried, Carried::Committed);
    assert_eq!(result.fences[0].principal, SVC);
    assert!(result.fences[0].durable);
    assert_eq!(r.counter("lease_holder"), Value::Null);
    let phone = r.rt.take(PHONE);
    assert!(
        phone
            .iter()
            .any(|m| m["data"]["op"] == "lease_changed" && m["data"]["reason"] == "revoked"),
        "{phone:?}"
    );
    assert_eq!(
        r.counter("attachments"),
        json!(1),
        "the bot's attachment is fenced"
    );
    assert_eq!(
        r.receipt(),
        (ReceiptState::Rejected, Some(DETAIL_CONTROL_REVOKED.into()))
    );
    r.flush();
    assert_eq!(r.counter("pty_writes_remote"), json!(0));
    assert_eq!(r.counter("pty_writes_dropped"), json!(1));
    assert_eq!(r.counter("dispatches"), json!(0));
    assert!(!r.rt.host.journal_halted(), "durable: nothing halts");
    assert_eq!(r.rt.host.control_gen(SVC), 2);
    assert_eq!(r.durable_control_gen(SVC), 2);
    // Local input goes on.
    r.rt.event(
        &HostEvent::LocalInput {
            session_id: SID.into(),
            bytes: b"ls\r".to_vec(),
        },
        r.rt.now(),
    )
    .unwrap();
    assert_eq!(r.counter("pty_writes_local"), json!(1));
    let r = r.restart(true);
    assert_eq!(
        r.receipt(),
        (ReceiptState::Rejected, Some(DETAIL_CONTROL_REVOKED.into()))
    );
    assert_eq!(r.rt.host.control_gen(SVC), 2, "not raised twice");
    assert!(r.m.held().is_none());
}

/// Every device-list write step fails once with the same removal pending:
/// the removed bot is fenced in memory (lease revoked, queued prompt
/// rejected, queued bytes dropped), the journal halts (no remote byte, no
/// dispatch, no welcome), local input goes on. Killed and restarted, the
/// carriage record is replayed: the removal is committed and fenced
/// durably, the queued prompt is rejected `authorization history unknown`
/// (no clean close), and the host is held.
#[test]
fn every_write_step_fault_fences_in_memory_and_the_restart_replays_and_holds() {
    let v = vectors();
    for (file, step) in [
        (DlFile::Carriage, Step::TempWrite),
        (DlFile::Carriage, Step::TempFsync),
        (DlFile::Carriage, Step::Rename),
        (DlFile::Carriage, Step::DirectoryFsync),
        (DlFile::Intent, Step::TempWrite),
        (DlFile::Intent, Step::TempFsync),
        (DlFile::Intent, Step::Rename),
        (DlFile::Intent, Step::DirectoryFsync),
        (DlFile::State, Step::TempWrite),
        (DlFile::State, Step::TempFsync),
        (DlFile::State, Step::Rename),
        (DlFile::State, Step::DirectoryFsync),
    ] {
        let what = format!("{file:?} {step:?}");
        let mut r = Runtime::start();
        r.queue_work();
        r.m.store_mut().inject(Injected { file, step });
        let result = r.carry(&["E7"]);
        assert_eq!(result.carried, Carried::NotRecorded, "{what}");
        assert!(r.rt.host.journal_halted(), "{what}");
        assert_eq!(r.counter("lease_holder"), Value::Null, "{what}");
        assert_eq!(
            r.receipt(),
            (ReceiptState::Rejected, Some(DETAIL_CONTROL_REVOKED.into())),
            "{what}: in memory"
        );
        r.flush();
        assert_eq!(r.counter("pty_writes_remote"), json!(0), "{what}");
        assert_eq!(r.counter("pty_writes_dropped"), json!(1), "{what}");
        // The phone is fenced only when Atem can't tell who the carriage
        // affects (the carriage record itself failed).
        let phone_fenced = file == DlFile::Carriage;
        assert_eq!(
            r.counter("attachments"),
            json!(if phone_fenced { 0 } else { 1 }),
            "{what}"
        );
        // Nothing remote passes: an acquire is busy, a reconnect unwelcomed.
        if !phone_fenced {
            let acquire = json!({"type": "session", "data": {"v": 1, "op": "acquire",
                "id": "aaaaaaaa-0000-4000-8000-000000000071", "takeover": false,
                "binding": binding(&r.rt, PHONE, false)}});
            r.rt.send(PHONE, &acquire);
            let replies = r.rt.take(PHONE);
            assert!(
                replies
                    .iter()
                    .any(|m| m["data"]["detail"] == "journal halted; restart Atem"),
                "{what}: {replies:?}"
            );
        }
        assert_eq!(r.m.init(), Init::Busy, "{what}");
        r.rt.event(
            &HostEvent::LocalInput {
                session_id: SID.into(),
                bytes: b"ls\r".to_vec(),
            },
            r.rt.now(),
        )
        .unwrap();
        assert_eq!(r.counter("pty_writes_local"), json!(1), "{what}");
        assert!(r.rig.exists(DlFile::Fault), "{what}");
        if file == DlFile::Carriage && step == Step::DirectoryFsync {
            // The machine lost the unsynced rename of the record.
            std::fs::remove_file(&r.rig.pairing.carriage).unwrap();
        }

        let r = r.restart(false);
        let replayed = file != DlFile::Carriage;
        assert_eq!(
            r.m.head(),
            v.head(if replayed { "E7" } else { "E6" }),
            "{what}"
        );
        assert_eq!(
            r.rt.host.control_gen(SVC),
            if replayed { 2 } else { 1 },
            "{what}: the replayed fence"
        );
        assert_eq!(
            r.receipt(),
            (ReceiptState::Rejected, Some(DETAIL_HISTORY_UNKNOWN.into())),
            "{what}"
        );
        assert!(r.m.held().is_some(), "{what}: held after a recorded fault");
        assert!(!r.rig.exists(DlFile::Carriage), "{what}");
        assert!(
            !r.rt.host.journal_halted(),
            "{what}: the restart ends the halt"
        );
    }
}

/// A freeze whose file can't be written: frozen in memory at once, every
/// remote principal fenced, the journal halted; the restart freezes again
/// from the carriage record.
#[test]
fn a_freeze_write_fault_fences_everyone_and_the_restart_freezes_again() {
    let mut r = Runtime::start();
    r.queue_work();
    r.m.store_mut().inject(Injected {
        file: DlFile::Freeze,
        step: Step::TempFsync,
    });
    let result = r.carry(&["C6_mac"]);
    assert_eq!(result.carried, Carried::Frozen);
    assert!(r.m.is_frozen() && !r.m.frozen_durable());
    assert_eq!(r.counter("attachments"), json!(0));
    assert_eq!(r.counter("lease_holder"), Value::Null);
    assert!(r.rt.host.journal_halted());
    r.flush();
    assert_eq!(r.counter("pty_writes_dropped"), json!(1));
    let r = r.restart(true);
    assert!(r.m.is_frozen() && r.m.frozen_durable());
    assert_eq!(r.m.init(), Init::Frozen);
    // The freeze's fences, durably now, for every member's principal.
    for p in ["member:dev-mac", PHONE, SVC] {
        assert_eq!(r.rt.host.control_gen(p), 2, "{p}");
    }
}

/// An uncertain rename (the directory fsync failed): kept, the restart
/// fsyncs and trusts it; lost, the record replays it. Held either way until
/// the phone, a manager at the host's head, reconciles.
#[test]
fn an_uncertain_rename_is_reconciled_whether_or_not_it_survived() {
    let v = vectors();
    for lost in [false, true] {
        let mut r = Runtime::start();
        r.m.store_mut().inject(Injected {
            file: DlFile::State,
            step: Step::DirectoryFsync,
        });
        assert_eq!(r.carry(&["E7"]).carried, Carried::NotRecorded);
        assert_eq!(r.rig.disk_head(), v.head("E7"), "the rename happened");
        if lost {
            let before = r.m.store().unsynced_rename().unwrap().clone();
            std::fs::write(&before.path, before.before.unwrap()).unwrap();
            assert_eq!(r.rig.disk_head(), v.head("E6"));
        }
        let mut r = r.restart(true);
        assert_eq!(r.m.head(), v.head("E7"), "lost {lost}");
        assert_eq!(r.rt.host.control_gen(SVC), 2);
        assert!(r.m.held().is_some());
        let now = r.now.clone();
        assert_eq!(
            r.m.hello("dev-phone", Some(v.head("E6")), None, false, &now),
            Hello::NotReconciled,
            "a manager behind the host's head fetches first"
        );
        assert!(matches!(
            r.m.hello("dev-phone", Some(v.head("E7")), None, false, &now),
            Hello::Admit(Admission::Member { .. })
        ));
        assert!(r.m.held().is_none() && !r.rig.exists(DlFile::Fault));
        let r = r.restart(true);
        assert!(r.m.held().is_none(), "reconciled for good");
    }
}

/// The fences survive a crash at any point between the commit and
/// `membership_applied`, and are raised once per entry: the applied record
/// fails, the journal halts; the restart replays the fence without raising
/// the bot's generation again.
#[test]
fn a_replayed_fence_is_never_raised_twice_for_one_entry() {
    let mut r = Runtime::start();
    r.m.store_mut().inject(Injected {
        file: DlFile::Applied,
        step: Step::TempWrite,
    });
    let result = r.carry(&["E7"]);
    assert_eq!(result.carried, Carried::Committed);
    assert!(r.rt.host.journal_halted(), "a failed journal write halts");
    assert_eq!(r.rt.host.control_gen(SVC), 2);
    assert_eq!(r.m.applied().head, vectors().head("E6"));
    let r = r.restart(false);
    assert_eq!(r.m.applied().head, vectors().head("E7"));
    assert_eq!(r.rt.host.control_gen(SVC), 2, "fence_seq 7 already durable");
    assert_eq!(r.rt.host.fence_seq(SVC), 7);
    assert!(r.m.held().is_none(), "no device-list fault");
}

/// A pending recovery keeps waiting across runtime restarts and a reboot,
/// counted on the host clock: only the persisted monotonic time carries
/// over a reboot, the wall clock alone never ends it.
#[test]
fn a_pending_recovery_survives_runtime_restarts_and_a_reboot() {
    let v = vectors();
    let mut r = Runtime::start();
    assert_eq!(r.carry(&["R7"]).carried, Carried::Committed);
    let hour = 3_600_000;
    let tick = |r: &mut Runtime, wall: u64, mono: u64, boot: &str| {
        r.now = clock(wall, mono, boot);
        let mut fences = HostFences::new(&mut r.rt.host);
        let changes = r.m.advance(&r.now, &mut fences);
        let effects = fences.effects;
        r.rt.apply(effects);
        changes
    };
    tick(&mut r, WALL0 + 8 * hour, 1_000 + 8 * hour, "boot-1");
    let mut r = r.restart(true);
    // Same boot: the monotonic clock goes on.
    tick(&mut r, WALL0 + 12 * hour, 1_000 + 12 * hour, "boot-1");
    let mut r = r.restart(true);
    // A reboot after 30 h off: the new boot's clock starts small, the wall
    // clock jumped. 12 h were persisted.
    r.now = clock(WALL0 + 42 * hour, 2_000, "boot-2");
    let mut r = r.restart(false);
    tick(
        &mut r,
        WALL0 + 42 * hour + 11 * hour,
        2_000 + 11 * hour,
        "boot-2",
    );
    let state = |r: &Runtime| r.m.membership().record(&v.hash("R7")).unwrap().state();
    assert_eq!(state(&r), RecoveryState::Pending, "23 h of host time");
    let changes = tick(
        &mut r,
        WALL0 + 42 * hour + 12 * hour + 1,
        2_001 + 12 * hour,
        "boot-2",
    );
    assert!(
        changes
            .iter()
            .any(|c| matches!(c, Change::RecoveryActive { .. }))
    );
    assert_eq!(state(&r), RecoveryState::Active);
    let r = r.restart(false);
    assert_eq!(
        state(&r),
        RecoveryState::Active,
        "written before the effect"
    );
}
