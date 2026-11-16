//! Host senders' mailbox in the real runtime (host-work-v1 §11.5, "The
//! mailbox calls" and "On the receiving host"; the delegated host-work
//! design II.4.2 to II.5): the receiving host's mailbox client end to end,
//! behind the debug-only hook (`host.delegated,host.senders`), against the
//! fake Station's mailbox (tests/support/station.rs). A temp profile with a
//! pinned device list (this host, a sending host and another host) and
//! agent hosting on (the host-work store, where the mailbox commits, opens
//! only then); the fake Astation as the relay with Astation in the room,
//! as Astation's local link, or as the relay routing the link on its host
//! route proof (§R9.7b). The sending host is the test's
//! (tests/support/sender.rs): it seals with the shared core and puts
//! through the fake Station. The host's state is read from the debug state
//! dump, its store (`runtime/host-work.sqlite`) and `atem status`; its
//! clocks are moved on the debug host clock, never by waiting. The fake
//! Station answers only when a test says (its own `heads` silenced), unless
//! the test puts it online ([`Rig::online`]).
#![cfg(target_os = "linux")]
mod support;

use atem_client::control::RefusedCall;
use atem_client::host_mail::mailbox::{MailboxDone, MailboxToStation, PutRefusal};
use serde_json::{Value, json};
use std::cell::Cell;
use std::collections::BTreeSet;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex, MutexGuard, mpsc};
use std::time::{Duration, Instant};
use support::astation::{ASTATION, Event, FakeAstation, RelayEvent, Reply, write_verified_pairing};
use support::delegated::{WAIT, hosting_toml, private};
use support::host_clock::HostClock;
use support::r9::write_pin;
use support::r9log::{TestLog, secret};
use support::sender::{Receiver, SenderHost};
use support::station::{FakeStation, Held, MailboxQuota, Pump};
use support::{Sandbox, within};

const ACCOUNT: &str = "acct-host-mail";
/// The receiving host (the runtime under test).
const HOST: &str = "host-mail";
/// The sending host the test plays.
const SENDER: &str = "host-sender";
/// Another host of the account (objects addressed to it go to its own
/// mailbox).
const OTHER_HOST: &str = "host-other";
/// The sending host's `host_key` seeds: its first `add_host`, and the one
/// of its re-verified trust generation 2.
const SENDER_SEED: &str = "host mail sender";
const SENDER_SEED_2: &str = "host mail sender, verified again";
/// The local link's relay setting (refused: the link is Astation's
/// `:8080`); the selected Station's origin is this, normalized.
const NO_RELAY: &str = "http://127.0.0.1:1";
/// A call's deadline on the host's monotonic clock (the Station's 30 s and
/// a 5 s grace, §11.5 rule 8).
const CALL_DEADLINE: u64 = 35_000;
/// The mailbox's reasons, as `atem status` and the dump give them
/// (`MailboxClient::closed`).
const READ_TO_HEAD: &str = "host senders' mailbox read to its head";

/// How the host reaches its Station.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Via {
    /// The relay, Astation authenticating the link in the room.
    Relay,
    /// Astation's local link (`ASTATION_WS`).
    Local,
    /// The relay, routed on the host's route proof, no Astation (§R9.7b).
    Routed,
}

/// The debug-only hook's features the runtime runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Hook {
    /// None (as every release build).
    Off,
    /// `host.delegated` alone.
    Delegated,
    /// `host.delegated,host.senders`.
    Senders,
}

struct Rig {
    sandbox: Sandbox,
    /// The fake Astation (`Local`) or relay (`Relay`, `Routed`).
    astation: FakeAstation,
    relay_events: Option<mpsc::Receiver<RelayEvent>>,
    /// The account's device list: pinned at the start, then grown where the
    /// test says.
    log: TestLog,
    station: Arc<Mutex<FakeStation>>,
    /// The Station online on its own ([`Rig::online`]).
    pump: Mutex<Option<Pump>>,
    clock: HostClock,
    runtime: Option<Child>,
    /// The host's link (the fake's connection number), the newest.
    link: Cell<u64>,
    via: Via,
    hook: Hook,
    /// The runtime's relay setting: the host's own Station's origin.
    relay_url: String,
    /// The sending host, in trust generation 1.
    sender: SenderHost,
}

impl Rig {
    /// A verified host whose pinned list is the Mac, this host, the sending
    /// host and another host, agent hosting on, the runtime running `hook`.
    /// The fake Station holds the same list and reads the host as one whose
    /// welcome lists `host.senders` when the hook turns it on.
    fn start(via: Via, hook: Hook) -> Rig {
        let sandbox = Sandbox::new();
        write_verified_pairing(&sandbox.config(), ACCOUNT, HOST, 1);
        let host_seed = secret("host mail host");
        let mut log = TestLog::genesis(ACCOUNT, &secret("host mail astation"));
        log.add_host(HOST, 1, &host_seed);
        log.add_host(SENDER, 1, &secret(SENDER_SEED));
        log.add_host(OTHER_HOST, 1, &secret("host mail other host"));
        write_pin(&sandbox.config(), &log, HOST, 1, &host_seed);
        // Agent hosting on: the host-work store opens only with it.
        let fake = sandbox.dir.path().join("fake");
        std::fs::create_dir_all(&fake).unwrap();
        let bin = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/approvals/fake-agent.py");
        let env_file = sandbox.dir.path().join("provider.json");
        private(
            &env_file,
            &json!({"CLAUDE_CLI_BIN": bin, "FAKE_DIR": fake}).to_string(),
        );
        private(
            &sandbox.config().join("runtime.toml"),
            &hosting_toml(
                &sandbox.home,
                &env_file,
                &[format!("member:{}", support::r9log::MAC)],
            ),
        );
        let head = log.log.head();
        let head = json!({"seq": head.seq, "hash": head.hash.to_hex()});
        let (astation, relay_events) = match via {
            Via::Local => (FakeAstation::start(), None),
            Via::Relay => {
                let (relay, events) = FakeAstation::start_relay(|_| Reply::AstationFirst {
                    ok: None,
                    reply_first: false,
                });
                (relay, Some(events))
            }
            Via::Routed => {
                let (relay, events) = FakeAstation::start_relay(move |_| Reply::Ok {
                    host_id: HOST.into(),
                    head: head.clone(),
                });
                (relay, Some(events))
            }
        };
        let relay_url = match via {
            Via::Local => NO_RELAY.to_owned(),
            Via::Relay | Via::Routed => astation.url.clone(),
        };
        // Made before the runtime: it takes the host's calls from the start.
        // Its heads only when a test says.
        let mut station = FakeStation::new(&astation, &relay_url, &log, HOST, 1);
        station.silence_heads(true);
        station.host_lists_senders(hook == Hook::Senders);
        let clock = HostClock::start(sandbox.dir.path(), "host-clock");
        let sender = SenderHost::new(&log, SENDER, 1, &secret(SENDER_SEED));
        let mut rig = Rig {
            sandbox,
            astation,
            relay_events,
            log,
            station: Arc::new(Mutex::new(station)),
            pump: Mutex::new(None),
            clock,
            runtime: None,
            link: Cell::new(0),
            via,
            hook,
            relay_url,
            sender,
        };
        rig.runtime = Some(rig.spawn());
        rig.link.set(rig.next_link(0));
        rig
    }

    /// `atem runtime` with the rig's hooks, its output appended to
    /// `runtime.log`.
    fn spawn(&self) -> Child {
        let output = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.sandbox.dir.path().join("runtime.log"))
            .unwrap();
        let mut command = Command::new(env!("CARGO_BIN_EXE_atem"));
        command.env_clear();
        match self.hook {
            Hook::Senders => {
                command.env("ATEM_TEST_HOST_FEATURES", "host.delegated,host.senders");
            }
            Hook::Delegated => {
                command.env("ATEM_TEST_HOST_FEATURES", "host.delegated");
            }
            // A release build compiles the hook out: it runs with it set,
            // and nothing may change.
            Hook::Off if !cfg!(debug_assertions) => {
                command.env("ATEM_TEST_HOST_FEATURES", "host.delegated,host.senders");
            }
            Hook::Off => {}
        }
        let local = match self.via {
            Via::Local => self.astation.url.clone(),
            Via::Relay | Via::Routed => "ws://127.0.0.1:1/ws".into(),
        };
        // A killed runtime's socket file and state dump aren't the new one's.
        let _ = std::fs::remove_file(self.sandbox.config().join("runtime.socket"));
        let _ = std::fs::remove_file(self.dump_file());
        // The crash points (`ATEM_TEST_PTY_FAULTS`): nothing acts until a
        // test puts a marker there ([`Rig::fault`]).
        std::fs::create_dir_all(self.faults()).unwrap();
        command
            .arg("runtime")
            .env("ATEM_TEST_PTY_FAULTS", self.faults())
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", &self.sandbox.home)
            .env("XDG_RUNTIME_DIR", &self.sandbox.run)
            .env("ASTATION_WS", local)
            .env("ASTATION_RELAY_URL", &self.relay_url)
            .env("ATEM_TEST_STATE_DUMP", self.dump_file())
            .env("ATEM_TEST_HOST_CLOCK", &self.clock.path)
            .env("ATEM_TEST_NO_INIT_LIMIT", "1")
            .stdin(Stdio::null())
            .stdout(output.try_clone().unwrap())
            .stderr(output)
            .spawn()
            .unwrap()
    }

    /// The runtime's next link after `after` (a connection number): the
    /// one Astation authenticated, or the one the relay routed.
    fn next_link(&self, after: u64) -> u64 {
        match self.via {
            Via::Local | Via::Relay => loop {
                match self.astation.events.recv_timeout(WAIT) {
                    Ok(Event::Authenticated(link)) if link > after => break link,
                    Ok(_) => {}
                    Err(_) => panic!("the runtime's link never authenticated"),
                }
            },
            Via::Routed => loop {
                match self.relay_events.as_ref().unwrap().recv_timeout(WAIT) {
                    Ok(RelayEvent::Proof { link, .. }) if link > after => break link,
                    Ok(_) => {}
                    Err(_) => panic!("no route proof"),
                }
            },
        }
    }

    /// Waits until the relay saw connection `link` end: everything the
    /// runtime sent on it has reached the fake (a relay link only).
    fn link_closed(&self, link: u64) {
        let events = self.relay_events.as_ref().expect("a relay");
        let deadline = Instant::now() + WAIT;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            match events.recv_timeout(left) {
                Ok(RelayEvent::Closed(n)) if n == link => return,
                Ok(_) => {}
                Err(_) => panic!("connection {link} never ended"),
            }
        }
    }

    /// The crash points' directory (`ATEM_TEST_PTY_FAULTS`).
    fn faults(&self) -> PathBuf {
        self.sandbox.dir.path().join("faults")
    }

    /// Arms the crash point `name` (its marker; used once).
    fn fault(&self, name: &str) {
        private(&self.faults().join(name), "");
    }

    /// A runtime again (after it died), on a new link.
    fn start_again(&mut self) {
        self.runtime = Some(self.spawn());
        let link = self.next_link(self.link.get());
        self.link.set(link);
    }

    fn link(&self) -> u64 {
        self.link.get()
    }

    fn runtime_log(&self) -> String {
        std::fs::read_to_string(self.sandbox.dir.path().join("runtime.log")).unwrap_or_default()
    }

    fn dump_file(&self) -> PathBuf {
        self.sandbox.dir.path().join("state.json")
    }

    /// The host's state after its last pass (the debug state dump).
    fn dump(&self) -> Value {
        std::fs::read(self.dump_file())
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or(Value::Null)
    }

    /// The mailbox client's state (`MailboxClient::dump`).
    fn mailbox(&self) -> Value {
        self.dump()["station"]["mailbox"].clone()
    }

    /// Waits up to a minute for `done`; a timeout shows the host's mailbox
    /// state and the end of its log.
    #[track_caller]
    fn within(&self, what: &str, mut done: impl FnMut() -> bool) {
        let deadline = Instant::now() + WAIT;
        while !done() {
            if Instant::now() >= deadline {
                let log = self.runtime_log();
                let tail: Vec<_> = log.lines().rev().take(30).collect();
                let station = self.dump()["station"].clone();
                panic!(
                    "timed out waiting for {what}\nmailbox: {}\nfetch: {}\nlog (newest first):\n{}",
                    station["mailbox"],
                    station["fetch"],
                    tail.join("\n")
                );
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// Waits for the mailbox client's state to satisfy `done`.
    #[track_caller]
    fn until_mailbox(&self, what: &str, done: impl Fn(&Value) -> bool) -> Value {
        let mut last = Value::Null;
        self.within(what, || {
            last = self.mailbox();
            done(&last)
        });
        last
    }

    /// Waits for two passes of the broker begun after now.
    fn two_passes(&self) {
        let pass = |rig: &Rig| rig.dump()["pass"].as_u64().unwrap_or(0);
        let now = pass(self);
        self.within("two passes", || pass(self) >= now + 2);
    }

    fn station(&self) -> MutexGuard<'_, FakeStation> {
        self.station.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The Station answers what the host asked so far, then announces its
    /// heads (its mailbox's included) on the host's link now.
    fn announce(&self) {
        let mut station = self.station();
        station.serve(self.link());
        station.heads_now();
    }

    /// [`Rig::announce`] a second later on the host's clock: past the pace
    /// of a sync a `heads` starts (§11.5 rule 8).
    fn announce_paced(&self) {
        self.clock.add_mono(1_000);
        self.announce();
    }

    /// The Station serves the host's link until `done`.
    #[track_caller]
    fn serve_until(&self, what: &str, done: impl Fn(&Rig) -> bool) {
        self.within(what, || {
            self.station().serve(self.link());
            done(self)
        });
    }

    /// The Station online on its own from now on ([`Pump`], every 10 ms):
    /// every call answered at once, `heads` every second and at once for a
    /// stored object.
    fn online(&self) {
        self.station().silence_heads(false);
        *self.pump.lock().unwrap() =
            Some(Pump::every(self.station.clone(), Duration::from_millis(10)));
    }

    /// The Station answers only when the test says again.
    fn offline(&self) {
        drop(self.pump.lock().unwrap().take());
        self.station().silence_heads(true);
    }

    /// This host as a sender seals to it, once its runtime made its
    /// encryption key for trust generation `generation` (with
    /// `host.senders`, at its start or at a reopen of its list).
    fn receiver(&self, generation: u64) -> Receiver {
        let mut found = None;
        self.within("the host's encryption key", || {
            found = Receiver::of(&self.sandbox.config(), HOST)
                .filter(|r| r.host_trust_gen == generation);
            found.is_some()
        });
        found.unwrap()
    }

    /// `object` put by the sending host, stored: its position in the host's
    /// mailbox.
    #[track_caller]
    fn put(&self, object: &atem_client::SignedObject) -> u64 {
        let mut station = self.station();
        self.sender.put_stored(&mut station, object);
        let id = atem_client::host_mail::MailBody::from_object(object)
            .unwrap()
            .1
            .id;
        station.position_of(&id).expect("stored")
    }

    /// The host-work store (`runtime/host-work.sqlite`), once the runtime
    /// made it (never made here: the runtime refuses a store it didn't
    /// make private).
    fn db(&self) -> rusqlite::Connection {
        self.store().expect("the host-work store")
    }

    /// The host-work store, if the runtime made it.
    fn store(&self) -> Option<rusqlite::Connection> {
        use rusqlite::OpenFlags;
        let db = rusqlite::Connection::open_with_flags(
            self.sandbox.config().join("runtime/host-work.sqlite"),
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .ok()?;
        db.busy_timeout(Duration::from_secs(5)).unwrap();
        Some(db)
    }

    /// Rows in `table` (none without it).
    fn count(&self, table: &str) -> u64 {
        self.db()
            .query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))
            .unwrap_or(0)
    }

    /// The stored cursor: `(mailbox_id, position)`.
    fn cursor(&self) -> Option<(String, u64)> {
        self.db()
            .query_row(
                "SELECT mailbox_id, cursor FROM mailbox_cursor WHERE one=1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .ok()
    }

    /// The dones the store owes: `(mailbox_id, position)`, in order.
    fn owed(&self) -> Vec<(String, u64)> {
        let db = self.db();
        let Ok(mut q) = db.prepare("SELECT mailbox_id, position FROM mailbox_dones ORDER BY 1, 2")
        else {
            return Vec::new();
        };
        q.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap()
            .map(Result::unwrap)
            .collect()
    }

    /// The inbox's rows: `(sender host, object id, kind)`, in order.
    fn inbox(&self) -> Vec<(String, String, String)> {
        let db = self.db();
        let Ok(mut q) =
            db.prepare("SELECT sender_host, object_id, kind FROM mailbox_inbox ORDER BY n")
        else {
            return Vec::new();
        };
        q.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .unwrap()
            .map(Result::unwrap)
            .collect()
    }

    /// The refusal rows: `(reason, report)`, in order.
    fn refused(&self) -> Vec<(String, bool)> {
        let db = self.db();
        let Ok(mut q) = db.prepare("SELECT reason, report FROM mailbox_refused ORDER BY n") else {
            return Vec::new();
        };
        q.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap()
            .map(Result::unwrap)
            .collect()
    }

    /// Every object the store decided into a row (the inbox, the refusals,
    /// the kept results).
    fn decided_rows(&self) -> u64 {
        self.count("mailbox_inbox") + self.count("mailbox_refused") + self.count("mailbox_results")
    }

    /// Admission takes every inbox row (it isn't built: the test does what
    /// it will do), in one transaction.
    fn admit_all(&self) {
        let mut db = self.db();
        let tx = db
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .unwrap();
        tx.execute("DELETE FROM mailbox_inbox", []).unwrap();
        tx.commit().unwrap();
    }

    /// The host's `mailbox_done`s so far, each with the link it came on.
    fn dones(&self) -> Vec<(u64, MailboxDone)> {
        self.station()
            .mailbox_calls()
            .into_iter()
            .filter_map(|(link, call)| match call {
                MailboxToStation::Done(done) => Some((link, done)),
                _ => None,
            })
            .collect()
    }

    /// The positions of `mailbox_id` the host's dones named so far, in
    /// order.
    fn done_positions(&self, mailbox_id: &str) -> Vec<u64> {
        self.dones()
            .into_iter()
            .filter(|(_, d)| d.mailbox_id == mailbox_id)
            .map(|(_, d)| d.position)
            .collect()
    }

    /// The host's `mailbox_sync`s so far (`mailbox_id`, `after`).
    fn syncs(&self) -> Vec<(String, u64)> {
        self.station()
            .mailbox_calls()
            .into_iter()
            .filter_map(|(_, call)| match call {
                MailboxToStation::Sync(sync) => Some((sync.mailbox_id, sync.after)),
                _ => None,
            })
            .collect()
    }

    /// The host's next mailbox call on its link that `take` takes, held
    /// unanswered (the ones before it answered as they come).
    fn hold(&self, take: impl Fn(&MailboxToStation) -> bool) -> (Held, MailboxToStation) {
        let held = self.station().hold_mailbox(self.link(), take);
        let call = held.mailbox().unwrap();
        (held, call)
    }

    /// The Station answers the held mailbox call now (late, when the host
    /// has moved on), on the link it came on.
    fn answer(&self, held: Held) {
        held.mailbox().expect("a mailbox call");
        // The §11.4 reader's view of it (`WrongMessage`) isn't the answer.
        let _ = self.station().answer_held(held);
    }

    /// `atem status`'s `Control feeds:` line, until it contains `expected`
    /// (the runtime's look is passive and may lag a pass).
    #[track_caller]
    fn status_feeds(&self, expected: &str) -> String {
        let mut last = String::new();
        self.within(&format!("Control feeds: …{expected}…"), || {
            let (out, err, _) = self.sandbox.atem(&["status"]);
            last = out
                .lines()
                .find_map(|l| l.strip_prefix("Control feeds:"))
                .map(|v| v.trim().to_string())
                .unwrap_or_else(|| format!("(no line) {out}{err}"));
            last.contains(expected)
        });
        last
    }
}

impl Drop for Rig {
    fn drop(&mut self) {
        drop(self.pump.get_mut().unwrap().take());
        self.sandbox.track();
        if let Some(mut child) = self.runtime.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn is_sync(call: &MailboxToStation) -> bool {
    matches!(call, MailboxToStation::Sync(_))
}

fn is_done(call: &MailboxToStation) -> bool {
    matches!(call, MailboxToStation::Done(_))
}

/// Astation's `auth_required` on the host's link again: it re-authenticates
/// it, a new link generation on the same socket.
fn reauthenticate(rig: &Rig, n: u8) {
    let generation = rig.dump()["station"]["link"]["gen"].as_u64().unwrap();
    let transport = match rig.via {
        Via::Local => "lan",
        Via::Relay | Via::Routed => "relay",
    };
    let challenge = json!({"type": "statusUpdate", "data": {"status": "auth_required",
        "data": {"astation_id": ASTATION, "challenge": format!("{n:x}").repeat(64),
                 "transport": transport, "protocol": "2"}}});
    rig.astation.send(rig.link(), challenge.to_string());
    rig.within("the next link generation", || {
        rig.dump()["station"]["link"]["gen"].as_u64() > Some(generation)
    });
}

// ── The fake Station's mailbox ──

/// The fake Station's puts follow §11.5 rules 1 and 3 (no runtime): stored
/// once per key while stored (the same bytes again answered `stored`,
/// other bytes `id_reused`), an answer lost and the put made again stored
/// once, the key free again once the object is done; `forbidden` for an
/// object that isn't the calling host's, or for a recipient that isn't a
/// current host at that generation; `expired`; `quota` at the per-sender
/// limit and while the switch is on; an object to another host stored in
/// that host's mailbox. Pages cover removed positions up to the next stored
/// object.
#[test]
fn the_fake_mailbox_follows_the_put_rules() {
    let astation = FakeAstation::start();
    let mut log = TestLog::genesis(ACCOUNT, &secret("host mail astation"));
    log.add_host(HOST, 1, &secret("host mail host"));
    log.add_host(SENDER, 1, &secret(SENDER_SEED));
    log.add_host(OTHER_HOST, 1, &secret("host mail other host"));
    let mut station = FakeStation::new(&astation, NO_RELAY, &log, HOST, 1);
    let sender = SenderHost::new(&log, SENDER, 1, &secret(SENDER_SEED));
    let to = Receiver::other(HOST, 1, "host mail host enc");
    let head = log.log.head();
    let a = sender.cancel(&to, head);
    sender.put_stored(&mut station, &a);
    sender.put_stored(&mut station, &a);
    assert_eq!(
        station.mailbox_positions(),
        [1],
        "the same bytes, stored once"
    );
    // The same id with other bytes: `id_reused`, the first stays.
    let mut fields = atem_client::host_mail::MailBody::from_object(&a)
        .unwrap()
        .1
        .fields();
    fields.created_at += 1;
    let reused = {
        let mut keys = atem_client::SoftwareKeys::new();
        keys.insert_ed25519(atem_client::KeyId::new("host_key"), &secret(SENDER_SEED));
        atem_client::host_mail::seal_envelope(
            &keys,
            &atem_client::KeyId::new("host_key"),
            &fields,
            &atem_client::host_mail::EnvelopePlain::Cancel {
                task_id: uuid::Uuid::new_v4().to_string(),
            },
            &to.enc_pub,
        )
        .unwrap()
    };
    assert_eq!(
        sender.put_refused(&mut station, &reused),
        PutRefusal::IdReused
    );
    // An answer lost: the put made again is stored once.
    let b = sender.cancel(&to, head);
    station.drop_stored(1);
    assert_eq!(sender.put(&mut station, &b), None);
    sender.put_stored(&mut station, &b);
    assert_eq!(station.mailbox_positions(), [1, 2]);
    // Not the calling host's object, or for a host that isn't one:
    // `forbidden`.
    let other_sender = SenderHost::new(&log, OTHER_HOST, 1, &secret("host mail other host"));
    let mut station_put = |object: &atem_client::SignedObject| {
        let put = atem_client::host_mail::mailbox::MailboxPut {
            request_id: uuid::Uuid::new_v4().to_string(),
            object: object.clone(),
        };
        station.put(SENDER, 1, put.to_json().unwrap().to_string().as_bytes())
    };
    let theirs = other_sender.cancel(&to, head);
    let answer = station_put(&theirs).unwrap();
    assert!(answer.contains("\"forbidden\""), "{answer}");
    let stranger = sender.cancel(&Receiver::other("host-unknown", 1, "unknown"), head);
    assert_eq!(
        sender.put_refused(&mut station, &stranger),
        PutRefusal::Forbidden
    );
    let stale = sender.cancel(&Receiver::other(HOST, 2, "host mail host enc"), head);
    assert_eq!(
        sender.put_refused(&mut station, &stale),
        PutRefusal::Forbidden
    );
    // Expired.
    let mut fields = sender.fields(&to, head);
    fields.created_at -= 2 * 60 * 60 * 1000;
    fields.expires_at -= 2 * 60 * 60 * 1000;
    let expired = {
        let mut keys = atem_client::SoftwareKeys::new();
        keys.insert_ed25519(atem_client::KeyId::new("host_key"), &secret(SENDER_SEED));
        atem_client::host_mail::seal_envelope(
            &keys,
            &atem_client::KeyId::new("host_key"),
            &fields,
            &atem_client::host_mail::EnvelopePlain::Cancel {
                task_id: uuid::Uuid::new_v4().to_string(),
            },
            &to.enc_pub,
        )
        .unwrap()
    };
    assert_eq!(
        sender.put_refused(&mut station, &expired),
        PutRefusal::Expired
    );
    // The quotas: the switch, then the per-sender limit.
    station.refuse_quota(true);
    assert_eq!(
        sender.put_refused(&mut station, &sender.cancel(&to, head)),
        PutRefusal::Quota
    );
    station.refuse_quota(false);
    station.set_mailbox_quota(MailboxQuota {
        per_sender: 2,
        ..MailboxQuota::default()
    });
    assert_eq!(
        sender.put_refused(&mut station, &sender.cancel(&to, head)),
        PutRefusal::Quota
    );
    station.set_mailbox_quota(MailboxQuota::default());
    // To another host: its own mailbox, not this host's.
    let elsewhere = sender.cancel(&Receiver::other(OTHER_HOST, 1, "other enc"), head);
    sender.put_stored(&mut station, &elsewhere);
    assert_eq!(station.stored_for(OTHER_HOST, 1), 1);
    assert_eq!(station.mailbox_positions(), [1, 2]);
    assert_eq!(station.puts_dropped(), 0);
    let c = sender.cancel(&to, head);
    sender.put_stored(&mut station, &c);
    assert_eq!(station.mailbox_positions(), [1, 2, 3]);
    assert_eq!(station.mailbox_head(), 3);
}

// ── Reading the mailbox ──

/// Rules 4 and 5, design II.4.2: announced a mailbox with a request, a
/// forged object, a result and one sealed to another host's key, the host
/// reads it to its head, object by object: the request opens into the
/// inbox, the forged one is refused (`bad_signature`) and the other
/// host's (`enc_key_not_accepted`), both evidence only, and the result is
/// kept for the sending host's own check. Each `mailbox_done` goes only
/// after its page committed: when it reaches the Station the store already
/// holds the cursor past its position, the object's row and the done owed.
/// Answered, the owed dones go and the Station's mailbox is empty; the
/// opened request holds host senders' gate until admission takes it. An
/// object addressed to another host is stored in that host's mailbox and
/// never reaches this one. On the relay with Astation in the room, on
/// Astation's local link and on a routed link.
#[test]
#[cfg_attr(
    not(debug_assertions),
    ignore = "needs the debug ATEM_TEST_HOST_FEATURES and ATEM_TEST_STATE_DUMP hooks"
)]
fn reads_its_mailbox_to_the_head_on_relay_local_and_routed_links() {
    for via in [Via::Relay, Via::Local, Via::Routed] {
        let rig = Rig::start(via, Hook::Senders);
        let to = rig.receiver(1);
        let head = rig.log.log.head();
        let request = rig.sender.request(&to, head, "Review the contract");
        let request_id = atem_client::host_mail::MailBody::from_object(&request)
            .unwrap()
            .1
            .id;
        let other_key = Receiver::other(OTHER_HOST, 1, "other enc");
        for object in [
            &request,
            &rig.sender.forged(&to, head),
            &rig.sender.result(&to, head),
            &rig.sender.sealed_to(&to, &other_key, head),
        ] {
            rig.put(object);
        }
        rig.put_elsewhere(&rig.sender.request(&other_key, head, "Not for this host"));
        let mailbox_id = rig.station().mailbox_id();
        assert_eq!(rig.station().mailbox_positions(), [1, 2, 3, 4], "{via:?}");
        rig.announce();
        let mut done = BTreeSet::new();
        while done.len() < 4 {
            let (held, call) = rig.hold(is_done);
            let MailboxToStation::Done(call) = call else {
                unreachable!()
            };
            assert_eq!(call.mailbox_id, mailbox_id, "{via:?}");
            // Committed before it went: the cursor, the row, the done owed.
            let (at_id, at) = rig.cursor().expect("a cursor");
            assert_eq!(at_id, mailbox_id);
            assert!(
                at >= call.position,
                "{via:?}: cursor {at}, done {}",
                call.position
            );
            assert!(
                rig.decided_rows() >= call.position,
                "{via:?}: the row of position {}",
                call.position
            );
            assert!(
                rig.owed().contains(&(mailbox_id.clone(), call.position)),
                "{via:?}: owed when it went"
            );
            assert!(done.insert(call.position), "{via:?}: a done once");
            rig.answer(held);
        }
        rig.serve_until("every done answered", |rig| rig.owed().is_empty());
        assert_eq!(rig.cursor(), Some((mailbox_id.clone(), 4)), "{via:?}");
        assert!(rig.station().mailbox_positions().is_empty(), "{via:?}");
        assert_eq!(
            rig.inbox(),
            [(SENDER.to_string(), request_id, "request".to_string())],
            "{via:?}"
        );
        assert_eq!(
            rig.refused(),
            [
                ("bad_signature".to_string(), false),
                ("enc_key_not_accepted".to_string(), false)
            ],
            "{via:?}"
        );
        assert_eq!(rig.count("mailbox_results"), 1, "{via:?}");
        assert_eq!(rig.count("mailbox_pending"), 0, "{via:?}");
        assert_eq!(rig.station().stored_for(OTHER_HOST, 1), 1, "{via:?}");
        // Each position done once; the syncs read on from the cursor.
        assert_eq!(rig.done_positions(&mailbox_id), [1, 2, 3, 4], "{via:?}");
        let afters: Vec<u64> = rig.syncs().into_iter().map(|(_, after)| after).collect();
        assert_eq!(afters, [0, 1, 2, 3], "{via:?}");
        let mailbox = rig.until_mailbox("the inbox waits", |m| m["open"] == false);
        assert_eq!(
            mailbox["closed"], "1 mailbox object(s) wait for admission",
            "{via:?}"
        );
        assert_eq!(mailbox["faults"], 0, "{via:?}");
        if via == Via::Relay {
            rig.status_feeds(
                "host senders' mailbox not checked (1 mailbox object(s) wait for admission)",
            );
        }
    }
}

impl Rig {
    /// `object`, addressed to another host, put by the sending host: stored
    /// in that host's mailbox.
    fn put_elsewhere(&self, object: &atem_client::SignedObject) {
        let mut station = self.station();
        self.sender.put_stored(&mut station, object);
    }

    /// The pinned device list's head `seq`, as written.
    fn list_head(&self) -> u64 {
        let path = self.sandbox.config().join("pairing/membership.json");
        let state: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        state["head"]["seq"].as_u64().unwrap()
    }

    /// The Station announces, each time past a fetch refusal's 30 s backoff
    /// on the host's clock, and serves until the host's list reached the
    /// test's (a refusal the host reads after the clock moved restarts its
    /// backoff: the next round asks again).
    fn fetch_list(&self) {
        let seq = self.log.log.head().seq;
        let deadline = Instant::now() + WAIT;
        while self.list_head() < seq {
            assert!(
                Instant::now() < deadline,
                "the list never reached {seq}: {}",
                self.dump()["station"]["fetch"]
            );
            self.clock.add_mono(30_000);
            self.announce();
            self.two_passes();
            self.station().serve(self.link());
            self.two_passes();
        }
    }
}

/// Rule 5 and Astation's ask (#120): the runtime killed (`SIGKILL`) right
/// after a page's commit and before its done (the debug crash point
/// `crash_after_mailbox_commit`): no done reached the Station, and the
/// store holds the decision, the cursor and the done owed. Started again,
/// on a new link, the host sends that done exactly once (no page is read
/// again, nothing decided twice), and nothing more after its answer.
#[test]
#[cfg_attr(
    not(debug_assertions),
    ignore = "needs the debug ATEM_TEST_HOST_FEATURES, ATEM_TEST_PTY_FAULTS and ATEM_TEST_STATE_DUMP hooks"
)]
fn a_kill_between_commit_and_done_sends_the_owed_done_once_after_restart() {
    use std::os::unix::process::ExitStatusExt;
    let mut rig = Rig::start(Via::Relay, Hook::Senders);
    let to = rig.receiver(1);
    rig.fault("crash_after_mailbox_commit");
    rig.put(
        &rig.sender
            .request(&to, rig.log.log.head(), "Before the crash"),
    );
    let mailbox_id = rig.station().mailbox_id();
    rig.announce();
    let deadline = Instant::now() + WAIT;
    let status = loop {
        rig.station().serve(rig.link());
        if let Some(status) = rig.runtime.as_mut().unwrap().try_wait().unwrap() {
            break status;
        }
        assert!(
            Instant::now() < deadline,
            "the crash point never fired\n{}",
            rig.runtime_log()
        );
        std::thread::sleep(Duration::from_millis(20));
    };
    rig.sandbox.track();
    rig.runtime = None;
    assert_eq!(status.signal(), Some(libc::SIGKILL));
    // Everything the runtime sent on its link has reached the fake.
    rig.link_closed(rig.link());
    assert!(
        rig.runtime_log()
            .contains("test hook: killed after a mailbox page's commit, before its dones")
    );
    rig.station().serve(rig.link());
    assert!(rig.dones().is_empty(), "no done before the crash");
    assert_eq!(rig.cursor(), Some((mailbox_id.clone(), 1)));
    assert_eq!(rig.owed(), [(mailbox_id.clone(), 1)]);
    assert_eq!(rig.inbox().len(), 1);
    // Started again: the owed done goes once its mailbox is announced.
    let old_link = rig.link();
    let syncs_before = rig.syncs().len();
    rig.start_again();
    rig.announce();
    rig.serve_until("the owed done answered", |rig| rig.owed().is_empty());
    let dones = rig.dones();
    assert_eq!(dones.len(), 1, "{dones:?}");
    assert_eq!(dones[0].0, rig.link());
    assert_ne!(rig.link(), old_link);
    assert_eq!(
        (dones[0].1.mailbox_id.as_str(), dones[0].1.position),
        (mailbox_id.as_str(), 1)
    );
    // Nothing more: no page read again, no done again, at later heads and
    // after a call's deadline.
    for _ in 0..2 {
        rig.clock.add_mono(CALL_DEADLINE);
        rig.announce();
        rig.two_passes();
    }
    rig.station().serve(rig.link());
    assert_eq!(rig.dones().len(), 1);
    let syncs = rig.syncs();
    assert!(
        syncs[syncs_before..].iter().all(|(_, after)| *after >= 1),
        "{syncs:?}"
    );
    assert_eq!(rig.inbox().len(), 1, "decided once");
    assert_eq!(rig.mailbox()["dones_answered"], 1);
}

// ── Resets (rule 7) ──

/// Rule 7: the Station's mailbox reset with a new `mailbox_id` (its store
/// lost) while two dones' answers were lost (both owed). The host marks
/// the reset (the old mailbox's dones dropped), reads the new mailbox from
/// 0 and marks done only what it read there: the object the sender put
/// again comes as a duplicate (no new row) and is done in the new
/// mailbox; the old mailbox gets no done again, even after the old dones'
/// deadline.
#[test]
#[cfg_attr(
    not(debug_assertions),
    ignore = "needs the debug ATEM_TEST_HOST_FEATURES and ATEM_TEST_STATE_DUMP hooks"
)]
fn a_reset_with_a_new_mailbox_id_rereads_from_0_and_marks_done_only_what_it_reads() {
    let rig = Rig::start(Via::Relay, Hook::Senders);
    let to = rig.receiver(1);
    let head = rig.log.log.head();
    let a = rig.sender.request(&to, head, "A");
    let b = rig.sender.cancel(&to, head);
    rig.put(&a);
    rig.put(&b);
    let old = rig.station().mailbox_id();
    rig.station().drop_done_results(2);
    rig.announce();
    rig.serve_until("both read, their dones sent", |rig| {
        rig.dones().len() == 2 && rig.cursor() == Some((old.clone(), 2))
    });
    assert_eq!(rig.owed(), [(old.clone(), 1), (old.clone(), 2)]);
    // The Station's store is lost: a new mailbox; the sender puts B again
    // (A it doesn't: no done for it may follow).
    rig.station().reset_mailbox(false);
    let new = rig.station().mailbox_id();
    assert_ne!(new, old);
    assert_eq!(rig.put(&b), 1);
    let before = rig.dones().len();
    rig.announce_paced();
    rig.serve_until("the new mailbox read", |rig| {
        rig.cursor() == Some((new.clone(), 1)) && rig.owed().is_empty()
    });
    let after: Vec<(String, u64)> = rig.dones()[before..]
        .iter()
        .map(|(_, d)| (d.mailbox_id.clone(), d.position))
        .collect();
    assert_eq!(after, [(new.clone(), 1)]);
    assert_eq!(rig.syncs().last(), Some(&(new.clone(), 0)), "from 0");
    // Nothing for the old mailbox again, after the old dones' deadline too.
    rig.clock.add_mono(CALL_DEADLINE + 1_000);
    rig.announce();
    rig.two_passes();
    rig.station().serve(rig.link());
    assert_eq!(
        rig.done_positions(&old),
        [1, 2],
        "only the two before the reset"
    );
    assert_eq!(rig.done_positions(&new), [1]);
    assert_eq!(rig.inbox().len(), 2, "B read again is a duplicate");
    let mailbox = rig.mailbox();
    assert_eq!(mailbox["resets"], 1, "{mailbox}");
    assert_eq!(mailbox["faults"], 0, "{mailbox}");
}

/// Rule 7: the Station's mailbox went back under the same `mailbox_id` (a
/// Station fault: its head below the host's cursor) while three dones'
/// answers were lost. The host marks the reset and reads the mailbox from
/// 0 again: it marks done only the object it reads there now (the one the
/// sender put again, at a position the rollback gave out again), never the
/// positions it doesn't see again.
#[test]
#[cfg_attr(
    not(debug_assertions),
    ignore = "needs the debug ATEM_TEST_HOST_FEATURES and ATEM_TEST_STATE_DUMP hooks"
)]
fn a_reset_under_the_same_mailbox_id_rereads_from_0_and_marks_done_only_what_it_reads() {
    let rig = Rig::start(Via::Relay, Hook::Senders);
    let to = rig.receiver(1);
    let head = rig.log.log.head();
    let objects = [
        rig.sender.request(&to, head, "A"),
        rig.sender.cancel(&to, head),
        rig.sender.cancel(&to, head),
    ];
    for object in &objects {
        rig.put(object);
    }
    let mailbox_id = rig.station().mailbox_id();
    rig.station().drop_done_results(3);
    rig.announce();
    rig.serve_until("all three read, their dones sent", |rig| {
        rig.dones().len() == 3 && rig.cursor() == Some((mailbox_id.clone(), 3))
    });
    assert_eq!(rig.owed().len(), 3);
    // The Station rolls back to position 1 and gives position 2 out again,
    // to the third object, put again.
    rig.station().roll_back_mailbox(1);
    assert_eq!(rig.put(&objects[2]), 2);
    let before = rig.dones().len();
    rig.announce_paced();
    rig.serve_until("the mailbox read again", |rig| {
        rig.cursor() == Some((mailbox_id.clone(), 2)) && rig.owed().is_empty()
    });
    assert_eq!(rig.station().mailbox_id(), mailbox_id, "the same id");
    let after: Vec<u64> = rig.dones()[before..]
        .iter()
        .map(|(_, d)| d.position)
        .collect();
    assert_eq!(after, [2], "only what it read again");
    let from_0 = rig
        .syncs()
        .iter()
        .filter(|sync| **sync == (mailbox_id.clone(), 0))
        .count();
    assert_eq!(from_0, 2, "read from 0 again");
    rig.clock.add_mono(CALL_DEADLINE + 1_000);
    rig.announce();
    rig.two_passes();
    rig.station().serve(rig.link());
    assert_eq!(rig.done_positions(&mailbox_id), [1, 2, 3, 2]);
    assert_eq!(rig.inbox().len(), 3, "the third read again is a duplicate");
    assert_eq!(rig.mailbox()["resets"], 1);
}

// ── Lost and late answers (rule 8) ──

/// Rule 8: a `mailbox_done_result` lost leaves the done owed: it goes again
/// with a fresh `request_id` on the next link generation (once that link's
/// `heads` announced the mailbox), and again after its 35 s deadline, until
/// an answer clears it. A page delivered after its call was retired (35 s
/// unanswered, asked again with a fresh id) is drained: nothing of it
/// applies twice.
#[test]
#[cfg_attr(
    not(debug_assertions),
    ignore = "needs the debug ATEM_TEST_HOST_FEATURES, ATEM_TEST_HOST_CLOCK and ATEM_TEST_STATE_DUMP hooks"
)]
fn lost_done_results_send_the_done_again_and_a_late_page_is_drained() {
    let rig = Rig::start(Via::Relay, Hook::Senders);
    let to = rig.receiver(1);
    let head = rig.log.log.head();
    rig.put(&rig.sender.request(&to, head, "A"));
    let mailbox_id = rig.station().mailbox_id();
    rig.station().drop_done_results(2);
    rig.announce();
    rig.serve_until("the first done", |rig| rig.dones().len() == 1);
    // A new link generation: the done again, once its heads came.
    reauthenticate(&rig, 0xc);
    rig.announce_paced();
    rig.serve_until("the done again", |rig| rig.dones().len() == 2);
    assert_eq!(rig.owed(), [(mailbox_id.clone(), 1)], "still owed");
    // Its deadline: again, answered this time.
    rig.clock.add_mono(CALL_DEADLINE);
    rig.serve_until("the done answered", |rig| rig.owed().is_empty());
    let dones = rig.dones();
    assert_eq!(dones.len(), 3, "{dones:?}");
    assert!(
        dones
            .iter()
            .all(|(_, d)| d.mailbox_id == mailbox_id && d.position == 1)
    );
    let ids: BTreeSet<&str> = dones.iter().map(|(_, d)| d.request_id.as_str()).collect();
    assert_eq!(ids.len(), 3, "a fresh id each time");
    assert_eq!(rig.mailbox()["dones_answered"], 1);
    // A late page: the sync held past its deadline, asked again and
    // answered; then the late one.
    rig.put(&rig.sender.cancel(&to, head));
    rig.announce_paced();
    let (late, call) = rig.hold(is_sync);
    let MailboxToStation::Sync(late_call) = call else {
        unreachable!()
    };
    assert_eq!(late_call.after, 1);
    let drained = rig.mailbox()["drained"].as_u64().unwrap();
    rig.clock.add_mono(CALL_DEADLINE);
    rig.until_mailbox("the call retired", |m| m["timeouts"] == 1);
    rig.announce_paced();
    rig.serve_until("read again with a fresh id", |rig| {
        rig.cursor() == Some((mailbox_id.clone(), 2)) && rig.owed().is_empty()
    });
    rig.answer(late);
    rig.until_mailbox("the late page drained", |m| {
        m["drained"].as_u64() == Some(drained + 1)
    });
    assert_eq!(rig.inbox().len(), 2, "nothing applied twice");
    assert_eq!(rig.mailbox()["faults"], 0);
    assert_eq!(rig.done_positions(&mailbox_id), [1, 1, 1, 2]);
}

// ── Waiting objects and overflow ──

/// Design II.4.2, rule 5: an object of the sending host's newer trust
/// generation (re-verified: its new `add_host` in the Station's list,
/// which this host can't fetch yet: the Station refuses the fetch) waits:
/// a pending row, never marked done, while the host reads past it; it
/// holds no gate. Once the host fetches the list it lacked, the object is
/// judged again, opens into the inbox, and its done goes, once.
#[test]
#[cfg_attr(
    not(debug_assertions),
    ignore = "needs the debug ATEM_TEST_HOST_FEATURES, ATEM_TEST_HOST_CLOCK and ATEM_TEST_STATE_DUMP hooks"
)]
fn a_waiting_object_is_kept_not_done_and_decided_once_the_device_list_advances() {
    let mut rig = Rig::start(Via::Relay, Hook::Senders);
    let to = rig.receiver(1);
    rig.station().refuse(RefusedCall::MembershipFetch, true);
    rig.log.add_host(SENDER, 2, &secret(SENDER_SEED_2));
    rig.station().set_log(&rig.log);
    let sender = SenderHost::new(&rig.log, SENDER, 2, &secret(SENDER_SEED_2));
    let object = sender.request(&to, rig.log.log.head(), "From the new generation");
    let position = {
        let mut station = rig.station();
        sender.put_stored(&mut station, &object);
        station.mailbox_positions()[0]
    };
    let mailbox_id = rig.station().mailbox_id();
    rig.announce();
    rig.serve_until("read past it", |rig| {
        rig.cursor() == Some((mailbox_id.clone(), position))
    });
    assert_eq!(rig.count("mailbox_pending"), 1);
    // Never done while it waits, through more heads and a call's deadline.
    for _ in 0..2 {
        rig.clock.add_mono(CALL_DEADLINE);
        rig.announce();
        rig.two_passes();
    }
    rig.station().serve(rig.link());
    assert!(rig.dones().is_empty());
    assert!(rig.owed().is_empty());
    assert_eq!(rig.station().mailbox_positions(), [position]);
    assert_eq!(rig.count("mailbox_pending"), 1);
    assert!(rig.inbox().is_empty());
    let mailbox = rig.until_mailbox("read to its head", |m| m["open"] == true);
    assert_eq!(
        mailbox["closed"],
        Value::Null,
        "a waiting object holds no gate"
    );
    // The fetch goes through: the list advances, the object is decided.
    rig.station().refuse(RefusedCall::MembershipFetch, false);
    rig.fetch_list();
    rig.serve_until("decided and done", |rig| {
        rig.count("mailbox_pending") == 0 && rig.owed().is_empty() && !rig.dones().is_empty()
    });
    assert_eq!(rig.inbox().len(), 1);
    assert_eq!(rig.inbox()[0].2, "request");
    assert_eq!(rig.done_positions(&mailbox_id), [position], "once");
    assert!(rig.station().mailbox_positions().is_empty());
}

/// Design II.4.2, rule 5 (Atem's refinement, agreed): the pending limits,
/// 64 per claimed `(host_id, host_trust_gen)`: the 65th waiting object of
/// the sending host's newer generation is dropped undecided and marked
/// done; the 64 others wait, never done, still on the Station.
#[test]
#[cfg_attr(
    not(debug_assertions),
    ignore = "needs the debug ATEM_TEST_HOST_FEATURES and ATEM_TEST_STATE_DUMP hooks"
)]
fn an_object_over_the_pending_limits_is_marked_done() {
    let mut rig = Rig::start(Via::Relay, Hook::Senders);
    let to = rig.receiver(1);
    rig.station().refuse(RefusedCall::MembershipFetch, true);
    rig.log.add_host(SENDER, 2, &secret(SENDER_SEED_2));
    rig.station().set_log(&rig.log);
    let sender = SenderHost::new(&rig.log, SENDER, 2, &secret(SENDER_SEED_2));
    let head = rig.log.log.head();
    {
        let mut station = rig.station();
        for _ in 0..65 {
            sender.put_stored(&mut station, &sender.cancel(&to, head));
        }
    }
    let mailbox_id = rig.station().mailbox_id();
    rig.online();
    rig.within("all 65 read", || {
        rig.cursor() == Some((mailbox_id.clone(), 65)) && rig.owed().is_empty()
    });
    rig.offline();
    assert_eq!(rig.count("mailbox_pending"), 64);
    assert_eq!(rig.done_positions(&mailbox_id), [65], "only the overflow");
    assert_eq!(
        rig.station().mailbox_positions(),
        (1..=64).collect::<Vec<u64>>()
    );
    assert!(rig.inbox().is_empty() && rig.refused().is_empty());
}

// ── The gate's mailbox part (design II.5) ──

/// Design II.5, §11.5: host senders' gate's mailbox part is closed until the
/// host has read its mailbox to the announced head and every inbox row is
/// admitted: closed with no mailbox announced, while a page is out, while
/// an opened request waits for admission; open once admission took it
/// (admission isn't built: the test takes the row as it will), a kept
/// result holding none; closed again by a new object until it is read.
#[test]
#[cfg_attr(
    not(debug_assertions),
    ignore = "needs the debug ATEM_TEST_HOST_FEATURES and ATEM_TEST_STATE_DUMP hooks"
)]
fn the_gates_mailbox_part_waits_for_the_head_and_the_inbox() {
    let rig = Rig::start(Via::Relay, Hook::Senders);
    let to = rig.receiver(1);
    let head = rig.log.log.head();
    let mailbox = rig.until_mailbox("the link", |m| !m.is_null());
    assert_eq!(mailbox["open"], false);
    rig.put(&rig.sender.request(&to, head, "A"));
    rig.put(&rig.sender.result(&to, head));
    rig.announce();
    let (first, _) = rig.hold(is_sync);
    rig.until_mailbox("reading from 0", |m| {
        m["closed"] == "reading the mailbox (0 of 2)"
    });
    rig.answer(first);
    let (second, _) = rig.hold(is_sync);
    rig.until_mailbox("reading on", |m| {
        m["closed"] == "reading the mailbox (1 of 2)"
    });
    rig.answer(second);
    rig.serve_until("read to the head", |rig| {
        rig.owed().is_empty() && rig.cursor().is_some_and(|c| c.1 == 2)
    });
    rig.until_mailbox("the inbox waits", |m| {
        m["closed"] == "1 mailbox object(s) wait for admission"
    });
    // Admission takes the request: open (the kept result holds nothing).
    rig.admit_all();
    rig.until_mailbox("open", |m| m["open"] == true);
    assert_eq!(rig.count("mailbox_results"), 1);
    rig.status_feeds(READ_TO_HEAD);
    // A new object: closed until it is read and admitted.
    rig.put(&rig.sender.cancel(&to, head));
    rig.announce_paced();
    let (third, _) = rig.hold(is_sync);
    rig.until_mailbox("reading the new one", |m| {
        m["closed"] == "reading the mailbox (2 of 3)"
    });
    rig.answer(third);
    rig.serve_until("read", |rig| {
        rig.owed().is_empty() && rig.cursor().is_some_and(|c| c.1 == 3)
    });
    rig.until_mailbox("waits again", |m| {
        m["closed"] == "1 mailbox object(s) wait for admission"
    });
    rig.admit_all();
    rig.until_mailbox("open again", |m| m["open"] == true);
}

/// Ruling R35: a flood of results over the sending host's results' share
/// (64) leaves the 65th on the Station (no row, no done; back-pressure,
/// never loss) and host senders' gate's mailbox part open: results start
/// no work. A request over its inbox share (32) left there closes it until
/// admission frees room and the host reads it again (the rewind to just
/// before the result, which still finds no room and stays there, holding
/// nothing); then it waits for admission as any opened request.
#[test]
#[cfg_attr(
    not(debug_assertions),
    ignore = "needs the debug ATEM_TEST_HOST_FEATURES and ATEM_TEST_STATE_DUMP hooks"
)]
fn a_results_flood_leaves_the_gate_open_and_a_skipped_request_closes_it() {
    const ROOM: &str = "a mailbox object waits on the Station for room in this host's inbox";
    let rig = Rig::start(Via::Relay, Hook::Senders);
    let to = rig.receiver(1);
    let head = rig.log.log.head();
    {
        let mut station = rig.station();
        for _ in 0..65 {
            rig.sender
                .put_stored(&mut station, &rig.sender.result(&to, head));
        }
    }
    let mailbox_id = rig.station().mailbox_id();
    rig.online();
    rig.within("the results read", || {
        rig.cursor() == Some((mailbox_id.clone(), 65)) && rig.owed().is_empty()
    });
    assert_eq!(rig.count("mailbox_results"), 64);
    assert_eq!(
        rig.station().mailbox_positions(),
        [65],
        "left on the Station"
    );
    let mailbox = rig.until_mailbox("the gate", |m| m["announced"]["head"] == 65);
    assert_eq!(mailbox["open"], true, "{mailbox}");
    // 33 requests: 32 into the inbox, the 33rd left on the Station.
    {
        let mut station = rig.station();
        for n in 0..33 {
            let request = rig.sender.request(&to, head, &format!("Request {n}"));
            rig.sender.put_stored(&mut station, &request);
        }
    }
    rig.within("the requests read", || {
        rig.cursor() == Some((mailbox_id.clone(), 98)) && rig.owed().is_empty()
    });
    assert_eq!(rig.inbox().len(), 32);
    assert_eq!(rig.station().mailbox_positions(), [65, 98]);
    rig.until_mailbox("closed by the request", |m| m["closed"] == ROOM);
    // Admission takes the inbox: room frees, the host reads again from the
    // result's position; the request opens, the result still waits.
    rig.admit_all();
    rig.within("the request read again", || {
        rig.inbox().len() == 1 && rig.owed().is_empty()
    });
    assert_eq!(rig.station().mailbox_positions(), [65]);
    rig.until_mailbox("waiting for admission", |m| {
        m["closed"] == "1 mailbox object(s) wait for admission"
    });
    rig.admit_all();
    rig.until_mailbox("open again", |m| m["open"] == true);
    assert_eq!(rig.count("mailbox_results"), 64);
    rig.offline();
}

// ── An identity change on the live link (§11.4, rule 8) ──

/// The P-256 generator, uncompressed: a valid Astation signing key for the
/// fake's `verifyKeys`.
const SIGN_PUB: &str = "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5";

/// The next message of type `kind` Atem sent the fake Astation, on the
/// link it came on (others skipped).
#[track_caller]
fn astation_saw(rig: &Rig, kind: &str) -> (u64, Value) {
    let deadline = Instant::now() + WAIT;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        match rig.astation.events.recv_timeout(left) {
            Ok(Event::Message(on, v)) if v["type"] == kind => return (on, v),
            Ok(_) => {}
            Err(_) => panic!("Astation never got {kind}\n{}", rig.runtime_log()),
        }
    }
}

/// `atem pair verify` run in a terminal against the rig's runtime on its
/// live link (as control_feed_binary's): it moves the pairing to the next
/// host trust generation on that link and waits at the safety-code
/// question.
fn start_reverify(rig: &Rig) -> support::Frontend {
    use base64::Engine;
    let b64 = |bytes: &[u8]| base64::engine::general_purpose::STANDARD.encode(bytes);
    support::astation::write_unverified_trust(&rig.sandbox.config());
    let cli = rig
        .sandbox
        .spawn(&["pair", "verify"], &rig.sandbox.home, &[]);
    let (on, commit) = astation_saw(rig, "verifyCommit");
    assert_eq!(on, rig.link(), "on the live link");
    assert_eq!(commit["data"]["host_trust_gen"], 2, "{commit}");
    let sign_pub: Vec<u8> = (0..SIGN_PUB.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&SIGN_PUB[i..i + 2], 16).unwrap())
        .collect();
    let keys = json!({"type": "verifyKeys", "data": {
        "sign_pub": b64(&sign_pub), "enc_pub": b64(&[5; 32]),
        "recovery_sign_pub": b64(&[6; 32]), "nonce": b64(&[7; 32]),
        "genesis_hash": "ab".repeat(32)}});
    rig.astation.send(on, keys.to_string());
    let (on, _) = astation_saw(rig, "verifyReveal");
    assert_eq!(on, rig.link());
    cli.shows("Does the code on your Mac match?");
    cli
}

/// What the ceremony's `deviceVerified` writes (the fake can't sign
/// Astation's side): the list grown with this host's `add_host` in trust
/// generation 2, pinned so, the device verified again; the fake Station
/// holds the same list. The runtime opens the list again and takes the new
/// identity on its live link.
fn finish_reverify(rig: &mut Rig) {
    let seed = secret("host mail host, verified again");
    rig.log.add_host(HOST, 2, &seed);
    write_pin(&rig.sandbox.config(), &rig.log, HOST, 2, &seed);
    support::astation::write_verified_trust(&rig.sandbox.config(), ACCOUNT, HOST);
    rig.station().set_log(&rig.log);
    let opened = format!(
        "device list: opened at seq {} for {HOST}",
        rig.log.log.head().seq
    );
    rig.within("the re-pinned list", || rig.runtime_log().contains(&opened));
}

/// The safety code refused at the terminal: the operation ends.
fn end_reverify(rig: &Rig, mut cli: support::Frontend, link: u64) {
    cli.send(b"n\r");
    let (on, _) = astation_saw(rig, "verifyAbort");
    assert_eq!(on, link);
    assert!(!cli.exits(), "a refused code fails the command");
}

/// §11.4 "An identity change", rule 8: `atem pair verify` on a live relay
/// link while a done is owed (its answer lost). The host's identity moves
/// on that link: every mailbox call is retired and nothing more is synced
/// or marked done on that socket, the owed done included (at a `heads` and
/// past its deadline). Once the operation ends the link reconnects under
/// the new identity, whose store is new: it owes nothing, reads its own
/// mailbox (a new one at the Station, the new trust generation's) from 0
/// and marks done only that mailbox's objects. No done ever names the old
/// identity's mailbox under the new one.
#[test]
#[cfg_attr(
    not(debug_assertions),
    ignore = "needs the debug ATEM_TEST_HOST_FEATURES, ATEM_TEST_HOST_CLOCK and ATEM_TEST_STATE_DUMP hooks"
)]
fn an_identity_change_on_the_live_link_sends_no_done_under_the_new_identity() {
    let mut rig = Rig::start(Via::Relay, Hook::Senders);
    let old_link = rig.link();
    let to = rig.receiver(1);
    rig.put(&rig.sender.request(&to, rig.log.log.head(), "A"));
    let old = rig.station().mailbox_id();
    rig.station().drop_done_results(1);
    rig.announce();
    rig.serve_until("its done sent, unanswered", |rig| rig.dones().len() == 1);
    assert_eq!(rig.owed(), [(old.clone(), 1)]);
    let verify = start_reverify(&rig);
    finish_reverify(&mut rig);
    let mailbox = rig.until_mailbox("the old association ended", |m| m["identity_moved"] == true);
    assert_eq!(mailbox["closed"], "this host's identity changed");
    assert_eq!(mailbox["in_flight"], Value::Null);
    // Nothing more on that socket: no done again at a heads or past its
    // deadline, no sync. (What the host sent before the move is read
    // first: an acknowledgment of the feed's first page may still wait.)
    rig.station().serve(old_link);
    rig.two_passes();
    rig.station().serve(old_link);
    let sent_before = rig.station().sent_on(old_link).len();
    rig.clock.add_mono(CALL_DEADLINE + 1_000);
    rig.station().heads_now();
    rig.two_passes();
    rig.station().serve(old_link);
    let sent = rig.station().sent_on(old_link);
    assert_eq!(
        sent.len(),
        sent_before,
        "{:#?}",
        &sent[sent_before.min(sent.len())..]
    );
    // The operation ends: a new link, under the new identity.
    end_reverify(&rig, verify, old_link);
    let new_link = rig.next_link(old_link);
    rig.link.set(new_link);
    rig.station().reassociate(2, new_link);
    let new = rig.station().mailbox_id();
    assert_ne!(new, old, "the new trust generation's mailbox");
    let to = rig.receiver(2);
    rig.put(&rig.sender.cancel(&to, rig.log.log.head()));
    rig.station().on_link(new_link);
    rig.announce_paced();
    rig.serve_until("the new mailbox read", |rig| {
        rig.cursor() == Some((new.clone(), 1)) && rig.owed().is_empty()
    });
    let dones = rig.dones();
    let named_old: Vec<u64> = dones
        .iter()
        .filter(|(_, d)| d.mailbox_id == old)
        .map(|(link, _)| *link)
        .collect();
    assert_eq!(named_old, [old_link], "the old mailbox's one done, before");
    let under_new: Vec<(String, u64)> = dones
        .iter()
        .filter(|(link, _)| *link == new_link)
        .map(|(_, d)| (d.mailbox_id.clone(), d.position))
        .collect();
    assert_eq!(under_new, [(new.clone(), 1)]);
    assert_eq!(rig.mailbox()["identity_moved"], false);
}

// ── The hook off ──

/// Hook off = main: with `host.delegated` alone (no `host.senders`), a
/// `heads` naming a mailbox (a Station that sends it to every host) is one
/// the link's reader refuses, unread; no mailbox is synced or marked done,
/// no mailbox state is kept, and the store gets no mailbox table and the
/// pairing no host encryption key.
#[test]
#[cfg_attr(
    not(debug_assertions),
    ignore = "needs the debug ATEM_TEST_HOST_FEATURES and ATEM_TEST_STATE_DUMP hooks"
)]
fn without_host_senders_heads_mailbox_is_refused_and_no_mailbox_table_is_made() {
    let rig = Rig::start(Via::Relay, Hook::Delegated);
    let to = Receiver::other(HOST, 1, "the host's key, never made");
    rig.put(&rig.sender.request(&to, rig.log.log.head(), "A"));
    rig.station().host_lists_senders(true);
    rig.announce();
    rig.within("the heads refused", || {
        rig.dump()["station"]["unread"].as_u64() >= Some(1)
    });
    rig.two_passes();
    rig.station().serve(rig.link());
    assert!(rig.station().mailbox_calls().is_empty());
    let station = rig.dump()["station"].clone();
    assert_eq!(station["mailbox"], Value::Null, "{station}");
    assert_eq!(station["heads"], 0, "{station}");
    assert!(
        rig.runtime_log()
            .contains("Station message(s) the reader refused were dropped")
    );
    assert_eq!(mailbox_tables(&rig), 0);
    assert!(!rig.sandbox.config().join("pairing/host_enc_key").exists());
    assert_eq!(rig.station().mailbox_positions(), [1], "nothing done");
}

/// The mailbox's tables in the host-work store.
fn mailbox_tables(rig: &Rig) -> i64 {
    rig.db()
        .query_row(
            "SELECT count(*) FROM sqlite_master WHERE name GLOB 'mailbox_*'",
            [],
            |r| r.get(0),
        )
        .unwrap()
}

/// Hook off = main (and every release build, which runs this with the
/// hook's variable set: compiled out): a `heads` naming the host's mailbox
/// is read and dropped as main drops it, and nothing of the mailbox
/// happens: no Station call, no mailbox table in the host-work store, no
/// host encryption key. Observed through the transport and the files only
/// (no debug state dump): a `push_ack` sent after the `heads` was read
/// (its runtime.log line), so they were too.
#[test]
fn with_the_hook_off_the_host_reads_no_mailbox() {
    let rig = Rig::start(Via::Relay, Hook::Off);
    let to = Receiver::other(HOST, 1, "the host's key, never made");
    rig.put(&rig.sender.request(&to, rig.log.log.head(), "A"));
    rig.station().host_lists_senders(true);
    rig.announce();
    rig.astation.send(
        rig.link(),
        json!({"type": "relay", "op": "push_ack", "acks": []}).to_string(),
    );
    within("the push_ack", || {
        rig.runtime_log()
            .contains("a push_ack acknowledged nothing pending")
    });
    // The store agent hosting opens.
    within("the host-work store", || {
        rig.store().is_some_and(|db| {
            db.query_row(
                "SELECT count(*) FROM sqlite_master WHERE name='work'",
                [],
                |r| r.get::<_, i64>(0),
            )
            .is_ok_and(|n| n == 1)
        })
    });
    assert!(rig.station().serve(rig.link()).is_empty());
    assert!(rig.station().sent().is_empty(), "no Station call");
    assert_eq!(mailbox_tables(&rig), 0);
    assert!(!rig.sandbox.config().join("pairing/host_enc_key").exists());
    assert_eq!(rig.station().mailbox_positions(), [1], "nothing done");
}
