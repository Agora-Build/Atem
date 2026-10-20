//! The r9 client machines used the way apps will, through the public API
//! only, over real loopback sockets (TCP on 127.0.0.1 and Unix socket
//! pairs, 4-byte length-prefixed frames). The host is a test host built
//! from the crate's responder role and host-side pieces
//! (`support/host.rs`; the real runtime host is Task 7). The relay for
//! pushes and restores is a socket peer running the crate's reference
//! relay ledger, or the fake log/envelope store of `support`. Keys and log
//! L are the r9 test vectors. One shared test clock drives both ends.
mod support;

use std::collections::BTreeSet;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use atem_client::canonical::StrictValue;
use atem_client::channel::HostAccept;
use atem_client::channel::wire::{Frame, parse_frame};
use atem_client::connect::{Attached, ConnectError, Connector, Event, Identity, NextStep};
use atem_client::membership::publish::AppendReply;
use atem_client::membership::{Entry, Head, Member, MemberKind, Membership, Role};
use atem_client::principal::{ClientKind, Permission};
use atem_client::push::{
    self, DeviceClass, Hint, HintBook, HintPlain, RecipientInfo, RelayLedger, Verdict, Verifier,
};
use atem_client::restore::{Enrollment, Freshness, RestoreError, RestoreFlow, UserNotice};
use atem_client::session::client::ReplyOutcome;
use atem_client::session::wire::{Op, ReceiptState};
use atem_client::{KeyId, SignedObject};
use serde_json::{Value, json};
use support::host::{HostConn, HostCore, HostSession};
use support::*;

const WALL: u64 = 1_793_264_001_000;
const ABAB: &str = "h1.b982533d.abababababababababababababababababababababababababababababababab";
const CDCD: &str = "h1.b982533d.cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd";
const SES_A: &str = "ses-aaaaaaaaaaaa";
const SES_B: &str = "ses-bbbbbbbbbbbb";

// ------------------------------------------------------------- transport

fn send(stream: &mut impl Write, frame: &[u8]) -> bool {
    let len = u32::try_from(frame.len()).unwrap().to_be_bytes();
    stream.write_all(&len).is_ok() && stream.write_all(frame).is_ok() && stream.flush().is_ok()
}

fn recv(stream: &mut impl Read) -> Option<Vec<u8>> {
    let mut len = [0u8; 4];
    stream.read_exact(&mut len).ok()?;
    let mut frame = vec![0u8; u32::from_be_bytes(len) as usize];
    stream.read_exact(&mut frame).ok()?;
    Some(frame)
}

/// One end of a connection: writes go out at once, reads arrive through a
/// reader thread (so a test can wait for "nothing more").
struct Wire {
    tx: Box<dyn Write + Send>,
    rx: Receiver<Vec<u8>>,
}

impl Wire {
    fn new<S: Read + Write + Send + 'static>(stream: S, reader: S) -> Wire {
        let (tx, rx) = mpsc::channel();
        let mut reader = reader;
        thread::spawn(move || {
            while let Some(frame) = recv(&mut reader) {
                if tx.send(frame).is_err() {
                    break;
                }
            }
        });
        Wire {
            tx: Box::new(stream),
            rx,
        }
    }

    fn tcp(stream: TcpStream) -> Wire {
        let reader = stream.try_clone().unwrap();
        Wire::new(stream, reader)
    }

    fn unix(stream: UnixStream) -> Wire {
        let reader = stream.try_clone().unwrap();
        Wire::new(stream, reader)
    }

    fn send(&mut self, frame: &[u8]) {
        assert!(send(&mut self.tx, frame), "the peer is gone");
    }

    fn recv(&self) -> Option<Vec<u8>> {
        self.rx.recv_timeout(Duration::from_secs(5)).ok()
    }

    /// The next frame within `ms`, or `None` (nothing came, or closed).
    fn try_recv(&self, ms: u64) -> Option<Vec<u8>> {
        self.rx.recv_timeout(Duration::from_millis(ms)).ok()
    }
}

// ----------------------------------------------------------------- world

/// The shared clock, the test host and its server.
struct World {
    v: Vectors,
    book: Book,
    clock: Arc<Mutex<Clock>>,
    core: Arc<Mutex<HostCore>>,
}

fn log_of(v: &Vectors, labels: &[&str], clock: &Clock) -> Membership {
    Membership::verify_chain(ACCOUNT, &genesis_hash(), &v.entries(labels), &clock.now)
        .unwrap()
        .membership
}

const L: [&str; 6] = ["E1", "E2", "E3", "E4", "E5", "E6"];

impl World {
    fn new(host_labels: &[&str]) -> World {
        let v = Vectors::load();
        let book = Book::load();
        let clock = Clock::at(WALL);
        let log = log_of(&v, host_labels, &clock);
        let seed = unhex32(
            book.keys["host-a"]["host_key"]["secret_hex"]
                .as_str()
                .unwrap(),
        );
        let sessions = vec![
            HostSession {
                session_id: SES_A.into(),
                process_gen: "22222222-2222-4222-8222-222222222222".into(),
                project: ABAB.into(),
            },
            HostSession {
                session_id: SES_B.into(),
                process_gen: "33333333-3333-4333-8333-333333333333".into(),
                project: CDCD.into(),
            },
        ];
        let core = HostCore::new(log, clock.now.clone(), &seed, sessions);
        World {
            v,
            book,
            clock: Arc::new(Mutex::new(clock)),
            core: Arc::new(Mutex::new(core)),
        }
    }

    fn mono(&self) -> u64 {
        self.clock.lock().unwrap().now.mono_ms
    }

    fn advance(&self, ms: u64) {
        self.clock.lock().unwrap().advance(ms);
        self.sync();
    }

    fn set_wall(&self, wall: u64) {
        self.clock.lock().unwrap().set_wall(wall);
        self.sync();
    }

    /// The host sees the clock and runs its timers.
    fn sync(&self) {
        let now = self.clock.lock().unwrap().now.clone();
        let mut core = self.core.lock().unwrap();
        core.now = now;
        core.tick();
    }

    fn log(&self, labels: &[&str]) -> Membership {
        log_of(&self.v, labels, &self.clock.lock().unwrap())
    }

    /// Serves one connection: a host thread reading frames from `wire`.
    fn serve(&self, mut wire: Wire) {
        let core = self.core.clone();
        let clock = self.clock.clone();
        thread::spawn(move || {
            let mut conn = HostConn::new(&mut core.lock().unwrap());
            loop {
                let frame = wire.try_recv(10);
                let mut core = core.lock().unwrap();
                core.now = clock.lock().unwrap().now.clone();
                let out = match frame {
                    Some(f) => conn.on_frame(&mut core, &f),
                    None => {
                        core.tick();
                        conn.poll(&mut core)
                    }
                };
                drop(core);
                for f in &out.frames {
                    if !send(&mut wire.tx, f) {
                        return;
                    }
                }
                if out.close {
                    return; // dropping the wire closes the transport
                }
            }
        });
    }

    /// A TCP connection to the host.
    fn tcp(&self) -> Wire {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        self.serve(Wire::tcp(server));
        Wire::tcp(client)
    }

    /// A Unix socket pair to the host.
    fn unix(&self) -> Wire {
        let (a, b) = UnixStream::pair().unwrap();
        self.serve(Wire::unix(b));
        Wire::unix(a)
    }
}

/// A device: its verified log and identity, the platform keys (the test
/// book), and its connection.
struct Device<'w> {
    world: &'w World,
    log: Membership,
    identity: Identity,
}

impl<'w> Device<'w> {
    fn native(world: &'w World, id: &str, log: Membership) -> Self {
        Device {
            world,
            log,
            identity: Identity::native(id, world.book.auth(id)),
        }
    }

    fn service(world: &'w World, id: &str, log: Membership) -> Self {
        Device {
            world,
            log,
            identity: Identity::service(id, world.book.auth(id)),
        }
    }

    fn browser(world: &'w World, grant: SignedObject, log: Membership) -> Self {
        Device {
            world,
            log,
            identity: Identity::browser(grant, KeyId::new("browser/auth")).unwrap(),
        }
    }

    /// The handshake and the welcome over `wire`.
    fn connect(&self, wire: &mut Wire) -> Result<Attached, ConnectError> {
        self.connect_with(wire, &Connector::new("host-a"))
    }

    fn connect_with(
        &self,
        wire: &mut Wire,
        connector: &Connector,
    ) -> Result<Attached, ConnectError> {
        let (connecting, init) = connector.start(&self.log, self.world.mono())?;
        wire.send(&init);
        let accept = wire.recv().expect("accept");
        let (await_welcome, finish) = connecting.on_accept(
            &accept,
            &self.log,
            &self.world.book.provider,
            &self.identity,
            self.world.mono(),
        )?;
        wire.send(&finish);
        let first = wire.recv().expect("the first record");
        await_welcome.on_frame(&first, &self.log, self.world.mono())
    }
}

/// Sends `frame` and collects events until `done` says so (or 5 s).
fn exchange(
    attached: &mut Attached,
    wire: &mut Wire,
    frame: &[u8],
    now: u64,
    done: impl Fn(&[Event]) -> bool,
) -> Vec<Event> {
    wire.send(frame);
    let mut events = Vec::new();
    while !done(&events) {
        let f = wire.recv().expect("a reply");
        events.extend(attached.on_frame(&f, now).expect("a record"));
    }
    events
}

fn has_receipt(events: &[Event], state: ReceiptState) -> bool {
    events.iter().any(
        |e| matches!(e, Event::Session(m) if matches!(&m.op, Op::Receipt(r) if r.state == state)),
    )
}

fn error_code(events: &[Event]) -> Option<String> {
    events.iter().find_map(|e| match e {
        Event::Error(err) | Event::Fenced(err) => Some(err.code.clone()),
        Event::Session(m) => match &m.op {
            Op::Error { code, .. } => Some(
                serde_json::to_value(code)
                    .unwrap()
                    .as_str()
                    .unwrap()
                    .to_owned(),
            ),
            _ => None,
        },
        _ => None,
    })
}

fn family_error(events: &[Event]) -> Option<String> {
    events.iter().find_map(|e| match e {
        Event::Family(f) => f
            .data
            .as_ref()
            .and_then(|d| d["code"].as_str())
            .map(str::to_owned),
        _ => None,
    })
}

fn refused(result: Result<Attached, ConnectError>) -> (String, Option<String>) {
    match result {
        Err(ConnectError::Refused { error, .. }) => (error.code, error.detail),
        other => panic!("expected a refusal, got {other:?}"),
    }
}

/// Lists and returns the session ids the registry holds.
fn list(attached: &mut Attached, wire: &mut Wire, now: u64) -> Vec<String> {
    let (_, frame) = attached.list(now).unwrap();
    exchange(attached, wire, &frame, now, |e| {
        e.iter().any(|e| matches!(e, Event::Registry(_)))
    });
    attached.registry().session_ids()
}

fn grant_vector() -> SignedObject {
    SignedObject::parse(
        load("r9-vectors-browser-grant")["grant"]
            .to_string()
            .as_bytes(),
    )
    .unwrap()
}

// ----------------------------------------------------------------- tests

/// A phone and a desktop (native), a Discord-style bot (service) and a
/// browser (grant) each connect, hello, get welcomed, list sessions, take a
/// lease, submit a prompt and see receipts; the bot is refused outside its
/// scope and after its expiry; the browser grant is refused when tampered
/// with or expired, and fenced when revoked.
#[test]
fn a_phone_a_desktop_a_bot_and_a_browser_use_the_host() {
    let world = World::new(&L);
    let log = world.log(&L);
    let now = || world.mono();

    // The phone (P-256 native manager) over TCP.
    let phone = Device::native(&world, "dev-phone", log.clone());
    let mut pw = world.tcp();
    let mut p = phone.connect(&mut pw).unwrap();
    let w = p.welcome().clone();
    assert_eq!(w.revision, 9);
    assert_eq!(w.principal, "member:dev-phone");
    assert_eq!(w.client_kind, ClientKind::Native);
    assert_eq!(w.permissions, vec![Permission::Control, Permission::View]);
    assert_eq!(w.head, log.head());
    assert!(w.pending_recovery.is_empty());
    assert_eq!(w.channel_id, p.channel_id());
    assert_eq!(p.fetch_to(&log), None);
    assert_eq!(list(&mut p, &mut pw, now()), vec![SES_A, SES_B]);
    let (_, frame) = p.acquire(SES_A, false, now()).unwrap();
    let ev = exchange(&mut p, &mut pw, &frame, now(), |e| {
        e.iter().any(|e| matches!(e, Event::Lease { .. }))
    });
    assert!(ev.contains(&Event::Lease {
        session_id: SES_A.into(),
        outcome: ReplyOutcome::Applied
    }));
    assert!(p.lease(SES_A).unwrap().controls(now()));
    let (_, frame) = p
        .submit_prompt(
            SES_A,
            "bbbbbbbb-0000-4000-8000-000000000001",
            "npm test",
            now(),
        )
        .unwrap();
    let ev = exchange(&mut p, &mut pw, &frame, now(), |e| {
        has_receipt(e, ReceiptState::Completed)
    });
    assert!(has_receipt(&ev, ReceiptState::Accepted));
    let (_, frame) = p
        .receipt_query(
            SES_A,
            &["bbbbbbbb-0000-4000-8000-000000000001".into()],
            now(),
        )
        .unwrap();
    let ev = exchange(&mut p, &mut pw, &frame, now(), |e| {
        e.iter()
            .any(|e| matches!(e, Event::Session(m) if matches!(m.op, Op::Receipts { .. })))
    });
    assert!(ev.iter().any(|e| matches!(e, Event::Session(m)
        if matches!(&m.op, Op::Receipts { receipts } if receipts[0].state == ReceiptState::Completed))));
    let (_, frame) = p.release(SES_A, now()).unwrap();
    let ev = exchange(&mut p, &mut pw, &frame, now(), |e| {
        e.iter().any(|e| matches!(e, Event::Lease { .. }))
    });
    assert!(
        ev.iter()
            .any(|e| matches!(e, Event::Session(m) if matches!(m.op, Op::LeaseReleased {})))
    );
    assert!(!p.lease(SES_A).unwrap().controls(now()));

    // The desktop (the Mac) over a Unix socket: an acquiring Send.
    let mac = Device::native(&world, "dev-mac", log.clone());
    let mut mw = world.unix();
    let mut m = mac.connect(&mut mw).unwrap();
    assert_eq!(m.welcome().principal, "member:dev-mac");
    list(&mut m, &mut mw, now());
    let (_, frame) = m
        .submit_prompt(
            SES_B,
            "bbbbbbbb-0000-4000-8000-000000000002",
            "status?",
            now(),
        )
        .unwrap();
    let ev = exchange(&mut m, &mut mw, &frame, now(), |e| {
        has_receipt(e, ReceiptState::Completed)
    });
    assert!(ev.iter().any(|e| matches!(e, Event::Session(msg)
        if matches!(&msg.op, Op::Receipt(r) if r.state == ReceiptState::Accepted && r.lease.is_some()))));
    assert!(
        m.lease(SES_B).unwrap().controls(now()),
        "the Send granted the lease"
    );

    // The bot (Ed25519 service) over TCP: scope and ops.
    let bot = Device::service(&world, "svc-discord", log.clone());
    let mut bw = world.tcp();
    let mut b = bot.connect(&mut bw).unwrap();
    let w = b.welcome().clone();
    assert_eq!(w.client_kind, ClientKind::Service);
    assert_eq!(w.principal, "service:svc-discord");
    assert_eq!(w.permissions, vec![Permission::Control, Permission::View]);
    assert_eq!(w.authorization_ms_left, 86_400_000);
    let scope = w.scope.unwrap();
    assert_eq!(
        atem_client::principal::op_names(&scope.ops),
        ["interrupt", "prompt", "view"]
    );
    assert_eq!(
        list(&mut b, &mut bw, now()),
        vec![SES_A],
        "only its project"
    );
    let (_, frame) = b
        .submit_prompt(
            SES_A,
            "bbbbbbbb-0000-4000-8000-000000000003",
            "status?",
            now(),
        )
        .unwrap();
    let ev = exchange(&mut b, &mut bw, &frame, now(), |e| {
        has_receipt(e, ReceiptState::Completed)
    });
    assert!(has_receipt(&ev, ReceiptState::Accepted));
    // Outside its scope: no terminal op, no other project's session.
    let binding = serde_json::to_value(b.binding(SES_A, now()).unwrap()).unwrap();
    let input = json!({"type": "terminal", "data": {"v": 1, "op": "input",
        "terminal_id": SES_A, "generation": "22222222-2222-4222-8222-222222222222",
        "stream_id": "dddddddd-0000-4000-8000-000000000001", "sequence": 0, "bytes": "eA==",
        "binding": binding}});
    let frame = b.send(&input, now()).unwrap();
    let ev = exchange(&mut b, &mut bw, &frame, now(), |e| !e.is_empty());
    assert_eq!(family_error(&ev).as_deref(), Some("forbidden"));
    // A session it can't see isn't in its registry: no binding to name it;
    // naming it anyway (a target learnt elsewhere) is unknown_session.
    assert!(b.binding(SES_B, now()).is_none());
    let forged = json!({"target": p.target(SES_B).unwrap(),
        "attachment_gen": b.welcome().attachment_gen});
    let open = json!({"type": "agentChat", "data": {"v": 1, "op": "open",
        "conversationId": "cccccccc-0000-4000-8000-000000000001", "agentId": SES_B,
        "binding": forged}});
    let frame = b.send(&open, now()).unwrap();
    let ev = exchange(&mut b, &mut bw, &frame, now(), |e| !e.is_empty());
    assert_eq!(family_error(&ev).as_deref(), Some("unknown_session"));
    // The same in the registry's lease ops and in receipts (§R9.6): an
    // acquire, or a receipt_query for the Mac's receipt on that session,
    // is unknown_session, never a lease or a receipt.
    for data in [
        json!({"v": 1, "op": "acquire", "id": "aaaaaaaa-0000-4000-8000-0000000000b1",
               "binding": forged, "takeover": false}),
        json!({"v": 1, "op": "receipt_query", "id": "aaaaaaaa-0000-4000-8000-0000000000b2",
               "binding": forged, "request_ids": ["bbbbbbbb-0000-4000-8000-000000000002"]}),
    ] {
        let frame = b
            .send(&json!({"type": "session", "data": data}), now())
            .unwrap();
        let ev = exchange(&mut b, &mut bw, &frame, now(), |e| !e.is_empty());
        assert_eq!(
            error_code(&ev).as_deref(),
            Some("unknown_session"),
            "{data}"
        );
    }
    // A query on its own session doesn't leak another session's receipt.
    let (_, frame) = b
        .receipt_query(
            SES_A,
            &["bbbbbbbb-0000-4000-8000-000000000002".into()],
            now(),
        )
        .unwrap();
    let ev = exchange(&mut b, &mut bw, &frame, now(), |e| {
        e.iter()
            .any(|e| matches!(e, Event::Session(m) if matches!(m.op, Op::Receipts { .. })))
    });
    assert!(ev.iter().any(|e| matches!(e, Event::Session(m)
        if matches!(&m.op, Op::Receipts { receipts } if receipts.is_empty()))));
    // Without the approval op, a seen is forbidden (no cards for it).
    let (_, frame) = b
        .approval_seen(SES_A, "8c3e9d6b-1f40-4b52-8dae-4f5a6b7c8d9e", now())
        .unwrap();
    let ev = exchange(&mut b, &mut bw, &frame, now(), |e| !e.is_empty());
    assert_eq!(error_code(&ev).as_deref(), Some("forbidden"));

    // The browser (WebCrypto P-256 grant from the phone), Unix socket.
    let browser = Device::browser(&world, grant_vector(), log.clone());
    let mut rw = world.unix();
    let mut r = browser.connect(&mut rw).unwrap();
    let w = r.welcome().clone();
    assert_eq!(w.client_kind, ClientKind::Browser);
    assert_eq!(w.principal, "browser:7b2d8c5a-0e3f-4a41-9c9d-3e4f5a6b7c8d");
    assert_eq!(w.permissions, vec![Permission::View]);
    assert_eq!(w.authorization_ms_left, 3_599_000);
    assert_eq!(list(&mut r, &mut rw, now()), vec![SES_A]);
    let (_, frame) = r.acquire(SES_A, false, now()).unwrap();
    let ev = exchange(&mut r, &mut rw, &frame, now(), |e| {
        e.iter().any(|e| matches!(e, Event::Lease { .. }))
    });
    assert_eq!(error_code(&ev).as_deref(), Some("forbidden"));
    assert!(!r.lease(SES_A).unwrap().controls(now()));

    // The phone revokes the grant: the browser is fenced at once.
    let (_, frame) = p
        .revoke_grant("7b2d8c5a-0e3f-4a41-9c9d-3e4f5a6b7c8d", now())
        .unwrap();
    let ev = exchange(&mut p, &mut pw, &frame, now(), |e| {
        e.iter().any(|e| matches!(e, Event::GrantRevoked { .. }))
    });
    assert!(!ev.is_empty());
    let fence = rw.recv().unwrap();
    let ev = r.on_frame(&fence, now()).unwrap();
    assert!(matches!(&ev[..], [Event::Fenced(e)] if e.detail.as_deref() == Some("grant revoked")));
    assert!(r.is_closed());
    let mut rw2 = world.tcp();
    assert_eq!(
        refused(browser.connect(&mut rw2)),
        ("unauthorized".into(), Some("grant revoked".into()))
    );

    // A tampered grant (ops widened, the signature left) is invalid.
    let mut tampered = load("r9-vectors-browser-grant")["grant"].clone();
    tampered["body"]["ops"] = json!(["prompt", "view"]);
    tampered["body"]["grant_id"] = json!("7b2d8c5a-0e3f-4a41-9c9d-3e4f5a6b7c8e");
    let tampered = SignedObject::parse(tampered.to_string().as_bytes()).unwrap();
    let forged = Device::browser(&world, tampered, log.clone());
    let mut fw = world.tcp();
    assert_eq!(
        refused(forged.connect(&mut fw)),
        ("unauthorized".into(), Some("invalid grant".into()))
    );

    // Time passes: the browser's hour ends, then the bot's 90 days.
    world.set_wall(1_793_267_600_000);
    let mut ew = world.tcp();
    let browser_again = Device::browser(&world, grant_vector(), log.clone());
    // (The revocation was journaled until the grant's expiry: it is gone
    // now, and the grant is refused for its expiry.)
    assert!(world.core.lock().unwrap().revoked.is_empty());
    assert_eq!(
        refused(browser_again.connect(&mut ew)),
        ("unauthorized".into(), Some("expired".into()))
    );
    world.set_wall(1_794_992_004_000);
    let fence = bw.recv().unwrap();
    let ev = b.on_frame(&fence, now()).unwrap();
    assert!(matches!(&ev[..], [Event::Fenced(e)] if e.detail.as_deref() == Some("expired")));
    let mut bw2 = world.unix();
    assert_eq!(
        refused(bot.connect(&mut bw2)),
        ("unauthorized".into(), Some("expired".into()))
    );
    // The natives never expire.
    let mut pw2 = world.tcp();
    assert!(phone.connect(&mut pw2).is_ok());
}

/// A phone carries a suffix (E7: it removes the bot); the host applies it
/// before judging the phone, fences the bot's open channel, and the bot's
/// next connection is refused `removed`. A device whose log is behind
/// learns the host's newer head from the welcome (fetch, never adopt).
#[test]
fn a_carried_removal_refuses_the_removed_devices_next_connection() {
    let world = World::new(&L);
    let now = || world.mono();
    let bot = Device::service(&world, "svc-discord", world.log(&L));
    let mut bw = world.tcp();
    let mut b = bot.connect(&mut bw).unwrap();

    let phone = Device::native(
        &world,
        "dev-phone",
        world.log(&["E1", "E2", "E3", "E4", "E5", "E6", "E7"]),
    );
    let mut pw = world.unix();
    let p = phone.connect(&mut pw).unwrap();
    assert_eq!(p.carriage().entries, vec![world.v.object("E7")]);
    assert_eq!(p.welcome().head, world.v.head("E7"));
    assert_eq!(world.core.lock().unwrap().log.head(), world.v.head("E7"));
    // The bot's open channel is fenced.
    let fence = bw.recv().unwrap();
    let ev = b.on_frame(&fence, now()).unwrap();
    assert!(matches!(&ev[..], [Event::Fenced(e)] if e.detail.as_deref() == Some("removed")));
    // Its next connection is refused, whatever log it holds.
    let mut bw2 = world.tcp();
    let (code, detail) = refused(bot.connect(&mut bw2));
    assert_eq!(
        (code.as_str(), detail.as_deref()),
        ("unauthorized", Some("removed"))
    );
    // The Mac, still at E6: the welcome's head is beyond its log; it
    // fetches and verifies, its log untouched by the connection.
    let mac_log = world.log(&L);
    let mac = Device::native(&world, "dev-mac", mac_log.clone());
    let mut mw = world.tcp();
    let m = mac.connect(&mut mw).unwrap();
    assert_eq!(m.fetch_to(&mac_log), Some(world.v.head("E7")));
    assert_eq!(mac.log, mac_log);
}

/// A welcome that contradicts what the client verified is refused and the
/// channel dropped: another revision, channel, principal or kind, a head
/// behind the signed `accept`, or another entry at a seq the client holds
/// on the chain it shares with the host. (A real man in the middle can't
/// forge one, the records being bound to `th4`: this is a misbehaving
/// host.) And a `need_before` beyond the widest window stops the client
/// instead of looping.
#[test]
fn a_contradicting_welcome_is_refused() {
    let world = World::new(&L);
    let log = world.log(&L);
    let phone = Device::native(&world, "dev-phone", log.clone());
    type Rewrite = fn(&mut atem_client::session::r9::Welcome);
    let cases: [(Rewrite, &str); 8] = [
        (|w| w.host_trust_gen = 2, "host"),
        (|w| w.atem_device_id = "host-b".into(), "host"),
        (|w| w.revision = 8, "revision"),
        (|w| w.channel_id = "00".repeat(16), "channel_id"),
        (|w| w.principal = "member:dev-mac".into(), "principal"),
        (
            |w| w.client_kind = atem_client::principal::ClientKind::Service,
            "principal",
        ),
        (|w| w.head.seq = 5, "head"),
        (|w| w.head.hash = atem_client::Hash32([7; 32]), "head"),
    ];
    for (rewrite, why) in cases {
        world.core.lock().unwrap().welcome_override = Some(rewrite);
        let mut wire = world.tcp();
        assert_eq!(
            phone.connect(&mut wire).err(),
            Some(ConnectError::BadWelcome(why))
        );
    }
    // A head beyond the client's own on its chain is fine: it fetches.
    world.core.lock().unwrap().welcome_override = Some(|w| {
        w.head.seq = 9;
    });
    let mut wire = world.tcp();
    let attached = phone.connect(&mut wire).unwrap();
    assert_eq!(attached.fetch_to(&log).map(|h| h.seq), Some(9));
    world.core.lock().unwrap().welcome_override = None;

    // A host that keeps answering need_before at the genesis: the client
    // stops with DivergenceTooDeep rather than reconnect forever.
    let diverged = Membership::verify_chain(
        ACCOUNT,
        &genesis_hash(),
        &world.v.entries(&["E1", "E2", "E3", "E4", "E5", "C6_ipad"]),
        &world.clock.lock().unwrap().now,
    );
    // C6_ipad (the iPad's add at seq 6, valid before E6 removed it): a
    // device holding it diverges from the host at seq 6.
    let device = Device::native(&world, "dev-phone", diverged.unwrap().membership);
    let mut wire = world.tcp();
    let next = NextStep::Reconnect {
        need_before: Some(1),
    };
    assert!(matches!(
        device.connect_with(&mut wire, &Connector::after("host-a", &next)),
        Err(ConnectError::Carry(_))
    ));
    // Its first connection carries the one-entry window, which the host
    // ignores (the iPad was removed): it is admitted, and its welcome's
    // head is the host's E6, which it can't place: it fetches.
    let mut wire = world.tcp();
    let attached = device.connect(&mut wire).unwrap();
    assert_eq!(attached.carriage().entries, vec![world.v.object("C6_ipad")]);
    assert_eq!(attached.fetch_to(&device.log), Some(world.v.head("E6")));
}

// ------------------------------------------------------------------ push

/// The relay end of the host's link: runs the reference ledger, answers
/// `push_ack`s (unless told to drop the next one), and hands provider
/// pushes to the test.
struct Relay {
    ledger: Arc<Mutex<RelayLedger>>,
    log: Membership,
    drop_next_ack: bool,
}

impl Relay {
    /// One relay message from the host; returns the `push_ack` (if sent).
    fn receive(&mut self, message: &Value, now: u64) -> (Vec<Verdict>, Option<Value>) {
        let mut verdicts = Vec::new();
        let mut acks = Vec::new();
        let mut ledger = self.ledger.lock().unwrap();
        match message["op"].as_str().unwrap() {
            "push_hint" => {
                for h in message["hints"].as_array().unwrap() {
                    let o = SignedObject::parse(h.to_string().as_bytes()).unwrap();
                    let (v, id) = ledger.receive_hint(&o, &self.log, now);
                    verdicts.push(v);
                    acks.extend(id);
                }
            }
            "push_seen" => {
                let o = SignedObject::parse(message["seen"].to_string().as_bytes()).unwrap();
                let (v, id) = ledger.receive_seen(&o, &self.log, now);
                verdicts.push(v);
                acks.extend(id);
            }
            other => panic!("relay op {other}"),
        }
        if std::mem::take(&mut self.drop_next_ack) {
            return (verdicts, None);
        }
        (verdicts, Some(push::push_ack(&acks)))
    }
}

fn devices(id: &str) -> RecipientInfo {
    RecipientInfo {
        class: if id == "dev-mac" {
            DeviceClass::Desktop
        } else {
            DeviceClass::Mobile
        },
        connected: false,
        immediate_mobile: false,
    }
}

/// Moves the relay's clock to `to`, firing every wake-up on the way.
fn run_until(ledger: &Mutex<RelayLedger>, from: u64, to: u64) -> Vec<push::Push> {
    let mut now = from;
    let mut out = Vec::new();
    loop {
        let mut l = ledger.lock().unwrap();
        out.extend(l.due(now, &devices));
        match l.next_wake(now, &devices) {
            Some(w) if w > now && w <= to => now = w,
            _ => break,
        }
    }
    out.extend(ledger.lock().unwrap().due(to, &devices));
    out
}

/// Push end to end: the host signs and seals hints over its link (a
/// socket) to the relay, which acknowledges them; the phone gets its open
/// hint from the relay (a socket) and opens tool and summary with its own
/// enc_key; the schedule fires at exact boundaries from the signed
/// created_at, after a late receipt and across a failover; the phone's seen
/// (from a foreground card, over its channel) suppresses the mobile stage;
/// a seen of another process generation suppresses nothing; a seen after
/// resolution reopens nothing; a lost push_ack leads to a resend.
#[test]
fn push_hints_seen_and_the_schedule_end_to_end() {
    let world = World::new(&L);
    let log = world.log(&L);
    let now = || world.mono();
    let c = WALL; // created_at: the host's wall clock at the approval
    // The host's link to the relay and the relay's to the phone: sockets.
    let (host_link, relay_end) = UnixStream::pair().unwrap();
    let mut host_link = Wire::unix(host_link);
    let mut relay_end = Wire::unix(relay_end);
    let (to_phone, phone_push) = UnixStream::pair().unwrap();
    let mut to_phone = Wire::unix(to_phone);
    let phone_push = Wire::unix(phone_push);
    let ledger = Arc::new(Mutex::new(RelayLedger::new()));
    let mut relay = Relay {
        ledger: ledger.clone(),
        log: log.clone(),
        drop_next_ack: false,
    };
    // What the host has sent to the relay goes over the link.
    let flush = |world: &World, link: &mut Wire| {
        let sent: Vec<Value> = std::mem::take(&mut world.core.lock().unwrap().relay_sent);
        for m in &sent {
            link.send(m.to_string().as_bytes());
        }
        sent.len()
    };
    let relay_step =
        |relay: &mut Relay, relay_end: &mut Wire, to_phone: &mut Wire, at: u64| -> Vec<Verdict> {
            let mut verdicts = Vec::new();
            while let Some(m) = relay_end.try_recv(100) {
                let message: Value = serde_json::from_slice(&m).unwrap();
                let (v, ack) = relay.receive(&message, at);
                verdicts.extend(v);
                if let Some(ack) = ack {
                    relay_end.send(ack.to_string().as_bytes());
                }
                // Forward the phone's own open hint to it (the provider path).
                if message["op"] == "push_hint" {
                    for h in message["hints"].as_array().unwrap() {
                        if h["body"]["recipient"]["device_id"] == "dev-phone" {
                            to_phone.send(h.to_string().as_bytes());
                        }
                    }
                }
            }
            verdicts
        };
    let deliver_acks = |world: &World, link: &mut Wire| {
        while let Some(a) = link.try_recv(100) {
            let ack: Value = serde_json::from_slice(&a).unwrap();
            world
                .core
                .lock()
                .unwrap()
                .outbox
                .on_ack(&push::parse_push_ack(&ack));
        }
    };

    // The phone is connected (it will send the seen).
    let phone = Device::native(&world, "dev-phone", log.clone());
    let mut pw = world.tcp();
    let mut p = phone.connect(&mut pw).unwrap();
    list(&mut p, &mut pw, now());

    // 1. The approval: two sealed hints (Mac and phone), one message.
    let plain = HintPlain {
        tool: "Bash".into(),
        summary: "npm test".into(),
    };
    let ap = "8c3e9d6b-1f40-4b52-8dae-4f5a6b7c8d9e";
    world.core.lock().unwrap().open_approval(SES_A, ap, &plain);
    assert_eq!(flush(&world, &mut host_link), 1);
    let verdicts = relay_step(&mut relay, &mut relay_end, &mut to_phone, c);
    assert_eq!(verdicts, vec![Verdict::Accepted, Verdict::Accepted]);
    deliver_acks(&world, &mut host_link);
    assert_eq!(
        world.core.lock().unwrap().outbox.len(),
        0,
        "both hints acked"
    );
    // The phone opens its own hint (tool and summary sealed to its key);
    // the Mac's is not for it.
    let bytes = phone_push.recv().unwrap();
    let object = SignedObject::parse(&bytes).unwrap();
    let hint = Hint::verify(&object, &log, c, Verifier::Client).unwrap();
    let mut book = HintBook::new();
    assert_eq!(book.offer(hint.clone()), Ok(push::Accepted::Accepted));
    assert_eq!(book.offer(hint.clone()), Ok(push::Accepted::Idempotent));
    assert_eq!(
        hint.open(
            &world.book.provider,
            &KeyId::new("dev-phone/enc"),
            "dev-phone"
        )
        .unwrap(),
        plain
    );
    assert!(
        hint.open(&world.book.provider, &KeyId::new("dev-mac/enc"), "dev-mac")
            .is_err()
    );
    // A tampered hint fails its signature.
    let mut tampered = object.to_json();
    tampered["body"]["created_at"] = json!(c - 1000);
    let tampered = SignedObject::parse(tampered.to_string().as_bytes()).unwrap();
    assert_eq!(
        Hint::verify(&tampered, &log, c, Verifier::Client),
        Err(push::Refusal::BadSignature)
    );

    // 2. The schedule at exact boundaries: desktop at 0 s, nothing at
    // 59.999 s, the mobile stage at 60 s.
    let pushes = run_until(&ledger, c, c);
    assert_eq!(pushes.len(), 1);
    assert_eq!(
        (pushes[0].device_id.as_str(), pushes[0].kind),
        ("dev-mac", "desktop_os")
    );
    assert!(run_until(&ledger, c, c + 59_999).is_empty());
    let pushes = run_until(&ledger, c + 59_999, c + 60_000);
    assert_eq!(pushes.len(), 1);
    assert_eq!(
        (
            pushes[0].device_id.as_str(),
            pushes[0].kind,
            pushes[0].due_at
        ),
        ("dev-phone", "mobile", c + 60_000)
    );
    assert!(
        run_until(&ledger, c + 60_000, c + 600_000).is_empty(),
        "each stage once"
    );

    // 3. The guard: a 75 s approval's mobile stage lands on expires − 15 s
    // and is never sent; 75.001 s, sent at 60 s.
    for (lifetime, sent) in [(75_000u64, false), (75_001, true)] {
        let l = Mutex::new(RelayLedger::new());
        let key = push::ApprovalKey::new(
            &log,
            "host-a",
            1,
            SES_A,
            "22222222-2222-4222-8222-222222222222",
            &format!("6c1d3e5f-7081-4293-a4b5-{lifetime:012}"),
        );
        let core = world.core.lock().unwrap();
        let o = push::open_hint(
            &core.keys,
            &core.host_key,
            &key,
            c,
            c + lifetime,
            "dev-phone",
            &world.book.public("dev-phone/enc"),
            &plain,
        )
        .unwrap();
        drop(core);
        assert_eq!(
            l.lock().unwrap().receive_hint(&o, &log, c).0,
            Verdict::Accepted
        );
        let pushes = run_until(&l, c, c + lifetime + 300_000);
        assert_eq!(
            pushes.iter().any(|p| p.kind == "mobile"),
            sent,
            "{lifetime}"
        );
    }

    // 4. A late receipt (30 s) and a failover: the desktop stage at
    // receipt, the mobile one still at created_at + 60 s, once, from the
    // replica that took over the shared store.
    let store = Arc::new(Mutex::new(RelayLedger::new()));
    let key = push::ApprovalKey::new(
        &log,
        "host-a",
        1,
        SES_A,
        "22222222-2222-4222-8222-222222222222",
        "7d2e4f60-8192-43a4-b5c6-d7e8f90a1b23",
    );
    let hints: Vec<SignedObject> = {
        let core = world.core.lock().unwrap();
        ["dev-mac", "dev-phone"]
            .iter()
            .map(|d| {
                push::open_hint(
                    &core.keys,
                    &core.host_key,
                    &key,
                    c,
                    c + 600_000,
                    d,
                    &world.book.public(&format!("{d}/enc")),
                    &plain,
                )
                .unwrap()
            })
            .collect()
    };
    for h in &hints {
        assert_eq!(
            store.lock().unwrap().receive_hint(h, &log, c + 30_000).0,
            Verdict::Accepted
        );
    }
    let r1 = run_until(&store, c + 30_000, c + 30_000);
    assert_eq!(r1.len(), 1);
    assert_eq!((r1[0].kind, r1[0].due_at), ("desktop_os", c + 30_000));
    // r1 fails at c + 45 s; r2 resumes from the shared store; both replicas
    // ticking at once still send the mobile stage only once.
    let r2_store = store.clone();
    let r2 = thread::spawn(move || run_until(&r2_store, c + 45_000, c + 60_000));
    let r1_late = run_until(&store, c + 45_000, c + 60_000);
    let r2 = r2.join().unwrap();
    let all: Vec<_> = r1_late.iter().chain(r2.iter()).collect();
    assert_eq!(all.len(), 1, "sent once across replicas");
    assert_eq!((all[0].kind, all[0].due_at), ("mobile", c + 60_000));
    assert_eq!(
        store
            .lock()
            .unwrap()
            .receive_hint(&hints[1], &log, c + 61_000)
            .0,
        Verdict::Idempotent
    );

    // 5. A seen from the phone suppresses the mobile stage; the first
    // push_ack is lost, so the host resends the same bytes after 10 s.
    let ap2 = "9a1b2c3d-4e5f-4061-8273-8495a6b7c8d9";
    world.core.lock().unwrap().open_approval(SES_A, ap2, &plain);
    flush(&world, &mut host_link);
    relay_step(&mut relay, &mut relay_end, &mut to_phone, c);
    deliver_acks(&world, &mut host_link);
    phone_push.try_recv(100);
    let (_, frame) = p.approval_seen(SES_A, ap2, now()).unwrap();
    let ev = exchange(&mut p, &mut pw, &frame, now(), |e| {
        e.iter().any(|e| matches!(e, Event::Seen { .. }))
    });
    assert!(!ev.is_empty());
    assert_eq!(flush(&world, &mut host_link), 1, "push_seen sent");
    let first_seen = relay_end.recv().unwrap();
    relay.drop_next_ack = true;
    let (v, ack) = relay.receive(&serde_json::from_slice(&first_seen).unwrap(), c + 20_000);
    assert_eq!(v, vec![Verdict::Applied]);
    assert!(ack.is_none(), "the ack is lost");
    // A repeated seen is answered, never re-signed or resent at once.
    let (_, frame) = p.approval_seen(SES_A, ap2, now()).unwrap();
    exchange(&mut p, &mut pw, &frame, now(), |e| {
        e.iter().any(|e| matches!(e, Event::Seen { .. }))
    });
    assert_eq!(flush(&world, &mut host_link), 0);
    world.advance(10_000);
    assert_eq!(flush(&world, &mut host_link), 1, "resent after 10 s");
    let resent = relay_end.recv().unwrap();
    assert_eq!(resent, first_seen, "the same signed bytes");
    let (v, ack) = relay.receive(&serde_json::from_slice(&resent).unwrap(), c + 30_000);
    assert_eq!(v, vec![Verdict::Idempotent]);
    relay_end.send(ack.unwrap().to_string().as_bytes());
    deliver_acks(&world, &mut host_link);
    world.advance(30_000);
    assert_eq!(flush(&world, &mut host_link), 0, "acked: nothing more");
    let ap2_pushes: Vec<_> = run_until(&ledger, c, c + 600_000)
        .into_iter()
        .filter(|p| p.collapse_id == ap2)
        .collect();
    assert_eq!(
        ap2_pushes.len(),
        1,
        "the desktop stage only: the seen suppressed mobile"
    );
    assert_eq!(ap2_pushes[0].kind, "desktop_os");

    // 6. A seen from another process generation suppresses nothing.
    let other = push::ApprovalKey::new(
        &log,
        "host-a",
        1,
        SES_A,
        "33333333-3333-4333-8333-333333333333",
        ap,
    );
    let foreign = {
        let core = world.core.lock().unwrap();
        push::seen(
            &core.keys,
            &core.host_key,
            &other,
            c,
            "dev-phone",
            c + 20_000,
        )
        .unwrap()
    };
    let l = Mutex::new(RelayLedger::new());
    for h in &hints {
        l.lock().unwrap().receive_hint(h, &log, c);
    }
    assert_eq!(
        l.lock().unwrap().receive_seen(&foreign, &log, c).0,
        Verdict::Pending
    );
    let pushes = run_until(&l, c, c + 600_000);
    assert!(pushes.iter().any(|p| p.kind == "mobile"), "still sent");

    // 7. After resolution a seen reopens nothing; the resolved replaces the
    // delivered notifications.
    world
        .core
        .lock()
        .unwrap()
        .close_approval(ap, "answered_terminal");
    flush(&world, &mut host_link);
    relay_step(&mut relay, &mut relay_end, &mut to_phone, c + 70_000);
    let replaced: BTreeSet<String> = run_until(&ledger, c + 70_000, c + 70_000)
        .into_iter()
        .filter(|p| p.kind == "replace" && p.collapse_id == ap)
        .map(|p| p.device_id)
        .collect();
    assert_eq!(
        replaced,
        ["dev-mac".to_string(), "dev-phone".to_string()].into()
    );
    let late_seen = {
        let core = world.core.lock().unwrap();
        push::seen(
            &core.keys,
            &core.host_key,
            hint.key(),
            c,
            "dev-phone",
            c + 71_000,
        )
        .unwrap()
    };
    assert_eq!(
        ledger
            .lock()
            .unwrap()
            .receive_seen(&late_seen, &log, c + 71_000)
            .0,
        Verdict::IgnoredAfterResolved
    );
    assert!(
        run_until(&ledger, c + 71_000, c + 900_000)
            .iter()
            .all(|p| p.collapse_id != ap)
    );
    // And the phone's own book: the resolved dominates the open it holds.
    let resolved = {
        let core = world.core.lock().unwrap();
        push::resolved_hint(
            &core.keys,
            &core.host_key,
            hint.key(),
            c,
            c + 600_000,
            "answered_terminal",
            c + 70_000,
        )
        .unwrap()
    };
    let resolved = Hint::verify(&resolved, &log, c + 70_000, Verifier::Client).unwrap();
    assert_eq!(book.offer(resolved), Ok(push::Accepted::Accepted));
    assert_eq!(book.offer(hint), Ok(push::Accepted::IgnoredAfterResolved));
}

// --------------------------------------------------------------- restore

/// The relay for a restore: serves the log, the envelope and the CAS
/// append over a socket (JSON requests).
fn relay_server(log: Vec<SignedObject>, blob: String) -> (Wire, thread::JoinHandle<Vec<Value>>) {
    let (client, server) = UnixStream::pair().unwrap();
    let handle = thread::spawn(move || {
        let mut wire = Wire::unix(server);
        let mut relay = FakeRelay::with_log(log);
        let mut appended = Vec::new();
        while let Some(req) = wire.try_recv(2_000) {
            let req: Value = serde_json::from_slice(&req).unwrap();
            let reply = match req["op"].as_str().unwrap() {
                "log" => {
                    json!({"entries": relay.after(0).iter().map(SignedObject::to_json).collect::<Vec<_>>()})
                }
                "blob" => json!({"blob": blob}),
                "append" => {
                    let entry = SignedObject::parse(req["entry"].to_string().as_bytes()).unwrap();
                    let expected = Head::from_json(&req["expected"]).unwrap();
                    let r = relay.append(&entry, expected);
                    appended.push(req["entry"].clone());
                    json!({"status": r.status()})
                }
                _ => break,
            };
            wire.send(reply.to_string().as_bytes());
        }
        appended
    });
    (Wire::unix(client), handle)
}

fn ask(wire: &mut Wire, req: Value) -> Value {
    wire.send(req.to_string().as_bytes());
    serde_json::from_slice(&wire.recv().unwrap()).unwrap()
}

/// The restoring device's init/accept with a host over a real socket (an
/// `init` needs no membership: it pins the host from the fetched chain).
fn host_head(world: &World, fetched: &Membership) -> HostAccept {
    let mut wire = world.tcp();
    let (_, init) = Connector::new("host-a")
        .start(fetched, world.mono())
        .unwrap();
    wire.send(&init);
    let accept = wire.recv().unwrap();
    assert!(matches!(parse_frame(&accept), Ok(Frame::Accept(_))));
    HostAccept::from_messages(
        &StrictValue::parse(&init, usize::MAX).unwrap(),
        &StrictValue::parse(&accept, usize::MAX).unwrap(),
    )
    .unwrap()
}

/// What a new phone does: fetch the log and envelope from the relay,
/// confirm with each reachable host, restore, publish.
fn restore_from(
    world: &World,
    kit: &str,
    relay_log: &[&str],
    blob: &Value,
    hosts: &[&World],
) -> (RestoreFlow, Result<Vec<String>, RestoreError>, Vec<Value>) {
    let objects: Vec<SignedObject> = relay_log.iter().map(|l| world.v.object(l)).collect();
    let (mut relay, handle) = relay_server(objects, blob.to_string());
    let entries: Vec<Entry> = ask(&mut relay, json!({"op": "log"}))["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| Entry::parse_bytes(e.to_string().as_bytes()).unwrap())
        .collect();
    let blob = ask(&mut relay, json!({"op": "blob"}))["blob"]
        .as_str()
        .unwrap()
        .to_owned();
    let entry = &world.book.keys[kit];
    let mut flow = RestoreFlow::read(
        &unhex32(entry["R_hex"].as_str().unwrap()),
        ACCOUNT,
        genesis_hash(),
        &hex16(entry["kit_tag_hex"].as_str().unwrap()),
    )
    .unwrap();
    let now = world.clock.lock().unwrap().now.clone();
    // The chain as fetched names the hosts to ask (their keys come from it).
    let fetched = Membership::verify_chain(ACCOUNT, &genesis_hash(), &entries, &now)
        .ok()
        .map(|v| v.membership);
    let heads: Vec<HostAccept> = match &fetched {
        Some(f) => hosts.iter().map(|h| host_head(h, f)).collect(),
        None => Vec::new(),
    };
    let result = flow
        .attempt(&entries, blob.as_bytes(), &heads, &now)
        .map(|r| r.keys.iter().map(|k| k.kid.clone()).collect::<Vec<_>>());
    if result.is_ok() {
        let member = Member {
            device_id: "dev-newmac".into(),
            auth_key: world.book.public("dev-newmac/auth"),
            kind: MemberKind::Native {
                enc_key: world.book.public("dev-newmac/enc"),
                roles: [Role::Control, Role::Manage, Role::View].into(),
            },
        };
        let (entry, expected) = flow.enroll(member, now.wall_ms).unwrap();
        let reply = ask(
            &mut relay,
            json!({"op": "append", "entry": entry.object().to_json(), "expected": expected.to_json()}),
        );
        assert_eq!(reply["status"], 200);
        assert!(matches!(
            flow.append_reply(AppendReply::Stored, &now),
            Ok(Enrollment::Published { .. })
        ));
    }
    relay.send(json!({"op": "bye"}).to_string().as_bytes());
    let appended = handle.join().unwrap();
    (flow, result, appended)
}

/// A new phone restores K from its Recovery Kit over a simulated relay,
/// confirmed by a host-signed head over a real handshake, and publishes its
/// recovery_add on that head; a rolled-back backup, a substitute chain, a
/// stale head, no host reachable and a remaining deferral are refused or
/// withheld, with nothing stored or published.
#[test]
fn a_new_phone_restores_k_from_the_kit() {
    let recovery = load("r9-vectors-recovery");
    let rotated = &recovery["k_backup_rotated"]["wire"];
    let older = &recovery["k_backup"]["wire"];
    let full = ["E1", "E2", "E3", "E4", "E5", "E6", "KB7", "KB8"];

    // Restored: the host at KB8 confirms the relay's log.
    let host = World::new(&full);
    let (flow, result, appended) = restore_from(&host, "recovery", &full, rotated, &[&host]);
    assert_eq!(result.unwrap(), ["7a3c9e10", "b982533d", "1f2e3d4c"]);
    assert!(flow.k_stored());
    assert_eq!(flow.freshness(), Some(Freshness::HostConfirmed));
    assert!(
        !flow.may_rotate_k("dev-newmac"),
        "pending: rotates nothing yet"
    );
    assert_eq!(appended.len(), 1);
    assert_eq!(appended[0]["body"]["action"], "recovery_add");
    assert_eq!(appended[0]["body"]["seq"], 9);
    assert_eq!(
        appended[0]["body"]["prev_hash"],
        host.v.hash("KB8").to_hex()
    );

    // A rolled-back backup (an older authentic envelope).
    let (flow, result, appended) = restore_from(&host, "recovery", &full, older, &[&host]);
    assert_eq!(result, Err(RestoreError::BackupHashMismatch));
    assert!(!flow.k_stored() && appended.is_empty());

    // A substitute chain under the kit's account: refused by the kit's
    // genesis anchor before any head is asked for.
    let sub = load("r9-vectors-recovery")["substitute_chain"]["backup"]["wire"].clone();
    let (flow, result, appended) =
        restore_from(&host, "recovery", &["SUB1", "SUB2", "SUB3"], &sub, &[]);
    assert_eq!(result, Err(RestoreError::GenesisMismatch));
    assert!(!flow.k_stored() && appended.is_empty());

    // A stale head: the relay serves L + KB7 while the host signed KB8.
    let (flow, result, appended) = restore_from(
        &host,
        "recovery",
        &["E1", "E2", "E3", "E4", "E5", "E6", "KB7"],
        older,
        &[&host],
    );
    assert_eq!(result, Err(RestoreError::LogBehindHost));
    assert!(flow.refetch() && !flow.k_stored() && appended.is_empty());

    // No host reachable: withheld, and the user is told why.
    let (flow, result, appended) = restore_from(&host, "recovery", &full, rotated, &[]);
    assert!(matches!(result, Err(RestoreError::Withheld { .. })));
    assert_eq!(
        flow.user_notice(),
        Some(UserNotice::WaitingForHost {
            hosts: vec!["host-a".into()]
        })
    );
    assert!(!flow.k_stored() && !flow.may_seal_backup("dev-newmac") && appended.is_empty());

    // A remaining deferral: the relay's log goes on past an entry signed by
    // a recovery still pending (N8 after R7), and the host only confirms
    // R7: the restore waits instead of going on with the prefix.
    let pending_host = World::new(&["E1", "E2", "E3", "E4", "E5", "E6", "R7"]);
    let (flow, result, appended) = restore_from(
        &pending_host,
        "recovery",
        &["E1", "E2", "E3", "E4", "E5", "E6", "R7", "N8"],
        rotated,
        &[&pending_host],
    );
    assert!(
        matches!(result, Err(RestoreError::Withheld { .. })),
        "{result:?}"
    );
    assert!(!flow.k_stored() && appended.is_empty());
}

/// The revoked-grant journal holds 256 unexpired revocations and refuses
/// the next one with `busy` rather than evicting one: 256 junk
/// `revoke_grant`s from a member with control (here the bot, which §R9.6
/// allows to revoke) can't re-enable a real revoked grant. Ids drop out at
/// their grant's expiry. A request the authority map doesn't know (a
/// second `hello` inside the channel) is refused, never let through.
#[test]
fn junk_revocations_cannot_reenable_a_revoked_grant() {
    let world = World::new(&L);
    let log = world.log(&L);
    let now = || world.mono();
    let browser = Device::browser(&world, grant_vector(), log.clone());
    let mut rw = world.tcp();
    let mut r = browser.connect(&mut rw).unwrap();
    let phone = Device::native(&world, "dev-phone", log.clone());
    let mut pw = world.tcp();
    let mut p = phone.connect(&mut pw).unwrap();
    let (_, frame) = p
        .revoke_grant("7b2d8c5a-0e3f-4a41-9c9d-3e4f5a6b7c8d", now())
        .unwrap();
    exchange(&mut p, &mut pw, &frame, now(), |e| {
        e.iter().any(|e| matches!(e, Event::GrantRevoked { .. }))
    });
    let fence = rw.recv().unwrap();
    assert!(matches!(
        &r.on_frame(&fence, now()).unwrap()[..],
        [Event::Fenced(_)]
    ));
    // The bot floods the journal: 255 more fit, the 256th is busy.
    let bot = Device::service(&world, "svc-discord", log.clone());
    let mut bw = world.unix();
    let mut b = bot.connect(&mut bw).unwrap();
    let mut busy = 0;
    for i in 0..256 {
        let (_, frame) = b
            .revoke_grant(&format!("00000000-0000-4000-8000-{i:012}"), now())
            .unwrap();
        let ev = exchange(&mut b, &mut bw, &frame, now(), |e| !e.is_empty());
        match &ev[..] {
            [Event::GrantRevoked { .. }] => {}
            [Event::Error(e)] if e.code == "busy" => busy += 1,
            other => panic!("{other:?}"),
        }
    }
    assert_eq!(busy, 1, "only the 257th revocation is refused");
    assert_eq!(world.core.lock().unwrap().revoked.len(), 256);
    let mut rw2 = world.tcp();
    assert_eq!(
        refused(browser.connect(&mut rw2)),
        ("unauthorized".into(), Some("grant revoked".into()))
    );
    // A second hello inside the channel isn't a request the map knows.
    let hello = json!({"type": "session", "data": {"v": 1, "op": "hello",
        "id": "aaaaaaaa-0000-4000-8000-0000000000c1", "revision": 9}});
    let frame = p.send(&hello, now()).unwrap();
    let ev = exchange(&mut p, &mut pw, &frame, now(), |e| !e.is_empty());
    assert_eq!(error_code(&ev).as_deref(), Some("invalid_request"));
    // At the grant's expiry its revocation drops out (the grant is refused
    // for its expiry then); the junk ids stay until their own (1 h 5 min).
    world.set_wall(1_793_267_600_000);
    assert_eq!(world.core.lock().unwrap().revoked.len(), 255);
    world.advance(3_900_001);
    assert!(world.core.lock().unwrap().revoked.is_empty());
}
