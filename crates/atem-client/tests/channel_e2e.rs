//! `atem-ch1` end to end through the public API only, the way it runs:
//! a simulated host serves each transport connection on its own thread, a
//! phone (P-256 native member) and a bot (Ed25519 service member) connect
//! over real loopback sockets (a Unix socketpair, TCP on 127.0.0.1) with
//! length-prefixed frames, and the crate does all the crypto. Faults are
//! injected by a man in the middle on the wire (a proxy thread between two
//! socketpairs) that flips bits, truncates, drops, reorders and replays
//! frames. Keys and log L are the r9 test vectors (`r9-vectors-keys`,
//! `r9-vectors-membership-log`).
mod support;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Instant;

use atem_client::canonical::StrictValue;
use atem_client::channel::responder::HostContext;
use atem_client::channel::wire::{self, Frame, MAX_FRAME_BYTES, Parsed};
use atem_client::channel::{
    Carriage, Channel, ChannelError, ClientProof, Failure, HANDSHAKE_STEP_MS, HeadRelation,
    InitLimiter, Initiator, MAX_PLAINTEXT, Principal, Responder,
};
use atem_client::encoding::{b64u, b64u_decode};
use atem_client::membership::entry::HostRecord;
use atem_client::membership::{Action, Admission, Entry, Membership, sign_entry};
use atem_client::{Alg, KeyId, KeyProvider, SoftwareKeys};
use serde_json::{Value, json};
use support::*;

/// What every plaintext in these tests carries; it must never be seen on
/// the wire.
const MARKER: &str = "PLAINTEXT-MARKER-7f3a";
const WALL: u64 = 1_793_264_000_000;

// ------------------------------------------------------------- transport

/// One frame: a 4-byte big-endian length, then the frame bytes.
fn send(stream: &mut impl Write, frame: &[u8]) -> bool {
    let len = u32::try_from(frame.len()).unwrap().to_be_bytes();
    stream.write_all(&len).is_ok() && stream.write_all(frame).is_ok() && stream.flush().is_ok()
}

/// The next frame, or `None` at the end of the stream (or a frame over the
/// channel's bound, which a real transport drops too).
fn recv(stream: &mut impl Read) -> Option<Vec<u8>> {
    let mut len = [0u8; 4];
    stream.read_exact(&mut len).ok()?;
    let len = u32::from_be_bytes(len) as usize;
    if len > MAX_FRAME_BYTES + 1024 {
        return None;
    }
    let mut frame = vec![0u8; len];
    stream.read_exact(&mut frame).ok()?;
    Some(frame)
}

/// Milliseconds on one monotonic clock shared by both ends.
#[derive(Clone)]
struct Mono(Instant);

impl Mono {
    fn new() -> Self {
        Mono(Instant::now())
    }

    fn now(&self) -> u64 {
        self.0.elapsed().as_millis() as u64
    }
}

// ----------------------------------------------------------------- world

/// The test keys and log L.
struct World {
    book: Book,
    v: Vectors,
    clock: Clock,
}

impl World {
    fn new() -> Arc<Self> {
        Arc::new(World {
            book: Book::load(),
            v: Vectors::load(),
            clock: Clock::at(WALL),
        })
    }

    /// A verified log of these entries (vector labels, then extra entries).
    fn log(&self, labels: &[&str], extra: &[Entry]) -> Membership {
        let mut entries = self.v.entries(labels);
        entries.extend_from_slice(extra);
        Membership::verify_chain(ACCOUNT, &genesis_hash(), &entries, &self.clock.now)
            .unwrap()
            .membership
    }

    fn log_l(&self) -> Membership {
        self.log(&["E1", "E2", "E3", "E4", "E5", "E6"], &[])
    }

    /// `add_host` re-keying host-a (trust generation 2, a new key), signed
    /// by dev-mac on `log`.
    fn rekey(&self, log: &Membership, new_key: &atem_client::PublicKey) -> Entry {
        let body = log.draft(
            "dev-mac",
            WALL + 7_000,
            &Action::AddHost {
                host: HostRecord {
                    host_id: "host-a".into(),
                    host_trust_gen: 2,
                    host_key: new_key.clone(),
                },
            },
        );
        sign_entry(&self.book.provider, &self.book.auth("dev-mac"), body).unwrap()
    }
}

// ------------------------------------------------------------------ host

/// A simulated host: its committed log (shared by its connections; a
/// carriage commits here), identity and channel key.
#[derive(Clone)]
struct HostSide {
    world: Arc<World>,
    log: Arc<Mutex<Membership>>,
    host_trust_gen: u64,
    /// The key it signs `accept` with (a book id, or `old` for the
    /// pre-rotation key of the re-key test).
    key: KeyId,
    keys: Arc<SoftwareKeys>,
    mono: Mono,
}

impl HostSide {
    fn new(world: &Arc<World>, log: Membership, mono: &Mono) -> Self {
        let mut keys = SoftwareKeys::new();
        let secret = unhex32(
            world.book.keys["host-a"]["host_key"]["secret_hex"]
                .as_str()
                .unwrap(),
        );
        keys.insert_ed25519(KeyId::new("host-a"), &secret);
        HostSide {
            world: world.clone(),
            log: Arc::new(Mutex::new(log)),
            host_trust_gen: 1,
            key: KeyId::new("host-a"),
            keys: Arc::new(keys),
            mono: mono.clone(),
        }
    }

    /// Serves `count` connections from a TCP listener on its own thread.
    fn listen_tcp(&self, count: usize) -> (u16, thread::JoinHandle<Vec<Vec<HostEvent>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let host = self.clone();
        let handle = thread::spawn(move || {
            (0..count)
                .map(|_| {
                    let (mut stream, _) = listener.accept().unwrap();
                    host.serve(&mut stream)
                })
                .collect()
        });
        (port, handle)
    }

    /// Serves one connection over a socketpair on its own thread.
    fn spawn(&self, mut stream: UnixStream) -> thread::JoinHandle<Vec<HostEvent>> {
        let host = self.clone();
        thread::spawn(move || host.serve(&mut stream))
    }

    /// One transport connection: handshake, admission, then an echo loop.
    fn serve<S: Read + Write>(&self, stream: &mut S) -> Vec<HostEvent> {
        let mut events = Vec::new();
        let mut limiter = InitLimiter::new();
        let refused = |events: &mut Vec<HostEvent>,
                       stream: &mut S,
                       error: &ChannelError,
                       reply: Option<Vec<u8>>| {
            events.push(HostEvent::Refused {
                code: error.code().to_owned(),
                reply: reply.clone(),
            });
            if let Some(reply) = reply {
                send(stream, &reply);
            }
        };
        let Some(init) = recv(stream) else {
            events.push(HostEvent::Eof);
            return events;
        };
        if let Ok(Parsed::Plain(_)) = wire::parse(&init) {
            events.push(HostEvent::Plain);
            return events;
        }
        if !limiter.admit(self.mono.now()) {
            let r = InitLimiter::busy();
            refused(&mut events, stream, &r.error, r.reply);
            return events;
        }
        let (await_finish, accept) = {
            let log = self.log.lock().unwrap();
            let ctx = HostContext {
                log: &log,
                host_id: "host-a",
                host_trust_gen: self.host_trust_gen,
                provider: &*self.keys,
                key: &self.key,
            };
            match Responder::on_init(&ctx, &init, self.mono.now()) {
                Ok(ok) => ok,
                Err(r) => {
                    refused(&mut events, stream, &r.error, r.reply);
                    return events;
                }
            }
        };
        events.push(HostEvent::Accepted(accept.clone()));
        send(stream, &accept);
        let Some(finish) = recv(stream) else {
            events.push(HostEvent::Eof);
            return events;
        };
        // A second `init` on the same transport within a second: `busy`.
        if let Ok(Frame::Init(_)) = wire::parse_frame(&finish)
            && !limiter.admit(self.mono.now())
        {
            let r = InitLimiter::busy();
            refused(&mut events, stream, &r.error, r.reply);
            return events;
        }
        let opened = match await_finish.on_finish(&finish, self.mono.now()) {
            Ok(opened) => opened,
            Err(r) => {
                refused(&mut events, stream, &r.error, r.reply);
                return events;
            }
        };
        let Some(hello) = Hello::parse(opened.hello()) else {
            let r = opened.malformed();
            refused(&mut events, stream, &r.error, r.reply);
            return events;
        };
        let keyed = opened.key(&hello.proof);
        // The carriage first, then the principal against the committed head,
        // then sig_c (§R9.7 step 6).
        let now = &self.world.clock.now;
        let admission = {
            let mut log = self.log.lock().unwrap();
            let eval = log.evaluate(&hello.entries, hello.entries_bytes, now);
            let device = match &hello.proof.principal {
                Principal::Native { device_id } | Principal::Service { device_id } => {
                    device_id.clone()
                }
                Principal::Browser { .. } => unreachable!("no browsers here"),
            };
            let admission = eval.admission(&device, hello.more, now);
            *log = eval.next;
            admission
        };
        let (auth_key, head) = match admission {
            Admission::Member { head, state } => (state.member.auth_key, head),
            other => {
                let code = match other {
                    Admission::Frozen => "account_frozen",
                    Admission::Invalid { .. } => "membership_invalid",
                    Admission::Incomplete { .. } => "membership_incomplete",
                    Admission::RecoveryPending { .. } => "recovery_pending",
                    _ => "unauthorized",
                };
                let reply = keyed.refuse(&session_error(code), self.mono.now()).unwrap();
                events.push(HostEvent::RefusedInChannel {
                    code: code.into(),
                    reply: reply.clone(),
                });
                send(stream, &reply);
                return events;
            }
        };
        let principal = hello.proof.principal.name();
        let mut channel = match keyed.admit(&auth_key) {
            Ok(channel) => channel,
            Err(refusal) => {
                let reply = refusal
                    .reply(&session_error("handshake_failed"), self.mono.now())
                    .unwrap();
                events.push(HostEvent::RefusedInChannel {
                    code: "handshake_failed".into(),
                    reply: reply.clone(),
                });
                send(stream, &reply);
                return events;
            }
        };
        let welcome = json!({"type": "session", "data": {"v": 1, "op": "welcome", "revision": 9,
            "principal": principal, "channel_id": channel.channel_id(),
            "head": {"seq": head.seq, "hash": head.hash.to_hex()}}});
        let frame = channel
            .seal(welcome.to_string().as_bytes(), self.mono.now())
            .unwrap();
        events.push(HostEvent::Welcomed {
            principal,
            channel_id: channel.channel_id().to_owned(),
        });
        send(stream, &frame);
        loop {
            let Some(frame) = recv(stream) else {
                events.push(HostEvent::Eof);
                return events;
            };
            match channel.open(&frame, self.mono.now()) {
                Ok(plain) => {
                    events.push(HostEvent::Received(plain.to_vec()));
                    // Echo it back (h2c records of the same size).
                    let echo = channel.seal(&plain, self.mono.now()).unwrap();
                    if !send(stream, &echo) {
                        return events;
                    }
                }
                Err(error) => {
                    // Closed without a reply.
                    assert!(channel.is_closed());
                    events.push(HostEvent::Closed(error.code().to_owned()));
                    return events;
                }
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
enum HostEvent {
    /// A plain frame outside any channel.
    Plain,
    Accepted(Vec<u8>),
    /// A clear refusal before `finish` opened (`reply` is what was sent).
    Refused {
        code: String,
        reply: Option<Vec<u8>>,
    },
    /// A refusal as the encrypted first record.
    RefusedInChannel {
        code: String,
        reply: Vec<u8>,
    },
    Welcomed {
        principal: String,
        channel_id: String,
    },
    Received(Vec<u8>),
    /// A record failed: closed without a reply.
    Closed(String),
    Eof,
}

fn session_error(code: &str) -> Vec<u8> {
    json!({"type": "session", "data": {"v": 1, "op": "error", "code": code}})
        .to_string()
        .into_bytes()
}

/// The parts of a `hello` the channel and the carriage need (the full r9
/// `hello` is Task 4's).
struct Hello {
    proof: ClientProof,
    entries: Vec<StrictValue>,
    entries_bytes: usize,
    more: bool,
}

impl Hello {
    fn build(principal: &Principal, sig_c: &[u8], carriage: &Carriage) -> Vec<u8> {
        let mut membership = json!({
            "head": {"seq": carriage.head.seq, "hash": carriage.head.hash.to_hex()},
            "entries": carriage.entries.iter().map(|o| o.to_json()).collect::<Vec<_>>(),
        });
        if carriage.more {
            membership["more"] = json!(true);
        }
        json!({"type": "session", "data": {"v": 1, "op": "hello", "revision": 9,
            "id": format!("hello-{MARKER}"),
            "proof": {"principal": principal.to_json(), "sig": b64u(sig_c)},
            "membership": membership}})
        .to_string()
        .into_bytes()
    }

    fn parse(bytes: &[u8]) -> Option<Hello> {
        let hello = StrictValue::parse(bytes, MAX_PLAINTEXT).ok()?;
        let data = hello.get("data")?;
        let proof = data.get("proof")?;
        let principal = Principal::from_json(proof.get("principal")?.value(), None).ok()?;
        let sig_c = b64u_decode(proof.get("sig")?.value().as_str()?).ok()?;
        let membership = data.get("membership")?;
        let entries = membership.get("entries")?;
        Some(Hello {
            proof: ClientProof { principal, sig_c },
            entries_bytes: entries.value().to_string().len(),
            entries: entries.items()?,
            more: membership.value().get("more") == Some(&Value::Bool(true)),
        })
    }
}

// ---------------------------------------------------------------- client

/// A simulated device: its verified log and its key behind a provider.
struct Device<'a> {
    log: Membership,
    principal: Principal,
    keys: &'a dyn KeyProvider,
    key: KeyId,
}

#[derive(Debug, PartialEq)]
enum ClientError {
    Channel(ChannelError),
    /// The host closed the transport.
    Eof,
}

impl From<ChannelError> for ClientError {
    fn from(e: ChannelError) -> Self {
        ClientError::Channel(e)
    }
}

/// What a client got from a full handshake.
struct Connected {
    channel: Channel,
    relation: HeadRelation,
    carriage: Carriage,
    welcome: Value,
}

impl Device<'_> {
    fn native<'w>(world: &'w World, id: &str, log: Membership) -> Device<'w> {
        Device {
            log,
            principal: Principal::Native {
                device_id: id.into(),
            },
            keys: &world.book.provider,
            key: world.book.auth(id),
        }
    }

    fn service<'w>(world: &'w World, id: &str, log: Membership) -> Device<'w> {
        Device {
            log,
            principal: Principal::Service {
                device_id: id.into(),
            },
            keys: &world.book.provider,
            key: world.book.auth(id),
        }
    }

    /// The handshake over `stream`, then the host's first record opened:
    /// `welcome`, or its encrypted refusal (a session `error`).
    fn connect<S: Read + Write>(
        &self,
        stream: &mut S,
        mono: &Mono,
    ) -> Result<Connected, ClientError> {
        let before = self.log.clone();
        let (await_accept, init) = Initiator::start(&self.log, "host-a", mono.now())?;
        send(stream, &init);
        let accept = recv(stream).ok_or(ClientError::Eof)?;
        let accepted = await_accept.on_frame(&accept, &self.log, mono.now())?;
        // The host's head is reported, never adopted.
        assert_eq!(self.log, before);
        let relation = accepted.relation();
        let carriage = Carriage::plan(&self.log, accepted.host_head().head(), None);
        let signed = accepted.sign(self.principal.clone(), self.keys, &self.key)?;
        let hello = Hello::build(&self.principal, signed.sig_c(), &carriage);
        let (mut channel, finish) = signed.finish(&hello, mono.now())?;
        send(stream, &finish);
        let first = recv(stream).ok_or(ClientError::Eof)?;
        let welcome = channel.open(&first, mono.now())?;
        let welcome: Value = serde_json::from_slice(&welcome).unwrap();
        Ok(Connected {
            channel,
            relation,
            carriage,
            welcome,
        })
    }
}

/// A session-family message of exactly `size` bytes carrying the marker.
fn message(n: usize, size: usize) -> Vec<u8> {
    let head =
        format!("{{\"type\":\"session\",\"data\":{{\"op\":\"note\",\"n\":{n},\"pad\":\"{MARKER}");
    let tail = "\"}}";
    assert!(size >= head.len() + tail.len());
    let mut out = head.into_bytes();
    out.resize(size - tail.len(), b'x');
    out.extend_from_slice(tail.as_bytes());
    out
}

/// Sends `plain` and returns the host's echo.
fn exchange<S: Read + Write>(
    channel: &mut Channel,
    stream: &mut S,
    plain: &[u8],
    mono: &Mono,
) -> Result<Vec<u8>, ClientError> {
    let frame = channel.seal(plain, mono.now())?;
    if !send(stream, &frame) {
        return Err(ClientError::Eof);
    }
    let echo = recv(stream).ok_or(ClientError::Eof)?;
    Ok(channel.open(&echo, mono.now())?.to_vec())
}

fn no_marker(frames: &[Vec<u8>]) {
    for frame in frames {
        assert!(
            !frame.windows(MARKER.len()).any(|w| w == MARKER.as_bytes()),
            "plaintext on the wire: {}",
            String::from_utf8_lossy(&frame[..frame.len().min(200)])
        );
    }
}

// ----------------------------------------------------------------- proxy

/// What the man in the middle does with the `i`-th frame of a direction:
/// the frames it forwards instead (none: dropped).
type Tamper = Box<dyn FnMut(usize, Vec<u8>) -> Vec<Vec<u8>> + Send>;

fn pass() -> Tamper {
    Box::new(|_, frame| vec![frame])
}

/// Applies `f` to frame `at` only.
fn at(index: usize, mut f: impl FnMut(Vec<u8>) -> Vec<Vec<u8>> + Send + 'static) -> Tamper {
    Box::new(move |i, frame| if i == index { f(frame) } else { vec![frame] })
}

/// The frames that crossed the wire, per direction.
#[derive(Default, Clone)]
struct Tap(Arc<Mutex<Directions>>);

/// Frames forwarded client to host, and host to client.
type Directions = (Vec<Vec<u8>>, Vec<Vec<u8>>);

impl Tap {
    fn c2h(&self) -> Vec<Vec<u8>> {
        self.0.lock().unwrap().0.clone()
    }

    fn h2c(&self) -> Vec<Vec<u8>> {
        self.0.lock().unwrap().1.clone()
    }

    fn all(&self) -> Vec<Vec<u8>> {
        let (a, b) = self.0.lock().unwrap().clone();
        a.into_iter().chain(b).collect()
    }
}

/// client ⇄ proxy ⇄ host over two socketpairs; returns the client's end,
/// the host thread and the tap (what the proxy forwarded).
fn through_proxy(
    host: &HostSide,
    c2h: Tamper,
    h2c: Tamper,
) -> (UnixStream, thread::JoinHandle<Vec<HostEvent>>, Tap) {
    let (client_end, proxy_client) = UnixStream::pair().unwrap();
    let (proxy_host, host_end) = UnixStream::pair().unwrap();
    let host_thread = host.spawn(host_end);
    let tap = Tap::default();
    let relay =
        |mut from: UnixStream, mut to: UnixStream, mut tamper: Tamper, tap: Tap, c2h: bool| {
            thread::spawn(move || {
                let mut i = 0;
                while let Some(frame) = recv(&mut from) {
                    for out in tamper(i, frame) {
                        {
                            let mut t = tap.0.lock().unwrap();
                            if c2h {
                                t.0.push(out.clone())
                            } else {
                                t.1.push(out.clone())
                            }
                        }
                        if !send(&mut to, &out) {
                            break;
                        }
                    }
                    i += 1;
                }
                let _ = to.shutdown(std::net::Shutdown::Write);
            })
        };
    relay(
        proxy_client.try_clone().unwrap(),
        proxy_host.try_clone().unwrap(),
        c2h,
        tap.clone(),
        true,
    );
    relay(proxy_host, proxy_client, h2c, tap.clone(), false);
    (client_end, host_thread, tap)
}

/// Mutates one JSON field of a frame (a bit flipped in its decoded bytes,
/// or a new value).
fn edit(frame: &[u8], f: impl FnOnce(&mut Value)) -> Vec<u8> {
    let mut value = wire::to_value(frame).unwrap();
    f(&mut value);
    value.to_string().into_bytes()
}

fn flip_b64u(value: &mut Value, bit: usize) {
    let mut bytes = b64u_decode(value.as_str().unwrap()).unwrap();
    bytes[bit / 8] ^= 1 << (bit % 8);
    *value = Value::String(b64u(&bytes));
}

fn flip_hex(value: &mut Value) {
    let mut text = value.as_str().unwrap().to_owned().into_bytes();
    text[0] = if text[0] == b'0' { b'1' } else { b'0' };
    *value = Value::String(String::from_utf8(text).unwrap());
}

fn flip_field(frame: &[u8], path: &[&str]) -> Vec<u8> {
    edit(frame, |v| {
        let mut node = v;
        for part in path {
            node = &mut node[*part];
        }
        match node {
            Value::Number(n) => *node = json!(n.as_u64().unwrap() ^ 2),
            Value::String(s) if s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()) => {
                flip_hex(node)
            }
            _ => flip_b64u(node, 3),
        }
    })
}

fn flip_ct(frame: &[u8], byte: usize) -> Vec<u8> {
    edit(frame, |v| flip_b64u(&mut v["ct"], byte * 8))
}

// ------------------------------------------------------------------ tests

/// A phone (P-256 native) over a Unix socketpair (through a passive tap) and
/// a bot (Ed25519 service) over TCP loopback each handshake with the host
/// and exchange several messages both ways, including 1 MiB records.
#[test]
fn a_phone_and_a_bot_talk_to_the_host_over_real_sockets() {
    let world = World::new();
    let mono = Mono::new();
    let host = HostSide::new(&world, world.log_l(), &mono);

    // The phone, through a tap that records every byte on the wire.
    let phone = Device::native(&world, "dev-phone", world.log_l());
    assert_eq!(world.book.public("dev-phone/auth").alg(), Alg::P256);
    let (mut stream, host_thread, tap) = through_proxy(&host, pass(), pass());
    let mut phone_conn = phone.connect(&mut stream, &mono).unwrap();
    assert_eq!(phone_conn.relation, HeadRelation::Same);
    assert!(phone_conn.carriage.entries.is_empty());
    assert_eq!(phone_conn.welcome["data"]["op"], "welcome");
    assert_eq!(phone_conn.welcome["data"]["principal"], "member:dev-phone");
    assert_eq!(
        phone_conn.welcome["data"]["channel_id"],
        phone_conn.channel.channel_id()
    );
    let mut sent = Vec::new();
    for (n, size) in [
        (1, 100),
        (2, 4096),
        (3, MAX_PLAINTEXT),
        (4, 200),
        (5, MAX_PLAINTEXT),
    ] {
        let plain = message(n, size);
        let echo = exchange(&mut phone_conn.channel, &mut stream, &plain, &mono).unwrap();
        assert_eq!(echo, plain, "echo {n}");
        sent.push(plain);
    }
    // One byte over the bound is refused locally; the channel stays open.
    assert_eq!(
        phone_conn
            .channel
            .seal(&message(6, MAX_PLAINTEXT + 1), mono.now()),
        Err(ChannelError::TooLarge)
    );
    let last = message(7, 120);
    assert_eq!(
        exchange(&mut phone_conn.channel, &mut stream, &last, &mono).unwrap(),
        last
    );
    sent.push(last);
    assert_eq!(phone_conn.channel.counters(), (6, 7));
    drop(stream);
    let events = host_thread.join().unwrap();
    let welcomed = events
        .iter()
        .find_map(|e| match e {
            HostEvent::Welcomed {
                principal,
                channel_id,
            } => Some((principal.clone(), channel_id.clone())),
            _ => None,
        })
        .unwrap();
    assert_eq!(welcomed.0, "member:dev-phone");
    assert_eq!(welcomed.1, phone_conn.channel.channel_id());
    let received: Vec<Vec<u8>> = events
        .iter()
        .filter_map(|e| match e {
            HostEvent::Received(p) => Some(p.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(received, sent);
    assert_eq!(events.last(), Some(&HostEvent::Eof));
    // Nothing of the hello or the messages crossed the wire in the clear,
    // and the largest records are within the frame bound.
    no_marker(&tap.all());
    assert!(tap.all().iter().all(|f| f.len() <= MAX_FRAME_BYTES));
    assert!(tap.c2h().iter().any(|f| f.len() > MAX_PLAINTEXT));
    assert!(tap.h2c().iter().any(|f| f.len() > MAX_PLAINTEXT));

    // The bot, over TCP.
    let bot = Device::service(&world, "svc-discord", world.log_l());
    assert_eq!(world.book.public("svc-discord/auth").alg(), Alg::Ed25519);
    let (port, listener) = host.listen_tcp(1);
    let mut tcp = TcpStream::connect(("127.0.0.1", port)).unwrap();
    let mut bot_conn = bot.connect(&mut tcp, &mono).unwrap();
    assert_eq!(bot_conn.welcome["data"]["principal"], "service:svc-discord");
    assert_ne!(
        bot_conn.channel.channel_id(),
        phone_conn.channel.channel_id()
    );
    for (n, size) in [(1, MAX_PLAINTEXT), (2, 100), (3, MAX_PLAINTEXT)] {
        let plain = message(n, size);
        assert_eq!(
            exchange(&mut bot_conn.channel, &mut tcp, &plain, &mono).unwrap(),
            plain
        );
    }
    drop(tcp);
    let events = listener.join().unwrap().remove(0);
    assert!(events.contains(&HostEvent::Welcomed {
        principal: "service:svc-discord".into(),
        channel_id: bot_conn.channel.channel_id().into(),
    }));
    assert_eq!(
        events
            .iter()
            .filter(|e| matches!(e, HostEvent::Received(_)))
            .count(),
        3
    );
}

/// One wire fault: what the client gets and what the host did.
fn run_fault(
    world: &Arc<World>,
    c2h: Tamper,
    h2c: Tamper,
    messages: usize,
) -> (Result<(), ClientError>, Vec<HostEvent>, Tap) {
    let mono = Mono::new();
    let host = HostSide::new(world, world.log_l(), &mono);
    let phone = Device::native(world, "dev-phone", world.log_l());
    let (mut stream, host_thread, tap) = through_proxy(&host, c2h, h2c);
    let result = phone.connect(&mut stream, &mono).and_then(|mut conn| {
        for n in 0..messages {
            let plain = message(n, 100);
            let echo = exchange(&mut conn.channel, &mut stream, &plain, &mono)?;
            assert_eq!(echo, plain);
        }
        Ok(())
    });
    drop(stream);
    let events = host_thread.join().unwrap();
    // Whatever happened, no plaintext crossed the wire.
    no_marker(&tap.all());
    (result, events, tap)
}

fn clear(code: &str) -> Option<Vec<u8>> {
    Some(
        Frame::Error {
            code: code.to_owned(),
        }
        .to_bytes(),
    )
}

fn refused(code: &str) -> HostEvent {
    HostEvent::Refused {
        code: code.into(),
        reply: clear(code),
    }
}

fn bad_host_sig() -> Result<(), ClientError> {
    Err(ClientError::Channel(ChannelError::HandshakeFailed(
        Failure::BadHostSignature,
    )))
}

fn advisory(code: &str) -> Result<(), ClientError> {
    Err(ClientError::Channel(ChannelError::Advisory {
        code: code.into(),
    }))
}

/// Faults in each handshake message, on the wire: each fails with the
/// specified error, the failing side's only output is the specified one,
/// and no plaintext leaks.
#[test]
fn handshake_faults_on_the_wire() {
    let world = World::new();
    // Frame indexes: c2h 0 = init, 1 = finish, 2… = records; h2c 0 =
    // accept, 1 = the first record, 2… = echoes.

    // init: a flipped bit in e_c or n_c makes the host sign another th2: the
    // client refuses sig_h and sends nothing more (the host sees the end of
    // the stream, never a finish).
    for field in ["e", "n"] {
        let (result, events, tap) = run_fault(
            &world,
            at(0, move |f| vec![flip_field(&f, &[field])]),
            pass(),
            1,
        );
        assert_eq!(result, bad_host_sig(), "init.{field}");
        assert!(matches!(
            events[..],
            [HostEvent::Accepted(_), HostEvent::Eof]
        ));
        assert_eq!(tap.c2h().len(), 1, "nothing sent after the bad accept");
    }
    // init: another genesis or trust generation is stale_target, in the
    // clear; the client takes it as advisory.
    for field in [&["genesis_hash"][..], &["host_trust_gen"]] {
        let (result, events, _) = run_fault(
            &world,
            at(0, move |f| vec![flip_field(&f, field)]),
            pass(),
            1,
        );
        assert_eq!(result, advisory("stale_target"), "init.{field:?}");
        assert_eq!(events, vec![refused("stale_target")]);
    }
    // init: truncated is malformed: handshake_failed in the clear.
    let (result, events, _) = run_fault(
        &world,
        at(0, |f| vec![f[..f.len() - 9].to_vec()]),
        pass(),
        1,
    );
    assert_eq!(result, advisory("handshake_failed"));
    assert_eq!(events, vec![refused("handshake_failed")]);
    // init: an all-zero ephemeral (low order) is refused before any HKDF.
    let (result, events, _) = run_fault(
        &world,
        at(0, |f| vec![edit(&f, |v| v["e"] = json!(b64u(&[0u8; 32])))]),
        pass(),
        1,
    );
    assert_eq!(result, advisory("handshake_failed"));
    assert_eq!(events, vec![refused("handshake_failed")]);

    // accept: any rewritten field (the head too) fails sig_h at the client.
    for field in [
        &["e"][..],
        &["n"],
        &["sig"],
        &["head", "seq"],
        &["head", "hash"],
    ] {
        let (result, events, tap) = run_fault(
            &world,
            pass(),
            at(0, move |f| vec![flip_field(&f, field)]),
            1,
        );
        assert_eq!(result, bad_host_sig(), "accept.{field:?}");
        assert!(matches!(
            events[..],
            [HostEvent::Accepted(_), HostEvent::Eof]
        ));
        assert_eq!(tap.c2h().len(), 1);
    }
    // accept: truncated is malformed at the client.
    let (result, _, _) = run_fault(&world, pass(), at(0, |f| vec![f[..20].to_vec()]), 1);
    assert_eq!(
        result,
        Err(ClientError::Channel(ChannelError::HandshakeFailed(
            Failure::Malformed
        )))
    );

    // finish: a flipped ciphertext bit (anywhere: first, middle, tag) fails
    // its tag; the host answers handshake_failed in the clear and the
    // client, waiting for its first record, gets it as advisory.
    for byte in [0, 40, usize::MAX] {
        let (result, events, _) = run_fault(
            &world,
            at(1, move |f| {
                let len = match wire::parse_frame(&f).unwrap() {
                    Frame::Finish { ct } => ct.len(),
                    _ => unreachable!(),
                };
                vec![flip_ct(&f, byte.min(len - 1))]
            }),
            pass(),
            1,
        );
        assert_eq!(result, advisory("handshake_failed"), "finish byte {byte}");
        assert!(
            matches!(&events[..], [HostEvent::Accepted(_), HostEvent::Refused { code, reply }]
            if code == "handshake_failed" && *reply == clear("handshake_failed"))
        );
    }
    // finish: truncated.
    let (result, events, _) = run_fault(
        &world,
        at(1, |f| {
            vec![edit(&f, |v| {
                let ct = b64u_decode(v["ct"].as_str().unwrap()).unwrap();
                v["ct"] = json!(b64u(&ct[..ct.len() - 1]));
            })]
        }),
        pass(),
        1,
    );
    assert_eq!(result, advisory("handshake_failed"));
    assert!(matches!(&events[1], HostEvent::Refused { code, .. } if code == "handshake_failed"));
    // A second init where the finish belongs: busy (one init a second).
    let (result, events, _) = run_fault(
        &world,
        Box::new({
            let mut first = None;
            move |i, f| {
                if i == 0 {
                    first = Some(f.clone());
                }
                if i == 1 {
                    vec![first.clone().unwrap()]
                } else {
                    vec![f]
                }
            }
        }),
        pass(),
        1,
    );
    assert_eq!(result, advisory("busy"));
    assert!(matches!(&events[1], HostEvent::Refused { code, .. } if code == "busy"));
}

/// Faults in records: a flipped bit, truncation, a replay, a reordering
/// and a dropped record close the receiving side without a reply.
#[test]
fn record_faults_on_the_wire() {
    let world = World::new();
    let host_closed = |events: &[HostEvent]| {
        assert!(
            matches!(events.last(), Some(HostEvent::Closed(code)) if code == "record_rejected"),
            "{events:?}"
        );
        // The host sent nothing after the failed record.
        let after = events
            .iter()
            .rposition(|e| matches!(e, HostEvent::Received(_) | HostEvent::Welcomed { .. }))
            .unwrap();
        assert_eq!(after, events.len() - 2);
    };
    // c2h: the first data record (c2h 2) or a later one (c2h 4).
    for index in [2, 4] {
        let (result, events, _) = run_fault(&world, at(index, |f| vec![flip_ct(&f, 5)]), pass(), 3);
        assert_eq!(result, Err(ClientError::Eof), "c2h {index}");
        host_closed(&events);
        // Truncated.
        let (result, events, _) = run_fault(
            &world,
            at(index, |f| vec![f[..f.len() - 3].to_vec()]),
            pass(),
            3,
        );
        assert_eq!(result, Err(ClientError::Eof));
        host_closed(&events);
    }
    // h2c: the welcome (h2c 1) or an echo (h2c 3): the client closes.
    for index in [1, 3] {
        let (result, _, _) = run_fault(&world, pass(), at(index, |f| vec![flip_ct(&f, 0)]), 3);
        assert_eq!(
            result,
            Err(ClientError::Channel(ChannelError::RecordRejected)),
            "h2c {index}"
        );
    }
    // A replayed record (sent twice): the second fails its counter.
    let (result, events, _) = run_fault(&world, at(2, |f| vec![f.clone(), f]), pass(), 2);
    // The client got the echo of the first, then the host closed.
    assert_eq!(result, Err(ClientError::Eof));
    host_closed(&events);
    // A replayed h2c record at the client.
    let (result, _, _) = run_fault(&world, pass(), at(2, |f| vec![f.clone(), f]), 2);
    assert_eq!(
        result,
        Err(ClientError::Channel(ChannelError::RecordRejected))
    );
    // A dropped record (a gap): the next one fails at the host.
    let events = pipelined(&world, at(2, |_| vec![]), 2);
    assert!(!events.iter().any(|e| matches!(e, HostEvent::Received(_))));
    assert!(matches!(events.last(), Some(HostEvent::Closed(c)) if c == "record_rejected"));
    // Reordering: the proxy holds record 0 and sends it after record 1.
    let held = Arc::new(Mutex::new(None));
    let reorder: Tamper = Box::new(move |i, f| match i {
        2 => {
            *held.lock().unwrap() = Some(f);
            vec![]
        }
        3 => vec![f, held.lock().unwrap().take().unwrap()],
        _ => vec![f],
    });
    let events = pipelined(&world, reorder, 2);
    assert!(!events.iter().any(|e| matches!(e, HostEvent::Received(_))));
    assert!(matches!(events.last(), Some(HostEvent::Closed(c)) if c == "record_rejected"));
}

/// Connects, sends `n` records without waiting for echoes, then reads until
/// the host closes; the host's events.
fn pipelined(world: &Arc<World>, c2h: Tamper, n: usize) -> Vec<HostEvent> {
    let mono = Mono::new();
    let host = HostSide::new(world, world.log_l(), &mono);
    let (mut stream, host_thread, tap) = through_proxy(&host, c2h, pass());
    let phone = Device::native(world, "dev-phone", world.log_l());
    let mut conn = phone.connect(&mut stream, &mono).unwrap();
    for i in 0..n {
        let frame = conn.channel.seal(&message(i, 100), mono.now()).unwrap();
        send(&mut stream, &frame);
    }
    // Whatever echoes come, the host ends by closing without a reply.
    while let Some(frame) = recv(&mut stream) {
        conn.channel.open(&frame, mono.now()).unwrap();
    }
    drop(stream);
    let events = host_thread.join().unwrap();
    no_marker(&tap.all());
    events
}

/// Replays across sessions: a recorded `init` gets a fresh `accept` (new
/// ephemeral) and the recorded `finish` then fails its tag; a recorded
/// `accept` fails sig_h in a new client session; nothing is admitted.
#[test]
fn replays_across_sessions_fail() {
    let world = World::new();
    let mono = Mono::new();
    let host = HostSide::new(&world, world.log_l(), &mono);
    let phone = Device::native(&world, "dev-phone", world.log_l());
    let (mut stream, host_thread, tap) = through_proxy(&host, pass(), pass());
    let mut conn = phone.connect(&mut stream, &mono).unwrap();
    exchange(&mut conn.channel, &mut stream, &message(1, 100), &mono).unwrap();
    drop(stream);
    host_thread.join().unwrap();
    let (init, finish, record) = (
        tap.c2h()[0].clone(),
        tap.c2h()[1].clone(),
        tap.c2h()[2].clone(),
    );
    let accept = tap.h2c()[0].clone();

    // The attacker replays init then finish to the host on a new transport.
    let (mut attacker, host_end) = UnixStream::pair().unwrap();
    let host_thread = host.spawn(host_end);
    send(&mut attacker, &init);
    let fresh = recv(&mut attacker).unwrap();
    let (Frame::Accept(a), Frame::Accept(b)) = (
        wire::parse_frame(&accept).unwrap(),
        wire::parse_frame(&fresh).unwrap(),
    ) else {
        panic!("accepts")
    };
    assert_ne!(a.e, b.e, "a fresh ephemeral");
    assert_ne!(a.n, b.n, "a fresh nonce");
    send(&mut attacker, &finish);
    assert_eq!(recv(&mut attacker), clear("handshake_failed"));
    assert_eq!(recv(&mut attacker), None);
    let events = host_thread.join().unwrap();
    assert_eq!(events.last(), Some(&refused("handshake_failed")));
    assert!(
        !events
            .iter()
            .any(|e| matches!(e, HostEvent::Welcomed { .. }))
    );

    // A recorded record has no channel to go to: on a new channel it fails
    // the new keys.
    let (mut stream, host_thread, _) =
        through_proxy(&host, at(2, move |_| vec![record.clone()]), pass());
    let mut conn = phone.connect(&mut stream, &mono).unwrap();
    let frame = conn.channel.seal(&message(2, 100), mono.now()).unwrap();
    send(&mut stream, &frame);
    assert_eq!(recv(&mut stream), None);
    drop(stream);
    let events = host_thread.join().unwrap();
    assert!(matches!(events.last(), Some(HostEvent::Closed(c)) if c == "record_rejected"));

    // The recorded accept answers a new client session: sig_h fails (th2
    // has the new e_c, n_c).
    let (mut stream, host_thread, _) =
        through_proxy(&host, pass(), at(0, move |_| vec![accept.clone()]));
    assert!(matches!(
        phone.connect(&mut stream, &mono),
        Err(ClientError::Channel(ChannelError::HandshakeFailed(
            Failure::BadHostSignature
        )))
    ));
    drop(stream);
    host_thread.join().unwrap();
}

/// The client's chain says host-a was re-keyed (trust generation 2): a host
/// still at generation 1 answers stale_target (advisory; nothing in the
/// client changes), and an accept signed with the old key for generation 2
/// (someone holding the retired key) fails sig_h.
#[test]
fn a_rekeyed_host_is_refused_with_its_old_key() {
    let world = World::new();
    let mono = Mono::new();
    let mut new_keys = SoftwareKeys::new();
    let new_key = new_keys
        .generate(KeyId::new("host-a"), Alg::Ed25519)
        .unwrap();
    let log_l = world.log_l();
    let rekey = world.rekey(&log_l, &new_key);
    let client_log = world.log(
        &["E1", "E2", "E3", "E4", "E5", "E6"],
        std::slice::from_ref(&rekey),
    );
    assert_eq!(client_log.host("host-a").unwrap().host_trust_gen, 2);
    let phone = Device::native(&world, "dev-phone", client_log.clone());

    // The stale host: generation 1, old key.
    let stale = HostSide::new(&world, log_l.clone(), &mono);
    let (mut stream, host_thread, _) = through_proxy(&stale, pass(), pass());
    assert_eq!(
        phone.connect(&mut stream, &mono).err(),
        Some(ClientError::Channel(ChannelError::Advisory {
            code: "stale_target".into()
        }))
    );
    drop(stream);
    assert_eq!(host_thread.join().unwrap(), vec![refused("stale_target")]);
    assert_eq!(phone.log, client_log, "an advisory error changes nothing");

    // Someone with the old key claims generation 2.
    let mut impostor = HostSide::new(&world, log_l.clone(), &mono);
    impostor.host_trust_gen = 2;
    let (mut stream, host_thread, tap) = through_proxy(&impostor, pass(), pass());
    assert_eq!(
        phone.connect(&mut stream, &mono).err(),
        Some(ClientError::Channel(ChannelError::HandshakeFailed(
            Failure::BadHostSignature
        )))
    );
    drop(stream);
    host_thread.join().unwrap();
    assert_eq!(tap.c2h().len(), 1, "the client sent nothing after accept");

    // The re-keyed host itself (new key, generation 2, the client's log).
    let mut rekeyed = HostSide::new(&world, client_log.clone(), &mono);
    rekeyed.host_trust_gen = 2;
    rekeyed.keys = Arc::new(new_keys);
    let (mut stream, host_thread, _) = through_proxy(&rekeyed, pass(), pass());
    let conn = phone.connect(&mut stream, &mono).unwrap();
    assert_eq!(conn.relation, HeadRelation::Same);
    drop(stream);
    host_thread.join().unwrap();

    // A client still at generation 1 is stale to the re-keyed host.
    let old_phone = Device::native(&world, "dev-phone", log_l);
    let (mut stream, host_thread, _) = through_proxy(&rekeyed, pass(), pass());
    assert_eq!(
        old_phone.connect(&mut stream, &mono).err(),
        Some(ClientError::Channel(ChannelError::Advisory {
            code: "stale_target".into()
        }))
    );
    drop(stream);
    host_thread.join().unwrap();
}

/// The host's head relative to the client's (§R9.3 table, §R9.7 step 3):
/// a client behind carries nothing, keeps its log, then fetches from the
/// relay and verifies; a forged suffix never reaches the signed head, and on
/// its next connect the client carries its diverged window. A client ahead
/// carries its suffix, which the host applies (and a removal it carried
/// fences the bot).
#[test]
fn the_host_head_is_verified_and_reconciled_never_adopted() {
    let world = World::new();
    let mono = Mono::new();
    let host = HostSide::new(&world, world.log_l(), &mono);

    // Client behind: E1–E5, host at E6.
    let behind = world.log(&["E1", "E2", "E3", "E4", "E5"], &[]);
    let mut phone = Device::native(&world, "dev-phone", behind.clone());
    let (mut stream, host_thread, _) = through_proxy(&host, pass(), pass());
    let conn = phone.connect(&mut stream, &mono).unwrap();
    assert_eq!(conn.relation, HeadRelation::HostAhead);
    assert!(conn.carriage.entries.is_empty());
    assert_eq!(conn.carriage.fetch_to, Some(world.v.head("E6")));
    assert_eq!(
        conn.welcome["data"]["head"]["hash"],
        world.v.hash("E6").to_hex()
    );
    assert_eq!(phone.log, behind, "the signed head is not adopted");
    drop(stream);
    host_thread.join().unwrap();

    // A relay serving a forged seq 6 (dev-ipad's sibling, valid on E5 but
    // not the host's E6): verified, it doesn't reach the signed head.
    let target = signed_head(&world, &behind).verify(&behind).unwrap();
    let forged = phone
        .log
        .evaluate_objects(&[world.v.object("C6_ipad")], &world.clock.now);
    assert_eq!(forged.stop, None);
    assert!(!target.reached_by(&forged.next));
    phone.log = forged.next;
    // Its next connect: diverged, it carries the window [C6_ipad]; the host
    // ignores the removed signer's sibling and admits the phone.
    let (mut stream, host_thread, _) = through_proxy(&host, pass(), pass());
    let conn = phone.connect(&mut stream, &mono).unwrap();
    assert_eq!(conn.relation, HeadRelation::Diverged);
    assert_eq!(conn.carriage.entries, vec![world.v.object("C6_ipad")]);
    assert_eq!(
        conn.welcome["data"]["head"]["hash"],
        world.v.hash("E6").to_hex()
    );
    drop(stream);
    host_thread.join().unwrap();
    // The honest relay: E6 verifies and reaches the head.
    let honest = behind.evaluate_objects(&[world.v.object("E6")], &world.clock.now);
    assert!(target.reached_by(&honest.next));

    // Client ahead: L + E7 (dev-phone removes svc-discord); host at L.
    let ahead = world.log(&["E1", "E2", "E3", "E4", "E5", "E6", "E7"], &[]);
    let phone = Device::native(&world, "dev-phone", ahead);
    let (mut stream, host_thread, _) = through_proxy(&host, pass(), pass());
    let conn = phone.connect(&mut stream, &mono).unwrap();
    assert_eq!(conn.relation, HeadRelation::HostBehind);
    assert_eq!(conn.carriage.entries, vec![world.v.object("E7")]);
    assert_eq!(
        conn.welcome["data"]["head"]["hash"],
        world.v.hash("E7").to_hex()
    );
    drop(stream);
    host_thread.join().unwrap();
    // The bot, removed by the carried E7, is refused in the channel.
    let bot = Device::service(&world, "svc-discord", world.log_l());
    let (mut stream, host_thread, tap) = through_proxy(&host, pass(), pass());
    let conn = bot.connect(&mut stream, &mono).unwrap();
    assert_eq!(conn.welcome["data"]["op"], "error");
    assert_eq!(conn.welcome["data"]["code"], "unauthorized");
    drop(stream);
    host_thread.join().unwrap();
    // The refusal was a record, not a clear frame.
    assert!(matches!(
        wire::parse_frame(&tap.h2c()[1]).unwrap(),
        Frame::Rec { .. }
    ));
}

/// The head host-a signs for `log`'s client (an `accept` the test verifies
/// with the client's own log).
fn signed_head(world: &World, log: &Membership) -> atem_client::channel::HostAccept {
    let mono = Mono::new();
    let host_log = world.log_l();
    let mut keys = SoftwareKeys::new();
    keys.insert_ed25519(
        KeyId::new("h"),
        &unhex32(
            world.book.keys["host-a"]["host_key"]["secret_hex"]
                .as_str()
                .unwrap(),
        ),
    );
    let ctx = HostContext {
        log: &host_log,
        host_id: "host-a",
        host_trust_gen: 1,
        provider: &keys,
        key: &KeyId::new("h"),
    };
    let (_, init) = Initiator::start(log, "host-a", mono.now()).unwrap();
    let (_, accept) = Responder::on_init(&ctx, &init, mono.now()).unwrap();
    match (
        wire::parse_frame(&init).unwrap(),
        wire::parse_frame(&accept).unwrap(),
    ) {
        (Frame::Init(i), Frame::Accept(a)) => atem_client::channel::HostAccept::new(&i, &a),
        _ => unreachable!(),
    }
}

/// After `finish` opens every refusal is the host's encrypted first record:
/// a bad sig_c (signed with another key, or for another principal) is
/// `handshake_failed` inside the channel.
#[test]
fn a_bad_client_signature_is_refused_inside_the_channel() {
    let world = World::new();
    let mono = Mono::new();
    let host = HostSide::new(&world, world.log_l(), &mono);
    // dev-phone's principal, signed by dev-mac's key.
    let mut thief = Device::native(&world, "dev-phone", world.log_l());
    thief.key = world.book.auth("dev-mac");
    let (mut stream, host_thread, tap) = through_proxy(&host, pass(), pass());
    let conn = thief.connect(&mut stream, &mono).unwrap();
    assert_eq!(conn.welcome["data"]["code"], "handshake_failed");
    drop(stream);
    let events = host_thread.join().unwrap();
    assert!(
        matches!(events.last(), Some(HostEvent::RefusedInChannel { code, .. }) if code == "handshake_failed")
    );
    assert!(matches!(
        wire::parse_frame(&tap.h2c()[1]).unwrap(),
        Frame::Rec { .. }
    ));

    // A hello naming svc-discord with dev-phone's sig_c (the relay can't
    // rewrite it: the hello is sealed; a client that lies fails sig_c).
    let liar = Device {
        principal: Principal::Service {
            device_id: "svc-discord".into(),
        },
        ..Device::native(&world, "dev-phone", world.log_l())
    };
    let (mut stream, host_thread, _) = through_proxy(&host, pass(), pass());
    let conn = liar.connect(&mut stream, &mono).unwrap();
    assert_eq!(conn.welcome["data"]["code"], "handshake_failed");
    drop(stream);
    host_thread.join().unwrap();
}

/// Timeouts, sans-I/O on a fake clock: `accept` and `finish` each within
/// 10 s; the client refuses to send a late `finish`.
#[test]
fn handshake_steps_time_out_after_10_s() {
    let world = World::new();
    let log = world.log_l();
    let ctx = HostContext {
        log: &log,
        host_id: "host-a",
        host_trust_gen: 1,
        provider: &world.book.provider,
        key: &KeyId::new("host-a/host_key"),
    };
    let phone_key = world.book.auth("dev-phone");
    let principal = Principal::Native {
        device_id: "dev-phone".into(),
    };
    // A late accept.
    let (client, init) = Initiator::start(&log, "host-a", 0).unwrap();
    let (_, accept) = Responder::on_init(&ctx, &init, 0).unwrap();
    assert_eq!(client.deadline_ms(), HANDSHAKE_STEP_MS);
    assert_eq!(
        client.on_frame(&accept, &log, HANDSHAKE_STEP_MS + 1).err(),
        Some(ChannelError::HandshakeFailed(Failure::Timeout))
    );
    // A late finish, at the host.
    let (client, init) = Initiator::start(&log, "host-a", 0).unwrap();
    let (host, accept) = Responder::on_init(&ctx, &init, 100).unwrap();
    assert_eq!(host.deadline_ms(), 100 + HANDSHAKE_STEP_MS);
    let signed = client
        .on_frame(&accept, &log, 200)
        .unwrap()
        .sign(principal.clone(), &world.book.provider, &phone_key)
        .unwrap();
    let carriage = Carriage::plan(&log, log.head(), None);
    let hello = Hello::build(&principal, signed.sig_c(), &carriage);
    let (_, finish) = signed.finish(&hello, 300).unwrap();
    let refused = host
        .on_finish(&finish, 100 + HANDSHAKE_STEP_MS + 1)
        .err()
        .unwrap();
    assert_eq!(
        refused.error,
        ChannelError::HandshakeFailed(Failure::Timeout)
    );
    assert_eq!(refused.reply, clear("handshake_failed"));
    // The client itself won't send a finish more than 10 s after accept.
    let (client, init) = Initiator::start(&log, "host-a", 0).unwrap();
    let (_, accept) = Responder::on_init(&ctx, &init, 0).unwrap();
    let signed = client
        .on_frame(&accept, &log, 0)
        .unwrap()
        .sign(principal, &world.book.provider, &phone_key)
        .unwrap();
    assert_eq!(
        signed.finish(&hello, HANDSHAKE_STEP_MS + 1).err(),
        Some(ChannelError::HandshakeFailed(Failure::Timeout))
    );
    // A host that isn't in the client's log: nothing is sent.
    assert_eq!(
        Initiator::start(&log, "host-b", 0).err(),
        Some(ChannelError::UnknownHost)
    );
}

/// A frozen host refuses `init` with a clear, advisory `account_frozen`;
/// a plain session message outside any channel is not a channel frame.
#[test]
fn a_frozen_host_and_a_plain_frame() {
    let world = World::new();
    let mono = Mono::new();
    let log_l = world.log_l();
    let frozen = log_l
        .evaluate_objects(&[world.v.object("C6_mac")], &world.clock.now)
        .next;
    assert!(frozen.frozen().is_some());
    let host = HostSide::new(&world, frozen, &mono);
    let phone = Device::native(&world, "dev-phone", log_l);
    let (mut stream, host_thread, _) = through_proxy(&host, pass(), pass());
    assert_eq!(
        phone.connect(&mut stream, &mono).err(),
        Some(ClientError::Channel(ChannelError::Advisory {
            code: "account_frozen".into()
        }))
    );
    drop(stream);
    assert_eq!(host_thread.join().unwrap(), vec![refused("account_frozen")]);

    let (mut stream, host_end) = UnixStream::pair().unwrap();
    let host_thread = host.spawn(host_end);
    send(
        &mut stream,
        br#"{"type":"session","data":{"v":1,"op":"hello","id":"x","revision":9}}"#,
    );
    drop(stream);
    assert_eq!(host_thread.join().unwrap(), vec![HostEvent::Plain]);
}

/// A flipped bit in every byte of each handshake message (bit `i mod 8` of
/// byte `i`), sans-I/O: never a success, and the failing side's reply (if
/// any) is a clear error frame.
#[test]
fn a_bit_flip_in_every_byte_of_the_handshake_fails() {
    let world = World::new();
    let log = world.log_l();
    let ctx = HostContext {
        log: &log,
        host_id: "host-a",
        host_trust_gen: 1,
        provider: &world.book.provider,
        key: &KeyId::new("host-a/host_key"),
    };
    let key = world.book.auth("dev-phone");
    let principal = Principal::Native {
        device_id: "dev-phone".into(),
    };
    let phone_auth = world.book.public("dev-phone/auth");
    let is_clear = |reply: &Option<Vec<u8>>| {
        reply
            .as_ref()
            .is_none_or(|r| matches!(wire::parse_frame(r), Ok(Frame::Error { .. })))
    };
    let (_, init) = Initiator::start(&log, "host-a", 0).unwrap();
    for bit in (0..init.len()).map(|i| i * 8 + i % 8) {
        let mut bad = init.clone();
        bad[bit / 8] ^= 1 << (bit % 8);
        // The host may answer a flipped init (e.g. in e or n), but the client
        // that sent the original refuses that accept.
        match Responder::on_init(&ctx, &bad, 0) {
            Err(r) => assert!(is_clear(&r.reply)),
            Ok(_) => {
                let parsed = wire::parse_frame(&bad).unwrap();
                let original = wire::parse_frame(&init).unwrap();
                assert_ne!(parsed, original, "bit {bit} changed nothing");
            }
        }
    }
    // Fixed ephemerals (the vectors' constructors), so each flipped run
    // starts from the same messages without signing again.
    let (e_c, n_c, e_h, n_h) = ([0x11; 32], [0x22; 32], [0x33; 32], [0x44; 32]);
    let start = || Initiator::start_with(&log, "host-a", e_c, n_c, 0).unwrap();
    let answer = |init: &[u8]| Responder::on_init_with(&ctx, init, e_h, n_h, 0).unwrap();
    let (client, init) = start();
    let (host, accept) = answer(&init);
    let signed = client
        .on_frame(&accept, &log, 0)
        .unwrap()
        .sign(principal.clone(), &world.book.provider, &key)
        .unwrap();
    let hello = Hello::build(
        &principal,
        signed.sig_c(),
        &Carriage::plan(&log, log.head(), None),
    );
    let (_, finish) = signed.finish(&hello, 0).unwrap();
    let opened = host.on_finish(&finish, 0).unwrap();
    let proof = Hello::parse(opened.hello()).unwrap().proof;
    assert!(
        opened.key(&proof).admit(&phone_auth).is_ok(),
        "unflipped, it works"
    );
    for bit in (0..accept.len()).map(|i| i * 8 + i % 8) {
        let mut bad = accept.clone();
        bad[bit / 8] ^= 1 << (bit % 8);
        let (client, _) = start();
        assert!(client.on_frame(&bad, &log, 0).is_err(), "accept bit {bit}");
    }
    for bit in (0..finish.len()).map(|i| i * 8 + i % 8) {
        let mut bad = finish.clone();
        bad[bit / 8] ^= 1 << (bit % 8);
        let (host, _) = answer(&init);
        let refused = host
            .on_finish(&bad, 0)
            .err()
            .unwrap_or_else(|| panic!("finish bit {bit}"));
        assert!(is_clear(&refused.reply));
    }
}
