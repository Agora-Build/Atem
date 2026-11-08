//! (test-only) Binary `Crypt` frames on the agent socket (agent_frame.rs):
//! agreed per connection in the build check, with v2 JSON lines kept for an
//! agent or a client of another build; round trips and limits; how the agent
//! reads malformed frames; what a framed request leaves behind; and the same
//! refusals as on a JSON line (designs/e2e-encryption.md "Keys on disk
//! (atem)").
use super::client_tests::{Proxy, feed, holds, served_device};
use super::tests::{eventually, make_private, own_uid, short_dir, sock};
use super::*;
use crate::memory::cred_agent::error_of;
use crate::memory::crypto::EncryptionMode;
use crate::memory::fake_astation::{ASTATION_ID, UnlockedDevice};
use std::io::{BufRead, BufReader, Write};

const KID: &str = "0123abcd";

/// A client as `autostart` makes them: it checks the build on every new
/// connection, and with that check agrees to frames.
fn framing_client(socket: &Path) -> CredAgentClient {
    CredAgentClient::at(socket.to_path_buf()).checking_build(build_id())
}

/// Serves `agent` on its own thread, as a released agent when `frames` is
/// false; with `held`, its connections report what they hold once they
/// have answered.
fn serve_on_thread(
    socket: &Path,
    agent: Arc<Mutex<CredAgent>>,
    frames: bool,
    held: Option<HeldLog>,
) {
    let (ready, started) = std::sync::mpsc::channel();
    let path = socket.to_path_buf();
    std::thread::spawn(move || {
        SETTLED.with(|settled| *settled.borrow_mut() = held);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async move {
            let listener = bind(&path).unwrap();
            ready.send(()).unwrap();
            let _ = if frames {
                serve(listener, agent, own_uid()).await
            } else {
                serve_without_frames(listener, agent, own_uid()).await
            };
        });
    });
    started.recv().unwrap();
}

/// A verified device whose agent holds `K` (mode on).
fn device_with_key(dir: &Path) -> UnlockedDevice {
    let mut device = UnlockedDevice::new(&dir.join("device"));
    device.set_key(EncryptionMode::On, KID, [7; 32]);
    device
}

/// A seal, an open, keyed hashes (current and named kid), and empty fields.
fn mixed_ops(sealed: &str) -> Vec<CryptOp> {
    vec![
        CryptOp::seal("mem-1", "content", b"a fact \x00\xff"),
        CryptOp::open("mem-1", "content", sealed),
        CryptOp::keyed_hash(b"github.com/agora/atem"),
        CryptOp::keyed_hash_under(b"github.com/agora/atem", KID),
        CryptOp::seal("mem-2", "content", b""),
        CryptOp::open("mem-2", "content", ""),
        CryptOp::keyed_hash(b""),
    ]
}

/// What a result says, the same however it travelled: a seal opened again
/// in process (seals are randomized), opened bytes, a hash.
fn reading(device: &UnlockedDevice, record: &str, result: CryptOut) -> Vec<u8> {
    match result {
        CryptOut::Sealed(text) if text.is_empty() => b"sealed:".to_vec(),
        CryptOut::Sealed(text) => {
            let opened = device
                .agent
                .crypt(ASTATION_ID, vec![CryptOp::open(record, "content", &text)])
                .unwrap()
                .remove(0)
                .into_plain()
                .unwrap();
            [&b"sealed:"[..], &opened].concat()
        }
        CryptOut::Opened(plain) => [&b"opened:"[..], &plain].concat(),
        CryptOut::Hashed(text) => text.into_bytes(),
    }
}

fn readings(device: &UnlockedDevice, results: Vec<CryptOut>) -> Vec<Vec<u8>> {
    let records = ["mem-1", "mem-1", "", "", "mem-2", "mem-2", ""];
    records
        .iter()
        .zip(results)
        .map(|(record, result)| reading(device, record, result))
        .collect()
}

#[test]
fn a_client_that_checks_the_build_sends_crypt_as_frames_with_the_same_results() {
    let dir = short_dir();
    let (device, socket) = served_device(dir.path());
    let proxy = Proxy::start(dir.path(), socket);
    let sealed = device
        .agent
        .crypt(
            ASTATION_ID,
            vec![CryptOp::seal("mem-1", "content", b"an older fact")],
        )
        .unwrap()
        .remove(0)
        .into_text()
        .unwrap();
    let framed = framing_client(&proxy.socket);
    // No build check: no agreement, JSON lines.
    let lines = CredAgentClient::at(proxy.socket.clone());
    let by_frame = framed.crypt(ASTATION_ID, mixed_ops(&sealed)).unwrap();
    let by_line = lines.crypt(ASTATION_ID, mixed_ops(&sealed)).unwrap();
    assert_eq!(framed.traffic().frames(), 1);
    assert_eq!(lines.traffic().frames(), 0);
    assert_eq!(proxy.frames(), 1, "{:?}", proxy.seen());
    let in_process = device.agent.crypt(ASTATION_ID, mixed_ops(&sealed)).unwrap();
    let expected = readings(&device, in_process);
    assert_eq!(&expected[0], b"sealed:a fact \x00\xff");
    assert_eq!(&expected[1], b"opened:an older fact");
    assert!(expected[2].starts_with(b"h1.0123abcd."));
    assert_eq!(expected[2], expected[3], "the current kid, named");
    assert_eq!(&expected[4], b"sealed:");
    assert_eq!(&expected[5], b"opened:");
    assert_eq!(readings(&device, by_frame), expected);
    assert_eq!(readings(&device, by_line), expected);
    // Frames go on the connection the build check agreed on.
    assert_eq!(framed.traffic().connections(), 1);
    assert_eq!(framed.traffic().probes(), 1);
}

#[test]
fn frames_carry_the_largest_batches_and_bigger_ones_go_as_lines() {
    let dir = short_dir();
    let (device, socket) = served_device(dir.path());
    let proxy = Proxy::start(dir.path(), socket);
    let client = framing_client(&proxy.socket);
    let hashes = |count: usize| -> Vec<CryptOp> {
        (0..count)
            .map(|n| CryptOp::keyed_hash(format!("project-{n}").as_bytes()))
            .collect()
    };
    // 1,024 ops: one frame.
    let results = client.crypt(ASTATION_ID, hashes(1024)).unwrap();
    assert_eq!(results.len(), 1024);
    assert_eq!(client.traffic().frames(), 1);
    // 1,025 ops, or two fields over 2 MiB together: JSON lines, answered
    // all the same.
    assert_eq!(client.crypt(ASTATION_ID, hashes(1025)).unwrap().len(), 1025);
    let half = vec![b'h'; (1 << 20) + 1];
    let pair = vec![CryptOp::keyed_hash(&half), CryptOp::keyed_hash(&half)];
    let pair = client.crypt(ASTATION_ID, pair).unwrap();
    assert_eq!(text_of(&pair[0]), text_of(&pair[1]));
    assert_eq!(client.traffic().frames(), 1);
    // One field alone may be bigger than 2 MiB: a frame each way.
    let big: Vec<u8> = (0..(2 << 20) + 7).map(|n| (n % 251) as u8).collect();
    let sealed = client
        .crypt(ASTATION_ID, vec![CryptOp::seal("v-1", "content", &big)])
        .unwrap()
        .remove(0)
        .into_text()
        .unwrap();
    let opened = client
        .crypt(ASTATION_ID, vec![CryptOp::open("v-1", "content", &sealed)])
        .unwrap()
        .remove(0)
        .into_plain()
        .unwrap();
    assert!(opened[..] == big[..]);
    assert_eq!(client.traffic().frames(), 3);
    assert_eq!(proxy.frames(), 3);
    assert_eq!(Proxy::count(&proxy.seen(), "crypt"), 5);
    drop(device);
}

/// The largest reply to a request within the bounds: one seal whose frame
/// body is exactly 6 MiB (the most one op may carry) comes back as an `e1.`
/// text of about 8 MiB, which the client reads through its reply check
/// (`agent_frame::reply_head`) as a frame.
#[test]
fn the_largest_seal_reply_passes_the_reply_check() {
    let dir = short_dir();
    let (device, socket) = served_device(dir.path());
    let proxy = Proxy::start(dir.path(), socket);
    let client = framing_client(&proxy.socket);
    // The body: the astation id, then the op's tag and its three fields,
    // each field with a 4-byte length.
    let plain = (6 << 20) - (4 + ASTATION_ID.len() + 1 + (4 + 1) + (4 + 1) + 4);
    let op = CryptOp::seal("r", "f", &vec![7; plain]);
    let request = agent_frame::crypt_request(ASTATION_ID, std::slice::from_ref(&op)).unwrap();
    assert_eq!(request.len() - agent_frame::HEADER, 6 << 20);
    let sealed = client
        .crypt(ASTATION_ID, vec![op])
        .unwrap()
        .remove(0)
        .into_text()
        .unwrap();
    assert_eq!(sealed.len(), crate::memory::account_keys::sealed_len(plain));
    assert!(sealed.len() > (8 << 20) - (1 << 10), "{}", sealed.len());
    assert!(sealed.starts_with(&format!("e1.{KID}.")));
    assert_eq!((client.traffic().frames(), proxy.frames()), (1, 1));
    drop(device);
}

/// A seal's or hash's text.
fn text_of(result: &CryptOut) -> &str {
    match result {
        CryptOut::Sealed(text) | CryptOut::Hashed(text) => text,
        CryptOut::Opened(_) => panic!("an open"),
    }
}

#[test]
fn a_client_keeps_json_lines_with_an_agent_that_offers_no_frames() {
    // A released agent (v0.6.11 to v0.8.3), modelled by this one with frames
    // off: its `status` has no `frames`, the same answer a released agent
    // gives to the same build check, and it reads only JSON lines.
    let dir = short_dir();
    let device = device_with_key(dir.path());
    let socket = sock(&dir.path().join("run"));
    serve_on_thread(&socket, device.agent.clone(), false, None);
    let mut raw = UnixStream::connect(&socket).unwrap();
    raw.write_all(b"{\"op\":\"status\",\"v\":2}\n").unwrap();
    let mut line = String::new();
    BufReader::new(&raw).read_line(&mut line).unwrap();
    assert!(!line.contains("frames"), "{line}");
    let proxy = Proxy::start(dir.path(), socket);
    let client = framing_client(&proxy.socket);
    let sealed = client
        .crypt(ASTATION_ID, vec![CryptOp::seal("r", "content", b"plain")])
        .unwrap()
        .remove(0)
        .into_text()
        .unwrap();
    let opened = client
        .crypt(ASTATION_ID, vec![CryptOp::open("r", "content", &sealed)])
        .unwrap()
        .remove(0)
        .into_plain()
        .unwrap();
    assert_eq!(&opened[..], b"plain");
    assert_eq!(client.traffic().frames(), 0);
    assert_eq!(proxy.frames(), 0);
    assert_eq!(proxy.seen(), ["status", "crypt", "crypt"]);
    assert_eq!(client.traffic().connections(), 1);
}

/// v0.8.3's `Reply`, as a released client reads a `status` answer.
#[derive(serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum ReleasedReply {
    Status {
        unlocked: bool,
        #[allow(dead_code)]
        storage_kid: Option<String>,
        #[allow(dead_code)]
        escrowed: bool,
        build: String,
    },
}

#[derive(serde::Deserialize)]
struct ReleasedResponse {
    ok: bool,
    reply: Option<ReleasedReply>,
}

/// Writes `line` on `stream` and reads one line back, as JSON.
fn line_round_trip(stream: &UnixStream, line: &str) -> serde_json::Value {
    (&*stream).write_all(line.as_bytes()).unwrap();
    let mut reply = String::new();
    BufReader::new(stream).read_line(&mut reply).unwrap();
    serde_json::from_str(&reply).unwrap()
}

#[test]
fn a_released_client_gets_json_lines_from_this_agent() {
    use base64::{Engine, engine::general_purpose::STANDARD};
    let dir = short_dir();
    let (_device, socket) = served_device(dir.path());
    let stream = UnixStream::connect(&socket).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    // Its build check: the answer offers frames, and a released client's
    // `Reply` reads it all the same (unknown fields are skipped).
    let status = line_round_trip(&stream, "{\"op\":\"status\",\"v\":2}\n");
    assert_eq!(status["reply"]["frames"], 1, "{status}");
    let released: ReleasedResponse = serde_json::from_value(status).unwrap();
    let Some(ReleasedReply::Status {
        unlocked, build, ..
    }) = released.reply
    else {
        panic!("a status");
    };
    assert!(released.ok && unlocked);
    assert_eq!(build, build_id());
    // It never sends a frame: its `Crypt` lines are answered as lines, on
    // the same connection.
    let seal = serde_json::json!({
        "op": "crypt", "astation_id": ASTATION_ID, "v": 2,
        "ops": [{"seal": {"record": "r", "field": "f", "plain": STANDARD.encode("old client")}}],
    });
    let sealed = line_round_trip(&stream, &format!("{seal}\n"));
    let sealed = sealed["reply"]["results"][0]["sealed"].as_str().unwrap();
    assert!(sealed.starts_with("e1.0123abcd."), "{sealed}");
    let open = serde_json::json!({
        "op": "crypt", "astation_id": ASTATION_ID, "v": 2,
        "ops": [{"open": {"record": "r", "field": "f", "value": sealed}}],
    });
    let opened = line_round_trip(&stream, &format!("{open}\n"));
    assert_eq!(
        opened["reply"]["results"][0]["opened"],
        STANDARD.encode("old client"),
        "{opened}"
    );
    // A client that checks no build never agrees, so never sends a frame.
    let client = CredAgentClient::at(socket.clone());
    client
        .crypt(ASTATION_ID, vec![CryptOp::keyed_hash(b"x")])
        .unwrap();
    assert_eq!(client.traffic().frames(), 0);
}

#[test]
fn a_frame_on_a_connection_that_never_agreed_is_read_as_a_line() {
    let dir = short_dir();
    let (_device, socket) = served_device(dir.path());
    let stream = UnixStream::connect(&socket).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut frame =
        agent_frame::crypt_request(ASTATION_ID, &[CryptOp::keyed_hash(b"x")]).unwrap()[..].to_vec();
    frame.push(b'\n');
    (&stream).write_all(&frame).unwrap();
    let mut reply = String::new();
    BufReader::new(&stream).read_line(&mut reply).unwrap();
    let reply: serde_json::Value = serde_json::from_str(&reply).unwrap();
    assert_eq!(reply["ok"], false, "{reply}");
    assert!(
        reply["error"].as_str().unwrap().contains("not JSON"),
        "{reply}"
    );
}

/// A connection on which a `status` agreed to frames.
fn agreed(socket: &Path) -> UnixStream {
    let stream = UnixStream::connect(socket).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let status = line_round_trip(&stream, "{\"op\":\"status\",\"v\":2}\n");
    assert_eq!(status["reply"]["frames"], 1, "{status}");
    stream
}

/// Whether the agent closed `stream` without answering.
fn closed_unanswered(mut stream: &UnixStream) -> bool {
    let mut byte = [0u8; 1];
    match stream.read(&mut byte) {
        Ok(0) => true,
        Ok(_) => false,
        Err(error) => error.kind() == std::io::ErrorKind::ConnectionReset,
    }
}

/// `frame` with its header's count and body length set.
fn with_head(mut frame: Vec<u8>, count: u32, len: u32) -> Vec<u8> {
    frame[2..6].copy_from_slice(&count.to_le_bytes());
    frame[6..10].copy_from_slice(&len.to_le_bytes());
    frame
}

#[test]
fn a_malformed_or_truncated_frame_closes_the_connection_and_the_agent_goes_on() {
    let dir = short_dir();
    let (_device, socket) = served_device(dir.path());
    let valid = agent_frame::crypt_request(
        ASTATION_ID,
        &[
            CryptOp::seal("r", "f", b"SECRET"),
            CryptOp::keyed_hash(b"x"),
        ],
    )
    .unwrap()[..]
        .to_vec();
    let len = (valid.len() - agent_frame::HEADER) as u32;
    // Cut at every byte: the agent never answers, and closes once the
    // client is done writing.
    for cut in 0..valid.len() {
        let stream = agreed(&socket);
        (&stream).write_all(&valid[..cut]).unwrap();
        stream.shutdown(std::net::Shutdown::Write).unwrap();
        assert!(closed_unanswered(&stream), "cut at {cut}");
    }
    // Headers out of bounds close it at once, before any body is read or
    // allocated: the client keeps its side open and sends no body.
    let header = |kind: u8, count: u32, len: u32| {
        let mut frame = with_head(valid[..agent_frame::HEADER].to_vec(), count, len);
        frame[1] = kind;
        frame
    };
    for (what, bytes) in [
        ("unknown kind", header(9, 2, len)),
        ("zero ops", header(agent_frame::REQUEST_CRYPT, 0, len)),
        ("1,025 ops", header(agent_frame::REQUEST_CRYPT, 1025, len)),
        (
            "over 2 MiB",
            header(agent_frame::REQUEST_CRYPT, 2, (2 << 20) + 1),
        ),
        (
            "one op over 6 MiB",
            header(agent_frame::REQUEST_CRYPT, 1, (6 << 20) + 1),
        ),
        ("4 GiB", header(agent_frame::REQUEST_CRYPT, 1, u32::MAX)),
    ] {
        let stream = agreed(&socket);
        (&stream).write_all(&bytes).unwrap();
        assert!(closed_unanswered(&stream), "{what}");
    }
    // Bodies that don't read: a count over the ops it holds, a byte past its
    // last field, a field longer than what is left, an unknown op.
    let mut trailing = with_head(valid.clone(), 2, len + 1);
    trailing.push(0);
    let mut long_field = valid.clone();
    long_field[agent_frame::HEADER..agent_frame::HEADER + 4]
        .copy_from_slice(&u32::MAX.to_le_bytes());
    let mut unknown_op = valid.clone();
    let tag_at = agent_frame::HEADER + 4 + ASTATION_ID.len();
    unknown_op[tag_at] = 77;
    for (what, bytes) in [
        ("count over its ops", with_head(valid.clone(), 3, len)),
        ("a byte past the end", trailing),
        ("a field past the end", long_field),
        ("an unknown op", unknown_op),
    ] {
        let stream = agreed(&socket);
        (&stream).write_all(&bytes).unwrap();
        assert!(closed_unanswered(&stream), "{what}");
    }
    // The agent still serves, frames included.
    let client = framing_client(&socket);
    let results = client
        .crypt(ASTATION_ID, vec![CryptOp::keyed_hash(b"x")])
        .unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(client.traffic().frames(), 1);
}

#[test]
fn a_frame_is_read_whole_however_it_arrives_and_leaves_nothing_behind() {
    let frame = agent_frame::crypt_request(
        ASTATION_ID,
        &[CryptOp::seal(
            "r",
            "f",
            &[b"SECRET-PLAIN-TEXT".as_slice(); 400].concat(),
        )],
    )
    .unwrap();
    for piece in [1usize, 7, 4096, frame.len()] {
        let mut lines = Lines::new();
        lines.frames = true;
        let mut got = None;
        for part in frame.chunks(piece) {
            assert!(got.is_none(), "whole before its end");
            feed(&mut lines, part);
            got = lines.next_message().unwrap();
        }
        let Some(Message::Frame(head, body)) = got else {
            panic!("a frame");
        };
        assert_eq!(head.len, frame.len() - agent_frame::HEADER);
        assert!(body[..] == frame[agent_frame::HEADER..]);
        // Answered: the body goes with its answer (wiped), the rest is
        // wiped by `settle`.
        drop(body);
        lines.settle();
        let retained = lines.held();
        assert!(!holds(&retained, b"SECRET"), "pieces of {piece}");
        assert!(retained.iter().all(|byte| *byte == 0), "pieces of {piece}");
    }
}

#[test]
fn a_frame_and_the_line_after_it_are_read_apart() {
    let frame = agent_frame::crypt_request(ASTATION_ID, &[CryptOp::keyed_hash(b"x")]).unwrap();
    let mut lines = Lines::new();
    lines.frames = true;
    feed(
        &mut lines,
        &[&frame[..], b"{\"op\":\"status\",\"v\":2}\n"].concat(),
    );
    assert!(matches!(
        lines.next_message().unwrap(),
        Some(Message::Frame(..))
    ));
    let Some(Message::Line(line)) = lines.next_message().unwrap() else {
        panic!("a line");
    };
    assert_eq!(&line[..], b"{\"op\":\"status\",\"v\":2}\n");
    assert!(lines.next_message().unwrap().is_none());
}

#[test]
fn a_frame_header_out_of_bounds_is_refused_before_its_body_is_allocated() {
    let frame = agent_frame::crypt_request(ASTATION_ID, &[CryptOp::keyed_hash(b"x")]).unwrap();
    let mut lines = Lines::new();
    lines.frames = true;
    feed(&mut lines, &with_head(frame[..].to_vec(), 1, (6 << 20) + 1));
    assert!(lines.next_message().is_err());
    assert!(lines.frame.is_none(), "nothing allocated for it");
    // Before the agreement the same bytes are part of a line.
    let mut lines = Lines::new();
    feed(&mut lines, &[&frame[..], b"\n"].concat());
    assert!(matches!(
        lines.next_message().unwrap(),
        Some(Message::Line(_))
    ));
}

#[test]
fn the_agent_wipes_what_a_framed_request_left_once_it_has_answered() {
    let dir = short_dir();
    // A locked agent refuses it; an unlocked one answers it.
    let locked = Arc::new(Mutex::new(
        CredAgent::new(CredPaths::in_dir(&dir.path().join("locked"))).unwrap(),
    ));
    let unlocked = device_with_key(dir.path()).agent;
    for (name, agent) in [("locked", locked), ("unlocked", unlocked)] {
        let socket = sock(&dir.path().join(name));
        make_private(socket.parent().unwrap());
        let held = HeldLog::default();
        serve_on_thread(&socket, agent, true, Some(held.clone()));
        let client = framing_client(&socket);
        let secret = b"SECRET-PLAIN-TEXT";
        let result = client.crypt(
            ASTATION_ID,
            vec![CryptOp::seal("r", "f", secret), CryptOp::keyed_hash(secret)],
        );
        if name == "locked" {
            let error = error_of(result);
            assert!(error.contains(crate::memory::cred_agent::LOCKED), "{error}");
        } else {
            assert_eq!(result.unwrap().len(), 2);
        }
        assert_eq!(client.traffic().frames(), 1, "{name}");
        assert!(eventually(|| held.lock().unwrap().len() >= 2), "{name}");
        for bytes in held.lock().unwrap().iter() {
            assert!(
                !holds(bytes, secret),
                "{name}: {}",
                String::from_utf8_lossy(bytes)
            );
            assert!(bytes.iter().all(|byte| *byte == 0), "{name}");
        }
        // The client keeps the connection, with nothing unread on it.
        assert_eq!(client.kept_unread(), Some(0), "{name}");
    }
}

#[test]
fn a_framed_crypt_dropped_unanswered_goes_once_more_as_a_frame() {
    let dir = short_dir();
    let (_device, socket) = served_device(dir.path());
    let proxy = Proxy::start(dir.path(), socket);
    let client = framing_client(&proxy.socket);
    let hash = || vec![CryptOp::keyed_hash(b"x")];
    let first = client.crypt(ASTATION_ID, hash()).unwrap();
    proxy.swallow_ops("crypt", 1);
    let again = client.crypt(ASTATION_ID, hash()).unwrap();
    assert_eq!(text_of(&first[0]), text_of(&again[0]));
    // The new connection was checked (and agreed again), a status proved
    // it before the resend, which went as a frame; the agent got it once.
    assert_eq!(
        proxy.seen(),
        ["status", "crypt", "crypt", "status", "status", "crypt"]
    );
    assert_eq!(Proxy::count(&proxy.passed(), "crypt"), 2);
    assert_eq!(client.traffic().frames(), 3);
    assert_eq!(proxy.frames(), 3);
}

#[test]
fn every_refusal_over_a_frame_is_the_one_a_json_line_gets() {
    let dir = short_dir();
    let mut device = device_with_key(dir.path());
    let socket = sock(&dir.path().join("run"));
    serve_on_thread(&socket, device.agent.clone(), true, None);
    let framed = framing_client(&socket);
    let lines = CredAgentClient::at(socket.clone());
    let mut frames = 0;
    let mut same = |what: &str, astation: &str, ops: &dyn Fn() -> Vec<CryptOp>, expected: &str| {
        let by_frame = error_of(framed.crypt(astation, ops()));
        frames += 1;
        assert_eq!(framed.traffic().frames(), frames, "{what}: went as a frame");
        let by_line = error_of(lines.crypt(astation, ops()));
        assert_eq!(by_frame, by_line, "{what}");
        assert!(by_frame.contains(expected), "{what}: {by_frame}");
    };
    let seal = || vec![CryptOp::seal("r", "f", b"plain")];
    same(
        "unverified Astation",
        "astation-unknown",
        &seal,
        "isn't verified with Astation astation-unknown",
    );
    same(
        "a kid it doesn't hold",
        ASTATION_ID,
        &|| vec![CryptOp::keyed_hash_under(b"x", "89abcdef")],
        crate::memory::account_keys::NOT_RETAINED,
    );
    device.state(EncryptionMode::On, Some("89abcdef"));
    same(
        "a signed state naming another kid",
        ASTATION_ID,
        &seal,
        crate::memory::account_keys::MISSING_KEY,
    );
    device.state(EncryptionMode::Off, None);
    same(
        "encryption off",
        ASTATION_ID,
        &seal,
        crate::memory::account_keys::ENCRYPTION_OFF,
    );
    device.state(EncryptionMode::On, Some(KID));
    let mut store: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&device.paths.trust).unwrap()).unwrap();
    store["astations"][ASTATION_ID]["account_state"]["statement"] = "not base64!".into();
    std::fs::write(&device.paths.trust, serde_json::to_vec(&store).unwrap()).unwrap();
    same(
        "a stored state that doesn't decode",
        ASTATION_ID,
        &seal,
        "not base64",
    );
    device.agent.lock_keys().unwrap();
    same(
        "a locked agent",
        ASTATION_ID,
        &seal,
        crate::memory::cred_agent::LOCKED,
    );
    // No signed state at all.
    let fresh = UnlockedDevice::new(&dir.path().join("fresh"));
    let socket = sock(&dir.path().join("fresh-run"));
    serve_on_thread(&socket, fresh.agent.clone(), true, None);
    let framed = framing_client(&socket);
    let by_frame = error_of(framed.crypt(ASTATION_ID, seal()));
    assert_eq!(framed.traffic().frames(), 1);
    let by_line = error_of(CredAgentClient::at(socket).crypt(ASTATION_ID, seal()));
    assert_eq!(by_frame, by_line);
    assert!(by_frame.contains("signed encryption state"), "{by_frame}");
}

/// `atem cred-agent` with only HOME, XDG_RUNTIME_DIR and PATH (temp dirs).
fn real_agent_process(home: &Path, run: &Path, log: &Path) -> super::tests::Reaped {
    let log = std::fs::File::create(log).unwrap();
    super::tests::Reaped(
        std::process::Command::new(super::tests::atem_binary())
            .arg("cred-agent")
            .env_clear()
            .env("HOME", home)
            .env("XDG_RUNTIME_DIR", run)
            .env("PATH", "/usr/bin:/bin")
            .stdin(std::process::Stdio::null())
            .stdout(log.try_clone().unwrap())
            .stderr(log)
            .spawn()
            .unwrap(),
    )
}

#[test]
fn the_real_agent_seals_opens_and_hashes_over_frames() {
    use crate::memory::device_keys::DeviceKeys;
    use crate::memory::fake_astation::{ACCOUNT, DEVICE_ID, pin, set_state};
    use crate::memory::statements::FakeAstation;
    let dir = short_dir();
    let (home, run) = (dir.path().join("h"), dir.path().join("r"));
    std::fs::create_dir_all(&home).unwrap();
    make_private(&run);
    let paths = CredPaths::in_dir(&home.join(".config").join("atem"));
    crate::paths::create_private_dir(&paths.dir).unwrap();
    // A fresh verified device: its agent starts unlocked from the plain
    // `device_keys` file.
    let keys = DeviceKeys::generate();
    keys.save_to(&paths.device_keys).unwrap();
    let astation = FakeAstation::new();
    pin(&paths, &astation, &keys, false);
    set_state(&paths, &astation, EncryptionMode::On, Some(KID), 2);
    let _agent = real_agent_process(&home, &run, &dir.path().join("agent.log"));
    let lines = CredAgentClient::for_paths(&paths, Some(run.clone().into_os_string()), None);
    assert!(eventually(|| lines
        .status()
        .is_ok_and(|status| status.unlocked)));
    let grant = crate::memory::grant::seal_k_grant(
        &astation,
        ACCOUNT,
        DEVICE_ID,
        keys.device_pub(),
        KID,
        [7; 32],
    );
    lines.install_grant(ASTATION_ID, &grant).unwrap();
    let build = lines.status().unwrap().build;
    let framed =
        CredAgentClient::for_paths(&paths, Some(run.into_os_string()), None).checking_build(&build);
    let sealed = framed
        .crypt(
            ASTATION_ID,
            vec![CryptOp::seal("r", "f", b"real \x00 agent")],
        )
        .unwrap()
        .remove(0)
        .into_text()
        .unwrap();
    let by_frame = framed
        .crypt(
            ASTATION_ID,
            vec![
                CryptOp::open("r", "f", &sealed),
                CryptOp::keyed_hash(b"github.com/agora/atem"),
            ],
        )
        .unwrap();
    let by_line = lines
        .crypt(
            ASTATION_ID,
            vec![
                CryptOp::open("r", "f", &sealed),
                CryptOp::keyed_hash(b"github.com/agora/atem"),
            ],
        )
        .unwrap();
    assert_eq!(framed.traffic().frames(), 2);
    assert_eq!(lines.traffic().frames(), 0);
    let read = |results: Vec<CryptOut>| {
        let mut results = results.into_iter();
        (
            results.next().unwrap().into_plain().unwrap().to_vec(),
            results.next().unwrap().into_text().unwrap(),
        )
    };
    let (plain, hash) = read(by_frame);
    assert_eq!(plain, b"real \x00 agent");
    assert_eq!((plain, hash), read(by_line));
}

/// An agent that agrees to frames in its `status` and answers every `Crypt`
/// frame with `reply` (closing the connection after it when `close`); the
/// number of frames it read.
fn start_frame_scripted_agent(
    dir: &Path,
    reply: Vec<u8>,
    close: bool,
) -> (PathBuf, Arc<std::sync::atomic::AtomicUsize>) {
    use super::client_tests::read_message;
    let socket = sock(&dir.join("run"));
    make_private(socket.parent().unwrap());
    let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
    let status = format!(
        r#"{{"v":2,"ok":true,"reply":{{"kind":"status","unlocked":true,"storage_kid":"0a1b2c3d","escrowed":true,"build":"{}","frames":1}}}}"#,
        build_id()
    );
    let frames = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let read = frames.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { return };
            let mut requests = BufReader::new(&stream);
            while let Some((_, framed)) = read_message(&mut requests) {
                if !framed {
                    let _ = (&stream).write_all(format!("{status}\n").as_bytes());
                    continue;
                }
                read.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let _ = (&stream).write_all(&reply);
                if close {
                    break;
                }
            }
        }
    });
    (socket, frames)
}

#[test]
fn a_reply_frame_that_does_not_read_is_an_error_and_its_connection_goes() {
    let header = |kind: u8, count: u32, len: u32| {
        let mut head = vec![agent_frame::MAGIC, kind];
        head.extend_from_slice(&count.to_le_bytes());
        head.extend_from_slice(&len.to_le_bytes());
        head
    };
    let results = agent_frame::crypted_reply(&[CryptOut::Hashed("h1.x".into())])[..].to_vec();
    let mut bad_tag = results.clone();
    bad_tag[agent_frame::HEADER] = 9;
    for (what, reply, expected) in [
        ("an unknown kind", header(7, 1, 0), "unreadable reply"),
        (
            "another count",
            header(agent_frame::REPLY_CRYPTED, 2, 0),
            "unreadable reply",
        ),
        (
            "over the bound",
            header(agent_frame::REPLY_CRYPTED, 1, (12 << 20) + 1),
            "unreadable reply",
        ),
        ("a result of unknown kind", bad_tag, "unreadable reply"),
        (
            "a JSON body that isn't UTF-8",
            [header(agent_frame::REPLY_JSON, 0, 1), vec![0xFF]].concat(),
            "unreadable reply",
        ),
    ] {
        let dir = short_dir();
        let (socket, frames) = start_frame_scripted_agent(dir.path(), reply, false);
        let client = framing_client(&socket);
        let error = error_of(client.crypt(ASTATION_ID, vec![CryptOp::keyed_hash(b"x")]));
        assert!(error.contains(expected), "{what}: {error}");
        assert_eq!(client.kept_unread(), None, "{what}: the connection went");
        assert_eq!(
            frames.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "{what}"
        );
    }
    // Cut short after its first byte: an error, never sent again (the
    // agent began to answer).
    let dir = short_dir();
    let cut = header(agent_frame::REPLY_CRYPTED, 1, 100)[..4].to_vec();
    let (socket, frames) = start_frame_scripted_agent(dir.path(), cut, true);
    let client = framing_client(&socket);
    let error = error_of(client.crypt(ASTATION_ID, vec![CryptOp::keyed_hash(b"x")]));
    assert!(error.contains("closed the connection"), "{error}");
    assert_eq!(frames.load(std::sync::atomic::Ordering::SeqCst), 1);
    // A refusal frame reads as the refusal, and the connection stays.
    let dir = short_dir();
    let refusal =
        agent_frame::json_reply(br#"{"v":2,"ok":false,"error":"no thanks"}"#)[..].to_vec();
    let (socket, _) = start_frame_scripted_agent(dir.path(), refusal, false);
    let client = framing_client(&socket);
    let error = error_of(client.crypt(ASTATION_ID, vec![CryptOp::keyed_hash(b"x")]));
    assert_eq!(error, "no thanks");
    assert_eq!(client.kept_unread(), Some(0));
}
