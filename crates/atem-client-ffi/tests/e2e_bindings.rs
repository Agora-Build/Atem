//! Binding-level end to end: a Kotlin "phone" (UniFFI + JNA, its keys in a
//! Kotlin `AppKeyProvider` on the JDK's crypto) and a Node "browser" (the
//! WASM build, its key a non-extractable WebCrypto P-256 key signing
//! through the deferred handshake) each connect over a real loopback TCP
//! socket to a host built from atem-client's responder role (the test host
//! of `atem-client/tests/support/host.rs`; the runtime host is Task 7). The
//! app-side code does every socket read and write itself; the binding only
//! turns bytes into bytes.
//!
//! Needs the built artifacts and toolchains, so it is `#[ignore]`d in a
//! plain `cargo test`; `scripts/check-atem-client-bindings.sh e2e` (and
//! CI) set these and run it:
//!
//! - `ATEM_E2E_JAVA`, `ATEM_E2E_KOTLIN_CP` (compiled tests + generated
//!   binding + JNA + kotlin-stdlib), `ATEM_E2E_JNA_PATH` (the cdylib's dir);
//! - `ATEM_E2E_NODE`, `ATEM_E2E_WASM_PKG` (wasm-bindgen `--target nodejs`).
#[path = "../../atem-client/tests/support/mod.rs"]
#[allow(unused_imports)]
mod support;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use atem_client::push::HintPlain;
use serde_json::Value;
use support::host::{HostConn, HostCore, HostSession};
use support::{Book, Clock, Vectors, genesis_hash, unhex32};

/// The host's wall clock starts here (the vectors' browser-grant era) and
/// then follows real time, as does its monotonic clock.
const WALL: u64 = 1_793_264_001_000;
const SES_A: &str = "ses-aaaaaaaaaaaa";
const SES_B: &str = "ses-bbbbbbbbbbbb";
const ABAB: &str = "h1.b982533d.abababababababababababababababababababababababababababababababab";
const CDCD: &str = "h1.b982533d.cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd";
const APPROVAL: &str = "8c3e9d6b-1f40-4b52-8dae-4f5a6b7c8d9e";

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

struct Host {
    core: Arc<Mutex<HostCore>>,
    started: Instant,
}

impl Host {
    fn new() -> Self {
        let v = Vectors::load();
        let book = Book::load();
        let clock = Clock::at(WALL);
        let labels = ["E1", "E2", "E3", "E4", "E5", "E6"];
        let log = atem_client::membership::Membership::verify_chain(
            support::ACCOUNT,
            &genesis_hash(),
            &v.entries(&labels),
            &clock.now,
        )
        .unwrap()
        .membership;
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
        Host {
            core: Arc::new(Mutex::new(HostCore::new(log, clock.now, &seed, sessions))),
            started: Instant::now(),
        }
    }

    /// The host's clock now (real time since the start, from `WALL`).
    fn sync(core: &mut HostCore, started: Instant) {
        let elapsed = started.elapsed().as_millis() as u64;
        core.now.wall_ms = WALL + elapsed;
        core.now.mono_ms = 1_000 + elapsed;
    }

    /// Accepts session connections: one host thread per connection, moving
    /// 4-byte length-prefixed frames.
    fn serve(&self, listener: TcpListener) {
        let core = self.core.clone();
        let started = self.started;
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { return };
                let core = core.clone();
                thread::spawn(move || serve_one(stream, core, started));
            }
        });
    }
}

fn serve_one(stream: TcpStream, core: Arc<Mutex<HostCore>>, started: Instant) {
    let (tx, rx) = mpsc::channel();
    let mut reader = stream.try_clone().unwrap();
    thread::spawn(move || {
        while let Some(frame) = recv(&mut reader) {
            if tx.send(frame).is_err() {
                break;
            }
        }
    });
    let mut writer = stream;
    let mut conn = HostConn::new(&mut core.lock().unwrap());
    loop {
        let frame = match rx.recv_timeout(Duration::from_millis(10)) {
            Ok(f) => Some(f),
            Err(mpsc::RecvTimeoutError::Timeout) => None,
            Err(mpsc::RecvTimeoutError::Disconnected) => return,
        };
        let mut core = core.lock().unwrap();
        Host::sync(&mut core, started);
        let out = match frame {
            Some(f) => conn.on_frame(&mut core, &f),
            None => {
                core.tick();
                conn.poll(&mut core)
            }
        };
        drop(core);
        for f in &out.frames {
            if !send(&mut writer, f) {
                return;
            }
        }
        if out.close {
            return;
        }
    }
}

/// The relay's side for the test: each client connects, names its device
/// in one frame, then receives what the test forwards.
fn relay(listener: TcpListener) -> Receiver<(String, TcpStream)> {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { return };
            let tx = tx.clone();
            thread::spawn(move || {
                if let Some(hello) = recv(&mut stream) {
                    let hello: Value = serde_json::from_slice(&hello).unwrap();
                    let device = hello["device_id"].as_str().unwrap().to_owned();
                    let _ = tx.send((device, stream));
                }
            });
        }
    });
    rx
}

fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| {
        panic!("{name} is not set: run scripts/check-atem-client-bindings.sh e2e")
    })
}

/// A child's stdout lines, forwarded with its name (and echoed for the log).
fn lines(name: &'static str, child: &mut Child, tx: Sender<(&'static str, String)>) {
    let out = child.stdout.take().unwrap();
    thread::spawn(move || {
        for line in BufReader::new(out).lines() {
            let Ok(line) = line else { break };
            println!("[{name}] {line}");
            if tx.send((name, line)).is_err() {
                break;
            }
        }
        let _ = tx.send((name, "<eof>".into()));
    });
}

struct Kill(Child);

impl Drop for Kill {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn fixtures() -> PathBuf {
    support::fixtures_dir()
}

/// Kotlin phone + WASM browser against the host, over loopback TCP.
///
/// Proves, through the bindings (not the crate's Rust API):
/// - the phone's handshake signs `sig_c` through the Kotlin provider with
///   purpose `CHANNEL` (no fresh confirmation) and is welcomed as
///   `member:dev-phone` (revision 9, control+view, head (6, E6));
/// - it lists both sessions, acquires `ses-a…` (lease applied), submits a
///   prompt (accepted, then completed), queries the receipt, releases;
/// - it issues a browser grant through the Kotlin provider (purpose
///   `BROWSER_GRANT`, fresh confirmation) for the browser's WebCrypto key;
/// - the browser connects with that grant through the deferred handshake
///   (WebCrypto signs the binding's `SignRequest`), is welcomed as
///   `browser:<grant>` with control, sees only the granted session, takes
///   its lease and submits a prompt (completed);
/// - the host opens an approval: the relay forwards the signed hints; the
///   phone verifies, dedups and opens its own (HPKE in Kotlin) and sends
///   `approval_seen` (answered `seen`); the browser verifies every hint as
///   a client and as the relay, cannot open them, and verifies the
///   host-signed seen.
#[test]
#[ignore = "needs the built bindings: scripts/check-atem-client-bindings.sh e2e"]
fn kotlin_phone_and_wasm_browser_use_the_host_over_tcp() {
    let java = env("ATEM_E2E_JAVA");
    let kotlin_cp = env("ATEM_E2E_KOTLIN_CP");
    let jna_path = env("ATEM_E2E_JNA_PATH");
    let node = env("ATEM_E2E_NODE");
    let wasm_pkg = env("ATEM_E2E_WASM_PKG");
    let browser_js = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("bindings/js/browser.mjs");

    let host = Host::new();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let host_port = listener.local_addr().unwrap().port();
    host.serve(listener);
    let relay_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let relay_port = relay_listener.local_addr().unwrap().port();
    let relays = relay(relay_listener);

    let (tx, rx) = mpsc::channel::<(&'static str, String)>();
    let mut browser = Kill(
        Command::new(&node)
            .arg(&browser_js)
            .arg(&wasm_pkg)
            .arg(fixtures())
            .arg(host_port.to_string())
            .arg(relay_port.to_string())
            .arg(WALL.to_string())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("node"),
    );
    lines("browser", &mut browser.0, tx.clone());
    let mut browser_in = browser.0.stdin.take().unwrap();

    let deadline = Instant::now() + Duration::from_secs(120);
    // Lines not asked for yet (the two clients run concurrently).
    let backlog = std::cell::RefCell::new(Vec::<(&'static str, String)>::new());
    let next = |who: &str, prefix: &str| -> String {
        let take = |name: &str, line: &str| name == who && line.starts_with(prefix);
        loop {
            let mut pending = backlog.borrow_mut();
            if let Some(i) = pending.iter().position(|(n, l)| take(n, l)) {
                let (_, line) = pending.remove(i);
                return line[prefix.len()..].trim().to_owned();
            }
            drop(pending);
            let left = deadline.saturating_duration_since(Instant::now());
            let (name, line) = rx
                .recv_timeout(left)
                .unwrap_or_else(|_| panic!("timed out waiting for {who} {prefix}"));
            if line.starts_with("FAIL") || (line == "<eof>" && name == who) {
                panic!("{name}: {line} (waiting for {who} {prefix})");
            }
            backlog.borrow_mut().push((name, line));
        }
    };

    let browser_key = next("browser", "BROWSER_KEY");
    let mut phone = Kill(
        Command::new(&java)
            .arg(format!("-Djna.library.path={jna_path}"))
            .arg("-cp")
            .arg(&kotlin_cp)
            .arg("atem.bindings.test.PhoneKt")
            .arg(fixtures())
            .arg(host_port.to_string())
            .arg(relay_port.to_string())
            .arg(&browser_key)
            .arg(WALL.to_string())
            .stdout(Stdio::piped())
            .spawn()
            .expect("java"),
    );
    lines("phone", &mut phone.0, tx.clone());

    assert_eq!(
        next("phone", "WELCOME"),
        "member:dev-phone native control,view 9 6"
    );
    assert_eq!(next("phone", "SESSIONS"), format!("{SES_A},{SES_B}"));
    assert_eq!(next("phone", "LEASE"), "applied");
    assert_eq!(next("phone", "PROMPT"), "accepted completed");
    assert_eq!(
        next("phone", "REQUESTS"),
        "renew interrupt approval rule_revoke stop terminal chat"
    );
    assert_eq!(next("phone", "RELEASED"), "lease_released");
    let grant = next("phone", "GRANT");
    writeln!(browser_in, "GRANT {grant}").unwrap();
    browser_in.flush().unwrap();

    let grant_id = serde_json::from_str::<Value>(&grant).unwrap()["body"]["grant_id"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(
        next("browser", "WELCOME"),
        format!("browser:{grant_id} browser control,view 9 6")
    );
    assert_eq!(next("browser", "SESSIONS"), SES_A);
    assert_eq!(next("browser", "LEASE"), "applied");
    assert_eq!(next("browser", "PROMPT"), "accepted completed");
    assert_eq!(
        next("browser", "REQUESTS"),
        "renew interrupt:forbidden release"
    );
    next("phone", "READY_FOR_PUSH");
    next("browser", "READY_FOR_PUSH");

    // Both clients' relay sockets.
    let mut sockets = std::collections::BTreeMap::new();
    while sockets.len() < 2 {
        let (device, stream) = relays
            .recv_timeout(Duration::from_secs(30))
            .expect("relay connections");
        sockets.insert(device, stream);
    }

    // The host opens an approval on ses-a…: its signed hints go to the
    // relay, which forwards the message to the phone and the browser.
    let message = {
        let mut core = host.core.lock().unwrap();
        Host::sync(&mut core, host.started);
        core.open_approval(
            SES_A,
            APPROVAL,
            &HintPlain {
                tool: "Bash".into(),
                summary: "npm test".into(),
            },
        );
        core.relay_sent.last().cloned().unwrap()
    };
    assert_eq!(message["op"], "push_hint");
    for stream in sockets.values_mut() {
        assert!(send(stream, message.to_string().as_bytes()));
    }
    assert_eq!(next("phone", "HINT"), "dev-phone Bash npm test");
    assert_eq!(
        next("browser", "HINTS_VERIFIED"),
        "dev-mac,dev-phone sealed"
    );
    assert_eq!(next("phone", "SEEN"), "ok");

    // The host signed a seen for the phone's attended card: the relay
    // forwards it, and the browser verifies it.
    let seen = {
        let core = host.core.lock().unwrap();
        core.relay_sent
            .iter()
            .rev()
            .find(|m| m["op"] == "push_seen")
            .cloned()
            .expect("a push_seen")
    };
    assert!(send(
        sockets.get_mut("browser").unwrap(),
        seen.to_string().as_bytes()
    ));
    assert_eq!(next("browser", "SEEN_VERIFIED"), "dev-phone");

    // The phone publishes E7 and carries it to the host on the open
    // channel; then it revokes the browser's grant: the browser is fenced
    // at once and its next connection is refused.
    assert_eq!(next("phone", "MEMBERSHIP"), "7");
    assert_eq!(next("phone", "REVOKED"), grant_id);
    assert_eq!(next("browser", "FENCED"), "unauthorized grant revoked");
    assert_eq!(next("browser", "REFUSED"), "unauthorized grant revoked");
    next("phone", "DONE");
    next("browser", "DONE");
    assert_eq!(host.core.lock().unwrap().log.head().seq, 7);
    assert!(phone.0.wait().unwrap().success());
    assert!(browser.0.wait().unwrap().success());
}
