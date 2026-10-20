//! r9 in the real runtime: a pinned device list written as the pairing
//! writes it (the runtime's `open` verifies all of it), and a router on the
//! fake Astation's link that carries clients' `atem-ch1` frames in the
//! channel envelope (atem-session-v1.md §R9.7a).
#![allow(dead_code)]

use super::astation::{Event, FakeAstation};
use super::r9log::TestLog;
use atem_client::connect::{Attached, ConnectError, Connector, Event as CEvent, Identity};
use serde_json::{Value, json};
use std::collections::{HashMap, VecDeque};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::time::{Duration, Instant};

const WAIT: Duration = Duration::from_secs(20);

fn private_dir(dir: &Path) {
    std::fs::create_dir_all(dir).unwrap();
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).unwrap();
}

fn private_file(path: &Path, text: &str) {
    std::fs::write(path, text).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

/// Pins `log` for `host_id` at `host_trust_gen` in the profile `config`,
/// with `host_seed` as its `host_channel_key` and the applied head at the
/// log's head: what `MembershipHost::pin` writes at pairing.
pub fn write_pin(
    config: &Path,
    log: &TestLog,
    host_id: &str,
    host_trust_gen: u64,
    host_seed: &[u8; 32],
) {
    let pairing = config.join("pairing");
    let journal = config.join("runtime").join("journal");
    private_dir(&pairing);
    private_dir(&config.join("runtime"));
    private_dir(&journal);
    let host_pub = ed25519_dalek::SigningKey::from_bytes(host_seed)
        .verifying_key()
        .to_bytes();
    private_file(
        &pairing.join("host_channel_key"),
        &json!({"v": 1, "seed": atem_client::encoding::b64u(host_seed),
                "pub": atem_client::encoding::b64u(&host_pub)})
        .to_string(),
    );
    let head = log.log.head();
    private_file(
        &journal.join("membership_applied"),
        &json!({"seq": head.seq, "hash": head.hash.to_hex()}).to_string(),
    );
    let mut state = log.log.to_stored();
    state["v"] = json!(1);
    state["host"] = json!({"host_id": host_id, "host_trust_gen": host_trust_gen});
    // Written last (a rename), as the pin does.
    let tmp = pairing.join("membership.json.pin");
    private_file(&tmp, &state.to_string());
    std::fs::rename(&tmp, pairing.join("membership.json")).unwrap();
}

/// A client's monotonic ms.
pub fn client_ms() -> u64 {
    static START: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
    START.get_or_init(Instant::now).elapsed().as_millis() as u64 + 1
}

/// What Atem sent on a channel.
#[derive(Debug)]
pub enum Out {
    Frame(Vec<u8>),
    Close(Option<String>),
}

/// The router on the fake Astation's link `link`.
pub struct Router<'a> {
    pub astation: &'a FakeAstation,
    pub link: u64,
    channels: HashMap<String, VecDeque<Out>>,
    /// Link messages that aren't envelopes (r8 replies), in order.
    pub other: VecDeque<Value>,
}

impl<'a> Router<'a> {
    /// Waits for the runtime's link to authenticate.
    pub fn new(astation: &'a FakeAstation) -> Router<'a> {
        let deadline = Instant::now() + WAIT;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            match astation.events.recv_timeout(left) {
                Ok(Event::Authenticated(link)) => {
                    return Router {
                        astation,
                        link,
                        channels: HashMap::new(),
                        other: VecDeque::new(),
                    };
                }
                Ok(_) => {}
                Err(_) => panic!("the runtime's link never authenticated"),
            }
        }
    }

    fn pump(&mut self, wait: Duration) -> bool {
        match self.astation.events.recv_timeout(wait) {
            Ok(Event::Message(link, value)) if link == self.link => {
                if value["type"] == "channel" {
                    let handle = value["channel"].as_str().unwrap_or_default().to_string();
                    let out = match value["event"].as_str() {
                        Some("frame") => Out::Frame(serde_json::to_vec(&value["frame"]).unwrap()),
                        _ => Out::Close(value["reason"].as_str().map(str::to_string)),
                    };
                    self.channels.entry(handle).or_default().push_back(out);
                } else {
                    self.other.push_back(value);
                }
                true
            }
            Ok(_) => true,
            Err(_) => false,
        }
    }

    /// The next thing Atem sent on `handle`.
    pub fn next(&mut self, handle: &str) -> Out {
        let deadline = Instant::now() + WAIT;
        loop {
            if let Some(out) = self.channels.get_mut(handle).and_then(VecDeque::pop_front) {
                return out;
            }
            let left = deadline.saturating_duration_since(Instant::now());
            assert!(!left.is_zero(), "Atem sent nothing on {handle}");
            self.pump(left.min(Duration::from_millis(200)));
        }
    }

    /// Whether Atem sends anything on `handle` within `wait`.
    pub fn quiet(&mut self, handle: &str, wait: Duration) -> bool {
        let deadline = Instant::now() + wait;
        while Instant::now() < deadline {
            if self.channels.get(handle).is_some_and(|q| !q.is_empty()) {
                return false;
            }
            self.pump(Duration::from_millis(50));
        }
        self.channels.get(handle).is_none_or(VecDeque::is_empty)
    }

    /// The next non-envelope message on the link.
    pub fn next_other(&mut self) -> Value {
        let deadline = Instant::now() + WAIT;
        loop {
            if let Some(v) = self.other.pop_front() {
                return v;
            }
            let left = deadline.saturating_duration_since(Instant::now());
            assert!(!left.is_zero(), "Atem sent nothing on the link");
            self.pump(left.min(Duration::from_millis(200)));
        }
    }

    /// The next non-envelope message on the link within `wait`, if any.
    pub fn other_within(&mut self, wait: Duration) -> Option<Value> {
        let deadline = Instant::now() + wait;
        loop {
            if let Some(v) = self.other.pop_front() {
                return Some(v);
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return None;
            }
            self.pump(left.min(Duration::from_millis(100)));
        }
    }

    pub fn send_raw(&self, text: String) {
        self.astation.send(self.link, text);
    }

    pub fn open(&self, handle: &str, transport: &str) {
        self.send_raw(
            json!({"type": "channel", "event": "open", "channel": handle,
                             "transport": transport})
            .to_string(),
        );
    }

    pub fn close(&self, handle: &str) {
        self.send_raw(
            json!({"type": "channel", "event": "close", "channel": handle,
                             "reason": "client_gone"})
            .to_string(),
        );
    }

    pub fn frame(&self, handle: &str, frame: &[u8]) {
        let frame: Value = serde_json::from_slice(frame).unwrap();
        self.send_raw(
            json!({"type": "channel", "event": "frame", "channel": handle,
                             "frame": frame})
            .to_string(),
        );
    }

    /// Opens `handle` and runs a full handshake for `identity` with `log`'s
    /// keys: the attachment, or the refusal (`code`, `detail`).
    pub fn connect(
        &mut self,
        handle: &str,
        log: &TestLog,
        host_id: &str,
        identity: &Identity,
    ) -> Result<Attached, (String, Option<String>)> {
        self.connect_via(handle, "relay", log, host_id, identity)
    }

    /// [`Router::connect`] with the router's `transport` label (`relay` or
    /// `direct`, Astation's :8080).
    pub fn connect_via(
        &mut self,
        handle: &str,
        transport: &str,
        log: &TestLog,
        host_id: &str,
        identity: &Identity,
    ) -> Result<Attached, (String, Option<String>)> {
        self.open(handle, transport);
        let (connecting, init) = Connector::new(host_id)
            .start(&log.log, client_ms())
            .map_err(|e| (format!("{e:?}"), None))?;
        self.frame(handle, &init);
        let accept = match self.next(handle) {
            Out::Frame(f) => f,
            Out::Close(r) => return Err(("closed".into(), r)),
        };
        if let Ok(atem_client::channel::wire::Frame::Error { code }) =
            atem_client::channel::wire::parse_frame(&accept)
        {
            return Err((code, None));
        }
        let (welcoming, finish) = connecting
            .on_accept(&accept, &log.log, &log.keys, identity, client_ms())
            .map_err(|e| (format!("{e:?}"), None))?;
        self.frame(handle, &finish);
        let first = match self.next(handle) {
            Out::Frame(f) => f,
            Out::Close(r) => return Err(("closed".into(), r)),
        };
        match welcoming.on_frame(&first, &log.log, client_ms()) {
            Ok(attached) => Ok(attached),
            Err(ConnectError::Refused { error, .. }) => {
                Err((error.code.clone(), error.detail.clone()))
            }
            Err(e) => Err((format!("{e:?}"), None)),
        }
    }

    /// Sends `frame` on `handle`; the events of Atem's next record, or the
    /// channel's close.
    pub fn round(
        &mut self,
        handle: &str,
        attached: &mut Attached,
        frame: &[u8],
    ) -> Result<Vec<CEvent>, Option<String>> {
        self.frame(handle, frame);
        self.events(handle, attached)
    }

    /// Atem's next record on `handle`, as events (or its close).
    pub fn events(
        &mut self,
        handle: &str,
        attached: &mut Attached,
    ) -> Result<Vec<CEvent>, Option<String>> {
        match self.next(handle) {
            Out::Frame(f) => Ok(attached.on_frame(&f, client_ms()).unwrap()),
            Out::Close(r) => Err(r),
        }
    }

    /// `list` on `handle`: the session ids its registry shows.
    pub fn list(&mut self, handle: &str, attached: &mut Attached) -> Vec<String> {
        let (_, frame) = attached.list(client_ms()).unwrap();
        let events = self
            .round(handle, attached, &frame)
            .expect("a sessions reply");
        events
            .into_iter()
            .find_map(|e| match e {
                CEvent::Session(m) => match m.op {
                    atem_client::session::wire::Op::Sessions { sessions, .. } => {
                        Some(sessions.into_iter().map(|d| d.session_id).collect())
                    }
                    _ => None,
                },
                _ => None,
            })
            .expect("a sessions reply")
    }
}
