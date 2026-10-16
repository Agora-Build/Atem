//! Agent sessions: one Claude Code or Codex process in a PTY with all of its
//! terminal state (canonical screen, terminal-v1 share, logs, chat).

use crate::agent_client::AgentKind;
use crate::pty_session::{PtyEvent, PtyHandle, PtyInput, PtySession};
use crate::terminal_share::SharedTerminal;
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime};
use tokio::sync::mpsc;
use vt100::Parser as VtParser;

const ID_PREFIX: &str = "ses-";
const ID_CHARS: usize = 12;
const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

/// `ses-` and 12 lowercase base32 characters (`[a-z2-7]`), random.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SessionId(String);

impl SessionId {
    pub fn new() -> Self {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let suffix: String = (0..ID_CHARS)
            .map(|_| ALPHABET[rng.gen_range(0..ALPHABET.len())] as char)
            .collect();
        Self(format!("{ID_PREFIX}{suffix}"))
    }

    pub fn parse(s: &str) -> Option<Self> {
        let suffix = s.strip_prefix(ID_PREFIX)?;
        (suffix.len() == ID_CHARS && suffix.bytes().all(|b| ALPHABET.contains(&b)))
            .then(|| Self(s.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for SessionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Provider {
    Claude,
    Codex,
}

impl Provider {
    /// The terminal id alias and log directory prefix.
    pub fn as_str(self) -> &'static str {
        match self {
            Provider::Claude => "claude",
            Provider::Codex => "codex",
        }
    }

    pub fn kind(self) -> AgentKind {
        match self {
            Provider::Claude => AgentKind::ClaudeCode,
            Provider::Codex => AgentKind::Codex,
        }
    }

    /// Short name shown to the user ("Claude", "Codex").
    pub fn label(self) -> &'static str {
        match self {
            Provider::Claude => "Claude",
            Provider::Codex => "Codex",
        }
    }

    /// Product name ("Claude Code", "Codex").
    pub fn product(self) -> &'static str {
        match self {
            Provider::Claude => "Claude Code",
            Provider::Codex => "Codex",
        }
    }

    pub fn from_alias(alias: &str) -> Option<Self> {
        match alias {
            "claude" => Some(Provider::Claude),
            "codex" => Some(Provider::Codex),
            _ => None,
        }
    }
}

/// How long an exited session stays (final screen, logs, chat history).
pub const EXITED_KEEP: Duration = Duration::from_secs(10 * 60);
/// Launch environment bounds.
pub const MAX_ENV_ENTRIES: usize = 512;
pub const MAX_ENV_BYTES: usize = 256 * 1024;

/// A new session: provider, its arguments (after `CLAUDE_CLI_ARGS`/`CODEX_CLI_ARGS`),
/// working directory, environment (`None` = Atem's own) and screen size.
/// `Debug` never prints the environment.
#[derive(Clone)]
pub struct LaunchRequest {
    pub provider: Provider,
    pub args: Vec<String>,
    pub cwd: PathBuf,
    pub env: Option<Vec<(OsString, OsString)>>,
    pub rows: u16,
    pub cols: u16,
}

impl std::fmt::Debug for LaunchRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LaunchRequest")
            .field("provider", &self.provider)
            .field("args", &self.args)
            .field("cwd", &self.cwd)
            .field("env", &crate::pty_session::EnvSummary(&self.env))
            .field("rows", &self.rows)
            .field("cols", &self.cols)
            .finish()
    }
}

impl LaunchRequest {
    /// Atem's own working directory and environment.
    pub fn here(provider: Provider, args: Vec<String>, rows: u16, cols: u16) -> Self {
        Self {
            provider,
            args,
            cwd: std::env::current_dir().unwrap_or_default(),
            env: None,
            rows,
            cols,
        }
    }
}

/// A launch environment holds at most `MAX_ENV_ENTRIES` entries and
/// `MAX_ENV_BYTES` in total (`name=value\0` each).
pub fn check_env(env: &[(OsString, OsString)]) -> Result<(), &'static str> {
    if env.len() > MAX_ENV_ENTRIES {
        return Err("The launch environment has more than 512 entries");
    }
    let bytes: usize = env.iter().map(|(k, v)| k.len() + v.len() + 2).sum();
    if bytes > MAX_ENV_BYTES {
        return Err("The launch environment is larger than 256 KiB");
    }
    Ok(())
}

/// Most bytes a tap holds between two takes; beyond it they're dropped (the
/// frontend gets a fresh restore instead).
pub const TAP_LIMIT: usize = 1024 * 1024;

/// The session's raw PTY output in order, after the canonical parser has seen
/// it, for an attached local frontend. `offset` counts every byte the session
/// has produced; bytes are kept only while the tap is open.
#[derive(Default)]
pub struct OutputTap {
    offset: u64,
    buf: Option<Vec<u8>>,
    overflowed: bool,
}

/// Bytes taken from a tap: `bytes` starts at stream position `start`;
/// `overflowed` when bytes were dropped since the last take.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct TapChunk {
    pub start: u64,
    pub bytes: Vec<u8>,
    pub overflowed: bool,
}

impl OutputTap {
    pub fn record(&mut self, bytes: &[u8]) {
        self.offset += bytes.len() as u64;
        let Some(buf) = &mut self.buf else { return };
        if self.overflowed {
            return;
        }
        if buf.len() + bytes.len() > TAP_LIMIT {
            buf.clear();
            self.overflowed = true;
        } else {
            buf.extend_from_slice(bytes);
        }
    }

    /// Start keeping bytes (from now on).
    pub fn open(&mut self) {
        self.buf = Some(Vec::new());
        self.overflowed = false;
    }

    pub fn close(&mut self) {
        self.buf = None;
        self.overflowed = false;
    }

    /// Bytes produced so far.
    pub fn offset(&self) -> u64 {
        self.offset
    }

    /// The bytes kept since the last take.
    pub fn take(&mut self) -> TapChunk {
        let bytes = self.buf.as_mut().map(std::mem::take).unwrap_or_default();
        let overflowed = std::mem::take(&mut self.overflowed);
        TapChunk {
            start: self.offset - bytes.len() as u64,
            bytes,
            overflowed,
        }
    }
}

pub struct Session {
    pub id: SessionId,
    pub provider: Provider,
    pub cwd: PathBuf,
    pub created_at: SystemTime,
    /// Bumped by local/remote input and launch.
    pub last_used: Instant,
    pub input: Option<PtyInput>,
    pub events: Option<mpsc::Receiver<PtyEvent>>,
    pub handle: Option<PtyHandle>,
    pub terminal: VtParser,
    pub share: SharedTerminal,
    pub raw_log: String,
    pub raw_log_start: usize,
    pub output_log: String,
    pub user_actions: Vec<String>,
    pub log_file: Option<PathBuf>,
    pub summary_file: Option<PathBuf>,
    pub waiting_exit: bool,
    /// Local viewport size, (0, 0) = unset.
    pub view: (u16, u16),
    /// chat-v1 state (Claude only).
    pub chat: Option<crate::app::chat::AgentChat>,
    pub exited_at: Option<Instant>,
    /// Raw output for an attached local frontend (`atem runtime`).
    pub tap: OutputTap,
}

impl Session {
    /// A session without a process yet: a `rows` x `cols` screen, no PTY.
    pub fn new(provider: Provider, rows: u16, cols: u16) -> Self {
        let id = SessionId::new();
        let share = SharedTerminal::new(id.as_str(), provider.as_str());
        Self {
            id,
            provider,
            cwd: std::env::current_dir().unwrap_or_default(),
            created_at: SystemTime::now(),
            last_used: Instant::now(),
            input: None,
            events: None,
            handle: None,
            terminal: VtParser::new(rows, cols, crate::pty_session::SCROLLBACK_ROWS),
            share,
            raw_log: String::new(),
            raw_log_start: 0,
            output_log: String::new(),
            user_actions: Vec::new(),
            log_file: None,
            summary_file: None,
            waiting_exit: false,
            view: (0, 0),
            chat: None,
            exited_at: None,
            tap: OutputTap::default(),
        }
    }

    /// Connect the spawned process.
    pub fn attach(&mut self, pty: PtySession) {
        self.input = Some(pty.sender);
        self.events = Some(pty.receiver);
        self.handle = Some(pty.resize_handle);
    }

    pub fn is_live(&self) -> bool {
        self.exited_at.is_none()
    }
}

/// Sessions by id, iterated in creation order.
#[derive(Default)]
pub struct Sessions {
    map: BTreeMap<SessionId, Session>,
    order: Vec<SessionId>,
}

impl Sessions {
    pub const MAX_LIVE: usize = 16;

    /// Refuses a live session beyond `MAX_LIVE` live ones.
    pub fn insert(&mut self, s: Session) -> anyhow::Result<&mut Session> {
        if s.is_live() {
            self.check_room()?;
        }
        if self.map.contains_key(&s.id) {
            anyhow::bail!("Session {} already exists", s.id);
        }
        let id = s.id.clone();
        self.order.push(id.clone());
        Ok(self.map.entry(id).or_insert(s))
    }

    /// Number of live sessions.
    pub fn live_count(&self) -> usize {
        self.map.values().filter(|s| s.is_live()).count()
    }

    /// Room for one more live session (checked before spawning).
    pub fn check_room(&self) -> anyhow::Result<()> {
        if self.live_count() >= Self::MAX_LIVE {
            anyhow::bail!("At most {} sessions can run at once", Self::MAX_LIVE);
        }
        Ok(())
    }

    pub fn get(&self, id: &SessionId) -> Option<&Session> {
        self.map.get(id)
    }

    pub fn get_mut(&mut self, id: &SessionId) -> Option<&mut Session> {
        self.map.get_mut(id)
    }

    pub fn remove(&mut self, id: &SessionId) -> Option<Session> {
        let session = self.map.remove(id)?;
        self.order.retain(|other| other != id);
        Some(session)
    }

    /// Creation order.
    pub fn iter(&self) -> impl Iterator<Item = &Session> {
        self.order.iter().filter_map(|id| self.map.get(id))
    }

    /// Creation order.
    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut Session> {
        let mut sessions: Vec<&mut Session> = self.map.values_mut().collect();
        let position = |id: &SessionId| self.order.iter().position(|other| other == id);
        sessions.sort_by_key(|s| position(&s.id));
        sessions.into_iter()
    }

    /// Session ids in creation order.
    pub fn ids(&self) -> Vec<SessionId> {
        self.order.clone()
    }

    /// The most recently used live session of `provider` (the newest on a tie).
    pub fn latest(&self, provider: Provider) -> Option<SessionId> {
        self.iter()
            .filter(|s| s.provider == provider && s.is_live())
            .max_by_key(|s| s.last_used)
            .map(|s| s.id.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn session(provider: Provider) -> Session {
        Session::new(provider, 24, 80)
    }

    #[test]
    fn a_tap_keeps_bytes_only_while_open_and_counts_every_byte() {
        let mut tap = OutputTap::default();
        tap.record(b"before");
        assert_eq!(
            tap.take(),
            TapChunk {
                start: 6,
                bytes: vec![],
                overflowed: false
            }
        );
        tap.open();
        tap.record(b"ab");
        tap.record(b"cd");
        assert_eq!(
            tap.take(),
            TapChunk {
                start: 6,
                bytes: b"abcd".to_vec(),
                overflowed: false
            }
        );
        tap.record(&vec![b'x'; TAP_LIMIT + 1]);
        tap.record(b"more");
        let chunk = tap.take();
        assert!(chunk.overflowed && chunk.bytes.is_empty());
        assert_eq!(tap.offset(), 10 + TAP_LIMIT as u64 + 1 + 4);
        tap.record(b"z");
        assert_eq!(tap.take().bytes, b"z");
        tap.close();
        tap.record(b"gone");
        assert!(tap.take().bytes.is_empty());
    }

    #[test]
    fn ids_are_ses_and_12_base32_characters() {
        let id = SessionId::new();
        let text = id.as_str();
        assert_eq!(text.len(), 16);
        assert!(text.starts_with("ses-"));
        assert!(
            text[4..]
                .chars()
                .all(|c| c.is_ascii_lowercase() || ('2'..='7').contains(&c))
        );
        assert_eq!(id.to_string(), text);
        assert_ne!(SessionId::new(), id);
    }

    #[test]
    fn parse_accepts_only_the_session_id_format() {
        let id = SessionId::new();
        assert_eq!(SessionId::parse(id.as_str()), Some(id));
        assert_eq!(
            SessionId::parse("ses-abcdefgh2345").unwrap().as_str(),
            "ses-abcdefgh2345"
        );
        for bad in [
            "",
            "ses-",
            "ses-abcdefgh234",
            "ses-abcdefgh23456",
            "ses-ABCDEFGH2345",
            "ses-abcdefgh2341",
            "xyz-abcdefgh2345",
            "claude",
            "ses-abcdefgh234\u{e9}",
        ] {
            assert_eq!(SessionId::parse(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn provider_names_and_kinds() {
        assert_eq!(Provider::Claude.as_str(), "claude");
        assert_eq!(Provider::Codex.as_str(), "codex");
        assert_eq!(Provider::Claude.kind(), AgentKind::ClaudeCode);
        assert_eq!(Provider::Codex.kind(), AgentKind::Codex);
    }

    #[test]
    fn insert_refuses_more_than_16_live_sessions() {
        let mut sessions = Sessions::default();
        for _ in 0..Sessions::MAX_LIVE {
            sessions.insert(session(Provider::Claude)).unwrap();
        }
        assert!(sessions.insert(session(Provider::Codex)).is_err());
        assert_eq!(sessions.iter().count(), Sessions::MAX_LIVE);
        // Exited sessions do not count.
        let first = sessions.ids()[0].clone();
        sessions.get_mut(&first).unwrap().exited_at = Some(Instant::now());
        sessions.insert(session(Provider::Codex)).unwrap();
        let mut exited = session(Provider::Codex);
        exited.exited_at = Some(Instant::now());
        sessions.insert(exited).unwrap();
        assert_eq!(sessions.iter().count(), Sessions::MAX_LIVE + 2);
    }

    #[test]
    fn launch_environment_is_bounded() {
        let entry = |i: usize| (OsString::from(format!("V{i}")), OsString::from("x"));
        let env: Vec<_> = (0..MAX_ENV_ENTRIES).map(entry).collect();
        assert_eq!(check_env(&env), Ok(()));
        let env: Vec<_> = (0..=MAX_ENV_ENTRIES).map(entry).collect();
        assert!(check_env(&env).is_err());
        // name + "=" + value + NUL
        let fits = vec![(
            OsString::from("A"),
            OsString::from("v".repeat(MAX_ENV_BYTES - 3)),
        )];
        assert_eq!(check_env(&fits), Ok(()));
        let over = vec![(
            OsString::from("A"),
            OsString::from("v".repeat(MAX_ENV_BYTES - 2)),
        )];
        assert!(check_env(&over).is_err());
        assert_eq!(check_env(&[]), Ok(()));
    }

    #[test]
    fn a_launch_request_never_prints_its_environment() {
        let mut request = LaunchRequest::here(Provider::Claude, vec!["--x".into()], 24, 80);
        request.env = Some(vec![("API_TOKEN".into(), "s3cr3t-value".into())]);
        let text = format!("{request:?}");
        assert!(!text.contains("s3cr3t-value"), "{text}");
        assert!(!text.contains("API_TOKEN"), "{text}");
        assert!(text.contains("env: <1 entries>"), "{text}");
        assert!(text.contains("--x"), "{text}");
        request.env = None;
        assert!(format!("{request:?}").contains("env: <inherited>"));
    }

    #[test]
    fn a_session_shares_its_terminal_under_its_own_id() {
        let s = session(Provider::Codex);
        assert_eq!(s.share.id, s.id.as_str());
        let screen = vt100::Parser::new(24, 80, 0);
        assert_eq!(s.share.info(screen.screen()).provider, "codex");
    }

    #[test]
    fn iteration_follows_creation_order_and_remove() {
        let mut sessions = Sessions::default();
        let ids: Vec<SessionId> = (0..5)
            .map(|i| {
                let provider = if i % 2 == 0 {
                    Provider::Claude
                } else {
                    Provider::Codex
                };
                sessions.insert(session(provider)).unwrap().id.clone()
            })
            .collect();
        let seen: Vec<SessionId> = sessions.iter().map(|s| s.id.clone()).collect();
        assert_eq!(seen, ids);
        assert_eq!(sessions.ids(), ids);
        let removed = sessions.remove(&ids[2]).unwrap();
        assert_eq!(removed.id, ids[2]);
        assert!(sessions.get(&ids[2]).is_none());
        assert!(sessions.remove(&ids[2]).is_none());
        let seen: Vec<SessionId> = sessions.iter_mut().map(|s| s.id.clone()).collect();
        assert_eq!(seen, [&ids[0], &ids[1], &ids[3], &ids[4]].map(Clone::clone));
    }

    #[test]
    fn latest_is_the_most_recently_used_live_session() {
        let mut sessions = Sessions::default();
        assert_eq!(sessions.latest(Provider::Claude), None);
        let start = Instant::now();
        let mut ids = Vec::new();
        for offset in [3, 7, 5] {
            let mut s = session(Provider::Claude);
            s.last_used = start + Duration::from_secs(offset);
            ids.push(sessions.insert(s).unwrap().id.clone());
        }
        let codex = sessions
            .insert(session(Provider::Codex))
            .unwrap()
            .id
            .clone();
        assert_eq!(sessions.latest(Provider::Claude), Some(ids[1].clone()));
        assert_eq!(sessions.latest(Provider::Codex), Some(codex));
        // Use moves the latest.
        sessions.get_mut(&ids[0]).unwrap().last_used = start + Duration::from_secs(9);
        assert_eq!(sessions.latest(Provider::Claude), Some(ids[0].clone()));
        // Exited sessions are never the latest.
        sessions.get_mut(&ids[0]).unwrap().exited_at = Some(Instant::now());
        assert_eq!(sessions.latest(Provider::Claude), Some(ids[1].clone()));
        sessions.get_mut(&ids[1]).unwrap().exited_at = Some(Instant::now());
        sessions.get_mut(&ids[2]).unwrap().exited_at = Some(Instant::now());
        assert_eq!(sessions.latest(Provider::Claude), None);
    }
}
