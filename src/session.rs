//! Agent sessions: one Claude Code or Codex process in a PTY with all of its
//! terminal state (canonical screen, terminal-v1 share, logs, chat).

use crate::agent_client::AgentKind;
use crate::pty_session::{PtyEvent, PtyHandle, PtyInput, PtySession};
use crate::terminal_share::SharedTerminal;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::{Instant, SystemTime};
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
}

impl Session {
    /// A session without a process yet: a `rows` x `cols` screen, no PTY.
    pub fn new(provider: Provider, rows: u16, cols: u16) -> Self {
        Self {
            id: SessionId::new(),
            provider,
            cwd: std::env::current_dir().unwrap_or_default(),
            created_at: SystemTime::now(),
            last_used: Instant::now(),
            input: None,
            events: None,
            handle: None,
            terminal: VtParser::new(rows, cols, crate::pty_session::SCROLLBACK_ROWS),
            share: SharedTerminal::new(provider.as_str()),
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
        if s.is_live() && self.map.values().filter(|s| s.is_live()).count() >= Self::MAX_LIVE {
            anyhow::bail!("At most {} sessions can run at once", Self::MAX_LIVE);
        }
        if self.map.contains_key(&s.id) {
            anyhow::bail!("Session {} already exists", s.id);
        }
        let id = s.id.clone();
        self.order.push(id.clone());
        Ok(self.map.entry(id).or_insert(s))
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

    /// "claude"/"codex" alias or a session id → the live session it names
    /// (alias = the most recently used live session of that provider).
    pub fn resolve(&self, id_or_alias: &str) -> Option<SessionId> {
        if let Some(provider) = Provider::from_alias(id_or_alias) {
            return self.latest(provider);
        }
        let id = SessionId::parse(id_or_alias)?;
        self.map
            .get(&id)
            .filter(|s| s.is_live())
            .map(|s| s.id.clone())
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
    fn aliases_resolve_to_the_most_recently_used_live_session() {
        let mut sessions = Sessions::default();
        assert_eq!(sessions.resolve("claude"), None);
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
        assert_eq!(sessions.resolve("claude"), Some(ids[1].clone()));
        assert_eq!(sessions.resolve("codex"), Some(codex.clone()));
        // Use moves the alias.
        sessions.get_mut(&ids[0]).unwrap().last_used = start + Duration::from_secs(9);
        assert_eq!(sessions.resolve("claude"), Some(ids[0].clone()));
        // Exited sessions are not aliased or resolved.
        sessions.get_mut(&ids[0]).unwrap().exited_at = Some(Instant::now());
        assert_eq!(sessions.resolve("claude"), Some(ids[1].clone()));
        assert_eq!(sessions.resolve(ids[0].as_str()), None);
        // A session id names its own session.
        assert_eq!(sessions.resolve(ids[2].as_str()), Some(ids[2].clone()));
        assert_eq!(sessions.resolve(codex.as_str()), Some(codex));
        assert_eq!(sessions.resolve("ses-aaaaaaaaaaaa"), None);
        assert_eq!(sessions.resolve("gemini"), None);
        sessions.get_mut(&ids[1]).unwrap().exited_at = Some(Instant::now());
        sessions.get_mut(&ids[2]).unwrap().exited_at = Some(Instant::now());
        assert_eq!(sessions.latest(Provider::Claude), None);
    }
}
