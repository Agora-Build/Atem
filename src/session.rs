//! Agent sessions: ids, providers, launch environment bounds and the output
//! tap a broker session keeps for its local frontend. Each session runs in
//! its own `atem worker` (src/runtime/).

use std::ffi::OsString;
use std::time::Duration;

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

    /// Continue the stream at `offset` (a worker's screen replaced the bytes
    /// before it): whatever was kept is dropped.
    pub fn restart_at(&mut self, offset: u64) {
        self.offset = offset;
        if let Some(buf) = &mut self.buf {
            buf.clear();
        }
        self.overflowed = false;
    }

    /// Bytes produced so far.
    #[cfg(test)]
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

/// At most this many live sessions per runtime.
pub const MAX_LIVE: usize = 16;

#[cfg(test)]
mod tests {
    use super::*;

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
    fn provider_names() {
        assert_eq!(Provider::Claude.as_str(), "claude");
        assert_eq!(Provider::Codex.as_str(), "codex");
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
}
