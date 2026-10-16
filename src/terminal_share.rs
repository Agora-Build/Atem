//! terminal-v1: canonical visible-screen ANSI updates over the authenticated link.
//! Viewers receive rendered state, never the CLI's terminal queries or hidden buffers.
use crate::pty_session::PtyInput;
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;

const FRAME_BYTES: usize = 16 * 1024;
const WINDOW_BYTES: u64 = 128 * 1024;
const RESTORE_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope {
    pub v: u8,
    #[serde(flatten)]
    pub message: Message,
}

impl From<Message> for Envelope {
    fn from(message: Message) -> Self {
        Self { v: 1, message }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Message {
    Subscribe {
        terminal_id: String,
        generation: String,
    },
    Unsubscribe {
        terminal_id: String,
        generation: String,
        stream_id: String,
    },
    Ack {
        terminal_id: String,
        generation: String,
        stream_id: String,
        offset: u64,
    },
    Input {
        terminal_id: String,
        generation: String,
        stream_id: String,
        sequence: u64,
        bytes: String,
    },
    Resize {
        terminal_id: String,
        generation: String,
        stream_id: String,
        rows: u16,
        cols: u16,
    },
    Stop {
        terminal_id: String,
        generation: String,
        stream_id: String,
    },
    Attached {
        session: SessionInfo,
        stream_id: String,
    },
    Frame {
        terminal_id: String,
        generation: String,
        stream_id: String,
        offset: u64,
        bytes: String,
        reset: bool,
        complete: bool,
        rows: u16,
        cols: u16,
    },
    Written {
        terminal_id: String,
        generation: String,
        stream_id: String,
        sequence: u64,
        error: Option<String>,
    },
    Exited {
        terminal_id: String,
        generation: String,
        status: String,
    },
    Error {
        terminal_id: Option<String>,
        message: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionInfo {
    pub terminal_id: String,
    pub generation: String,
    pub provider: String,
    pub rows: u16,
    pub cols: u16,
    pub exit_status: Option<String>,
    pub rendering: String,
    pub width_profile: String,
}

/// One remote viewer's stream of canonical-screen frames (terminal-v1
/// `frame`/`exited`), opened by the session host's `subscribe`. Only one
/// bounded state transaction is outstanding: a slow viewer skips
/// intermediate redraws while the host goes on draining the PTY.
pub struct FrameStream {
    pub terminal_id: String,
    pub generation: String,
    pub stream_id: String,
    baseline: Option<vt100::Screen>,
    pending: VecDeque<u8>,
    reset: bool,
    size: (u16, u16),
    sent: u64,
    acked: u64,
    boundaries: VecDeque<u64>,
    exit_sent: bool,
}

/// The whole screen as ANSI: reset, contents, input modes. A terminal of the
/// screen's size shows the same screen after it.
pub fn restore_bytes(screen: &vt100::Screen) -> Vec<u8> {
    let mut bytes = b"\x1bc".to_vec();
    bytes.extend(screen.contents_formatted());
    bytes.extend(screen.input_mode_formatted());
    bytes
}

impl FrameStream {
    pub fn new(terminal_id: &str, generation: &str, stream_id: &str) -> Self {
        Self {
            terminal_id: terminal_id.into(),
            generation: generation.into(),
            stream_id: stream_id.into(),
            baseline: None,
            pending: VecDeque::new(),
            reset: true,
            size: (0, 0),
            sent: 0,
            acked: 0,
            boundaries: VecDeque::new(),
            exit_sent: false,
        }
    }

    /// The viewer acknowledged everything up to `offset` (a frame boundary).
    pub fn ack(&mut self, offset: u64) -> Result<(), String> {
        if offset == self.acked {
            return Ok(());
        }
        let position = self
            .boundaries
            .iter()
            .position(|end| *end == offset)
            .ok_or("Invalid terminal acknowledgement")?;
        self.boundaries.drain(..=position);
        self.acked = offset;
        Ok(())
    }

    /// The frames to send now for `screen`; once the final screen is
    /// acknowledged, `exited` with `exit_status`.
    pub fn frames(
        &mut self,
        screen: &vt100::Screen,
        exit_status: Option<&str>,
    ) -> Result<Vec<Message>, String> {
        if self.pending.is_empty() && self.sent == self.acked && !self.exit_sent {
            let reset = self
                .baseline
                .as_ref()
                .is_none_or(|prev| prev.size() != screen.size());
            let bytes = if reset {
                restore_bytes(screen)
            } else {
                let previous = self.baseline.as_ref().unwrap();
                let mut bytes = screen.contents_diff(previous);
                bytes.extend(screen.input_mode_diff(previous));
                bytes
            };
            if bytes.len() > RESTORE_BYTES {
                return Err("Terminal restore exceeds 1 MiB".into());
            }
            self.pending = bytes.into();
            self.reset = reset;
            self.size = screen.size();
            self.baseline = Some(screen.clone());
        }
        let mut frames = Vec::new();
        while !self.pending.is_empty() && self.sent - self.acked < WINDOW_BYTES {
            let count = self
                .pending
                .len()
                .min(FRAME_BYTES)
                .min((WINDOW_BYTES - (self.sent - self.acked)) as usize);
            let bytes: Vec<_> = self.pending.drain(..count).collect();
            let offset = self.sent;
            self.sent += count as u64;
            self.boundaries.push_back(self.sent);
            frames.push(Message::Frame {
                terminal_id: self.terminal_id.clone(),
                generation: self.generation.clone(),
                stream_id: self.stream_id.clone(),
                offset,
                bytes: STANDARD.encode(bytes),
                reset: self.reset,
                complete: self.pending.is_empty(),
                rows: self.size.0,
                cols: self.size.1,
            });
            self.reset = false;
        }
        if self.pending.is_empty()
            && self.sent == self.acked
            && !self.exit_sent
            && let Some(status) = exit_status
        {
            frames.push(Message::Exited {
                terminal_id: self.terminal_id.clone(),
                generation: self.generation.clone(),
                status: status.to_string(),
            });
            self.exit_sent = true;
        }
        Ok(frames)
    }
}

/// A session's terminal on the host: answers the CLI's terminal queries
/// from the canonical screen and keeps the exit status. Remote viewers get
/// frames through `FrameStream`s the session host opens.
pub struct SharedTerminal {
    /// This process's generation; tests use it to tell the same process.
    #[cfg_attr(not(test), allow(dead_code))]
    pub generation: String,
    utf8: Vec<u8>,
    queries: vte::Parser,
    pub exit_status: Option<String>,
}

impl SharedTerminal {
    pub fn new() -> Self {
        Self {
            generation: uuid::Uuid::new_v4().to_string(),
            utf8: Vec::new(),
            queries: vte::Parser::new(),
            exit_status: None,
        }
    }

    pub fn exited(&mut self, status: String, input: &PtyInput) {
        self.exit_status = Some(status);
        input.set_remote(false);
    }

    pub fn process(
        &mut self,
        parser: &mut vt100::Parser,
        input: &PtyInput,
        bytes: &[u8],
    ) -> String {
        let mut queries = Queries::default();
        for byte in bytes {
            parser.process(&[*byte]);
            self.queries.advance(&mut queries, *byte);
            for query in queries.pending.drain(..) {
                let response = match query {
                    Query::Cursor(private) => {
                        let (row, col) = parser.screen().cursor_position();
                        format!(
                            "\x1b[{}{};{}R",
                            if private { "?" } else { "" },
                            row + 1,
                            col + 1
                        )
                    }
                    Query::Literal(value) => value.into(),
                };
                let _ = input.respond(response.into_bytes());
            }
        }
        // Keep only an incomplete UTF-8 suffix between reads for the optional log.
        self.utf8.extend_from_slice(bytes);
        let mut text = String::new();
        loop {
            match std::str::from_utf8(&self.utf8) {
                Ok(valid) => {
                    text.push_str(valid);
                    self.utf8.clear();
                    break;
                }
                Err(error) => {
                    let valid = error.valid_up_to();
                    text.push_str(std::str::from_utf8(&self.utf8[..valid]).unwrap());
                    if let Some(invalid) = error.error_len() {
                        text.push('\u{fffd}');
                        self.utf8.drain(..valid + invalid);
                    } else {
                        self.utf8.drain(..valid);
                        break;
                    }
                }
            }
        }
        text
    }
}

enum Query {
    Cursor(bool),
    Literal(&'static str),
}
#[derive(Default)]
struct Queries {
    pending: Vec<Query>,
}
impl vte::Perform for Queries {
    fn csi_dispatch(
        &mut self,
        params: &vte::Params,
        intermediates: &[u8],
        ignore: bool,
        action: char,
    ) {
        if ignore {
            return;
        }
        let params: Vec<_> = params.iter().map(|p| p[0]).collect();
        let query = match (action, intermediates, params.as_slice()) {
            ('n', b"", [6]) => Query::Cursor(false),
            ('n', b"?", [6]) => Query::Cursor(true),
            ('n', b"", [5]) => Query::Literal("\x1b[0n"),
            ('c', b"", [0]) => Query::Literal("\x1b[?1;2c"),
            ('c', b">", [0]) => Query::Literal("\x1b[>0;0;0c"),
            ('u', b"?", [0]) => Query::Literal("\x1b[?0u"),
            _ => return,
        };
        self.pending.push(query);
    }
    fn osc_dispatch(&mut self, params: &[&[u8]], _bell_terminated: bool) {
        match params {
            [b"10", b"?"] => self
                .pending
                .push(Query::Literal("\x1b]10;rgb:ffff/ffff/ffff\x1b\\")),
            [b"11", b"?"] => self
                .pending
                .push(Query::Literal("\x1b]11;rgb:0000/0000/0000\x1b\\")),
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renderer_width_table_matches_every_unicode_scalar() {
        use unicode_width::UnicodeWidthChar;
        let ranges: Vec<[u32; 3]> =
            serde_json::from_str(include_str!("../assets/terminal/unicode-width-0.1.14.json"))
                .unwrap();
        let mut index = 0;
        for scalar in 0..=0x10ffff {
            while index < ranges.len() && ranges[index][1] < scalar {
                index += 1;
            }
            if let Some(character) = char::from_u32(scalar) {
                let width = if index < ranges.len() && ranges[index][0] <= scalar {
                    ranges[index][2] as usize
                } else {
                    1
                };
                assert_eq!(width, character.width().unwrap_or(0), "U+{scalar:04X}");
            }
        }
    }

    fn fixture() -> (SharedTerminal, vt100::Parser) {
        (SharedTerminal::new(), vt100::Parser::new(24, 80, 100))
    }

    fn subscribe(share: &SharedTerminal) -> FrameStream {
        FrameStream::new("ses-abcdefgh2345", &share.generation, "stream-1")
    }

    fn paint(stream: &mut FrameStream, host: &mut vt100::Parser, remote: &mut vt100::Parser) {
        for _ in 0..100 {
            let frames = stream.frames(host.screen(), None).unwrap();
            if frames.is_empty() {
                return;
            }
            for frame in frames {
                if let Message::Frame {
                    offset,
                    bytes,
                    reset,
                    rows,
                    cols,
                    ..
                } = frame
                {
                    if reset {
                        *remote = vt100::Parser::new(rows, cols, 0);
                    }
                    let bytes = STANDARD.decode(bytes).unwrap();
                    assert!(bytes.len() <= FRAME_BYTES);
                    remote.process(&bytes);
                    stream.ack(offset + bytes.len() as u64).unwrap();
                }
            }
        }
        panic!("screen stream did not settle");
    }

    fn same_screen(host: &vt100::Screen, remote: &vt100::Screen) {
        assert_eq!(host.size(), remote.size());
        let (rows, cols) = host.size();
        for row in 0..rows {
            for col in 0..cols {
                let a = host.cell(row, col).unwrap();
                let b = remote.cell(row, col).unwrap();
                assert_eq!(a, b, "cell {row},{col}");
            }
        }
        assert_eq!(host.cursor_position(), remote.cursor_position());
        assert_eq!(host.hide_cursor(), remote.hide_cursor());
        assert_eq!(host.application_cursor(), remote.application_cursor());
        assert_eq!(host.bracketed_paste(), remote.bracketed_paste());
    }

    #[test]
    fn utf8_and_queries_survive_every_byte_boundary() {
        let (mut share, mut parser) = fixture();
        let (input, mut captured) = PtyInput::test_channel();
        let bytes = "a\u{4e2d}\u{1f680}\x1b[6n\x1b[5n\x1b[c\x1b]11;?\x1b\\".as_bytes();
        let mut log = String::new();
        for byte in bytes {
            log.push_str(&share.process(&mut parser, &input, &[*byte]));
        }
        assert_eq!(log.as_bytes(), bytes);
        assert_eq!(parser.screen().contents(), "a\u{4e2d}\u{1f680}");
        assert_eq!(captured.try_recv().unwrap(), "\x1b[1;6R");
        assert_eq!(captured.try_recv().unwrap(), "\x1b[0n");
        assert_eq!(captured.try_recv().unwrap(), "\x1b[?1;2c");
        assert_eq!(
            captured.try_recv().unwrap(),
            "\x1b]11;rgb:0000/0000/0000\x1b\\"
        );
        assert!(captured.try_recv().is_err());
    }

    #[test]
    fn restore_and_diffs_preserve_cells_across_hidden_buffers_and_resize() {
        let (share, mut host) = fixture();
        let mut remote = vt100::Parser::new(24, 80, 0);
        host.process(b"main screen\x1b[s\x1b[?1049h\x1b[?2004h\x1b[?1h\x1b[31malt");
        let mut stream = subscribe(&share);
        paint(&mut stream, &mut host, &mut remote);
        same_screen(host.screen(), remote.screen());
        for bytes in [
            b"\r\n\x1b[38;2;12;34;56mcolored".as_slice(),
            "\r\n\u{4e2d}\u{1f680}".as_bytes(),
            b"\x1b[?1049l\x1b[u restored",
            b"\x1b[2;5r\x1b[2;1Hone\ntwo\nthree\nfour\nfive\x1b[r\x1b[?25l",
        ] {
            host.process(bytes);
            paint(&mut stream, &mut host, &mut remote);
            same_screen(host.screen(), remote.screen());
        }
        host.set_size(30, 100);
        paint(&mut stream, &mut host, &mut remote);
        same_screen(host.screen(), remote.screen());
    }

    #[test]
    fn invalid_ack_is_rejected() {
        let (share, host) = fixture();
        let mut stream = subscribe(&share);
        stream.frames(host.screen(), None).unwrap();
        assert!(stream.ack(9999999).is_err());
    }

    #[test]
    fn slow_viewer_bounds_memory_and_catches_up_to_latest_screen() {
        let (share, mut host) = fixture();
        host.set_size(100, 200);
        for i in 0..19000 {
            host.process(
                format!(
                    "\x1b[38;2;{};{};{}mx",
                    i % 256,
                    (i / 3) % 256,
                    (i / 7) % 256
                )
                .as_bytes(),
            );
        }
        let mut stream = subscribe(&share);
        let initial = stream.frames(host.screen(), None).unwrap();
        assert_eq!(stream.sent - stream.acked, WINDOW_BYTES);
        assert!(stream.pending.len() <= RESTORE_BYTES);
        for _ in 0..100 {
            host.process(b"\r\nnew output");
            assert!(stream.frames(host.screen(), None).unwrap().is_empty());
        }
        let mut remote = vt100::Parser::new(100, 200, 0);
        for frame in initial {
            if let Message::Frame { offset, bytes, .. } = frame {
                let bytes = STANDARD.decode(bytes).unwrap();
                remote.process(&bytes);
                stream.ack(offset + bytes.len() as u64).unwrap();
            }
        }
        paint(&mut stream, &mut host, &mut remote);
        same_screen(host.screen(), remote.screen());
    }

    #[test]
    fn final_screen_precedes_exit() {
        let (share, mut host) = fixture();
        let mut stream = subscribe(&share);
        host.process(b"final output");
        let frames = stream.frames(host.screen(), Some("exit 0")).unwrap();
        assert!(frames.iter().all(|f| matches!(f, Message::Frame { .. })));
        assert!(
            stream
                .frames(host.screen(), Some("exit 0"))
                .unwrap()
                .is_empty()
        );
        stream.ack(stream.sent).unwrap();
        assert!(matches!(
            stream.frames(host.screen(), Some("exit 0")).unwrap()[0],
            Message::Exited { .. }
        ));
        assert!(
            stream
                .frames(host.screen(), Some("exit 0"))
                .unwrap()
                .is_empty()
        );
        // A new subscription starts with a full screen.
        let mut again = subscribe(&share);
        assert!(matches!(
            again.frames(host.screen(), Some("exit 0")).unwrap()[0],
            Message::Frame { reset: true, .. }
        ));
    }

    #[test]
    fn wire_envelope_is_versioned_and_relay_compatible() {
        let outer = crate::websocket_client::AstationMessage::Terminal(
            Message::Subscribe {
                terminal_id: "ses-abcdefgh2345".into(),
                generation: "g".into(),
            }
            .into(),
        );
        let json = serde_json::to_value(outer).unwrap();
        assert_eq!(
            json,
            serde_json::json!({"type":"terminal","data":{
                "v":1,"op":"subscribe","terminal_id":"ses-abcdefgh2345","generation":"g"}})
        );
        serde_json::from_value::<crate::websocket_client::AstationMessage>(json).unwrap();
    }
}
