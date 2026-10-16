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

impl Message {
    /// The terminal a request names (`None` for replies).
    pub fn request_terminal_id(&self) -> Option<&str> {
        match self {
            Message::Subscribe { terminal_id, .. }
            | Message::Unsubscribe { terminal_id, .. }
            | Message::Ack { terminal_id, .. }
            | Message::Input { terminal_id, .. }
            | Message::Resize { terminal_id, .. }
            | Message::Stop { terminal_id, .. } => Some(terminal_id),
            _ => None,
        }
    }
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

struct Viewer {
    id: String,
    baseline: Option<vt100::Screen>,
    pending: VecDeque<u8>,
    reset: bool,
    size: (u16, u16),
    sent: u64,
    acked: u64,
    boundaries: VecDeque<u64>,
}

/// The whole screen as ANSI: reset, contents, input modes. A terminal of the
/// screen's size shows the same screen after it.
pub fn restore_bytes(screen: &vt100::Screen) -> Vec<u8> {
    let mut bytes = b"\x1bc".to_vec();
    bytes.extend(screen.contents_formatted());
    bytes.extend(screen.input_mode_formatted());
    bytes
}

pub struct SharedTerminal {
    pub id: String,
    pub generation: String,
    provider: String,
    viewer: Option<Viewer>,
    utf8: Vec<u8>,
    queries: vte::Parser,
    pub exit_status: Option<String>,
    exit_sent: bool,
}

impl SharedTerminal {
    /// `id` is the session id (the terminal id on the wire).
    pub fn new(id: &str, provider: &str) -> Self {
        Self {
            id: id.into(),
            generation: uuid::Uuid::new_v4().to_string(),
            provider: provider.into(),
            viewer: None,
            utf8: Vec::new(),
            queries: vte::Parser::new(),
            exit_status: None,
            exit_sent: false,
        }
    }

    pub fn info(&self, screen: &vt100::Screen) -> SessionInfo {
        let (rows, cols) = screen.size();
        SessionInfo {
            terminal_id: self.id.clone(),
            generation: self.generation.clone(),
            provider: self.provider.clone(),
            rows,
            cols,
            exit_status: self.exit_status.clone(),
            rendering: "vt100-screen-diff".into(),
            width_profile: "atem-unicode-width-0.1.14".into(),
        }
    }

    #[cfg(test)]
    pub fn has_viewer(&self) -> bool {
        self.viewer.is_some()
    }

    pub fn exited(&mut self, status: String, input: &PtyInput) {
        self.exit_status = Some(status);
        input.set_remote(false);
    }

    pub fn disconnect(&mut self, input: &PtyInput) {
        input.set_remote(false);
        self.viewer = None;
    }

    /// A viewer's request: `subscribe`, `unsubscribe` or `ack`. Viewing never
    /// changes the session; remote input, resize and stop are not handled
    /// here (the App refuses them until atem-session v1 grants a lease).
    pub fn handle(
        &mut self,
        message: Message,
        screen: &vt100::Screen,
        input: &PtyInput,
    ) -> Result<Vec<Message>, String> {
        let (terminal_id, generation) = match &message {
            Message::Subscribe {
                terminal_id,
                generation,
            }
            | Message::Unsubscribe {
                terminal_id,
                generation,
                ..
            }
            | Message::Ack {
                terminal_id,
                generation,
                ..
            } => (terminal_id, generation),
            _ => return Err("Expected a terminal view request".into()),
        };
        if terminal_id != &self.id || generation != &self.generation {
            return Err("Terminal process is no longer available; refresh the session list".into());
        }
        if matches!(message, Message::Subscribe { .. }) {
            self.disconnect(input);
            self.exit_sent = false;
            let id = uuid::Uuid::new_v4().to_string();
            let response = Message::Attached {
                session: self.info(screen),
                stream_id: id.clone(),
            };
            self.viewer = Some(Viewer {
                id,
                baseline: None,
                pending: VecDeque::new(),
                reset: true,
                size: screen.size(),
                sent: 0,
                acked: 0,
                boundaries: VecDeque::new(),
            });
            return Ok(vec![response]);
        }
        let viewer = self
            .viewer
            .as_mut()
            .ok_or("Subscribe to the terminal first")?;
        let stream_id = match &message {
            Message::Unsubscribe { stream_id, .. } | Message::Ack { stream_id, .. } => stream_id,
            _ => unreachable!(),
        };
        if stream_id != &viewer.id {
            return Err("Stale terminal stream".into());
        }
        match message {
            Message::Unsubscribe { .. } => {
                self.disconnect(input);
                Ok(vec![])
            }
            Message::Ack { offset, .. } => {
                if offset == viewer.acked {
                    return Ok(vec![]);
                }
                let position = viewer
                    .boundaries
                    .iter()
                    .position(|end| *end == offset)
                    .ok_or("Invalid terminal acknowledgement")?;
                viewer.boundaries.drain(..=position);
                viewer.acked = offset;
                Ok(vec![])
            }
            _ => unreachable!(),
        }
    }

    /// Only one bounded state transaction is outstanding. A slow viewer skips
    /// intermediate redraws while the host continues to drain the PTY normally.
    pub fn frames(&mut self, screen: &vt100::Screen) -> Result<Vec<Message>, String> {
        let Some(viewer) = &mut self.viewer else {
            return Ok(vec![]);
        };
        if viewer.pending.is_empty() && viewer.sent == viewer.acked {
            let reset = viewer
                .baseline
                .as_ref()
                .is_none_or(|prev| prev.size() != screen.size());
            let bytes = if reset {
                restore_bytes(screen)
            } else {
                let previous = viewer.baseline.as_ref().unwrap();
                let mut bytes = screen.contents_diff(previous);
                bytes.extend(screen.input_mode_diff(previous));
                bytes
            };
            if bytes.len() > RESTORE_BYTES {
                return Err("Terminal restore exceeds 1 MiB".into());
            }
            viewer.pending = bytes.into();
            viewer.reset = reset;
            viewer.size = screen.size();
            viewer.baseline = Some(screen.clone());
        }
        let mut frames = Vec::new();
        while !viewer.pending.is_empty() && viewer.sent - viewer.acked < WINDOW_BYTES {
            let count = viewer
                .pending
                .len()
                .min(FRAME_BYTES)
                .min((WINDOW_BYTES - (viewer.sent - viewer.acked)) as usize);
            let bytes: Vec<_> = viewer.pending.drain(..count).collect();
            let offset = viewer.sent;
            viewer.sent += count as u64;
            viewer.boundaries.push_back(viewer.sent);
            frames.push(Message::Frame {
                terminal_id: self.id.clone(),
                generation: self.generation.clone(),
                stream_id: viewer.id.clone(),
                offset,
                bytes: STANDARD.encode(bytes),
                reset: viewer.reset,
                complete: viewer.pending.is_empty(),
                rows: viewer.size.0,
                cols: viewer.size.1,
            });
            viewer.reset = false;
        }
        if viewer.pending.is_empty()
            && viewer.sent == viewer.acked
            && !self.exit_sent
            && let Some(status) = &self.exit_status
        {
            frames.push(Message::Exited {
                terminal_id: self.id.clone(),
                generation: self.generation.clone(),
                status: status.clone(),
            });
            self.exit_sent = true;
        }
        Ok(frames)
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

    fn fixture() -> (
        SharedTerminal,
        vt100::Parser,
        crate::pty_session::PtySession,
    ) {
        (
            SharedTerminal::new("ses-abcdefgh2345", "codex"),
            vt100::Parser::new(24, 80, 100),
            crate::pty_session::spawn("cat", &[]).unwrap(),
        )
    }

    fn subscribe(
        share: &mut SharedTerminal,
        parser: &mut vt100::Parser,
        pty: &crate::pty_session::PtySession,
    ) -> String {
        let message = Message::Subscribe {
            terminal_id: share.id.clone(),
            generation: share.generation.clone(),
        };
        let result = share.handle(message, parser.screen(), &pty.sender).unwrap();
        match &result[0] {
            Message::Attached { stream_id, .. } => stream_id.clone(),
            _ => panic!(),
        }
    }

    fn paint(
        share: &mut SharedTerminal,
        host: &mut vt100::Parser,
        remote: &mut vt100::Parser,
        pty: &crate::pty_session::PtySession,
    ) {
        for _ in 0..100 {
            let frames = share.frames(host.screen()).unwrap();
            if frames.is_empty() {
                return;
            }
            for frame in frames {
                if let Message::Frame {
                    terminal_id,
                    generation,
                    stream_id,
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
                    share
                        .handle(
                            Message::Ack {
                                terminal_id,
                                generation,
                                stream_id,
                                offset: offset + bytes.len() as u64,
                            },
                            host.screen(),
                            &pty.sender,
                        )
                        .unwrap();
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
        let (mut share, mut parser, _pty) = fixture();
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
        let (mut share, mut host, pty) = fixture();
        let mut remote = vt100::Parser::new(24, 80, 0);
        host.process(b"main screen\x1b[s\x1b[?1049h\x1b[?2004h\x1b[?1h\x1b[31malt");
        subscribe(&mut share, &mut host, &pty);
        paint(&mut share, &mut host, &mut remote, &pty);
        same_screen(host.screen(), remote.screen());
        for bytes in [
            b"\r\n\x1b[38;2;12;34;56mcolored".as_slice(),
            "\r\n\u{4e2d}\u{1f680}".as_bytes(),
            b"\x1b[?1049l\x1b[u restored",
            b"\x1b[2;5r\x1b[2;1Hone\ntwo\nthree\nfour\nfive\x1b[r\x1b[?25l",
        ] {
            host.process(bytes);
            paint(&mut share, &mut host, &mut remote, &pty);
            same_screen(host.screen(), remote.screen());
        }
        host.set_size(30, 100);
        paint(&mut share, &mut host, &mut remote, &pty);
        same_screen(host.screen(), remote.screen());
    }

    #[test]
    fn attach_is_view_only_and_mutations_are_not_handled_here() {
        let (mut share, mut host, pty) = fixture();
        let stream = subscribe(&mut share, &mut host, &pty);
        assert!(!pty.sender.remote_controlled());
        for request in [
            Message::Input {
                terminal_id: share.id.clone(),
                generation: share.generation.clone(),
                stream_id: stream.clone(),
                sequence: 0,
                bytes: STANDARD.encode(b"hello\r"),
            },
            Message::Resize {
                terminal_id: share.id.clone(),
                generation: share.generation.clone(),
                stream_id: stream.clone(),
                rows: 30,
                cols: 100,
            },
            Message::Stop {
                terminal_id: share.id.clone(),
                generation: share.generation.clone(),
                stream_id: stream.clone(),
            },
        ] {
            assert!(share.handle(request, host.screen(), &pty.sender).is_err());
        }
        assert!(!pty.sender.remote_controlled());
        assert_eq!(host.screen().size(), (24, 80));
        // A new subscription replaces the old stream.
        share.disconnect(&pty.sender);
        subscribe(&mut share, &mut host, &pty);
        let stale = Message::Unsubscribe {
            terminal_id: share.id.clone(),
            generation: share.generation.clone(),
            stream_id: stream,
        };
        assert!(share.handle(stale, host.screen(), &pty.sender).is_err());
        assert!(share.has_viewer());
    }

    #[test]
    fn stale_process_and_invalid_ack_are_rejected() {
        let (mut share, mut host, pty) = fixture();
        assert!(
            share
                .handle(
                    Message::Subscribe {
                        terminal_id: share.id.clone(),
                        generation: "old-process".into()
                    },
                    host.screen(),
                    &pty.sender
                )
                .is_err()
        );
        let stream = subscribe(&mut share, &mut host, &pty);
        share.frames(host.screen()).unwrap();
        assert!(
            share
                .handle(
                    Message::Ack {
                        terminal_id: share.id.clone(),
                        generation: share.generation.clone(),
                        stream_id: stream,
                        offset: 9999999
                    },
                    host.screen(),
                    &pty.sender
                )
                .is_err()
        );
    }

    #[test]
    fn slow_viewer_bounds_memory_and_catches_up_to_latest_screen() {
        let (mut share, mut host, pty) = fixture();
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
        subscribe(&mut share, &mut host, &pty);
        let initial = share.frames(host.screen()).unwrap();
        let viewer = share.viewer.as_ref().unwrap();
        assert_eq!(viewer.sent - viewer.acked, WINDOW_BYTES);
        assert!(viewer.pending.len() <= RESTORE_BYTES);
        for _ in 0..100 {
            host.process(b"\r\nnew output");
            assert!(share.frames(host.screen()).unwrap().is_empty());
        }
        let mut remote = vt100::Parser::new(100, 200, 0);
        for frame in initial {
            if let Message::Frame {
                terminal_id,
                generation,
                stream_id,
                offset,
                bytes,
                ..
            } = frame
            {
                let bytes = STANDARD.decode(bytes).unwrap();
                remote.process(&bytes);
                share
                    .handle(
                        Message::Ack {
                            terminal_id,
                            generation,
                            stream_id,
                            offset: offset + bytes.len() as u64,
                        },
                        host.screen(),
                        &pty.sender,
                    )
                    .unwrap();
            }
        }
        paint(&mut share, &mut host, &mut remote, &pty);
        same_screen(host.screen(), remote.screen());
    }

    #[test]
    fn final_screen_precedes_exit_and_read_only_reconnect_still_works() {
        let (mut share, mut host, pty) = fixture();
        subscribe(&mut share, &mut host, &pty);
        host.process(b"final output");
        share.exited("exit 0".into(), &pty.sender);
        let frames = share.frames(host.screen()).unwrap();
        assert!(frames.iter().all(|f| matches!(f, Message::Frame { .. })));
        assert!(share.frames(host.screen()).unwrap().is_empty());
        let viewer = share.viewer.as_ref().unwrap();
        share
            .handle(
                Message::Ack {
                    terminal_id: share.id.clone(),
                    generation: share.generation.clone(),
                    stream_id: viewer.id.clone(),
                    offset: viewer.sent,
                },
                host.screen(),
                &pty.sender,
            )
            .unwrap();
        assert!(matches!(
            share.frames(host.screen()).unwrap()[0],
            Message::Exited { .. }
        ));
        subscribe(&mut share, &mut host, &pty);
        assert!(matches!(
            share.frames(host.screen()).unwrap()[0],
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
