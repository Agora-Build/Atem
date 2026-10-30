//! The local frontend of one runtime session (`atem agent launch|attach`,
//! and the menu's agent entries): a local parser fed by the runtime's
//! restore and output, keys, paste and resize sent back as `input` and
//! `resize`, and the status row, prefix keys, history and copy kept here.
//! Detaching leaves the session running in its worker.

use super::{clipboard, draw, terminal_view};
use crate::runtime::client::{RuntimeClient, RuntimeWriter};
use crate::runtime::protocol::{
    ClientMsg, MAX_INPUT, MAX_PASTE, RuntimeMsg, SessionSummary, unb64,
};
use crate::session::Provider;
use anyhow::{Result, anyhow};
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind};
use ratatui::{
    Frame, Terminal,
    backend::Backend,
    layout::Rect,
    style::{Color, Style},
    widgets::{Block, Borders, Clear, Paragraph, Wrap},
};
use std::time::{Duration, Instant};
use terminal_view::Action;
use tokio::sync::mpsc;

/// How long a detach waits for the runtime's confirmation.
const DETACH_WAIT: Duration = Duration::from_secs(2);

/// Why a frontend ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrontendExit {
    /// The user detached; the session keeps running.
    Detached,
    /// The agent exited with this status (the user closed the final screen).
    Exited(String),
    /// The runtime detached this frontend (attached elsewhere, removed).
    DetachedBy(String),
    /// The runtime closed the connection.
    RuntimeGone,
}

impl FrontendExit {
    /// The line printed once the terminal is restored.
    pub fn message(&self, sid: &str) -> String {
        let manage =
            format!("Reattach: atem agent attach {sid} \u{b7} Stop: atem agent stop {sid}");
        match self {
            FrontendExit::Detached => format!("Session {sid} is still running. {manage}"),
            FrontendExit::Exited(status) => format!("Session {sid} exited ({status})."),
            FrontendExit::DetachedBy(reason) => {
                format!("Session {sid} was detached here ({reason}) and is still running. {manage}")
            }
            FrontendExit::RuntimeGone => format!(
                "The atem runtime closed the connection; session {sid} keeps running in its worker. {manage}"
            ),
        }
    }
}

/// The frontend's state, apart from the terminal and the connection.
pub struct View {
    pub sid: String,
    pub summary: Option<SessionSummary>,
    /// The session's screen as the runtime's restore and output build it.
    pub parser: vt100::Parser,
    /// The stream position the next output byte has.
    pub next_offset: u64,
    pub astation: bool,
    /// The runtime's r9 device list, when it has one (the row shows its
    /// label: held, frozen, paused, failed, recovery pending).
    pub device_list: Option<crate::runtime::protocol::DeviceListStatus>,
    pub ui: terminal_view::State,
    /// The agent's exit status once it ended.
    pub exited: Option<String>,
    /// Clear the outer terminal before the next draw.
    pub redraw: bool,
}

/// What a runtime message means for the frontend.
#[derive(Debug, PartialEq, Eq)]
pub enum Applied {
    Continue,
    End(FrontendExit),
    /// The runtime refused the attach.
    Failed(String),
    /// The runtime is restarting (another atem asked for it): reattach to
    /// the next one.
    Reattach,
}

impl View {
    pub fn new(sid: &str, astation: bool, prefix: Option<&str>) -> Self {
        Self {
            sid: sid.to_string(),
            summary: None,
            parser: vt100::Parser::new(24, 80, crate::pty_session::SCROLLBACK_ROWS),
            next_offset: 0,
            astation,
            device_list: None,
            ui: terminal_view::State::new(prefix),
            exited: None,
            redraw: false,
        }
    }

    fn notice(&mut self, text: String) {
        self.ui.record(text.clone());
        self.ui.feedback = Some((text, Instant::now()));
    }

    pub fn apply(&mut self, message: RuntimeMsg) -> Applied {
        match message {
            RuntimeMsg::Attached {
                session,
                restore,
                offset,
            } if session.id == self.sid => {
                self.parser = vt100::Parser::new(
                    session.rows.max(2),
                    session.cols.max(2),
                    crate::pty_session::SCROLLBACK_ROWS,
                );
                self.parser.process(&unb64(&restore).unwrap_or_default());
                self.next_offset = offset;
                self.summary = Some(session);
                self.ui.browse = None;
                self.redraw = true;
            }
            RuntimeMsg::Output {
                session_id,
                bytes,
                offset,
            } if session_id == self.sid => {
                let bytes = unb64(&bytes).unwrap_or_default();
                let end = offset + bytes.len() as u64;
                if end > self.next_offset {
                    let skip = self.next_offset.saturating_sub(offset) as usize;
                    self.parser.process(&bytes[skip..]);
                    self.next_offset = end;
                }
            }
            RuntimeMsg::Session { session } if session.id == self.sid => {
                self.summary = Some(session);
            }
            RuntimeMsg::Exited {
                session_id, status, ..
            } if session_id == self.sid => {
                self.exited = Some(status);
            }
            RuntimeMsg::Detached { session_id, reason } if session_id == self.sid => {
                return Applied::End(if reason == "detached" {
                    FrontendExit::Detached
                } else {
                    FrontendExit::DetachedBy(reason)
                });
            }
            RuntimeMsg::Restarting => {
                self.notice("Atem's runtime is restarting; reattaching…".into());
                return Applied::Reattach;
            }
            RuntimeMsg::Astation { connected } => self.astation = connected,
            RuntimeMsg::DeviceList { status } => {
                // A new state is a notice (its text says what to do).
                if let Some(s) = status.as_ref().filter(|s| s.label.is_some())
                    && self.device_list.as_ref().map(|d| &d.text) != Some(&s.text)
                {
                    self.notice(format!("Device list: {}", s.text));
                }
                self.device_list = status;
            }
            RuntimeMsg::Notice { text } => self.notice(text),
            RuntimeMsg::Error { text, op } if op.as_deref() == Some("attach") => {
                return Applied::Failed(text);
            }
            RuntimeMsg::Error { text, .. } => self.notice(text),
            _ => {}
        }
        Applied::Continue
    }

    fn provider(&self) -> &'static str {
        self.summary
            .as_ref()
            .and_then(|s| Provider::from_alias(&s.provider))
            .map_or("Agent", |p| p.label())
    }

    /// The status row (`Atem | Claude|Codex | Local|Remote | Astation ✓|✗ …`).
    pub fn status_line(&self) -> String {
        let prefix = self.ui.prefix.label();
        if self.ui.help {
            return "Atem | Esc: close help | Up/Down: scroll details".to_string();
        }
        if self.ui.pending {
            return format!(
                "{prefix} | h:detach g:take a:answered x:stop r:redraw [:history c:copy ?:help"
            );
        }
        if let Some(browse) = &self.ui.browse {
            return format!(
                "Atem | history +{} | arrows:move Space:select Enter:copy PgUp/PgDn:scroll Esc:live",
                browse.offset
            );
        }
        if let Some((message, _)) = self
            .ui
            .feedback
            .as_ref()
            .filter(|(_, when)| when.elapsed().as_secs() < 4)
        {
            return format!("Atem | {message}");
        }
        let provider = self.provider();
        if let Some(status) = &self.exited {
            return format!(
                "Atem | {provider} | Exited ({status}) | any key: close | {prefix} then [:history c:copy"
            );
        }
        let control = if self.summary.as_ref().is_some_and(|s| s.remote_controlled) {
            "Remote"
        } else {
            "Local"
        };
        let link = if self.astation { "✓" } else { "✗" };
        let list = self
            .device_list
            .as_ref()
            .and_then(|d| d.label.as_deref())
            .map(|label| format!(" | {label}"))
            .unwrap_or_default();
        let notice = if self.ui.messages.is_empty() {
            ""
        } else {
            " | Notice"
        };
        format!(
            "Atem | {provider} | {control} | Astation {link}{list}{notice} | {prefix} then ?:help"
        )
    }

    /// History at `offset` rows back, from the local parser.
    pub fn browse(&mut self, offset: usize) {
        // Browsing never changes the live screen.
        self.parser.set_scrollback(offset);
        let screen = self.parser.screen().clone();
        let offset = screen.scrollback();
        self.parser.set_scrollback(0);
        let (rows, cols) = screen.size();
        let (vrows, vcols) = self.ui.viewport;
        let rows = if vrows == 0 { rows } else { rows.min(vrows) };
        let cols = if vcols == 0 { cols } else { cols.min(vcols) };
        let cursor = self.ui.browse.as_ref().map_or((0, 0), |b| b.cursor);
        self.ui.browse = Some(terminal_view::Browse {
            screen,
            viewport: (rows, cols),
            offset,
            cursor: (cursor.0.min(rows - 1), cursor.1.min(cols - 1)),
            anchor: None,
        });
    }

    /// The text a copy takes: the selection, else the visible screen.
    pub fn copy_text(&self) -> String {
        match &self.ui.browse {
            Some(view) => view.text(),
            None => terminal_view::visible_text(self.parser.screen(), self.ui.viewport),
        }
    }

    /// A paste as one `paste` message: the runtime writes it whole
    /// (bracketed when the agent asked for it), revoking a remote lease once.
    pub fn paste(&self, text: &str) -> Result<ClientMsg, String> {
        if text.len() > MAX_PASTE {
            return Err("Paste exceeds 1 MiB; it was not sent".into());
        }
        Ok(ClientMsg::paste(&self.sid, text))
    }

    pub fn draw(&self, frame: &mut Frame) {
        let size = frame.area();
        frame.render_widget(Clear, size);
        let area = terminal_view::viewport(size);
        let screen = self
            .ui
            .browse
            .as_ref()
            .map_or(self.parser.screen(), |b| &b.screen);
        draw::draw_terminal_screen(frame, area, screen, self.ui.browse.as_ref(), self.ui.help);
        if size.height > 0 {
            frame.render_widget(
                Paragraph::new(self.status_line()).style(Style::default().fg(Color::Cyan)),
                Rect {
                    y: size.y + size.height - 1,
                    height: 1,
                    ..size
                },
            );
        }
        if self.ui.help {
            let area = draw::centered_rect(85, 85, size);
            frame.render_widget(Clear, area);
            frame.render_widget(
                Paragraph::new(help_text(&self.ui))
                    .wrap(Wrap { trim: false })
                    .scroll((self.ui.help_scroll, 0))
                    .block(
                        Block::default()
                            .borders(Borders::ALL)
                            .title("Atem terminal controls"),
                    ),
                area,
            );
        }
    }
}

/// `bytes` in pieces of at most `MAX_INPUT`.
fn pieces(bytes: &[u8]) -> Vec<Vec<u8>> {
    bytes.chunks(MAX_INPUT).map(<[u8]>::to_vec).collect()
}

fn help_text(ui: &terminal_view::State) -> String {
    let prefix = ui.prefix.label();
    let mut text = format!(
        "{prefix}, then:\n\nh / m  Detach; the session keeps running (atem agent attach reopens it)\ng      Take control back from a remote viewer\na      An approval was answered here, in the agent's own dialog: end its wait\n       (Atem can't tell from the agent; chat prompts are held until then)\nx      Stop the agent\nr      Redraw the screen\n[      Browse local history\nc      Copy the visible terminal text\n?      Open these details\n\nPress the prefix twice to send it to the agent.\nterminal_prefix in ~/.config/atem/config.toml or ATEM_TERMINAL_PREFIX changes the prefix (for example Ctrl-a).\n\nHistory: arrows move, Space starts a selection, Enter copies; Esc returns live.\nMouse selection stays with your terminal or tmux.\nCopy requests use the tmux buffer or OSC 52; the outer terminal must support clipboard access.\n\nRecent notices (newest first):\n"
    );
    for message in ui.messages.iter().rev() {
        text.push('\n');
        text.push_str(message);
        text.push('\n');
    }
    text
}

/// The canonical screen size for a local terminal of `size` (one row for status).
pub fn viewport_size(size: ratatui::layout::Size) -> (u16, u16) {
    (
        size.height.saturating_sub(1).clamp(2, 200),
        size.width.clamp(2, 400),
    )
}

/// The frontend on its own: enters the alternate screen, attaches to `sid`,
/// and prints the line saying how the session was left.
pub async fn run_frontend(client: RuntimeClient, sid: &str) -> Result<FrontendExit> {
    let diagnostics = crate::diagnostics::Capture::start();
    let exit = {
        let _guard = super::TerminalGuard::enter()?;
        let mut terminal =
            Terminal::new(ratatui::backend::CrosstermBackend::new(std::io::stdout()))?;
        attach_in(&mut terminal, client, sid, &diagnostics).await
    };
    for warning in diagnostics.drain() {
        eprintln!("{warning}");
    }
    let exit = exit?;
    println!("{}", exit.message(sid));
    Ok(exit)
}

/// Attaches to `sid` and runs the frontend in `terminal` (already in raw
/// mode on the alternate screen) until it ends.
pub async fn attach_in<B: Backend>(
    terminal: &mut Terminal<B>,
    client: RuntimeClient,
    sid: &str,
    diagnostics: &crate::diagnostics::Capture,
) -> Result<FrontendExit> {
    let prefix = crate::config::AtemConfig::load()
        .unwrap_or_default()
        .terminal_prefix;
    let mut view = View::new(sid, client.welcome.astation, prefix.as_deref());
    view.device_list = client.welcome.device_list.clone();
    let mut client = client;
    loop {
        let (mut reader, mut writer) = client.split();
        let (tx, mut rx) = mpsc::unbounded_channel();
        let reading = tokio::spawn(async move {
            while let Ok(Some(message)) = reader.recv().await {
                if tx.send(message).is_err() {
                    break;
                }
            }
        });
        let (rows, cols) = viewport_size(terminal.size()?);
        view.ui.viewport = (rows, cols);
        let result = async {
            writer
                .send(&ClientMsg::Attach {
                    session_id: sid.to_string(),
                    rows,
                    cols,
                })
                .await?;
            terminal.clear()?;
            run_loop(terminal, &mut view, &mut writer, &mut rx, diagnostics).await
        }
        .await;
        reading.abort();
        match result? {
            Some(exit) => return Ok(exit),
            // The runtime restarted: the same session from the next one
            // (its worker kept running), restored on `attached`.
            None => {
                terminal.draw(|frame| view.draw(frame))?;
                client = RuntimeClient::reconnect().await?;
                view.astation = client.welcome.astation;
                view.device_list = client.welcome.device_list.clone();
            }
        }
    }
}

async fn run_loop<B: Backend>(
    terminal: &mut Terminal<B>,
    view: &mut View,
    writer: &mut RuntimeWriter,
    rx: &mut mpsc::UnboundedReceiver<RuntimeMsg>,
    diagnostics: &crate::diagnostics::Capture,
) -> Result<Option<FrontendExit>> {
    loop {
        for message in diagnostics.drain() {
            view.ui.record(message);
        }
        loop {
            match rx.try_recv() {
                Ok(message) => match view.apply(message) {
                    Applied::Continue => {}
                    Applied::End(exit) => return Ok(Some(exit)),
                    Applied::Failed(text) => return Err(anyhow!(text)),
                    Applied::Reattach => return Ok(None),
                },
                Err(mpsc::error::TryRecvError::Empty) => break,
                Err(mpsc::error::TryRecvError::Disconnected) => {
                    return Ok(Some(match view.exited.take() {
                        Some(status) => FrontendExit::Exited(status),
                        None => FrontendExit::RuntimeGone,
                    }));
                }
            }
        }
        if view.redraw {
            view.redraw = false;
            terminal.clear()?;
        }
        terminal.draw(|frame| view.draw(frame))?;
        // Events that are ready, without blocking the runtime's messages long.
        let mut timeout = Duration::from_millis(10);
        while event::poll(timeout)? {
            timeout = Duration::ZERO;
            if let Some(exit) = handle_event(view, writer, rx, event::read()?).await? {
                return Ok(Some(exit));
            }
        }
    }
}

async fn send_bytes(view: &View, writer: &mut RuntimeWriter, bytes: &[u8]) -> Result<()> {
    for piece in pieces(bytes) {
        writer.send(&ClientMsg::input(&view.sid, &piece)).await?;
    }
    Ok(())
}

async fn handle_event(
    view: &mut View,
    writer: &mut RuntimeWriter,
    rx: &mut mpsc::UnboundedReceiver<RuntimeMsg>,
    event: Event,
) -> Result<Option<FrontendExit>> {
    match event {
        Event::Resize(width, height) => {
            view.ui.reset_view();
            view.redraw = true;
            let (rows, cols) = viewport_size(ratatui::layout::Size { width, height });
            view.ui.viewport = (rows, cols);
            writer
                .send(&ClientMsg::Resize {
                    session_id: view.sid.clone(),
                    rows,
                    cols,
                })
                .await?;
        }
        Event::Paste(text) => {
            if view.ui.help {
                view.notice("Close help before pasting into the agent".into());
            } else if view.exited.is_none() && !text.is_empty() {
                view.ui.browse = None;
                if view.ui.pending {
                    view.ui.pending = false;
                    send_bytes(view, writer, view.ui.prefix.bytes().as_bytes()).await?;
                }
                match view.paste(&text) {
                    Ok(message) => writer.send(&message).await?,
                    Err(text) => view.notice(text),
                }
            }
        }
        Event::Key(key) if key.kind != KeyEventKind::Release => {
            return handle_key(view, writer, rx, key).await;
        }
        _ => {}
    }
    Ok(None)
}

async fn copy(view: &mut View) {
    let text = view.copy_text();
    let message = match clipboard::copy(&text).await {
        Ok(message) => {
            view.ui.browse = None;
            message.to_string()
        }
        Err(error) => error.to_string(),
    };
    view.notice(message);
}

/// Sends `detach` and waits (bounded) for the runtime to confirm.
async fn detach(
    view: &View,
    writer: &mut RuntimeWriter,
    rx: &mut mpsc::UnboundedReceiver<RuntimeMsg>,
) -> FrontendExit {
    let sent = writer
        .send(&ClientMsg::Detach {
            session_id: view.sid.clone(),
        })
        .await;
    if sent.is_ok() {
        let _ = tokio::time::timeout(DETACH_WAIT, async {
            while let Some(message) = rx.recv().await {
                if matches!(&message, RuntimeMsg::Detached { session_id, .. } if *session_id == view.sid)
                    || matches!(&message, RuntimeMsg::Error { op, .. } if op.as_deref() == Some("detach"))
                {
                    break;
                }
            }
        })
        .await;
    }
    FrontendExit::Detached
}

async fn handle_key(
    view: &mut View,
    writer: &mut RuntimeWriter,
    rx: &mut mpsc::UnboundedReceiver<RuntimeMsg>,
    key: KeyEvent,
) -> Result<Option<FrontendExit>> {
    if view.ui.help {
        let scroll = &mut view.ui.help_scroll;
        match key.code {
            KeyCode::Esc | KeyCode::Enter => view.ui.help = false,
            KeyCode::Up => *scroll = scroll.saturating_sub(1),
            KeyCode::Down => *scroll = scroll.saturating_add(1),
            KeyCode::PageUp => *scroll = scroll.saturating_sub(10),
            KeyCode::PageDown => *scroll = scroll.saturating_add(10),
            _ => {}
        }
        return Ok(None);
    }
    let action = view.ui.key(key);
    match action {
        Action::Prefix | Action::Cancel => {}
        Action::Hide => {
            if let Some(status) = view.exited.clone() {
                return Ok(Some(FrontendExit::Exited(status)));
            }
            return Ok(Some(detach(view, writer, rx).await));
        }
        Action::Take => {
            writer
                .send(&ClientMsg::Reclaim {
                    session_id: view.sid.clone(),
                })
                .await?;
        }
        Action::Answered => {
            if view.exited.is_none() {
                writer
                    .send(&ClientMsg::ApprovalsAnswered {
                        session_id: view.sid.clone(),
                    })
                    .await?;
                view.notice("Marked the waiting approvals as answered here".into());
            }
        }
        Action::Stop => {
            if view.exited.is_none() {
                writer
                    .send(&ClientMsg::Stop {
                        session_id: view.sid.clone(),
                    })
                    .await?;
            }
        }
        Action::Redraw => view.redraw = true,
        Action::Help => {
            view.ui.help = true;
            view.ui.help_scroll = 0;
        }
        Action::Browse => view.browse(0),
        Action::Copy => copy(view).await,
        Action::SendPrefix if view.exited.is_none() => {
            send_bytes(view, writer, view.ui.prefix.bytes().as_bytes()).await?;
        }
        Action::Agent(key) if view.ui.browse.is_some() => {
            let browse = view.ui.browse.as_mut().unwrap();
            let (rows, cols) = browse.viewport;
            let offset = browse.offset;
            let page = usize::from(rows.saturating_sub(1));
            match key.code {
                KeyCode::Esc => view.ui.browse = None,
                KeyCode::Enter => copy(view).await,
                KeyCode::PageUp => view.browse(offset.saturating_add(page)),
                KeyCode::PageDown => view.browse(offset.saturating_sub(page)),
                KeyCode::Up => browse.cursor.0 = browse.cursor.0.saturating_sub(1),
                KeyCode::Down => browse.cursor.0 = (browse.cursor.0 + 1).min(rows - 1),
                KeyCode::Left => browse.cursor.1 = browse.cursor.1.saturating_sub(1),
                KeyCode::Right => browse.cursor.1 = (browse.cursor.1 + 1).min(cols - 1),
                KeyCode::Home => browse.cursor.1 = 0,
                KeyCode::End => browse.cursor.1 = cols - 1,
                KeyCode::Char(' ') => {
                    browse.anchor = if browse.anchor.is_some() {
                        None
                    } else {
                        Some(browse.cursor)
                    }
                }
                _ => {}
            }
        }
        // After the exit, any other key closes the final screen.
        Action::Agent(_) | Action::AgentWithPrefix(_) | Action::SendPrefix
            if view.exited.is_some() =>
        {
            return Ok(view.exited.clone().map(FrontendExit::Exited));
        }
        Action::Agent(key) | Action::AgentWithPrefix(key) => {
            let application_cursor = view.parser.screen().application_cursor();
            if let Some(bytes) = crate::terminal_keys::encode(key, application_cursor) {
                let bytes = if matches!(action, Action::AgentWithPrefix(_)) {
                    view.ui.prefix.bytes() + &bytes
                } else {
                    bytes
                };
                send_bytes(view, writer, bytes.as_bytes()).await?;
            }
        }
        Action::SendPrefix => {}
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::protocol::b64;

    fn summary(sid: &str) -> SessionSummary {
        SessionSummary {
            id: sid.into(),
            provider: "codex".into(),
            cwd: "/tmp".into(),
            created_at_ms: 1,
            state: "running".into(),
            status: "unknown".into(),
            attached: true,
            remote_controlled: false,
            exited: None,
            rows: 4,
            cols: 20,
            generation: "g".into(),
            worker_build: None,
        }
    }

    const SID: &str = "ses-abcdefghijkl";

    fn attached(view: &mut View, text: &str, offset: u64) {
        assert_eq!(
            view.apply(RuntimeMsg::Attached {
                session: summary(SID),
                restore: b64(format!("\x1bc{text}").as_bytes()),
                offset,
            }),
            Applied::Continue
        );
    }

    fn output(view: &mut View, text: &str, offset: u64) {
        view.apply(RuntimeMsg::Output {
            session_id: SID.into(),
            bytes: b64(text.as_bytes()),
            offset,
        });
    }

    #[test]
    fn the_screen_is_the_restore_then_output_in_order_without_repeats() {
        let mut view = View::new(SID, false, None);
        attached(&mut view, "one", 10);
        assert_eq!(view.parser.screen().size(), (4, 20));
        output(&mut view, " two", 10);
        // Bytes already applied are skipped; only the rest is new.
        output(&mut view, "two three", 11);
        assert!(view.parser.screen().contents().starts_with("one two three"));
        // Another session's output is ignored.
        view.apply(RuntimeMsg::Output {
            session_id: "ses-other0000000".into(),
            bytes: b64(b"NOPE"),
            offset: 20,
        });
        assert!(!view.parser.screen().contents().contains("NOPE"));
        // A fresh restore replaces the screen.
        attached(&mut view, "fresh", 99);
        assert_eq!(view.parser.screen().contents().trim_end(), "fresh");
        assert_eq!(view.next_offset, 99);
    }

    /// r9: the row shows the device list's short state (held, frozen,
    /// paused, failed, a pending recovery), and a new state is a notice
    /// saying what to do; back to normal, the segment goes.
    #[test]
    fn the_status_row_shows_the_device_list_state() {
        use crate::runtime::protocol::DeviceListStatus;
        let mut view = View::new(SID, true, None);
        attached(&mut view, "x", 0);
        let held = DeviceListStatus {
            state: "held".into(),
            text: "held (a device-list write fault was recorded); ...".into(),
            label: Some("Remote held".into()),
            ..Default::default()
        };
        view.apply(RuntimeMsg::DeviceList { status: Some(held) });
        view.ui.feedback = None;
        let row = view.status_line();
        assert!(
            row.contains("| Astation ✓ | Remote held | Notice |"),
            "{row}"
        );
        assert!(
            view.ui
                .messages
                .iter()
                .any(|m| m.contains("Device list: held"))
        );
        view.apply(RuntimeMsg::DeviceList {
            status: Some(DeviceListStatus {
                state: "open".into(),
                text: "pinned at seq 4 (0 remote clients)".into(),
                ..Default::default()
            }),
        });
        assert!(!view.status_line().contains("Remote held"));
    }

    #[test]
    fn the_status_row_keeps_its_shape_and_follows_the_runtime() {
        let mut view = View::new(SID, false, None);
        attached(&mut view, "x", 0);
        assert_eq!(
            view.status_line(),
            "Atem | Codex | Local | Astation ✗ | Ctrl+] then ?:help"
        );
        view.apply(RuntimeMsg::Astation { connected: true });
        let mut remote = summary(SID);
        remote.remote_controlled = true;
        view.apply(RuntimeMsg::Session { session: remote });
        assert_eq!(
            view.status_line(),
            "Atem | Codex | Remote | Astation ✓ | Ctrl+] then ?:help"
        );
        view.apply(RuntimeMsg::Notice {
            text: "Hello".into(),
        });
        assert_eq!(view.status_line(), "Atem | Hello");
        view.ui.feedback = None;
        assert!(view.status_line().contains("Astation ✓ | Notice |"));
        view.apply(RuntimeMsg::Exited {
            session_id: SID.into(),
            generation: "g".into(),
            status: "0".into(),
        });
        assert!(
            view.status_line()
                .starts_with("Atem | Codex | Exited (0) | any key: close")
        );
    }

    #[test]
    fn detach_attach_errors_and_exits_end_the_frontend() {
        let mut view = View::new(SID, false, None);
        assert_eq!(
            view.apply(RuntimeMsg::error("Unknown session", Some("attach"))),
            Applied::Failed("Unknown session".into())
        );
        // Other errors are notices.
        assert_eq!(
            view.apply(RuntimeMsg::error("The session has ended", Some("input"))),
            Applied::Continue
        );
        assert_eq!(view.ui.messages.back().unwrap(), "The session has ended");
        assert_eq!(
            view.apply(RuntimeMsg::Detached {
                session_id: SID.into(),
                reason: "attached elsewhere".into(),
            }),
            Applied::End(FrontendExit::DetachedBy("attached elsewhere".into()))
        );
        assert_eq!(
            view.apply(RuntimeMsg::Detached {
                session_id: SID.into(),
                reason: "detached".into(),
            }),
            Applied::End(FrontendExit::Detached)
        );
        assert_eq!(
            FrontendExit::Detached.message(SID),
            format!(
                "Session {SID} is still running. Reattach: atem agent attach {SID} \u{b7} Stop: atem agent stop {SID}"
            )
        );
    }

    #[test]
    fn a_large_paste_is_one_paste_message_and_a_huge_one_is_refused() {
        let view = View::new(SID, false, None);
        let text = "x".repeat(MAX_INPUT * 2 + 5);
        assert_eq!(view.paste(&text).unwrap(), ClientMsg::paste(SID, &text));
        assert!(view.paste(&"y".repeat(MAX_PASTE + 1)).is_err());
    }

    #[test]
    fn history_and_copy_come_from_the_local_parser() {
        let mut view = View::new(SID, false, None);
        view.ui.viewport = (4, 20);
        attached(&mut view, "", 0);
        for line in 0..10 {
            let offset = view.next_offset;
            output(&mut view, &format!("line{line}\r\n"), offset);
        }
        assert!(view.copy_text().contains("line9"));
        view.browse(3);
        let browse = view.ui.browse.as_ref().unwrap();
        assert_eq!(browse.offset, 3);
        assert!(view.copy_text().contains("line4"), "{}", view.copy_text());
        // The live screen is unchanged.
        assert_eq!(view.parser.screen().scrollback(), 0);
    }
}
