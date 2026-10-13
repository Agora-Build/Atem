use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::layout::Rect;
use std::collections::VecDeque;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Prefix(char);

impl Default for Prefix {
    fn default() -> Self {
        Self(']')
    }
}

impl Prefix {
    pub fn parse(raw: &str) -> Option<Self> {
        let raw = raw.to_ascii_lowercase();
        let value = raw
            .strip_prefix("ctrl+")
            .or_else(|| raw.strip_prefix("ctrl-"))
            .or_else(|| raw.strip_prefix("c-"))?;
        let mut chars = value.chars();
        let key = chars.next()?;
        (chars.next().is_none()
            && (key.is_ascii_lowercase() || matches!(key, ']' | '\\'))
            && !matches!(key, 'i' | 'm'))
        .then_some(Self(key))
    }

    pub fn label(self) -> String {
        format!("Ctrl+{}", self.0)
    }

    pub fn bytes(self) -> String {
        crate::terminal_keys::encode(
            KeyEvent::new(KeyCode::Char(self.0), KeyModifiers::CONTROL),
            false,
        )
        .unwrap()
    }

    fn matches(self, key: KeyEvent) -> bool {
        // Classic terminals report Ctrl+] as Ctrl+5 (the same byte), including tmux.
        key.modifiers.contains(KeyModifiers::CONTROL)
            && !key.modifiers.contains(KeyModifiers::ALT)
            && crate::terminal_keys::encode(key, false).as_deref() == Some(self.bytes().as_str())
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Action {
    Agent(KeyEvent),
    AgentWithPrefix(KeyEvent),
    Prefix,
    SendPrefix,
    Cancel,
    Hide,
    Take,
    Stop,
    Redraw,
    Help,
    Browse,
    Copy,
}

pub struct Browse {
    pub screen: vt100::Screen,
    pub viewport: (u16, u16),
    pub offset: usize,
    pub cursor: (u16, u16),
    pub anchor: Option<(u16, u16)>,
}

impl Browse {
    pub fn selected(&self, row: u16, col: u16) -> bool {
        self.anchor.is_some_and(|anchor| {
            let start = anchor.min(self.cursor);
            let end = anchor.max(self.cursor);
            (start..=end).contains(&(row, col))
                || (self
                    .screen
                    .cell(row, col)
                    .is_some_and(|cell| cell.is_wide())
                    && (start..=end).contains(&(row, col + 1)))
        })
    }

    pub fn text(&self) -> String {
        let Some(anchor) = self.anchor else {
            return visible_text(&self.screen, self.viewport);
        };
        let (mut start_row, mut start_col) = anchor.min(self.cursor);
        let (end_row, mut end_col) = anchor.max(self.cursor);
        if self
            .screen
            .cell(start_row, start_col)
            .is_some_and(|c| c.is_wide_continuation())
        {
            start_col = start_col.saturating_sub(1);
        }
        let cols = self.viewport.1.min(self.screen.size().1);
        end_col += if self
            .screen
            .cell(end_row, end_col)
            .is_some_and(|c| c.is_wide())
        {
            2
        } else {
            1
        };
        start_row = start_row.min(self.screen.size().0 - 1);
        if cols == self.screen.size().1 {
            self.screen
                .contents_between(start_row, start_col, end_row, end_col.min(cols))
        } else {
            let mut text = String::new();
            for row in start_row..=end_row {
                let start = if row == start_row { start_col } else { 0 };
                let end = if row == end_row {
                    end_col.min(cols)
                } else {
                    cols
                };
                text.push_str(
                    &self
                        .screen
                        .rows(start, end.saturating_sub(start))
                        .nth(usize::from(row))
                        .unwrap_or_default(),
                );
                if row != end_row {
                    text.push('\n');
                }
            }
            text
        }
    }
}

pub fn visible_text(screen: &vt100::Screen, viewport: (u16, u16)) -> String {
    let (rows, cols) = screen.size();
    let rows = if viewport.0 == 0 {
        rows
    } else {
        rows.min(viewport.0)
    };
    let cols = if viewport.1 == 0 {
        cols
    } else {
        cols.min(viewport.1)
    };
    let mut text = String::new();
    for (index, line) in screen.rows(0, cols).take(usize::from(rows)).enumerate() {
        text.push_str(&line);
        if cols < screen.size().1 || !screen.row_wrapped(index as u16) {
            text.push('\n');
        }
    }
    text.trim_end_matches('\n').to_string()
}

pub struct State {
    pub prefix: Prefix,
    pub pending: bool,
    pub help: bool,
    pub help_scroll: u16,
    pub browse: Option<Browse>,
    pub viewport: (u16, u16),
    pub feedback: Option<(String, std::time::Instant)>,
    pub messages: VecDeque<String>,
    last_status: Option<String>,
}

impl State {
    pub fn new() -> Self {
        let mut state = Self {
            prefix: Prefix::default(),
            pending: false,
            help: false,
            help_scroll: 0,
            browse: None,
            viewport: (0, 0),
            feedback: None,
            messages: VecDeque::new(),
            last_status: None,
        };
        if let Ok(raw) = std::env::var("ATEM_TERMINAL_PREFIX") {
            if let Some(prefix) = Prefix::parse(&raw) {
                state.prefix = prefix;
            } else {
                state.record(
                    "Invalid ATEM_TERMINAL_PREFIX; use Ctrl-] or Ctrl-a. Using Ctrl-].".into(),
                );
            }
        }
        state
    }

    pub fn record(&mut self, message: String) {
        if self.messages.back() == Some(&message) {
            return;
        }
        if self.messages.len() == 32 {
            self.messages.pop_front();
        }
        self.messages.push_back(message);
    }

    pub fn observe_status(&mut self, status: &Option<String>) {
        if self.last_status != *status {
            self.last_status = status.clone();
            if let Some(message) = status.as_ref().filter(|s| !s.is_empty()) {
                self.record(message.clone());
            }
        }
    }

    pub fn reset_view(&mut self) {
        self.pending = false;
        self.help = false;
        self.browse = None;
    }

    pub fn key(&mut self, key: KeyEvent) -> Action {
        if self.pending {
            self.pending = false;
            if self.prefix.matches(key) {
                return Action::SendPrefix;
            }
            return match key.code {
                KeyCode::Esc => Action::Cancel,
                KeyCode::Char('h' | 'm') if key.modifiers.is_empty() => Action::Hide,
                KeyCode::Char('g') if key.modifiers.is_empty() => Action::Take,
                KeyCode::Char('x') if key.modifiers.is_empty() => Action::Stop,
                KeyCode::Char('r') if key.modifiers.is_empty() => Action::Redraw,
                KeyCode::Char('?') => Action::Help,
                KeyCode::Char('[') if key.modifiers.is_empty() => Action::Browse,
                KeyCode::Char('c') if key.modifiers.is_empty() => Action::Copy,
                _ => Action::AgentWithPrefix(key),
            };
        }
        if self.prefix.matches(key) {
            self.pending = true;
            Action::Prefix
        } else {
            Action::Agent(key)
        }
    }
}

pub fn viewport(area: Rect) -> Rect {
    Rect {
        height: area.height.saturating_sub(1),
        ..area
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tmux_and_agent_control_keys_pass_through_without_the_atem_prefix() {
        let mut state = State::new();
        state.prefix = Prefix::default();
        for character in ['b', 'g', 'c'] {
            let key = KeyEvent::new(KeyCode::Char(character), KeyModifiers::CONTROL);
            assert_eq!(state.key(key), Action::Agent(key));
        }
        assert_eq!(
            state.key(KeyEvent::new(KeyCode::Char(']'), KeyModifiers::CONTROL)),
            Action::Prefix
        );
        assert_eq!(
            state.key(KeyEvent::new(KeyCode::Char('h'), KeyModifiers::NONE)),
            Action::Hide
        );
    }

    #[test]
    fn prefix_can_be_changed_and_can_be_sent_literally() {
        let mut state = State::new();
        state.prefix = Prefix::parse("Ctrl-a").unwrap();
        let key = KeyEvent::new(KeyCode::Char('a'), KeyModifiers::CONTROL);
        assert_eq!(state.key(key), Action::Prefix);
        assert_eq!(state.key(key), Action::SendPrefix);
        assert_eq!(state.prefix.bytes(), "\x01");
        assert!(Prefix::parse("Ctrl-word").is_none());
        assert!(Prefix::parse("plain").is_none());
        assert!(Prefix::parse("Ctrl-i").is_none());
        assert!(Prefix::parse("Ctrl-[").is_none());
        state.prefix = Prefix::default();
        assert_eq!(
            state.key(KeyEvent::new(KeyCode::Char('5'), KeyModifiers::CONTROL)),
            Action::Prefix
        );
    }

    #[test]
    fn selection_copies_plain_text_and_complete_wide_characters() {
        let mut parser = vt100::Parser::new(3, 20, 0);
        parser.process("one\r\n\u{4e2d}two".as_bytes());
        let mut view = Browse {
            screen: parser.screen().clone(),
            viewport: (3, 20),
            offset: 0,
            cursor: (1, 4),
            anchor: Some((0, 0)),
        };
        assert_eq!(view.text(), "one\n\u{4e2d}two");
        view.anchor = Some((1, 1));
        view.cursor = (1, 1);
        assert_eq!(view.text(), "\u{4e2d}");
    }

    #[test]
    fn copy_clips_a_larger_remote_screen_to_the_local_viewport() {
        let mut parser = vt100::Parser::new(4, 20, 0);
        parser.process(b"visible HIDDEN\r\nsecond HIDDEN\r\nOFFSCREEN");
        assert_eq!(visible_text(parser.screen(), (2, 7)), "visible\nsecond ");
        let view = Browse {
            screen: parser.screen().clone(),
            viewport: (2, 7),
            offset: 0,
            cursor: (1, 5),
            anchor: Some((0, 0)),
        };
        assert_eq!(view.text(), "visible\nsecond");
    }
}
