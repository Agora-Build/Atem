use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

/// Encode the classic xterm keyboard protocol used by Atem's terminal emulator.
pub fn encode(key: KeyEvent, application_cursor: bool) -> Option<String> {
    let shift = key.modifiers.contains(KeyModifiers::SHIFT);
    let alt = key.modifiers.contains(KeyModifiers::ALT);
    let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
    let modifier = 1 + u8::from(shift) + 2 * u8::from(alt) + 4 * u8::from(ctrl);
    let csi = |suffix: char| {
        if modifier != 1 {
            format!("\x1b[1;{modifier}{suffix}")
        } else if application_cursor {
            format!("\x1bO{suffix}")
        } else {
            format!("\x1b[{suffix}")
        }
    };
    let tilde = |number: u8| {
        if modifier != 1 {
            format!("\x1b[{number};{modifier}~")
        } else {
            format!("\x1b[{number}~")
        }
    };
    let mut plain = match key.code {
        KeyCode::Up => return Some(csi('A')),
        KeyCode::Down => return Some(csi('B')),
        KeyCode::Right => return Some(csi('C')),
        KeyCode::Left => return Some(csi('D')),
        KeyCode::Home => return Some(csi('H')),
        KeyCode::End => return Some(csi('F')),
        KeyCode::Insert => return Some(tilde(2)),
        KeyCode::Delete => return Some(tilde(3)),
        KeyCode::PageUp => return Some(tilde(5)),
        KeyCode::PageDown => return Some(tilde(6)),
        KeyCode::F(n @ 1..=4) => {
            return Some(if modifier == 1 {
                format!("\x1bO{}", (b'P' + n - 1) as char)
            } else {
                format!("\x1b[1;{modifier}{}", (b'P' + n - 1) as char)
            });
        }
        KeyCode::F(n @ 5..=12) => {
            return Some(tilde([15, 17, 18, 19, 20, 21, 23, 24][usize::from(n - 5)]));
        }
        KeyCode::Char(c) if ctrl => match c.to_ascii_lowercase() {
            'a'..='z' => ((c.to_ascii_lowercase() as u8 - b'a' + 1) as char).to_string(),
            ' ' | '@' | '2' => "\0".into(),
            '[' | '3' => "\x1b".into(),
            '\\' | '4' => "\x1c".into(),
            ']' | '5' => "\x1d".into(),
            '^' | '6' => "\x1e".into(),
            '_' | '7' | '/' => "\x1f".into(),
            '?' | '8' => "\x7f".into(),
            _ => return None,
        },
        KeyCode::Char(c) => c.to_string(),
        KeyCode::Enter => "\r".into(),
        KeyCode::Backspace => if ctrl { "\x08" } else { "\x7f" }.into(),
        KeyCode::Tab => if shift { "\x1b[Z" } else { "\t" }.into(),
        KeyCode::BackTab => "\x1b[Z".into(),
        KeyCode::Esc => "\x1b".into(),
        _ => return None,
    };
    if alt {
        plain.insert(0, '\x1b');
    }
    Some(plain)
}

pub fn paste(text: &str, bracketed: bool) -> String {
    if bracketed {
        // Strip an embedded end marker so paste cannot escape bracketed mode.
        format!("\x1b[200~{}\x1b[201~", text.replace('\x1b', ""))
    } else {
        text.replace("\r\n", "\r").replace('\n', "\r")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn modifiers_and_application_cursor() {
        assert_eq!(
            encode(KeyEvent::new(KeyCode::Left, KeyModifiers::ALT), false).unwrap(),
            "\x1b[1;3D"
        );
        assert_eq!(
            encode(KeyEvent::new(KeyCode::Up, KeyModifiers::NONE), true).unwrap(),
            "\x1bOA"
        );
        assert_eq!(
            encode(KeyEvent::new(KeyCode::Char('b'), KeyModifiers::ALT), false).unwrap(),
            "\x1bb"
        );
        assert_eq!(
            encode(
                KeyEvent::new(KeyCode::Char(' '), KeyModifiers::CONTROL),
                false
            )
            .unwrap(),
            "\0"
        );
    }
    #[test]
    fn multiline_paste_stays_inside_one_bracketed_paste() {
        assert_eq!(paste("one\ntwo", true), "\x1b[200~one\ntwo\x1b[201~");
        assert_eq!(
            paste("one\x1b[201~two", true),
            "\x1b[200~one[201~two\x1b[201~"
        );
    }
}
