//! Background diagnostics must not write over an active terminal renderer.
use std::collections::VecDeque;
use std::sync::Mutex;

static CAPTURE: Mutex<Option<VecDeque<String>>> = Mutex::new(None);
const LIMIT: usize = 64;

pub struct Capture;

impl Capture {
    pub fn start() -> Self {
        *CAPTURE.lock().unwrap() = Some(VecDeque::new());
        Self
    }

    pub fn drain(&self) -> Vec<String> {
        CAPTURE
            .lock()
            .unwrap()
            .as_mut()
            .map(|q| q.drain(..).collect())
            .unwrap_or_default()
    }
}

impl Drop for Capture {
    fn drop(&mut self) {
        let pending = CAPTURE.lock().unwrap().take().unwrap_or_default();
        for message in pending {
            eprintln!("{message}");
        }
    }
}

fn queue(queue: &mut VecDeque<String>, message: String) {
    if queue.len() == LIMIT {
        queue.pop_front();
    }
    queue.push_back(message);
}

pub fn warn(message: impl Into<String>) {
    let message = message.into();
    let mut capture = CAPTURE.lock().unwrap();
    if let Some(queue) = capture.as_mut() {
        self::queue(queue, message);
    } else {
        eprintln!("{message}");
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn an_active_renderer_receives_background_warnings_instead_of_stderr() {
        let capture = super::Capture::start();
        super::warn("renderer warning fixture");
        assert!(
            capture
                .drain()
                .iter()
                .any(|message| message == "renderer warning fixture")
        );
    }

    #[test]
    fn diagnostics_are_bounded_and_preserve_the_latest_warning() {
        let mut queue = std::collections::VecDeque::new();
        for index in 0..100 {
            super::queue(&mut queue, format!("warning {index}"));
        }
        assert_eq!(queue.len(), super::LIMIT);
        assert_eq!(queue.back().unwrap(), "warning 99");
    }
}
