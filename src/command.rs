use std::collections::VecDeque;

/// Serial task queue: one task active at a time, FIFO ordering, deferred finalization flag.
pub struct TaskQueue {
    pending: VecDeque<String>,
    active: Option<String>,
    needs_finalize: bool,
}

impl TaskQueue {
    pub fn new() -> Self {
        Self {
            pending: VecDeque::new(),
            active: None,
            needs_finalize: false,
        }
    }

    /// Add a task to the back of the queue.
    pub fn enqueue(&mut self, task_id: String) {
        self.pending.push_back(task_id);
    }

    /// Pop the next pending task and mark it active.
    /// Returns `None` if there are no pending tasks or a task is already active.
    pub fn start_next(&mut self) -> Option<String> {
        if self.active.is_some() {
            return None;
        }
        let id = self.pending.pop_front()?;
        self.active = Some(id.clone());
        Some(id)
    }

    /// Complete the active task and return its ID.
    pub fn complete_active(&mut self) -> Option<String> {
        self.active.take()
    }

    /// Whether a task is currently running.
    pub fn is_busy(&self) -> bool {
        self.active.is_some()
    }

    /// Whether there are pending tasks waiting.
    pub fn has_pending(&self) -> bool {
        !self.pending.is_empty()
    }

    /// Number of pending tasks.
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// Flag the active task for deferred finalization (e.g. session ended mid-task).
    pub fn set_needs_finalize(&mut self) {
        if self.active.is_some() {
            self.needs_finalize = true;
        }
    }

    /// Consume the finalize flag, returning `true` if it was set.
    pub fn take_needs_finalize(&mut self) -> bool {
        let was_set = self.needs_finalize;
        self.needs_finalize = false;
        was_set
    }
}

/// Accumulates text chunks and detects trigger phrases at the end of the buffer.
pub struct StreamBuffer {
    buffer: String,
    triggers: Vec<String>,
}

impl StreamBuffer {
    /// Create a new buffer with the given trigger phrases (stored lowercase).
    pub fn new(triggers: &[&str]) -> Self {
        Self {
            buffer: String::new(),
            triggers: triggers.iter().map(|t| t.to_lowercase()).collect(),
        }
    }

    /// Append text to the buffer (space-separated from previous content).
    pub fn push(&mut self, text: &str) {
        if !self.buffer.is_empty() {
            self.buffer.push(' ');
        }
        self.buffer.push_str(text);
    }

    /// Check if the buffer ends with a trigger phrase. If found, strip it and return `true`.
    pub fn detect_trigger(&mut self) -> bool {
        let lower = self.buffer.to_lowercase();
        for trigger in &self.triggers {
            if lower.trim_end().ends_with(trigger.as_str()) {
                let buf_len = self.buffer.trim_end().len();
                let trigger_len = trigger.len();
                if buf_len >= trigger_len {
                    self.buffer.truncate(buf_len - trigger_len);
                    let trimmed = self.buffer.trim_end().to_string();
                    self.buffer = trimmed;
                }
                return true;
            }
        }
        false
    }

    /// Take the buffer contents, leaving it empty.
    pub fn take(&mut self) -> String {
        let val = self.buffer.trim().to_string();
        self.buffer.clear();
        val
    }

    /// Whether the buffer has non-whitespace content.
    pub fn has_content(&self) -> bool {
        !self.buffer.trim().is_empty()
    }

    /// Discard all buffered text.
    pub fn clear(&mut self) {
        self.buffer.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── TaskQueue ──────────────────────────────────────────

    #[test]
    fn task_queue_empty() {
        let q = TaskQueue::new();
        assert!(!q.is_busy());
        assert!(!q.has_pending());
        assert_eq!(q.pending_count(), 0);
    }

    #[test]
    fn task_queue_enqueue() {
        let mut q = TaskQueue::new();
        q.enqueue("a".into());
        q.enqueue("b".into());
        assert!(q.has_pending());
        assert_eq!(q.pending_count(), 2);
        assert!(!q.is_busy());
    }

    #[test]
    fn task_queue_start_next() {
        let mut q = TaskQueue::new();
        q.enqueue("a".into());
        let id = q.start_next();
        assert_eq!(id.as_deref(), Some("a"));
        assert!(q.is_busy());
        assert!(!q.has_pending());
    }

    #[test]
    fn task_queue_start_blocked_while_busy() {
        let mut q = TaskQueue::new();
        q.enqueue("a".into());
        q.enqueue("b".into());
        q.start_next(); // starts "a"
        assert_eq!(q.start_next(), None); // blocked
        assert_eq!(q.pending_count(), 1);
    }

    #[test]
    fn task_queue_complete_active() {
        let mut q = TaskQueue::new();
        q.enqueue("a".into());
        q.start_next();
        let completed = q.complete_active();
        assert_eq!(completed.as_deref(), Some("a"));
        assert!(!q.is_busy());
    }

    #[test]
    fn task_queue_complete_empty() {
        let mut q = TaskQueue::new();
        assert_eq!(q.complete_active(), None);
    }

    #[test]
    fn task_queue_fifo_order() {
        let mut q = TaskQueue::new();
        q.enqueue("first".into());
        q.enqueue("second".into());
        q.enqueue("third".into());

        assert_eq!(q.start_next().as_deref(), Some("first"));
        q.complete_active();
        assert_eq!(q.start_next().as_deref(), Some("second"));
        q.complete_active();
        assert_eq!(q.start_next().as_deref(), Some("third"));
        q.complete_active();
        assert_eq!(q.start_next(), None);
    }

    #[test]
    fn task_queue_finalize_lifecycle() {
        let mut q = TaskQueue::new();
        // No active task → set_needs_finalize is a no-op
        q.set_needs_finalize();
        assert!(!q.take_needs_finalize());

        q.enqueue("x".into());
        q.start_next();
        q.set_needs_finalize();
        assert!(q.take_needs_finalize());
        // Consumed
        assert!(!q.take_needs_finalize());
    }

    // ── StreamBuffer ───────────────────────────────────────

    #[test]
    fn stream_buffer_empty() {
        let buf = StreamBuffer::new(&["go"]);
        assert!(!buf.has_content());
    }

    #[test]
    fn stream_buffer_push_and_take() {
        let mut buf = StreamBuffer::new(&["go"]);
        buf.push("hello");
        buf.push("world");
        assert!(buf.has_content());
        assert_eq!(buf.take(), "hello world");
        assert!(!buf.has_content());
    }

    #[test]
    fn stream_buffer_take_trims() {
        let mut buf = StreamBuffer::new(&["go"]);
        buf.push("  padded  ");
        assert_eq!(buf.take(), "padded");
    }

    #[test]
    fn stream_buffer_trigger_strips() {
        let mut buf = StreamBuffer::new(&["execute", "run it"]);
        buf.push("fix the bug execute");
        assert!(buf.detect_trigger());
        assert_eq!(buf.take(), "fix the bug");
    }

    #[test]
    fn stream_buffer_trigger_case_insensitive() {
        let mut buf = StreamBuffer::new(&["execute"]);
        buf.push("fix the bug EXECUTE");
        assert!(buf.detect_trigger());
        assert_eq!(buf.take(), "fix the bug");
    }

    #[test]
    fn stream_buffer_trigger_multi_word() {
        let mut buf = StreamBuffer::new(&["run it"]);
        buf.push("deploy the app run it");
        assert!(buf.detect_trigger());
        assert_eq!(buf.take(), "deploy the app");
    }

    #[test]
    fn stream_buffer_no_match() {
        let mut buf = StreamBuffer::new(&["execute"]);
        buf.push("hello world");
        assert!(!buf.detect_trigger());
        assert_eq!(buf.take(), "hello world");
    }

    #[test]
    fn stream_buffer_clear() {
        let mut buf = StreamBuffer::new(&["go"]);
        buf.push("some text");
        buf.clear();
        assert!(!buf.has_content());
        assert_eq!(buf.take(), "");
    }
}
