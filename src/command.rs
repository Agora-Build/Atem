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

    /// The task `start_next` would start (none while one is active).
    pub fn peek_next(&self) -> Option<&str> {
        if self.active.is_some() {
            return None;
        }
        self.pending.front().map(String::as_str)
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
}
