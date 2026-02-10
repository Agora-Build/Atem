use tokio::sync::mpsc;

use crate::command::TaskQueue;

// ── Types ────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecTarget {
    Main,
    Background,
}

#[derive(Debug, Clone)]
pub enum WorkKind {
    MarkTask,
}

#[derive(Debug, Clone)]
pub struct WorkItem {
    pub task_id: String,
    pub received_at_ms: u64,
    pub kind: WorkKind,
    pub prompt: String,
}

#[derive(Debug, Clone)]
pub struct BackgroundResult {
    pub task_id: String,
    pub success: bool,
    pub output: String,
}

/// Tracks a running background `claude -p` process.
struct BackgroundTask {
    task_id: String,
}

// ── TaskDispatcher ───────────────────────────────────────────────

pub struct TaskDispatcher {
    main_queue: TaskQueue,
    background_tasks: Vec<BackgroundTask>,
    max_background: usize,
    bg_result_tx: mpsc::UnboundedSender<BackgroundResult>,
    bg_result_rx: mpsc::UnboundedReceiver<BackgroundResult>,
    triage_tx: mpsc::UnboundedSender<(WorkItem, ExecTarget)>,
    triage_rx: mpsc::UnboundedReceiver<(WorkItem, ExecTarget)>,
    claude_binary: String,
}

impl TaskDispatcher {
    pub fn new() -> Self {
        let (bg_result_tx, bg_result_rx) = mpsc::unbounded_channel();
        let (triage_tx, triage_rx) = mpsc::unbounded_channel();
        let claude_binary =
            std::env::var("CLAUDE_CLI_BIN").unwrap_or_else(|_| "claude".to_string());
        Self {
            main_queue: TaskQueue::new(),
            background_tasks: Vec::new(),
            max_background: 2,
            bg_result_tx,
            bg_result_rx,
            triage_tx,
            triage_rx,
            claude_binary,
        }
    }

    // ── Public API ───────────────────────────────────────────

    /// Triage and route a work item.
    ///
    /// Fast-path rules:
    ///   1. Main is idle → Main (no reason to background)
    ///   2. Main is busy, no background slots → Main (queue, wait)
    ///   3. Main is busy + slots available → AI triage
    pub fn submit(&mut self, item: WorkItem, main_is_busy: bool) {
        if !main_is_busy {
            // Rule 1: main idle → route directly
            self.main_queue.enqueue(item.task_id.clone());
            return;
        }

        if self.background_tasks.len() >= self.max_background {
            // Rule 2: no background slots → queue for main
            self.main_queue.enqueue(item.task_id.clone());
            return;
        }

        // Rule 3: AI triage
        self.spawn_triage(item);
    }

    /// Pop next task ID for the main agent, marking it active.
    pub fn next_for_main(&mut self) -> Option<String> {
        self.main_queue.start_next()
    }

    /// Finish the active main task, returning its ID.
    pub fn complete_main(&mut self) -> Option<String> {
        self.main_queue.complete_active()
    }

    /// Is the main agent currently busy with a task?
    pub fn main_is_active(&self) -> bool {
        self.main_queue.is_busy()
    }

    /// Flag the active main task for deferred finalization.
    pub fn set_main_needs_finalize(&mut self) {
        self.main_queue.set_needs_finalize();
    }

    /// Consume the deferred finalize flag.
    pub fn take_main_needs_finalize(&mut self) -> bool {
        self.main_queue.take_needs_finalize()
    }

    /// Drain completed background task results.
    pub fn poll_background_results(&mut self) -> Vec<BackgroundResult> {
        let mut results = Vec::new();
        while let Ok(r) = self.bg_result_rx.try_recv() {
            // Remove the tracked background task
            self.background_tasks.retain(|bt| bt.task_id != r.task_id);
            results.push(r);
        }
        results
    }

    /// Drain AI triage verdicts and route items accordingly.
    pub fn poll_triage_results(&mut self) {
        let mut pending: Vec<(WorkItem, ExecTarget)> = Vec::new();
        while let Ok(pair) = self.triage_rx.try_recv() {
            pending.push(pair);
        }

        for (item, target) in pending {
            match target {
                ExecTarget::Main => {
                    self.main_queue.enqueue(item.task_id.clone());
                }
                ExecTarget::Background => {
                    self.spawn_background(item);
                }
            }
        }
    }

    // ── Internal ─────────────────────────────────────────────

    /// Spawn an AI triage call to classify the item.
    fn spawn_triage(&self, item: WorkItem) {
        let tx = self.triage_tx.clone();
        let binary = self.claude_binary.clone();

        tokio::spawn(async move {
            let target = run_triage(&binary, &item).await;
            let _ = tx.send((item, target));
        });
    }

    /// Spawn a background `claude -p` process for the item.
    fn spawn_background(&mut self, item: WorkItem) {
        let tx = self.bg_result_tx.clone();
        let binary = self.claude_binary.clone();
        let task_id = item.task_id.clone();

        self.background_tasks.push(BackgroundTask {
            task_id: task_id.clone(),
        });

        tokio::spawn(async move {
            let (success, output) = run_background(&binary, &item).await;
            let _ = tx.send(BackgroundResult {
                task_id,
                success,
                output,
            });
        });
    }
}

// ── Background executor ──────────────────────────────────────────

async fn run_background(binary: &str, item: &WorkItem) -> (bool, String) {
    let result = tokio::process::Command::new(binary)
        .arg("-p")
        .arg(&item.prompt)
        .arg("--output-format")
        .arg("json")
        .output()
        .await;

    match result {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            (output.status.success(), stdout)
        }
        Err(err) => (false, format!("Failed to run background claude: {}", err)),
    }
}

// ── AI triage ────────────────────────────────────────────────────

/// Classify prompt to ask haiku whether a task should run on MAIN or BACKGROUND.
fn build_triage_prompt(item: &WorkItem) -> String {
    format!(
        "You are a task router. Given the following task prompt, decide whether it should run on \
         MAIN (interactive Claude Code PTY session — best for tasks that modify files, need the \
         full project context, or require multi-turn interaction) or BACKGROUND (one-shot CLI — \
         best for simple read-only queries, summaries, or quick lookups).\n\n\
         Task prompt (first 500 chars):\n{}\n\n\
         Respond with ONLY a JSON object: {{\"target\": \"MAIN\"}} or {{\"target\": \"BACKGROUND\"}}",
        &item.prompt[..item.prompt.len().min(500)]
    )
}

/// Parse triage response JSON. Returns `Main` on any error.
fn parse_triage_response(text: &str) -> ExecTarget {
    // Try to find JSON in the response
    if let Some(start) = text.find('{')
        && let Some(end) = text[start..].find('}')
    {
        let json_str = &text[start..=start + end];
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(json_str)
            && let Some(target) = val.get("target").and_then(|v| v.as_str())
            && target.eq_ignore_ascii_case("BACKGROUND")
        {
            return ExecTarget::Background;
        }
    }
    ExecTarget::Main // safe default
}

async fn run_triage(binary: &str, item: &WorkItem) -> ExecTarget {
    let prompt = build_triage_prompt(item);

    let result = tokio::process::Command::new(binary)
        .arg("-p")
        .arg(&prompt)
        .arg("--model")
        .arg("haiku")
        .arg("--max-turns")
        .arg("1")
        .arg("--output-format")
        .arg("json")
        .output()
        .await;

    match result {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            parse_triage_response(&stdout)
        }
        Err(_) => ExecTarget::Main, // safe default on error
    }
}

// ── Tests ────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_item(id: &str) -> WorkItem {
        WorkItem {
            task_id: id.to_string(),
            received_at_ms: 1000,
            kind: WorkKind::MarkTask,
            prompt: "test prompt".to_string(),
        }
    }

    #[test]
    fn submit_when_idle_routes_to_main() {
        let mut d = TaskDispatcher::new();
        let item = make_item("t1");
        d.submit(item, false); // main is NOT busy
        assert_eq!(d.next_for_main().as_deref(), Some("t1"));
    }

    #[test]
    fn submit_when_busy_no_slots_routes_to_main() {
        let mut d = TaskDispatcher::new();
        // Fill background slots
        d.background_tasks.push(BackgroundTask {
            task_id: "bg1".into(),
        });
        d.background_tasks.push(BackgroundTask {
            task_id: "bg2".into(),
        });
        let item = make_item("t2");
        d.submit(item, true); // main busy, no bg slots
        // Should be queued for main
        // First activate something so the queue has a pending item
        assert!(!d.main_is_active());
        assert_eq!(d.next_for_main().as_deref(), Some("t2"));
    }

    #[tokio::test]
    async fn submit_when_busy_with_slots_triggers_triage() {
        let mut d = TaskDispatcher::new();
        let item = make_item("t3");
        d.submit(item, true); // main busy, slots available
        // Item should NOT be in main queue (it went to triage)
        assert_eq!(d.next_for_main(), None);
    }

    #[test]
    fn poll_background_results_drains_channel() {
        let mut d = TaskDispatcher::new();
        d.background_tasks.push(BackgroundTask {
            task_id: "bg1".into(),
        });
        // Simulate a result arriving
        let _ = d.bg_result_tx.send(BackgroundResult {
            task_id: "bg1".into(),
            success: true,
            output: "done".into(),
        });
        let results = d.poll_background_results();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].task_id, "bg1");
        assert!(results[0].success);
        // Background task should be removed
        assert!(d.background_tasks.is_empty());
    }

    #[test]
    fn poll_triage_results_routes_to_main() {
        let mut d = TaskDispatcher::new();
        let item = make_item("t4");
        let _ = d.triage_tx.send((item, ExecTarget::Main));
        d.poll_triage_results();
        assert_eq!(d.next_for_main().as_deref(), Some("t4"));
    }

    #[tokio::test]
    async fn poll_triage_results_routes_to_background() {
        let mut d = TaskDispatcher::new();
        let item = make_item("t5");
        let _ = d.triage_tx.send((item, ExecTarget::Background));
        d.poll_triage_results();
        // Should NOT be in main queue
        assert_eq!(d.next_for_main(), None);
        // Should be in background_tasks
        assert_eq!(d.background_tasks.len(), 1);
        assert_eq!(d.background_tasks[0].task_id, "t5");
    }

    #[test]
    fn parse_triage_response_valid_main() {
        let r = parse_triage_response(r#"{"target": "MAIN"}"#);
        assert_eq!(r, ExecTarget::Main);
    }

    #[test]
    fn parse_triage_response_valid_background() {
        let r = parse_triage_response(r#"{"target": "BACKGROUND"}"#);
        assert_eq!(r, ExecTarget::Background);
    }

    #[test]
    fn parse_triage_response_case_insensitive() {
        let r = parse_triage_response(r#"{"target": "background"}"#);
        assert_eq!(r, ExecTarget::Background);
    }

    #[test]
    fn parse_triage_response_invalid_json() {
        let r = parse_triage_response("this is not json");
        assert_eq!(r, ExecTarget::Main); // safe default
    }

    #[test]
    fn parse_triage_response_missing_target() {
        let r = parse_triage_response(r#"{"foo": "bar"}"#);
        assert_eq!(r, ExecTarget::Main); // safe default
    }

    #[test]
    fn parse_triage_response_embedded_json() {
        let r = parse_triage_response(r#"Some text before {"target": "BACKGROUND"} and after"#);
        assert_eq!(r, ExecTarget::Background);
    }

    #[test]
    fn complete_main_returns_id() {
        let mut d = TaskDispatcher::new();
        d.submit(make_item("t6"), false);
        d.next_for_main(); // activate "t6"
        let completed = d.complete_main();
        assert_eq!(completed.as_deref(), Some("t6"));
        assert!(!d.main_is_active());
    }

    #[test]
    fn finalize_flag_lifecycle() {
        let mut d = TaskDispatcher::new();
        // No active task → flag is no-op
        d.set_main_needs_finalize();
        assert!(!d.take_main_needs_finalize());

        // With active task
        d.submit(make_item("t7"), false);
        d.next_for_main();
        d.set_main_needs_finalize();
        assert!(d.take_main_needs_finalize());
        // Consumed
        assert!(!d.take_main_needs_finalize());
    }

    #[test]
    fn background_result_roundtrip() {
        let r = BackgroundResult {
            task_id: "abc".into(),
            success: true,
            output: "hello".into(),
        };
        assert_eq!(r.task_id, "abc");
        assert!(r.success);
        assert_eq!(r.output, "hello");
    }
}
