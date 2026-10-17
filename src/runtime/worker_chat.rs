//! The worker's chat backlog: what the chat adapter read, held until a broker
//! takes it, bounded in items and bytes, and cut into `chat` messages well
//! below the protocol's line bound.
//!
//! - One oversized text (a prompt, an assistant part, a backfilled entry) is
//!   cut with a `… (truncated)` marker so every item fits a message.
//! - Batches keep the terminal input count of the moment they were read.
//! - Beyond the bounds the oldest items go, never `SessionStarted` (it names
//!   the log the rest belongs to); the next message says how many went
//!   (`gap`) so the broker can show the history as incomplete.

use crate::chat::adapter::{AgentEvent, LogItem, Part};
use std::collections::VecDeque;

/// Bytes of chat items in one `chat` message (JSON as sent).
pub const BATCH_BYTES: usize = 256 * 1024;
/// Largest text in one item before it is cut (the chat session's own cap).
pub const MAX_TEXT: usize = 131_072;
/// Largest encoded item: texts are cut further until an item fits.
const MAX_ITEM_BYTES: usize = 192 * 1024;
/// Items and bytes held while no broker takes them.
pub const BACKLOG_ITEMS: usize = 4096;
pub const BACKLOG_BYTES: usize = 8 * 1024 * 1024;
pub const TRUNCATED: &str = "… (truncated)";

/// One `chat` message's content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChatChunk {
    pub events: Vec<AgentEvent>,
    pub log: Vec<LogItem>,
    pub input_count: u64,
    /// Items dropped right before this chunk.
    pub gap: u64,
}

fn cut(text: &mut String, max: usize) -> bool {
    if text.len() <= max {
        return false;
    }
    let mut end = max;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text.truncate(end);
    text.push_str(TRUNCATED);
    true
}

fn cut_item(item: &mut LogItem, max: usize) {
    match item {
        LogItem::UserMessage { text, .. } => {
            cut(text, max);
        }
        LogItem::AssistantPart { part, .. } => match part {
            Part::Text { markdown, .. } => {
                cut(markdown, max);
            }
            Part::Tool { name, summary, .. } => {
                cut(name, max);
                cut(summary, max);
            }
            Part::Approval(_) => {}
        },
        LogItem::Backfill(inner) => cut_item(inner, max),
        LogItem::Problem { detail, .. } => {
            cut(detail, max);
        }
        LogItem::ToolResult { text, .. } => {
            cut(text, max);
        }
        LogItem::TurnStarted { .. } | LogItem::TurnEnded { .. } => {}
    }
}

fn cut_event(event: &mut AgentEvent, max: usize) {
    match event {
        AgentEvent::PromptSubmitted { text, .. } => {
            cut(text, max);
        }
        AgentEvent::WaitingForPermission { detail } | AgentEvent::NotReady { detail } => {
            cut(detail, max);
        }
        AgentEvent::SessionStarted { source, .. } => {
            cut(source, max);
        }
        AgentEvent::ToolStarted | AgentEvent::ToolFinished | AgentEvent::TurnEnded { .. } => {}
    }
}

fn size<T: serde::Serialize>(value: &T) -> usize {
    serde_json::to_string(value).map_or(0, |s| s.len() + 1)
}

/// `item` with its texts cut until it encodes within `MAX_ITEM_BYTES`.
pub fn cap_item(mut item: LogItem) -> LogItem {
    let mut max = MAX_TEXT;
    cut_item(&mut item, max);
    while size(&item) > MAX_ITEM_BYTES && max > 64 {
        max /= 2;
        cut_item(&mut item, max);
    }
    item
}

pub fn cap_event(mut event: AgentEvent) -> AgentEvent {
    let mut max = MAX_TEXT;
    cut_event(&mut event, max);
    while size(&event) > MAX_ITEM_BYTES && max > 64 {
        max /= 2;
        cut_event(&mut event, max);
    }
    event
}

/// Bytes of history messages (JSON as sent) in one `chat_history_part` or
/// in the final `chat_snapshot`/`chat_history`: a quarter of the line bound,
/// so the largest message (131 072 bytes of text, escaped) always fits.
pub const SNAPSHOT_CHUNK_BYTES: usize = 1024 * 1024;

/// `history` (oldest first) cut into runs of at most `max_bytes` of encoded
/// messages each, oldest run first; a single larger message is a run of its
/// own. Never empty: no history is one empty run.
pub fn split_history(
    history: Vec<crate::chat::session::ChatMessage>,
    max_bytes: usize,
) -> Vec<Vec<crate::chat::session::ChatMessage>> {
    let mut runs = vec![Vec::new()];
    let mut bytes = 0;
    for message in history {
        let n = size(&message);
        let run = runs.last_mut().expect("never empty");
        if !run.is_empty() && bytes + n > max_bytes {
            runs.push(vec![message]);
            bytes = n;
        } else {
            run.push(message);
            bytes += n;
        }
    }
    runs
}

#[derive(Debug)]
struct Batch {
    events: Vec<AgentEvent>,
    log: VecDeque<LogItem>,
    input_count: u64,
}

impl Batch {
    fn items(&self) -> usize {
        self.events.len() + self.log.len()
    }
}

#[derive(Debug, Default)]
pub struct ChatBacklog {
    batches: VecDeque<Batch>,
    items: usize,
    bytes: usize,
    /// Items dropped since the last chunk taken.
    dropped: u64,
}

impl ChatBacklog {
    pub fn is_empty(&self) -> bool {
        self.batches.is_empty() && self.dropped == 0
    }

    /// What one poll read, with the input count at that moment.
    pub fn push(&mut self, events: Vec<AgentEvent>, log: Vec<LogItem>, input_count: u64) {
        if events.is_empty() && log.is_empty() {
            return;
        }
        let events: Vec<AgentEvent> = events.into_iter().map(cap_event).collect();
        let log: VecDeque<LogItem> = log.into_iter().map(cap_item).collect();
        self.bytes += events.iter().map(size).sum::<usize>() + log.iter().map(size).sum::<usize>();
        self.items += events.len() + log.len();
        self.batches.push_back(Batch {
            events,
            log,
            input_count,
        });
        self.evict();
    }

    /// Drops the oldest items while over the bounds: log items first, then
    /// events other than `SessionStarted`, which moves on to the next batch.
    fn evict(&mut self) {
        while self.items > BACKLOG_ITEMS || self.bytes > BACKLOG_BYTES {
            let Some(front) = self.batches.front_mut() else {
                return;
            };
            if let Some(item) = front.log.pop_front() {
                self.forget(size(&item));
                continue;
            }
            // Only events are left in the oldest batch.
            let events = std::mem::take(&mut front.events);
            let (kept, gone): (Vec<_>, Vec<_>) = events
                .into_iter()
                .partition(|e| matches!(e, AgentEvent::SessionStarted { .. }));
            for event in &gone {
                self.forget(size(event));
            }
            if self.batches.len() == 1 {
                // Nothing newer: keep the session starts here and stop.
                self.batches[0].events = kept;
                if self.batches[0].items() == 0 {
                    self.batches.clear();
                }
                return;
            }
            self.batches.pop_front();
            if let Some(next) = self.batches.front_mut() {
                next.events.splice(0..0, kept);
            }
        }
    }

    fn forget(&mut self, bytes: usize) {
        self.items -= 1;
        self.bytes -= bytes;
        self.dropped += 1;
    }

    /// Everything held, as chunks of at most `BATCH_BYTES` of items each, in
    /// the order the App handles them (events, the log, then turn ends):
    /// a batch is cut along that order, so each chunk keeps it.
    pub fn take(&mut self) -> Vec<ChatChunk> {
        let mut chunks = Vec::new();
        let mut gap = std::mem::take(&mut self.dropped);
        for batch in std::mem::take(&mut self.batches) {
            let (ends, others): (Vec<_>, Vec<_>) = batch
                .events
                .into_iter()
                .partition(|e| matches!(e, AgentEvent::TurnEnded { .. }));
            enum Item {
                Event(AgentEvent),
                Log(LogItem),
            }
            let sequence = others
                .into_iter()
                .map(Item::Event)
                .chain(batch.log.into_iter().map(Item::Log))
                .chain(ends.into_iter().map(Item::Event));
            let mut chunk = ChatChunk {
                events: Vec::new(),
                log: Vec::new(),
                input_count: batch.input_count,
                gap,
            };
            let mut bytes = 0;
            for item in sequence {
                let item_bytes = match &item {
                    Item::Event(e) => size(e),
                    Item::Log(l) => size(l),
                };
                if bytes > 0 && bytes + item_bytes > BATCH_BYTES {
                    let next = ChatChunk {
                        events: Vec::new(),
                        log: Vec::new(),
                        input_count: batch.input_count,
                        gap: 0,
                    };
                    chunks.push(std::mem::replace(&mut chunk, next));
                    bytes = 0;
                }
                bytes += item_bytes;
                match item {
                    Item::Event(e) => chunk.events.push(e),
                    Item::Log(l) => chunk.log.push(l),
                }
            }
            chunks.push(chunk);
            gap = 0;
        }
        if gap > 0 {
            chunks.push(ChatChunk {
                events: Vec::new(),
                log: Vec::new(),
                input_count: 0,
                gap,
            });
        }
        self.items = 0;
        self.bytes = 0;
        chunks
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chat::adapter::Outcome;
    use crate::runtime::worker_protocol::{MAX_LINE, WorkerMsg, encode_worker};

    fn part(text: String) -> LogItem {
        LogItem::AssistantPart {
            message_id: "m".into(),
            part: Part::Text {
                id: "p".into(),
                markdown: text,
            },
            turn_id: "t".into(),
            created_at_ms: 1,
        }
    }

    fn started(id: &str) -> AgentEvent {
        AgentEvent::SessionStarted {
            session_id: id.into(),
            log_path: "/tmp/l".into(),
            source: "resume".into(),
            same_log: false,
        }
    }

    fn line(chunk: &ChatChunk) -> String {
        encode_worker(&WorkerMsg::Chat {
            events: chunk.events.clone(),
            log: chunk.log.clone(),
            input_count: chunk.input_count,
            chat_v1: true,
            reason: None,
            unavailable: Vec::new(),
            gap: chunk.gap,
        })
    }

    #[test]
    fn a_huge_backfill_is_cut_into_messages_and_an_oversized_item_truncated() {
        let mut backlog = ChatBacklog::default();
        let mut log: Vec<LogItem> = (0..400)
            .map(|i| LogItem::Backfill(Box::new(part(format!("{i}:{}", "x".repeat(4000))))))
            .collect();
        // One entry of 1 MiB of control characters (6 bytes each as JSON).
        log.push(LogItem::Backfill(Box::new(part(
            "\u{1}".repeat(1024 * 1024),
        ))));
        log.push(LogItem::TurnEnded {
            turn_id: "t".into(),
            outcome: Outcome::Done,
            at_ms: 1,
        });
        backlog.push(
            vec![started("s"), AgentEvent::TurnEnded { at_ms: None }],
            log,
            7,
        );
        let chunks = backlog.take();
        assert!(chunks.len() > 5, "{}", chunks.len());
        for chunk in &chunks {
            assert!(line(chunk).len() < BATCH_BYTES + 4096);
            assert!(line(chunk).len() < MAX_LINE);
            assert_eq!(chunk.input_count, 7);
            assert_eq!(chunk.gap, 0);
        }
        // Order kept: the session start first, the turn end last, every item once.
        assert_eq!(chunks[0].events, vec![started("s")]);
        assert_eq!(
            chunks.last().unwrap().events,
            vec![AgentEvent::TurnEnded { at_ms: None }]
        );
        let log: Vec<&LogItem> = chunks.iter().flat_map(|c| &c.log).collect();
        assert_eq!(log.len(), 402);
        let LogItem::Backfill(big) = log[400] else {
            panic!()
        };
        let LogItem::AssistantPart {
            part: Part::Text { markdown, .. },
            ..
        } = big.as_ref()
        else {
            panic!()
        };
        assert!(markdown.ends_with(TRUNCATED));
        assert!(markdown.len() < MAX_TEXT);
        assert!(backlog.take().is_empty());
    }

    #[test]
    fn long_texts_are_cut_at_the_chat_cap_on_a_char_boundary() {
        let item = cap_item(LogItem::UserMessage {
            id: "u".into(),
            turn_id: "t".into(),
            text: "é".repeat(MAX_TEXT),
            created_at_ms: 1,
        });
        let LogItem::UserMessage { text, .. } = item else {
            panic!()
        };
        assert!(text.ends_with(TRUNCATED) && text.len() <= MAX_TEXT + TRUNCATED.len());
        let event = cap_event(AgentEvent::PromptSubmitted {
            text: "a".repeat(MAX_TEXT + 1),
            turn_id: None,
            at_ms: None,
        });
        assert_eq!(
            event,
            AgentEvent::PromptSubmitted {
                text: format!("{}{TRUNCATED}", "a".repeat(MAX_TEXT)),
                turn_id: None,
                at_ms: None,
            }
        );
        let small = part("fine".into());
        assert_eq!(cap_item(small.clone()), small);
    }

    #[test]
    fn each_batch_keeps_its_own_input_count() {
        let mut backlog = ChatBacklog::default();
        backlog.push(
            vec![AgentEvent::PromptSubmitted {
                text: "a".into(),
                turn_id: None,
                at_ms: None,
            }],
            vec![],
            1,
        );
        backlog.push(vec![], vec![part("b".into())], 3);
        backlog.push(vec![], vec![], 9);
        let counts: Vec<u64> = backlog.take().iter().map(|c| c.input_count).collect();
        assert_eq!(counts, [1, 3]);
    }

    #[test]
    fn overflow_drops_the_oldest_but_keeps_session_starts_and_reports_the_gap() {
        let mut backlog = ChatBacklog::default();
        backlog.push(
            vec![started("one"), AgentEvent::ToolStarted],
            vec![part("old".into())],
            1,
        );
        for i in 0..BACKLOG_ITEMS {
            backlog.push(vec![], vec![part(format!("n{i}"))], 2);
        }
        let chunks = backlog.take();
        let dropped: u64 = chunks.iter().map(|c| c.gap).sum();
        assert_eq!(chunks[0].gap, dropped);
        assert!(dropped >= 3, "{dropped}");
        // The session start survived, ahead of what followed it.
        assert_eq!(chunks[0].events, vec![started("one")]);
        let log: Vec<&LogItem> = chunks.iter().flat_map(|c| &c.log).collect();
        assert!(!log.contains(&&part("old".into())));
        assert_eq!(log.last(), Some(&&part(format!("n{}", BACKLOG_ITEMS - 1))));
        let items: usize = chunks.iter().map(|c| c.events.len() + c.log.len()).sum();
        assert!(items <= BACKLOG_ITEMS);

        // By bytes too; a lone batch keeps its session start.
        let mut backlog = ChatBacklog::default();
        let log = (0..100).map(|_| part("z".repeat(120_000))).collect();
        backlog.push(vec![started("two")], log, 1);
        let chunks = backlog.take();
        assert!(chunks[0].gap > 0);
        assert_eq!(chunks[0].events, vec![started("two")]);
        let bytes: usize = chunks.iter().map(|c| line(c).len()).sum();
        assert!(bytes <= BACKLOG_BYTES + chunks.len() * 4096);
    }
}
