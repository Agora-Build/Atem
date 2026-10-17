//! Push requests for the relay (atem-session §6a): `push_approval` when an
//! approval opens, `push_resolved` when it stops being pending. Best effort
//! and bounded: it never blocks an approval or touches a receipt. While the
//! link is down it keeps the latest state per approval; on reconnect it
//! sends `push_approval` only for approvals still pending and not expired,
//! and `push_resolved` only for ones whose `push_approval` went out.
//!
//! Beyond `MAX_PUSHES` entries one unsent entry is evicted — an expired one
//! first, else the oldest (possibly the new one). An approval already pushed
//! is never evicted: its `push_resolved` must still go out. (The new entry
//! is always unsent, so there is always one to evict.)

use crate::session_protocol::wire::ApprovalCloseReason;
use serde_json::{Value, json};
use std::collections::VecDeque;

/// Entries kept at most.
pub const MAX_PUSHES: usize = 64;

#[derive(Debug, Clone)]
struct Entry {
    approval_id: String,
    /// `push_approval`'s data.
    request: Value,
    /// Wall ms when the agent's hook gives up.
    expires_at: u64,
    /// `push_approval` went out.
    sent: bool,
    /// No longer pending.
    resolved: Option<ApprovalCloseReason>,
}

#[derive(Debug, Default)]
pub struct PushQueue {
    entries: VecDeque<Entry>,
}

/// The relay message for `data`.
pub fn relay_message(data: Value) -> String {
    json!({"type": "relay", "data": data}).to_string()
}

fn resolved_data(approval_id: &str, reason: ApprovalCloseReason) -> Value {
    json!({"v": 1, "op": "push_resolved", "approval_id": approval_id, "reason": reason})
}

impl PushQueue {
    /// A new pending approval (`request`: `push_approval`'s data).
    pub fn open(&mut self, approval_id: &str, request: Value, expires_at: u64, wall: u64) {
        self.entries.push_back(Entry {
            approval_id: approval_id.to_string(),
            request,
            expires_at,
            sent: false,
            resolved: None,
        });
        while self.entries.len() > MAX_PUSHES {
            let expired = self
                .entries
                .iter()
                .position(|e| !e.sent && e.expires_at <= wall);
            let Some(at) = expired.or_else(|| self.entries.iter().position(|e| !e.sent)) else {
                break;
            };
            self.entries.remove(at);
        }
    }

    /// The approval is no longer pending: never pushed → forgotten;
    /// pushed → `push_resolved` is due.
    pub fn resolve(&mut self, approval_id: &str, reason: ApprovalCloseReason) {
        let Some(i) = self
            .entries
            .iter()
            .position(|e| e.approval_id == approval_id)
        else {
            return;
        };
        if self.entries[i].sent {
            self.entries[i].resolved = Some(reason);
        } else {
            self.entries.remove(i);
        }
    }

    /// Sends what is due, in order, while `send` succeeds (a failure stops
    /// the pass; the rest stays for the next one). Nothing without a link.
    pub fn flush(&mut self, link_up: bool, wall: u64, send: &mut dyn FnMut(String) -> bool) {
        if !link_up {
            return;
        }
        // Expired before it went out: no longer relevant.
        self.entries
            .retain(|e| e.sent || e.resolved.is_some() || e.expires_at > wall);
        let mut i = 0;
        while i < self.entries.len() {
            let e = &self.entries[i];
            let data = match (e.sent, e.resolved) {
                (false, None) => e.request.clone(),
                (true, Some(reason)) => resolved_data(&e.approval_id, reason),
                _ => {
                    i += 1;
                    continue;
                }
            };
            if !send(relay_message(data)) {
                return;
            }
            if self.entries[i].sent {
                self.entries.remove(i);
            } else {
                self.entries[i].sent = true;
                i += 1;
            }
        }
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.entries.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ApprovalCloseReason::*;

    fn request(id: &str) -> Value {
        json!({"v": 1, "op": "push_approval", "approval_id": id})
    }

    /// (op, approval_id, reason?) of what went out.
    fn sent(out: &[String]) -> Vec<(String, String, Option<String>)> {
        out.iter()
            .map(|t| {
                let v: Value = serde_json::from_str(t).unwrap();
                assert_eq!(v["type"], "relay");
                let d = &v["data"];
                (
                    d["op"].as_str().unwrap().to_string(),
                    d["approval_id"].as_str().unwrap().to_string(),
                    d["reason"].as_str().map(str::to_string),
                )
            })
            .collect()
    }

    fn open(q: &mut PushQueue, id: &str, expires_at: u64) {
        q.open(id, request(id), expires_at, 1);
    }

    fn flush(q: &mut PushQueue, up: bool, wall: u64) -> Vec<String> {
        let mut out = Vec::new();
        q.flush(up, wall, &mut |t| {
            out.push(t);
            true
        });
        out
    }

    fn p(op: &str, id: &str, reason: Option<&str>) -> (String, String, Option<String>) {
        (op.into(), id.into(), reason.map(str::to_string))
    }

    #[test]
    fn nothing_goes_out_without_a_link() {
        let mut q = PushQueue::default();
        open(&mut q, "a", 1000);
        assert!(flush(&mut q, false, 0).is_empty());
        assert_eq!(
            sent(&flush(&mut q, true, 0)),
            [p("push_approval", "a", None)]
        );
    }

    /// A send that keeps failing (a full or dead link) costs one attempt
    /// per pass and loses nothing; the queue holds no approval or receipt
    /// state, so it can't change either.
    #[test]
    fn a_failing_link_never_blocks() {
        let mut q = PushQueue::default();
        for i in 0..MAX_PUSHES {
            open(&mut q, &format!("a{i}"), 1000);
        }
        let mut attempts = 0;
        q.flush(true, 0, &mut |_| {
            attempts += 1;
            false
        });
        assert_eq!(attempts, 1);
        assert_eq!(q.len(), MAX_PUSHES);
        assert_eq!(flush(&mut q, true, 0).len(), MAX_PUSHES);
    }

    #[test]
    fn an_approval_resolved_before_it_was_pushed_is_dropped() {
        let mut q = PushQueue::default();
        open(&mut q, "a", 1000);
        q.resolve("a", AnsweredTerminal);
        assert!(flush(&mut q, true, 0).is_empty());
        assert_eq!(q.len(), 0);
    }

    #[test]
    fn an_unsent_approval_expires() {
        let mut q = PushQueue::default();
        open(&mut q, "a", 1000);
        open(&mut q, "b", 5000);
        assert_eq!(
            sent(&flush(&mut q, true, 1000)),
            [p("push_approval", "b", None)]
        );
    }

    #[test]
    fn pushed_then_resolved_while_down_sends_only_the_resolution() {
        let mut q = PushQueue::default();
        open(&mut q, "a", 1000);
        assert_eq!(
            sent(&flush(&mut q, true, 0)),
            [p("push_approval", "a", None)]
        );
        // The link drops; it is answered meanwhile.
        q.resolve("a", AnsweredRemote);
        assert!(flush(&mut q, false, 10).is_empty());
        // Reconnected, even after its expiry: only push_resolved, once.
        assert_eq!(
            sent(&flush(&mut q, true, 5000)),
            [p("push_resolved", "a", Some("answered_remote"))]
        );
        assert!(flush(&mut q, true, 5000).is_empty());
        assert_eq!(q.len(), 0);
    }

    #[test]
    fn a_failed_send_keeps_the_order() {
        let mut q = PushQueue::default();
        for id in ["a", "b", "c"] {
            open(&mut q, id, 1000);
        }
        let mut n = 0;
        let mut first = Vec::new();
        q.flush(true, 0, &mut |t| {
            n += 1;
            if n == 2 {
                return false;
            }
            first.push(t);
            true
        });
        assert_eq!(sent(&first), [p("push_approval", "a", None)]);
        q.resolve("a", TimedOut);
        assert_eq!(
            sent(&flush(&mut q, true, 0)),
            [
                p("push_resolved", "a", Some("timed_out")),
                p("push_approval", "b", None),
                p("push_approval", "c", None)
            ]
        );
    }

    #[test]
    fn eviction_spares_pushed_approvals_until_it_must() {
        let mut q = PushQueue::default();
        // One pushed and still pending.
        open(&mut q, "pushed", 10_000);
        flush(&mut q, true, 0);
        // Then a full queue of unsent ones (the link is down), one expired.
        open(&mut q, "expired", 1);
        for i in 0..MAX_PUSHES - 2 {
            open(&mut q, &format!("u{i}"), 10_000);
        }
        assert_eq!(q.len(), MAX_PUSHES);
        // Over the bound: the expired unsent one goes first...
        open(&mut q, "n1", 10_000);
        assert_eq!(q.len(), MAX_PUSHES);
        // ...then the oldest unsent one, never the pushed one.
        open(&mut q, "n2", 10_000);
        assert_eq!(q.len(), MAX_PUSHES);
        q.resolve("pushed", AnsweredTerminal);
        let due = sent(&flush(&mut q, true, 0));
        assert!(!due.iter().any(|(_, id, _)| id == "expired" || id == "u0"));
        assert_eq!(
            due[0],
            p("push_resolved", "pushed", Some("answered_terminal"))
        );
        assert!(due.contains(&p("push_approval", "u1", None)));
        // A queue of pushed ones only: the new one goes, the pushed stay.
        let mut q = PushQueue::default();
        for i in 0..MAX_PUSHES {
            open(&mut q, &format!("s{i}"), 10_000);
        }
        flush(&mut q, true, 0);
        open(&mut q, "late", 10_000);
        assert_eq!(q.len(), MAX_PUSHES);
        assert!(flush(&mut q, true, 0).is_empty());
        for i in 0..MAX_PUSHES {
            q.resolve(&format!("s{i}"), Released);
        }
        assert_eq!(flush(&mut q, true, 0).len(), MAX_PUSHES);
    }
}
