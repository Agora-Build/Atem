//! The sending host's live puts on its Station link (host-work-v1 §11.5,
//! "The mailbox calls", rule 8), behind the debug-only hook's
//! `host.senders`: what goes to the Station for the put engine's due rows
//! ([`super::outbox`]), and which answers apply. Pure: the rows are handed
//! in ([`PutClient::take`]) and the store's writes are the bridge's
//! (`send_pass.rs`).
//!
//! - Puts go only once the Station associated the link with this host
//!   (rule 1): after a `heads` on this link generation announcing this
//!   host's mailbox, as the mailbox's own calls wait for one; none while
//!   the latest `heads` announces none (a Station that serves no mailbox).
//! - At most [`MAX_LIVE_PUTS`] live per link generation, each with a fresh
//!   lowercase UUID v4 `request_id`; a row being put isn't due again.
//! - `mailbox_stored` and `mailbox_put_refused` apply only to a live put
//!   with that `request_id` and `id` ([`MailboxStored::answers`]); one of a
//!   retired put is drained, one the host never sent is unsolicited:
//!   counted, no Station fault (nothing rests on it).
//! - A put unanswered for 35 s is retired: its row is due again, put with
//!   a fresh id (puts are idempotent).
//! - A new link generation retires every live put (their rows go again on
//!   it); an identity change on the live link retires them and nothing more
//!   is put on that socket (§11.4, "An identity change").
use super::outbox::{Due, Place};
use super::station::StationLink;
use super::sync::{RETIRED_KEPT, SYNC_TIMEOUT_MS};
use atem_client::host_mail::mailbox::{MailboxPut, MailboxPutRefused, MailboxStored};
use atem_client::host_mail::parse_object;
use serde_json::{Value, json};
use std::collections::VecDeque;

/// The most puts live per link generation (rule 8).
pub const MAX_LIVE_PUTS: usize = 8;

/// A live `mailbox_put`, and the row it puts.
#[derive(Debug, Clone)]
struct Live {
    call: MailboxPut,
    n: i64,
    sent_at: u64,
    /// Where it went: its link generation and the committed head then.
    place: Place,
}

/// What an answer is to the live puts ([`PutClient::on_stored`],
/// [`PutClient::on_refused`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Answer {
    /// It answers the live put of row `n`, which went at that place (a
    /// `forbidden` is held there: a list move since the put counts, review
    /// L-N2).
    Row(i64, Place),
    /// A retired put's (answered, unanswered for 35 s, of an earlier link
    /// generation or identity): nothing applies.
    Drained,
    /// One the host never sent (or no longer keeps): nothing applies.
    Unsolicited,
}

/// The host's live puts on its Station link (rule 8): at most
/// [`MAX_LIVE_PUTS`] per link generation, each with a fresh `request_id`;
/// an answer applies only to a live put with that `request_id` and `id`;
/// one unanswered for 35 s is retired (its row is due again, a fresh id);
/// a new link generation or an identity change retires them all, and
/// after an identity change nothing more is put on that socket.
#[derive(Debug, Default)]
pub struct PutClient {
    link: Option<(u64, u64)>,
    /// The latest `heads` on this link generation announced this host's
    /// mailbox.
    announced: bool,
    moved: bool,
    now: u64,
    live: Vec<Live>,
    retired: VecDeque<String>,
    /// Due rows whose bytes no longer read, for the store to refuse.
    unreadable: Vec<i64>,
    sent: u64,
    stored: u64,
    refused: u64,
    timeouts: u64,
    drained: u64,
    unsolicited: u64,
}

impl PutClient {
    /// The link as the Station link has it (`None`: down).
    pub fn on_link(&mut self, link: Option<&StationLink>) {
        let now = link.map(|l| (l.link_gen, l.socket));
        if now == self.link {
            return;
        }
        self.retire_all();
        self.announced = false;
        if now.map(|(_, socket)| socket) != self.link.map(|(_, socket)| socket) {
            self.moved = false;
        }
        self.link = now;
    }

    /// A `heads` on the link, announcing this host's mailbox or not.
    /// Nothing counts on a socket whose identity moved.
    pub fn on_heads(&mut self, mailbox: bool) {
        if self.link.is_some() && !self.moved {
            self.announced = mailbox;
        }
    }

    /// The host's identity changed on the live link: every live put
    /// retired, nothing more put on that socket.
    pub fn on_identity_moved(&mut self) {
        self.retire_all();
        self.announced = false;
        self.moved = true;
    }

    /// The pass's monotonic time: a put unanswered for 35 s is retired.
    pub fn tick(&mut self, now: u64) {
        self.now = now;
        let late: Vec<String> = self
            .live
            .iter()
            .filter(|l| now >= l.sent_at.saturating_add(SYNC_TIMEOUT_MS))
            .map(|l| l.call.request_id.clone())
            .collect();
        self.timeouts += late.len() as u64;
        for id in late {
            self.retire(&id);
        }
    }

    /// The rows being put now (not due again until answered or retired).
    pub fn live_rows(&self) -> Vec<i64> {
        self.live.iter().map(|l| l.n).collect()
    }

    /// The puts of `due` to send now, live from now (none without a link,
    /// before its `heads` announced this host's mailbox, after an identity
    /// change, or past [`MAX_LIVE_PUTS`]). A row whose bytes no longer read
    /// isn't put: it is reported ([`PutClient::take_unreadable`]) for the
    /// store to refuse.
    pub fn take(&mut self, due: Vec<Due>, place: Place) -> Vec<MailboxPut> {
        let mut out = Vec::new();
        if self.link.is_none() || self.moved || !self.announced {
            return out;
        }
        for row in due {
            if self.live.len() >= MAX_LIVE_PUTS {
                break;
            }
            if self.live.iter().any(|l| l.n == row.n) {
                continue;
            }
            let Ok(object) = parse_object(&row.bytes) else {
                self.unreadable.push(row.n);
                continue;
            };
            let call = MailboxPut::new(super::mailbox::fresh_request_id(), object);
            self.live.push(Live {
                call: call.clone(),
                n: row.n,
                sent_at: self.now,
                place,
            });
            self.sent += 1;
            out.push(call);
        }
        out
    }

    /// The rows `take` found whose bytes no longer read (taken).
    pub fn take_unreadable(&mut self) -> Vec<i64> {
        std::mem::take(&mut self.unreadable)
    }

    /// The put `request_id` wasn't handed to the link: no longer live (its
    /// row is due again), its id never one an answer may carry.
    pub fn unsent(&mut self, request_id: &str) {
        self.live.retain(|l| l.call.request_id != request_id);
    }

    /// `mailbox_stored`.
    pub fn on_stored(&mut self, stored: &MailboxStored) -> Answer {
        let answer = self.answer(&stored.request_id, |put| stored.answers(put).is_ok());
        if matches!(answer, Answer::Row(..)) {
            self.stored += 1;
        }
        answer
    }

    /// `mailbox_put_refused`.
    pub fn on_refused(&mut self, refused: &MailboxPutRefused) -> Answer {
        let answer = self.answer(&refused.request_id, |put| refused.answers(put).is_ok());
        if matches!(answer, Answer::Row(..)) {
            self.refused += 1;
        }
        answer
    }

    fn answer(&mut self, request_id: &str, answers: impl Fn(&MailboxPut) -> bool) -> Answer {
        match self.live.iter().find(|l| l.call.request_id == request_id) {
            Some(live) if answers(&live.call) => {
                let (n, place) = (live.n, live.place);
                self.retire(request_id);
                Answer::Row(n, place)
            }
            Some(_) => {
                self.unsolicited += 1;
                Answer::Unsolicited
            }
            None if self.retired.iter().any(|id| id == request_id) => {
                self.drained += 1;
                Answer::Drained
            }
            None => {
                self.unsolicited += 1;
                Answer::Unsolicited
            }
        }
    }

    fn retire(&mut self, request_id: &str) {
        self.live.retain(|l| l.call.request_id != request_id);
        if self.retired.len() >= RETIRED_KEPT {
            self.retired.pop_front();
        }
        self.retired.push_back(request_id.to_owned());
    }

    fn retire_all(&mut self) {
        let ids: Vec<String> = self
            .live
            .iter()
            .map(|l| l.call.request_id.clone())
            .collect();
        for id in ids {
            self.retire(&id);
        }
    }

    /// For the state dump.
    pub fn dump(&self) -> Value {
        json!({
            "live": self.live.iter().map(|l| l.n).collect::<Vec<_>>(),
            "sent": self.sent,
            "stored": self.stored,
            "refused": self.refused,
            "timeouts": self.timeouts,
            "drained": self.drained,
            "unsolicited": self.unsolicited,
            "announced": self.announced,
            "identity_moved": self.moved,
        })
    }
}

#[cfg(test)]
#[path = "puts_tests.rs"]
mod tests;
