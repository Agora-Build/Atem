//! The client's log against the host's signed head (§R9.7 step 3) and what
//! its `hello` carries (§R9.3's table). The client never adopts the host's
//! head: a head beyond its own is a reason to fetch the suffix from the
//! relay and verify it ([`crate::membership::Membership::evaluate_objects`]),
//! after which [`super::HostHead::reached_by`] tells whether it reached it.
use crate::SignedObject;
use crate::membership::{Head, Membership};

/// At most this many entries per `hello` (§R9.3).
pub const MAX_CARRIED_ENTRIES: usize = crate::membership::MAX_CARRIAGE_ENTRIES;
/// At most this many bytes of carried entries, measured by
/// [`carried_bytes`] (the client's planner and the host's
/// [`Membership::evaluate`] use the same measure).
pub const MAX_CARRIED_BYTES: usize = crate::membership::MAX_CARRIAGE_BYTES;

/// The one measure of a carriage's size (§R9.3 "at most 64 entries /
/// 256 KiB"): the length of the `entries` array in its compact JSON
/// encoding, `[e1,e2,…]` (brackets and commas included), each entry the
/// compact encoding of its wire object. The hello builder emits exactly this
/// encoding, so the bytes the host receives and the bytes the client
/// budgeted are the same.
pub fn carried_bytes<'a>(entries: impl IntoIterator<Item = &'a serde_json::Value>) -> usize {
    let mut total = 1; // '['
    let mut n = 0;
    for entry in entries {
        total += entry.to_string().len() + 1; // the entry, then ',' or ']'
        n += 1;
    }
    if n == 0 { 2 } else { total }
}

/// The client can't build the window the host asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CarryError {
    /// The host's `need_before` is at or before the start of the widest
    /// window this client can carry (64 entries ending at `min(s, own
    /// head)`): the divergence is deeper than any carriage. Reconnecting
    /// would repeat the same window, so the client stops and reports it (a
    /// manager must look at the two branches; R9.4).
    DivergenceTooDeep { need_before: u64, earliest: u64 },
}

/// How the client's verified log relates to the head the host signed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeadRelation {
    /// Same head.
    Same,
    /// The client holds the host's head and more: it carries its suffix.
    HostBehind,
    /// The host's head is beyond the client's: it carries nothing, fetches
    /// from the relay after `welcome` and verifies up to that head (a
    /// mismatch then makes it the diverged case on its next connect).
    HostAhead,
    /// The client holds another entry at the host's `seq`: it carries a
    /// window ending there.
    Diverged,
}

impl HeadRelation {
    pub fn of(log: &Membership, host: Head) -> Self {
        let own = log.head();
        match log.entry(host.seq) {
            Some(entry) if entry.hash() == host.hash => {
                if own.seq == host.seq {
                    HeadRelation::Same
                } else {
                    HeadRelation::HostBehind
                }
            }
            Some(_) => HeadRelation::Diverged,
            None => HeadRelation::HostAhead,
        }
    }
}

/// One entry's share of [`carried_bytes`]: its compact wire JSON and the
/// `,` or `]` after it.
fn entry_size(log: &Membership, seq: u64) -> usize {
    log.entry(seq)
        .expect("within the log")
        .object()
        .to_json()
        .to_string()
        .len()
        + 1
}

/// The `hello`'s `membership{head, entries, more?}`, and whether to fetch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Carriage {
    /// The client's own head.
    pub head: Head,
    pub entries: Vec<SignedObject>,
    pub more: bool,
    /// The host's head the client must fetch and verify up to (never
    /// adopted unverified).
    pub fetch_to: Option<Head>,
}

impl Carriage {
    /// §R9.3: the suffix after the host's head (≤ 64 entries / 256 KiB,
    /// `more` when longer); for a divergence the window ending at
    /// `min(host seq, own head)`: that one entry first (the fixtures'
    /// window), the widest window (64 entries) after the host answered
    /// `membership_invalid` with `need_before`; none when the host is ahead.
    ///
    /// The byte budget is [`carried_bytes`] of the entries, the measure the
    /// host bounds.
    pub fn plan(
        log: &Membership,
        host: Head,
        need_before: Option<u64>,
    ) -> Result<Self, CarryError> {
        let own = log.head();
        let mut carriage = Carriage {
            head: own,
            entries: Vec::new(),
            more: false,
            fetch_to: None,
        };
        match HeadRelation::of(log, host) {
            HeadRelation::Same => {}
            HeadRelation::HostAhead => carriage.fetch_to = Some(host),
            HeadRelation::HostBehind => {
                // `[` then each entry followed by `,` or `]`: the running
                // total is `carried_bytes` of the entries taken so far.
                let mut bytes = 1;
                for seq in host.seq + 1..=own.seq {
                    let object = log.entry(seq).expect("within the log").object();
                    let size = entry_size(log, seq);
                    if carriage.entries.len() == MAX_CARRIED_ENTRIES
                        || bytes + size > MAX_CARRIED_BYTES
                    {
                        carriage.more = true;
                        break;
                    }
                    bytes += size;
                    carriage.entries.push(object.clone());
                }
            }
            HeadRelation::Diverged => {
                let end = host.seq.min(own.seq);
                // The widest window: up to 64 entries ending at `end`, within
                // the byte budget (taken backwards from `end`).
                let mut earliest = end;
                let mut bytes = 1 + entry_size(log, end);
                while earliest > 1 && (end - earliest + 1) < MAX_CARRIED_ENTRIES as u64 {
                    let size = entry_size(log, earliest - 1);
                    if bytes + size > MAX_CARRIED_BYTES {
                        break;
                    }
                    bytes += size;
                    earliest -= 1;
                }
                // The host said the divergence is before the first window:
                // the second one is the widest. If even that starts at or
                // after `need_before`, no window can reach the divergence:
                // stop instead of sending the same window again.
                let start = match need_before {
                    None => end,
                    Some(need_before) if earliest >= need_before => {
                        return Err(CarryError::DivergenceTooDeep {
                            need_before,
                            earliest,
                        });
                    }
                    Some(_) => earliest,
                };
                carriage.entries = (start..=end)
                    .map(|seq| log.entry(seq).expect("within the log").object().clone())
                    .collect();
            }
        }
        Ok(carriage)
    }

    /// [`carried_bytes`] of this carriage's entries.
    pub fn bytes(&self) -> usize {
        let values: Vec<serde_json::Value> =
            self.entries.iter().map(SignedObject::to_json).collect();
        carried_bytes(&values)
    }
}
