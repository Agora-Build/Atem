//! The client's log against the host's signed head (§R9.7 step 3) and what
//! its `hello` carries (§R9.3's table). The client never adopts the host's
//! head: a head beyond its own is a reason to fetch the suffix from the
//! relay and verify it ([`crate::membership::Membership::evaluate_objects`]),
//! after which [`super::HostHead::reached_by`] tells whether it reached it.
use crate::SignedObject;
use crate::membership::{Head, Membership};

/// At most this many entries per `hello` (§R9.3).
pub const MAX_CARRIED_ENTRIES: usize = 64;
/// At most this many bytes of carried entries (their wire JSON).
pub const MAX_CARRIED_BYTES: usize = 256 * 1024;

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
    pub fn plan(log: &Membership, host: Head, need_before: Option<u64>) -> Self {
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
                let mut bytes = 0;
                for seq in host.seq + 1..=own.seq {
                    let object = log.entry(seq).expect("within the log").object();
                    let size = object.to_json().to_string().len();
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
                let earliest = end.saturating_sub(MAX_CARRIED_ENTRIES as u64 - 1).max(1);
                // The host said the divergence is before the first window:
                // the second one is the widest (64 entries).
                let start = if need_before.is_some() { earliest } else { end };
                carriage.entries = (start..=end)
                    .map(|seq| log.entry(seq).expect("within the log").object().clone())
                    .collect();
            }
        }
        carriage
    }
}
