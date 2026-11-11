//! The receiver's checks 1 to 6 of an envelope (delegated host-work design
//! II.4.2) and the sending host's check of a result (II.4.4).
//!
//! [`open_envelope`] judges an `atem-envelope` that arrived in this host's
//! mailbox, from this host's own device list and clock, in the design's
//! order:
//!
//! 1. **Strict parse and pin.** The body's exact fields ([`MailBody`]), the
//!    `type`, and `account_id` and `genesis_hash` equal this list's.
//! 2. **The recipient.** It is this host, at its current trust generation,
//!    and `enc_kid` names one of the keys the caller passes in
//!    [`Recipient::keys`] (its current key; its previous one only while the 24 h
//!    window and a rotation's `retire_previous` allow it, which is the
//!    caller's to say).
//! 3. **The sender.** A current host, at exactly its newest `add_host`
//!    generation; `authorized(g)` at this list's head; `signed_at_head.seq`
//!    at least `g`; and this list's entry at `signed_at_head.seq` has
//!    `signed_at_head.hash`. A sender signs at a head that includes its own
//!    `add_host`, so the claimed generation's `add_host` is also at or before
//!    `signed_at_head.seq`. What this list's head settles is refused: a
//!    sender it doesn't know, has removed or holds `revoked`, a generation
//!    below the sender's newest or one this list doesn't hold at that head
//!    (`generation_ahead`), a `signed_at_head` before `g` or with another
//!    hash.
//! 4. **The signature**, with the key of the sender's newest `add_host`
//!    ([`VerifiedMail::verify`]: the only way to a [`VerifiedMail`], which is
//!    all `unseal_*` take).
//! 5. **The times.** `expires_at` after `created_at`, at most 24 h later, not
//!    passed; `created_at` at most 60 s ahead of the caller's clock.
//! 6. **`sealed_hash`, the open, the plaintext's strict parse**, and (for a
//!    request) the Message's id, times and sender equal to the body's and a
//!    Message a host sender may send ([`Message::valid_from_host`]).
//!
//! **Pending.** A `signed_at_head.seq` beyond this host's head can't be
//! judged yet, whatever the sender's standing in this list: entries this host
//! hasn't seen may add the sender (unknown here), re-add it (removed), readmit
//! it (revoked) or bring its newer generation, and no sender can know the hash
//! of an entry that doesn't exist. Step 5 runs first, on the body's times; an
//! object that fails it is [`EnvelopeVerdict::Refused`]. Then, when this list
//! already holds the claimed `(host_id, host_trust_gen)`'s `add_host` (a
//! current or removed host at its newest generation), the signature is
//! checked before waiting, since that pair has exactly one key forever: a bad
//! one is `bad_signature`, so junk can't fill a known sender's waiting slots.
//! Otherwise the signature can't be checked yet. An object that passes is
//! [`EnvelopeVerdict::Pending`], to be judged again after each device-list
//! advance. When the head is **not** beyond this list's, that head settles the
//! standing and the generation: an unknown sender at or below it is
//! `unknown_sender`, a removed one `removed_sender`, a revoked one
//! `revoked_sender`, and a claimed generation the list doesn't hold, or whose
//! `add_host` comes after `signed_at_head.seq`, is `generation_ahead`: at a
//! head this list holds it knows the list the sender signed at (generations
//! rise with `seq`), so every head gives the same verdict.
//!
//! **Refused or refused-authenticated.** Until step 4 passes, nothing says who
//! sent the object, so a failure is [`EnvelopeVerdict::Refused`] (kept as
//! evidence; nothing is told to anyone). After it, the sender is
//! authenticated and a failure of step 5 or 6 is
//! [`EnvelopeVerdict::RefusedAuthenticated`]: the host answers it with a
//! status naming the object's id and `refused: "invalid_request"` (II.4.4).
//!
//! [`accept_result`] is the sending host's side of II.4.4: the same checks 1
//! to 6 for an `atem-result` (`atem-result-v1`, `atem-result-seal-v1`), with
//! these differences: the sender must be the recipient host of the outbox row
//! ([`ExpectedResult`]); check 3's `authorized` and `current` parts don't
//! refuse a result: a result of a host this list holds revoked, or has
//! removed, is verified (with the key that host last held, a removed host's
//! from [`Membership::removed_host`]) and returned as
//! [`ResultVerdict::NotDelivered`], to be kept as data (II.4.4); and step 6's
//! plaintext must answer the row. A result that doesn't verify is refused.
//! The delivery rule itself (the return grant, route and project) stays in
//! the host.
//!
//! This module only judges. It never marks anything done, stores, counts
//! pending objects or delivers a result.
use crate::encoding::{Hash32, hex_decode_array};
use crate::error::Error;
use crate::host_mail::{
    EnvelopePlain, HostRef, MailBody, MailKind, ResultPlain, VerifiedMail, unseal_envelope,
    unseal_result,
};
use crate::host_principal::host_principal;
use crate::keys::{PublicKey, enc_kid_bytes};
use crate::membership::{Action, HostSenderState, Membership};
use crate::provider::{KeyId, KeyProvider};
use crate::session::host_work::MAX_LIFETIME_MS;
use crate::signed::SignedObject;

/// `created_at` may be at most this far ahead of the host's clock at first
/// acceptance (host-work-v1 §5).
pub const MAX_CREATED_AHEAD_MS: u64 = 60_000;

/// The reasons a verdict names: short, snake_case and stable, except
/// [`NOT_DELIVERED_SENDER_REVOKED`] and [`NOT_DELIVERED_SENDER_REMOVED`], which
/// are II.4.4's return-grant details, quoted. The design names no other; the
/// host reports an authenticated refusal to its sender as `invalid_request`
/// whatever the reason.
pub mod reason {
    /// Check 1: not an envelope or a result, or a body that isn't exactly one.
    pub const MALFORMED: &str = "malformed";
    /// An envelope given to [`accept_result`](super::accept_result), or a
    /// result to [`open_envelope`](super::open_envelope).
    pub const WRONG_KIND: &str = "wrong_kind";
    /// Check 1: `account_id` or `genesis_hash` isn't this list's.
    pub const PIN_MISMATCH: &str = "pin_mismatch";
    /// Check 2: the recipient is another host.
    pub const NOT_FOR_THIS_HOST: &str = "not_for_this_host";
    /// Check 2: the recipient's trust generation isn't this host's current one.
    pub const RECIPIENT_GENERATION: &str = "recipient_generation_not_current";
    /// Check 2: `enc_kid` names none of the keys the caller accepts (a retired
    /// previous key, an older one, or none of this host's).
    pub const ENC_KEY_NOT_ACCEPTED: &str = "enc_key_not_accepted";
    /// Check 3: no `add_host` here names the sender, and `signed_at_head` is
    /// not beyond this head (which would make the object wait).
    pub const UNKNOWN_SENDER: &str = "unknown_sender";
    /// Check 3: the sender was removed, and `signed_at_head` is not beyond
    /// this head (an envelope; also a result claiming a generation the removed
    /// host never had). A removed host's result is otherwise kept as data.
    pub const REMOVED_SENDER: &str = "removed_sender";
    /// Check 3: `sender.host_trust_gen` is below the sender's newest `add_host`.
    pub const STALE_SENDER_GENERATION: &str = "stale_sender_generation";
    /// Check 3: the sender claims a generation this list's entries up to
    /// `signed_at_head.seq` don't hold: above its newest `add_host`, or an
    /// `add_host` that comes after `signed_at_head.seq` (a sender signs at a
    /// head that includes its own `add_host`).
    pub const GENERATION_AHEAD: &str = "generation_ahead";
    /// Check 3: the sender is `revoked` in this list and `signed_at_head` is
    /// not beyond this head. Only an envelope: a revoked host's result is
    /// kept as data.
    pub const REVOKED_SENDER: &str = "revoked_sender";
    /// Check 3: `signed_at_head.seq` is below the sender's authorization
    /// generation.
    pub const SIGNED_AT_HEAD_BEFORE_GENERATION: &str = "signed_at_head_before_generation";
    /// Check 3: this list's entry at `signed_at_head.seq` has another hash.
    pub const SIGNED_AT_HEAD_WRONG_HASH: &str = "signed_at_head_wrong_hash";
    /// A result's sender isn't the host (at the generation) the outbox row
    /// went to.
    pub const NOT_THE_RECIPIENT: &str = "not_the_recipient";
    /// Check 4: the signature isn't the sender's newest `add_host` key's.
    pub const BAD_SIGNATURE: &str = "bad_signature";
    /// Check 5: `expires_at` isn't after `created_at`.
    pub const BAD_TIMES: &str = "bad_times";
    /// Check 5: more than 24 h between `created_at` and `expires_at`.
    pub const LIFETIME_TOO_LONG: &str = "lifetime_too_long";
    /// Check 5: `expires_at` has passed.
    pub const EXPIRED: &str = "expired";
    /// Check 5: `created_at` is more than 60 s ahead of the clock.
    pub const CREATED_TOO_FAR_AHEAD: &str = "created_too_far_ahead";
    /// Check 6: `sealed_hash` doesn't name `enc` and `ct`.
    pub const SEALED_HASH_MISMATCH: &str = "sealed_hash_mismatch";
    /// Check 6: the sealed part doesn't open (another `info`, another key,
    /// tampering).
    pub const OPEN_FAILED: &str = "open_failed";
    /// Check 6: a `null` in the plaintext (R9.1).
    pub const PLAINTEXT_NULL: &str = "plaintext_null";
    /// Check 6: the plaintext is over its bound.
    pub const PLAINTEXT_TOO_LARGE: &str = "plaintext_too_large";
    /// Check 6: the plaintext isn't one of the exact, canonical shapes.
    pub const PLAINTEXT_MALFORMED: &str = "plaintext_malformed";
    /// Check 6: a request's Message id, times or sender differ from the body's.
    pub const PLAINTEXT_MISMATCH: &str = "plaintext_mismatch";
    /// Check 6: a host sender's Message carries a mark or a task with
    /// attachments (none in this version).
    pub const ATTACHMENTS_NOT_ALLOWED: &str = "attachments_not_allowed";
    /// Check 6: any other way the Message isn't one a host sender may send.
    pub const INVALID_MESSAGE: &str = "invalid_message";
    /// A result's plaintext doesn't answer the outbox row.
    pub const DOES_NOT_ANSWER_OUTBOX_ROW: &str = "does_not_answer_outbox_row";
    /// A verified result of a host this list holds `revoked`: kept as data
    /// (II.4.4's return-grant detail).
    pub const NOT_DELIVERED_SENDER_REVOKED: &str = "result not delivered: sender revoked";
    /// A verified result of a host this list has removed: kept as data
    /// (II.4.4's return-grant detail).
    pub const NOT_DELIVERED_SENDER_REMOVED: &str = "result not delivered: sender removed";
}

use reason::*;

/// This host as the recipient of mail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Recipient {
    /// This host's `host_id`.
    pub host_id: String,
    /// This host's current trust generation.
    pub host_trust_gen: u64,
    /// The keys that may open mail now, each with its `enc_kid`: the current
    /// `enc_key`, and the previous one only while its 24 h window (counted on
    /// this host's clock from when it applied the rotation) is open and the
    /// rotation didn't `retire_previous`. A kid not listed is refused.
    ///
    /// The caller may also list a key it generated and handed out, and hasn't
    /// retired, before that key's `host_enc_key` entry applies here: a sender
    /// whose list already has the entry seals to it, and until this host
    /// applies the entry that mail would be refused as `enc_key_not_accepted`
    /// (and wait for a resend).
    pub keys: Vec<(KeyId, [u8; 8])>,
}

/// What the receiver decides about an envelope.
// An opened request carries a whole Message and the others a few words: a
// verdict lives only until the host has acted on it.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnvelopeVerdict {
    /// Checks 1 to 6 passed. `sender` is the sender's principal,
    /// `host:<host_id>` ([`host_principal`]). Step 7, the host-work checks of
    /// a message (route, project, ops, target), is the host's.
    Open {
        plain: EnvelopePlain,
        sender: String,
    },
    /// The claimed sender generation, or the head the sender signed at, is
    /// beyond this host's list, and the body's times passed: kept, judged
    /// again after each device-list advance. `host_id` and `host_trust_gen`
    /// are the *claimed* ones (the pending bound is per claimed pair).
    Pending {
        host_id: String,
        host_trust_gen: u64,
    },
    /// Refused before the signature verified. Nothing is reported to anyone.
    /// `evidence` is [`evidence_hash`] of the received object.
    Refused {
        reason: &'static str,
        evidence: Hash32,
    },
    /// Refused after the signature verified: the sender is authenticated, so
    /// the host reports it (a status naming `object_id`, II.4.4).
    RefusedAuthenticated {
        object_id: String,
        reason: &'static str,
    },
    /// A local failure, not the sender's, so retryable: the key provider
    /// failed (the key is missing or locked, or isn't the one its kid names).
    /// Nothing is decided; the host doesn't mark the object done and judges it
    /// again later.
    Unavailable { error: Error },
}

/// What a sending host's outbox row expects back (II.4.4): the row for one
/// message to one target host. The delivery rule (the return grant, the
/// project and route checks, whether a revoked host's result is delivered)
/// stays in the host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectedResult {
    /// The host, at the trust generation, the row's envelopes were addressed
    /// to: the only sender whose results it takes.
    pub recipient: HostRef,
    /// The row's request: the Message's `message_id`, which is also its
    /// envelope's `id`. A status names it as `message_id`.
    pub message_id: String,
    /// The `id` of each cancel or complete envelope the row has sent (a
    /// refusal of one names it as `object_id`; a refusal of the request names
    /// `message_id`).
    pub cancel_complete_ids: Vec<String>,
    /// The tasks of this host's recorded resolution for the row: what a
    /// result's `task_id` must be one of.
    pub task_ids: Vec<String>,
}

/// What the sending host decides about a result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResultVerdict {
    /// Checks 1 to 6 passed, the plaintext answers the row, and the sender is
    /// a current, `authorized` host. `sender` is `host:<host_id>`. Whether it
    /// is delivered into a session is the host's delivery rule (the return
    /// grant, the route, the project).
    Accepted { plain: ResultPlain, sender: String },
    /// The result verified (with the key its sender last held) and answers the
    /// row, but its sender is a host this list holds revoked or has removed
    /// (II.4.4): it is **not delivered**, only kept as data (stored with the
    /// outbox row, shown by `atem message status`, never prompted). `reason` is
    /// the return grant's detail: [`reason::NOT_DELIVERED_SENDER_REVOKED`] or
    /// [`reason::NOT_DELIVERED_SENDER_REMOVED`] (revoked when both apply).
    NotDelivered {
        plain: ResultPlain,
        sender: String,
        reason: &'static str,
    },
    /// As [`EnvelopeVerdict::Pending`].
    Pending {
        host_id: String,
        host_trust_gen: u64,
    },
    /// As [`EnvelopeVerdict::Refused`].
    Refused {
        reason: &'static str,
        evidence: Hash32,
    },
    /// As [`EnvelopeVerdict::RefusedAuthenticated`], though nothing is
    /// reported back to the host that ran the work (II.4.4): it tells the
    /// host a verified host sent a result that can't be used.
    RefusedAuthenticated {
        object_id: String,
        reason: &'static str,
    },
    /// As [`EnvelopeVerdict::Unavailable`]: a local failure, retryable.
    Unavailable { error: Error },
}

/// The hash a refusal keeps as evidence: `SHA-256(enc([jcs(body), sig, enc,
/// ct]))` of the received object (`enc` and `ct` as their raw bytes, empty
/// for an object with no sealed part). Every part is length-framed, so two
/// different objects never share it, and any changed byte of the body, the
/// signature or the sealed part changes it. Also what a host keeps for an
/// id seen again with other bytes.
pub fn evidence_hash(obj: &SignedObject) -> Hash32 {
    let empty: &[u8] = &[];
    let (enc, ct) = obj
        .sealed()
        .map_or((empty, empty), |s| (s.enc.as_slice(), s.ct.as_slice()));
    Hash32::of_enc(&[obj.jcs().as_bytes(), obj.sig(), enc, ct])
}

/// Checks 1 to 6 of II.4.2 for the mailbox's envelope `obj`, from this
/// host's device list `list`, its identity and keys `me`, the provider
/// holding those keys and its clock `now_ms` (I.6.5's). See the module
/// documentation for the order and the verdicts.
pub fn open_envelope(
    obj: &SignedObject,
    list: &Membership,
    me: &Recipient,
    provider: &dyn KeyProvider,
    now_ms: u64,
) -> EnvelopeVerdict {
    let (mail, key) = match admit(MailKind::Envelope, obj, list, me, None, now_ms) {
        Admission::Verified { mail, key, .. } => (mail, key),
        Admission::Pending {
            host_id,
            host_trust_gen,
        } => {
            return EnvelopeVerdict::Pending {
                host_id,
                host_trust_gen,
            };
        }
        Admission::Refused { reason, evidence } => {
            return EnvelopeVerdict::Refused { reason, evidence };
        }
        Admission::RefusedAuthenticated { object_id, reason } => {
            return EnvelopeVerdict::RefusedAuthenticated { object_id, reason };
        }
    };
    let body = mail.body();
    let refuse = |reason| EnvelopeVerdict::RefusedAuthenticated {
        object_id: body.id.clone(),
        reason,
    };
    // 6. `sealed_hash`, the open, the plaintext's strict parse.
    let plain = match open_with(&mail, &key, provider, unseal_envelope) {
        Ok(plain) => plain,
        Err(Failed::Refused(reason)) => return refuse(reason),
        Err(Failed::Unavailable(error)) => return EnvelopeVerdict::Unavailable { error },
    };
    // 6. ... and what the plaintext repeats equals the body's.
    if let EnvelopePlain::Request { message } = &plain {
        let sender = host_principal(&body.sender.host_id);
        if message.message_id != body.id
            || message.created_at != body.created_at
            || message.expires_at != body.expires_at
            || message.sender != sender
        {
            return refuse(PLAINTEXT_MISMATCH);
        }
        // No attachments in this version (owner decision 2026-11-07,
        // choice 16): a mark, or a task that carries one.
        if message.mark.is_some()
            || message
                .recipients
                .iter()
                .filter_map(|r| message.task(r))
                .any(|task| !task.attachments.is_empty())
        {
            return refuse(ATTACHMENTS_NOT_ALLOWED);
        }
        if !message.valid_from_host(&body.sender.host_id) {
            return refuse(INVALID_MESSAGE);
        }
    }
    EnvelopeVerdict::Open {
        plain,
        sender: host_principal(&body.sender.host_id),
    }
}

/// The sending host's check of an `atem-result` (II.4.4): checks 1 to 6 as
/// for an envelope (with a result's labels, a result's sender and
/// `authorized` rule, see the module documentation), then that the plaintext
/// answers `outbox`: a status names its `message_id`, a refusal names the
/// request's or one of its cancel or complete envelopes' ids, a result names
/// a task of the recorded resolution. A verified result of a revoked or
/// removed host is [`ResultVerdict::NotDelivered`] (kept as data), one that
/// doesn't verify is refused. The delivery rule (return grant, route,
/// project) stays in the host.
pub fn accept_result(
    obj: &SignedObject,
    list: &Membership,
    me: &Recipient,
    outbox: &ExpectedResult,
    provider: &dyn KeyProvider,
    now_ms: u64,
) -> ResultVerdict {
    let (mail, key, standing) = match admit(MailKind::Result, obj, list, me, Some(outbox), now_ms) {
        Admission::Verified {
            mail,
            key,
            standing,
        } => (mail, key, standing),
        Admission::Pending {
            host_id,
            host_trust_gen,
        } => {
            return ResultVerdict::Pending {
                host_id,
                host_trust_gen,
            };
        }
        Admission::Refused { reason, evidence } => {
            return ResultVerdict::Refused { reason, evidence };
        }
        Admission::RefusedAuthenticated { object_id, reason } => {
            return ResultVerdict::RefusedAuthenticated { object_id, reason };
        }
    };
    let body = mail.body();
    let refuse = |reason| ResultVerdict::RefusedAuthenticated {
        object_id: body.id.clone(),
        reason,
    };
    let plain = match open_with(&mail, &key, provider, unseal_result) {
        Ok(plain) => plain,
        Err(Failed::Refused(reason)) => return refuse(reason),
        Err(Failed::Unavailable(error)) => return ResultVerdict::Unavailable { error },
    };
    let answers = match &plain {
        ResultPlain::Status { message_id, .. } => *message_id == outbox.message_id,
        ResultPlain::Refusal { object_id, .. } => {
            *object_id == outbox.message_id || outbox.cancel_complete_ids.contains(object_id)
        }
        ResultPlain::Result { task_id, .. } => outbox.task_ids.contains(task_id),
    };
    if !answers {
        return refuse(DOES_NOT_ANSWER_OUTBOX_ROW);
    }
    let sender = host_principal(&body.sender.host_id);
    // II.4.4: a result of a revoked or removed host verified, but isn't
    // delivered; it is kept as data.
    match standing {
        Standing::Current => ResultVerdict::Accepted { plain, sender },
        Standing::Revoked => ResultVerdict::NotDelivered {
            plain,
            sender,
            reason: NOT_DELIVERED_SENDER_REVOKED,
        },
        Standing::Removed => ResultVerdict::NotDelivered {
            plain,
            sender,
            reason: NOT_DELIVERED_SENDER_REMOVED,
        },
    }
}

/// What checks 1 to 5 settle.
// Short-lived, like the verdicts it becomes.
#[allow(clippy::large_enum_variant)]
enum Admission {
    /// The signature verified and the times passed. `key` is the recipient's
    /// key the object is sealed to, with its kid; `standing` is the sender's.
    Verified {
        mail: VerifiedMail,
        key: (KeyId, [u8; 8]),
        standing: Standing,
    },
    Pending {
        host_id: String,
        host_trust_gen: u64,
    },
    Refused {
        reason: &'static str,
        evidence: Hash32,
    },
    RefusedAuthenticated {
        object_id: String,
        reason: &'static str,
    },
}

/// A verified sender's standing in this list. Only a result can have another
/// than `Current`: an envelope of a revoked or removed host is refused.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Standing {
    /// A current, `authorized` host.
    Current,
    /// Held `revoked` (also when removed since: a removal keeps the state).
    Revoked,
    /// Removed.
    Removed,
}

/// Step 5 on a body's times, with the clock `now_ms`.
fn check_times(created_at: u64, expires_at: u64, now_ms: u64) -> Result<(), &'static str> {
    if expires_at <= created_at {
        Err(BAD_TIMES)
    } else if expires_at - created_at > MAX_LIFETIME_MS {
        Err(LIFETIME_TOO_LONG)
    } else if now_ms >= expires_at {
        Err(EXPIRED)
    } else if created_at > now_ms.saturating_add(MAX_CREATED_AHEAD_MS) {
        Err(CREATED_TOO_FAR_AHEAD)
    } else {
        Ok(())
    }
}

/// The `seq` of the `add_host` entry of `host_id` at exactly `host_trust_gen`
/// (a reverse scan: the newest is usually late in the log).
fn add_host_seq(list: &Membership, host_id: &str, host_trust_gen: u64) -> Option<u64> {
    list.entries()
        .iter()
        .rev()
        .find(|entry| {
            matches!(&entry.action, Action::AddHost { host }
                if host.host_id == host_id && host.host_trust_gen == host_trust_gen)
        })
        .map(|entry| entry.seq)
}

/// Checks 1 to 5 of a mailbox object of `kind` (`expected` is a result's
/// outbox row, `None` for an envelope).
fn admit(
    kind: MailKind,
    obj: &SignedObject,
    list: &Membership,
    me: &Recipient,
    expected: Option<&ExpectedResult>,
    now_ms: u64,
) -> Admission {
    let refuse = |reason| Admission::Refused {
        reason,
        evidence: evidence_hash(obj),
    };

    // 1. Strict parse and pin.
    let Ok((found, body)) = MailBody::from_object(obj) else {
        return refuse(MALFORMED);
    };
    if found != kind {
        return refuse(WRONG_KIND);
    }
    if body.account_id != list.account_id() || body.genesis_hash != list.genesis_hash() {
        return refuse(PIN_MISMATCH);
    }

    // 2. The recipient: this host, its current generation, an accepted key.
    if body.recipient.host_id != me.host_id {
        return refuse(NOT_FOR_THIS_HOST);
    }
    if body.recipient.host_trust_gen != me.host_trust_gen {
        return refuse(RECIPIENT_GENERATION);
    }
    // `from_object` checked `enc_kid` is 16 lowercase hex characters.
    let Ok(kid) = hex_decode_array::<8>(&body.enc_kid) else {
        return refuse(MALFORMED);
    };
    let Some(key) = me.keys.iter().find(|(_, accepted)| *accepted == kid) else {
        return refuse(ENC_KEY_NOT_ACCEPTED);
    };

    // 3. The sender. A result is only taken from the host the row went to.
    let sender = &body.sender;
    if expected.is_some_and(|row| *sender != row.recipient) {
        return refuse(NOT_THE_RECIPIENT);
    }
    let signed_at = body.signed_at_head;
    // A head beyond this list's can't be judged yet: entries this host lacks
    // may add the sender, re-add it, readmit it or bring its newer generation,
    // and no sender can know the hash of an entry that doesn't exist. Such an
    // object waits (after step 5 on the body's times; see `wait`). A refusal
    // below is only for what this head settles: at a head this list holds, it
    // knows the list the sender signed at.
    let head_ahead = signed_at.seq > list.head().seq;
    let wait = |key: Option<&PublicKey>| {
        if let Err(reason) = check_times(body.created_at, body.expires_at, now_ms) {
            return refuse(reason);
        }
        // A `(host_id, host_trust_gen)` this list holds has exactly one key
        // forever (generations only rise), so the signature can be checked
        // now: junk can't fill a known sender's waiting slots.
        if key.is_some_and(|key| VerifiedMail::verify(obj, key).is_err()) {
            return refuse(BAD_SIGNATURE);
        }
        Admission::Pending {
            host_id: sender.host_id.clone(),
            host_trust_gen: sender.host_trust_gen,
        }
    };
    // The sender's newest `add_host`, current or removed: a removed host's
    // key still verifies what it signed before it left (a result kept as data).
    let (known, removed) = match list.host(&sender.host_id) {
        Some(host) => (Some(host), false),
        None => (list.removed_host(&sender.host_id), true),
    };
    let Some(host) = known else {
        return if head_ahead {
            wait(None)
        } else {
            refuse(UNKNOWN_SENDER)
        };
    };
    if sender.host_trust_gen < host.host_trust_gen {
        return refuse(STALE_SENDER_GENERATION);
    }
    let generation_ahead = sender.host_trust_gen > host.host_trust_gen;
    let state = list.host_sender_state(&sender.host_id);
    if !head_ahead {
        // This head settles the sender's standing.
        if removed && (kind == MailKind::Envelope || generation_ahead) {
            return refuse(REMOVED_SENDER);
        }
        // Generations rise with `seq`, so a generation above the newest was
        // not in the list the sender signed at.
        if generation_ahead {
            return refuse(GENERATION_AHEAD);
        }
        match state {
            // A revoked host's results are kept as data, not refused.
            Some(HostSenderState::Revoked { .. }) if kind == MailKind::Envelope => {
                return refuse(REVOKED_SENDER);
            }
            Some(HostSenderState::Authorized { generation }) if signed_at.seq < generation => {
                return refuse(SIGNED_AT_HEAD_BEFORE_GENERATION);
            }
            _ => {}
        }
        // A sender signs at a head that includes its own `add_host`: the
        // claimed generation's must be at or before `signed_at_head.seq`.
        if add_host_seq(list, &sender.host_id, sender.host_trust_gen)
            .is_none_or(|added| added > signed_at.seq)
        {
            return refuse(GENERATION_AHEAD);
        }
        if list.entry_hash_at(signed_at.seq) != Some(signed_at.hash) {
            return refuse(SIGNED_AT_HEAD_WRONG_HASH);
        }
    }
    if head_ahead {
        // Only a generation this list holds has a known key.
        return wait((!generation_ahead).then_some(&host.host_key));
    }
    let standing = match state {
        Some(HostSenderState::Revoked { .. }) => Standing::Revoked,
        _ if removed => Standing::Removed,
        _ => Standing::Current,
    };

    // 4. The signature, with the key of the sender's newest `add_host`.
    let Ok(mail) = VerifiedMail::verify(obj, &host.host_key) else {
        return refuse(BAD_SIGNATURE);
    };

    // 5. The times; the sender is authenticated now.
    if let Err(reason) = check_times(body.created_at, body.expires_at, now_ms) {
        return Admission::RefusedAuthenticated {
            object_id: body.id,
            reason,
        };
    }
    Admission::Verified {
        mail,
        key: key.clone(),
        standing,
    }
}

/// Why step 6's open didn't give a plaintext.
enum Failed {
    /// The sender's doing: the object is refused.
    Refused(&'static str),
    /// Not the sender's: the key provider failed.
    Unavailable(Error),
}

/// Step 6 for a verified object: `sealed_hash`, then the open and the
/// plaintext's strict parse through `unseal` (`unseal_envelope` or
/// `unseal_result`, the only way to open one).
fn open_with<T>(
    mail: &VerifiedMail,
    key: &(KeyId, [u8; 8]),
    provider: &dyn KeyProvider,
    unseal: fn(&dyn KeyProvider, &KeyId, &VerifiedMail) -> Result<T, Error>,
) -> Result<T, Failed> {
    let Some(sealed) = mail.object().sealed() else {
        return Err(Failed::Refused(MALFORMED));
    };
    if !mail.body().names(sealed) {
        return Err(Failed::Refused(SEALED_HASH_MISMATCH));
    }
    // The key the caller named behind its kid must be that key.
    match provider.public_key(&key.0).and_then(|k| enc_kid_bytes(&k)) {
        Ok(ours) if ours == key.1 => {}
        Ok(_) => {
            return Err(Failed::Unavailable(Error::Malformed(
                "the recipient key is not the one its kid names",
            )));
        }
        Err(error) => return Err(Failed::Unavailable(error)),
    }
    unseal(provider, &key.0, mail).map_err(|error| match error {
        Error::OpenFailed | Error::ZeroSharedSecret | Error::BadKey | Error::WeakKey => {
            Failed::Refused(OPEN_FAILED)
        }
        Error::NullValue => Failed::Refused(PLAINTEXT_NULL),
        Error::TooLarge => Failed::Refused(PLAINTEXT_TOO_LARGE),
        Error::Strict(_)
        | Error::Canonical(_)
        | Error::Malformed(_)
        | Error::UnknownType
        | Error::ArrayNotCanonical => Failed::Refused(PLAINTEXT_MALFORMED),
        other => Failed::Unavailable(other),
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use serde_json::json;

    use super::reason::*;
    use super::*;
    use crate::encoding::{Hash32, b64u};
    use crate::host_mail::test_support::{CREATED_AT, ID, ID2, REPLY_ID, message, reply, snapshot};
    use crate::host_mail::{
        EnvelopePlain, HostRef, MailBody, MailFields, MailKind, ResultPlain, seal_envelope,
        seal_info, seal_result,
    };
    use crate::hpke;
    use crate::keys::{Alg, PublicKey, enc_kid_bytes};
    use crate::membership::{
        Action, Head, HostNow, HostRecord, Member, MemberKind, Membership, Role, draft_on,
        host_enc_key, host_sender_readmit, host_sender_revoke, sign_entry, sign_host_enc_key,
    };
    use crate::provider::{KeyId, KeyProvider};
    use crate::session::messages::{Delivery, Message, MessageKind, RecipientReceipt, ReplyTo};
    use crate::signed::{SealedPart, SignedObject};
    use crate::software::SoftwareKeys;

    const ACCOUNT: &str = "acct-receive";
    const NOW: u64 = CREATED_AT;

    fn now(wall_ms: u64) -> HostNow {
        HostNow {
            wall_ms,
            mono_ms: wall_ms,
            boot_id: "b".into(),
        }
    }

    fn auth() -> KeyId {
        KeyId::new("auth")
    }

    fn host_key_id(host_id: &str, host_trust_gen: u64) -> KeyId {
        KeyId::new(format!("host:{host_id}:{host_trust_gen}"))
    }

    fn enc_key_id(host_id: &str, n: u64) -> KeyId {
        KeyId::new(format!("enc:{host_id}:{n}"))
    }

    /// A device list on one verifier with hosts `host-a`, `host-b` and
    /// `host-c`, each with an `enc_key`; `dev-mac`, a native manager,
    /// signs every entry. Every host's host keys (one per generation) are in
    /// `hosts` and every `enc_key` in `encs`.
    struct World {
        m: Membership,
        mac: SoftwareKeys,
        hosts: SoftwareKeys,
        encs: SoftwareKeys,
        /// `enc_kid` -> the key behind `encs`.
        enc_ids: BTreeMap<[u8; 8], KeyId>,
        at: u64,
    }

    impl World {
        fn new() -> World {
            let mut mac = SoftwareKeys::new();
            let auth_key = mac.generate(auth(), Alg::Ed25519).unwrap();
            let enc_key = mac.generate(KeyId::new("enc"), Alg::X25519).unwrap();
            let recovery_key = mac.generate(KeyId::new("kit"), Alg::Ed25519).unwrap();
            let body = draft_on(
                ACCOUNT,
                &Hash32([0; 32]),
                1,
                &Hash32([0; 32]),
                "dev-mac",
                NOW,
                &Action::Genesis {
                    member: Member {
                        device_id: "dev-mac".into(),
                        auth_key,
                        kind: MemberKind::Native {
                            enc_key,
                            roles: [Role::Control, Role::Manage, Role::View]
                                .into_iter()
                                .collect(),
                        },
                    },
                    recovery_key,
                },
            );
            let genesis = sign_entry(&mac, &auth(), body).unwrap();
            let m = Membership::from_genesis(ACCOUNT, &genesis.hash(), genesis).unwrap();
            let mut w = World {
                m,
                mac,
                hosts: SoftwareKeys::new(),
                encs: SoftwareKeys::new(),
                enc_ids: BTreeMap::new(),
                at: NOW,
            };
            for host in ["host-a", "host-b", "host-c"] {
                w.add_host(host, 1);
            }
            for host in ["host-a", "host-b", "host-c"] {
                w.set_enc_key(host, 1, false);
            }
            w
        }

        fn apply(&mut self, action: Action) {
            self.at += 1;
            let entry = sign_entry(
                &self.mac,
                &auth(),
                self.m.draft("dev-mac", self.at, &action),
            )
            .unwrap();
            let eval = self
                .m
                .evaluate_objects(&[entry.object().clone()], &now(self.at));
            assert_eq!(eval.stop, None, "{action:?}");
            self.m = eval.next;
        }

        /// An `add_host` with a new host key for that generation.
        fn add_host(&mut self, host_id: &str, host_trust_gen: u64) {
            let host_key = self
                .hosts
                .generate(host_key_id(host_id, host_trust_gen), Alg::Ed25519)
                .unwrap();
            self.apply(Action::AddHost {
                host: HostRecord {
                    host_id: host_id.into(),
                    host_trust_gen,
                    host_key,
                },
            });
        }

        fn remove_host(&mut self, host_id: &str) {
            self.apply(Action::RemoveHost {
                host_id: host_id.into(),
            });
        }

        fn revoke(&mut self, host_id: &str) {
            self.apply(host_sender_revoke(host_id, false, NOW).unwrap());
        }

        fn readmit(&mut self, host_id: &str) {
            self.apply(host_sender_readmit(host_id, NOW).unwrap());
        }

        /// A new `enc_key` for the host, vouched for by its host key of
        /// generation `host_trust_gen`; `n` names it.
        fn set_enc_key(&mut self, host_id: &str, host_trust_gen: u64, retire_previous: bool) {
            let n = self.enc_ids.keys().count() as u64 + 1;
            let id = enc_key_id(host_id, n);
            let key = self.encs.generate(id.clone(), Alg::X25519).unwrap();
            self.enc_ids.insert(enc_kid_bytes(&key).unwrap(), id);
            let sig = sign_host_enc_key(
                &self.hosts,
                &host_key_id(host_id, host_trust_gen),
                ACCOUNT,
                &self.m.genesis_hash(),
                host_id,
                host_trust_gen,
                key.as_32().unwrap(),
            )
            .unwrap();
            self.apply(
                host_enc_key(host_id, host_trust_gen, &key, &sig, retire_previous, NOW).unwrap(),
            );
        }

        fn head(&self) -> Head {
            self.m.head()
        }

        fn gen_of(&self, host_id: &str) -> u64 {
            self.m.host(host_id).unwrap().host_trust_gen
        }

        /// The host's current `enc_key`.
        fn enc_pub(&self, host_id: &str) -> PublicKey {
            let kid = self.m.host_enc_key(host_id).unwrap().current.kid;
            self.encs.public_key(&self.enc_ids[&kid]).unwrap()
        }

        /// What the host passes as itself: its current key, and its previous
        /// key only while the 24 h window is open and the rotation didn't
        /// retire it.
        fn recipient(&self, host_id: &str, previous_window_open: bool) -> Recipient {
            let keys = self.m.host_enc_key(host_id).unwrap();
            let mut ids = vec![keys.current.kid];
            if let Some(previous) = &keys.previous
                && previous_window_open
                && !previous.retired
            {
                ids.push(previous.key.kid);
            }
            Recipient {
                host_id: host_id.into(),
                host_trust_gen: self.gen_of(host_id),
                keys: ids
                    .into_iter()
                    .map(|kid| (self.enc_ids[&kid].clone(), kid))
                    .collect(),
            }
        }

        /// A body from `sender` to `recipient`, signed at the head now.
        fn fields(&self, sender: &str, recipient: &str) -> MailFields {
            MailFields {
                account_id: ACCOUNT.into(),
                genesis_hash: self.m.genesis_hash(),
                sender: HostRef {
                    host_id: sender.into(),
                    host_trust_gen: self.gen_of(sender),
                },
                recipient: HostRef {
                    host_id: recipient.into(),
                    host_trust_gen: self.gen_of(recipient),
                },
                enc_kid: crate::keys::enc_kid(&self.enc_pub(recipient)).unwrap(),
                id: ID.into(),
                created_at: NOW - 1_000,
                expires_at: NOW + 3_600_000,
                signed_at_head: self.head(),
            }
        }

        fn sender_key(&self, f: &MailFields) -> KeyId {
            host_key_id(&f.sender.host_id, f.sender.host_trust_gen)
        }

        fn envelope(&self, f: &MailFields, plain: &EnvelopePlain) -> SignedObject {
            seal_envelope(
                &self.hosts,
                &self.sender_key(f),
                f,
                plain,
                &self.enc_pub(&f.recipient.host_id),
            )
            .unwrap()
        }

        fn request(&self, f: &MailFields) -> EnvelopePlain {
            EnvelopePlain::Request {
                message: message(f),
            }
        }

        /// `seal_*` with a plaintext of the sender's own making.
        fn forged(&self, kind: MailKind, f: &MailFields, plaintext: &[u8]) -> SignedObject {
            let to = self.enc_pub(&f.recipient.host_id);
            let sealed =
                hpke::seal(to.as_32().unwrap(), &seal_info(kind, f), b"", plaintext).unwrap();
            let body = MailBody::from_fields(f.clone(), sealed.hash()).to_value(kind);
            SignedObject::sign(&self.hosts, &self.sender_key(f), body)
                .unwrap()
                .with_sealed(SealedPart {
                    enc: sealed.enc.to_vec(),
                    ct: sealed.ct,
                })
        }

        /// `object`'s body replaced by `body_of(old fields)`, signed by `by`,
        /// the sealed part kept.
        fn resigned(
            &self,
            kind: MailKind,
            object: &SignedObject,
            by: &KeyId,
            edit: impl FnOnce(&mut MailFields),
        ) -> SignedObject {
            let (_, old) = MailBody::from_object(object).unwrap();
            let mut f = old.fields();
            edit(&mut f);
            let body = MailBody::from_fields(f, old.sealed_hash).to_value(kind);
            SignedObject::sign(&self.hosts, by, body)
                .unwrap()
                .with_sealed(object.sealed().unwrap().clone())
        }

        fn open(&self, object: &SignedObject, me: &Recipient) -> EnvelopeVerdict {
            open_envelope(object, &self.m, me, &self.encs, NOW)
        }

        fn open_at(&self, object: &SignedObject, me: &Recipient, now_ms: u64) -> EnvelopeVerdict {
            open_envelope(object, &self.m, me, &self.encs, now_ms)
        }
    }

    /// A change to a Message, boxed so a table of them has one type.
    type Edit = Box<dyn Fn(&mut Message)>;

    fn edited(object: &SignedObject, edit: impl FnOnce(&mut serde_json::Value)) -> SignedObject {
        let mut value = object.to_json();
        edit(&mut value);
        SignedObject::from_value(&value).unwrap()
    }

    fn refused(reason: &'static str, object: &SignedObject) -> EnvelopeVerdict {
        EnvelopeVerdict::Refused {
            reason,
            evidence: evidence_hash(object),
        }
    }

    fn refused_authenticated(reason: &'static str) -> EnvelopeVerdict {
        EnvelopeVerdict::RefusedAuthenticated {
            object_id: ID.into(),
            reason,
        }
    }

    fn pending(host_id: &str, host_trust_gen: u64) -> EnvelopeVerdict {
        EnvelopeVerdict::Pending {
            host_id: host_id.into(),
            host_trust_gen,
        }
    }

    // ------------------------------------------------------------ opening

    #[test]
    fn a_valid_envelope_opens_with_its_sender() {
        let w = World::new();
        let me = w.recipient("host-b", true);
        let f = w.fields("host-a", "host-b");
        let plains = [
            w.request(&f),
            EnvelopePlain::Cancel {
                task_id: ID2.into(),
            },
            EnvelopePlain::Complete {
                task_id: ID2.into(),
                result: snapshot(0, 100),
            },
        ];
        for plain in plains {
            let object = w.envelope(&f, &plain);
            assert_eq!(
                w.open(&object, &me),
                EnvelopeVerdict::Open {
                    plain,
                    sender: "host:host-a".into(),
                }
            );
        }
    }

    #[test]
    fn evidence_is_a_hash_of_the_received_object() {
        let w = World::new();
        let f = w.fields("host-a", "host-b");
        let object = w.envelope(&f, &w.request(&f));
        let evidence = evidence_hash(&object);
        // The same object, the same hash; any byte of any part changes it.
        assert_eq!(evidence, evidence_hash(&object));
        let sig = edited(&object, |v| {
            let mut sig = crate::encoding::b64u_decode(v["sig"].as_str().unwrap()).unwrap();
            sig[0] ^= 1;
            v["sig"] = json!(b64u(&sig));
        });
        let ct = edited(&object, |v| {
            let mut ct = crate::encoding::b64u_decode(v["ct"].as_str().unwrap()).unwrap();
            ct[0] ^= 1;
            v["ct"] = json!(b64u(&ct));
        });
        let enc = edited(&object, |v| {
            let mut enc = crate::encoding::b64u_decode(v["enc"].as_str().unwrap()).unwrap();
            enc[0] ^= 1;
            v["enc"] = json!(b64u(&enc));
        });
        let body = edited(&object, |v| v["body"]["created_at"] = json!(1));
        for other in [&sig, &ct, &enc, &body] {
            assert_ne!(evidence_hash(other), evidence);
        }
        // Moving a byte from `enc` to `ct` doesn't collide (framed).
        let a = Hash32::of_enc(&[b"ab", b"c"]);
        let b = Hash32::of_enc(&[b"a", b"bc"]);
        assert_ne!(a, b);
        let verdict = w.open(
            &edited(&object, |v| v["sig"] = json!(b64u(&[1u8; 64]))),
            &w.recipient("host-b", true),
        );
        let EnvelopeVerdict::Refused { evidence: e, .. } = verdict else {
            panic!("{verdict:?}");
        };
        assert_ne!(e, evidence);
    }

    #[test]
    fn a_junk_signature_is_refused_before_anything_opens() {
        let w = World::new();
        let me = w.recipient("host-b", true);
        let f = w.fields("host-a", "host-b");
        let object = w.envelope(&f, &w.request(&f));
        for sig in [b64u(&[1u8; 64]), b64u(&[0u8; 64]), b64u(&[1u8; 63])] {
            let junk = edited(&object, |v| v["sig"] = json!(sig));
            assert_eq!(w.open(&junk, &me), refused(BAD_SIGNATURE, &junk), "{sig}");
        }
    }

    /// HPKE base mode is unauthenticated and `info` is public: whatever
    /// another host (or the Station) seals to the recipient, only the sender's
    /// signature says who sent it.
    #[test]
    fn what_anyone_can_seal_cannot_pass_for_the_sender() {
        let w = World::new();
        let me = w.recipient("host-b", true);
        // Host C seals a cancel to B and says it is from A, signing as C.
        let mut f = w.fields("host-a", "host-b");
        let cancel = EnvelopePlain::Cancel {
            task_id: ID2.into(),
        };
        let forged = seal_envelope(
            &w.hosts,
            &host_key_id("host-c", 1),
            &f,
            &cancel,
            &w.enc_pub("host-b"),
        )
        .unwrap();
        assert_eq!(w.open(&forged, &me), refused(BAD_SIGNATURE, &forged));
        // As itself it is a real envelope of C's.
        f.sender = HostRef {
            host_id: "host-c".into(),
            host_trust_gen: 1,
        };
        let real = w.envelope(&f, &cancel);
        assert!(matches!(w.open(&real, &me), EnvelopeVerdict::Open { .. }));
    }

    // ----------------------------------------------------------- check 1

    #[test]
    fn another_account_or_list_is_refused() {
        let w = World::new();
        let me = w.recipient("host-b", true);
        let mut f = w.fields("host-a", "host-b");
        f.account_id = "acct-other".into();
        let object = w.envelope(&f, &w.request(&f));
        assert_eq!(w.open(&object, &me), refused(PIN_MISMATCH, &object));
        let mut f = w.fields("host-a", "host-b");
        f.genesis_hash = Hash32([9; 32]);
        let object = w.envelope(&f, &w.request(&f));
        assert_eq!(w.open(&object, &me), refused(PIN_MISMATCH, &object));
    }

    #[test]
    fn not_an_envelope_is_refused() {
        let w = World::new();
        let me = w.recipient("host-b", true);
        // A result, an object with no sealed part, another kind of object.
        let f = w.fields("host-a", "host-b");
        let result = seal_result(
            &w.hosts,
            &w.sender_key(&f),
            &f,
            &ResultPlain::Refusal {
                object_id: ID2.into(),
                refused: "invalid_request".into(),
            },
            &w.enc_pub("host-b"),
        )
        .unwrap();
        assert_eq!(w.open(&result, &me), refused(WRONG_KIND, &result));
        let object = w.envelope(&f, &w.request(&f));
        let bare = edited(&object, |v| {
            v.as_object_mut().unwrap().remove("enc");
            v.as_object_mut().unwrap().remove("ct");
        });
        assert_eq!(w.open(&bare, &me), refused(MALFORMED, &bare));
        let seen =
            SignedObject::from_value(&json!({"body": {"type": "atem-seen", "v": 1}, "sig": "AA"}))
                .unwrap();
        assert_eq!(w.open(&seen, &me), refused(MALFORMED, &seen));
        let short = edited(&object, |v| v["body"]["id"] = json!("not-a-uuid"));
        assert_eq!(w.open(&short, &me), refused(MALFORMED, &short));
    }

    // ----------------------------------------------------------- check 2

    #[test]
    fn redirected_copy_refused() {
        let mut w = World::new();
        let f = w.fields("host-a", "host-b");
        let object = w.envelope(&f, &w.request(&f));
        // Another host is handed B's mail.
        let c = w.recipient("host-c", true);
        assert_eq!(w.open(&object, &c), refused(NOT_FOR_THIS_HOST, &object));
        // The body edited to name C (and C's key) breaks the signature.
        let to_c = edited(&object, |v| {
            v["body"]["recipient"]["host_id"] = json!("host-c");
            v["body"]["recipient"]["enc_kid"] =
                json!(crate::keys::enc_kid(&w.enc_pub("host-c")).unwrap());
        });
        assert_eq!(w.open(&to_c, &c), refused(BAD_SIGNATURE, &to_c));
        // Another trust generation of B: only the current one is itself.
        let mut stale = w.recipient("host-b", true);
        stale.host_trust_gen = 2;
        assert_eq!(
            w.open(&object, &stale),
            refused(RECIPIENT_GENERATION, &object)
        );
        // B re-verified: the object for its old generation never opens, and
        // one for the new generation names it.
        w.add_host("host-b", 2);
        w.set_enc_key("host-b", 2, false);
        let me = w.recipient("host-b", true);
        assert_eq!(w.open(&object, &me), refused(RECIPIENT_GENERATION, &object));
    }

    #[test]
    fn retired_previous_key_refused() {
        let mut w = World::new();
        let f = w.fields("host-a", "host-b");
        let to_first = w.envelope(&f, &w.request(&f));
        // A routine rotation: the previous key opens mail in flight while
        // the host's 24 h window is open ...
        w.set_enc_key("host-b", 1, false);
        let f2 = w.fields("host-a", "host-b");
        let to_second = w.envelope(&f2, &w.request(&f2));
        assert!(matches!(
            w.open(&to_first, &w.recipient("host-b", true)),
            EnvelopeVerdict::Open { .. }
        ));
        assert!(matches!(
            w.open(&to_second, &w.recipient("host-b", true)),
            EnvelopeVerdict::Open { .. }
        ));
        // ... and not after it.
        assert_eq!(
            w.open(&to_first, &w.recipient("host-b", false)),
            refused(ENC_KEY_NOT_ACCEPTED, &to_first)
        );
        // A rotation that retires the previous key refuses it at once,
        // whatever the window (the caller passes only the current key).
        w.set_enc_key("host-b", 1, true);
        let me = w.recipient("host-b", true);
        assert_eq!(me.keys.len(), 1);
        assert_eq!(
            w.open(&to_second, &me),
            refused(ENC_KEY_NOT_ACCEPTED, &to_second)
        );
        assert_eq!(
            w.open(&to_first, &me),
            refused(ENC_KEY_NOT_ACCEPTED, &to_first)
        );
    }

    // ----------------------------------------------------------- check 3

    #[test]
    fn stale_generation_refused() {
        let mut w = World::new();
        let f = w.fields("host-a", "host-b");
        let object = w.envelope(&f, &w.request(&f));
        let me = w.recipient("host-b", true);
        assert!(matches!(w.open(&object, &me), EnvelopeVerdict::Open { .. }));
        // A re-verified (`atem pair verify`): its newest add_host is gen 2,
        // and the old key's envelopes are refused.
        w.add_host("host-a", 2);
        assert_eq!(
            w.open(&object, &me),
            refused(STALE_SENDER_GENERATION, &object)
        );
    }

    #[test]
    fn newer_generation_pending() {
        let mut w = World::new();
        let me = w.recipient("host-b", true);
        let before = w.m.clone();
        // A re-verified; its envelope is signed at its own newer head.
        w.add_host("host-a", 2);
        let f = w.fields("host-a", "host-b");
        assert_eq!(f.sender.host_trust_gen, 2);
        let object = w.envelope(&f, &w.request(&f));
        // This host hasn't the new add_host: pending (by the claimed
        // generation, and by the head it names).
        assert_eq!(
            open_envelope(&object, &before, &me, &w.encs, NOW),
            pending("host-a", 2)
        );
        // Once its device list advanced, the same object is judged again.
        assert!(matches!(w.open(&object, &me), EnvelopeVerdict::Open { .. }));
    }

    /// II.4.2's reason to wait is that this host may lack the sender's new
    /// `add_host`. At a head this list holds it knows the list the sender
    /// signed at, so a generation it doesn't hold there can't be waited for.
    #[test]
    fn a_generation_the_list_does_not_hold_is_refused_at_a_head_we_hold() {
        let mut w = World::new();
        let me = w.recipient("host-b", true);
        w.hosts
            .generate(host_key_id("host-a", 2), Alg::Ed25519)
            .unwrap();
        let mut f = w.fields("host-a", "host-b");
        f.sender.host_trust_gen = 2;
        // At this host's head, and at an older head with its right hash.
        for head in [
            w.head(),
            Head {
                seq: 3,
                hash: w.m.entry_hash_at(3).unwrap(),
            },
        ] {
            f.signed_at_head = head;
            let object = w.envelope(&f, &w.request(&f));
            assert_eq!(
                w.open(&object, &me),
                refused(GENERATION_AHEAD, &object),
                "{head:?}"
            );
        }
        // The same claim past this host's head waits; once the list reaches
        // that head it is refused (the list then holds the head).
        f.signed_at_head = Head {
            seq: w.head().seq + 1,
            hash: Hash32([0x66; 32]),
        };
        let object = w.envelope(&f, &w.request(&f));
        assert_eq!(w.open(&object, &me), pending("host-a", 2));
        w.add_host("host-c", 2);
        assert_eq!(w.open(&object, &me), refused(GENERATION_AHEAD, &object));
        // A result of the host the row went to: the same.
        let mut w = World::new();
        w.hosts
            .generate(host_key_id("host-b", 2), Alg::Ed25519)
            .unwrap();
        let mut row = expected(&w);
        row.recipient.host_trust_gen = 2;
        let mut f = w.fields("host-b", "host-a");
        f.sender.host_trust_gen = 2;
        let object = result(&w, &f, &status(ID));
        assert_eq!(
            accept_result(
                &object,
                &w.m,
                &w.recipient("host-a", true),
                &row,
                &w.encs,
                NOW
            ),
            result_refused(GENERATION_AHEAD, &object)
        );
        // The generation is checked before the sender's authorization (the
        // design's order): a revoked host's claim of one it doesn't hold.
        let mut w = World::new();
        let me = w.recipient("host-b", true);
        w.hosts
            .generate(host_key_id("host-a", 2), Alg::Ed25519)
            .unwrap();
        let mut f = w.fields("host-a", "host-b");
        f.sender.host_trust_gen = 2;
        w.revoke("host-a");
        f.signed_at_head = w.head();
        let object = w.envelope(&f, &w.request(&f));
        assert_eq!(w.open(&object, &me), refused(GENERATION_AHEAD, &object));
        // A removed host in the same case keeps its removal refusal.
        let mut w = World::new();
        let me = w.recipient("host-b", true);
        let mut f = w.fields("host-a", "host-b");
        f.sender.host_trust_gen = 2;
        w.hosts
            .generate(host_key_id("host-a", 2), Alg::Ed25519)
            .unwrap();
        w.remove_host("host-a");
        f.signed_at_head = w.head();
        let object = w.envelope(&f, &w.request(&f));
        assert_eq!(w.open(&object, &me), refused(REMOVED_SENDER, &object));
    }

    /// A sender signs at a head that includes its own `add_host`: one signed
    /// at a head before the claimed generation's `add_host` is refused, and
    /// the same bytes get the same verdict at every later head.
    #[test]
    fn a_generation_whose_add_host_follows_the_signed_at_head_is_refused() {
        let mut w = World::new();
        let me = w.recipient("host-b", true);
        let before_add = w.head();
        w.add_host("host-a", 2);
        let add_seq = w.head().seq;
        assert_eq!(add_seq, before_add.seq + 1);
        let mut f = w.fields("host-a", "host-b");
        assert_eq!(f.sender.host_trust_gen, 2);
        f.signed_at_head = before_add;
        let object = w.envelope(&f, &w.request(&f));
        assert_eq!(w.open(&object, &me), refused(GENERATION_AHEAD, &object));
        w.add_host("host-c", 2);
        w.revoke("host-c");
        assert_eq!(w.open(&object, &me), refused(GENERATION_AHEAD, &object));
        // Signed at the `add_host` itself: it is judged on its other merits.
        f.signed_at_head = Head {
            seq: add_seq,
            hash: w.m.entry_hash_at(add_seq).unwrap(),
        };
        let object = w.envelope(&f, &w.request(&f));
        assert!(matches!(w.open(&object, &me), EnvelopeVerdict::Open { .. }));
        // A result: the host the row went to re-verified, and signed at a head
        // before its new `add_host`.
        let mut w = World::new();
        let before_add = w.head();
        w.add_host("host-b", 2);
        let mut row = expected(&w);
        row.recipient.host_trust_gen = 2;
        let mut f = w.fields("host-b", "host-a");
        f.signed_at_head = before_add;
        let object = result(&w, &f, &status(ID));
        let judge = |w: &World| {
            accept_result(
                &object,
                &w.m,
                &w.recipient("host-a", true),
                &row,
                &w.encs,
                NOW,
            )
        };
        assert_eq!(judge(&w), result_refused(GENERATION_AHEAD, &object));
        w.add_host("host-c", 2);
        assert_eq!(judge(&w), result_refused(GENERATION_AHEAD, &object));
    }

    /// Exactly one key belongs to a `(host_id, host_trust_gen)` the list
    /// holds, so the signature is checked before the object waits: junk can't
    /// fill a known sender's waiting slots.
    #[test]
    fn a_junk_signature_on_a_waiting_object_of_a_known_generation_is_refused() {
        let junk_sig =
            |object: &SignedObject| edited(object, |v| v["sig"] = json!(b64u(&[1u8; 64])));
        // A current host, a head beyond ours.
        let mut w = World::new();
        let me = w.recipient("host-b", true);
        let before = w.m.clone();
        w.add_host("host-c", 2);
        let f = w.fields("host-a", "host-b");
        assert!(f.signed_at_head.seq > before.head().seq);
        let real = w.envelope(&f, &w.request(&f));
        let junk = junk_sig(&real);
        let judge = |object: &SignedObject| open_envelope(object, &before, &me, &w.encs, NOW);
        assert_eq!(judge(&junk), refused(BAD_SIGNATURE, &junk));
        assert_eq!(judge(&real), pending("host-a", 1));
        // Another host's signature isn't the sender's either.
        let as_c = w.resigned(MailKind::Envelope, &real, &host_key_id("host-c", 1), |_| {});
        assert_eq!(judge(&as_c), refused(BAD_SIGNATURE, &as_c));
        // The time checks on the body's times still come first.
        let mut late = f.clone();
        late.expires_at = NOW - 500;
        let object = junk_sig(&w.envelope(&late, &w.request(&late)));
        assert_eq!(judge(&object), refused(EXPIRED, &object));

        // A host held revoked, waiting for a readmit.
        let mut w = World::new();
        let me = w.recipient("host-b", true);
        w.revoke("host-a");
        let before = w.m.clone();
        w.readmit("host-a");
        let f = w.fields("host-a", "host-b");
        let real = w.envelope(&f, &w.request(&f));
        let junk = junk_sig(&real);
        let judge = |object: &SignedObject| open_envelope(object, &before, &me, &w.encs, NOW);
        assert_eq!(judge(&junk), refused(BAD_SIGNATURE, &junk));
        assert_eq!(judge(&real), pending("host-a", 1));

        // A removed host, at the generation it last held.
        let mut w = World::new();
        let me = w.recipient("host-b", true);
        let mut f = w.fields("host-a", "host-b");
        w.remove_host("host-a");
        f.signed_at_head = Head {
            seq: w.head().seq + 1,
            hash: Hash32([0x66; 32]),
        };
        let real = w.envelope(&f, &w.request(&f));
        let junk = junk_sig(&real);
        assert_eq!(w.open(&junk, &me), refused(BAD_SIGNATURE, &junk));
        assert_eq!(w.open(&real, &me), pending("host-a", 1));

        // A result from the row's host, a head beyond ours.
        let mut w = World::new();
        let outbox = expected(&w);
        let before = w.m.clone();
        w.add_host("host-c", 2);
        let f = w.fields("host-b", "host-a");
        let real = result(&w, &f, &status(ID));
        let junk = junk_sig(&real);
        let judge = |object: &SignedObject| {
            accept_result(
                object,
                &before,
                &w.recipient("host-a", true),
                &outbox,
                &w.encs,
                NOW,
            )
        };
        assert_eq!(judge(&junk), result_refused(BAD_SIGNATURE, &junk));
        assert_eq!(
            judge(&real),
            ResultVerdict::Pending {
                host_id: "host-b".into(),
                host_trust_gen: 1,
            }
        );

        // Where the key isn't known yet nothing can be checked: a sender the
        // list doesn't name, or a generation above its newest, waits.
        let mut w = World::new();
        let me = w.recipient("host-b", true);
        let before = w.m.clone();
        w.add_host("host-nobody", 1);
        w.add_host("host-a", 2);
        for sender in ["host-nobody", "host-a"] {
            let f = w.fields(sender, "host-b");
            let junk = junk_sig(&w.envelope(&f, &w.request(&f)));
            assert_eq!(
                open_envelope(&junk, &before, &me, &w.encs, NOW),
                pending(sender, f.sender.host_trust_gen),
                "{sender}"
            );
        }
    }

    #[test]
    fn a_head_beyond_ours_is_pending_until_the_list_catches_up() {
        let mut w = World::new();
        let me = w.recipient("host-b", true);
        let before = w.m.clone();
        w.add_host("host-c", 2);
        let f = w.fields("host-a", "host-b");
        assert!(f.signed_at_head.seq > before.head().seq);
        let object = w.envelope(&f, &w.request(&f));
        assert_eq!(
            open_envelope(&object, &before, &me, &w.encs, NOW),
            pending("host-a", 1)
        );
        assert!(matches!(w.open(&object, &me), EnvelopeVerdict::Open { .. }));
    }

    #[test]
    fn a_pending_object_still_gets_the_time_checks_first() {
        let mut w = World::new();
        let me = w.recipient("host-b", true);
        let before = w.m.clone();
        w.add_host("host-a", 2);
        for (created_at, expires_at, reason) in [
            (NOW - 7_200_000, NOW - 3_600_000, EXPIRED),
            (NOW, NOW, BAD_TIMES),
            (NOW, NOW + 86_400_001, LIFETIME_TOO_LONG),
            (NOW + 60_001, NOW + 3_600_000, CREATED_TOO_FAR_AHEAD),
        ] {
            let mut f = w.fields("host-a", "host-b");
            f.created_at = created_at;
            f.expires_at = expires_at;
            let object = w.envelope(&f, &w.request(&f));
            assert_eq!(
                open_envelope(&object, &before, &me, &w.encs, NOW),
                refused(reason, &object),
                "{reason}"
            );
        }
    }

    #[test]
    fn signed_at_head_before_generation_refused() {
        let mut w = World::new();
        let me = w.recipient("host-b", true);
        // Signed at the genesis, before the host's first add_host (its
        // generation).
        let mut f = w.fields("host-a", "host-b");
        f.signed_at_head = Head {
            seq: 1,
            hash: w.m.entry_hash_at(1).unwrap(),
        };
        let object = w.envelope(&f, &w.request(&f));
        assert_eq!(
            w.open(&object, &me),
            refused(SIGNED_AT_HEAD_BEFORE_GENERATION, &object)
        );
        // After a revoke and a readmit, an envelope signed before the
        // readmit is refused (no replay across a revoke); one signed at or
        // after it opens.
        let before_revoke = w.fields("host-a", "host-b");
        w.revoke("host-a");
        w.readmit("host-a");
        let object = w.envelope(&before_revoke, &w.request(&before_revoke));
        assert_eq!(
            w.open(&object, &me),
            refused(SIGNED_AT_HEAD_BEFORE_GENERATION, &object)
        );
        let after = w.fields("host-a", "host-b");
        let object = w.envelope(&after, &w.request(&after));
        assert!(matches!(w.open(&object, &me), EnvelopeVerdict::Open { .. }));
        // Signed at the readmit itself.
        let mut at_readmit = w.fields("host-a", "host-b");
        at_readmit.signed_at_head = w.head();
        let object = w.envelope(&at_readmit, &w.request(&at_readmit));
        assert!(matches!(w.open(&object, &me), EnvelopeVerdict::Open { .. }));
    }

    #[test]
    fn signed_at_head_wrong_hash_refused() {
        let w = World::new();
        let me = w.recipient("host-b", true);
        // The right seq with another entry's hash, with a made-up one, and
        // an old seq with the head's hash.
        for head in [
            Head {
                seq: w.head().seq,
                hash: w.m.entry_hash_at(w.head().seq - 1).unwrap(),
            },
            Head {
                seq: w.head().seq,
                hash: Hash32([0x42; 32]),
            },
            Head {
                seq: w.head().seq - 1,
                hash: w.head().hash,
            },
        ] {
            let mut f = w.fields("host-a", "host-b");
            f.signed_at_head = head;
            let object = w.envelope(&f, &w.request(&f));
            assert_eq!(
                w.open(&object, &me),
                refused(SIGNED_AT_HEAD_WRONG_HASH, &object),
                "{head:?}"
            );
        }
    }

    #[test]
    fn revoked_sender_refused() {
        let mut w = World::new();
        let me = w.recipient("host-b", true);
        // Signed before the revoke, and at the revoke: both refused.
        let before = w.fields("host-a", "host-b");
        w.revoke("host-a");
        let after = w.fields("host-a", "host-b");
        for f in [before, after] {
            let object = w.envelope(&f, &w.request(&f));
            assert_eq!(w.open(&object, &me), refused(REVOKED_SENDER, &object));
        }
    }

    /// A readmit this host hasn't got yet, and a revoked host that signs for a
    /// head that doesn't exist yet.
    #[test]
    fn a_revoked_sender_with_a_head_beyond_ours_is_pending() {
        let mut w = World::new();
        let me = w.recipient("host-b", true);
        w.revoke("host-a");
        let before = w.m.clone();
        w.readmit("host-a");
        let f = w.fields("host-a", "host-b");
        let object = w.envelope(&f, &w.request(&f));
        assert_eq!(
            open_envelope(&object, &before, &me, &w.encs, NOW),
            pending("host-a", 1)
        );
        assert!(matches!(w.open(&object, &me), EnvelopeVerdict::Open { .. }));
        // A host that stays revoked can't know the hash of an entry that
        // doesn't exist yet: its object stays pending, then fails once the
        // list reaches that seq.
        let mut w = World::new();
        w.revoke("host-a");
        let me = w.recipient("host-b", true);
        let mut f = w.fields("host-a", "host-b");
        f.signed_at_head = Head {
            seq: w.head().seq + 1,
            hash: Hash32([0x66; 32]),
        };
        let object = w.envelope(&f, &w.request(&f));
        assert_eq!(w.open(&object, &me), pending("host-a", 1));
        w.add_host("host-c", 2);
        assert_eq!(w.open(&object, &me), refused(REVOKED_SENDER, &object));
    }

    #[test]
    fn removed_sender_refused() {
        let mut w = World::new();
        let me = w.recipient("host-b", true);
        let before = w.fields("host-a", "host-b");
        w.remove_host("host-a");
        // Signed before the removal, and at it: this head holds the removal.
        let mut at_removal = before.clone();
        at_removal.signed_at_head = w.head();
        for f in [before, at_removal] {
            let object = w.envelope(&f, &w.request(&f));
            assert_eq!(w.open(&object, &me), refused(REMOVED_SENDER, &object));
        }
    }

    /// Entries this host hasn't seen may re-add a removed host (II.4.2): its
    /// envelope signed at a head beyond ours waits.
    #[test]
    fn a_removed_sender_with_a_head_beyond_ours_is_pending() {
        let mut w = World::new();
        let me = w.recipient("host-b", true);
        w.remove_host("host-a");
        let before = w.m.clone();
        // Re-added at a new generation (authorized, as it was), then signs.
        w.add_host("host-a", 2);
        let f = w.fields("host-a", "host-b");
        assert!(f.signed_at_head.seq > before.head().seq);
        let object = w.envelope(&f, &w.request(&f));
        assert_eq!(
            open_envelope(&object, &before, &me, &w.encs, NOW),
            pending("host-a", 2)
        );
        assert!(matches!(w.open(&object, &me), EnvelopeVerdict::Open { .. }));
        // The same claim at its old generation, for a head that doesn't
        // exist yet: pending; once the list reaches that seq it is refused.
        let mut w = World::new();
        let me = w.recipient("host-b", true);
        let mut f = w.fields("host-a", "host-b");
        w.remove_host("host-a");
        f.signed_at_head = Head {
            seq: w.head().seq + 1,
            hash: Hash32([0x66; 32]),
        };
        let object = w.envelope(&f, &w.request(&f));
        assert_eq!(w.open(&object, &me), pending("host-a", 1));
        w.add_host("host-c", 2);
        assert_eq!(w.open(&object, &me), refused(REMOVED_SENDER, &object));
        // The time checks on the body's times come first.
        let mut late = f.clone();
        late.signed_at_head.seq = w.head().seq + 1;
        late.expires_at = NOW - 500;
        let object = w.envelope(&late, &w.request(&late));
        assert_eq!(w.open(&object, &me), refused(EXPIRED, &object));
    }

    #[test]
    fn an_unknown_sender_refused() {
        let mut w = World::new();
        let me = w.recipient("host-b", true);
        let mut f = w.fields("host-a", "host-b");
        f.sender.host_id = "host-nobody".into();
        // It has a key of its own, which no device list names.
        w.hosts
            .generate(host_key_id("host-nobody", 1), Alg::Ed25519)
            .unwrap();
        // At this host's head, and at an older head with its right hash:
        // this head settles it.
        for head in [
            w.head(),
            Head {
                seq: 2,
                hash: w.m.entry_hash_at(2).unwrap(),
            },
        ] {
            f.signed_at_head = head;
            let object = w.envelope(&f, &w.request(&f));
            assert_eq!(w.open(&object, &me), refused(UNKNOWN_SENDER, &object));
        }
    }

    /// Entries this host hasn't seen may add the sender (II.4.2): an unknown
    /// sender's envelope signed at a head beyond ours waits.
    #[test]
    fn an_unknown_sender_with_a_head_beyond_ours_is_pending() {
        let mut w = World::new();
        let me = w.recipient("host-b", true);
        let before = w.m.clone();
        w.add_host("host-nobody", 1);
        let f = w.fields("host-nobody", "host-b");
        assert!(f.signed_at_head.seq > before.head().seq);
        let object = w.envelope(&f, &w.request(&f));
        assert_eq!(
            open_envelope(&object, &before, &me, &w.encs, NOW),
            pending("host-nobody", 1)
        );
        assert!(matches!(w.open(&object, &me), EnvelopeVerdict::Open { .. }));
        // The time checks on the body's times come first.
        let mut late = f.clone();
        late.expires_at = NOW - 500;
        let object = w.envelope(&late, &w.request(&late));
        assert_eq!(
            open_envelope(&object, &before, &me, &w.encs, NOW),
            refused(EXPIRED, &object)
        );
    }

    // ----------------------------------------------------------- check 4

    #[test]
    fn resigned_copy_refused() {
        let w = World::new();
        let me = w.recipient("host-b", true);
        let f = w.fields("host-a", "host-b");
        let object = w.envelope(&f, &w.request(&f));
        let c_key = host_key_id("host-c", 1);
        // C re-signs A's sealed part as its own: the signature is C's and
        // verifies, but the seal's `info` binds A as the sender, so it
        // doesn't open (and C is authenticated, so it is told).
        let as_c = w.resigned(MailKind::Envelope, &object, &c_key, |f| {
            f.sender = HostRef {
                host_id: "host-c".into(),
                host_trust_gen: 1,
            };
        });
        assert_eq!(w.open(&as_c, &me), refused_authenticated(OPEN_FAILED));
        // C re-signs and keeps naming A: C's signature isn't A's.
        let still_a = w.resigned(MailKind::Envelope, &object, &c_key, |_| {});
        assert_eq!(w.open(&still_a, &me), refused(BAD_SIGNATURE, &still_a));
        // C names itself but keeps A's signature.
        let kept_sig = edited(&object, |v| {
            v["body"]["sender"]["host_id"] = json!("host-c");
        });
        assert_eq!(w.open(&kept_sig, &me), refused(BAD_SIGNATURE, &kept_sig));
    }

    #[test]
    fn tampered_sealed_hash_refused() {
        let w = World::new();
        let me = w.recipient("host-b", true);
        let f = w.fields("host-a", "host-b");
        let object = w.envelope(&f, &w.request(&f));
        // The body's `sealed_hash` changed after the signature.
        let moved = edited(&object, |v| {
            v["body"]["sealed_hash"] = json!("ab".repeat(32))
        });
        assert_eq!(w.open(&moved, &me), refused(BAD_SIGNATURE, &moved));
        // A sealed part changed in transit: the signature is the sender's,
        // the hash names other bytes.
        let flipped = edited(&object, |v| {
            let mut ct = crate::encoding::b64u_decode(v["ct"].as_str().unwrap()).unwrap();
            ct[3] ^= 1;
            v["ct"] = json!(b64u(&ct));
        });
        assert_eq!(
            w.open(&flipped, &me),
            refused_authenticated(SEALED_HASH_MISMATCH)
        );
        // The sender signs a body whose hash names nothing it sealed.
        let (_, old) = MailBody::from_object(&object).unwrap();
        let mut body = old;
        body.sealed_hash = Hash32([0x77; 32]);
        let lying = SignedObject::sign(
            &w.hosts,
            &w.sender_key(&f),
            body.to_value(MailKind::Envelope),
        )
        .unwrap()
        .with_sealed(object.sealed().unwrap().clone());
        assert_eq!(
            w.open(&lying, &me),
            refused_authenticated(SEALED_HASH_MISMATCH)
        );
    }

    // ----------------------------------------------------------- check 5

    #[test]
    fn expired_refused() {
        let w = World::new();
        let me = w.recipient("host-b", true);
        let f = w.fields("host-a", "host-b");
        let object = w.envelope(&f, &w.request(&f));
        // The sender is authenticated, so the refusal goes back to it.
        assert!(matches!(
            w.open_at(&object, &me, f.expires_at - 1),
            EnvelopeVerdict::Open { .. }
        ));
        for at in [f.expires_at, f.expires_at + 1, f.expires_at + 3_600_000] {
            assert_eq!(
                w.open_at(&object, &me, at),
                refused_authenticated(EXPIRED),
                "{at}"
            );
        }
    }

    #[test]
    fn created_too_far_ahead_refused() {
        let w = World::new();
        let me = w.recipient("host-b", true);
        let mut f = w.fields("host-a", "host-b");
        f.created_at = NOW + 60_000;
        f.expires_at = NOW + 3_600_000;
        let object = w.envelope(&f, &w.request(&f));
        assert!(matches!(w.open(&object, &me), EnvelopeVerdict::Open { .. }));
        f.created_at = NOW + 60_001;
        let object = w.envelope(&f, &w.request(&f));
        assert_eq!(
            w.open(&object, &me),
            refused_authenticated(CREATED_TOO_FAR_AHEAD)
        );
    }

    #[test]
    fn the_lifetime_is_at_most_24_hours_and_positive() {
        let w = World::new();
        let me = w.recipient("host-b", true);
        let mut f = w.fields("host-a", "host-b");
        f.created_at = NOW;
        f.expires_at = NOW + 86_400_000;
        let object = w.envelope(&f, &w.request(&f));
        assert!(matches!(w.open(&object, &me), EnvelopeVerdict::Open { .. }));
        for (expires_at, reason) in [
            (NOW + 86_400_001, LIFETIME_TOO_LONG),
            (NOW, BAD_TIMES),
            (NOW - 1, BAD_TIMES),
        ] {
            f.expires_at = expires_at;
            let object = w.forged(MailKind::Envelope, &f, b"{}");
            assert_eq!(
                w.open(&object, &me),
                refused_authenticated(reason),
                "{expires_at}"
            );
        }
    }

    // ----------------------------------------------------------- check 6

    #[test]
    fn plaintext_ids_mismatch_refused_authenticated() {
        let w = World::new();
        let me = w.recipient("host-b", true);
        let f = w.fields("host-a", "host-b");
        let edits: [(&str, Edit); 4] = [
            ("message_id", Box::new(|m| m.message_id = ID2.into())),
            ("created_at", Box::new(|m| m.created_at += 1)),
            ("expires_at", Box::new(|m| m.expires_at -= 1)),
            ("sender", Box::new(|m| m.sender = "host:host-c".into())),
        ];
        for (what, edit) in edits {
            let mut m = message(&f);
            edit(&mut m);
            let object = w.envelope(&f, &EnvelopePlain::Request { message: m });
            assert_eq!(
                w.open(&object, &me),
                refused_authenticated(PLAINTEXT_MISMATCH),
                "{what}"
            );
        }
    }

    #[test]
    fn attachments_refused_authenticated() {
        let w = World::new();
        let me = w.recipient("host-b", true);
        let f = w.fields("host-a", "host-b");
        let mut m = message(&f);
        m.mark = Some(crate::session::mark::MarkTask {
            mark_id: "mark_123".into(),
            url: "http://localhost:3000".into(),
            title: "Page".into(),
            screenshot: crate::session::attachments::Attachment {
                attachment_id: ID2.into(),
                digest: crate::session::host_work::digest(b"png"),
                size: 68,
                media_type: "image/png".into(),
            },
            annotations: vec![],
        });
        let object = w.envelope(&f, &EnvelopePlain::Request { message: m.clone() });
        assert_eq!(
            w.open(&object, &me),
            refused_authenticated(ATTACHMENTS_NOT_ALLOWED)
        );
        // A request whose agent task carries the screenshot (a task's
        // attachments are its message's mark: `Message::task`).
        let host = m.recipients[0].host.clone();
        m.recipients.push(crate::session::messages::Recipient {
            recipient_id: REPLY_ID.replace("-5", "-4"),
            host: host.clone(),
            destination: crate::session::messages::Destination::Agent {
                route_id: "backend".into(),
                route_revision: 1,
                target: crate::session::wire::Target {
                    account_id: host.account_id.clone(),
                    atem_device_id: host.atem_device_id.clone(),
                    host_trust_gen: host.host_trust_gen,
                    session_id: "ses-aaaaaaaaaaaa".into(),
                    process_gen: ID2.into(),
                },
            },
        });
        let task = m.task(&m.recipients[1]).unwrap();
        assert_eq!(task.attachments.len(), 1);
        let object = w.envelope(&f, &EnvelopePlain::Request { message: m });
        assert_eq!(
            w.open(&object, &me),
            refused_authenticated(ATTACHMENTS_NOT_ALLOWED)
        );
        // Anything else `valid_from_host` refuses: the local-only fields, a
        // kind other than request, a message that isn't valid.
        let edits: [(&str, Edit); 4] = [
            (
                "from_session",
                Box::new(|m| m.from_session = Some("ses-abcdefghijkl".into())),
            ),
            (
                "reply_to",
                Box::new(|m| {
                    m.reply_to = Some(ReplyTo {
                        message_id: ID2.into(),
                        task_id: ID2.into(),
                    })
                }),
            ),
            ("kind", Box::new(|m| m.kind = MessageKind::Status)),
            ("blank", Box::new(|m| m.text = " ".into())),
        ];
        for (what, edit) in edits {
            let mut m = message(&f);
            edit(&mut m);
            let object = w.envelope(&f, &EnvelopePlain::Request { message: m });
            assert_eq!(
                w.open(&object, &me),
                refused_authenticated(INVALID_MESSAGE),
                "{what}"
            );
        }
    }

    #[test]
    fn a_plaintext_that_does_not_read_is_refused_authenticated() {
        let w = World::new();
        let me = w.recipient("host-b", true);
        let f = w.fields("host-a", "host-b");
        let cancel = format!(r#"{{"kind":"cancel","task_id":"{ID2}"}}"#);
        let cases: [(&str, String, &str); 6] = [
            (
                "null",
                format!(r#"{{"kind":"cancel","task_id":"{ID2}","extra":null}}"#),
                PLAINTEXT_NULL,
            ),
            (
                "unknown kind",
                r#"{"kind":"shout"}"#.into(),
                PLAINTEXT_MALFORMED,
            ),
            (
                "extra member",
                format!(r#"{{"kind":"cancel","task_id":"{ID2}","extra":1}}"#),
                PLAINTEXT_MALFORMED,
            ),
            (
                "not canonical",
                format!(r#"{{ "kind":"cancel","task_id":"{ID2}" }}"#),
                PLAINTEXT_MALFORMED,
            ),
            ("not json", "cancel".into(), PLAINTEXT_MALFORMED),
            (
                "too large",
                format!(
                    r#"{{"kind":"cancel","task_id":"{}"}}"#,
                    "a".repeat(crate::host_mail::MAX_PLAINTEXT_BYTES + 100)
                ),
                PLAINTEXT_TOO_LARGE,
            ),
        ];
        for (what, plaintext, reason) in cases {
            let object = w.forged(MailKind::Envelope, &f, plaintext.as_bytes());
            assert_eq!(
                w.open(&object, &me),
                refused_authenticated(reason),
                "{what}"
            );
        }
        // The well-formed one, for contrast.
        let object = w.forged(MailKind::Envelope, &f, cancel.as_bytes());
        assert!(matches!(w.open(&object, &me), EnvelopeVerdict::Open { .. }));
    }

    #[test]
    fn a_key_provider_that_fails_decides_nothing() {
        let w = World::new();
        let f = w.fields("host-a", "host-b");
        let object = w.envelope(&f, &w.request(&f));
        let mut me = w.recipient("host-b", true);
        // The caller's key id isn't behind the provider.
        me.keys[0].0 = KeyId::new("not-there");
        let verdict = w.open(&object, &me);
        assert!(
            matches!(verdict, EnvelopeVerdict::Unavailable { .. }),
            "{verdict:?}"
        );
        // A key behind the provider that isn't the declared one.
        let mut me = w.recipient("host-b", true);
        me.keys[0].0 = enc_key_id("host-c", 3);
        let verdict = w.open(&object, &me);
        assert!(
            matches!(verdict, EnvelopeVerdict::Unavailable { .. }),
            "{verdict:?}"
        );
    }

    // ------------------------------------------------------------ results

    /// B ran the work for A: the result's sender is B, its recipient A, and
    /// A's outbox row expects B's answer to the request `ID`.
    fn expected(w: &World) -> ExpectedResult {
        ExpectedResult {
            recipient: HostRef {
                host_id: "host-b".into(),
                host_trust_gen: w.gen_of("host-b"),
            },
            message_id: ID.into(),
            cancel_complete_ids: vec![ID2.into()],
            task_ids: vec![ID2.into(), REPLY_ID.into()],
        }
    }

    fn result(w: &World, f: &MailFields, plain: &ResultPlain) -> SignedObject {
        seal_result(
            &w.hosts,
            &w.sender_key(f),
            f,
            plain,
            &w.enc_pub(&f.recipient.host_id),
        )
        .unwrap()
    }

    fn status(message_id: &str) -> ResultPlain {
        ResultPlain::Status {
            message_id: message_id.into(),
            recipients: vec![RecipientReceipt {
                recipient_id: ID2.into(),
                delivery: Delivery::Stored,
            }],
        }
    }

    fn accept(w: &World, object: &SignedObject, outbox: &ExpectedResult) -> ResultVerdict {
        accept_result(
            object,
            &w.m,
            &w.recipient("host-a", true),
            outbox,
            &w.encs,
            NOW,
        )
    }

    fn result_refused(reason: &'static str, object: &SignedObject) -> ResultVerdict {
        ResultVerdict::Refused {
            reason,
            evidence: evidence_hash(object),
        }
    }

    fn result_refused_authenticated(reason: &'static str) -> ResultVerdict {
        ResultVerdict::RefusedAuthenticated {
            object_id: ID.into(),
            reason,
        }
    }

    #[test]
    fn a_result_from_the_recipient_is_accepted() {
        let w = World::new();
        let f = w.fields("host-b", "host-a");
        let outbox = expected(&w);
        let plains = [
            status(ID),
            ResultPlain::Refusal {
                object_id: ID2.into(),
                refused: "invalid_request".into(),
            },
            ResultPlain::Refusal {
                object_id: ID.into(),
                refused: "forbidden".into(),
            },
            ResultPlain::Result {
                task_id: REPLY_ID.into(),
                reply: reply(0),
            },
        ];
        for plain in plains {
            let object = result(&w, &f, &plain);
            assert_eq!(
                accept(&w, &object, &outbox),
                ResultVerdict::Accepted {
                    plain,
                    sender: "host:host-b".into(),
                }
            );
        }
    }

    #[test]
    fn result_from_non_recipient_refused() {
        let w = World::new();
        let outbox = expected(&w);
        // Host C is a valid host of the account and signs a well-formed
        // result of its own, but the outbox row went to B.
        let f = w.fields("host-c", "host-a");
        let object = result(&w, &f, &status(ID));
        assert_eq!(
            accept(&w, &object, &outbox),
            result_refused(NOT_THE_RECIPIENT, &object)
        );
        // B at another generation than the one the row went to.
        let mut other_gen = outbox.clone();
        other_gen.recipient.host_trust_gen += 1;
        let f = w.fields("host-b", "host-a");
        let object = result(&w, &f, &status(ID));
        assert_eq!(
            accept(&w, &object, &other_gen),
            result_refused(NOT_THE_RECIPIENT, &object)
        );
        // An envelope isn't a result.
        let env = w.envelope(
            &w.fields("host-b", "host-a"),
            &EnvelopePlain::Cancel {
                task_id: ID2.into(),
            },
        );
        assert_eq!(accept(&w, &env, &outbox), result_refused(WRONG_KIND, &env));
    }

    #[test]
    fn a_result_must_answer_the_outbox_row() {
        let w = World::new();
        let f = w.fields("host-b", "host-a");
        let outbox = expected(&w);
        let other = "8b3e4c60-5d9f-4a0c-9e23-4f7b9c1d5e60";
        let plains = [
            status(other),
            ResultPlain::Refusal {
                object_id: other.into(),
                refused: "busy".into(),
            },
            ResultPlain::Result {
                task_id: other.into(),
                reply: reply(0),
            },
        ];
        for plain in plains {
            let object = result(&w, &f, &plain);
            assert_eq!(
                accept(&w, &object, &outbox),
                result_refused_authenticated(DOES_NOT_ANSWER_OUTBOX_ROW),
                "{plain:?}"
            );
        }
    }

    #[test]
    fn a_result_is_checked_like_an_envelope() {
        let mut w = World::new();
        let outbox = expected(&w);
        let f = w.fields("host-b", "host-a");
        let object = result(&w, &f, &status(ID));
        // Times.
        let late = accept_result(
            &object,
            &w.m,
            &w.recipient("host-a", true),
            &outbox,
            &w.encs,
            f.expires_at,
        );
        assert_eq!(late, result_refused_authenticated(EXPIRED));
        // Another recipient (host-c) is told nothing about it.
        let to_c = accept_result(
            &object,
            &w.m,
            &w.recipient("host-c", true),
            &outbox,
            &w.encs,
            NOW,
        );
        assert_eq!(to_c, result_refused(NOT_FOR_THIS_HOST, &object));
        // A wrong hash at the head it names; a junk signature.
        let mut bad = f.clone();
        bad.signed_at_head.hash = Hash32([5; 32]);
        let object2 = result(&w, &bad, &status(ID));
        assert_eq!(
            accept(&w, &object2, &outbox),
            result_refused(SIGNED_AT_HEAD_WRONG_HASH, &object2)
        );
        let junk = edited(&object, |v| v["sig"] = json!(b64u(&[1u8; 64])));
        assert_eq!(
            accept(&w, &junk, &outbox),
            result_refused(BAD_SIGNATURE, &junk)
        );
        // B's head is beyond A's: pending, not refused.
        let before = w.m.clone();
        w.add_host("host-c", 2);
        let ahead = result(&w, &w.fields("host-b", "host-a"), &status(ID));
        assert_eq!(
            accept_result(
                &ahead,
                &before,
                &w.recipient("host-a", true),
                &outbox,
                &w.encs,
                NOW
            ),
            ResultVerdict::Pending {
                host_id: "host-b".into(),
                host_trust_gen: 1,
            }
        );
        assert!(matches!(
            accept(&w, &ahead, &outbox),
            ResultVerdict::Accepted { .. }
        ));
    }

    /// II.4.4: a result of a host this list holds revoked is not delivered
    /// but kept as data.
    #[test]
    fn a_revoked_hosts_result_is_kept_as_data() {
        let mut w = World::new();
        let outbox = expected(&w);
        w.revoke("host-b");
        let f = w.fields("host-b", "host-a");
        for plain in [
            status(ID),
            ResultPlain::Result {
                task_id: REPLY_ID.into(),
                reply: reply(0),
            },
        ] {
            let object = result(&w, &f, &plain);
            assert_eq!(
                accept(&w, &object, &outbox),
                ResultVerdict::NotDelivered {
                    plain,
                    sender: "host:host-b".into(),
                    reason: NOT_DELIVERED_SENDER_REVOKED,
                }
            );
        }
        // A bad signature is refused, kept or not.
        let object = result(&w, &f, &status(ID));
        let junk = edited(&object, |v| v["sig"] = json!(b64u(&[1u8; 64])));
        assert_eq!(
            accept(&w, &junk, &outbox),
            result_refused(BAD_SIGNATURE, &junk)
        );
        // Another host's signature isn't the sender's.
        let as_c = w.resigned(MailKind::Result, &object, &host_key_id("host-c", 1), |_| {});
        assert_eq!(
            accept(&w, &as_c, &outbox),
            result_refused(BAD_SIGNATURE, &as_c)
        );
        // It still has to answer the row, and to name a head this list has.
        let object = result(&w, &f, &status("8b3e4c60-5d9f-4a0c-9e23-4f7b9c1d5e60"));
        assert_eq!(
            accept(&w, &object, &outbox),
            result_refused_authenticated(DOES_NOT_ANSWER_OUTBOX_ROW)
        );
        let mut bad = f.clone();
        bad.signed_at_head.hash = Hash32([5; 32]);
        let object = result(&w, &bad, &status(ID));
        assert_eq!(
            accept(&w, &object, &outbox),
            result_refused(SIGNED_AT_HEAD_WRONG_HASH, &object)
        );
    }

    /// II.4.4: a result of a removed host is verified with the key it last
    /// held, and is kept as data.
    #[test]
    fn a_removed_hosts_result_is_kept_as_data() {
        let mut w = World::new();
        let outbox = expected(&w);
        let f = w.fields("host-b", "host-a");
        w.remove_host("host-b");
        let kept = |plain: ResultPlain| ResultVerdict::NotDelivered {
            plain,
            sender: "host:host-b".into(),
            reason: NOT_DELIVERED_SENDER_REMOVED,
        };
        // Signed before the removal, and at it.
        let mut at_removal = f.clone();
        at_removal.signed_at_head = w.head();
        for f in [&f, &at_removal] {
            let object = result(&w, f, &status(ID));
            assert_eq!(accept(&w, &object, &outbox), kept(status(ID)));
        }
        // A bad signature, or another host's, is refused.
        let object = result(&w, &f, &status(ID));
        let junk = edited(&object, |v| v["sig"] = json!(b64u(&[1u8; 64])));
        assert_eq!(
            accept(&w, &junk, &outbox),
            result_refused(BAD_SIGNATURE, &junk)
        );
        let as_c = w.resigned(MailKind::Result, &object, &host_key_id("host-c", 1), |_| {});
        assert_eq!(
            accept(&w, &as_c, &outbox),
            result_refused(BAD_SIGNATURE, &as_c)
        );
        // The row's other rules hold: the answer, the head's hash.
        let object = result(&w, &f, &status("8b3e4c60-5d9f-4a0c-9e23-4f7b9c1d5e60"));
        assert_eq!(
            accept(&w, &object, &outbox),
            result_refused_authenticated(DOES_NOT_ANSWER_OUTBOX_ROW)
        );
        let mut bad = f.clone();
        bad.signed_at_head.hash = Hash32([5; 32]);
        let object = result(&w, &bad, &status(ID));
        assert_eq!(
            accept(&w, &object, &outbox),
            result_refused(SIGNED_AT_HEAD_WRONG_HASH, &object)
        );
        // A generation the list never gave the removed host, at a head the
        // list has: settled (past its head it would wait).
        let mut never = f.clone();
        never.sender.host_trust_gen = 2;
        never.signed_at_head = w.head();
        w.hosts
            .generate(host_key_id("host-b", 2), Alg::Ed25519)
            .unwrap();
        let mut row = outbox.clone();
        row.recipient.host_trust_gen = 2;
        let object = result(&w, &never, &status(ID));
        assert_eq!(
            accept_result(
                &object,
                &w.m,
                &w.recipient("host-a", true),
                &row,
                &w.encs,
                NOW
            ),
            result_refused(REMOVED_SENDER, &object)
        );
        // Revoked and then removed: still revoked (a removal keeps the state).
        let mut w = World::new();
        let outbox = expected(&w);
        let f = w.fields("host-b", "host-a");
        w.revoke("host-b");
        w.remove_host("host-b");
        let object = result(&w, &f, &status(ID));
        assert_eq!(
            accept(&w, &object, &outbox),
            ResultVerdict::NotDelivered {
                plain: status(ID),
                sender: "host:host-b".into(),
                reason: NOT_DELIVERED_SENDER_REVOKED,
            }
        );
    }

    /// A removed host, once re-added, is judged by its newest key: a result
    /// with the key it held before the removal is for a generation this list
    /// has replaced.
    #[test]
    fn a_removed_hosts_result_beyond_our_head_waits_and_a_readded_one_is_stale() {
        let mut w = World::new();
        let outbox = expected(&w);
        let f = w.fields("host-b", "host-a");
        w.remove_host("host-b");
        let before = w.m.clone();
        let mut ahead = f.clone();
        w.add_host("host-c", 2);
        ahead.signed_at_head = w.head();
        let object = result(&w, &ahead, &status(ID));
        let verdict = |list: &Membership| {
            accept_result(
                &object,
                list,
                &w.recipient("host-a", true),
                &outbox,
                &w.encs,
                NOW,
            )
        };
        assert_eq!(
            verdict(&before),
            ResultVerdict::Pending {
                host_id: "host-b".into(),
                host_trust_gen: 1,
            }
        );
        assert!(matches!(
            verdict(&w.m),
            ResultVerdict::NotDelivered {
                reason: NOT_DELIVERED_SENDER_REMOVED,
                ..
            }
        ));
        // Re-added at generation 2: the old key's result is stale.
        w.add_host("host-b", 2);
        let object = result(&w, &f, &status(ID));
        assert_eq!(
            accept(&w, &object, &outbox),
            result_refused(STALE_SENDER_GENERATION, &object)
        );
    }

    #[test]
    fn a_removed_hosts_last_key_is_its_newest_add_host() {
        let mut w = World::new();
        // A current host and a host never named have none.
        assert_eq!(w.m.removed_host("host-a"), None);
        assert_eq!(w.m.removed_host("host-nobody"), None);
        w.add_host("host-a", 2);
        let newest = w.m.host("host-a").unwrap().clone();
        assert_eq!(newest.host_trust_gen, 2);
        w.remove_host("host-a");
        assert_eq!(w.m.host("host-a"), None);
        assert_eq!(w.m.removed_host("host-a"), Some(&newest));
        // The stored form and a replay agree.
        let back = Membership::from_stored(ACCOUNT, &w.m.genesis_hash(), &w.m.to_stored()).unwrap();
        assert_eq!(back.removed_host("host-a"), Some(&newest));
        // A re-add makes it current again, with its new key.
        w.add_host("host-a", 3);
        assert_eq!(w.m.removed_host("host-a"), None);
        assert_eq!(w.m.host("host-a").unwrap().host_trust_gen, 3);
    }

    #[test]
    fn a_results_head_before_the_senders_generation_is_refused() {
        let w = World::new();
        let outbox = expected(&w);
        let mut f = w.fields("host-b", "host-a");
        f.signed_at_head = Head {
            seq: 1,
            hash: w.m.entry_hash_at(1).unwrap(),
        };
        let object = result(&w, &f, &status(ID));
        assert_eq!(
            accept(&w, &object, &outbox),
            result_refused(SIGNED_AT_HEAD_BEFORE_GENERATION, &object)
        );
    }
}
