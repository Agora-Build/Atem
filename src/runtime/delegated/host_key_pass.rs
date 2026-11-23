//! Host senders' encryption key in the bridge (the routine rotation, agreed
//! with Astation on 2026-11-23, #120 comment 7089435308; `r9::host_enc`):
//! with `host.delegated` and `host.senders` on, the key file is brought to
//! the committed device list on the pass where the list's head moved, when
//! the previous key's window ends on the delegated clock's `D`, and once a
//! minute besides; the receiver's view does the same before any mail is
//! opened (`mail_receiver`). A change of the key file (a promotion, a
//! retirement) has the waiting objects judged again. The commit watch the
//! device list runs just before it writes a commit (`commit_watch`)
//! stamps a pending key's application with the start view's `D`.
//!
//! Nothing runs with the hook off, or while the list doesn't serve.
use super::*;
use crate::session_protocol::r9::host_enc;

/// The key file is brought to the list at least this often (a write that
/// failed, `D` read again after none, a file changed by another process).
const HOST_KEY_EVERY: Duration = Duration::from_secs(60);

impl HostBridge {
    /// See the module doc. A failure is a runtime.log line; nothing is
    /// decided on the key state until a pass brings it to the list.
    pub(crate) fn host_key_pass(&mut self) {
        if !(self.features.delegated && self.features.senders) {
            return;
        }
        let Some(pairing) = self.pairing.clone() else {
            return;
        };
        let (list, now_d) = {
            let view = self.start_view();
            (view.list.clone(), view.now_d_ms)
        };
        let Some(list) = list.filter(FeedStore::serves) else {
            return;
        };
        let identity = self.work_host();
        let head = list.membership.head();
        let due = match &self.work.host_key_checked {
            Some((who, seq, hash, at, retire_at)) => {
                *who != identity
                    || *seq != head.seq
                    || *hash != head.hash
                    || at.elapsed() >= HOST_KEY_EVERY
                    || retire_at.zip(now_d).is_some_and(|(due, now)| now >= due)
            }
            None => true,
        };
        if !due {
            return;
        }
        match host_enc::reconcile(
            &pairing,
            &identity.atem_device_id,
            identity.host_trust_gen,
            &list.membership,
            now_d,
        ) {
            Ok(done) => {
                self.work.host_key_checked = Some((
                    identity,
                    head.seq,
                    head.hash,
                    Instant::now(),
                    done.retire_at,
                ));
                self.host_keys_reconciled(&done);
            }
            Err(why) => {
                // Tried again within the minute.
                self.work.host_key_checked = None;
                delegated_mail_pass::log_limited(&UNRECONCILED, || {
                    format!("atem runtime: host encryption key: {why}")
                });
            }
        }
    }

    /// After the key file was brought to the list: its lines to runtime.log,
    /// and a change has the waiting objects judged again.
    pub(crate) fn host_keys_reconciled(&mut self, done: &host_enc::Reconciled) {
        for line in &done.lines {
            eprintln!("atem runtime: host encryption key: {line}");
        }
        if done.changed {
            self.work.host_keys_changed += 1;
        }
    }
}

/// The device list's commit watch (`MembershipHost::set_commit_watch`), with
/// `host.senders` on: a commit that sets this host's pending key stamps it,
/// just before the list is written, with `D` as the start view last read it
/// (at or before the commit).
pub(crate) fn commit_watch(
    view: &Arc<std::sync::Mutex<StartView>>,
) -> crate::session_protocol::membership::CommitWatch {
    let view = view.clone();
    Box::new(move |store, prev, next, pin| {
        let now_d = view
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .now_d_ms;
        for line in host_enc::stamp_application_locked(
            store,
            prev,
            next,
            &pin.host_id,
            pin.host_trust_gen,
            now_d,
        ) {
            eprintln!("atem runtime: host encryption key: {line}");
        }
    })
}

static UNRECONCILED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
