//! The receiving host's mailbox client (host-work-v1 §11.5, "The mailbox
//! calls"; the delegated host-work design II.4.2, II.4.3, II.5), behind the
//! debug-only hook's `host.senders` (with `host.delegated`): the host's own
//! mailbox on its Station, as `heads` announces it.
use atem_client::control::MailboxHead;

/// The host's side of its own mailbox on its Station link.
#[derive(Debug, Default)]
pub struct MailboxClient {
    /// The host's own mailbox, as the last `heads` on this link announced
    /// it (none: that `heads` named none).
    announced: Option<MailboxHead>,
}

impl MailboxClient {
    /// A `heads` on the link: its mailbox head, the host's own mailbox
    /// (rule 6), or none (a `heads` without one announces no mailbox).
    pub fn on_heads(&mut self, mailbox: Option<MailboxHead>) {
        self.announced = mailbox;
    }

    /// The host's own mailbox as last announced.
    pub fn announced(&self) -> Option<&MailboxHead> {
        self.announced.as_ref()
    }
}
