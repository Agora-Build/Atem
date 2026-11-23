//! Domain separation (§R9.1). Every signature is over
//! `enc([label, …])` with a label of `SignLabel`; every hash, KDF and seal
//! input starts with its own label from this module. No label is used for
//! two purposes, and `enc`'s length prefixes keep fields from shifting.
use crate::encoding::enc;

/// Labels of signing inputs. A `SigningInput` can only be built with one, so
/// nothing in this crate signs bytes without a domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignLabel {
    /// `atem-membership-entry` bodies.
    MembershipEntry,
    /// `kit_sig` beside a `set_recovery_key` entry with `kit: "current"`.
    RecoveryCosign,
    /// `atem-browser-grant` bodies.
    BrowserGrant,
    /// `atem-push-hint` bodies.
    PushHint,
    /// `atem-seen` bodies.
    Seen,
    /// `sig_h` over `th2` (§R9.7).
    ChannelHost,
    /// `sig_c` over `th3` (§R9.7).
    ChannelClient,
    /// `atem-host-route` bodies (§R9.7b).
    HostRoute,
    /// `atem-host-route-proxy` bodies (§R9.7b, a Station's challenge through
    /// Astation's `:8080` proxy; agreed with Astation 2026-11-16, #174): the
    /// host route proof's fields under their own domain, so a proof given
    /// on a local link is never a relay route.
    HostRouteProxy,
    /// A host's `enc_sig` inside a `host_enc_key` entry (delegated
    /// host-work design II.4.1): Ed25519 by its `host_key` over
    /// [`SigningInput::fields`], not over a body.
    HostEncKey,
    /// `atem-host-work-control` bodies: control records (delegated
    /// host-work design I.5.3).
    HostWorkControl,
    /// `atem-envelope` bodies (delegated host-work design II.4.2): a host
    /// sender's request, cancel or complete, signed by its `host_key`.
    Envelope,
    /// `atem-result` bodies (II.4.4): the status or result the host that ran
    /// the work sends back, signed by its `host_key`.
    Result,
    /// `atem-verifier-report` bodies (`member_report`; session-v1 R9.2 "How
    /// a verifier reports itself", agreed for implementation on Astation
    /// #101): a native member's or a service's signed report of the
    /// verifier its loaded core runs, for a minter's challenge.
    VerifierReport,
    /// `atem-signer-report` bodies (`member_report::signer`; host-work-v1
    /// §11.1 "The signer report", agreed with Astation, #114 comment
    /// 7089435073): a native manager's signed report of its control-record
    /// signing journal, for a Station's recovery from a rollback.
    SignerReport,
}

impl SignLabel {
    pub const fn as_str(self) -> &'static str {
        match self {
            SignLabel::MembershipEntry => "atem-membership-entry-v1",
            SignLabel::RecoveryCosign => "atem-recovery-cosign-v1",
            SignLabel::BrowserGrant => "atem-browser-grant-v1",
            SignLabel::PushHint => "atem-push-hint-v1",
            SignLabel::Seen => "atem-seen-v1",
            SignLabel::ChannelHost => "atem-ch1-host-sig-v1",
            SignLabel::ChannelClient => "atem-ch1-client-sig-v1",
            SignLabel::HostRoute => "atem-host-route-v1",
            SignLabel::HostRouteProxy => "atem-host-route-proxy-v1",
            SignLabel::HostEncKey => "atem-host-enc-key-v1",
            SignLabel::HostWorkControl => "atem-host-work-control-v1",
            SignLabel::Envelope => "atem-envelope-v1",
            SignLabel::Result => "atem-result-v1",
            SignLabel::VerifierReport => "atem-verifier-report-v1",
            SignLabel::SignerReport => "atem-signer-report-v1",
        }
    }

    /// The label of a signed body's `type` (§R9.1 table). The co-signature,
    /// the channel signatures and a host's `enc_sig` have no body type.
    pub fn of_body_type(body_type: &str) -> Option<Self> {
        match body_type {
            "atem-membership-entry" => Some(SignLabel::MembershipEntry),
            "atem-browser-grant" => Some(SignLabel::BrowserGrant),
            "atem-push-hint" => Some(SignLabel::PushHint),
            "atem-seen" => Some(SignLabel::Seen),
            "atem-host-route" => Some(SignLabel::HostRoute),
            "atem-host-route-proxy" => Some(SignLabel::HostRouteProxy),
            "atem-host-work-control" => Some(SignLabel::HostWorkControl),
            "atem-envelope" => Some(SignLabel::Envelope),
            "atem-result" => Some(SignLabel::Result),
            "atem-verifier-report" => Some(SignLabel::VerifierReport),
            "atem-signer-report" => Some(SignLabel::SignerReport),
            _ => None,
        }
    }
}

/// Exactly the bytes a signer signs: `enc([label, payload])`, or
/// `enc([label, f1, …])` for a signature over fields ([`Self::fields`]).
/// The label is always the first field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigningInput {
    label: SignLabel,
    bytes: Vec<u8>,
}

impl SigningInput {
    /// `enc([label, jcs(body)])` for a signed object, or
    /// `enc([label, th])` for a channel signature.
    pub fn new(label: SignLabel, payload: &[u8]) -> Self {
        Self::fields(label, &[payload])
    }

    /// `enc([label, f1, …])`: a signature over fields rather than a body
    /// (a host's `enc_sig`, II.4.1). `new(label, p)` is `fields(label, &[p])`.
    pub fn fields(label: SignLabel, fields: &[&[u8]]) -> Self {
        let mut all = Vec::with_capacity(fields.len() + 1);
        all.push(label.as_str().as_bytes());
        all.extend_from_slice(fields);
        SigningInput {
            label,
            bytes: enc(&all),
        }
    }

    pub fn label(&self) -> SignLabel {
        self.label
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

// Hash, KDF and seal domains (never signing inputs).
pub const MEMBERSHIP_HASH: &str = "atem-membership-hash-v1";
pub const BROWSER_GRANT_HASH: &str = "atem-browser-grant-hash-v1";
pub const CH1_TH2: &str = "atem-ch1-th2";
pub const CH1_TH3: &str = "atem-ch1-th3";
pub const CH1_TH4: &str = "atem-ch1-th4";
pub const CH1_FINISH_KEY: &str = "atem-ch1 finish c2h";
pub const CH1_AP_C2H: &str = "atem-ch1 ap c2h";
pub const CH1_AP_H2C: &str = "atem-ch1 ap h2c";
pub const CH1_FINISH_AAD: &str = "atem-ch1-finish";
pub const CH1_RECORD_AAD: &str = "atem-ch1-rec";
pub const PUSH_SEAL: &str = "atem-push-seal-v1";
/// The HPKE `info` label of an `atem-envelope`'s sealed part (II.4.2).
pub const ENVELOPE_SEAL: &str = "atem-envelope-seal-v1";
/// The HPKE `info` label of an `atem-result`'s sealed part (II.4.4).
pub const RESULT_SEAL: &str = "atem-result-seal-v1";
pub const ENC_KID: &str = "atem-enc-kid-v1";
pub const K_BACKUP: &str = "atem-k-backup-v2";
pub const RECOVERY_KIT: &str = "atem-recovery-kit-v2";
pub const RECOVERY_KIT_TAG: &str = "atem-recovery-kit-tag-v1";
pub const K_BACKUP_HASH: &str = "atem-k-backup-hash-v1";
pub const RECOVERY_SIGN: &str = "atem-recovery-sign-v1";
pub const SAFETY_CODE: &str = "atem-safety-code-v2";
/// A Station's report ids to the Portal (`control::ledger`).
pub const STATION_REPORT_ID: &str = "atem-station-report-id-v1";
/// The `mailbox_id`s the reference mailbox mints from its seed
/// (`host_mail::reference`).
pub const REFERENCE_MAILBOX_ID: &str = "atem-reference-mailbox-id-v1";
/// A signer report's `journal.records_hash`: SHA-256 over this label and
/// the sorted SHA-256 of each record body (`member_report::signer`).
pub const SIGNER_REPORT_RECORDS: &str = "atem-signer-report-records-v1";
/// A signer report's `journal.drafts_hash`, the same over its drafts.
pub const SIGNER_REPORT_DRAFTS: &str = "atem-signer-report-drafts-v1";

#[cfg(test)]
mod tests {
    use super::*;

    /// Every label, in one list. The match fails to compile until a new
    /// label is listed here too, so the distinctness test covers it.
    const LABELS: [SignLabel; 15] = [
        SignLabel::MembershipEntry,
        SignLabel::RecoveryCosign,
        SignLabel::BrowserGrant,
        SignLabel::PushHint,
        SignLabel::Seen,
        SignLabel::ChannelHost,
        SignLabel::ChannelClient,
        SignLabel::HostRoute,
        SignLabel::HostEncKey,
        SignLabel::HostWorkControl,
        SignLabel::Envelope,
        SignLabel::Result,
        SignLabel::HostRouteProxy,
        SignLabel::VerifierReport,
        SignLabel::SignerReport,
    ];

    const fn listed(label: SignLabel) -> usize {
        match label {
            SignLabel::MembershipEntry => 0,
            SignLabel::RecoveryCosign => 1,
            SignLabel::BrowserGrant => 2,
            SignLabel::PushHint => 3,
            SignLabel::Seen => 4,
            SignLabel::ChannelHost => 5,
            SignLabel::ChannelClient => 6,
            SignLabel::HostRoute => 7,
            SignLabel::HostEncKey => 8,
            SignLabel::HostWorkControl => 9,
            SignLabel::Envelope => 10,
            SignLabel::Result => 11,
            SignLabel::HostRouteProxy => 12,
            SignLabel::VerifierReport => 13,
            SignLabel::SignerReport => 14,
        }
    }

    #[test]
    fn every_label_is_listed() {
        for (i, label) in LABELS.iter().enumerate() {
            assert_eq!(listed(*label), i, "{label:?}");
        }
    }

    #[test]
    fn a_fields_input_is_enc_with_the_label_first() {
        let input = SigningInput::fields(SignLabel::HostEncKey, &[b"a", b"", b"bc"]);
        assert_eq!(input.label(), SignLabel::HostEncKey);
        assert_eq!(
            crate::encoding::dec(input.as_bytes()).unwrap(),
            [&b"atem-host-enc-key-v1"[..], b"a", b"", b"bc"]
        );
        assert_eq!(
            SigningInput::new(SignLabel::Seen, b"{}"),
            SigningInput::fields(SignLabel::Seen, &[b"{}"])
        );
        // Not a body's label.
        assert_eq!(SignLabel::of_body_type("atem-host-enc-key"), None);
    }

    #[test]
    fn the_mailbox_objects_have_their_own_labels() {
        assert_eq!(
            SignLabel::of_body_type("atem-envelope"),
            Some(SignLabel::Envelope)
        );
        assert_eq!(
            SignLabel::of_body_type("atem-result"),
            Some(SignLabel::Result)
        );
        assert_eq!(SignLabel::Envelope.as_str(), "atem-envelope-v1");
        assert_eq!(SignLabel::Result.as_str(), "atem-result-v1");
        assert_eq!(ENVELOPE_SEAL, "atem-envelope-seal-v1");
        assert_eq!(RESULT_SEAL, "atem-result-seal-v1");
    }

    /// A member's signed verifier report (Astation #101): its own body
    /// type and label, distinct from every route, channel, control and
    /// membership label (`every_domain_string_is_distinct`).
    #[test]
    fn the_verifier_report_has_its_own_label() {
        assert_eq!(
            SignLabel::of_body_type("atem-verifier-report"),
            Some(SignLabel::VerifierReport)
        );
        assert_eq!(
            SignLabel::VerifierReport.as_str(),
            "atem-verifier-report-v1"
        );
    }

    /// A native manager's signed report of its signing journal (Astation
    /// #114 item 4): its own body type and label, and its two set-hash
    /// domains, distinct from every other domain string
    /// (`every_domain_string_is_distinct`).
    #[test]
    fn the_signer_report_has_its_own_label() {
        assert_eq!(
            SignLabel::of_body_type("atem-signer-report"),
            Some(SignLabel::SignerReport)
        );
        assert_eq!(SignLabel::SignerReport.as_str(), "atem-signer-report-v1");
        assert_eq!(SIGNER_REPORT_RECORDS, "atem-signer-report-records-v1");
        assert_eq!(SIGNER_REPORT_DRAFTS, "atem-signer-report-drafts-v1");
    }

    #[test]
    fn every_domain_string_is_distinct() {
        let signing = LABELS.map(SignLabel::as_str);
        let others = [
            MEMBERSHIP_HASH,
            BROWSER_GRANT_HASH,
            CH1_TH2,
            CH1_TH3,
            CH1_TH4,
            CH1_FINISH_KEY,
            CH1_AP_C2H,
            CH1_AP_H2C,
            CH1_FINISH_AAD,
            CH1_RECORD_AAD,
            PUSH_SEAL,
            ENVELOPE_SEAL,
            RESULT_SEAL,
            ENC_KID,
            K_BACKUP,
            RECOVERY_KIT,
            RECOVERY_KIT_TAG,
            K_BACKUP_HASH,
            RECOVERY_SIGN,
            SAFETY_CODE,
            STATION_REPORT_ID,
            REFERENCE_MAILBOX_ID,
            SIGNER_REPORT_RECORDS,
            SIGNER_REPORT_DRAFTS,
        ];
        let mut all: Vec<&str> = signing.iter().chain(others.iter()).copied().collect();
        let n = all.len();
        all.sort_unstable();
        all.dedup();
        assert_eq!(all.len(), n);
    }
}
