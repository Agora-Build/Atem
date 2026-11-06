//! Immutable messages and per-host delivery receipts over authenticated channels.
use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use super::host_work::{
    self, ContextKind, ContextSnapshot, HostTarget, WorkState, WorkStatus, WorkTask,
};
use super::wire::{Target, is_digest, is_opaque_id, is_session_id, is_uuid_v4};
use crate::canonical::MAX_SAFE_INTEGER;

pub const FEATURE: &str = "host.messages";
pub const MAX_RECIPIENTS: usize = 32;

/// Recipients are resolved before publication; retries never expand a role again.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Recipient {
    pub recipient_id: String,
    pub host: HostTarget,
    pub destination: Destination,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Destination {
    /// Store a notice for this host without submitting agent input.
    Host,
    /// Expanded once by the receiving host and persisted before acceptance.
    /// Stage 1 uses this internally; remote admission requires host.select.
    Select { selectors: Vec<String>, budget: u32 },
    /// Store context for an approved project route without submitting input.
    Project {
        route_id: String,
        route_revision: u64,
    },
    /// Submit through the route's ordinary readiness and receipt machinery.
    Agent {
        route_id: String,
        route_revision: u64,
        target: Target,
    },
}

impl Destination {
    pub fn route(&self) -> Option<(&str, u64)> {
        match self {
            Self::Host | Self::Select { .. } => None,
            Self::Project {
                route_id,
                route_revision,
            }
            | Self::Agent {
                route_id,
                route_revision,
                ..
            } => Some((route_id, *route_revision)),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageKind {
    #[default]
    Request,
    Status,
    Result,
}

impl MessageKind {
    fn is_request(&self) -> bool {
        *self == Self::Request
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplyTo {
    pub message_id: String,
    pub task_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Message {
    pub message_id: String,
    pub workflow_id: String,
    /// Must equal the channel's current authenticated principal. Forwarders
    /// cannot assert an original sender using this field.
    pub sender: String,
    #[serde(default, skip_serializing_if = "MessageKind::is_request")]
    pub kind: MessageKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reply_to: Option<ReplyTo>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from_session: Option<String>,
    pub created_at: u64,
    pub expires_at: u64,
    pub recipients: Vec<Recipient>,
    pub text: String,
    pub context: Vec<ContextSnapshot>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mark: Option<super::mark::MarkTask>,
}

impl Message {
    pub fn valid(&self) -> bool {
        let sender_ok = ["member:", "service:"]
            .iter()
            .any(|prefix| self.sender.strip_prefix(prefix).is_some_and(is_opaque_id));
        sender_ok && self.valid_body(false)
    }

    /// Only the runtime's internal attachment may accept this sender.
    pub fn valid_local(&self) -> bool {
        self.sender == "local"
            && self.from_session.as_deref().is_some_and(is_session_id)
            && self.valid_body(true)
    }

    fn valid_body(&self, local: bool) -> bool {
        let mut ids = BTreeSet::new();
        let mut destinations = BTreeSet::new();
        let budget: u32 = self
            .recipients
            .iter()
            .map(|r| match r.destination {
                Destination::Select { budget, .. } => budget,
                _ => 1,
            })
            .try_fold(0u32, u32::checked_add)
            .unwrap_or(u32::MAX);
        is_uuid_v4(&self.message_id)
            && is_uuid_v4(&self.workflow_id)
            && budget <= super::select::MAX_AGENTS
            && self.from_session.as_deref().is_none_or(is_session_id)
            && self.reply_to.as_ref().is_none_or(|r| {
                is_uuid_v4(&r.message_id)
                    && (is_uuid_v4(&r.task_id) || local && super::wire::is_uuid_v5(&r.task_id))
            })
            && (self.kind == MessageKind::Request || self.reply_to.is_some())
            && self.created_at <= MAX_SAFE_INTEGER
            && self.expires_at <= MAX_SAFE_INTEGER
            && self.expires_at > self.created_at
            && self.expires_at - self.created_at <= host_work::MAX_LIFETIME_MS
            && (1..=MAX_RECIPIENTS).contains(&self.recipients.len())
            && self.text.len() <= 16 * 1024
            && !self
                .text
                .chars()
                .any(|c| c.is_control() && c != '\n' && c != '\t')
            && (!self.text.trim().is_empty() || !self.context.is_empty() || self.mark.is_some())
            && self.mark.as_ref().is_none_or(|m| {
                m.valid()
                    && self
                        .recipients
                        .iter()
                        .all(|r| matches!(r.destination, Destination::Agent { .. }))
            })
            && self.context.len() <= 8
            && self.context.iter().all(ContextSnapshot::valid)
            && serde_json::to_vec(self).is_ok_and(|b| b.len() <= 240 * 1024)
            && self.recipients.iter().all(|r| {
                is_uuid_v4(&r.recipient_id)
                    && ids.insert(&r.recipient_id)
                    && r.host.valid()
                    && r.host.account_id == self.recipients[0].host.account_id
                    && destinations.insert(match &r.destination {
                        Destination::Agent { target, .. } => {
                            serde_json::to_string(&("agent", target)).unwrap()
                        }
                        _ => serde_json::to_string(&(&r.host, &r.destination)).unwrap(),
                    })
                    && r.destination.route().is_none_or(|(id, revision)| {
                        is_opaque_id(id) && revision > 0 && revision <= MAX_SAFE_INTEGER
                    })
                    && match &r.destination {
                        Destination::Select { selectors, budget } => {
                            super::select::valid_selectors(selectors, *budget)
                        }
                        Destination::Agent { target, .. } => {
                            r.host.contains(target)
                                && self.task(r).is_some_and(|t| t.valid(&r.host))
                        }
                        _ => true,
                    }
            })
    }

    /// A fingerprint covers sender, every resolved recipient and exact content.
    pub fn digest(&self) -> String {
        crate::canonical::payload_digest(&serde_json::to_value(self).expect("serializable message"))
            .expect("validated message in the canonical domain")
    }

    /// One independent idempotent publication per destination host. Callers
    /// retain this immutable message until every host has durably accepted it.
    pub fn publications(&self) -> Result<Vec<host_work::Request>, &'static str> {
        if !self.valid() {
            return Err("invalid_request");
        }
        let mut seen = BTreeSet::new();
        Ok(self
            .recipients
            .iter()
            .filter_map(|r| {
                let key = serde_json::to_string(&r.host).unwrap();
                seen.insert(key).then(|| host_work::Request::Publish {
                    v: 1,
                    id: super::new_id(),
                    host: r.host.clone(),
                    message: self.clone(),
                })
            })
            .collect())
    }

    pub fn task(&self, r: &Recipient) -> Option<WorkTask> {
        let Destination::Agent { target, .. } = &r.destination else {
            return None;
        };
        Some(WorkTask {
            task_id: r.recipient_id.clone(),
            workflow_id: self.workflow_id.clone(),
            target: target.clone(),
            expires_at: self.expires_at,
            prompt: format!(
                "[Message {} from {}]\n{}",
                self.message_id,
                self.sender,
                self.mark.as_ref().map_or_else(
                    || self.text.clone(),
                    |m| format!("{}\n{}", self.text, m.render())
                )
            ),
            context: self.context.clone(),
            attachments: self
                .mark
                .as_ref()
                .map(|m| vec![m.screenshot.clone()])
                .unwrap_or_default(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum Delivery {
    /// Durable inbox acceptance; does not mean read or task completion.
    Stored,
    /// No input was queued for this recipient.
    Refused { code: String },
    /// Progress is the ordinary task receipt, independently per recipient.
    Work { work: WorkProgress },
}

/// Aggregate receipts carry immutable references, not a copy of each result.
/// The full snapshot remains available through the original task query.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextReference {
    pub kind: ContextKind,
    pub id: String,
    pub version: u64,
    pub digest: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkProgress {
    pub task_id: String,
    pub receipt_id: String,
    pub state: WorkState,
    pub detail: String,
    pub result: Option<ContextReference>,
}

impl From<&WorkStatus> for WorkProgress {
    fn from(work: &WorkStatus) -> Self {
        Self {
            task_id: work.task_id.clone(),
            receipt_id: work.receipt_id.clone(),
            state: work.state,
            detail: work.detail.clone(),
            result: work.result.as_ref().map(|r| ContextReference {
                kind: r.kind,
                id: r.id.clone(),
                version: r.version,
                digest: r.digest.clone(),
            }),
        }
    }
}

impl WorkProgress {
    fn valid(&self) -> bool {
        is_uuid_v4(&self.task_id)
            && is_uuid_v4(&self.receipt_id)
            && self.detail.len() <= 1024
            && self.result.as_ref().is_none_or(|r| {
                is_opaque_id(&r.id)
                    && r.version > 0
                    && r.version <= MAX_SAFE_INTEGER
                    && is_digest(&r.digest)
            })
            && (self.state == WorkState::Completed) == self.result.is_some()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecipientReceipt {
    pub recipient_id: String,
    pub delivery: Delivery,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MessageReceipt {
    pub message_id: String,
    pub digest: String,
    pub sender: String,
    pub recipients: Vec<RecipientReceipt>,
}

impl MessageReceipt {
    pub fn valid(&self) -> bool {
        let mut ids = BTreeSet::new();
        is_uuid_v4(&self.message_id)
            && is_digest(&self.digest)
            && ["member:", "service:"]
                .iter()
                .any(|p| self.sender.strip_prefix(p).is_some_and(is_opaque_id))
            && self.recipients.len() <= MAX_RECIPIENTS
            && !self.recipients.is_empty()
            && self.recipients.iter().all(|r| {
                is_uuid_v4(&r.recipient_id)
                    && ids.insert(&r.recipient_id)
                    && match &r.delivery {
                        Delivery::Stored => true,
                        Delivery::Refused { code } => {
                            matches!(code.as_str(), "forbidden" | "stale_target")
                        }
                        Delivery::Work { work } => work.task_id == r.recipient_id && work.valid(),
                    }
            })
    }

    pub fn answers(&self, message: &Message, host: &HostTarget) -> bool {
        self.valid()
            && self.message_id == message.message_id
            && self.sender == message.sender
            && self.digest == message.digest()
            && self
                .recipients
                .iter()
                .map(|r| &r.recipient_id)
                .collect::<Vec<_>>()
                == message
                    .recipients
                    .iter()
                    .filter(|r| &r.host == host)
                    .map(|r| &r.recipient_id)
                    .collect::<Vec<_>>()
    }
}

#[cfg(test)]
mod tests {
    use super::super::{host_work::Request, new_id};
    use super::*;

    fn message() -> Message {
        Message {
            message_id: new_id(),
            workflow_id: new_id(),
            sender: "member:phone".into(),
            kind: MessageKind::Request,
            reply_to: None,
            from_session: None,
            mark: None,
            created_at: 1_000,
            expires_at: 60_000,
            text: "Ready to work".into(),
            context: vec![],
            recipients: vec![Recipient {
                recipient_id: new_id(),
                host: HostTarget {
                    account_id: "account".into(),
                    atem_device_id: "backend".into(),
                    host_trust_gen: 1,
                },
                destination: Destination::Host,
            }],
        }
    }

    #[test]
    fn deterministic_local_reply_ids_never_widen_remote_admission() {
        let mut m = message();
        m.sender = "local".into();
        m.from_session = Some("ses-aaaaaaaaaaaa".into());
        m.kind = MessageKind::Result;
        m.reply_to = Some(ReplyTo {
            message_id: new_id(),
            task_id: "18f208d8-a1d7-5fba-8a53-7fb8f9bc5dc4".into(),
        });
        assert!(m.valid_local());
        assert!(!m.valid());
        m.sender = "service:sender".into();
        assert!(!m.valid());
        let snapshot = ContextSnapshot {
            kind: ContextKind::Result,
            id: "result:local".into(),
            version: 1,
            digest: host_work::digest(b"done"),
            text: "done".into(),
        };
        assert!(snapshot.valid_local());
        assert!(!snapshot.valid());
    }

    #[test]
    fn select_budgets_total_at_most_32() {
        let mut m = message();
        m.recipients[0].destination = Destination::Select {
            selectors: vec!["tag:a".into()],
            budget: 20,
        };
        let mut other = m.recipients[0].clone();
        other.recipient_id = new_id();
        other.host.atem_device_id = "other".into();
        other.destination = Destination::Select {
            selectors: vec!["tag:b".into()],
            budget: 13,
        };
        m.recipients.push(other);
        assert!(!m.valid());
        if let Destination::Select { budget, .. } = &mut m.recipients[1].destination {
            *budget = 12;
        }
        assert!(m.valid());
        for (selectors, budget) in [
            (vec![], 1),
            (vec!["tag:".into()], 1),
            (vec!["tag:a".into(); 17], 1),
            (vec!["tag:a".into()], 0),
        ] {
            m.recipients[0].destination = Destination::Select { selectors, budget };
            assert!(!m.valid());
        }
    }

    #[test]
    fn a_local_envelope_is_valid_only_through_valid_local() {
        let mut m = message();
        assert!(!m.valid_local());
        m.sender = "local".into();
        assert!(!m.valid_local());
        m.from_session = Some("ses-abcdefghijkl".into());
        assert!(m.valid_local());
        assert!(!m.valid());
        assert!(m.publications().is_err());
        m.sender = "member:phone".into();
        assert!(!m.valid_local());
    }

    #[test]
    fn serde_round_trip_keeps_new_fields_optional() {
        let m = message();
        let old = serde_json::to_value(&m).unwrap();
        assert!(old.get("kind").is_none());
        assert!(old.get("reply_to").is_none());
        assert!(old.get("from_session").is_none());
        let mut decoded: Message = serde_json::from_value(old.clone()).unwrap();
        assert!(decoded.kind == MessageKind::Request);
        assert_eq!(serde_json::to_value(&decoded).unwrap(), old);
        decoded.kind = MessageKind::Result;
        assert!(!decoded.valid());
        decoded.reply_to = Some(ReplyTo {
            message_id: new_id(),
            task_id: new_id(),
        });
        assert!(decoded.valid());
        assert_eq!(
            serde_json::from_value::<Message>(serde_json::to_value(&decoded).unwrap()).unwrap(),
            decoded
        );
    }

    #[test]
    fn inline_only_and_context_only_messages_use_the_same_model() {
        let mut m = message();
        assert!(m.valid());
        m.text.clear();
        assert!(!m.valid());
        m.context.push(ContextSnapshot {
            kind: host_work::ContextKind::Vault,
            id: "contract".into(),
            version: 3,
            text: "Exact version three".into(),
            digest: host_work::digest(b"Exact version three"),
        });
        assert!(m.valid());
        m.context[0].text = "Latest version four".into();
        assert!(!m.valid());
    }

    #[test]
    fn fanout_freezes_all_recipients_and_correlates_each_hosts_receipt() {
        let mut m = message();
        let mut second = m.recipients[0].clone();
        second.host.atem_device_id = "mobile".into();
        second.recipient_id = new_id();
        m.recipients.push(second);
        let requests = m.publications().unwrap();
        assert_eq!(requests.len(), 2);
        for req in &requests {
            assert_eq!(
                Request::decode(req.to_json().to_string().as_bytes()).unwrap(),
                *req
            );
            let receipt = MessageReceipt {
                message_id: m.message_id.clone(),
                digest: m.digest(),
                sender: m.sender.clone(),
                recipients: m
                    .recipients
                    .iter()
                    .filter(|r| &r.host == req.host())
                    .map(|r| RecipientReceipt {
                        recipient_id: r.recipient_id.clone(),
                        delivery: Delivery::Stored,
                    })
                    .collect(),
            };
            assert!(receipt.answers(&m, req.host()));
            let mut changed = m.clone();
            changed.text.push('!');
            assert!(!receipt.answers(&changed, req.host()));
            assert!(
                !receipt.answers(
                    &m,
                    requests
                        .iter()
                        .find(|r| r.host() != req.host())
                        .unwrap()
                        .host()
                )
            );
        }
        m.recipients.swap(0, 1);
        assert_ne!(
            m.digest(),
            match &requests[0] {
                Request::Publish { message, .. } => message.digest(),
                _ => unreachable!(),
            }
        );
    }

    #[test]
    fn fanout_rejects_duplicate_identities_destinations_and_accounts() {
        let m = message();
        let mut bad = m.clone();
        bad.recipients.push(m.recipients[0].clone());
        assert!(!bad.valid());
        bad.recipients[1].recipient_id = new_id();
        assert!(!bad.valid());
        bad.recipients[1].host.account_id = "another-account".into();
        assert!(!bad.valid());
        let mut bad = m;
        bad.text.push('\u{1b}');
        assert!(!bad.valid());
    }

    #[test]
    fn agent_messages_allow_inline_text_and_bind_the_process_generation() {
        let mut m = message();
        let host = m.recipients[0].host.clone();
        m.recipients[0].destination = Destination::Agent {
            route_id: "backend".into(),
            route_revision: 1,
            target: Target {
                account_id: host.account_id.clone(),
                atem_device_id: host.atem_device_id.clone(),
                host_trust_gen: 1,
                session_id: "ses-abcdefghijkl".into(),
                process_gen: new_id(),
            },
        };
        assert!(m.valid());
        let task = m.task(&m.recipients[0]).unwrap();
        assert!(task.valid(&host));
        assert!(task.render_prompt().contains("from member:phone"));
        let mut alias = m.recipients[0].clone();
        alias.recipient_id = new_id();
        if let Destination::Agent { route_id, .. } = &mut alias.destination {
            *route_id = "alias".into();
        }
        let mut duplicate = m.clone();
        duplicate.recipients.push(alias);
        assert!(!duplicate.valid());
        if let Destination::Agent { target, .. } = &mut m.recipients[0].destination {
            target.host_trust_gen = 2;
        }
        assert!(!m.valid());
    }

    #[test]
    fn mark_tasks_use_the_same_agent_message_and_preserve_the_screenshot_identity() {
        let mut m = message();
        let host = m.recipients[0].host.clone();
        m.recipients[0].destination = Destination::Agent {
            route_id: "backend".into(),
            route_revision: 1,
            target: super::super::wire::Target {
                account_id: host.account_id.clone(),
                atem_device_id: host.atem_device_id.clone(),
                host_trust_gen: host.host_trust_gen,
                session_id: "ses-abcdefghijkl".into(),
                process_gen: new_id(),
            },
        };
        m.text.clear();
        m.mark = Some(super::super::mark::MarkTask {
            mark_id: "mark_123".into(),
            url: "http://localhost:3000".into(),
            title: "Page".into(),
            screenshot: super::super::attachments::Attachment {
                attachment_id: new_id(),
                digest: host_work::digest(b"png"),
                size: 68,
                media_type: "image/png".into(),
            },
            annotations: vec![super::super::mark::Annotation {
                tool: "arrow".into(),
                text: "Make this red".into(),
                x: 20,
                y: 40,
            }],
        });
        assert!(m.valid());
        let task = m.task(&m.recipients[0]).unwrap();
        assert!(task.prompt.contains("Make this red"));
        assert_eq!(
            task.attachments,
            vec![m.mark.as_ref().unwrap().screenshot.clone()]
        );
        let request = m.publications().unwrap().remove(0);
        assert_eq!(
            Request::decode(request.to_json().to_string().as_bytes()).unwrap(),
            request
        );
        let mut bad = m.clone();
        bad.recipients[0].destination = Destination::Host;
        assert!(!bad.valid());
        let mut bad = m.clone();
        bad.mark.as_mut().unwrap().screenshot.attachment_id = "../../local.png".into();
        assert!(!bad.valid());
        let mut bad = m;
        bad.mark.as_mut().unwrap().annotations[0]
            .text
            .push('\u{1b}');
        assert!(!bad.valid());
    }

    #[test]
    fn decode_rejects_unknown_or_duplicate_fields_before_delivery() {
        let request = message().publications().unwrap().remove(0);
        let mut wire = request.to_json();
        wire["data"]["message"]["forwarded_sender"] = serde_json::json!("member:other");
        assert!(Request::decode(wire.to_string().as_bytes()).is_err());
        let wire = request.to_json().to_string().replacen(
            "\"message_id\":",
            "\"message_id\":\"forged\",\"message_id\":",
            1,
        );
        assert!(Request::decode(wire.as_bytes()).is_err());
    }

    #[test]
    fn aggregate_receipts_use_small_exact_result_references() {
        let text = "x".repeat(host_work::MAX_CONTEXT_BYTES);
        let status = WorkStatus {
            task_id: new_id(),
            receipt_id: new_id(),
            state: WorkState::Completed,
            detail: "explicit result".into(),
            result: Some(ContextSnapshot {
                kind: ContextKind::Memory,
                id: "fact".into(),
                version: 7,
                digest: host_work::digest(text.as_bytes()),
                text,
            }),
        };
        let progress = WorkProgress::from(&status);
        assert!(progress.valid());
        assert_eq!(
            progress.result.as_ref().unwrap().digest,
            status.result.as_ref().unwrap().digest
        );
        let receipt = MessageReceipt {
            message_id: new_id(),
            sender: "member:phone".into(),
            digest: host_work::digest(b"message"),
            recipients: (0..MAX_RECIPIENTS)
                .map(|_| {
                    let mut work = progress.clone();
                    work.task_id = new_id();
                    RecipientReceipt {
                        recipient_id: work.task_id.clone(),
                        delivery: Delivery::Work { work },
                    }
                })
                .collect(),
        };
        assert!(receipt.valid());
        assert!(serde_json::to_vec(&receipt).unwrap().len() < 32 * 1024);
    }
}
