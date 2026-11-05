//! Opt-in host launch and directed work inside an admitted atem-ch1 channel.
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::wire::{Target, is_digest, is_opaque_id, is_session_id, is_uuid_v4, is_uuid_v5};
use crate::canonical::MAX_SAFE_INTEGER;

pub const LAUNCH_FEATURE: &str = "host.launch";
pub const WORK_FEATURE: &str = "host.work";
/// `reply_query`: the reply the agent working on a task submitted.
pub const REPLY_FEATURE: &str = "host.reply";
pub const MAX_LIFETIME_MS: u64 = 24 * 60 * 60 * 1000;
pub const MAX_CONTEXT_BYTES: usize = 128 * 1024;
pub const MAX_REQUEST_BYTES: usize = 256 * 1024;
/// The longest reply text an agent can submit.
pub const MAX_REPLY_TEXT_BYTES: usize = 16 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostTarget {
    pub account_id: String,
    pub atem_device_id: String,
    pub host_trust_gen: u64,
}

impl HostTarget {
    pub fn valid(&self) -> bool {
        is_opaque_id(&self.account_id)
            && is_opaque_id(&self.atem_device_id)
            && self.host_trust_gen <= MAX_SAFE_INTEGER
    }

    pub fn contains(&self, target: &Target) -> bool {
        self.account_id == target.account_id
            && self.atem_device_id == target.atem_device_id
            && self.host_trust_gen == target.host_trust_gen
    }
}

/// A committed context version, resolved by the authorized publisher. The
/// receiver checks its content digest; the publisher vouches for publication.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextSnapshot {
    pub kind: ContextKind,
    pub id: String,
    pub version: u64,
    pub digest: String,
    pub text: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContextKind {
    Memory,
    Vault,
    /// A locally stored explicit reply. Never admitted as remote context.
    Result,
}

pub fn digest(bytes: &[u8]) -> String {
    crate::encoding::hex(&Sha256::digest(bytes))
}

impl ContextSnapshot {
    pub fn valid(&self) -> bool {
        self.kind != ContextKind::Result && self.valid_local()
    }

    pub fn valid_local(&self) -> bool {
        is_opaque_id(&self.id)
            && self.version > 0
            && self.version <= MAX_SAFE_INTEGER
            && is_digest(&self.digest)
            && self.digest == digest(self.text.as_bytes())
            && self.text.len() <= MAX_CONTEXT_BYTES
            && !self.text.contains('\0')
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkTask {
    pub task_id: String,
    pub workflow_id: String,
    pub target: Target,
    pub expires_at: u64,
    pub prompt: String,
    pub context: Vec<ContextSnapshot>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attachments: Vec<super::attachments::Attachment>,
}

impl WorkTask {
    pub fn valid(&self, host: &HostTarget) -> bool {
        self.valid_for(host, false)
    }

    /// A task of the runtime's own `local` sender: its ids may be the
    /// deterministic UUIDv5 of a selector's fixed resolution. Every bound
    /// (prompt and context size, characters, snapshots) is the remote one.
    pub fn valid_local(&self, host: &HostTarget) -> bool {
        self.valid_for(host, true)
    }

    fn valid_for(&self, host: &HostTarget, local: bool) -> bool {
        (is_uuid_v4(&self.task_id) || local && is_uuid_v5(&self.task_id))
            && is_uuid_v4(&self.workflow_id)
            && host.contains(&self.target)
            && is_session_id(&self.target.session_id)
            && is_uuid_v4(&self.target.process_gen)
            && self.expires_at <= MAX_SAFE_INTEGER
            && !self.prompt.trim().is_empty()
            && self.prompt.len() <= 17 * 1024
            && !self.prompt.contains('\0')
            && !self
                .render_prompt()
                .chars()
                .any(|c| c.is_control() && c != '\n' && c != '\t')
            && self.context.len() <= 8
            && self.context.iter().all(|c| {
                if local {
                    c.valid_local()
                } else {
                    c.valid()
                }
            })
            && self.attachments.len() <= 4
            && self.attachments.iter().all(super::attachments::Attachment::valid)
            && self.attachments.iter().map(|a| &a.attachment_id).collect::<std::collections::BTreeSet<_>>().len() == self.attachments.len()
            // Reserve space for receiver-generated paths appended at dispatch.
            && (self.attachments.is_empty() || self.render_prompt().len() <= super::wire::MAX_PROMPT_BYTES - 4096)
            && self.render_prompt().len() <= super::wire::MAX_PROMPT_BYTES
    }

    pub fn render_prompt(&self) -> String {
        let mut prompt = format!(
            "[Atem task {} / workflow {}]\n{}",
            self.task_id, self.workflow_id, self.prompt
        );
        for item in &self.context {
            prompt.push_str(&format!(
                "\n\n[Context {:?}:{} version {} sha256 {}]\n{}",
                item.kind, item.id, item.version, item.digest, item.text
            ));
        }
        prompt
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", deny_unknown_fields)]
pub enum Request {
    #[serde(rename = "attachment_put")]
    AttachmentPut {
        v: u8,
        id: String,
        host: HostTarget,
        attachment: super::attachments::Attachment,
        offset: u64,
        data: String,
    },
    #[serde(rename = "host_profiles")]
    Profiles { v: u8, id: String, host: HostTarget },
    #[serde(rename = "host_launch")]
    Launch {
        v: u8,
        id: String,
        host: HostTarget,
        request_id: String,
        profile_id: String,
        profile_revision: u64,
        expires_at: u64,
    },
    #[serde(rename = "host_launch_query")]
    LaunchQuery {
        v: u8,
        id: String,
        host: HostTarget,
        request_id: String,
    },
    #[serde(rename = "work_enqueue")]
    Enqueue {
        v: u8,
        id: String,
        host: HostTarget,
        route_id: String,
        route_revision: u64,
        task: WorkTask,
    },
    #[serde(rename = "work_query")]
    WorkQuery {
        v: u8,
        id: String,
        host: HostTarget,
        task_id: String,
    },
    #[serde(rename = "reply_query")]
    ReplyQuery {
        v: u8,
        id: String,
        host: HostTarget,
        task_id: String,
    },
    #[serde(rename = "work_cancel")]
    Cancel {
        v: u8,
        id: String,
        host: HostTarget,
        task_id: String,
    },
    #[serde(rename = "work_complete")]
    Complete {
        v: u8,
        id: String,
        host: HostTarget,
        task_id: String,
        result: ContextSnapshot,
    },
    #[serde(rename = "message_publish")]
    Publish {
        v: u8,
        id: String,
        host: HostTarget,
        message: super::messages::Message,
    },
    #[serde(rename = "message_query")]
    MessageQuery {
        v: u8,
        id: String,
        host: HostTarget,
        message_id: String,
    },
}

impl Request {
    pub fn decode(bytes: &[u8]) -> Result<Self, &'static str> {
        let value = crate::canonical::StrictValue::parse(bytes, MAX_REQUEST_BYTES)
            .map_err(|_| "invalid_request")?;
        let root = value.value();
        if root["type"] != "session" || root.as_object().is_none_or(|o| o.len() != 2) {
            return Err("invalid_request");
        }
        Self::from_data(&root["data"])
    }
    pub fn id(&self) -> &str {
        match self {
            Self::Profiles { id, .. }
            | Self::AttachmentPut { id, .. }
            | Self::Launch { id, .. }
            | Self::LaunchQuery { id, .. }
            | Self::Enqueue { id, .. }
            | Self::WorkQuery { id, .. }
            | Self::ReplyQuery { id, .. }
            | Self::Cancel { id, .. }
            | Self::Complete { id, .. }
            | Self::Publish { id, .. }
            | Self::MessageQuery { id, .. } => id,
        }
    }

    pub fn host(&self) -> &HostTarget {
        match self {
            Self::Profiles { host, .. }
            | Self::AttachmentPut { host, .. }
            | Self::Launch { host, .. }
            | Self::LaunchQuery { host, .. }
            | Self::Enqueue { host, .. }
            | Self::WorkQuery { host, .. }
            | Self::ReplyQuery { host, .. }
            | Self::Cancel { host, .. }
            | Self::Complete { host, .. }
            | Self::Publish { host, .. }
            | Self::MessageQuery { host, .. } => host,
        }
    }

    pub fn is_launch(&self) -> bool {
        matches!(
            self,
            Self::Profiles { .. } | Self::Launch { .. } | Self::LaunchQuery { .. }
        )
    }

    pub fn feature(&self) -> &'static str {
        if matches!(self, Self::AttachmentPut { .. }) {
            super::attachments::FEATURE
        } else if self.is_launch() {
            LAUNCH_FEATURE
        } else if matches!(self, Self::Publish { .. } | Self::MessageQuery { .. }) {
            super::messages::FEATURE
        } else if matches!(self, Self::ReplyQuery { .. }) {
            REPLY_FEATURE
        } else {
            WORK_FEATURE
        }
    }

    pub fn from_data(value: &Value) -> Result<Self, &'static str> {
        if value.get("v").and_then(Value::as_u64) != Some(1)
            || serde_json::to_vec(value).map_or(true, |b| b.len() > MAX_REQUEST_BYTES)
        {
            return Err("invalid_request");
        }
        let request: Self = serde_json::from_value(value.clone()).map_err(|_| "invalid_request")?;
        if serde_json::to_value(&request).map_err(|_| "invalid_request")? != *value {
            return Err("invalid_request");
        }
        let valid = request.host().valid()
            && is_uuid_v4(request.id())
            && match &request {
                Self::AttachmentPut {
                    attachment,
                    offset,
                    data,
                    ..
                } => {
                    use base64::Engine;
                    attachment.valid()
                        && *offset < attachment.size
                        && data.len() <= super::attachments::CHUNK_BYTES.div_ceil(3) * 4
                        && base64::engine::general_purpose::STANDARD
                            .decode(data)
                            .is_ok_and(|bytes| {
                                !bytes.is_empty()
                                    && bytes.len() <= super::attachments::CHUNK_BYTES
                                    && offset
                                        .checked_add(bytes.len() as u64)
                                        .is_some_and(|end| end <= attachment.size)
                            })
                }
                Self::Launch {
                    request_id,
                    profile_id,
                    profile_revision,
                    expires_at,
                    ..
                } => {
                    is_uuid_v4(request_id)
                        && is_opaque_id(profile_id)
                        && *profile_revision > 0
                        && *profile_revision <= MAX_SAFE_INTEGER
                        && *expires_at <= MAX_SAFE_INTEGER
                }
                Self::LaunchQuery { request_id, .. } => is_uuid_v4(request_id),
                Self::Enqueue {
                    route_id,
                    route_revision,
                    task,
                    host,
                    ..
                } => {
                    is_opaque_id(route_id)
                        && *route_revision > 0
                        && *route_revision <= MAX_SAFE_INTEGER
                        && task.valid(host)
                }
                Self::WorkQuery { task_id, .. }
                | Self::ReplyQuery { task_id, .. }
                | Self::Cancel { task_id, .. } => is_uuid_v4(task_id),
                Self::Complete {
                    task_id, result, ..
                } => is_uuid_v4(task_id) && result.valid(),
                Self::Profiles { .. } => true,
                Self::Publish { host, message, .. } => {
                    message.valid() && message.recipients.iter().any(|r| &r.host == host)
                }
                Self::MessageQuery { message_id, .. } => is_uuid_v4(message_id),
            };
        if valid {
            Ok(request)
        } else {
            Err("invalid_request")
        }
    }

    pub fn to_json(&self) -> Value {
        json!({"type": "session", "data": self})
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileInfo {
    pub id: String,
    pub revision: u64,
    pub label: String,
    pub provider: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LaunchState {
    Starting,
    Started,
    Failed,
    OutcomeUnknown,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaunchStatus {
    pub request_id: String,
    pub session_id: String,
    pub process_gen: String,
    pub state: LaunchState,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkState {
    Queued,
    Blocked,
    Submitting,
    Submitted,
    AwaitingResult,
    Completed,
    Failed,
    Cancelled,
    Expired,
    OutcomeUnknown,
}

impl WorkState {
    pub fn terminal(self) -> bool {
        matches!(
            self,
            Self::Completed | Self::Failed | Self::Cancelled | Self::Expired | Self::OutcomeUnknown
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkStatus {
    pub task_id: String,
    pub receipt_id: String,
    pub state: WorkState,
    pub detail: String,
    pub result: Option<ContextSnapshot>,
}

impl WorkStatus {
    pub fn valid(&self) -> bool {
        is_uuid_v4(&self.task_id)
            && is_uuid_v4(&self.receipt_id)
            && self.detail.len() <= 1024
            && self.result.as_ref().is_none_or(ContextSnapshot::valid)
            && (self.state == WorkState::Completed) == self.result.is_some()
    }
}

/// Where a task's reply stands. `publishing`: the agent's reply is recorded
/// and its context is being published (the context is empty meanwhile);
/// `submitted`: the reply is final, context included; `refused`: the host
/// refused it, and a corrected reply replaces it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplyState {
    Publishing,
    Submitted,
    Refused,
}

impl ReplyState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Publishing => "publishing",
            Self::Submitted => "submitted",
            Self::Refused => "refused",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        Some(match text {
            "publishing" => Self::Publishing,
            "submitted" => Self::Submitted,
            "refused" => Self::Refused,
            _ => return None,
        })
    }
}

/// The one reply of a task. `result_id` never changes for the task, a
/// corrected reply included; `digest` identifies the reply's content (the
/// same for an identical retry, another for a corrected one).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResultReply {
    pub result_id: String,
    pub state: ReplyState,
    pub digest: String,
    pub text: String,
    /// The published context snapshots; empty unless `submitted`.
    pub context: Vec<ContextSnapshot>,
    /// Unix ms on the host's wall clock; exactly when `submitted`.
    pub submitted_at: Option<u64>,
}

impl ResultReply {
    pub fn valid(&self) -> bool {
        is_uuid_v5(&self.result_id)
            && is_digest(&self.digest)
            && self.text.len() <= MAX_REPLY_TEXT_BYTES
            && !self
                .text
                .chars()
                .any(|c| c.is_control() && c != '\n' && c != '\t')
            && self.context.len() <= 8
            && self.context.iter().all(ContextSnapshot::valid)
            && (self.state == ReplyState::Submitted || self.context.is_empty())
            && (self.state == ReplyState::Submitted) == self.submitted_at.is_some()
            && self.submitted_at.is_none_or(|at| at <= MAX_SAFE_INTEGER)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ResultBody {
    Attachment {
        upload: super::attachments::AttachmentStatus,
    },
    Profiles {
        profiles: Vec<ProfileInfo>,
    },
    Launch {
        launch: LaunchStatus,
    },
    Work {
        work: WorkStatus,
    },
    /// The task's reply, or none yet.
    Reply {
        reply: Option<ResultReply>,
    },
    Message {
        message: super::messages::MessageReceipt,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Response {
    pub v: u8,
    pub op: String,
    pub id: String,
    pub re: String,
    pub host: HostTarget,
    pub attachment_gen: String,
    pub channel_id: String,
    pub result: ResultBody,
}

impl Response {
    pub fn from_data(value: &Value) -> Result<Self, &'static str> {
        let r: Self =
            serde_json::from_value(value.clone()).map_err(|_| "invalid host work result")?;
        if r.v != 1
            || r.op != "host_work_result"
            || !is_uuid_v4(&r.id)
            || !is_uuid_v4(&r.re)
            || !r.host.valid()
            || !is_uuid_v4(&r.attachment_gen)
            || r.channel_id.is_empty()
        {
            return Err("invalid host work result");
        }
        let valid = match &r.result {
            ResultBody::Attachment { upload } => upload.valid(),
            ResultBody::Profiles { profiles } => {
                profiles.len() <= 64
                    && profiles.iter().all(|p| {
                        is_opaque_id(&p.id)
                            && p.revision > 0
                            && p.revision <= MAX_SAFE_INTEGER
                            && !p.label.is_empty()
                            && p.label.len() <= 128
                            && !p.label.chars().any(char::is_control)
                            && matches!(p.provider.as_str(), "claude" | "codex")
                    })
            }
            ResultBody::Launch { launch } => {
                is_uuid_v4(&launch.request_id)
                    && is_session_id(&launch.session_id)
                    && is_uuid_v4(&launch.process_gen)
            }
            ResultBody::Work { work } => work.valid(),
            ResultBody::Reply { reply } => reply.as_ref().is_none_or(ResultReply::valid),
            ResultBody::Message { message } => message.valid(),
        };
        if !valid {
            return Err("invalid host work result");
        }
        Ok(r)
    }

    pub fn answers(&self, request: &Request) -> bool {
        if self.re != request.id() || &self.host != request.host() {
            return false;
        }
        match (&self.result, request) {
            (
                ResultBody::Attachment { upload },
                Request::AttachmentPut {
                    attachment,
                    offset,
                    data,
                    ..
                },
            ) => {
                use base64::Engine;
                &upload.attachment == attachment
                    && base64::engine::general_purpose::STANDARD
                        .decode(data)
                        .is_ok_and(|b| upload.received >= offset + b.len() as u64)
            }
            (ResultBody::Message { message: receipt }, Request::Publish { message, host, .. }) => {
                receipt.answers(message, host)
            }
            (ResultBody::Message { message }, Request::MessageQuery { message_id, .. }) => {
                &message.message_id == message_id
            }
            (ResultBody::Profiles { .. }, Request::Profiles { .. }) => true,
            (
                ResultBody::Launch { launch },
                Request::Launch { request_id, .. } | Request::LaunchQuery { request_id, .. },
            ) => &launch.request_id == request_id,
            (ResultBody::Reply { .. }, Request::ReplyQuery { .. }) => true,
            (ResultBody::Work { work }, Request::Enqueue { task, .. }) => {
                work.task_id == task.task_id
            }
            (
                ResultBody::Work { work },
                Request::WorkQuery { task_id, .. } | Request::Cancel { task_id, .. },
            ) => &work.task_id == task_id,
            (
                ResultBody::Work { work },
                Request::Complete {
                    task_id, result, ..
                },
            ) => &work.task_id == task_id && work.result.as_ref() == Some(result),
            _ => false,
        }
    }
}

pub fn result(
    id: &str,
    re: &str,
    host: &HostTarget,
    attachment: &str,
    channel: &str,
    body: ResultBody,
) -> Value {
    json!({"type":"session", "data": {
        "v":1, "op":"host_work_result", "id":id, "re":re,
        "host":host, "attachment_gen":attachment, "channel_id":channel, "result":body
    }})
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_host_work_fixture_requests() {
        let fixtures: Value = serde_json::from_str(include_str!(
            "../../../../designs/protocol/fixtures/host-work/requests-v1.json"
        ))
        .unwrap();
        for case in fixtures["cases"].as_array().unwrap() {
            let raw = case
                .get("raw")
                .and_then(Value::as_str)
                .map(str::to_owned)
                .unwrap_or_else(|| case["message"].to_string());
            assert_eq!(
                Request::decode(raw.as_bytes()).is_ok(),
                case["valid"].as_bool().unwrap(),
                "{}",
                case["name"]
            );
            if let Some(expected) = case["digest"].as_str() {
                let Request::Publish { message, .. } = Request::decode(raw.as_bytes()).unwrap()
                else {
                    panic!("message digest fixture")
                };
                assert_eq!(message.digest(), expected, "{}", case["name"]);
            }
        }
    }

    #[test]
    fn result_correlation_distinguishes_task_and_message_identities() {
        let request = Request::LaunchQuery {
            v: 1,
            id: super::super::new_id(),
            host: HostTarget {
                account_id: "account".into(),
                atem_device_id: "host".into(),
                host_trust_gen: 1,
            },
            request_id: super::super::new_id(),
        };
        let Request::LaunchQuery { request_id, .. } = &request else {
            unreachable!()
        };
        let body = ResultBody::Launch {
            launch: LaunchStatus {
                request_id: request_id.clone(),
                session_id: "ses-aaaaaaaaaaaa".into(),
                process_gen: super::super::new_id(),
                state: LaunchState::Starting,
            },
        };
        let json = result(
            &super::super::new_id(),
            request.id(),
            request.host(),
            &super::super::new_id(),
            "channel",
            body,
        );
        let mut response = Response::from_data(&json["data"]).unwrap();
        assert!(response.answers(&request));
        response.re = super::super::new_id();
        assert!(!response.answers(&request));
        response.re = request.id().into();
        response.host.host_trust_gen += 1;
        assert!(!response.answers(&request));
    }

    fn reply_host() -> HostTarget {
        HostTarget {
            account_id: "account".into(),
            atem_device_id: "host".into(),
            host_trust_gen: 1,
        }
    }

    fn reply_query() -> Request {
        Request::ReplyQuery {
            v: 1,
            id: super::super::new_id(),
            host: reply_host(),
            task_id: super::super::new_id(),
        }
    }

    fn reply_answer(request: &Request, reply: Option<ResultReply>) -> Response {
        let json = result(
            &super::super::new_id(),
            request.id(),
            request.host(),
            &super::super::new_id(),
            "channel",
            ResultBody::Reply { reply },
        );
        Response::from_data(&json["data"]).unwrap()
    }

    fn submitted_reply() -> ResultReply {
        let context = ContextSnapshot {
            kind: ContextKind::Vault,
            id: "v-notes:entry".into(),
            version: 2,
            digest: digest(b"the notes"),
            text: "the notes".into(),
        };
        ResultReply {
            result_id: "6ba7b810-9dad-51d1-80b4-00c04fd430c8".into(),
            state: ReplyState::Submitted,
            digest: digest(b"reply"),
            text: "Done: /v2/orders is live".into(),
            context: vec![context],
            submitted_at: Some(1_793_620_800_000),
        }
    }

    /// `reply_query` names one task, is a `host.reply` request, and has
    /// exactly the fields of `work_query`.
    #[test]
    fn reply_query_names_one_task_under_its_own_feature() {
        let request = reply_query();
        assert_eq!(request.feature(), REPLY_FEATURE);
        assert_eq!(REPLY_FEATURE, "host.reply");
        assert!(!request.is_launch());
        let data = request.to_json()["data"].clone();
        assert_eq!(data["op"], "reply_query");
        assert_eq!(Request::from_data(&data), Ok(request.clone()));
        assert_eq!(
            Request::decode(request.to_json().to_string().as_bytes()),
            Ok(request)
        );
        for (field, value) in [
            ("task_id", json!("6ba7b810-9dad-51d1-80b4-00c04fd430c8")),
            ("task_id", json!("not a uuid")),
            ("extra", json!(1)),
            ("result_id", json!("6ba7b810-9dad-51d1-80b4-00c04fd430c8")),
        ] {
            let mut bad = data.clone();
            bad[field] = value;
            assert!(Request::from_data(&bad).is_err(), "{bad}");
        }
        let mut missing = data;
        missing.as_object_mut().unwrap().remove("task_id");
        assert!(Request::from_data(&missing).is_err());
    }

    #[test]
    fn a_reply_result_round_trips_in_every_state_and_answers_only_its_query() {
        let request = reply_query();
        let none = reply_answer(&request, None);
        assert!(none.answers(&request));
        assert_eq!(
            serde_json::to_value(&none.result).unwrap(),
            json!({"kind":"reply","reply":null})
        );
        let mut reply = submitted_reply();
        let submitted = reply_answer(&request, Some(reply.clone()));
        assert!(submitted.answers(&request));
        let wire = serde_json::to_value(&submitted.result).unwrap();
        assert_eq!(wire["kind"], "reply");
        assert_eq!(wire["reply"]["state"], "submitted");
        assert_eq!(wire["reply"]["submitted_at"], 1_793_620_800_000u64);
        assert_eq!(wire["reply"]["context"][0]["kind"], "vault");
        assert_eq!(
            serde_json::from_value::<ResultBody>(wire).unwrap(),
            submitted.result
        );
        // Not yet submitted: no time and no context.
        for state in [ReplyState::Publishing, ReplyState::Refused] {
            reply.state = state;
            reply.submitted_at = None;
            reply.context = vec![];
            assert!(reply_answer(&request, Some(reply.clone())).answers(&request));
        }
        // Only a reply query is answered by a reply, and only its own.
        assert!(!submitted.answers(&Request::WorkQuery {
            v: 1,
            id: request.id().into(),
            host: reply_host(),
            task_id: super::super::new_id(),
        }));
        let other = reply_query();
        assert!(!submitted.answers(&other));
    }

    #[test]
    fn a_reply_result_that_breaks_a_bound_is_not_a_result() {
        let request = reply_query();
        let build = |edit: &dyn Fn(&mut ResultReply)| {
            let mut reply = submitted_reply();
            edit(&mut reply);
            let json = result(
                &super::super::new_id(),
                request.id(),
                request.host(),
                &super::super::new_id(),
                "channel",
                ResultBody::Reply { reply: Some(reply) },
            );
            Response::from_data(&json["data"])
        };
        assert!(build(&|_| {}).is_ok());
        let cases: [(&str, &dyn Fn(&mut ResultReply)); 10] = [
            ("result id is not a UUID", &|r| r.result_id = "x".into()),
            ("result id is a v4", &|r| {
                r.result_id = super::super::new_id()
            }),
            ("digest", &|r| r.digest = "abc".into()),
            ("text too long", &|r| {
                r.text = "x".repeat(MAX_REPLY_TEXT_BYTES + 1)
            }),
            ("control character", &|r| r.text = "bell \u{7}".into()),
            ("NUL", &|r| r.text = "a\0b".into()),
            ("nine context snapshots", &|r| {
                r.context = vec![r.context[0].clone(); 9]
            }),
            ("a result snapshot is never remote context", &|r| {
                r.context[0].kind = ContextKind::Result
            }),
            ("submitted without a time", &|r| r.submitted_at = None),
            ("a time on a reply that is not submitted", &|r| {
                r.state = ReplyState::Publishing;
                r.context = vec![];
            }),
        ];
        for (name, edit) in cases {
            assert!(build(edit).is_err(), "{name}");
        }
        // Context only comes with a submitted reply.
        assert!(
            build(&|r| {
                r.state = ReplyState::Refused;
                r.submitted_at = None;
            })
            .is_err()
        );
        // The longest text the host accepts, and tabs and newlines.
        assert!(build(&|r| r.text = "a\tb\nc".repeat(2_000)).is_ok());
        assert!(build(&|r| r.text = "x".repeat(MAX_REPLY_TEXT_BYTES)).is_ok());
    }

    #[test]
    fn launch_is_strict_and_never_accepts_remote_commands_or_environment() {
        let request = Request::Launch {
            v: 1,
            id: super::super::new_id(),
            host: HostTarget {
                account_id: "account".into(),
                atem_device_id: "host".into(),
                host_trust_gen: 1,
            },
            request_id: super::super::new_id(),
            profile_id: "backend".into(),
            profile_revision: 1,
            expires_at: 100,
        };
        let mut data = request.to_json()["data"].clone();
        assert_eq!(Request::from_data(&data), Ok(request));
        data["env"] = json!({"API_KEY":"secret"});
        assert!(Request::from_data(&data).is_err());
        data.as_object_mut().unwrap().remove("env");
        data["command"] = json!("sh -c evil");
        assert!(Request::from_data(&data).is_err());
    }

    #[test]
    fn context_versions_are_immutable_and_content_is_digest_bound() {
        let mut snapshot = ContextSnapshot {
            kind: ContextKind::Vault,
            id: "v-contract".into(),
            version: 1,
            text: "API contract".into(),
            digest: digest(b"API contract"),
        };
        assert!(snapshot.valid());
        snapshot.text.push('!');
        assert!(!snapshot.valid());
        snapshot.digest = digest(snapshot.text.as_bytes());
        snapshot.version = 0;
        assert!(!snapshot.valid());
    }

    /// The runtime's own `local` sender makes deterministic UUIDv5 task ids;
    /// every other rule is the remote one.
    #[test]
    fn a_local_task_may_carry_a_derived_id_but_obeys_every_other_bound() {
        let host = HostTarget {
            account_id: "account".into(),
            atem_device_id: "host".into(),
            host_trust_gen: 1,
        };
        let task = |prompt: &str| WorkTask {
            task_id: "6ba7b810-9dad-51d1-80b4-00c04fd430c8".into(),
            workflow_id: super::super::new_id(),
            target: Target {
                account_id: "account".into(),
                atem_device_id: "host".into(),
                host_trust_gen: 1,
                session_id: "ses-aaaaaaaaaaaa".into(),
                process_gen: super::super::new_id(),
            },
            expires_at: 1,
            prompt: prompt.into(),
            context: vec![],
            attachments: vec![],
        };
        let derived = task("work");
        assert!(!derived.valid(&host), "a remote task id is a UUIDv4");
        assert!(derived.valid_local(&host));
        assert!(!task("bell \u{7}").valid_local(&host));
        assert!(!task(&"x".repeat(33_000)).valid_local(&host));
        let mut context = task("work");
        let text = "y".repeat(40_000);
        context.context = vec![ContextSnapshot {
            kind: ContextKind::Vault,
            id: "v-big:1".into(),
            version: 1,
            digest: digest(text.as_bytes()),
            text,
        }];
        assert!(
            !context.valid_local(&host),
            "prompt and context share the 32 KiB bound"
        );
    }
}
