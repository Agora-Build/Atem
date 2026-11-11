//! `alert_list` and the alerts it returns (feature `host.alerts`; delegated
//! host-work design I.4.6, host-work-v1 §11.3).
//!
//! An alert is the host's record that a task became `outcome_unknown`: it
//! names the host, session, task and sender, and why the outcome is unknown.
//! It lasts until the task is resolved (`work_resolve`, or the host's own
//! command), or a reply moves the task to `awaiting_result`. The request
//! ([`Request::AlertList`](super::host_work::Request::AlertList)) and its
//! result ([`ResultBody::Alerts`](super::host_work::ResultBody::Alerts)) are
//! host-work messages, read as strictly as every other; the push hint of the
//! same kind (`outcome_unknown`, [`crate::push::AlertHint`]) seals the same
//! four facts (task, session, sender, reason) to the owner's devices.
use serde::{Deserialize, Serialize};

use super::wire::{is_opaque_id, is_session_id, is_uuid_v4, is_uuid_v5};
use crate::canonical::MAX_SAFE_INTEGER;

/// The feature: `alert_list`, and the push hint of kind `outcome_unknown`.
pub const FEATURE: &str = super::host_work::ALERTS_FEATURE;
/// The most alerts one `alert_list` result carries (**Atem's choice, for
/// Astation to confirm**): 64 of at most about 450 bytes each stay far under
/// every bound, and a host holds at most 256 unresolved outcomes (design
/// I.4.6), so a full list is four pages.
pub const MAX_PAGE: usize = 64;
/// The longest `reason`, in bytes (**Atem's choice, for Astation to
/// confirm**): a short phrase (`agent exited`, `write interrupted`), well
/// under the 1,024 bytes of a status `detail`.
pub const MAX_REASON_BYTES: usize = 256;

/// What an alert is about. One kind exists; a reader refuses any other.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertKind {
    OutcomeUnknown,
}

/// One alert, as `alert_list` returns it. `alert_id` is a UUID v4 the host
/// chose and keeps (an alert is durable); `host_id` is the host's own
/// `atem_device_id`; `created_at` is the host's wall clock, Unix ms, when the
/// task became `outcome_unknown`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Alert {
    pub alert_id: String,
    pub kind: AlertKind,
    pub host_id: String,
    pub session_id: String,
    pub task_id: String,
    pub sender: String,
    pub reason: String,
    pub created_at: u64,
}

/// A task id as an alert names it: a UUID v4, or the UUID v5 of a local
/// selector's fixed resolution (sender `local`).
pub fn valid_task_id(task_id: &str) -> bool {
    is_uuid_v4(task_id) || is_uuid_v5(task_id)
}

/// A task's sender as an alert names it: the principal that enqueued it,
/// `member:<id>`, `service:<id>`, `browser:<grant_id>` or `host:<host_id>`
/// (an id of 1-128 bytes of `[A-Za-z0-9._:-]`), or the literal `local`.
pub fn valid_sender(sender: &str) -> bool {
    sender == "local"
        || ["member:", "service:", "browser:", "host:"]
            .iter()
            .any(|prefix| sender.strip_prefix(prefix).is_some_and(is_opaque_id))
}

/// A reason: 1-[`MAX_REASON_BYTES`] bytes, no control character.
pub fn valid_reason(reason: &str) -> bool {
    (1..=MAX_REASON_BYTES).contains(&reason.len()) && !reason.chars().any(char::is_control)
}

impl Alert {
    pub fn valid(&self) -> bool {
        is_uuid_v4(&self.alert_id)
            && is_opaque_id(&self.host_id)
            && is_session_id(&self.session_id)
            && valid_task_id(&self.task_id)
            && valid_sender(&self.sender)
            && valid_reason(&self.reason)
            && self.created_at <= MAX_SAFE_INTEGER
    }

    /// Where the alert stands in the list: oldest first, ties by id.
    fn position(&self) -> (u64, &str) {
        (self.created_at, &self.alert_id)
    }
}

/// A page is in the host's order: strictly ascending by `(created_at,
/// alert_id)`, so no alert repeats.
pub fn in_order(alerts: &[Alert]) -> bool {
    alerts
        .windows(2)
        .all(|pair| pair[0].position() < pair[1].position())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::host_work::{
        ALERTS_FEATURE, HostTarget, Request, Response, ResultBody, result,
    };
    use crate::session::new_id;
    use serde_json::{Value, json};

    fn host() -> HostTarget {
        HostTarget {
            account_id: "account".into(),
            atem_device_id: "host".into(),
            host_trust_gen: 1,
        }
    }

    /// The nth alert (ids ascend with `n`).
    fn alert(n: u64, created_at: u64) -> Alert {
        Alert {
            alert_id: format!("aaaaaaaa-0000-4000-8000-{n:012x}"),
            kind: AlertKind::OutcomeUnknown,
            host_id: "host".into(),
            session_id: "ses-aaaaaaaaaaaa".into(),
            task_id: format!("bbbbbbbb-0000-4000-8000-{n:012x}"),
            sender: "service:svc-1".into(),
            reason: "agent exited".into(),
            created_at,
        }
    }

    fn list(after: Option<&str>) -> Request {
        Request::AlertList {
            v: 1,
            id: new_id(),
            host: host(),
            after: after.map(str::to_owned),
        }
    }

    fn answer(request: &Request, alerts: Vec<Alert>, more: bool) -> Value {
        result(
            &new_id(),
            request.id(),
            request.host(),
            &new_id(),
            "channel",
            ResultBody::Alerts { alerts, more },
        )["data"]
            .clone()
    }

    #[test]
    fn alert_list_round_trip() {
        for after in [None, Some("aaaaaaaa-0000-4000-8000-000000000002")] {
            let request = list(after);
            let wire = request.to_json();
            assert_eq!(wire["data"]["op"], "alert_list");
            // `after` is omitted when absent, never null.
            assert_eq!(wire["data"].get("after").is_some(), after.is_some());
            let decoded = Request::decode(wire.to_string().as_bytes()).unwrap();
            assert_eq!(decoded, request);
            assert_eq!(decoded.feature(), ALERTS_FEATURE);
            assert!(!decoded.is_launch());
            assert_eq!(decoded.host(), &host());
        }
        // Exactly its fields, read as they were written.
        let data = list(Some("aaaaaaaa-0000-4000-8000-000000000002")).to_json()["data"].clone();
        let refuse = |edit: &dyn Fn(&mut Value)| {
            let mut data = data.clone();
            edit(&mut data);
            Request::from_data(&data).is_err()
        };
        assert!(Request::from_data(&data).is_ok());
        assert!(refuse(&|d| d["after"] = Value::Null), "null is no value");
        assert!(refuse(&|d| d["after"] = json!("not-a-uuid")));
        assert!(
            refuse(&|d| d["after"] = json!("6ba7b810-9dad-51d1-80b4-00c04fd430c8")),
            "an alert id is a UUID v4"
        );
        assert!(refuse(&|d| d["after"] = json!("")));
        assert!(refuse(&|d| d["limit"] = json!(10)), "an unknown field");
        assert!(refuse(&|d| d["v"] = json!(2)));
        assert!(refuse(&|d| d["id"] = json!("x")));
        assert!(refuse(&|d| {
            d.as_object_mut().unwrap().remove("host");
        }));
        assert!(refuse(&|d| d["host"]["host_trust_gen"] = json!(-1)));

        // A result answers the request it is for, and only that one.
        let request = list(None);
        let page = vec![alert(1, 100), alert(2, 100), alert(3, 200)];
        let json = answer(&request, page.clone(), true);
        assert_eq!(json["result"]["kind"], "alerts");
        assert_eq!(json["result"]["more"], true);
        let response = Response::from_data(&json).unwrap();
        assert!(response.answers(&request));
        assert_eq!(
            response.result,
            ResultBody::Alerts {
                alerts: page.clone(),
                more: true
            }
        );
        assert!(!response.answers(&list(None)), "another exchange");
        let mut elsewhere = request.host().clone();
        elsewhere.host_trust_gen = 2;
        let mut other = Response::from_data(&json).unwrap();
        other.host = elsewhere;
        assert!(!other.answers(&request), "another host");
        // It answers no other op, and no other result answers it.
        let work = Request::WorkQuery {
            v: 1,
            id: request.id().into(),
            host: host(),
            task_id: new_id(),
        };
        assert!(!response.answers(&work));
        // A page after a cursor never carries the cursor itself.
        let after = list(Some(&page[1].alert_id));
        let mut from = answer(&after, page[2..].to_vec(), false);
        from["re"] = json!(after.id());
        assert!(Response::from_data(&from).unwrap().answers(&after));
        let mut again = answer(&after, page[1..].to_vec(), false);
        again["re"] = json!(after.id());
        assert!(!Response::from_data(&again).unwrap().answers(&after));
        // An empty page is a whole answer.
        let empty = answer(&request, Vec::new(), false);
        assert!(Response::from_data(&empty).unwrap().answers(&request));
    }

    #[test]
    fn alerts_result_strict() {
        let request = list(None);
        let good = answer(&request, vec![alert(1, 100), alert(2, 100)], false);
        assert!(Response::from_data(&good).is_ok());
        let refused = |edit: &dyn Fn(&mut Value)| {
            let mut data = good.clone();
            edit(&mut data);
            Response::from_data(&data).is_err()
        };
        // Exact fields: an unknown one anywhere, a missing one.
        assert!(refused(&|d| d["result"]["extra"] = json!(1)));
        assert!(refused(&|d| d["result"]["alerts"][0]["extra"] = json!(1)));
        assert!(refused(&|d| {
            d["result"].as_object_mut().unwrap().remove("more");
        }));
        assert!(refused(&|d| d["result"]["more"] = json!(null)));
        assert!(refused(&|d| d["result"]["more"] = json!("no")));
        for field in [
            "alert_id",
            "kind",
            "host_id",
            "session_id",
            "task_id",
            "sender",
            "reason",
            "created_at",
        ] {
            assert!(
                refused(&|d| {
                    d["result"]["alerts"][0]
                        .as_object_mut()
                        .unwrap()
                        .remove(field);
                }),
                "{field} is required"
            );
        }
        assert!(refused(
            &|d| d["result"]["alerts"][0]["reason"] = json!(null)
        ));
        // The kind is the one kind there is.
        assert!(refused(
            &|d| d["result"]["alerts"][0]["kind"] = json!("expired")
        ));
        // Each field's rule.
        assert!(refused(
            &|d| d["result"]["alerts"][0]["alert_id"] = json!("x")
        ));
        assert!(refused(
            &|d| d["result"]["alerts"][0]["task_id"] = json!("x")
        ));
        assert!(refused(
            &|d| d["result"]["alerts"][0]["session_id"] = json!("ses-A")
        ));
        assert!(refused(
            &|d| d["result"]["alerts"][0]["sender"] = json!("phone")
        ));
        assert!(refused(
            &|d| d["result"]["alerts"][0]["sender"] = json!("member:")
        ));
        assert!(refused(
            &|d| d["result"]["alerts"][0]["sender"] = json!("admin:x")
        ));
        assert!(refused(&|d| d["result"]["alerts"][0]["reason"] = json!("")));
        assert!(refused(
            &|d| d["result"]["alerts"][0]["reason"] = json!("a\nb")
        ));
        assert!(refused(
            &|d| d["result"]["alerts"][0]["reason"] = json!("x".repeat(257))
        ));
        assert!(refused(
            &|d| d["result"]["alerts"][0]["created_at"] = json!(-1)
        ));
        assert!(refused(
            &|d| d["result"]["alerts"][0]["created_at"] = json!(1u64 << 53)
        ));
        // The bounds themselves are fine.
        for (field, value) in [
            ("reason", json!("x".repeat(256))),
            ("sender", json!("local")),
            ("sender", json!("browser:grant-1")),
            ("sender", json!("host:host-b")),
            ("sender", json!(format!("member:{}", "d".repeat(128)))),
            ("task_id", json!("6ba7b810-9dad-51d1-80b4-00c04fd430c8")),
        ] {
            let mut data = good.clone();
            data["result"]["alerts"][0][field] = value.clone();
            assert!(Response::from_data(&data).is_ok(), "{field} {value}");
        }
        // The largest safe time, on the last alert of the page (the order).
        let mut data = good.clone();
        data["result"]["alerts"][1]["created_at"] = json!((1u64 << 53) - 1);
        assert!(Response::from_data(&data).is_ok());
        assert!(refused(
            &|d| d["result"]["alerts"][0]["sender"] = json!(format!("member:{}", "d".repeat(129)))
        ));
        // The alert is this host's.
        assert!(refused(
            &|d| d["result"]["alerts"][1]["host_id"] = json!("other-host")
        ));
        // In order: ascending by (created_at, alert_id), no repeat.
        assert!(refused(&|d| {
            let a = d["result"]["alerts"].as_array_mut().unwrap();
            a.swap(0, 1);
        }));
        assert!(refused(&|d| {
            let first = d["result"]["alerts"][0].clone();
            d["result"]["alerts"].as_array_mut().unwrap().push(first);
        }));
        assert!(refused(
            &|d| d["result"]["alerts"][0]["created_at"] = json!(101)
        ));
        // A page holds at most 64; `more` needs a last alert to continue from.
        let page = |n: u64, more: bool| {
            answer(
                &request,
                (1..=n).map(|i| alert(i, 1_000 + i)).collect(),
                more,
            )
        };
        assert!(Response::from_data(&page(64, true)).is_ok());
        assert!(Response::from_data(&page(65, true)).is_err());
        assert!(Response::from_data(&page(0, true)).is_err());
        assert!(Response::from_data(&page(0, false)).is_ok());
        // The result is read as written: no other kind of body is one.
        let mut as_work = good.clone();
        as_work["result"]["kind"] = json!("work");
        assert!(Response::from_data(&as_work).is_err());
    }
}
