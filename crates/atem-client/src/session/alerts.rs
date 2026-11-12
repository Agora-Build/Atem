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

use super::wire::{is_delegated_sender, is_opaque_id, is_session_id, is_uuid_v4};
use crate::canonical::MAX_SAFE_INTEGER;

/// The feature: `alert_list`, and the push hint of kind `outcome_unknown`.
pub const FEATURE: &str = super::host_work::ALERTS_FEATURE;
/// The most alerts one `alert_list` result carries (**Atem's choice, for
/// Astation to confirm**): an alert is typically about 450 bytes, at most
/// about 750 (about 1 KB with escaping), so 64 stay far under every bound;
/// a host holds at most 256 unresolved outcomes (design I.4.6), so a full
/// list is four pages.
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
/// chose and keeps (an alert is durable); `seq` is the host's sequence
/// number of it, from 1, rising with every alert the host creates and never
/// reused: the list's order; `host_id` is the host's own
/// `atem_device_id`; `created_at` is the host's wall clock, Unix ms, when the
/// task became `outcome_unknown`, for people only: it orders nothing.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Alert {
    pub alert_id: String,
    pub seq: u64,
    pub kind: AlertKind,
    pub host_id: String,
    pub session_id: String,
    pub task_id: String,
    pub sender: String,
    pub reason: String,
    pub created_at: u64,
}

/// A task id as an alert names it: a UUID v4. Only a delegated sender's
/// task raises an alert (design I.1.3, I.4.6), and a remote
/// task's id is a UUID v4. A local selector's UUID v5 task keeps v1, whose
/// unknown outcomes expire.
pub fn valid_task_id(task_id: &str) -> bool {
    is_uuid_v4(task_id)
}

/// A task's sender as an alert names it: the delegated sender that enqueued
/// it, `member:<id>`, `service:<id>` or `host:<host_id>` (an id of 1-128
/// bytes of `[A-Za-z0-9._:-]`; [`is_delegated_sender`], as a receipt's
/// provenance names it). Never `local` or a browser grant: their tasks keep
/// v1 and raise no alert.
pub fn valid_sender(sender: &str) -> bool {
    is_delegated_sender(sender)
}

/// A reason: 1-[`MAX_REASON_BYTES`] bytes, not blank (empty after trimming
/// white space, as a `failed` resolution's detail is judged), no control or
/// Cf character (the framing module's rule: no bidi control or zero-width
/// character in text shown to the owner). The reason is kept as given:
/// padding is no fault, only a reason of nothing else.
pub fn valid_reason(reason: &str) -> bool {
    (1..=MAX_REASON_BYTES).contains(&reason.len())
        && !reason.trim().is_empty()
        && !reason
            .chars()
            .any(|c| c.is_control() || super::framing::is_format(c))
}

impl Alert {
    pub fn valid(&self) -> bool {
        is_uuid_v4(&self.alert_id)
            && (1..=MAX_SAFE_INTEGER).contains(&self.seq)
            && is_opaque_id(&self.host_id)
            && is_session_id(&self.session_id)
            && valid_task_id(&self.task_id)
            && valid_sender(&self.sender)
            && valid_reason(&self.reason)
            && self.created_at <= MAX_SAFE_INTEGER
    }
}

/// A page is in the host's order: strictly ascending by `seq`, so no alert
/// repeats. `created_at` orders nothing: a wall clock set back gives a later
/// alert an earlier time.
pub fn in_order(alerts: &[Alert]) -> bool {
    alerts.windows(2).all(|pair| pair[0].seq < pair[1].seq)
}

/// The host's side of `alert_list` (the host keeps its alerts; step 4): the
/// page after `after`, at most `limit` alerts in the host's order, and
/// whether more follow.
/// - `Ok(None)` for an `after` the host has no alert for (the alert ended,
///   or never was): `stale_target`, detail `unknown alert`.
/// - `Err("invalid_request")` for a `limit` of 0, checked first: a page of
///   no alert that says more follow is a result no reader takes (`more`
///   needs a last alert to continue from) and a caller could not follow. The
///   limit is the host's own (the request has no such field; the host passes
///   [`MAX_PAGE`]), so this is a host's fault, never a wire input.
pub fn page(
    alerts: &[Alert],
    after: Option<&str>,
    limit: usize,
) -> Result<Option<(Vec<Alert>, bool)>, &'static str> {
    if limit == 0 {
        return Err("invalid_request");
    }
    let mut ordered: Vec<&Alert> = alerts.iter().collect();
    ordered.sort_by_key(|a| a.seq);
    let start = match after {
        None => 0,
        Some(after) => match ordered.iter().position(|a| a.alert_id == after) {
            Some(at) => at + 1,
            None => return Ok(None),
        },
    };
    let rest = &ordered[start..];
    let taken: Vec<Alert> = rest.iter().take(limit).map(|a| (*a).clone()).collect();
    let more = rest.len() > taken.len();
    Ok(Some((taken, more)))
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

    /// The nth alert (its host sequence number is `n`).
    fn alert(n: u64, created_at: u64) -> Alert {
        Alert {
            alert_id: format!("aaaaaaaa-0000-4000-8000-{n:012x}"),
            seq: n,
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

    /// The host lists its alerts in the order it created them, by its
    /// sequence number, never by `created_at`: a wall clock set
    /// back gives a new alert an earlier `created_at`, and a client paging
    /// with `after` still gets it after the cursor.
    #[test]
    fn a_later_alert_with_an_earlier_created_at_is_listed_after_the_cursor() {
        // Alert 2 was created after alert 1, with the wall clock set back.
        let held = vec![alert(2, 1_000), alert(1, 5_000), alert(3, 6_000)];
        let (first, more) = page(&held, None, 1).unwrap().unwrap();
        assert_eq!((first.len(), more), (1, true));
        assert_eq!(first[0].seq, 1);
        let (next, more) = page(&held, Some(&first[0].alert_id), 1).unwrap().unwrap();
        assert_eq!((next[0].seq, next[0].created_at, more), (2, 1_000, true));
        let (last, more) = page(&held, Some(&next[0].alert_id), 10).unwrap().unwrap();
        assert_eq!((last.len(), last[0].seq, more), (1, 3, false));
        // Every page is in order, and a client reading it agrees.
        for (p, _) in [
            page(&held, None, MAX_PAGE).unwrap().unwrap(),
            page(&held, Some(&first[0].alert_id), MAX_PAGE)
                .unwrap()
                .unwrap(),
        ] {
            assert!(in_order(&p));
        }
        let (all, more) = page(&held, None, MAX_PAGE).unwrap().unwrap();
        assert_eq!(
            (all.iter().map(|a| a.seq).collect::<Vec<_>>(), more),
            (vec![1, 2, 3], false)
        );
        // A cursor the host has no alert for is `stale_target`'s case.
        assert_eq!(
            page(&held, Some("aaaaaaaa-0000-4000-8000-0000000000ff"), 10),
            Ok(None)
        );
        // Past the last alert: an empty page, and no more.
        let (none, more) = page(&held, Some(&last[0].alert_id), 10).unwrap().unwrap();
        assert_eq!((none.len(), more), (0, false));
    }

    /// A reason says something: one that is blank after trimming white space
    /// (as a `failed` resolution's detail is judged) is refused, in the
    /// alert and in a result carrying it. White space is `White_Space`, the
    /// Unicode ones (no-break, ideographic) included; control white space
    /// (a tab, a newline) was already refused as a control character.
    #[test]
    fn an_all_blank_alert_reason_is_refused() {
        for blank in [
            " ",
            "   ",
            "\u{00A0}",
            "\u{2003}\u{00A0}",
            "\u{3000}",
            " \u{00A0}\u{3000} ",
            "\u{0085}",
            "\t",
            "\n",
        ] {
            assert!(!valid_reason(blank), "{blank:?}");
            let mut a = alert(1, 100);
            a.reason = blank.into();
            assert!(!a.valid(), "{blank:?}");
        }
        // What says something stays valid, padding and inner spaces as given.
        for good in [
            "agent exited",
            " agent exited ",
            "write  interrupted",
            "\u{00A0}x",
            "é 中文",
        ] {
            assert!(valid_reason(good), "{good:?}");
            let mut a = alert(1, 100);
            a.reason = good.into();
            assert!(a.valid(), "{good:?}");
        }
        // A result with a blank reason is no result.
        let request = list(None);
        let good = answer(&request, vec![alert(1, 100)], false);
        assert!(Response::from_data(&good).is_ok());
        for blank in [" ", "   ", "\u{00A0}\u{3000}"] {
            let mut data = good.clone();
            data["result"]["alerts"][0]["reason"] = json!(blank);
            assert!(Response::from_data(&data).is_err(), "{blank:?}");
        }
    }

    /// A page asks for at least one alert: with a limit of 0 the host would
    /// answer an empty page with `more` true, which no reader takes (`more`
    /// needs a last alert to continue from) and a caller could never follow.
    /// It is refused as a request is, `invalid_request`, and the check comes
    /// before the cursor's, so it is no `stale_target` either.
    #[test]
    fn page_with_limit_zero_is_refused() {
        let held = vec![alert(1, 100), alert(2, 200), alert(3, 300)];
        assert_eq!(page(&held, None, 0), Err("invalid_request"));
        assert_eq!(
            page(&held, Some(&held[0].alert_id), 0),
            Err("invalid_request")
        );
        // Whatever the list holds, even nothing, and whatever the cursor
        // names, even an alert the host has none for.
        assert_eq!(page(&[], None, 0), Err("invalid_request"));
        assert_eq!(
            page(&held, Some("aaaaaaaa-0000-4000-8000-0000000000ff"), 0),
            Err("invalid_request")
        );
        // One alert is the least a page carries, and it goes on.
        let (one, more) = page(&held, None, 1).unwrap().unwrap();
        assert_eq!((one.len(), more), (1, true));
        // An answer built from a page is a result a reader takes.
        let request = list(None);
        let (taken, more) = page(&held, None, MAX_PAGE).unwrap().unwrap();
        assert!(Response::from_data(&answer(&request, taken, more)).is_ok());
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
            "seq",
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
        // Only a delegated sender's task raises an alert: a
        // UUID v4 task of a `member:`, `service:` or `host:` sender. `local`
        // and browser grants keep v1, whose unknown outcomes expire.
        for (field, value) in [
            ("sender", json!("local")),
            ("sender", json!("browser:grant-1")),
            ("sender", json!("host-work")),
            ("task_id", json!("6ba7b810-9dad-51d1-80b4-00c04fd430c8")),
        ] {
            assert!(
                refused(&|d| d["result"]["alerts"][0][field] = value.clone()),
                "{field} {value}"
            );
        }
        // A reason with a Cf character (bidi controls, zero-width
        // characters) is refused, as a failed resolution's detail is.
        for reason in ["a\u{202E}b", "\u{200B}agent exited", "x\u{2066}"] {
            assert!(
                refused(&|d| d["result"]["alerts"][0]["reason"] = json!(reason)),
                "{reason:?}"
            );
        }
        // The host's sequence number: from 1, a safe integer.
        assert!(refused(&|d| d["result"]["alerts"][0]["seq"] = json!(0)));
        assert!(refused(&|d| d["result"]["alerts"][0]["seq"] = json!(null)));
        assert!(refused(
            &|d| d["result"]["alerts"][1]["seq"] = json!(1u64 << 53)
        ));
        // The bounds themselves are fine.
        for (field, value) in [
            ("reason", json!("x".repeat(256))),
            ("sender", json!("host:host-b")),
            ("sender", json!(format!("member:{}", "d".repeat(128)))),
            ("sender", json!(format!("service:{}", "s".repeat(128)))),
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
        // In the host's order: strictly ascending by `seq`, no repeat.
        // `created_at` is informational and orders nothing.
        assert!(refused(&|d| {
            let a = d["result"]["alerts"].as_array_mut().unwrap();
            a.swap(0, 1);
        }));
        assert!(refused(&|d| {
            let first = d["result"]["alerts"][0].clone();
            d["result"]["alerts"].as_array_mut().unwrap().push(first);
        }));
        assert!(refused(&|d| d["result"]["alerts"][1]["seq"] = json!(1)));
        let mut earlier = good.clone();
        earlier["result"]["alerts"][0]["created_at"] = json!(101);
        assert!(
            Response::from_data(&earlier).is_ok(),
            "a later alert may carry an earlier created_at"
        );
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
        // The sequence may skip numbers (alerts end), but never goes back.
        let mut gaps = good.clone();
        gaps["result"]["alerts"][1]["seq"] = json!(9);
        assert!(Response::from_data(&gaps).is_ok());
        // The result is read as written: no other kind of body is one.
        let mut as_work = good.clone();
        as_work["result"]["kind"] = json!("work");
        assert!(Response::from_data(&as_work).is_err());
    }
}
