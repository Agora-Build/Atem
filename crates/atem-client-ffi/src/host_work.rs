//! Host work (host-work-v1) over `atem_client::session::host_work`: the
//! derivation and the checks an app needs beside the connection's own.
//!
//! `ClientConnection` already checks what the core checks: a host-work
//! request the app sends (`send_json`) is refused before it is sealed when
//! it isn't valid (a `message_publish` whose Message has a `select`
//! recipient included: no channel admits one, host-work-v1 §11.5), and a
//! `host_work_result` it reads is taken only when it answers its request (a
//! `reply_query`'s non-null reply only with the asked task's `result_id`;
//! a `work` status only of the task the request named). One that answers
//! nothing fails `on_frame` with `malformed` and the connection closes the
//! channel, like any unbound result: the app reconnects and asks again with
//! a new id. (The Rust core's `Attached` returns the error and leaves the
//! request pending.)
//!
//! - [`host_work_result_id`] gives an app the same derivation, for a reply
//!   it holds or shows;
//! - [`host_work_request_valid`] is the reader `send_json` applies, for an
//!   app's own check before it sends (the owner's `work_query`,
//!   `work_interrupt` and `work_resolve` name a host sender's selector task,
//!   its UUID v5, as well as a UUID v4: host-work-v1 §11.2, §11.5);
//! - [`host_work_result_answers`] is the strict reader and the request
//!   correlation the connection applies to a result, for a result an app
//!   holds (not its binding to the channel, which it has none of).

use atem_client::session::host_work::{Request, Response};

/// A task's one `result_id`, the same for every reply to it, a corrected
/// one included (host-work-v1 §11.5, "`result_id`"):
/// `UUIDv5(NAMESPACE_OID, "result:" + task_id)`, with `task_id` as written
/// in the request (lowercase, with hyphens), the shared core's derivation.
/// A reply to `reply_query{task_id}` whose `result_id` isn't this one
/// doesn't answer it.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn host_work_result_id(task_id: String) -> String {
    atem_client::session::host_work::result_id(&task_id)
}

/// Whether the shared core's strict reader takes `message_json`, a whole
/// host-work request (`{"type":"session","data":{…}}`, host-work-v1 §1):
/// the check `ClientConnection::send_json` makes before it seals one (the
/// welcome's features and host aside). The owner's `work_query`,
/// `work_interrupt` and `work_resolve` may name a host sender's selector
/// task (a lowercase UUID v5, §11.2, §11.5); every other op naming a task
/// takes a UUID v4. Valid says nothing of who may name the task: the host
/// answers a caller that may not exactly as it answers a missing task.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn host_work_request_valid(message_json: String) -> bool {
    Request::decode(message_json.as_bytes()).is_ok()
}

/// Whether `result_json`, a `host_work_result`'s `data` (host-work-v1 §7),
/// reads and answers the host-work request `request_json` (a whole request,
/// as [`host_work_request_valid`] takes it). False when either doesn't
/// read. What it checks:
///
/// - `result_json` is strict JSON as the connection reads a record (no
///   duplicate key, an escaped spelling of one included; at most 1 MiB)
///   and the shared core's `host_work_result` reader takes it (its exact
///   fields and their forms);
/// - it answers the request: its `re` is the request's `id`, its `host`
///   the request's, and its body the request's own (a `work` status of the
///   task the request named, a reply with that task's `result_id` or none
///   yet, and so on: `Response::answers`).
///
/// Not checked: the channel binding. The connection also takes a result
/// only with its own channel's `attachment_gen` and `channel_id` and only
/// for a request it still waits for; this function has no channel, so it
/// checks only that both fields are well formed.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn host_work_result_answers(request_json: String, result_json: String) -> bool {
    let Ok(request) = Request::decode(request_json.as_bytes()) else {
        return false;
    };
    let Ok(value) = atem_client::canonical::parse_strict(
        result_json.as_bytes(),
        atem_client::channel::MAX_PLAINTEXT,
        atem_client::canonical::Numbers::AllowFractions,
    ) else {
        return false;
    };
    Response::from_data(&value).is_ok_and(|response| response.answers(&request))
}
