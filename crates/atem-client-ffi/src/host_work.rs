//! Host work (host-work-v1) over `atem_client::session::host_work`: the
//! derivation an app needs beside the connection's own checks.
//!
//! `ClientConnection` already checks what the core checks: a host-work
//! request the app sends (`send_json`) is refused before it is sealed when
//! it isn't valid (a `message_publish` whose Message has a `select`
//! recipient included: no channel admits one, host-work-v1 §11.5), and a
//! `host_work_result` it reads is taken only when it answers its request (a
//! `reply_query`'s non-null reply only with the asked task's `result_id`).
//! [`host_work_result_id`] gives an app the same derivation, for a reply it
//! holds or shows.

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
