//! The Station's suspension of this host's service (the delegated
//! host-work design III.5; session-v1 R9.7b and R9.7a): the built-in
//! Station refuses relay service to the hosts of an account disabled at
//! Agora.Build, or with no Agora.Build owner at this Station, with
//! `service_suspended` and a text. In every build, the host reads it, shows
//! it and retries; it is a service outage, never a revocation:
//!
//! - **At connect** (the relay link's route proof refused
//!   `service_suspended`, `AstationMessage::HostRouteSuspended`, or the
//!   Station's notice while the link is authenticated): the connect fails
//!   (no route, no Astation authentication on that socket,
//!   `ServiceSuspendedError`), the text is recorded, and the next attempt
//!   goes after the connect loop's usual 30 s, never at once.
//! - **On an open relay or routed link** (the notice,
//!   `AstationMessage::ServiceSuspended`): the text is recorded with the
//!   link it came on (with `host.delegated`, the broker's Station link
//!   takes it at the start of its next pass, before it reads the link
//!   again, even when the Station closed the socket right after: it
//!   retires every live call on the socket and closes its gates,
//!   `runtime/delegated/station.rs`). The Station closes the socket; if it
//!   hasn't within [`DROP_AFTER`] the host drops it. Either way the next
//!   attempt waits [`RETRY_AFTER`].
//! - **On Astation's local link** (a proxied refusal of the local route's
//!   proof, or the notice): the text is recorded and the link is kept (with
//!   `host.delegated`, as a refusal of the link's every call kind).
//! - **Never** a fence, revoke, unpair, re-pair, reset or identity change,
//!   nor a route-proof reconnect: no R9 state moves.
//!
//! `atem status` shows the text on its `Relay:` line (`not connected
//! (service suspended: <text>; retrying)`; the text as sent when it begins
//! `service suspended:`, else prefixed, [`shown`]), and with
//! `host.delegated` on its `Control feeds:` line too. The text clears at
//! the next `host_route_ok` or Astation authentication on a relay link; one
//! read on the local link also when that link ends or its route proof is
//! accepted; with `host.delegated`, any once the Station serves the host
//! again (its feed gate open, on whatever link). With the hook off, a
//! relay's text while Astation's local link is up is shown as the relay's
//! last answer ([`Suspension::status_text`]). runtime.log gets one line per
//! text an hour, at most four an hour in all.
//!
//! The next connect after a suspension waits 30 s, the normal connect
//! loop's pace after a suspension, even when the link it came on had been
//! up for more than 10 s (an immediate reconnect is a sure refusal).
//!
//! The `text` field, the disclosure order and the 10 s drop are **Atem's
//! proposal, for Astation's agreement (#120 7207832274)**.
use super::App;
use crate::websocket_client::{LinkVia, ServiceSuspendedError};
use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// A relay or routed link the Station's `service_suspended` came on is
/// dropped by the host this long after it, if the Station hasn't closed it.
pub const DROP_AFTER: Duration = Duration::from_secs(10);
/// After a suspension the next connect attempt waits the connect loop's
/// usual retry, never at once.
pub const RETRY_AFTER: Duration = Duration::from_secs(30);
/// One runtime.log line per text this often.
const LINE_EVERY: Duration = Duration::from_secs(60 * 60);
/// The texts whose last line is remembered (the oldest forgotten first).
const LINES_KEPT: usize = 16;

/// Where a suspension was read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SuspendedOn {
    /// The relay link's connect (its route proof refused, or the notice
    /// while it was authenticated): no link.
    Connect,
    /// An open relay or routed link's notice: its socket
    /// (`AstationClient::socket_id`).
    Relay { socket: u64 },
    /// Astation's local link: its socket.
    Local { socket: u64 },
}

/// The Station's suspension of this host's service, as last read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Suspension {
    /// The Station's text (`atem_client::host_route::service_text_ok`'s).
    pub text: String,
    pub on: SuspendedOn,
    /// The Station's origin, as normalized (`None`: not known).
    pub origin: Option<String>,
    /// An open link's notice: its number in this run (the broker's Station
    /// link takes each once), and the link generation it came on.
    pub notice: Option<u64>,
    pub link_gen: u64,
}

impl Suspension {
    /// What `atem status` shows of it with the App's link up locally or
    /// not (`local_link`): the text ([`shown`]); one the relay gave, shown
    /// while Astation's local link is up, as the relay's last answer (a
    /// local link says nothing of the relay's service; review M3): `the
    /// relay last answered: service suspended: <text>`.
    pub fn status_text(&self, local_link: bool) -> String {
        if local_link && !self.local() {
            format!("the relay last answered: {}", self.shown())
        } else {
            self.shown()
        }
    }

    /// The socket it was read on (none at a connect).
    pub fn socket(&self) -> Option<u64> {
        match self.on {
            SuspendedOn::Connect => None,
            SuspendedOn::Relay { socket } | SuspendedOn::Local { socket } => Some(socket),
        }
    }

    /// What `atem status` shows ([`shown`]).
    pub fn shown(&self) -> String {
        shown(&self.text)
    }

    /// Read on Astation's local link.
    pub fn local(&self) -> bool {
        matches!(self.on, SuspendedOn::Local { .. })
    }
}

/// The Station's `text` as `atem status` shows it: as sent when it begins
/// `service suspended:` (III.5's texts do: "service suspended: account
/// disabled at Agora.Build"), otherwise with `service suspended: ` before
/// it. Exact, case-sensitive. **Atem's reading, for Astation's agreement
/// (#120 7207832274).**
pub fn shown(text: &str) -> String {
    if text.starts_with("service suspended:") {
        text.to_owned()
    } else {
        format!("service suspended: {text}")
    }
}

/// At most this many suspension lines an hour in all (review L4), then one
/// line saying how many more were suppressed.
const LINES_AN_HOUR: u32 = 4;

/// The runtime.log line's limit: one per text an hour, and at most
/// [`LINES_AN_HOUR`] in all.
#[derive(Debug, Default)]
pub struct Lines {
    logged: VecDeque<(String, Instant)>,
    /// The hour's window, its lines, the lines suppressed in it.
    window: Option<Instant>,
    in_window: u32,
    suppressed: u64,
}

/// What [`Lines::due`] says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Due {
    /// Not now.
    Skip,
    /// The line goes, after one naming how many an earlier window
    /// suppressed (0: none).
    Log { suppressed: u64 },
}

impl Lines {
    /// Whether a line about `text` is due at `now` (counted when it is).
    fn due(&mut self, text: &str, now: Instant) -> Due {
        let known = self.logged.iter().position(|(t, _)| t == text);
        if let Some(i) = known
            && now.duration_since(self.logged[i].1) < LINE_EVERY
        {
            return Due::Skip;
        }
        let mut carried = 0;
        if self
            .window
            .is_none_or(|start| now.duration_since(start) >= LINE_EVERY)
        {
            self.window = Some(now);
            self.in_window = 0;
            carried = std::mem::take(&mut self.suppressed);
        }
        if self.in_window >= LINES_AN_HOUR {
            self.suppressed += 1;
            return Due::Skip;
        }
        self.in_window += 1;
        match known {
            Some(i) => self.logged[i].1 = now,
            None => {
                if self.logged.len() >= LINES_KEPT {
                    self.logged.pop_front();
                }
                self.logged.push_back((text.to_owned(), now));
            }
        }
        Due::Log {
            suppressed: carried,
        }
    }
}

/// The 10 s drop of a relay or routed link a suspension came on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SuspensionDrop {
    socket: u64,
    at: Instant,
}

impl App {
    /// A relay link's connect the Station refused with `service_suspended`
    /// (its route proof, or the notice while it was authenticated): the
    /// text recorded; the caller schedules the usual 30 s retry.
    pub(super) fn suspended_at_connect(&mut self, error: &ServiceSuspendedError) {
        self.record_suspension(Suspension {
            text: error.text.clone(),
            on: SuspendedOn::Connect,
            origin: error.origin.clone(),
            notice: None,
            link_gen: self.astation_link_gen,
        });
    }

    /// The Station's `service_suspended` notice on the open link: recorded
    /// with its link, for the broker's Station link (`host.delegated`); a
    /// relay or routed link is dropped [`DROP_AFTER`] later if the Station
    /// hasn't closed it, and reconnects after [`RETRY_AFTER`]; a local link
    /// stays.
    pub(super) fn service_suspended(&mut self, text: String) {
        let socket = self.astation_client.socket_id();
        let local = matches!(self.astation_client.via(), Some(LinkVia::Local));
        let on = if local {
            SuspendedOn::Local { socket }
        } else {
            SuspendedOn::Relay { socket }
        };
        self.suspension_notices += 1;
        self.record_suspension(Suspension {
            text,
            on,
            origin: self.astation_client.selected_station_origin(),
            notice: Some(self.suspension_notices),
            link_gen: self.astation_link_gen,
        });
        if !local {
            self.suspension_drop = Some(SuspensionDrop {
                socket,
                at: Instant::now() + DROP_AFTER,
            });
        }
    }

    /// The Station refused the local link's route proof with
    /// `service_suspended` (`host.delegated` only: the link's route answers
    /// a challenge only then): recorded; the link stays.
    pub(super) fn local_route_suspended(&mut self, text: String) {
        let socket = self.astation_client.socket_id();
        self.record_suspension(Suspension {
            text,
            on: SuspendedOn::Local { socket },
            origin: self.astation_client.selected_station_origin(),
            notice: None,
            link_gen: self.astation_link_gen,
        });
    }

    fn record_suspension(&mut self, suspension: Suspension) {
        let shown = suspension.shown();
        if let Due::Log { suppressed } = self.suspension_lines.due(&suspension.text, Instant::now())
        {
            if suppressed > 0 {
                eprintln!(
                    "atem runtime: … {suppressed} more service_suspended line(s) suppressed (at most {LINES_AN_HOUR} an hour)"
                );
            }
            if suspension.local() {
                eprintln!(
                    "atem runtime: the Station, through Astation's local link: {shown}; the link stays (no trust or state change)"
                );
            } else {
                eprintln!("atem runtime: relay: {shown}; retrying (no trust or state change)");
            }
        }
        self.status_message = Some(format!("{shown}; retrying"));
        self.service_suspension = Some(suspension);
    }

    /// A relay link proved its route (`host_route_ok`) or Astation
    /// authenticated it: whatever the Station suspended before is lifted.
    pub(super) fn suspension_lifted(&mut self) {
        self.service_suspension = None;
        self.suspension_drop = None;
    }

    /// Astation's local link connected (`socket`), with the suspension its
    /// connect read, if any: one read on an earlier local link is gone
    /// with that link.
    pub(super) fn local_link_suspension(&mut self, read: Option<String>) {
        if self
            .service_suspension
            .as_ref()
            .is_some_and(Suspension::local)
        {
            self.service_suspension = None;
        }
        if let Some(text) = read {
            self.local_route_suspended(text);
        }
    }

    /// The local link's route proof was accepted: a suspension read on it
    /// is lifted.
    pub(super) fn local_route_ok(&mut self) {
        if self
            .service_suspension
            .as_ref()
            .is_some_and(Suspension::local)
        {
            self.service_suspension = None;
        }
    }

    /// [`DROP_AFTER`] past a relay or routed link's suspension, the link
    /// still open on that socket: dropped, the next attempt after
    /// [`RETRY_AFTER`]. A link the Station closed (or another link) needs
    /// nothing.
    pub(super) fn check_suspension_drop(&mut self) {
        let Some(drop) = self.suspension_drop else {
            return;
        };
        if self.astation_client.socket_id() != drop.socket || !self.r9_link_up() {
            if self.astation_client.socket_id() != drop.socket {
                self.suspension_drop = None;
            }
            return;
        }
        if Instant::now() < drop.at {
            return;
        }
        self.suspension_drop = None;
        eprintln!(
            "atem runtime: the Station didn't close this host's link within 10 s of its service_suspended; dropping it"
        );
        let reason = match &self.service_suspension {
            Some(s) => format!("{}; retrying", s.shown()),
            None => "The Station suspended this host's service; retrying".to_string(),
        };
        self.drop_astation_link(reason);
        self.astation_reconnect_at = Some(Instant::now() + RETRY_AFTER);
    }

    /// When to reconnect after the link on `socket` ended, the loop's own
    /// choice being `at`: never before [`RETRY_AFTER`] once the Station
    /// suspended this host's service on that socket.
    pub(super) fn suspension_retry_at(&self, socket: u64, at: Instant) -> Instant {
        let suspended_here = self
            .service_suspension
            .as_ref()
            .is_some_and(|s| s.on == SuspendedOn::Relay { socket });
        if suspended_here {
            at.max(Instant::now() + RETRY_AFTER)
        } else {
            at
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The status rule (Atem's reading, for Astation's agreement): the
    /// text as sent when it begins `service suspended:`, exactly; else
    /// prefixed. A relay's record while the local link is up is shown as
    /// the relay's last answer (review M3).
    #[test]
    fn the_text_is_shown_once_prefixed() {
        assert_eq!(
            shown("service suspended: account disabled at Agora.Build"),
            "service suspended: account disabled at Agora.Build"
        );
        assert_eq!(
            shown("account disabled"),
            "service suspended: account disabled"
        );
        for other in ["Service suspended: x", "service suspended (x)"] {
            assert_eq!(shown(other), format!("service suspended: {other}"));
        }
        let record = |on| Suspension {
            text: "service suspended: account disabled at Agora.Build".into(),
            on,
            origin: None,
            notice: None,
            link_gen: 1,
        };
        assert_eq!(
            record(SuspendedOn::Connect).status_text(true),
            "the relay last answered: service suspended: account disabled at Agora.Build"
        );
        assert_eq!(
            record(SuspendedOn::Relay { socket: 1 }).status_text(false),
            "service suspended: account disabled at Agora.Build"
        );
        assert_eq!(
            record(SuspendedOn::Local { socket: 1 }).status_text(true),
            "service suspended: account disabled at Agora.Build"
        );
    }

    fn logs(due: Due) -> bool {
        matches!(due, Due::Log { .. })
    }

    #[test]
    fn one_line_per_text_an_hour_and_a_bounded_memory() {
        let mut lines = Lines::default();
        let t0 = Instant::now();
        assert!(logs(lines.due("a", t0)));
        assert!(!logs(lines.due("a", t0 + Duration::from_secs(59 * 60))));
        assert!(
            logs(lines.due("b", t0 + Duration::from_secs(1))),
            "another text"
        );
        assert!(logs(lines.due("a", t0 + LINE_EVERY)));
        // Each in a window of its own (the hour's cap aside).
        let at = |i: u32| t0 + (i + 2) * LINE_EVERY;
        for i in 0..LINES_KEPT as u32 {
            assert!(logs(lines.due(&format!("t{i}"), at(i))));
        }
        assert_eq!(lines.logged.len(), LINES_KEPT);
        // "a" was forgotten: due again at once, though logged within the
        // hour of the last "t".
        assert!(logs(lines.due("a", at(LINES_KEPT as u32 - 1))));
    }

    /// Review L4: texts that change each time are capped at four lines an
    /// hour in all; the next window's first line says how many went
    /// unlogged.
    #[test]
    fn at_most_four_lines_an_hour_whatever_the_texts() {
        let mut lines = Lines::default();
        let t0 = Instant::now();
        let logged = (0..10)
            .filter(|i| logs(lines.due(&format!("t{i}"), t0 + Duration::from_secs(*i))))
            .count();
        assert_eq!(logged, LINES_AN_HOUR as usize);
        assert_eq!(
            lines.due("next", t0 + LINE_EVERY),
            Due::Log { suppressed: 6 }
        );
        assert_eq!(
            lines.due("next 2", t0 + LINE_EVERY),
            Due::Log { suppressed: 0 }
        );
    }

    fn app_on(socket: u64) -> App {
        let mut app = App::new();
        app.astation_client = crate::websocket_client::AstationClient::new();
        app.service_suspension = Some(Suspension {
            text: "service suspended: account disabled at Agora.Build".into(),
            on: SuspendedOn::Relay { socket },
            origin: None,
            notice: Some(1),
            link_gen: 1,
        });
        app
    }

    #[test]
    fn a_link_the_station_suspended_reconnects_after_30_s_never_at_once() {
        let _profile = crate::test_profile::temp();
        let app = app_on(7);
        let now = Instant::now();
        assert!(app.suspension_retry_at(7, now) >= now + Duration::from_secs(29));
        // Another socket's end is the loop's own choice.
        assert_eq!(app.suspension_retry_at(8, now), now);
    }

    const TEXT: &str = "service suspended: account disabled at Agora.Build";

    /// An App with an open link `via`, on socket `socket` (no real socket:
    /// a fresh client counts as open), whose relay messages the broker
    /// would take.
    fn linked(via: LinkVia, socket: u64) -> App {
        let mut app = App::new();
        app.hosted = Some(Default::default());
        app.astation_connected = true;
        app.astation_client = crate::websocket_client::AstationClient::new();
        app.astation_client.set_via_for_test(via);
        app.astation_client.socket_id_for_test(socket);
        app
    }

    /// B-2 on a relay link: recorded with its socket, link generation and
    /// notice number (for the broker's Station link), and the link dropped
    /// 10 s later if the Station hasn't closed it, then the next attempt
    /// after 30 s, never at once. The record stays for `atem status`;
    /// nothing else moves.
    #[tokio::test]
    async fn the_notice_on_an_open_relay_link_is_recorded_and_dropped_after_10_s() {
        let _profile = crate::test_profile::temp();
        let mut app = linked(LinkVia::Relay { label: "r".into() }, 5);
        app.astation_link_gen = 4;
        app.handle_astation_message(crate::websocket_client::AstationMessage::ServiceSuspended(
            TEXT.into(),
        ))
        .await;
        let record = app.service_suspension.clone().expect("recorded");
        assert_eq!(record.on, SuspendedOn::Relay { socket: 5 });
        assert_eq!(record.text, TEXT);
        assert_eq!((record.notice, record.link_gen), (Some(1), 4));
        assert!(app.hosted.as_ref().unwrap().relay.is_empty());
        // Not due yet: the link stays.
        app.check_suspension_drop();
        assert!(app.astation_connected);
        // Due: dropped, the retry after 30 s.
        app.suspension_drop = Some(SuspensionDrop {
            socket: 5,
            at: Instant::now(),
        });
        app.check_suspension_drop();
        assert!(!app.astation_connected);
        assert!(app.suspension_drop.is_none());
        let at = app.astation_reconnect_at.expect("a retry");
        assert!(at >= Instant::now() + Duration::from_secs(29));
        assert_eq!(app.service_suspension, Some(record), "kept for the status");
    }

    /// A drop due for a socket the Station already closed (another socket
    /// now) does nothing.
    #[tokio::test]
    async fn a_drop_for_another_socket_does_nothing() {
        let _profile = crate::test_profile::temp();
        let mut app = linked(LinkVia::Relay { label: "r".into() }, 6);
        app.suspension_drop = Some(SuspensionDrop {
            socket: 5,
            at: Instant::now(),
        });
        app.check_suspension_drop();
        assert!(app.astation_connected);
        assert!(app.suspension_drop.is_none());
    }

    /// B-2 on Astation's local link: recorded as the local link's, the link
    /// kept (no drop), handed over the same way.
    #[tokio::test]
    async fn the_notice_on_the_local_link_keeps_the_link() {
        let _profile = crate::test_profile::temp();
        let mut app = linked(LinkVia::Local, 9);
        app.handle_astation_message(crate::websocket_client::AstationMessage::ServiceSuspended(
            TEXT.into(),
        ))
        .await;
        assert_eq!(
            app.service_suspension.as_ref().map(|s| s.on),
            Some(SuspendedOn::Local { socket: 9 })
        );
        assert!(app.suspension_drop.is_none());
        assert_eq!(app.service_suspension.as_ref().unwrap().notice, Some(1));
    }

    /// B-1: a relay connect the Station refused with `service_suspended`
    /// records the text with the connect's origin, and the next attempt
    /// goes after the usual 30 s.
    #[test]
    fn a_refused_connect_records_the_text_and_retries_after_30_s() {
        let _profile = crate::test_profile::temp();
        let mut app = App::new();
        let (tx, rx) = tokio::sync::oneshot::channel();
        app.astation_connect_rx = Some(rx);
        tx.send(Err(anyhow::Error::new(ServiceSuspendedError {
            text: TEXT.into(),
            origin: Some("https://station.test".into()),
        })))
        .ok()
        .unwrap();
        app.poll_astation_connect();
        assert_eq!(
            app.service_suspension,
            Some(Suspension {
                text: TEXT.into(),
                on: SuspendedOn::Connect,
                origin: Some("https://station.test".into()),
                notice: None,
                link_gen: 0,
            })
        );
        let at = app.astation_reconnect_at.expect("a retry");
        assert!(at >= Instant::now() + Duration::from_secs(29));
        assert_eq!(
            app.status_message.as_deref(),
            Some("service suspended: account disabled at Agora.Build; retrying")
        );
    }

    /// Review L10: a suspension that carries the local link's session
    /// advice records the text and keeps the advice for a waiting
    /// operation.
    #[test]
    fn a_refused_connect_keeps_the_local_links_session_advice() {
        let _profile = crate::test_profile::temp();
        let mut app = App::new();
        let (tx, rx) = tokio::sync::oneshot::channel();
        app.astation_connect_rx = Some(rx);
        let error = anyhow::Error::new(ServiceSuspendedError {
            text: TEXT.into(),
            origin: None,
        })
        .context(crate::runtime::ops::SessionAdvice("the advice".into()));
        tx.send(Err(error)).ok().unwrap();
        app.poll_astation_connect();
        assert!(app.service_suspension.is_some());
        assert_eq!(app.astation_connect_error.as_deref(), Some("the advice"));
    }

    /// Review L7: the local route's verdicts in the App: the Station's
    /// suspension of the proxy proof records the local link's text, the
    /// link kept; its `host_route_ok` lifts it; a relay's record survives an
    /// ok of the local link's (it says nothing of the relay).
    #[test]
    fn the_local_routes_verdicts_record_and_lift_the_local_text() {
        use crate::session_protocol::r9::route::RouteResult;
        let _profile = crate::test_profile::temp();
        let mut app = linked(LinkVia::Local, 3);
        app.local_route_verdict(Some(RouteResult::Suspended(TEXT.into())));
        assert_eq!(
            app.service_suspension.as_ref().map(|s| s.on),
            Some(SuspendedOn::Local { socket: 3 })
        );
        assert!(app.astation_connected, "the link stays");
        assert!(app.suspension_drop.is_none());
        let routed = RouteResult::Routed {
            host_id: "host".into(),
            head: atem_client::membership::Head {
                seq: 1,
                hash: atem_client::encoding::Hash32([0; 32]),
            },
        };
        app.local_route_verdict(Some(routed.clone()));
        assert!(app.service_suspension.is_none());
        app.service_suspension = Some(Suspension {
            text: TEXT.into(),
            on: SuspendedOn::Connect,
            origin: None,
            notice: None,
            link_gen: 0,
        });
        app.local_route_verdict(Some(routed));
        assert!(app.service_suspension.is_some(), "the relay's record stays");
        app.local_route_verdict(None);
        assert!(app.service_suspension.is_some());
    }

    #[test]
    fn a_relay_authentication_or_route_lifts_it_and_a_local_link_keeps_a_relay_record() {
        let _profile = crate::test_profile::temp();
        let mut app = app_on(7);
        app.local_link_suspension(None);
        assert!(app.service_suspension.is_some(), "a relay record stays");
        app.local_route_ok();
        assert!(app.service_suspension.is_some());
        app.suspension_lifted();
        assert!(app.service_suspension.is_none());
        // One read on a local link goes with that link.
        app.service_suspension = Some(Suspension {
            text: "t".into(),
            on: SuspendedOn::Local { socket: 3 },
            origin: None,
            notice: None,
            link_gen: 1,
        });
        app.local_link_suspension(None);
        assert!(app.service_suspension.is_none());
    }
}
