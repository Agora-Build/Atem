//! The alerts' push hints, in the bridge (session-v1 R9.9, "`outcome_unknown`
//! hint"; feature `host.alerts`; delegated host-work I.4.6, host-work-v1
//! §11.3, "The push hint"): at each pass the alerts committed since the last
//! look go to the r9 side, which signs one `outcome_unknown` hint per native
//! member holding `control` and resends it until the relay acknowledges it,
//! and the alerts that ended stop their hints. An alert is in the store
//! before its hint exists (durable before visible). Only with
//! `host.delegated` and `host.alerts` on: with the hook off nothing is read
//! and nothing is sent, as on main.
use super::*;

impl HostBridge {
    /// One look, after the pass's host work and before its relay flush:
    /// the alerts raised since ([`Store::alert_changes`]) are handed to the
    /// r9 side (`R9Host::alert_opened`, which sends nothing while push is
    /// suppressed), and the tracked ones that ended stop their hints
    /// (`R9Host::alert_ended`). Nothing is read while no alert was raised
    /// or ended; a failed read is tried again at the next pass.
    pub(in crate::runtime) fn alert_hint_pass(&mut self) {
        if !(self.features.delegated && self.features.alerts) {
            return;
        }
        let Some(store) = self.work.store.as_ref() else {
            return;
        };
        let tracked = self.r9.hinted_alerts();
        let Ok(changes) = store.alert_changes(&tracked) else {
            return;
        };
        if changes == crate::runtime::delegated::alerts::AlertChanges::default() {
            return;
        }
        self.r9_call(|r9, parts| {
            for alert_id in &changes.ended {
                r9.alert_ended(alert_id);
            }
            for alert in &changes.raised {
                r9.alert_opened(alert, parts);
            }
        });
    }
}
