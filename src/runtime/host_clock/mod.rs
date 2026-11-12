//! The delegated lifecycle's clock (host-work-v1 §11.6 "Clocks", design
//! I.6.5, owner decision 2026-11-10): automatic, host-local, with no command
//! and no network time. `os` takes the OS's readings; `state` applies §11.6's
//! rules to them.

// Read by the clock state and `HostClock`, which the runtime doesn't run yet.
#[allow(dead_code)]
pub mod os;
// Run by `HostClock`, which the runtime doesn't run yet.
#[allow(dead_code)]
pub mod state;
