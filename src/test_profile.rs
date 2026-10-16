//! Tests never reach the user's real profile (`~/.config/atem`), runtime
//! dir or key agent: under `cfg(test)` every function that resolves them
//! asks here, and this panics unless the test injected a temp profile
//! (`use_dir`) or a key agent (`use_agent`) on its thread. `blocking`
//! carries them to its worker thread (`carry`/`Carried::enter`).

use crate::memory::key_agent::KeyAgentApi;
use std::cell::RefCell;
use std::path::{Path, PathBuf};
use std::sync::Arc;

thread_local! {
    static DIR: RefCell<Option<PathBuf>> = const { RefCell::new(None) };
    static AGENT: RefCell<Option<Arc<dyn KeyAgentApi>>> = const { RefCell::new(None) };
}

/// What a test's panic says.
pub const REAL_PROFILE: &str =
    "a test reached the real atem profile; inject a temp one with test_profile::use_dir";
pub const REAL_AGENT: &str =
    "a test reached the real key agent; inject one with test_profile::use_agent";

/// Restores the previous injection when dropped.
#[must_use]
pub struct Scope {
    dir: Option<PathBuf>,
    agent: Option<Arc<dyn KeyAgentApi>>,
}

impl Drop for Scope {
    fn drop(&mut self) {
        DIR.with(|d| *d.borrow_mut() = self.dir.take());
        AGENT.with(|a| *a.borrow_mut() = self.agent.take());
    }
}

fn scope() -> Scope {
    Scope {
        dir: DIR.with(|d| d.borrow().clone()),
        agent: AGENT.with(|a| a.borrow().clone()),
    }
}

/// `dir` stands in for `~/.config/atem` on this thread.
pub fn use_dir(dir: &Path) -> Scope {
    let scope = scope();
    DIR.with(|d| *d.borrow_mut() = Some(dir.to_path_buf()));
    scope
}

/// `agent` stands in for the user's key agent on this thread.
pub fn use_agent(agent: Arc<dyn KeyAgentApi>) -> Scope {
    let scope = scope();
    AGENT.with(|a| *a.borrow_mut() = Some(agent));
    scope
}

/// A fresh temp profile for this thread, kept until both are dropped.
pub fn temp() -> (tempfile::TempDir, Scope) {
    let dir = tempfile::Builder::new()
        .prefix("atem-profile")
        .tempdir()
        .expect("a temp profile");
    let scope = use_dir(dir.path());
    (dir, scope)
}

/// The injected profile dir; panics without one.
pub fn dir() -> PathBuf {
    DIR.with(|d| d.borrow().clone())
        .unwrap_or_else(|| panic!("{REAL_PROFILE}"))
}

/// The injected key agent; panics without one.
pub fn agent() -> Arc<dyn KeyAgentApi> {
    AGENT
        .with(|a| a.borrow().clone())
        .unwrap_or_else(|| panic!("{REAL_AGENT}"))
}

/// This thread's injections, for another thread.
#[derive(Clone)]
pub struct Carried {
    dir: Option<PathBuf>,
    agent: Option<Arc<dyn KeyAgentApi>>,
}

pub fn carry() -> Carried {
    Carried {
        dir: DIR.with(|d| d.borrow().clone()),
        agent: AGENT.with(|a| a.borrow().clone()),
    }
}

impl Carried {
    pub fn enter(self) -> Scope {
        let scope = scope();
        DIR.with(|d| *d.borrow_mut() = self.dir);
        AGENT.with(|a| *a.borrow_mut() = self.agent);
        scope
    }
}

/// The injected agent behind the `Box` `default_agent` returns.
pub struct Injected(pub Arc<dyn KeyAgentApi>);

impl KeyAgentApi for Injected {
    fn call(
        &self,
        request: crate::memory::key_agent::Request,
    ) -> anyhow::Result<crate::memory::key_agent::Reply> {
        self.0.call(request)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_real_profile_and_agent_are_out_of_reach() {
        let profile = std::panic::catch_unwind(crate::config::AtemConfig::config_dir);
        assert!(
            profile.is_err(),
            "config_dir resolved without an injected profile"
        );
        assert!(std::panic::catch_unwind(crate::credentials::CredentialStore::path).is_err());
        assert!(std::panic::catch_unwind(crate::status::Sources::current).is_err());
        assert!(std::panic::catch_unwind(crate::auth::SessionManager::sessions_path).is_err());
        assert!(
            std::panic::catch_unwind(crate::memory::verification::KeyPaths::default_paths).is_err()
        );
        assert!(std::panic::catch_unwind(crate::rtc_test_server::servers_dir).is_err());
        assert!(std::panic::catch_unwind(crate::memory::key_agent::default_agent).is_err());
        assert!(std::panic::catch_unwind(crate::memory::key_agent::running_agent).is_err());
        assert!(std::panic::catch_unwind(crate::memory::agent_socket::agent_socket_path).is_err());
        assert!(std::panic::catch_unwind(crate::chat::claude::hooks::session_dir_root).is_err());
        // Injected: the temp profile.
        let temp = tempfile::tempdir().unwrap();
        let _scope = use_dir(temp.path());
        assert_eq!(crate::config::AtemConfig::config_dir(), temp.path());
        assert_eq!(
            crate::credentials::CredentialStore::path(),
            temp.path().join("credentials.enc")
        );
    }

    #[test]
    fn blocking_work_keeps_the_injection() {
        let temp = tempfile::tempdir().unwrap();
        let _scope = use_dir(temp.path());
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        let dir = runtime
            .block_on(crate::memory::key_agent::blocking(|| {
                Ok(crate::config::AtemConfig::config_dir())
            }))
            .unwrap();
        assert_eq!(dir, temp.path());
    }
}
