/// In-memory registry of the agents Atem launched (PTY sessions from
/// `atem agent launch`).
///
/// The registry is the single source of truth that Astation queries when it
/// wants to know which agents are available and what their current status is.
/// All mutations go through the registry so the rest of the codebase never
/// holds stale `AgentInfo` snapshots.
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use crate::agent_client::{AgentInfo, AgentStatus};

// ── AgentRegistry ─────────────────────────────────────────────────────────

/// Thread-safe, clone-friendly agent registry.
///
/// Cloning an `AgentRegistry` gives a second handle to the *same* data —
/// all writes are immediately visible through every clone.
#[derive(Clone, Default)]
pub struct AgentRegistry {
    inner: Arc<RwLock<HashMap<String, AgentInfo>>>,
}

impl AgentRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a new agent.  If an agent with the same `id` already exists
    /// it is replaced.  Returns the agent's `id`.
    pub fn register(&self, info: AgentInfo) -> String {
        let id = info.id.clone();
        self.inner.write().unwrap().insert(id.clone(), info);
        id
    }

    /// Retrieve a snapshot of an agent by ID.
    pub fn get(&self, id: &str) -> Option<AgentInfo> {
        self.inner.read().unwrap().get(id).cloned()
    }

    /// Return snapshots of all registered agents.
    pub fn all(&self) -> Vec<AgentInfo> {
        self.inner.read().unwrap().values().cloned().collect()
    }

    /// Update the status field of an existing agent.  No-ops silently if
    /// the ID is not found.
    pub fn update_status(&self, id: &str, status: AgentStatus) {
        if let Some(entry) = self.inner.write().unwrap().get_mut(id) {
            entry.status = status;
        }
    }

    /// Add a session ID to an agent's session list (deduplicating).
    pub fn add_session(&self, agent_id: &str, session_id: &str) {
        if let Some(entry) = self.inner.write().unwrap().get_mut(agent_id) {
            if !entry.session_ids.contains(&session_id.to_string()) {
                entry.session_ids.push(session_id.to_string());
            }
        }
    }

    /// Remove a session ID from an agent's session list.
    pub fn remove_session(&self, agent_id: &str, session_id: &str) {
        if let Some(entry) = self.inner.write().unwrap().get_mut(agent_id) {
            entry.session_ids.retain(|s| s != session_id);
        }
    }

    /// Remove an agent from the registry.  No-ops silently if not found.
    pub fn remove(&self, id: &str) {
        self.inner.write().unwrap().remove(id);
    }

    /// Return the number of registered agents.
    pub fn len(&self) -> usize {
        self.inner.read().unwrap().len()
    }

    /// Return true if no agents are registered.
    pub fn is_empty(&self) -> bool {
        self.inner.read().unwrap().is_empty()
    }

    /// Return all agents that are currently connected (not Disconnected).
    pub fn connected(&self) -> Vec<AgentInfo> {
        self.inner
            .read()
            .unwrap()
            .values()
            .filter(|a| a.status != AgentStatus::Disconnected)
            .cloned()
            .collect()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent_client::{AgentKind, AgentOrigin, AgentProtocol, AgentStatus};

    fn make_info(id: &str, protocol: AgentProtocol) -> AgentInfo {
        AgentInfo {
            id: id.to_string(),
            name: format!("agent-{id}"),
            kind: AgentKind::ClaudeCode,
            protocol,
            origin: AgentOrigin::Launched,
            status: AgentStatus::Idle,
            session_ids: vec![],
            acp_url: None,
            pty_pid: None,
        }
    }

    // ── register / get ────────────────────────────────────────────────────

    #[test]
    fn test_register_and_get() {
        let reg = AgentRegistry::new();
        let info = make_info("agent-1", AgentProtocol::Pty);
        reg.register(info.clone());
        let got = reg.get("agent-1").unwrap();
        assert_eq!(got.id, "agent-1");
        assert_eq!(got.name, "agent-agent-1");
    }

    #[test]
    fn test_get_nonexistent_returns_none() {
        let reg = AgentRegistry::new();
        assert!(reg.get("nope").is_none());
    }

    #[test]
    fn test_register_replaces_existing() {
        let reg = AgentRegistry::new();
        reg.register(make_info("a", AgentProtocol::Pty));

        let updated = AgentInfo {
            name: "updated-name".to_string(),
            ..make_info("a", AgentProtocol::Pty)
        };
        reg.register(updated);

        let got = reg.get("a").unwrap();
        assert_eq!(got.name, "updated-name");
        assert_eq!(got.protocol, AgentProtocol::Pty);
    }

    #[test]
    fn test_register_returns_id() {
        let reg = AgentRegistry::new();
        let returned = reg.register(make_info("agent-42", AgentProtocol::Pty));
        assert_eq!(returned, "agent-42");
    }

    // ── all ───────────────────────────────────────────────────────────────

    #[test]
    fn test_all_empty() {
        let reg = AgentRegistry::new();
        assert!(reg.all().is_empty());
    }

    #[test]
    fn test_all_returns_every_agent() {
        let reg = AgentRegistry::new();
        reg.register(make_info("a", AgentProtocol::Pty));
        reg.register(make_info("b", AgentProtocol::Pty));
        reg.register(make_info("c", AgentProtocol::Pty));

        let ids: Vec<_> = {
            let mut v: Vec<_> = reg.all().into_iter().map(|a| a.id).collect();
            v.sort();
            v
        };
        assert_eq!(ids, vec!["a", "b", "c"]);
    }

    // ── remove ────────────────────────────────────────────────────────────

    #[test]
    fn test_remove_existing() {
        let reg = AgentRegistry::new();
        reg.register(make_info("x", AgentProtocol::Pty));
        reg.remove("x");
        assert!(reg.get("x").is_none());
    }

    #[test]
    fn test_remove_nonexistent_is_noop() {
        let reg = AgentRegistry::new();
        reg.remove("ghost"); // should not panic
        assert!(reg.is_empty());
    }

    // ── update_status ─────────────────────────────────────────────────────

    #[test]
    fn test_update_status() {
        let reg = AgentRegistry::new();
        reg.register(make_info("a", AgentProtocol::Pty));

        reg.update_status("a", AgentStatus::Thinking);
        assert_eq!(reg.get("a").unwrap().status, AgentStatus::Thinking);

        reg.update_status("a", AgentStatus::Idle);
        assert_eq!(reg.get("a").unwrap().status, AgentStatus::Idle);
    }

    #[test]
    fn test_update_status_nonexistent_is_noop() {
        let reg = AgentRegistry::new();
        reg.update_status("ghost", AgentStatus::Thinking); // no panic
    }

    // ── session tracking ──────────────────────────────────────────────────

    #[test]
    fn test_add_session() {
        let reg = AgentRegistry::new();
        reg.register(make_info("a", AgentProtocol::Pty));

        reg.add_session("a", "sess-1");
        reg.add_session("a", "sess-2");

        let sessions = reg.get("a").unwrap().session_ids;
        assert_eq!(sessions.len(), 2);
        assert!(sessions.contains(&"sess-1".to_string()));
        assert!(sessions.contains(&"sess-2".to_string()));
    }

    #[test]
    fn test_add_session_deduplicates() {
        let reg = AgentRegistry::new();
        reg.register(make_info("a", AgentProtocol::Pty));

        reg.add_session("a", "sess-1");
        reg.add_session("a", "sess-1"); // duplicate

        assert_eq!(reg.get("a").unwrap().session_ids.len(), 1);
    }

    #[test]
    fn test_remove_session() {
        let reg = AgentRegistry::new();
        reg.register(make_info("a", AgentProtocol::Pty));

        reg.add_session("a", "sess-1");
        reg.add_session("a", "sess-2");
        reg.remove_session("a", "sess-1");

        let sessions = reg.get("a").unwrap().session_ids;
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0], "sess-2");
    }

    // ── len / is_empty ────────────────────────────────────────────────────

    #[test]
    fn test_len_and_is_empty() {
        let reg = AgentRegistry::new();
        assert_eq!(reg.len(), 0);
        assert!(reg.is_empty());

        reg.register(make_info("a", AgentProtocol::Pty));
        assert_eq!(reg.len(), 1);
        assert!(!reg.is_empty());

        reg.remove("a");
        assert_eq!(reg.len(), 0);
        assert!(reg.is_empty());
    }

    // ── connected ─────────────────────────────────────────────────────────

    #[test]
    fn test_connected_excludes_disconnected() {
        let reg = AgentRegistry::new();
        reg.register(make_info("active", AgentProtocol::Pty));
        reg.register(AgentInfo {
            status: AgentStatus::Disconnected,
            ..make_info("gone", AgentProtocol::Pty)
        });

        let connected = reg.connected();
        assert_eq!(connected.len(), 1);
        assert_eq!(connected[0].id, "active");
    }

    #[test]
    fn test_connected_includes_all_non_disconnected_states() {
        let reg = AgentRegistry::new();
        reg.register(make_info("idle", AgentProtocol::Pty));
        reg.register(AgentInfo {
            id: "thinking".into(),
            name: "thinking".into(),
            status: AgentStatus::Thinking,
            ..make_info("thinking", AgentProtocol::Pty)
        });
        reg.register(AgentInfo {
            id: "waiting".into(),
            name: "waiting".into(),
            status: AgentStatus::WaitingForInput,
            ..make_info("waiting", AgentProtocol::Pty)
        });

        assert_eq!(reg.connected().len(), 3);
    }

    // ── Clone shares state ────────────────────────────────────────────────

    #[test]
    fn test_clone_shares_inner_state() {
        let reg1 = AgentRegistry::new();
        let reg2 = reg1.clone();

        reg1.register(make_info("shared", AgentProtocol::Pty));

        // reg2 (clone) should see the new agent immediately
        assert!(reg2.get("shared").is_some());
    }

    // ── Concurrent access ─────────────────────────────────────────────────

    #[test]
    fn test_concurrent_registrations() {
        use std::sync::Arc;
        use std::thread;

        let reg = Arc::new(AgentRegistry::new());
        let mut handles = Vec::new();

        for i in 0..20 {
            let r = reg.clone();
            handles.push(thread::spawn(move || {
                r.register(make_info(&format!("agent-{i}"), AgentProtocol::Pty));
            }));
        }

        for h in handles {
            h.join().unwrap();
        }

        assert_eq!(reg.len(), 20);
    }
}
