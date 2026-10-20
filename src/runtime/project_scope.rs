//! Service `projects` scopes (atem-session-v1.md §R9.6): a session is in a
//! scope's `projects` when the keyed hash of its launch project key, under
//! the kid the scope entry names (`h1.<kid>.<hash>`), is listed.
//!
//! The launch project key is recorded with the session at launch
//! (`WorkerSpec::project_key`). Its hashes are made by the cred agent
//! (`K` never leaves it), in batched `Crypt` requests, on a background
//! thread, and cached: the runtime's pass never waits for the agent. Until
//! a hash is known (the agent is locked or absent, the account isn't
//! encrypting, the kid isn't held) the comparison is pending and the
//! session out of scope (fail closed). A known hash stays known: it never
//! changes for a session, and the spec's "until the first unlock" makes
//! the first successful comparison final for that kid.
use crate::memory::account_keys::CryptOp;
use crate::session_protocol::r9::ProjectScope;
use anyhow::{Result, anyhow};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// While a hash is missing, the agent is asked again this often (an
/// unlock, a newly granted `K`).
pub const RETRY: Duration = Duration::from_secs(5);
/// Hashes per `Crypt` request.
const BATCH: usize = 64;

/// Makes `h1.<kid>.<hash>` of each (project key, kid), in order.
pub trait ProjectHasher: Send + Sync {
    fn hash(&self, items: &[(String, String)]) -> Result<Vec<String>>;
}

/// The running cred agent of this profile (never started for this), for
/// the paired Astation's account.
pub struct AgentHasher {
    pub src: crate::profile::Sources,
}

impl ProjectHasher for AgentHasher {
    fn hash(&self, items: &[(String, String)]) -> Result<Vec<String>> {
        let state = crate::pairing::load(&self.src)?;
        let astation = state
            .binding
            .as_ref()
            .ok_or_else(|| anyhow!("not paired"))?
            .astation_id
            .clone();
        let agent = crate::memory::cred_agent::running_agent()
            .ok_or_else(|| anyhow!("the cred agent isn't running (locked)"))?;
        hash_with(agent.as_ref(), &astation, items)
    }
}

/// The kids the device list's services name in their `projects` scopes,
/// of the services that can be admitted now (in the list, not expired):
/// their hashes are made before a service even connects, so its first
/// `list` already sees its sessions (with the agent unlocked).
pub fn project_kids_of(m: &atem_client::membership::Membership, now_wall: u64) -> BTreeSet<String> {
    use atem_client::membership::entry::MemberKind;
    m.members()
        .into_iter()
        .filter_map(|id| match &m.member(id)?.member.kind {
            MemberKind::Service { scope, expires_at } if *expires_at > now_wall => {
                scope.projects.clone()
            }
            _ => None,
        })
        .flatten()
        .filter_map(|e| kid_of(&e).map(str::to_string))
        .collect()
}

/// `items` hashed by `agent` for the account of `astation_id`, in batched
/// `Crypt` requests (`K` stays in the agent).
pub fn hash_with(
    agent: &dyn crate::memory::cred_agent::CredAgentApi,
    astation_id: &str,
    items: &[(String, String)],
) -> Result<Vec<String>> {
    let mut out = Vec::with_capacity(items.len());
    for chunk in items.chunks(BATCH) {
        let ops = chunk
            .iter()
            .map(|(key, kid)| CryptOp::keyed_hash_under(key.as_bytes(), kid))
            .collect();
        for (result, (_, kid)) in agent.crypt(astation_id, ops)?.into_iter().zip(chunk) {
            let hash = result.into_text()?;
            // An agent that ignored the kid (an older build) hashed under
            // its current key: never cached as this kid's answer.
            if !hash.starts_with(&format!("h1.{kid}.")) {
                anyhow::bail!(
                    "the cred agent hashed under another key than {kid} (an older cred agent may be running: atem cred lock, then atem cred unlock)"
                );
            }
            out.push(hash);
        }
    }
    Ok(out)
}

/// A hasher over a given cred agent (tests: an injected or fake agent on
/// the same `Crypt` requests as [`AgentHasher`]).
#[cfg(test)]
pub struct CredAgentHasher {
    pub agent: Arc<dyn crate::memory::cred_agent::CredAgentApi>,
    pub astation_id: String,
}

#[cfg(test)]
impl ProjectHasher for CredAgentHasher {
    fn hash(&self, items: &[(String, String)]) -> Result<Vec<String>> {
        hash_with(self.agent.as_ref(), &self.astation_id, items)
    }
}

/// Tests: a cred agent that answers `Crypt` keyed hashes from a table
/// ((project key, kid) → `h1.` value) while "unlocked", and refuses as a
/// locked agent does otherwise; it counts the requests.
#[cfg(test)]
pub struct TableAgent {
    pub table: std::sync::Mutex<HashMap<Pair, String>>,
    pub unlocked: std::sync::Mutex<bool>,
    pub requests: std::sync::Mutex<usize>,
}

#[cfg(test)]
impl TableAgent {
    pub fn new(unlocked: bool) -> Arc<Self> {
        Arc::new(TableAgent {
            table: Default::default(),
            unlocked: std::sync::Mutex::new(unlocked),
            requests: Default::default(),
        })
    }
}

#[cfg(test)]
impl crate::memory::cred_agent::CredAgentApi for TableAgent {
    fn call(
        &self,
        request: crate::memory::cred_agent::Request,
    ) -> Result<crate::memory::cred_agent::Reply> {
        use crate::memory::account_keys::CryptOut;
        use crate::memory::cred_agent::{Reply, Request};
        use base64::Engine as _;
        *self.requests.lock().unwrap() += 1;
        let Request::Crypt { ops, .. } = request else {
            anyhow::bail!("not a crypt request");
        };
        if !*self.unlocked.lock().unwrap() {
            anyhow::bail!("the cred agent is locked; run atem cred unlock");
        }
        let table = self.table.lock().unwrap();
        let results = ops
            .into_iter()
            .map(|op| match op {
                CryptOp::KeyedHash { value, kid } => {
                    let key = String::from_utf8(
                        base64::engine::general_purpose::STANDARD.decode(value.as_bytes())?,
                    )?;
                    let kid = kid.ok_or_else(|| anyhow!("no kid"))?;
                    table
                        .get(&(key, kid.clone()))
                        .cloned()
                        .map(CryptOut::Hashed)
                        .ok_or_else(|| anyhow!("no retained key {kid}"))
                }
                _ => Err(anyhow!("unexpected op")),
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Reply::Crypted { results })
    }
}

type Pair = (String, String);
/// A job's kid and its outcome.
type Done = (String, Result<Vec<(Pair, String)>, String>);

/// The launch projects of the sessions and their known hashes.
pub struct ProjectScopes {
    hasher: Arc<dyn ProjectHasher>,
    keys: BTreeMap<String, String>,
    hashes: HashMap<Pair, String>,
    /// The kid of the job that is out (one at a time, one kid per job:
    /// a kid the agent can't hash never holds another back).
    pending: Option<String>,
    /// Per kid, after a failure: not asked again before then.
    retry_at: HashMap<String, Instant>,
    tx: mpsc::Sender<Done>,
    rx: mpsc::Receiver<Done>,
    /// Per kid, the last failure, logged once until it changes.
    failure: HashMap<String, String>,
}

fn kid_of(entry: &str) -> Option<&str> {
    entry
        .strip_prefix("h1.")?
        .split_once('.')
        .map(|(kid, _)| kid)
}

impl ProjectScopes {
    pub fn new(hasher: Arc<dyn ProjectHasher>) -> Self {
        let (tx, rx) = mpsc::channel();
        ProjectScopes {
            hasher,
            keys: BTreeMap::new(),
            hashes: HashMap::new(),
            pending: None,
            retry_at: HashMap::new(),
            tx,
            rx,
            failure: HashMap::new(),
        }
    }

    /// A session and its recorded launch project key (none: never in a
    /// `projects` scope).
    pub fn session(&mut self, sid: &str, key: Option<String>) {
        match key {
            Some(key) => {
                if self.keys.insert(sid.to_string(), key).is_none() {
                    // A new session is hashed at once.
                    self.retry_at.clear();
                }
            }
            None => self.forget(sid),
        }
    }

    pub fn forget(&mut self, sid: &str) {
        self.keys.remove(sid);
        self.hashes.retain(|(s, _), _| s != sid);
    }

    /// The scope kids in use now (`kids`): results that arrived (the
    /// sessions whose hashes became known: their scope may have changed),
    /// then a job for what is still missing.
    pub fn pass(&mut self, kids: &BTreeSet<String>, now: Instant) -> Vec<String> {
        let mut fresh = BTreeSet::new();
        while let Ok((kid, done)) = self.rx.try_recv() {
            self.pending = None;
            match done {
                Ok(results) => {
                    if self.failure.remove(&kid).is_some() {
                        eprintln!(
                            "atem runtime: project scopes: the cred agent hashes under {kid} again"
                        );
                    }
                    self.retry_at.remove(&kid);
                    for ((sid, kid), hash) in results {
                        if self.keys.contains_key(&sid) {
                            fresh.insert(sid.clone());
                            self.hashes.insert((sid, kid), hash);
                        }
                    }
                }
                Err(why) => {
                    if self.failure.get(&kid) != Some(&why) {
                        eprintln!(
                            "atem runtime: project scopes under {kid} pending (sessions stay out of the services that name it): {why}"
                        );
                        self.failure.insert(kid.clone(), why);
                    }
                    self.retry_at.insert(kid, now + RETRY);
                }
            }
        }
        if self.pending.is_none() {
            let due = kids.iter().find_map(|kid| {
                if self.retry_at.get(kid).is_some_and(|at| now < *at) {
                    return None;
                }
                let missing: Vec<(Pair, String)> = self
                    .keys
                    .iter()
                    .map(|(sid, key)| ((sid.clone(), kid.clone()), key.clone()))
                    .filter(|(pair, _)| !self.hashes.contains_key(pair))
                    .collect();
                (!missing.is_empty()).then(|| (kid.clone(), missing))
            });
            if let Some((kid, missing)) = due {
                self.pending = Some(kid.clone());
                self.spawn(kid, missing);
            }
        }
        fresh.into_iter().collect()
    }

    fn spawn(&self, kid: String, missing: Vec<(Pair, String)>) {
        let hasher = self.hasher.clone();
        let tx = self.tx.clone();
        #[cfg(test)]
        let carried = crate::test_profile::carry();
        std::thread::spawn(move || {
            #[cfg(test)]
            let _scope = carried.enter();
            let items: Vec<(String, String)> = missing
                .iter()
                .map(|((_, kid), key)| (key.clone(), kid.clone()))
                .collect();
            let done =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| hasher.hash(&items)))
                    .map_err(|_| "the hash job failed".to_string())
                    .and_then(|r| r.map_err(|e| e.to_string()))
                    .and_then(|hashes| {
                        if hashes.len() != missing.len() {
                            return Err(
                                "the cred agent answered a different number of hashes".into()
                            );
                        }
                        Ok(missing
                            .into_iter()
                            .map(|(pair, _)| pair)
                            .zip(hashes)
                            .collect())
                    });
            let _ = tx.send((kid, done));
        });
    }

    /// No job out and nothing missing for `kids` (tests).
    #[cfg(test)]
    pub fn idle(&self, kids: &BTreeSet<String>) -> bool {
        self.pending.is_none()
            && self.keys.keys().all(|sid| {
                kids.iter()
                    .all(|kid| self.hashes.contains_key(&(sid.clone(), kid.clone())))
            })
    }
}

impl ProjectScope for ProjectScopes {
    fn matches(&self, session_id: &str, entry: &str) -> Option<bool> {
        let kid = kid_of(entry)?;
        self.hashes
            .get(&(session_id.to_string(), kid.to_string()))
            .map(|hash| hash == entry)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// A hasher answering from a table while "unlocked".
    pub(crate) struct Table {
        pub unlocked: Mutex<bool>,
        pub calls: Mutex<usize>,
    }

    impl ProjectHasher for Table {
        fn hash(&self, items: &[(String, String)]) -> Result<Vec<String>> {
            *self.calls.lock().unwrap() += 1;
            if !*self.unlocked.lock().unwrap() {
                anyhow::bail!("locked");
            }
            Ok(items
                .iter()
                .map(|(key, kid)| format!("h1.{kid}.{}", key.len()))
                .collect())
        }
    }

    fn settle(p: &mut ProjectScopes, kids: &BTreeSet<String>, now: Instant) -> Vec<String> {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let fresh = p.pass(kids, now);
            if !fresh.is_empty() || p.pending.is_none() {
                return fresh;
            }
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// Review N1: a kid the agent doesn't hold (pruned after a rotation, a
    /// typo) never holds another kid back: the held kid's sessions come
    /// into scope, the unheld one stays out, with its own failure.
    #[test]
    fn an_unheld_kid_never_blocks_a_held_one() {
        let agent = TableAgent::new(true);
        agent
            .table
            .lock()
            .unwrap()
            .insert(("proj".into(), "k1".into()), "h1.k1.aa".into());
        let mut p = ProjectScopes::new(Arc::new(CredAgentHasher {
            agent: agent.clone(),
            astation_id: "astation-1".into(),
        }));
        p.session("ses-a", Some("proj".into()));
        let kids: BTreeSet<String> = ["k0-unheld".to_string(), "k1".to_string()].into();
        let deadline = Instant::now() + Duration::from_secs(5);
        while p.matches("ses-a", "h1.k1.aa").is_none() {
            assert!(Instant::now() < deadline, "the held kid was never hashed");
            p.pass(&kids, Instant::now());
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(p.matches("ses-a", "h1.k1.aa"), Some(true));
        assert_eq!(p.matches("ses-a", "h1.k0-unheld.aa"), None);
        assert!(
            p.failure
                .get("k0-unheld")
                .is_some_and(|why| why.contains("no retained key")),
            "{:?}",
            p.failure
        );
    }

    /// Review N2: an agent answering under another key than the one asked
    /// (an older build ignoring `kid`) is a failure, never cached.
    #[test]
    fn a_hash_under_another_kid_is_refused() {
        let agent = TableAgent::new(true);
        agent
            .table
            .lock()
            .unwrap()
            .insert(("proj".into(), "k1".into()), "h1.k2.aa".into());
        let error = hash_with(
            agent.as_ref(),
            "astation-1",
            &[("proj".into(), "k1".into())],
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("older cred agent"), "{error}");
    }

    /// Pending while locked (no answer, never a guess), retried every
    /// `RETRY`, known after the unlock; only the named kid counts.
    #[test]
    fn hashes_are_pending_while_locked_and_known_after_an_unlock() {
        let table = Arc::new(Table {
            unlocked: Mutex::new(false),
            calls: Mutex::new(0),
        });
        let mut p = ProjectScopes::new(table.clone());
        p.session("ses-a", Some("github.com/agora/atem".into()));
        p.session("ses-b", None);
        let kids: BTreeSet<String> = ["k1".to_string()].into();
        let t0 = Instant::now();
        p.pass(&kids, t0);
        while p.pending.is_some() {
            std::thread::sleep(Duration::from_millis(5));
            p.pass(&kids, t0);
        }
        assert_eq!(p.matches("ses-a", "h1.k1.21"), None, "locked: pending");
        // Not asked again before RETRY.
        p.pass(&kids, t0 + Duration::from_secs(1));
        assert!(p.pending.is_none());
        *table.unlocked.lock().unwrap() = true;
        p.pass(&kids, t0 + RETRY);
        assert!(p.pending.is_some());
        let fresh = settle(&mut p, &kids, t0 + RETRY);
        assert_eq!(fresh, vec!["ses-a".to_string()]);
        assert_eq!(p.matches("ses-a", "h1.k1.21"), Some(true));
        assert_eq!(p.matches("ses-a", "h1.k1.99"), Some(false));
        assert_eq!(
            p.matches("ses-a", "h1.k2.21"),
            None,
            "another kid: not asked yet"
        );
        assert_eq!(p.matches("ses-b", "h1.k1.21"), None, "no launch project");
        assert_eq!(p.matches("ses-a", "not-h1"), None);
        // Nothing missing: no more calls.
        let calls = *table.calls.lock().unwrap();
        p.pass(&kids, t0 + RETRY * 3);
        assert_eq!(*table.calls.lock().unwrap(), calls);
        p.forget("ses-a");
        assert_eq!(p.matches("ses-a", "h1.k1.21"), None);
    }
}
