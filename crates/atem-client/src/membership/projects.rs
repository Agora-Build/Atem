//! Signed project grants (delegated host-work design II.2.2): the
//! `project_set` and `project_remove` entries of the device list, what
//! follows from them on a verifier, and their typed builders.
//!
//! A project is a device-list entry signed by a native manager, so grants
//! share the log's signing, carriage, durable head, deferred entries, fences
//! and freeze rules (§R9.2–§R9.5). It names 2 to 64 current hosts and the
//! ops (`launch`, `message`, `notify`, `prompt`) every host it lists may
//! send to every other host it lists, through routes that consent (II.2.3).
//! `project_set` carries the project's whole new state, replacing any
//! project of that name; `project_remove` ends one in effect. Projects never
//! expire: one ends by `project_remove`, a narrowing `project_set` or
//! `remove_host`.
//!
//! **Membership.** A host counts in a project only if no `remove_host` of it
//! comes after the project's latest `project_set`. A host added again
//! (`add_host` after its `remove_host`) needs a new `project_set` that lists
//! it; a newer `add_host` without a removal (re-verification) keeps the host
//! in its projects. [`Membership::project`] is the project as signed;
//! [`Membership::project_hosts`], [`Membership::host_projects`] and
//! [`Membership::project_ops_between`] count memberships in effect only.
//!
//! Atem never signs these. Astation signs them only once every strict
//! verifier of the account knows them (the signing gate, II.2.2): a verifier
//! that doesn't know an action fails the whole chain at that entry.
use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Value, json};

use super::draft::verified;
use super::entry::{Action, field, id_ok, only_fields, str_field, string_set};
use super::{Invalid, Membership};

/// A project name is at most this long (the collaboration label grammar).
pub const MAX_PROJECT_NAME: usize = 32;
/// A project lists at least this many hosts.
pub const MIN_PROJECT_HOSTS: usize = 2;
/// A project lists at most this many hosts (as many as a log holds).
pub const MAX_PROJECT_HOSTS: usize = 64;

/// What a project lets its hosts send each other (II.2.2). A set on the
/// wire; the variants are in its canonical (byte) order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ProjectOp {
    Launch,
    Message,
    Notify,
    Prompt,
}

impl ProjectOp {
    pub const ALL: [ProjectOp; 4] = [
        ProjectOp::Launch,
        ProjectOp::Message,
        ProjectOp::Notify,
        ProjectOp::Prompt,
    ];

    /// The op of a wire name; `None` for any other string.
    pub fn parse(name: &str) -> Option<ProjectOp> {
        ProjectOp::ALL.into_iter().find(|op| op.as_str() == name)
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            ProjectOp::Launch => "launch",
            ProjectOp::Message => "message",
            ProjectOp::Notify => "notify",
            ProjectOp::Prompt => "prompt",
        }
    }
}

/// A project as a `project_set` signs it: its whole state. `hosts` and
/// `ops` are sets (sorted by bytes, no duplicates, §R9.2 "Arrays"), as
/// every parsed entry and [`project_set`] hold them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Project {
    pub name: String,
    pub hosts: Vec<String>,
    pub ops: Vec<ProjectOp>,
}

impl Project {
    /// The `project` object, lists as held.
    pub fn to_json(&self) -> Value {
        json!({
            "name": self.name,
            "hosts": self.hosts,
            "ops": self.ops.iter().map(|op| op.as_str()).collect::<Vec<_>>(),
        })
    }

    /// The rules of the `project` object alone (the signed-object parse
    /// already checked that its arrays are canonical sets): exactly `name`,
    /// `hosts` and `ops`, the name grammar, 2 to 64 host ids, a non-empty
    /// set of the four ops, and `notify` only with `message` and `prompt`.
    /// Whether each host is current is the chain's rule.
    pub(super) fn parse(value: &Value) -> Result<Project, Invalid> {
        let object = value.as_object().ok_or(Invalid::Malformed("project"))?;
        only_fields(object, &["name", "hosts", "ops"])?;
        let name = project_name(str_field(object, "name")?)?;
        let hosts = string_set(field(object, "hosts")?, "hosts")?;
        if !(MIN_PROJECT_HOSTS..=MAX_PROJECT_HOSTS).contains(&hosts.len())
            || !hosts.iter().all(|h| id_ok(h))
        {
            return Err(Invalid::BadProject);
        }
        let ops = string_set(field(object, "ops")?, "ops")?
            .iter()
            .map(|op| ProjectOp::parse(op))
            .collect::<Option<Vec<_>>>()
            .ok_or(Invalid::BadProject)?;
        let has = |op| ops.contains(&op);
        if ops.is_empty()
            || (has(ProjectOp::Notify) && !(has(ProjectOp::Message) && has(ProjectOp::Prompt)))
        {
            return Err(Invalid::BadProject);
        }
        Ok(Project { name, hosts, ops })
    }
}

/// 1 to 32 characters of `[a-z0-9-]` (collaboration §4's label grammar).
pub fn project_name_ok(name: &str) -> bool {
    (1..=MAX_PROJECT_NAME).contains(&name.len())
        && name
            .bytes()
            .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'-'))
}

/// A project name, or `BadProject`.
pub(super) fn project_name(name: &str) -> Result<String, Invalid> {
    if project_name_ok(name) {
        Ok(name.to_owned())
    } else {
        Err(Invalid::BadProject)
    }
}

/// A project in effect on a verifier: as last set, and the hosts it lists
/// whose membership is in effect (no `remove_host` of them since).
#[derive(Debug, Clone, PartialEq, Eq)]
struct InEffect {
    project: Project,
    members: BTreeSet<String>,
}

/// The projects in effect at a chain position (part of the derived state:
/// a pure function of the entries, replayed like the rest).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct Projects {
    by_name: BTreeMap<String, InEffect>,
}

impl Projects {
    /// `project_set`: the project's whole new state, every listed host a
    /// member (the chain checked each is current at `seq-1`).
    pub(super) fn set(&mut self, project: &Project) {
        self.by_name.insert(
            project.name.clone(),
            InEffect {
                project: project.clone(),
                members: project.hosts.iter().cloned().collect(),
            },
        );
    }

    /// `project_remove`.
    pub(super) fn remove(&mut self, name: &str) {
        self.by_name.remove(name);
    }

    /// `remove_host`: out of every project at once; only a later
    /// `project_set` that lists it brings it back.
    pub(super) fn host_removed(&mut self, host_id: &str) {
        for project in self.by_name.values_mut() {
            project.members.remove(host_id);
        }
    }

    pub(super) fn contains(&self, name: &str) -> bool {
        self.by_name.contains_key(name)
    }
}

impl Membership {
    /// The project `name` in effect, as its latest `project_set` signed it
    /// (its `hosts` may name hosts whose membership has since ended:
    /// [`Membership::project_hosts`]).
    pub fn project(&self, name: &str) -> Option<&Project> {
        self.derived.projects.by_name.get(name).map(|p| &p.project)
    }

    /// The projects in effect, by name.
    pub fn projects(&self) -> impl Iterator<Item = &Project> {
        self.derived.projects.by_name.values().map(|p| &p.project)
    }

    /// The hosts whose membership of the project `name` is in effect, in
    /// order (empty for a project not in effect).
    pub fn project_hosts(&self, name: &str) -> Vec<&str> {
        self.derived
            .projects
            .by_name
            .get(name)
            .map(|p| p.members.iter().map(String::as_str).collect())
            .unwrap_or_default()
    }

    /// The projects `host_id`'s membership of is in effect, by name.
    pub fn host_projects(&self, host_id: &str) -> Vec<&str> {
        self.derived
            .projects
            .by_name
            .iter()
            .filter(|(_, p)| p.members.contains(host_id))
            .map(|(name, _)| name.as_str())
            .collect()
    }

    /// What `a` and `b` may send each other: the union of the ops of every
    /// project in effect whose memberships of both are in effect. Empty
    /// when `a` is `b` (a project lets a host reach every *other* host it
    /// lists). Stage 3's `host:<id>` route consent reads it (II.2.3).
    pub fn project_ops_between(&self, a: &str, b: &str) -> BTreeSet<ProjectOp> {
        if a == b {
            return BTreeSet::new();
        }
        self.derived
            .projects
            .by_name
            .values()
            .filter(|p| p.members.contains(a) && p.members.contains(b))
            .flat_map(|p| p.project.ops.iter().copied())
            .collect()
    }
}

/// A `project_set` of `name` listing `hosts` with `ops`, as the verifier
/// parses it (its shape only; whether each host is current is checked
/// against the chain). Both lists are sets: any order, duplicates collapse.
/// `signed_at` is the time the manager signs it (display only).
pub fn project_set<I, S, O>(name: &str, hosts: I, ops: O, signed_at: u64) -> Result<Action, Invalid>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
    O: IntoIterator<Item = ProjectOp>,
{
    let hosts: BTreeSet<String> = hosts.into_iter().map(Into::into).collect();
    let ops: BTreeSet<ProjectOp> = ops.into_iter().collect();
    verified(
        Action::ProjectSet {
            project: Project {
                name: name.to_owned(),
                hosts: hosts.into_iter().collect(),
                ops: ops.into_iter().collect(),
            },
        },
        signed_at,
    )
}

/// A `project_remove` of `name`, as the verifier parses it (that a project
/// of that name is in effect is checked against the chain).
pub fn project_remove(name: &str, signed_at: u64) -> Result<Action, Invalid> {
    verified(
        Action::ProjectRemove {
            name: name.to_owned(),
        },
        signed_at,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn project_ops_are_in_wire_order() {
        let mut names: Vec<&str> = ProjectOp::ALL.iter().map(|op| op.as_str()).collect();
        let declared = names.clone();
        names.sort_unstable();
        assert_eq!(names, declared);
        let set: BTreeSet<ProjectOp> = ProjectOp::ALL.into_iter().rev().collect();
        assert_eq!(set.into_iter().collect::<Vec<_>>(), ProjectOp::ALL);
        assert_eq!(ProjectOp::parse("view"), None);
        assert_eq!(ProjectOp::parse("Launch"), None);
    }

    #[test]
    fn project_name_bounds() {
        assert!(project_name_ok("a"));
        assert!(project_name_ok(&"-".repeat(MAX_PROJECT_NAME)));
        assert!(!project_name_ok(&"a".repeat(MAX_PROJECT_NAME + 1)));
        assert!(!project_name_ok(""));
        for bad in ["A", "a_b", "a.b", "a:b", "a b", "é"] {
            assert!(!project_name_ok(bad), "{bad}");
        }
    }

    #[test]
    fn project_memberships_end_at_a_removal_and_return_with_a_set() {
        let project = |hosts: &[&str]| Project {
            name: "p".into(),
            hosts: hosts.iter().map(|h| h.to_string()).collect(),
            ops: vec![ProjectOp::Launch],
        };
        let mut projects = Projects::default();
        projects.set(&project(&["a", "b", "c"]));
        projects.host_removed("c");
        projects.host_removed("z");
        let members = |p: &Projects| p.by_name["p"].members.iter().cloned().collect::<Vec<_>>();
        assert_eq!(members(&projects), ["a", "b"]);
        assert_eq!(projects.by_name["p"].project.hosts, ["a", "b", "c"]);
        projects.set(&project(&["a", "c"]));
        assert_eq!(members(&projects), ["a", "c"]);
        assert!(projects.contains("p"));
        projects.remove("p");
        assert!(!projects.contains("p"));
    }
}
