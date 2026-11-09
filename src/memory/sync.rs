//! The learning loop: harvest what Claude learned → push local changes →
//! pull what other agents/machines learned → apply to every agent here.
use anyhow::{anyhow, bail, Result};
use serde_json::Value;
use std::collections::{BTreeMap, HashSet};
use std::future::Future;
use std::sync::Arc;
use crate::memory::adapters::{apply_memory, apply_skills, Agent, Ctx, ReportLine};
use crate::memory::api::{seal_cost, ApiError, ConflictCheck, KnowledgeClient, ModeRefusal, OpResult, SealState, StoredVersion, MAX_SKILL_VERSION, PULL_LIMIT, TEMPORARY_REFUSALS};
use crate::memory::crypto::{total, Planner};
use crate::memory::block::contains_reserved;
use crate::memory::harvest::{claude_memory_dir, harvest_dir, origin_prefix, Harvested};
use crate::memory::model::{content_hash, new_memory_id, now_secs, skill_hash, HeldSkill, Memory, PulledSkill, Scope, Skill};
use crate::memory::secrets::{find_secrets, skill_file_problems};
use crate::memory::store::{memory_cursor_key, skill_cursor_key, HarvestEntry, HarvestStatus, PendingOp, RefusedRun, Store, LAST_SYNC_AT, SYNC_RUNS};
#[cfg(test)]
use crate::memory::store::{MEMORY_CURSOR, SKILL_CURSOR};

const MEMORY_PUSH_CHUNK: usize = 50;
const SKILL_PUSH_CHUNK: usize = 8;

#[derive(Debug, Default, Clone, PartialEq)]
pub struct HarvestSummary {
    pub added: usize,
    /// Memories marked outdated because their file was edited (replaced)
    /// or deleted.
    pub invalidated: usize,
    pub held_back: Vec<String>,
}

/// Whether harvest may retire memory `id`, which is linked from `origin`:
/// this machine's Claude harvest created it, and no other harvested file
/// still points at it. A harvest can dedupe onto a CLI add, another
/// machine's memory, or a relay canonical id, and those must survive.
fn owns_memory(store: &Store, origin: &str, id: &str, atem_id: &str) -> Result<bool> {
    let ours = store.get_memory(id)?
        .map(|m| m.source_agent == "claude" && m.source_machine == atem_id)
        .unwrap_or(false);
    let shared = store.harvest_entries_for_memory(id)?.iter().any(|e| e.origin != origin);
    Ok(ours && !shared)
}

/// Invalidate `id` locally and queue the op; `successor` is recorded as its
/// replacement. Returns false, and queues nothing, when `id` is unknown,
/// deleted, or already invalid (invalidation is final).
pub fn invalidate_and_queue(store: &Store, id: &str, invalid_at: i64, successor: Option<&str>) -> Result<bool> {
    if !store.invalidate_memory(id, invalid_at, successor)? {
        return Ok(false);
    }
    if let Some(s) = successor {
        store.record_replacement(s, id)?;
    }
    store.enqueue(&PendingOp::InvalidateMemory {
        id: id.to_string(),
        invalid_at,
        superseded_by: successor.map(str::to_string),
    })?;
    Ok(true)
}

/// Replace `old` with `content`: same scope/project/machine/confidence. An
/// existing valid fact with the same text becomes the successor; otherwise
/// a new memory is added. The add is queued before the invalidate (same
/// batch unless a chunk boundary splits them). `old` stops being true when
/// the new fact starts (`valid_at`, else now). The caller has already run
/// the secret check on `content`. Returns the successor's id.
///
/// All-or-nothing: if `old` turns out to be outdated already (e.g. another
/// atem got there first), nothing is added or queued and it's an error.
pub fn replace_memory(store: &Store, old: &Memory, content: &str, valid_at: Option<i64>, source_agent: &str, source_machine: &str) -> Result<String> {
    let hash = content_hash(content);
    if hash == old.content_hash {
        bail!("That is the same fact as {}; nothing to replace.", old.id);
    }
    store.in_transaction(|| {
        let successor = match store.find_live_by_hash(old.scope, &old.project, &old.machine, &hash)? {
            Some(existing) => existing.id,
            None => {
                let m = Memory {
                    id: new_memory_id(), scope: old.scope, project: old.project.clone(), machine: old.machine.clone(),
                    content: content.to_string(), content_hash: hash.clone(), confidence: old.confidence.clone(),
                    source_agent: source_agent.to_string(), source_machine: source_machine.to_string(),
                    created_at: now_secs(), valid_at, ..Default::default()
                };
                store.upsert_memory(&m)?;
                store.enqueue(&PendingOp::AddMemory { memory: m.clone() })?;
                m.id
            }
        };
        if !invalidate_and_queue(store, &old.id, valid_at.unwrap_or_else(now_secs), Some(&successor))? {
            bail!("{} is already outdated; nothing changed. See `atem memory list --history {}`.", old.id, old.id);
        }
        Ok(successor)
    })
}

/// An edited file replaces its memory (the new fact is added, the old one
/// invalidated with `superseded_by`). A deleted file invalidates it. The
/// history is kept either way.
pub fn harvest_into_store(store: &Store, items: &[Harvested], prefix: &str, project_key: &str, atem_id: &str) -> Result<HarvestSummary> {
    let mut sum = HarvestSummary::default();
    let seen: HashSet<&str> = items.iter().map(|h| h.origin.as_str()).collect();
    for h in items {
        let prev = store.harvest_get(&h.origin)?;
        if prev.as_ref().is_some_and(|p| p.content_hash == h.hash) {
            continue; // unchanged (synced, held back, or excluded)
        }
        // The file changed: the memory it used to yield (if harvest owns it) is outdated.
        let outdated = match &prev {
            Some(p) if p.status == HarvestStatus::Synced && !p.memory_id.is_empty()
                && owns_memory(store, &h.origin, &p.memory_id, atem_id)? => Some(p.memory_id.clone()),
            _ => None,
        };
        let findings = find_secrets(&h.content);
        if !findings.is_empty() || contains_reserved(&h.content) {
            let why = if findings.is_empty() {
                "contains the reserved token atem:memory:".to_string()
            } else {
                findings.iter().map(|f| format!("{} {}", f.kind, f.masked)).collect::<Vec<_>>().join(", ")
            };
            // Nothing can replace it (the new text never leaves the machine).
            if let Some(old) = &outdated
                && invalidate_and_queue(store, old, now_secs(), None)? {
                sum.invalidated += 1;
            }
            store.harvest_put(&HarvestEntry { origin: h.origin.clone(), memory_id: String::new(), content_hash: h.hash.clone(), status: HarvestStatus::HeldBack })?;
            sum.held_back.push(format!("{} — {}", h.origin, why));
            continue;
        }
        let project = if h.scope == Scope::Project { project_key.to_string() } else { String::new() };
        let id = match store.find_live_by_hash(h.scope, &project, "", &h.hash)? {
            Some(existing) => existing.id,
            None => {
                let m = Memory {
                    id: new_memory_id(), scope: h.scope, project, machine: String::new(),
                    content: h.content.clone(), content_hash: h.hash.clone(), confidence: "medium".into(),
                    source_agent: "claude".into(), source_machine: atem_id.to_string(),
                    created_at: now_secs(), seq: 0, ..Default::default()
                };
                store.upsert_memory(&m)?;
                store.enqueue(&PendingOp::AddMemory { memory: m.clone() })?;
                sum.added += 1;
                m.id
            }
        };
        // Queued after the add, so both go out in order.
        if let Some(old) = &outdated
            && *old != id
            && invalidate_and_queue(store, old, now_secs(), Some(&id))? {
            sum.invalidated += 1;
        }
        store.harvest_put(&HarvestEntry { origin: h.origin.clone(), memory_id: id, content_hash: h.hash.clone(), status: HarvestStatus::Synced })?;
    }
    for e in store.harvest_with_prefix(prefix)? {
        if seen.contains(e.origin.as_str()) {
            continue;
        }
        if e.status == HarvestStatus::Synced && !e.memory_id.is_empty()
            && owns_memory(store, &e.origin, &e.memory_id, atem_id)?
            && invalidate_and_queue(store, &e.memory_id, now_secs(), None)? {
            sum.invalidated += 1;
        }
        store.harvest_remove(&e.origin)?;
    }
    Ok(sum)
}

fn describe(op: &PendingOp) -> String {
    match op {
        PendingOp::AddMemory { memory } => format!("memory {}", memory.id),
        PendingOp::DeleteMemory { id } => format!("delete of {}", id),
        PendingOp::InvalidateMemory { id, .. } => format!("invalidation of {}", id),
        PendingOp::PushSkill { skill, .. } => format!("skill {} v{}", skill.name, skill.version),
        PendingOp::DeleteSkill { name, .. } => format!("delete of skill {}", name),
        PendingOp::PurgeSkill { name, .. } => format!("purge of skill {}", name),
    }
}

pub const RELAY_UNAUTHORIZED_NOTE: &str = "The relay doesn't recognize this machine's Astation session. Make sure your Astation (latest version) is running and connected to the relay, then sync again. Changes stay queued.";
pub const RELAY_UNAVAILABLE_NOTE: &str = "The relay is temporarily unavailable; changes stay queued.";

/// The note shown for a relay request that failed with `e`. Every failure
/// leaves the changes queued.
pub fn relay_error_note(e: &ApiError) -> String {
    match e {
        ApiError::Http(401, _) => RELAY_UNAUTHORIZED_NOTE.to_string(),
        ApiError::Http(503, _) => RELAY_UNAVAILABLE_NOTE.to_string(),
        _ => e.to_string(),
    }
}

/// The note for one op the relay refused with 413 even on its own.
pub fn too_large_note(op: &PendingOp) -> String {
    format!("{} is too large for the relay; it stays queued", describe(op))
}

/// `apply_batch`'s notes.
#[cfg(test)]
pub fn apply_push_results(store: &Store, sent: &[(i64, PendingOp)], results: &[OpResult]) -> Result<Vec<String>> {
    Ok(apply_batch(store, sent, results, None)?.notes)
}

/// What applying a batch's results did (`apply_batch`).
#[derive(Debug, Default)]
struct Applied {
    notes: Vec<String>,
    /// The ops refused for now that stay queued (`Deferred::Retry`):
    /// nothing more of their skill or memory goes out in this sync.
    retried: Vec<PendingOp>,
    /// How many ops stay queued for a refusal for now (`Retry` and
    /// `AfterAdd`): not pushed.
    kept: usize,
}

/// Apply one batch's results. Every op is acked: successes are done, and
/// permanent refusals (e.g. the server's secret check) must not retry
/// forever. The exceptions:
/// - a skill push answered `version_conflict` (checked by
///   `check_conflicts`): a concurrent edit stays queued, re-based past the
///   Station's latest version (`coalesce_pushes`), and an unchecked one stays
///   as it was; only one a later push of the same skill in the batch
///   superseded is acked;
/// - a refusal for now (`OpResult::is_temporary_refusal`: the Station's
///   encryption mode or key differs from the one the op was sealed under,
///   and the op's own value isn't the cause) stays queued as it was, with a
///   note, unless a later op of the batch that landed withdrew it, and a
///   landed invalidation of a memory whose add it kept stays queued behind
///   that add (`defer_refusals`); after `REFUSED_FOR_NOW_SYNCS` syncs in a
///   row over at least `REFUSED_FOR_NOW_SECS` it is refused for good. In a
///   row: consecutive syncs (`SYNC_RUNS`) that sent it, sealed under the same
///   state (`sealed_under`: `SealState::fingerprint`; `None` in tests that
///   apply results directly); a refusal because this device isn't verified
///   (`ModeRefusal::Unverified`) never counts and ends a run.
///
/// A result count that doesn't match can't be paired
/// up, so nothing is acked: the batch stays queued and a note explains why.
///
/// One transaction: the batch's effects, re-bases and acks commit together,
/// before the caller reports anything. An error or a crash part way leaves
/// the whole batch queued as it was, and the next sync sends it again, as
/// after a sync that stopped between the POST and its results. Memory ops
/// are idempotent on the relay (add by id, delete, invalidate); a re-sent
/// skill push meets its own applied version, which `check_conflicts` finds
/// (a Station that renumbers, as before Astation PR #76, appends it again). It opens
/// that transaction itself, so it must not be called inside
/// `Store::in_transaction` (not nestable).
///
/// Returns the notes, and what stays queued for a refusal for now.
fn apply_batch(store: &Store, sent: &[(i64, PendingOp)], results: &[OpResult], sealed_under: Option<&SealState>) -> Result<Applied> {
    if results.len() != sent.len() {
        return Ok(Applied {
            notes: vec![format!(
                "relay returned {} results for {} changes; they stay queued for the next sync",
                results.len(), sent.len()
            )],
            ..Default::default()
        });
    }
    store.in_transaction(|| apply_paired_results(store, sent, results, sealed_under))
}

/// How many syncs in a row, over at least `REFUSED_FOR_NOW_SECS`, may
/// refuse an op for now before Atem stops retrying it (refused for good).
/// A sync runs after every local change too, so the time bound keeps an
/// ordinary rotation or migration race (minutes) from dropping an edit.
pub const REFUSED_FOR_NOW_SYNCS: i64 = 5;
pub const REFUSED_FOR_NOW_SECS: i64 = 24 * 3600;

fn apply_paired_results(store: &Store, sent: &[(i64, PendingOp)], results: &[OpResult], sealed_under: Option<&SealState>) -> Result<Applied> {
    let mut notes = Vec::new();
    let conflicts = settle_conflicts(sent, results);
    // Each refusal for now goes on its op's run, or starts a new one when
    // the last sync didn't send it or sealed it under another state; a
    // refusal because this device isn't verified is never counted. Refused
    // for now too often for too long: refused for good from here.
    let now = now_secs();
    let this_run = store.get_state(SYNC_RUNS)?;
    let state = sealed_under.map(SealState::fingerprint).unwrap_or_default();
    let mut given_up = BTreeMap::new();
    let mut runs = BTreeMap::new();
    for (i, (n, _)) in sent.iter().enumerate().filter(|(i, _)| results[*i].is_temporary_refusal()) {
        if results[i].mode_refusal == ModeRefusal::Unverified {
            runs.insert(i, RefusedRun::default());
            continue;
        }
        let last = store.refused_for_now(*n)?;
        let in_a_row = last.run == Some(this_run - 1) && last.state.as_deref() == Some(state.as_str());
        let run = RefusedRun {
            count: if in_a_row { last.count + 1 } else { 1 },
            since: if in_a_row { last.since.or(Some(now)) } else { Some(now) },
            run: Some(this_run),
            state: Some(state.clone()),
        };
        match run.since {
            Some(since) if run.count >= REFUSED_FOR_NOW_SYNCS && now - since >= REFUSED_FOR_NOW_SECS => {
                given_up.insert(i, (run.count, since));
            }
            _ => {
                runs.insert(i, run);
            }
        }
    }
    let deferred = defer_refusals(sent, results, &given_up);
    for (i, ((n, op), r)) in sent.iter().zip(results).enumerate() {
        if let Some(settled) = conflicts.get(&i) {
            // A conflicted push is acked only when this batch's later push,
            // delete or purge of the same skill landed; the others stay queued.
            if matches!(settled, Settled::Superseded | Settled::Withdrawn) {
                store.ack(*n)?;
            }
            continue;
        }
        match deferred.get(&i) {
            // Said once for the batch, below.
            Some(Deferred::Retry) => {
                if let Some(run) = runs.get(&i) {
                    store.set_refused_for_now(*n, run)?;
                }
                continue;
            }
            Some(Deferred::AfterAdd) => continue,
            // The delete or purge stands; nothing to add.
            Some(Deferred::Withdrawn) => {
                store.ack(*n)?;
                continue;
            }
            None => {}
        }
        if r.ok {
            match op {
                PendingOp::AddMemory { memory } => {
                    let id = match &r.canonical_id {
                        Some(c) if c != &memory.id => {
                            store.rewrite_memory_id(&memory.id, c)?;
                            c.clone()
                        }
                        _ => memory.id.clone(),
                    };
                    if let Some(seq) = r.seq {
                        store.set_memory_seq(&id, seq)?;
                    }
                }
                PendingOp::PushSkill { skill, .. } => {
                    if let (Some(v), Some(cur)) = (r.version, store.get_skill(skill.scope, &skill.project, &skill.name)?)
                        && cur.version == skill.version && v != skill.version {
                        let mut s = cur.clone();
                        s.version = v;
                        s.seq = r.seq.unwrap_or(s.seq);
                        store.put_skill(&s)?;
                    }
                    if r.superseded_concurrent {
                        notes.push(concurrent_note(skill, r.version.unwrap_or(skill.version)));
                    }
                }
                _ => {}
            }
        } else {
            let error = r.error.clone().unwrap_or_else(|| "unknown error".into());
            // A refused add stays here (local only, never synced) while its
            // row is live, unless the relay found a possible credential or
            // the reserved token: knowledge.db holds no secret, and the token
            // would break the managed blocks. A row deleted or purged here
            // since is neither kept nor quoted.
            let live = match op {
                PendingOp::AddMemory { memory } => store.get_memory(&memory.id)?.is_some_and(|row| !row.is_deleted()),
                _ => false,
            };
            let kept_here = match op {
                PendingOp::AddMemory { memory } if live && !refused_as_secret(&error) => Some(memory),
                _ => None,
            };
            let what = match kept_here {
                Some(memory) => format!("{} (\"{}\")", describe(op), excerpt(&memory.content)),
                None => describe(op),
            };
            let then = if kept_here.is_some() { "; it stays on this machine only, never synced" } else { "" };
            notes.push(match (&r.mode_refusal, given_up.get(&i)) {
                (ModeRefusal::Own(why), _) if kept_here.is_some() => format!("relay refused {what}: {error} ({why}){then}"),
                (ModeRefusal::Own(why), _) => format!("relay refused {what}: {error} ({why}); not sent again"),
                (_, Some((count, since))) => format!(
                    "relay refused {what} for now at {count} syncs in a row since {} UTC: {error}; Atem stopped retrying it (refused for good){then}",
                    crate::memory::model::format_datetime(*since)
                ),
                _ => format!("relay refused {what}: {error}{then}"),
            });
            if let PendingOp::AddMemory { memory } = op
                && live
                && kept_here.is_none() {
                store.mark_memory_deleted(&memory.id)?;
                for mut e in store.harvest_entries_for_memory(&memory.id)? {
                    e.memory_id = String::new();
                    e.status = HarvestStatus::HeldBack;
                    store.harvest_put(&e)?;
                }
            }
        }
        store.ack(*n)?;
    }
    notes.extend(refused_for_now_notes(sent, results, &deferred));
    notes.extend(settle_skills(store, sent, results, &conflicts)?);
    Ok(Applied {
        notes,
        retried: deferred.iter().filter(|(_, d)| **d == Deferred::Retry).map(|(&i, _)| sent[i].1.clone()).collect(),
        kept: deferred.values().filter(|d| **d != Deferred::Withdrawn).count(),
    })
}

/// Whether a refusal is the relay's secret check (a possible credential, or
/// the reserved token): what it refused must not stay in knowledge.db.
fn refused_as_secret(error: &str) -> bool {
    error.starts_with("possible credential") || error == "reserved token"
}

/// A fact's first line, at most 60 characters, to name it in a note.
fn excerpt(content: &str) -> String {
    let line = content.lines().next().unwrap_or_default();
    match line.char_indices().nth(60) {
        Some((cut, _)) => format!("{}…", &line[..cut]),
        None => line.to_string(),
    }
}

/// The note for a concurrent edit where this machine's edit already
/// landed as `version` (the latest now).
fn concurrent_note(skill: &Skill, version: i64) -> String {
    let scope_flag = if skill.scope == Scope::Project { " --scope project" } else { "" };
    format!(
        "skill {}: another machine pushed an edit at the same time; both versions are kept and v{} is now the latest. See them with `atem skill history {}{}`.",
        skill.name, version, skill.name, scope_flag
    )
}

/// The note for a concurrent edit settled by coalescing: what is true now
/// is that the other machine's `current` is the latest, and this machine's
/// edit goes on top as `next` at the next sync.
fn concurrent_pending_note(skill: &Skill, current: i64, next: i64) -> String {
    let scope_flag = if skill.scope == Scope::Project { " --scope project" } else { "" };
    format!(
        "skill {}: another machine pushed an edit at the same time; its v{current} is the latest for now, and this machine's edit will be pushed on top as v{next} at the next sync. Both versions are kept: see them with `atem skill history {}{}`.",
        skill.name, skill.name, scope_flag
    )
}

/// What a push answered `version_conflict` becomes (`check_conflicts` has
/// checked it).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Settled {
    /// A later push of the same skill in this batch landed: this one, older,
    /// is acked and never pushed again (the later one is a full snapshot
    /// built on it).
    Superseded,
    /// A later delete of the skill, or a purge of all its versions or of
    /// this one, landed in this batch: this push is acked and never pushed
    /// again, so it can't undo the delete or bring purged content back.
    Withdrawn,
    /// Another machine's edit holds the version: the skill's queued pushes
    /// are coalesced past it (`coalesce_pushes`).
    Rebased,
    /// It couldn't be settled (`ConflictCheck`): queued as it was.
    Unchecked,
}

type SkillKey = (Scope, String, String);

fn skill_key(skill: &Skill) -> (Scope, &str, &str) {
    (skill.scope, skill.project.as_str(), skill.name.as_str())
}

fn owned_key(skill: &Skill) -> SkillKey {
    (skill.scope, skill.project.clone(), skill.name.clone())
}

/// The skill an op writes (its push, delete or purge), if any.
fn op_skill_key(op: &PendingOp) -> Option<SkillKey> {
    match op {
        PendingOp::PushSkill { skill, .. } => Some(owned_key(skill)),
        PendingOp::DeleteSkill { scope, project, name } | PendingOp::PurgeSkill { scope, project, name, .. } => {
            Some((*scope, project.clone(), name.clone()))
        }
        _ => None,
    }
}

/// The batch's version conflicts on pushes, by index. A conflicted push
/// that a later landed push of the skill in this batch superseded is
/// `Superseded`; one a later landed delete, or a purge of all versions or of
/// its version, withdrew is `Withdrawn`. Per skill, the others are
/// `Rebased` only when every one of them was found a concurrent edit or a
/// Station behind the local copy (`Concurrent`, `Ahead`), else all
/// `Unchecked` (never a re-base of a push whose check failed: it may be
/// this Atem's own applied write).
fn settle_conflicts(sent: &[(i64, PendingOp)], results: &[OpResult]) -> BTreeMap<usize, Settled> {
    let pushed = |i: usize| match &sent[i].1 {
        PendingOp::PushSkill { skill, .. } => Some(skill),
        _ => None,
    };
    let conflicted: Vec<usize> = (0..sent.len())
        .filter(|&i| pushed(i).is_some() && results[i].is_version_conflict())
        .collect();
    let mooted = |i: usize, how: Settled| {
        let skill = pushed(i).unwrap();
        (i + 1..sent.len()).any(|j| results[j].ok && moots_push(&sent[j].1, skill) == Some(how))
    };
    let superseded = |i: usize| mooted(i, Settled::Superseded);
    let withdrawn = |i: usize| mooted(i, Settled::Withdrawn);
    let settled_later = |i: usize| superseded(i) || withdrawn(i);
    let all_concurrent = |i: usize| {
        let skill = pushed(i).unwrap();
        conflicted.iter()
            .filter(|&&j| !settled_later(j) && pushed(j).is_some_and(|other| skill_key(other) == skill_key(skill)))
            .all(|&j| matches!(results[j].check, ConflictCheck::Concurrent | ConflictCheck::Ahead))
    };
    conflicted.iter()
        .map(|&i| {
            let settled = if superseded(i) {
                Settled::Superseded
            } else if withdrawn(i) {
                Settled::Withdrawn
            } else if all_concurrent(i) {
                Settled::Rebased
            } else {
                Settled::Unchecked
            };
            (i, settled)
        })
        .collect()
}

/// What `later`, landed after a push of `skill` in the same batch, makes of
/// that push: a later push of the skill supersedes it (the later one is a
/// full snapshot built on it); a delete of the skill, or a purge of all its
/// versions or of the pushed one, withdraws it (it must not undo the delete
/// or bring purged content back).
fn moots_push(later: &PendingOp, skill: &Skill) -> Option<Settled> {
    match later {
        PendingOp::PushSkill { skill: later, .. } if skill_key(later) == skill_key(skill) => Some(Settled::Superseded),
        PendingOp::DeleteSkill { scope, project, name } if (*scope, project.as_str(), name.as_str()) == skill_key(skill) => {
            Some(Settled::Withdrawn)
        }
        PendingOp::PurgeSkill { scope, project, name, versions }
            if (*scope, project.as_str(), name.as_str()) == skill_key(skill)
                && versions.as_ref().is_none_or(|versions| versions.contains(&skill.version)) => Some(Settled::Withdrawn),
        _ => None,
    }
}

/// What an op refused for now (`OpResult::is_temporary_refusal`), or an op
/// that depends on one, becomes (`defer_refusals`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Deferred {
    /// Refused for now: queued as it was, sealed again and sent at the next
    /// sync (never again in this one: nothing more of its skill or memory
    /// goes out, `Held`).
    Retry,
    /// Refused (for now; for a memory add, in any way), but a later op of
    /// the batch that landed made it moot (`moots_push`, or a delete of that
    /// memory): acked and never sent, so deleted or purged content never
    /// goes back to the relay, and a refused fact purged since is neither
    /// kept here nor quoted.
    Withdrawn,
    /// Landed, but it invalidates a memory whose add was refused for now, so
    /// the Station had no such row and ignored it: queued, to go again after
    /// that add.
    AfterAdd,
}

/// The batch's refusals for now, by index, and the landed invalidations
/// that must follow their adds (`Deferred`). A refused add of a memory whose
/// delete (or purge) landed later in the batch is withdrawn, whatever the
/// refusal: never kept here, never quoted. Other ops refused for good are
/// not listed: they are acked as before, and so are the ones `given_up`
/// (refused for now too long).
fn defer_refusals<T>(sent: &[(i64, PendingOp)], results: &[OpResult], given_up: &BTreeMap<usize, T>) -> BTreeMap<usize, Deferred> {
    let mut deferred = BTreeMap::new();
    let refused = |i: usize| !results[i].ok && !results[i].is_version_conflict();
    for i in (0..sent.len()).filter(|&i| refused(i)) {
        let later = || (i + 1..sent.len()).filter(|&j| results[j].ok);
        let for_now = results[i].is_temporary_refusal();
        let withdrawn = match &sent[i].1 {
            PendingOp::PushSkill { skill, .. } => for_now && later().any(|j| moots_push(&sent[j].1, skill).is_some()),
            PendingOp::AddMemory { memory } => later().any(|j| matches!(&sent[j].1, PendingOp::DeleteMemory { id } if *id == memory.id)),
            _ => false,
        };
        if withdrawn {
            deferred.insert(i, Deferred::Withdrawn);
            continue;
        }
        if !for_now || given_up.contains_key(&i) {
            continue;
        }
        deferred.insert(i, Deferred::Retry);
        if let PendingOp::AddMemory { memory } = &sent[i].1 {
            for j in later().filter(|&j| matches!(&sent[j].1, PendingOp::InvalidateMemory { id, .. } if *id == memory.id)) {
                deferred.insert(j, Deferred::AfterAdd);
            }
        }
    }
    deferred
}

/// The notes for a batch's ops refused for now (`Deferred::Retry`): one per
/// reason and cause (`ModeRefusal`), naming the first few (a key rotation
/// can refuse a whole batch).
fn refused_for_now_notes(sent: &[(i64, PendingOp)], results: &[OpResult], deferred: &BTreeMap<usize, Deferred>) -> Vec<String> {
    let mut by_reason: Vec<((&str, bool), Vec<String>)> = Vec::new();
    for (&i, _) in deferred.iter().filter(|(_, d)| **d == Deferred::Retry) {
        let reason = (results[i].error.as_deref().unwrap_or_default(), results[i].mode_refusal == ModeRefusal::Unverified);
        let what = describe(&sent[i].1);
        match by_reason.iter_mut().find(|(r, _)| *r == reason) {
            Some((_, ops)) => ops.push(what),
            None => by_reason.push((reason, vec![what])),
        }
    }
    const NAMED: usize = 3;
    by_reason.into_iter()
        .map(|((reason, unverified), ops)| {
            let (what, stay) = match ops.len() {
                1 => (ops[0].clone(), "it stays queued and is"),
                n if n <= NAMED => (format!("{n} changes ({})", ops.join(", ")), "they stay queued and are"),
                n => (format!("{n} changes ({} and {} more)", ops[..NAMED].join(", "), n - NAMED), "they stay queued and are"),
            };
            if unverified {
                format!(
                    "relay refused {what} for now: {reason} (this device isn't verified, so it sends without end-to-end encryption, and the account encrypts); {stay} sent sealed once this device is verified: run `atem pair verify` (see `atem status`)."
                )
            } else {
                format!(
                    "relay refused {what} for now: {reason} (the account's encryption mode or key is changing); {stay} sealed again at the next sync. If this repeats, check `atem status` and that Astation is connected."
                )
            }
        })
        .collect()
}

/// Judges the batch's refusals in `TEMPORARY_REFUSALS` (`ModeRefusal`)
/// against each op as it went out (`wire`; the chunk sealed under `state`).
fn judge_mode_refusals(wire: &[Value], state: &SealState, posted: std::result::Result<Vec<OpResult>, ApiError>) -> std::result::Result<Vec<OpResult>, ApiError> {
    let mut results = posted?;
    if results.len() != wire.len() {
        return Ok(results);
    }
    for (sent, result) in wire.iter().zip(results.iter_mut()) {
        if !result.ok && result.error.as_deref().is_some_and(|error| TEMPORARY_REFUSALS.contains(&error)) {
            result.mode_refusal = mode_refusal(sent, state);
        }
    }
    Ok(results)
}

/// What a mode refusal of `sent` (an op's wire form) means. The Station
/// accepts a field only as its mode allows: while it encrypts, an envelope
/// or keyed hash under its current key; while off, a value that doesn't
/// start with `e1.` (text) or `h1.` (a hash); while disabling, either
/// (Astation `knowledge_routes.rs` `allowed_field` at 9eb5320).
/// - Sealed (a keyed `content_hash`): refused for good when its project is
///   a hash under another key than the rest of it (a project this machine
///   can't name, kept as an earlier key's hash), which never passes under
///   the current key; else the Station's key or mode isn't the one it was
///   sealed under (for now).
/// - Plain from a device that isn't verified: for now (it goes sealed once
///   the device is verified).
/// - Plain under a signed off or disabling state: refused for good when one
///   of its values starts like a sealed one (`e1.` text, a file's name or
///   text, an `h1.` project), which the Station refuses while off; else the
///   Station already encrypts (for now).
fn mode_refusal(sent: &Value, state: &SealState) -> ModeRefusal {
    let row = match sent["op"].as_str() {
        Some("add") => &sent["memory"],
        Some("push") => &sent["skill"],
        _ => return ModeRefusal::Changing,
    };
    let field = |name: &str| row[name].as_str().unwrap_or_default();
    let (project, content_hash) = (field("project"), field("content_hash"));
    let kid = atem_client::project::kid_of_project_hash;
    if content_hash.starts_with("h1.") || state.encrypts() {
        if kid(project).is_some() && kid(content_hash).is_some() && kid(project) != kid(content_hash) {
            return ModeRefusal::Own(
                "its project is kept as an earlier key's hash, a project this machine can't name, which the account's current key doesn't accept".into(),
            );
        }
        return ModeRefusal::Changing;
    }
    if !state.verified() {
        return ModeRefusal::Unverified;
    }
    let sealed_like = |text: &str| text.starts_with("e1.");
    let files = || {
        row["files"].as_object().into_iter().flatten().map(|(path, value)| {
            let text = value.as_str()
                .and_then(|text| base64::Engine::decode(&base64::engine::general_purpose::STANDARD, text).ok())
                .and_then(|bytes| String::from_utf8(bytes).ok())
                .unwrap_or_default();
            (path.clone(), text)
        })
    };
    let why = if project.starts_with("h1.") {
        Some("its project is kept as a key's hash, a project this machine can't name")
    } else if sealed_like(field("content")) {
        Some("its text starts with `e1.`")
    } else if files().any(|(path, _)| sealed_like(&path)) {
        Some("a file's name starts with `e1.`")
    } else if files().any(|(_, text)| sealed_like(&text)) {
        Some("a file's text starts with `e1.`")
    } else {
        None
    };
    match why {
        Some(why) => ModeRefusal::Own(format!("{why}, which the relay takes for an encrypted value while the account's encryption is off")),
        None => ModeRefusal::Changing,
    }
}

/// The skills a batch's results coalesced past a concurrent edit: no later
/// op of theirs goes out in this sync (`push_group`).
fn rebased_skills(sent: &[(i64, PendingOp)], posted: &std::result::Result<Vec<OpResult>, ApiError>) -> Vec<SkillKey> {
    let Ok(results) = posted else { return Vec::new() };
    if results.len() != sent.len() {
        return Vec::new();
    }
    settle_conflicts(sent, results).into_iter()
        .filter(|(_, settled)| *settled == Settled::Rebased)
        .filter_map(|(i, _)| op_skill_key(&sent[i].1))
        .collect()
}

/// After a batch's acks, per skill with conflicts: a concurrent edit
/// coalesces its queued pushes past the Station's latest version, with the
/// note the concurrent-edit handling gives; an older push our own later
/// push superseded gets that note too; an unsettled conflict says why.
/// `Rebased` and `Unchecked` settle the whole skill once; `Superseded` and
/// `Withdrawn` are per push (already acked), so a later conflict of the
/// skill in the batch (a re-add after a delete) is still settled.
fn settle_skills(store: &Store, sent: &[(i64, PendingOp)], results: &[OpResult], conflicts: &BTreeMap<usize, Settled>) -> Result<Vec<String>> {
    let mut notes = Vec::new();
    let mut done: Vec<SkillKey> = Vec::new();
    for (&i, &settled) in conflicts {
        let PendingOp::PushSkill { skill, .. } = &sent[i].1 else { continue };
        let key = owned_key(skill);
        if done.contains(&key) {
            continue;
        }
        if matches!(settled, Settled::Rebased | Settled::Unchecked) {
            done.push(key);
        }
        let same = |j: &usize| matches!(&sent[*j].1, PendingOp::PushSkill { skill: other, .. } if skill_key(other) == skill_key(skill));
        match settled {
            Settled::Rebased => {
                // Past the latest version any of its conflicts reported
                // (`check_conflicts` checked each is below the safe bound).
                let current = conflicts.iter()
                    .filter(|(j, s)| **s == Settled::Rebased && same(j))
                    .filter_map(|(j, _)| results[*j].current_version)
                    .max()
                    .unwrap_or(0);
                let latest = coalesce_pushes(store, skill.scope, &skill.project, &skill.name, current)?;
                let ahead = conflicts.iter()
                    .filter(|(j, s)| **s == Settled::Rebased && same(j))
                    .all(|(j, _)| results[*j].check == ConflictCheck::Ahead);
                notes.push(if ahead { ahead_note(skill, current, latest) } else { concurrent_pending_note(skill, current, latest) });
            }
            Settled::Superseded => {
                let latest = (i + 1..sent.len()).filter(|j| same(j) && results[*j].ok)
                    .filter_map(|j| results[j].version)
                    .max();
                if results[i].check == ConflictCheck::Concurrent {
                    notes.push(concurrent_note(skill, latest.unwrap_or(skill.version)));
                }
            }
            // The delete or purge stands; nothing to add.
            Settled::Withdrawn => {}
            Settled::Unchecked => {
                // The first of the skill's conflicts that wasn't settleable says why.
                let why = conflicts.keys()
                    .filter(|j| same(j) && !matches!(results[**j].check, ConflictCheck::Concurrent | ConflictCheck::Ahead))
                    .map(|&j| (results[j].check, results[j].current_version))
                    .next()
                    .unwrap_or((ConflictCheck::NotChecked, None));
                notes.push(unsettled_note(skill, why));
            }
        }
    }
    Ok(notes)
}

/// The note for a push coalesced onto a Station that is behind the local
/// copy (no other machine's edit involved).
fn ahead_note(skill: &Skill, current: i64, version: i64) -> String {
    format!(
        "skill {}: the Station's latest version is v{current}, behind this machine's copy (a push it refused earlier, or a delete of a skill it didn't have); this edit goes out as v{version} at the next sync.",
        skill.name
    )
}

/// Why a conflicted push stays queued as it was.
fn unsettled_note(skill: &Skill, (check, current): (ConflictCheck, Option<i64>)) -> String {
    let why = match (check, current) {
        (ConflictCheck::ReadFailed, _) => format!("reading v{} to check it failed", skill.version),
        (ConflictCheck::NoCurrentVersion, _) => "the answer names no current version (a protocol error)".to_string(),
        (ConflictCheck::BadCurrentVersion, Some(current)) => {
            format!("the answer names v{current} as the latest, out of range (a protocol error)")
        }
        _ => "it couldn't be checked".to_string(),
    };
    format!("skill {}: the Station reports a version conflict, but {why}; it stays queued for the next sync.", skill.name)
}

/// Coalesces a skill's still-queued pushes into one, its newest: each push
/// is a full snapshot of the local skill when it was queued, so the newest
/// holds every earlier local edit. The others are acked (unpushed local
/// intermediates never become versions; the other machine's version stays
/// in history), and the newest goes out at `current + 1` on base `current`
/// (the Station's latest version), sealed again when it is sent: at the
/// next sync, since `push_group` holds the skill back for the rest of this
/// one. The local copy moves with it when it is that edit, as the
/// concurrent-edit handling renumbers it. Returns the version it takes.
fn coalesce_pushes(store: &Store, scope: Scope, project: &str, name: &str, current: i64) -> Result<i64> {
    let version = current.checked_add(1).ok_or_else(|| anyhow!("skill version {current} is out of range"))?;
    let pushes: Vec<(i64, Skill)> = store.pending()?.into_iter()
        .filter_map(|(n, op)| match op {
            PendingOp::PushSkill { skill, .. } if skill_key(&skill) == (scope, project, name) => Some((n, skill)),
            _ => None,
        })
        .collect();
    let Some(((newest_n, newest), older)) = pushes.split_last() else { return Ok(version) };
    for (n, _) in older {
        store.ack(*n)?;
    }
    let original = newest.version;
    store.replace_pending(*newest_n, &PendingOp::PushSkill { skill: Skill { version, ..newest.clone() }, base_version: current })?;
    if let Some(mut local) = store.get_skill(scope, project, name)?
        && local.version == original {
        local.version = version;
        store.put_skill(&local)?;
    }
    Ok(version)
}

/// A full page (more may follow) must move the cursor forward, or pulling
/// again would fetch the same page forever.
pub fn cursor_advances(page_max: i64, since: i64, page_len: usize) -> bool {
    page_len < PULL_LIMIT as usize || page_max > since
}

const STUCK_CURSOR_NOTE: &str = "relay returned a page that doesn't advance the cursor; stopping pull";

/// Returns the highest seq seen (the next cursor).
pub fn apply_pulled_memories(store: &Store, items: &[Memory]) -> Result<i64> {
    let mut max = 0;
    for m in items {
        max = max.max(m.seq);
        let mut row = m.clone();
        if row.is_deleted() {
            row.content.clear();
            row.content_hash.clear();
        }
        store.upsert_memory(&row)?;
    }
    Ok(max)
}

/// Keeps the highest version per skill. An equal version replaces the local
/// copy (the server is authoritative, e.g. a purge tombstone).
pub fn apply_pulled_skills(store: &Store, items: &[Skill]) -> Result<i64> {
    let mut max = 0;
    for s in items {
        max = max.max(s.seq);
        match store.get_skill(s.scope, &s.project, &s.name)? {
            Some(cur) if s.version < cur.version => {}
            _ => store.put_skill(s)?,
        }
    }
    Ok(max)
}

/// A pulled page with held rows: each readable row applied as
/// `apply_pulled_skills` does, clearing the holds it replaces (a later
/// version, a tombstone, or the held version itself purged or rewritten);
/// each held row recorded, unless a version this Atem already read
/// replaces it. Never applied, so never installed or injected.
///
/// Unpushed edits win locally: while a push of a skill is queued, no pulled
/// row of it replaces the local copy (or its directory). The remote version
/// stays in the relay's history, a note says so, and the queued push
/// settles through the version conflict (the last writer wins, both kept).
///
/// Returns the highest seq (the next cursor), held rows included: the pull
/// moves on; and the notes, given once the page committed.
pub fn apply_pulled_skill_rows(store: &Store, items: &[PulledSkill]) -> Result<(i64, Vec<String>)> {
    let mut max = 0;
    let mut notes = Vec::new();
    for item in items {
        max = max.max(item.seq());
        match item {
            PulledSkill::Row(skill) => {
                store.clear_held_skills(skill.scope, &skill.project, &skill.name, skill.version)?;
                // Read in this page's transaction, so another atem process
                // queuing an edit or acking a push meanwhile is seen.
                if let Some(local) = store.get_skill(skill.scope, &skill.project, &skill.name)?
                    && skill.version >= local.version
                    && store.has_queued_push(skill.scope, &skill.project, &skill.name)? {
                    // Its own push, applied but not acknowledged yet, comes
                    // back with the same content: nothing to say.
                    if skill.content_hash != local.content_hash {
                        notes.push(shadowed_note(skill));
                    }
                    continue;
                }
                apply_pulled_skills(store, std::slice::from_ref(skill))?;
            }
            PulledSkill::Held(held) => {
                let replaced = store.get_skill(held.scope, &held.project, &held.name)?
                    .is_some_and(|read| read.seq > 0 && read.version > held.version);
                if !replaced {
                    store.hold_skill(held)?;
                }
            }
        }
    }
    Ok((max, notes))
}

/// The note for a pulled version kept out of the local copy because an
/// edit of that skill here still waits to sync.
fn shadowed_note(skill: &Skill) -> String {
    let scope_flag = if skill.scope == Scope::Project { " --scope project" } else { "" };
    format!(
        "skill {}: another machine pushed an edit (v{}) while this machine's edit waits to sync; this machine's edit stays here and goes out after it, and both versions are kept. See them with `atem skill history {}{}`.",
        skill.name, skill.version, skill.name, scope_flag
    )
}

pub fn apply_all(store: &Store, ctx: &Ctx) -> Result<Vec<ReportLine>> {
    let mems = store.live_memories()?;
    let skills = store.all_skills()?;
    let mut report = Vec::new();
    for agent in Agent::all() {
        if agent.discover(ctx) {
            report.extend(apply_memory(agent, ctx, &mems));
            report.extend(apply_skills(agent, ctx, &skills));
        }
    }
    Ok(report)
}

#[derive(Debug, Clone)]
pub struct SyncOptions {
    pub harvest: bool,
}

#[derive(Debug, Default)]
pub struct SyncOutcome {
    pub harvest: Option<HarvestSummary>,
    pub pushed: usize,
    /// Skills whose conflicted push was re-based onto the Station's latest
    /// version this sync; they go out at the next one.
    pub rebased: usize,
    pub pulled: usize,
    pub notes: Vec<String>,
    pub offline: bool,
    /// Some relay request failed (HTTP error, bad response, or unpaired
    /// results); what it carried stays queued. The sync isn't complete.
    pub relay_error: bool,
    pub report: Vec<ReportLine>,
}

impl SyncOutcome {
    /// Notes repeat per group/page otherwise (e.g. one 401 per request).
    fn note(&mut self, n: String) {
        if !self.notes.contains(&n) {
            self.notes.push(n);
        }
    }

    /// Record a failed request. `single` is the op when exactly one was sent
    /// (a 413 then means that op alone is too large).
    fn failed(&mut self, e: ApiError, single: Option<&PendingOp>) {
        match (e, single) {
            (ApiError::Offline(_), _) => self.offline = true,
            (ApiError::Http(413, _), Some(op)) => {
                self.relay_error = true;
                self.note(too_large_note(op));
            }
            (e, _) => {
                self.relay_error = true;
                self.note(relay_error_note(&e));
            }
        }
    }
}

/// Apply a POSTed chunk's results (`posted`). `Ok(true)`: acked, carry on
/// with the group; `Ok(false)`: results couldn't be paired up (nothing
/// acked), stop the group; `Err`: the request failed, nothing acked.
/// Ops refused for now (`Deferred::Retry`) are `held` for the rest of the
/// sync, and the sync is incomplete.
fn finish_chunk(store: &Store, chunk: &[(i64, PendingOp)], posted: std::result::Result<Vec<OpResult>, ApiError>, sealed_under: &SealState, held: &mut Held, out: &mut SyncOutcome) -> Result<std::result::Result<bool, ApiError>> {
    match posted {
        Ok(results) => {
            let applied = apply_batch(store, chunk, &results, Some(sealed_under))?;
            for note in applied.notes {
                out.note(note);
            }
            if results.len() != chunk.len() {
                out.relay_error = true;
                return Ok(Ok(false));
            }
            for op in &applied.retried {
                held.hold(op);
                out.relay_error = true;
            }
            // Only the acked ops count as pushed: a conflicted push that stays
            // queued (re-based, or unsettled) doesn't, nor does an op refused
            // for now or one queued behind it; the skills re-based are
            // counted apart.
            let conflicts = settle_conflicts(chunk, &results);
            let waiting = conflicts.values().filter(|s| matches!(s, Settled::Rebased | Settled::Unchecked)).count() + applied.kept;
            out.pushed += chunk.len() - waiting;
            out.rebased += rebased_skills(chunk, &Ok(results)).into_iter().collect::<HashSet<_>>().len();
            Ok(Ok(true))
        }
        Err(e) => Ok(Err(e)),
    }
}

/// What goes out no more in this sync (`push_group`): a skill coalesced
/// past a concurrent edit (the Station judges a batch's ops in order, so
/// only a later batch could see them out of order), and the skill or memory
/// of an op refused for now, with every later op naming it (a memory's
/// delete, its invalidation, or a replacement's invalidation naming it as
/// the successor), so nothing of it lands before it and nothing is sent
/// twice in one sync. Other skills and memories go on.
#[derive(Default)]
struct Held {
    skills: HashSet<SkillKey>,
    memories: HashSet<String>,
}

impl Held {
    fn holds(&self, op: &PendingOp) -> bool {
        match op {
            PendingOp::AddMemory { memory } => self.memories.contains(&memory.id),
            PendingOp::DeleteMemory { id } => self.memories.contains(id),
            PendingOp::InvalidateMemory { id, superseded_by, .. } => {
                self.memories.contains(id) || superseded_by.as_ref().is_some_and(|successor| self.memories.contains(successor))
            }
            _ => op_skill_key(op).is_some_and(|key| self.skills.contains(&key)),
        }
    }

    fn hold(&mut self, op: &PendingOp) {
        match op {
            PendingOp::AddMemory { memory } => {
                self.memories.insert(memory.id.clone());
            }
            _ => {
                if let Some(key) = op_skill_key(op) {
                    self.skills.insert(key);
                }
            }
        }
    }
}

/// The note for a memory batch carrying an invalidation that the relay
/// rejected as a bad request: a relay from before outdating facts existed.
pub fn invalidate_unsupported_note(queued: usize) -> String {
    format!("This relay doesn't support outdating facts yet — update the relay (Astation). {} change(s) stay queued.", queued)
}

/// Record the request for `sent` failing with `e`; the group stops there.
fn group_failed(store: &Store, e: ApiError, sent: &[(i64, PendingOp)], is_mem: bool, out: &mut SyncOutcome) -> Result<()> {
    if is_mem
        && matches!(e, ApiError::Http(400, _))
        && sent.iter().any(|(_, op)| matches!(op, PendingOp::InvalidateMemory { .. })) {
        let queued = store.pending()?.iter().filter(|(_, op)| op.is_memory()).count();
        out.relay_error = true;
        out.note(invalidate_unsupported_note(queued));
        return Ok(());
    }
    let single = if sent.len() == 1 { Some(&sent[0].1) } else { None };
    out.failed(e, single);
    Ok(())
}

/// One push group's ops sealed ahead of their POST (F2), by queue `n`: each
/// with the op as it was sealed (as read, with a project hash named since put
/// under its name: `seal_ops`) and the state its group was sealed under.
struct ReadAhead {
    sealed: BTreeMap<i64, (PendingOp, Value, Arc<SealState>)>,
    /// The last queue `n` a group was read through.
    through: i64,
}

/// Whether an op sealed ahead may be sent as sealed: the queued op, as it
/// would be sealed now (`KnowledgeClient::seal_state`), is still exactly the
/// op that was sealed, under the same state (mode, key, data account). An
/// earlier chunk's results or another writer may have changed the op, and a
/// project pulled as a hash may have been named since (resolution, or this
/// Atem hashing that project): either counts as a change, so the op is
/// sealed again, never sent under the hash it was sealed with.
fn reusable(sealed: &PendingOp, sealed_under: &SealState, op: &PendingOp, state: &SealState) -> bool {
    sealed == op && sealed_under == state
}

impl ReadAhead {
    fn new() -> Self {
        Self { sealed: BTreeMap::new(), through: i64::MIN }
    }

    fn add(&mut self, state: SealState, ns: &[i64], ops: Vec<(PendingOp, Value)>) {
        let state = Arc::new(state);
        for (&n, (op, wire)) in ns.iter().zip(ops) {
            self.sealed.insert(n, (op, wire, state.clone()));
        }
    }

    /// The sealed wire of each op of `chunk` (each op as it would be sealed
    /// now) that is `reusable`; `None` for the others (rewritten or named
    /// since, sealed under another state, or never read ahead). Forgets every
    /// entry up to the chunk's last op: sent now, or gone from the queue
    /// (acked or removed meanwhile).
    fn take(&mut self, chunk: &[(i64, PendingOp)], state: &SealState) -> Vec<Option<Value>> {
        let wire = chunk.iter()
            .map(|(n, op)| match self.sealed.remove(n) {
                Some((sealed, wire, under)) if reusable(&sealed, &under, op, state) => Some(wire),
                _ => None,
            })
            .collect();
        if let Some(&(last, _)) = chunk.last() {
            self.sealed = self.sealed.split_off(&last.saturating_add(1));
        }
        wire
    }
}

/// The queued ops of one kind after `after` that are sealed together as one
/// group: whole chunks, read `chunk` at a time as the push will send them,
/// planned by `Planner` (as the migration's groups: at most
/// `GROUP_REQUESTS` requests' worth per step, never more requests than
/// sealing each chunk alone; the run's `first` group is one chunk).
fn read_group(store: &Store, after: i64, is_mem: bool, chunk: usize, first: bool) -> Result<Vec<(i64, PendingOp)>> {
    let mut group: Vec<(i64, PendingOp)> = Vec::new();
    let mut planner = Planner::new(first);
    let mut cursor = after;
    loop {
        let read = store.pending_after(cursor, is_mem, chunk)?;
        let Some(&(last, _)) = read.last() else { return Ok(group) };
        if !planner.take(&total(&read, |(_, op)| seal_cost(op)), read.len()) {
            return Ok(group);
        }
        let whole = read.len() == chunk;
        group.extend(read);
        cursor = last;
        if !whole {
            return Ok(group);
        }
    }
}

/// Whether sealing `op` under `state` asked the cred agent: an op with a
/// protected field (a memory's content or project, a skill, a project-scoped
/// skill's delete or purge) while the account encrypts. Deletes and
/// invalidations of memories and a global skill's delete or purge never do,
/// so they never wait for the unlocked check and never start the agent.
fn sealed_by_agent(op: &PendingOp, state: &SealState) -> bool {
    state.encrypts() && seal_cost(op).iter().any(|step| step.ops > 0)
}

/// Whether some of `sealed` (as `seal_ops` returned them, under `state`)
/// asked the cred agent: a `Crypt` request that succeeded, which shows the
/// agent unlocked when it was answered.
fn asked_agent(state: &SealState, sealed: &[(PendingOp, Value)]) -> bool {
    sealed.iter().any(|(op, _)| sealed_by_agent(op, state))
}

/// Seals `group` into the read-ahead: whether that asked the cred agent
/// (`asked_agent`), or the seal's error.
async fn seal_ahead(client: &KnowledgeClient, ahead: &mut ReadAhead, group: Vec<(i64, PendingOp)>) -> std::result::Result<bool, ApiError> {
    let (ns, ops): (Vec<i64>, Vec<PendingOp>) = group.into_iter().unzip();
    let (state, sealed) = client.seal_ops(ops).await?;
    let asked = asked_agent(&state, &sealed);
    ahead.add(state, &ns, sealed);
    Ok(asked)
}

/// The wire form of every op of `chunk` (each op as it would be sealed now:
/// `KnowledgeClient::seal_state`; as sealed ahead where `reusable`, the
/// others sealed now, together), and whether its POST must first check
/// that the cred agent is still unlocked: some op goes out as sealed by an
/// earlier `Crypt` request (`sealed_by_agent`), and no `Crypt` request since
/// (`asked`: a group sealed in this pass, or this chunk's ops sealed again
/// now) showed the agent unlocked.
async fn chunk_wire(client: &KnowledgeClient, ahead: &mut ReadAhead, chunk: &[(i64, PendingOp)], state: &SealState, mut asked: bool) -> std::result::Result<(Vec<Value>, bool), ApiError> {
    let mut wire = ahead.take(chunk, state);
    let sealed_earlier = chunk.iter().zip(&wire).any(|((_, op), value)| value.is_some() && sealed_by_agent(op, state));
    let stale: Vec<usize> = (0..chunk.len()).filter(|&i| wire[i].is_none()).collect();
    if !stale.is_empty() {
        let (now, sealed) = client.seal_ops(stale.iter().map(|&i| chunk[i].1.clone()).collect()).await?;
        asked |= asked_agent(&now, &sealed);
        for (&i, (_, value)) in stale.iter().zip(sealed) {
            wire[i] = Some(value);
        }
    }
    let wire = wire.into_iter()
        .map(|value| value.ok_or_else(|| ApiError::Encryption("an op of the chunk was not sealed".into())))
        .collect::<std::result::Result<_, _>>()?;
    Ok((wire, sealed_earlier && !asked))
}

/// Push a group in chunks, in queue order. Any failure stops the group (its
/// remaining ops stay queued, preserving order). A chunk the relay refuses
/// as too large (413) is retried one op at a time; a single op that is still
/// too large is never acked — it stays queued with a note.
///
/// Each chunk is read from the queue just before it is sent, after `after`,
/// the last op sent (an `n > ?` cursor): every op is read once per group,
/// each send moves strictly forward in queue order, and a chunk carries what
/// an earlier chunk's results rewrote in still-queued ops (a relay canonical
/// id; the relay only knows the rewritten ids).
///
/// Sealing runs ahead of the chunks (F2): the ops are sealed in groups of
/// whole chunks (`read_group`; the first is chunk 1 alone), the next group
/// while the chunk before it is POSTed. A chunk sends an op as sealed ahead
/// only while it is `reusable`; any other op is sealed again first. Before a
/// chunk with ops the agent sealed in an earlier request is POSTed, the cred
/// agent must still be unlocked (a status, unless a `Crypt` request since
/// showed it), so a lock stops the push within one POST, as when each chunk
/// was sealed just before it. Ops sealed without the agent (deletes,
/// invalidations, a global skill's delete or purge) go out while it is
/// locked, as before read-ahead. A group that fails to seal stops the push
/// with that error (after the chunk in flight, whose results are applied
/// first); nothing is retried. A chunk's results are applied in their own
/// transaction after its POST, before the next chunk is read; no request is
/// in flight then. Before that, a skill chunk's version conflicts are
/// checked (`check_conflicts`, one GET each); a push one re-bases is sealed
/// again when its chunk goes (it no longer matches what was sealed ahead),
/// and a conflict that couldn't be checked stops the push. An op refused
/// for now (`defer_refusals`) holds back its skill or memory for the rest
/// of the sync (`Held`); the others go on.
async fn push_group(store: &Store, client: &KnowledgeClient, is_mem: bool, chunk_size: usize, out: &mut SyncOutcome) -> Result<()> {
    let mut after = i64::MIN;
    let mut ahead = ReadAhead::new();
    let mut held = Held::default();
    loop {
        if out.offline {
            return Ok(());
        }
        let read = store.pending_after(after, is_mem, chunk_size)?;
        let Some(&(last, _)) = read.last() else { return Ok(()) };
        let chunk: Vec<(i64, PendingOp)> = read.into_iter().filter(|(_, op)| !held.holds(op)).collect();
        if chunk.is_empty() {
            after = last;
            continue;
        }
        // The state ops are sealed under now, and the chunk's ops as they
        // would be sealed now (a project hash named since under its name):
        // what an op sealed ahead must still be to go out as sealed.
        let (state, named) = match client.seal_state(chunk.iter().map(|(_, op)| op.clone()).collect()) {
            Ok((state, named)) => (state, chunk.iter().map(|&(n, _)| n).zip(named).collect::<Vec<_>>()),
            Err(e) => return group_failed(store, e, &chunk, is_mem, out),
        };
        // The first group, or the read-ahead fell behind: seal from here.
        // Only a group that asked the agent (deletes and invalidations alone
        // don't) shows it is unlocked now.
        let mut asked = false;
        while last > ahead.through {
            let first = ahead.through == i64::MIN;
            let group = read_group(store, ahead.through.max(after), is_mem, chunk_size, first)?;
            ahead.through = group.last().map_or(last, |&(n, _)| n);
            match seal_ahead(client, &mut ahead, group).await {
                Ok(group_asked) => asked |= group_asked,
                Err(e) => return group_failed(store, e, &chunk, is_mem, out),
            }
        }
        let (wire, unchecked) = match chunk_wire(client, &mut ahead, &named, &state, asked).await {
            Ok(wire) => wire,
            Err(e) => return group_failed(store, e, &chunk, is_mem, out),
        };
        // Ops the agent sealed in an earlier request: still unlocked?
        if unchecked && let Err(e) = client.confirm_unlocked().await {
            return group_failed(store, e, &chunk, is_mem, out);
        }
        // Seal the next group while this chunk is in flight, once the
        // read-ahead no longer covers the next chunk.
        let next = if ahead.sealed.len() < chunk_size {
            read_group(store, ahead.through.max(last), is_mem, chunk_size, false)?
        } else {
            Vec::new()
        };
        let mut ahead_failed = None;
        let posted = if let Some(&(through, _)) = next.last() {
            ahead.through = through;
            let (ns, ops): (Vec<i64>, Vec<PendingOp>) = next.into_iter().unzip();
            let (posted, sealed) = tokio::join!(client.post_ops(&wire, is_mem), client.seal_ops(ops));
            match sealed {
                Ok((state, sealed)) => ahead.add(state, &ns, sealed),
                Err(e) => ahead_failed = Some(e),
            }
            posted
        } else {
            client.post_ops(&wire, is_mem).await
        };
        let posted = judge_mode_refusals(&wire, &state, check_conflicts(client, &chunk, &wire, posted).await);
        let unsettled = has_unchecked_conflict(&chunk, &posted);
        held.skills.extend(rebased_skills(&chunk, &posted));
        match finish_chunk(store, &chunk, posted, &state, &mut held, out)? {
            Ok(true) if unsettled => return conflict_unchecked(out),
            Ok(true) => {}
            Ok(false) => return Ok(()),
            Err(ApiError::Http(413, _)) if chunk.len() > 1 => {
                for ((n, sent), sealed) in named.iter().zip(&wire) {
                    // Re-read by `n`: an earlier single op may have rewritten it.
                    let Some(op) = store.pending_op(*n)? else { continue };
                    if held.holds(&op) {
                        continue;
                    }
                    let one = [(*n, op)];
                    let single = match client.seal_state(vec![one[0].1.clone()]) {
                        // Sealed before the chunk's POST: an op the agent
                        // sealed waits for the unlocked check, so a lock
                        // while the chunk was in flight stops it.
                        Ok((now, renamed)) if reusable(sent, &state, &renamed[0], &now) => {
                            let checked = if sealed_by_agent(sent, &state) { client.confirm_unlocked().await } else { Ok(()) };
                            checked.map(|()| (now, vec![sealed.clone()]))
                        }
                        Ok(_) => client.seal_ops(vec![one[0].1.clone()]).await
                            .map(|(now, ops)| (now, ops.into_iter().map(|(_, wire)| wire).collect())),
                        Err(e) => Err(e),
                    };
                    let (single_state, single) = match single {
                        Ok(single) => single,
                        Err(e) => return group_failed(store, e, &one, is_mem, out),
                    };
                    let posted = check_conflicts(client, &one, &single, client.post_ops(&single, is_mem).await).await;
                    let posted = judge_mode_refusals(&single, &single_state, posted);
                    let unsettled = has_unchecked_conflict(&one, &posted);
                    held.skills.extend(rebased_skills(&one, &posted));
                    match finish_chunk(store, &one, posted, &single_state, &mut held, out)? {
                        Ok(true) if unsettled => return conflict_unchecked(out),
                        Ok(true) => {}
                        Ok(false) => return Ok(()),
                        Err(e) => return group_failed(store, e, &one, is_mem, out),
                    }
                }
            }
            Err(e) => return group_failed(store, e, &chunk, is_mem, out),
        }
        // The next group failed to seal while this chunk was in flight: the
        // push stops here, as it did when that chunk's seal failed.
        if let Some(e) = ahead_failed {
            return group_failed(store, e, &[], is_mem, out);
        }
        after = last;
    }
}

/// The version conflicts of a skill batch's results, checked. The Station
/// stores a push at the version it was sealed under only when its base is
/// the skill's latest version (compare-and-set; Astation PR #76 at
/// 89a2d50, Atem #130), else answers `version_conflict` with
/// `current_version`. Atem reads its attempted version
/// (`/api/skills/version`): the same content hash and metadata as the push
/// (the files differ only in their nonces) is its own write, applied before
/// but never acknowledged (a lost answer, a crash before the results
/// committed), and counts as stored. Another write there, or a purged
/// (410) or missing (404) version, is a concurrent edit
/// (`ConflictCheck::Concurrent`). An attempted version above
/// `current_version` (the push's base is too: the local copy is ahead of
/// the Station) was never stored and is `Ahead`, with no GET; both settle
/// by coalescing. A version it couldn't read, or an answer with no usable
/// `current_version` (missing, or out of the safe range), leaves the
/// conflict unsettled. At most one GET per conflict, none without one.
async fn check_conflicts(
    client: &KnowledgeClient,
    sent: &[(i64, PendingOp)],
    wire: &[Value],
    posted: std::result::Result<Vec<OpResult>, ApiError>,
) -> std::result::Result<Vec<OpResult>, ApiError> {
    let mut results = posted?;
    if results.len() != sent.len() || results.len() != wire.len() {
        return Ok(results);
    }
    for (((_, op), sent), result) in sent.iter().zip(wire).zip(results.iter_mut()) {
        if !result.is_version_conflict() || !matches!(op, PendingOp::PushSkill { .. }) {
            continue;
        }
        let skill = &sent["skill"];
        let scope = skill["scope"].as_str().and_then(|scope| Scope::parse(scope).ok());
        let (Some(scope), Some(project), Some(name), Some(version)) =
            (scope, skill["project"].as_str(), skill["name"].as_str(), skill["version"].as_i64()) else { continue };
        let Some(current) = result.current_version else {
            result.check = ConflictCheck::NoCurrentVersion;
            continue;
        };
        // Out of JavaScript's safe integers, or leaving no room for the next
        // version: a protocol error. A latest version below the push's base
        // is legal (the local copy is ahead of the Station, e.g. after a
        // push it refused was acked): such a version was never stored, so
        // it is a concurrent edit just below, coalesced onto it.
        if !(0..MAX_SKILL_VERSION).contains(&current) {
            result.check = ConflictCheck::BadCurrentVersion;
            continue;
        }
        // Above the Station's latest version (its base is too): it was never
        // stored, and the local copy is ahead of the Station.
        if version > current {
            result.check = ConflictCheck::Ahead;
            continue;
        }
        result.check = match client.stored_skill(scope, project, name, version).await {
            Ok(StoredVersion::Row(stored)) if same_write(skill, &stored) => {
                *result = OpResult { ok: true, version: Some(stored.version), seq: Some(stored.seq), ..Default::default() };
                continue;
            }
            // Another write, or one purged (its content gone) or never
            // stored: not this push.
            Ok(StoredVersion::Row(_) | StoredVersion::Purged | StoredVersion::Missing) => ConflictCheck::Concurrent,
            Err(_) => ConflictCheck::ReadFailed,
        };
    }
    Ok(results)
}

/// Whether `stored` is the write `sent` (a push's skill as it went out):
/// the same content hash and metadata. The files aren't compared: every
/// seal has fresh nonces.
fn same_write(sent: &Value, stored: &Skill) -> bool {
    sent["scope"] == stored.scope.as_str()
        && sent["project"] == stored.project.as_str()
        && sent["name"] == stored.name.as_str()
        && sent["version"] == stored.version
        && sent["content_hash"] == stored.content_hash.as_str()
        && sent["deleted"] == stored.deleted
        && sent["source_agent"] == stored.source_agent.as_str()
        && sent["source_machine"] == stored.source_machine.as_str()
        && sent["created_at"] == stored.created_at
}

/// Whether the batch has a conflict that stays unsettled (`Settled::Unchecked`).
fn has_unchecked_conflict(sent: &[(i64, PendingOp)], posted: &std::result::Result<Vec<OpResult>, ApiError>) -> bool {
    posted.as_ref().is_ok_and(|results| {
        results.len() == sent.len() && settle_conflicts(sent, results).values().any(|s| *s == Settled::Unchecked)
    })
}

/// A conflict that couldn't be checked stops the push (its note given):
/// nothing after it goes this sync, so no later edit of that skill lands
/// before it is settled.
fn conflict_unchecked(out: &mut SyncOutcome) -> Result<()> {
    out.relay_error = true;
    Ok(())
}

async fn push_all(store: &Store, client: &KnowledgeClient, out: &mut SyncOutcome) -> Result<()> {
    push_group(store, client, true, MEMORY_PUSH_CHUNK, out).await?;
    push_group(store, client, false, SKILL_PUSH_CHUNK, out).await?;
    Ok(())
}

/// Pull cursors are per account (the paired Astation id); see
/// `memory_cursor_key`.
async fn pull_all(store: &Store, client: &KnowledgeClient, out: &mut SyncOutcome) -> Result<()> {
    let memories = {
        let (fetching, opening) = (client.clone(), client.clone());
        pull_pages(store, out, &memory_cursor_key(client.account()),
            move |since| {
                let client = fetching.clone();
                async move { client.fetch_memories(since).await }
            },
            move |rows| {
                let client = opening.clone();
                async move { client.open_memories(rows).await }
            },
            |store: &Store, rows: &[Memory]| Ok((apply_pulled_memories(store, rows)?, Vec::new())), |m: &Memory| m.seq).await?
    };
    if memories {
        let (fetching, opening) = (client.clone(), client.clone());
        // project_names.json, read once for the whole pull (only the agent's
        // pushes and the resolve step after the pull write it).
        let names = std::sync::Arc::new(std::sync::OnceLock::new());
        pull_pages(store, out, &skill_cursor_key(client.account()),
            move |since| {
                let client = fetching.clone();
                async move { client.fetch_skills(since).await }
            },
            move |rows: Vec<Skill>| {
                let (client, names) = (opening.clone(), names.clone());
                async move { client.open_skills(rows, names).await }
            },
            apply_pulled_skill_rows, |s: &Skill| s.seq).await?;
        let held = store.take_new_held_skills()?;
        if !held.is_empty() {
            out.note(held_note(&held));
        }
    }
    Ok(())
}

/// The sync note for skill versions held since the last one.
pub fn held_note(held: &[HeldSkill]) -> String {
    let which: Vec<String> = held.iter().map(|h| format!("{} v{} ({})", h.name, h.version, h.reason)).collect();
    format!(
        "{} skill version(s) can't open on this machine and are held: {}. They are never installed; a later version replaces them. See `atem memory status`.",
        held.len(), which.join(", ")
    )
}

/// A task's handle that aborts it when dropped: its result is never used.
/// Aborting stops the task at its next await; work it handed to the blocking
/// pool (an open in flight, `cred_agent::blocking`) still runs to its end,
/// and only its result is dropped.
struct AbortOnDrop<T>(tokio::task::JoinHandle<T>);

impl<T> Drop for AbortOnDrop<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// A fetched page: the cursor it was fetched from, its row count, and its
/// rows being opened on a task of their own.
struct FetchedPage<R> {
    since: i64,
    len: usize,
    opened: AbortOnDrop<std::result::Result<Vec<R>, ApiError>>,
}

impl<R> FetchedPage<R> {
    async fn opened(mut self) -> std::result::Result<Vec<R>, ApiError> {
        (&mut self.opened.0).await
            .unwrap_or_else(|e| Err(ApiError::Encryption(format!("opening the page didn't finish: {e}"))))
    }
}

/// One kind's pages from `since`, fetched in order on a task of their own,
/// each from the cursor the page before it ends at, and each opened on a task
/// of its own as it arrives (F2). At most one page beyond the one being
/// applied is fetched or opened: a page is fetched only once the page two
/// before it is committed (`permits`, one given back per committed page).
/// Dropping it aborts the fetching (a GET in flight is cancelled) and stops
/// waiting for the openings: an open already running on the blocking pool
/// runs to completion, holding the cred agent connection for that one
/// request, and its result is dropped. The pages not applied are discarded.
struct PagesInFlight<R> {
    pages: tokio::sync::mpsc::Receiver<std::result::Result<FetchedPage<R>, ApiError>>,
    permits: std::sync::Arc<tokio::sync::Semaphore>,
    _fetching: AbortOnDrop<()>,
}

impl<R: Send + 'static> PagesInFlight<R> {
    /// `fetch` gives a page's rows as the relay sent them (`Raw`, whose
    /// `seq` moves the cursor); `open` turns them into the rows applied.
    fn start<Raw, F, FF, O, OF>(since: i64, fetch: F, open: O, seq: fn(&Raw) -> i64) -> Self
    where
        Raw: Send + 'static,
        F: Fn(i64) -> FF + Send + 'static,
        FF: Future<Output = std::result::Result<Vec<Raw>, ApiError>> + Send + 'static,
        O: Fn(Vec<Raw>) -> OF + Send + 'static,
        OF: Future<Output = std::result::Result<Vec<R>, ApiError>> + Send + 'static,
    {
        let (tx, pages) = tokio::sync::mpsc::channel(2);
        let permits = std::sync::Arc::new(tokio::sync::Semaphore::new(2));
        let available = permits.clone();
        let fetching = tokio::spawn(async move {
            let mut since = since;
            loop {
                let Ok(permit) = available.acquire().await else { return };
                permit.forget();
                let (page, next) = match fetch(since).await {
                    Ok(rows) => {
                        let (len, max) = (rows.len(), rows.iter().map(seq).fold(0, i64::max));
                        // The next page starts where this one ends; none after
                        // a short page or one that doesn't move the cursor.
                        let next = (len >= PULL_LIMIT as usize && max > since).then_some(max);
                        let opened = AbortOnDrop(tokio::spawn(open(rows)));
                        (Ok(FetchedPage { since, len, opened }), next)
                    }
                    Err(e) => (Err(e), None),
                };
                if tx.send(page).await.is_err() {
                    return;
                }
                match next {
                    Some(next) => since = next,
                    None => return,
                }
            }
        });
        Self { pages, permits, _fetching: AbortOnDrop(fetching) }
    }
}

/// Pulls one kind's pages from its committed cursor `key`. Each page's rows
/// and its cursor commit in one transaction, before the page is counted: the
/// cursor never passes a row that isn't stored, and a page cut short (an
/// error, a crash) is pulled again whole (upserts are idempotent).
///
/// The next page is fetched and opened while this one is applied
/// (`PagesInFlight`, F2), from the cursor this one ends at. A page's
/// transaction never waits for that work; a page is applied only after the
/// one before it committed, from the committed cursor, and a page that
/// fails to open or apply discards the page after it unapplied (the next
/// sync starts from the committed cursor). `Ok(false)`: a request failed
/// (noted); stop pulling.
/// `apply` applies a page's rows in its transaction and returns the highest
/// seq (the next cursor) and the notes to give once it committed.
async fn pull_pages<Raw, R, F, FF, O, OF, A>(
    store: &Store,
    out: &mut SyncOutcome,
    key: &str,
    fetch: F,
    open: O,
    apply: A,
    seq: fn(&Raw) -> i64,
) -> Result<bool>
where
    Raw: Send + 'static,
    R: Send + 'static,
    A: Fn(&Store, &[R]) -> Result<(i64, Vec<String>)>,
    F: Fn(i64) -> FF + Clone + Send + 'static,
    FF: Future<Output = std::result::Result<Vec<Raw>, ApiError>> + Send + 'static,
    O: Fn(Vec<Raw>) -> OF + Clone + Send + 'static,
    OF: Future<Output = std::result::Result<Vec<R>, ApiError>> + Send + 'static,
{
    let mut since = store.get_state(key)?;
    let mut in_flight = PagesInFlight::start(since, fetch.clone(), open.clone(), seq);
    loop {
        let page = match in_flight.pages.recv().await {
            Some(Ok(page)) => page,
            Some(Err(e)) => {
                out.failed(e, None);
                return Ok(false);
            }
            // The fetching always ends with a last page or a failure.
            None => {
                out.failed(ApiError::Decode("the page requests stopped".into()), None);
                return Ok(false);
            }
        };
        if page.len == 0 {
            return Ok(true);
        }
        if page.since != since {
            // Another writer moved the cursor: start again from it.
            in_flight = PagesInFlight::start(since, fetch.clone(), open.clone(), seq);
            continue;
        }
        let len = page.len;
        let opened = match page.opened().await {
            Ok(opened) => opened,
            Err(e) => {
                out.failed(e, None);
                return Ok(false);
            }
        };
        let (max, notes) = store.in_transaction(|| {
            let (max, notes) = apply(store, &opened)?;
            store.set_state(key, max.max(since))?;
            Ok((max, notes))
        })?;
        // Only once the page committed.
        for note in notes {
            out.note(note);
        }
        in_flight.permits.add_permits(1);
        out.pulled += opened.len();
        if !cursor_advances(max, since, len) {
            out.note(STUCK_CURSOR_NOTE.into());
            return Ok(true);
        }
        if len < PULL_LIMIT as usize {
            return Ok(true);
        }
        since = store.get_state(key)?;
    }
}

/// Names the projects of rows pulled as hashes this Atem had no name for
/// (`model::is_unresolved_project`), once it has one: recorded since in
/// project_names.json, or learned now (the checkout this sync runs in, and
/// after a rotation the projects it already knows). Skills under a hash it
/// can never name are dropped (see `Store::resolve_projects`). Rows it
/// still can't name stay unresolved: kept, listed, never applied.
///
/// Runs once the pull is over (`pull_all` returns after its last page
/// committed, the pages fetched or opened beyond it discarded), never inside
/// a page's transaction: the agent's work comes first, then one transaction
/// of its own.
async fn resolve_projects(store: &Store, client: &KnowledgeClient, ctx: &Ctx) -> Result<()> {
    let hashes = store.unresolved_projects()?;
    if hashes.is_empty() {
        return Ok(());
    }
    let current = ctx.repo.as_ref().map(|repo| repo.key.clone());
    let naming = client.learn_project_names(hashes, current).await?;
    store.resolve_projects(&naming.named, &naming.stale)
}

/// `client = None` means offline: harvest and apply still run locally.
pub async fn run_sync(store: &Store, client: Option<&KnowledgeClient>, ctx: &Ctx, opts: &SyncOptions) -> Result<SyncOutcome> {
    let mut out = SyncOutcome::default();
    // Every run counts, offline too: a refusal for now is "in a row" only
    // across consecutive runs (`apply_batch`).
    store.set_state(SYNC_RUNS, store.get_state(SYNC_RUNS)? + 1)?;
    if opts.harvest
        && let Some(repo) = &ctx.repo {
        let dir = claude_memory_dir(&ctx.home, &repo.root);
        let items = harvest_dir(&dir, &ctx.atem_id)?;
        out.harvest = Some(harvest_into_store(store, &items, &origin_prefix(&ctx.atem_id, &dir), &repo.key, &ctx.atem_id)?);
    }
    match client {
        Some(c) => {
            // Never from sealed to plain text within this sync.
            let c = &c.for_sync();
            push_all(store, c, &mut out).await?;
            if !out.offline {
                pull_all(store, c, &mut out).await?;
            }
            // A failure only leaves those rows unresolved.
            if let Err(e) = resolve_projects(store, c, ctx).await {
                out.note(format!("rows of projects this machine doesn't know yet stay unapplied: {:#}", e));
            }
            // Only a sync where push and pull both finished cleanly counts.
            if !out.offline && !out.relay_error {
                store.set_state(LAST_SYNC_AT, now_secs())?;
            }
        }
        None => out.offline = true,
    }
    out.report = apply_all(store, ctx)?;
    Ok(out)
}

pub const SKILL_HISTORY_OFFLINE: &str = "Skill history lives on the relay, which is unreachable right now. Try again when you're online.";

pub const SKILL_HISTORY_UNAUTHORIZED: &str = "The relay doesn't recognize this machine's Astation session. Make sure your Astation (latest version) is running and connected to the relay, then try again.";
pub const SKILL_HISTORY_UNAVAILABLE: &str = "The relay is temporarily unavailable; try again shortly.";

/// A skill-history request failed: say why, plainly. Only a 404 whose body
/// is the Station's own "no such skill version" means the version is
/// missing; any other 404 (a route the relay doesn't have) is reported as
/// the error it is.
pub fn skill_history_error(e: ApiError, name: &str, version: Option<i64>) -> anyhow::Error {
    match (e, version) {
        (ApiError::Offline(_), _) => anyhow!(SKILL_HISTORY_OFFLINE),
        (ApiError::Http(401, _), _) => anyhow!(SKILL_HISTORY_UNAUTHORIZED),
        (ApiError::Http(503, _), _) => anyhow!(SKILL_HISTORY_UNAVAILABLE),
        (ApiError::Http(404, body), Some(v)) if crate::memory::api::is_missing_version(&body) => {
            anyhow!("Skill {} has no version {}. See `atem skill history {}`.", name, v, name)
        }
        (ApiError::Http(410, _), Some(v)) => anyhow!("v{} of skill {} was purged: its files were erased, so it can't be restored.", v, name),
        (e, _) => anyhow!("{}", e),
    }
}

/// Whether `atem skill purge` of `versions` (`None`: every version) may go
/// now. A purge that names versions waits while the skill has a queued push:
/// until it syncs, its version numbers can still move (a concurrent edit
/// coalesces this machine's pushes past another machine's version, and an
/// unsettled conflict stays queued too), so `--version N` could erase
/// another machine's version and leave the one meant, maybe a leaked
/// credential, in place. Purging every version needs no number and always
/// goes.
pub fn check_purge(store: &Store, scope: Scope, project: &str, name: &str, versions: Option<&[i64]>) -> Result<()> {
    if versions.is_none() || !store.has_queued_push(scope, project, name)? {
        return Ok(());
    }
    let scope_flag = if scope == Scope::Project { " --scope project" } else { "" };
    bail!(
        "Skill {name} has an edit on this machine that hasn't synced yet, so its version numbers can still change (a concurrent edit moves it past another machine's version). Run `atem sync`, then check `atem skill history {name}{scope_flag}` before purging a version. Nothing was purged; `--all-versions` purges every version now."
    )
}

/// Push the files of version `version` as a new version on top of the
/// current latest (the relay's newest, or this machine's if it has an
/// unpushed newer one). History is never rewritten. Refuses purged versions
/// and delete markers, and re-runs the secret check like `skill add`. Queues
/// the push; the caller syncs.
pub async fn restore_skill(store: &Store, client: &KnowledgeClient, atem_id: &str, scope: Scope, project: &str, name: &str, version: i64) -> Result<Skill> {
    let old = client.skill_version(scope, project, name, version).await
        .map_err(|e| skill_history_error(e, name, Some(version)))?;
    if old.deleted {
        bail!("v{} of skill {} is a delete marker; it has no files to restore. See `atem skill history {}`.", version, name, name);
    }
    let problems = skill_file_problems(&old.files);
    if !problems.is_empty() {
        bail!(
            "Refusing to restore v{} of skill {} — possible credentials (or unreadable files) found:\n  {}\nRemove the credential values; refer to credentials by name only.",
            version, name, problems.join("\n  ")
        );
    }
    let relay_latest = client.skill_versions(scope, project, name).await
        .map_err(|e| skill_history_error(e, name, None))?
        .iter().map(|v| v.version).max().unwrap_or(0);
    let local_latest = store.get_skill(scope, project, name)?.map(|s| s.version).unwrap_or(0);
    let base_version = relay_latest.max(local_latest);
    let files = old.files;
    let skill = Skill {
        scope, project: project.to_string(), name: name.to_string(), version: base_version + 1,
        content_hash: skill_hash(&files), files,
        source_agent: "cli".into(), source_machine: atem_id.to_string(), created_at: now_secs(), deleted: false, seq: 0,
    };
    store.put_skill(&skill)?;
    store.enqueue(&PendingOp::PushSkill { skill: skill.clone(), base_version })?;
    Ok(skill)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::model::{content_hash, skill_hash};
    use std::collections::BTreeMap;
    use std::path::Path;
    use std::sync::{Arc, Mutex};

    pub(super) fn valid(id: &str, content: &str) -> Memory {
        Memory {
            id: id.into(), scope: Scope::Global, content: content.into(), content_hash: content_hash(content),
            confidence: "high".into(), source_agent: "cli".into(), source_machine: "m1".into(), created_at: 1,
            ..Default::default()
        }
    }

    #[test]
    fn replace_queues_add_then_invalidate() {
        let s = Store::open_in_memory().unwrap();
        let old = valid("mem_old", "DialF listens on TCP 8765");
        s.upsert_memory(&old).unwrap();
        let new_id = replace_memory(&s, &old, "DialF listens on TCP 9000", Some(1_790_000_000), "cli", "m1").unwrap();
        let ops: Vec<PendingOp> = s.pending().unwrap().into_iter().map(|(_, op)| op).collect();
        assert_eq!(ops.len(), 2);
        let PendingOp::AddMemory { memory } = &ops[0] else { panic!("{:?}", ops[0]) };
        assert_eq!(
            (memory.id.as_str(), memory.content.as_str(), memory.valid_at, memory.confidence.as_str()),
            (new_id.as_str(), "DialF listens on TCP 9000", Some(1_790_000_000), "high")
        );
        assert_eq!(ops[1], PendingOp::InvalidateMemory { id: "mem_old".into(), invalid_at: 1_790_000_000, superseded_by: Some(new_id.clone()) });
        let o = s.get_memory("mem_old").unwrap().unwrap();
        assert_eq!((o.invalid_at, o.superseded_by.as_deref(), o.content.as_str()), (Some(1_790_000_000), Some(new_id.as_str()), "DialF listens on TCP 8765"));
        let live: Vec<String> = s.live_memories().unwrap().into_iter().map(|m| m.id).collect();
        assert_eq!(live, vec![new_id]);
    }

    #[test]
    fn replace_of_a_fact_invalidated_meanwhile_queues_nothing() {
        let s = Store::open_in_memory().unwrap();
        let old = valid("mem_old", "port 8765");
        s.upsert_memory(&old).unwrap();
        // Another process outdated it after we resolved `old`.
        s.invalidate_memory("mem_old", 5, None).unwrap();
        let err = replace_memory(&s, &old, "port 9000", None, "cli", "m1").unwrap_err().to_string();
        assert!(err.contains("already outdated"), "{err}");
        assert_eq!(s.pending_count().unwrap(), 0);
        assert!(s.live_memories().unwrap().is_empty()); // the add was rolled back too
        assert!(s.multi_successors().unwrap().is_empty());
        let o = s.get_memory("mem_old").unwrap().unwrap();
        assert_eq!((o.invalid_at, o.superseded_by), (Some(5), None));
    }

    #[test]
    fn invalidate_and_queue_is_final() {
        let s = Store::open_in_memory().unwrap();
        s.upsert_memory(&valid("mem_a", "A")).unwrap();
        assert!(invalidate_and_queue(&s, "mem_a", 10, None).unwrap());
        assert!(!invalidate_and_queue(&s, "mem_a", 20, Some("mem_b")).unwrap());
        assert!(!invalidate_and_queue(&s, "mem_nope", 20, None).unwrap());
        let a = s.get_memory("mem_a").unwrap().unwrap();
        assert_eq!((a.invalid_at, a.superseded_by), (Some(10), None));
        assert_eq!(s.pending_count().unwrap(), 1);
    }

    #[test]
    fn replace_reuses_an_existing_fact_and_refuses_the_same_fact() {
        let s = Store::open_in_memory().unwrap();
        let old = valid("mem_old", "port 8765");
        s.upsert_memory(&old).unwrap();
        s.upsert_memory(&valid("mem_9000", "port 9000")).unwrap();
        assert_eq!(replace_memory(&s, &old, "Port  9000", None, "cli", "m1").unwrap(), "mem_9000");
        let ops = s.pending().unwrap();
        assert_eq!(ops.len(), 1);
        assert!(matches!(&ops[0].1, PendingOp::InvalidateMemory { id, superseded_by: Some(sb), invalid_at } if id == "mem_old" && sb == "mem_9000" && *invalid_at > 0));
        let same = valid("mem_same", "same fact");
        s.upsert_memory(&same).unwrap();
        assert!(replace_memory(&s, &same, "SAME  fact", None, "cli", "m1").unwrap_err().to_string().contains("same fact as mem_same"));
    }

    #[test]
    fn canonical_rewrite_fixes_the_queued_invalidation() {
        let s = Store::open_in_memory().unwrap();
        let old = valid("mem_old", "port 8765");
        s.upsert_memory(&old).unwrap();
        replace_memory(&s, &old, "port 9000", None, "cli", "m1").unwrap();
        // Only the add went out (a chunk boundary fell between the two ops).
        let sent: Vec<_> = s.pending().unwrap().into_iter().take(1).collect();
        apply_push_results(&s, &sent, &[OpResult { ok: true, canonical_id: Some("mem_canon".into()), seq: Some(4), ..Default::default() }]).unwrap();
        let left = s.pending().unwrap();
        assert_eq!(left.len(), 1);
        assert!(matches!(&left[0].1, PendingOp::InvalidateMemory { id, superseded_by: Some(sb), .. } if id == "mem_old" && sb == "mem_canon"));
        assert_eq!(s.get_memory("mem_old").unwrap().unwrap().superseded_by.as_deref(), Some("mem_canon"));
    }

    const P: &str = "m1:/home/u/.claude/projects/x/memory/";

    fn h(file: &str, scope: Scope, content: &str) -> Harvested {
        Harvested { origin: format!("{}{}", P, file), scope, content: content.into(), hash: content_hash(content) }
    }

    fn harvest(s: &Store, items: &[Harvested]) -> HarvestSummary {
        harvest_into_store(s, items, P, "github.com/acme/dialf", "m1").unwrap()
    }

    #[test]
    fn new_harvest_adds_and_queues() {
        let s = Store::open_in_memory().unwrap();
        let sum = harvest(&s, &[h("a.md", Scope::Project, "DialF uses TCP 8765")]);
        assert_eq!(sum.added, 1);
        let live = s.live_memories().unwrap();
        assert_eq!(live[0].project, "github.com/acme/dialf");
        assert_eq!(live[0].source_agent, "claude");
        assert!(matches!(s.pending().unwrap()[0].1, PendingOp::AddMemory { .. }));
    }

    #[test]
    fn unchanged_harvest_is_a_noop() {
        let s = Store::open_in_memory().unwrap();
        let items = [h("a.md", Scope::Global, "Prefers ripgrep")];
        harvest(&s, &items);
        let sum = harvest(&s, &items);
        assert_eq!((sum.added, sum.invalidated), (0, 0));
        assert_eq!(s.pending_count().unwrap(), 1);
    }

    #[test]
    fn credential_is_held_back_once() {
        let s = Store::open_in_memory().unwrap();
        let items = [h("k.md", Scope::Project, "OpenAI key sk-abcdefghijklmnopqrstuvwx")];
        let sum = harvest(&s, &items);
        assert_eq!(sum.held_back.len(), 1);
        assert!(sum.held_back[0].contains("sk-…"));
        assert!(s.live_memories().unwrap().is_empty());
        assert_eq!(s.pending_count().unwrap(), 0);
        assert_eq!(s.held_back_count().unwrap(), 1);
        assert!(harvest(&s, &items).held_back.is_empty()); // not re-reported until the file changes
    }

    #[test]
    fn duplicate_content_reuses_existing_memory() {
        let s = Store::open_in_memory().unwrap();
        let existing = Memory {
            id: "mem_old".into(), scope: Scope::Global, project: String::new(), machine: String::new(),
            content: "Prefers ripgrep".into(), content_hash: content_hash("Prefers ripgrep"), confidence: "high".into(),
            source_agent: "cli".into(), source_machine: "m2".into(), created_at: 1, seq: 3, ..Default::default()
        };
        s.upsert_memory(&existing).unwrap();
        let sum = harvest(&s, &[h("a.md", Scope::Global, "prefers  RIPGREP")]);
        assert_eq!(sum.added, 0);
        assert_eq!(s.harvest_get(&format!("{}a.md", P)).unwrap().unwrap().memory_id, "mem_old");
    }

    fn invalidations_queued_for(s: &Store, id: &str) -> usize {
        s.pending().unwrap().iter().filter(|(_, op)| matches!(op, PendingOp::InvalidateMemory { id: d, .. } if d == id)).count()
    }

    #[test]
    fn changed_file_replaces_its_memory() {
        let s = Store::open_in_memory().unwrap();
        harvest(&s, &[h("a.md", Scope::Global, "v1 fact")]);
        let old = s.harvest_get(&format!("{}a.md", P)).unwrap().unwrap().memory_id;
        let sum = harvest(&s, &[h("a.md", Scope::Global, "v2 fact")]);
        assert_eq!((sum.added, sum.invalidated), (1, 1));
        let live = s.live_memories().unwrap();
        assert_eq!(live.len(), 1);
        assert_eq!(live[0].content, "v2 fact");
        let o = s.get_memory(&old).unwrap().unwrap();
        assert_eq!((o.content.as_str(), o.superseded_by.as_deref()), ("v1 fact", Some(live[0].id.as_str())));
        assert!(o.invalid_at.is_some());
        let kinds: Vec<&'static str> = s.pending().unwrap().iter().map(|(_, op)| match op {
            PendingOp::AddMemory { .. } => "add", PendingOp::InvalidateMemory { .. } => "invalidate", _ => "other",
        }).collect();
        assert_eq!(kinds, vec!["add", "add", "invalidate"]); // v1, v2, then v1's invalidation
        assert_eq!(s.harvest_get(&format!("{}a.md", P)).unwrap().unwrap().memory_id, live[0].id);
    }

    #[test]
    fn deleted_file_invalidates_its_memory() {
        let s = Store::open_in_memory().unwrap();
        harvest(&s, &[h("a.md", Scope::Global, "Prefers ripgrep")]);
        let id = s.harvest_get(&format!("{}a.md", P)).unwrap().unwrap().memory_id;
        let sum = harvest(&s, &[]);
        assert_eq!(sum.invalidated, 1);
        assert!(s.live_memories().unwrap().is_empty());
        assert!(matches!(&s.pending().unwrap().last().unwrap().1, PendingOp::InvalidateMemory { id: d, superseded_by: None, .. } if *d == id));
        assert_eq!(s.get_memory(&id).unwrap().unwrap().content, "Prefers ripgrep"); // kept as history
        assert!(s.harvest_with_prefix(P).unwrap().is_empty());
    }

    #[test]
    fn edit_to_a_credential_invalidates_the_old_fact_without_a_successor() {
        let s = Store::open_in_memory().unwrap();
        harvest(&s, &[h("a.md", Scope::Global, "Prefers ripgrep")]);
        let old = s.harvest_get(&format!("{}a.md", P)).unwrap().unwrap().memory_id;
        let sum = harvest(&s, &[h("a.md", Scope::Global, "key sk-abcdefghijklmnopqrstuvwx")]);
        assert_eq!((sum.added, sum.invalidated, sum.held_back.len()), (0, 1, 1));
        let m = s.get_memory(&old).unwrap().unwrap();
        assert!(m.invalid_at.is_some() && m.superseded_by.is_none());
    }

    #[test]
    fn changed_file_does_not_invalidate_shared_memory() {
        let s = Store::open_in_memory().unwrap();
        let existing = Memory {
            id: "mem_cli".into(), scope: Scope::Global, project: String::new(), machine: String::new(),
            content: "Prefers ripgrep".into(), content_hash: content_hash("Prefers ripgrep"), confidence: "high".into(),
            source_agent: "cli".into(), source_machine: "m1".into(), created_at: 1, seq: 3, ..Default::default()
        };
        s.upsert_memory(&existing).unwrap();
        harvest(&s, &[h("a.md", Scope::Global, "Prefers ripgrep")]);
        assert_eq!(s.harvest_get(&format!("{}a.md", P)).unwrap().unwrap().memory_id, "mem_cli");
        let sum = harvest(&s, &[h("a.md", Scope::Global, "Prefers fd")]);
        assert_eq!((sum.added, sum.invalidated), (1, 0));
        assert!(s.get_memory("mem_cli").unwrap().unwrap().is_valid());
        assert_eq!(invalidations_queued_for(&s, "mem_cli"), 0);
        // Deleting the file doesn't touch it either.
        harvest(&s, &[]);
        assert!(s.get_memory("mem_cli").unwrap().unwrap().is_valid());
        assert_eq!(invalidations_queued_for(&s, "mem_cli"), 0);
    }

    #[test]
    fn deleted_file_keeps_memory_other_origin_references() {
        let s = Store::open_in_memory().unwrap();
        harvest(&s, &[h("a.md", Scope::Global, "Prefers ripgrep"), h("b.md", Scope::Global, "prefers ripgrep")]);
        let id = s.harvest_get(&format!("{}a.md", P)).unwrap().unwrap().memory_id;
        assert_eq!(s.harvest_get(&format!("{}b.md", P)).unwrap().unwrap().memory_id, id);
        let sum = harvest(&s, &[h("b.md", Scope::Global, "prefers ripgrep")]);
        assert_eq!(sum.invalidated, 0);
        assert!(s.get_memory(&id).unwrap().unwrap().is_valid());
        assert_eq!(invalidations_queued_for(&s, &id), 0);
        assert!(s.harvest_get(&format!("{}a.md", P)).unwrap().is_none());
        // The last reference going away does invalidate it.
        assert_eq!(harvest(&s, &[]).invalidated, 1);
        assert!(!s.get_memory(&id).unwrap().unwrap().is_valid());
        assert_eq!(invalidations_queued_for(&s, &id), 1);
    }

    #[test]
    fn excluded_file_is_not_reharvested_until_changed() {
        let s = Store::open_in_memory().unwrap();
        harvest(&s, &[h("a.md", Scope::Global, "leaked thing")]);
        let origin = format!("{}a.md", P);
        let mut e = s.harvest_get(&origin).unwrap().unwrap();
        s.mark_memory_deleted(&e.memory_id).unwrap();
        e.status = HarvestStatus::Excluded;
        s.harvest_put(&e).unwrap();
        assert_eq!(harvest(&s, &[h("a.md", Scope::Global, "leaked thing")]).added, 0);
        assert_eq!(harvest(&s, &[h("a.md", Scope::Global, "cleaned thing")]).added, 1);
    }

    #[test]
    fn push_results_rewrite_canonical_id_and_ack() {
        let s = Store::open_in_memory().unwrap();
        harvest(&s, &[h("a.md", Scope::Global, "Prefers ripgrep")]);
        let sent = s.pending().unwrap();
        let PendingOp::AddMemory { memory } = &sent[0].1 else { panic!() };
        let local_id = memory.id.clone();
        let results = vec![OpResult { ok: true, canonical_id: Some("mem_canon".into()), seq: Some(9), ..Default::default() }];
        let notes = apply_push_results(&s, &sent, &results).unwrap();
        assert!(notes.is_empty());
        assert!(s.get_memory(&local_id).unwrap().is_none());
        assert_eq!(s.get_memory("mem_canon").unwrap().unwrap().seq, 9);
        assert_eq!(s.harvest_get(&format!("{}a.md", P)).unwrap().unwrap().memory_id, "mem_canon");
        assert_eq!(s.pending_count().unwrap(), 0);
    }

    #[test]
    fn refused_add_is_dropped_locally() {
        let s = Store::open_in_memory().unwrap();
        harvest(&s, &[h("a.md", Scope::Global, "something")]);
        let sent = s.pending().unwrap();
        let results = vec![OpResult { ok: false, error: Some("possible credential: jwt".into()), ..Default::default() }];
        let notes = apply_push_results(&s, &sent, &results).unwrap();
        assert!(notes[0].contains("possible credential"));
        assert!(s.live_memories().unwrap().is_empty());
        assert_eq!(s.pending_count().unwrap(), 0);
    }

    #[test]
    fn refused_harvested_add_is_marked_held_back() {
        let s = Store::open_in_memory().unwrap();
        let items = [h("a.md", Scope::Global, "something")];
        harvest(&s, &items);
        let sent = s.pending().unwrap();
        let results = vec![OpResult { ok: false, error: Some("possible credential: jwt".into()), ..Default::default() }];
        apply_push_results(&s, &sent, &results).unwrap();
        let origin = format!("{}a.md", P);
        let e = s.harvest_get(&origin).unwrap().unwrap();
        assert_eq!(e.status, HarvestStatus::HeldBack);
        assert!(e.memory_id.is_empty());
        assert_eq!(s.held_back_count().unwrap(), 1);
        let sum = harvest(&s, &items);
        assert_eq!(sum.added, 0);
        assert_eq!(s.pending_count().unwrap(), 0);
    }

    #[test]
    fn refused_add_holds_back_every_origin() {
        let s = Store::open_in_memory().unwrap();
        harvest(&s, &[h("a.md", Scope::Global, "same fact"), h("b.md", Scope::Global, "Same  fact")]);
        let sent = s.pending().unwrap();
        assert_eq!(sent.len(), 1);
        let results = vec![OpResult { ok: false, error: Some("possible credential".into()), ..Default::default() }];
        apply_push_results(&s, &sent, &results).unwrap();
        for f in ["a.md", "b.md"] {
            let e = s.harvest_get(&format!("{}{}", P, f)).unwrap().unwrap();
            assert_eq!(e.status, HarvestStatus::HeldBack, "{}", f);
            assert!(e.memory_id.is_empty());
        }
    }

    /// A fact the relay refuses for good, for anything but its secret check,
    /// stays here: its queued add is acked (never sent again), the row stays
    /// live (still injected here), its harvested file stays linked, and it
    /// counts as local only. A possible credential or the reserved token is
    /// removed here as before (knowledge.db holds no secret).
    #[test]
    fn a_fact_refused_for_good_stays_here_and_is_never_synced() {
        for (error, kept) in [
            ("invalid memory", true),
            ("id conflict", true),
            ("memory does not match the account encryption mode, maybe", true),
            ("possible credential: jwt", false),
            ("reserved token", false),
        ] {
            let s = Store::open_in_memory().unwrap();
            let items = [h("a.md", Scope::Global, "e1.example.com is the staging host")];
            harvest(&s, &items);
            let sent = s.pending().unwrap();
            let PendingOp::AddMemory { memory } = &sent[0].1 else { panic!("{sent:?}") };
            assert_eq!(s.local_only_count().unwrap(), 0, "{error}"); // queued, not local only
            let notes = apply_push_results(&s, &sent, &[refused(error)]).unwrap();
            assert_eq!(s.pending_count().unwrap(), 0, "{error}");
            let entry = s.harvest_get(&format!("{}a.md", P)).unwrap().unwrap();
            if kept {
                assert_eq!(notes, vec![format!(
                    "relay refused memory {} (\"e1.example.com is the staging host\"): {error}; it stays on this machine only, never synced",
                    memory.id
                )]);
                assert_eq!(s.live_memories().unwrap(), vec![memory.clone()], "{error}");
                assert_eq!((entry.status, entry.memory_id.as_str()), (HarvestStatus::Synced, memory.id.as_str()), "{error}");
                assert_eq!((s.held_back_count().unwrap(), s.local_only_count().unwrap()), (0, 1), "{error}");
            } else {
                assert_eq!(notes, vec![format!("relay refused memory {}: {error}", memory.id)]);
                assert!(s.live_memories().unwrap().is_empty(), "{error}");
                assert_eq!(entry.status, HarvestStatus::HeldBack, "{error}");
                assert_eq!(s.local_only_count().unwrap(), 0, "{error}");
            }
            // The unchanged file is never queued again.
            harvest(&s, &items);
            assert_eq!(s.pending_count().unwrap(), 0, "{error}");
        }
        // A long first line is cut in the note.
        let long = "x".repeat(80);
        assert_eq!(excerpt(&format!("{long}\nsecond")), format!("{}…", "x".repeat(60)));
        assert_eq!(excerpt("short"), "short");
    }

    /// The Station's refusals its contract makes temporary (Astation
    /// `relay-server/src/knowledge_routes.rs` and `knowledge_store.rs` at
    /// 9eb5320): a field that doesn't match the account's encryption mode or
    /// key there, from the route's check or the store's repeat of it.
    const FOR_NOW: [&str; 3] = [
        "memory does not match the account encryption mode",
        "skill does not match the account encryption mode",
        "content does not match the account encryption mode",
    ];

    fn refused(error: &str) -> OpResult {
        OpResult { ok: false, error: Some(error.into()), ..Default::default() }
    }

    fn landed() -> OpResult {
        OpResult { ok: true, seq: Some(1), ..Default::default() }
    }

    /// A refusal for now (a mode change, key rotation or migration racing
    /// the push) keeps the op queued as it was, with a note; a refused add
    /// stays live here and its harvested file stays synced.
    #[test]
    fn a_temporary_refusal_keeps_the_op_queued() {
        for error in FOR_NOW {
            let s = Store::open_in_memory().unwrap();
            let items = [h("a.md", Scope::Global, "Prefers ripgrep")];
            harvest(&s, &items);
            let skill = skill_v1("deploy", "# deploy steps", "m1");
            s.put_skill(&skill).unwrap();
            s.enqueue(&PendingOp::PushSkill { skill, base_version: 0 }).unwrap();
            let sent = s.pending().unwrap();
            let id = s.live_memories().unwrap()[0].id.clone();
            let notes = apply_push_results(&s, &sent, &[refused(error), refused(error)]).unwrap();
            assert_eq!(s.pending().unwrap(), sent, "{error}");
            // One note for the batch's refusals with the same reason.
            assert_eq!(notes, vec![format!(
                "relay refused 2 changes (memory {id}, skill deploy v1) for now: {error} (the account's encryption mode or key is changing); they stay queued and are sealed again at the next sync. If this repeats, check `atem status` and that Astation is connected."
            )], "{error}");
            assert_eq!(s.live_memories().unwrap().len(), 1, "{error}");
            let e = s.harvest_get(&format!("{}a.md", P)).unwrap().unwrap();
            assert_eq!(e.status, HarvestStatus::Synced, "{error}");
            assert_eq!(s.held_back_count().unwrap(), 0, "{error}");
        }
    }

    /// Any other refusal, or one with no reason, is permanent as before:
    /// acked, with a note naming the skill and the reason.
    #[test]
    fn a_permanent_skill_refusal_is_acked_with_its_reason() {
        let answers = [
            (refused("invalid skill"), "invalid skill"),
            (refused("invalid base64"), "invalid base64"),
            (refused("possible credential: SKILL.md: jwt"), "possible credential: SKILL.md: jwt"),
            (refused("invalid skill version"), "invalid skill version"),
            (refused("does not match the account encryption mode, maybe"), "does not match the account encryption mode, maybe"),
            (OpResult { ok: false, ..Default::default() }, "unknown error"),
        ];
        for (answer, why) in answers {
            let s = Store::open_in_memory().unwrap();
            let skill = skill_v1("deploy", "# deploy steps", "m1");
            s.put_skill(&skill).unwrap();
            s.enqueue(&PendingOp::PushSkill { skill, base_version: 0 }).unwrap();
            let notes = apply_push_results(&s, &s.pending().unwrap(), &[answer]).unwrap();
            assert_eq!(notes, vec![format!("relay refused skill deploy v1: {why}")], "{why}");
            assert_eq!(s.pending_count().unwrap(), 0, "{why}");
        }
    }

    /// What landed after an op refused for now in the same batch: a delete
    /// of that memory, or a purge of that skill's version (or of all of
    /// them), withdraws it (both acked: purged or deleted content never goes
    /// back to the relay); an invalidation of that memory, which the Station
    /// ignored (it has no such id yet), stays queued to go again after its
    /// add; anything else is acked as usual.
    #[test]
    fn what_lands_after_a_temporary_refusal_in_the_same_batch() {
        let error = FOR_NOW[0];
        // An add, then its invalidation and another fact's add.
        let s = Store::open_in_memory().unwrap();
        s.upsert_memory(&valid("mem_a", "port 8765")).unwrap();
        s.enqueue(&PendingOp::AddMemory { memory: valid("mem_a", "port 8765") }).unwrap();
        assert!(invalidate_and_queue(&s, "mem_a", 10, None).unwrap());
        s.upsert_memory(&valid("mem_b", "other")).unwrap();
        s.enqueue(&PendingOp::AddMemory { memory: valid("mem_b", "other") }).unwrap();
        let sent = s.pending().unwrap();
        apply_push_results(&s, &sent, &[refused(error), landed(), landed()]).unwrap();
        assert_eq!(s.pending().unwrap(), sent[..2].to_vec());
        // An add, then its delete (`memory purge`): both acked.
        let s = Store::open_in_memory().unwrap();
        s.upsert_memory(&valid("mem_a", "a leaked value")).unwrap();
        s.enqueue(&PendingOp::AddMemory { memory: valid("mem_a", "a leaked value") }).unwrap();
        s.mark_memory_deleted("mem_a").unwrap();
        s.enqueue(&PendingOp::DeleteMemory { id: "mem_a".into() }).unwrap();
        let notes = apply_push_results(&s, &s.pending().unwrap(), &[refused(error), landed()]).unwrap();
        assert_eq!(s.pending_count().unwrap(), 0, "{notes:?}");
        // A push, then a purge: of another version (the push stays), of its
        // own, or of every version (withdrawn).
        for (versions, stays) in [(Some(vec![7]), true), (Some(vec![1]), false), (None, false)] {
            let s = Store::open_in_memory().unwrap();
            let skill = skill_v1("deploy", "# a leaked value", "m1");
            s.put_skill(&skill).unwrap();
            s.enqueue(&PendingOp::PushSkill { skill, base_version: 0 }).unwrap();
            s.enqueue(&PendingOp::PurgeSkill { scope: Scope::Global, project: String::new(), name: "deploy".into(), versions: versions.clone() }).unwrap();
            let sent = s.pending().unwrap();
            apply_push_results(&s, &sent, &[refused(FOR_NOW[1]), landed()]).unwrap();
            let want = if stays { sent[..1].to_vec() } else { Vec::new() };
            assert_eq!(s.pending().unwrap(), want, "{versions:?}");
        }
        // A push, then the skill's delete: withdrawn.
        let s = Store::open_in_memory().unwrap();
        let skill = skill_v1("deploy", "# deploy steps", "m1");
        s.put_skill(&skill).unwrap();
        s.enqueue(&PendingOp::PushSkill { skill, base_version: 0 }).unwrap();
        s.enqueue(&PendingOp::DeleteSkill { scope: Scope::Global, project: String::new(), name: "deploy".into() }).unwrap();
        apply_push_results(&s, &s.pending().unwrap(), &[refused(FOR_NOW[2]), landed()]).unwrap();
        assert_eq!(s.pending_count().unwrap(), 0);
    }

    /// An op refused for now (the Station's account state ahead of this
    /// Atem's, or behind it) holds back its own skill or memory for the rest
    /// of the sync: it is sent once, a later edit of that skill isn't sent at
    /// all, and every other skill and memory goes on. The next sync seals
    /// them again and they land, in order, at the versions they were queued
    /// at.
    #[tokio::test]
    async fn an_edit_refused_for_now_holds_back_only_its_item_and_lands_at_the_next_sync() {
        let relay = Arc::new(Mutex::new(KeepingRelay::default()));
        let refuse = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let (refusing, keeping) = (refuse.clone(), relay.clone());
        let (base, log) = stub_relay(Box::new(move |m, p, body| {
            let refusing = refusing.load(std::sync::atomic::Ordering::SeqCst);
            let mut r = keeping.lock().unwrap();
            let refused = |error: &str| serde_json::json!({"ok": false, "error": error});
            match (m, p.split('?').next().unwrap()) {
                ("POST", "/api/memory/batch") => {
                    let results: Vec<_> = body["ops"].as_array().unwrap().iter()
                        .map(|op| if refusing && op["memory"]["content"] == "port 8765" { refused(FOR_NOW[0]) } else { r.op(op) })
                        .collect();
                    (200, serde_json::json!({"results": results}))
                }
                ("POST", "/api/skills/batch") => crate::memory::fake_station_skills::batch(body, |op| {
                    if refusing && op["skill"]["name"] == "skill3" { refused(FOR_NOW[1]) } else { r.skill_op(op) }
                }),
                _ => {
                    drop(r);
                    keeping_relay(keeping.clone())(m, p, body)
                }
            }
        })).await;
        let s = Store::open_in_memory().unwrap();
        let (_td, ctx) = test_ctx();
        queue_memories(&s, &["port 8765", "other fact"]);
        // Two skill chunks: skill0..skill7, then skill8, skill9 and an edit
        // of skill3 (v2).
        for i in 0..10 {
            let skill = skill_v1(&format!("skill{i}"), &format!("# skill {i}"), "m1");
            s.put_skill(&skill).unwrap();
            s.enqueue(&PendingOp::PushSkill { skill, base_version: 0 }).unwrap();
        }
        let edit = Skill { version: 2, ..skill_v1("skill3", "# skill 3, edited", "m1") };
        let edit = Skill { content_hash: skill_hash(&edit.files), ..edit };
        s.put_skill(&edit).unwrap();
        s.enqueue(&PendingOp::PushSkill { skill: edit.clone(), base_version: 1 }).unwrap();
        let queued = s.pending().unwrap();
        let out = run_sync(&s, Some(&client(&base, "ast-a")), &ctx, &NO_HARVEST).await.unwrap();
        assert!(out.relay_error, "{:?}", out.notes);
        assert_eq!(out.pushed, 10, "{:?}", out.notes);
        // An unverified device (this client) sends plain: told to verify.
        let why = "(this device isn't verified, so it sends without end-to-end encryption, and the account encrypts)";
        assert_eq!(out.notes, vec![
            format!("relay refused memory mem_port 8765 for now: {} {why}; it stays queued and is sent sealed once this device is verified: run `atem pair verify` (see `atem status`).", FOR_NOW[0]),
            format!("relay refused skill skill3 v1 for now: {} {why}; it stays queued and is sent sealed once this device is verified: run `atem pair verify` (see `atem status`).", FOR_NOW[1]),
        ]);
        let left: Vec<_> = queued.iter().filter(|(_, op)| match op {
            PendingOp::AddMemory { memory } => memory.content == "port 8765",
            PendingOp::PushSkill { skill, .. } => skill.name == "skill3",
            _ => false,
        }).cloned().collect();
        assert_eq!(s.pending().unwrap(), left);
        assert_eq!(s.live_memories().unwrap().len(), 2);
        // Each op sent at most once: skill3's edit not at all.
        let posts = |log: &RelayLog| log.lock().unwrap().iter().filter(|(m, _, _)| m == "POST").map(|(_, p, body)| (
            p.split('?').next().unwrap().to_string(),
            body["ops"].as_array().unwrap().iter().map(|op| op["memory"]["content"].as_str().or(op["skill"]["name"].as_str()).unwrap().to_string()).collect::<Vec<_>>(),
        )).collect::<Vec<_>>();
        let names = |names: &[&str]| names.iter().map(|n| n.to_string()).collect::<Vec<_>>();
        assert_eq!(posts(&log), vec![
            ("/api/memory/batch".to_string(), names(&["port 8765", "other fact"])),
            ("/api/skills/batch".to_string(), (0..8).map(|i| format!("skill{i}")).collect()),
            ("/api/skills/batch".to_string(), names(&["skill8", "skill9"])),
        ]);
        assert!(s.get_state(LAST_SYNC_AT).unwrap() == 0);

        refuse.store(false, std::sync::atomic::Ordering::SeqCst);
        let out = run_sync(&s, Some(&client(&base, "ast-a")), &ctx, &NO_HARVEST).await.unwrap();
        assert!(out.notes.is_empty() && !out.relay_error, "{:?}", out.notes);
        assert_eq!(out.pushed, 3);
        assert_eq!(s.pending_count().unwrap(), 0);
        let r = relay.lock().unwrap();
        assert_eq!(r.rows.values().filter(|m| m.content == "port 8765").count(), 1);
        for i in 0..10 {
            let stored = r.latest_skill(&format!("skill{i}")).unwrap();
            let want = if i == 3 { (2, edit.files["SKILL.md"].clone()) } else { (1, format!("# skill {i}").into_bytes()) };
            assert_eq!((stored.version, stored.files["SKILL.md"].clone()), want);
        }
    }

    /// A fact purged here (`atem memory purge`: deleted, its delete queued)
    /// after its add was queued: when the relay refuses the add in any way
    /// (for good, for now past the retry limit, or for its own value) and
    /// the purge's delete lands in the same batch, the add is withdrawn: no
    /// note quoting it, not kept here. When the delete isn't in that batch,
    /// the refusal's note still doesn't quote the purged fact, and it isn't
    /// kept either.
    #[test]
    fn a_refused_fact_purged_since_is_neither_kept_nor_quoted() {
        let secret = "staging token is in the deploy notes";
        let given_up = || {
            let s = Store::open_in_memory().unwrap();
            queue_memories(&s, &[secret]);
            let n = s.pending().unwrap()[0].0;
            s.set_state(SYNC_RUNS, 10).unwrap();
            let since = now_secs() - REFUSED_FOR_NOW_SECS - 60;
            s.set_refused_for_now(n, &RefusedRun { count: REFUSED_FOR_NOW_SYNCS, since: Some(since), run: Some(10), state: Some(String::new()) }).unwrap();
            s.set_state(SYNC_RUNS, 11).unwrap();
            s
        };
        let fresh = || {
            let s = Store::open_in_memory().unwrap();
            queue_memories(&s, &[secret]);
            s
        };
        let own = OpResult { mode_refusal: ModeRefusal::Own("its text starts with `e1.`".into()), ..refused(FOR_NOW[0]) };
        let cases = [("for good", refused("invalid memory")), ("its own value", own), ("past the retry limit", refused(FOR_NOW[0]))];
        for (label, answer) in cases {
            let s = if label == "past the retry limit" { given_up() } else { fresh() };
            let id = format!("mem_{secret}");
            // `atem memory purge`, queued behind the add.
            s.mark_memory_deleted(&id).unwrap();
            s.enqueue(&PendingOp::DeleteMemory { id: id.clone() }).unwrap();
            let sent = s.pending().unwrap();
            let notes = apply_push_results(&s, &sent, &[answer.clone(), landed()]).unwrap();
            assert!(notes.is_empty(), "{label}: {notes:?}"); // withdrawn: nothing to say
            assert_eq!(s.pending_count().unwrap(), 0, "{label}");
            assert!(s.live_memories().unwrap().is_empty(), "{label}");
            assert_eq!(s.local_only_count().unwrap(), 0, "{label}");
            // The delete in a later batch: the add's refusal comes first,
            // with the fact already purged here.
            let s = fresh();
            s.mark_memory_deleted(&id).unwrap();
            let sent = s.pending().unwrap();
            let notes = apply_push_results(&s, &sent, &[refused("invalid memory")]).unwrap();
            assert_eq!(notes, vec![format!("relay refused memory {id}: invalid memory")], "{label}");
            assert!(s.live_memories().unwrap().is_empty() && s.local_only_count().unwrap() == 0, "{label}");
        }
    }

    /// One sync's results: the sync counter moved on (`run_sync` does), then
    /// the batch applied as sealed under `state`.
    fn sync_round(s: &Store, sent: &[(i64, PendingOp)], results: &[OpResult], state: &SealState) -> Vec<String> {
        s.set_state(SYNC_RUNS, s.get_state(SYNC_RUNS).unwrap() + 1).unwrap();
        apply_batch(s, sent, results, Some(state)).unwrap().notes
    }

    fn on(kid: &str) -> SealState {
        SealState::for_test(crate::memory::crypto::EncryptionMode::On, Some(kid), true)
    }

    /// Refused for now at every sync: kept while that lasts less than
    /// `REFUSED_FOR_NOW_SYNCS` syncs in a row or less than
    /// `REFUSED_FOR_NOW_SECS` (syncs after local changes can come seconds
    /// apart); past both, Atem stops retrying and treats it as refused for
    /// good, with a note. The fact stays here.
    #[test]
    fn an_op_refused_for_now_too_long_is_refused_for_good() {
        let s = Store::open_in_memory().unwrap();
        harvest(&s, &[h("a.md", Scope::Global, "Prefers ripgrep")]);
        let sent = s.pending().unwrap();
        let n = sent[0].0;
        let state = on("0123abcd");
        for round in 1..=REFUSED_FOR_NOW_SYNCS + 1 {
            let notes = sync_round(&s, &sent, &[refused(FOR_NOW[0])], &state);
            assert!(notes[0].contains(" for now: "), "{round}: {notes:?}");
            assert_eq!(s.pending().unwrap(), sent, "{round}");
        }
        assert_eq!(s.refused_for_now(n).unwrap().count, REFUSED_FOR_NOW_SYNCS + 1);
        // The first refusal was over a day ago.
        let since = now_secs() - REFUSED_FOR_NOW_SECS - 60;
        s.test_conn().execute("UPDATE pending_ops SET refused_since = ?1", rusqlite::params![since]).unwrap();
        let notes = sync_round(&s, &sent, &[refused(FOR_NOW[0])], &state);
        let PendingOp::AddMemory { memory } = &sent[0].1 else { panic!("{sent:?}") };
        let id = &memory.id;
        assert_eq!(notes, vec![format!(
            "relay refused memory {id} (\"Prefers ripgrep\") for now at {} syncs in a row since {} UTC: {}; Atem stopped retrying it (refused for good); it stays on this machine only, never synced",
            REFUSED_FOR_NOW_SYNCS + 2, crate::memory::model::format_datetime(since), FOR_NOW[0]
        )]);
        assert_eq!(s.pending_count().unwrap(), 0);
        // As any refusal for good of a fact: kept here, never synced.
        assert_eq!(s.live_memories().unwrap().len(), 1);
        assert_eq!((s.held_back_count().unwrap(), s.local_only_count().unwrap()), (0, 1));
    }

    /// A run of refusals for now starts again when a sync didn't send the op
    /// (offline, held, a stopped push) or sealed it under another state (a
    /// new key, mode or verification), so a long sleep followed by a few
    /// refusals, or a refusal under each of several states, never gives up
    /// at once. A refusal because this device isn't verified never counts
    /// and ends a run.
    #[test]
    fn a_run_of_refusals_for_now_restarts_on_a_gap_or_a_new_state() {
        let s = Store::open_in_memory().unwrap();
        harvest(&s, &[h("a.md", Scope::Global, "Prefers ripgrep")]);
        let sent = s.pending().unwrap();
        let n = sent[0].0;
        let a_day_ago = now_secs() - REFUSED_FOR_NOW_SECS - 60;
        let backdate = || s.test_conn().execute("UPDATE pending_ops SET refused_since = ?1", rusqlite::params![a_day_ago]).unwrap();
        let (old_key, new_key) = (on("0123abcd"), on("89abcdef"));
        // Four in a row, the first long ago...
        for _ in 0..REFUSED_FOR_NOW_SYNCS - 1 {
            sync_round(&s, &sent, &[refused(FOR_NOW[0])], &old_key);
        }
        backdate();
        assert_eq!(s.refused_for_now(n).unwrap().count, REFUSED_FOR_NOW_SYNCS - 1);
        // ...then a sync that didn't send it: the next refusal starts a new run.
        s.set_state(SYNC_RUNS, s.get_state(SYNC_RUNS).unwrap() + 1).unwrap();
        sync_round(&s, &sent, &[refused(FOR_NOW[0])], &old_key);
        let run = s.refused_for_now(n).unwrap();
        assert!(run.count == 1 && run.since.unwrap() > a_day_ago, "{run:?}");
        // Four more in a row, backdated: then a refusal under a new key
        // starts a new run instead of giving up.
        for _ in 0..REFUSED_FOR_NOW_SYNCS - 2 {
            sync_round(&s, &sent, &[refused(FOR_NOW[0])], &old_key);
        }
        backdate();
        let notes = sync_round(&s, &sent, &[refused(FOR_NOW[0])], &new_key);
        assert!(notes[0].contains(" for now: "), "{notes:?}");
        assert_eq!(s.refused_for_now(n).unwrap().count, 1);
        // An unverified device's refusal ends the run and never counts.
        let unverified = SealState::for_test(crate::memory::crypto::EncryptionMode::Off, None, false);
        let as_unverified = OpResult { mode_refusal: ModeRefusal::Unverified, ..refused(FOR_NOW[0]) };
        for _ in 0..2 * REFUSED_FOR_NOW_SYNCS {
            sync_round(&s, &sent, std::slice::from_ref(&as_unverified), &unverified);
        }
        assert_eq!(s.refused_for_now(n).unwrap(), RefusedRun::default());
        assert_eq!(s.pending().unwrap(), sent);
    }

    /// A chunk refused as too large goes one op at a time; an op refused for
    /// now there holds back its memory too: its own invalidation and a
    /// replacement naming it aren't sent in that sync, and the next sync
    /// sends them after it. Other ops go on.
    #[tokio::test]
    async fn an_op_refused_for_now_on_the_one_at_a_time_path_holds_back_its_memory() {
        let relay = Arc::new(Mutex::new(KeepingRelay::default()));
        let refuse = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let (refusing, keeping) = (refuse.clone(), relay.clone());
        let (base, log) = stub_relay(Box::new(move |m, p, body| {
            if m == "POST" && p.starts_with("/api/memory/batch?") {
                let ops = body["ops"].as_array().unwrap();
                if ops.len() > 1 {
                    return (413, serde_json::json!({"error": "request body too large"}));
                }
                if refusing.load(std::sync::atomic::Ordering::SeqCst) && ops[0]["memory"]["content"] == "port 9000" {
                    return (200, serde_json::json!({"results": [{"ok": false, "error": FOR_NOW[0]}]}));
                }
            }
            keeping_relay(keeping.clone())(m, p, body)
        })).await;
        let s = Store::open_in_memory().unwrap();
        let (_td, ctx) = test_ctx();
        let old = valid("mem_old", "port 8765");
        s.upsert_memory(&old).unwrap();
        queue_memories(&s, &["alpha"]);
        let new_id = replace_memory(&s, &old, "port 9000", None, "cli", "m1").unwrap(); // its add, then old's invalidation
        assert!(invalidate_and_queue(&s, &new_id, T, None).unwrap()); // and the new fact's own invalidation
        queue_memories(&s, &["omega"]);
        let out = run_sync(&s, Some(&client(&base, "ast-a")), &ctx, &NO_HARVEST).await.unwrap();
        assert!(out.relay_error, "{:?}", out.notes);
        assert_eq!(out.pushed, 2, "{:?}", out.notes);
        let singles: Vec<String> = log.lock().unwrap().iter()
            .filter(|(m, p, body)| m == "POST" && p.starts_with("/api/memory/batch?") && body["ops"].as_array().unwrap().len() == 1)
            .map(|(_, _, body)| body["ops"][0]["memory"]["content"].as_str().or(body["ops"][0]["id"].as_str()).unwrap().to_string())
            .collect();
        assert_eq!(singles, vec!["alpha", "port 9000", "omega"]);
        let left: Vec<String> = s.pending().unwrap().into_iter().map(|(_, op)| match op {
            PendingOp::AddMemory { memory } => format!("add {}", memory.content),
            PendingOp::InvalidateMemory { id, .. } => format!("invalidate {id}"),
            other => format!("{other:?}"),
        }).collect();
        assert_eq!(left, vec!["add port 9000".to_string(), "invalidate mem_old".into(), format!("invalidate {new_id}")]);

        refuse.store(false, std::sync::atomic::Ordering::SeqCst);
        let out = run_sync(&s, Some(&client(&base, "ast-a")), &ctx, &NO_HARVEST).await.unwrap();
        assert!(!out.relay_error && out.pushed == 3, "{:?}", out.notes);
        assert_eq!(s.pending_count().unwrap(), 0);
        let r = relay.lock().unwrap();
        assert_eq!(r.rows[&new_id].invalid_at, Some(T));
    }

    #[test]
    fn result_count_mismatch_is_a_note_and_keeps_ops_queued() {
        let s = Store::open_in_memory().unwrap();
        harvest(&s, &[h("a.md", Scope::Global, "x fact")]);
        let notes = apply_push_results(&s, &s.pending().unwrap(), &[]).unwrap();
        assert_eq!(notes.len(), 1);
        assert!(notes[0].contains("0 results for 1"), "{}", notes[0]);
        assert_eq!(s.pending_count().unwrap(), 1);
        assert_eq!(s.live_memories().unwrap().len(), 1);
    }

    #[test]
    fn skill_pushes_chunk_smaller_than_memory_pushes() {
        // Skill payloads (file contents) are much heavier per-op than memory
        // rows, so they're batched in smaller groups.
        assert_eq!(MEMORY_PUSH_CHUNK, 50);
        assert_eq!(SKILL_PUSH_CHUNK, 8);
        assert!(SKILL_PUSH_CHUNK < MEMORY_PUSH_CHUNK);
    }

    #[test]
    fn full_page_must_advance_the_cursor() {
        let full = PULL_LIMIT as usize;
        assert!(cursor_advances(120, 100, full));
        assert!(!cursor_advances(100, 100, full));
        assert!(!cursor_advances(40, 100, full));
        // A short page ends the pull anyway, so it never loops.
        assert!(cursor_advances(40, 100, 3));
    }

    #[test]
    fn pulled_memories_upsert_and_tombstone() {
        let s = Store::open_in_memory().unwrap();
        let mut a = Memory {
            id: "mem_a".into(), scope: Scope::Global, project: String::new(), machine: String::new(),
            content: "A".into(), content_hash: content_hash("A"), confidence: "medium".into(),
            source_agent: "codex".into(), source_machine: "hal".into(), created_at: 1, seq: 5, ..Default::default()
        };
        let mut b = a.clone();
        b.id = "mem_b".into();
        b.seq = 7;
        b.deleted_at = Some(7);
        assert_eq!(apply_pulled_memories(&s, &[a.clone(), b]).unwrap(), 7);
        let got_b = s.get_memory("mem_b").unwrap().unwrap();
        assert!(got_b.is_deleted() && got_b.content.is_empty());
        a.seq = 8;
        apply_pulled_memories(&s, &[a]).unwrap();
        assert_eq!(s.live_memories().unwrap().len(), 1);
    }

    #[test]
    fn pulled_skills_follow_versions() {
        let s = Store::open_in_memory().unwrap();
        let mk = |v: i64, deleted: bool| {
            let mut files = BTreeMap::new();
            files.insert("SKILL.md".to_string(), format!("v{}", v).into_bytes());
            Skill {
                scope: Scope::Global, project: String::new(), name: "demo".into(), version: v,
                content_hash: skill_hash(&files), files,
                source_agent: "cli".into(), source_machine: "m".into(), created_at: 1, deleted, seq: v * 10,
            }
        };
        apply_pulled_skills(&s, &[mk(2, false)]).unwrap();
        apply_pulled_skills(&s, &[mk(1, true)]).unwrap(); // older version (e.g. purged) → ignored
        assert_eq!(s.get_skill(Scope::Global, "", "demo").unwrap().unwrap().version, 2);
        assert_eq!(apply_pulled_skills(&s, &[mk(3, false)]).unwrap(), 30);
        apply_pulled_skills(&s, &[mk(3, true)]).unwrap(); // latest purged → deleted
        assert!(s.get_skill(Scope::Global, "", "demo").unwrap().unwrap().deleted);
    }

    // ─────────────── relay round trips (local stub relay) ───────────────

    pub(super) type Handler = dyn Fn(&str, &str, &serde_json::Value) -> (u16, serde_json::Value) + Send + Sync;

    /// A tiny HTTP/1.1 relay stub on 127.0.0.1: one request per connection,
    /// answered by `f(method, path_and_query, json_body)`; a status of 0
    /// closes the connection with no answer (an uncertain outcome). Returns
    /// the base URL and a log of (method, path_and_query, body) for every
    /// request.
    pub(super) async fn stub_relay(f: Box<Handler>) -> (String, std::sync::Arc<std::sync::Mutex<Vec<(String, String, serde_json::Value)>>>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let log = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let f: std::sync::Arc<Handler> = std::sync::Arc::from(f);
        let log2 = log.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else { return };
                let f = f.clone();
                let log = log2.clone();
                tokio::spawn(async move {
                    let mut buf = Vec::new();
                    let mut tmp = [0u8; 65536];
                    let head_end = loop {
                        let n = sock.read(&mut tmp).await.unwrap_or(0);
                        if n == 0 {
                            return;
                        }
                        buf.extend_from_slice(&tmp[..n]);
                        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                            break i + 4;
                        }
                    };
                    let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
                    let mut lines = head.lines();
                    let mut first = lines.next().unwrap_or("").split(' ');
                    let method = first.next().unwrap_or("").to_string();
                    let path = first.next().unwrap_or("").to_string();
                    let len = lines
                        .filter_map(|l| l.split_once(':'))
                        .find(|(k, _)| k.trim().eq_ignore_ascii_case("content-length"))
                        .and_then(|(_, v)| v.trim().parse::<usize>().ok())
                        .unwrap_or(0);
                    while buf.len() < head_end + len {
                        let n = sock.read(&mut tmp).await.unwrap_or(0);
                        if n == 0 {
                            break;
                        }
                        buf.extend_from_slice(&tmp[..n]);
                    }
                    let body: serde_json::Value = serde_json::from_slice(&buf[head_end..]).unwrap_or(serde_json::Value::Null);
                    let (code, resp) = f(&method, &path, &body);
                    log.lock().unwrap().push((method, path, body));
                    if code == 0 {
                        let _ = sock.shutdown().await;
                        return;
                    }
                    let text = resp.to_string();
                    let out = format!(
                        "HTTP/1.1 {} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                        code, text.len(), text
                    );
                    let _ = sock.write_all(out.as_bytes()).await;
                    let _ = sock.shutdown().await;
                });
            }
        });
        (base, log)
    }

    fn empty_pulls(method: &str, path: &str) -> Option<(u16, serde_json::Value)> {
        if method != "GET" {
            return None;
        }
        if path.starts_with("/api/memory?") {
            return Some((200, serde_json::json!({"memories": []})));
        }
        // The skill collection; any other GET is the test's own, or no route.
        path.starts_with("/api/skills?").then(|| (200, serde_json::json!({"skills": []})))
    }

    /// Every op accepted. A skills batch goes through the fake Station
    /// (`fake_station_skills::batch`): refused as the Station refuses it.
    fn ok_results(path: &str, body: &serde_json::Value) -> (u16, serde_json::Value) {
        let mut seq = 0;
        let mut ok = |_: &serde_json::Value| {
            seq += 1;
            serde_json::json!({"ok": true, "seq": seq})
        };
        if path.starts_with("/api/skills/batch?") {
            return crate::memory::fake_station_skills::batch(body, ok);
        }
        let results: Vec<serde_json::Value> = body["ops"].as_array().map_or(Vec::new(), |ops| ops.iter().map(&mut ok).collect());
        (200, serde_json::json!({"results": results}))
    }

    pub(super) fn test_ctx() -> (tempfile::TempDir, Ctx) {
        let td = tempfile::tempdir().unwrap();
        let ctx = Ctx { home: td.path().to_path_buf(), repo: None, atem_id: "m1".into(), allow_tracked: false };
        (td, ctx)
    }

    /// Keys in a profile that doesn't exist (unverified: encryption off),
    /// never the user's.
    fn client(base: &str, account: &str) -> KnowledgeClient {
        let nowhere = std::env::temp_dir().join(format!("atem-sync-{}", uuid::Uuid::new_v4()));
        let paths = crate::paths::CredPaths::in_dir(&nowhere);
        let agent = std::sync::Arc::new(crate::memory::cred_agent::test_agent(&paths));
        KnowledgeClient::new(base.to_string(), "inst".into(), "sess".into(), account.into())
            .with_encryption(paths, agent)
    }

    fn queue_memories(s: &Store, contents: &[&str]) {
        for c in contents {
            let m = Memory {
                id: format!("mem_{}", c), scope: Scope::Global, project: String::new(), machine: String::new(),
                content: c.to_string(), content_hash: content_hash(c), confidence: "high".into(),
                source_agent: "cli".into(), source_machine: "m1".into(), created_at: 1, seq: 0, ..Default::default()
            };
            s.upsert_memory(&m).unwrap();
            s.enqueue(&PendingOp::AddMemory { memory: m }).unwrap();
        }
    }

    pub(super) const NO_HARVEST: SyncOptions = SyncOptions { harvest: false };

    #[tokio::test]
    async fn pulled_replacement_leaves_the_block_but_stays_in_history() {
        let s = Store::open_in_memory().unwrap();
        let (base, _log) = stub_relay(Box::new(|m, p, _| {
            if m == "GET" && p.starts_with("/api/memory?") && p.contains("since=0&") {
                let row = |id: &str, content: &str, invalid_at: serde_json::Value, superseded_by: serde_json::Value, seq: i64| serde_json::json!({
                    "id": id, "scope": "global", "project": "", "machine": "", "content": content,
                    "content_hash": content_hash(content), "confidence": "high", "source_agent": "cli",
                    "source_machine": "m2", "created_at": 1, "deleted": false, "deleted_at": null,
                    "valid_at": null, "invalid_at": invalid_at, "superseded_by": superseded_by, "seq": seq,
                });
                return (200, serde_json::json!({"memories": [
                    row("mem_new", "DialF listens on TCP 9000", serde_json::Value::Null, serde_json::Value::Null, 2),
                    row("mem_old", "DialF listens on TCP 8765", serde_json::json!(1_790_000_000), serde_json::json!("mem_new"), 3),
                ]}));
            }
            empty_pulls(m, p).unwrap()
        })).await;
        let (_td, ctx) = test_ctx();
        std::fs::create_dir_all(ctx.home.join(".claude")).unwrap();
        run_sync(&s, Some(&client(&base, "ast-a")), &ctx, &NO_HARVEST).await.unwrap();
        let text = std::fs::read_to_string(ctx.home.join(".claude/CLAUDE.md")).unwrap();
        assert!(text.contains("TCP 9000") && !text.contains("TCP 8765"), "{text}");
        let old = s.get_memory("mem_old").unwrap().unwrap();
        assert_eq!((old.invalid_at, old.superseded_by.as_deref()), (Some(1_790_000_000), Some("mem_new")));
        assert_eq!(s.history_memories().unwrap().len(), 2);
        assert_eq!(s.live_memories().unwrap().len(), 1);
    }

    #[test]
    fn relay_error_notes_are_actionable() {
        let n401 = relay_error_note(&ApiError::Http(401, "invalid or unbound session".into()));
        assert_eq!(n401, RELAY_UNAUTHORIZED_NOTE);
        assert!(n401.contains("Astation (latest version)") && n401.contains("stay queued"));
        assert_eq!(relay_error_note(&ApiError::Http(503, "x".into())), RELAY_UNAVAILABLE_NOTE);
        assert!(RELAY_UNAVAILABLE_NOTE.contains("temporarily unavailable") && RELAY_UNAVAILABLE_NOTE.contains("stay queued"));
        assert!(relay_error_note(&ApiError::Http(500, "boom".into())).contains("500"));
        let big = too_large_note(&PendingOp::DeleteMemory { id: "mem_x".into() });
        assert!(big.contains("delete of mem_x") && big.contains("too large for the relay") && big.contains("stays queued"), "{}", big);
    }

    #[tokio::test]
    async fn unauthorized_keeps_everything_queued_with_one_reconnect_note() {
        let s = Store::open_in_memory().unwrap();
        queue_memories(&s, &["a"]);
        s.enqueue(&PendingOp::DeleteSkill { scope: Scope::Global, project: String::new(), name: "x".into() }).unwrap();
        let (base, _log) = stub_relay(Box::new(|_, _, _| (401, serde_json::json!({"error": "invalid or unbound session"})))).await;
        let (_td, ctx) = test_ctx();
        let out = run_sync(&s, Some(&client(&base, "ast-a")), &ctx, &NO_HARVEST).await.unwrap();
        assert_eq!(out.notes, vec![RELAY_UNAUTHORIZED_NOTE.to_string()]);
        assert_eq!(s.pending_count().unwrap(), 2);
        assert_eq!(s.get_state(LAST_SYNC_AT).unwrap(), 0);
    }

    #[tokio::test]
    async fn unavailable_keeps_everything_queued() {
        let s = Store::open_in_memory().unwrap();
        queue_memories(&s, &["a", "b"]);
        let (base, _log) = stub_relay(Box::new(|_, _, _| (503, serde_json::json!({"error": "temporarily unavailable"})))).await;
        let (_td, ctx) = test_ctx();
        let out = run_sync(&s, Some(&client(&base, "ast-a")), &ctx, &NO_HARVEST).await.unwrap();
        assert!(out.notes.contains(&RELAY_UNAVAILABLE_NOTE.to_string()), "{:?}", out.notes);
        assert_eq!(s.pending_count().unwrap(), 2);
        assert_eq!(s.live_memories().unwrap().len(), 2);
        assert_eq!(s.get_state(LAST_SYNC_AT).unwrap(), 0);
    }

    #[tokio::test]
    async fn chunk_413_retries_ops_one_at_a_time() {
        let s = Store::open_in_memory().unwrap();
        queue_memories(&s, &["a", "b", "c"]);
        let (base, log) = stub_relay(Box::new(|m, p, body| {
            if let Some(r) = empty_pulls(m, p) {
                return r;
            }
            if body["ops"].as_array().unwrap().len() > 1 {
                return (413, serde_json::json!({"error": "request body too large"}));
            }
            ok_results(p, body)
        })).await;
        let (_td, ctx) = test_ctx();
        let out = run_sync(&s, Some(&client(&base, "ast-a")), &ctx, &NO_HARVEST).await.unwrap();
        assert!(out.notes.is_empty(), "{:?}", out.notes);
        assert_eq!(out.pushed, 3);
        assert_eq!(s.pending_count().unwrap(), 0);
        let sizes: Vec<usize> = log.lock().unwrap().iter().filter(|(m, _, _)| m == "POST")
            .map(|(_, _, b)| b["ops"].as_array().unwrap().len()).collect();
        assert_eq!(sizes, vec![3, 1, 1, 1]);
        assert!(s.get_state(LAST_SYNC_AT).unwrap() > 0);
    }

    #[tokio::test]
    async fn single_op_413_stays_queued_and_stops_its_group() {
        let s = Store::open_in_memory().unwrap();
        queue_memories(&s, &["a", "huge", "c"]);
        s.enqueue(&PendingOp::DeleteSkill { scope: Scope::Global, project: String::new(), name: "x".into() }).unwrap();
        let (base, log) = stub_relay(Box::new(|m, p, body| {
            if let Some(r) = empty_pulls(m, p) {
                return r;
            }
            let ops = body["ops"].as_array().unwrap();
            if ops.len() > 1 || ops[0]["memory"]["content"] == "huge" {
                return (413, serde_json::json!({"error": "request body too large"}));
            }
            ok_results(p, body)
        })).await;
        let (_td, ctx) = test_ctx();
        let out = run_sync(&s, Some(&client(&base, "ast-a")), &ctx, &NO_HARVEST).await.unwrap();
        assert_eq!(out.notes.len(), 1, "{:?}", out.notes);
        assert!(out.notes[0].contains("memory mem_huge") && out.notes[0].contains("too large"), "{}", out.notes[0]);
        // "a" was acked; "huge" is never acked and "c" (after it) wasn't sent.
        let left: Vec<String> = s.pending().unwrap().iter().map(|(_, op)| describe(op)).collect();
        assert_eq!(left, vec!["memory mem_huge".to_string(), "memory mem_c".to_string()]);
        assert!(s.get_memory("mem_huge").unwrap().is_some_and(|m| !m.is_deleted()));
        let posted: Vec<String> = log.lock().unwrap().iter().filter(|(m, _, _)| m == "POST")
            .map(|(_, _, b)| b["ops"].as_array().unwrap().iter().map(|o| o["op"].as_str().unwrap().to_string()).collect::<Vec<_>>().join(",")).collect();
        // Skills are a separate group and still go out.
        assert_eq!(posted, vec!["add,add,add", "add", "add", "delete"]);
        assert_eq!(s.get_state(LAST_SYNC_AT).unwrap(), 0);
    }

    /// A relay that dedups the add of `dup_content` onto `mem_canon` and
    /// accepts everything else; 413s any batch bigger than `max_ops`.
    fn dedup_relay(dup_content: &'static str, max_ops: usize) -> Box<Handler> {
        Box::new(move |m, p, body| {
            if let Some(r) = empty_pulls(m, p) {
                return r;
            }
            let ops = body["ops"].as_array().unwrap();
            if ops.len() > max_ops {
                return (413, serde_json::json!({"error": "request body too large"}));
            }
            let results: Vec<_> = ops.iter().enumerate().map(|(i, o)| {
                if o["op"] == "add" && o["memory"]["content"] == dup_content {
                    serde_json::json!({"ok": true, "seq": i + 1, "canonical_id": "mem_canon"})
                } else {
                    serde_json::json!({"ok": true, "seq": i + 1})
                }
            }).collect();
            (200, serde_json::json!({"results": results}))
        })
    }

    pub(super) fn posted_ops(log: &std::sync::Arc<std::sync::Mutex<Vec<(String, String, serde_json::Value)>>>) -> Vec<Vec<serde_json::Value>> {
        log.lock().unwrap().iter().filter(|(m, _, _)| m == "POST")
            .map(|(_, _, b)| b["ops"].as_array().unwrap().clone()).collect()
    }

    fn fillers(s: &Store, n: usize) {
        let names: Vec<String> = (0..n).map(|i| format!("filler{i}")).collect();
        queue_memories(s, &names.iter().map(String::as_str).collect::<Vec<_>>());
    }

    #[tokio::test]
    async fn later_chunk_sends_the_canonical_successor() {
        let s = Store::open_in_memory().unwrap();
        let old = valid("mem_old", "port 8765");
        s.upsert_memory(&old).unwrap();
        fillers(&s, MEMORY_PUSH_CHUNK - 1);
        // The add is op 50 (end of chunk 1); the invalidate is op 51.
        replace_memory(&s, &old, "port 9000", None, "cli", "m1").unwrap();
        let (base, log) = stub_relay(dedup_relay("port 9000", usize::MAX)).await;
        let (_td, ctx) = test_ctx();
        let out = run_sync(&s, Some(&client(&base, "ast-a")), &ctx, &NO_HARVEST).await.unwrap();
        assert!(out.notes.is_empty(), "{:?}", out.notes);
        let posts = posted_ops(&log);
        assert_eq!(posts.iter().map(Vec::len).collect::<Vec<_>>(), vec![MEMORY_PUSH_CHUNK, 1]);
        assert_eq!(posts[1][0]["op"], "invalidate");
        assert_eq!(posts[1][0]["id"], "mem_old");
        assert_eq!(posts[1][0]["superseded_by"], "mem_canon");
        assert_eq!(s.pending_count().unwrap(), 0);
        assert_eq!(s.get_memory("mem_old").unwrap().unwrap().superseded_by.as_deref(), Some("mem_canon"));
    }

    #[tokio::test]
    async fn later_chunk_invalidates_the_canonical_id() {
        let s = Store::open_in_memory().unwrap();
        fillers(&s, MEMORY_PUSH_CHUNK - 1);
        queue_memories(&s, &["dup"]); // op 50: add mem_dup
        assert!(invalidate_and_queue(&s, "mem_dup", 5, None).unwrap()); // op 51
        let (base, log) = stub_relay(dedup_relay("dup", usize::MAX)).await;
        let (_td, ctx) = test_ctx();
        let out = run_sync(&s, Some(&client(&base, "ast-a")), &ctx, &NO_HARVEST).await.unwrap();
        assert!(out.notes.is_empty(), "{:?}", out.notes);
        let posts = posted_ops(&log);
        assert_eq!(posts.len(), 2);
        assert_eq!(posts[1][0]["op"], "invalidate");
        assert_eq!(posts[1][0]["id"], "mem_canon");
        assert_eq!(s.pending_count().unwrap(), 0);
        assert_eq!(s.get_memory("mem_canon").unwrap().unwrap().invalid_at, Some(5));
    }

    #[tokio::test]
    async fn one_at_a_time_retry_sends_the_canonical_successor() {
        let s = Store::open_in_memory().unwrap();
        let old = valid("mem_old", "port 8765");
        s.upsert_memory(&old).unwrap();
        replace_memory(&s, &old, "port 9000", None, "cli", "m1").unwrap();
        let (base, log) = stub_relay(dedup_relay("port 9000", 1)).await;
        let (_td, ctx) = test_ctx();
        let out = run_sync(&s, Some(&client(&base, "ast-a")), &ctx, &NO_HARVEST).await.unwrap();
        assert!(out.notes.is_empty(), "{:?}", out.notes);
        let posts = posted_ops(&log);
        assert_eq!(posts.iter().map(Vec::len).collect::<Vec<_>>(), vec![2, 1, 1]);
        assert_eq!(posts[2][0]["op"], "invalidate");
        assert_eq!(posts[2][0]["superseded_by"], "mem_canon");
        assert_eq!(s.pending_count().unwrap(), 0);
    }

    #[tokio::test]
    async fn old_relay_rejecting_invalidate_says_update() {
        let s = Store::open_in_memory().unwrap();
        let old = valid("mem_old", "port 8765");
        s.upsert_memory(&old).unwrap();
        replace_memory(&s, &old, "port 9000", None, "cli", "m1").unwrap();
        queue_memories(&s, &["later"]);
        let (base, _log) = stub_relay(Box::new(|m, p, body| {
            if let Some(r) = empty_pulls(m, p) {
                return r;
            }
            if body["ops"].as_array().unwrap().iter().any(|o| o["op"] == "invalidate") {
                return (400, serde_json::json!({"error": "unknown op"}));
            }
            ok_results(p, body)
        })).await;
        let (_td, ctx) = test_ctx();
        let out = run_sync(&s, Some(&client(&base, "ast-a")), &ctx, &NO_HARVEST).await.unwrap();
        assert_eq!(out.notes, vec!["This relay doesn't support outdating facts yet — update the relay (Astation). 3 change(s) stay queued.".to_string()]);
        assert!(out.relay_error);
        assert_eq!(s.pending_count().unwrap(), 3);

        // Any other 400 keeps today's note.
        let s2 = Store::open_in_memory().unwrap();
        queue_memories(&s2, &["a"]);
        let (base2, _log2) = stub_relay(Box::new(|m, p, _| {
            empty_pulls(m, p).unwrap_or((400, serde_json::json!({"error": "bad op"})))
        })).await;
        let out2 = run_sync(&s2, Some(&client(&base2, "ast-a")), &ctx, &NO_HARVEST).await.unwrap();
        assert_eq!(out2.notes.len(), 1);
        assert!(out2.notes[0].contains("400") && !out2.notes[0].contains("outdating"), "{:?}", out2.notes);
    }

    #[tokio::test]
    async fn clean_sync_records_last_sync_and_pull_error_does_not() {
        let s = Store::open_in_memory().unwrap();
        let (base, _log) = stub_relay(Box::new(|m, p, _| empty_pulls(m, p).unwrap())).await;
        let (_td, ctx) = test_ctx();
        let out = run_sync(&s, Some(&client(&base, "ast-a")), &ctx, &NO_HARVEST).await.unwrap();
        assert!(out.notes.is_empty(), "{:?}", out.notes);
        assert!(s.get_state(LAST_SYNC_AT).unwrap() > 0);

        let s2 = Store::open_in_memory().unwrap();
        let (base2, _log2) = stub_relay(Box::new(|m, p, _| {
            if p.starts_with("/api/skills?") {
                return (503, serde_json::json!({"error": "temporarily unavailable"}));
            }
            empty_pulls(m, p).unwrap()
        })).await;
        let out2 = run_sync(&s2, Some(&client(&base2, "ast-a")), &ctx, &NO_HARVEST).await.unwrap();
        assert_eq!(out2.notes, vec![RELAY_UNAVAILABLE_NOTE.to_string()]);
        assert_eq!(s2.get_state(LAST_SYNC_AT).unwrap(), 0);
    }

    #[tokio::test]
    async fn switching_account_pulls_from_zero() {
        let s = Store::open_in_memory().unwrap();
        s.set_state(MEMORY_CURSOR, 99).unwrap(); // legacy, unkeyed: ignored
        s.set_state(SKILL_CURSOR, 99).unwrap();
        let (base, log) = stub_relay(Box::new(|m, p, _| {
            if m == "GET" && p.starts_with("/api/memory?") && p.contains("since=0&") {
                let row = serde_json::json!({
                    "id": "mem_r", "scope": "global", "project": "", "machine": "", "content": "remote",
                    "content_hash": content_hash("remote"), "confidence": "high", "source_agent": "codex",
                    "source_machine": "m2", "created_at": 1, "deleted": false, "seq": 7,
                });
                return (200, serde_json::json!({"memories": [row]}));
            }
            empty_pulls(m, p).unwrap()
        })).await;
        let (_td, ctx) = test_ctx();
        run_sync(&s, Some(&client(&base, "ast-a")), &ctx, &NO_HARVEST).await.unwrap();
        assert_eq!(s.get_state(&memory_cursor_key("ast-a")).unwrap(), 7);
        run_sync(&s, Some(&client(&base, "ast-b")), &ctx, &NO_HARVEST).await.unwrap();
        run_sync(&s, Some(&client(&base, "ast-a")), &ctx, &NO_HARVEST).await.unwrap();
        let mem_sinces: Vec<String> = log.lock().unwrap().iter()
            .filter(|(_, p, _)| p.starts_with("/api/memory?"))
            .map(|(_, p, _)| p.split('&').find(|kv| kv.starts_with("since=")).unwrap().to_string()).collect();
        // a: from 0 (legacy 99 ignored); b: its own cursor, from 0; a again: resumes at 7.
        assert_eq!(mem_sinces, vec!["since=0", "since=0", "since=7"]);
        assert_eq!(s.get_state(&memory_cursor_key("ast-b")).unwrap(), 7);
        let skill_first = log.lock().unwrap().iter().find(|(_, p, _)| p.starts_with("/api/skills?")).unwrap().1.clone();
        assert!(skill_first.contains("since=0&"), "{}", skill_first);
    }

    fn remote_skill(version: i64, body: &str, deleted: bool) -> serde_json::Value {
        let mut files = BTreeMap::new();
        if !deleted {
            files.insert("SKILL.md".to_string(), body.as_bytes().to_vec());
        }
        crate::memory::fake_station_skills::row(&Skill {
            scope: Scope::Global, project: String::new(), name: "demo".into(), version,
            content_hash: skill_hash(&files), files, source_agent: "codex".into(), source_machine: "m2".into(),
            created_at: 1_790_000_000, deleted, seq: version * 10,
        })
    }

    fn history_relay() -> Box<Handler> {
        Box::new(|m, p, body| {
            if m == "GET" && p.starts_with("/api/skills/versions?") {
                return (200, serde_json::json!({"versions": [
                    {"version": 5, "created_at": 1_791_036_600, "source_agent": "claude", "source_machine": "mac-mini", "file_count": 1, "deleted": false, "purged": false},
                    {"version": 4, "created_at": 1_791_036_540, "source_agent": "codex", "source_machine": "genie", "file_count": 1, "deleted": false, "purged": false},
                    {"version": 3, "created_at": 1_790_900_000, "source_agent": "cli", "source_machine": "genie", "file_count": 0, "deleted": true, "purged": false},
                    {"version": 2, "created_at": 1_790_800_000, "source_agent": "cli", "source_machine": "genie", "file_count": 1, "deleted": false, "purged": false},
                    {"version": 1, "created_at": 1_790_700_000, "source_agent": "claude", "source_machine": "genie", "file_count": 0, "deleted": true, "purged": true},
                ]}));
            }
            if m == "GET" && p.starts_with("/api/skills/version?") {
                let v = p.split('&').find_map(|kv| kv.strip_prefix("version=")).unwrap_or("");
                return match v {
                    "4" => (200, serde_json::json!({"skill": remote_skill(4, "# v4 body", false)})),
                    "3" => (200, serde_json::json!({"skill": remote_skill(3, "", true)})),
                    "2" => (200, serde_json::json!({"skill": remote_skill(2, "key AKIAIOSFODNN7EXAMPLE", false)})),
                    "1" => (410, serde_json::json!({"error": "skill version purged"})),
                    _ => (404, serde_json::json!({"error": "no such skill version"})),
                };
            }
            if let Some(r) = empty_pulls(m, p) {
                return r;
            }
            ok_results(p, body)
        })
    }

    #[tokio::test]
    async fn restore_pushes_old_files_as_a_new_version() {
        let s = Store::open_in_memory().unwrap();
        let (base, _log) = stub_relay(history_relay()).await;
        let sk = restore_skill(&s, &client(&base, "ast-a"), "m1", Scope::Global, "", "demo", 4).await.unwrap();
        assert_eq!(sk.version, 6);
        assert_eq!(sk.files.get("SKILL.md").unwrap(), b"# v4 body");
        assert_eq!((sk.source_agent.as_str(), sk.source_machine.as_str(), sk.deleted), ("cli", "m1", false));
        let p = s.pending().unwrap();
        assert!(matches!(&p[0].1, PendingOp::PushSkill { skill, base_version: 5 } if skill.version == 6 && skill.content_hash == skill_hash(&skill.files)));
        assert_eq!(s.get_skill(Scope::Global, "", "demo").unwrap().unwrap().version, 6);
    }

    #[tokio::test]
    async fn restore_refuses_purged_deleted_secret_and_unknown_versions() {
        let s = Store::open_in_memory().unwrap();
        let (base, _log) = stub_relay(history_relay()).await;
        let c = client(&base, "ast-a");
        for (v, want) in [(1, "was purged"), (3, "delete marker"), (2, "possible credentials"), (9, "has no version 9")] {
            let err = restore_skill(&s, &c, "m1", Scope::Global, "", "demo", v).await.unwrap_err().to_string();
            assert!(err.contains(want), "{v}: {err}");
        }
        assert_eq!(s.pending_count().unwrap(), 0);
    }

    #[tokio::test]
    async fn restore_offline_says_so_plainly() {
        let s = Store::open_in_memory().unwrap();
        let err = restore_skill(&s, &client("http://127.0.0.1:1", "ast-a"), "m1", Scope::Global, "", "demo", 4).await.unwrap_err();
        assert_eq!(err.to_string(), SKILL_HISTORY_OFFLINE);
    }

    #[test]
    fn concurrent_push_note_points_to_history() {
        let s = Store::open_in_memory().unwrap();
        let mut files = BTreeMap::new();
        files.insert("SKILL.md".to_string(), b"# s".to_vec());
        let mk = |scope: Scope, project: &str| Skill {
            scope, project: project.into(), name: "demo".into(), version: 2, content_hash: skill_hash(&files),
            files: files.clone(), source_agent: "cli".into(), source_machine: "m1".into(), created_at: 1, deleted: false, seq: 0,
        };
        s.enqueue(&PendingOp::PushSkill { skill: mk(Scope::Global, ""), base_version: 1 }).unwrap();
        s.enqueue(&PendingOp::PushSkill { skill: mk(Scope::Project, "github.com/a/b"), base_version: 1 }).unwrap();
        let sent = s.pending().unwrap();
        let r = OpResult { ok: true, version: Some(3), seq: Some(9), superseded_concurrent: true, ..Default::default() };
        let notes = apply_push_results(&s, &sent, &[r.clone(), r]).unwrap();
        assert_eq!(notes[0], "skill demo: another machine pushed an edit at the same time; both versions are kept and v3 is now the latest. See them with `atem skill history demo`.");
        assert!(notes[1].ends_with("See them with `atem skill history demo --scope project`."), "{}", notes[1]);
    }

    #[test]
    fn skill_history_errors_are_plain() {
        let msg = |e: ApiError, v: Option<i64>| skill_history_error(e, "demo", v).to_string();
        assert_eq!(msg(ApiError::Http(401, "{\"error\":\"invalid or unbound session\"}".into()), Some(4)), SKILL_HISTORY_UNAUTHORIZED);
        assert_eq!(msg(ApiError::Http(401, "x".into()), None), SKILL_HISTORY_UNAUTHORIZED);
        assert!(SKILL_HISTORY_UNAUTHORIZED.contains("Astation (latest version)") && !SKILL_HISTORY_UNAUTHORIZED.contains("queued"));
        assert_eq!(msg(ApiError::Http(503, "x".into()), None), SKILL_HISTORY_UNAVAILABLE);
        assert!(!SKILL_HISTORY_UNAVAILABLE.contains("queued"));
        assert_eq!(msg(ApiError::Http(404, "{\"error\":\"no such skill version\"}".into()), Some(9)),
            "Skill demo has no version 9. See `atem skill history demo`.");
        // A 404 that isn't the Station's own "no such skill version" (a
        // route the relay doesn't have) is reported as the error it is.
        assert_eq!(msg(ApiError::Http(404, "404 page not found".into()), Some(9)), "relay returned 404: 404 page not found");
        assert_eq!(msg(ApiError::Http(404, "".into()), None), "relay returned 404: ");
        assert!(msg(ApiError::Http(500, "boom".into()), None).contains("500"));
    }

    #[tokio::test]
    async fn chunks_walk_the_queue_in_order_past_the_other_kind() {
        let s = Store::open_in_memory().unwrap();
        // 120 memory adds with a skill delete after every tenth.
        for i in 0..120 {
            queue_memories(&s, &[format!("f{i:03}").as_str()]);
            if i % 10 == 9 {
                s.enqueue(&PendingOp::DeleteSkill { scope: Scope::Global, project: String::new(), name: format!("s{i:03}") }).unwrap();
            }
        }
        let (base, log) = stub_relay(Box::new(|m, p, body| empty_pulls(m, p).unwrap_or_else(|| ok_results(p, body)))).await;
        let (_td, ctx) = test_ctx();
        let out = run_sync(&s, Some(&client(&base, "ast-a")), &ctx, &NO_HARVEST).await.unwrap();
        assert!(out.notes.is_empty(), "{:?}", out.notes);
        assert_eq!(out.pushed, 132);
        assert_eq!(s.pending_count().unwrap(), 0);
        let posts = posted_ops(&log);
        assert_eq!(posts.iter().map(Vec::len).collect::<Vec<_>>(), vec![50, 50, 20, 8, 4]);
        let sent: Vec<&str> = posts.iter().flatten()
            .map(|o| o["memory"]["id"].as_str().or_else(|| o["name"].as_str()).unwrap()).collect();
        let want: Vec<String> = (0..120).map(|i| format!("mem_f{i:03}"))
            .chain((0..12).map(|k| format!("s{:03}", k * 10 + 9))).collect();
        assert_eq!(sent, want);
    }

    // ─────────────── a crash inside a store transaction ───────────────

    const T: i64 = 1_790_000_000;

    /// A relay that keeps its memory rows, so an op sent again meets what its
    /// first send did: an add of an id it has is a no-op, an add of a fact it
    /// has under another id (same scope, project, machine and content hash,
    /// still valid) is deduped onto that row (`canonical_id`), and
    /// invalidation is final (a repeat changes nothing). Skills travel as
    /// the Station's skill file transport carries them
    /// (`fake_station_skills`) and are numbered as the Station numbers them
    /// (`versioning`): by default its compare-and-set (Astation PR #76 at
    /// 89a2d50), each push stored at exactly its version when its base is
    /// the skill's latest version, tombstones and purged rows included, else
    /// a `version_conflict` with `current_version`; or renumbered as
    /// `max(version) + 1` like the Station before it. Every version stays a
    /// row. Every write takes the next seq; pulls page by seq.
    #[derive(Default)]
    pub(super) struct KeepingRelay {
        pub(super) rows: BTreeMap<String, Memory>,
        pub(super) skills: BTreeMap<i64, Skill>,
        next_seq: i64,
        pub(super) ops_received: usize,
        pub(super) versioning: crate::memory::fake_station_skills::Versioning,
        /// The seqs of purged skill rows (`/api/skills/version` answers 410).
        purged: HashSet<i64>,
    }

    impl KeepingRelay {
        pub(super) fn with(versioning: crate::memory::fake_station_skills::Versioning) -> Self {
            Self { versioning, ..Default::default() }
        }

        pub(super) fn put(&mut self, mut m: Memory) -> i64 {
            self.next_seq += 1;
            m.seq = self.next_seq;
            self.rows.insert(m.id.clone(), m);
            self.next_seq
        }

        pub(super) fn op(&mut self, op: &serde_json::Value) -> serde_json::Value {
            self.ops_received += 1;
            match op["op"].as_str().unwrap() {
                "add" => {
                    let m: Memory = serde_json::from_value(op["memory"].clone()).unwrap();
                    if let Some(r) = self.rows.get(&m.id) {
                        return serde_json::json!({"ok": true, "seq": r.seq});
                    }
                    let key = |r: &Memory| (r.scope, r.project.clone(), r.machine.clone(), r.content_hash.clone());
                    if let Some(r) = self.rows.values().find(|r| r.is_valid() && key(r) == key(&m)) {
                        return serde_json::json!({"ok": true, "seq": r.seq, "canonical_id": r.id});
                    }
                    serde_json::json!({"ok": true, "seq": self.put(m)})
                }
                "invalidate" => {
                    let Some(mut r) = self.rows.get(op["id"].as_str().unwrap()).cloned() else {
                        return serde_json::json!({"ok": true});
                    };
                    if r.invalid_at.is_none() {
                        r.invalid_at = op["invalid_at"].as_i64();
                        r.superseded_by = op["superseded_by"].as_str().map(str::to_string);
                        self.put(r);
                    }
                    serde_json::json!({"ok": true})
                }
                // An encryption migration's rewrite of a row's protected fields.
                "rewrite" => {
                    let mut r = self.rows[op["id"].as_str().unwrap()].clone();
                    for field in ["project", "content", "content_hash"] {
                        let value = op[field].as_str().unwrap().to_string();
                        match field {
                            "project" => r.project = value,
                            "content" => r.content = value,
                            _ => r.content_hash = value,
                        }
                    }
                    serde_json::json!({"ok": true, "seq": self.put(r)})
                }
                "delete" => serde_json::json!({"ok": true}),
                other => panic!("unexpected op {other}"),
            }
        }

        fn page(&self, since: i64, limit: usize) -> serde_json::Value {
            let mut rows: Vec<&Memory> = self.rows.values().filter(|r| r.seq > since).collect();
            rows.sort_by_key(|r| r.seq);
            rows.truncate(limit);
            serde_json::json!({"memories": rows})
        }

        fn latest_skill(&self, name: &str) -> Option<&Skill> {
            self.skills.values().filter(|s| s.name == name).max_by_key(|s| s.version)
        }

        /// The stored row of `scope`, `project` (as stored), `name` at `version`.
        pub(super) fn skill_at(&self, scope: &str, project: &str, name: &str, version: i64) -> Option<&Skill> {
            self.skills.values().find(|s| s.scope.as_str() == scope && s.project == project && s.name == name && s.version == version)
        }

        pub(super) fn put_skill(&mut self, mut skill: Skill) -> i64 {
            self.next_seq += 1;
            skill.seq = self.next_seq;
            self.skills.insert(skill.seq, skill);
            self.next_seq
        }

        pub(super) fn skill_op(&mut self, op: &serde_json::Value) -> serde_json::Value {
            self.ops_received += 1;
            let key = |s: &Skill| (s.scope.as_str().to_string(), s.project.clone(), s.name.clone());
            let named = (
                op["scope"].as_str().unwrap_or("").to_string(),
                op["project"].as_str().unwrap_or("").to_string(),
                op["name"].as_str().unwrap_or("").to_string(),
            );
            match op["op"].as_str().unwrap() {
                "push" => {}
                // As the Station: a tombstone appended at the next version
                // (nothing for a skill it doesn't have).
                "delete" => {
                    let Some(latest) = self.skills.values().filter(|s| key(s) == named).max_by_key(|s| s.version).cloned() else {
                        return serde_json::json!({"ok": true, "version": 0, "seq": 0});
                    };
                    let version = latest.version + 1;
                    let tombstone = Skill { version, files: BTreeMap::new(), content_hash: String::new(), deleted: true, ..latest };
                    return serde_json::json!({"ok": true, "version": version, "seq": self.put_skill(tombstone)});
                }
                // As the Station: the chosen versions (all without a list)
                // blanked, each under a new seq.
                "purge" => {
                    let chosen: Option<Vec<i64>> = serde_json::from_value(op["versions"].clone()).unwrap_or(None);
                    let seqs: Vec<i64> = self.skills.values()
                        .filter(|s| key(s) == named && chosen.as_ref().is_none_or(|v| v.contains(&s.version)))
                        .map(|s| s.seq)
                        .collect();
                    for seq in seqs {
                        let mut row = self.skills.remove(&seq).unwrap();
                        row.files.clear();
                        row.content_hash.clear();
                        row.deleted = true;
                        let seq = self.put_skill(row);
                        self.purged.insert(seq);
                    }
                    return serde_json::json!({"ok": true});
                }
                "rewrite" => {
                    let (name, version) = (op["name"].as_str().unwrap(), op["version"].as_i64().unwrap());
                    let seq = self.skills.values().find(|k| k.name == name && k.version == version).unwrap().seq;
                    let mut skill = self.skills.remove(&seq).unwrap();
                    skill.project = op["project"].as_str().unwrap().into();
                    skill.files = crate::memory::model::b64map::deserialize(&op["files"]).unwrap();
                    skill.content_hash = op["content_hash"].as_str().unwrap().into();
                    return serde_json::json!({"ok": true, "version": version, "seq": self.put_skill(skill)});
                }
                other => panic!("unexpected skill op {other}"),
            }
            let mut skill: Skill = serde_json::from_value(op["skill"].clone()).unwrap();
            let existing: Vec<(i64, bool)> = self.skills.values()
                .filter(|s| (s.scope, &s.project, &s.name) == (skill.scope, &skill.project, &skill.name))
                .map(|s| (s.version, s.deleted))
                .collect();
            let (version, superseded) = match crate::memory::fake_station_skills::push_version(self.versioning, op, existing) {
                Ok(placed) => placed,
                Err(conflict) => return conflict,
            };
            skill.version = version;
            let seq = self.put_skill(skill);
            serde_json::json!({"ok": true, "version": version, "seq": seq, "superseded_concurrent": superseded})
        }

        fn skill_page(&self, since: i64, limit: usize) -> serde_json::Value {
            crate::memory::fake_station_skills::page(self.skills.range(since + 1..).map(|(_, s)| s).take(limit))
        }
    }

    pub(super) fn keeping_relay(relay: Arc<Mutex<KeepingRelay>>) -> Box<Handler> {
        Box::new(move |m, p, body| {
            let (path, query) = p.split_once('?').unwrap_or((p, ""));
            let arg = |k: &str| query.split('&').find_map(|kv| kv.strip_prefix(k)?.strip_prefix('=')?.parse::<i64>().ok());
            let mut r = relay.lock().unwrap();
            match (m, path) {
                ("POST", "/api/memory/batch") => {
                    let results: Vec<_> = body["ops"].as_array().unwrap().iter().map(|op| r.op(op)).collect();
                    (200, serde_json::json!({"results": results}))
                }
                ("POST", "/api/skills/batch") => crate::memory::fake_station_skills::batch(body, |op| r.skill_op(op)),
                ("GET", "/api/memory") => (200, r.page(arg("since").unwrap_or(0), arg("limit").unwrap_or(200) as usize)),
                ("GET", "/api/skills") => (200, r.skill_page(arg("since").unwrap_or(0), arg("limit").unwrap_or(200) as usize)),
                ("GET", "/api/skills/version") => {
                    let text = |k: &str| query.split('&').find_map(|kv| kv.strip_prefix(k)?.strip_prefix('='))
                        .map(|v| urlencoding::decode(v).unwrap().into_owned()).unwrap_or_default();
                    let stored = r.skill_at(&text("scope"), &text("project"), &text("name"), arg("version").unwrap_or(0));
                    let purged = stored.is_some_and(|s| r.purged.contains(&s.seq));
                    crate::memory::fake_station_skills::version_answer(stored, purged)
                }
                _ => panic!("unexpected request {m} {p}"),
            }
        })
    }

    /// Arm a crash inside the store's next transaction: `trigger` creates a
    /// TEMP trigger that calls `crash()`. That copies the database file and
    /// its rollback journal into `image`'s directory, as a process killed at
    /// that instant leaves them on disk, then fails the statement (the sync
    /// gets an error and its transaction rolls back). It copies the database
    /// and `-journal` only (the store's default rollback journal): a switch to
    /// WAL must also copy `-wal` and `-shm`.
    pub(super) fn arm_crash(s: &Store, db: &Path, image: &Path, trigger: &str) {
        use rusqlite::functions::FunctionFlags;
        let (db, image) = (db.to_path_buf(), image.to_path_buf());
        s.test_conn().create_scalar_function("crash", 0, FunctionFlags::SQLITE_UTF8, move |_| -> rusqlite::Result<i64> {
            let copy = || -> std::io::Result<()> {
                std::fs::create_dir_all(image.parent().unwrap())?;
                for suffix in ["", "-journal"] {
                    let (mut from, mut to) = (db.clone().into_os_string(), image.clone().into_os_string());
                    from.push(suffix);
                    to.push(suffix);
                    if Path::new(&from).exists() {
                        std::fs::copy(&from, &to)?;
                    }
                }
                Ok(())
            };
            copy().map_err(|e| rusqlite::Error::UserFunctionError(e.into()))?;
            Err(rusqlite::Error::UserFunctionError("injected crash".into()))
        }).unwrap();
        s.test_conn().execute_batch(trigger).unwrap();
    }

    #[tokio::test]
    async fn a_crash_while_push_results_are_applied_leaves_the_chunk_queued_and_the_next_sync_completes() {
        let td = tempfile::tempdir().unwrap();
        let (db, image) = (td.path().join("knowledge.db"), td.path().join("crash/knowledge.db"));
        let relay = Arc::new(Mutex::new(KeepingRelay::default()));
        let mut old = valid("mem_old", "port 8765");
        {
            let mut r = relay.lock().unwrap();
            r.put(valid("mem_canon", "beta")); // another machine added "beta" first
            old.seq = r.put(old.clone()); // synced from here earlier
        }
        let s = Store::open(&db).unwrap();
        s.upsert_memory(&old).unwrap();
        queue_memories(&s, &["alpha", "beta"]); // ops 1 and 2
        s.harvest_put(&HarvestEntry { origin: "m1:/x/beta.md".into(), memory_id: "mem_beta".into(), content_hash: content_hash("beta"), status: HarvestStatus::Synced }).unwrap();
        assert!(invalidate_and_queue(&s, "mem_old", T, Some("mem_alpha")).unwrap()); // op 3
        queue_memories(&s, &["gamma"]); // op 4
        let queued = s.pending().unwrap();
        let rows_before = s.history_memories().unwrap();
        // At op 3's ack: ops 1 and 2 were applied (a seq, a canonical rewrite) and acked.
        arm_crash(&s, &db, &image, &format!(
            "CREATE TEMP TRIGGER crash_mid_chunk BEFORE DELETE ON pending_ops WHEN old.n = {} BEGIN SELECT crash(); END;", queued[2].0));
        let (base, _log) = stub_relay(keeping_relay(relay.clone())).await;
        let (_home, ctx) = test_ctx();
        let err = run_sync(&s, Some(&client(&base, "ast-a")), &ctx, &NO_HARVEST).await.unwrap_err();
        assert!(format!("{err:#}").contains("injected crash"), "{err:#}");
        assert_eq!(relay.lock().unwrap().ops_received, 4); // the relay applied the chunk
        drop(s);

        // As the crash left the disk, and after the error's rollback: the
        // chunk still queued as it was, none of its results applied.
        let as_before = |s: &Store| {
            assert_eq!(s.pending().unwrap(), queued);
            assert_eq!(s.history_memories().unwrap(), rows_before);
            assert!(s.get_memory("mem_canon").unwrap().is_none());
            assert_eq!(s.harvest_get("m1:/x/beta.md").unwrap().unwrap().memory_id, "mem_beta");
            assert_eq!(s.get_state(LAST_SYNC_AT).unwrap(), 0);
        };
        as_before(&Store::open(&db).unwrap());
        let s = Store::open(&image).unwrap();
        as_before(&s);

        // The next sync sends the chunk again and completes.
        let out = run_sync(&s, Some(&client(&base, "ast-a")), &ctx, &NO_HARVEST).await.unwrap();
        assert!(out.notes.is_empty() && !out.relay_error && !out.offline, "{:?}", out.notes);
        assert_eq!(out.pushed, 4);
        assert_eq!(s.pending_count().unwrap(), 0);
        assert!(s.get_state(LAST_SYNC_AT).unwrap() > 0);
        let r = relay.lock().unwrap();
        // Sent twice, applied once: one row per fact, the invalidation as first sent.
        assert_eq!(r.ops_received, 8);
        assert_eq!(r.rows.keys().map(String::as_str).collect::<Vec<_>>(), vec!["mem_alpha", "mem_canon", "mem_gamma", "mem_old"]);
        assert_eq!((r.rows["mem_old"].invalid_at, r.rows["mem_old"].superseded_by.as_deref()), (Some(T), Some("mem_alpha")));
        // This store holds the relay's rows exactly, the canonical rewrite done.
        assert_eq!(s.history_memories().unwrap().len(), r.rows.len());
        for row in r.rows.values() {
            assert_eq!(s.get_memory(&row.id).unwrap().as_ref(), Some(row), "{}", row.id);
        }
        assert_eq!(s.harvest_get("m1:/x/beta.md").unwrap().unwrap().memory_id, "mem_canon");
        assert_eq!(s.get_state(&memory_cursor_key("ast-a")).unwrap(), r.next_seq);
    }

    #[tokio::test]
    async fn a_crash_inside_a_pulled_page_keeps_the_cursor_at_the_last_whole_page() {
        let td = tempfile::tempdir().unwrap();
        let (db, image) = (td.path().join("knowledge.db"), td.path().join("crash/knowledge.db"));
        let page = PULL_LIMIT as usize;
        let total = 2 * page + 50;
        let relay = Arc::new(Mutex::new(KeepingRelay::default()));
        {
            let mut r = relay.lock().unwrap();
            for i in 1..=total {
                let mut m = valid(&format!("mem_r{i:03}"), &format!("remote fact {i}"));
                m.source_machine = "m2".into();
                r.put(m);
            }
        }
        let s = Store::open(&db).unwrap();
        // Half way through the second page.
        arm_crash(&s, &db, &image, &format!(
            "CREATE TEMP TRIGGER crash_mid_page BEFORE INSERT ON memories WHEN new.id = 'mem_r{:03}' BEGIN SELECT crash(); END;", page + page / 2));
        let (base, _log) = stub_relay(keeping_relay(relay.clone())).await;
        let (_home, ctx) = test_ctx();
        let err = run_sync(&s, Some(&client(&base, "ast-a")), &ctx, &NO_HARVEST).await.unwrap_err();
        assert!(format!("{err:#}").contains("injected crash"), "{err:#}");
        drop(s);

        // The first page whole, with its cursor; nothing of the second.
        let first_page_only = |s: &Store| {
            let cursor = s.get_state(&memory_cursor_key("ast-a")).unwrap();
            assert_eq!(cursor, page as i64);
            let rows = s.history_memories().unwrap();
            assert_eq!(rows.len(), page);
            assert!(rows.iter().all(|m| m.seq <= cursor));
            assert_eq!(s.get_state(LAST_SYNC_AT).unwrap(), 0);
        };
        first_page_only(&Store::open(&db).unwrap());
        let s = Store::open(&image).unwrap();
        first_page_only(&s);

        // The next sync pulls the second page again, whole, and the rest.
        let out = run_sync(&s, Some(&client(&base, "ast-a")), &ctx, &NO_HARVEST).await.unwrap();
        assert!(out.notes.is_empty() && !out.relay_error && !out.offline, "{:?}", out.notes);
        assert_eq!(out.pulled, total - page);
        assert_eq!(s.get_state(&memory_cursor_key("ast-a")).unwrap(), total as i64);
        let r = relay.lock().unwrap();
        assert_eq!(s.history_memories().unwrap().len(), total);
        for row in r.rows.values() {
            assert_eq!(s.get_memory(&row.id).unwrap().as_ref(), Some(row), "{}", row.id);
        }
    }

    pub(super) fn skill_v1(name: &str, body: &str, machine: &str) -> Skill {
        let mut files = BTreeMap::new();
        files.insert("SKILL.md".to_string(), body.as_bytes().to_vec());
        Skill {
            scope: Scope::Global, project: String::new(), name: name.into(), version: 1,
            content_hash: skill_hash(&files), files, source_agent: "cli".into(), source_machine: machine.into(),
            created_at: 1, deleted: false, seq: 0,
        }
    }

    /// The Station before Astation PR #76, which renumbers every push (plain skills, so
    /// the renumbered rows stay readable here).
    #[tokio::test]
    async fn a_crash_while_skill_push_results_are_applied_leaves_every_skill_op_queued() {
        let td = tempfile::tempdir().unwrap();
        let (db, image) = (td.path().join("knowledge.db"), td.path().join("crash/knowledge.db"));
        let relay = Arc::new(Mutex::new(KeepingRelay::with(crate::memory::fake_station_skills::Versioning::Renumbered)));
        relay.lock().unwrap().put_skill(skill_v1("beta", "# beta from m2", "m2")); // another machine pushed beta first
        let s = Store::open(&db).unwrap();
        for name in ["alpha", "beta", "gamma"] {
            let skill = skill_v1(name, &format!("# {name}"), "m1");
            s.put_skill(&skill).unwrap();
            s.enqueue(&PendingOp::PushSkill { skill, base_version: 0 }).unwrap();
        }
        let queued = s.pending().unwrap();
        let skills_before = s.all_skills().unwrap();
        // At op 2's ack: op 1 was acked, op 2's result applied (beta moved to the relay's v2).
        arm_crash(&s, &db, &image, &format!(
            "CREATE TEMP TRIGGER crash_mid_skill_batch BEFORE DELETE ON pending_ops WHEN old.n = {} BEGIN SELECT crash(); END;", queued[1].0));
        let (base, _log) = stub_relay(keeping_relay(relay.clone())).await;
        let (_home, ctx) = test_ctx();
        let err = run_sync(&s, Some(&client(&base, "ast-a")), &ctx, &NO_HARVEST).await.unwrap_err();
        assert!(format!("{err:#}").contains("injected crash"), "{err:#}");
        assert_eq!(relay.lock().unwrap().ops_received, 3); // the relay applied the batch
        drop(s);

        // As the crash left the disk, and after the error's rollback: no
        // skill op acked, none of the batch's results applied.
        let as_before = |s: &Store| {
            assert_eq!(s.pending().unwrap(), queued);
            assert_eq!(s.all_skills().unwrap(), skills_before);
            assert_eq!(s.get_state(&skill_cursor_key("ast-a")).unwrap(), 0);
            assert_eq!(s.get_state(LAST_SYNC_AT).unwrap(), 0);
        };
        as_before(&Store::open(&db).unwrap());
        let s = Store::open(&image).unwrap();
        as_before(&s);

        // The next sync sends the batch again and completes. The relay
        // appends every push as a new version (designs/atem-memory.md), so the
        // re-sent pushes are new versions, each flagged concurrent.
        let out = run_sync(&s, Some(&client(&base, "ast-a")), &ctx, &NO_HARVEST).await.unwrap();
        assert!(!out.relay_error && !out.offline, "{:?}", out.notes);
        assert_eq!(out.pushed, 3);
        assert_eq!(out.notes.len(), 3, "{:?}", out.notes);
        assert!(out.notes.iter().all(|n| n.contains("another machine pushed an edit at the same time")), "{:?}", out.notes);
        assert_eq!(s.pending_count().unwrap(), 0);
        assert!(s.get_state(LAST_SYNC_AT).unwrap() > 0);
        let r = relay.lock().unwrap();
        assert_eq!(r.ops_received, 6);
        let versions = |name: &str| r.skills.values().filter(|k| k.name == name).map(|k| k.version).collect::<Vec<_>>();
        assert_eq!((versions("alpha"), versions("beta"), versions("gamma")), (vec![1, 2], vec![1, 2, 3], vec![1, 2]));
        // This store holds each skill's latest relay version exactly.
        assert_eq!(s.all_skills().unwrap().len(), 3);
        for name in ["alpha", "beta", "gamma"] {
            assert_eq!(s.get_skill(Scope::Global, "", name).unwrap().as_ref(), r.latest_skill(name), "{name}");
        }
        assert_eq!(s.get_state(&skill_cursor_key("ast-a")).unwrap(), r.next_seq);
    }

    #[tokio::test]
    async fn a_crash_inside_a_pulled_skill_page_keeps_the_skill_cursor_at_the_last_whole_page() {
        let td = tempfile::tempdir().unwrap();
        let (db, image) = (td.path().join("knowledge.db"), td.path().join("crash/knowledge.db"));
        let page = PULL_LIMIT as usize;
        let total = 2 * page + 50;
        let relay = Arc::new(Mutex::new(KeepingRelay::default()));
        {
            let mut r = relay.lock().unwrap();
            for i in 1..=total {
                r.put_skill(skill_v1(&format!("skill{i:03}"), &format!("# skill {i}"), "m2"));
            }
        }
        let s = Store::open(&db).unwrap();
        // Half way through the second skill page.
        arm_crash(&s, &db, &image, &format!(
            "CREATE TEMP TRIGGER crash_mid_skill_page BEFORE INSERT ON skills WHEN new.name = 'skill{:03}' BEGIN SELECT crash(); END;", page + page / 2));
        let (base, _log) = stub_relay(keeping_relay(relay.clone())).await;
        let (_home, ctx) = test_ctx();
        let err = run_sync(&s, Some(&client(&base, "ast-a")), &ctx, &NO_HARVEST).await.unwrap_err();
        assert!(format!("{err:#}").contains("injected crash"), "{err:#}");
        drop(s);

        // The first skill page whole, with its cursor; nothing of the second.
        let first_page_only = |s: &Store| {
            let cursor = s.get_state(&skill_cursor_key("ast-a")).unwrap();
            assert_eq!(cursor, page as i64);
            let skills = s.all_skills().unwrap();
            assert_eq!(skills.len(), page);
            assert!(skills.iter().all(|k| k.seq <= cursor));
            assert_eq!(s.get_state(LAST_SYNC_AT).unwrap(), 0);
        };
        first_page_only(&Store::open(&db).unwrap());
        let s = Store::open(&image).unwrap();
        first_page_only(&s);

        // The next sync pulls the second page again, whole, and the rest.
        let out = run_sync(&s, Some(&client(&base, "ast-a")), &ctx, &NO_HARVEST).await.unwrap();
        assert!(out.notes.is_empty() && !out.relay_error && !out.offline, "{:?}", out.notes);
        assert_eq!(out.pulled, total - page);
        assert_eq!(s.get_state(&skill_cursor_key("ast-a")).unwrap(), total as i64);
        let r = relay.lock().unwrap();
        assert_eq!(s.all_skills().unwrap().len(), total);
        for row in r.skills.values() {
            assert_eq!(s.get_skill(row.scope, &row.project, &row.name).unwrap().as_ref(), Some(row), "{}", row.name);
        }
    }

    /// A route the relay doesn't have (a 404 that isn't the Station's "no
    /// such skill version") is an error like any other.
    #[tokio::test]
    async fn restore_and_history_report_a_route_level_404_as_an_error() {
        let s = Store::open_in_memory().unwrap();
        let (base, _log) = stub_relay(Box::new(|_, _, _| (404, serde_json::json!("404 page not found")))).await;
        let c = client(&base, "ast-a");
        let err = restore_skill(&s, &c, "m1", Scope::Global, "", "demo", 4).await.unwrap_err();
        assert_eq!(err.to_string(), "relay returned 404: \"404 page not found\"");
        let err = c.skill_versions(Scope::Global, "", "demo").await.map_err(|e| skill_history_error(e, "demo", None)).unwrap_err();
        assert_eq!(err.to_string(), "relay returned 404: \"404 page not found\"");
        assert_eq!(s.pending_count().unwrap(), 0);
    }

    /// The Station keeps each push at its version (compare-and-set): after a
    /// crash before the results were committed, the re-sent pushes meet
    /// their own applied writes (`version_conflict`, then the same content
    /// hash and metadata at that version) and are acked with no duplicate;
    /// the one that met another machine's version is re-based and lands at
    /// the next sync.
    #[tokio::test]
    async fn after_a_crash_the_resent_skill_pushes_are_acked_without_duplicates() {
        let td = tempfile::tempdir().unwrap();
        let (db, image) = (td.path().join("knowledge.db"), td.path().join("crash/knowledge.db"));
        let relay = Arc::new(Mutex::new(KeepingRelay::default()));
        relay.lock().unwrap().put_skill(skill_v1("beta", "# beta from m2", "m2")); // another machine pushed beta first
        let s = Store::open(&db).unwrap();
        for name in ["alpha", "beta", "gamma"] {
            let skill = skill_v1(name, &format!("# {name}"), "m1");
            s.put_skill(&skill).unwrap();
            s.enqueue(&PendingOp::PushSkill { skill, base_version: 0 }).unwrap();
        }
        let queued = s.pending().unwrap();
        arm_crash(&s, &db, &image, &format!(
            "CREATE TEMP TRIGGER crash_mid_skill_batch BEFORE DELETE ON pending_ops WHEN old.n = {} BEGIN SELECT crash(); END;", queued[0].0));
        let (base, log) = stub_relay(keeping_relay(relay.clone())).await;
        let (_home, ctx) = test_ctx();
        let err = run_sync(&s, Some(&client(&base, "ast-a")), &ctx, &NO_HARVEST).await.unwrap_err();
        assert!(format!("{err:#}").contains("injected crash"), "{err:#}");
        drop(s);
        let s = Store::open(&image).unwrap();
        assert_eq!(s.pending().unwrap(), queued);

        let out = run_sync(&s, Some(&client(&base, "ast-a")), &ctx, &NO_HARVEST).await.unwrap();
        assert!(!out.relay_error && !out.offline, "{:?}", out.notes);
        assert_eq!(out.notes.len(), 1, "{:?}", out.notes);
        assert!(out.notes[0].starts_with("skill beta: another machine pushed an edit at the same time"), "{:?}", out.notes);
        let left = s.pending().unwrap();
        assert!(matches!(&left[..], [(_, PendingOp::PushSkill { skill, base_version: 1 })] if skill.name == "beta" && skill.version == 2), "{left:?}");
        let out = run_sync(&s, Some(&client(&base, "ast-a")), &ctx, &NO_HARVEST).await.unwrap();
        assert!(out.notes.is_empty() && !out.relay_error, "{:?}", out.notes);
        assert_eq!(s.pending_count().unwrap(), 0);
        let r = relay.lock().unwrap();
        let versions = |name: &str| r.skills.values().filter(|k| k.name == name).map(|k| k.version).collect::<Vec<_>>();
        assert_eq!((versions("alpha"), versions("beta"), versions("gamma")), (vec![1], vec![1, 2], vec![1]));
        assert_eq!(s.get_skill(Scope::Global, "", "beta").unwrap().unwrap().files[&"SKILL.md".to_string()], b"# beta");
        // Each conflict cost one GET of the conflicting version: beta's
        // before the crash, then all three.
        let gets = log.lock().unwrap().iter().filter(|(m, p, _)| m == "GET" && p.starts_with("/api/skills/version?")).count();
        assert_eq!(gets, 1 + 3);
    }

    /// A conflict Atem couldn't check (the version's GET failed) changes
    /// nothing: the push stays queued as it was, and the push stops there.
    #[tokio::test]
    async fn an_unchecked_version_conflict_leaves_the_push_queued_as_it_was() {
        let s = Store::open_in_memory().unwrap();
        queue_skill(&s, "deploy");
        let queued = s.pending().unwrap();
        let (base, log) = stub_relay(Box::new(|m, p, _| {
            if m == "POST" && p.starts_with("/api/skills/batch?") {
                return (200, serde_json::json!({"results": [{"ok": false, "error": "version_conflict", "current_version": 1}]}));
            }
            if p.starts_with("/api/skills/version?") {
                return (503, serde_json::json!({"error": "temporarily unavailable"}));
            }
            empty_pulls(m, p).unwrap()
        })).await;
        let (_td, ctx) = test_ctx();
        let out = run_sync(&s, Some(&client(&base, "ast-a")), &ctx, &NO_HARVEST).await.unwrap();
        assert!(out.relay_error, "{:?}", out.notes);
        assert_eq!(out.notes.len(), 1, "{:?}", out.notes);
        assert_eq!(out.notes[0], "skill deploy: the Station reports a version conflict, but reading v1 to check it failed; it stays queued for the next sync.");
        assert_eq!(s.pending().unwrap(), queued);
        assert_eq!(s.get_skill(Scope::Global, "", "deploy").unwrap().unwrap().version, 1);
        assert_eq!(skill_requests(&log), [("POST", "/api/skills/batch"), ("GET", "/api/skills/version"), ("GET", "/api/skills")]
            .map(|(m, p)| (m.to_string(), p.to_string())));
    }

    /// A conflict whose answer names no usable latest version (none, or one
    /// out of range: a protocol error) is never settled from it: the push
    /// stays queued as it was, and the note says which.
    #[tokio::test]
    async fn a_version_conflict_without_a_usable_current_version_leaves_the_push_queued() {
        let answers = [
            (serde_json::json!({"ok": false, "error": "version_conflict"}), "the answer names no current version (a protocol error)"),
            (serde_json::json!({"ok": false, "error": "version_conflict", "current_version": -1}), "the answer names v-1 as the latest, out of range (a protocol error)"),
            (serde_json::json!({"ok": false, "error": "version_conflict", "current_version": i64::MAX}), "out of range (a protocol error)"),
        ];
        for (answer, why) in answers {
            let s = Store::open_in_memory().unwrap();
            queue_skill(&s, "deploy");
            let queued = s.pending().unwrap();
            let (base, log) = stub_relay(Box::new(move |m, p, _| {
                if m == "POST" && p.starts_with("/api/skills/batch?") {
                    return (200, serde_json::json!({"results": [answer.clone()]}));
                }
                empty_pulls(m, p).unwrap()
            })).await;
            let (_td, ctx) = test_ctx();
            let out = run_sync(&s, Some(&client(&base, "ast-a")), &ctx, &NO_HARVEST).await.unwrap();
            assert!(out.relay_error, "{why}: {:?}", out.notes);
            assert!(out.notes.len() == 1 && out.notes[0].contains(why), "{why}: {:?}", out.notes);
            assert_eq!(s.pending().unwrap(), queued, "{why}");
            // Nothing was read to check it.
            assert!(!skill_requests(&log).iter().any(|(_, p)| p == "/api/skills/version"), "{why}");
        }
    }

    /// A push the Station refused per op for good is acked, so the local copy stays
    /// at a version the Station never stored; the next edit bases on it, and
    /// the Station's latest version comes back below the base. That is a
    /// legal conflict, not a protocol error: the edit is coalesced onto the
    /// Station's version and lands, and the ops after it aren't stuck.
    #[tokio::test]
    async fn a_push_based_above_the_stations_latest_version_lands_after_its_conflict() {
        let relay = Arc::new(Mutex::new(KeepingRelay::default()));
        let keeping = keeping_relay(relay.clone());
        let refuse = std::sync::atomic::AtomicBool::new(true);
        let (base, log) = stub_relay(Box::new(move |m, p, body| {
            if m == "POST" && p.starts_with("/api/skills/batch?") && refuse.swap(false, std::sync::atomic::Ordering::SeqCst) {
                let n = body["ops"].as_array().unwrap().len();
                return (200, serde_json::json!({"results": vec![serde_json::json!({"ok": false, "error": "possible credential: SKILL.md: jwt"}); n]}));
            }
            keeping(m, p, body)
        })).await;
        let s = Store::open_in_memory().unwrap();
        let (_td, ctx) = test_ctx();
        queue_skill(&s, "deploy");
        let out = run_sync(&s, Some(&client(&base, "ast-a")), &ctx, &NO_HARVEST).await.unwrap();
        assert!(out.notes.iter().any(|n| n.starts_with("relay refused skill deploy v1")), "{:?}", out.notes);
        assert_eq!(s.pending_count().unwrap(), 0);
        // `atem skill add` on the local v1, then another skill after it.
        let edit = Skill { version: 2, ..skill_v1("deploy", "# deploy, edited", "m1") };
        let edit = Skill { content_hash: skill_hash(&edit.files), ..edit };
        s.put_skill(&edit).unwrap();
        s.enqueue(&PendingOp::PushSkill { skill: edit.clone(), base_version: 1 }).unwrap();
        queue_skill(&s, "other");
        let out = run_sync(&s, Some(&client(&base, "ast-a")), &ctx, &NO_HARVEST).await.unwrap();
        assert!(!out.relay_error, "{:?}", out.notes);
        assert_eq!(out.notes, vec!["skill deploy: the Station's latest version is v0, behind this machine's copy (a push it refused earlier, or a delete of a skill it didn't have); this edit goes out as v1 at the next sync.".to_string()]);
        let left = s.pending().unwrap();
        assert!(matches!(&left[..], [(_, PendingOp::PushSkill { skill, base_version: 0 })] if skill.name == "deploy" && skill.version == 1), "{left:?}");
        let out = run_sync(&s, Some(&client(&base, "ast-a")), &ctx, &NO_HARVEST).await.unwrap();
        assert!(out.notes.is_empty() && !out.relay_error, "{:?}", out.notes);
        assert_eq!(s.pending_count().unwrap(), 0);
        let r = relay.lock().unwrap();
        let versions = |name: &str| r.skills.values().filter(|k| k.name == name).map(|k| k.version).collect::<Vec<_>>();
        assert_eq!((versions("deploy"), versions("other")), (vec![1], vec![1]));
        assert_eq!(r.latest_skill("deploy").unwrap().files, edit.files);
        // Never stored, so nothing was read to check it.
        assert!(!skill_requests(&log).iter().any(|(_, p)| p == "/api/skills/version"));
    }

    /// A push that meets another machine's version, followed in the same
    /// batch by a delete (or a purge of every version) of the skill that
    /// lands: the push is withdrawn, never coalesced, so the skill stays
    /// deleted (or erased) on every device and the purged content never
    /// goes back to the relay.
    #[tokio::test]
    async fn a_delete_or_purge_in_the_same_batch_withdraws_a_conflicted_push() {
        for purge in [false, true] {
            let relay = Arc::new(Mutex::new(KeepingRelay::default()));
            relay.lock().unwrap().put_skill(skill_v1("deploy", "# deploy from m2", "m2"));
            let (base, _log) = stub_relay(keeping_relay(relay.clone())).await;
            let s = Store::open_in_memory().unwrap();
            let mine = skill_v1("deploy", "# deploy with a leaked value", "m1");
            s.put_skill(&mine).unwrap();
            s.enqueue(&PendingOp::PushSkill { skill: mine.clone(), base_version: 0 }).unwrap();
            let mut local = mine.clone();
            local.deleted = true;
            local.files.clear();
            local.content_hash.clear();
            if purge {
                // As `atem skill purge deploy --all-versions`.
                s.put_skill(&local).unwrap();
                s.enqueue(&PendingOp::PurgeSkill { scope: Scope::Global, project: String::new(), name: "deploy".into(), versions: None }).unwrap();
            } else {
                // As `atem skill rm deploy`.
                local.version += 1;
                s.put_skill(&local).unwrap();
                s.enqueue(&PendingOp::DeleteSkill { scope: Scope::Global, project: String::new(), name: "deploy".into() }).unwrap();
            }
            let (_td, ctx) = test_ctx();
            let out = run_sync(&s, Some(&client(&base, "ast-a")), &ctx, &NO_HARVEST).await.unwrap();
            assert!(out.notes.is_empty() && !out.relay_error, "purge {purge}: {:?}", out.notes);
            assert_eq!(s.pending_count().unwrap(), 0, "purge {purge}");
            assert!(s.get_skill(Scope::Global, "", "deploy").unwrap().unwrap().deleted, "purge {purge}");
            // Nothing goes later either.
            let out = run_sync(&s, Some(&client(&base, "ast-a")), &ctx, &NO_HARVEST).await.unwrap();
            assert!(out.notes.is_empty(), "purge {purge}: {:?}", out.notes);
            {
                let r = relay.lock().unwrap();
                assert!(r.latest_skill("deploy").unwrap().deleted, "purge {purge}");
                assert!(r.skills.values().all(|k| k.files.values().all(|bytes| bytes != b"# deploy with a leaked value")), "purge {purge}");
            }
            // Another device has it deleted too.
            let other = Store::open_in_memory().unwrap();
            let (_td2, ctx2) = test_ctx();
            run_sync(&other, Some(&client(&base, "ast-a")), &ctx2, &NO_HARVEST).await.unwrap();
            assert!(other.get_skill(Scope::Global, "", "deploy").unwrap().unwrap().deleted, "purge {purge}");
        }
    }

    /// In one batch: a push that meets another machine's version, then a
    /// delete (or a purge of every version) that withdraws it, then a re-add
    /// that conflicts with the new tombstone (or the purged row). The
    /// withdrawn push settles nothing for the skill, so the re-add is still
    /// coalesced in that sync and lands at the next; the withdrawn edit
    /// never reaches the relay.
    #[tokio::test]
    async fn a_conflicting_re_add_after_a_withdrawn_push_is_coalesced_in_the_same_sync() {
        for purge in [false, true] {
            let relay = Arc::new(Mutex::new(KeepingRelay::default()));
            {
                let mut r = relay.lock().unwrap();
                r.put_skill(skill_v1("deploy", "# deploy 1 from m2", "m2"));
                r.put_skill(Skill { version: 2, ..skill_v1("deploy", "# deploy 2 from m2", "m2") });
            }
            let (base, _log) = stub_relay(keeping_relay(relay.clone())).await;
            let s = Store::open_in_memory().unwrap();
            let first = skill_v1("deploy", "# first edit, withdrawn", "m1");
            s.put_skill(&first).unwrap();
            s.enqueue(&PendingOp::PushSkill { skill: first.clone(), base_version: 0 }).unwrap();
            let mut tombstone = first.clone();
            tombstone.deleted = true;
            tombstone.files.clear();
            tombstone.content_hash.clear();
            if purge {
                s.put_skill(&tombstone).unwrap();
                s.enqueue(&PendingOp::PurgeSkill { scope: Scope::Global, project: String::new(), name: "deploy".into(), versions: None }).unwrap();
            } else {
                tombstone.version += 1;
                s.put_skill(&tombstone).unwrap();
                s.enqueue(&PendingOp::DeleteSkill { scope: Scope::Global, project: String::new(), name: "deploy".into() }).unwrap();
            }
            // `atem skill add` again, on the local tombstone.
            let base_version = tombstone.version;
            let readd = Skill { version: base_version + 1, ..skill_v1("deploy", "# re-added", "m1") };
            let readd = Skill { content_hash: skill_hash(&readd.files), ..readd };
            s.put_skill(&readd).unwrap();
            s.enqueue(&PendingOp::PushSkill { skill: readd.clone(), base_version }).unwrap();
            let (_td, ctx) = test_ctx();
            let out = run_sync(&s, Some(&client(&base, "ast-a")), &ctx, &NO_HARVEST).await.unwrap();
            assert!(!out.relay_error, "purge {purge}: {:?}", out.notes);
            assert!(out.notes.iter().any(|n| n.starts_with("skill deploy: another machine pushed an edit at the same time")), "purge {purge}: {:?}", out.notes);
            let left = s.pending().unwrap();
            let current = if purge { 2 } else { 3 };
            assert!(
                matches!(&left[..], [(_, PendingOp::PushSkill { skill, base_version })] if *base_version == current && skill.version == current + 1 && skill.files == readd.files),
                "purge {purge}: {left:?}"
            );
            let out = run_sync(&s, Some(&client(&base, "ast-a")), &ctx, &NO_HARVEST).await.unwrap();
            assert!(out.notes.is_empty() && !out.relay_error, "purge {purge}: {:?}", out.notes);
            let r = relay.lock().unwrap();
            assert_eq!(r.latest_skill("deploy").unwrap().files, readd.files, "purge {purge}");
            assert!(r.skills.values().all(|k| k.files.values().all(|bytes| bytes != b"# first edit, withdrawn")), "purge {purge}");
        }
    }

    /// Another atem process queues an edit of a skill while this one pulls:
    /// the queued push is read in each page's transaction, so a row of that
    /// skill on a later page doesn't replace the unpushed edit.
    #[tokio::test]
    async fn an_edit_queued_by_another_process_during_the_pull_wins_locally() {
        let td = tempfile::tempdir().unwrap();
        let db = td.path().join("knowledge.db");
        let relay = Arc::new(Mutex::new(KeepingRelay::default()));
        {
            let mut r = relay.lock().unwrap();
            for i in 0..200 {
                r.put_skill(skill_v1(&format!("filler{i:03}"), "# filler", "m2"));
            }
            r.put_skill(skill_v1("target", "# target from m2", "m2"));
        }
        let keeping = keeping_relay(relay.clone());
        let other_db = db.clone();
        let (base, _log) = stub_relay(Box::new(move |m, p, body| {
            // The second page's request: another process queues an edit.
            if m == "GET" && p.starts_with("/api/skills?") && p.contains("since=200&") {
                let other = Store::open(&other_db).unwrap();
                let mine = skill_v1("target", "# target from this machine", "m1");
                other.put_skill(&mine).unwrap();
                other.enqueue(&PendingOp::PushSkill { skill: mine, base_version: 0 }).unwrap();
            }
            keeping(m, p, body)
        })).await;
        let s = Store::open(&db).unwrap();
        let (_td2, ctx) = test_ctx();
        let out = run_sync(&s, Some(&client(&base, "ast-a")), &ctx, &NO_HARVEST).await.unwrap();
        assert!(!out.relay_error, "{:?}", out.notes);
        assert!(out.notes.iter().any(|n| n.starts_with("skill target: another machine pushed an edit (v1) while this machine's edit waits to sync")), "{:?}", out.notes);
        let local = s.get_skill(Scope::Global, "", "target").unwrap().unwrap();
        assert_eq!(local.files["SKILL.md"], b"# target from this machine");
        assert_eq!(s.get_state(&skill_cursor_key("ast-a")).unwrap(), 201);
        assert!(s.has_queued_push(Scope::Global, "", "target").unwrap());
        assert!(!s.has_queued_push(Scope::Global, "", "filler000").unwrap());
    }

    /// The attempted version was purged (410): its content is gone, so it
    /// isn't this push's; the push is a concurrent edit, coalesced past it,
    /// and lands at the next sync.
    #[tokio::test]
    async fn a_conflict_on_a_purged_version_is_a_concurrent_edit() {
        let relay = Arc::new(Mutex::new(KeepingRelay::default()));
        {
            let mut r = relay.lock().unwrap();
            r.put_skill(skill_v1("beta", "# beta from m2", "m2"));
            r.skill_op(&serde_json::json!({"op": "purge", "scope": "global", "project": "", "name": "beta", "versions": [1]}));
        }
        let s = Store::open_in_memory().unwrap();
        queue_skill(&s, "beta");
        let (base, log) = stub_relay(keeping_relay(relay.clone())).await;
        let (_td, ctx) = test_ctx();
        let out = run_sync(&s, Some(&client(&base, "ast-a")), &ctx, &NO_HARVEST).await.unwrap();
        assert!(!out.relay_error, "{:?}", out.notes);
        assert!(out.notes.iter().any(|n| n.starts_with("skill beta: another machine pushed an edit at the same time")), "{:?}", out.notes);
        assert!(log.lock().unwrap().iter().any(|(m, p, _)| m == "GET" && p.starts_with("/api/skills/version?") && p.contains("version=1")));
        let left = s.pending().unwrap();
        assert!(matches!(&left[..], [(_, PendingOp::PushSkill { skill, base_version: 1 })] if skill.version == 2), "{left:?}");
        let out = run_sync(&s, Some(&client(&base, "ast-a")), &ctx, &NO_HARVEST).await.unwrap();
        assert!(out.notes.is_empty() && !out.relay_error, "{:?}", out.notes);
        let r = relay.lock().unwrap();
        let mut versions: Vec<i64> = r.skills.values().filter(|k| k.name == "beta").map(|k| k.version).collect();
        versions.sort();
        assert_eq!(versions, vec![1, 2]);
    }

    /// A crash inside the coalescing writes of a batch's results (the
    /// squashed push acked, the newest re-based) leaves the whole batch
    /// queued as it was; the next sync settles it again the same way, and
    /// the newest edit lands once.
    #[tokio::test]
    async fn a_crash_while_a_conflict_is_coalesced_leaves_the_batch_queued() {
        let td = tempfile::tempdir().unwrap();
        let (db, image) = (td.path().join("knowledge.db"), td.path().join("crash/knowledge.db"));
        let relay = Arc::new(Mutex::new(KeepingRelay::default()));
        {
            let mut r = relay.lock().unwrap();
            r.put_skill(skill_v1("beta", "# beta 1 from m2", "m2"));
            r.put_skill(Skill { version: 2, ..skill_v1("beta", "# beta 2 from m2", "m2") });
        }
        let s = Store::open(&db).unwrap();
        let first = skill_v1("beta", "# first edit", "m1");
        let second = Skill { version: 2, ..skill_v1("beta", "# second edit", "m1") };
        s.put_skill(&first).unwrap();
        s.enqueue(&PendingOp::PushSkill { skill: first, base_version: 0 }).unwrap();
        s.put_skill(&second).unwrap();
        s.enqueue(&PendingOp::PushSkill { skill: second.clone(), base_version: 1 }).unwrap();
        let queued = s.pending().unwrap();
        let local = s.all_skills().unwrap();
        arm_crash(&s, &db, &image, "CREATE TEMP TRIGGER crash_in_coalesce BEFORE UPDATE ON pending_ops BEGIN SELECT crash(); END;");
        let (base, _log) = stub_relay(keeping_relay(relay.clone())).await;
        let (_home, ctx) = test_ctx();
        let err = run_sync(&s, Some(&client(&base, "ast-a")), &ctx, &NO_HARVEST).await.unwrap_err();
        assert!(format!("{err:#}").contains("injected crash"), "{err:#}");
        drop(s);
        for s in [Store::open(&db).unwrap(), Store::open(&image).unwrap()] {
            assert_eq!(s.pending().unwrap(), queued);
            assert_eq!(s.all_skills().unwrap(), local);
        }
        let s = Store::open(&image).unwrap();
        let out = run_sync(&s, Some(&client(&base, "ast-a")), &ctx, &NO_HARVEST).await.unwrap();
        assert!(!out.relay_error, "{:?}", out.notes);
        let left = s.pending().unwrap();
        assert!(matches!(&left[..], [(_, PendingOp::PushSkill { skill, base_version: 2 })] if skill.version == 3 && skill.files == second.files), "{left:?}");
        let out = run_sync(&s, Some(&client(&base, "ast-a")), &ctx, &NO_HARVEST).await.unwrap();
        assert!(out.notes.is_empty() && !out.relay_error, "{:?}", out.notes);
        let r = relay.lock().unwrap();
        let mut versions: Vec<i64> = r.skills.values().filter(|k| k.name == "beta").map(|k| k.version).collect();
        versions.sort();
        assert_eq!(versions, vec![1, 2, 3]);
        assert_eq!(r.latest_skill("beta").unwrap().files, second.files);
    }

    // ─────────────── skill files on the wire (F8) ───────────────

    /// Queues a push of skill `name` (as `atem skill add` does).
    fn queue_skill(s: &Store, name: &str) {
        let skill = skill_v1(name, "# deploy steps", "m1");
        s.put_skill(&skill).unwrap();
        s.enqueue(&PendingOp::PushSkill { skill, base_version: 0 }).unwrap();
    }

    /// A stub relay's log of (method, path and query, body).
    type RelayLog = std::sync::Arc<std::sync::Mutex<Vec<(String, String, serde_json::Value)>>>;

    /// The skill requests of `log`, as (method, path without the query).
    fn skill_requests(log: &RelayLog) -> Vec<(String, String)> {
        log.lock().unwrap().iter()
            .filter(|(_, p, _)| p.starts_with("/api/skills"))
            .map(|(m, p, _)| (m.clone(), p.split('?').next().unwrap().to_string()))
            .collect()
    }

    /// `atem skill purge <name> --version N` waits while the skill has an
    /// edit that hasn't synced: a queued push, which is also what a conflict
    /// leaves (coalesced past another machine's version, or unsettled).
    /// Version numbers may still move then, so N could name another
    /// machine's version and miss the one meant. A sync that settles it lets
    /// the purge go; `--all-versions` always goes.
    #[tokio::test]
    async fn a_version_purge_waits_until_the_skills_edits_have_synced() {
        let refused = |s: &Store, scope: Scope, project: &str, name: &str| {
            check_purge(s, scope, project, name, Some(&[1])).map(|()| String::new()).unwrap_or_else(|e| e.to_string())
        };
        let s = Store::open_in_memory().unwrap();
        queue_skill(&s, "deploy");
        let project = Skill { scope: Scope::Project, project: "github.com/acme/dialf".into(), ..skill_v1("lint", "# lint", "m1") };
        s.put_skill(&project).unwrap();
        s.enqueue(&PendingOp::PushSkill { skill: project, base_version: 0 }).unwrap();
        assert_eq!(
            refused(&s, Scope::Global, "", "deploy"),
            "Skill deploy has an edit on this machine that hasn't synced yet, so its version numbers can still change (a concurrent edit moves it past another machine's version). Run `atem sync`, then check `atem skill history deploy` before purging a version. Nothing was purged; `--all-versions` purges every version now."
        );
        assert!(refused(&s, Scope::Project, "github.com/acme/dialf", "lint").contains("`atem skill history lint --scope project`"));
        // Another skill, and every version, are not held up.
        assert_eq!(refused(&s, Scope::Global, "", "other"), "");
        assert!(check_purge(&s, Scope::Global, "", "deploy", None).is_ok());

        // A conflict that stays unsettled keeps the push queued: still refused.
        let (base, _log) = stub_relay(Box::new(|m, p, _| {
            if m == "POST" && p.starts_with("/api/skills/batch?") {
                let n = 2;
                return (200, serde_json::json!({"results": vec![serde_json::json!({"ok": false, "error": "version_conflict", "current_version": 1}); n]}));
            }
            if p.starts_with("/api/skills/version?") {
                return (503, serde_json::json!({"error": "temporarily unavailable"}));
            }
            empty_pulls(m, p).unwrap()
        })).await;
        let (_td, ctx) = test_ctx();
        let out = run_sync(&s, Some(&client(&base, "ast-a")), &ctx, &NO_HARVEST).await.unwrap();
        assert!(out.relay_error, "{:?}", out.notes);
        assert_ne!(refused(&s, Scope::Global, "", "deploy"), "");

        // Coalesced past another machine's v1: the edit goes as v2 next sync.
        let relay = Arc::new(Mutex::new(KeepingRelay::default()));
        relay.lock().unwrap().put_skill(skill_v1("deploy", "# deploy from m2", "m2"));
        relay.lock().unwrap().put_skill(Skill { scope: Scope::Project, project: "github.com/acme/dialf".into(), ..skill_v1("lint", "# lint from m2", "m2") });
        let (base, _log) = stub_relay(keeping_relay(relay.clone())).await;
        let out = run_sync(&s, Some(&client(&base, "ast-a")), &ctx, &NO_HARVEST).await.unwrap();
        assert!(out.rebased == 2, "{:?}", out.notes);
        assert_ne!(refused(&s, Scope::Global, "", "deploy"), "");
        // Once it has synced, the history is final: the purge may go.
        let out = run_sync(&s, Some(&client(&base, "ast-a")), &ctx, &NO_HARVEST).await.unwrap();
        assert!(!out.relay_error && s.pending_count().unwrap() == 0, "{:?}", out.notes);
        assert_eq!(refused(&s, Scope::Global, "", "deploy"), "");
        assert_eq!(refused(&s, Scope::Project, "github.com/acme/dialf", "lint"), "");
    }

    /// A failed skill request is an error as before and is never sent
    /// again another way: one POST to the batch and one GET of the
    /// collection, the push still queued, the cursor where it was.
    #[tokio::test]
    async fn a_failed_skill_request_keeps_the_push_queued_and_tries_nothing_else() {
        let cases: Vec<(&str, (u16, serde_json::Value), &str)> = vec![
            ("401", (401, serde_json::json!({"error": "invalid or unbound session"})), RELAY_UNAUTHORIZED_NOTE),
            ("403", (403, serde_json::json!({"error": "forbidden"})), "relay returned 403"),
            ("400", (400, serde_json::json!({"error": "invalid skill files encoding"})), "relay returned 400"),
            ("500", (500, serde_json::json!({"error": "boom"})), "relay returned 500"),
            ("503", (503, serde_json::json!({"error": "temporarily unavailable"})), RELAY_UNAVAILABLE_NOTE),
            ("unsupported encoding", (400, serde_json::json!({"error": "unsupported skill files encoding; update Atem"})), "relay returned 400"),
            ("not JSON", (200, serde_json::json!("<html>")), "unexpected relay response"),
        ];
        for (label, answer, note) in cases {
            let s = Store::open_in_memory().unwrap();
            queue_skill(&s, "deploy");
            let (base, log) = stub_relay(Box::new(move |m, p, _| {
                if p.starts_with("/api/skills") {
                    return answer.clone();
                }
                empty_pulls(m, p).unwrap()
            })).await;
            let (_td, ctx) = test_ctx();
            let out = run_sync(&s, Some(&client(&base, "ast-a")), &ctx, &NO_HARVEST).await.unwrap();
            assert!(out.relay_error && !out.notes.is_empty() && out.notes.iter().all(|n| n.contains(note)), "{label}: {:?}", out.notes);
            assert_eq!((out.pushed, s.pending_count().unwrap()), (0, 1), "{label}");
            assert_eq!(s.get_state(&skill_cursor_key("ast-a")).unwrap(), 0, "{label}");
            assert_eq!(skill_requests(&log), [("POST", "/api/skills/batch"), ("GET", "/api/skills")]
                .map(|(m, p)| (m.to_string(), p.to_string())), "{label}");
        }
    }

    /// A pulled row that breaks the wire rules is refused, by the client too:
    /// the page is not applied and the cursor stays.
    #[tokio::test]
    async fn a_pulled_skill_row_that_breaks_the_wire_rules_is_refused() {
        let envelope = |marker: u8| format!("e1.0123abcd.{}", base64::Engine::encode(&base64::engine::general_purpose::STANDARD, [marker; 40]));
        let row = |encoding: serde_json::Value, files: serde_json::Value| {
            let mut row = serde_json::to_value(skill_v1("deploy", "# x", "m2")).unwrap();
            row["seq"] = serde_json::json!(5);
            row["files"] = files;
            if !encoding.is_null() {
                row["files_encoding"] = encoding;
            }
            row
        };
        let pages = [
            ("a non-empty value that isn't sealed", serde_json::json!({"skills": [row("e1-text".into(), serde_json::json!({envelope(1): "plaintext"}))]})),
            ("a plain path", serde_json::json!({"skills": [row("e1-text".into(), serde_json::json!({"SKILL.md": envelope(2)}))]})),
            ("a malformed envelope", serde_json::json!({"skills": [row("e1-text".into(), serde_json::json!({envelope(1): "e1.0123abcd.bad"}))]})),
            ("no files_encoding", serde_json::json!({"skills": [row(serde_json::Value::Null, serde_json::json!({"SKILL.md": "IyB4"}))]})),
            ("an unknown files_encoding", serde_json::json!({"skills": [row("guess".into(), serde_json::json!({"SKILL.md": "IyB4"}))]})),
            ("invalid base64", serde_json::json!({"skills": [row("base64".into(), serde_json::json!({"SKILL.md": "not base64!"}))]})),
        ];
        for (label, page) in pages {
            let s = Store::open_in_memory().unwrap();
            let (base, _log) = stub_relay(Box::new(move |m, p, _| {
                if m == "GET" && p.starts_with("/api/skills?") {
                    return (200, page.clone());
                }
                empty_pulls(m, p).unwrap()
            })).await;
            let (_td, ctx) = test_ctx();
            let out = run_sync(&s, Some(&client(&base, "ast-a")), &ctx, &NO_HARVEST).await.unwrap();
            assert!(out.relay_error && out.notes.len() == 1 && out.notes[0].contains("unexpected relay response"), "{label}: {:?}", out.notes);
            assert!(s.all_skills().unwrap().is_empty(), "{label}");
            assert_eq!(s.get_state(&skill_cursor_key("ast-a")).unwrap(), 0, "{label}");
        }
    }
}

#[cfg(test)]
#[path = "sync_pipeline_tests.rs"]
mod pipeline_tests;
