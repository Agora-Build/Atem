//! The learning loop: harvest what Claude learned → push local changes →
//! pull what other agents/machines learned → apply to every agent here.
use anyhow::Result;
use std::collections::HashSet;
use crate::memory::adapters::{apply_memory, apply_skills, Agent, Ctx, ReportLine};
use crate::memory::api::{ApiError, KnowledgeClient, OpResult, PULL_LIMIT};
use crate::memory::block::contains_reserved;
use crate::memory::harvest::{claude_memory_dir, harvest_dir, origin_prefix, Harvested};
use crate::memory::model::{new_memory_id, now_secs, Memory, Scope, Skill};
use crate::memory::secrets::find_secrets;
use crate::memory::store::{HarvestEntry, HarvestStatus, PendingOp, Store, LAST_SYNC_AT, MEMORY_CURSOR, SKILL_CURSOR};

const MEMORY_PUSH_CHUNK: usize = 50;
const SKILL_PUSH_CHUNK: usize = 8;

#[derive(Debug, Default, Clone, PartialEq)]
pub struct HarvestSummary {
    pub added: usize,
    pub removed: usize,
    pub held_back: Vec<String>,
}

/// `origin` no longer yields `id`. The memory itself is deleted only when
/// this machine's Claude harvest created it and no other harvested file
/// still points at it — a harvest can dedupe onto a CLI add, another
/// machine's memory, or a relay canonical id, which must survive.
/// Returns true if the memory was deleted.
fn release_memory(store: &Store, origin: &str, id: &str, atem_id: &str) -> Result<bool> {
    let ours = store.get_memory(id)?
        .map(|m| m.source_agent == "claude" && m.source_machine == atem_id)
        .unwrap_or(false);
    let shared = store.harvest_entries_for_memory(id)?.iter().any(|e| e.origin != origin);
    if !ours || shared {
        return Ok(false);
    }
    store.mark_memory_deleted(id)?;
    store.enqueue(&PendingOp::DeleteMemory { id: id.to_string() })?;
    Ok(true)
}

pub fn harvest_into_store(store: &Store, items: &[Harvested], prefix: &str, project_key: &str, atem_id: &str) -> Result<HarvestSummary> {
    let mut sum = HarvestSummary::default();
    let seen: HashSet<&str> = items.iter().map(|h| h.origin.as_str()).collect();
    for h in items {
        let prev = store.harvest_get(&h.origin)?;
        if let Some(p) = &prev {
            if p.content_hash == h.hash {
                continue; // unchanged (synced, held back, or excluded)
            }
            if p.status == HarvestStatus::Synced && !p.memory_id.is_empty()
                && release_memory(store, &h.origin, &p.memory_id, atem_id)? {
                sum.removed += 1;
            }
        }
        let findings = find_secrets(&h.content);
        if !findings.is_empty() || contains_reserved(&h.content) {
            let why = if findings.is_empty() {
                "contains the reserved token atem:memory:".to_string()
            } else {
                findings.iter().map(|f| format!("{} {}", f.kind, f.masked)).collect::<Vec<_>>().join(", ")
            };
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
                    created_at: now_secs(), deleted: false, seq: 0,
                };
                store.upsert_memory(&m)?;
                store.enqueue(&PendingOp::AddMemory { memory: m.clone() })?;
                sum.added += 1;
                m.id
            }
        };
        store.harvest_put(&HarvestEntry { origin: h.origin.clone(), memory_id: id, content_hash: h.hash.clone(), status: HarvestStatus::Synced })?;
    }
    for e in store.harvest_with_prefix(prefix)? {
        if seen.contains(e.origin.as_str()) {
            continue;
        }
        if e.status == HarvestStatus::Synced && !e.memory_id.is_empty()
            && release_memory(store, &e.origin, &e.memory_id, atem_id)? {
            sum.removed += 1;
        }
        store.harvest_remove(&e.origin)?;
    }
    Ok(sum)
}

fn describe(op: &PendingOp) -> String {
    match op {
        PendingOp::AddMemory { memory } => format!("memory {}", memory.id),
        PendingOp::DeleteMemory { id } => format!("delete of {}", id),
        PendingOp::PushSkill { skill, .. } => format!("skill {} v{}", skill.name, skill.version),
        PendingOp::DeleteSkill { name, .. } => format!("delete of skill {}", name),
        PendingOp::PurgeSkill { name, .. } => format!("purge of skill {}", name),
    }
}

/// Apply one batch's results. Every op is acked: successes are done, and
/// refusals (e.g. the server's secret check) must not retry forever.
/// A result count that doesn't match can't be paired up, so nothing is
/// acked: the batch stays queued and a note explains why.
pub fn apply_push_results(store: &Store, sent: &[(i64, PendingOp)], results: &[OpResult]) -> Result<Vec<String>> {
    if results.len() != sent.len() {
        return Ok(vec![format!(
            "relay returned {} results for {} changes; they stay queued for the next sync",
            results.len(), sent.len()
        )]);
    }
    let mut notes = Vec::new();
    for ((n, op), r) in sent.iter().zip(results) {
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
                        notes.push(format!(
                            "skill {}: another machine pushed an edit at the same time; both versions are kept and v{} is now the latest",
                            skill.name, r.version.unwrap_or(skill.version)
                        ));
                    }
                }
                _ => {}
            }
        } else {
            notes.push(format!("relay refused {}: {}", describe(op), r.error.clone().unwrap_or_else(|| "unknown error".into())));
            if let PendingOp::AddMemory { memory } = op {
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
    Ok(notes)
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
        if row.deleted {
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
    pub pulled: usize,
    pub notes: Vec<String>,
    pub offline: bool,
    pub report: Vec<ReportLine>,
}

async fn push_all(store: &Store, client: &KnowledgeClient, out: &mut SyncOutcome) -> Result<()> {
    let pending = store.pending()?;
    let (mem_ops, skill_ops): (Vec<_>, Vec<_>) = pending.into_iter().partition(|(_, op)| op.is_memory());
    for (group, is_mem, chunk_size) in [(mem_ops, true, MEMORY_PUSH_CHUNK), (skill_ops, false, SKILL_PUSH_CHUNK)] {
        for chunk in group.chunks(chunk_size) {
            if out.offline {
                return Ok(());
            }
            let refs: Vec<&PendingOp> = chunk.iter().map(|(_, op)| op).collect();
            match client.push(&refs, is_mem).await {
                Ok(results) => {
                    out.notes.extend(apply_push_results(store, chunk, &results)?);
                    if results.len() != chunk.len() {
                        break; // nothing acked; leave this group queued
                    }
                    out.pushed += chunk.len();
                }
                Err(ApiError::Offline(_)) => out.offline = true,
                Err(e) => {
                    out.notes.push(e.to_string());
                    break; // leave this group queued; try again next sync
                }
            }
        }
    }
    Ok(())
}

async fn pull_all(store: &Store, client: &KnowledgeClient, out: &mut SyncOutcome) -> Result<()> {
    loop {
        let since = store.get_state(MEMORY_CURSOR)?;
        match client.pull_memories(since).await {
            Ok(page) => {
                if page.is_empty() {
                    break;
                }
                let max = apply_pulled_memories(store, &page)?;
                store.set_state(MEMORY_CURSOR, max.max(since))?;
                out.pulled += page.len();
                if !cursor_advances(max, since, page.len()) {
                    out.notes.push(STUCK_CURSOR_NOTE.into());
                    break;
                }
                if page.len() < PULL_LIMIT as usize {
                    break;
                }
            }
            Err(ApiError::Offline(_)) => {
                out.offline = true;
                return Ok(());
            }
            Err(e) => {
                out.notes.push(e.to_string());
                return Ok(());
            }
        }
    }
    loop {
        let since = store.get_state(SKILL_CURSOR)?;
        match client.pull_skills(since).await {
            Ok(page) => {
                if page.is_empty() {
                    break;
                }
                let max = apply_pulled_skills(store, &page)?;
                store.set_state(SKILL_CURSOR, max.max(since))?;
                out.pulled += page.len();
                if !cursor_advances(max, since, page.len()) {
                    out.notes.push(STUCK_CURSOR_NOTE.into());
                    break;
                }
                if page.len() < PULL_LIMIT as usize {
                    break;
                }
            }
            Err(ApiError::Offline(_)) => {
                out.offline = true;
                return Ok(());
            }
            Err(e) => {
                out.notes.push(e.to_string());
                return Ok(());
            }
        }
    }
    Ok(())
}

/// `client = None` means offline: harvest and apply still run locally.
pub async fn run_sync(store: &Store, client: Option<&KnowledgeClient>, ctx: &Ctx, opts: &SyncOptions) -> Result<SyncOutcome> {
    let mut out = SyncOutcome::default();
    if opts.harvest
        && let Some(repo) = &ctx.repo {
        let dir = claude_memory_dir(&ctx.home, &repo.root);
        let items = harvest_dir(&dir, &ctx.atem_id)?;
        out.harvest = Some(harvest_into_store(store, &items, &origin_prefix(&ctx.atem_id, &dir), &repo.key, &ctx.atem_id)?);
    }
    match client {
        Some(c) => {
            push_all(store, c, &mut out).await?;
            if !out.offline {
                pull_all(store, c, &mut out).await?;
            }
            if !out.offline {
                store.set_state(LAST_SYNC_AT, now_secs())?;
            }
        }
        None => out.offline = true,
    }
    out.report = apply_all(store, ctx)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::model::{content_hash, skill_hash};
    use std::collections::BTreeMap;

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
        assert_eq!((sum.added, sum.removed), (0, 0));
        assert_eq!(s.pending_count().unwrap(), 1);
    }

    #[test]
    fn changed_file_replaces_its_memory() {
        let s = Store::open_in_memory().unwrap();
        harvest(&s, &[h("a.md", Scope::Global, "v1 fact")]);
        let sum = harvest(&s, &[h("a.md", Scope::Global, "v2 fact")]);
        assert_eq!((sum.added, sum.removed), (1, 1));
        let live = s.live_memories().unwrap();
        assert_eq!(live.len(), 1);
        assert_eq!(live[0].content, "v2 fact");
        assert_eq!(s.pending_count().unwrap(), 3); // add, delete, add
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
    fn deleted_file_removes_its_memory() {
        let s = Store::open_in_memory().unwrap();
        harvest(&s, &[h("a.md", Scope::Global, "Prefers ripgrep")]);
        let sum = harvest(&s, &[]);
        assert_eq!(sum.removed, 1);
        assert!(s.live_memories().unwrap().is_empty());
        assert!(matches!(s.pending().unwrap().last().unwrap().1, PendingOp::DeleteMemory { .. }));
        assert!(s.harvest_with_prefix(P).unwrap().is_empty());
    }

    #[test]
    fn duplicate_content_reuses_existing_memory() {
        let s = Store::open_in_memory().unwrap();
        let existing = Memory {
            id: "mem_old".into(), scope: Scope::Global, project: String::new(), machine: String::new(),
            content: "Prefers ripgrep".into(), content_hash: content_hash("Prefers ripgrep"), confidence: "high".into(),
            source_agent: "cli".into(), source_machine: "m2".into(), created_at: 1, deleted: false, seq: 3,
        };
        s.upsert_memory(&existing).unwrap();
        let sum = harvest(&s, &[h("a.md", Scope::Global, "prefers  RIPGREP")]);
        assert_eq!(sum.added, 0);
        assert_eq!(s.harvest_get(&format!("{}a.md", P)).unwrap().unwrap().memory_id, "mem_old");
    }

    fn deletes_queued_for(s: &Store, id: &str) -> usize {
        s.pending().unwrap().iter().filter(|(_, op)| matches!(op, PendingOp::DeleteMemory { id: d } if d == id)).count()
    }

    #[test]
    fn changed_file_does_not_delete_shared_memory() {
        let s = Store::open_in_memory().unwrap();
        let existing = Memory {
            id: "mem_cli".into(), scope: Scope::Global, project: String::new(), machine: String::new(),
            content: "Prefers ripgrep".into(), content_hash: content_hash("Prefers ripgrep"), confidence: "high".into(),
            source_agent: "cli".into(), source_machine: "m1".into(), created_at: 1, deleted: false, seq: 3,
        };
        s.upsert_memory(&existing).unwrap();
        harvest(&s, &[h("a.md", Scope::Global, "Prefers ripgrep")]);
        assert_eq!(s.harvest_get(&format!("{}a.md", P)).unwrap().unwrap().memory_id, "mem_cli");
        let sum = harvest(&s, &[h("a.md", Scope::Global, "Prefers fd")]);
        assert_eq!((sum.added, sum.removed), (1, 0));
        assert!(!s.get_memory("mem_cli").unwrap().unwrap().deleted);
        assert_eq!(deletes_queued_for(&s, "mem_cli"), 0);
        // Deleting the file doesn't touch it either.
        harvest(&s, &[]);
        assert!(!s.get_memory("mem_cli").unwrap().unwrap().deleted);
        assert_eq!(deletes_queued_for(&s, "mem_cli"), 0);
    }

    #[test]
    fn deleted_file_keeps_memory_other_origin_references() {
        let s = Store::open_in_memory().unwrap();
        harvest(&s, &[h("a.md", Scope::Global, "Prefers ripgrep"), h("b.md", Scope::Global, "prefers ripgrep")]);
        let id = s.harvest_get(&format!("{}a.md", P)).unwrap().unwrap().memory_id;
        assert_eq!(s.harvest_get(&format!("{}b.md", P)).unwrap().unwrap().memory_id, id);
        let sum = harvest(&s, &[h("b.md", Scope::Global, "prefers ripgrep")]);
        assert_eq!(sum.removed, 0);
        assert!(!s.get_memory(&id).unwrap().unwrap().deleted);
        assert_eq!(deletes_queued_for(&s, &id), 0);
        assert!(s.harvest_get(&format!("{}a.md", P)).unwrap().is_none());
        // The last reference going away does delete it.
        assert_eq!(harvest(&s, &[]).removed, 1);
        assert!(s.get_memory(&id).unwrap().unwrap().deleted);
        assert_eq!(deletes_queued_for(&s, &id), 1);
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
            source_agent: "codex".into(), source_machine: "hal".into(), created_at: 1, deleted: false, seq: 5,
        };
        let mut b = a.clone();
        b.id = "mem_b".into();
        b.seq = 7;
        b.deleted = true;
        assert_eq!(apply_pulled_memories(&s, &[a.clone(), b]).unwrap(), 7);
        let got_b = s.get_memory("mem_b").unwrap().unwrap();
        assert!(got_b.deleted && got_b.content.is_empty());
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
}
