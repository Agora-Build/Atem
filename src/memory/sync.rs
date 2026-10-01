//! The learning loop: harvest what Claude learned → push local changes →
//! pull what other agents/machines learned → apply to every agent here.
use anyhow::{anyhow, bail, Result};
use std::collections::HashSet;
use crate::memory::adapters::{apply_memory, apply_skills, Agent, Ctx, ReportLine};
use crate::memory::api::{ApiError, KnowledgeClient, OpResult, PULL_LIMIT};
use crate::memory::block::contains_reserved;
use crate::memory::harvest::{claude_memory_dir, harvest_dir, origin_prefix, Harvested};
use crate::memory::model::{content_hash, new_memory_id, now_secs, skill_hash, Memory, Scope, Skill};
use crate::memory::secrets::{find_secrets, skill_file_problems};
use crate::memory::store::{memory_cursor_key, skill_cursor_key, HarvestEntry, HarvestStatus, PendingOp, Store, LAST_SYNC_AT};
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
                        let scope_flag = if skill.scope == Scope::Project { " --scope project" } else { "" };
                        notes.push(format!(
                            "skill {}: another machine pushed an edit at the same time; both versions are kept and v{} is now the latest. See them with `atem skill history {}{}`.",
                            skill.name, r.version.unwrap_or(skill.version), skill.name, scope_flag
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

/// Send one chunk and apply its results. `Ok(true)`: acked, carry on with
/// the group; `Ok(false)`: results couldn't be paired up (nothing acked),
/// stop the group; `Err`: the request failed, nothing acked.
async fn send_chunk(store: &Store, client: &KnowledgeClient, chunk: &[(i64, PendingOp)], is_mem: bool, out: &mut SyncOutcome) -> Result<std::result::Result<bool, ApiError>> {
    let refs: Vec<&PendingOp> = chunk.iter().map(|(_, op)| op).collect();
    match client.push(&refs, is_mem).await {
        Ok(results) => {
            out.notes.extend(apply_push_results(store, chunk, &results)?);
            if results.len() != chunk.len() {
                out.relay_error = true;
                return Ok(Ok(false));
            }
            out.pushed += chunk.len();
            Ok(Ok(true))
        }
        Err(e) => Ok(Err(e)),
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

/// Push a group in chunks, in queue order. Any failure stops the group (its
/// remaining ops stay queued, preserving order). A chunk the relay refuses
/// as too large (413) is retried one op at a time; a single op that is still
/// too large is never acked — it stays queued with a note.
///
/// Every send re-reads its ops from the queue: an earlier chunk's results
/// can rewrite still-queued ops (a relay canonical id), and the relay only
/// knows the rewritten ids. `after` is the last op sent, so each send moves
/// strictly forward in queue order.
async fn push_group(store: &Store, client: &KnowledgeClient, is_mem: bool, chunk_size: usize, out: &mut SyncOutcome) -> Result<()> {
    let queued_after = |after: i64| -> Result<Vec<(i64, PendingOp)>> {
        Ok(store.pending()?.into_iter().filter(|(n, op)| *n > after && op.is_memory() == is_mem).collect())
    };
    let mut after = i64::MIN;
    loop {
        if out.offline {
            return Ok(());
        }
        let chunk: Vec<_> = queued_after(after)?.into_iter().take(chunk_size).collect();
        let Some(&(last, _)) = chunk.last() else { return Ok(()) };
        match send_chunk(store, client, &chunk, is_mem, out).await? {
            Ok(true) => {}
            Ok(false) => return Ok(()),
            Err(ApiError::Http(413, _)) if chunk.len() > 1 => {
                for n in chunk.iter().map(|(n, _)| *n) {
                    // Re-fetched by `n`: an earlier single op may have rewritten it.
                    let Some(one) = store.pending()?.into_iter().find(|(m, _)| *m == n) else { continue };
                    let one = [one];
                    match send_chunk(store, client, &one, is_mem, out).await? {
                        Ok(true) => {}
                        Ok(false) => return Ok(()),
                        Err(e) => return group_failed(store, e, &one, is_mem, out),
                    }
                }
            }
            Err(e) => return group_failed(store, e, &chunk, is_mem, out),
        }
        after = last;
    }
}

async fn push_all(store: &Store, client: &KnowledgeClient, out: &mut SyncOutcome) -> Result<()> {
    push_group(store, client, true, MEMORY_PUSH_CHUNK, out).await?;
    push_group(store, client, false, SKILL_PUSH_CHUNK, out).await?;
    Ok(())
}

/// Pull cursors are per account (the paired Astation id); see
/// `memory_cursor_key`.
async fn pull_all(store: &Store, client: &KnowledgeClient, out: &mut SyncOutcome) -> Result<()> {
    let mem_key = memory_cursor_key(client.account());
    loop {
        let since = store.get_state(&mem_key)?;
        match client.pull_memories(since).await {
            Ok(page) => {
                if page.is_empty() {
                    break;
                }
                let max = apply_pulled_memories(store, &page)?;
                store.set_state(&mem_key, max.max(since))?;
                out.pulled += page.len();
                if !cursor_advances(max, since, page.len()) {
                    out.note(STUCK_CURSOR_NOTE.into());
                    break;
                }
                if page.len() < PULL_LIMIT as usize {
                    break;
                }
            }
            Err(e) => {
                out.failed(e, None);
                return Ok(());
            }
        }
    }
    let skill_key = skill_cursor_key(client.account());
    loop {
        let since = store.get_state(&skill_key)?;
        match client.pull_skills(since).await {
            Ok(page) => {
                if page.is_empty() {
                    break;
                }
                let max = apply_pulled_skills(store, &page)?;
                store.set_state(&skill_key, max.max(since))?;
                out.pulled += page.len();
                if !cursor_advances(max, since, page.len()) {
                    out.note(STUCK_CURSOR_NOTE.into());
                    break;
                }
                if page.len() < PULL_LIMIT as usize {
                    break;
                }
            }
            Err(e) => {
                out.failed(e, None);
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
pub const SKILL_HISTORY_UNSUPPORTED: &str = "This relay doesn't support skill history yet — update the relay (Astation) and try again.";

/// A skill-history request failed: say why, plainly. Only a 404 whose body
/// is the relay's own "no such skill version" means the version is missing;
/// any other 404 is a relay without the history routes.
pub fn skill_history_error(e: ApiError, name: &str, version: Option<i64>) -> anyhow::Error {
    match (e, version) {
        (ApiError::Offline(_), _) => anyhow!(SKILL_HISTORY_OFFLINE),
        (ApiError::Http(401, _), _) => anyhow!(SKILL_HISTORY_UNAUTHORIZED),
        (ApiError::Http(503, _), _) => anyhow!(SKILL_HISTORY_UNAVAILABLE),
        (ApiError::Http(404, body), Some(v)) if body.contains("no such skill version") => {
            anyhow!("Skill {} has no version {}. See `atem skill history {}`.", name, v, name)
        }
        (ApiError::Http(404, _), _) => anyhow!(SKILL_HISTORY_UNSUPPORTED),
        (ApiError::Http(410, _), Some(v)) => anyhow!("v{} of skill {} was purged: its files were erased, so it can't be restored.", v, name),
        (e, _) => anyhow!("{}", e),
    }
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

    fn valid(id: &str, content: &str) -> Memory {
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

    type Handler = dyn Fn(&str, &str, &serde_json::Value) -> (u16, serde_json::Value) + Send + Sync;

    /// A tiny HTTP/1.1 relay stub on 127.0.0.1: one request per connection,
    /// answered by `f(method, path_and_query, json_body)`. Returns the base
    /// URL and a log of (method, path_and_query, body) for every request.
    async fn stub_relay(f: Box<Handler>) -> (String, std::sync::Arc<std::sync::Mutex<Vec<(String, String, serde_json::Value)>>>) {
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
        Some((200, serde_json::json!({"skills": []})))
    }

    fn ok_results(body: &serde_json::Value) -> serde_json::Value {
        let n = body["ops"].as_array().map(|a| a.len()).unwrap_or(0);
        serde_json::json!({"results": (0..n).map(|i| serde_json::json!({"ok": true, "seq": i + 1})).collect::<Vec<_>>()})
    }

    fn test_ctx() -> (tempfile::TempDir, Ctx) {
        let td = tempfile::tempdir().unwrap();
        let ctx = Ctx { home: td.path().to_path_buf(), repo: None, atem_id: "m1".into(), allow_tracked: false };
        (td, ctx)
    }

    fn client(base: &str, account: &str) -> KnowledgeClient {
        KnowledgeClient::new(base.to_string(), "inst".into(), "sess".into(), account.into())
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

    const NO_HARVEST: SyncOptions = SyncOptions { harvest: false };

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
            (200, ok_results(body))
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
            (200, ok_results(body))
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

    fn posted_ops(log: &std::sync::Arc<std::sync::Mutex<Vec<(String, String, serde_json::Value)>>>) -> Vec<Vec<serde_json::Value>> {
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
            (200, ok_results(body))
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
        serde_json::to_value(Skill {
            scope: Scope::Global, project: String::new(), name: "demo".into(), version,
            content_hash: skill_hash(&files), files, source_agent: "codex".into(), source_machine: "m2".into(),
            created_at: 1_790_000_000, deleted, seq: version * 10,
        }).unwrap()
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
            (200, ok_results(body))
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
        // An older relay without the routes answers a bare 404.
        assert_eq!(msg(ApiError::Http(404, "404 page not found".into()), Some(9)), SKILL_HISTORY_UNSUPPORTED);
        assert_eq!(msg(ApiError::Http(404, "".into()), None), SKILL_HISTORY_UNSUPPORTED);
        assert!(msg(ApiError::Http(500, "boom".into()), None).contains("500"));
    }

    #[tokio::test]
    async fn restore_and_history_on_an_old_relay_say_update() {
        let s = Store::open_in_memory().unwrap();
        let (base, _log) = stub_relay(Box::new(|_, _, _| (404, serde_json::json!("404 page not found")))).await;
        let c = client(&base, "ast-a");
        let err = restore_skill(&s, &c, "m1", Scope::Global, "", "demo", 4).await.unwrap_err();
        assert_eq!(err.to_string(), SKILL_HISTORY_UNSUPPORTED);
        let err = c.skill_versions(Scope::Global, "", "demo").await.map_err(|e| skill_history_error(e, "demo", None)).unwrap_err();
        assert_eq!(err.to_string(), SKILL_HISTORY_UNSUPPORTED);
        assert_eq!(s.pending_count().unwrap(), 0);
    }
}
