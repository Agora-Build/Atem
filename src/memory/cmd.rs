//! CLI handlers for `atem sync`, `atem memory …`, `atem skill …`.
use anyhow::{anyhow, bail, Result};
use std::path::{Path, PathBuf};
use crate::auth::PairingProblem;
use crate::cli::{MemoryCommands, SkillCommands};
use crate::memory::adapters::{valid_skill_name, Agent, Ctx};
use crate::memory::api::KnowledgeClient;
use crate::memory::block::{contains_reserved, one_line};
use crate::memory::harvest::claude_memory_dir;
use crate::memory::model::{content_hash, format_date, new_memory_id, now_secs, parse_confidence, parse_date, skill_hash, Memory, Scope, Skill};
use crate::memory::project::{detect_repo, display_name};
use crate::memory::secrets::{check_bytes, find_secrets, SecretFinding};
use crate::memory::skills_fs::{self, DirState, SkillMarker};
use crate::memory::store::{HarvestStatus, PendingOp, SearchQuery, Store, LAST_SYNC_AT};
use crate::memory::sync::{self, SyncOptions, SyncOutcome};

const ROTATE_WARNING: &str = "⚠ Rotate the credential: it may already be on other machines' disks or backups, so treat it as exposed.";

pub fn store_path() -> PathBuf {
    crate::config::AtemConfig::config_dir().join("knowledge.db")
}

fn default_scope(in_repo: bool) -> Scope {
    if in_repo { Scope::Project } else { Scope::Global }
}

fn findings_message(findings: &[SecretFinding]) -> String {
    let list = findings.iter().map(|f| format!("  line {}: {} {}", f.line, f.kind, f.masked)).collect::<Vec<_>>().join("\n");
    format!(
        "This looks like a credential, so it was not stored:\n{}\nName the vault credential instead, e.g. \"DialF's OpenAI key is the vault credential dialf/openai\".",
        list
    )
}

/// What `memory add` does with the text, given the secret check.
#[derive(Debug, PartialEq)]
enum AddPlan {
    /// A possible credential and no `--force`: refuse.
    Refuse,
    /// `--force` over a finding: keep it on this machine only, never queued
    /// for sync — a credential value never leaves the machine.
    LocalOnly,
    /// No finding: store and sync.
    StoreAndSync,
}

fn add_plan(findings_empty: bool, forced: bool) -> AddPlan {
    match (findings_empty, forced) {
        (true, _) => AddPlan::StoreAndSync,
        (false, true) => AddPlan::LocalOnly,
        (false, false) => AddPlan::Refuse,
    }
}

const LOCAL_ONLY_MSG: &str = "Stored locally only — it looks like a credential, so it is never synced.";

fn harvest_enabled_in(config_toml: &str) -> bool {
    config_toml.parse::<toml::Value>().ok()
        .and_then(|v| v.get("memory")?.get("harvest_claude")?.as_bool())
        .unwrap_or(true)
}

fn harvest_enabled() -> bool {
    harvest_enabled_in(&std::fs::read_to_string(crate::config::AtemConfig::config_path()).unwrap_or_default())
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    format!("{}…", s.chars().take(max - 1).collect::<String>())
}

fn build_ctx(allow_tracked: bool) -> Result<Ctx> {
    let home = dirs::home_dir().ok_or_else(|| anyhow!("cannot find the home directory"))?;
    let cwd = std::env::current_dir()?;
    Ok(Ctx {
        home,
        repo: detect_repo(&cwd),
        atem_id: crate::websocket_client::resolved_atem_id(&crate::auth::get_hostname()),
        allow_tracked,
    })
}

const NOT_CONFIGURED_MSG: &str = "No Astation configured — set astation_relay_code (or ASTATION_RELAY_CODE); changes stay queued.";
const NOT_PAIRED_MSG: &str = "Not paired with your Astation — run `atem pair`; changes stay queued.";

/// `Err` when no relay client can be built (no Astation configured, or no
/// pairing session). `crate::auth::require_pairing` should already have
/// caught this before any of these callers run, but `client()` resolves the
/// session itself so it never trusts a stale gate check. Relay reachability
/// is found out later, when a request actually goes out.
async fn client() -> Result<KnowledgeClient, PairingProblem> {
    let paired = crate::auth::pairing_session()?;
    Ok(KnowledgeClient::new(
        paired.relay_base,
        crate::config::AtemConfig::ensure_instance_id(),
        paired.session_id,
        paired.astation_id,
    ))
}

/// `atem memory status`'s "Astation:" line. `status` only runs after
/// `require_pairing()` succeeds, so the machine is paired with `astation_id`
/// by construction — there's no unpaired case to render here.
fn astation_status_line(astation_id: &str) -> String {
    format!("{} (paired)", astation_id)
}

/// `problem`: why `client()` couldn't build a client, if it couldn't.
fn sync_status_line(out: &SyncOutcome, problem: Option<&PairingProblem>) -> String {
    match problem {
        Some(PairingProblem::NotConfigured) => NOT_CONFIGURED_MSG.to_string(),
        Some(PairingProblem::NotPaired) => NOT_PAIRED_MSG.to_string(),
        None if out.offline => "Relay unreachable — changes stay queued and sync next time.".to_string(),
        None if out.relay_error => format!(
            "Sync incomplete — pushed {} change(s), pulled {} update(s); the rest stay queued (see notes).",
            out.pushed, out.pulled
        ),
        None => format!("Pushed {} change(s), pulled {} update(s).", out.pushed, out.pulled),
    }
}

fn print_outcome(out: &SyncOutcome, problem: Option<&PairingProblem>) {
    if let Some(h) = &out.harvest {
        println!("Harvested from Claude: {} new, {} outdated", h.added, h.invalidated);
        for hb in &h.held_back {
            println!("  held back (possible credential): {}", hb);
        }
    }
    println!("{}", sync_status_line(out, problem));
    for n in &out.notes {
        println!("note: {}", n);
    }
    for line in &out.report {
        println!("{}", line.render());
    }
}

/// After a local change: push/pull/apply without harvesting; quiet offline.
async fn best_effort_sync(store: &Store, ctx: &Ctx) {
    let c = client().await;
    match sync::run_sync(store, c.as_ref().ok(), ctx, &SyncOptions { harvest: false }).await {
        Ok(out) => {
            for n in &out.notes {
                eprintln!("note: {}", n);
            }
        }
        Err(e) => eprintln!("note: {}", e),
    }
}

fn project_for_scope(scope: Scope, ctx: &Ctx, explicit: Option<String>) -> Result<String> {
    if scope != Scope::Project {
        return Ok(String::new());
    }
    explicit
        .or_else(|| ctx.repo.as_ref().map(|r| r.key.clone()))
        .ok_or_else(|| anyhow!("--scope project needs a git repo (or --project <key>)"))
}

/// What `atem skill add <dir>` publishes, and whether `dir` should carry
/// the resulting marker afterwards.
#[derive(Debug, PartialEq)]
struct SkillAddTarget {
    scope: Scope,
    project: String,
    name: String,
    /// True when `dir` is the managed copy of exactly this skill (accept the
    /// edit), or an unmanaged dir sitting where atem would write this skill
    /// for some agent (adopt it). Otherwise the dir's marker is left alone.
    write_marker: bool,
}

fn resolve_skill_add_target(dir: &Path, scope: Option<Scope>, name: Option<String>, ctx: &Ctx) -> Result<SkillAddTarget> {
    let state = skills_fs::dir_state(dir);
    let marker = match &state {
        DirState::Managed(m) => Some(m),
        _ => None,
    };
    // A managed dir already knows which skill it holds.
    let (scope, marker_project) = match (scope, marker) {
        (Some(s), _) => (s, None),
        (None, Some(m)) => (m.scope, Some(m.project.clone())),
        (None, None) => (Scope::Global, None),
    };
    if scope == Scope::Machine {
        bail!("Skills support --scope global or project.");
    }
    let project = match marker_project {
        Some(p) if scope != Scope::Project || !p.is_empty() => p,
        _ => project_for_scope(scope, ctx, None)?,
    };
    let name = name
        .or_else(|| dir.canonicalize().ok().and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_string())))
        .ok_or_else(|| anyhow!("Could not determine the skill name; pass --name"))?;
    if !valid_skill_name(&name) {
        bail!("Invalid skill name {:?}: use letters, digits, '-', '_' or '.'", name);
    }
    let write_marker = match &state {
        DirState::Managed(m) => m.scope == scope && m.project == project && m.name == name,
        DirState::Unmanaged => match dir.canonicalize() {
            Ok(here) => Agent::all().iter().any(|a| {
                a.skills_root(ctx, scope)
                    .and_then(|root| root.join(&name).canonicalize().ok())
                    .is_some_and(|target| target == here)
            }),
            Err(_) => false,
        },
        DirState::Missing => false,
    };
    Ok(SkillAddTarget { scope, project, name, write_marker })
}

fn where_label(m: &Memory) -> String {
    match m.scope {
        Scope::Global => "global".into(),
        Scope::Machine => format!("machine:{}", m.machine),
        Scope::Project => format!("project:{}", display_name(&m.project)),
    }
}

fn print_memories(ms: &[Memory]) {
    if ms.is_empty() {
        println!("(no memories)");
    }
    for m in ms {
        let note = m.invalid_at.map(|t| format!("  (outdated since {})", format_date(t))).unwrap_or_default();
        println!("{}  {:<24} {:<6} {}{}", m.id, where_label(m), m.confidence, truncate(&one_line(&m.content), 90), note);
    }
}

/// `memory list`'s default view: global, this machine, and the current
/// project (or exactly `--scope` / `--project`; everything with `--all`).
fn in_view(m: &Memory, scope: Option<Scope>, project: Option<&str>, all: bool, ctx: &Ctx) -> bool {
    if let Some(sf) = scope
        && m.scope != sf {
        return false;
    }
    if let Some(p) = project {
        return m.project == p;
    }
    if all {
        return true;
    }
    match m.scope {
        Scope::Global => true,
        Scope::Machine => m.machine == ctx.atem_id,
        Scope::Project => ctx.repo.as_ref().is_some_and(|r| r.key == m.project),
    }
}

/// A fact can't stop being true before it started: `end` must not be
/// earlier than `m.valid_from()`.
fn check_end(m: &Memory, end: i64) -> Result<()> {
    if end < m.valid_from() {
        bail!("{} can't end before it became valid ({}).", m.id, format_date(m.valid_from()));
    }
    Ok(())
}

/// Checks the end of `m`'s validity: an explicit `given` date, or `now` when
/// none was given. A future-dated fact can't be ended "now" either.
fn check_end_or_now(m: &Memory, given: Option<i64>, now: i64) -> Result<()> {
    check_end(m, given.unwrap_or(now))
}

/// Replacement chains via `superseded_by`, each oldest first; chains ordered
/// by their first memory's creation time. A successor not in `mems` ends
/// the chain; a memory reached twice stays in the first chain.
fn history_chains(mems: &[Memory]) -> Vec<Vec<Memory>> {
    use std::collections::{HashMap, HashSet};
    let by_id: HashMap<&str, &Memory> = mems.iter().map(|m| (m.id.as_str(), m)).collect();
    let has_pred: HashSet<&str> = mems.iter()
        .filter_map(|m| m.superseded_by.as_deref())
        .filter(|s| by_id.contains_key(s))
        .collect();
    let mut order: Vec<&Memory> = mems.iter().collect();
    order.sort_by(|a, b| a.created_at.cmp(&b.created_at).then(a.id.cmp(&b.id)));
    let mut seen: HashSet<String> = HashSet::new();
    let mut chains = Vec::new();
    // Heads first, then anything left (only a cycle, which the relay never makes).
    let heads = order.iter().filter(|m| !has_pred.contains(m.id.as_str()));
    let rest = order.iter().filter(|m| has_pred.contains(m.id.as_str()));
    for start in heads.chain(rest) {
        let mut chain = Vec::new();
        let mut cur = Some(*start);
        while let Some(m) = cur {
            if !seen.insert(m.id.clone()) {
                break;
            }
            chain.push(m.clone());
            cur = m.superseded_by.as_deref().and_then(|s| by_id.get(s).copied());
        }
        if !chain.is_empty() {
            chains.push(chain);
        }
    }
    chains.sort_by(|a, b| a[0].created_at.cmp(&b[0].created_at).then(a[0].id.cmp(&b[0].id)));
    chains
}

fn validity_span(m: &Memory) -> String {
    format!("{} → {}", format_date(m.valid_from()), m.invalid_at.map(format_date).unwrap_or_else(|| "now".into()))
}

/// One numbered block per chain; later links indented under the first.
fn render_history(chains: &[Vec<Memory>]) -> Vec<String> {
    if chains.is_empty() {
        return vec!["(no memories)".into()];
    }
    let mut out = Vec::new();
    for (i, chain) in chains.iter().enumerate() {
        for (j, m) in chain.iter().enumerate() {
            let lead = if j == 0 { format!("{:>3}. ", i + 1) } else { "     ".to_string() };
            out.push(format!("{}{}  {:<24} {:<25} {}", lead, m.id, where_label(m), validity_span(m), truncate(&one_line(&m.content), 80)));
        }
    }
    out
}

fn files_under(dir: &Path, depth: usize, out: &mut Vec<PathBuf>) {
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    for e in rd.flatten() {
        let Ok(ft) = e.file_type() else { continue };
        if ft.is_symlink() {
            continue;
        }
        if ft.is_dir() && depth > 0 {
            files_under(&e.path(), depth - 1, out);
        } else if ft.is_file() {
            out.push(e.path());
        }
    }
}

/// Credentials sitting in files atem reads or writes. Reported, never uploaded.
fn credential_findings(ctx: &Ctx) -> Vec<String> {
    let mut files = Vec::new();
    for agent in Agent::all() {
        if !agent.discover(ctx) {
            continue;
        }
        files.push(agent.global_memory_file(ctx));
        if let Some(r) = &ctx.repo {
            files.push(agent.project_memory_file(&r.root));
        }
        for scope in [Scope::Global, Scope::Project] {
            if let Some(root) = agent.skills_root(ctx, scope) {
                files_under(&root, 4, &mut files);
            }
        }
    }
    if let Some(r) = &ctx.repo {
        files_under(&claude_memory_dir(&ctx.home, &r.root), 0, &mut files);
    }
    let mut out = Vec::new();
    for f in files {
        let Ok(bytes) = std::fs::read(&f) else { continue };
        let Ok(text) = std::str::from_utf8(&bytes) else { continue };
        for s in find_secrets(text) {
            out.push(format!("{}:{}  {} {}", f.display(), s.line, s.kind, s.masked));
        }
    }
    out
}

pub async fn handle_sync(no_harvest: bool, allow_tracked: bool) -> Result<()> {
    crate::auth::require_pairing("Atem Memory")?;
    let ctx = build_ctx(allow_tracked)?;
    let store = Store::open(&store_path())?;
    let c = client().await;
    let opts = SyncOptions { harvest: !no_harvest && harvest_enabled() };
    let out = sync::run_sync(&store, c.as_ref().ok(), &ctx, &opts).await?;
    print_outcome(&out, c.as_ref().err());
    Ok(())
}

pub async fn handle_memory(command: MemoryCommands) -> Result<()> {
    crate::auth::require_pairing("Atem Memory")?;
    match command {
        MemoryCommands::Add { content, scope, project, confidence, agent, force, valid_at } => {
            let ctx = build_ctx(false)?;
            let valid_at = valid_at.as_deref().map(parse_date).transpose()?;
            if contains_reserved(&content) {
                bail!("The text contains the reserved token `atem:memory:`.");
            }
            let findings = find_secrets(&content);
            let plan = add_plan(findings.is_empty(), force);
            if plan == AddPlan::Refuse {
                bail!(findings_message(&findings));
            }
            let scope = match scope {
                Some(s) => Scope::parse(&s)?,
                None => default_scope(ctx.repo.is_some()),
            };
            let project = project_for_scope(scope, &ctx, project)?;
            let machine = if scope == Scope::Machine { ctx.atem_id.clone() } else { String::new() };
            let confidence = parse_confidence(&confidence)?;
            let store = Store::open(&store_path())?;
            let hash = content_hash(&content);
            if let Some(existing) = store.find_live_by_hash(scope, &project, &machine, &hash)? {
                println!("Already stored as {}", existing.id);
                return Ok(());
            }
            let m = Memory {
                id: new_memory_id(), scope, project, machine, content, content_hash: hash, confidence,
                source_agent: agent, source_machine: ctx.atem_id.clone(), created_at: now_secs(), valid_at, seq: 0, ..Default::default()
            };
            store.upsert_memory(&m)?;
            println!("Added {} ({})", m.id, where_label(&m));
            if plan == AddPlan::LocalOnly {
                println!("{}", LOCAL_ONLY_MSG);
                return Ok(());
            }
            store.enqueue(&PendingOp::AddMemory { memory: m.clone() })?;
            best_effort_sync(&store, &ctx).await;
        }
        MemoryCommands::List { scope, project, all, history } => {
            let ctx = build_ctx(false)?;
            let store = Store::open(&store_path())?;
            let scope_f = scope.map(|s| Scope::parse(&s)).transpose()?;
            match history {
                None => {
                    let shown: Vec<Memory> = store.live_memories()?.into_iter()
                        .filter(|m| in_view(m, scope_f, project.as_deref(), all, &ctx)).collect();
                    print_memories(&shown);
                }
                Some(None) => {
                    let shown: Vec<Memory> = store.history_memories()?.into_iter()
                        .filter(|m| in_view(m, scope_f, project.as_deref(), all, &ctx)).collect();
                    for l in render_history(&history_chains(&shown)) {
                        println!("{}", l);
                    }
                }
                Some(Some(id)) => {
                    let id = store.resolve_memory_id(&id)?;
                    let chains: Vec<Vec<Memory>> = history_chains(&store.history_memories()?)
                        .into_iter().filter(|c| c.iter().any(|m| m.id == id)).collect();
                    for l in render_history(&chains) {
                        println!("{}", l);
                    }
                }
            }
        }
        MemoryCommands::Search { text, scope, project, history, limit } => {
            let store = Store::open(&store_path())?;
            let scope = scope.map(|s| Scope::parse(&s)).transpose()?;
            let hits = store.search_memories(&SearchQuery { text, scope, project, history, limit })?;
            print_memories(&hits);
        }
        MemoryCommands::Rm { id } => {
            let ctx = build_ctx(false)?;
            let store = Store::open(&store_path())?;
            store.get_memory(&id)?.filter(|m| !m.is_deleted()).ok_or_else(|| anyhow!("No memory {}", id))?;
            store.mark_memory_deleted(&id)?;
            store.enqueue(&PendingOp::DeleteMemory { id: id.clone() })?;
            println!("Removed {}", id);
            best_effort_sync(&store, &ctx).await;
        }
        MemoryCommands::Replace { id, content, valid_at } => {
            let ctx = build_ctx(false)?;
            if contains_reserved(&content) {
                bail!("The text contains the reserved token `atem:memory:`.");
            }
            let findings = find_secrets(&content);
            if !findings.is_empty() {
                bail!(findings_message(&findings));
            }
            let valid_at = valid_at.as_deref().map(parse_date).transpose()?;
            let store = Store::open(&store_path())?;
            let old_id = store.resolve_memory_id(&id)?;
            let old = store.get_memory(&old_id)?.ok_or_else(|| anyhow!("No memory {}", id))?;
            if let Some(at) = old.invalid_at {
                bail!(
                    "{} is already outdated (since {}){}. See `atem memory list --history {}`.",
                    old.id, format_date(at),
                    old.superseded_by.as_deref().map(|s| format!(", replaced by {}", s)).unwrap_or_default(),
                    old.id
                );
            }
            check_end_or_now(&old, valid_at, now_secs())?;
            let new_id = sync::replace_memory(&store, &old, &content, valid_at, "cli", &ctx.atem_id)?;
            println!("Replaced {} with {}", old.id, new_id);
            best_effort_sync(&store, &ctx).await;
        }
        MemoryCommands::Invalidate { id, at } => {
            let ctx = build_ctx(false)?;
            let given = at.as_deref().map(parse_date).transpose()?;
            let at = given.unwrap_or_else(now_secs);
            let store = Store::open(&store_path())?;
            let id = store.resolve_memory_id(&id)?;
            if let Some(m) = store.get_memory(&id)?
                && m.invalid_at.is_none() {
                check_end_or_now(&m, given, at)?;
            }
            if sync::invalidate_and_queue(&store, &id, at, None)? {
                println!("Marked {} outdated as of {}. It's kept in `atem memory list --history`.", id, format_date(at));
                best_effort_sync(&store, &ctx).await;
            } else {
                println!("{} is already outdated; nothing changed.", id);
            }
        }
        MemoryCommands::Purge { id } => {
            let ctx = build_ctx(false)?;
            let store = Store::open(&store_path())?;
            store.get_memory(&id)?.ok_or_else(|| anyhow!("No memory {}", id))?;
            store.mark_memory_deleted(&id)?;
            store.enqueue(&PendingOp::DeleteMemory { id: id.clone() })?;
            for mut e in store.harvest_entries_for_memory(&id)? {
                e.status = HarvestStatus::Excluded;
                store.harvest_put(&e)?;
            }
            println!("Purged {}. Its text is removed from the relay and from other machines at their next sync.", id);
            println!("{}", ROTATE_WARNING);
            best_effort_sync(&store, &ctx).await;
        }
        MemoryCommands::Apply { allow_tracked } => {
            let ctx = build_ctx(allow_tracked)?;
            let store = Store::open(&store_path())?;
            for line in sync::apply_all(&store, &ctx)? {
                println!("{}", line.render());
            }
        }
        MemoryCommands::Status => {
            let ctx = build_ctx(false)?;
            let store = Store::open(&store_path())?;
            let config = crate::config::AtemConfig::load()?;
            let astation_id = config.astation_relay_code.clone().unwrap_or_default();
            let last = store.get_state(LAST_SYNC_AT)?;
            println!("Astation:   {}", astation_status_line(&astation_id));
            println!("Machine:    {}", ctx.atem_id);
            println!("Project:    {}", ctx.repo.as_ref().map(|r| r.key.as_str()).unwrap_or("(not in a git repo)"));
            let valid = store.live_memories()?.len();
            let outdated = store.history_memories()?.len() - valid;
            println!("Memories:   {} valid, {} outdated (kept as history)", valid, outdated);
            println!("Skills:     {} live", store.live_skills()?.len());
            println!("Pending:    {} change(s) waiting to sync", store.pending_count()?);
            println!("Last sync:  {}", if last == 0 { "never".to_string() } else { format!("{}s ago", now_secs() - last) });
            println!("Held back:  {} harvested memory file(s) (possible credentials)", store.held_back_count()?);
            let forks = store.multi_successors()?;
            if !forks.is_empty() {
                println!("Replaced more than once (more than one valid successor — replace or invalidate all but one):");
                for (old, news) in forks {
                    println!("  {} → {}", old, news.join(", "));
                }
            }
            for agent in Agent::all() {
                println!("Agent:      {} {}", agent.name(), if agent.discover(&ctx) { "(found)" } else { "(not installed)" });
            }
            let findings = credential_findings(&ctx);
            if findings.is_empty() {
                println!("Credential findings: none");
            } else {
                println!("Credential findings (never uploaded — move them to the vault):");
                for f in findings {
                    println!("  {}", f);
                }
            }
        }
    }
    Ok(())
}

pub async fn handle_skill(command: SkillCommands) -> Result<()> {
    crate::auth::require_pairing("Atem Memory")?;
    let ctx = build_ctx(false)?;
    let store = Store::open(&store_path())?;
    match command {
        SkillCommands::Add { dir, scope, name } => {
            let dir = PathBuf::from(dir);
            let files = skills_fs::read_skill_dir(&dir)?;
            let mut problems = Vec::new();
            for (path, bytes) in &files {
                for f in check_bytes(bytes) {
                    problems.push(format!("{}:{}  {} {}", path, f.line, f.kind, f.masked));
                }
            }
            if !problems.is_empty() {
                bail!(
                    "Refusing to add the skill — possible credentials (or unreadable files) found:\n  {}\nKeep credentials in the vault and read them at run time, e.g. `atem vault get <name>`.",
                    problems.join("\n  ")
                );
            }
            let scope = scope.map(|s| Scope::parse(&s)).transpose()?;
            let SkillAddTarget { scope, project, name, write_marker } = resolve_skill_add_target(&dir, scope, name, &ctx)?;
            let base_version = store.get_skill(scope, &project, &name)?.map(|s| s.version).unwrap_or(0);
            let hash = skill_hash(&files);
            let skill = Skill {
                scope, project: project.clone(), name: name.clone(), version: base_version + 1, content_hash: hash.clone(), files,
                source_agent: "cli".into(), source_machine: ctx.atem_id.clone(), created_at: now_secs(), deleted: false, seq: 0,
            };
            store.put_skill(&skill)?;
            store.enqueue(&PendingOp::PushSkill { skill: skill.clone(), base_version })?;
            // An edit made in this skill's own managed dir (accept it there), or
            // a hand-made dir at this skill's location (adopt it).
            if write_marker {
                skills_fs::write_marker(&dir, &SkillMarker { name, version: skill.version, hash, scope, project })?;
            }
            println!("Added skill {} v{} ({})", skill.name, skill.version, scope.as_str());
            best_effort_sync(&store, &ctx).await;
        }
        SkillCommands::List => {
            let skills = store.live_skills()?;
            if skills.is_empty() {
                println!("(no skills)");
            }
            for s in skills {
                let where_ = if s.scope == Scope::Project { format!("project:{}", display_name(&s.project)) } else { "global".into() };
                println!("{:<28} v{:<4} {:<24} {} file(s)", s.name, s.version, where_, s.files.len());
            }
        }
        SkillCommands::Rm { name, scope } => {
            let scope = Scope::parse(&scope)?;
            let project = project_for_scope(scope, &ctx, None)?;
            let cur = store.get_skill(scope, &project, &name)?.filter(|s| !s.deleted)
                .ok_or_else(|| anyhow!("No skill {} ({})", name, scope.as_str()))?;
            let mut t = cur.clone();
            t.deleted = true;
            t.version += 1;
            t.files.clear();
            t.content_hash.clear();
            store.put_skill(&t)?;
            store.enqueue(&PendingOp::DeleteSkill { scope, project, name: name.clone() })?;
            println!("Removed skill {}", name);
            best_effort_sync(&store, &ctx).await;
        }
        SkillCommands::Purge { name, scope, version, all_versions } => {
            let scope = Scope::parse(&scope)?;
            let project = project_for_scope(scope, &ctx, None)?;
            let versions = if all_versions {
                None
            } else {
                Some(vec![version.ok_or_else(|| anyhow!("Pass --version <n> or --all-versions"))?])
            };
            if let Some(cur) = store.get_skill(scope, &project, &name)? {
                let hits_latest = versions.as_ref().map(|v| v.contains(&cur.version)).unwrap_or(true);
                if hits_latest {
                    let mut t = cur.clone();
                    t.deleted = true;
                    t.files.clear();
                    t.content_hash.clear();
                    store.put_skill(&t)?;
                }
            }
            store.enqueue(&PendingOp::PurgeSkill { scope, project, name: name.clone(), versions })?;
            println!("Purged skill {}. Other machines remove it at their next sync (locally edited copies are reported, not deleted).", name);
            println!("{}", ROTATE_WARNING);
            best_effort_sync(&store, &ctx).await;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hist(id: &str, content: &str, created: i64, invalid_at: Option<i64>, superseded_by: Option<&str>) -> Memory {
        Memory {
            id: id.into(), scope: Scope::Global, content: content.into(), content_hash: content_hash(content),
            confidence: "high".into(), source_agent: "cli".into(), source_machine: "m".into(), created_at: created,
            invalid_at, superseded_by: superseded_by.map(str::to_string), ..Default::default()
        }
    }

    #[test]
    fn history_chains_run_oldest_first() {
        let ms = vec![
            hist("mem_c", "port 9100", 30, None, None),
            hist("mem_x", "unrelated", 5, None, None),
            hist("mem_a", "port 8765", 10, Some(20), Some("mem_b")),
            hist("mem_b", "port 9000", 20, Some(30), Some("mem_c")),
        ];
        let chains: Vec<Vec<String>> = history_chains(&ms).into_iter().map(|c| c.into_iter().map(|m| m.id).collect()).collect();
        assert_eq!(chains, vec![vec!["mem_x".to_string()], vec!["mem_a".into(), "mem_b".into(), "mem_c".into()]]);
        let lines = render_history(&history_chains(&ms));
        assert!(lines[0].starts_with("  1. mem_x"), "{}", lines[0]);
        assert!(lines[1].starts_with("  2. mem_a") && lines[1].contains("1970-01-01 → 1970-01-01"), "{}", lines[1]);
        assert!(lines[2].starts_with("     mem_b"), "{}", lines[2]);
        assert!(lines[3].starts_with("     mem_c") && lines[3].contains("→ now"), "{}", lines[3]);
        assert_eq!(render_history(&[]), vec!["(no memories)".to_string()]);
    }

    #[test]
    fn validity_commands_parse() {
        use clap::Parser;
        let ok = |args: &[&str]| crate::cli::Cli::try_parse_from(args).is_ok();
        assert!(ok(&["atem", "memory", "replace", "1a2b3c4d", "new fact"]));
        assert!(ok(&["atem", "memory", "replace", "1a2b3c4d", "new fact", "--valid-at", "2026-09-30"]));
        assert!(ok(&["atem", "memory", "invalidate", "mem_x", "--at", "1790000000"]));
        assert!(ok(&["atem", "memory", "add", "x", "--valid-at", "2026-09-30"]));
        let history = |args: &[&str]| match crate::cli::Cli::try_parse_from(args).unwrap().command {
            Some(crate::cli::Commands::Memory { command: MemoryCommands::List { history, .. } }) => history,
            _ => panic!("not memory list"),
        };
        assert_eq!(history(&["atem", "memory", "list"]), None);
        assert_eq!(history(&["atem", "memory", "list", "--history"]), Some(None));
        assert_eq!(history(&["atem", "memory", "list", "--history", "1a2b"]), Some(Some("1a2b".to_string())));
        assert_eq!(history(&["atem", "memory", "list", "--history", "--all"]), Some(None));
    }

    #[test]
    fn a_fact_cannot_end_before_it_became_valid() {
        let mut m = hist("mem_a", "port 8765", 1_790_000_000, None, None);
        assert!(check_end(&m, 1_790_000_000).is_ok());
        assert!(check_end(&m, 1_790_000_001).is_ok());
        let err = check_end(&m, 1_789_000_000).unwrap_err().to_string();
        assert!(err.contains("can't end before it became valid (2026-09-21)"), "{err}");
        m.valid_at = Some(1_700_000_000);
        assert!(check_end(&m, 1_789_000_000).is_ok());
    }

    #[test]
    fn ending_a_future_dated_fact_now_is_refused() {
        let mut m = hist("mem_f", "port 8765", 1_790_000_000, None, None);
        m.valid_at = Some(1_800_000_000);
        let err = check_end_or_now(&m, None, 1_790_000_000).unwrap_err().to_string();
        assert!(err.contains("can't end before it became valid"), "{err}");
        assert!(check_end_or_now(&m, None, 1_800_000_000).is_ok());
        assert!(check_end_or_now(&m, Some(1_800_000_001), 1_790_000_000).is_ok());
    }

    #[test]
    fn search_command_parses() {
        use clap::Parser;
        let ok = |args: &[&str]| crate::cli::Cli::try_parse_from(args).is_ok();
        assert!(ok(&["atem", "memory", "search", "tcp port"]));
        assert!(ok(&["atem", "memory", "search", "端口", "--scope", "project", "--project", "github.com/a/b", "--history", "--limit", "5"]));
        assert!(!ok(&["atem", "memory", "search", "x", "--limit", "many"]));
    }

    #[test]
    fn default_scope_depends_on_repo() {
        assert_eq!(default_scope(true), Scope::Project);
        assert_eq!(default_scope(false), Scope::Global);
    }

    #[test]
    fn findings_message_is_masked_and_actionable() {
        let msg = findings_message(&crate::memory::secrets::find_secrets("sk-abcdefghijklmnopqrstuvwx"));
        assert!(msg.contains("sk-…uvwx"));
        assert!(!msg.contains("abcdefghijklmnop"));
        assert!(msg.contains("vault credential"));
    }

    #[test]
    fn forced_credential_is_stored_locally_but_never_synced() {
        assert_eq!(add_plan(true, false), AddPlan::StoreAndSync);
        assert_eq!(add_plan(true, true), AddPlan::StoreAndSync); // --force without a finding changes nothing
        assert_eq!(add_plan(false, true), AddPlan::LocalOnly);
        assert_eq!(add_plan(false, false), AddPlan::Refuse);
        assert!(LOCAL_ONLY_MSG.contains("never synced"));
    }

    #[test]
    fn harvest_switch_defaults_on() {
        assert!(harvest_enabled_in(""));
        assert!(!harvest_enabled_in("[memory]\nharvest_claude = false\n"));
        assert!(harvest_enabled_in("[memory]\nharvest_claude = true\n"));
    }

    fn skill_ctx() -> (tempfile::TempDir, Ctx) {
        let td = tempfile::tempdir().unwrap();
        let base = td.path().canonicalize().unwrap();
        let home = base.join("home");
        std::fs::create_dir_all(home.join(".claude")).unwrap();
        let root = base.join("repo");
        std::fs::create_dir_all(&root).unwrap();
        let ctx = Ctx {
            home,
            repo: Some(crate::memory::project::RepoInfo { root, key: "github.com/acme/dialf".into() }),
            atem_id: "nixps-0001".into(),
            allow_tracked: false,
        };
        (td, ctx)
    }

    fn project_skill(name: &str) -> Skill {
        let mut files = std::collections::BTreeMap::new();
        files.insert("SKILL.md".to_string(), b"# s".to_vec());
        Skill {
            scope: Scope::Project, project: "github.com/acme/dialf".into(), name: name.into(), version: 4,
            content_hash: skill_hash(&files), files,
            source_agent: "cli".into(), source_machine: "m".into(), created_at: 1, deleted: false, seq: 0,
        }
    }

    #[test]
    fn skill_add_from_managed_project_dir_keeps_project_scope() {
        let (_td, ctx) = skill_ctx();
        let dir = ctx.repo.as_ref().unwrap().root.join(".claude/skills/dialf-run");
        skills_fs::write_skill_dir(&dir, &project_skill("dialf-run")).unwrap();
        std::fs::write(dir.join("SKILL.md"), "# edited").unwrap();
        let t = resolve_skill_add_target(&dir, None, None, &ctx).unwrap();
        assert_eq!(t, SkillAddTarget {
            scope: Scope::Project, project: "github.com/acme/dialf".into(), name: "dialf-run".into(), write_marker: true,
        });
        // Explicitly pushing it somewhere else leaves this dir's marker alone.
        let g = resolve_skill_add_target(&dir, Some(Scope::Global), None, &ctx).unwrap();
        assert_eq!((g.scope, g.project.as_str(), g.write_marker), (Scope::Global, "", false));
        let renamed = resolve_skill_add_target(&dir, None, Some("other".into()), &ctx).unwrap();
        assert!(!renamed.write_marker);
    }

    #[test]
    fn skill_add_adopts_dir_at_own_target_location() {
        let (td, ctx) = skill_ctx();
        let own = ctx.home.join(".claude/skills/review");
        std::fs::create_dir_all(&own).unwrap();
        std::fs::write(own.join("SKILL.md"), "# mine").unwrap();
        let t = resolve_skill_add_target(&own, None, None, &ctx).unwrap();
        assert_eq!((t.scope, t.name.as_str(), t.write_marker), (Scope::Global, "review", true));
        // Same dir pushed as a project skill isn't at that scope's location.
        assert!(!resolve_skill_add_target(&own, Some(Scope::Project), None, &ctx).unwrap().write_marker);
        // A skill dir anywhere else stays unmanaged.
        let elsewhere = td.path().join("src/review");
        std::fs::create_dir_all(&elsewhere).unwrap();
        std::fs::write(elsewhere.join("SKILL.md"), "# mine").unwrap();
        assert!(!resolve_skill_add_target(&elsewhere, None, None, &ctx).unwrap().write_marker);
        assert!(resolve_skill_add_target(&own, Some(Scope::Machine), None, &ctx).is_err());
    }

    #[test]
    fn memory_add_agent_is_cli_or_codex() {
        use clap::Parser;
        let parse = |agent: &str| crate::cli::Cli::try_parse_from(["atem", "memory", "add", "x", "--agent", agent]);
        assert!(parse("cli").is_ok());
        assert!(parse("codex").is_ok());
        assert!(parse("claude").is_err());
        assert!(parse("anything").is_err());
    }

    #[test]
    fn sync_status_line_distinguishes_pairing_problems_from_offline() {
        let offline = SyncOutcome { offline: true, ..Default::default() };
        assert_eq!(sync_status_line(&offline, Some(&PairingProblem::NotConfigured)), NOT_CONFIGURED_MSG);
        assert_eq!(sync_status_line(&offline, Some(&PairingProblem::NotPaired)), NOT_PAIRED_MSG);
        assert!(NOT_CONFIGURED_MSG.contains("astation_relay_code") && NOT_CONFIGURED_MSG.contains("stay queued"));
        assert!(NOT_PAIRED_MSG.contains("atem pair") && NOT_PAIRED_MSG.contains("stay queued"));
        assert!(sync_status_line(&offline, None).starts_with("Relay unreachable"));
        let done = SyncOutcome { pushed: 2, pulled: 3, ..Default::default() };
        assert_eq!(sync_status_line(&done, None), "Pushed 2 change(s), pulled 3 update(s).");
        let partial = SyncOutcome { pushed: 1, relay_error: true, ..Default::default() };
        assert!(sync_status_line(&partial, None).starts_with("Sync incomplete — pushed 1 change(s)"));
    }

    #[test]
    fn astation_status_line_shows_paired_id() {
        assert_eq!(astation_status_line("astation-abc123"), "astation-abc123 (paired)");
    }

    #[test]
    fn pairing_gate_message_is_byte_identical_to_before() {
        // Locks the exact text memory commands have always shown; the shared
        // gate now lives in `crate::auth`, but this text must not drift.
        assert_eq!(
            crate::auth::pairing_gate_message("Atem Memory"),
            "Atem Memory works only on machines paired with your Astation. Run `atem pair` (Astation approves this machine), then retry."
        );
    }

    #[test]
    fn truncate_keeps_short_text() {
        assert_eq!(truncate("abc", 10), "abc");
        assert_eq!(truncate(&"x".repeat(20), 10), format!("{}…", "x".repeat(9)));
    }
}
