//! Cross-agent apply: one canonical store, written into each agent's native
//! locations. Agents only declare paths and instruction lines; one shared
//! code path does the writing and the safety checks.
use std::path::{Path, PathBuf};
use crate::memory::block::{self, CODEX_CAPTURE_INSTRUCTION, CREDENTIAL_INSTRUCTION};
use crate::memory::gitguard;
use crate::memory::model::{Memory, Scope, Skill};
use crate::memory::project::RepoInfo;
use crate::memory::skills_fs::{self, DirState};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mark {
    Applied,
    Skipped,
    Clash,
}

impl Mark {
    pub fn symbol(&self) -> &'static str {
        match self {
            Mark::Applied => "✓",
            Mark::Skipped => "◐",
            Mark::Clash => "✗",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ReportLine {
    pub mark: Mark,
    pub target: String,
    pub detail: String,
}

impl ReportLine {
    pub fn render(&self) -> String {
        format!("{} {:<44} {}", self.mark.symbol(), self.target, self.detail)
    }
}

#[derive(Debug, Clone)]
pub struct Ctx {
    pub home: PathBuf,
    pub repo: Option<RepoInfo>,
    pub atem_id: String,
    pub allow_tracked: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Agent {
    Claude,
    Codex,
}

impl Agent {
    pub fn all() -> [Agent; 2] {
        [Agent::Claude, Agent::Codex]
    }

    pub fn name(&self) -> &'static str {
        match self {
            Agent::Claude => "claude",
            Agent::Codex => "codex",
        }
    }

    pub fn discover(&self, ctx: &Ctx) -> bool {
        match self {
            Agent::Claude => ctx.home.join(".claude").is_dir(),
            Agent::Codex => ctx.home.join(".codex").is_dir(),
        }
    }

    pub fn global_memory_file(&self, ctx: &Ctx) -> PathBuf {
        match self {
            Agent::Claude => ctx.home.join(".claude").join("CLAUDE.md"),
            Agent::Codex => ctx.home.join(".codex").join("AGENTS.md"),
        }
    }

    pub fn project_memory_file(&self, repo_root: &Path) -> PathBuf {
        match self {
            Agent::Claude => repo_root.join("CLAUDE.local.md"),
            Agent::Codex => repo_root.join("AGENTS.md"),
        }
    }

    pub fn skills_root(&self, ctx: &Ctx, scope: Scope) -> Option<PathBuf> {
        let dot = match self {
            Agent::Claude => ".claude",
            Agent::Codex => ".agents",
        };
        match scope {
            Scope::Global => Some(ctx.home.join(dot).join("skills")),
            Scope::Project => ctx.repo.as_ref().map(|r| r.root.join(dot).join("skills")),
            Scope::Machine => None,
        }
    }

    pub fn instructions(&self) -> Vec<&'static str> {
        match self {
            Agent::Claude => vec![CREDENTIAL_INSTRUCTION],
            Agent::Codex => vec![CODEX_CAPTURE_INSTRUCTION, CREDENTIAL_INSTRUCTION],
        }
    }

    /// Claude already has the project memories it harvested itself on this
    /// machine (they live in its per-project memory dir). Global and machine
    /// memories it harvested are still written to ~/.claude/CLAUDE.md, since
    /// that per-project dir isn't loaded in other projects.
    pub fn skips_echo(&self, m: &Memory, ctx: &Ctx) -> bool {
        *self == Agent::Claude && m.scope == Scope::Project
            && m.source_agent == "claude" && m.source_machine == ctx.atem_id
    }
}

pub fn valid_skill_name(n: &str) -> bool {
    !n.is_empty() && n != "." && n != ".."
        && n.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
}

fn display_path(p: &Path, ctx: &Ctx) -> String {
    match p.strip_prefix(&ctx.home) {
        Ok(rel) => format!("~/{}", rel.display()),
        Err(_) => p.display().to_string(),
    }
}

fn line(mark: Mark, target: String, detail: impl Into<String>) -> ReportLine {
    ReportLine { mark, target, detail: detail.into() }
}

pub fn apply_memory(agent: Agent, ctx: &Ctx, mems: &[Memory]) -> Vec<ReportLine> {
    let visible: Vec<Memory> = mems.iter().filter(|m| m.is_valid() && !agent.skips_echo(m, ctx)).cloned().collect();
    let global: Vec<Memory> = visible.iter()
        .filter(|m| m.scope == Scope::Global || (m.scope == Scope::Machine && m.machine == ctx.atem_id))
        .cloned().collect();
    let instr = agent.instructions();
    let mut report = vec![write_block(&agent.global_memory_file(ctx), None, &global, &instr, ctx)];
    if let Some(repo) = &ctx.repo {
        let proj: Vec<Memory> = visible.iter()
            .filter(|m| m.scope == Scope::Project && m.project == repo.key)
            .cloned().collect();
        report.push(write_block(&agent.project_memory_file(&repo.root), Some(&repo.root), &proj, &instr, ctx));
    }
    report
}

/// Write via a sibling temp file + rename, so a crash never leaves a
/// half-written instruction file. A symlink (e.g. into a dotfiles repo) is
/// followed and the file it points at is replaced, keeping the link.
fn write_atomic(path: &Path, text: &str) -> std::io::Result<()> {
    let real = match std::fs::symlink_metadata(path) {
        Ok(md) if md.file_type().is_symlink() => match std::fs::canonicalize(path) {
            Ok(p) => p,
            // Dangling link: write where it points.
            Err(_) => {
                let to = std::fs::read_link(path)?;
                path.parent().map(|d| d.join(&to)).unwrap_or(to)
            }
        },
        _ => path.to_path_buf(),
    };
    let dir = real.parent().ok_or_else(|| std::io::Error::other("no parent directory"))?;
    let name = real.file_name().ok_or_else(|| std::io::Error::other("no file name"))?;
    // Unpredictable name + create_new (O_EXCL): an entry planted at the temp
    // path — e.g. a symlink committed by a malicious repo — is never opened,
    // so the write can't be redirected outside the target's directory.
    let tmp = dir.join(format!(".{}.atem-tmp-{}", name.to_string_lossy(), uuid::Uuid::new_v4().simple()));
    let mut file = std::fs::OpenOptions::new().write(true).create_new(true).open(&tmp)?;
    let result = (|| {
        use std::io::Write;
        file.write_all(text.as_bytes())?;
        if let Ok(md) = std::fs::metadata(&real) {
            file.set_permissions(md.permissions())?;
        }
        file.sync_all()?;
        std::fs::rename(&tmp, &real)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

fn write_block(path: &Path, repo_root: Option<&Path>, mems: &[Memory], instr: &[&str], ctx: &Ctx) -> ReportLine {
    let target = display_path(path, ctx);
    if let Some(root) = repo_root
        && !ctx.allow_tracked && gitguard::is_tracked(root, path) {
        return line(Mark::Skipped, target, "skipped: tracked by git");
    }
    let existed = path.exists();
    let current = if existed {
        match std::fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) => return line(Mark::Skipped, target, format!("skipped: unreadable ({})", e)),
        }
    } else {
        String::new()
    };
    let entries = block::select_entries(mems);
    let rendered = block::render_block(&entries, instr);
    let next = match block::splice(&current, &rendered) {
        Ok(n) => n,
        Err(e) => return line(Mark::Skipped, target, format!("skipped: {}", e)),
    };
    if next != current {
        if let Some(dir) = path.parent()
            && let Err(e) = std::fs::create_dir_all(dir) {
            return line(Mark::Skipped, target, format!("skipped: {}", e));
        }
        if let Err(e) = write_atomic(path, &next) {
            return line(Mark::Skipped, target, format!("skipped: {}", e));
        }
    }
    if let (Some(root), false) = (repo_root, existed) {
        let _ = gitguard::exclude_locally(root, path);
    }
    line(Mark::Applied, target, format!("{} memories", entries.len()))
}

pub fn apply_skills(agent: Agent, ctx: &Ctx, skills: &[Skill]) -> Vec<ReportLine> {
    let mut report = Vec::new();
    for s in skills {
        if s.scope == Scope::Project && ctx.repo.as_ref().map(|r| r.key != s.project).unwrap_or(true) {
            continue;
        }
        let Some(root) = agent.skills_root(ctx, s.scope) else { continue };
        if !valid_skill_name(&s.name) {
            report.push(line(Mark::Clash, display_path(&root, ctx), format!("skipped: invalid skill name {:?}", s.name)));
            continue;
        }
        let dir = root.join(&s.name);
        let repo_root = if s.scope == Scope::Project { ctx.repo.as_ref().map(|r| r.root.clone()) } else { None };
        if let Some(l) = apply_one_skill(&dir, repo_root.as_deref(), s, ctx) {
            report.push(l);
        }
    }
    report
}

fn apply_one_skill(dir: &Path, repo_root: Option<&Path>, s: &Skill, ctx: &Ctx) -> Option<ReportLine> {
    let target = display_path(dir, ctx);
    if let Some(root) = repo_root
        && !ctx.allow_tracked && gitguard::is_tracked(root, dir) {
        return Some(line(Mark::Skipped, target, "skipped: tracked by git"));
    }
    match skills_fs::dir_state(dir) {
        DirState::Unmanaged => Some(line(Mark::Clash, target, "skipped: unmanaged skill with same name")),
        DirState::Managed(marker) => {
            if skills_fs::is_drifted(dir, &marker) {
                return Some(line(Mark::Skipped, target,
                    format!("skipped: edited locally — run `atem skill add {} --scope {}` to push the edit",
                        dir.display(), s.scope.as_str())));
            }
            if s.deleted {
                return Some(match std::fs::remove_dir_all(dir) {
                    Ok(()) => line(Mark::Applied, target, "removed"),
                    Err(e) => line(Mark::Skipped, target, format!("skipped: {}", e)),
                });
            }
            if marker.hash == s.content_hash && marker.version == s.version {
                return Some(line(Mark::Applied, target, format!("v{} (unchanged)", s.version)));
            }
            Some(match skills_fs::write_skill_dir(dir, s) {
                Ok(()) => line(Mark::Applied, target, format!("v{}", s.version)),
                Err(e) => line(Mark::Skipped, target, format!("skipped: {}", e)),
            })
        }
        DirState::Missing => {
            if s.deleted {
                return None;
            }
            Some(match skills_fs::write_skill_dir(dir, s) {
                Ok(()) => {
                    if let Some(root) = repo_root {
                        let _ = gitguard::exclude_locally(root, dir);
                    }
                    line(Mark::Applied, target, format!("v{}", s.version))
                }
                Err(e) => line(Mark::Skipped, target, format!("skipped: {}", e)),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::model::{content_hash, skill_hash};
    use std::collections::BTreeMap;
    use std::process::Command;

    #[test]
    fn invalid_facts_are_not_applied() {
        let (_td, ctx) = setup();
        let mut old = m(Scope::Global, "", "", "DialF listens on TCP 8765", "cli", "x");
        old.invalid_at = Some(5);
        let new = m(Scope::Global, "", "", "DialF listens on TCP 9000", "cli", "x");
        apply_memory(Agent::Claude, &ctx, &[old, new]);
        let text = read(ctx.home.join(".claude/CLAUDE.md"));
        assert!(text.contains("TCP 9000") && !text.contains("TCP 8765"));
    }

    fn run_git(dir: &Path, args: &[&str]) {
        assert!(Command::new("git").arg("-C").arg(dir).args(args).output().unwrap().status.success());
    }

    fn setup() -> (tempfile::TempDir, Ctx) {
        let td = tempfile::tempdir().unwrap();
        let base = td.path().canonicalize().unwrap();
        let home = base.join("home");
        std::fs::create_dir_all(home.join(".claude")).unwrap();
        std::fs::create_dir_all(home.join(".codex")).unwrap();
        let root = base.join("repo");
        std::fs::create_dir_all(&root).unwrap();
        run_git(&root, &["init", "-q"]);
        let ctx = Ctx {
            home,
            repo: Some(RepoInfo { root, key: "github.com/acme/dialf".into() }),
            atem_id: "nixps-0001".into(),
            allow_tracked: false,
        };
        (td, ctx)
    }

    fn m(scope: Scope, project: &str, machine: &str, content: &str, agent: &str, src: &str) -> Memory {
        Memory {
            id: format!("mem_{}", content_hash(content)), scope, project: project.into(), machine: machine.into(),
            content: content.into(), content_hash: content_hash(content), confidence: "medium".into(),
            source_agent: agent.into(), source_machine: src.into(), created_at: 1, seq: 0, ..Default::default()
        }
    }

    fn sk(scope: Scope, project: &str, name: &str, version: i64, body: &str) -> Skill {
        let mut files = BTreeMap::new();
        files.insert("SKILL.md".to_string(), body.as_bytes().to_vec());
        Skill {
            scope, project: project.into(), name: name.into(), version,
            content_hash: skill_hash(&files), files,
            source_agent: "cli".into(), source_machine: "m".into(), created_at: 1, deleted: false, seq: 0,
        }
    }

    fn read(p: PathBuf) -> String {
        std::fs::read_to_string(p).unwrap_or_default()
    }

    #[test]
    fn scopes_route_to_the_right_files() {
        let (_td, ctx) = setup();
        let mems = vec![
            m(Scope::Global, "", "", "Run tests before committing", "cli", "x"),
            m(Scope::Machine, "", "nixps-0001", "nixps runs NixOS + Niri", "cli", "x"),
            m(Scope::Machine, "", "hal-0002", "HAL9000 has the GPU", "cli", "x"),
            m(Scope::Project, "github.com/acme/dialf", "", "DialF uses TCP 8765", "cli", "x"),
            m(Scope::Project, "github.com/acme/other", "", "Other uses 9999", "cli", "x"),
        ];
        apply_memory(Agent::Claude, &ctx, &mems);
        let global = read(ctx.home.join(".claude/CLAUDE.md"));
        assert!(global.contains("Run tests before committing") && global.contains("nixps runs NixOS"));
        assert!(!global.contains("HAL9000") && !global.contains("TCP 8765"));
        let local = read(ctx.repo.as_ref().unwrap().root.join("CLAUDE.local.md"));
        assert!(local.contains("DialF uses TCP 8765") && !local.contains("9999"));
    }

    #[test]
    fn instructions_per_agent() {
        let (_td, ctx) = setup();
        apply_memory(Agent::Claude, &ctx, &[]);
        apply_memory(Agent::Codex, &ctx, &[]);
        let claude = read(ctx.home.join(".claude/CLAUDE.md"));
        let codex = read(ctx.home.join(".codex/AGENTS.md"));
        assert!(claude.contains(CREDENTIAL_INSTRUCTION) && !claude.contains(CODEX_CAPTURE_INSTRUCTION));
        assert!(codex.contains(CREDENTIAL_INSTRUCTION) && codex.contains(CODEX_CAPTURE_INSTRUCTION));
    }

    #[test]
    fn claude_does_not_see_its_own_harvest_twice() {
        let (_td, ctx) = setup();
        let root = ctx.repo.as_ref().unwrap().root.clone();
        let mems = vec![m(Scope::Project, "github.com/acme/dialf", "", "DialF uses TCP 8765", "claude", "nixps-0001")];
        apply_memory(Agent::Claude, &ctx, &mems);
        apply_memory(Agent::Codex, &ctx, &mems);
        assert!(!read(root.join("CLAUDE.local.md")).contains("TCP 8765"));
        assert!(read(root.join("AGENTS.md")).contains("TCP 8765"));
    }

    #[test]
    fn claude_sees_its_own_global_harvest_in_global_file() {
        let (_td, ctx) = setup();
        let mems = vec![
            m(Scope::Global, "", "", "Prefers ripgrep", "claude", "nixps-0001"),
            m(Scope::Machine, "", "nixps-0001", "nixps runs NixOS", "claude", "nixps-0001"),
        ];
        apply_memory(Agent::Claude, &ctx, &mems);
        let global = read(ctx.home.join(".claude/CLAUDE.md"));
        assert!(global.contains("Prefers ripgrep") && global.contains("nixps runs NixOS"));
    }

    #[test]
    fn tracked_project_file_is_skipped_unless_allowed() {
        let (_td, mut ctx) = setup();
        let root = ctx.repo.as_ref().unwrap().root.clone();
        std::fs::write(root.join("AGENTS.md"), "team file\n").unwrap();
        run_git(&root, &["add", "AGENTS.md"]);
        let mems = vec![m(Scope::Project, "github.com/acme/dialf", "", "DialF uses TCP 8765", "cli", "x")];
        let report = apply_memory(Agent::Codex, &ctx, &mems);
        let line = report.iter().find(|l| l.target.ends_with("AGENTS.md") && !l.target.starts_with('~')).unwrap();
        assert_eq!(line.mark, Mark::Skipped);
        assert!(line.detail.contains("tracked"));
        assert_eq!(read(root.join("AGENTS.md")), "team file\n");
        ctx.allow_tracked = true;
        apply_memory(Agent::Codex, &ctx, &mems);
        assert!(read(root.join("AGENTS.md")).contains("TCP 8765"));
    }

    #[test]
    fn created_project_file_is_excluded_locally() {
        let (_td, ctx) = setup();
        apply_memory(Agent::Claude, &ctx, &[]);
        let root = &ctx.repo.as_ref().unwrap().root;
        assert!(read(root.join(".git/info/exclude")).lines().any(|l| l == "/CLAUDE.local.md"));
    }

    #[test]
    fn user_text_kept_and_broken_markers_refused() {
        let (_td, ctx) = setup();
        let f = ctx.home.join(".claude/CLAUDE.md");
        std::fs::write(&f, "# mine\n").unwrap();
        apply_memory(Agent::Claude, &ctx, &[]);
        assert!(read(f.clone()).starts_with("# mine\n"));
        let broken = format!("# mine\n{}\n", crate::memory::block::BEGIN);
        std::fs::write(&f, &broken).unwrap();
        let report = apply_memory(Agent::Claude, &ctx, &[]);
        assert_eq!(report[0].mark, Mark::Skipped);
        assert_eq!(read(f), broken);
    }

    #[cfg(unix)]
    #[test]
    fn planted_temp_symlink_is_never_written_through() {
        // A malicious repo can commit `.AGENTS.md.atem-tmp` as a symlink to a
        // file outside the repo. Applying memory must not write through it.
        let (_td, ctx) = setup();
        let root = ctx.repo.as_ref().unwrap().root.clone();
        let victim = ctx.home.join("victim.txt");
        std::fs::write(&victim, "precious\n").unwrap();
        std::os::unix::fs::symlink(&victim, root.join(".AGENTS.md.atem-tmp")).unwrap();
        let mems = vec![m(Scope::Project, "github.com/acme/dialf", "", "DialF uses TCP 8765", "cli", "x")];
        apply_memory(Agent::Codex, &ctx, &mems);
        assert_eq!(read(victim), "precious\n");
        let agents = root.join("AGENTS.md");
        assert!(!std::fs::symlink_metadata(&agents).unwrap().file_type().is_symlink());
        assert!(read(agents).contains("TCP 8765"));
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_claude_md_is_updated_through_the_link() {
        let (_td, ctx) = setup();
        let dotfiles = ctx.home.join("dotfiles");
        std::fs::create_dir_all(&dotfiles).unwrap();
        let real = dotfiles.join("CLAUDE.md");
        std::fs::write(&real, "# mine\n").unwrap();
        let link = ctx.home.join(".claude/CLAUDE.md");
        std::os::unix::fs::symlink("../dotfiles/CLAUDE.md", &link).unwrap();
        let r = apply_memory(Agent::Claude, &ctx, &[m(Scope::Global, "", "", "Prefers ripgrep", "cli", "x")]);
        assert_eq!(r[0].mark, Mark::Applied, "{:?}", r[0]);
        assert!(std::fs::symlink_metadata(&link).unwrap().file_type().is_symlink());
        let text = read(real);
        assert!(text.starts_with("# mine\n") && text.contains("Prefers ripgrep"));
        let leftovers: Vec<_> = std::fs::read_dir(&dotfiles).unwrap().flatten()
            .chain(std::fs::read_dir(ctx.home.join(".claude")).unwrap().flatten())
            .filter(|e| e.file_name().to_string_lossy().contains("atem-tmp")).collect();
        assert!(leftovers.is_empty());
    }

    #[test]
    fn skills_written_for_both_agents() {
        let (_td, ctx) = setup();
        let skills = vec![sk(Scope::Global, "", "deploy-check", 3, "# deploy")];
        let r1 = apply_skills(Agent::Claude, &ctx, &skills);
        let r2 = apply_skills(Agent::Codex, &ctx, &skills);
        assert_eq!(r1[0].mark, Mark::Applied);
        assert_eq!(r2[0].mark, Mark::Applied);
        assert!(ctx.home.join(".claude/skills/deploy-check/SKILL.md").exists());
        assert!(ctx.home.join(".agents/skills/deploy-check/SKILL.md").exists());
    }

    #[test]
    fn unmanaged_skill_is_a_clash() {
        let (_td, ctx) = setup();
        let dir = ctx.home.join(".claude/skills/review");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("SKILL.md"), "# mine").unwrap();
        let r = apply_skills(Agent::Claude, &ctx, &[sk(Scope::Global, "", "review", 1, "# theirs")]);
        assert_eq!(r[0].mark, Mark::Clash);
        assert_eq!(read(dir.join("SKILL.md")), "# mine");
    }

    #[test]
    fn drifted_skill_is_not_overwritten_or_removed() {
        let (_td, ctx) = setup();
        apply_skills(Agent::Claude, &ctx, &[sk(Scope::Global, "", "demo", 1, "# v1")]);
        let f = ctx.home.join(".claude/skills/demo/SKILL.md");
        std::fs::write(&f, "# my edit").unwrap();
        let r = apply_skills(Agent::Claude, &ctx, &[sk(Scope::Global, "", "demo", 2, "# v2")]);
        assert_eq!(r[0].mark, Mark::Skipped);
        assert!(r[0].detail.contains("atem skill add"));
        assert!(r[0].detail.contains("--scope global"), "{}", r[0].detail);
        let mut gone = sk(Scope::Global, "", "demo", 3, "");
        gone.deleted = true;
        apply_skills(Agent::Claude, &ctx, &[gone]);
        assert_eq!(read(f), "# my edit");
    }

    #[test]
    fn deleted_managed_skill_is_removed() {
        let (_td, ctx) = setup();
        apply_skills(Agent::Claude, &ctx, &[sk(Scope::Global, "", "demo", 1, "# v1")]);
        let mut gone = sk(Scope::Global, "", "demo", 2, "");
        gone.deleted = true;
        let r = apply_skills(Agent::Claude, &ctx, &[gone]);
        assert_eq!(r[0].detail, "removed");
        assert!(!ctx.home.join(".claude/skills/demo").exists());
    }

    #[test]
    fn project_skill_only_in_matching_repo_and_excluded() {
        let (_td, ctx) = setup();
        let r = apply_skills(Agent::Claude, &ctx, &[
            sk(Scope::Project, "github.com/acme/dialf", "dialf-run", 1, "# run"),
            sk(Scope::Project, "github.com/acme/other", "other-run", 1, "# other"),
        ]);
        assert_eq!(r.len(), 1);
        let root = &ctx.repo.as_ref().unwrap().root;
        assert!(root.join(".claude/skills/dialf-run/SKILL.md").exists());
        assert!(read(root.join(".git/info/exclude")).lines().any(|l| l == "/.claude/skills/dialf-run"));
    }

    #[test]
    fn invalid_skill_names_are_rejected() {
        assert!(valid_skill_name("deploy-check_2.0"));
        for bad in ["", ".", "..", "a/b", "../x", "a b"] {
            assert!(!valid_skill_name(bad), "{}", bad);
        }
    }
}
