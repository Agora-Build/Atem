//! Personal memory must never land in a file teammates receive via git.
use anyhow::{anyhow, Result};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// True if `path` (inside `repo_root`) is tracked by git. If git can't be
/// run at all, answer `true` so callers skip the write (the safe side).
pub fn is_tracked(repo_root: &Path, path: &Path) -> bool {
    let rel = match path.strip_prefix(repo_root) {
        Ok(r) => r,
        Err(_) => return false,
    };
    match Command::new("git").arg("-C").arg(repo_root)
        .env("GIT_LITERAL_PATHSPECS", "1")
        .args(["ls-files", "--error-unmatch", "--"]).arg(rel)
        .stdout(Stdio::null()).stderr(Stdio::null()).status()
    {
        Ok(s) => s.success(),
        Err(_) => true,
    }
}

/// Add `/relpath` to the repo's local-only exclude file (worktree-aware via
/// `git rev-parse --git-path`). Never touches a committed .gitignore.
pub fn exclude_locally(repo_root: &Path, path: &Path) -> Result<()> {
    let rel = path.strip_prefix(repo_root)
        .map_err(|_| anyhow!("{} is outside {}", path.display(), repo_root.display()))?;
    let out = Command::new("git").arg("-C").arg(repo_root)
        .args(["rev-parse", "--git-path", "info/exclude"]).output()?;
    if !out.status.success() {
        return Err(anyhow!("git rev-parse --git-path info/exclude failed"));
    }
    let p = String::from_utf8_lossy(&out.stdout).trim().to_string();
    let exclude = if Path::new(&p).is_absolute() { PathBuf::from(p) } else { repo_root.join(p) };
    let line = format!("/{}", rel.to_string_lossy().replace('\\', "/"));
    let existing = std::fs::read_to_string(&exclude).unwrap_or_default();
    if existing.lines().any(|l| l.trim() == line) {
        return Ok(());
    }
    if let Some(dir) = exclude.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let mut body = existing;
    if !body.is_empty() && !body.ends_with('\n') {
        body.push('\n');
    }
    body.push_str(&line);
    body.push('\n');
    std::fs::write(&exclude, body)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run_git(dir: &Path, args: &[&str]) {
        assert!(Command::new("git").arg("-C").arg(dir).args(args).output().unwrap().status.success());
    }

    fn repo() -> (tempfile::TempDir, PathBuf) {
        let td = tempfile::tempdir().unwrap();
        run_git(td.path(), &["init", "-q"]);
        let root = td.path().canonicalize().unwrap();
        (td, root)
    }

    #[test]
    fn tracked_vs_untracked() {
        let (_td, root) = repo();
        std::fs::write(root.join("CLAUDE.md"), "x").unwrap();
        run_git(&root, &["add", "CLAUDE.md"]);
        assert!(is_tracked(&root, &root.join("CLAUDE.md")));
        std::fs::write(root.join("CLAUDE.local.md"), "y").unwrap();
        assert!(!is_tracked(&root, &root.join("CLAUDE.local.md")));
        assert!(!is_tracked(&root, &root.join("missing.md")));
    }

    #[test]
    fn exclude_is_local_and_idempotent() {
        let (_td, root) = repo();
        let p = root.join("CLAUDE.local.md");
        exclude_locally(&root, &p).unwrap();
        exclude_locally(&root, &p).unwrap();
        let ex = std::fs::read_to_string(root.join(".git/info/exclude")).unwrap();
        assert_eq!(ex.lines().filter(|l| *l == "/CLAUDE.local.md").count(), 1);
        assert!(!root.join(".gitignore").exists());
    }

    #[test]
    fn leading_colon_filename_is_tracked() {
        let (_td, root) = repo();
        std::fs::write(root.join(":weird.md"), "x").unwrap();
        run_git(&root, &["add", "--", "./:weird.md"]);
        assert!(is_tracked(&root, &root.join(":weird.md")));
    }
}
