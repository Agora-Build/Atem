//! Project identity = the normalized git `origin` URL, so two repos that
//! share a folder name never collide. Credentials in the URL are dropped.
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Debug, Clone, PartialEq)]
pub struct RepoInfo {
    pub root: PathBuf,
    /// Lowercased match key (`github.com/agora-build/atem`): clones whose
    /// remotes differ only in case still share one project.
    pub key: String,
    /// The same path as the remote spells it (`github.com/Agora-Build/Atem`),
    /// for display only.
    pub label: String,
}

impl RepoInfo {
    /// Short display name for a project key: this repo's own spelling when the
    /// key is this repo, else the stored (lowercase) key's last segment.
    pub fn name_for(&self, key: &str) -> String {
        if key == self.key { display_name(&self.label) } else { display_name(key) }.to_string()
    }
}

/// Short display name for `key`, using `repo`'s spelling when it is that repo.
pub fn project_name(key: &str, repo: Option<&RepoInfo>) -> String {
    match repo {
        Some(r) => r.name_for(key),
        None => display_name(key).to_string(),
    }
}

/// `git@github.com:Agora-Build/Atem.git` and `https://github.com/Agora-Build/Atem`
/// both become `github.com/agora-build/atem`. The one definition is
/// `atem_client::project`, so a manager drafting a service `projects`
/// scope (§R9.6) computes the key Atem records.
pub fn normalize_remote(url: &str) -> Option<String> {
    atem_client::project::project_key_of_remote(url)
}

/// The remote as `<host>/<path>` with its own capitalization
/// (`github.com/Agora-Build/Atem`); credentials, port and `.git` dropped.
pub fn remote_label(url: &str) -> Option<String> {
    atem_client::project::remote_label(url)
}

/// Short name for display: the last path segment (`atem`, `scratch`).
pub fn display_name(key: &str) -> &str {
    key.rsplit('/').next().unwrap_or(key).trim_start_matches("local:")
}

fn git(cwd: &Path, args: &[&str]) -> Option<String> {
    let out = Command::new("git").arg("-C").arg(cwd).args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8(out.stdout).ok()?.trim().to_string();
    if s.is_empty() { None } else { Some(s) }
}

fn dir_name(p: &Path) -> String {
    p.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_else(|| "root".into())
}

pub fn detect_repo(cwd: &Path) -> Option<RepoInfo> {
    let root = PathBuf::from(git(cwd, &["rev-parse", "--show-toplevel"])?);
    let label = git(&root, &["remote", "get-url", "origin"])
        .and_then(|u| remote_label(&u))
        .unwrap_or_else(|| atem_client::project::local_project_key(&dir_name(&root)));
    // `local:` keys keep the folder name's case, as they always have.
    let key = if label.starts_with("local:") { label.clone() } else { label.to_lowercase() };
    Some(RepoInfo { root, key, label })
}

/// The project key of a working directory: its repository's (normalized
/// remote), else `local:<folder>`. Also the launch project of an agent
/// session (atem-session-v1.md §R9.6 service `projects` scopes).
pub fn project_key_for(cwd: &Path) -> String {
    detect_repo(cwd)
        .map(|r| r.key)
        .unwrap_or_else(|| atem_client::project::local_project_key(&dir_name(cwd)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run_git(dir: &Path, args: &[&str]) {
        let ok = std::process::Command::new("git").arg("-C").arg(dir).args(args)
            .output().unwrap().status.success();
        assert!(ok, "git {:?} failed", args);
    }

    #[test]
    fn normalizes_ssh_https_scp_forms() {
        let want = Some("github.com/agora-build/atem".to_string());
        assert_eq!(normalize_remote("git@github.com:Agora-Build/Atem.git"), want);
        assert_eq!(normalize_remote("https://github.com/Agora-Build/Atem"), want);
        assert_eq!(normalize_remote("https://github.com/Agora-Build/Atem.git/"), want);
        assert_eq!(normalize_remote("ssh://git@github.com:22/Agora-Build/Atem.git"), want);
    }

    #[test]
    fn strips_credentials_from_remote() {
        assert_eq!(
            normalize_remote("https://user:tok123@gitlab.com/g/sub/r.git"),
            Some("gitlab.com/g/sub/r".into())
        );
    }

    #[test]
    fn rejects_unusable_remotes() {
        assert_eq!(normalize_remote(""), None);
        assert_eq!(normalize_remote("file:///srv/repo.git"), None);
        assert_eq!(normalize_remote("justaname"), None);
    }

    #[test]
    fn display_name_is_last_segment() {
        assert_eq!(display_name("github.com/agora-build/atem"), "atem");
        assert_eq!(display_name("local:scratch"), "scratch");
    }

    #[test]
    fn detects_repo_key_from_origin() {
        let td = tempfile::tempdir().unwrap();
        run_git(td.path(), &["init", "-q"]);
        run_git(td.path(), &["remote", "add", "origin", "git@github.com:Agora-Build/Atem.git"]);
        let sub = td.path().join("src");
        std::fs::create_dir(&sub).unwrap();
        let info = detect_repo(&sub).unwrap();
        assert_eq!(info.key, "github.com/agora-build/atem");
        assert_eq!(info.label, "github.com/Agora-Build/Atem");
        assert_eq!(info.root, td.path().canonicalize().unwrap());
    }

    #[test]
    fn label_keeps_the_remotes_case_and_key_does_not() {
        assert_eq!(remote_label("git@github.com:Agora-Build/Atem.git").as_deref(), Some("github.com/Agora-Build/Atem"));
        assert_eq!(remote_label("https://user:tok@github.com/Agora-Build/Atem.git/").as_deref(), Some("github.com/Agora-Build/Atem"));
        assert_eq!(normalize_remote("git@github.com:Agora-Build/Atem.git").as_deref(), Some("github.com/agora-build/atem"));
    }

    #[test]
    fn project_name_uses_this_repos_spelling_only_for_this_repo() {
        let repo = RepoInfo {
            root: PathBuf::from("/r"),
            key: "github.com/agora-build/atem".into(),
            label: "github.com/Agora-Build/Atem".into(),
        };
        assert_eq!(project_name("github.com/agora-build/atem", Some(&repo)), "Atem");
        assert_eq!(project_name("github.com/agora-build/astation", Some(&repo)), "astation");
        assert_eq!(project_name("github.com/agora-build/atem", None), "atem");
    }

    #[test]
    fn falls_back_to_local_key_without_remote() {
        let td = tempfile::tempdir().unwrap();
        run_git(td.path(), &["init", "-q"]);
        let info = detect_repo(td.path()).unwrap();
        let name = td.path().canonicalize().unwrap().file_name().unwrap().to_string_lossy().to_string();
        assert_eq!(info.key, format!("local:{}", name));
    }

    #[test]
    fn not_a_repo_returns_none() {
        let td = tempfile::tempdir().unwrap();
        assert!(detect_repo(td.path()).is_none());
        let name = td.path().file_name().unwrap().to_string_lossy().to_string();
        assert_eq!(project_key_for(td.path()), format!("local:{}", name));
    }
}
