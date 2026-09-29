//! Project identity = the normalized git `origin` URL, so two repos that
//! share a folder name never collide. Credentials in the URL are dropped.
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Debug, Clone, PartialEq)]
pub struct RepoInfo {
    pub root: PathBuf,
    pub key: String,
}

/// `git@github.com:Agora-Build/Atem.git` and `https://github.com/Agora-Build/Atem`
/// both become `github.com/agora-build/atem`.
pub fn normalize_remote(url: &str) -> Option<String> {
    let u = url.trim();
    if u.is_empty() {
        return None;
    }
    let (host, path) = if let Some(idx) = u.find("://") {
        let rest = &u[idx + 3..];
        let (authority, path) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i + 1..]),
            None => (rest, ""),
        };
        let host = authority.rsplit('@').next().unwrap_or(authority);
        let host = match host.rsplit_once(':') {
            Some((h, port)) if !port.is_empty() && port.chars().all(|c| c.is_ascii_digit()) => h,
            _ => host,
        };
        (host.to_string(), path.to_string())
    } else if let Some((left, path)) = u.split_once(':') {
        let host = left.rsplit('@').next().unwrap_or(left);
        (host.to_string(), path.to_string())
    } else {
        return None;
    };
    let path = path.trim_matches('/');
    let path = path.strip_suffix(".git").unwrap_or(path);
    if host.is_empty() || path.is_empty() {
        return None;
    }
    Some(format!("{}/{}", host, path).to_lowercase())
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
    let key = git(&root, &["remote", "get-url", "origin"])
        .and_then(|u| normalize_remote(&u))
        .unwrap_or_else(|| format!("local:{}", dir_name(&root)));
    Some(RepoInfo { root, key })
}

#[cfg(test)]
pub fn project_key_for(cwd: &Path) -> String {
    detect_repo(cwd).map(|r| r.key).unwrap_or_else(|| format!("local:{}", dir_name(cwd)))
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
        assert_eq!(info.root, td.path().canonicalize().unwrap());
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
