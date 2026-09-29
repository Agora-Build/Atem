//! Skill directories on disk. atem marks every directory it writes with
//! `.atem-skill` and never overwrites a directory it didn't create or one
//! that was edited locally (drift).
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;
use crate::memory::model::{skill_hash, Scope, Skill};

pub const MARKER_FILE: &str = ".atem-skill";
pub const MAX_SKILL_BYTES: usize = 1_048_576;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SkillMarker {
    pub name: String,
    pub version: i64,
    /// skill_hash of the files atem last wrote (or accepted) here.
    pub hash: String,
    /// Which skill this dir holds. Markers written before these fields
    /// existed parse as global / no project.
    #[serde(default)]
    pub scope: Scope,
    #[serde(default)]
    pub project: String,
}

#[derive(Debug, PartialEq)]
pub enum DirState {
    Missing,
    Unmanaged,
    Managed(SkillMarker),
}

/// All files under `dir` (excluding the marker and .git), keyed by
/// '/'-separated relative path. Rejects symlinks and anything over 1 MB.
pub fn read_all(dir: &Path) -> Result<BTreeMap<String, Vec<u8>>> {
    let mut files = BTreeMap::new();
    let mut total = 0usize;
    collect(dir, dir, &mut files, &mut total)?;
    Ok(files)
}

/// `read_all`, plus the requirement that SKILL.md sits at the top level.
pub fn read_skill_dir(dir: &Path) -> Result<BTreeMap<String, Vec<u8>>> {
    let files = read_all(dir)?;
    if !files.contains_key("SKILL.md") {
        return Err(anyhow!("{} has no SKILL.md at its top level", dir.display()));
    }
    Ok(files)
}

fn collect(root: &Path, dir: &Path, files: &mut BTreeMap<String, Vec<u8>>, total: &mut usize) -> Result<()> {
    let mut entries: Vec<_> = std::fs::read_dir(dir)?.filter_map(|e| e.ok()).collect();
    entries.sort_by_key(|e| e.file_name());
    for e in entries {
        let name = e.file_name().to_string_lossy().to_string();
        if name == MARKER_FILE || name == ".git" {
            continue;
        }
        let path = e.path();
        let ft = e.file_type()?;
        if ft.is_symlink() {
            return Err(anyhow!("{} is a symlink; skills must contain regular files only", path.display()));
        }
        if ft.is_dir() {
            collect(root, &path, files, total)?;
            continue;
        }
        let bytes = std::fs::read(&path)?;
        *total += bytes.len();
        if *total > MAX_SKILL_BYTES {
            return Err(anyhow!("skill is larger than 1 MB"));
        }
        let rel = path.strip_prefix(root)?.to_string_lossy().replace('\\', "/");
        files.insert(rel, bytes);
    }
    Ok(())
}

pub fn dir_state(dir: &Path) -> DirState {
    if !dir.exists() {
        return DirState::Missing;
    }
    match std::fs::read_to_string(dir.join(MARKER_FILE))
        .ok()
        .and_then(|t| serde_json::from_str::<SkillMarker>(&t).ok())
    {
        Some(m) => DirState::Managed(m),
        None => DirState::Unmanaged,
    }
}

/// True if the files on disk no longer match what atem last wrote.
pub fn is_drifted(dir: &Path, marker: &SkillMarker) -> bool {
    match read_all(dir) {
        Ok(files) => skill_hash(&files) != marker.hash,
        Err(_) => true,
    }
}

pub fn write_marker(dir: &Path, marker: &SkillMarker) -> Result<()> {
    std::fs::write(dir.join(MARKER_FILE), serde_json::to_string_pretty(marker)?)?;
    Ok(())
}

fn safe_rel(rel: &str) -> bool {
    !rel.is_empty() && !rel.starts_with('/') && !rel.contains('\\')
        && rel.split('/').all(|seg| !seg.is_empty() && seg != "." && seg != ".." && seg != ".git" && seg != MARKER_FILE)
}

/// Replace `dir` with the skill's files and a fresh marker. Callers must have
/// checked `dir_state` first (Missing, or Managed and not drifted).
/// Writes atomically: files go into a temp sibling dir, then swapped via rename-aside.
pub fn write_skill_dir(dir: &Path, skill: &Skill) -> Result<()> {
    if let Some(bad) = skill.files.keys().find(|k| !safe_rel(k)) {
        return Err(anyhow!("unsafe path in skill: {}", bad));
    }

    // Enforce size cap before touching disk
    let total_bytes: usize = skill.files.values().map(|b| b.len()).sum();
    if total_bytes > MAX_SKILL_BYTES {
        return Err(anyhow!("skill is larger than 1 MB"));
    }

    // Get the directory name for the temp directory
    let dir_name = dir.file_name().ok_or_else(|| anyhow!("invalid directory path"))?;
    let tmp_name = format!(".{}.atem-tmp", dir_name.to_string_lossy());
    let tmp = dir.parent().ok_or_else(|| anyhow!("cannot get parent directory"))?.join(&tmp_name);

    // Clean up any leftover temp directory
    if tmp.exists() {
        std::fs::remove_dir_all(&tmp)?;
    }

    // Helper closure to write files into the temp directory
    let write_to_tmp = || -> Result<()> {
        std::fs::create_dir_all(&tmp)?;
        for (rel, bytes) in &skill.files {
            let p = tmp.join(rel);
            if let Some(parent) = p.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(&p, bytes)?;
            #[cfg(unix)]
            if bytes.starts_with(b"#!") {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755))?;
            }
        }
        write_marker(&tmp, &SkillMarker {
            name: skill.name.clone(), version: skill.version, hash: skill_hash(&skill.files),
            scope: skill.scope, project: skill.project.clone(),
        })?;
        Ok(())
    };

    // Execute the write, with cleanup on error
    if let Err(e) = write_to_tmp() {
        let _ = std::fs::remove_dir_all(&tmp);
        return Err(e);
    }

    // Rename-aside swap: atomically move target to old, then temp to target
    let do_swap = || -> Result<()> {
        let old_name = format!(".{}.atem-old", dir_name.to_string_lossy());
        let old = dir.parent().unwrap().join(&old_name);

        // Clean up any stale leftover old directory
        if old.exists() {
            std::fs::remove_dir_all(&old)?;
        }

        // Move current target to old (if it exists)
        if dir.exists() {
            std::fs::rename(dir, &old)?;
        }

        // Try to move temp to target
        match std::fs::rename(&tmp, dir) {
            Ok(()) => {
                // Success: clean up old (best effort)
                let _ = std::fs::remove_dir_all(&old);
                Ok(())
            }
            Err(e) => {
                // Rename failed: restore old if we moved it
                if old.exists() {
                    let _ = std::fs::rename(&old, dir);
                }
                Err(e.into())
            }
        }
    };

    // Execute swap with cleanup on error
    if let Err(e) = do_swap() {
        let _ = std::fs::remove_dir_all(&tmp);
        return Err(e);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk(dir: &Path, files: &[(&str, &str)]) {
        for (p, c) in files {
            let path = dir.join(p);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, c).unwrap();
        }
    }

    fn skill_from(files: BTreeMap<String, Vec<u8>>, version: i64) -> Skill {
        Skill {
            scope: Scope::Global, project: String::new(), name: "demo".into(), version,
            content_hash: skill_hash(&files), files,
            source_agent: "cli".into(), source_machine: "m".into(),
            created_at: 1, deleted: false, seq: 0,
        }
    }

    #[test]
    fn reads_skill_with_nested_files() {
        let td = tempfile::tempdir().unwrap();
        mk(td.path(), &[("SKILL.md", "# s"), ("scripts/run.sh", "#!/bin/sh\necho hi\n")]);
        let f = read_skill_dir(td.path()).unwrap();
        assert_eq!(f.keys().cloned().collect::<Vec<_>>(), vec!["SKILL.md", "scripts/run.sh"]);
    }

    #[test]
    fn requires_skill_md() {
        let td = tempfile::tempdir().unwrap();
        mk(td.path(), &[("README.md", "x")]);
        assert!(read_skill_dir(td.path()).is_err());
    }

    #[test]
    fn enforces_size_cap() {
        let td = tempfile::tempdir().unwrap();
        let big = "x".repeat(MAX_SKILL_BYTES);
        mk(td.path(), &[("SKILL.md", "# s"), ("big.txt", &big)]);
        assert!(read_skill_dir(td.path()).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlinks() {
        let td = tempfile::tempdir().unwrap();
        mk(td.path(), &[("SKILL.md", "# s")]);
        std::os::unix::fs::symlink("/etc/hostname", td.path().join("link")).unwrap();
        assert!(read_skill_dir(td.path()).is_err());
    }

    #[test]
    fn write_then_state_is_managed_and_clean() {
        let src = tempfile::tempdir().unwrap();
        mk(src.path(), &[("SKILL.md", "# s"), ("scripts/run.sh", "#!/bin/sh\necho hi\n")]);
        let skill = skill_from(read_skill_dir(src.path()).unwrap(), 2);
        let out = tempfile::tempdir().unwrap();
        let dir = out.path().join("demo");
        assert_eq!(dir_state(&dir), DirState::Missing);
        write_skill_dir(&dir, &skill).unwrap();
        match dir_state(&dir) {
            DirState::Managed(m) => {
                assert_eq!(m.version, 2);
                assert!(!is_drifted(&dir, &m));
            }
            other => panic!("unexpected {:?}", other),
        }
    }

    #[cfg(unix)]
    #[test]
    fn shebang_files_are_executable() {
        use std::os::unix::fs::PermissionsExt;
        let mut files = BTreeMap::new();
        files.insert("SKILL.md".to_string(), b"# s".to_vec());
        files.insert("run.sh".to_string(), b"#!/bin/sh\n".to_vec());
        let out = tempfile::tempdir().unwrap();
        let dir = out.path().join("demo");
        write_skill_dir(&dir, &skill_from(files, 1)).unwrap();
        let mode = std::fs::metadata(dir.join("run.sh")).unwrap().permissions().mode();
        assert_eq!(mode & 0o111, 0o111);
    }

    #[test]
    fn local_edit_is_drift() {
        let mut files = BTreeMap::new();
        files.insert("SKILL.md".to_string(), b"# s".to_vec());
        let out = tempfile::tempdir().unwrap();
        let dir = out.path().join("demo");
        write_skill_dir(&dir, &skill_from(files, 1)).unwrap();
        std::fs::write(dir.join("SKILL.md"), "edited").unwrap();
        let DirState::Managed(m) = dir_state(&dir) else { panic!("not managed") };
        assert!(is_drifted(&dir, &m));
    }

    #[test]
    fn write_marker_accepts_a_local_edit() {
        let mut files = BTreeMap::new();
        files.insert("SKILL.md".to_string(), b"# s".to_vec());
        let out = tempfile::tempdir().unwrap();
        let dir = out.path().join("demo");
        write_skill_dir(&dir, &skill_from(files, 1)).unwrap();
        std::fs::write(dir.join("SKILL.md"), "edited").unwrap();
        let now = read_skill_dir(&dir).unwrap();
        write_marker(&dir, &SkillMarker { name: "demo".into(), version: 2, hash: skill_hash(&now), scope: Scope::Global, project: String::new() }).unwrap();
        let DirState::Managed(m) = dir_state(&dir) else { panic!("not managed") };
        assert!(!is_drifted(&dir, &m));
    }

    #[test]
    fn old_marker_without_scope_still_parses() {
        let m: SkillMarker = serde_json::from_str(r#"{"name":"demo","version":3,"hash":"abc"}"#).unwrap();
        assert_eq!((m.scope, m.project.as_str(), m.version), (Scope::Global, "", 3));
        let td = tempfile::tempdir().unwrap();
        std::fs::write(td.path().join(MARKER_FILE), r#"{"name":"demo","version":3,"hash":"abc"}"#).unwrap();
        assert!(matches!(dir_state(td.path()), DirState::Managed(_)));
    }

    #[test]
    fn marker_records_scope_and_project() {
        let mut files = BTreeMap::new();
        files.insert("SKILL.md".to_string(), b"# s".to_vec());
        let mut skill = skill_from(files, 1);
        skill.scope = Scope::Project;
        skill.project = "github.com/acme/dialf".into();
        let out = tempfile::tempdir().unwrap();
        let dir = out.path().join("demo");
        write_skill_dir(&dir, &skill).unwrap();
        let DirState::Managed(m) = dir_state(&dir) else { panic!("not managed") };
        assert_eq!((m.scope, m.project.as_str()), (Scope::Project, "github.com/acme/dialf"));
    }

    #[test]
    fn unmanaged_dir_detected() {
        let td = tempfile::tempdir().unwrap();
        mk(td.path(), &[("SKILL.md", "# mine")]);
        assert_eq!(dir_state(td.path()), DirState::Unmanaged);
    }

    #[test]
    fn refuses_unsafe_paths() {
        for bad in ["../evil", "/abs", "a//b", "a/../b", ".git/config", "sub/.git/hooks/pre-commit", ".atem-skill", "x/.atem-skill"] {
            let mut files = BTreeMap::new();
            files.insert("SKILL.md".to_string(), b"# s".to_vec());
            files.insert(bad.to_string(), b"x".to_vec());
            let out = tempfile::tempdir().unwrap();
            assert!(write_skill_dir(&out.path().join("demo"), &skill_from(files, 1)).is_err(), "{}", bad);
        }
    }

    #[test]
    fn write_refuses_oversized_skill() {
        let out = tempfile::tempdir().unwrap();
        let dir = out.path().join("demo");
        let mut files = BTreeMap::new();
        files.insert("SKILL.md".to_string(), b"# s".to_vec());
        let big = vec![0u8; MAX_SKILL_BYTES + 1];
        files.insert("big.bin".to_string(), big);

        let result = write_skill_dir(&dir, &skill_from(files, 1));
        assert!(result.is_err());
        assert!(!dir.exists());
    }

    #[test]
    fn failed_write_leaves_target_untouched() {
        let out = tempfile::tempdir().unwrap();
        let dir = out.path().join("demo");

        // Write v1: valid skill
        let mut files_v1 = BTreeMap::new();
        files_v1.insert("SKILL.md".to_string(), b"# s".to_vec());
        write_skill_dir(&dir, &skill_from(files_v1, 1)).unwrap();

        // Attempt v2 with conflicting structure
        let mut files_v2 = BTreeMap::new();
        files_v2.insert("SKILL.md".to_string(), b"# s".to_vec());
        files_v2.insert("a".to_string(), b"file".to_vec());
        files_v2.insert("a/b".to_string(), b"x".to_vec()); // This will fail: "a" is a file, not a dir

        let result = write_skill_dir(&dir, &skill_from(files_v2, 2));
        assert!(result.is_err());

        // Check that the target is still v1 and not drifted
        let DirState::Managed(m) = dir_state(&dir) else { panic!("not managed") };
        assert_eq!(m.version, 1);
        assert!(!is_drifted(&dir, &m));

        // Check that temp dir doesn't exist
        let tmp_name = ".demo.atem-tmp";
        let tmp = out.path().join(tmp_name);
        assert!(!tmp.exists());
    }

    #[test]
    fn successful_rewrite_leaves_no_temp_or_old_dirs() {
        let out = tempfile::tempdir().unwrap();
        let dir = out.path().join("demo");

        // Write v1
        let mut files_v1 = BTreeMap::new();
        files_v1.insert("SKILL.md".to_string(), b"# s".to_vec());
        write_skill_dir(&dir, &skill_from(files_v1, 1)).unwrap();

        // Write v2 successfully
        let mut files_v2 = BTreeMap::new();
        files_v2.insert("SKILL.md".to_string(), b"# s modified".to_vec());
        write_skill_dir(&dir, &skill_from(files_v2, 2)).unwrap();

        // Check state
        let DirState::Managed(m) = dir_state(&dir) else { panic!("not managed") };
        assert_eq!(m.version, 2);
        assert!(!is_drifted(&dir, &m));

        // Check no temp or old dirs exist
        let tmp_name = ".demo.atem-tmp";
        let old_name = ".demo.atem-old";
        let tmp = out.path().join(tmp_name);
        let old = out.path().join(old_name);
        assert!(!tmp.exists(), "temp dir should not exist");
        assert!(!old.exists(), "old dir should not exist");
    }
}
