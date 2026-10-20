//! The device list's files (§R9.3 "Writing the device list"), in the same
//! style as `FileJournal`: every file is private (0600 in a 0700 directory,
//! never through a symlink) and replaced whole — temp file (`O_EXCL`,
//! `O_NOFOLLOW`), write, fsync, rename, directory fsync — and a removal is
//! followed by a directory fsync.
//!
//! ```text
//! <profile>/pairing/membership.json      the verified log and the host's state
//! <profile>/pairing/membership.carriage  a carriage, durable before it is evaluated
//! <profile>/pairing/membership.intent    the head about to be written
//! <profile>/pairing/membership.freeze    both entries of a freeze
//! <profile>/pairing/membership.fault     an observed device-list write fault
//! <profile>/pairing/frozen_genesis       genesis hashes this host froze on (≤ 16)
//! <config>/runtime/journal/membership_applied  the head whose fences are durable
//! ```
//!
//! Every step can fail on purpose (tests, and the debug-only hook
//! `ATEM_TEST_MEMBERSHIP_FAULTS`, `runtime::test_hooks`): the next write of
//! a given file fails at its temp write, temp fsync, rename or directory
//! fsync, like the real failure would (the temp file is removed; after a
//! failed directory fsync the renamed file is there, its durability
//! unknown).
use crate::paths::PairingPaths;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

/// Largest device-list file read (a full log of 1024 entries ≤ 4 KiB
/// bodies, plus recovery records and evidence).
const MAX_FILE: u64 = 16 << 20;

/// The device-list files a write can fail on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DlFile {
    /// `membership.carriage`.
    Carriage,
    /// `membership.intent`.
    Intent,
    /// `membership.json`.
    State,
    /// `membership.freeze`.
    Freeze,
    /// `membership.fault`.
    Fault,
    /// `<journal>/membership_applied`.
    Applied,
    /// `frozen_genesis`.
    FrozenGenesis,
    /// `host_channel_key`.
    HostChannelKey,
}

impl DlFile {
    pub fn name(self) -> &'static str {
        match self {
            DlFile::Carriage => "membership.carriage",
            DlFile::Intent => "membership.intent",
            DlFile::State => "membership.json",
            DlFile::Freeze => "membership.freeze",
            DlFile::Fault => "membership.fault",
            DlFile::Applied => "membership_applied",
            DlFile::FrozenGenesis => "frozen_genesis",
            DlFile::HostChannelKey => "host_channel_key",
        }
    }

    /// The fixtures' names (`fail_next_membership_write.file`).
    pub fn parse(name: &str) -> Option<DlFile> {
        Some(match name {
            "carriage" => DlFile::Carriage,
            "intent" => DlFile::Intent,
            "state" | "membership" => DlFile::State,
            "freeze" => DlFile::Freeze,
            "fault" => DlFile::Fault,
            "applied" => DlFile::Applied,
            _ => return None,
        })
    }
}

/// Where a write fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    /// Writing the temp file (it is left half written, then removed).
    TempWrite,
    /// Its fsync.
    TempFsync,
    /// The rename over the file.
    Rename,
    /// The directory fsync after the rename.
    DirectoryFsync,
    /// A removal's directory fsync (the unlink may not be durable).
    Remove,
}

impl Step {
    pub fn parse(name: &str) -> Option<Step> {
        Some(match name {
            "temp_write" => Step::TempWrite,
            "temp_fsync" => Step::TempFsync,
            "rename" => Step::Rename,
            "directory_fsync" => Step::DirectoryFsync,
            "remove" => Step::Remove,
            _ => return None,
        })
    }

    pub fn name(self) -> &'static str {
        match self {
            Step::TempWrite => "temp_write",
            Step::TempFsync => "temp_fsync",
            Step::Rename => "rename",
            Step::DirectoryFsync => "directory_fsync",
            Step::Remove => "remove",
        }
    }
}

/// An injected failure: the next write of `file` fails at `step`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Injected {
    pub file: DlFile,
    pub step: Step,
}

impl Injected {
    /// `"<file>:<step>"` (the debug hook's marker), or the fixtures' `at`
    /// alone (`"intent"` is the intent's temp write; else `membership.json`).
    pub fn parse(text: &str) -> Option<Injected> {
        let text = text.trim();
        if let Some((file, step)) = text.split_once(':') {
            return Some(Injected {
                file: DlFile::parse(file)?,
                step: Step::parse(step)?,
            });
        }
        if text == "intent" {
            return Some(Injected {
                file: DlFile::Intent,
                step: Step::TempWrite,
            });
        }
        Some(Injected {
            file: DlFile::State,
            step: Step::parse(text)?,
        })
    }
}

/// A failed write or removal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteError {
    pub file: DlFile,
    pub step: Step,
    pub message: String,
}

impl std::fmt::Display for WriteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} ({}): {}",
            self.file.name(),
            self.step.name(),
            self.message
        )
    }
}

/// A rename whose directory fsync failed: the file before it (`None`: there
/// was none). Tests use it to simulate a machine that lost the rename.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsyncedRename {
    pub path: PathBuf,
    pub before: Option<Vec<u8>>,
}

pub struct Store {
    pairing: PairingPaths,
    journal_dir: PathBuf,
    injected: Option<Injected>,
    unsynced: Option<UnsyncedRename>,
}

impl std::fmt::Debug for Store {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Store")
            .field("pairing", &self.pairing.dir())
            .finish_non_exhaustive()
    }
}

fn euid() -> u32 {
    unsafe { libc::geteuid() }
}

/// `dir` is a real directory of this user nobody else can write (created
/// 0700 when missing).
pub fn private_dir(dir: &Path) -> io::Result<()> {
    match fs::symlink_metadata(dir) {
        Ok(meta) => {
            if meta.file_type().is_symlink() || !meta.is_dir() {
                return Err(io::Error::other(format!(
                    "{} is not a directory (a symlink is refused)",
                    dir.display()
                )));
            }
            if meta.uid() != euid() || meta.mode() & 0o077 != 0 {
                return Err(io::Error::other(format!(
                    "{} is not a private directory of this user (0700); run chmod 700 {}",
                    dir.display(),
                    dir.display()
                )));
            }
            Ok(())
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            if let Some(parent) = dir.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::DirBuilder::new().mode(0o700).create(dir)?;
            fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
        }
        Err(e) => Err(e),
    }
}

fn sync_dir(dir: &Path) -> io::Result<()> {
    File::open(dir)?.sync_all()
}

/// Reads a private file (never through a symlink, a regular file of this
/// user, bounded). `None` when it doesn't exist.
pub fn read_private(path: &Path) -> io::Result<Option<Vec<u8>>> {
    let mut file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
    {
        Ok(file) => file,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let meta = file.metadata()?;
    if !meta.is_file() || meta.uid() != euid() {
        return Err(io::Error::other("not a regular file of this user"));
    }
    if meta.len() > MAX_FILE {
        return Err(io::Error::other("too large"));
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    Ok(Some(bytes))
}

/// Whether `path` exists in any state (a symlink or a damaged file counts).
pub fn present(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok()
}

fn temp_of(path: &Path) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".tmp");
    path.with_file_name(name)
}

fn remove_entry(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        other => other,
    }
}

impl Store {
    pub fn new(pairing: &PairingPaths, journal_dir: &Path) -> Self {
        Store {
            pairing: pairing.clone(),
            journal_dir: journal_dir.to_path_buf(),
            injected: None,
            unsynced: None,
        }
    }

    pub fn pairing(&self) -> &PairingPaths {
        &self.pairing
    }

    pub fn path(&self, file: DlFile) -> PathBuf {
        match file {
            DlFile::Carriage => self.pairing.carriage.clone(),
            DlFile::Intent => self.pairing.intent.clone(),
            DlFile::State => self.pairing.membership.clone(),
            DlFile::Freeze => self.pairing.freeze.clone(),
            DlFile::Fault => self.pairing.fault.clone(),
            DlFile::Applied => self.journal_dir.join("membership_applied"),
            DlFile::FrozenGenesis => self.pairing.frozen_genesis.clone(),
            DlFile::HostChannelKey => self.pairing.host_channel_key.clone(),
        }
    }

    fn dir_of(&self, file: DlFile) -> PathBuf {
        match file {
            DlFile::Applied => self.journal_dir.clone(),
            _ => self.pairing.dir().to_path_buf(),
        }
    }

    /// The next write of `injected.file` fails at `injected.step`.
    pub fn inject(&mut self, injected: Injected) {
        self.injected = Some(injected);
    }

    /// The last rename whose directory fsync failed, if any.
    pub fn unsynced_rename(&self) -> Option<&UnsyncedRename> {
        self.unsynced.as_ref()
    }

    /// Whether the step fails now (an injected fault, else the debug hook).
    fn fails(&mut self, file: DlFile, step: Step) -> bool {
        if self.injected.is_none()
            && let Some(marker) = crate::runtime::test_hooks::membership_fault()
        {
            self.injected = Injected::parse(&marker);
        }
        if self.injected == Some(Injected { file, step }) {
            self.injected = None;
            return true;
        }
        false
    }

    fn failure(file: DlFile, step: Step, message: impl Into<String>) -> WriteError {
        WriteError {
            file,
            step,
            message: message.into(),
        }
    }

    /// Replaces `file` with `bytes`: temp, fsync, rename, directory fsync.
    pub fn replace(&mut self, file: DlFile, bytes: &[u8]) -> Result<(), WriteError> {
        let path = self.path(file);
        let dir = self.dir_of(file);
        let tmp = temp_of(&path);
        let injected = |s: &mut Self, step| s.fails(file, step);
        let io = |step, e: io::Error| Self::failure(file, step, e.to_string());
        private_dir(&dir).map_err(|e| io(Step::TempWrite, e))?;
        remove_entry(&tmp).map_err(|e| io(Step::TempWrite, e))?;
        let written = (|| -> Result<(), WriteError> {
            let mut f = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW)
                .open(&tmp)
                .map_err(|e| io(Step::TempWrite, e))?;
            if injected(self, Step::TempWrite) {
                let _ = f.write_all(&bytes[..bytes.len() / 2]);
                return Err(Self::failure(
                    file,
                    Step::TempWrite,
                    "injected write failure",
                ));
            }
            f.write_all(bytes).map_err(|e| io(Step::TempWrite, e))?;
            if injected(self, Step::TempFsync) {
                return Err(Self::failure(
                    file,
                    Step::TempFsync,
                    "injected fsync failure",
                ));
            }
            f.sync_all().map_err(|e| io(Step::TempFsync, e))?;
            drop(f);
            if injected(self, Step::Rename) {
                return Err(Self::failure(file, Step::Rename, "injected rename failure"));
            }
            Ok(())
        })();
        if let Err(e) = written {
            let _ = remove_entry(&tmp);
            return Err(e);
        }
        // The bytes a lost rename would bring back: kept only for tests
        // (in-process, or a debug build with the hooks set), never read on
        // a release write path.
        let before = if cfg!(test) || crate::runtime::test_hooks::membership_hooks() {
            read_private(&path).ok().flatten()
        } else {
            None
        };
        fs::rename(&tmp, &path).map_err(|e| {
            let _ = remove_entry(&tmp);
            io(Step::Rename, e)
        })?;
        let synced = if injected(self, Step::DirectoryFsync) {
            Err(io::Error::other("injected directory fsync failure"))
        } else {
            sync_dir(&dir)
        };
        synced.map_err(|e| {
            self.unsynced = Some(UnsyncedRename {
                path: path.clone(),
                before,
            });
            io(Step::DirectoryFsync, e)
        })
    }

    /// Removes `file` (if present), then fsyncs its directory.
    pub fn remove(&mut self, file: DlFile) -> Result<(), WriteError> {
        let path = self.path(file);
        let dir = self.dir_of(file);
        if !present(&path) && !present(&temp_of(&path)) {
            return Ok(()); // nothing to remove, nothing to sync
        }
        // The unlink itself (reported as `Rename`: nothing changed).
        if self.fails(file, Step::Rename) {
            return Err(Self::failure(file, Step::Rename, "injected unlink failure"));
        }
        remove_entry(&temp_of(&path))
            .and_then(|()| remove_entry(&path))
            .map_err(|e| Self::failure(file, Step::Rename, e.to_string()))?;
        if self.fails(file, Step::Remove) {
            return Err(Self::failure(
                file,
                Step::Remove,
                "injected directory fsync failure",
            ));
        }
        sync_dir(&dir).map_err(|e| Self::failure(file, Step::Remove, e.to_string()))
    }

    /// The file's bytes (`None`: absent). A file that can't be read is an
    /// error, never "absent".
    pub fn read(&self, file: DlFile) -> io::Result<Option<Vec<u8>>> {
        read_private(&self.path(file))
    }

    /// Whether `file` exists in any state; for the freeze, a leftover temp
    /// file counts too (a freeze write that reached the disk in any state).
    pub fn present(&self, file: DlFile) -> bool {
        let path = self.path(file);
        present(&path) || (file == DlFile::Freeze && present(&temp_of(&path)))
    }

    /// At start, before anything is trusted: `membership.json` and the
    /// pairing directory are fsynced, so a rename that is visible is
    /// durable (§R9.3 "Crash recovery").
    pub fn sync_at_start(&self) -> io::Result<()> {
        private_dir(self.pairing.dir())?;
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&self.pairing.membership)?;
        file.sync_all()?;
        sync_dir(self.pairing.dir())
    }

    /// Takes `pairing/trust_gen.lock` (every write of the device list holds
    /// it, §R9.3).
    pub fn lock(&self) -> anyhow::Result<crate::memory::trust::TrustLock> {
        crate::memory::trust::TrustStore::lock(&self.pairing.trust_gen)
    }
}
