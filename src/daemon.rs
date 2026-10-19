//! Plumbing shared by Atem's detached daemons (the key agent, the runtime):
//! per-user socket directories, peer checks, pid-bearing lock files, socket
//! binding and detached spawning. Same-user only; nothing here knows a
//! protocol.

use std::ffi::OsString;
use std::io::{self, Write};
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::io::AsRawFd;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// The files one daemon owns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DaemonFiles {
    /// The listening socket.
    pub socket: PathBuf,
    /// Lock file; the holder writes its pid into it.
    pub lock: PathBuf,
    /// Records the socket path for clients whose runtime dir differs.
    pub record: PathBuf,
    /// Output of the detached daemon.
    pub log: PathBuf,
}

impl DaemonFiles {
    /// Files for a new daemon `name`: `<name>.sock`, `<name>.lock`,
    /// `<name>.socket` and `<name>.log`. Socket, lock and record sit in
    /// `$XDG_RUNTIME_DIR/atem` when that is an absolute, safe directory, else
    /// in `config_dir`; the log is always in `config_dir`.
    pub fn for_name(config_dir: &Path, runtime_dir: Option<OsString>, name: &str) -> Self {
        let dir = runtime_dir
            .filter(|dir| {
                !dir.is_empty()
                    && Path::new(dir).is_absolute()
                    && check_parent_dir(Path::new(dir), unsafe { libc::getuid() }).is_ok()
            })
            .map(|dir| PathBuf::from(dir).join("atem"))
            .unwrap_or_else(|| config_dir.to_path_buf());
        Self {
            socket: dir.join(format!("{name}.sock")),
            lock: dir.join(format!("{name}.lock")),
            record: dir.join(format!("{name}.socket")),
            log: config_dir.join(format!("{name}.log")),
        }
    }
}

fn refuse(message: String) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}

/// A directory the socket's directory lives in: a real directory (not a
/// symlink) owned by `uid` that nobody else can write to.
pub fn check_parent_dir(dir: &Path, uid: u32) -> io::Result<()> {
    let meta = std::fs::symlink_metadata(dir).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("cannot inspect {}: {error}", dir.display()),
        )
    })?;
    if meta.file_type().is_symlink() {
        return Err(refuse(format!("{} is a symlink", dir.display())));
    }
    if !meta.is_dir() {
        return Err(refuse(format!("{} is not a directory", dir.display())));
    }
    if meta.uid() != uid {
        return Err(refuse(format!(
            "{} is owned by another user",
            dir.display()
        )));
    }
    if meta.mode() & 0o022 != 0 {
        return Err(refuse(format!(
            "{} can be written by other users",
            dir.display()
        )));
    }
    Ok(())
}

/// The socket's own directory: created if missing, never a symlink, owned by
/// `uid`; then tightened to 0700.
pub fn prepare_socket_dir(dir: &Path, uid: u32) -> io::Result<()> {
    match std::fs::symlink_metadata(dir) {
        Ok(meta) => {
            if meta.file_type().is_symlink() {
                return Err(refuse(format!(
                    "{} is a symlink; refusing to put the socket there",
                    dir.display()
                )));
            }
            if !meta.is_dir() {
                return Err(refuse(format!("{} is not a directory", dir.display())));
            }
            if meta.uid() != uid {
                return Err(refuse(format!(
                    "{} is owned by another user",
                    dir.display()
                )));
            }
            if meta.mode() & 0o022 != 0 {
                // Others could already have planted entries in it.
                return Err(refuse(format!(
                    "{} can be written by other users; refusing to use it (make it private with `chmod 700` after checking its contents)",
                    dir.display()
                )));
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            if let Some(parent) = dir.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::create_dir(dir).map_err(|error| {
                io::Error::new(
                    error.kind(),
                    format!("could not create {}: {error}", dir.display()),
                )
            })?;
        }
        Err(error) => return Err(error),
    }
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
}

/// The user id of the process listening on the other end of `stream`.
pub fn peer_uid(stream: &UnixStream) -> io::Result<u32> {
    #[cfg(target_os = "linux")]
    {
        let mut cred = libc::ucred {
            pid: 0,
            uid: 0,
            gid: 0,
        };
        let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        let rc = unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                (&mut cred as *mut libc::ucred).cast(),
                &mut len,
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(cred.uid)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let (mut uid, mut gid) = (0 as libc::uid_t, 0 as libc::gid_t);
        if unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(uid)
    }
}

/// The owner of process `pid` (Linux; `None` elsewhere or when gone).
pub fn process_uid(pid: u32) -> Option<u32> {
    #[cfg(target_os = "linux")]
    {
        std::fs::metadata(format!("/proc/{pid}"))
            .ok()
            .map(|meta| meta.uid())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = pid;
        None
    }
}

/// An exclusive `flock` on a lock file holding the owner's pid. Released when
/// dropped or the process exits.
#[derive(Debug)]
pub struct HeldLock {
    file: std::fs::File,
}

impl HeldLock {
    /// Takes the pid out of the lock file (a clean exit), keeping the lock.
    pub fn clear_pid(&self) -> io::Result<()> {
        self.file.set_len(0)
    }

    /// The locked file itself; the lock lasts as long as it lives.
    pub fn into_file(self) -> std::fs::File {
        self.file
    }
}

/// Tries once, without waiting, to take an exclusive lock on `path` (created
/// 0600, never through a symlink, its directory created if missing) and writes
/// this process's pid into it. `None`: another process holds it.
pub fn lock_exclusive_with_pid(path: &Path) -> io::Result<Option<HeldLock>> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|error| {
            io::Error::new(
                error.kind(),
                format!(
                    "could not open {} (a symlink there is refused): {error}",
                    path.display()
                ),
            )
        })?;
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::EWOULDBLOCK) {
            return Ok(None);
        }
        return Err(io::Error::new(
            error.kind(),
            format!("could not lock {}: {error}", path.display()),
        ));
    }
    file.set_len(0)?;
    file.write_all(format!("{}\n", std::process::id()).as_bytes())?;
    Ok(Some(HeldLock { file }))
}

/// Whether some process holds the lock on `path` (`None` when that can't be
/// told). A shared, non-blocking try: it never waits.
pub fn lock_is_held(path: &Path) -> Option<bool> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .ok()?;
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_SH | libc::LOCK_NB) } == 0 {
        unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_UN) };
        return Some(false);
    }
    (io::Error::last_os_error().raw_os_error() == Some(libc::EWOULDBLOCK)).then_some(true)
}

/// The pid recorded in a lock file (it survives the process, so it may name
/// an unrelated one; see `confirmed_atem_pid`).
pub fn read_lock_pid(path: &Path) -> Option<u32> {
    let pid: u32 = std::fs::read_to_string(path).ok()?.trim().parse().ok()?;
    (pid != 0).then_some(pid)
}

/// Whether `pid` is a live process of this user running atem with
/// `subcommand` as an argument. Linux: read from its command line; elsewhere
/// nothing can be confirmed.
pub fn confirmed_atem_pid(pid: u32, subcommand: &str) -> bool {
    if pid == 0 || unsafe { libc::kill(pid as libc::pid_t, 0) } != 0 {
        return false;
    }
    #[cfg(target_os = "linux")]
    {
        let own = unsafe { libc::getuid() };
        if process_uid(pid) != Some(own) {
            return false;
        }
        let Ok(cmdline) = std::fs::read(format!("/proc/{pid}/cmdline")) else {
            return false;
        };
        let mut args = cmdline.split(|byte| *byte == 0);
        let Some(program) = args.next() else {
            return false;
        };
        let program = Path::new(std::ffi::OsStr::new(
            std::str::from_utf8(program).unwrap_or(""),
        ));
        program
            .file_name()
            .is_some_and(|name| name.to_string_lossy().starts_with("atem"))
            && args.any(|arg| arg == subcommand.as_bytes())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = subcommand;
        false
    }
}

/// Starts `exe subcommand` detached from this command and its terminal (new
/// session, working directory `cwd`, stdin null, stdout and stderr appended to
/// `log`, 0600), with `envs` added to its environment. Returns its pid.
pub fn spawn_detached(
    exe: &Path,
    subcommand: &str,
    cwd: &Path,
    log: &Path,
    envs: &[(OsString, OsString)],
) -> io::Result<u32> {
    spawn(exe, &[subcommand.as_ref()], cwd, log, envs, false)
}

/// `spawn_detached` with several arguments (`worker --state … --session …`).
pub fn spawn_detached_args(
    exe: &Path,
    args: &[&std::ffi::OsStr],
    cwd: &Path,
    log: &Path,
    envs: &[(OsString, OsString)],
) -> io::Result<u32> {
    spawn(exe, args, cwd, log, envs, false)
}

/// `spawn_detached` with exactly `envs` as the environment (nothing inherited).
pub fn spawn_detached_clean(
    exe: &Path,
    subcommand: &str,
    cwd: &Path,
    log: &Path,
    envs: &[(OsString, OsString)],
) -> io::Result<u32> {
    spawn(exe, &[subcommand.as_ref()], cwd, log, envs, true)
}

fn spawn(
    exe: &Path,
    args: &[&std::ffi::OsStr],
    cwd: &Path,
    log: &Path,
    envs: &[(OsString, OsString)],
    clear_env: bool,
) -> io::Result<u32> {
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::process::CommandExt;
    if let Some(dir) = log.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let log_file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(log)?;
    // `mode` only applies to a new file; tighten one that already existed.
    log_file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    let cwd = std::ffi::CString::new(cwd.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "cwd contains a NUL byte"))?;
    let mut command = std::process::Command::new(exe);
    if clear_env {
        command.env_clear();
    }
    command
        .args(args)
        .envs(envs.iter().map(|(key, value)| (key, value)))
        .stdin(std::process::Stdio::null())
        .stdout(log_file.try_clone()?)
        .stderr(log_file);
    let detach = move || -> io::Result<()> {
        if unsafe { libc::setsid() } == -1 {
            return Err(io::Error::last_os_error());
        }
        // Don't pin the directory the command was run from.
        if unsafe { libc::chdir(cwd.as_ptr()) } == -1 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    };
    // SAFETY: setsid and chdir are async-signal-safe, as pre_exec requires.
    unsafe {
        command.pre_exec(detach);
    }
    let mut child = command.spawn()?;
    let pid = child.id();
    // Reap the daemon if it exits while this process is still running.
    std::thread::spawn(move || {
        let _ = child.wait();
    });
    Ok(pid)
}

/// Listens on `socket` (its directory must be prepared): a socket file nobody
/// answers on is left by a daemon that died and is replaced; one that answers
/// is `AddrInUse`, and anything else at that path is refused and left alone.
/// The socket is made 0600.
pub fn listen_replacing_dead(socket: &Path) -> io::Result<tokio::net::UnixListener> {
    match std::fs::symlink_metadata(socket) {
        Ok(meta) => {
            if !meta.file_type().is_socket() {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    format!(
                        "{} exists and is not a socket; refusing to replace it",
                        socket.display()
                    ),
                ));
            }
            if UnixStream::connect(socket).is_ok() {
                return Err(io::Error::new(
                    io::ErrorKind::AddrInUse,
                    format!("something already answers on {}", socket.display()),
                ));
            }
            std::fs::remove_file(socket)?;
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let listener = tokio::net::UnixListener::bind(socket).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("could not listen on {}: {error}", socket.display()),
        )
    })?;
    std::fs::set_permissions(socket, std::fs::Permissions::from_mode(0o600))?;
    Ok(listener)
}

/// Lock files of daemons this process serves; held until it exits.
static HELD: Mutex<Vec<HeldLock>> = Mutex::new(Vec::new());

/// Takes the daemon's lock (`AddrInUse` when held elsewhere), prepares the
/// socket directory, listens (replacing a dead socket, 0600) and records the
/// socket path in `files.record` (0600). The lock stays held for the life of
/// the process. Must run inside a tokio runtime.
pub fn bind_socket(files: &DaemonFiles, uid: u32) -> io::Result<tokio::net::UnixListener> {
    let dir = files.socket.parent().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "socket path has no directory")
    })?;
    prepare_socket_dir(dir, uid)?;
    let Some(lock) = lock_exclusive_with_pid(&files.lock)? else {
        return Err(io::Error::new(
            io::ErrorKind::AddrInUse,
            format!("another daemon holds {}", files.lock.display()),
        ));
    };
    let listener = listen_replacing_dead(&files.socket)?;
    write_private(&files.record, files.socket.as_os_str().as_encoded_bytes())?;
    if let Ok(mut held) = HELD.lock() {
        held.push(lock);
    }
    Ok(listener)
}

/// A clean exit: takes this process's pid out of the lock files it holds
/// (the locks stay held until it exits).
pub fn clear_held_pids() {
    if let Ok(held) = HELD.lock() {
        for lock in held.iter() {
            let _ = lock.clear_pid();
        }
    }
}

/// The socket path `record` names, if it names an absolute one.
pub fn recorded_socket(record: &Path) -> Option<PathBuf> {
    use std::os::unix::ffi::OsStrExt;
    let bytes = std::fs::read(record).ok()?;
    let path = PathBuf::from(std::ffi::OsStr::from_bytes(&bytes));
    path.is_absolute().then_some(path)
}

/// Removes this daemon's socket and, when it still names that socket, its record.
pub fn remove_socket(files: &DaemonFiles) {
    if recorded_socket(&files.record).as_deref() == Some(files.socket.as_path()) {
        let _ = std::fs::remove_file(&files.record);
    }
    if std::fs::symlink_metadata(&files.socket).is_ok_and(|meta| meta.file_type().is_socket()) {
        let _ = std::fs::remove_file(&files.socket);
    }
}

/// Writes `bytes` to `path` through a private temporary file and a rename.
fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let tmp = path.with_extension(format!("tmp{}", std::process::id()));
    let result = (|| {
        let mut file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        std::fs::rename(&tmp, path)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Unix socket paths are limited to ~100 bytes; keep them short.
    fn short_dir() -> tempfile::TempDir {
        tempfile::Builder::new()
            .prefix("atem-dm")
            .tempdir_in("/tmp")
            .unwrap()
    }

    fn own_uid() -> u32 {
        unsafe { libc::getuid() }
    }

    #[test]
    fn names_follow_the_daemon() {
        let dir = short_dir();
        let config = dir.path().join("config");
        let runtime = dir.path().join("run");
        std::fs::create_dir_all(&runtime).unwrap();
        std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o700)).unwrap();
        let files = DaemonFiles::for_name(&config, Some(runtime.as_os_str().to_owned()), "runtime");
        assert_eq!(files.socket, runtime.join("atem").join("runtime.sock"));
        assert_eq!(files.lock, runtime.join("atem").join("runtime.lock"));
        assert_eq!(files.record, runtime.join("atem").join("runtime.socket"));
        assert_eq!(files.log, config.join("runtime.log"));
        // Unset, relative or unsafe runtime dirs fall back to the config dir.
        let open = dir.path().join("open");
        std::fs::create_dir_all(&open).unwrap();
        std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o777)).unwrap();
        for runtime in [
            None,
            Some(OsString::from("rel")),
            Some(open.into_os_string()),
        ] {
            let files = DaemonFiles::for_name(&config, runtime, "runtime");
            assert_eq!(files.socket, config.join("runtime.sock"));
            assert_eq!(files.lock, config.join("runtime.lock"));
        }
    }

    #[test]
    fn socket_directories_must_be_private_and_ours() {
        let dir = short_dir();
        let open = dir.path().join("open");
        let private = dir.path().join("private");
        for (path, mode) in [(&open, 0o777), (&private, 0o700)] {
            std::fs::create_dir_all(path).unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
        }
        let uid = own_uid();
        assert!(check_parent_dir(&private, uid).is_ok());
        assert!(
            check_parent_dir(&open, uid)
                .unwrap_err()
                .to_string()
                .contains("written")
        );
        assert!(
            check_parent_dir(&private, uid + 1)
                .unwrap_err()
                .to_string()
                .contains("another user")
        );
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&private, &link).unwrap();
        assert!(
            check_parent_dir(&link, uid)
                .unwrap_err()
                .to_string()
                .contains("symlink")
        );
        assert!(check_parent_dir(&dir.path().join("missing"), uid).is_err());
        assert!(
            prepare_socket_dir(&private, uid + 1)
                .unwrap_err()
                .to_string()
                .contains("another user")
        );
        assert!(prepare_socket_dir(&link, uid).is_err());
        // A missing directory is created private.
        let fresh = dir.path().join("fresh");
        prepare_socket_dir(&fresh, uid).unwrap();
        assert_eq!(std::fs::metadata(&fresh).unwrap().mode() & 0o777, 0o700);
    }

    #[test]
    fn peer_uid_is_ours() {
        let (a, _b) = UnixStream::pair().unwrap();
        assert_eq!(peer_uid(&a).unwrap(), own_uid());
    }

    #[test]
    fn lock_is_exclusive_and_records_the_pid() {
        let dir = short_dir();
        let path = dir.path().join("sub").join("d.lock");
        let held = lock_exclusive_with_pid(&path).unwrap().unwrap();
        assert_eq!(read_lock_pid(&path), Some(std::process::id()));
        assert_eq!(lock_is_held(&path), Some(true));
        assert!(lock_exclusive_with_pid(&path).unwrap().is_none());
        held.clear_pid().unwrap();
        assert_eq!(read_lock_pid(&path), None);
        drop(held);
        // Another test thread may fork between our open and its exec; the child
        // briefly shares our open file description (and its flock) until exec
        // closes it (O_CLOEXEC). Wait for that window to pass.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while lock_is_held(&path) != Some(false) && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert_eq!(lock_is_held(&path), Some(false));
        assert!(lock_exclusive_with_pid(&path).unwrap().is_some());
        let link = dir.path().join("link.lock");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(lock_exclusive_with_pid(&link).is_err());
    }

    #[test]
    fn pid_files_are_parsed_strictly() {
        let dir = short_dir();
        let path = dir.path().join("p");
        assert_eq!(read_lock_pid(&path), None);
        for (text, pid) in [("42\n", Some(42)), ("0\n", None), ("x", None), ("", None)] {
            std::fs::write(&path, text).unwrap();
            assert_eq!(read_lock_pid(&path), pid, "{text:?}");
        }
    }

    #[test]
    fn a_non_atem_pid_is_not_confirmed() {
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .unwrap();
        assert!(!confirmed_atem_pid(child.id(), "key-agent"));
        assert!(!confirmed_atem_pid(0, "key-agent"));
        let _ = child.kill();
        let _ = child.wait();
        assert!(!confirmed_atem_pid(child.id(), "key-agent"));
    }

    #[tokio::test]
    async fn bind_replaces_a_dead_socket_and_refuses_a_live_one() {
        let dir = short_dir();
        let run = dir.path().join("run");
        let files = DaemonFiles {
            socket: run.join("d.sock"),
            lock: run.join("d.lock"),
            record: run.join("d.socket"),
            log: dir.path().join("d.log"),
        };
        // A leftover socket nobody answers on.
        std::fs::create_dir_all(&run).unwrap();
        std::fs::set_permissions(&run, std::fs::Permissions::from_mode(0o700)).unwrap();
        drop(std::os::unix::net::UnixListener::bind(&files.socket).unwrap());
        let listener = bind_socket(&files, own_uid()).unwrap();
        assert_eq!(
            std::fs::metadata(&files.socket).unwrap().mode() & 0o777,
            0o600
        );
        assert_eq!(
            std::fs::read(&files.record).unwrap(),
            files.socket.as_os_str().as_encoded_bytes()
        );
        assert_eq!(
            std::fs::metadata(&files.record).unwrap().mode() & 0o777,
            0o600
        );
        assert_eq!(read_lock_pid(&files.lock), Some(std::process::id()));
        // The lock is held for the life of the process: a second bind is refused.
        let error = bind_socket(&files, own_uid()).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::AddrInUse);
        // A live socket is never replaced, nor is a non-socket.
        let error = listen_replacing_dead(&files.socket).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::AddrInUse);
        let plain = run.join("plain");
        std::fs::write(&plain, "x").unwrap();
        assert!(listen_replacing_dead(&plain).is_err());
        assert!(plain.exists());
        drop(listener);
    }

    #[test]
    fn spawn_detached_logs_privately_in_its_own_session() {
        let dir = short_dir();
        let log = dir.path().join("logs").join("d.log");
        // `sh <subcommand>` runs the named script file: write one.
        let script = dir.path().join("script.sh");
        // It stays alive (its log written) until the test has read its
        // session: `getsid` of a reaped pid would fail. (`ps -o sid` is
        // Linux-only: macOS `ps` has no such keyword.)
        let gate = dir.path().join("gate");
        std::fs::write(
            &script,
            format!(
                "pwd; echo \"$MARK\"; echo $$; while [ ! -e '{}' ]; do sleep 0.05; done\n",
                gate.display()
            ),
        )
        .unwrap();
        let pid = spawn_detached(
            Path::new("/bin/sh"),
            script.to_str().unwrap(),
            Path::new("/"),
            &log,
            &[(OsString::from("MARK"), OsString::from("hello"))],
        )
        .unwrap();
        assert!(pid > 0);
        let mut text = String::new();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while text.lines().count() < 3 && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(20));
            text = std::fs::read_to_string(&log).unwrap_or_default();
        }
        // A new session: its id is its own pid, not ours (and it leads its
        // own process group).
        let sid = unsafe { libc::getsid(pid as libc::pid_t) };
        let pgid = unsafe { libc::getpgid(pid as libc::pid_t) };
        std::fs::write(&gate, "").unwrap();
        let lines: Vec<_> = text.lines().map(str::trim).collect();
        assert_eq!(lines, ["/", "hello", &pid.to_string()], "{text:?}");
        assert_eq!(sid, pid as libc::pid_t);
        assert_eq!(pgid, pid as libc::pid_t);
        assert_ne!(sid, unsafe { libc::getsid(0) });
        assert_eq!(std::fs::metadata(&log).unwrap().mode() & 0o777, 0o600);
    }
}
