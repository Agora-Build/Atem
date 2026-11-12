//! The OS readings of the delegated lifecycle's clock (host-work-v1 §11.6
//! "Clocks"; design I.6.5; owner decision 2026-11-10, Decisions 17 and 18 of
//! step 4): the wall clock, the boot-time counter, the boot it counts in, a
//! hash of this machine's identity, the time namespace's boot-time offset and
//! the OS's own report on whether its wall clock is synchronized. Readings
//! only: the rules that use them are the clock state's. Every reading is
//! taken afresh (only the Mach timebase, a constant, is kept), so a process
//! restored into another boot, machine or namespace reads where it now runs.
//!
//! The boot-time counter counts suspend and is never slewed or stepped:
//! - Linux: `CLOCK_MONOTONIC_RAW + (CLOCK_BOOTTIME − CLOCK_MONOTONIC)`, read
//!   consistently (`compose`);
//! - macOS: `mach_continuous_time`, scaled by the Mach timebase.

use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

/// One reading of the host's clocks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OsReading {
    /// The wall clock, in ms since the Unix epoch.
    pub wall_ms: u64,
    /// The boot-time counter, in ns. Meaningful within `boot_id` only.
    pub boot_ns: u64,
    /// The boot the counter was read in (`boot_session_id`).
    pub boot_id: String,
    /// `machine_identity()`.
    pub machine: [u8; 16],
    /// The time namespace's boot-time offset in ns, which `boot_ns`
    /// includes: 0 outside a namespace, and on macOS.
    pub timens_boot_ns: i64,
    /// The OS's report on its wall clock.
    pub synced: Synced,
}

/// Whether the OS reports its wall clock synchronized.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Synced {
    Yes,
    No,
    /// No report: macOS until `ntp_gettime` is confirmed as `timed`'s
    /// report (`macos_ntp_state`), or an `adjtimex` that failed.
    Unknown,
}

/// The host's clocks now. The boot id and the namespace offset are read
/// before the counter, the wall clock right after it, then the sync report.
pub fn read() -> OsReading {
    let boot_id = boot_session_id();
    let timens_boot_ns = timens_offsets().1;
    let boot_ns = boot_ns();
    let wall_ms = wall_ms();
    let synced = sync_report();
    OsReading {
        wall_ms,
        boot_ns,
        boot_id,
        machine: machine_identity(),
        timens_boot_ns,
        synced,
    }
}

fn wall_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|since| u64::try_from(since.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

// The boot-time counter.

/// Two suspend offsets more than this apart mean a resume fell between
/// them, or the thread was preempted that long: the whole read is retried.
#[cfg(any(target_os = "linux", test))]
pub(crate) const TOLERANCE_NS: u64 = 1_000_000;
/// Retries before the last read is taken as it is.
#[cfg(any(target_os = "linux", test))]
pub(crate) const MAX_RETRIES: u8 = 3;

/// The three Linux clocks the counter is composed of (injected in tests).
#[cfg(any(target_os = "linux", test))]
pub(crate) trait RawClocks {
    /// `CLOCK_MONOTONIC_RAW`, in ns: never slewed, stops in suspend.
    fn raw_ns(&self) -> u64;
    /// `CLOCK_MONOTONIC`, in ns.
    fn monotonic_ns(&self) -> u64;
    /// `CLOCK_BOOTTIME`, in ns: `CLOCK_MONOTONIC` plus the suspended time.
    fn boottime_ns(&self) -> u64;
}

/// `CLOCK_BOOTTIME − CLOCK_MONOTONIC`: the suspended time, which the kernel
/// measures at each resume and never slews (plus a time namespace's
/// boot-time offset minus its monotonic one). `CLOCK_MONOTONIC` is read
/// first, so the reads' own span adds to it and never takes from it.
#[cfg(any(target_os = "linux", test))]
fn suspend_offset(c: &impl RawClocks) -> i128 {
    let monotonic = c.monotonic_ns();
    let boottime = c.boottime_ns();
    i128::from(boottime) - i128::from(monotonic)
}

/// The boot-time counter in ns and the retries it took (§11.6): the suspend
/// offset is read before and after `CLOCK_MONOTONIC_RAW`, and a move of more
/// than `TOLERANCE_NS` between them retries the whole read. After
/// `MAX_RETRIES` the last raw reading plus the offset read after it is
/// taken: the suspended time only grows, so that is the counter at some
/// point of the read. The offset is signed: in a time namespace whose
/// monotonic offset is above its boot-time one it is negative, and adding
/// it cancels the monotonic offset the raw clock carries.
#[cfg(any(target_os = "linux", test))]
pub(crate) fn compose(c: &impl RawClocks) -> (u64 /* boot_ns */, u8 /* retries */) {
    let mut retries = 0;
    loop {
        let before = suspend_offset(c);
        let raw = c.raw_ns();
        let after = suspend_offset(c);
        if before.abs_diff(after) <= u128::from(TOLERANCE_NS) || retries == MAX_RETRIES {
            let ns = (i128::from(raw) + after).max(0);
            return (u64::try_from(ns).unwrap_or(u64::MAX), retries);
        }
        retries += 1;
    }
}

#[cfg(target_os = "linux")]
struct LinuxClocks;

#[cfg(target_os = "linux")]
impl RawClocks for LinuxClocks {
    fn raw_ns(&self) -> u64 {
        clock_ns(libc::CLOCK_MONOTONIC_RAW)
    }

    fn monotonic_ns(&self) -> u64 {
        clock_ns(libc::CLOCK_MONOTONIC)
    }

    fn boottime_ns(&self) -> u64 {
        clock_ns(libc::CLOCK_BOOTTIME)
    }
}

/// One clock in ns. These clocks exist on every kernel Atem runs on (2.6.39
/// and later), and a time namespace keeps them non-negative.
#[cfg(all(unix, not(target_os = "macos")))]
fn clock_ns(id: libc::clockid_t) -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `ts` is a valid timespec for the call to fill.
    unsafe { libc::clock_gettime(id, &mut ts) };
    u64::try_from(ts.tv_sec)
        .unwrap_or(0)
        .saturating_mul(1_000_000_000)
        .saturating_add(u64::try_from(ts.tv_nsec).unwrap_or(0))
}

#[cfg(target_os = "linux")]
fn boot_ns() -> u64 {
    compose(&LinuxClocks).0
}

#[cfg(target_os = "macos")]
fn boot_ns() -> u64 {
    continuous_ns()
}

/// Elsewhere no counter that counts suspend is known: `CLOCK_MONOTONIC`.
#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
fn boot_ns() -> u64 {
    clock_ns(libc::CLOCK_MONOTONIC)
}

#[cfg(target_os = "macos")]
#[repr(C)]
struct MachTimebaseInfo {
    numer: u32,
    denom: u32,
}

// libc lacks `mach_continuous_time`, and marks `mach_timebase_info`
// deprecated in favour of the mach2 crate: both from libSystem directly.
#[cfg(target_os = "macos")]
unsafe extern "C" {
    /// Mach time units since an arbitrary point, counting sleep (macOS
    /// 10.12+). That the point is the boot is checked by
    /// `continuous_time_counts_from_boot`.
    fn mach_continuous_time() -> u64;
    fn mach_timebase_info(info: *mut MachTimebaseInfo) -> libc::c_int;
}

/// `mach_continuous_time` in ns: units × numer / denom (1/1 on Intel,
/// 125/3 on Apple silicon), in 128 bits so nothing overflows.
#[cfg(target_os = "macos")]
fn continuous_ns() -> u64 {
    static TIMEBASE: std::sync::OnceLock<(u32, u32)> = std::sync::OnceLock::new();
    let &(numer, denom) = TIMEBASE.get_or_init(|| {
        let mut info = MachTimebaseInfo { numer: 0, denom: 0 };
        // SAFETY: `info` is a valid timebase for the call to fill.
        let rc = unsafe { mach_timebase_info(&mut info) };
        if rc == 0 && info.numer != 0 && info.denom != 0 {
            (info.numer, info.denom)
        } else {
            (1, 1)
        }
    });
    // SAFETY: no arguments; it reads the counter.
    let units = unsafe { mach_continuous_time() };
    let ns = u128::from(units) * u128::from(numer) / u128::from(denom);
    u64::try_from(ns).unwrap_or(u64::MAX)
}

// The boot id (Decision 18).

/// The prefix of the boot id made when the OS gives none.
pub(crate) const UNKNOWN_BOOT_PREFIX: &str = "unknown-";

/// This boot's id: Linux `/proc/sys/kernel/random/boot_id`, macOS
/// `kern.bootsessionuuid` (which a wall-clock step doesn't change, unlike
/// the `kern.boottime` R9.5's waits key on). Unreadable: an id made once per
/// process (`UNKNOWN_BOOT_PREFIX` and a UUID), which the clock state takes
/// for an unknown boot: no boot time crosses it, and it sets no mark.
pub fn boot_session_id() -> String {
    static UNKNOWN: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    os_boot_id().unwrap_or_else(|| {
        UNKNOWN
            .get_or_init(|| format!("{UNKNOWN_BOOT_PREFIX}{}", uuid::Uuid::new_v4()))
            .clone()
    })
}

#[cfg(target_os = "linux")]
fn os_boot_id() -> Option<String> {
    let text = std::fs::read_to_string("/proc/sys/kernel/random/boot_id").ok()?;
    let id = text.trim();
    (!id.is_empty()).then(|| id.to_string())
}

#[cfg(target_os = "macos")]
fn os_boot_id() -> Option<String> {
    let mut buf = [0u8; 128];
    let mut len = buf.len();
    // SAFETY: `buf` and `len` describe a valid buffer for the value.
    let rc = unsafe {
        libc::sysctlbyname(
            c"kern.bootsessionuuid".as_ptr(),
            buf.as_mut_ptr().cast(),
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    if rc != 0 {
        return None;
    }
    // A C string: up to its first NUL.
    let value = buf[..len.min(buf.len())].split(|&b| b == 0).next()?;
    let id = std::str::from_utf8(value).ok()?.trim();
    (!id.is_empty()).then(|| id.to_string())
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn os_boot_id() -> Option<String> {
    None
}

// The machine identity (Decision 17).

/// The label of the machine identity's hash.
const MACHINE_LABEL: &str = "atem-host-clock-machine-v1";

/// This machine, hashed: the first 16 bytes of
/// `SHA-256(enc(["atem-host-clock-machine-v1", id]))`, where `id` is Linux's
/// `/etc/machine-id` (else `/var/lib/dbus/machine-id`) or macOS's
/// `gethostuuid` (the hardware UUID as `ioreg` shows it, uppercase with
/// hyphens). Stored hashed, never raw: the raw id also keys the
/// machine-bound credentials (`machine_key.rs`). A machine with no id
/// readable gets the hash of the empty id.
pub fn machine_identity() -> [u8; 16] {
    machine_identity_of(machine_id().unwrap_or_default().as_bytes())
}

/// The identity of a machine with no id readable (the empty id's hash),
/// which the clock state takes for an unknown machine: no boot time crosses
/// a boot change on it.
pub(crate) fn unknown_machine() -> [u8; 16] {
    machine_identity_of(b"")
}

fn machine_identity_of(id: &[u8]) -> [u8; 16] {
    let digest = Sha256::digest(atem_client::encoding::enc(&[MACHINE_LABEL.as_bytes(), id]));
    let mut identity = [0u8; 16];
    identity.copy_from_slice(&digest[..16]);
    identity
}

/// An id file's text, trimmed: empty, or systemd's `uninitialized` (early
/// boot, before the id is set), is no id.
#[cfg(any(target_os = "linux", test))]
fn usable_machine_id(text: &str) -> Option<String> {
    let id = text.trim();
    (!id.is_empty() && id != "uninitialized").then(|| id.to_string())
}

#[cfg(target_os = "linux")]
fn machine_id() -> Option<String> {
    ["/etc/machine-id", "/var/lib/dbus/machine-id"]
        .iter()
        .find_map(|path| usable_machine_id(&std::fs::read_to_string(path).ok()?))
}

#[cfg(target_os = "macos")]
fn machine_id() -> Option<String> {
    let mut uuid = [0u8; 16];
    // At most 2 s (a zero timespec would wait indefinitely).
    let wait = libc::timespec {
        tv_sec: 2,
        tv_nsec: 0,
    };
    // SAFETY: `uuid` is the 16-byte `uuid_t` the call fills; `wait` is a
    // valid timespec.
    let rc = unsafe { libc::gethostuuid(uuid.as_mut_ptr(), &wait) };
    (rc == 0).then(|| {
        uuid::Uuid::from_bytes(uuid)
            .hyphenated()
            .to_string()
            .to_ascii_uppercase()
    })
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn machine_id() -> Option<String> {
    None
}

// The time namespace (Decision 17).

/// `/proc/self/timens_offsets` as `(monotonic, boottime)` in ns; (0, 0)
/// where the file is absent (no time namespaces, and macOS).
fn timens_offsets() -> (i64, i64) {
    if cfg!(target_os = "linux") {
        timens_offsets_at(std::path::Path::new("/proc/self/timens_offsets"))
    } else {
        (0, 0)
    }
}

fn timens_offsets_at(path: &std::path::Path) -> (i64, i64) {
    std::fs::read_to_string(path)
        .map(|text| parse_timens_offsets(&text))
        .unwrap_or((0, 0))
}

/// The offsets in the kernel's format, one clock a line: its name
/// (`monotonic`, `boottime`; or its id, 1 and 7, as written to the file),
/// seconds (signed) and nanoseconds. A line it can't read counts for nothing
/// (0), as an absent file does: the kernel writes this format, so only a
/// change to it could.
pub(crate) fn parse_timens_offsets(text: &str) -> (i64 /* monotonic */, i64 /* boottime */) {
    let (mut monotonic, mut boottime) = (0, 0);
    for line in text.lines() {
        let mut fields = line.split_whitespace();
        let (Some(clock), Some(secs), Some(nanos), None) =
            (fields.next(), fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        let (Ok(secs), Ok(nanos)) = (secs.parse::<i64>(), nanos.parse::<i64>()) else {
            continue;
        };
        let Some(ns) = secs
            .checked_mul(1_000_000_000)
            .and_then(|ns| ns.checked_add(nanos))
        else {
            continue;
        };
        match clock {
            "monotonic" | "1" => monotonic = ns,
            "boottime" | "7" => boottime = ns,
            _ => {}
        }
    }
    (monotonic, boottime)
}

// The sync report.

/// `adjtimex`'s "clock not synchronized" bit (the kernel's ABI; libc has it
/// for glibc only).
#[cfg(any(target_os = "linux", test))]
const STA_UNSYNC: libc::c_int = 0x0040;

/// Linux's report: `adjtimex` with `modes = 0` (a read, no privilege
/// needed), `Yes` when `STA_UNSYNC` is clear. In a container it is the host
/// kernel's state, which is the right answer.
#[cfg(target_os = "linux")]
fn sync_report() -> Synced {
    synced_from(adjtimex_status())
}

/// macOS: `Unknown` until the real-OS check confirms `ntp_gettime` as
/// `timed`'s report (`macos_ntp_state`); elsewhere none is known.
#[cfg(not(target_os = "linux"))]
fn sync_report() -> Synced {
    Synced::Unknown
}

#[cfg(any(target_os = "linux", test))]
fn synced_from(status: Option<libc::c_int>) -> Synced {
    match status {
        Some(status) if status & STA_UNSYNC == 0 => Synced::Yes,
        Some(_) => Synced::No,
        None => Synced::Unknown,
    }
}

/// `adjtimex`'s status bits, read without changing anything.
#[cfg(target_os = "linux")]
fn adjtimex_status() -> Option<libc::c_int> {
    // SAFETY: an all-zero `timex` is a valid value; `modes = 0` only reads.
    let mut tx: libc::timex = unsafe { std::mem::zeroed() };
    tx.modes = 0;
    // SAFETY: `tx` is a valid timex for the call to fill.
    let rc = unsafe { libc::adjtimex(&mut tx) };
    (rc >= 0).then_some(tx.status)
}

/// `ntp_gettime` as `<sys/timex.h>` declares it.
#[cfg(target_os = "macos")]
type NtpGettime = unsafe extern "C" fn(*mut libc::ntptimeval) -> libc::c_int;

/// libSystem's `ntp_gettime`, looked up at run time: it is macOS 10.13+
/// (the 10.12 SDK has no `<sys/timex.h>`), and Atem runs on 10.12, where a
/// linked reference could keep the whole binary from loading. `None` where
/// the symbol is absent.
#[cfg(target_os = "macos")]
fn ntp_gettime_symbol() -> Option<NtpGettime> {
    // SAFETY: a lookup in the loaded images by a NUL-terminated name.
    let symbol = unsafe { libc::dlsym(libc::RTLD_DEFAULT, c"ntp_gettime".as_ptr()) };
    if symbol.is_null() {
        return None;
    }
    // SAFETY: the symbol is libSystem's `ntp_gettime`, whose C signature is
    // `NtpGettime`'s.
    Some(unsafe { std::mem::transmute::<*mut libc::c_void, NtpGettime>(symbol) })
}

/// macOS's `ntp_gettime` clock state (`TIME_OK` 0 … `TIME_ERROR` 5), for
/// the real-OS check that confirms or refutes it as `timed`'s report; `None`
/// when it can't be read (no `ntp_gettime` before macOS 10.13), and off
/// macOS. xnu returns the state as the call's own result, so every state
/// but `TIME_OK` comes back as -1 with the state in `errno`; the structure
/// holds it either way.
#[cfg(target_os = "macos")]
pub fn macos_ntp_state() -> Option<i32> {
    let ntp_gettime = ntp_gettime_symbol()?;
    // SAFETY: an all-zero `ntptimeval` is a valid value.
    let mut ntv: libc::ntptimeval = unsafe { std::mem::zeroed() };
    ntv.time_state = -1;
    // SAFETY: `ntv` is a valid ntptimeval for the call to fill.
    unsafe { ntp_gettime(&mut ntv) };
    (libc::TIME_OK..=libc::TIME_ERROR)
        .contains(&ntv.time_state)
        .then_some(ntv.time_state)
}

#[cfg(not(target_os = "macos"))]
pub fn macos_ntp_state() -> Option<i32> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    use std::cell::RefCell;
    use std::collections::VecDeque;

    const SEC: u64 = 1_000_000_000;
    /// Three hours asleep so far.
    const ASLEEP: u64 = 3 * 3600 * SEC;

    /// Clocks that answer from scripts: each read takes its clock's next
    /// value, so the test says what every read returns.
    struct Scripted {
        raw: RefCell<VecDeque<u64>>,
        monotonic: RefCell<VecDeque<u64>>,
        boottime: RefCell<VecDeque<u64>>,
    }

    impl Scripted {
        fn new(raw: &[u64], monotonic: &[u64], boottime: &[u64]) -> Self {
            Scripted {
                raw: RefCell::new(raw.iter().copied().collect()),
                monotonic: RefCell::new(monotonic.iter().copied().collect()),
                boottime: RefCell::new(boottime.iter().copied().collect()),
            }
        }

        /// Every scripted value was read, and no more.
        fn drained(&self) -> bool {
            self.raw.borrow().is_empty()
                && self.monotonic.borrow().is_empty()
                && self.boottime.borrow().is_empty()
        }
    }

    impl RawClocks for Scripted {
        fn raw_ns(&self) -> u64 {
            self.raw
                .borrow_mut()
                .pop_front()
                .expect("a raw read too many")
        }

        fn monotonic_ns(&self) -> u64 {
            self.monotonic
                .borrow_mut()
                .pop_front()
                .expect("a monotonic read too many")
        }

        fn boottime_ns(&self) -> u64 {
            self.boottime
                .borrow_mut()
                .pop_front()
                .expect("a boottime read too many")
        }
    }

    #[test]
    fn compose_adds_the_suspend_offset_to_the_raw_counter() {
        // Three hours asleep before and after the raw read; the difference
        // moves by its reads' own span (40 ns), and the one read after the
        // raw counter is taken.
        let mono = 100 * SEC;
        let clocks = Scripted::new(
            &[90 * SEC],
            &[mono, mono + 1_000],
            &[mono + ASLEEP + 20, mono + 1_000 + ASLEEP + 60],
        );
        assert_eq!(compose(&clocks), (90 * SEC + ASLEEP + 60, 0));
        assert!(clocks.drained(), "the offset, the raw counter, the offset");

        // Never asleep: the raw counter itself.
        let clocks = Scripted::new(&[90 * SEC], &[mono, mono + 10], &[mono, mono + 10]);
        assert_eq!(compose(&clocks), (90 * SEC, 0));

        // A time namespace whose monotonic offset (1 day) is above its
        // boot-time offset (0) makes the difference negative; it is added
        // as it is, which cancels the monotonic offset in the raw counter.
        let day = 86_400 * SEC;
        let clocks = Scripted::new(
            &[day + 90 * SEC],
            &[day + mono, day + mono],
            &[mono + ASLEEP, mono + ASLEEP],
        );
        assert_eq!(compose(&clocks), (90 * SEC + ASLEEP, 0));
    }

    #[test]
    fn compose_retries_when_the_offset_moves_more_than_1ms() {
        assert_eq!(TOLERANCE_NS, 1_000_000);
        // A resume between the first two offset reads moves it by 5 s: the
        // whole read is taken again, and the second one is consistent.
        let clocks = Scripted::new(
            &[90 * SEC, 91 * SEC],
            &[100 * SEC, 101 * SEC, 102 * SEC, 103 * SEC],
            &[
                100 * SEC + ASLEEP,
                101 * SEC + ASLEEP + 5 * SEC,
                102 * SEC + ASLEEP + 5 * SEC,
                103 * SEC + ASLEEP + 5 * SEC + 300,
            ],
        );
        assert_eq!(compose(&clocks), (91 * SEC + ASLEEP + 5 * SEC + 300, 1));
        assert!(clocks.drained(), "two whole reads");

        // A move of exactly 1 ms is within the tolerance; 1 ms and 1 ns is
        // more (a preempted read, or a short suspend).
        let moved_by = |moved: u64| {
            Scripted::new(
                &[90 * SEC, 91 * SEC],
                &[100 * SEC, 100 * SEC, 101 * SEC, 101 * SEC],
                &[
                    100 * SEC + ASLEEP,
                    100 * SEC + ASLEEP + moved,
                    101 * SEC + ASLEEP + moved,
                    101 * SEC + ASLEEP + moved,
                ],
            )
        };
        assert_eq!(
            compose(&moved_by(TOLERANCE_NS)),
            (90 * SEC + ASLEEP + TOLERANCE_NS, 0)
        );
        assert_eq!(
            compose(&moved_by(TOLERANCE_NS + 1)),
            (91 * SEC + ASLEEP + TOLERANCE_NS + 1, 1)
        );
    }

    #[test]
    fn compose_after_3_retries_takes_the_last_raw_plus_the_offset_after_it() {
        assert_eq!(MAX_RETRIES, 3);
        // A machine suspending and resuming again and again: each offset
        // read is 2 s past the one before.
        let raw: Vec<u64> = (0..4).map(|i| (90 + i) * SEC).collect();
        let mono: Vec<u64> = (0..8).map(|k| (100 + k) * SEC).collect();
        let boot: Vec<u64> = (0..8)
            .map(|k| (100 + k) * SEC + ASLEEP + 2 * k * SEC)
            .collect();
        let clocks = Scripted::new(&raw, &mono, &boot);
        // The first read and 3 retries; then the last raw counter (93 s)
        // plus the offset read after it (the eighth: 14 s more asleep).
        assert_eq!(
            compose(&clocks),
            (93 * SEC + ASLEEP + 14 * SEC, MAX_RETRIES)
        );
        assert!(clocks.drained(), "four reads, no fifth");
    }

    #[test]
    fn timens_offsets_parse() {
        // The kernel's own format: name, seconds, nanoseconds.
        let text = "monotonic           0         0\nboottime        86400         0\n";
        assert_eq!(parse_timens_offsets(text), (0, 86_400 * SEC as i64));
        // A normalized timespec: -2 s and 0.5 s is -1.5 s.
        let text = "monotonic          -2 500000000\nboottime            1         5\n";
        assert_eq!(parse_timens_offsets(text), (-1_500_000_000, 1_000_000_005));
        // Clock ids as numbers (1 monotonic, 7 boottime), either order.
        assert_eq!(
            parse_timens_offsets("7 3 0\n1 -4 0\n"),
            (-4 * SEC as i64, 3 * SEC as i64)
        );
        // Lines it can't read count for nothing.
        assert_eq!(
            parse_timens_offsets("boottime x 0\nunknown 5 0\nboottime 2\nboottime 1 2 3\n"),
            (0, 0)
        );
    }

    #[test]
    fn timens_offsets_absent_is_zero() {
        assert_eq!(parse_timens_offsets(""), (0, 0));
        let missing = std::env::temp_dir()
            .join(format!("atem-no-timens-{}", uuid::Uuid::new_v4()))
            .join("timens_offsets");
        assert_eq!(timens_offsets_at(&missing), (0, 0));
    }

    #[test]
    fn machine_identity_is_a_domain_separated_hash() {
        assert_eq!(MACHINE_LABEL, "atem-host-clock-machine-v1");
        let id = b"0123456789abcdef0123456789abcdef";
        let digest = Sha256::digest(atem_client::encoding::enc(&[
            b"atem-host-clock-machine-v1",
            id,
        ]));
        assert_eq!(machine_identity_of(id)[..], digest[..16]);
        // Known answer, computed outside Atem.
        assert_eq!(
            atem_client::encoding::hex(&machine_identity_of(id)),
            "a436b4554e2286f9e5f543b1ff75f93b"
        );
        // Never the id's own hash, and one byte changes it.
        assert_ne!(machine_identity_of(id)[..], Sha256::digest(id)[..16]);
        assert_ne!(
            machine_identity_of(id),
            machine_identity_of(b"0123456789abcdef0123456789abcdee")
        );
        // The id file's text, trimmed; empty or not yet set is no id.
        assert_eq!(
            usable_machine_id("0123456789abcdef0123456789abcdef\n").as_deref(),
            Some("0123456789abcdef0123456789abcdef")
        );
        assert_eq!(usable_machine_id(" \n"), None);
        assert_eq!(usable_machine_id("uninitialized\n"), None);
    }

    #[test]
    fn sync_report_reads_sta_unsync() {
        assert_eq!(STA_UNSYNC, 0x0040);
        assert_eq!(synced_from(Some(0x2001)), Synced::Yes); // PLL, nano
        assert_eq!(synced_from(Some(0x0041)), Synced::No);
        assert_eq!(synced_from(None), Synced::Unknown);
    }

    // The real OS (every CI job, release builds included).

    #[cfg(target_os = "linux")]
    #[test]
    fn real_boot_counter_is_monotonic_and_not_below_monotonic_raw() {
        // Outside a time namespace both offsets are 0; inside one, the raw
        // counter carries the monotonic offset and the composition the
        // boot-time one.
        let (ns_monotonic, ns_boottime) = timens_offsets();
        let shift = i128::from(ns_boottime) - i128::from(ns_monotonic);
        let clocks = LinuxClocks;
        let mut previous = 0;
        for _ in 0..10_000 {
            let raw = clocks.raw_ns();
            let (boot, retries) = compose(&clocks);
            assert!(
                i128::from(boot) >= i128::from(raw) + shift,
                "{boot} below the raw counter {raw}"
            );
            assert!(boot >= previous, "{boot} after {previous}");
            assert!(retries <= MAX_RETRIES);
            previous = boot;
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn suspend_offset_is_non_negative_and_non_decreasing() {
        let (ns_monotonic, ns_boottime) = timens_offsets();
        let shift = i128::from(ns_boottime) - i128::from(ns_monotonic);
        let clocks = LinuxClocks;
        // Each read brackets the suspended time at its boot-time read:
        // `boottime − the monotonic read after` ≤ it ≤ `boottime − the
        // monotonic read before` (the composition's own reading).
        let mut previous_low = i128::MIN;
        for _ in 0..10_000 {
            let before = i128::from(clocks.monotonic_ns());
            let boottime = i128::from(clocks.boottime_ns());
            let after = i128::from(clocks.monotonic_ns());
            let high = boottime - before - shift;
            let low = boottime - after - shift;
            assert!(high >= 0, "a negative suspended time: {high}");
            assert!(
                high >= previous_low,
                "the suspended time went down: {high} after at least {previous_low}"
            );
            previous_low = low;
        }
    }

    #[test]
    fn boot_session_id_is_stable_within_a_process() {
        let first = boot_session_id();
        assert!(!first.is_empty());
        assert!(!first.starts_with("unknown-"), "the OS's boot id: {first}");
        for _ in 0..100 {
            assert_eq!(boot_session_id(), first);
        }
        let other = std::thread::spawn(boot_session_id).join().unwrap();
        assert_eq!(other, first);
        #[cfg(target_os = "linux")]
        assert_eq!(
            first,
            std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
                .unwrap()
                .trim()
        );
        #[cfg(target_os = "macos")]
        assert!(
            uuid::Uuid::parse_str(&first).is_ok(),
            "kern.bootsessionuuid is a UUID: {first}"
        );
    }

    #[test]
    fn machine_identity_is_stable() {
        let first = machine_identity();
        for _ in 0..10 {
            assert_eq!(machine_identity(), first);
        }
        // This machine's own id, not the fallback.
        let id = machine_id().expect("this machine has an id");
        assert_eq!(first, machine_identity_of(id.as_bytes()));
        assert_ne!(first, machine_identity_of(b""));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn adjtimex_status_reads_without_privilege() {
        let status = adjtimex_status().expect("adjtimex with modes = 0 needs no privilege");
        assert_eq!(STA_UNSYNC, libc::STA_UNSYNC);
        eprintln!(
            "adjtimex: status {status:#06x}, euid {}, {:?}",
            // SAFETY: geteuid has no preconditions.
            unsafe { libc::geteuid() },
            synced_from(Some(status))
        );
        assert_ne!(sync_report(), Synced::Unknown);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn continuous_time_counts_from_boot() {
        let mut tv = libc::timeval {
            tv_sec: 0,
            tv_usec: 0,
        };
        let mut size = std::mem::size_of::<libc::timeval>();
        // SAFETY: `tv` and `size` describe a valid buffer for the value.
        let rc = unsafe {
            libc::sysctlbyname(
                c"kern.boottime".as_ptr(),
                (&mut tv as *mut libc::timeval).cast(),
                &mut size,
                std::ptr::null_mut(),
                0,
            )
        };
        assert_eq!(rc, 0, "kern.boottime");
        let booted_at = i128::from(tv.tv_sec) * i128::from(SEC) + i128::from(tv.tv_usec) * 1_000;
        let counter = i128::from(continuous_ns());
        let wall = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as i128;
        let since_boot = wall - booted_at;
        eprintln!(
            "mach_continuous_time {counter} ns, now − kern.boottime {since_boot} ns, gap {} ns",
            since_boot - counter
        );
        assert!(
            (since_boot - counter).abs() < 5 * i128::from(SEC),
            "mach_continuous_time ({counter} ns) doesn't count from boot ({since_boot} ns)"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn ntp_gettime_reports_a_state() {
        let state = macos_ntp_state().expect("ntp_gettime reports a state");
        let name = match state {
            libc::TIME_OK => "TIME_OK",
            libc::TIME_ERROR => "TIME_ERROR",
            _ => "another state",
        };
        eprintln!("ntp_gettime: {state} ({name})");
        assert!((libc::TIME_OK..=libc::TIME_ERROR).contains(&state));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn ntp_gettime_is_resolved_at_run_time_and_answers_on_a_current_macos() {
        // Looked up in the loaded images (macOS 10.13+), never linked, so a
        // 10.12 Mac still loads atem and gets `None` here.
        assert!(ntp_gettime_symbol().is_some(), "libSystem has ntp_gettime");
        for _ in 0..100 {
            assert!(macos_ntp_state().is_some());
        }
    }

    #[test]
    fn read_takes_every_field_from_this_host() {
        let first = read();
        eprintln!("{first:?}");
        assert!(first.wall_ms > 1_700_000_000_000, "a wall clock after 2023");
        assert!(first.boot_ns > 0);
        assert_eq!(first.boot_id, boot_session_id());
        assert_eq!(first.machine, machine_identity());
        let second = read();
        assert!(second.boot_ns >= first.boot_ns);
        #[cfg(target_os = "linux")]
        {
            assert_eq!(first.timens_boot_ns, timens_offsets().1);
            assert_ne!(first.synced, Synced::Unknown);
        }
        #[cfg(target_os = "macos")]
        {
            assert_eq!(first.timens_boot_ns, 0);
            // Until the real-OS check confirms `ntp_gettime` as timed's report.
            assert_eq!(first.synced, Synced::Unknown);
        }
    }
}
