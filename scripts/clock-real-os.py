#!/usr/bin/env python3
"""Real-OS clock checks on CI runners (delegated lifecycle, host-work-v1 §11.6).

Used by `.github/workflows/test.yml` (find-bin) and the manual
`.github/workflows/clock-real-os.yml` (the rest). Every reading comes from
Atem's own code: the ignored tests `real_os_report_linux` and
`real_os_report_macos` in `src/runtime/host_clock/os.rs` print one JSON line
(prefixed `ATEM_CLOCK_REPORT `) of what `os::read()` sees, and this script
only calls them and keeps their lines.

  find-bin BUILD_JSON
      Print the path of the `atem` bin's test binary from the output of
      `cargo test --bin atem --no-run --message-format=json`; fail unless
      there is exactly one.
  read --bin BIN
      Print one reading (the report test's JSON line), to show the test runs
      before anything steps a clock.
  linux-step-window --bin BIN --out FILE --ref FILE
      Step the wall clock forward, read at once (rule 4 expects STA_UNSYNC
      set), poll every 100 ms until it clears or 15 minutes pass, record the
      step window, step back, write a JSON artifact.
  macos-sync-report --bin BIN --out FILE --ref FILE
      Read `ntp_gettime` before and after a wall-clock step, resync with
      `sntp`, poll the state, write a JSON artifact.
  restore --ref FILE
      Put the wall clock back where the reference file says it should be
      (idempotent: nothing when it is already there). The workflow runs it in
      an `if: always()` step, so a crashed or cancelled run never leaves the
      runner's clock stepped.

The wall clock is stepped only on GitHub Actions (or under --dry-run, which
runs everything but `sudo date` and `sntp`): never run this on a machine
whose clock matters.
"""

import argparse
import datetime
import json
import os
import platform
import signal
import subprocess
import sys
import time

PREFIX = "ATEM_CLOCK_REPORT "
TESTS = {
    "Linux": "runtime::host_clock::os::tests::real_os_report_linux",
    "Darwin": "runtime::host_clock::os::tests::real_os_report_macos",
}
# The wall clock is put back to within this many seconds.
RESTORE_TOLERANCE_S = 1.5


def die(message):
    print(f"error: {message}", file=sys.stderr)
    sys.exit(1)


def utc_now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="milliseconds")


# The product's readings.


class ReportError(Exception):
    pass


def report(bin_path, timeout=30):
    """One reading: the JSON line of the ignored report test."""
    test = TESTS.get(platform.system())
    if test is None:
        raise ReportError(f"no report test for {platform.system()}")
    try:
        p = subprocess.run(
            [bin_path, "--exact", test, "--ignored", "--nocapture", "--test-threads=1"],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (OSError, subprocess.SubprocessError) as e:
        raise ReportError(str(e))
    # The harness prints `test <name> ... ` before the test runs, so the
    # report follows it on the same line.
    hits = [line[line.index(PREFIX) + len(PREFIX):] for line in p.stdout.splitlines() if PREFIX in line]
    if p.returncode != 0 or len(hits) != 1:
        raise ReportError(f"exit {p.returncode}, {len(hits)} report lines: {(p.stdout + p.stderr)[-500:]}")
    try:
        return json.loads(hits[0])
    except ValueError as e:
        raise ReportError(f"not JSON ({e}): {hits[0][:200]}")


# Running things, best effort.


def sh(cmd, timeout=30):
    shown = " ".join(cmd)
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError) as e:
        return {"cmd": shown, "error": str(e)}
    return {"cmd": shown, "rc": p.returncode, "out": (p.stdout + p.stderr).strip()[-2000:]}


def context():
    if platform.system() == "Linux":
        cmds = [
            ["uname", "-a"],
            ["sh", "-c", "grep PRETTY_NAME /etc/os-release"],
            ["timedatectl", "show"],
            ["systemctl", "is-active", "systemd-timesyncd", "chrony", "chronyd"],
            ["chronyc", "tracking"],
        ]
    else:
        cmds = [
            ["sw_vers"],
            ["uname", "-a"],
            ["sysctl", "kern.boottime", "kern.bootsessionuuid"],
            ["pgrep", "-lf", "timed"],
            ["sudo", "-n", "systemsetup", "-getusingnetworktime"],
            ["sudo", "-n", "systemsetup", "-getnetworktimeserver"],
        ]
    return [sh(c) for c in cmds]


# Stepping the wall clock, and putting it back.


def set_wall(epoch, dry_run):
    """Set the wall clock to `epoch` (Unix seconds): only on GitHub Actions."""
    if platform.system() == "Linux":
        cmd = ["sudo", "-n", "date", "-u", "-s", f"@{epoch:.6f}"]
    else:
        # BSD date: [[[mm]dd]HH]MM[[cc]yy][.ss], whole seconds.
        cmd = ["sudo", "-n", "date", "-u", time.strftime("%m%d%H%M%Y.%S", time.gmtime(round(epoch)))]
    shown = " ".join(cmd)
    if dry_run:
        print(f"dry run, would run: {shown}")
        return {"cmd": shown, "dry_run": True}
    if os.environ.get("GITHUB_ACTIONS") != "true":
        die("refusing to step this machine's clock outside GitHub Actions (use --dry-run)")
    result = sh(cmd)
    if result.get("rc") != 0:
        raise RuntimeError(f"the clock step failed: {result}")
    return result


def write_ref(path):
    """Where the wall clock should be, from now on: the monotonic clock
    (which no step moves) says how far it has run since."""
    ref = {"wall": time.time(), "mono": time.monotonic(), "utc": utc_now()}
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w") as f:
        json.dump(ref, f)
    return ref


def expected_wall(ref):
    return ref["wall"] + (time.monotonic() - ref["mono"])


def restore(ref_path, dry_run):
    """Step the wall clock back to the reference's trajectory when it is off."""
    if not os.path.exists(ref_path):
        return {"restored": False, "why": "no reference file: nothing was stepped"}
    with open(ref_path) as f:
        ref = json.load(f)
    skew = time.time() - expected_wall(ref)
    if abs(skew) <= RESTORE_TOLERANCE_S:
        return {"restored": False, "skew_s": skew}
    step = set_wall(expected_wall(ref), dry_run)
    return {
        "restored": not dry_run,
        "skew_before_s": skew,
        "skew_after_s": time.time() - expected_wall(ref),
        "step": step,
    }


# Output.


def write_json(path, value):
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    tmp = f"{path}.tmp"
    with open(tmp, "w") as f:
        json.dump(value, f, indent=2, sort_keys=True)
        f.write("\n")
    os.replace(tmp, path)


def summary(lines):
    text = "\n".join(lines)
    print(text)
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if path:
        with open(path, "a") as f:
            f.write(text + "\n")


def note_poll_error(out, error):
    samples = out.setdefault("poll_error_samples", [])
    if len(samples) < 20:
        samples.append(str(error)[:300])


def ns_to_s(ns):
    return None if ns is None else ns / 1e9


# find-bin.


def find_bin(args):
    exes = set()
    with open(args.build_json) as f:
        for line in f:
            try:
                m = json.loads(line)
            except ValueError:
                continue
            if m.get("reason") != "compiler-artifact":
                continue
            target = m.get("target", {})
            if "bin" in target.get("kind", []) and m.get("profile", {}).get("test") and m.get("executable"):
                if target.get("name") == "atem":
                    exes.add(m["executable"])
    if len(exes) != 1:
        die(f"expected one atem test binary in {args.build_json}, found {sorted(exes)}")
    exe = exes.pop()
    if not os.access(exe, os.X_OK):
        die(f"{exe} is not an executable")
    print(exe)


# linux-step-window.


def linux_step_window(args):
    if platform.system() != "Linux":
        die("this job measures the Linux kernel's STA_UNSYNC")
    out = {
        "job": "linux-step-window",
        "started_utc": utc_now(),
        "params": {
            "step_seconds": args.step_seconds,
            "poll_ms": args.poll_ms,
            "timeout_s": args.timeout_s,
            "dry_run": args.dry_run,
        },
    }
    failed = False
    write_ref(args.ref)
    try:
        out["context"] = context()
        before = out["before"] = report(args.bin)
        mono_step = time.monotonic()
        out["step_command"] = set_wall(time.time() + args.step_seconds, args.dry_run)
        mono_stepped = time.monotonic()
        # At once: rule 4 expects a step to set STA_UNSYNC.
        stepped = out["after_step"] = report(args.bin)
        out["step_command_s"] = mono_stepped - mono_step

        cleared = stepped["synced"] == "yes"
        latest = stepped
        polls = poll_errors = consecutive_errors = 0
        status = stepped.get("adjtimex_status")
        transitions = [{"after_s": 0.0, "adjtimex_status_hex": stepped.get("adjtimex_status_hex")}]
        deadline = mono_stepped + args.timeout_s
        mono_cleared = mono_stepped if cleared else None
        while not cleared and time.monotonic() < deadline:
            time.sleep(args.poll_ms / 1000)
            try:
                r = report(args.bin)
                consecutive_errors = 0
            except ReportError as e:
                poll_errors += 1
                consecutive_errors += 1
                note_poll_error(out, e)
                if consecutive_errors >= 50:
                    raise
                continue
            polls += 1
            latest = r
            if r.get("adjtimex_status") != status:
                status = r.get("adjtimex_status")
                transitions.append({
                    "after_s": ns_to_s(r["boot_ns"] - stepped["boot_ns"]),
                    "adjtimex_status_hex": r.get("adjtimex_status_hex"),
                })
            if r["synced"] == "yes":
                cleared, mono_cleared = True, time.monotonic()
        out["context_after"] = [
            sh(["timedatectl", "show", "-p", "NTP", "-p", "NTPSynchronized"]),
            sh(["chronyc", "tracking"]),
        ]
        out["last_reading"] = latest
        out["result"] = {
            "was_synced_before": before.get("sta_unsync") is False,
            "unsync_set_by_step": stepped.get("sta_unsync") is True,
            "cleared": cleared,
            # By the product's own raw counter (a step doesn't move it), from
            # the reading just after the step to the first one that reads
            # synchronized; the driver's monotonic clock agrees to a poll.
            "window_s": ns_to_s(latest["boot_ns"] - stepped["boot_ns"]) if cleared else None,
            "window_s_monotonic": mono_cleared - mono_stepped if cleared else None,
            "waited_s": time.monotonic() - mono_stepped,
            "timed_out": not cleared,
            "polls": polls,
            "poll_errors": poll_errors,
            "transitions": transitions,
        }
    except Exception as e:  # noqa: BLE001 - recorded, then the job fails
        failed = True
        out["error"] = f"{type(e).__name__}: {e}"
    finally:
        try:
            out["restore"] = restore(args.ref, args.dry_run)
        except Exception as e:  # noqa: BLE001
            failed = True
            out["restore"] = {"error": f"{type(e).__name__}: {e}"}
        try:
            out["after_restore"] = report(args.bin)
        except ReportError as e:
            out["after_restore"] = {"error": str(e)[:300]}
        out["finished_utc"] = utc_now()
        write_json(args.out, out)
    result = out.get("result")
    lines = ["### linux-step-window"]
    if result:
        lines += [
            f"- STA_UNSYNC was clear before the step: {result['was_synced_before']}",
            f"- the step set STA_UNSYNC at once (rule 4): {result['unsync_set_by_step']}",
            (
                f"- it cleared after {result['window_s']:.1f} s"
                if result["cleared"]
                else f"- it never cleared in {result['waited_s']:.0f} s"
            ),
        ]
    lines.append(f"- restore: {out.get('restore')}")
    if "error" in out:
        lines.append(f"- error: {out['error']}")
    summary(lines)
    if failed:
        sys.exit(1)


# macos-sync-report.

MAC_COLUMNS = [
    "t_s", "phase", "wall_ms", "synced", "ntp_state", "ntp_return", "ntp_errno",
    "kern_boottime_ns", "counter_gap_ns", "boot_ns",
]


def mac_row(t, phase, r):
    n = r.get("ntp_gettime") or {}
    return [
        round(t, 3), phase, r["wall_ms"], r["synced"], r.get("ntp_state"), n.get("return"), n.get("errno"),
        r.get("kern_boottime_ns"), r.get("counter_gap_ns"), r["boot_ns"],
    ]


def macos_sync_report(args):
    if platform.system() != "Darwin":
        die("this job reads macOS's ntp_gettime")
    out = {
        "job": "macos-sync-report",
        "started_utc": utc_now(),
        "params": {
            "step_seconds": args.step_seconds,
            "pre_sync_s": args.pre_sync_s,
            "duration_s": args.duration_s,
            "dry_run": args.dry_run,
        },
        "columns": MAC_COLUMNS,
    }
    rows = out["rows"] = []
    failed = False
    t0 = time.monotonic()
    write_ref(args.ref)

    def sample(phase):
        r = report(args.bin)
        rows.append(mac_row(time.monotonic() - t0, phase, r))
        return r

    def poll(phase, seconds):
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            time.sleep(args.poll_s)
            try:
                sample(phase)
            except ReportError as e:
                note_poll_error(out, e)

    try:
        out["context"] = context()
        before = out["before"] = sample("before")
        out["step_command"] = set_wall(time.time() + args.step_seconds, args.dry_run)
        stepped = out["after_step"] = sample("step")
        # `timed` alone, before anything asks for a resync.
        poll("pre_sync", args.pre_sync_s)
        if args.dry_run:
            print("dry run, would run: sudo -n sntp -sS time.apple.com")
            out["sntp"] = {"dry_run": True}
        else:
            out["sntp"] = sh(["sudo", "-n", "sntp", "-sS", "time.apple.com"], timeout=120)
        synced = out["after_sntp"] = sample("sntp")
        poll("post_sync", args.duration_s)

        states = [row[4] for row in rows]
        transitions = []
        for i in range(1, len(rows)):
            if rows[i][4] != rows[i - 1][4]:
                transitions.append({"t_s": rows[i][0], "phase": rows[i][1], "from": rows[i - 1][4], "to": rows[i][4]})
        kb = lambda r: r.get("kern_boottime_ns")  # noqa: E731
        out["result"] = {
            "ntp_state_before": before.get("ntp_state"),
            "ntp_state_after_step": stepped.get("ntp_state"),
            "ntp_state_after_sntp": synced.get("ntp_state"),
            "states_seen": sorted({s for s in states if s is not None}),
            "transitions": transitions,
            # Does `mach_continuous_time` count from boot (`kern.boottime`),
            # and does the step move `kern.boottime`?
            "counter_gap_ns_before": before.get("counter_gap_ns"),
            "counter_gap_ns_after_step": stepped.get("counter_gap_ns"),
            "kern_boottime_moved_by_step_ns": (
                kb(stepped) - kb(before) if kb(stepped) is not None and kb(before) is not None else None
            ),
            "sntp_rc": out["sntp"].get("rc"),
            "samples": len(rows),
        }
    except Exception as e:  # noqa: BLE001 - recorded, then the job fails
        failed = True
        out["error"] = f"{type(e).__name__}: {e}"
    finally:
        try:
            out["restore"] = restore(args.ref, args.dry_run)
        except Exception as e:  # noqa: BLE001
            failed = True
            out["restore"] = {"error": f"{type(e).__name__}: {e}"}
        out["finished_utc"] = utc_now()
        write_json(args.out, out)
    result = out.get("result")
    lines = ["### macos-sync-report"]
    if result:
        lines += [
            f"- ntp_gettime state: before {result['ntp_state_before']}, after the step "
            f"{result['ntp_state_after_step']}, after sntp {result['ntp_state_after_sntp']}",
            f"- states seen: {result['states_seen']}; transitions: {result['transitions']}",
            f"- mach_continuous_time vs kern.boottime gap (ns): before {result['counter_gap_ns_before']}, "
            f"after the step {result['counter_gap_ns_after_step']}",
            f"- sntp rc: {result['sntp_rc']}",
        ]
    lines.append(f"- restore: {out.get('restore')}")
    if "error" in out:
        lines.append(f"- error: {out['error']}")
    summary(lines)
    if failed:
        sys.exit(1)


# restore.


def read_command(args):
    print(json.dumps(report(args.bin), sort_keys=True))


def restore_command(args):
    result = restore(args.ref, args.dry_run)
    print(json.dumps(result, sort_keys=True))


def main():
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(143))  # run the `finally`s
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("find-bin")
    p.add_argument("build_json")
    p.set_defaults(run=find_bin)

    p = sub.add_parser("read")
    p.add_argument("--bin", required=True)
    p.set_defaults(run=read_command)

    def common(p):
        p.add_argument("--bin", required=True, help="the atem bin's test binary")
        p.add_argument("--out", required=True, help="the JSON artifact")
        p.add_argument("--ref", required=True, help="the reference file `restore` reads")
        p.add_argument("--dry-run", action="store_true", help="step no clock, run no sntp")

    p = sub.add_parser("linux-step-window")
    common(p)
    p.add_argument("--step-seconds", type=float, default=120)
    p.add_argument("--poll-ms", type=float, default=100)
    p.add_argument("--timeout-s", type=float, default=900)
    p.set_defaults(run=linux_step_window)

    p = sub.add_parser("macos-sync-report")
    common(p)
    p.add_argument("--step-seconds", type=float, default=60)
    p.add_argument("--pre-sync-s", type=float, default=30)
    p.add_argument("--duration-s", type=float, default=300)
    p.add_argument("--poll-s", type=float, default=1)
    p.set_defaults(run=macos_sync_report)

    p = sub.add_parser("restore")
    p.add_argument("--ref", required=True)
    p.add_argument("--dry-run", action="store_true")
    p.set_defaults(run=restore_command)

    args = parser.parse_args()
    args.run(args)


if __name__ == "__main__":
    main()
