//! `knsh-exec` against the real `sandbox-exec` on this machine (KNSH-046).
//!
//! Each test runs the built binary in a fresh temporary directory: a line under a profile that denies writes cannot
//! write; the line leads its own process group; only stdio and listed descriptors are inherited; and a profile that
//! `sandbox-exec` cannot apply never lets the line run.

#![cfg(target_os = "macos")]
// Setup helpers outside `#[test]` functions unwrap too: a failed setup is a failed test.
#![allow(clippy::unwrap_used)]

use std::ffi::c_int;
use std::fs;
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};

const EXEC: &str = env!("CARGO_BIN_EXE_knsh-exec");

/// `<sysexits.h>` codes the trampoline uses (`src/exit.rs`).
const USAGE: i32 = 64;
const PROFILE: i32 = 66;
/// `sandbox-exec`'s exit when it cannot read or compile the profile.
const SANDBOX_EXEC_BAD_PROFILE: i32 = 65;

/// A private temporary directory, removed on drop. Canonical, because Seatbelt matches real paths
/// (`/private/var/…`, not `/var/…`).
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("knsh-exec-it-{name}-{}-{n}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        Self(fs::canonicalize(&dir).unwrap())
    }

    /// Writes a `0600` profile file.
    fn profile(&self, name: &str, text: &str) -> PathBuf {
        let path = self.0.join(name);
        fs::write(&path, text).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        path
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn allow_all(scratch: &Scratch) -> PathBuf {
    scratch.profile("allow.sb", "(version 1)(allow default)")
}

/// A `knsh-exec` command running `line` with `/bin/sh` under `profile`, with an empty environment plus `env`.
fn trampoline(profile: &Path, line: &str, env: &[(&str, &Path)]) -> Command {
    let mut command = Command::new(EXEC);
    command
        .args(["--profile".as_ref(), profile.as_os_str()])
        .args(["--interpreter", "/bin/sh", "--line", line])
        .env_clear()
        .envs(env.iter().copied())
        .stdin(Stdio::null());
    command
}

fn run(command: &mut Command) -> Output {
    command.output().unwrap()
}

fn stdout(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).unwrap()
}

// KNSH-046: a line under a profile that denies writes cannot write; the same line under an allowing profile can.
#[test]
fn denied_write_fails_under_the_profile() {
    let scratch = Scratch::new("deny");
    let deny = scratch.profile(
        "deny.sb",
        &format!(
            "(version 1)(allow default)(deny file-write* (subpath \"{}\"))",
            scratch.0.display()
        ),
    );
    let target = scratch.0.join("written");
    let line = r#"echo knsh > "$TARGET""#;

    let denied = run(&mut trampoline(&deny, line, &[("TARGET", &target)]));
    assert_ne!(denied.status.code(), Some(0));
    assert!(!target.exists(), "the write was denied");

    // Control: the line itself works, so the denial above came from the profile.
    let allowed = run(&mut trampoline(&allow_all(&scratch), line, &[("TARGET", &target)]));
    assert_eq!(allowed.status.code(), Some(0), "{allowed:?}");
    assert_eq!(fs::read_to_string(&target).unwrap(), "knsh\n");
}

// KNSH-046: the line leads its own process group (`echo $$` equals its group id), although the test process that
// started it leads a different group. The group id is read from outside while the line waits on stdin: `/bin/ps` is
// setuid, which Seatbelt refuses to run.
#[test]
fn line_leads_its_own_process_group() {
    use std::io::{BufRead, BufReader};

    let scratch = Scratch::new("pgid");
    let mut child = trampoline(&allow_all(&scratch), "echo $$; read reply; exit 0", &[])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut first = String::new();
    BufReader::new(child.stdout.take().unwrap())
        .read_line(&mut first)
        .unwrap();
    let pid: c_int = first.trim().parse().unwrap();
    // SAFETY: plain integers, no memory.
    let (group, own_group) = unsafe { (getpgid(pid), getpgid(0)) };
    drop(child.stdin.take());
    assert!(child.wait().unwrap().success());
    assert_eq!(
        u32::try_from(pid).unwrap(),
        child.id(),
        "the line is the trampoline's process, exec'd in place"
    );
    assert_eq!(group, pid);
    assert_ne!(group, own_group);
}

// SAFETY (for the block): libSystem signatures on Darwin; both take and return plain integers.
unsafe extern "C" {
    fn dup2(from: c_int, to: c_int) -> c_int;
    fn getpgid(pid: c_int) -> c_int;
}

// KNSH-046: only stdio and `--keep-fd` descriptors reach the line; any other inherited descriptor is closed at exec.
#[test]
fn closes_unlisted_descriptors() {
    let scratch = Scratch::new("fds");
    let kept = fs::File::open("/dev/null").unwrap();
    let leaked = fs::File::open("/dev/null").unwrap();
    let (kept_fd, leaked_fd) = (kept.as_raw_fd(), leaked.as_raw_fd());
    let mut command = trampoline(
        &allow_all(&scratch),
        "for n in 20 21; do if [ -e /dev/fd/$n ]; then echo $n open; else echo $n closed; fi; done",
        &[],
    );
    command.args(["--keep-fd", "20"]);
    // SAFETY: runs in the forked child before exec; `dup2` is async-signal-safe and allocates nothing. The copies
    // at 20 and 21 have `FD_CLOEXEC` cleared, as a descriptor `knshd` leaked by mistake would.
    unsafe {
        command.pre_exec(move || {
            if dup2(kept_fd, 20) == -1 || dup2(leaked_fd, 21) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let output = run(&mut command);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert_eq!(stdout(&output), "20 open\n21 closed\n");
}

// KNSH-046: a listed descriptor that is not open is malformed input; nothing runs.
#[test]
fn refuses_a_kept_descriptor_that_is_not_open() {
    let scratch = Scratch::new("fdmissing");
    let marker = scratch.0.join("ran");
    let mut command = trampoline(&allow_all(&scratch), r#"echo > "$MARKER""#, &[("MARKER", &marker)]);
    command.args(["--keep-fd", "250"]);
    let output = run(&mut command);
    assert_eq!(output.status.code(), Some(USAGE));
    assert!(!marker.exists());
}

// KNSH-046: the trampoline refuses to exec unless it is single-threaded (`src/main.rs`), so a line that runs at all
// proves the thread count was 1 just before the exec.
#[test]
fn execs_single_threaded() {
    let scratch = Scratch::new("threads");
    let output = run(&mut trampoline(&allow_all(&scratch), "exit 7", &[]));
    assert_eq!(output.status.code(), Some(7), "{output:?}");
    assert!(
        output.stderr.is_empty(),
        "{:?}",
        String::from_utf8_lossy(&output.stderr)
    );
}

// KNSH-046: SIGPIPE is back at its default action, so a writer to a closed pipe ends by the signal (`yes | head`):
// `yes` exits with 128 + 13. Had the trampoline kept the Rust runtime's ignored SIGPIPE, `yes` would see `EPIPE` and
// exit 1.
#[test]
fn sigpipe_is_not_ignored_by_the_line() {
    let scratch = Scratch::new("sigpipe");
    let output = run(&mut trampoline(
        &allow_all(&scratch),
        r#"{ /usr/bin/yes; echo "yes $?" >&2; } | /usr/bin/head -n 1 >/dev/null"#,
        &[],
    ));
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert_eq!(String::from_utf8_lossy(&output.stderr), "yes 141\n");
}

// KNSH-046: a profile sandbox-exec cannot apply, a missing profile, or malformed arguments never run the line.
#[test]
fn failing_sandbox_never_falls_back_to_running_the_line() {
    let scratch = Scratch::new("fail");
    let marker = scratch.0.join("ran");
    let line = r#"echo ran > "$MARKER""#;

    let broken = scratch.profile("broken.sb", "(version 1)(allow default");
    let output = run(&mut trampoline(&broken, line, &[("MARKER", &marker)]));
    assert_eq!(output.status.code(), Some(SANDBOX_EXEC_BAD_PROFILE), "{output:?}");
    assert!(!marker.exists());

    let missing = scratch.0.join("missing.sb");
    let output = run(&mut trampoline(&missing, line, &[("MARKER", &marker)]));
    assert_eq!(output.status.code(), Some(PROFILE), "{output:?}");
    assert!(String::from_utf8_lossy(&output.stderr).starts_with("knsh-exec: "));
    assert!(!marker.exists());

    // A profile others could rewrite is refused before sandbox-exec ever reads it.
    let shared = allow_all(&scratch);
    fs::set_permissions(&shared, fs::Permissions::from_mode(0o666)).unwrap();
    let output = run(&mut trampoline(&shared, line, &[("MARKER", &marker)]));
    assert_eq!(output.status.code(), Some(PROFILE), "{output:?}");
    assert!(!marker.exists());

    let output = run(Command::new(EXEC)
        .args(["--profile", "relative.sb", "--interpreter", "/bin/sh", "--line"])
        .arg(line)
        .env("MARKER", &marker));
    assert_eq!(output.status.code(), Some(USAGE), "{output:?}");
    assert!(!marker.exists());

    let output = run(Command::new(EXEC).arg("--line").arg(line).env("MARKER", &marker));
    assert_eq!(output.status.code(), Some(USAGE), "{output:?}");
    assert!(!marker.exists());
}

// KNSH-046: a line that starts with `-` is a command, never an interpreter option.
#[test]
fn option_like_line_is_a_command() {
    let scratch = Scratch::new("dash");
    let output = run(&mut trampoline(&allow_all(&scratch), "-i", &[]));
    assert_eq!(output.status.code(), Some(127), "{output:?}");
}

// KNSH-046: the capability probe's exact profile and line (`crates/knshd/src/probe.rs`: `PROBE_PROFILE`,
// `PROBE_LINE`, `PROBE_DENIED_EXIT`) through the real trampoline. Seatbelt works here, so the line reports its write
// denied (42) and nothing is written; with no sandbox in force the same line exits 1. Copied rather than shared:
// knsh-exec depends on nothing (NFR-SUP-01).
#[test]
fn capability_probe_line_observes_the_denial() {
    const PROBE_PROFILE: &str = "(version 1)(allow default)(deny file-write*)";
    const PROBE_LINE: &str =
        r#"[ -n "$KNSH_PROBE_TARGET" ] || exit 1; if echo knsh > "$KNSH_PROBE_TARGET"; then exit 1; fi; exit 42"#;

    let scratch = Scratch::new("probe");
    let target = scratch.0.join("probe.target");
    let denied = run(&mut trampoline(
        &scratch.profile("probe.sb", PROBE_PROFILE),
        PROBE_LINE,
        &[("KNSH_PROBE_TARGET", &target)],
    ));
    assert_eq!(denied.status.code(), Some(42), "{denied:?}");
    assert!(!target.exists());

    let unconfined = run(&mut trampoline(
        &allow_all(&scratch),
        PROBE_LINE,
        &[("KNSH_PROBE_TARGET", &target)],
    ));
    assert_eq!(unconfined.status.code(), Some(1), "{unconfined:?}");
    assert!(target.exists());

    // Without the target variable the line can never pass.
    let lost = run(&mut trampoline(
        &scratch.profile("probe2.sb", PROBE_PROFILE),
        PROBE_LINE,
        &[],
    ));
    assert_eq!(lost.status.code(), Some(1), "{lost:?}");
}

/// Runs `command` with the write end of a fresh pipe at descriptor 30 and `--status-fd 30`, and returns its output
/// and every byte the trampoline reported there.
fn with_status(mut command: Command) -> (Output, Vec<u8>) {
    use std::io::Read;

    let (mut reader, writer) = std::io::pipe().unwrap();
    let writer_fd = writer.as_raw_fd();
    command.args(["--status-fd", "30"]);
    // SAFETY: runs in the forked child before exec; `dup2` is async-signal-safe and allocates nothing. The copy at
    // 30 has `FD_CLOEXEC` cleared, as `knshd` leaves its status descriptor.
    unsafe {
        command.pre_exec(move || {
            if dup2(writer_fd, 30) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let output = run(&mut command);
    // The parent's write end, closed so the read ends once every child copy is gone.
    drop(command);
    drop(writer);
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes).unwrap();
    (output, bytes)
}

// KNSH-051: a trampoline failure is written to the status descriptor; once `sandbox-exec` has started, the
// descriptor is closed with nothing written, even when the line exits with a trampoline code. That is how the
// supervisor tells "the profile was not applied" from a line that exits 66 itself.
#[test]
fn reports_failures_on_the_status_descriptor_only() {
    let scratch = Scratch::new("status");
    let missing = scratch.0.join("missing.sb");
    let (output, status) = with_status(trampoline(&missing, "true", &[]));
    assert_eq!(output.status.code(), Some(PROFILE));
    assert_eq!(status, [66]);

    let (output, status) = with_status(trampoline(&allow_all(&scratch), "exit 66", &[]));
    assert_eq!(output.status.code(), Some(PROFILE), "the line's own exit");
    assert!(status.is_empty(), "{status:?}");

    // The status descriptor never reaches the line.
    let (output, _) = with_status(trampoline(
        &allow_all(&scratch),
        "if [ -e /dev/fd/30 ]; then echo open; else echo closed; fi",
        &[],
    ));
    assert_eq!(stdout(&output), "closed\n");
}

// KNSH-051: operands follow the line as `$0`, `$1`, … (`bash -c 'line' name arg…`), unchanged.
#[test]
fn passes_operands_after_the_line() {
    let scratch = Scratch::new("operands");
    let mut command = trampoline(&allow_all(&scratch), r#"printf '%s|' "$0" "$1" "$2""#, &[]);
    command.args(["--arg", "name", "--arg", "two words", "--arg", "-x"]);
    let output = run(&mut command);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert_eq!(stdout(&output), "name|two words|-x|");
}
