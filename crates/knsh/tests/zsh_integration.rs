//! End-to-end checks of integration mode against the real `/bin/zsh` (KNSH-019, FR-SES-20, FR-SES-22,
//! NFR-COMPAT-01, NFR-COMPAT-03).
//!
//! Every test uses a temporary `HOME` (and so a temporary engine directory), a minimal environment, and feeds the
//! interactive shell its command lines on standard input, which runs `preexec`/`precmd` just as typing does. The
//! terminal itself (process groups, job control, terminal ownership) cannot be exercised without a pseudo-terminal
//! here; see the story's PR for the manual check.

#![cfg(all(test, target_os = "macos"))]
// Helpers outside `#[test]` functions fail loudly too; clippy only exempts the test functions themselves.
#![allow(clippy::expect_used, clippy::panic)]

use std::ffi::OsStr;
use std::fs;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, mpsc};
use std::time::{Duration, Instant};

use knsh::integration::host::{self, Flow, Isolation, TelemetrySink};
use knsh::integration::telemetry::TelemetryLine;
use knsh::integration::zsh::{SYSTEM_ZSH, ZshLaunch};
use knsh_platform::EnginePaths;
use knsh_platform::macos::{RealFs, effective_uid};

/// A directory removed when dropped, unique per test.
struct TempDir(PathBuf);

impl TempDir {
    fn new(name: &str) -> Self {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
        // Canonical, so that `$PWD`, `$HOME` and the paths in assertions agree (`/var` is a symlink on macOS).
        let base = fs::canonicalize(std::env::temp_dir()).expect("temp dir");
        let dir = base.join(format!("knsh-zsh-{name}-{}-{unique}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("create temp dir");
        Self(dir)
    }

    fn path(&self, relative: &str) -> PathBuf {
        self.0.join(relative)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Writes a startup file that appends its name, the `ZDOTDIR` it sees and whether any knsh variable leaked into it
/// to `trace`, then runs `extra`.
fn write_rc(dir: &Path, name: &str, trace: &Path, extra: &str) {
    fs::create_dir_all(dir).expect("rc dir");
    let body = format!(
        "print -r -- \"{name} 0=$0 ZDOTDIR=${{ZDOTDIR-<unset>}} leaked=${{+KNSH_ZSH_ZDOTDIR}}${{+KNSH_TELEMETRY_FD}}\" >> '{}'\n{extra}\n",
        trace.display()
    );
    fs::write(dir.join(name), body).expect("write rc");
}

/// Writes all four recording startup files into `dir`.
fn write_all_rcs(dir: &Path, trace: &Path) {
    for name in [".zshenv", ".zprofile", ".zshrc", ".zlogin"] {
        write_rc(dir, name, trace, "");
    }
}

/// The `PATH` of the minimal test environment.
const TEST_PATH: &str = "/usr/bin:/bin:/usr/sbin:/sbin";

/// A minimal environment with `HOME` and optionally `ZDOTDIR`.
fn base_env(command: &mut Command, home: &Path, zdotdir: Option<&Path>) {
    command
        .env_clear()
        .env("HOME", home)
        .env("PATH", TEST_PATH)
        .env("TERM", "dumb");
    if let Some(zdotdir) = zdotdir {
        command.env("ZDOTDIR", zdotdir);
    }
}

/// Runs `command` with `script` on standard input and returns its output.
fn run_with_script(mut command: Command, script: &str) -> Output {
    use std::io::Write;
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // Spawning creates the stdio pipes, which on macOS are inheritable until std marks them close-on-exec; a recorded
    // run forking on another thread at that moment would hand them to its commands, and the descriptor-leak check
    // would blame knsh. Holding the recorded-run lock around the spawn closes that window (see `RECORDED_RUNS`).
    let mut child = {
        let _serial = RECORDED_RUNS.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        command.spawn().expect("spawn")
    };
    let mut stdin = child.stdin.take().expect("stdin");
    stdin.write_all(script.as_bytes()).expect("write script");
    drop(stdin);
    child.wait_with_output().expect("wait")
}

fn plain_zsh(home: &Path, zdotdir: Option<&Path>, login: bool, script: &str) -> Output {
    let mut command = Command::new(SYSTEM_ZSH);
    // The `argv[0]` knsh gives zsh (and `login(1)` gives a login shell), so that `$0` compares equal.
    command
        .arg0(if login { "-zsh" } else { "zsh" })
        .arg(if login { "-il" } else { "-i" });
    base_env(&mut command, home, zdotdir);
    run_with_script(command, script)
}

fn knsh_binary(home: Option<&Path>, zdotdir: Option<&Path>, login: bool, script: &str) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_knsh"));
    command.arg(if login { "-il" } else { "-i" });
    match home {
        Some(home) => base_env(&mut command, home, zdotdir),
        None => {
            command.env_clear().env("PATH", "/usr/bin:/bin").env("TERM", "dumb");
        }
    }
    run_with_script(command, script)
}

/// Pipes in a `/bin/ls -l /dev/fd/` listing that knsh did not open: the descriptor names of pipes that any child of
/// this test process inherits. CI runners (GitHub Actions) pass their own pipes down to every process, so a pipe
/// seen by a command is a telemetry leak only if a plain child does not see it too.
fn leaked_pipes(listing: &str) -> Vec<String> {
    let pipes = |listing: &str| -> Vec<String> {
        listing
            .lines()
            .filter(|line| line.starts_with('p'))
            .filter_map(|line| line.split_whitespace().last().map(str::to_owned))
            .collect()
    };
    let baseline = {
        // Its stdout pipe must not reach a recorded run on another thread (see `RECORDED_RUNS`).
        let _serial = RECORDED_RUNS.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        Command::new("/bin/ls")
            .args(["-l", "/dev/fd/"])
            .output()
            .expect("list inherited descriptors")
    };
    let inherited = pipes(&String::from_utf8_lossy(&baseline.stdout));
    pipes(listing)
        .into_iter()
        .filter(|fd| !inherited.contains(fd))
        .collect()
}

fn read_trace(path: &Path) -> String {
    fs::read_to_string(path).unwrap_or_default()
}

fn stderr_text(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

// KNSH-019 acceptance / integration test (NFR-COMPAT-01): with a temp HOME and recording rc files, the startup
// files run in the same order, see the same ZDOTDIR and see no knsh variable under knsh as under plain zsh, for
// login and non-login shells.
#[test]
fn startup_trace_matches_plain_zsh_with_zdotdir_unset() {
    for login in [true, false] {
        let tmp = TempDir::new("unset");
        let home = tmp.path("home");
        let trace = tmp.path("trace");
        write_all_rcs(&home, &trace);
        // /etc/zshrc sets HISTFILE from ZDOTDIR: proves the system files see the user's ZDOTDIR too.
        let script = format!("print -r -- \"HISTFILE=$HISTFILE\" >> '{}'\nexit 0\n", trace.display());

        let plain = plain_zsh(&home, None, login, &script);
        let expected = read_trace(&trace);
        fs::remove_file(&trace).expect("reset trace");
        let hosted = knsh_binary(Some(&home), None, login, &script);
        let actual = read_trace(&trace);

        assert_eq!(plain.status.code(), Some(0));
        assert_eq!(hosted.status.code(), Some(0), "{}", stderr_text(&hosted));
        let expected_files = if login { 4 } else { 2 };
        assert_eq!(expected.lines().count(), expected_files + 1, "{expected}");
        assert_eq!(actual, expected, "login={login}");
        assert_no_hook_noise(&stderr_text(&hosted));
    }
}

// KNSH-019 acceptance: the same with ZDOTDIR set, where the user's .zshenv moves ZDOTDIR elsewhere, so the later
// files must come from the new directory, exactly as in plain zsh.
#[test]
fn startup_trace_matches_plain_zsh_when_zshenv_moves_zdotdir() {
    for login in [true, false] {
        let tmp = TempDir::new("moved");
        let home = tmp.path("home");
        let first = tmp.path("first");
        let second = tmp.path("second");
        let trace = tmp.path("trace");
        fs::create_dir_all(&home).expect("home");
        write_rc(&first, ".zshenv", &trace, &format!("ZDOTDIR='{}'", second.display()));
        // Decoys: plain zsh never reads these, so neither may knsh.
        for name in [".zprofile", ".zshrc", ".zlogin"] {
            write_rc(&first, name, &trace, "print WRONG");
        }
        write_all_rcs(&second, &trace);
        fs::remove_file(second.join(".zshenv")).expect("only first has .zshenv");
        let script = format!(
            "print -r -- \"after ZDOTDIR=$ZDOTDIR HISTFILE=$HISTFILE\" >> '{}'\nexit 0\n",
            trace.display()
        );

        let plain = plain_zsh(&home, Some(&first), login, &script);
        let expected = read_trace(&trace);
        fs::remove_file(&trace).expect("reset trace");
        let hosted = knsh_binary(Some(&home), Some(&first), login, &script);
        let actual = read_trace(&trace);

        assert_eq!(plain.status.code(), Some(0));
        assert_eq!(hosted.status.code(), Some(0), "{}", stderr_text(&hosted));
        assert!(
            expected.lines().any(|line| line.starts_with(".zshrc ")
                && line.ends_with(&format!("ZDOTDIR={} leaked=00", second.display()))),
            "{expected}"
        );
        assert_eq!(actual, expected, "login={login}");
    }
}

// KNSH-019 acceptance: knsh exits with zsh's status (recording off: knsh has become zsh).
#[test]
fn knsh_exits_with_zsh_status() {
    let tmp = TempDir::new("status");
    let home = tmp.path("home");
    fs::create_dir_all(&home).expect("home");
    let output = knsh_binary(Some(&home), None, false, "exit 7\n");
    assert_eq!(output.status.code(), Some(7));
}

// KNSH-019 acceptance: with recording off no hook is installed and nothing is passed to the shell, so no
// telemetry can be produced; knsh never opens a connection (it has replaced itself with zsh).
#[test]
fn recording_off_installs_no_hooks() {
    let tmp = TempDir::new("off");
    let home = tmp.path("home");
    let out = tmp.path("out");
    fs::create_dir_all(&home).expect("home");
    let script = format!(
        "print -r -- \"${{+functions[_knsh_preexec]}} ${{+_knsh_telemetry_fd}} [$preexec_functions] [$precmd_functions]\" > '{}'\nexit 0\n",
        out.display()
    );
    let output = knsh_binary(Some(&home), None, false, &script);
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(read_trace(&out), "0 0 [] []\n");
    // The engine wrapper was installed, but no socket directory was used.
    let paths = EnginePaths::for_home(&home).expect("paths");
    assert!(paths.zsh_startup_dir().join(".zshenv").is_file());
    assert!(!paths.user_socket().exists());
}

// FR-SES-22: if the wrapper cannot be installed (here: no HOME), plain zsh still starts, after a warning.
#[test]
fn without_a_startup_dir_plain_zsh_still_starts() {
    let output = knsh_binary(None, None, false, "exit 4\n");
    assert_eq!(output.status.code(), Some(4));
    assert!(
        stderr_text(&output).contains("starting plain zsh"),
        "{}",
        stderr_text(&output)
    );
}

/// Sends every delivered line to a channel; optionally stops after `stop_after` lines.
struct ChannelSink {
    lines: mpsc::Sender<TelemetryLine>,
    stop_after: Option<usize>,
    delivered: usize,
}

impl ChannelSink {
    /// A sink and the receiver of the lines it is given.
    fn new(stop_after: Option<usize>) -> (Self, mpsc::Receiver<TelemetryLine>) {
        let (lines, receiver) = mpsc::channel();
        let sink = Self {
            lines,
            stop_after,
            delivered: 0,
        };
        (sink, receiver)
    }
}

impl TelemetrySink for ChannelSink {
    fn deliver(&mut self, line: TelemetryLine) -> Flow {
        let _ = self.lines.send(line);
        self.delivered += 1;
        if self.stop_after.is_some_and(|limit| self.delivered >= limit) {
            Flow::Stop
        } else {
            Flow::Continue
        }
    }
}

/// Serialises the recorded runs, and every other spawn in this file against them. The telemetry pipe's write end is
/// inheritable until zsh has started, so a recorded zsh spawned by another thread at that moment would inherit a
/// second, foreign write end and see it as a pipe (the documented precondition of `TelemetryPipe::new`; `knsh` itself
/// starts no other process then). The other way round, the stdio pipes `Command::spawn` creates on macOS are
/// inheritable for a moment too, so a recorded run forking then would pass them to its commands (CI saw this as
/// a false telemetry leak); `run_with_script` takes this lock around its spawn for that reason.
static RECORDED_RUNS: Mutex<()> = Mutex::new(());

/// Runs the hosted zsh with recording on, in a minimal environment whose HOME is `home`, with `script` on standard
/// input. Returns its status, its stderr and the elapsed time.
fn run_recorded(home: &Path, sink: Box<dyn TelemetrySink>, script: &str) -> (ExitStatus, String, Duration) {
    run_recorded_with(home, true, sink, script)
}

/// [`run_recorded`], optionally without the startup directory (the fallback when it cannot be installed).
fn run_recorded_with(
    home: &Path,
    with_startup_dir: bool,
    sink: Box<dyn TelemetrySink>,
    script: &str,
) -> (ExitStatus, String, Duration) {
    let script_path = home.with_extension("script");
    fs::write(&script_path, script).expect("script");
    let stderr_path = home.with_extension("stderr");
    let paths = EnginePaths::for_home(home).expect("paths");
    let startup_dir = host::install_zsh_startup_dir(&RealFs::new(), &paths, effective_uid()).expect("install");
    let launch = ZshLaunch {
        zsh: Path::new(SYSTEM_ZSH),
        startup_dir: with_startup_dir.then_some(startup_dir.as_path()),
        user_zdotdir: None,
        login: false,
        force_interactive: true,
        telemetry_fd: None,
        marks: false,
    };
    let isolation = Isolation {
        stdin: Stdio::from(fs::File::open(&script_path).expect("open script")),
        stdout: Stdio::null(),
        stderr: Stdio::from(fs::File::create(&stderr_path).expect("stderr file")),
        env: vec![
            ("HOME".into(), home.as_os_str().to_owned()),
            ("PATH".into(), TEST_PATH.into()),
            ("TERM".into(), "dumb".into()),
        ],
    };
    let _serial = RECORDED_RUNS.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let started = Instant::now();
    let status = host::run_recorded(launch, sink, Some(isolation)).expect("run");
    let elapsed = started.elapsed();
    (status, fs::read_to_string(&stderr_path).unwrap_or_default(), elapsed)
}

fn started(cwd: &str, command: &str) -> TelemetryLine {
    TelemetryLine::CommandStarted {
        cwd: cwd.as_bytes().to_vec(),
        command: command.as_bytes().to_vec(),
    }
}

fn finished(exit_code: u8, cwd: &str) -> TelemetryLine {
    TelemetryLine::CommandFinished {
        exit_code,
        cwd: cwd.as_bytes().to_vec(),
    }
}

/// Errors the hooks must never produce on the user's terminal.
fn assert_no_hook_noise(stderr: &str) {
    // Not plain "knsh": the default prompt shows the working directory, which may be this repository.
    for noise in [
        "knsh:",
        "_knsh",
        "bad file descriptor",
        "broken pipe",
        "command not found",
        "no such",
    ] {
        assert!(!stderr.to_lowercase().contains(noise), "stderr has {noise:?}: {stderr}");
    }
}

// FR-SES-21 / KNSH-019: with recording on, each command line produces a started and a finished line with the
// command as typed, its directory and its status; the user's own hooks (add-zsh-hook and a plain `precmd`
// function, as frameworks use) still run; no knsh variable or descriptor reaches commands.
#[test]
fn recorded_session_reports_commands_and_keeps_user_hooks() {
    let tmp = TempDir::new("hooks");
    let home = tmp.path("home");
    let trace = tmp.path("trace");
    let fds = tmp.path("fds");
    // The user's own hooks, as a framework installs them: add-zsh-hook, plus a plain `precmd` function.
    write_rc(
        &home,
        ".zshrc",
        &trace,
        &format!(
            concat!(
                "autoload -Uz add-zsh-hook\n",
                "u_pre() {{ print -r -- \"user preexec $1\" >> '{trace}' }}\n",
                "u_cmd() {{ print -r -- \"user precmd $?\" >> '{trace}' }}\n",
                "add-zsh-hook preexec u_pre\n",
                "add-zsh-hook precmd u_cmd\n",
                "precmd() {{ print -r -- \"user precmd function $?\" >> '{trace}' }}\n",
            ),
            trace = trace.display()
        ),
    );
    let script = format!(
        concat!(
            "true\n",
            "false\n",
            "cd '{home}'\n",
            "print -r -- $'tab\\there' \"${{ZDOTDIR-unset}} ${{+KNSH_TELEMETRY_FD}}${{+KNSH_ZSH_ZDOTDIR}}\" >> '{trace}'\n",
            "/bin/ls -l /dev/fd/ > '{fds}'\n",
            "cd /\n",
            "exit 3\n",
        ),
        trace = trace.display(),
        home = home.display(),
        fds = fds.display(),
    );
    let (sink, receiver) = ChannelSink::new(None);
    // zsh starts in this process's working directory.
    let cwd = std::env::current_dir().expect("cwd");
    let cwd = cwd.to_str().expect("utf-8 cwd");
    let home_text = home.to_str().expect("utf-8 home");
    let (status, stderr, _) = run_recorded(&home, Box::new(sink), &script);

    assert_eq!(status.code(), Some(3), "{stderr}");
    assert_no_hook_noise(&stderr);
    let lines: Vec<_> = receiver.try_iter().collect();
    let print_line = format!(
        "print -r -- $'tab\\there' \"${{ZDOTDIR-unset}} ${{+KNSH_TELEMETRY_FD}}${{+KNSH_ZSH_ZDOTDIR}}\" >> '{}'",
        trace.display()
    );
    let ls_line = format!("/bin/ls -l /dev/fd/ > '{}'", fds.display());
    let cd_line = format!("cd '{home_text}'");
    let expected_tail = [
        started(cwd, "true"),
        finished(0, cwd),
        started(cwd, "false"),
        finished(1, cwd),
        started(cwd, &cd_line),
        finished(0, home_text),
        started(home_text, &print_line),
        finished(0, home_text),
        started(home_text, &ls_line),
        finished(0, home_text),
        started(home_text, "cd /"),
        finished(0, "/"),
        started("/", "exit 3"),
    ];
    assert_eq!(lines, expected_tail);

    let trace_text = read_trace(&trace);
    assert!(
        trace_text.starts_with(".zshrc 0=zsh ZDOTDIR=<unset> leaked=00\n"),
        "{trace_text}"
    );
    // The user's hooks ran for every command, and saw the real status.
    assert!(trace_text.contains("user preexec false\n"), "{trace_text}");
    assert!(trace_text.contains("user precmd 1\n"), "{trace_text}");
    assert!(trace_text.contains("user precmd function 1\n"), "{trace_text}");
    assert!(trace_text.contains("tab\there unset 00\n"), "{trace_text}");
    // Every standard stream here is a file, so a pipe visible to a command that a plain child of the test does not
    // inherit could only be the telemetry descriptor leaking (`ls` itself opens directories, never pipes).
    let listing = read_trace(&fds);
    assert!(listing.lines().any(|line| line.ends_with(" 0")), "{listing}");
    assert!(
        leaked_pipes(&listing).is_empty(),
        "telemetry pipe leaked to a command: {listing}"
    );
}

// KNSH-019: without the startup directory nothing could take the descriptor over, so none is passed: commands see
// no pipe and no knsh variable, and the shell still runs.
#[test]
fn recorded_run_without_startup_dir_leaks_no_descriptor() {
    let tmp = TempDir::new("nodir");
    let home = tmp.path("home");
    let fds = tmp.path("fds");
    fs::create_dir_all(&home).expect("home");
    let script = format!(
        "/bin/ls -l /dev/fd/ > '{}'\nprint -r -- \"${{+KNSH_TELEMETRY_FD}}\" >> '{}'\nexit 2\n",
        fds.display(),
        fds.display()
    );
    let (sink, receiver) = ChannelSink::new(None);
    let (status, stderr, _) = run_recorded_with(&home, false, Box::new(sink), &script);

    assert_eq!(status.code(), Some(2), "{stderr}");
    assert_eq!(receiver.try_iter().count(), 0);
    let listing = read_trace(&fds);
    assert!(listing.ends_with("\n0\n"), "{listing}");
    assert!(
        leaked_pipes(&listing).is_empty(),
        "telemetry pipe leaked to a command: {listing}"
    );
}

// KNSH-019 acceptance / integration test: when the forwarder goes away (closes the read end) mid-session, or the
// user closes the descriptor, the hooks do nothing: no output, no delay, and the shell carries on (interactive zsh
// would otherwise die of SIGPIPE).
#[test]
fn closed_telemetry_descriptor_is_silent_and_harmless() {
    let tmp = TempDir::new("closed");
    let home = tmp.path("home");
    fs::create_dir_all(&home).expect("home");
    let mut script = (0..50)
        .map(|index| format!("echo {index}"))
        .collect::<Vec<_>>()
        .join("\n");
    script.push('\n');
    script.push_str("exec {_knsh_telemetry_fd}>&-\necho after-user-close\nexit 5\n");
    let (sink, receiver) = ChannelSink::new(Some(1));
    let (status, stderr, elapsed) = run_recorded(&home, Box::new(sink), &script);

    assert_eq!(status.code(), Some(5), "the shell survived: {stderr}");
    assert_no_hook_noise(&stderr);
    assert_eq!(receiver.try_iter().count(), 1);
    assert!(elapsed < Duration::from_secs(10), "took {elapsed:?}");
}

// FR-SES-22: after the user closes the telemetry descriptor, a file they open next reuses its number; the hooks must
// not write telemetry into that file.
#[test]
fn reused_descriptor_number_never_receives_telemetry() {
    let tmp = TempDir::new("reuse");
    let home = tmp.path("home");
    let reused = tmp.path("reused");
    let numbers = tmp.path("numbers");
    fs::create_dir_all(&home).expect("home");
    let script = format!(
        concat!(
            // zsh hands out the lowest free number from 10: open until the file lands on the closed one.
            "old=$_knsh_telemetry_fd; exec {{_knsh_telemetry_fd}}>&-; ",
            "while :; do exec {{f}}>'{reused}'; (( f == old )) && break; done; ",
            "print -r -- \"$old $f\" > '{numbers}'\n",
            "true\n",
            "false\n",
            "exit 0\n",
        ),
        reused = reused.display(),
        numbers = numbers.display(),
    );
    let (sink, _receiver) = ChannelSink::new(None);
    let (status, stderr, _) = run_recorded(&home, Box::new(sink), &script);

    assert_eq!(status.code(), Some(0), "{stderr}");
    assert_no_hook_noise(&stderr);
    let numbers = read_trace(&numbers);
    let mut pair = numbers.split_whitespace();
    assert_eq!(
        pair.next(),
        pair.next(),
        "the file must reuse the closed number: {numbers}"
    );
    assert_eq!(read_trace(&reused), "", "telemetry was written into the user's file");
}

/// Blocks on its first line until released (or a watchdog expires), so the pipe fills behind it.
struct StuckSink {
    release: mpsc::Receiver<()>,
}

impl TelemetrySink for StuckSink {
    fn deliver(&mut self, _line: TelemetryLine) -> Flow {
        let _ = self.release.recv_timeout(Duration::from_secs(60));
        Flow::Continue
    }
}

// FR-SES-22 / NFR-REL-02: a forwarder that stops reading never delays the prompt: the pipe fills and the hooks
// drop lines instead of waiting.
#[test]
fn stalled_forwarder_never_blocks_the_shell() {
    let tmp = TempDir::new("stalled");
    let home = tmp.path("home");
    fs::create_dir_all(&home).expect("home");
    // Each line is ~4 KiB of command text, so 200 of them far exceed any pipe buffer.
    let filler = "x".repeat(4096);
    let mut script = format!(": {filler}\n").repeat(200);
    script.push_str("exit 6\n");
    let (release, released) = mpsc::channel();
    let (status, stderr, elapsed) = run_recorded(&home, Box::new(StuckSink { release: released }), &script);
    let _ = release.send(());

    assert_eq!(status.code(), Some(6), "{stderr}");
    assert_no_hook_noise(&stderr);
    assert!(
        elapsed < Duration::from_secs(30),
        "the shell waited for the forwarder: {elapsed:?}"
    );
}

// KNSH-019 acceptance: a hosted shell killed by a signal is reported as such, for knsh to end the same way.
#[test]
fn recorded_shell_killed_by_signal_reports_the_signal() {
    let tmp = TempDir::new("signal");
    let home = tmp.path("home");
    fs::create_dir_all(&home).expect("home");
    let (sink, _receiver) = ChannelSink::new(None);
    let (status, _, _) = run_recorded(&home, Box::new(sink), "kill -KILL $$\n");
    assert_eq!(status.signal(), Some(9));
}

#[test]
fn launch_inputs_are_paths() {
    // Guards the assumption the tests above rely on: the system zsh exists where the plan says.
    assert!(Path::new(SYSTEM_ZSH).is_file());
    assert_eq!(Path::new(SYSTEM_ZSH).file_name(), Some(OsStr::new("zsh")));
}
