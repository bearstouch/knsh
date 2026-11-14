//! End-to-end checks of integration mode against real bash (KNSH-020, FR-SES-20, FR-SES-21, FR-SES-22,
//! NFR-COMPAT-01, NFR-COMPAT-04).
//!
//! Every test runs under `/bin/bash` (3.2 on macOS) and, when one is installed, under a bash 5 too: Homebrew's
//! (`/opt/homebrew/bin/bash`, `/usr/local/bin/bash`) or the one named by `KNSH_TEST_BASH`. A test prints which
//! bashes it ran under; without a bash 5 only 3.2 is covered, which the story records as pending.
//!
//! Every test uses a temporary `HOME` (and so a temporary engine directory), a minimal environment, and feeds the
//! interactive shell its command lines on standard input, which runs `PROMPT_COMMAND` and the `DEBUG` trap just as
//! typing does. The terminal itself (job control, terminal ownership) cannot be exercised without a pseudo-terminal.

#![cfg(all(test, target_os = "macos"))]
// Helpers outside `#[test]` functions fail loudly too; clippy only exempts the test functions themselves.
#![allow(clippy::expect_used, clippy::panic)]

use std::ffi::OsString;
use std::fs;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard, mpsc};
use std::time::{Duration, Instant};

use knsh::integration::bash::{BashLaunch, SYSTEM_BASH};
use knsh::integration::host::{self, Flow, Isolation, TelemetrySink};
use knsh::integration::telemetry::TelemetryLine;
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
        let dir = base.join(format!("knsh-bash-{name}-{}-{unique}", std::process::id()));
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

/// Serialises every test of this file. A recorded run's telemetry descriptors are inheritable until bash has
/// started, so a bash started by another thread at that moment would inherit them too (the documented precondition
/// of `TelemetryPipe::new`; `knsh` itself starts no other process then).
static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// The bashes to test: `/bin/bash` and any bash 5 found.
fn bashes() -> Vec<PathBuf> {
    let mut found = vec![PathBuf::from(SYSTEM_BASH)];
    let candidates = std::env::var_os("KNSH_TEST_BASH")
        .map(PathBuf::from)
        .into_iter()
        .chain(["/opt/homebrew/bin/bash", "/usr/local/bin/bash"].map(PathBuf::from));
    for candidate in candidates {
        if candidate.is_file() && !found.contains(&candidate) {
            found.push(candidate);
        }
    }
    let versions: Vec<String> = found
        .iter()
        .map(|bash| format!("{} ({})", bash.display(), version(bash).0))
        .collect();
    eprintln!("bashes under test: {}", versions.join(", "));
    if !found.iter().any(|bash| version(bash).0 >= 5) {
        eprintln!("note: no bash 5 installed; only bash 3.2 is covered (KNSH-020 records bash 5 as pending)");
    }
    found
}

/// `BASH_VERSINFO[0..2]` of `bash`.
fn version(bash: &Path) -> (u32, u32) {
    let output = Command::new(bash)
        .args(["-c", "echo ${BASH_VERSINFO[0]} ${BASH_VERSINFO[1]}"])
        .env_clear()
        .output()
        .expect("bash version");
    let text = String::from_utf8_lossy(&output.stdout);
    let mut parts = text.split_whitespace().map(|part| part.parse().expect("number"));
    (parts.next().expect("major"), parts.next().expect("minor"))
}

/// The `PATH` of the minimal test environment.
const TEST_PATH: &str = "/usr/bin:/bin:/usr/sbin:/sbin";

/// The minimal environment every shell here starts with.
fn base_env(home: &Path) -> Vec<(OsString, OsString)> {
    vec![
        ("HOME".into(), home.as_os_str().to_owned()),
        ("PATH".into(), TEST_PATH.into()),
        ("TERM".into(), "dumb".into()),
        // macOS's bash 3.2 otherwise announces zsh at every interactive start.
        ("BASH_SILENCE_DEPRECATION_WARNING".into(), "1".into()),
    ]
}

/// Runs `command` with `script` on standard input and returns its output.
fn run_with_script(mut command: Command, script: &str) -> Output {
    use std::io::Write;
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().expect("spawn");
    let mut stdin = child.stdin.take().expect("stdin");
    stdin.write_all(script.as_bytes()).expect("write script");
    drop(stdin);
    child.wait_with_output().expect("wait")
}

/// Plain bash, started as `login(1)` (`-bash`) or a terminal (`bash`) would start it.
fn plain_bash(bash: &Path, home: &Path, login: bool, script: &str) -> Output {
    let mut command = Command::new(bash);
    command
        .arg0(if login { "-bash" } else { "bash" })
        .arg("-i")
        .env_clear()
        .envs(base_env(home));
    run_with_script(command, script)
}

/// The `knsh` binary with `SHELL` naming `bash` (recording off).
fn knsh_binary(bash: &Path, home: &Path, login: bool, script: &str) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_knsh"));
    command
        .arg(if login { "-il" } else { "-i" })
        .env_clear()
        .envs(base_env(home))
        .env("SHELL", bash);
    run_with_script(command, script)
}

fn read(path: &Path) -> String {
    fs::read_to_string(path).unwrap_or_default()
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// Sends every delivered line to a channel; optionally stops after `stop_after` lines.
struct ChannelSink {
    lines: mpsc::Sender<TelemetryLine>,
    stop_after: Option<usize>,
    delivered: usize,
}

impl ChannelSink {
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

/// What a recorded run produced.
struct Recorded {
    status: ExitStatus,
    stdout: String,
    stderr: String,
    elapsed: Duration,
}

/// Runs bash with recording on, through the library as KNSH-021 will, in the minimal environment.
fn run_recorded(bash: &Path, home: &Path, login: bool, sink: Box<dyn TelemetrySink>, script: &str) -> Recorded {
    let script_path = home.with_extension("script");
    fs::write(&script_path, script).expect("script");
    let stdout_path = home.with_extension("stdout");
    let stderr_path = home.with_extension("stderr");
    let paths = EnginePaths::for_home(home).expect("paths");
    let startup_dir = host::install_bash_startup_dir(&RealFs::new(), &paths, effective_uid()).expect("install");
    let launch = BashLaunch {
        bash,
        startup_dir: Some(&startup_dir),
        login,
        force_interactive: true,
        telemetry: None,
        user_prompt_command: None,
    };
    let isolation = Isolation {
        stdin: Stdio::from(fs::File::open(&script_path).expect("open script")),
        stdout: Stdio::from(fs::File::create(&stdout_path).expect("stdout file")),
        stderr: Stdio::from(fs::File::create(&stderr_path).expect("stderr file")),
        env: base_env(home),
    };
    let started = Instant::now();
    let status = host::run_recorded(launch, sink, Some(isolation)).expect("run");
    Recorded {
        status,
        stdout: read(&stdout_path),
        stderr: read(&stderr_path),
        elapsed: started.elapsed(),
    }
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
    for noise in [
        "knsh:",
        "_knsh",
        "bad file descriptor",
        "broken pipe",
        "command not found",
        "no such",
        "syntax error",
        "not a valid identifier",
        "unbound variable",
        "bad substitution",
    ] {
        assert!(!stderr.to_lowercase().contains(noise), "stderr has {noise:?}: {stderr}");
    }
}

/// Writes startup file `name` into `home`: it appends its name, `$0`, whether bash calls it a login shell and
/// whether a knsh variable is visible to `trace`, then runs `extra`.
fn write_rc(home: &Path, name: &str, trace: &Path, extra: &str) {
    fs::create_dir_all(home).expect("home");
    let body = format!(
        concat!(
            "echo \"{name} 0=$0 login=$(shopt -q login_shell && echo y || echo n) ",
            "knsh=${{KNSH_TELEMETRY_FD+fd}}${{KNSH_TELEMETRY_PPID+ppid}}${{KNSH_BASH_BOOT+boot}}\" >> '{trace}'\n",
            "{extra}\n"
        ),
        name = name,
        trace = trace.display(),
        extra = extra,
    );
    fs::write(home.join(name), body).expect("write rc");
}

/// Writes every startup file bash may read.
fn write_all_rcs(home: &Path, trace: &Path) {
    for name in [".bash_profile", ".bash_login", ".profile", ".bashrc", ".bash_logout"] {
        write_rc(home, name, trace, "");
    }
}

/// The trace without the knsh-variable field, which a recorded login shell's profile files see (documented).
fn without_knsh_field(trace: &str) -> String {
    trace
        .lines()
        .map(|line| line.split(" knsh=").next().unwrap_or(line))
        .collect::<Vec<_>>()
        .join("\n")
}

// KNSH-020 acceptance (NFR-COMPAT-01): with recording off, `knsh` runs plain bash, so the user's
// .bash_profile/.bashrc/.profile/.bash_logout run exactly as under plain bash, for login and non-login shells, and
// no knsh variable reaches them.
#[test]
fn startup_trace_matches_plain_bash_with_recording_off() {
    let _serial = serial();
    for bash in bashes() {
        for login in [true, false] {
            // With every file, and with only ~/.profile (a login bash falls back to it).
            for only_profile in [false, true] {
                let tmp = TempDir::new("off");
                let home = tmp.path("home");
                let trace = tmp.path("trace");
                write_all_rcs(&home, &trace);
                if only_profile {
                    for name in [".bash_profile", ".bash_login"] {
                        fs::remove_file(home.join(name)).expect("remove");
                    }
                }
                let script = format!("echo \"typed $BASH_VERSION\" >> '{}'\nexit 0\n", trace.display());

                let plain = plain_bash(&bash, &home, login, &script);
                let expected = read(&trace);
                fs::remove_file(&trace).expect("reset trace");
                let hosted = knsh_binary(&bash, &home, login, &script);
                let actual = read(&trace);

                assert_eq!(plain.status.code(), Some(0), "{}", text(&plain.stderr));
                assert_eq!(hosted.status.code(), Some(0), "{}", text(&hosted.stderr));
                let first = if !login {
                    ".bashrc 0=bash login=n knsh=\n"
                } else if only_profile {
                    ".profile 0=-bash login=y knsh=\n"
                } else {
                    ".bash_profile 0=-bash login=y knsh=\n"
                };
                assert!(expected.starts_with(first), "{expected}");
                assert_eq!(expected.contains(".bash_logout"), login, "{expected}");
                assert_eq!(
                    actual,
                    expected,
                    "{} login={login} only_profile={only_profile}",
                    bash.display()
                );
            }
        }
    }
}

// KNSH-020 acceptance (NFR-COMPAT-01): with recording on, the same startup files run in the same order with the
// same $0 and login state as under plain bash. A non-login shell's .bashrc sees no knsh variable; after the first
// prompt no command sees any, nor an exported PROMPT_COMMAND.
#[test]
fn startup_trace_matches_plain_bash_while_recording() {
    let _serial = serial();
    for bash in bashes() {
        for login in [true, false] {
            let tmp = TempDir::new("on");
            let home = tmp.path("home");
            let trace = tmp.path("trace");
            write_all_rcs(&home, &trace);
            let script = format!(
                "echo \"typed $(env | grep -c '^KNSH_') $(export -p | grep -c PROMPT_COMMAND)\" >> '{}'\nexit 0\n",
                trace.display()
            );

            let plain = plain_bash(&bash, &home, login, &script);
            let expected = read(&trace);
            fs::remove_file(&trace).expect("reset trace");
            let (sink, _receiver) = ChannelSink::new(None);
            let recorded = run_recorded(&bash, &home, login, Box::new(sink), &script);
            let actual = read(&trace);

            assert_eq!(plain.status.code(), Some(0));
            assert_eq!(recorded.status.code(), Some(0), "{}", recorded.stderr);
            assert_no_hook_noise(&recorded.stderr);
            assert!(expected.contains("typed 0 0\n"), "{expected}");
            if login {
                assert_eq!(
                    without_knsh_field(&actual),
                    without_knsh_field(&expected),
                    "{}",
                    bash.display()
                );
                assert!(
                    actual.contains("typed 0 0\n"),
                    "variables gone by the first command: {actual}"
                );
            } else {
                assert_eq!(actual, expected, "{}", bash.display());
            }
        }
    }
}

// FR-SES-21 / KNSH-020 acceptance: one started and one finished line per command line typed, with the line as
// typed, its directory and its status; nothing for the hooks' own commands, nothing for an empty line, one report
// for a line of several commands or a pipeline, and lines that run no simple command in the shell itself (a
// subshell, a function definition) are reported too.
#[test]
fn recorded_session_reports_each_line_once() {
    let _serial = serial();
    for bash in bashes() {
        for login in [false, true] {
            let tmp = TempDir::new("lines");
            let home = tmp.path("home");
            fs::create_dir_all(&home).expect("home");
            let home_text = home.to_str().expect("utf-8 home");
            let script = format!(
                concat!(
                    "true\n",
                    "false\n",
                    "echo a; echo b | cat; x=1\n",
                    "\n",
                    "cd '{home}'\n",
                    "( cd / )\n",
                    "f() {{ :; }}\n",
                    "for i in 1 2; do :; done\n",
                    "printf '%s\\n' $'tab\\there'\n",
                    "cd /\n",
                    "exit 3\n",
                ),
                home = home_text,
            );
            let (sink, receiver) = ChannelSink::new(None);
            let cwd = std::env::current_dir().expect("cwd");
            let cwd = cwd.to_str().expect("utf-8 cwd");
            let recorded = run_recorded(&bash, &home, login, Box::new(sink), &script);

            assert_eq!(recorded.status.code(), Some(3), "{}", recorded.stderr);
            assert_no_hook_noise(&recorded.stderr);
            assert_eq!(recorded.stdout, "a\nb\ntab\there\n");
            let lines: Vec<_> = receiver.try_iter().collect();
            let cd_home = format!("cd '{home_text}'");
            let expected = [
                started(cwd, "true"),
                finished(0, cwd),
                started(cwd, "false"),
                finished(1, cwd),
                started(cwd, "echo a; echo b | cat; x=1"),
                finished(0, cwd),
                started(cwd, &cd_home),
                finished(0, home_text),
                started(home_text, "( cd / )"),
                finished(0, home_text),
                started(home_text, "f() { :; }"),
                finished(0, home_text),
                started(home_text, "for i in 1 2; do :; done"),
                finished(0, home_text),
                started(home_text, "printf '%s\\n' $'tab\\there'"),
                finished(0, home_text),
                started(home_text, "cd /"),
                finished(0, "/"),
                started("/", "exit 3"),
            ];
            assert_eq!(lines, expected, "{} login={login}", bash.display());
        }
    }
}

// KNSH-020: a line that never reaches history (a leading blank with HISTCONTROL=ignorespace, a repeat with
// ignoredups) is still reported, from the command bash is about to run or the repeated entry.
#[test]
fn lines_missing_from_history_are_still_reported() {
    let _serial = serial();
    for bash in bashes() {
        let tmp = TempDir::new("histcontrol");
        let home = tmp.path("home");
        write_rc(&home, ".bashrc", &tmp.path("trace"), "HISTCONTROL=ignoreboth");
        let (sink, receiver) = ChannelSink::new(None);
        let cwd = std::env::current_dir().expect("cwd");
        let cwd = cwd.to_str().expect("utf-8 cwd");
        let script = "echo one | cat\necho one | cat\n echo hidden\nexit 0\n";
        let recorded = run_recorded(&bash, &home, false, Box::new(sink), script);

        assert_eq!(recorded.status.code(), Some(0), "{}", recorded.stderr);
        assert_no_hook_noise(&recorded.stderr);
        let lines: Vec<_> = receiver.try_iter().collect();
        assert_eq!(
            lines,
            [
                started(cwd, "echo one | cat"),
                finished(0, cwd),
                started(cwd, "echo one | cat"),
                finished(0, cwd),
                started(cwd, "echo hidden"),
                finished(0, cwd),
                started(cwd, "exit 0"),
            ],
            "{}",
            bash.display()
        );
    }
}

/// A prompt that shows `$?` and `PIPESTATUS`.
const STATUS_PS1: &str = "PS1='<ps $? ${PIPESTATUS[*]}>'";

/// A `PROMPT_COMMAND` of the user's that records `$?` and `PIPESTATUS`, and a DEBUG trap of the user's that counts
/// commands.
fn user_hooks(trace: &Path) -> String {
    format!(
        concat!(
            "PROMPT_COMMAND=\"${{PROMPT_COMMAND:+$PROMPT_COMMAND; }}echo \\\"pc \\$? \\${{PIPESTATUS[*]}}\\\" >> '{trace}'\"\n",
            "trap 'udbg=$((udbg+1))' DEBUG\n",
        ),
        trace = trace.display()
    )
}

/// The prompts in `stderr`: the text of every `<ps …>`.
fn prompts(stderr: &str) -> Vec<String> {
    stderr
        .split("<ps ")
        .skip(1)
        .map(|rest| rest.split('>').next().unwrap_or_default().to_owned())
        .collect()
}

/// Lines that set statuses and pipelines in every interesting shape.
const STATUS_SCRIPT: &str = concat!(
    "true\n",
    "false\n",
    "(exit 4) | (exit 5)\n",
    "echo \"next line sees ${PIPESTATUS[*]}\"\n",
    "false | true | (exit 7)\n",
    "! false\n",
    "! true | true\n",
    "(exit 1) | (exit 2) | (exit 3) | (exit 4) | (exit 5) | (exit 6) | (exit 0)\n",
    "\n",
    "(exit 130)\n",
    "echo \"udbg ran: $(( ${udbg:-0} > 0 ))\"\n",
    "exit 0\n",
);

/// The non-empty lines of [`STATUS_SCRIPT`].
const STATUS_LINES: usize = 11;

// KNSH-020 acceptance ("Hook failures ... never change $? seen by the user's prompt"; integration test "verify $?
// and PIPESTATUS are unchanged at the prompt"): the prompt shows the same $? and PIPESTATUS as under plain bash,
// after single commands, pipelines, negations and long pipelines, and so does the next line. Login (bootstrap) and
// non-login (--rcfile).
#[test]
fn status_and_pipestatus_at_the_prompt_match_plain_bash() {
    let _serial = serial();
    for bash in bashes() {
        for login in [false, true] {
            let tmp = TempDir::new("status");
            let home = tmp.path("home");
            let rc = if login { ".bash_profile" } else { ".bashrc" };
            write_rc(&home, rc, &tmp.path("trace"), STATUS_PS1);

            let plain = plain_bash(&bash, &home, login, STATUS_SCRIPT);
            let (sink, receiver) = ChannelSink::new(None);
            let recorded = run_recorded(&bash, &home, login, Box::new(sink), STATUS_SCRIPT);

            assert_eq!(recorded.status.code(), Some(0), "{}", recorded.stderr);
            assert_no_hook_noise(&recorded.stderr);
            let expected = prompts(&text(&plain.stderr));
            for shown in ["1 1", "5 4 5", "7 1 0 7", "0 1", "1 0 0", "0 1 2 3 4 5 6 0", "130 130"] {
                assert!(
                    expected.contains(&shown.to_owned()),
                    "plain bash shows {shown}: {expected:?}"
                );
            }
            assert_eq!(prompts(&recorded.stderr), expected, "{} login={login}", bash.display());
            assert_eq!(recorded.stdout, text(&plain.stdout));
            assert!(recorded.stdout.contains("next line sees 4 5\n"), "{}", recorded.stdout);
            let lines: Vec<_> = receiver.try_iter().collect();
            assert_eq!(lines.len(), 2 * STATUS_LINES - 1, "{lines:?}");
        }
    }
}

// KNSH-020 acceptance ("Existing PROMPT_COMMAND (string ...) and DEBUG traps of the user still run"): the user's
// PROMPT_COMMAND runs at every prompt and sees the same $? and PIPESTATUS as under plain bash (bash 3.2's own DEBUG
// trap handling included), the user's DEBUG trap still runs, and the prompt is unchanged. In the login case the
// user's trap makes bash 3.2 undo ours at the end of the bootstrap, so it is set at the next prompt.
#[test]
fn user_prompt_command_and_debug_trap_still_run() {
    let _serial = serial();
    for bash in bashes() {
        for login in [false, true] {
            let tmp = TempDir::new("userhooks");
            let home = tmp.path("home");
            let trace = tmp.path("trace");
            let rc = if login { ".bash_profile" } else { ".bashrc" };
            write_rc(&home, rc, &trace, &format!("{STATUS_PS1}\n{}", user_hooks(&trace)));

            let plain = plain_bash(&bash, &home, login, STATUS_SCRIPT);
            let expected_trace = read(&trace);
            fs::remove_file(&trace).expect("reset trace");
            let (sink, receiver) = ChannelSink::new(None);
            let recorded = run_recorded(&bash, &home, login, Box::new(sink), STATUS_SCRIPT);
            let actual_trace = read(&trace);

            assert_eq!(recorded.status.code(), Some(0), "{}", recorded.stderr);
            assert_no_hook_noise(&recorded.stderr);
            assert_eq!(
                expected_trace.matches("\npc ").count(),
                STATUS_LINES + 1,
                "{expected_trace}"
            );
            assert_eq!(
                without_knsh_field(&actual_trace),
                without_knsh_field(&expected_trace),
                "{} login={login}",
                bash.display()
            );
            assert_eq!(
                prompts(&recorded.stderr),
                prompts(&text(&plain.stderr)),
                "{} login={login}",
                bash.display()
            );
            assert_eq!(recorded.stdout, text(&plain.stdout));
            assert!(recorded.stdout.contains("udbg ran: 1\n"), "{}", recorded.stdout);
            let lines: Vec<_> = receiver.try_iter().collect();
            assert_eq!(lines.len(), 2 * STATUS_LINES - 1, "{lines:?}");
            let cwd = std::env::current_dir().expect("cwd");
            assert!(lines.contains(&finished(130, cwd.to_str().expect("cwd"))), "{lines:?}");
        }
    }
}

// KNSH-020 acceptance: an array PROMPT_COMMAND (bash 5.1+) keeps all its entries, run in order around ours.
#[test]
fn array_prompt_command_entries_still_run() {
    let _serial = serial();
    let mut covered = false;
    for bash in bashes() {
        if version(&bash) < (5, 1) {
            continue;
        }
        covered = true;
        let tmp = TempDir::new("array");
        let home = tmp.path("home");
        let trace = tmp.path("trace");
        let extra = format!(
            "PROMPT_COMMAND=('echo \"a $?\" >> {trace}' 'echo \"b ${{PIPESTATUS[*]}}\" >> {trace}')",
            trace = trace.display()
        );
        write_rc(&home, ".bashrc", &trace, &extra);
        let script = "false\n(exit 2) | (exit 3)\nexit 0\n";
        let plain = plain_bash(&bash, &home, false, script);
        let expected = read(&trace);
        fs::remove_file(&trace).expect("reset trace");
        let (sink, receiver) = ChannelSink::new(None);
        let recorded = run_recorded(&bash, &home, false, Box::new(sink), script);

        assert_eq!(plain.status.code(), Some(0));
        assert_eq!(recorded.status.code(), Some(0), "{}", recorded.stderr);
        assert_no_hook_noise(&recorded.stderr);
        assert!(expected.contains("a 1\n"), "{expected}");
        assert_eq!(read(&trace), expected, "{}", bash.display());
        assert_eq!(receiver.try_iter().count(), 5);
    }
    if !covered {
        eprintln!("note: no bash 5.1+ installed; array PROMPT_COMMAND not covered (pending)");
    }
}

// KNSH-020: a bash started by a startup file inherits the login bootstrap but sends nothing, and the startup files
// that append to PROMPT_COMMAND after the bootstrap keep working; the first line typed is still reported.
#[test]
fn nested_bash_in_a_startup_file_sends_nothing() {
    let _serial = serial();
    for bash in bashes() {
        let tmp = TempDir::new("nested");
        let home = tmp.path("home");
        let trace = tmp.path("trace");
        let extra = format!(
            concat!(
                "'{bash}' -i <<< 'echo nested >> {trace}' 2>/dev/null\n",
                "PROMPT_COMMAND=\"$PROMPT_COMMAND; echo appended >> {trace}\"\n",
            ),
            bash = bash.display(),
            trace = trace.display()
        );
        write_rc(&home, ".bash_profile", &trace, &extra);
        let (sink, receiver) = ChannelSink::new(None);
        let cwd = std::env::current_dir().expect("cwd");
        let cwd = cwd.to_str().expect("utf-8 cwd");
        let recorded = run_recorded(&bash, &home, true, Box::new(sink), "true\nfalse\nexit 0\n");

        assert_eq!(recorded.status.code(), Some(0), "{}", recorded.stderr);
        assert_no_hook_noise(&recorded.stderr);
        let trace_text = read(&trace);
        assert!(trace_text.contains("nested\n"), "{trace_text}");
        assert_eq!(trace_text.matches("appended\n").count(), 3, "{trace_text}");
        let lines: Vec<_> = receiver.try_iter().collect();
        assert_eq!(
            lines,
            [
                started(cwd, "true"),
                finished(0, cwd),
                started(cwd, "false"),
                finished(1, cwd),
                started(cwd, "exit 0"),
            ],
            "{}",
            bash.display()
        );
    }
}

// KNSH-020 acceptance ("Hook failures are silent"): when the forwarder stops reading and closes its end, or stalls,
// or the user closes the descriptor and a file reuses its number, the hooks print nothing, never delay the prompt,
// never kill the shell (interactive bash dies of SIGPIPE) and never write into the user's file.
#[test]
fn closed_stalled_or_reused_descriptor_is_silent_and_harmless() {
    let _serial = serial();
    for bash in bashes() {
        // Forwarder gone after one line.
        let tmp = TempDir::new("closed");
        let home = tmp.path("home");
        fs::create_dir_all(&home).expect("home");
        let mut script = (0..50)
            .map(|index| format!("echo {index}"))
            .collect::<Vec<_>>()
            .join("\n");
        script.push('\n');
        script.push_str("exit 5\n");
        let (sink, receiver) = ChannelSink::new(Some(1));
        let recorded = run_recorded(&bash, &home, false, Box::new(sink), &script);
        assert_eq!(
            recorded.status.code(),
            Some(5),
            "the shell survived: {}",
            recorded.stderr
        );
        assert_no_hook_noise(&recorded.stderr);
        assert_eq!(receiver.try_iter().count(), 1);
        assert!(
            recorded.elapsed < Duration::from_secs(20),
            "took {:?}",
            recorded.elapsed
        );

        // Forwarder stalled: ~4 KiB lines, far more than a pipe holds.
        let filler = "x".repeat(4096);
        let mut script = format!(": {filler}\n").repeat(200);
        script.push_str("exit 6\n");
        let (release, released) = mpsc::channel();
        let recorded = run_recorded(&bash, &home, false, Box::new(StuckSink { release: released }), &script);
        let _ = release.send(());
        assert_eq!(recorded.status.code(), Some(6), "{}", recorded.stderr);
        assert_no_hook_noise(&recorded.stderr);
        assert!(
            recorded.elapsed < Duration::from_secs(60),
            "waited: {:?}",
            recorded.elapsed
        );

        // The user closes the descriptor; a file then takes its number.
        let reused = tmp.path("reused");
        let script = format!(
            concat!(
                // `_knsh_fd` spelt indirectly, so the echoed line does not look like hook output on stderr.
                "v=_kn; v=${{v}}sh_fd; old=${{!v}}; eval \"exec $old>&-\"; eval \"exec $old>'{reused}'\"\n",
                "true\n",
                "false\n",
                "exit 0\n",
            ),
            reused = reused.display()
        );
        let (sink, _receiver) = ChannelSink::new(None);
        let recorded = run_recorded(&bash, &home, false, Box::new(sink), &script);
        assert_eq!(recorded.status.code(), Some(0), "{}", recorded.stderr);
        assert_no_hook_noise(&recorded.stderr);
        assert!(reused.exists());
        assert_eq!(read(&reused), "", "telemetry was written into the user's file");
    }
}

/// Blocks on its first line until released (or a watchdog expires), so the pipe fills behind it.
struct StuckSink {
    release: mpsc::Receiver<()>,
}

impl TelemetrySink for StuckSink {
    fn deliver(&mut self, _line: TelemetryLine) -> Flow {
        let _ = self.release.recv_timeout(Duration::from_secs(90));
        Flow::Continue
    }
}

// FR-SES-22: shells that turn on `set -u` or `set -e`, or `extdebug`, or an ERR trap, are not disturbed by the hooks:
// no error, no exit, no skipped command, no extra ERR.
#[test]
fn strict_shell_options_are_not_disturbed() {
    let _serial = serial();
    for bash in bashes() {
        let tmp = TempDir::new("strict");
        let home = tmp.path("home");
        let trace = tmp.path("trace");
        let extra = format!("set -u\ntrap 'echo err >> {}' ERR\nshopt -s extdebug", trace.display());
        write_rc(&home, ".bashrc", &trace, &extra);
        let script = "false | true\necho ran-1\nfalse && true\necho ran-2\n(exit 3) | (exit 4)\necho ran-3\nexit 0\n";
        let plain = plain_bash(&bash, &home, false, script);
        let expected = read(&trace);
        fs::remove_file(&trace).expect("reset trace");
        let (sink, receiver) = ChannelSink::new(None);
        let recorded = run_recorded(&bash, &home, false, Box::new(sink), script);

        assert_eq!(recorded.status.code(), plain.status.code(), "{}", recorded.stderr);
        assert_no_hook_noise(&recorded.stderr);
        assert_eq!(recorded.stdout, "ran-1\nran-2\nran-3\n");
        assert_eq!(read(&trace), expected, "ERR trap runs as often as in plain bash");
        assert_eq!(receiver.try_iter().count(), 13);
    }
}

// FR-SES-22: a user IFS without a blank (or an empty one) does not break the hooks: no arithmetic error on stderr,
// and the prompt shows the same $? and PIPESTATUS as plain bash.
#[test]
fn unusual_ifs_is_not_disturbed() {
    let _serial = serial();
    for bash in bashes() {
        for (ifs, login) in [(":", false), (":", true), ("$'\\n'", false), ("''", true)] {
            let tmp = TempDir::new("ifs");
            let home = tmp.path("home");
            let rc = if login { ".bash_profile" } else { ".bashrc" };
            write_rc(&home, rc, &tmp.path("trace"), &format!("{STATUS_PS1}\nIFS={ifs}"));
            let script = "false | (exit 3) | true\n(exit 4) | (exit 5)\ntrue\nexit 0\n";

            let plain = plain_bash(&bash, &home, login, script);
            let (sink, receiver) = ChannelSink::new(None);
            let recorded = run_recorded(&bash, &home, login, Box::new(sink), script);

            assert_eq!(recorded.status.code(), Some(0), "{}", recorded.stderr);
            assert_no_hook_noise(&recorded.stderr);
            assert!(!recorded.stderr.contains("((:"), "{}", recorded.stderr);
            assert_eq!(
                prompts(&recorded.stderr),
                prompts(&text(&plain.stderr)),
                "{} IFS={ifs} login={login}",
                bash.display()
            );
            let lines: Vec<_> = receiver.try_iter().collect();
            assert_eq!(lines.len(), 7, "{lines:?}");
        }
    }
}

// FR-SES-22: when the bash `SHELL` names cannot be started, `knsh` starts zsh instead of refusing the shell.
#[test]
fn binary_falls_back_to_zsh_when_bash_is_missing() {
    let _serial = serial();
    let tmp = TempDir::new("missing");
    let home = tmp.path("home");
    fs::create_dir_all(&home).expect("home");
    let output = knsh_binary(
        &tmp.path("gone/bash"),
        &home,
        false,
        "echo \"zsh=${ZSH_NAME-}\"\nexit 4\n",
    );
    assert_eq!(output.status.code(), Some(4), "{}", text(&output.stderr));
    assert_eq!(text(&output.stdout), "zsh=zsh\n");
    assert!(
        text(&output.stderr).contains("starting zsh"),
        "{}",
        text(&output.stderr)
    );
}

// KNSH-020: a recorded bash killed by a signal is reported as such, and its exit status passes through.
#[test]
fn recorded_bash_exit_status_and_signal_pass_through() {
    let _serial = serial();
    for bash in bashes() {
        let tmp = TempDir::new("signal");
        let home = tmp.path("home");
        fs::create_dir_all(&home).expect("home");
        let (sink, _receiver) = ChannelSink::new(None);
        let recorded = run_recorded(&bash, &home, false, Box::new(sink), "kill -KILL $$\n");
        assert_eq!(recorded.status.signal(), Some(9));
        let (sink, _receiver) = ChannelSink::new(None);
        let recorded = run_recorded(&bash, &home, true, Box::new(sink), "exit 42\n");
        assert_eq!(recorded.status.code(), Some(42));
    }
}

// KNSH-020: `knsh` hosts the bash `SHELL` names, and passes its exit status on; it is the same bash
// (NFR-COMPAT-04: /bin/bash is 3.2 on macOS).
#[test]
fn binary_hosts_the_bash_named_by_shell() {
    let _serial = serial();
    for bash in bashes() {
        let tmp = TempDir::new("binary");
        let home = tmp.path("home");
        fs::create_dir_all(&home).expect("home");
        let output = knsh_binary(&bash, &home, false, "echo \"$BASH ${BASH_VERSINFO[0]}\"\nexit 7\n");
        assert_eq!(output.status.code(), Some(7), "{}", text(&output.stderr));
        let (major, _) = version(&bash);
        assert_eq!(text(&output.stdout), format!("{} {major}\n", bash.display()));
        // Recording is off: no wrapper is installed for bash.
        let paths = EnginePaths::for_home(&home).expect("paths");
        assert!(!paths.bash_startup_dir().exists());
    }
}

#[test]
fn system_bash_is_3_2() {
    // NFR-COMPAT-04 and the story's premise: macOS ships bash 3.2 at /bin/bash.
    assert_eq!(version(Path::new(SYSTEM_BASH)), (3, 2));
}
