//! End-to-end checks of the terminal marks and login shell support (KNSH-022, NFR-COMPAT-10, NFR-COMPAT-08) through
//! the real `knsh` binary, on the real `/bin/zsh` and `/bin/bash`, on a pseudo-terminal.
//!
//! The pseudo-terminal comes from `script(1)` (`script -q /dev/null <command>`), so no test code opens one itself.
//! Lines are typed with pauses so that each reaches the shell at its prompt. Every test uses a temporary `HOME` and a
//! minimal environment, never the user's own.

#![cfg(all(test, target_os = "macos"))]
#![allow(clippy::expect_used, clippy::panic)]

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use knsh::integration::marks;
use knsh_platform::EnginePaths;

/// The `PATH` of the minimal environment.
const TEST_PATH: &str = "/usr/bin:/bin:/usr/sbin:/sbin";

/// How long a test waits for the shell to finish before failing.
const TIMEOUT: Duration = Duration::from_secs(20);

/// The pause before each typed line.
const TYPING_PAUSE: Duration = Duration::from_millis(400);

/// A temporary home, removed when dropped.
struct Home(PathBuf);

impl Home {
    fn new(name: &str) -> Self {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = PathBuf::from(format!("/private/tmp/knshterm-{name}-{}-{n}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("home");
        Self(dir)
    }

    /// Writes `text` as the user's `config.toml`.
    fn write_config(&self, text: &str) {
        let paths = EnginePaths::for_home(&self.0).expect("paths");
        fs::create_dir_all(paths.config_dir()).expect("config dir");
        fs::write(paths.config_file(), text).expect("config");
    }

    /// A directory inside the home whose name needs percent-encoding.
    fn odd_dir(&self) -> PathBuf {
        let dir = self.0.join("a b é#");
        fs::create_dir_all(&dir).expect("odd dir");
        dir
    }
}

impl Drop for Home {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// What a session on the pseudo-terminal printed.
struct Session {
    /// Everything the terminal received.
    terminal: Vec<u8>,
}

/// Runs `shell_command` (run by `/bin/zsh -c`, so `exec -a` can set `argv[0]`) on a pseudo-terminal with `home` as
/// `HOME`, typing `lines` one by one.
fn on_terminal(home: &Home, env: &[(&str, &str)], shell_command: &str, lines: &[&str]) -> Session {
    let mut command = Command::new("/usr/bin/script");
    command
        .args(["-q", "/dev/null", "/bin/zsh", "-fc", shell_command])
        .env_clear()
        .env("HOME", &home.0)
        .env("PATH", TEST_PATH)
        .env("TERM", "xterm-256color")
        // bash 3.2's line editor drops non-ASCII input in the C locale.
        .env("LANG", "en_US.UTF-8")
        .env("BASH_SILENCE_DEPRECATION_WARNING", "1")
        .current_dir(&home.0)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    for (name, value) in env {
        command.env(name, value);
    }
    let mut child = command.spawn().expect("spawn script");
    let mut stdin = child.stdin.take().expect("stdin");
    let typed: Vec<String> = lines.iter().map(|line| format!("{line}\n")).collect();
    // Typed on a thread; standard input stays open until the shell has exited, as at a real terminal.
    let typist = thread::spawn(move || {
        for line in typed {
            thread::sleep(TYPING_PAUSE);
            if stdin.write_all(line.as_bytes()).is_err() {
                return stdin;
            }
        }
        stdin
    });
    let mut stdout = child.stdout.take().expect("stdout");
    let reader = thread::spawn(move || {
        let mut terminal = Vec::new();
        let _ = std::io::Read::read_to_end(&mut stdout, &mut terminal);
        terminal
    });
    let deadline = Instant::now() + TIMEOUT;
    loop {
        if child.try_wait().expect("wait").is_some() {
            break;
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!("the session did not end in time");
        }
        thread::sleep(Duration::from_millis(20));
    }
    drop(typist.join());
    Session {
        terminal: reader.join().expect("reader"),
    }
}

/// `knsh` itself, quoted for `zsh -c`.
fn knsh_exe() -> String {
    format!("'{}'", env!("CARGO_BIN_EXE_knsh"))
}

/// The marks in `bytes`, in order: OSC 133 as its letter and parameters (`A`, `D;0`), OSC 7 as `7:<url>`.
fn marks_in(bytes: &[u8]) -> Vec<String> {
    let mut found = Vec::new();
    let mut rest = bytes;
    while let Some(start) = find(rest, b"\x1b]") {
        rest = &rest[start + 2..];
        let Some(end) = rest.iter().position(|&byte| byte == 0x07) else {
            break;
        };
        let body = String::from_utf8_lossy(&rest[..end]).into_owned();
        if let Some(mark) = body.strip_prefix("133;") {
            found.push(mark.to_owned());
        } else if let Some(url) = body.strip_prefix("7;") {
            found.push(format!("7:{url}"));
        }
        rest = &rest[end + 1..];
    }
    found
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|window| window == needle)
}

/// This machine's host name, as both shells report it.
fn host_name() -> String {
    let output = Command::new("/bin/hostname").output().expect("hostname");
    String::from_utf8(output.stdout).expect("utf-8").trim().to_owned()
}

/// The OSC 7 URL for `path`, as [`marks::working_directory`] writes it.
fn url(path: &Path) -> String {
    use std::os::unix::ffi::OsStrExt;

    let sequence = marks::working_directory(host_name().as_bytes(), path.as_os_str().as_bytes());
    let url = sequence
        .strip_prefix("\x1b]7;")
        .and_then(|rest| rest.strip_suffix('\x07'))
        .expect("osc 7");
    format!("7:{url}")
}

/// The hosted shells, as `(name, extra environment)`.
fn shells() -> [(&'static str, Vec<(&'static str, &'static str)>); 2] {
    [("zsh", vec![]), ("bash", vec![("SHELL", "/bin/bash")])]
}

/// Checks the marks of the lines `cd <odd dir>`, `true`, `false` and `exit`: on start OSC 7 for the home,
/// then for each line A, B, C, D;<status>, then OSC 7 (the new directory after `cd`), in that order.
fn assert_marks_for_lines(home: &Home, session: &Session, label: &str) {
    let odd = home.odd_dir();
    let found = marks_in(&session.terminal);
    let start = url(&home.0);
    let moved = url(&odd);
    let expected = [
        start.as_str(),
        "A",
        "B",
        "C",
        "D;0",
        moved.as_str(),
        "A",
        "B",
        "C",
        "D;0",
        moved.as_str(),
        "A",
        "B",
        "C",
        "D;1",
        moved.as_str(),
        "A",
        "B",
        "C",
    ];
    assert_eq!(
        found,
        expected,
        "{label}: {}",
        String::from_utf8_lossy(&session.terminal)
    );
}

// KNSH-022 test `osc133_sequence_order_for_one_command` (NFR-COMPAT-10): OSC 133 A, B, C and D;<exit> come in that
// order for every line, with OSC 7 (percent-encoded, as `marks` encodes it) on start and after each directory
// change, for zsh and bash, whether or not recording is on. Recording on without a reachable knshd only drops the
// telemetry (NFR-REL-02).
#[test]
fn osc133_sequence_order_for_one_command() {
    for recording in [false, true] {
        for (name, env) in shells() {
            let home = Home::new(name);
            let odd = home.odd_dir();
            home.write_config(&format!("[recording]\nhuman = {recording}\n"));
            let cd = format!("cd '{}'", odd.display());
            let session = on_terminal(
                &home,
                &env,
                &format!("exec {} -i", knsh_exe()),
                &[&cd, "true", "false", "exit"],
            );
            assert_marks_for_lines(&home, &session, &format!("{name}, recording {recording}"));
        }
    }
}

// KNSH-022 test `login_invocation_starts_hosted_shell_as_login` (NFR-COMPAT-08): `knsh` started as `-knsh` (as
// login(1) and terminals start a login shell), or with `-l`, starts the hosted shell as a login shell, with the
// marks; when `$SHELL` names knsh itself (knsh is the login shell), the hosted shell comes from `[shell] hosted`.
#[test]
fn login_invocation_starts_hosted_shell_as_login() {
    let knsh = env!("CARGO_BIN_EXE_knsh");
    let probes = [
        ("zsh", "[[ -o login ]] && echo LOGIN-zsh-$0"),
        ("bash", "shopt -q login_shell && echo LOGIN-bash-$0"),
    ];
    for (name, probe) in probes {
        for invocation in [
            format!("exec -a -knsh {}", knsh_exe()),
            format!("exec {} -l", knsh_exe()),
        ] {
            let home = Home::new(name);
            home.write_config(&format!("[shell]\nhosted = \"{name}\"\n"));
            let session = on_terminal(&home, &[("SHELL", knsh)], &invocation, &[probe, "exit"]);
            let text = String::from_utf8_lossy(&session.terminal);
            assert!(
                text.contains(&format!("LOGIN-{name}--{name}")),
                "{name} via {invocation}: {text}"
            );
            let found = marks_in(&session.terminal);
            assert!(
                found.starts_with(&[url(&home.0), "A".to_owned(), "B".to_owned(), "C".to_owned()]),
                "{name} via {invocation}: {found:?}"
            );
        }
    }
}

// KNSH-022 test `invalid_hosted_shell_falls_back_to_zsh` end to end: a hosted shell that cannot be used starts
// /bin/zsh with a warning, never no shell.
#[test]
fn invalid_hosted_shell_starts_zsh_with_a_warning() {
    for setting in ["hosted = \"fish\"", "hosted = \"/opt/nowhere/bash\""] {
        let home = Home::new("invalid");
        home.write_config(&format!("[shell]\n{setting}\n"));
        let session = on_terminal(
            &home,
            &[("SHELL", env!("CARGO_BIN_EXE_knsh"))],
            &format!("exec {} -i", knsh_exe()),
            &["echo SHELL-IS-$ZSH_VERSION", "exit"],
        );
        let text = String::from_utf8_lossy(&session.terminal);
        assert!(text.contains("starting /bin/zsh"), "{setting}: {text}");
        assert!(text.contains("SHELL-IS-5."), "{setting}: {text}");
    }
}

// KNSH-022 test `no_sequences_when_not_a_tty`: with knsh's standard output redirected away from the terminal, no
// mark reaches the terminal or the file, for zsh and bash, recorded or not.
#[test]
fn no_sequences_when_not_a_tty() {
    for recording in [false, true] {
        for (name, env) in shells() {
            let home = Home::new(name);
            home.write_config(&format!("[recording]\nhuman = {recording}\n"));
            let out = home.0.join("stdout.txt");
            let session = on_terminal(
                &home,
                &env,
                &format!("{} -i > '{}'", knsh_exe(), out.display()),
                &["echo hello", "cd /tmp", "exit"],
            );
            let file = fs::read(&out).expect("stdout file");
            assert!(String::from_utf8_lossy(&file).contains("hello"), "{name}");
            for bytes in [&file, &session.terminal] {
                assert_eq!(
                    marks_in(bytes),
                    Vec::<String>::new(),
                    "{name}, recording {recording}: {}",
                    String::from_utf8_lossy(bytes)
                );
            }
        }
    }
}

// KNSH-022: a prompt the user's own hooks set each time (zsh `precmd`, bash `PROMPT_COMMAND`) still ends with
// OSC 133 B: the marks' hooks run after the user's. In zsh a hook added by `.zshrc` runs after the wrapper's on the
// first prompt only, so that prompt may lack B; from the second prompt on the marks' hooks have moved last.
#[test]
fn prompt_set_by_user_hooks_is_still_marked() {
    let cases = [
        (
            ".zshrc",
            "_my_prompt() { PS1='custom> ' }\nprecmd_functions+=(_my_prompt)\n",
            vec![],
        ),
        (
            ".bashrc",
            "PROMPT_COMMAND='PS1=\"custom> \"'\n",
            vec![("SHELL", "/bin/bash")],
        ),
    ];
    for (rc, body, env) in cases {
        let home = Home::new("prompt");
        fs::write(home.0.join(rc), body).expect("rc");
        let session = on_terminal(
            &home,
            &env,
            &format!("exec {} -i", knsh_exe()),
            &["true", "false", "exit"],
        );
        let text = String::from_utf8_lossy(&session.terminal).into_owned();
        assert!(text.contains("custom> "), "{rc}: {text}");
        let found = marks_in(&session.terminal);
        let start = url(&home.0);
        let tail = [
            "C",
            "D;0",
            start.as_str(),
            "A",
            "B",
            "C",
            "D;1",
            start.as_str(),
            "A",
            "B",
            "C",
        ];
        assert!(found.ends_with(&tail.map(str::to_owned)), "{rc}: {found:?}");
        // The user's prompt text is unchanged apart from the mark.
        assert!(text.contains("custom> \x1b]133;B\x07"), "{rc}: {text:?}");
    }
}
