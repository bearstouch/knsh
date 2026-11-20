//! KNSH-096 integration test: a 50-line script mixing lists, `if`, loops and `case` runs under the native interpreter
//! (real processes through `SystemProcesses`, real lookups through `RealFs`) and under `/bin/bash`; standard output
//! and exit status must match (NFR-COMPAT-01, NFR-COMPAT-02).
//!
//! The script uses only what KNSH-096 evaluates: literal words, external commands and the builtins that run as their
//! programs (`echo`, `printf`, `test`, `true`, `false`). Loop conditions change through a flag file, since variables
//! are not expanded yet. Each run gets its own temporary directory as working directory and a fixed `PATH`.

#![cfg(target_os = "macos")]
#![allow(clippy::unwrap_used)]

use std::ffi::OsString;
use std::io::Read;
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use knsh_interp::{Interpreter, ShellState};
use knsh_platform::macos::{RealFs, SystemProcesses};
use knsh_platform::{ProcessCommandSpawner, SharedFd, Stdio};

/// Fifty lines; the last command fails, so the scripts' status is 1.
const SCRIPT: &str = r#"echo start
true && echo and-ran
false && echo never-and
false || echo or-ran
true || echo never-or
! false && echo negated
! true || echo negated-true
true && false || echo chained
if true; then echo if-true; fi
if false; then echo no; elif true; then echo elif-true; else echo no; fi
if false; then echo no; else echo else-ran; fi
if false; then echo no; fi && echo if-none-is-zero
if test a = b
then
  echo multi-line-no
else
  echo multi-line-else
fi
for w in alpha 'beta gamma' "delta"; do echo item w; done
for w in; do echo never-for; done && echo empty-for-is-zero
for w in a b c; do if test w = w; then printf '%s\n' same; fi; done
touch flag
while test -e flag; do echo while-body; rm flag; done
while false; do echo never-while; done && echo empty-while-is-zero
until test -e flag; do echo until-body; touch flag; done
until true; do echo never-until; done
rm flag
case hello.txt in *.md) echo md;; *.txt) echo txt;; *) echo other;; esac
case x in a|b) echo ab;; [xyz]) echo xyz;; esac
case '*' in \*) echo star;; *) echo not-star;; esac
case none in a) echo a;; esac && echo case-none-is-zero
case 7up in [[:digit:]]*) echo digit-first;; esac
case "a b" in 'a b') echo quoted-subject;; esac
case abc in a?c) echo question;; esac
case abc in [!a]*) echo no;; *) echo negated-bracket;; esac
{ echo group1; echo group2; }
{ false; } || echo group-failed
{ true; false; } && echo never-group
nonexistent_command_zz || echo not-found-handled
./not-a-file || echo no-such-file-handled
printf '%s-%s\n' one two
echo -n no-newline
echo
A=1 B=2
X=prefixed env -i /usr/bin/printf '%s\n' env-ran
if ! test -e flag; then echo flag-gone; fi
for a in 1 2; do for b in x y; do echo nested a b; done; done
echo 'single quoted' "double quoted" back\ slash
echo end
test -e flag
"#;

/// A fresh temporary directory, unique per call.
fn temp_dir(label: &str) -> PathBuf {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    let dir = std::env::temp_dir()
        .canonicalize()
        .unwrap()
        .join(format!("knsh-interp-{label}-{}-{nanos}", std::process::id()));
    std::fs::create_dir(&dir).unwrap();
    dir
}

const PATH: &str = "/usr/bin:/bin";

/// Runs `script` under `/bin/bash -c` in `dir`: (stdout, status).
fn run_bash(script: &str, dir: &Path) -> (String, u8) {
    let output = Command::new("/bin/bash")
        .arg("-c")
        .arg(script)
        .current_dir(dir)
        .env_clear()
        .env("PATH", PATH)
        .output()
        .unwrap();
    let status = u8::try_from(output.status.code().unwrap()).unwrap();
    (String::from_utf8(output.stdout).unwrap(), status)
}

/// Runs `script` under the native interpreter in `dir`: (stdout, status).
fn run_knsh(script: &str, dir: &Path) -> (String, u8) {
    let (mut reader, writer) = std::io::pipe().unwrap();
    let null = || SharedFd::new(OwnedFd::from(std::fs::File::open("/dev/null").unwrap()));
    let stdio = Stdio::Passed(Box::new([null(), SharedFd::new(OwnedFd::from(writer)), null()]));
    let spawner = ProcessCommandSpawner::new(Arc::new(SystemProcesses::new()), stdio);
    let state = ShellState::new("knsh", dir)
        .unwrap()
        .with_environment([(OsString::from("PATH"), OsString::from(PATH))]);
    let mut interpreter = Interpreter::new(
        state,
        Arc::new(RealFs::new()),
        Arc::new(spawner),
        Box::new(std::io::sink()),
    );
    let parsed = knsh_bash::parse(script).unwrap();
    let status = interpreter.run(&parsed, script).unwrap();
    // The interpreter holds the spawner, which holds the pipe's write end: drop it so the read sees end of file.
    drop(interpreter);
    let mut stdout = String::new();
    reader.read_to_string(&mut stdout).unwrap();
    (stdout, status.code())
}

// NFR-COMPAT-01, NFR-COMPAT-02: the native interpreter and bash agree on output and status.
#[test]
fn fifty_line_script_matches_bash() {
    assert_eq!(SCRIPT.lines().count(), 50);
    let bash_dir = temp_dir("bash");
    let knsh_dir = temp_dir("knsh");
    let bash = run_bash(SCRIPT, &bash_dir);
    let knsh = run_knsh(SCRIPT, &knsh_dir);
    std::fs::remove_dir_all(&bash_dir).unwrap();
    std::fs::remove_dir_all(&knsh_dir).unwrap();
    assert!(bash.0.contains("negated-bracket"), "bash output: {}", bash.0);
    assert_eq!(bash.1, 1);
    assert_eq!(knsh, bash);
}

// NFR-COMPAT-01: a command killed by a signal is 128 + n with real processes too.
#[test]
fn signalled_command_is_128_plus_signal() {
    let script = "/bin/kill -9 0\n";
    let dir = temp_dir("signal");
    // `kill 0` signals the caller's own process group: the native spawner puts every command in a new group, so
    // only the command dies. Under bash it would kill bash too, so compare against the documented value instead.
    let knsh = run_knsh(script, &dir);
    std::fs::remove_dir_all(&dir).unwrap();
    assert_eq!(knsh, (String::new(), 137));
}
