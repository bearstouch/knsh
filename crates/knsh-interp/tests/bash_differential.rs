//! KNSH-096 and KNSH-097 integration tests: scripts run under the native interpreter (real processes through
//! `SystemProcesses`, real lookups through `RealFs`) and under `/bin/bash`; standard output and exit status must match
//! (NFR-COMPAT-01, NFR-COMPAT-02).
//!
//! The first script uses only what KNSH-096 evaluates: literal words, external commands and the builtins that run as
//! their programs (`echo`, `printf`, `test`, `true`, `false`). The second exercises parameter and arithmetic
//! expansion (KNSH-097) with forms bash 3.2 (the `/bin/bash` here) and 5.2 agree on. Each run gets its own temporary
//! directory as working directory and a fixed `PATH`.

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
use knsh_platform::macos::{RealFs, SystemProcesses, SystemUserHomes};
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
    run_bash_with(script, dir, &[])
}

/// Runs `script` under `/bin/bash -c script knsh args…` in `dir`: (stdout, status).
fn run_bash_with(script: &str, dir: &Path, args: &[&str]) -> (String, u8) {
    let output = Command::new("/bin/bash")
        .arg("-c")
        .arg(script)
        .arg("knsh")
        .args(args)
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
    run_knsh_with(script, dir, &[])
}

/// Runs `script` under the native interpreter in `dir` with positional parameters `args`: (stdout, status).
fn run_knsh_with(script: &str, dir: &Path, args: &[&str]) -> (String, u8) {
    let (mut reader, writer) = std::io::pipe().unwrap();
    let null = || SharedFd::new(OwnedFd::from(std::fs::File::open("/dev/null").unwrap()));
    let stdio = Stdio::Passed(Box::new([null(), SharedFd::new(OwnedFd::from(writer)), null()]));
    let spawner = ProcessCommandSpawner::new(Arc::new(SystemProcesses::new()), stdio);
    let state = ShellState::new("knsh", dir)
        .unwrap()
        .with_environment([(OsString::from("PATH"), OsString::from(PATH))])
        .with_positional(args.iter().map(|arg| (*arg).to_owned()).collect());
    let mut interpreter = Interpreter::new(
        state,
        Arc::new(RealFs::new()),
        Arc::new(spawner),
        Arc::new(SystemUserHomes::new()),
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

/// Parameter and arithmetic expansion in forms bash 3.2 and 5.2 agree on; `printf '[%s]'` shows word boundaries.
const EXPANSIONS: &str = r#"printf '[%s]\n' "$@"
printf '[%s]\n' "$*" "$#" "${#}" "$0"
printf '[%s]\n' x"$@"y
x=hello; y=
printf '[%s]\n' "$x" ${x} "${x:-d}" "${y:-d}" "${y-d}" "${z-unset}" "${x:+alt}" "${y:+alt}" "${y+set}"
printf '[%s]\n' "${#x}" "${x#h*l}" "${x##h*l}" "${x%l*}" "${x%%l*}"
p=/usr/local/lib/file.tar.gz
printf '[%s]\n' "${p##*/}" "${p%/*}" "${p#*.}" "${p%%.*}" "${p/lib/LIB}" "${p//l/L}" "${p/%gz/bz2}"
printf '[%s]\n' "${x:1}" "${x:1:3}" "${x: -2}" "${x:10}" "${@:2}" "${@:1:1}"
name=x; printf '[%s]\n' "${!name}"
printf '[%s]\n' $((1 + 2 * 3)) $((2 ** 10)) $(( (5 > 3) && 1 )) $((0x10 + 010 + 2#11)) $((7 / 2)) $((-7 % 3))
n=5; printf '[%s]\n' $((n * 2)) $((n += 1)) "$n" $((n++)) "$n"
(( n > 3 )) && echo gt
(( 0 )) || echo zero-is-false
let 'm = 4 * 2' && printf '[%s]\n' "$m"
for ((i = 0; i < 3; i++)); do printf '%s,' "$i"; done; echo
a=b; b=7; printf '[%s]\n' $((a + 1))
u=$y; printf '[%s]\n' "${u:=assigned}" "$u"
printf '[%s]\n' ~ ~/x
case "$p" in *.gz) echo gz;; esac
v=abc; case b in *"$v"*) echo no;; [$v]) echo in-class;; esac
w=; printf '[%s]\n' $w x $w ""$w
false; printf '[%s]\n' "$?"
echo $((1/0)); echo same-line-skipped
echo next-line-runs "$?"
(( n == 0 ))
"#;

// NFR-COMPAT-02: parameter and arithmetic expansion match bash, including `"$@"` boundaries, a discarded line after
// an arithmetic error and `(( ))` statuses.
#[test]
fn expansion_script_matches_bash() {
    let args = ["a b", "", "c"];
    let bash_dir = temp_dir("bash-expand");
    let knsh_dir = temp_dir("knsh-expand");
    let bash = run_bash_with(EXPANSIONS, &bash_dir, &args);
    let knsh = run_knsh_with(EXPANSIONS, &knsh_dir, &args);
    std::fs::remove_dir_all(&bash_dir).unwrap();
    std::fs::remove_dir_all(&knsh_dir).unwrap();
    assert!(bash.0.contains("next-line-runs 1"), "bash output: {}", bash.0);
    assert_eq!(bash.1, 1);
    assert_eq!(knsh, bash);
}
