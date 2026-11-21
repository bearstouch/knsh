//! KNSH-096 to KNSH-100 integration tests: scripts run under the native interpreter (real processes
//! through `SystemProcesses`, real lookups and directory listings through `RealFs`, the system's collation) and under
//! `/bin/bash`; standard output and exit status must match (NFR-COMPAT-01, NFR-COMPAT-02).
//!
//! The first script uses only what KNSH-096 evaluates: literal words, external commands and the builtins that run as
//! their programs (`echo`, `printf`, `test`, `true`, `false`). The second exercises parameter and arithmetic
//! expansion (KNSH-097), the third brace expansion, word splitting, pathname expansion and quote removal (KNSH-098),
//! with forms bash 3.2 (the `/bin/bash` here) and 5.2 agree on; the glob options are compared one by one, and the
//! order of matches in the C and UTF-8 locales. Each run gets its own temporary directory as working directory and a
//! fixed `PATH`.

#![cfg(target_os = "macos")]
#![allow(clippy::unwrap_used)]

use std::ffi::OsString;
use std::io::Read;
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use knsh_interp::{Interpreter, ShellOptions, ShellState};
use knsh_platform::macos::{RealFs, SystemCollation, SystemDescriptors, SystemProcesses, SystemUserHomes};
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
    run_bash_full(script, dir, args, &[], &[])
}

/// Runs `script` under `/bin/bash flags… -c script knsh args…` in `dir` with `PATH` and `env`: (stdout, status).
fn run_bash_full(script: &str, dir: &Path, args: &[&str], flags: &[&str], env: &[(&str, &str)]) -> (String, u8) {
    let output = Command::new("/bin/bash")
        .args(flags)
        .arg("-c")
        .arg(script)
        .arg("knsh")
        .args(args)
        .current_dir(dir)
        .env_clear()
        .env("PATH", PATH)
        .envs(env.iter().copied())
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
    run_knsh_full(script, dir, args, |_| {}, &[], 0o022)
}

/// Runs `script` under the native interpreter in `dir` with positional parameters `args`, the options `options`
/// sets (the line parsed with `extglob` when it is on) and `PATH` and `env` in the environment: (stdout, status).
fn run_knsh_full(
    script: &str,
    dir: &Path,
    args: &[&str],
    options: impl FnOnce(&mut ShellOptions),
    env: &[(&str, &str)],
    umask: u32,
) -> (String, u8) {
    let (mut reader, writer) = std::io::pipe().unwrap();
    let null = || SharedFd::new(OwnedFd::from(std::fs::File::open("/dev/null").unwrap()));
    // KNSH-100: what the shell writes to standard output itself (`jobs`) goes into the same pipe as its commands'.
    let own_output = std::fs::File::from(OwnedFd::from(writer.try_clone().unwrap()));
    let stdio = Stdio::Passed(Box::new([null(), SharedFd::new(OwnedFd::from(writer)), null()]));
    let spawner = ProcessCommandSpawner::new(Arc::new(SystemProcesses::new()), stdio);
    let environment = std::iter::once(("PATH", PATH))
        .chain(env.iter().copied())
        .map(|(name, value)| (OsString::from(name), OsString::from(value)));
    let mut state = ShellState::new("knsh", dir)
        .unwrap()
        .with_environment(environment)
        .with_positional(args.iter().map(|arg| (*arg).to_owned()).collect())
        .with_umask(umask);
    options(state.options_mut());
    let extglob = state.options().extglob;
    let mut interpreter = Interpreter::new(
        state,
        Arc::new(RealFs::new()),
        Arc::new(spawner),
        Arc::new(SystemUserHomes::new()),
        Arc::new(SystemCollation::new()),
        Arc::new(SystemDescriptors::new()),
        Box::new(std::io::sink()),
    )
    .with_output(Box::new(own_output));
    let parsed = knsh_bash::parse_with(script, knsh_bash::ParseOptions::default().with_extglob(extglob)).unwrap();
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
    // `kill 0` signals the caller's own process group. Without job control a command stays in the shell's group, as
    // in bash (KNSH-100), where it would kill the test runner too; under `set -m` it leads a group of its own, so
    // only the command dies. Compared against the documented value.
    let knsh = run_knsh_full(script, &dir, &[], |options| options.monitor = true, &[], 0o022);
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

/// Brace expansion, word splitting, pathname expansion and quote removal in forms bash 3.2 and 5.2 agree on (no
/// `{01..03}` or `{1..9..2}`, which bash 3.2 lacks, no `.*`, which bash 3.2 matches against `.` and `..`, and no `?`
/// against a multibyte name in the C locale, where bash matches bytes). `printf '[%s]'` shows word boundaries.
const WORDS: &str = r#"touch B a _x 'a b' Zed .hid c.rs d.rs 'e f.rs' é
mkdir -p dir/sub dir/.h
touch dir/f.rs dir/sub/g.rs dir/.h/i.rs
printf '[%s]' {a,b}{1,2} x{a,b,}y {1..4} {c..a} {5..1} {-1..2} {a} {} '{a,b}' \{a,b} {a,'b c'} {a,{b,c}d}e; echo
n=2; a1=one; a2=two; printf '[%s]' {1..$n} $a{1,2} ~/{x,y} a={b,c}; echo
v='  one  two	three  '
printf '[%s]' $v; echo
printf '[%s]' "$v" x$v"y"; echo
IFS=:; w='a::b:'; printf '[%s]' $w x$w; echo
IFS=': '; m=' a : b  ::c '; printf '[%s]' $m; echo
IFS=; printf '[%s]' $v; echo
IFS=' '; e=; printf '[%s]' $e "" ""$v $v"" "$e"; echo
IFS=1; printf '[%s]' $((11 + 1)) x$((10 + 1))y; echo
IFS='*?'; g='a*b'; printf '[%s]' $g * *.rs ?; echo
IFS=$' \t\n'
printf '[%s]' *; echo
printf '[%s]' *.rs dir/*.rs */*.rs */ d*/s*/; echo
printf '[%s]' *.zig 'a'* [ab]* [!a-z]* \*.rs "*".rs [[:upper:]]*; echo
g='*.rs'; s='e f'; printf '[%s]' $g "$g" $s*; echo
printf '[%s]' .h* dir/.h* dir/*/; echo
printf '[%s]' $'a\tb' $'\x41\101' $'it\'s'; echo
for f in *.rs; do printf '<%s>' "$f"; done; echo
case 'a b' in a\ *) echo escaped-pattern;; esac
"#;

// NFR-COMPAT-02 (KNSH-098): brace expansion, splitting, globbing and quote removal match bash.
#[test]
fn words_script_matches_bash() {
    let bash_dir = temp_dir("bash-words");
    let knsh_dir = temp_dir("knsh-words");
    let home = [("HOME", "/Users/nobody-knsh")];
    let bash = run_bash_full(WORDS, &bash_dir, &[], &[], &home);
    let knsh = run_knsh_full(WORDS, &knsh_dir, &[], |_| {}, &home, 0o022);
    std::fs::remove_dir_all(&bash_dir).unwrap();
    std::fs::remove_dir_all(&knsh_dir).unwrap();
    assert!(bash.0.contains("escaped-pattern"), "bash output: {}", bash.0);
    assert_eq!(knsh, bash);
}

/// One script per glob option, run with the option on in both shells.
const OPTION_SCRIPTS: &[(&str, &str)] = &[
    ("dotglob", "printf '[%s]' * dir/*; echo"),
    (
        "nullglob",
        "printf '[%s]' x *.zig y *.rs; echo; for f in *.zig; do echo never; done; echo done",
    ),
    (
        "failglob",
        "echo before; printf '[%s]' *.zig; echo same-line\necho next-line $?",
    ),
    ("nocaseglob", "printf '[%s]' b* Z* [a-c]*; echo"),
    (
        "extglob",
        "printf '[%s]' !(*.rs) @(a|B) +([a-z]).rs *(x)a ?(d).rs; echo; p=main.test.rs; printf '[%s]' ${p%%.+([a-z])} ${p##+([a-z]).}; case $p in *.@(rs|c)) echo ext;; esac",
    ),
];

// NFR-COMPAT-02 (KNSH-098): each glob option bash 3.2 and 5.2 share behaves as bash's.
#[test]
fn glob_options_match_bash() {
    let setup = "touch B a .hid c.rs d.rs; mkdir dir; touch dir/.x dir/y\n";
    for (option, script) in OPTION_SCRIPTS {
        let script = format!("{setup}{script}\n");
        let bash_dir = temp_dir("bash-option");
        let knsh_dir = temp_dir("knsh-option");
        let bash = run_bash_full(&script, &bash_dir, &[], &["-O", option], &[]);
        let knsh = run_knsh_full(
            &script,
            &knsh_dir,
            &[],
            |options| match *option {
                "dotglob" => options.dotglob = true,
                "nullglob" => options.nullglob = true,
                "failglob" => options.failglob = true,
                "nocaseglob" => options.nocaseglob = true,
                "extglob" => options.extglob = true,
                other => panic!("{other}"),
            },
            &[],
            0o022,
        );
        std::fs::remove_dir_all(&bash_dir).unwrap();
        std::fs::remove_dir_all(&knsh_dir).unwrap();
        assert_eq!(knsh, bash, "{option}: {script}");
    }
}

// NFR-COMPAT-02 (KNSH-098): matches are sorted as bash sorts them (`strcoll`) in the C locale and the UTF-8 locales.
#[test]
fn glob_order_matches_bash_in_c_and_utf8_locales() {
    let script = "touch B a _x 'a b' Zed '#h' '~t' 0 ' sp' é Ab-x\nprintf '[%s]' *; echo\n";
    for locale in ["C", "C.UTF-8", "en_US.UTF-8"] {
        let env = [("LANG", locale)];
        let bash_dir = temp_dir("bash-order");
        let knsh_dir = temp_dir("knsh-order");
        let bash = run_bash_full(script, &bash_dir, &[], &[], &env);
        let knsh = run_knsh_full(script, &knsh_dir, &[], |_| {}, &env, 0o022);
        std::fs::remove_dir_all(&bash_dir).unwrap();
        std::fs::remove_dir_all(&knsh_dir).unwrap();
        assert_eq!(knsh, bash, "LANG={locale}");
    }
}

/// Redirections in forms bash 3.2 and 5.2 agree on (no `{name}>`, `&>>` or `|&`, which bash 3.2 lacks, and no
/// unquoted expansion in a here-string, which bash 3.2 splits and bash 4.4 and later do not), with real files and
/// processes. `/bin/ls /dev/fd` shows exactly which descriptors a command receives.
const REDIRECTIONS: &str = r#"echo one >out; cat out
echo two >>out; cat out
echo err 2>&1 >/dev/null
echo swapped 3>&1 1>&2 2>&3 3>&- 2>/dev/null
{ echo g1; echo g2; } >grp; cat grp
cat <out
if true; then echo in-if; fi >ifout; cat ifout
for i in 1 2; do echo "$i"; done >loop; cat loop
exec 3>fd3; echo three >&3; /bin/cat /dev/fd/3 </dev/null 2>/dev/null; exec 3>&-; cat fd3
/bin/ls /dev/fd/; exec 4>f4; /bin/ls /dev/fd/; exec 4>&-; /bin/ls /dev/fd/
exec 6>&1; exec >redirected; echo hidden; exec >&6 6>&-; cat redirected
cat <<< "here  string"
y='v  w'; cat <<<"$y"
exec 5<out; cat <&5; exec 5<&-
echo moved 6>&1 7>&6- >&7
echo hi >&5 || echo bad-fd
cat <missing || echo missing
x='a b'; echo ambiguous >$x || echo ambiguous
: >empty; cat empty; echo "empty $?"
echo both &>both; cat both
echo dup >&dupfile; cat dupfile
echo rw 1<>rw; cat rw
echo a >/dev/stdout
cat /dev/fd/0 <out
echo end
"#;

// NFR-COMPAT-02, KNSH-099: redirections, `exec` and the descriptors a command receives match bash.
#[test]
fn redirection_script_matches_bash() {
    let bash_dir = temp_dir("bash-redirect");
    let knsh_dir = temp_dir("knsh-redirect");
    let bash = run_bash(REDIRECTIONS, &bash_dir);
    let knsh = run_knsh(REDIRECTIONS, &knsh_dir);
    std::fs::remove_dir_all(&bash_dir).unwrap();
    std::fs::remove_dir_all(&knsh_dir).unwrap();
    assert!(bash.0.contains("here  string\nv  w\n"), "bash output: {}", bash.0);
    assert!(bash.0.contains("0\n1\n2\n3\n4\n"), "bash output: {}", bash.0);
    assert_eq!(knsh, bash);
}

// NFR-COMPAT-02, KNSH-099: under `set -C` (`bash -C`), `>` refuses an existing file and `>|` overrides it.
#[test]
fn noclobber_matches_bash() {
    let script = "echo a >f; echo b >f || echo refused; cat f; echo c >|f; cat f; echo d >/dev/null && echo null-ok\n";
    let bash_dir = temp_dir("bash-noclobber");
    let knsh_dir = temp_dir("knsh-noclobber");
    let bash = run_bash_full(script, &bash_dir, &[], &["-C"], &[]);
    let knsh = run_knsh_full(script, &knsh_dir, &[], |options| options.noclobber = true, &[], 0o022);
    std::fs::remove_dir_all(&bash_dir).unwrap();
    std::fs::remove_dir_all(&knsh_dir).unwrap();
    assert_eq!(bash.0, "refused\na\nc\nnull-ok\n");
    assert_eq!(knsh, bash);
}

/// Pipelines, `PIPESTATUS`, subshells, background jobs and `wait` (KNSH-100), in forms bash 3.2 and 5.2 agree on.
/// `yes | head` checks that no copy of a pipe's read end is left open in the shell: `yes` must die of `SIGPIPE`.
const PIPELINES: &str = r#"printf 'a\nb\nc\n' | /usr/bin/sort -r
printf 'x y\n' | /usr/bin/tr ' ' '\n' | /usr/bin/wc -l | /usr/bin/tr -d ' '
false | true; echo "${PIPESTATUS[@]}" $?
true | false; echo "$PIPESTATUS" "${#PIPESTATUS[@]}" "${PIPESTATUS[1]}" "${PIPESTATUS[*]}"
! false | false; echo $? "${PIPESTATUS[@]}"
{ false | true; }; echo "${PIPESTATUS[@]}"
( /bin/sh -c 'exit 3' ); echo "${PIPESTATUS[@]}" $?
false; /bin/sleep 0 & echo "${PIPESTATUS[@]}"
(( 0 )); echo "${PIPESTATUS[@]}"
v=1; ( v=2; echo "in $v" ); echo "out $v"
x=1 | x=2; echo "x=$x"
echo grouped | { /bin/cat; echo after-cat; }
{ echo one; echo two; } | /usr/bin/sort -r
( echo sub-a; echo sub-b ) | /usr/bin/tail -n 1
if true; then echo in-if; fi | /usr/bin/tr a-z A-Z
for w in p q; do echo "$w"; done | /usr/bin/sort -r
echo upper | /usr/bin/tr a-z A-Z > out.txt; /bin/cat out.txt
/usr/bin/yes | /usr/bin/head -n 2; echo "${PIPESTATUS[@]}"
( echo to-stderr >&2 ) 2>&1 | /usr/bin/tr a-z A-Z
/bin/sleep 0.1 & wait $!; echo "waited $?"
/bin/sh -c 'exit 4' & p=$!; wait $p; echo "status $?"
/bin/sh -c 'exit 6' & /bin/sh -c 'exit 7' & wait; echo "all $?"
/bin/sh -c 'exit 2' | /bin/sh -c 'exit 5' & wait $!; echo "last $?"
/bin/echo bg-out & wait
wait 999999; echo "notchild $?"
/bin/sleep 0.3 & jobs; wait; jobs; echo jobs-done
w=1 & wait; echo "w=${w-unset}"
false && echo no & wait; echo after-list
"#;

// NFR-COMPAT-02, KNSH-100: pipelines, PIPESTATUS, subshells, `&` and `wait` match bash with real processes and pipes.
#[test]
fn pipeline_script_matches_bash() {
    let bash_dir = temp_dir("bash-pipes");
    let knsh_dir = temp_dir("knsh-pipes");
    let bash = run_bash(PIPELINES, &bash_dir);
    let knsh = run_knsh(PIPELINES, &knsh_dir);
    std::fs::remove_dir_all(&bash_dir).unwrap();
    std::fs::remove_dir_all(&knsh_dir).unwrap();
    assert!(bash.0.contains("141 0\n"), "bash output: {}", bash.0);
    assert!(
        bash.0.contains("[1]+  Running                 /bin/sleep 0.3 &\n"),
        "bash output: {}",
        bash.0
    );
    assert_eq!(knsh, bash);
}

// NFR-COMPAT-02, KNSH-100: under `set -o pipefail` a pipeline's status is its last failing command's.
#[test]
fn pipefail_matches_bash() {
    let script = "false | true; echo $?; true | false | true; echo $?; (/bin/sh -c 'exit 2') | (/bin/sh -c 'exit 3') | true; echo $?; \
                  true | true; echo $?; ! false | true; echo $?\n";
    let bash_dir = temp_dir("bash-pipefail");
    let knsh_dir = temp_dir("knsh-pipefail");
    let bash = run_bash_full(script, &bash_dir, &[], &["-o", "pipefail"], &[]);
    let knsh = run_knsh_full(script, &knsh_dir, &[], |options| options.pipefail = true, &[], 0o022);
    std::fs::remove_dir_all(&bash_dir).unwrap();
    std::fs::remove_dir_all(&knsh_dir).unwrap();
    assert_eq!(bash.0, "1\n1\n3\n0\n0\n");
    assert_eq!(knsh, bash);
}

/// The core builtins (KNSH-101) in forms bash 3.2 (`/bin/bash` here) and 5.2 agree on. Directories are printed
/// relative to the run's own temporary directory, `$base`. Left out because 3.2 differs from 5.2, which the
/// interpreter follows: `type -t` of a name not found (5.2: status 1), `return` outside a sourced file (5.2: 2),
/// `exit abc` (5.2: 2), `echo -e '\e'`, and usage errors (5.2: 2).
const BUILTINS: &str = r#"base=$PWD
export -p | sed "s|$base|BASE|"
echo -e 'a\tb\x41\0101'; echo -n x; echo; echo -ne 'y\cz'; echo; echo 'a\nb' -E -n; echo -e -n; echo -- -n
x=1; export y="a\"b\$c"; declare -p x y; declare -rx z=2; declare -p z
declare -i n=3+4; n+=2; echo $n; declare -p n
set -- a 'b c' d; shift; echo $# "$1"; shift 5; echo $?
set x y; echo "$*"; set --; echo $#
for i in 1 2 3; do for j in a b; do continue 2; done; echo no; done; echo $i
while :; do while :; do break 2; done; echo no; done; echo broke
for i in 1 2; do (break); echo $i; done
for ((k = 0; k < 3; k++)); do continue; done; echo $k
readonly r=1; r=2 /bin/echo temp; unset r; echo $?
unset nosuch; echo $?; unset 1a; echo $?
type cd if ls; type -t cd if ls; echo $?; type nosuch; echo $?
command -v cd ls if nosuch; echo $?; command -V cd ls if
hash; ls >/dev/null; hash; hash -t ls; hash -r; hash
mkdir -p d/sub; cd d; echo "${PWD#$base}" "${OLDPWD#$base}"; cd sub; cd ..; echo "${PWD#$base}"
cd "$base"; ln -s d link; cd link; echo "${PWD#$base}"; pwd -P | sed "s|^$base||"; cd -P .; echo "${PWD#$base}"
cd "$base"; CDPATH=/nowhere:$base/d; cd sub > "$base/cdout"; echo "${PWD#$base}"; sed "s|^$base||" "$base/cdout"
unset CDPATH; cd - >/dev/null; echo "${PWD#$base}"; cd /nonexistent; echo $?
umask 077; umask; umask -S; umask -p; touch f; ls -l f | cut -c1-10; umask u=rwx,g=rx,o=; umask; umask 022
eval 'echo "$#"'; eval "w=5"; echo $w; eval ''; echo $?
printf 'echo sourced $#\nreturn 3\necho never\n' > inc.sh; . ./inc.sh a b; echo $? $#
alias ll='ls -l'; alias q="it's"; alias; alias ll; unalias ll; alias; type -t q; echo $?
x=hi eval 'echo $x'; echo "[$x]"
exec /bin/echo bye
echo never
"#;

/// The umask this process runs with, as `/bin/sh` reports it: what both shells inherit.
fn inherited_umask() -> u32 {
    let output = Command::new("/bin/sh").arg("-c").arg("umask").output().unwrap();
    u32::from_str_radix(String::from_utf8(output.stdout).unwrap().trim(), 8).unwrap()
}

// NFR-COMPAT-02, KNSH-101: the core builtins' output and statuses match bash.
#[test]
fn builtin_script_matches_bash() {
    let bash_dir = temp_dir("bash-builtins");
    let knsh_dir = temp_dir("knsh-builtins");
    let bash = run_bash(BUILTINS, &bash_dir);
    let umask = inherited_umask();
    let knsh = run_knsh_full(BUILTINS, &knsh_dir, &[], |_| {}, &[], umask);
    std::fs::remove_dir_all(&bash_dir).unwrap();
    std::fs::remove_dir_all(&knsh_dir).unwrap();
    assert!(bash.0.ends_with("[1]\nbye\n"), "bash output: {}", bash.0);
    assert_eq!(knsh.0, bash.0);
    assert_eq!(knsh, bash);
}
