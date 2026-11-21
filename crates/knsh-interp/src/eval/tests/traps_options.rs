//! Traps, signals, `set` and `shopt` over the fake filesystem (KNSH-104; NFR-COMPAT-02). Outputs were checked
//! against bash 3.2 (`/bin/bash` here) where it agrees with bash 5.2; where they differ the case follows bash 5.2's
//! source and says so.

use knsh_platform::signals::{SIGINT, SIGQUIT, SIGTERM};

use super::*;

/// Runs `script` and returns its status, what the shell wrote to standard output, and its diagnostics.
fn outcome(script: &str) -> (u8, String, String) {
    let mut h = Harness::new();
    let status = h.status(script);
    (status, h.output.text(), h.diagnostics.text())
}

// KNSH-104 acceptance: `set -e` is ignored in conditions, in `&&` and `||` lists but for their last command, under
// `!`, and in everything run from those (a function called in a condition); it exits on the last command of a list
// (checked against bash 3.2).
#[test]
fn errexit_ignored_in_conditions() {
    let script = "set -e
if false; then echo no; fi
while false; do echo no; done
until true; do echo no; done
false || echo or-ran
false && echo no
! true
! { false; echo in-negation; }
f() { false; echo in-f; }
if f; then echo then; fi
f && echo and
f || echo no
{ false && true; }
for i in 1; do false && true; done
echo before
true && false
echo never";
    let (status, out, err) = outcome(script);
    assert_eq!(
        out, "or-ran\nin-negation\nin-f\nthen\nin-f\nand\nin-f\nbefore\n",
        "{err}"
    );
    assert_eq!(status, 1);
    // A function that fails outside those contexts exits, even when its own last command was exempt.
    let (status, out, _) = outcome("set -e; f() { false && true; }; f; echo never");
    assert_eq!((status, out.as_str()), (1, ""));
    // `[[ … ]]` and `(( … ))` are subject to `set -e` (bash 4.1 and later; bash 3.2 exempts them).
    assert_eq!(outcome("set -e; [[ a == b ]]; echo never").0, 1);
    assert_eq!(outcome("set -e; (( 0 )); echo never").0, 1);
    // `set +e` turns it off; `set -o errexit` on again.
    let (status, out, _) = outcome("set -e; set +e; false; echo after; set -o errexit; false; echo never");
    assert_eq!((status, out.as_str()), (1, "after\n"));
}

// KNSH-104 acceptance: a subshell inherits `set -e` and the exemption of the context it runs in, with or without
// `inherit_errexit` (which bash applies to command substitution only, KNSH-105).
#[test]
fn errexit_in_subshell_respects_inherit_errexit() {
    for option in ["", "shopt -s inherit_errexit; ", "shopt -u inherit_errexit; "] {
        let script =
            format!("{option}set -e; ( false; echo in-sub ) || echo or; echo after; ( false; echo no ); echo never");
        let (status, out, err) = outcome(&script);
        assert_eq!((status, out.as_str()), (1, "in-sub\nafter\n"), "{script}: {err}");
    }
    let (status, out, _) =
        outcome("shopt -s inherit_errexit; shopt -q inherit_errexit && echo on; shopt -p inherit_errexit");
    assert_eq!((status, out.as_str()), (0, "on\nshopt -s inherit_errexit\n"));
    // A background list keeps `set -e` too, and its failure never ends the shell.
    let mut h = Harness::new();
    assert_eq!(h.status("set -e; { false; echo never; } & wait; echo after"), 0);
    assert_eq!(h.output.text(), "after\n");
}

// KNSH-104 acceptance: the `EXIT` trap runs once: at the end of the script, on `exit` (with `$?` the exit status),
// on `set -e`, and on a signal bash runs it for; a trap's `exit` decides the status (checked against bash 3.2).
#[test]
fn exit_trap_runs_once() {
    let (status, out, _) = outcome("trap 'echo bye $?' EXIT; echo hi; false");
    assert_eq!((status, out.as_str()), (1, "hi\nbye 1\n"));
    let (status, out, _) = outcome("trap 'echo bye $?' EXIT; exit 3; echo never");
    assert_eq!((status, out.as_str()), (3, "bye 3\n"));
    let (status, out, _) = outcome("trap 'echo bye; exit 9' EXIT; exit 2");
    assert_eq!((status, out.as_str()), (9, "bye\n"));
    let (status, out, _) = outcome("trap false EXIT; exit 3");
    assert_eq!((status, out.as_str()), (3, ""));
    let (status, out, _) = outcome("set -e; trap 'echo bye' EXIT; false; echo never");
    assert_eq!((status, out.as_str()), (1, "bye\n"));
    let (status, out, _) = outcome("set -e; trap 'false; echo never' EXIT; true");
    assert_eq!((status, out.as_str()), (1, ""));
    // Replaced, it runs the last one set; reset, nothing.
    assert_eq!(outcome("trap 'echo a' EXIT; trap 'echo b' 0").1, "b\n");
    assert_eq!(outcome("trap 'echo a' EXIT; trap - EXIT").1, "");
    // A subshell runs its own, never its parent's.
    let (_, out, _) = outcome("trap 'echo top' EXIT; (echo in); (trap 'echo sub' EXIT; echo in2); echo out");
    assert_eq!(out, "in\nin2\nsub\nout\ntop\n");
    // Once: the interpreter's next run does not run it again.
    let mut h = Harness::new();
    h.run("trap 'echo bye' EXIT").unwrap();
    h.run("echo again").unwrap();
    assert_eq!(h.output.text(), "bye\nagain\n");
    // SIGTERM at its default: the trap runs, the shell ends with 128 + 15 and tells the host the signal.
    let mut h = Harness::new();
    h.interpreter.shell_signals().raise(SIGTERM);
    assert_eq!(h.status("trap 'echo bye $?' EXIT; echo never"), 143);
    assert_eq!(h.output.text(), "bye 0\n");
    assert_eq!(h.interpreter.terminating_signal(), Some(SIGTERM));
    // SIGQUIT at its default ends the shell without the trap, as bash's default action does.
    let mut h = Harness::new();
    h.interpreter.shell_signals().raise(SIGQUIT);
    assert_eq!(h.status("trap 'echo bye' EXIT; echo never"), 131);
    assert_eq!(h.output.text(), "");
    // An interactive shell runs it on `exit`, or when its host finishes it at the end of input.
    let mut h = Harness::with(|interpreter| interpreter.with_job_control(None));
    h.run("trap 'echo bye' EXIT").unwrap();
    h.run("echo still").unwrap();
    assert_eq!(h.interpreter.finish().unwrap(), Status::SUCCESS);
    assert_eq!(h.interpreter.finish().unwrap(), Status::SUCCESS);
    assert_eq!(h.output.text(), "still\nbye\n");
}

// KNSH-104: a signal trap runs after the command running when the signal arrived, `$?` put back after it.
#[test]
fn signal_traps_run_between_commands() {
    let mut h = Harness::new();
    h.interpreter.shell_signals().raise(SIGTERM);
    assert_eq!(h.status("trap 'echo got $?' TERM; false; echo after $?"), 0);
    assert_eq!(h.output.text(), "got 0\nafter 1\n");
    assert_eq!(h.interpreter.terminating_signal(), None);
    // An `exit` in the trap ends the shell, through the `EXIT` trap.
    let mut h = Harness::new();
    h.run("trap 'echo int; exit 5' INT").unwrap();
    h.interpreter.shell_signals().raise(SIGINT);
    assert_eq!(h.status("trap 'echo bye' EXIT; echo never"), 5);
    assert_eq!(h.output.text(), "int\nbye\n");
    // Ignored, it does nothing; a signal ignored by default (SIGWINCH) too.
    let mut h = Harness::new();
    h.interpreter.shell_signals().raise(SIGTERM);
    h.interpreter.shell_signals().raise(28);
    assert_eq!(h.status("trap '' TERM; echo after"), 0);
    assert_eq!(h.output.text(), "after\n");
}

// KNSH-104 acceptance: `ERR` runs where `set -e` would exit, with the failing status; functions inherit it only
// under `set -E` (checked against bash 3.2).
#[test]
fn err_trap_runs_on_failure() {
    let script = "trap 'echo ERR $?' ERR
false
f() { false; echo after; }
f
set -E
f
g() { return 3; }
g
false || true
! false
if false; then :; fi
echo end";
    let (status, out, err) = outcome(script);
    assert_eq!(out, "ERR 1\nafter\nERR 1\nafter\nERR 3\nend\n", "{err}");
    assert_eq!(status, 0);
    // Before `set -e` exits; `$?` after it is the failure's.
    let (status, out, _) = outcome("set -e; trap 'echo ERR $?' ERR; trap 'echo EXIT $?' EXIT; false; echo never");
    assert_eq!((status, out.as_str()), (1, "ERR 1\nEXIT 1\n"));
    let (_, out, _) = outcome("trap 'echo ERR' ERR; false; echo $?");
    assert_eq!(out, "ERR\n1\n");
    // Bash 5.2 runs it after a failing `( … )`, `[[ … ]]` and `(( … ))` too (bash 3.2 does not).
    let (_, out, _) = outcome("trap 'echo ERR' ERR; (false); [[ a == b ]]; (( 0 )); echo end");
    assert_eq!(out, "ERR\nERR\nERR\nend\n");
    // It never runs inside itself.
    assert_eq!(outcome("trap 'echo E; false' ERR; false").1, "E\n");
}

// KNSH-104: `DEBUG` runs before each simple command, `for` iteration, `case`, `[[ … ]]` and `(( … ))`, not inside
// functions without `set -T`, with `$?` of the command before (checked against bash 3.2).
#[test]
fn debug_trap_runs_before_commands() {
    let script = "trap 'echo D$?' DEBUG
for i in 1 2; do :; done
case a in a) ;; esac
[[ a ]]
(( 1 ))
f() { :; }
f
false
true";
    let (_, out, err) = outcome(script);
    assert_eq!(out, "D0\nD0\nD0\nD0\nD0\nD0\nD0\nD0\nD0\nD1\n", "{err}");
    // With `set -T` a function's commands run it too; a function's own trap is kept after it returns.
    let (_, out, _) = outcome("set -T; trap 'echo D' DEBUG; f() { :; }; f");
    assert_eq!(out, "D\nD\nD\n");
    let (_, out, _) = outcome("f() { trap 'echo FD' DEBUG; :; }; f; :; trap -p DEBUG");
    assert_eq!(out, "FD\nFD\nFD\ntrap -- 'echo FD' DEBUG\n");
}

// KNSH-104: `RETURN` runs as a function or sourced file returns: a function inherits it only under `set -T`; a trap
// a function sets is its own, and the caller's comes back after (bash 5.2: unless the function set one).
#[test]
fn return_trap_runs_as_functions_return() {
    let mut h = Harness::new();
    h.fs.write(Path::new("/work/lib.sh"), b"echo sourced\n", 0o644).unwrap();
    let script = "trap 'echo R $?' RETURN
f() { echo in-f; return 4; }
f
set -T
f
set +T
. ./lib.sh
g() { trap 'echo G' RETURN; echo in-g; }
g";
    h.run(script).unwrap();
    assert_eq!(
        h.output.text(),
        "in-f\nin-f\nR 4\nsourced\nR 0\nin-g\nG\n",
        "{}",
        h.diagnostics.text()
    );
    // Bash 5.2's `trap_if_untrapped`: the function's own trap stays (bash 3.2 puts the caller's back).
    h.run("trap -p RETURN").unwrap();
    assert!(h.output.text().ends_with("trap -- 'echo G' RETURN\n"));
}

// KNSH-104 acceptance: `set -x` writes each command after expansion behind `PS4`, expanded, its first character
// repeated for each `eval` or `source` level; words are quoted as bash's trace quotes them (checked against bash
// 3.2).
#[test]
fn xtrace_uses_ps4() {
    let script = r#"set -x
a=1 b="x y" true
c=
echo "a b" '' "it's" '$x' a~ \#x x#
x=a
[[ $x == "b c" && -n $x ]]
[[ ! -n "" ]]
(( 1 + 2 ))
for i in 1; do :; done
case $x in *) ;; esac
eval "echo hi"
PS4='[$x] '
echo there
PS4='++\\ '
echo more
PS4=
echo bare
set +x
echo off"#;
    let (status, out, err) = outcome(script);
    assert_eq!(status, 0);
    assert_eq!(out, "a b  it's $x a~ #x x#\nhi\nthere\nmore\nbare\noff\n");
    assert_eq!(
        err,
        "+ a=1\n+ b='x y'\n+ true\n+ c=\n+ echo 'a b' '' 'it'\\''s' '$x' a~ '#x' x#\n+ x=a\n\
         + [[ a == \\b\\ \\c ]]\n+ [[ ! -n '' ]]\n+ ((  1 + 2  ))\n+ for i in 1\n+ :\n+ case $x in\n\
         + eval 'echo hi'\n++ echo hi\n+ PS4='[$x] '\n[a] echo there\n[a] PS4='++\\\\ '\n++\\ echo more\n\
         ++\\ PS4=\necho bare\nset +x\n"
    );
    // Prompt escapes needing the user, host or directory are refused.
    let mut h = Harness::new();
    assert_eq!(refused(h.run("PS4='\\w '; set -x; :")), Unsupported::PromptExpansion);
    // A list assignment's trace differs between bash versions: refused while tracing.
    let mut h = Harness::new();
    assert_eq!(refused(h.run("set -x; a=(1 2)")), Unsupported::Trap);
}

// KNSH-104 acceptance: signals ignored when the shell started stay ignored: `trap` neither traps nor resets them,
// commands inherit them ignored, and the shell does not act on them.
#[test]
fn ignored_signal_at_entry_stays_ignored() {
    let mut h = Harness::new();
    h.on("tool", &[exited(0)]);
    let ignored: knsh_platform::SignalSet = [SIGINT].into_iter().collect();
    let state = std::mem::replace(h.interpreter.state_mut(), ShellState::new("x", "/").unwrap());
    *h.interpreter.state_mut() = state.with_ignored_signals(ignored);
    h.interpreter.shell_signals().raise(SIGINT);
    assert_eq!(
        h.status("trap 'echo int' INT; tool; trap - INT; tool; echo survived"),
        0
    );
    assert_eq!(h.output.text(), "survived\n");
    let options = h.commands.options();
    assert!(options.iter().all(|options| options.ignore.contains(SIGINT)));
    // `trap -p` would list it: bash 3.2 leaves it out, 5.2 prints it, so listing it is refused.
    assert_eq!(refused(h.run("trap -p INT")), Unsupported::Trap);
}

// KNSH-104: `trap ''` makes commands start with the signal ignored; `trap -` gives them its default again.
#[test]
fn ignored_traps_reach_commands() {
    let mut h = Harness::new();
    h.on("tool", &[exited(0)]);
    h.status("trap '' TERM; tool; trap 'echo x' TERM; tool; trap - TERM; tool");
    let options = h.commands.options();
    assert!(options[0].ignore.contains(SIGTERM));
    assert!(!options[1].ignore.contains(SIGTERM));
    assert!(!options[2].ignore.contains(SIGTERM));
}

// KNSH-104: `trap` lists, prints and changes traps as bash 5.2 does; errors are bash's.
#[test]
fn trap_lists_and_changes_traps_like_bash() {
    let (status, out, err) = outcome(
        "trap 'echo exit' EXIT; trap \"echo \\\"it's\\\"\" INT; trap '' QUIT; trap 'x' ERR; trap; trap -p INT TERM; trap 2; trap -p",
    );
    assert_eq!(status, 0, "{err}");
    assert_eq!(
        out,
        "trap -- 'echo exit' EXIT\ntrap -- 'echo \"it'\\''s\"' SIGINT\ntrap -- '' SIGQUIT\ntrap -- 'x' ERR\n\
         trap -- 'echo \"it'\\''s\"' SIGINT\n\
         trap -- 'echo exit' EXIT\ntrap -- '' SIGQUIT\ntrap -- 'x' ERR\nexit\n"
    );
    let (status, out, err) = outcome("trap 'echo a' sigint SIGEXIT bogus 99; echo $?; trap -p SIGINT");
    assert_eq!(status, 0);
    assert_eq!(out, "1\ntrap -- 'echo a' SIGINT\n");
    assert_eq!(
        err,
        "knsh: line 1: trap: SIGEXIT: invalid signal specification\n\
         knsh: line 1: trap: bogus: invalid signal specification\n\
         knsh: line 1: trap: 99: invalid signal specification\n"
    );
    let (status, _, err) = outcome("trap -- -");
    assert_eq!(
        (status, err.as_str()),
        (2, "trap: usage: trap [-lp] [[arg] signal_spec ...]\n")
    );
    let (status, _, err) = outcome("trap -x");
    assert_eq!(status, 2);
    assert!(err.starts_with("knsh: line 1: trap: -x: invalid option\n"));
    let (_, out, _) = outcome("trap -l");
    assert!(out.starts_with(" 1) SIGHUP\t 2) SIGINT\t 3) SIGQUIT\t 4) SIGILL\t 5) SIGTRAP\n"));
    // A subshell keeps ignored signals and drops command traps.
    assert_eq!(outcome("trap '' TERM; (trap)").1, "trap -- '' SIGTERM\n");
    // Bash 5.2 still lists the parent's command traps in a subshell until it changes one: refused.
    let mut h = Harness::new();
    assert_eq!(refused(h.run("trap 'echo a' INT; (trap)")), Unsupported::Trap);
    assert_eq!(h.status("trap 'echo a' INT; (trap '' TERM; trap)"), 0);
}

// KNSH-104: `set` turns options on and off as bash 5.2 reads its arguments; `$-` and `set -o` report them.
#[test]
fn set_changes_and_lists_options_like_bash() {
    let (status, out, err) = outcome(
        "set -o errexit -o pipefail; echo $-; set -eu +e; echo $-; set +u; set -- a b; set -e -- x y; echo $1 $#; \
         set -; echo $1 $-; set -x - z; echo $1 $-; set -o pipefail extra; echo $1; set +o nounset nounset; echo $1",
    );
    assert_eq!(status, 0, "{err}");
    assert_eq!(out, "ehBc\nhuBc\nx 2\nx ehBc\nz ehBc\nextra\nnounset\n");
    let (status, out, err) = outcome("set -o bogus; echo $?");
    assert_eq!((status, out.as_str()), (0, "1\n"));
    assert_eq!(err, "knsh: line 1: set: bogus: invalid option name\n");
    let (status, _, err) = outcome("set -q");
    assert_eq!(status, 2);
    assert_eq!(
        err,
        "knsh: line 1: set: -q: invalid option\n\
         set: usage: set [-abefhkmnptuvxBCEHPT] [-o option-name] [--] [-] [arg ...]\n"
    );
    let (_, out, _) = outcome("set -e; set -o");
    assert!(out.starts_with("allexport      \toff\nbraceexpand    \ton\nemacs          \toff\nerrexit        \ton\n"));
    assert!(out.contains("\ninteractive-comments\ton\n"));
    let (_, out, _) = outcome("set +o");
    assert!(out.starts_with("set +o allexport\nset -o braceexpand\n"));
    assert!(out.ends_with("set +o vi\nset +o xtrace\n"));
    // Options the interpreter holds as bash's defaults can be set to them; changing them is refused.
    assert_eq!(outcome("set -h -B; echo ok").1, "ok\n");
    let mut h = Harness::new();
    assert_eq!(refused(h.run("x=+h; set $x")), Unsupported::ShellOption);
    assert_eq!(h.status("[ -o errexit ] || [ -o hashall ]"), 0);
}

// KNSH-104 unit test named in the story: an unknown `shopt` option is bash's error, status 1, and the others named
// still change.
#[test]
fn shopt_unknown_option_is_error() {
    let (status, out, err) =
        outcome("shopt -s bogus extglob; echo $?; shopt -q extglob && echo on; shopt bogus; echo $?");
    assert_eq!(status, 0);
    assert_eq!(out, "1\non\n1\n");
    assert_eq!(
        err,
        "knsh: line 1: shopt: bogus: invalid shell option name\n\
         knsh: line 1: shopt: bogus: invalid shell option name\n"
    );
    let (status, _, err) = outcome("shopt -os bogus");
    assert_eq!(
        (status, err.as_str()),
        (1, "knsh: line 1: shopt: bogus: invalid option name\n")
    );
    let (status, _, err) = outcome("shopt -x");
    assert_eq!(status, 2);
    assert!(err.ends_with("shopt: usage: shopt [-pqsu] [-o] [optname ...]\n"));
    let (status, _, err) = outcome("shopt -s -u x");
    assert_eq!(
        (status, err.as_str()),
        (
            1,
            "knsh: line 1: shopt: cannot set and unset shell options simultaneously\n"
        )
    );
}

// KNSH-104: `shopt` lists and changes the options in scope (checked against bash 3.2 for the format).
#[test]
fn shopt_lists_and_changes_options() {
    let (status, out, _) = outcome(
        "shopt extglob nullglob; echo $?; shopt -s nullglob dotglob globstar failglob nocaseglob lastpipe xpg_echo \
         expand_aliases; shopt -p nullglob extglob; shopt -po errexit; shopt -so errexit; echo $-; shopt -u xpg_echo",
    );
    assert_eq!(status, 0);
    assert_eq!(
        out,
        "extglob        \toff\nnullglob       \toff\n1\nshopt -s nullglob\nshopt -u extglob\nset +o errexit\nehBc\n"
    );
    let (_, out, _) = outcome("shopt -s xpg_echo; echo 'a\\tb'");
    assert_eq!(out, "a\tb\n");
    let (_, out, _) = outcome("shopt");
    assert!(out.starts_with("assoc_expand_once\toff\nautocd         \toff\n"));
    assert!(out.ends_with("xpg_echo       \toff\n"));
    let (_, out, _) = outcome("shopt -s");
    assert!(out.starts_with("checkwinsize   \ton\ncmdhist        \ton\n"));
}

// KNSH-104: `set -n` reads but runs nothing more; `set -v` writes each line as it is read (checked against bash
// 3.2).
#[test]
fn noexec_and_verbose_follow_bash() {
    let (status, out, _) = outcome("set -n; echo never\necho never2");
    assert_eq!((status, out.as_str()), (0, ""));
    let (_, out, err) = outcome("set -v; echo a\necho b; echo c\n# note\nif true; then\n  echo d\nfi\neval 'echo e'");
    assert_eq!(out, "a\nb\nc\nd\ne\n");
    assert_eq!(
        err,
        "echo b; echo c\n# note\nif true; then\n  echo d\nfi\neval 'echo e'\necho e\n"
    );
}

// KNSH-104 (review): a subshell started from a trap is still inside that trap, as bash's forked subshell keeps the
// trap's in-progress mark: an inherited `DEBUG` or `ERR` does not run again in it, so the trap does not recurse
// (checked against bash 3.2).
#[test]
fn traps_do_not_recurse_through_subshells() {
    let (status, out, err) = outcome("set -T; trap '(echo d)' DEBUG; echo x");
    assert_eq!((status, out.as_str()), (0, "d\nx\n"), "{err}");
    let (status, out, err) = outcome("set -E; trap '(false); echo e' ERR; false; echo x");
    assert_eq!((status, out.as_str()), (0, "e\nx\n"), "{err}");
}

// KNSH-104 (review): a trap's commands are subject to `set -e` and `ERR` even when the trap fires inside a condition
// or an `&&` operand, as bash's trap text never carries the condition's exemption (checked against bash 3.2).
#[test]
fn errexit_applies_inside_traps_fired_in_conditions() {
    let (status, out, _) = outcome("set -e; trap 'false; echo t' DEBUG; if true; then echo in; fi; echo after");
    assert_eq!((status, out.as_str()), (1, ""));
    let (status, out, _) = outcome("trap 'echo E' ERR; trap 'false' DEBUG; if true; then echo in; fi");
    assert_eq!((status, out.as_str()), (0, "E\nE\nin\n"));
    // The exemption is back once the trap ends.
    let (status, out, _) = outcome("set -e; trap 'true' DEBUG; if false; then :; fi; false || echo or; echo after");
    assert_eq!((status, out.as_str()), (0, "or\nafter\n"));
}

// KNSH-104 (review): bash's `set` checks every option letter before it changes any, so an invalid one leaves the
// options as they were (checked against bash 3.2).
#[test]
fn set_with_an_invalid_letter_changes_nothing() {
    let (status, out, err) = outcome("set -e -q; false; echo after $-");
    assert_eq!((status, out.as_str()), (0, "after hBc\n"), "{err}");
    assert!(err.starts_with("knsh: line 1: set: -q: invalid option\n"));
    let (status, out, _) = outcome("set -eq; echo $?; set -o -q; echo $- $#");
    assert_eq!((status, out.as_str()), (0, "2\nhBc 0\n"));
    // `-o` takes the next word as its name, which is not checked as letters.
    let (status, out, _) = outcome("set -o pipefail -u; echo $-; shopt -po pipefail");
    assert_eq!((status, out.as_str()), (0, "huBc\nset -o pipefail\n"));
}
