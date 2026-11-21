//! Bash's POSIX mode over the fake filesystem (KNSH-106; NFR-COMPAT-02). Expected outputs come from macOS's
//! `/bin/sh` (bash 3.2 in POSIX mode) where it agrees with bash 5.2, and otherwise from bash 5.2's source and its test
//! suite (`errors.right`, `builtins.right`, `func3.sub`, `varenv12.sub`, `tilde.right`, `redir.right`), which each
//! case names.

use std::ffi::OsStr;

use super::*;

/// A harness whose shell is in POSIX mode, as a shell started as `sh` is.
fn posix_harness() -> Harness {
    let mut h = Harness::new();
    h.interpreter.state_mut().set_posix_mode(true);
    h
}

/// Runs `script` in POSIX mode: its status, what the shell wrote to standard output, and its diagnostics.
fn posix(script: &str) -> (u8, String, String) {
    let mut h = posix_harness();
    let status = h.status(script);
    (status, h.output.text(), h.diagnostics.text())
}

/// Runs `script` outside POSIX mode, as [`posix`].
fn plain(script: &str) -> (u8, String, String) {
    let mut h = Harness::new();
    let status = h.status(script);
    (status, h.output.text(), h.diagnostics.text())
}

// KNSH-106 acceptance: a special builtin's usage error (bash's `EX_USAGE`) ends a non-interactive shell with status 2
// in POSIX mode, unless `command` runs it or its status is tested (bash's `special_builtin_failed` check, which
// `CMD_IGNORE_RETURN` skips; errors8.sub, errors.right line 298); outside POSIX mode the script goes on.
#[test]
fn special_builtin_error_is_fatal_in_posix_mode() {
    for script in [
        "set -Q\necho never",
        "set -o notanoption\necho never",
        "export -Q\necho never",
        "readonly -Q\necho never",
        "unset -Q\necho never",
        "trap -Q\necho never",
        "trap 'echo x'\necho never",
        "eval -Q\necho never",
        ".\necho never",
        "return\necho never",
    ] {
        let (status, out, err) = posix(script);
        assert_eq!((status, out.as_str()), (2, ""), "{script}: {err}");
        let (status, out, _) = plain(script);
        assert_eq!((status, out.as_str()), (0, "never\n"), "{script}");
    }
    let (status, out, err) = posix("set -Q");
    assert_eq!(status, 2);
    assert_eq!(out, "");
    assert_eq!(
        err,
        "knsh: line 1: set: -Q: invalid option\nset: usage: set [-abefhkmnptuvxBCEHPT] [-o option-name] [--] [-] \
         [arg ...]\n"
    );
    // `command` takes the special properties away; a tested status is not fatal.
    let (status, out, _) = posix("command set -Q || echo ok 1\ncommand return 16 || echo ok 2\nset -Q || echo tested");
    assert_eq!((status, out.as_str()), (0, "ok 1\nok 2\ntested\n"));
    assert_eq!(posix("if set -Q; then :; fi; ! set -Q; echo after").1, "after\n");
    // A builtin that is not special, or a special builtin failing without a usage error, goes on (`export 1a`
    // without `=` is bash's `any_failed`, not `EX_BADASSIGN`).
    let (status, out, _) = posix("cd /nonexistent\necho one\nshift 5\necho two\nexport 1a\necho three");
    assert_eq!((status, out.as_str()), (0, "one\ntwo\nthree\n"));
    // A redirection error of a special builtin is fatal with status 1 (errors3.sub); of another command it is not.
    let (status, out, err) = posix("exec 9</nonexistent || echo TEST\necho never");
    assert_eq!((status, out.as_str()), (1, ""), "{err}");
    assert_eq!(err, "knsh: line 1: /nonexistent: No such file or directory\n");
    assert_eq!(posix(": > /nonexistent/f\necho never").0, 1);
    assert_eq!(posix("true > /nonexistent/f\necho after").1, "after\n");
    assert_eq!(plain("exec 9</nonexistent || echo TEST").1, "TEST\n");
}

// KNSH-106 acceptance: assignments before a special builtin stay in the shell after it, exported (bash's
// `merge_temporary_env`; builtins.tests `AVAR=foo . ./source1.sub`, ifs.tests `IFS=: export x`); before any other
// command, or through `command`, they last for the command only.
#[test]
fn assignment_before_special_builtin_persists() {
    let mut h = posix_harness();
    h.fs.write(Path::new("/work/source1.sub"), b"echo \"in $AVAR\"\n", 0o644)
        .unwrap();
    h.on("env", &[exited(0)]);
    let script = "x=1 :
echo \"x=$x\"
y=2 true
echo \"y=${y-unset}\"
z=3 command :
echo \"z=${z-unset}\"
AVAR=foo . ./source1.sub
echo \"AVAR=$AVAR\"
IFS=: export w
echo \"IFS=$IFS\"
env";
    assert_eq!(h.status(script), 0, "{}", h.diagnostics.text());
    assert_eq!(h.output.text(), "x=1\ny=unset\nz=unset\nin foo\nAVAR=foo\nIFS=:\n");
    assert!(h.interpreter.state().is_exported("x"));
    let runs = h.commands.runs();
    let env = &runs[0].env;
    assert!(env.iter().any(|(name, value)| name == "x" && value == "1"));
    // Outside POSIX mode they are undone.
    let (_, out, _) = plain("x=1 :\necho \"x=${x-unset}\"");
    assert_eq!(out, "x=unset\n");
    // In a function the visible (local) variable is set (varenv12.sub: bash 5.2 no longer sets the caller's).
    let (_, out, _) = posix("f() { local v=l; v=2 :; echo \"in $v\"; }\nv=g\nf\necho \"out $v\"");
    assert_eq!(out, "in 2\nout g\n");
    // `return` is special too (func3.sub: `var=20 return 5` leaves 20).
    let (_, out, _) = posix("var=0\nfunc() { var=20 return 5; }\nvar=30 func\necho \"$? $var\"");
    assert_eq!(out, "5 20\n");
}

// KNSH-106: in POSIX mode an assignment error before a special builtin, or with no command, ends a non-interactive
// shell with status 1; before another command the command does not run and the line is abandoned with status 1
// (errors7.sub with `-o posix`, errors.right).
#[test]
fn assignment_errors_follow_posix_mode() {
    let mut h = posix_harness();
    h.on("tool", &[exited(0)]);
    let script = "readonly x=4
x=8 tool
echo \"after no such command: $?\"
x=8 echo echo builtin
echo \"after non-special builtin: $?\"
x=8 : nosuchdir
echo never";
    assert_eq!(h.status(script), 1);
    assert_eq!(
        h.output.text(),
        "after no such command: 1\nafter non-special builtin: 1\n"
    );
    assert_eq!(
        h.diagnostics.text(),
        "knsh: line 2: x: readonly variable\nknsh: line 4: x: readonly variable\nknsh: line 6: x: readonly \
         variable\n"
    );
    assert_eq!(h.ran(), Vec::<String>::new());
    for script in ["readonly x=4\nx=8\necho never", "readonly x=4\nx=8 $nocmd\necho never"] {
        let (status, out, _) = posix(script);
        assert_eq!((status, out.as_str()), (1, ""), "{script}");
    }
    // errors4.sub with `-o posix`: a read-only assignment in a loop ends the shell; so does a read-only `for`
    // variable.
    let script = "var=foo
readonly var
for num in 1 2 3 4 5; do
  if [ $num -eq 3 ]; then
    var=bar
  fi
  echo $num
done
echo after readonly assignment";
    let (status, out, _) = posix(script);
    assert_eq!((status, out.as_str()), (1, "1\n2\n"));
    // Outside POSIX mode the error abandons the rest of the `for` command (errors.right).
    assert_eq!(plain(script).1, "1\n2\nafter readonly assignment\n");
    assert_eq!(
        posix("readonly r=1\nfor r in a; do :; done\necho never"),
        (1, String::new(), "knsh: line 2: r: readonly variable\n".to_owned())
    );
}

// KNSH-106: POSIX mode wants a function name to be an identifier and not a special builtin's; a non-interactive
// shell ends with status 2 otherwise (errors.tests `function !! ()`, POSIX interpretation 383).
#[test]
fn function_names_follow_posix_rules() {
    let (status, out, err) = posix("f-g() { echo fn; }\necho never");
    assert_eq!((status, out.as_str()), (2, ""));
    assert_eq!(err, "knsh: line 1: `f-g': not a valid identifier\n");
    let (status, _, err) = posix("eval() { :; }\necho never");
    assert_eq!(status, 2);
    assert_eq!(err, "knsh: line 1: `eval': is a special builtin\n");
    // Outside POSIX mode both are defined.
    let (status, out, _) = plain("f-g() { echo fn; }\nf-g\ntrue() { echo mytrue; }\ntrue");
    assert_eq!((status, out.as_str()), (0, "fn\nmytrue\n"));
    // A function named like a builtin that is not special is still found first.
    assert_eq!(posix("true() { echo mytrue; }\ntrue").1, "mytrue\n");
}

// KNSH-106: a special builtin is found before a function of its name in POSIX mode, in lookup and in `type`.
#[test]
fn special_builtins_are_found_before_functions() {
    let script = "eval() { echo fn; }
eval echo builtin
type -t eval
command -v eval
set -o posix
eval echo builtin
type -t eval
command -v eval
type -at eval";
    let (status, out, err) = plain(script);
    assert_eq!(
        out, "fn\nfunction\neval\nbuiltin\nbuiltin\neval\nbuiltin\nfunction\n",
        "{err}"
    );
    assert_eq!(status, 0);
}

// KNSH-106: `.` does not look in the working directory in POSIX mode, and a file it cannot read ends a
// non-interactive shell with status 1 unless `command` runs it (source5.sub, builtins7.sub).
#[test]
fn source_follows_posix_mode() {
    let mut h = posix_harness();
    h.fs.write(Path::new("/work/lib.sh"), b"echo sourced\n", 0o644).unwrap();
    assert_eq!(h.status("command . lib.sh\necho \"one $?\"\n. lib.sh\necho never"), 1);
    assert_eq!(h.output.text(), "one 1\n");
    assert_eq!(
        h.diagnostics.text(),
        "knsh: line 1: .: lib.sh: file not found\nknsh: line 3: .: lib.sh: file not found\n"
    );
    let (status, out, err) = posix(". ./missing\necho never");
    assert_eq!((status, out.as_str()), (1, ""));
    assert_eq!(err, "knsh: line 1: ./missing: No such file or directory\n");
    // Outside POSIX mode the working directory is searched last, and a missing file is only an error.
    let mut h = Harness::new();
    h.fs.write(Path::new("/work/lib.sh"), b"echo sourced\n", 0o644).unwrap();
    assert_eq!(h.status(". lib.sh\n. ./missing\necho after"), 0);
    assert_eq!(h.output.text(), "sourced\nafter\n");
    // `set +o posix` searches it again.
    let mut h = posix_harness();
    h.fs.write(Path::new("/work/lib.sh"), b"echo sourced\n", 0o644).unwrap();
    assert_eq!(h.status("set +o posix\n. lib.sh"), 0);
    assert_eq!(h.output.text(), "sourced\n");
}

// KNSH-106: a syntax error in `eval` or `.` text ends a non-interactive shell with status 2 in POSIX mode, unless
// `command` runs it (evalstring.c; errors8.sub `command eval '( '`).
#[test]
fn eval_syntax_errors_are_fatal_in_posix_mode() {
    let (status, out, err) = posix("eval 'if'\necho never");
    assert_eq!((status, out.as_str()), (2, ""));
    assert_eq!(err, "knsh: eval: line 1: syntax error: unexpected end of file\n");
    assert_eq!(posix("command eval 'if' || echo ok").1, "ok\n");
    assert_eq!(plain("eval 'if'\necho after").1, "after\n");
}

// KNSH-106: expansion errors that abandon the line outside POSIX mode end a non-interactive shell in it: a bad
// substitution, an arithmetic error in `$((…))`, `${name=word}` on a read-only variable (bash's `expand_wdesc_fatal`
// and `FORCE_EOF`).
#[test]
fn expansion_errors_are_fatal_in_posix_mode() {
    for script in [
        "echo ${x!}\necho never",
        "echo $((1+))\necho never",
        "readonly r\necho ${r=2}\necho never",
    ] {
        let (status, out, _) = posix(script);
        assert_eq!((status, out.as_str()), (1, ""), "{script}");
        assert_eq!(plain(script).1, "never\n", "{script}");
    }
    // A `failglob` failure is not one of them.
    assert_eq!(posix("shopt -s failglob\necho *.none\necho after").1, "after\n");
}

// KNSH-106: tilde expansion after `=` in a word that only looks like an assignment is not done in POSIX mode
// (tilde.tests, tilde3.sub); assignments and declaration builtins still expand.
#[test]
fn tilde_follows_posix_mode() {
    let script = "HOME=/home/u
echo foo=bar:~ a=~/x
foo=~:~
echo \"$foo\"
export q=~
echo \"$q\"
echo ~/y";
    let (_, out, _) = posix(script);
    assert_eq!(out, "foo=bar:~ a=~/x\n/home/u:/home/u\n/home/u\n/home/u/y\n");
    let (_, out, _) = plain(script);
    assert_eq!(
        out,
        "foo=bar:/home/u a=/home/u/x\n/home/u:/home/u\n/home/u\n/home/u/y\n"
    );
}

// KNSH-106: in POSIX mode a redirection's word is neither split nor (in a non-interactive shell) matched against
// file names (redir.tests `cat < redir1.*`, new-exp2.sub `$(< file*)`).
#[test]
fn redirection_words_follow_posix_mode() {
    let mut h = posix_harness();
    h.fs.write(Path::new("/work/g1"), b"", 0o644).unwrap();
    assert_eq!(
        h.status("x='a b'\necho hi > $x\necho there > g*"),
        0,
        "{}",
        h.diagnostics.text()
    );
    assert_eq!(h.file("a b").as_deref(), Some("hi\n"));
    assert_eq!(h.file("g*").as_deref(), Some("there\n"));
    assert_eq!(h.file("g1").as_deref(), Some(""));
    let mut h = Harness::new();
    h.fs.write(Path::new("/work/g1"), b"", 0o644).unwrap();
    assert_eq!(h.status("x='a b'\necho hi > $x\necho there > g*"), 0);
    assert_eq!(h.diagnostics.text(), "knsh: line 2: $x: ambiguous redirect\n");
    assert_eq!(h.file("g1").as_deref(), Some("there\n"));
}

// KNSH-106: `echo` takes no options and interprets escapes in POSIX mode, as macOS's `/bin/sh` does (checked
// against it), whether POSIX mode came at start-up or from `set -o posix`; `set +o posix` gives bash's `echo` back.
#[test]
fn echo_follows_macos_sh() {
    let (_, out, _) = posix("echo -n 'a\\tb'\necho -e x\nset +o posix\necho -n 'a\\tb'\necho");
    assert_eq!(out, "-n a\tb\n-e x\na\\tb\n");
    let (_, out, _) = plain("set -o posix\necho 'a\\nb'");
    assert_eq!(out, "a\nb\n");
}

// KNSH-106 acceptance: `set -o posix` turns POSIX mode on as bash's `set_posix_mode` does: `POSIXLY_CORRECT=y`, and
// `inherit_errexit`, `shift_verbose` and `expand_aliases` on; `set +o posix` removes the variable and turns
// `shift_verbose` and (in a script) `expand_aliases` off, leaving `inherit_errexit` (bash 5.2's `posix_initialize`).
// Assigning or unsetting `POSIXLY_CORRECT` turns it on or off too (`sv_strict_posix`).
#[test]
fn set_o_posix_enables_posix_mode() {
    let script = "shopt -oq posix || echo off
set -o posix
shopt -oq posix && echo on
echo \"P=$POSIXLY_CORRECT\"
shopt inherit_errexit shift_verbose expand_aliases
set +o posix
echo \"P=${POSIXLY_CORRECT-unset}\"
shopt inherit_errexit shift_verbose expand_aliases
POSIXLY_CORRECT=
shopt -oq posix && echo on again
unset POSIXLY_CORRECT
shopt -oq posix || echo off again
shopt -so posix
echo \"P=$POSIXLY_CORRECT\"";
    let (status, out, err) = plain(script);
    assert_eq!(
        out,
        "off\non\nP=y\ninherit_errexit\ton\nshift_verbose  \ton\nexpand_aliases \ton\nP=unset\n\
         inherit_errexit\ton\nshift_verbose  \toff\nexpand_aliases \toff\non again\noff again\nP=y\n",
        "{err}"
    );
    assert_eq!(status, 0);
    // A temporary `POSIXLY_CORRECT` for one builtin puts the options back as it ends (`save_posix_options`).
    let (_, out, _) =
        plain("POSIXLY_CORRECT=1 shopt -q shift_verbose && echo during\nshopt -q shift_verbose || echo after");
    assert_eq!(out, "during\nafter\n");
}

// KNSH-106 acceptance: the host starts the shell in POSIX mode with `with_posix_mode` (`sh`, `--posix`), and an
// inherited `POSIXLY_CORRECT` starts it so too, keeping its value.
#[test]
fn start_up_enables_posix_mode() {
    let state = ShellState::new("sh", "/work").unwrap().with_posix_mode();
    assert!(state.options().posix());
    assert!(state.options().inherit_errexit);
    assert_eq!(state.variable("POSIXLY_CORRECT"), Some(OsStr::new("y")));
    let state = ShellState::new("knsh", "/work")
        .unwrap()
        .with_environment([("POSIXLY_CORRECT".into(), "1".into())]);
    assert!(state.options().posix());
    assert_eq!(state.variable("POSIXLY_CORRECT"), Some(OsStr::new("1")));
    let state = ShellState::new("knsh", "/work").unwrap().with_environment([]);
    assert!(!state.options().posix());
}

// KNSH-106: POSIX mode sets `inherit_errexit`, so a command substitution keeps `set -e` (set-e1.sub: "should be
// silent in posix mode").
#[test]
fn command_substitution_inherits_errexit_in_posix_mode() {
    let mut h = Harness::with_data_pipes();
    h.interpreter.state_mut().set_posix_mode(true);
    assert_eq!(h.status("set -e\nz=$(false; echo posix foo)\necho \"$z\""), 1);
    assert_eq!(h.output.text(), "");
    let mut h = Harness::with_data_pipes();
    assert_eq!(h.status("set -e\nz=$(false; echo non-posix foo)\necho \"$z\""), 0);
    assert_eq!(h.output.text(), "non-posix foo\n");
}

// KNSH-106: listings in POSIX mode: `trap` names signals without `SIG`, `alias` without `-p` leaves out `alias `,
// `export -p` lists as `export` (checked against `/bin/sh`); `trap -p` alone, which also lists every signal at its
// default, is refused.
#[test]
fn listings_follow_posix_mode() {
    let (_, out, _) = posix("trap 'echo t' INT TERM\ntrap\ntrap -p INT");
    assert_eq!(
        out,
        "trap -- 'echo t' INT\ntrap -- 'echo t' TERM\ntrap -- 'echo t' INT\n"
    );
    let (_, out, _) = posix("alias ll='ls -l'\nalias\nalias ll\nalias -p");
    assert_eq!(out, "ll='ls -l'\nll='ls -l'\nalias ll='ls -l'\n");
    let (_, out, _) = posix("export E=1\nexport -p");
    assert!(out.lines().any(|line| line == "export E=\"1\""), "{out}");
    assert!(out.lines().all(|line| line.starts_with("export ")), "{out}");
    let mut h = posix_harness();
    assert_eq!(refused(h.run("trap -p")), Unsupported::Trap);
    // In POSIX mode a signal alone is an action without signals: the usage error, fatal for `trap`.
    let (status, _, err) = posix("trap INT\necho never");
    assert_eq!(status, 2);
    assert_eq!(err, "trap: usage: trap [-lp] [[arg] signal_spec ...]\n");
}

// KNSH-106: `shift_verbose` (on in POSIX mode) reports a count past the parameters; `break` and `continue` outside a
// loop say nothing in POSIX mode (bash's `check_loop_level`).
#[test]
fn shift_and_loop_builtins_follow_posix_mode() {
    let (status, out, err) = posix("shift 5\necho \"$?\"\nshift\necho \"$?\"\nbreak\ncontinue\necho done");
    assert_eq!((status, out.as_str()), (0, "1\n1\ndone\n"));
    assert_eq!(
        err,
        "knsh: line 1: shift: 5: shift count out of range\nknsh: line 3: shift: shift count out of range\n"
    );
    let (_, _, err) = plain("shift 5\nbreak");
    assert_eq!(
        err,
        "knsh: line 2: break: only meaningful in a `for', `while', or `until' loop\n"
    );
}

// KNSH-106: in POSIX mode `command` before a declaration builtin keeps its assignment arguments expanded as
// assignments (bash's `fix_assignment_words`).
#[test]
fn command_keeps_declaration_words_in_posix_mode() {
    let (_, out, _) = posix("v='a b'\ncommand export w=$v\necho \"$w\"");
    assert_eq!(out, "a b\n");
    let (_, out, _) = plain("v='a b'\ncommand export w=$v\necho \"$w\"");
    assert_eq!(out, "a\n");
}

// KNSH-106: a `}` or `"` between single quotes in a double-quoted `${name-word}` ends the expansion in POSIX mode
// (posixexp.tests); the parser has no POSIX mode, so that word is refused rather than read differently.
#[test]
fn posix_quotes_in_braces_are_refused() {
    let mut h = posix_harness();
    assert_eq!(refused(h.run("echo \"${IFS+'}'z}\"")), Unsupported::PosixMode);
    // Without such a quote both modes read it alike, and outside double quotes it is not refused.
    let (_, out, _) = posix("unset x\necho \"${x-'a b'}\" ${IFS+'}'z}");
    assert_eq!(out, "'a b' }z\n");
    let (_, out, _) = plain("echo \"${IFS+'}'z}\"");
    assert_eq!(out, "'}'z\n");
}

// KNSH-106: POSIX mode searches `PATH` again for a hashed program that is gone (bash's `search_for_command`).
#[test]
fn hashed_program_is_searched_again_in_posix_mode() {
    let mut h = posix_harness();
    h.on("tool", &[exited(0)]);
    assert_eq!(
        h.status("hash -p /work/gone/tool tool\ntool"),
        0,
        "{}",
        h.diagnostics.text()
    );
    assert_eq!(h.commands.runs()[0].program, Path::new("/bin/tool"));
    // Outside POSIX mode the hashed path is used as it is.
    let mut h = Harness::new();
    h.commands.on("/work/gone/tool", CommandOutcome::NotFound);
    assert_eq!(h.status("hash -p /work/gone/tool tool\ntool"), 127);
    assert_eq!(h.commands.runs()[0].program, Path::new("/work/gone/tool"));
}

// KNSH-106: a usage error of a builtin that `eval` or `.` text runs is that builtin's, made status 2 as it ends: it
// does not end the shell as `eval`'s or `.`'s own would (bash's `special_builtin_failed` is the outer builtin's
// `EX_USAGE` only). A special builtin's usage error inside the text still ends it.
#[test]
fn nested_usage_error_is_not_the_special_builtins() {
    let mut h = posix_harness();
    h.fs.write(Path::new("/work/bad.sub"), b"pwd -Q\n", 0o644).unwrap();
    let status = h.status("eval 'pwd -Q'\necho one\neval 'declare -Q; true'\necho two\n. ./bad.sub\necho three");
    assert_eq!(
        (status, h.output.text().as_str()),
        (0, "one\ntwo\nthree\n"),
        "{}",
        h.diagnostics.text()
    );
    let (status, out, _) = posix("eval 'set -Q'\necho never");
    assert_eq!((status, out.as_str()), (2, ""));
}

// KNSH-106: `export` or `readonly` failing to make an assignment it was given (bash 5.2's `EX_BADASSIGN` from
// `set_or_show_attributes`) ends a non-interactive shell in POSIX mode with status 1, even when the status is tested;
// through `command`, or outside POSIX mode, the script goes on.
#[test]
fn bad_assignment_in_export_is_fatal_in_posix_mode() {
    for script in [
        "readonly x=1\nexport x=2\necho never",
        "readonly x=1\nreadonly x=2 || echo tested\necho never",
        "export 1a=b\necho never",
    ] {
        let (status, out, err) = posix(script);
        assert_eq!((status, out.as_str()), (1, ""), "{script}: {err}");
        let (status, out, _) = plain(script);
        assert_eq!(out.lines().last(), Some("never"), "{script}");
        assert_eq!(status, 0, "{script}");
    }
    let (status, out, _) = posix("readonly x=1\ncommand export x=2 || echo ok\nexport y=1 z=2\necho \"$y$z\"");
    assert_eq!((status, out.as_str()), (0, "ok\n12\n"));
}

// KNSH-106: `POSIXLY_CORRECT` before a function call turns POSIX mode on for the call and puts the options back as
// it returns (bash's `assign_in_env` and `push_func_var`, each running `sv_strict_posix`); a local one goes away
// with the call too.
#[test]
fn posix_variable_before_function_call_lasts_for_the_call() {
    let script = "f() { shopt -oq posix && echo on; shopt -q shift_verbose && echo verbose; }
POSIXLY_CORRECT=1 f
shopt -oq posix || echo off
shopt -q shift_verbose || echo quiet
g() { local POSIXLY_CORRECT=1; shopt -oq posix && echo local on; }
g
shopt -oq posix || echo off again";
    let (status, out, err) = plain(script);
    assert_eq!(out, "on\nverbose\noff\nquiet\nlocal on\noff again\n", "{err}");
    assert_eq!(status, 0);
}
