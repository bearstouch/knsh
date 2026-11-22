//! The interactive shell's side of the interpreter over the fake filesystem (KNSH-107; NFR-COMPAT-02): lines typed
//! at the prompt, prompt expansion, completion and the `history`, `complete` and `compgen` builtins. Expected
//! outputs were checked against bash 3.2 (`bash -i` and `bash -c`) where it agrees with bash 5.2.

use super::*;
use crate::LineStatus;

/// A harness whose shell is interactive, as the native front end makes it.
fn interactive() -> Harness {
    Harness::with(|interpreter| interpreter.with_job_control(None))
}

// KNSH-107: in command position, Tab offers aliases, reserved words, builtins, functions and programs on `PATH`.
#[test]
fn completion_lists_matching_commands() {
    let mut h = interactive();
    h.run("alias ech='echo'; ef() { :; }").unwrap();
    let completion = h.interpreter.complete("e", 1);
    assert_eq!(completion.start, 0);
    assert!(!completion.filenames);
    for name in [
        "ech", "echo", "ef", "elif", "else", "enable", "env", "esac", "eval", "exec", "exit", "export",
    ] {
        assert!(
            completion.matches.contains(&name.to_owned()),
            "{name}: {:?}",
            completion.matches
        );
    }
    let mut sorted = completion.matches.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(completion.matches, sorted, "sorted, without repeats");
    // After `|` and `;` the word is a command again; after a command it is a file name.
    assert!(
        h.interpreter
            .complete("ls | tr", 7)
            .matches
            .contains(&"true".to_owned())
    );
    assert!(h.interpreter.complete("x; tr", 5).matches.contains(&"true".to_owned()));
    assert_eq!(h.interpreter.complete("echo tr", 7).matches, Vec::<String>::new());
}

#[test]
fn completion_of_file_and_variable_names() {
    let mut h = interactive();
    h.fs.add_dir_all(Path::new("/work/docs/old")).unwrap();
    h.fs.write(Path::new("/work/docs/notes.txt"), b"", 0o644).unwrap();
    h.fs.write(Path::new("/work/docs/.hidden"), b"", 0o644).unwrap();
    h.fs.write(Path::new("/work/my file"), b"", 0o644).unwrap();
    let completion = h.interpreter.complete("cat docs/", 9);
    assert_eq!((completion.start, completion.filenames), (4, true));
    assert_eq!(completion.matches, ["docs/notes.txt", "docs/old/"]);
    assert_eq!(h.interpreter.complete("cat docs/.", 10).matches, ["docs/.hidden"]);
    assert_eq!(h.interpreter.complete("cat my", 6).matches, ["my file"]);
    assert_eq!(h.interpreter.complete("cat 'my", 7).quote, Some('\''));
    h.run("MYVAR=1 MYOTHER=2").unwrap();
    assert_eq!(h.interpreter.complete("echo $MY", 8).matches, ["$MYOTHER", "$MYVAR"]);
    assert_eq!(h.interpreter.complete("echo ${MYV", 10).matches, ["${MYVAR}"]);
    // A command typed with a `/`: directories and executable files.
    h.fs.write(Path::new("/work/docs/run"), b"", 0o755).unwrap();
    assert_eq!(h.interpreter.complete("docs/", 5).matches, ["docs/old/", "docs/run"]);
}

#[test]
fn completion_specifications_are_used() {
    let mut h = interactive();
    h.run("complete -W 'start stop status' svc").unwrap();
    assert_eq!(h.interpreter.complete("svc st", 6).matches, ["start", "status", "stop"]);
    assert_eq!(
        h.interpreter.complete("/usr/sbin/svc sta", 17).matches,
        ["start", "status"]
    );
    // A function's `COMPREPLY`, with bash's `COMP_*` variables, which are removed afterwards.
    h.run("_tool() { COMPREPLY=(\"$2-x\" \"$COMP_CWORD\" \"${COMP_WORDS[0]}\" \"$3\"); }; complete -F _tool tool")
        .unwrap();
    let completion = h.interpreter.complete("tool one ab", 11);
    assert_eq!(completion.matches, ["2", "ab-x", "one", "tool"]);
    h.run("echo \"${COMP_WORDS-unset}${COMPREPLY-unset}\"").unwrap();
    assert_eq!(h.output.text(), "unsetunset\n");
    // `-o default` falls back to file names; `-X` filters.
    h.fs.write(Path::new("/work/a.c"), b"", 0o644).unwrap();
    h.fs.write(Path::new("/work/a.o"), b"", 0o644).unwrap();
    h.run("complete -o default -W 'zz' cc1; complete -f -X '*.o' cc2")
        .unwrap();
    assert_eq!(h.interpreter.complete("cc1 a", 5).matches, ["a.c", "a.o"]);
    assert_eq!(h.interpreter.complete("cc2 a", 5).matches, ["a.c"]);
    // A missing function is reported, not run.
    h.run("complete -F nosuch broken").unwrap();
    assert!(h.interpreter.complete("broken x", 8).message.is_some());
}

#[test]
fn complete_and_compgen_builtins_match_bash() {
    let mut h = interactive();
    assert_eq!(h.status("compgen -W 'alpha beta alps' al"), 0);
    assert_eq!(h.output.text(), "alpha\nalps\n");
    assert_eq!(h.status("compgen -W x zz"), 1);
    assert_eq!(h.status("complete -W 'a b' -o nospace -c foo bar; complete -p foo"), 0);
    assert!(h.output.text().ends_with("complete -o nospace -c -W 'a b' foo\n"));
    assert_eq!(h.status("complete -r foo; complete -p foo"), 1);
    assert!(
        h.diagnostics
            .text()
            .contains("knsh: complete: foo: no completion specification\n")
    );
    assert_eq!(h.status("complete -Q x"), 2);
    assert!(
        h.diagnostics
            .text()
            .contains("knsh: complete: -Q: invalid option\ncomplete: usage:")
    );
    assert_eq!(h.status("compgen -u r"), 2);
    assert!(h.diagnostics.text().contains("compgen: -A user: not supported"));
    let mut h = interactive();
    assert_eq!(
        h.status("compgen -k fu; compgen -b ec; compgen -A shopt -X '!*glob*' ext"),
        0
    );
    assert_eq!(h.output.text(), "function\necho\nextglob\n");
}

// KNSH-107: the `history` builtin lists, deletes, adds and expands as bash's.
#[test]
fn history_builtin_matches_bash() {
    let mut h = interactive();
    for line in ["ls", "echo a b c", "pwd"] {
        h.interpreter.add_history(line);
    }
    assert_eq!(h.status("history"), 0);
    assert_eq!(h.output.text(), "    1  ls\n    2  echo a b c\n    3  pwd\n");
    let mut h2 = interactive();
    for line in ["ls", "echo a b c", "pwd"] {
        h2.interpreter.add_history(line);
    }
    assert_eq!(h2.status("history 1; history -p '!-2:$' '!!'"), 0);
    assert_eq!(h2.output.text(), "    3  pwd\nc\npwd\n");
    assert_eq!(h2.status("history -d 1; history -d -1; history -s added"), 0);
    assert_eq!(h2.interpreter.state().history().entries(), ["added"]);
    assert_eq!(h2.status("history -d 99"), 1);
    assert!(
        h2.diagnostics
            .text()
            .contains("history: 99: history position out of range")
    );
    assert_eq!(h2.status("history -c; history"), 0);
    assert_eq!(h2.interpreter.state().history().entries(), &[] as &[String]);
    assert_eq!(h2.status("history -x"), 2);
}

#[test]
fn history_file_is_written_and_read_owner_only() {
    let mut h = interactive();
    h.interpreter.add_history("one");
    h.interpreter.add_history("two");
    h.run("HISTFILESIZE=1; history -w /work/hist").unwrap();
    assert_eq!(h.file("hist").as_deref(), Some("two\n"));
    assert_eq!(h.fs.metadata(Path::new("/work/hist")).unwrap().mode & 0o777, 0o600);
    h.interpreter.add_history("three");
    h.run("HISTFILESIZE=10; history -a /work/hist").unwrap();
    assert_eq!(h.file("hist").as_deref(), Some("two\nthree\n"));
    h.run("history -c; history -r /work/hist").unwrap();
    assert_eq!(h.interpreter.state().history().entries(), ["two", "three"]);
    assert_eq!(h.interpreter.state().history().unsaved(), &[] as &[String]);
}

// KNSH-107 (review): a symlinked history file is written where the link points, and the link is kept.
#[test]
fn history_file_symlink_is_written_through() {
    let mut h = interactive();
    h.fs.write(Path::new("/work/real"), b"old\n", 0o600).unwrap();
    h.fs.add_symlink(Path::new("/work/hist"), Path::new("/work/real"))
        .unwrap();
    h.interpreter.add_history("new");
    h.run("history -a /work/hist").unwrap();
    assert_eq!(h.file("real").as_deref(), Some("old\nnew\n"));
    let link = h.fs.status(Path::new("/work/hist"), false).unwrap();
    assert_eq!(link.file_type, knsh_platform::FileType::Symlink);
}

// KNSH-107 (review): a quote inside a word (`a"b`) is not the word's opening quote; completing there, or with a
// cursor inside a character, never panics.
#[test]
fn completion_after_a_quote_inside_a_word_does_not_panic() {
    let mut h = interactive();
    let completion = h.interpreter.complete("a\"b", 3);
    assert_eq!((completion.start, completion.quote), (0, Some('"')));
    let completion = h.interpreter.complete("echo x\"y", 8);
    assert_eq!(completion.start, 5);
    let _ = h.interpreter.complete("echo 日", 6);
}

// KNSH-107 (review): a prompt ending in a backslash shows it, instead of an unterminated here-document error.
#[test]
fn prompt_ending_in_a_backslash_is_shown() {
    let mut h = interactive();
    h.run("X=hi").unwrap();
    assert_eq!(h.interpreter.expand_prompt("$X\\"), "hi\\");
    assert_eq!(h.diagnostics.text(), "");
}

#[test]
fn history_control_comes_from_the_shell() {
    let mut h = interactive();
    h.run("HISTCONTROL=ignoreboth HISTSIZE=2").unwrap();
    assert!(h.interpreter.add_history("ls"));
    assert!(!h.interpreter.add_history("ls"));
    assert!(!h.interpreter.add_history(" secret"));
    assert!(h.interpreter.add_history("pwd"));
    assert!(h.interpreter.add_history("id"));
    assert_eq!(h.interpreter.state().history().entries(), ["pwd", "id"]);
}

#[test]
fn prompts_are_expanded_as_here_documents() {
    let mut h = interactive();
    h.run("X=hi; false").unwrap();
    assert_eq!(
        h.interpreter.expand_prompt("$X \\$ $((1+2)) ${#X} \"q\" $?"),
        "hi $ 3 2 \"q\" 1"
    );
    // `$?` is left as it was.
    assert_eq!(h.interpreter.state().last_status(), Status::FAILURE);
    // Text from an escape was quoted by the decoder, so it is not expanded again.
    assert_eq!(h.interpreter.expand_prompt("/tmp/\\$(x)"), "/tmp/$(x)");
    // A bad substitution is reported and the prompt shown as decoded.
    assert_eq!(h.interpreter.expand_prompt("${x"), "${x");
    assert_eq!(h.interpreter.expand_prompt("plain"), "plain");
}

#[test]
fn lines_typed_at_the_prompt() {
    let mut h = interactive();
    assert_eq!(
        h.interpreter.run_line("if true; then\n").unwrap(),
        LineStatus::Incomplete
    );
    assert_eq!(h.interpreter.run_line("echo a \\\n").unwrap(), LineStatus::Incomplete);
    assert_eq!(
        h.interpreter.run_line("echo )\n").unwrap(),
        LineStatus::Ran(Status::new(2))
    );
    assert_eq!(h.diagnostics.text(), "knsh: syntax error near unexpected token `)'\n");
    assert_eq!(
        h.interpreter.run_line("echo hi\n").unwrap(),
        LineStatus::Ran(Status::SUCCESS)
    );
    assert_eq!(h.output.text(), "hi\n");
    assert!(!h.interpreter.has_exited());
    h.interpreter.run_line("exit 3\n").unwrap();
    assert!(h.interpreter.has_exited());
}

// An interactive shell's messages carry no line number, as bash's.
#[test]
fn interactive_messages_have_no_line_number() {
    let mut h = interactive();
    h.run("cd /nonexistent").unwrap();
    assert_eq!(
        h.diagnostics.text(),
        "knsh: cd: /nonexistent: No such file or directory\n"
    );
    let mut script = Harness::new();
    script.run("cd /nonexistent").unwrap();
    assert_eq!(
        script.diagnostics.text(),
        "knsh: line 1: cd: /nonexistent: No such file or directory\n"
    );
}

#[test]
fn editing_modes_follow_set_o() {
    let mut h = interactive();
    h.run("set -o emacs").unwrap();
    assert!(h.interpreter.state().options().emacs);
    h.run("set -o vi").unwrap();
    let options = h.interpreter.state().options();
    assert!(options.vi && !options.emacs);
    h.run("set +o emacs").unwrap();
    assert!(
        h.interpreter.state().options().vi,
        "turning off the mode not in use changes nothing"
    );
    h.run("set +o vi").unwrap();
    let options = h.interpreter.state().options();
    assert!(!options.vi && !options.emacs, "no line editing");
    h.run("set -H; set -o history; shopt -s histappend lithist").unwrap();
    let options = h.interpreter.state().options();
    assert!(options.histexpand && options.history && options.histappend && options.lithist);
    h.run("echo $-").unwrap();
    assert_eq!(h.output.text(), "himBH\n");
}
