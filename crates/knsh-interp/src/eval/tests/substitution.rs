//! Command substitution, process substitution, coprocesses and here-documents over the fakes (KNSH-105;
//! NFR-COMPAT-02, decision 6). Outputs and statuses were checked against bash (3.2 here; it has no `coproc`, whose
//! behaviour follows bash 5.2's source and is marked).

use std::time::{Duration, Instant};

use super::*;

/// Waits until `program` has run (a process substitution is not waited for), at most a few seconds.
fn wait_for_run(h: &Harness, program: &str) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !h.ran().iter().any(|name| name == program) {
        assert!(Instant::now() < deadline, "{program} never ran: {:?}", h.ran());
        std::thread::sleep(Duration::from_millis(2));
    }
}

/// The value of variable `name`, as text.
fn var(h: &Harness, name: &str) -> Option<String> {
    h.interpreter
        .state()
        .variable(name)
        .map(|value| value.to_string_lossy().into_owned())
}

// NFR-COMPAT-02: `$(cmd)` and backticks give the output without its trailing newlines, split and matched against
// file names when unquoted; the substitution runs in a copy of the shell.
#[test]
fn command_substitution_gives_output_split_and_globbed_as_bash() {
    let mut h = Harness::with_data_pipes();
    h.fs.write(Path::new("/work/f1"), b"", 0o644).unwrap();
    h.fs.write(Path::new("/work/f2"), b"", 0o644).unwrap();
    let script = r#"x=$(printf 'a\n\n'); echo "[$x]"
y=`echo hi`; echo $y
set -- $(echo 'a  b'); echo $#
echo "$(echo 'a  b')"
echo $(echo 'f*')
echo "$(echo 'f*')"
x=1; y=$(x=2; echo $x); echo $x $y
echo `echo \`echo nested\``
echo $(echo $(echo deep))
echo "$(printf 'a\0b')"
echo "a$(echo)b"
"#;
    assert_eq!(h.status(script), 0);
    assert_eq!(
        h.output.text(),
        "[a]\nhi\n2\na  b\nf1 f2\nf*\n1 2\nnested\ndeep\nab\nab\n"
    );
}

// NFR-COMPAT-02: `$?` after a command of assignments is its last substitution's status; the substitution's status
// is `$?` for the rest of the command's words too.
#[test]
fn substitution_status_is_the_status_of_an_assignment() {
    let mut h = Harness::with_data_pipes();
    h.on("a", &[exited(5)]);
    assert_eq!(h.status("x=$(exit 4)"), 4);
    assert_eq!(h.status("x=$(false) y=1"), 1);
    assert_eq!(h.status("x=$(a)"), 5);
    assert_eq!(h.status("x=$(exit 3) y=$(true)"), 0);
    assert_eq!(h.status("x=1"), 0);
    assert_eq!(h.status(">/dev/null $(exit 6)"), 6);
    assert_eq!(h.status("f() { return 7; }; x=$(f) y=2"), 7);
    assert_eq!(h.status("echo $(exit 3) $?"), 0);
    assert!(h.output.text().ends_with("3\n"), "{}", h.output.text());
    // A command with a name ends with its own status.
    assert_eq!(h.status("true $(false)"), 0);
}

// KNSH-104: `set -e` is off inside a command substitution unless `inherit_errexit`; the assignment's failure still
// ends the script.
#[test]
fn errexit_in_command_substitution_follows_inherit_errexit() {
    let mut h = Harness::with_data_pipes();
    assert_eq!(h.status("set -e; x=$(false; echo yes); echo \"$x\""), 0);
    assert_eq!(h.output.text(), "yes\n");
    let mut h = Harness::with_data_pipes();
    assert_eq!(
        h.status("set -e; shopt -s inherit_errexit; x=$(false; echo yes); echo \"[$x]\""),
        1
    );
    assert_eq!(h.output.text(), "");
    let mut h = Harness::with_data_pipes();
    assert_eq!(h.status("set -e; x=$(false); echo no"), 1);
    assert_eq!(h.output.text(), "");
}

// `$(< file)` reads the file without running a command; a missing file is bash's error, status 1.
#[test]
fn command_substitution_of_a_redirection_reads_the_file() {
    let mut h = Harness::with_data_pipes();
    h.fs.write(Path::new("/work/data"), b"line 1\nline 2\n\n", 0o644)
        .unwrap();
    assert_eq!(h.status("echo \"$(< data)\"; x=$(< missing)"), 1);
    assert_eq!(h.output.text(), "line 1\nline 2\n");
    assert!(
        h.diagnostics.text().contains("missing: No such file or directory"),
        "{}",
        h.diagnostics.text()
    );
    assert_eq!(h.ran(), Vec::<String>::new());
}

// NFR-COMPAT-02: `<(…)` and `>(…)` are `/dev/fd/N` names, from 63 down; the command receives the descriptor, and
// the shell closes it once the command is done.
#[test]
fn process_substitution_provides_dev_fd_path() {
    let mut h = Harness::new();
    h.on("x", &[exited(0)]);
    h.on("a", &[exited(0)]);
    assert_eq!(h.status("echo <(true) >(true)"), 0);
    assert_eq!(h.output.text(), "/dev/fd/63 /dev/fd/62\n");
    assert_eq!(h.status("x <(true) >(true); a"), 0);
    let runs = h.commands.runs();
    let x = runs.iter().position(|run| run.argv0 == "x").unwrap();
    let y = runs.iter().position(|run| run.argv0 == "a").unwrap();
    let x_table = h.table(x);
    assert!(x_table.contains(&(63, "<2|".to_owned())), "{x_table:?}");
    assert!(x_table.contains(&(62, "|3>".to_owned())), "{x_table:?}");
    assert_eq!(args_of_run(&h, x), ["/dev/fd/63", "/dev/fd/62"]);
    // Closed after the command: the next one does not receive them, and the next substitution reuses 63.
    assert_eq!(
        h.table(y),
        [(0, "stdin".into()), (1, "stdout".into()), (2, "stderr".into())]
    );
    assert_eq!(h.status("echo <(true)"), 0);
    assert!(h.output.text().ends_with("/dev/fd/63\n"));
}

/// The arguments of the `index`th command run.
fn args_of_run(h: &Harness, index: usize) -> Vec<String> {
    h.commands.runs()[index]
        .args
        .iter()
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect()
}

// NFR-COMPAT-02: the shell's own redirections read a process substitution as its descriptor: `done < <(cmd)`, the
// most common form, and `exec 3< <(cmd)`, whose duplicate outlives the substitution's own descriptor.
#[test]
fn redirections_read_process_substitutions() {
    let mut h = Harness::with_data_pipes();
    let script = "while read -r line; do echo \"got $line\"; done < <(printf 'l1\\nl2\\n')\n\
                  exec 3< <(echo kept); read -r k <&3; echo $k\n";
    assert_eq!(h.status(script), 0);
    assert_eq!(h.output.text(), "got l1\ngot l2\nkept\n");
}

// KNSH-108 seam: every command a process or command substitution starts goes through the spawner, the decision
// hook, with its own arguments.
#[test]
fn commands_inside_process_substitution_are_decided() {
    let mut h = Harness::new();
    for program in ["a", "b", "c", "x"] {
        h.on(program, &[exited(0)]);
    }
    assert_eq!(h.status("x <(a 1) >(b 2) \"$(c 3)\""), 0);
    wait_for_run(&h, "a");
    wait_for_run(&h, "b");
    let runs = h.commands.runs();
    for (program, arg) in [("a", "1"), ("b", "2"), ("c", "3")] {
        let run = runs.iter().find(|run| run.argv0 == program).unwrap();
        assert_eq!(run.args, [arg], "{program}");
    }
    // The command substitution ran before the command it is a word of.
    let c = runs.iter().position(|run| run.argv0 == "c").unwrap();
    let x = runs.iter().position(|run| run.argv0 == "x").unwrap();
    assert!(c < x);
}

// Bash 5.2 (`execute_coproc`): `coproc command` names its array `COPROC`; `COPROC[0]` reads the coprocess's output,
// `COPROC[1]` writes its input; `COPROC_PID` and `$!` are its process id; the ends are the shell's alone.
#[test]
fn coproc_default_name_is_coproc() {
    let mut h = Harness::new();
    h.on("a", &[exited(0)]);
    h.on("x", &[exited(0)]);
    assert_eq!(
        h.status("coproc a -n; echo ${COPROC[0]} ${COPROC[1]} $COPROC_PID $!; x"),
        0
    );
    assert_eq!(h.output.text(), "63 62 20000 20000\n");
    assert_eq!(h.ran(), ["a", "x"]);
    assert_eq!(args_of_run(&h, 0), ["-n"]);
    assert_eq!(h.table(0), [(0, "<0|".into()), (1, "|1>".into()), (2, "stderr".into())]);
    // Close-on-exec: the next command does not receive them.
    assert_eq!(
        h.table(1),
        [(0, "stdin".into()), (1, "stdout".into()), (2, "stderr".into())]
    );
    assert_eq!(h.interpreter.state().last_status().code(), 0);
}

// Bash 5.2: a named coprocess (a compound command) talks through its array's descriptors; one the shell runs
// itself has no process id, so `NAME_PID` is refused rather than made up, as `$!` is.
#[test]
fn named_coproc_reads_and_writes_through_its_array() {
    let mut h = Harness::with_data_pipes();
    let script = "coproc worker { read -r line; echo \"got $line\"; }\n\
                  echo ping >&${worker[1]}\n\
                  read -r reply <&${worker[0]}; echo \"$reply\"\n\
                  wait\n";
    assert_eq!(h.status(script), 0);
    assert_eq!(h.output.text(), "got ping\n");
    assert_eq!(var(&h, "worker"), Some("63".to_owned()));
    assert_eq!(refused(h.run("echo $worker_PID")), Unsupported::ShellVariable);
    assert_eq!(refused(h.run("echo $!")), Unsupported::InShellProcessId);
}

// NFR-COMPAT-02: a quoted delimiter leaves the body as written; an unquoted one expands parameters, arithmetic and
// command substitutions, but never splits or matches file names. A here-document is standard input by default.
#[test]
fn quoted_heredoc_delimiter_disables_expansion() {
    let mut h = Harness::with_data_pipes();
    let script = "x='a  *'\n\
                  read -r -d '' q <<'E'\n$x $(echo run) `echo b` \\$y\nE\n\
                  read -r -d '' u <<E\n$x $((1+2)) $(echo run) \\$y \"q\"\nE\n\
                  { read -r t <&3; } 3<<E\nthree\nE\n\
                  printf '[%s]' \"$q\" \"$u\" \"$t\"\n";
    assert_eq!(h.status(script), 0);
    assert_eq!(
        h.output.text(),
        "[$x $(echo run) `echo b` \\$y][a  * 3 run $y \"q\"][three]"
    );
    // The body reaches a command as its standard input, a here-document's text.
    let mut h = Harness::new();
    h.on("cat", &[exited(0)]);
    h.fs.write(Path::new("/bin/cat"), b"", 0o755).unwrap();
    assert_eq!(h.status("cat <<'E'\n$x\nE\n"), 0);
    assert_eq!(h.table(0)[0], (0, "<<<$x\n".to_owned()));
}

// NFR-COMPAT-02: `<<-` removes the tabs starting each body line and the delimiter line; `<<` keeps them.
#[test]
fn heredoc_dash_strips_leading_tabs() {
    let mut h = Harness::new();
    h.on("cat", &[exited(0)]);
    h.fs.write(Path::new("/bin/cat"), b"", 0o755).unwrap();
    assert_eq!(h.status("cat <<-E\n\t\tone\n\t two\n\tE\ncat <<E\n\tthree\nE\n"), 0);
    assert_eq!(h.table(0)[0], (0, "<<<one\n two\n".to_owned()));
    assert_eq!(h.table(1)[0], (0, "<<<\tthree\n".to_owned()));
}
