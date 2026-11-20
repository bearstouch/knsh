//! Evaluator tests over the fake filesystem and scripted commands: no process ever starts.

use std::path::Path;
use std::sync::{Arc, Mutex, PoisonError};

use knsh_bash::{AndOr, CompoundCommand, Group, ListItem, Pipeline, parse};
use knsh_platform::PlatformError;
use knsh_platform::testing::{FakeUserHomes, MemFs, ScriptedCommands};

use super::*;

/// Programs present in the fake `/bin`.
const PROGRAMS: &[&str] = &[
    "true", "false", "x", "a", "b", "c", "cond", "body", "echo", "test", "printf", "env", "tool",
];

/// Diagnostics shared with the test.
#[derive(Clone, Default)]
struct Buffer(Arc<Mutex<Vec<u8>>>);

impl Write for Buffer {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Buffer {
    fn text(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
    }
}

struct Harness {
    interpreter: Interpreter,
    commands: Arc<ScriptedCommands>,
    fs: Arc<MemFs>,
    diagnostics: Buffer,
}

impl Harness {
    /// `/bin` holds [`PROGRAMS`]; `true` exits 0 and `false` 1; `PATH=/bin`.
    fn new() -> Self {
        let fs = Arc::new(MemFs::new());
        fs.add_dir_all(Path::new("/bin")).unwrap();
        fs.add_dir_all(Path::new("/work")).unwrap();
        for program in PROGRAMS {
            fs.write(&Path::new("/bin").join(program), b"", 0o755).unwrap();
        }
        let commands = Arc::new(ScriptedCommands::new());
        commands.on("/bin/true", exited(0));
        commands.on("/bin/false", exited(1));
        let diagnostics = Buffer::default();
        let state = ShellState::new("knsh", "/work")
            .unwrap()
            .with_environment([("PATH".into(), "/bin".into())]);
        let homes = Arc::new(FakeUserHomes::new().with_user("alice", "/Users/alice"));
        let interpreter = Interpreter::new(
            state,
            fs.clone(),
            commands.clone(),
            homes,
            Box::new(diagnostics.clone()),
        );
        Self {
            interpreter,
            commands,
            fs,
            diagnostics,
        }
    }

    /// Scripts `/bin/<program>` to give `outcomes` in order, the last repeated.
    fn on(&self, program: &str, outcomes: &[CommandOutcome]) {
        for outcome in outcomes {
            self.commands.on(Path::new("/bin").join(program), *outcome);
        }
    }

    fn run(&mut self, line: &str) -> Result<Status, InterpError> {
        let script = parse(line).unwrap();
        self.interpreter.run(&script, line)
    }

    fn status(&mut self, line: &str) -> u8 {
        self.run(line).unwrap().code()
    }

    fn ran(&self) -> Vec<String> {
        self.commands.names()
    }
}

fn exited(code: i32) -> CommandOutcome {
    CommandOutcome::Finished(ExitStatus::Exited(code))
}

fn refused(result: Result<Status, InterpError>) -> Unsupported {
    match result {
        Err(InterpError::Unsupported { feature, .. }) => feature,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

// NFR-COMPAT-01: `&&` and `||` short-circuit as in bash.
#[test]
fn and_or_lists_short_circuit_like_bash() {
    let mut h = Harness::new();
    h.on("x", &[exited(0)]);
    assert_eq!(h.status("false && x; true || x"), 0);
    assert_eq!(h.ran(), ["false", "true"]);
}

// NFR-COMPAT-01: `a && b || c` is `(a && b) || c`, and the status is the last pipeline run.
#[test]
fn and_or_lists_associate_left_and_keep_the_last_status() {
    let mut h = Harness::new();
    h.on("a", &[exited(0)]);
    h.on("b", &[exited(3)]);
    h.on("c", &[exited(4)]);
    assert_eq!(h.status("a && b || c"), 4);
    assert_eq!(h.ran(), ["a", "b", "c"]);
    assert_eq!(h.status("false && a"), 1);
    assert_eq!(h.status("b || false && a"), 1);
}

// NFR-COMPAT-01: `!` inverts the pipeline's status.
#[test]
fn negation_inverts_exit_status() {
    let mut h = Harness::new();
    h.on("x", &[exited(5)]);
    assert_eq!(h.status("! false"), 0);
    assert_eq!(h.status("! true"), 1);
    assert_eq!(h.status("! x"), 0);
    assert_eq!(h.interpreter.state().last_status(), Status::SUCCESS);
}

// NFR-COMPAT-01: a `case` with no matching arm is 0, whatever `$?` was.
#[test]
fn case_without_match_returns_zero() {
    let mut h = Harness::new();
    assert_eq!(h.status("false; case a in b) x;; c|d) x;; esac"), 0);
    assert_eq!(h.ran(), ["false"]);
    assert_eq!(h.status("false; case a in esac"), 0);
}

#[test]
fn case_runs_the_first_matching_arm_with_patterns() {
    let mut h = Harness::new();
    h.on("a", &[exited(2)]);
    h.on("b", &[exited(0)]);
    assert_eq!(h.status("case main.rs in *.md) b;; *.rs|*.c) a;; *) b;; esac"), 2);
    assert_eq!(h.ran(), ["a"]);
    // A quoted star matches only itself.
    assert_eq!(h.status("case x in '*') a;; [xyz]) b;; esac"), 0);
    assert_eq!(h.ran(), ["a", "b"]);
}

#[test]
fn case_arm_with_empty_body_is_zero() {
    let mut h = Harness::new();
    assert_eq!(h.status("false; case a in a) ;; esac"), 0);
}

// Bash 4: `;&` runs the next body without testing it, `;;&` goes on testing.
#[test]
fn case_fall_through_and_continue() {
    let mut h = Harness::new();
    for program in ["a", "b", "c"] {
        h.on(program, &[exited(0)]);
    }
    h.status("case a in a) a ;& z) b ;; *) c ;; esac");
    assert_eq!(h.ran(), ["a", "b"]);
    h.status("case a in a) a ;;& z) b ;; *) c ;; esac");
    assert_eq!(h.ran(), ["a", "b", "a", "c"]);
}

// NFR-COMPAT-09: command not found is 127, with bash's message.
#[test]
fn missing_command_returns_127() {
    let mut h = Harness::new();
    assert_eq!(h.status("true\nnope_zz"), 127);
    assert_eq!(h.diagnostics.text(), "knsh: line 2: nope_zz: command not found\n");
    assert_eq!(h.status("./missing"), 127);
    assert!(h.diagnostics.text().ends_with("./missing: No such file or directory\n"));
    assert_eq!(h.ran(), ["true"]);
}

// NFR-COMPAT-09: found but not executable is 126.
#[test]
fn non_executable_returns_126() {
    let mut h = Harness::new();
    h.fs.write(Path::new("/bin/data"), b"", 0o644).unwrap();
    h.fs.add_dir_all(Path::new("/work/dir")).unwrap();
    assert_eq!(h.status("data"), 126);
    assert_eq!(h.status("./dir"), 126);
    assert_eq!(
        h.diagnostics.text(),
        "knsh: line 1: data: Permission denied\nknsh: line 1: ./dir: Is a directory\n"
    );
    // The system refusing at exec time is 126 too, and nothing is looked up twice.
    h.on("tool", &[CommandOutcome::NotExecutable]);
    assert_eq!(h.status("tool"), 126);
    h.on("x", &[CommandOutcome::NotFound]);
    assert_eq!(h.status("x"), 127);
}

// NFR-COMPAT-01: a command killed by signal n is 128 + n.
#[test]
fn signal_exit_is_128_plus_signal() {
    let mut h = Harness::new();
    h.on("x", &[CommandOutcome::Finished(ExitStatus::Signalled(9))]);
    assert_eq!(h.status("x"), 137);
    assert_eq!(h.interpreter.state().last_status(), Status::new(137));
}

/// `true` nested in `levels` groups: `{ { … true; }; }`, built by hand to pass the parser's own limit.
fn nested_groups(levels: usize) -> Script {
    let mut script = parse("true").unwrap();
    for _ in 0..levels {
        let span = script.span;
        let group = Command::Compound(CompoundCommand {
            kind: CompoundKind::Group(Group {
                open: span,
                body: std::mem::take(&mut script.items),
                close: span,
            }),
            redirections: Vec::new(),
            span,
        });
        script.items = vec![ListItem {
            and_or: AndOr {
                first: Pipeline {
                    time: None,
                    negation: None,
                    first: group,
                    rest: Vec::new(),
                    span,
                },
                rest: Vec::new(),
                span,
            },
            separator: None,
        }];
    }
    script
}

/// Runs `test` on a thread with a large stack: building and dropping a tree a thousand levels deep recurses in the
/// test itself, outside the interpreter's control.
fn with_large_stack(test: impl FnOnce() + Send + 'static) {
    std::thread::Builder::new()
        .stack_size(256 * 1024 * 1024)
        .spawn(test)
        .unwrap()
        .join()
        .unwrap();
}

// KNSH-096: nesting past the explicit limit is an error, never a stack overflow, and the limit itself fits.
#[test]
fn deep_recursion_fails_with_error_not_crash() {
    with_large_stack(|| {
        let mut h = Harness::new();
        // The script's own list is one level, so this many groups reach the limit exactly.
        let at_limit = nested_groups(MAX_EVAL_DEPTH - 1);
        assert_eq!(h.interpreter.run(&at_limit, "true"), Ok(Status::SUCCESS));
        let past_limit = nested_groups(MAX_EVAL_DEPTH);
        assert_eq!(
            h.interpreter.run(&past_limit, "true"),
            Err(InterpError::DepthExceeded { limit: MAX_EVAL_DEPTH })
        );
        assert_eq!(h.ran(), ["true"]);
    });
}

// The evaluator's own guard (not only the check before it) stops at the limit, so dynamic nesting added later
// (functions, `source`, `eval`) is bounded too.
#[test]
fn evaluator_enforces_the_depth_limit_itself() {
    let mut h = Harness::new();
    h.interpreter.max_depth = 4;
    let script = nested_groups(10);
    let run = Run { source: "true" };
    assert_eq!(
        h.interpreter.list(&script.items, &run),
        Err(Stop::Error(InterpError::DepthExceeded { limit: 4 }))
    );
    assert_eq!(h.ran(), Vec::<String>::new());
    // Depth is released on the way out, so the next run starts from zero.
    assert_eq!(h.interpreter.depth, 0);
}

#[test]
fn max_depth_is_clamped_to_what_the_stack_holds() {
    let h = Harness::new();
    assert_eq!(h.interpreter.with_max_depth(usize::MAX).max_depth, MAX_EVAL_DEPTH);
}

// NFR-COMPAT-01: `if` statuses, `elif` and `else`.
#[test]
fn if_runs_the_first_true_branch_and_is_zero_without_one() {
    let mut h = Harness::new();
    h.on("a", &[exited(7)]);
    assert_eq!(h.status("if false; then a; elif true; then a; else b; fi"), 7);
    assert_eq!(h.status("if false; then a; fi"), 0);
    assert_eq!(h.status("if false; then a; else false; fi"), 1);
    assert_eq!(h.ran(), ["false", "true", "a", "false", "false", "false"]);
}

#[test]
fn for_loops_set_the_variable_and_keep_the_last_body_status() {
    let mut h = Harness::new();
    h.on("a", &[exited(0), exited(0), exited(6)]);
    assert_eq!(h.status("for v in one 'two 2' three; do a \"v\"; done"), 6);
    assert_eq!(h.interpreter.state().variable("v"), Some(std::ffi::OsStr::new("three")));
    assert_eq!(h.status("false; for v in; do a; done"), 0);
    assert_eq!(h.ran(), ["a", "a", "a", "false"]);
}

#[test]
fn for_without_in_walks_the_positional_parameters() {
    let mut h = Harness::new();
    h.on("a", &[exited(0)]);
    let state = h
        .interpreter
        .state()
        .clone()
        .with_positional(vec!["p1".into(), "p2".into()]);
    *h.interpreter.state_mut() = state;
    h.status("for p; do a; done");
    assert_eq!(h.ran(), ["a", "a"]);
    assert_eq!(h.interpreter.state().variable("p"), Some(std::ffi::OsStr::new("p2")));
}

// Bash: an invalid `for` variable is reported and the loop is status 1.
#[test]
fn for_with_an_invalid_name_fails_with_one() {
    let mut h = Harness::new();
    assert_eq!(h.status("for 1 in a; do x; done"), 1);
    assert_eq!(h.diagnostics.text(), "knsh: line 1: `1': not a valid identifier\n");
    assert_eq!(h.ran(), Vec::<String>::new());
}

#[test]
fn while_and_until_loop_on_their_condition() {
    let mut h = Harness::new();
    h.on("cond", &[exited(0), exited(0), exited(1)]);
    h.on("body", &[exited(3), exited(4)]);
    assert_eq!(h.status("while cond; do body; done"), 4);
    assert_eq!(h.ran(), ["cond", "body", "cond", "body", "cond"]);
    // A condition true from the start: `until` never runs its body, nor `while` with a false one.
    assert_eq!(h.status("until true; do body; done"), 0);
    assert_eq!(h.status("while false; do body; done"), 0);
}

#[test]
fn until_runs_the_body_while_the_condition_fails() {
    let mut h = Harness::new();
    h.on("cond", &[exited(1), exited(1), exited(0)]);
    h.on("body", &[exited(0)]);
    assert_eq!(h.status("until cond; do body; done"), 0);
    assert_eq!(h.ran(), ["cond", "body", "cond", "body", "cond"]);
}

#[test]
fn groups_run_in_the_current_shell() {
    let mut h = Harness::new();
    assert_eq!(h.status("{ X=1; false; }"), 1);
    assert_eq!(h.interpreter.state().variable("X"), Some(std::ffi::OsStr::new("1")));
}

// `$?` is set after each pipeline; an empty script leaves it alone.
#[test]
fn last_status_follows_each_pipeline() {
    let mut h = Harness::new();
    assert_eq!(h.status("true; false"), 1);
    assert_eq!(h.interpreter.state().last_status(), Status::FAILURE);
    assert_eq!(h.status("# nothing"), 1);
    assert_eq!(h.status("X=1"), 0);
}

#[test]
fn passes_argv_environment_and_directory_to_the_spawner() {
    let mut h = Harness::new();
    h.on("env", &[exited(0)]);
    assert_eq!(h.status("A=1 env 'x y' z"), 0);
    let request = &h.commands.runs()[0];
    assert_eq!(request.program, Path::new("/bin/env"));
    assert_eq!(request.argv0, "env");
    assert_eq!(request.args, [OsString::from("x y"), OsString::from("z")]);
    assert_eq!(request.cwd, Path::new("/work"));
    assert_eq!(
        request.env,
        [
            (OsString::from("A"), OsString::from("1")),
            (OsString::from("PATH"), OsString::from("/bin")),
            (OsString::from("PWD"), OsString::from("/work")),
            (OsString::from("SHLVL"), OsString::from("1")),
        ]
    );
    // The prefix assignment did not change the shell.
    assert_eq!(h.interpreter.state().variable("A"), None);
}

#[test]
fn assignments_set_shell_variables_without_exporting_them() {
    let mut h = Harness::new();
    h.on("env", &[exited(0)]);
    h.status("A=1 B=2 A+=3; env");
    assert_eq!(h.interpreter.state().variable("A"), Some(std::ffi::OsStr::new("13")));
    assert!(!h.interpreter.state().is_exported("A"));
    let env = &h.commands.runs()[0].env;
    assert!(env.iter().all(|(name, _)| name != "A"));
    // An exported variable reaches commands with its new value.
    h.status("PATH=/bin:/nowhere; env");
    assert!(
        h.commands.runs()[1]
            .env
            .contains(&("PATH".into(), "/bin:/nowhere".into()))
    );
}

// Bash looks a command up with its own `PATH=` assignment.
#[test]
fn a_prefix_path_assignment_is_used_for_lookup() {
    let mut h = Harness::new();
    h.fs.add_dir_all(Path::new("/opt")).unwrap();
    h.fs.write(Path::new("/opt/only"), b"", 0o755).unwrap();
    h.commands.on("/opt/only", exited(0));
    assert_eq!(h.status("only"), 127);
    assert_eq!(h.status("PATH=/opt only"), 0);
}

// Fail closed before anything runs: a script using a later story's feature runs none of its commands.
#[test]
fn unsupported_constructs_are_refused_before_anything_runs() {
    let mut h = Harness::new();
    let cases: &[(&str, Unsupported)] = &[
        ("true; echo $(ls)", Unsupported::CommandSubstitution),
        ("true; echo $RANDOM", Unsupported::ShellVariable),
        ("true; echo ${#LINENO}", Unsupported::ShellVariable),
        ("true; echo ${!BASH*}", Unsupported::ShellVariable),
        ("true; echo ${a[0]}", Unsupported::Array),
        ("true; echo ${x@P}", Unsupported::PromptExpansion),
        ("true; (( x )) > out", Unsupported::Redirection),
        ("true; ls *.rs", Unsupported::PathnameExpansion),
        ("true > out", Unsupported::Redirection),
        ("{ true; } 2>&1", Unsupported::Redirection),
        ("true | true", Unsupported::Pipeline),
        ("true &", Unsupported::Background),
        ("(true)", Unsupported::Subshell),
        ("time true", Unsupported::Time),
        ("f() { true; }", Unsupported::FunctionDefinition),
        ("true; cd /", Unsupported::Builtin),
        ("if true; then export X; fi", Unsupported::Builtin),
        ("mapfile x", Unsupported::Builtin),
        ("for v in *; do true; done", Unsupported::PathnameExpansion),
        ("echo {a,$x}", Unsupported::BraceExpansion),
    ];
    for (line, feature) in cases {
        assert_eq!(refused(h.run(line)), *feature, "{line}");
    }
    assert!(matches!(refused(h.run("[[ -n x ]]")), Unsupported::Construct(_)));
    assert_eq!(h.ran(), Vec::<String>::new());
}

// The builtins with an equivalent program run as that program for now.
#[test]
fn stateless_builtins_run_as_their_programs() {
    let mut h = Harness::new();
    for program in ["echo", "test", "printf"] {
        h.on(program, &[exited(0)]);
    }
    assert_eq!(h.status("echo hi; test -n x; printf x; true"), 0);
    assert_eq!(h.ran(), ["echo", "test", "printf", "true"]);
}

// Fail closed: a builtin whose program would act differently for these arguments is refused, never run as the
// program (macOS `/bin/echo` has no `-e` and stops at `\c`; `printf -v` sets a variable; `test -v` reads one).
#[test]
fn builtin_forms_the_programs_do_not_share_are_refused() {
    let mut h = Harness::new();
    for line in [
        "echo -e 'a\\nb'",
        "echo -n -n x",
        "echo -nE x",
        r"echo 'a\c'",
        "printf -v x %s y",
        "printf '%q' x",
        "printf '%-5Q' x",
        "printf '%(%Y)T'",
        "test -v HOME",
        "[ -o emacs ]",
        "true; [ a = a -a b = b ]",
    ] {
        assert_eq!(refused(h.run(line)), Unsupported::Builtin, "{line}");
    }
    assert_eq!(h.ran(), Vec::<String>::new());
    for program in ["echo", "printf", "test"] {
        h.on(program, &[exited(0)]);
    }
    assert_eq!(h.status("echo -n x; echo - -x; printf '%s %%q\\n' a; test -e x"), 0);
    assert_eq!(h.ran(), ["echo", "echo", "printf", "test"]);
}

// Bash never searches `PATH` for a builtin: another `echo` on `PATH`, or `PATH` unset, changes nothing.
#[test]
fn builtins_ignore_path() {
    let mut h = Harness::new();
    h.fs.add_dir_all(Path::new("/evil")).unwrap();
    h.fs.write(Path::new("/evil/echo"), b"", 0o755).unwrap();
    h.on("echo", &[exited(0)]);
    assert_eq!(h.status("PATH=/evil echo hi"), 0);
    assert_eq!(h.status("PATH=/nowhere; echo hi"), 0);
    let programs: Vec<_> = h.commands.runs().into_iter().map(|run| run.program).collect();
    assert_eq!(programs, [Path::new("/bin/echo"), Path::new("/bin/echo")]);
}

// A failure to start a command that is not the command's fault stops the script.
#[test]
fn platform_failures_stop_the_script() {
    let mut h = Harness::new();
    // `x` is on the filesystem but not scripted: the fake spawner fails.
    assert_eq!(h.run("x; true"), Err(InterpError::Platform(PlatformError::NotScripted)));
    assert_eq!(h.ran(), ["x"]);
}

#[test]
fn a_script_parsed_from_other_text_is_refused() {
    let mut h = Harness::new();
    let script = parse("true hello").unwrap();
    assert!(matches!(
        h.interpreter.run(&script, "true"),
        Err(InterpError::SourceMismatch { .. })
    ));
}

// ---- KNSH-097: expansions in commands ----

/// The arguments of each run, in order.
fn args(h: &Harness) -> Vec<Vec<String>> {
    h.commands
        .runs()
        .into_iter()
        .map(|run| run.args.into_iter().map(|arg| arg.into_string().unwrap()).collect())
        .collect()
}

#[test]
fn expanded_words_reach_the_command() {
    let mut h = Harness::new();
    h.on("tool", &[exited(0)]);
    h.interpreter.state_mut().set_variable("x", "a b");
    assert_eq!(h.status(r#"y=$((2 * 3)); tool "$x" ${y} "${x#a }" $z"#), 0);
    assert_eq!(args(&h), [vec!["a b", "6", "b"]]);
}

// Bash expands the words first, then the assignments in order, each seeing the ones before it; prefix assignments
// reach only the command's environment.
#[test]
fn assignments_expand_in_order_after_the_words() {
    let mut h = Harness::new();
    h.on("env", &[exited(0)]);
    h.interpreter.state_mut().set_variable("a", "old");
    assert_eq!(h.status("a=new b=$a env $a"), 0);
    let run = &h.commands.runs()[0];
    assert_eq!(run.args, [OsString::from("old")]);
    assert!(run.env.contains(&("b".into(), "new".into())));
    assert_eq!(h.interpreter.state().variable("a"), Some(std::ffi::OsStr::new("old")));
    assert_eq!(h.status("c=1 d=$c"), 0);
    assert_eq!(h.interpreter.state().variable("d"), Some(std::ffi::OsStr::new("1")));
}

// Bash: `(( ))` is 0 for a non-zero result, 1 for zero or an error, and the script goes on after an error.
#[test]
fn double_paren_status_is_zero_for_nonzero_result() {
    let mut h = Harness::new();
    assert_eq!(h.status("(( 2 ))"), 0);
    assert_eq!(h.status("(( 0 ))"), 1);
    assert_eq!(h.status("(( -1 ))"), 0);
    assert_eq!(h.status("((x = 5, x > 3))"), 0);
    assert_eq!(h.interpreter.state().variable("x"), Some(std::ffi::OsStr::new("5")));
    assert_eq!(h.status("(( 1/0 )); true"), 0);
    assert_eq!(h.status("(( 1/0 ))"), 1);
    assert_eq!(
        h.diagnostics.text(),
        "knsh: line 1: ((: 1/0 : division by 0 (error token is \"0 \")\n\
         knsh: line 1: ((: 1/0 : division by 0 (error token is \"0 \")\n"
    );
}

#[test]
fn let_evaluates_each_argument_and_tests_the_last() {
    let mut h = Harness::new();
    // Unquoted, `b=a*2` would be a pathname pattern (refused until KNSH-098), as in bash.
    assert_eq!(h.status("let a=1+2 'b=a*2'"), 0);
    assert_eq!(h.interpreter.state().variable("b"), Some(std::ffi::OsStr::new("6")));
    assert_eq!(h.status("let 'c = 0'"), 1);
    assert_eq!(h.status("let"), 1);
    assert_eq!(h.status("let 1/0 d=9"), 1);
    assert_eq!(h.interpreter.state().variable("d"), None);
    assert_eq!(
        h.diagnostics.text(),
        "knsh: line 1: let: expression expected\nknsh: line 1: let: 1/0: division by 0 (error token is \"0\")\n"
    );
}

// Fail closed: `a=1 let …` gives `let` a temporary scope that is not emulated, and a prefix assignment to a variable
// bash maintains (read-only `UID` makes bash run nothing) is refused before anything runs.
#[test]
fn let_with_prefix_assignments_and_bash_variables_are_refused() {
    let mut h = Harness::new();
    h.on("tool", &[exited(0)]);
    assert_eq!(refused(h.run("tool; a=5 let 'x=a'")), Unsupported::Builtin);
    assert_eq!(h.interpreter.state().variable("x"), None);
    assert_eq!(refused(h.run("tool; UID=0 tool")), Unsupported::ShellVariable);
    assert_eq!(refused(h.run("tool; RANDOM=1")), Unsupported::ShellVariable);
    // Only the first `tool`, of the first script: the others were refused before running.
    assert_eq!(h.ran(), ["tool"]);
}

#[test]
fn arithmetic_for_loops_like_bash() {
    let mut h = Harness::new();
    h.on("tool", &[exited(0)]);
    assert_eq!(h.status("for ((i = 0; i < 3; i++)); do tool $i; done"), 0);
    assert_eq!(args(&h), [vec!["0"], vec!["1"], vec!["2"]]);
    assert_eq!(h.interpreter.state().variable("i"), Some(std::ffi::OsStr::new("3")));
    // The body's last status; 0 when it never runs.
    assert_eq!(h.status("for ((;0;)); do tool; done"), 0);
    assert_eq!(h.status("for ((n = 2; n; n--)) { false; }"), 1);
    // An arithmetic error ends the loop with status 1.
    assert_eq!(h.status("for ((j = 0; j < 1/0; j++)); do tool; done"), 1);
    // Three `tool` runs and two `false` runs: the last loop's body never ran.
    assert_eq!(h.commands.runs().len(), 5);
}

// Bash (`-c`): an expansion error abandons the rest of its line with status 1; the next line runs.
#[test]
fn expansion_errors_discard_the_rest_of_the_line() {
    let mut h = Harness::new();
    h.on("tool", &[exited(0)]);
    let status = h.status("tool one; echo $((1/0)); tool same-line\ntool next \"$?\"\nif true; then\n  tool ${x!}\n  tool inside\nfi\ntool after");
    assert_eq!(status, 0);
    // `true` (the `if` condition) ran; nothing else of the `if` did.
    let expected: [&[&str]; 4] = [&["one"], &["next", "1"], &[], &["after"]];
    assert_eq!(args(&h), expected);
    assert_eq!(
        h.diagnostics.text(),
        "knsh: line 1: 1/0: division by 0 (error token is \"0\")\nknsh: line 4: ${x!}: bad substitution\n"
    );
    assert_eq!(h.status("tool; x=$((2/0))"), 1);
}

// With `set -u`, an unset parameter ends the script with status 1 and bash's message.
#[test]
fn nounset_ends_the_script_with_status_one() {
    let mut h = Harness::new();
    h.on("tool", &[exited(0)]);
    h.interpreter.state_mut().options_mut().nounset = true;
    assert_eq!(h.status("tool a\ntool $missing\ntool never"), 1);
    assert_eq!(args(&h), [vec!["a"]]);
    assert_eq!(h.interpreter.state().last_status(), Status::FAILURE);
    assert_eq!(h.diagnostics.text(), "knsh: line 2: missing: unbound variable\n");
    assert_eq!(h.status("tool ${missing:-ok} \"$@\""), 0);
    assert_eq!(h.status("tool ${missing?gone}; tool never"), 1);
    assert!(h.diagnostics.text().ends_with("knsh: line 1: missing: gone\n"));
}

// Fail closed: a builtin or a split word that only an expansion reveals is refused when it is found.
#[test]
fn refusals_found_by_expansion_stop_the_script_there() {
    let mut h = Harness::new();
    h.on("tool", &[exited(0)]);
    h.interpreter.state_mut().set_variable("cmd", "cd");
    h.interpreter.state_mut().set_variable("words", "a b");
    assert_eq!(refused(h.run("tool; $cmd /; tool")), Unsupported::Builtin);
    assert_eq!(refused(h.run("tool $words")), Unsupported::WordSplitting);
    assert_eq!(refused(h.run("echo -e${cmd:+n} x")), Unsupported::Builtin);
    assert_eq!(h.ran(), ["tool"]);
}

// Fail closed: where bash does not split, it joins an unquoted `$*` or `$@` with the first character of `IFS` or a
// space depending on the context and version (bash 3.2: `x=$*` is `a:b` but `${x:?$*}` says `a b` with `IFS=:`).
// With a space first in `IFS` every form agrees; otherwise the join is refused.
#[test]
fn unquoted_lists_joined_without_splitting_follow_ifs_or_are_refused() {
    let mut h = Harness::new();
    h.on("tool", &[exited(0)]);
    let state = h
        .interpreter
        .state()
        .clone()
        .with_positional(vec!["a".into(), "b".into()]);
    *h.interpreter.state_mut() = state;
    assert_eq!(h.status("x=$* y=$@; case $* in 'a b') tool \"$x\" \"$y\";; esac"), 0);
    assert_eq!(args(&h), [vec!["a b", "a b"]]);
    for line in [
        "IFS=:; x=$*",
        "IFS=:; x=$@",
        "IFS=; x=$*",
        "IFS=:; case $* in *) ;; esac",
        "IFS=:; x=${u:=$@}",
    ] {
        assert_eq!(refused(h.run(line)), Unsupported::WordSplitting, "{line}");
    }
    // Quoted, the join is bash's in every context: `"$*"` with the first character of `IFS`, `"$@"` with spaces.
    assert_eq!(h.status("IFS=:; x=\"$*\" y=\"$@\"; IFS=' '; tool \"$x\" \"$y\""), 0);
    assert_eq!(args(&h)[1], ["a:b", "a b"]);
}

#[test]
fn case_and_for_words_expand() {
    let mut h = Harness::new();
    h.on("tool", &[exited(0)]);
    h.interpreter.state_mut().set_variable("f", "main.rs");
    h.interpreter.state_mut().set_variable("pat", "*.rs");
    assert_eq!(
        h.status(
            "case $f in \"$pat\") tool quoted;; $pat) tool pattern;; esac; for v in \"$f\" ${f%.rs}; do tool $v; done"
        ),
        0
    );
    assert_eq!(args(&h), [vec!["pattern"], vec!["main.rs"], vec!["main"]]);
}
