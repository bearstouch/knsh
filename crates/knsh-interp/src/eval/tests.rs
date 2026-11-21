//! Evaluator tests over the fake filesystem and scripted commands: no process ever starts.

use std::path::Path;
use std::sync::{Arc, Mutex, PoisonError};

use knsh_bash::{AndOr, CompoundCommand, Group, ListItem, ParseOptions, Pipeline, parse, parse_with};
use knsh_platform::testing::{FakeCollation, FakeDescriptors, FakeOpened, FakeUserHomes, MemFs, ScriptedCommands};
use knsh_platform::{ChildDescriptor, PlatformError, StandardStream};

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
    descriptors: Arc<FakeDescriptors>,
    diagnostics: Buffer,
    /// The spawner's standard output, as the shell itself writes to it.
    output: Buffer,
}

impl Harness {
    /// `/bin` holds [`PROGRAMS`]; `true` exits 0 and `false` 1; `PATH=/bin`.
    fn new() -> Self {
        Self::with(|interpreter| interpreter)
    }

    /// As [`Harness::new`], with the interpreter changed by `configure` (job control, clocks).
    fn with(configure: impl FnOnce(Interpreter) -> Interpreter) -> Self {
        Self::with_descriptors(|interpreter, _| configure(interpreter))
    }

    /// As [`Harness::with`], `configure` also given the fake descriptors (to make standard input, KNSH-102).
    fn with_descriptors(configure: impl FnOnce(Interpreter, &FakeDescriptors) -> Interpreter) -> Self {
        Self::build(false, configure)
    }

    /// As [`Harness::new`], with pipes that carry data and scripted commands that keep none of their descriptors
    /// open, so the shell reads what its own builtins write into a pipe (KNSH-105: command substitution, coprocesses).
    fn with_data_pipes() -> Self {
        Self::build(true, |interpreter, _| interpreter)
    }

    fn build(data_pipes: bool, configure: impl FnOnce(Interpreter, &FakeDescriptors) -> Interpreter) -> Self {
        let fs = Arc::new(MemFs::new());
        fs.add_dir_all(Path::new("/bin")).unwrap();
        fs.add_dir_all(Path::new("/work")).unwrap();
        for program in PROGRAMS {
            fs.write(&Path::new("/bin").join(program), b"", 0o755).unwrap();
        }
        let commands = Arc::new(if data_pipes {
            ScriptedCommands::new().releasing_descriptors()
        } else {
            ScriptedCommands::new()
        });
        commands.on("/bin/true", exited(0));
        commands.on("/bin/false", exited(1));
        let diagnostics = Buffer::default();
        let output = Buffer::default();
        let descriptors = FakeDescriptors::new(fs.clone());
        let descriptors = Arc::new(if data_pipes {
            descriptors.with_data_pipes()
        } else {
            descriptors
        });
        let state = ShellState::new("knsh", "/work")
            .unwrap()
            .with_environment([("PATH".into(), "/bin".into())]);
        let homes = Arc::new(FakeUserHomes::new().with_user("alice", "/Users/alice"));
        let interpreter = Interpreter::new(
            state,
            fs.clone(),
            commands.clone(),
            homes,
            Arc::new(FakeCollation::new().with_locale("en_US.UTF-8")),
            descriptors.clone(),
            Box::new(diagnostics.clone()),
        )
        .with_output(Box::new(output.clone()));
        let interpreter = configure(interpreter, &descriptors);
        Self {
            interpreter,
            commands,
            fs,
            descriptors,
            diagnostics,
            output,
        }
    }

    /// Scripts `/bin/<program>` to give `outcomes` in order, the last repeated.
    fn on(&self, program: &str, outcomes: &[CommandOutcome]) {
        for outcome in outcomes {
            self.commands.on(Path::new("/bin").join(program), *outcome);
        }
    }

    /// Runs `line`, read as bash 5.2 reads it (`{name}>file` is a redirection, KNSH-099; `coproc`, KNSH-105).
    fn run(&mut self, line: &str) -> Result<Status, InterpError> {
        let options = ParseOptions::default()
            .with_redirection_variables(true)
            .with_arrays(true)
            .with_coproc(true);
        let script = parse_with(line, options).unwrap();
        self.interpreter.run(&script, line)
    }

    /// The descriptor table of the `index`th command run: each number with what it holds, as text (`stdout`, a
    /// file's path, `<<<text`).
    fn table(&self, index: usize) -> Vec<(i32, String)> {
        let runs = self.commands.runs();
        runs[index]
            .descriptors
            .iter()
            .map(|(fd, held)| {
                let text = match held {
                    ChildDescriptor::Standard(StandardStream::Input) => "stdin".to_owned(),
                    ChildDescriptor::Standard(StandardStream::Output) => "stdout".to_owned(),
                    ChildDescriptor::Standard(StandardStream::Error) => "stderr".to_owned(),
                    ChildDescriptor::Open(file) => match self.descriptors.opened(file) {
                        Some(FakeOpened::File { path, .. }) => path.display().to_string(),
                        Some(FakeOpened::HereString(text)) => format!("<<<{}", String::from_utf8_lossy(&text)),
                        Some(FakeOpened::Pipe { n, write: true }) => format!("|{n}>"),
                        Some(FakeOpened::Pipe { n, write: false }) => format!("<{n}|"),
                        Some(FakeOpened::Input { .. }) => "input".to_owned(),
                        None => "unknown".to_owned(),
                    },
                };
                (*fd, text)
            })
            .collect()
    }

    /// The contents of `/work/<name>` as text, if it exists.
    fn file(&self, name: &str) -> Option<String> {
        self.fs
            .contents(&Path::new("/work").join(name))
            .map(|data| String::from_utf8(data).unwrap())
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
    // `true` and `false` are builtins (KNSH-101): nothing ran.
    assert_eq!(h.ran(), Vec::<String>::new());
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
    assert_eq!(h.ran(), Vec::<String>::new());
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
    assert_eq!(h.ran(), Vec::<String>::new());
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
        // The innermost command is the builtin `true` (KNSH-101): no program ran.
        assert_eq!(h.ran(), Vec::<String>::new());
    });
}

// The evaluator's own guard (not only the check before it) stops at the limit, so dynamic nesting added later
// (functions, `source`, `eval`) is bounded too.
#[test]
fn evaluator_enforces_the_depth_limit_itself() {
    let mut h = Harness::new();
    h.interpreter.max_depth = 4;
    let script = nested_groups(10);
    let run = Run::new("true");
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
    assert_eq!(h.ran(), ["a"]);
}

#[test]
fn for_loops_set_the_variable_and_keep_the_last_body_status() {
    let mut h = Harness::new();
    h.on("a", &[exited(0), exited(0), exited(6)]);
    assert_eq!(h.status("for v in one 'two 2' three; do a \"v\"; done"), 6);
    assert_eq!(h.interpreter.state().variable("v"), Some(std::ffi::OsStr::new("three")));
    assert_eq!(h.status("false; for v in; do a; done"), 0);
    assert_eq!(h.ran(), ["a", "a", "a"]);
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
        // KNSH-105: what a substitution's or here-document's body holds is checked with the script.
        ("true; echo $(echo $RANDOM)", Unsupported::ShellVariable),
        ("true; echo `echo \\`echo $RANDOM\\``", Unsupported::ShellVariable),
        ("true; cat <(echo $RANDOM)", Unsupported::ShellVariable),
        ("true; cat <<EOF\n$RANDOM\nEOF\n", Unsupported::ShellVariable),
        ("true; coproc cat | x", Unsupported::Coproc),
        ("true; ! coproc cat", Unsupported::Coproc),
        ("true; coproc cat &", Unsupported::Coproc),
        ("true; coproc RANDOM { cat; }", Unsupported::ShellVariable),
        ("true; echo $RANDOM", Unsupported::ShellVariable),
        ("true; echo ${#LINENO}", Unsupported::ShellVariable),
        ("true; echo ${!BASH*}", Unsupported::ShellVariable),
        ("true; echo ${x@P}", Unsupported::PromptExpansion),
        ("true; (( x )) > out", Unsupported::Redirection),
        // KNSH-100: without clocks `time` cannot report; PIPESTATUS is read, never assigned.
        ("time true", Unsupported::Time),
        ("true; PIPESTATUS=1", Unsupported::ShellVariable),
        ("true | { echo $(echo $RANDOM); }", Unsupported::ShellVariable),
        ("true & (ulimit -n)", Unsupported::Builtin),
        // KNSH-104: a `SIGCHLD` trap, and a trap's text, are checked before anything runs.
        ("true; trap x CHLD", Unsupported::Trap),
        ("true; trap 'echo $(echo $RANDOM)' EXIT", Unsupported::ShellVariable),
        // KNSH-102: `[[ … ]]` with what bash's parser rejects, or a command substitution inside.
        ("true; [[ a b ]]", Unsupported::Conditional),
        ("true; [[ $(ls) ]]", Unsupported::CommandSubstitution),
        ("true; [[ x ]] >out", Unsupported::Conditional),
        ("if true; then shopt -s nocasematch; fi", Unsupported::ShellOption),
        // KNSH-103: `mapfile` reads standard input, which the host did not give; a function's definition is not
        // printed; the call stack's arrays are the shell's.
        ("mapfile x", Unsupported::StandardDescriptor),
        ("f() { :; }; type f", Unsupported::FunctionPrint),
        ("true; FUNCNAME=x", Unsupported::ShellVariable),
        // KNSH-104: options the interpreter does not implement; `set` alone would list bash's own variables.
        ("true; set -a", Unsupported::ShellOption),
        ("true; set -o posix", Unsupported::ShellOption),
        ("true; set", Unsupported::ShellVariable),
    ];
    for (line, feature) in cases {
        assert_eq!(refused(h.run(line)), *feature, "{line}");
    }
    assert!(matches!(
        refused(h.run("select x in a; do true; done")),
        Unsupported::Construct(_)
    ));
    assert_eq!(h.ran(), Vec::<String>::new());
}

// KNSH-102: `test`, `[` and `printf` are builtins the interpreter runs itself; no program starts.
#[test]
fn test_and_printf_run_in_the_shell() {
    let mut h = Harness::new();
    assert_eq!(h.status("test -n x && [ a = a ] && printf '%s\\n' ok"), 0);
    assert_eq!(h.output.text(), "ok\n");
    assert_eq!(h.ran(), Vec::<String>::new());
}

// Bash never searches `PATH` for a builtin: another `printf` on `PATH`, or `PATH` unset, changes nothing.
#[test]
fn builtins_ignore_path() {
    let mut h = Harness::new();
    h.fs.add_dir_all(Path::new("/evil")).unwrap();
    h.fs.write(Path::new("/evil/printf"), b"", 0o755).unwrap();
    assert_eq!(h.status("PATH=/evil printf hi"), 0);
    assert_eq!(h.status("PATH=/nowhere; printf hi"), 0);
    assert_eq!(h.output.text(), "hihi");
    assert_eq!(h.commands.runs().len(), 0);
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
    // Three `tool` runs (`false` is a builtin): the last loop's body never ran.
    assert_eq!(h.commands.runs().len(), 3);
}

// Bash (`-c`): an expansion error abandons the rest of its line with status 1; the next line runs.
#[test]
fn expansion_errors_discard_the_rest_of_the_line() {
    let mut h = Harness::new();
    h.on("tool", &[exited(0)]);
    let status = h.status("tool one; echo $((1/0)); tool same-line\ntool next \"$?\"\nif true; then\n  tool ${x!}\n  tool inside\nfi\ntool after");
    assert_eq!(status, 0);
    // Nothing of the `if` but its condition (the builtin `true`) ran.
    let expected: [&[&str]; 3] = [&["one"], &["next", "1"], &["after"]];
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

// Fail closed: a builtin that only an expansion reveals is refused when it is found.
#[test]
fn refusals_found_by_expansion_stop_the_script_there() {
    let mut h = Harness::new();
    h.on("tool", &[exited(0)]);
    h.interpreter.state_mut().set_variable("cmd", "getopts");
    assert_eq!(refused(h.run("tool; $cmd x y; tool")), Unsupported::Builtin);
    assert_eq!(refused(h.run("set -${cmd:+a}")), Unsupported::ShellOption);
    // A builtin produced by brace or pathname expansion too (KNSH-098).
    assert_eq!(refused(h.run("{getop,x}ts x")), Unsupported::Builtin);
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
        assert_eq!(refused(h.run(line)), Unsupported::UnsplitJoin, "{line}");
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

// ---- KNSH-098: brace expansion, word splitting, pathname expansion, quote removal ----

/// A harness whose working directory `/work` holds `files` (a name ending in `/` is a directory), with `tool`
/// scripted to succeed.
fn with_files(files: &[&str]) -> Harness {
    let h = Harness::new();
    for file in files {
        let path = Path::new("/work").join(file.trim_end_matches('/'));
        if file.ends_with('/') {
            h.fs.add_dir_all(&path).unwrap();
        } else {
            h.fs.write(&path, b"", 0o644).unwrap();
        }
    }
    h.on("tool", &[exited(0)]);
    h
}

// NFR-COMPAT-02: bash's order is brace, tilde, parameter and arithmetic, splitting, pathname, quote removal.
#[test]
fn expansion_order_matches_bash() {
    let mut h = with_files(&["a b.rs", "c.rs", "x1"]);
    let state = h.interpreter.state_mut();
    state.set_variable("a1", "one");
    state.set_variable("a2", "two");
    state.set_variable("braces", "{p,q}");
    state.set_variable("both", "*.rs z");
    state.set_variable("n", "2");
    let line = concat!(
        // Brace expansion comes first, so it builds the names expanded next; a value never brace-expands.
        "tool $a{1,2} $braces;",
        // Tilde expansion follows brace expansion.
        "tool ~{alice,nobody};",
        // Splitting before matching; matched names are never split; quoted results never match.
        "tool $both \"$both\";",
        // A sequence of literal bounds only; arithmetic inside a pattern; quotes removed last.
        "tool {1..$n} x$((n-1))* 'q'\"r\"\\s"
    );
    assert_eq!(h.status(line), 0);
    assert_eq!(
        args(&h),
        [
            vec!["one", "two", "{p,q}"],
            vec!["/Users/alice", "~nobody"],
            vec!["a b.rs", "c.rs", "z", "*.rs z"],
            vec!["{1..2}", "x1", "qrs"],
        ]
    );
}

// KNSH-098 unit test named by the story: `IFS` white space collapses and is trimmed; every other `IFS` character
// delimits a field of its own, so consecutive ones delimit empty fields.
#[test]
fn ifs_whitespace_and_nonwhitespace_delimiters() {
    let mut h = with_files(&[]);
    let state = h.interpreter.state_mut();
    state.set_variable("v", "  a  b\t\nc  ");
    state.set_variable("w", "a::b:");
    state.set_variable("m", " a : b  ::c ");
    state.set_variable("lead", ":a");
    state.set_variable("e", "");
    let line = concat!(
        "tool $v;",
        "IFS=:; tool $w;",
        "IFS=': '; tool $m;",
        "IFS=:; tool $lead x$lead;",
        // Literal text never splits; a quoted empty string in a partly quoted word is dropped (bash); tab and newline
        // are not separators when IFS is only a space.
        "IFS=' '; tool a:b \"\"$v $v\"\";",
        // Unset IFS splits on space, tab and newline.
        "unset_ifs_marker"
    );
    let line = line.replace(";unset_ifs_marker", "");
    assert_eq!(h.status(&line), 0);
    assert_eq!(
        args(&h),
        [
            vec!["a", "b", "c"],
            vec!["a", "", "b"],
            vec!["a", "b", "", "c"],
            vec!["", "a", "x", "a"],
            vec!["a:b", "a", "b\t\nc", "a", "b\t\nc"],
        ]
    );
}

// KNSH-098: bash quotes an unquoted literal character of `IFS` as it reads the word, so it never matches as a
// pattern character; the same character from an expansion splits instead (observed with `/bin/bash`).
#[test]
fn literal_ifs_characters_are_not_pattern_characters() {
    let mut h = with_files(&["a.rs", "b"]);
    h.interpreter.state_mut().set_variable("x", "a*b");
    assert_eq!(h.status("IFS='*'; tool $x * *.rs"), 0);
    assert_eq!(args(&h), [vec!["a", "b", "*", "*.rs"]]);
    assert_eq!(h.status("IFS='.?'; tool *.rs ? ?.rs"), 0);
    assert_eq!(args(&h)[1], ["a.rs", "?", "?.rs"]);
}

// KNSH-098 unit test named by the story.
#[test]
fn empty_ifs_disables_splitting() {
    let mut h = with_files(&[]);
    h.interpreter.state_mut().set_variable("v", " a b ");
    h.interpreter.state_mut().set_variable("e", "");
    assert_eq!(h.status("IFS=; tool $v $e \"$e\" ${e:- x y }"), 0);
    // Nothing splits, but an unquoted empty expansion still vanishes.
    assert_eq!(args(&h), [vec![" a b ", "", " x y "]]);
    // Unset, IFS is bash's default.
    h.interpreter.state_mut().unset("IFS").unwrap();
    assert_eq!(h.status("tool $v"), 0);
    assert_eq!(args(&h)[1], ["a", "b"]);
}

// KNSH-098 unit test named by the story, through the evaluator.
#[test]
fn unmatched_glob_stays_literal_as_an_argument() {
    let mut h = with_files(&["a.rs"]);
    h.interpreter.state_mut().set_variable("p", "*.zig");
    assert_eq!(h.status("tool *.zig $p '*'.rs [ab].rs \\*.rs"), 0);
    assert_eq!(args(&h), [vec!["*.zig", "*.zig", "*.rs", "a.rs", "*.rs"]]);
    // `set -f` turns pathname expansion off.
    h.interpreter.state_mut().options_mut().noglob = true;
    assert_eq!(h.status("tool *.rs"), 0);
    assert_eq!(args(&h)[1], ["*.rs"]);
}

// KNSH-098 unit test named by the story.
#[test]
fn nullglob_removes_unmatched_word() {
    let mut h = with_files(&["a.rs"]);
    h.interpreter.state_mut().options_mut().nullglob = true;
    assert_eq!(h.status("tool x *.zig y *.rs; for f in *.zig; do tool never; done"), 0);
    assert_eq!(args(&h), [vec!["x", "y", "a.rs"]]);
}

// KNSH-098 unit test named by the story: bash's `no match` error abandons the command and the rest of its line
// with status 1, and wins over nullglob.
#[test]
fn failglob_reports_error() {
    let mut h = with_files(&["a.rs"]);
    let options = h.interpreter.state_mut().options_mut();
    options.failglob = true;
    options.nullglob = true;
    assert_eq!(h.status("tool *.rs; tool *.zig; tool same-line\ntool next-line"), 0);
    assert_eq!(args(&h), [vec!["a.rs"], vec!["next-line"]]);
    assert_eq!(h.diagnostics.text(), "knsh: line 1: no match: *.zig\n");
    assert_eq!(h.status("tool *.zig"), 1);
    assert_eq!(h.interpreter.state().last_status(), Status::FAILURE);
}

#[test]
fn dotglob_and_globstar_options_reach_pathname_expansion() {
    let mut h = with_files(&[".env", "src/", "src/a.rs", "src/deep/", "src/deep/b.rs"]);
    assert_eq!(h.status("tool * **/*.rs"), 0);
    let options = h.interpreter.state_mut().options_mut();
    options.dotglob = true;
    options.globstar = true;
    assert_eq!(h.status("tool * **/*.rs"), 0);
    assert_eq!(
        args(&h),
        [
            vec!["src", "src/a.rs"],
            vec![".env", "src", "src/a.rs", "src/deep/b.rs"]
        ]
    );
}

// With extglob on (and the line parsed with it), groups work in words, `case` patterns and `${…}` operators.
#[test]
fn extglob_patterns_match_in_words_case_and_parameter_operators() {
    let mut h = with_files(&["a.rs", "b.c", "c.o"]);
    h.interpreter.state_mut().options_mut().extglob = true;
    h.interpreter.state_mut().set_variable("f", "main.test.rs");
    let line = "tool !(*.o) @(a|b).*; case $f in *.@(rs|c)) tool rust;; esac; tool ${f##+([a-z]).} ${f%%.+([a-z])}";
    let script = knsh_bash::parse_with(line, knsh_bash::ParseOptions::default().with_extglob(true)).unwrap();
    assert_eq!(h.interpreter.run(&script, line).unwrap().code(), 0);
    assert_eq!(
        args(&h),
        [
            vec!["a.rs", "b.c", "a.rs", "b.c"],
            vec!["rust"],
            vec!["test.rs", "main.test"]
        ]
    );
}

// CLAUDE.md "Untrusted input": a brace expansion past its bound runs nothing.
#[test]
fn oversized_brace_expansion_is_refused_before_anything_runs() {
    let mut h = with_files(&[]);
    assert!(matches!(
        h.run("tool; tool {1..99999999999}"),
        Err(InterpError::ExpansionLimit { .. })
    ));
    assert_eq!(h.ran(), Vec::<String>::new());
    assert_eq!(h.status("tool {a,b}{1..2}"), 0);
    assert_eq!(args(&h), [vec!["a1", "a2", "b1", "b2"]]);
}

// `$-` shows `f` under `set -f`, in bash's order.
#[test]
fn dollar_dash_shows_noglob() {
    let mut h = with_files(&[]);
    h.interpreter.state_mut().options_mut().noglob = true;
    assert_eq!(h.status("tool $-"), 0);
    assert_eq!(args(&h), [vec!["fhBc"]]);
}

// Bash sorts matches with `strcoll` in its locale: `LC_ALL`, else `LC_COLLATE`, else `LANG`, else C; a locale the
// system lacks leaves the C order. (The fake collation folds case in `en_US.UTF-8`; the macOS tables are tested in
// `knsh-platform`.)
#[test]
fn glob_results_are_sorted_in_the_shell_s_locale() {
    let mut h = with_files(&["B", "a", "_x"]);
    let line = concat!(
        "tool *;",
        "LANG=en_US.UTF-8; tool *;",
        "LC_COLLATE=C; tool *;",
        "LC_ALL=en_US.UTF-8; tool *;",
        "LC_ALL=xx_NOPE.UTF-8; tool *"
    );
    assert_eq!(h.status(line), 0);
    assert_eq!(
        args(&h),
        [
            vec!["B", "_x", "a"],
            vec!["_x", "a", "B"],
            vec!["B", "_x", "a"],
            vec!["_x", "a", "B"],
            vec!["B", "_x", "a"],
        ]
    );
}

// Bash drops a quoted empty string in a partly quoted word before splitting; it keeps the word only when the word
// expands to nothing at all.
#[test]
fn quoted_empty_strings_in_partly_quoted_words() {
    let mut h = with_files(&[]);
    h.interpreter.state_mut().set_variable("e", "");
    h.interpreter.state_mut().set_variable("blank", "   ");
    h.interpreter.state_mut().set_variable("v", " a ");
    assert_eq!(h.status("tool \"\"$e x ''$blank y $v\"\" \"$e\"$v"), 0);
    assert_eq!(args(&h), [vec!["", "x", "y", "a", "a"]]);
}

// ---- Redirections (KNSH-099) ----

/// `(fd, what)` pairs for [`Harness::table`] comparisons.
fn fds(entries: &[(i32, &str)]) -> Vec<(i32, String)> {
    entries.iter().map(|&(fd, what)| (fd, what.to_owned())).collect()
}

/// The table of a command without redirections.
fn standard() -> Vec<(i32, String)> {
    fds(&[(0, "stdin"), (1, "stdout"), (2, "stderr")])
}

// NFR-COMPAT-02: redirections apply left to right: `2>&1 >file` sends errors where output went before, `>file 2>&1`
// sends both to the file. The shell's own messages follow the same table.
#[test]
fn redirection_order_matters_like_bash() {
    let mut h = Harness::new();
    h.on("x", &[exited(0)]);
    assert_eq!(h.status("x 2>&1 >out; x >out 2>&1"), 0);
    assert_eq!(h.table(0), fds(&[(0, "stdin"), (1, "/work/out"), (2, "stdout")]));
    assert_eq!(h.table(1), fds(&[(0, "stdin"), (1, "/work/out"), (2, "/work/out")]));
    assert_eq!(h.status("let 1/0 2>&1 >out2; let 1/0 >out3 2>&1"), 1);
    assert!(
        h.output.text().contains("let: 1/0: division by 0"),
        "{}",
        h.output.text()
    );
    assert_eq!(h.file("out2").as_deref(), Some(""));
    assert!(h.file("out3").unwrap().contains("division by 0"));
    assert_eq!(h.diagnostics.text(), "");
}

// NFR-COMPAT-02: `set -C` makes `>` (and `&>`) refuse an existing regular file, leaving it as it was; the command
// does not run and the status is 1. New files and devices are still written.
#[test]
fn noclobber_blocks_overwrite() {
    let mut h = Harness::new();
    h.on("x", &[exited(0)]);
    h.fs.write(Path::new("/work/f"), b"old", 0o644).unwrap();
    h.interpreter.state_mut().options_mut().noclobber = true;
    assert_eq!(h.status("x >f"), 1);
    assert_eq!(h.status("x &>f"), 1);
    assert_eq!(h.file("f").as_deref(), Some("old"));
    assert_eq!(
        h.diagnostics.text(),
        "knsh: line 1: f: cannot overwrite existing file\nknsh: line 1: f: cannot overwrite existing file\n"
    );
    assert_eq!(h.ran(), Vec::<String>::new());
    assert_eq!(h.status("x >new; x >/dev/null; x >>f"), 0);
    assert_eq!(h.ran(), ["x", "x", "x"]);
    assert_eq!(h.status("echo $- >flags"), 0);
    assert_eq!(h.file("flags").as_deref(), Some("hBCc\n"));
}

// NFR-COMPAT-02: `>|` truncates even under `set -C`.
#[test]
fn force_clobber_overrides_noclobber() {
    let mut h = Harness::new();
    h.on("x", &[exited(0)]);
    h.fs.write(Path::new("/work/f"), b"old", 0o644).unwrap();
    h.interpreter.state_mut().options_mut().noclobber = true;
    assert_eq!(h.status("x >|f"), 0);
    assert_eq!(h.file("f").as_deref(), Some(""));
    assert_eq!(h.table(0), fds(&[(0, "stdin"), (1, "/work/f"), (2, "stderr")]));
}

// NFR-COMPAT-02: redirections on builtins and on compound commands hold for that command only; afterwards every
// descriptor is what it was. A redirection that fails undoes the ones before it and the command does not run.
#[test]
fn builtin_redirection_is_restored() {
    let mut h = Harness::new();
    h.on("x", &[exited(0)]);
    assert_eq!(h.status("let 1/0 2>err; let 2/0"), 1);
    assert!(h.file("err").unwrap().contains("1/0"));
    assert!(h.diagnostics.text().contains("2/0") && !h.diagnostics.text().contains("1/0"));
    assert_eq!(h.status(": >made 2>&1; x"), 0);
    assert_eq!(h.file("made").as_deref(), Some(""));
    assert_eq!(h.status("{ x; x 2>e; } >out; x"), 0);
    assert_eq!(h.table(0), standard());
    assert_eq!(h.table(1), fds(&[(0, "stdin"), (1, "/work/out"), (2, "stderr")]));
    assert_eq!(h.table(2), fds(&[(0, "stdin"), (1, "/work/out"), (2, "/work/e")]));
    assert_eq!(h.table(3), standard());
    // A failure part-way: `>a` was applied, then `<missing` failed; nothing runs and `>a` is undone.
    assert_eq!(h.status("x >a <missing; x"), 0);
    assert!(h.diagnostics.text().contains("missing: No such file or directory"));
    assert_eq!(h.commands.runs().len(), 5);
    assert_eq!(h.table(4), standard());
    assert_eq!(h.status("if x; then x; fi </missing"), 1);
    assert_eq!(h.commands.runs().len(), 5);
}

// NFR-COMPAT-02: `exec` with only redirections changes the shell's own descriptors, for the rest of the script and
// later runs; `exec 3>&-` closes; a redirection on a group around it is still undone. A failed `exec` keeps nothing.
#[test]
fn exec_redirection_persists() {
    let mut h = Harness::new();
    h.on("x", &[exited(0)]);
    assert_eq!(h.status("exec 3>file; x"), 0);
    assert_eq!(h.status("x; exec 3>&-; x"), 0);
    let with_three = fds(&[(0, "stdin"), (1, "stdout"), (2, "stderr"), (3, "/work/file")]);
    assert_eq!(h.table(0), with_three);
    assert_eq!(h.table(1), with_three);
    assert_eq!(h.table(2), standard());
    assert_eq!(h.status("{ exec 4>g; } >out; x; exec 4>&-"), 0);
    assert_eq!(
        h.table(3),
        fds(&[(0, "stdin"), (1, "stdout"), (2, "stderr"), (4, "/work/g")])
    );
    assert_eq!(h.status("exec 3>a 4</missing; x"), 0);
    assert_eq!(h.table(4), standard());
    assert_eq!(h.status("exec 2>log; let 1/0; x"), 0);
    assert!(h.file("log").unwrap().contains("1/0"));
    assert_eq!(h.table(5), fds(&[(0, "stdin"), (1, "stdout"), (2, "/work/log")]));
}

// NFR-COMPAT-02: `{name}>file` opens the lowest free descriptor from 10, stores its number in `name`, and outlives
// the command; `{name}>&-` closes the descriptor `name` holds.
#[test]
fn named_fd_assigns_variable() {
    let mut h = Harness::new();
    h.on("x", &[exited(0)]);
    assert_eq!(h.status("exec {fd}>f; x $fd {b}<&0; x $b; exec {fd}>&-; x"), 0);
    let runs = h.commands.runs();
    assert_eq!(runs[0].args, ["10"]);
    assert_eq!(runs[1].args, ["11"]);
    assert_eq!(
        h.table(0),
        fds(&[
            (0, "stdin"),
            (1, "stdout"),
            (2, "stderr"),
            (10, "/work/f"),
            (11, "stdin")
        ])
    );
    assert_eq!(
        h.table(2),
        fds(&[(0, "stdin"), (1, "stdout"), (2, "stderr"), (11, "stdin")])
    );
}

// NFR-COMPAT-02: `<<<` gives the command its word, expanded without splitting or globbing, and a newline.
#[test]
fn here_string_appends_newline() {
    let mut h = Harness::new();
    h.on("x", &[exited(0)]);
    assert_eq!(h.status("y='a  b'; x <<< $y; x <<<''; x 3<<<\"*\""), 0);
    assert_eq!(h.table(0)[0], (0, "<<<a  b\n".to_owned()));
    assert_eq!(h.table(1)[0], (0, "<<<\n".to_owned()));
    assert_eq!(h.table(2)[3], (3, "<<<*\n".to_owned()));
}

// KNSH-099: a command gets exactly the shell's open descriptors: none left over from another command's
// redirections, none the shell closed, and only what the script itself opened.
#[test]
fn no_descriptor_leak_to_children() {
    let mut h = Harness::new();
    h.on("x", &[exited(0)]);
    assert_eq!(h.status("x 3>a 7<&0; x >&- 2<&-; x"), 0);
    assert_eq!(
        h.table(0),
        fds(&[(0, "stdin"), (1, "stdout"), (2, "stderr"), (3, "/work/a"), (7, "stdin")])
    );
    assert_eq!(h.table(1), fds(&[(0, "stdin")]));
    assert_eq!(h.table(2), standard());
}

// NFR-COMPAT-02: `/dev/stdin`, `/dev/stdout`, `/dev/stderr` and `/dev/fd/N` are the shell's own descriptors (never
// the interpreter process's); `n>&m-` moves a descriptor; `>&file`, `&>` and `&>>` take output and errors.
#[test]
fn special_names_and_descriptor_forms_follow_bash() {
    let mut h = Harness::new();
    h.on("x", &[exited(0)]);
    assert_eq!(h.status("exec 3>f; x >/dev/fd/3 2>/dev/stdout </dev/stderr"), 0);
    assert_eq!(
        h.table(0),
        // `</dev/stderr` reads descriptor 2 as `2>/dev/stdout` just left it.
        fds(&[(0, "/work/f"), (1, "/work/f"), (2, "/work/f"), (3, "/work/f")])
    );
    assert_eq!(h.status("x 4>&3-; x; exec 3>&-"), 0);
    assert_eq!(
        h.table(1),
        fds(&[(0, "stdin"), (1, "stdout"), (2, "stderr"), (4, "/work/f")])
    );
    assert_eq!(h.table(2)[3], (3, "/work/f".to_owned()));
    assert_eq!(h.status("x >&both; x &>all; x &>>all; x 1>&one"), 0);
    for (index, file) in [(3, "/work/both"), (4, "/work/all"), (5, "/work/all"), (6, "/work/one")] {
        assert_eq!(h.table(index), fds(&[(0, "stdin"), (1, file), (2, file)]), "{file}");
    }
    assert_eq!(h.status("x </dev/fd/9"), 1);
    assert!(h.diagnostics.text().contains("/dev/fd/9: Bad file descriptor"));
}

// FR-NET-08 (decision 18): `/dev/tcp` and `/dev/udp` would make the shell itself connect; they are refused with a
// message, the command does not run, and the status is 1, as for any failed redirection.
#[test]
fn network_redirections_are_refused() {
    let mut h = Harness::new();
    h.on("x", &[exited(0)]);
    assert_eq!(h.status("x >/dev/tcp/example.com/80"), 1);
    assert_eq!(h.status("h=example.com; x </dev/udp/$h/53"), 1);
    assert_eq!(h.status("exec 3<>/dev/tcp/10.0.0.1/22"), 1);
    assert_eq!(h.ran(), Vec::<String>::new());
    let text = h.diagnostics.text();
    assert!(
        text.contains("/dev/tcp/example.com/80: network redirections are refused"),
        "{text}"
    );
    assert!(text.contains("/dev/udp/example.com/53"), "{text}");
}

// NFR-COMPAT-02: bash's redirection errors, each reported with status 1 and the command not run: a target that is
// not exactly one word, a descriptor that is not open or out of range, `2>&word`, an empty file name.
#[test]
fn redirection_errors_match_bash() {
    let mut h = Harness::new();
    h.on("x", &[exited(0)]);
    h.fs.write(Path::new("/work/g1"), b"", 0o644).unwrap();
    h.fs.write(Path::new("/work/g2"), b"", 0o644).unwrap();
    for (line, message) in [
        ("v='a b'; x >$v", "$v: ambiguous redirect"),
        ("x >{p,q}", "{p,q}: ambiguous redirect"),
        ("e=; x >$e", "$e: ambiguous redirect"),
        ("x >g*", "g*: ambiguous redirect"),
        ("x >&5", "5: Bad file descriptor"),
        ("x 300>f", "300: Bad file descriptor"),
        ("x 99999999999>f", "file descriptor out of range: Bad file descriptor"),
        ("x 2>&f", "f: ambiguous redirect"),
        ("x <''", ": No such file or directory"),
        ("x >/work", "/work: Is a directory"),
    ] {
        assert_eq!(h.status(line), 1, "{line}");
        let text = h.diagnostics.text();
        assert!(text.ends_with(&format!("knsh: line 1: {message}\n")), "{line}: {text}");
    }
    assert_eq!(h.ran(), Vec::<String>::new());
    // A glob matching one file is that file.
    assert_eq!(h.status("x >g1*"), 0);
    assert_eq!(h.table(0)[1], (1, "/work/g1".to_owned()));
}

// The shell's messages go nowhere while its descriptor 2 is closed.
#[test]
fn messages_to_a_closed_standard_error_are_dropped() {
    let mut h = Harness::new();
    assert_eq!(h.status("let 1/0 2>&-"), 1);
    assert_eq!(h.diagnostics.text(), "");
    assert_eq!(h.output.text(), "");
}

// NFR-COMPAT-02: a failed redirection is reported through the descriptors as the redirections before it left them,
// then undone, as bash does: `x 2>/dev/null <missing` prints nothing, `{ …; } 2>err <missing` writes to `err`.
#[test]
fn redirection_error_is_reported_before_the_undo() {
    let mut h = Harness::new();
    h.on("x", &[exited(0)]);
    assert_eq!(h.status("x 2>/dev/null <missing; exec 2>/dev/null >&9"), 1);
    assert_eq!(h.diagnostics.text(), "");
    assert_eq!(h.status("{ x; } 2>err <missing"), 1);
    assert!(h.file("err").unwrap().contains("missing: No such file or directory"));
    assert_eq!(h.diagnostics.text(), "");
    assert_eq!(h.ran(), Vec::<String>::new());
    // The undo still happened: the shell's descriptor 2 is its own again.
    assert_eq!(h.status("x <missing"), 1);
    assert!(h.diagnostics.text().contains("missing: No such file or directory"));
}

// NFR-COMPAT-02: `n>&n-` duplicates a descriptor onto itself, which bash does not do, so it neither duplicates nor
// closes it: `exec 4>&4-` leaves 4 open.
#[test]
fn moving_a_descriptor_onto_itself_keeps_it() {
    let mut h = Harness::new();
    h.on("x", &[exited(0)]);
    assert_eq!(h.status("exec 4>f; exec 4>&4-; x"), 0);
    assert_eq!(h.table(0)[3], (4, "/work/f".to_owned()));
}

mod builtins;
mod functions_arrays;
mod jobs;
mod substitution;
mod test_printf_read;
mod traps_options;
