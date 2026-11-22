//! KNSH-108: the interpreter of a native-mode line, whose every external command goes to the supervisor through
//! [`SupervisedSpawner`] (FR-LC-53 to FR-LC-57). The supervisor is [`FakeSupervisor`]: it records each command,
//! denies the programs it is told to, and lets the others exit at once.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use knsh_bash::{ParseOptions, parse_with};
use knsh_platform::Fs as _;
use knsh_platform::supervision::{SupervisedSpawner, UNREACHABLE};
use knsh_platform::testing::{FakeCollation, FakeDescriptors, FakeSupervisor, FakeUserHomes, MemFs};

use super::Buffer;
use crate::{InterpError, Interpreter, ShellState, Status};

/// Programs present in the fake `/bin`.
const PROGRAMS: &[&str] = &["a", "b", "c", "git", "tool"];

struct Supervised {
    interpreter: Interpreter,
    supervisor: Arc<FakeSupervisor>,
    spawner: Arc<SupervisedSpawner>,
    fs: Arc<MemFs>,
    /// What the shell's builtins write on standard output.
    output: Buffer,
    /// The process's standard error, where a denial of a command without redirections is reported.
    stderr: Buffer,
}

impl Supervised {
    fn new(supervisor: FakeSupervisor) -> Self {
        let fs = Arc::new(MemFs::new());
        fs.add_dir_all(Path::new("/bin")).unwrap();
        fs.add_dir_all(Path::new("/work")).unwrap();
        for program in PROGRAMS {
            fs.write(&Path::new("/bin").join(program), b"", 0o755).unwrap();
        }
        let supervisor = Arc::new(supervisor);
        let output = Buffer::default();
        let stderr = Buffer::default();
        let spawner = Arc::new(SupervisedSpawner::new(
            supervisor.clone(),
            Box::new(output.clone()),
            Box::new(stderr.clone()),
        ));
        let state = ShellState::new("knsh", "/work")
            .unwrap()
            .with_environment([("PATH".into(), "/bin".into())]);
        let interpreter = Interpreter::new(
            state,
            fs.clone(),
            spawner.clone(),
            Arc::new(FakeUserHomes::new()),
            Arc::new(FakeCollation::new().with_locale("en_US.UTF-8")),
            Arc::new(FakeDescriptors::new(fs.clone())),
            Box::new(stderr.clone()),
        )
        .with_output(Box::new(output.clone()));
        Self {
            interpreter,
            supervisor,
            spawner,
            fs,
            output,
            stderr,
        }
    }

    fn run(&mut self, line: &str) -> Result<Status, InterpError> {
        let script = parse_with(line, ParseOptions::default().with_arrays(true)).unwrap();
        self.interpreter.run(&script, line)
    }

    fn status(&mut self, line: &str) -> u8 {
        self.run(line).unwrap().code()
    }

    /// `(program, argv[1..])` of every command the supervisor was asked about, as text.
    fn asked(&self) -> Vec<(String, Vec<String>)> {
        self.supervisor
            .argvs()
            .into_iter()
            .map(|(program, args)| (text(program.as_os_str()), args.iter().map(|arg| text(arg)).collect()))
            .collect()
    }
}

fn text(value: &std::ffi::OsStr) -> String {
    value.to_string_lossy().into_owned()
}

fn asked(program: &str, args: &[&str]) -> (String, Vec<String>) {
    (program.to_owned(), args.iter().map(|&arg| arg.to_owned()).collect())
}

// FR-LC-53: every external command of the script, in a loop, in a function and in a pipeline, is submitted to the
// supervisor on its own, with its descriptors; builtins are not.
#[test]
fn each_external_command_requests_decision() {
    let mut h = Supervised::new(FakeSupervisor::new());
    let status =
        h.status("f() { c inside; }\na first\nfor i in 1 2; do b \"$i\"; done\nf\necho builtin\ntool x | tool y");
    assert_eq!(status, 0);
    let asked = h.asked();
    assert_eq!(
        asked[..4],
        [
            asked_of("/bin/a", &["first"]),
            asked_of("/bin/b", &["1"]),
            asked_of("/bin/b", &["2"]),
            asked_of("/bin/c", &["inside"]),
        ]
    );
    // The pipeline's two stages start side by side: both were asked about, in either order.
    let mut stages = asked[4..].to_vec();
    stages.sort();
    assert_eq!(stages, [asked_of("/bin/tool", &["x"]), asked_of("/bin/tool", &["y"])]);
    // Each came with its whole descriptor table: stdin, stdout and stderr at least.
    assert!(h.supervisor.descriptor_counts().iter().all(|&count| count >= 3));
    assert_eq!(h.output.text(), "builtin\n");
}

fn asked_of(program: &str, args: &[&str]) -> (String, Vec<String>) {
    asked(program, args)
}

// FR-LC-53: a command built by `eval`, by `source` or from variables is submitted after expansion, with the argv it
// really has: the supervisor sees `git push`, not `eval`.
#[test]
fn eval_command_decided_after_expansion() {
    let mut h = Supervised::new(FakeSupervisor::new());
    h.fs.write(Path::new("/work/steps.sh"), b"a \"from source\"\n", 0o644)
        .unwrap();
    let status = h.status(
        "cmd=git; sub=push\neval \"$cmd \\\"\\$sub\\\" --force\"\n\"$cmd\" status\n. ./steps.sh\nx=$(tool inner)",
    );
    assert_eq!(status, 0);
    assert_eq!(
        h.asked(),
        [
            asked("/bin/git", &["push", "--force"]),
            asked("/bin/git", &["status"]),
            asked("/bin/a", &["from source"]),
            asked("/bin/tool", &["inner"]),
        ]
    );
    let first = &h.supervisor.submitted()[0];
    assert_eq!(first.argv0, OsString::from("git"));
    assert_eq!(first.cwd, PathBuf::from("/work"));
    assert!(first.env.iter().any(|(name, value)| name == "PATH" && value == "/bin"));
}

// FR-LC-55: a denied command fails with 126 inside the script, its reason on the command's standard error, and the
// script goes on as bash's rules say.
#[test]
fn denied_command_returns_126_inside_script() {
    let supervisor = FakeSupervisor::new().denying("/bin/git", "denied by exec.deny[0]");
    let mut h = Supervised::new(supervisor);
    let status = h.status("git push\necho \"status $?\"\ngit push || echo fallback\na after");
    assert_eq!(status, 0);
    assert_eq!(h.output.text(), "status 126\nfallback\n");
    assert_eq!(
        h.stderr.text(),
        "knsh: git: denied by exec.deny[0]\nknsh: git: denied by exec.deny[0]\n"
    );
    // The denied command was asked about each time and never "ran"; the script carried on to `a`.
    assert_eq!(
        h.asked(),
        [
            asked("/bin/git", &["push"]),
            asked("/bin/git", &["push"]),
            asked("/bin/a", &["after"]),
        ]
    );
}

// FR-LC-55: under `set -e` a denial ends the script with 126, as any failing command would.
#[test]
fn errexit_stops_script_after_denial() {
    let supervisor = FakeSupervisor::new().denying("/bin/git", "the authority denied it");
    let mut h = Supervised::new(supervisor);
    let status = h.status("set -e\na before\ngit push\necho after");
    assert_eq!(status, 126);
    assert_eq!(h.output.text(), "");
    assert_eq!(h.asked(), [asked("/bin/a", &["before"]), asked("/bin/git", &["push"])]);
    assert_eq!(h.stderr.text(), "knsh: git: the authority denied it\n");
}

// FR-LC-57, NFR-REL-01: without the supervisor nothing runs: every command is denied with 126 and the reason, and the
// spawner stays broken.
#[test]
fn unreachable_supervisor_denies_everything() {
    let mut h = Supervised::new(FakeSupervisor::unreachable());
    let status = h.status("a\necho \"a=$?\"\nb x\necho \"b=$?\"");
    assert_eq!(status, 0);
    assert_eq!(h.output.text(), "a=126\nb=126\n");
    assert_eq!(
        h.stderr.text(),
        format!("knsh: a: {UNREACHABLE}\nknsh: b: {UNREACHABLE}\n")
    );
    assert_eq!(h.supervisor.submitted(), Vec::new());
    assert!(h.spawner.is_broken());
}

// A program's own exit status comes back from the supervisor unchanged.
#[test]
fn allowed_command_status_comes_from_the_supervisor() {
    let mut h = Supervised::new(FakeSupervisor::new().exiting("/bin/tool", 3));
    assert_eq!(h.status("tool; echo \"$?\""), 0);
    assert_eq!(h.output.text(), "3\n");
}
