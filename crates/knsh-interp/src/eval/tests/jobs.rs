//! Pipelines, subshells, background jobs, job control and `time` over scripted commands (KNSH-100).

use std::time::Duration;

use knsh_platform::testing::{FakeShellTimes, FakeTerminal};
use knsh_platform::{ChildOptions, ChildSignals, GroupMembership, ProcessGroupId, Signal, signals};

use super::*;

/// Fake process ids start here (`ScriptedCommands`).
const FIRST_PID: i32 = 20_000;

/// The arguments of the `index`th command run.
fn args(h: &Harness, index: usize) -> Vec<String> {
    h.commands.runs()[index]
        .args
        .iter()
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect()
}

/// The arguments of the last command run.
fn last_args(h: &Harness) -> Vec<String> {
    args(h, h.commands.runs().len() - 1)
}

/// A harness whose shell is interactive with job control over a recording terminal.
fn interactive() -> (Harness, Arc<FakeTerminal>) {
    let terminal = Arc::new(FakeTerminal::new());
    let shared: Arc<dyn knsh_platform::JobTerminal> = terminal.clone();
    (
        Harness::with(|interpreter| interpreter.with_job_control(Some(shared))),
        terminal,
    )
}

fn group(pid: i32) -> ProcessGroupId {
    ProcessGroupId::from_raw(pid)
}

// NFR-COMPAT-02: each command's status lands in PIPESTATUS, in order; the pipeline's status is the last one's; the
// commands are connected by pipes.
#[test]
fn pipestatus_records_each_stage() {
    let mut h = Harness::new();
    h.on("a", &[exited(1)]);
    h.on("b", &[exited(0)]);
    h.on("c", &[exited(3)]);
    assert_eq!(h.status("a | b | c"), 3);
    let statuses: Vec<u8> = h.interpreter.state().pipestatus().iter().map(|s| s.code()).collect();
    assert_eq!(statuses, [1, 0, 3]);
    assert_eq!(
        h.table(0),
        [(0, "stdin".into()), (1, "|0>".into()), (2, "stderr".into())]
    );
    assert_eq!(h.table(1), [(0, "<0|".into()), (1, "|1>".into()), (2, "stderr".into())]);
    assert_eq!(
        h.table(2),
        [(0, "<1|".into()), (1, "stdout".into()), (2, "stderr".into())]
    );
    // Read as bash reads the array: every element, the first, the count, one by index, from the end.
    h.on("x", &[exited(0)]);
    h.status(r#"a | b; x "${PIPESTATUS[@]}" $PIPESTATUS ${#PIPESTATUS[@]} ${PIPESTATUS[1]} ${PIPESTATUS[-1]} "${PIPESTATUS[*]}""#);
    assert_eq!(last_args(&h), ["1", "0", "1", "2", "0", "0", "1 0"]);
    // `!` inverts the status, not PIPESTATUS; a simple command and a subshell are pipelines of one; a group run in
    // the shell leaves PIPESTATUS to its own pipelines; `&` leaves it alone.
    assert_eq!(h.status("! a | a; x ${PIPESTATUS[@]}"), 0);
    assert_eq!(last_args(&h), ["1", "1"]);
    h.status("a | b; { a | c; }; x ${PIPESTATUS[@]}");
    assert_eq!(last_args(&h), ["1", "3"]);
    h.status("a; (b); x ${PIPESTATUS[@]}");
    assert_eq!(last_args(&h), ["0"]);
    h.status("a; b & x ${PIPESTATUS[@]}");
    assert_eq!(last_args(&h), ["1"]);
}

// NFR-COMPAT-02: under pipefail the status is the rightmost failure, 0 when none failed.
#[test]
fn pipefail_returns_rightmost_failure() {
    let mut h = Harness::new();
    h.on("a", &[exited(2)]);
    h.on("b", &[exited(0)]);
    h.on("c", &[exited(3)]);
    assert_eq!(h.status("a | c | b"), 0);
    h.interpreter.state_mut().options_mut().pipefail = true;
    assert_eq!(h.status("a | c | b"), 3);
    assert_eq!(h.status("c | a | b"), 2);
    assert_eq!(h.status("b | b"), 0);
    assert_eq!(h.status("! a | b"), 0);
}

// NFR-COMPAT-02: with lastpipe and no job control the last command runs in the shell, so its assignments last;
// otherwise every command is a subshell.
#[test]
fn lastpipe_runs_last_stage_in_shell() {
    let mut h = Harness::new();
    h.status("true | v=5");
    assert_eq!(h.interpreter.state().variable("v"), None);
    h.interpreter.state_mut().options_mut().lastpipe = true;
    assert_eq!(h.status("false | v=5"), 0);
    assert_eq!(h.interpreter.state().variable("v").unwrap(), "5");
    // Its standard input is still the pipe, only while it runs.
    h.on("x", &[exited(0)]);
    h.status("true | x");
    assert_eq!(h.table(h.commands.runs().len() - 1)[0], (0, "<2|".into()));
    // Under job control lastpipe has no effect, as in bash.
    let (mut h, _) = interactive();
    h.interpreter.state_mut().options_mut().lastpipe = true;
    h.status("true | w=1");
    assert_eq!(h.interpreter.state().variable("w"), None);
}

// NFR-COMPAT-02: a subshell's variables, descriptors and exit do not reach the shell; stages are subshells too.
#[test]
fn subshell_changes_do_not_leak() {
    let mut h = Harness::new();
    h.on("x", &[exited(0)]);
    h.status("v=1; (v=2; exec 3>f; x $v); x $v");
    assert_eq!(args(&h, 0), ["2"]);
    assert_eq!(h.table(0).len(), 4, "the subshell's own descriptor 3");
    assert_eq!(args(&h, 1), ["1"]);
    assert_eq!(h.table(1).len(), 3);
    assert_eq!(h.interpreter.state().variable("v").unwrap(), "1");
    // `exit` is a refused builtin until KNSH-101; a fatal expansion error ends only the subshell, with status 1.
    h.interpreter.state_mut().options_mut().nounset = true;
    assert_eq!(h.status("(x $unset; x never); x after"), 0);
    assert_eq!(last_args(&h), ["after"]);
    h.interpreter.state_mut().options_mut().nounset = false;
    // A compound stage runs in a subshell on its own thread.
    h.status("{ w=3; x in-group; } | x reader; x ${w-unset}");
    assert_eq!(last_args(&h), ["unset"]);
    assert!(h.ran().iter().filter(|name| *name == "x").count() >= 4);
    // A subshell's redirections and status.
    h.on("a", &[exited(4)]);
    assert_eq!(h.status("(a) 2>err"), 4);
    assert_eq!(h.table(h.commands.runs().len() - 1)[2], (2, "/work/err".into()));
    assert_eq!(h.status("(true; a)"), 4);
}

// NFR-COMPAT-02: `cmd &` returns at once with status 0 and sets `$!` to the last command's process id; `wait $!`
// gives its status. Without job control it stays in the shell's group and ignores interrupts.
#[test]
fn background_job_sets_last_pid() {
    let mut h = Harness::new();
    h.on("a", &[exited(0)]);
    h.commands.on_after("/bin/b", Duration::from_millis(50), exited(7));
    h.on("x", &[exited(0)]);
    h.status("x \"$!\"");
    assert_eq!(last_args(&h), [""]);
    assert_eq!(h.status("a | b & x $!"), 0);
    // `x` was 20,000, `a` 20,001: `$!` is the last command, `b`.
    assert_eq!(last_args(&h), [(FIRST_PID + 2).to_string()]);
    assert_eq!(h.status("wait $!"), 7);
    assert_eq!(
        h.status(&format!("wait {}", FIRST_PID + 2)),
        127,
        "a job waited for is forgotten"
    );
    assert!(h.diagnostics.text().contains("is not a child of this shell"));
    let options = h.commands.options();
    assert_eq!(options[0].signals, ChildSignals::Inherit);
    assert_eq!(options[2].group, GroupMembership::Inherit);
    assert_eq!(options[2].signals, ChildSignals::IgnoreInterrupt);
    // `$!` of a list the shell runs itself has no process id: refused, never made up.
    assert!(matches!(refused(h.run("{ a; } & x $!")), Unsupported::InShellProcessId));
    h.status("wait");
    // A background list runs whole in a subshell.
    h.status("v=1 && x in-list & wait; x ${v-unset}");
    assert_eq!(last_args(&h), ["unset"]);
}

// NFR-COMPAT-02: `wait -n` returns the first job to end (an ended, unreported one first), then 127 once none is
// left.
#[test]
fn wait_n_returns_first_finished_job() {
    let mut h = Harness::new();
    h.commands.on_after("/bin/a", Duration::from_millis(400), exited(3));
    h.commands.on_after("/bin/b", Duration::from_millis(10), exited(5));
    h.on("x", &[exited(0)]);
    assert_eq!(h.status("a & b & wait -n"), 5);
    assert_eq!(h.status("wait -n"), 3);
    assert_eq!(h.status("wait -n"), 127);
    // Already ended before `wait -n` runs: reported at once.
    h.commands.on_after("/bin/c", Duration::ZERO, exited(9));
    h.on("c", &[exited(9)]);
    h.status("c &");
    std::thread::sleep(Duration::from_millis(50));
    assert_eq!(h.status("wait -n"), 9);
    // Only among the jobs named.
    h.commands.on_after("/bin/a", Duration::from_millis(300), exited(3));
    h.status("a & b &");
    assert_eq!(h.status("wait -n %1"), 3);
    h.status("wait");
}

// NFR-COMPAT-02: `time` reports the real, user and system time on the shell's standard error, in bash's default
// format, the POSIX one with `-p`, or TIMEFORMAT.
#[test]
fn time_keyword_reports_times() {
    let ms = Duration::from_millis;
    let times = FakeShellTimes::new()
        .then(ms(0), ms(0), ms(0))
        .then(ms(1500), ms(250), ms(125))
        .then(ms(1500), ms(250), ms(125))
        .then(ms(2500), ms(250), ms(125))
        .then(ms(2500), ms(250), ms(125))
        .then(ms(3500), ms(1250), ms(125));
    let mut h = Harness::with(|interpreter| interpreter.with_times(Arc::new(times)));
    h.on("a", &[exited(2)]);
    assert_eq!(h.status("time a | true"), 0);
    assert_eq!(
        h.diagnostics.text(),
        "\nreal\t0m1.500s\nuser\t0m0.250s\nsys\t0m0.125s\n"
    );
    assert_eq!(h.status("time -p ! a"), 0);
    assert!(h.diagnostics.text().ends_with("real 1.00\nuser 0.00\nsys 0.00\n"));
    h.status("TIMEFORMAT='%R/%U/%S %P%%'; time a 2>/dev/null");
    assert!(
        h.diagnostics.text().ends_with("1.000/1.000/0.000 100.00%\n"),
        "{}",
        h.diagnostics.text()
    );
    let before = h.diagnostics.text();
    h.status("TIMEFORMAT=; time true");
    assert_eq!(h.diagnostics.text(), before, "an empty TIMEFORMAT prints nothing");
}

// AC: non-interactive scripts do not create job-control process groups, like bash.
#[test]
fn scripts_do_not_create_process_groups() {
    let mut h = Harness::new();
    h.on("a", &[exited(0)]);
    h.status("a; a | a; (a); a & wait; { a; } | a");
    let options = h.commands.options();
    assert_eq!(options.len(), 7);
    for option in &options {
        assert_eq!(option.group, GroupMembership::Inherit);
        assert_eq!(option.terminal, None);
    }
    assert_eq!(h.interpreter.job_signals().groups(), Vec::new());
}

// AC: in an interactive shell each pipeline is a job with a process group of its own, led by its first command,
// which takes the terminal; the shell takes it back when the job ends.
#[test]
fn interactive_pipelines_get_their_own_process_group() {
    let (mut h, terminal) = interactive();
    // `a` outlives `b`'s start, so `b` joins its group rather than leading a new one after `a` was reaped.
    h.commands.on_after("/bin/a", Duration::from_millis(50), exited(0));
    h.on("b", &[exited(0)]);
    h.status("a | b; b");
    let options = h.commands.options();
    assert_eq!(options[0].group, GroupMembership::Lead);
    assert!(options[0].terminal.is_some());
    assert_eq!(options[0].signals, ChildSignals::Default);
    assert_eq!(options[1].group, GroupMembership::Join(group(FIRST_PID)));
    assert_eq!(options[1].terminal, None);
    assert_eq!(options[2].group, GroupMembership::Lead);
    assert_eq!(terminal.changes(), [None, None]);
    // A background job leads its group without the terminal and is announced.
    h.commands.on_after("/bin/c", Duration::from_millis(30), exited(0));
    h.status("c &");
    let options = h.commands.options();
    assert_eq!(
        options[3],
        ChildOptions {
            group: GroupMembership::Lead,
            terminal: None,
            signals: ChildSignals::Default,
            ignore: knsh_platform::SignalSet::new(),
        }
    );
    assert!(h.diagnostics.text().ends_with(&format!("[1] {}\n", FIRST_PID + 3)));
    std::thread::sleep(Duration::from_millis(80));
    h.interpreter.notify_jobs().unwrap();
    assert!(h.diagnostics.text().ends_with("[1]+  Done                    c\n"));
    h.on("x", &[exited(0)]);
    h.status("x $-");
    assert_eq!(last_args(&h), ["himB"]);
}

// NFR-COMPAT-02: Ctrl-Z stops a foreground job; `jobs`, `bg` and `fg` follow bash's output and signals.
#[test]
fn stopped_jobs_resume_with_bg_and_fg() {
    let (mut h, terminal) = interactive();
    h.commands.on_stopping("/bin/a", signals::SIGTSTP, exited(0));
    let stopped = 128 + u8::try_from(signals::SIGTSTP).unwrap();
    assert_eq!(h.status("a"), stopped);
    assert!(h.diagnostics.text().ends_with("\n[1]+  Stopped                 a\n"));
    h.status("jobs");
    assert_eq!(h.output.text(), "[1]+  Stopped                 a\n");
    h.status("bg");
    assert!(h.output.text().ends_with("[1]+ a &\n"));
    assert_eq!(h.commands.signals(), [(group(FIRST_PID), Signal::Continue)]);
    assert_eq!(h.status("wait"), 0);
    // `fg` gives the job the terminal and waits for it.
    h.commands.on_stopping("/bin/b", signals::SIGTSTP, exited(6));
    assert_eq!(h.status("b"), stopped);
    let before = terminal.changes().len();
    assert_eq!(h.status("fg %1"), 6);
    assert!(h.output.text().ends_with("b\n"));
    assert_eq!(terminal.changes()[before..], [Some(group(FIRST_PID + 1)), None]);
    assert_eq!(h.status("fg"), 1);
    assert!(h.diagnostics.text().ends_with("fg: current: no such job\n"));
}

// FR-SES-10: the supervisor's pause stops every job's group and its resume continues them; a stop it causes is not
// taken for Ctrl-Z.
#[test]
fn pause_and_resume_signal_every_job_group() {
    let (mut h, _) = interactive();
    h.commands.on_after("/bin/a", Duration::from_millis(200), exited(0));
    h.commands.on_after("/bin/b", Duration::from_millis(200), exited(0));
    h.status("a & b &");
    let signals = h.interpreter.job_signals();
    assert_eq!(signals.groups(), [group(FIRST_PID), group(FIRST_PID + 1)]);
    signals.pause().unwrap();
    signals.resume().unwrap();
    assert_eq!(
        h.commands.signals(),
        [
            (group(FIRST_PID), Signal::Stop),
            (group(FIRST_PID + 1), Signal::Stop),
            (group(FIRST_PID), Signal::Continue),
            (group(FIRST_PID + 1), Signal::Continue),
        ]
    );
    assert_eq!(h.status("wait"), 0);
    assert_eq!(signals.groups(), Vec::new(), "ended jobs leave the registry");
    assert_eq!(signals.pause(), Ok(()), "nothing left to signal");
}

// NFR-COMPAT-02: `|&` sends standard error into the pipe after the command's own redirections, as bash does.
#[test]
fn pipe_all_joins_standard_error_after_redirections() {
    let mut h = Harness::new();
    h.on("a", &[exited(0)]);
    h.on("b", &[exited(0)]);
    let script = knsh_bash::parse("a 2>/dev/null |& b").unwrap();
    h.interpreter.run(&script, "a 2>/dev/null |& b").unwrap();
    assert_eq!(h.table(0), [(0, "stdin".into()), (1, "|0>".into()), (2, "|0>".into())]);
    assert_eq!(h.table(1)[0], (0, "<0|".into()));
}

// NFR-COMPAT-02: the job builtins' errors and statuses follow bash.
#[test]
fn job_builtin_errors_match_bash() {
    let mut h = Harness::new();
    assert_eq!(h.status("wait 12345"), 127);
    assert_eq!(h.status("wait %3"), 127);
    assert_eq!(h.status("wait x"), 1);
    assert_eq!(h.status("wait -z"), 2);
    assert_eq!(h.status("fg"), 1);
    assert_eq!(h.status("bg"), 1);
    assert_eq!(h.status("disown"), 1);
    assert_eq!(h.status("jobs %1"), 1);
    assert_eq!(h.status("jobs; wait"), 0);
    let text = h.diagnostics.text();
    for message in [
        "knsh: line 1: wait: pid 12345 is not a child of this shell\n",
        "knsh: line 1: wait: %3: no such job\n",
        "knsh: line 1: wait: `x': not a pid or valid job spec\n",
        "knsh: line 1: wait: -z: invalid option\n",
        "knsh: line 1: fg: no job control\n",
        "knsh: line 1: bg: no job control\n",
        "knsh: line 1: disown: current: no such job\n",
        "knsh: line 1: jobs: %1: no such job\n",
    ] {
        assert!(text.contains(message), "{message:?} in {text:?}");
    }
    assert_eq!(h.output.text(), "");
    // A running job is listed with `&`; disowned, it is gone.
    h.commands.on_after("/bin/a", Duration::from_millis(100), exited(0));
    h.status("a & jobs; jobs -p; disown %1; jobs");
    assert_eq!(
        h.output.text(),
        format!("[1]+  Running                 a &\n{FIRST_PID}\n")
    );
}

// CLAUDE.md "Concurrency": every child is waited for through its handle; none is left unreaped by a pipeline.
#[test]
fn pipelines_reap_every_child() {
    let mut h = Harness::new();
    h.on("a", &[exited(0)]);
    h.status("a | a | a; (a | a) | a; a & wait");
    assert_eq!(h.commands.unreaped(), Vec::<i32>::new());
}

// FR-SES-10: a job inside a job (a command of a compound stage) shares the outer job's group; its end must not take
// that group out of what the pause reaches while the outer job still runs.
#[test]
fn nested_jobs_keep_the_outer_group_paused() {
    let (mut h, _) = interactive();
    // Both outlive the other's start, so they share one group whichever starts first.
    h.commands.on_after("/bin/a", Duration::from_millis(50), exited(0));
    h.commands.on_after("/bin/b", Duration::from_millis(300), exited(0));
    h.status("{ a; } | b &");
    std::thread::sleep(Duration::from_millis(100));
    assert_eq!(h.interpreter.job_signals().groups(), [group(FIRST_PID)]);
    assert_eq!(h.status("wait"), 0);
    assert_eq!(h.interpreter.job_signals().groups(), Vec::new());
}

// CLAUDE.md "Concurrency": `fg` of a job that already ended neither continues it nor gives its group (whose id may
// be free again) the terminal; bash reports `job has terminated`.
#[test]
fn fg_refuses_a_job_that_ended() {
    let (mut h, terminal) = interactive();
    h.on("a", &[exited(0)]);
    h.status("a &");
    std::thread::sleep(Duration::from_millis(50));
    let before = terminal.changes().len();
    assert_eq!(h.status("fg %1"), 1);
    assert_eq!(h.status("bg %1"), 1);
    assert!(h.diagnostics.text().contains("fg: job has terminated\n"));
    assert!(h.diagnostics.text().contains("bg: job has terminated\n"));
    assert_eq!(terminal.changes().len(), before, "the terminal was not handed over");
    assert_eq!(h.commands.signals(), []);
}

// NFR-COMPAT-02: Ctrl-Z on a subshell alone stops the job as bash's would (the subshell reports its stopped
// programs to the shell) instead of leaving the shell waiting for them; `fg` continues it.
#[test]
fn stopped_subshell_is_reported_and_resumed() {
    let (mut h, _) = interactive();
    h.commands.on_stopping("/bin/a", signals::SIGTSTP, exited(4));
    let stopped = 128 + u8::try_from(signals::SIGTSTP).unwrap();
    assert_eq!(h.status("( a )"), stopped);
    assert!(
        h.diagnostics
            .text()
            .ends_with("\n[1]+  Stopped                 ( a )\n")
    );
    assert_eq!(h.status("fg"), 4);
    assert_eq!(h.commands.signals(), [(group(FIRST_PID), Signal::Continue)]);
    assert_eq!(h.commands.unreaped(), Vec::<i32>::new());
    // A group alone runs in the shell, so its program is a job of its own and stops as one.
    h.commands.on_stopping("/bin/b", signals::SIGTSTP, exited(0));
    assert_eq!(h.status("{ b; }"), stopped);
    assert_eq!(h.status("fg"), 0);
}
