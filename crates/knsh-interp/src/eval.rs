//! The evaluator: walks the `knsh-bash` tree and runs it (KNSH-096, KNSH-097; NFR-COMPAT-01, NFR-COMPAT-02,
//! NFR-COMPAT-09).
//!
//! Exit statuses follow bash:
//!
//! - A list's status is its last and-or list's; `a && b` runs `b` only after a success and `a || b` only after a
//!   failure, and the status is that of the last pipeline run. `!` inverts a pipeline's status. `$?` is set after
//!   every pipeline.
//! - `if` with no branch taken is 0; `for`, `while` and `until` are their body's last status, or 0 when the body never
//!   ran; `case` is its arm's last status, or 0 when no pattern matched or the arm is empty.
//! - A command not found is 127, found but not executable 126, killed by signal `n` `128 + n`.
//!
//! External commands are found with [`crate::lookup`] through [`Fs`] and started through [`CommandSpawner`], the one
//! seam every command passes through (KNSH-108 wraps it to decide on each); pipelines, subshells and jobs are in
//! `eval::job` (KNSH-100). The shell's own error messages go to
//! the injected diagnostics writer as `name: line n: message`, bash 5's format.
//!
//! - `(( expression ))` is 0 when the expression is not zero, 1 when it is zero or fails; `let` likewise for its
//!   last argument. An arithmetic error there is reported and the script goes on, as in bash.
//!
//! Words are expanded when the command runs ([`crate::expand`]): the command's words first (each brace-expanded
//! into its words by [`crate::brace`], then expanded, split and matched against file names), then its assignments
//! left to right, each seeing the ones before it. An expansion error bash treats as fatal (`set -u`, `${x?}`) ends
//! the script with status 1; any other (a bad substitution, `$((1/0))`) abandons the command and the rest of its
//! line, sets `$?` to 1, and the script goes on with the next line, as `bash -c` does.
//!
//! Nesting is counted per list entered (each compound command body, condition and case arm, and later each function
//! call), against an explicit limit, so a deep tree ends in [`InterpError::DepthExceeded`] rather than a stack
//! overflow. Loops do not nest: a loop runs any number of iterations at the same depth.

use std::ffi::{OsStr, OsString};
use std::fmt;
use std::io::Write;
use std::sync::{Arc, Mutex, PoisonError};

use knsh_bash::{
    AndOr, AndOrOperator, ArithmeticParts, CaseClause, CaseCommand, CaseTerminatorKind, Command, CommandWord,
    CompoundKind, ForCommand, IfCommand, ListItem, LoopBody, LoopCommand, Script, SimpleCommand, Span,
    UnsupportedCommand,
};
use knsh_platform::{
    ChildHandle, Collation, CommandOutcome, CommandRequest, CommandSpawner, Descriptors, ExitStatus, Fs, JobTerminal,
    ShellTimes, Started, UserHomes,
};

use crate::arith::Failure;
use crate::brace;
use crate::check;
use crate::error::{InterpError, Unsupported};
use crate::expand::{ExpandError, Expander};
use crate::jobs::{JobSignals, Jobs, Parent, Registry};
use crate::lookup::{self, Missing, Refusal, Resolved};
use crate::pattern::Pattern;
use crate::scan;
use crate::state::{ShellState, is_name};
use crate::status::Status;
use crate::word;

mod job;
mod job_builtins;
mod redirect;

use job::JobContext;
use redirect::FdTable;
pub(crate) use redirect::here_document;

/// Deepest nesting of lists the evaluator follows: compound command bodies, conditions and case arms today, and
/// function calls, `source` and `eval` once later stories add them. Past it the run fails with
/// [`InterpError::DepthExceeded`].
///
/// Bash itself has no limit by default (`FUNCNEST` unset) and crashes when its stack runs out; this limit replaces
/// that crash with an error. 1,000 is far above what scripts nest by hand (the parser alone stops at
/// [`knsh_bash::MAX_NESTING_DEPTH`]) and leaves room for recursive functions.
pub const MAX_EVAL_DEPTH: usize = 1000;

/// Stack of the thread [`Interpreter::run`] evaluates on, sized so that [`MAX_EVAL_DEPTH`] levels fit with a wide
/// margin in an unoptimised build: [`MAX_EVAL_DEPTH`] levels were measured to need more than 2 MiB (a default thread
/// stack overflows) and less than 8 MiB. `deep_recursion_fails_with_error_not_crash` runs at the limit, so growth
/// that breaks the margin fails a test instead of a user's script. Only the pages used are committed, so the size
/// costs address space, not memory.
pub const EVAL_STACK_SIZE: usize = 64 * 1024 * 1024;

/// Builtins run as their external program for now: for the arguments a script without expansions can pass, the
/// programs in `/bin` and `/usr/bin` behave as bash's builtins do. KNSH-101 and KNSH-102 replace them.
const EXTERNAL_BUILTINS: &[&str] = &["[", "echo", "false", "printf", "test", "true"];

/// Where the programs standing in for [`EXTERNAL_BUILTINS`] are looked up, whatever `PATH` says: bash runs its
/// builtin without searching `PATH`, so a `PATH` entry holding another `echo` (or `PATH` unset) must not change what
/// runs.
const BUILTIN_PROGRAM_PATH: &str = "/bin:/usr/bin";

/// Bash 4 and 5 builtins that `knsh_bash::is_builtin` leaves out (it lists bash 3.2's), which must not be looked up
/// on `PATH` either.
const LATER_BUILTINS: &[&str] = &["compopt", "mapfile", "readarray"];

/// Whether `name` is a builtin the interpreter does not run yet: running a program of that name instead would not
/// do what bash does (`cd`, `export`, `exit` change the shell itself).
pub(crate) fn is_refused_builtin(name: &str) -> bool {
    (knsh_bash::is_builtin(name) && !EXTERNAL_BUILTINS.contains(&name) && !NATIVE_BUILTINS.contains(&name))
        || LATER_BUILTINS.contains(&name)
}

/// Builtins the interpreter runs itself: `let` (KNSH-097), `:` and `exec` with redirections only (KNSH-099), and
/// the job builtins `wait`, `jobs`, `fg`, `bg` and `disown` (KNSH-100).
const NATIVE_BUILTINS: &[&str] = &["let", ":", "exec", "wait", "jobs", "fg", "bg", "disown"];

/// Whether `exec` with `args` only changes the shell's descriptors (no arguments, or only `--`): the form the
/// interpreter runs. `exec cmd` replaces the shell and is refused until KNSH-101.
pub(crate) fn exec_redirects_only(args: &[String]) -> bool {
    matches!(args, [] | [_]) && args.first().is_none_or(|arg| arg == "--")
}

/// Whether running the builtin `name` (one of [`EXTERNAL_BUILTINS`]) as its program with `args` could do something
/// other than bash's builtin, so it must be refused until the builtin is implemented. Conservative: it refuses every
/// form the programs in `/bin` and `/usr/bin` were seen to treat differently, and a few more.
///
/// - `echo`: bash takes any leading `-n`, `-e` and `-E` words (`-ne`, `-n -n`) as options and prints backslashes
///   as written; `/bin/echo` on macOS takes only one leading `-n` and stops at a `\c`.
/// - `printf`: bash's `-v` (sets a variable) and `--`, and the `%q`, `%Q` and `%(…)T` conversions.
/// - `test` and `[`: the unary `-N`, `-v`, `-R`, `-a` and `-o`, which the programs reject or read as binary
///   operators (the binary `-a` and `-o` are refused with them).
pub(crate) fn external_builtin_differs(name: &str, args: &[String]) -> bool {
    match name {
        "echo" => {
            let mut options = args.iter().take_while(|arg| is_echo_option(arg));
            let options_differ = match (options.next(), options.next()) {
                (None, _) => false,
                (Some(only), None) => only != "-n",
                (Some(_), Some(_)) => true,
            };
            options_differ || args.iter().any(|arg| arg.contains('\\'))
        }
        "printf" => args
            .first()
            .is_some_and(|format| format.starts_with('-') || has_bash_only_conversion(format)),
        "test" | "[" => args
            .iter()
            .any(|arg| matches!(arg.as_str(), "-N" | "-v" | "-R" | "-a" | "-o")),
        _ => false,
    }
}

/// Whether bash's `echo` reads `arg` as options: `-` followed only by `n`, `e` and `E`.
fn is_echo_option(arg: &str) -> bool {
    arg.strip_prefix('-')
        .is_some_and(|letters| !letters.is_empty() && letters.chars().all(|ch| matches!(ch, 'n' | 'e' | 'E')))
}

/// Whether the `printf` format `format` holds a conversion only bash's builtin knows: `%q`, `%Q` or `%(…)T`, after
/// any flags, width and precision.
fn has_bash_only_conversion(format: &str) -> bool {
    let mut chars = format.chars();
    while let Some(ch) = chars.next() {
        if ch != '%' {
            continue;
        }
        let conversion = chars
            .by_ref()
            .find(|ch| !matches!(ch, '-' | '+' | ' ' | '#' | '0'..='9' | '.' | '*'));
        if matches!(conversion, Some('q' | 'Q' | '(')) {
            return true;
        }
    }
    false
}

/// How evaluation stopped early, inside the evaluator.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Stop {
    /// The run fails with this error.
    Error(InterpError),
    /// A bash expansion error: the rest of the current line is abandoned (already reported, `$?` set to 1).
    Discard,
    /// The shell exits with this status (already reported).
    Exit(Status),
}

impl From<InterpError> for Stop {
    fn from(error: InterpError) -> Self {
        Self::Error(error)
    }
}

impl From<knsh_platform::PlatformError> for Stop {
    fn from(error: knsh_platform::PlatformError) -> Self {
        Self::Error(InterpError::Platform(error))
    }
}

/// The evaluator's result.
type Flow<T> = Result<T, Stop>;

/// Where the program a pipeline stage starts goes (KNSH-100).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum Sink {
    /// Not evaluating a stage: a program started is waited for at once.
    #[default]
    Off,
    /// Evaluating a stage that has started nothing yet: a program started is kept here, not waited for.
    Open,
    /// The stage's program.
    Started(ChildHandle),
}

impl Sink {
    /// The program kept, if any.
    const fn started(self) -> Option<ChildHandle> {
        match self {
            Self::Started(child) => Some(child),
            Self::Off | Self::Open => None,
        }
    }
}

/// A writer the shell and its subshells (pipeline stages on other threads) share.
type SharedWriter = Arc<Mutex<Box<dyn Write + Send>>>;

/// Writes `bytes` to `writer`, ignoring a failure as bash ignores it.
fn write_shared(writer: &SharedWriter, bytes: &[u8]) {
    let mut writer = writer.lock().unwrap_or_else(PoisonError::into_inner);
    let _ = writer.write_all(bytes);
    let _ = writer.flush();
}

/// The native interpreter: shell state plus the injected effects it runs commands through.
pub struct Interpreter {
    /// Variables, positional parameters, `$?`, options and the working directory.
    state: ShellState,
    /// Where commands are looked up.
    fs: Arc<dyn Fs>,
    /// Where external commands run.
    spawner: Arc<dyn CommandSpawner>,
    /// Home directories for `~name`.
    homes: Arc<dyn UserHomes>,
    /// The order of pathname expansion results.
    collation: Arc<dyn Collation>,
    /// Where redirections open their files (KNSH-099) and pipes are made (KNSH-100).
    descriptors: Arc<dyn Descriptors>,
    /// The clocks of the `time` keyword, if given (KNSH-100).
    times: Option<Arc<dyn ShellTimes>>,
    /// The terminal of an interactive shell with job control (KNSH-100).
    terminal: Option<Arc<dyn JobTerminal>>,
    /// The spawner's standard error, for the shell's own messages while its descriptor 2 is that (bash's standard
    /// error). Shared with the shell's subshells.
    diagnostics: SharedWriter,
    /// The spawner's standard output, for what the shell itself writes there (its messages after `2>&1`, `jobs`).
    output: SharedWriter,
    /// The shell's descriptor table: what each number holds for the script (KNSH-099). Kept across runs, so
    /// `exec 3>file` lasts as long as the shell.
    fds: FdTable,
    /// The nesting limit.
    max_depth: usize,
    /// Lists currently entered.
    depth: usize,
    /// The shell's jobs (KNSH-100).
    jobs: Jobs,
    /// The job whose commands the shell is starting or running, if any: a pipeline stage, a background list or a
    /// subshell places every program it starts in that job (KNSH-100).
    placement: Option<JobContext>,
    /// While a pipeline stage that is a simple command is evaluated: where its program goes once started, so the
    /// stage does not wait for it.
    sink: Sink,
    /// The stage is followed by `|&`: its next redirections are followed by `2>&1`, as bash does.
    pipe_stderr: bool,
    /// This is a subshell: a copy of a shell, which never does job control.
    is_subshell: bool,
    /// A subshell on a thread of its own, a member of a job of its parent: where it reports that its foreground job
    /// stopped under job control (KNSH-100).
    parent: Option<Parent>,
}

impl fmt::Debug for Interpreter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Interpreter")
            .field("state", &self.state)
            .field("max_depth", &self.max_depth)
            .finish_non_exhaustive()
    }
}

impl Interpreter {
    /// An interpreter over `state` that looks commands up and matches file names through `fs`, runs commands through
    /// `spawner`, finds home directories for `~name` through `homes`, sorts file names with `collation` (bash's
    /// `strcoll` order in the shell's locale), opens redirection files through `descriptors` and writes its own
    /// error messages to `diagnostics` (the spawner's standard error, while the shell's descriptor 2 is that), with
    /// the default nesting limit [`MAX_EVAL_DEPTH`]. What the shell writes to the spawner's standard output is
    /// discarded unless [`Interpreter::with_output`] says where it goes.
    ///
    /// The shell starts with descriptors 0, 1 and 2 as the spawner's own and nothing else open.
    #[must_use]
    pub fn new(
        state: ShellState,
        fs: Arc<dyn Fs>,
        spawner: Arc<dyn CommandSpawner>,
        homes: Arc<dyn UserHomes>,
        collation: Arc<dyn Collation>,
        descriptors: Arc<dyn Descriptors>,
        diagnostics: Box<dyn Write + Send>,
    ) -> Self {
        Self {
            state,
            fs,
            spawner,
            homes,
            collation,
            descriptors,
            times: None,
            terminal: None,
            diagnostics: Arc::new(Mutex::new(diagnostics)),
            output: Arc::new(Mutex::new(Box::new(std::io::sink()))),
            fds: FdTable::standard(),
            max_depth: MAX_EVAL_DEPTH,
            depth: 0,
            jobs: Jobs::new(Arc::new(Registry::default())),
            placement: None,
            sink: Sink::Off,
            pipe_stderr: false,
            is_subshell: false,
            parent: None,
        }
    }

    /// The same interpreter writing what the shell itself sends to the spawner's standard output to `output` (its
    /// messages after `2>&1`, the output of `jobs`), so they land where commands' output does.
    #[must_use]
    pub fn with_output(mut self, output: Box<dyn Write + Send>) -> Self {
        self.output = Arc::new(Mutex::new(output));
        self
    }

    /// The same interpreter reading `times` for the `time` keyword (KNSH-100). Without clocks a script using `time`
    /// is refused before it runs ([`Unsupported::Time`]).
    #[must_use]
    pub fn with_times(mut self, times: Arc<dyn ShellTimes>) -> Self {
        self.times = Some(times);
        self
    }

    /// The same interpreter as an interactive shell with job control (`bash -i`, KNSH-100): `set -m` is on, `$-`
    /// holds `i` and `m`, each job runs in a process group of its own, a background job is announced as `[n] pid`,
    /// and with `terminal` (the shell's controlling terminal, already taken for job control) each foreground job is
    /// given the terminal, so Ctrl-Z stops it and the shell reports it stopped. The host calls
    /// [`Interpreter::notify_jobs`] before each prompt.
    #[must_use]
    pub fn with_job_control(mut self, terminal: Option<Arc<dyn JobTerminal>>) -> Self {
        self.state.set_interactive(true);
        self.state.options_mut().monitor = true;
        self.terminal = terminal;
        self
    }

    /// A handle that stops and continues every job's process group: the supervisor's pause and resume (FR-SES-10).
    #[must_use]
    pub fn job_signals(&self) -> JobSignals {
        JobSignals::new(Arc::clone(&self.jobs.registry), Arc::clone(&self.spawner))
    }

    /// Reports the background jobs that ended or stopped since the last report, as an interactive bash does before
    /// each prompt (`[1]+  Done                    sleep 1`), and forgets those that ended.
    ///
    /// # Errors
    ///
    /// [`InterpError::Platform`] if waiting for a job's process failed.
    pub fn notify_jobs(&mut self) -> Result<(), InterpError> {
        self.notify()
    }

    /// The same interpreter with nesting limit `max_depth` instead of [`MAX_EVAL_DEPTH`]. A limit above
    /// [`MAX_EVAL_DEPTH`] is clamped to it, so the evaluation thread's stack ([`EVAL_STACK_SIZE`]) always suffices.
    #[must_use]
    pub fn with_max_depth(mut self, max_depth: usize) -> Self {
        self.max_depth = max_depth.min(MAX_EVAL_DEPTH);
        self
    }

    /// The shell state.
    #[must_use]
    pub fn state(&self) -> &ShellState {
        &self.state
    }

    /// The shell state, to change between runs.
    pub fn state_mut(&mut self) -> &mut ShellState {
        &mut self.state
    }

    /// Runs `script`, parsed by [`knsh_bash::parse`] from `source`, and returns its exit status, which is also left
    /// in `$?`. An empty script leaves `$?` as it was.
    ///
    /// The whole script is checked first, so a script using something the interpreter does not support yet runs
    /// nothing. What only an expansion's value reveals is refused when the expansion runs, which stops the script
    /// there. Evaluation runs on a thread of its own with an [`EVAL_STACK_SIZE`] stack, so the nesting limit, not
    /// the caller's stack, decides how deep it goes.
    ///
    /// # Errors
    ///
    /// [`InterpError::Unsupported`] before anything runs, or when an expansion needs a later story;
    /// [`InterpError::DepthExceeded`] past the nesting limit; [`InterpError::SourceMismatch`] if `script` was not
    /// parsed from `source`; [`InterpError::Platform`] if a command could not be started or waited for, which stops
    /// the script there; [`InterpError::EvaluationThread`] if the evaluation thread could not start.
    pub fn run(&mut self, script: &Script, source: &str) -> Result<Status, InterpError> {
        std::thread::scope(|scope| {
            let worker = std::thread::Builder::new()
                .name("knsh-eval".to_owned())
                .stack_size(EVAL_STACK_SIZE)
                .spawn_scoped(scope, || self.run_here(script, source))
                .map_err(|_| InterpError::EvaluationThread)?;
            worker.join().map_err(|_| InterpError::EvaluationThread)?
        })
    }

    /// [`Interpreter::run`] on the current thread.
    fn run_here(&mut self, script: &Script, source: &str) -> Result<Status, InterpError> {
        check::check(&script.items, source, self.max_depth, self.times.is_some())?;
        self.depth = 0;
        let run = Run { source };
        match self.script(&script.items, &run) {
            Ok(status) => Ok(status),
            // Bash exits: the script ends here with this status.
            Err(Stop::Exit(status)) => {
                self.state.set_last_status(status);
                Ok(status)
            }
            Err(Stop::Discard) => Ok(self.state.last_status()),
            Err(Stop::Error(error)) => Err(error),
        }
    }

    /// Writes one of the shell's own error messages, as bash 5 does: `name: line n: message`, to the shell's
    /// descriptor 2 as the redirections in force leave it (KNSH-099). A failed write is ignored, as bash ignores it.
    fn report(&mut self, span: Span, run: &Run<'_>, message: fmt::Arguments<'_>) {
        let line = run
            .source
            .get(..span.start)
            .map_or(1, |before| before.matches('\n').count() + 1);
        let text = format!("{}: line {line}: {message}\n", self.state.name());
        self.write_shell(2, text.as_bytes());
    }

    /// Enters one more list, or fails past the nesting limit.
    fn enter(&mut self) -> Result<(), InterpError> {
        if self.depth >= self.max_depth {
            return Err(InterpError::DepthExceeded { limit: self.max_depth });
        }
        self.depth += 1;
        Ok(())
    }

    // ---- Expansion ----

    /// The outcome of an expansion at `span`: bash's errors are reported, `$?` set to 1, and turned into the way
    /// evaluation stops.
    fn expanded<T>(&mut self, result: Result<T, ExpandError>, span: Span, run: &Run<'_>) -> Flow<T> {
        result.map_err(|error| match error {
            ExpandError::Interp(error) => Stop::Error(error),
            ExpandError::Discard(message) => {
                self.report(span, run, format_args!("{message}"));
                self.state.set_last_status(Status::FAILURE);
                Stop::Discard
            }
            ExpandError::Fatal(message) => {
                self.report(span, run, format_args!("{message}"));
                Stop::Exit(Status::FAILURE)
            }
        })
    }

    /// An expander over the shell state, with the command's own assignments `overlay`.
    fn expander<'s>(&'s mut self, run: &Run<'s>, overlay: &'s [(String, OsString)]) -> Expander<'s> {
        Expander::new(
            &mut self.state,
            &*self.homes,
            &*self.fs,
            &*self.collation,
            run.source,
            overlay,
        )
    }

    /// The arguments `words` expand into: each brace-expanded, then each resulting word expanded in turn.
    fn arguments(&mut self, words: &[CommandWord], run: &Run<'_>) -> Flow<Vec<String>> {
        let mut out = Vec::with_capacity(words.len());
        for command_word in words {
            let pieces = word::pieces(&command_word.word.segments, run.source, 0)?;
            for parts in brace::expand(&pieces, command_word.span)? {
                let result = self.expander(run, &[]).arguments(&parts, command_word.span);
                out.extend(self.expanded(result, command_word.span, run)?);
            }
        }
        Ok(out)
    }

    /// The single string `command_word` expands into, without splitting.
    fn string(&mut self, command_word: &CommandWord, run: &Run<'_>) -> Flow<String> {
        let parts = word::parts(&command_word.word.segments, run.source, 0)?;
        let result = self.expander(run, &[]).string(&parts, command_word.span);
        self.expanded(result, command_word.span, run)
    }

    /// Evaluates the arithmetic expression spanning `expression` for a command at `span` named `name` (`((` or
    /// `let`) in messages: `None` when it failed with a bash error, which is reported.
    fn arithmetic(&mut self, expression: &str, name: &str, span: Span, run: &Run<'_>) -> Flow<Option<i64>> {
        let result = self.expander(run, &[]).evaluate(expression);
        match result {
            Ok(value) => Ok(Some(value)),
            Err(Failure::Error(message)) => {
                self.report(span, run, format_args!("{name}: {message}"));
                Ok(None)
            }
            Err(Failure::Unbound(variable)) => {
                self.report(span, run, format_args!("{variable}: unbound variable"));
                Err(Stop::Exit(Status::FAILURE))
            }
            Err(Failure::Unsupported(feature)) => Err(unsupported(feature, span).into()),
        }
    }

    /// The text `expression` spans, expanded as an arithmetic expression, then evaluated as for `((`.
    fn arithmetic_span(&mut self, expression: Span, span: Span, run: &Run<'_>) -> Flow<Option<i64>> {
        let result = self.expander(run, &[]).arithmetic_text(expression);
        let text = self.expanded(result, span, run)?;
        self.arithmetic(&text, "((", span, run)
    }

    // ---- Lists ----

    /// The script's own list: like [`Interpreter::list`], but a discarded line ends only that line, as in bash.
    fn script(&mut self, items: &[ListItem], run: &Run<'_>) -> Flow<Status> {
        self.enter()?;
        let result = self.script_items(items, run);
        self.depth -= 1;
        result
    }

    fn script_items(&mut self, items: &[ListItem], run: &Run<'_>) -> Flow<Status> {
        let mut status = self.state.last_status();
        // The end of the last item on a line being discarded.
        let mut discarding: Option<usize> = None;
        for item in items {
            if let Some(end) = discarding {
                let between = run.source.get(end..item.and_or.span.start).unwrap_or("\n");
                if !between.contains('\n') {
                    discarding = Some(item.and_or.span.end);
                    continue;
                }
                discarding = None;
            }
            let result = if item.is_background() {
                self.background(&item.and_or, run)
            } else {
                self.and_or(&item.and_or, run)
            };
            match result {
                Ok(done) => status = done,
                Err(Stop::Discard) => {
                    status = Status::FAILURE;
                    discarding = Some(item.and_or.span.end);
                }
                Err(stop) => return Err(stop),
            }
        }
        Ok(status)
    }

    /// Runs a list: each and-or list in turn. Its status is the last one's; an empty list leaves `$?` as it was.
    fn list(&mut self, items: &[ListItem], run: &Run<'_>) -> Flow<Status> {
        self.enter()?;
        let result = self.list_items(items, run);
        self.depth -= 1;
        result
    }

    fn list_items(&mut self, items: &[ListItem], run: &Run<'_>) -> Flow<Status> {
        let mut status = self.state.last_status();
        for item in items {
            status = if item.is_background() {
                self.background(&item.and_or, run)?
            } else {
                self.and_or(&item.and_or, run)?
            };
        }
        Ok(status)
    }

    /// `a && b || c`: left to right, each pipeline run or skipped on the status so far.
    fn and_or(&mut self, and_or: &AndOr, run: &Run<'_>) -> Flow<Status> {
        let mut status = self.pipeline(&and_or.first, run)?;
        for part in &and_or.rest {
            let runs = match part.operator {
                AndOrOperator::And => status.is_success(),
                AndOrOperator::Or => !status.is_success(),
            };
            if runs {
                status = self.pipeline(&part.pipeline, run)?;
            }
        }
        Ok(status)
    }

    fn command(&mut self, command: &Command, run: &Run<'_>) -> Flow<Status> {
        match command {
            Command::Simple(simple) => self.simple(simple, run),
            Command::Compound(compound) => {
                if let Some(span) = here_document(&compound.redirections) {
                    return Err(unsupported(Unsupported::HereDocument, span).into());
                }
                // The redirections hold for the whole body and are undone after it, however it ends.
                let Some(saved) = self.redirect(&compound.redirections, run)? else {
                    return Ok(Status::FAILURE);
                };
                let result = match &compound.kind {
                    CompoundKind::Group(group) => self.list(&group.body, run),
                    // Reached only in a subshell already (a pipeline stage, `( … )` alone): the body runs here.
                    CompoundKind::Subshell(subshell) => self.list(&subshell.body, run),
                    CompoundKind::If(command) => self.if_command(command, run),
                    CompoundKind::For(command) => self.for_command(command, run),
                    CompoundKind::While(command) => self.loop_command(command, true, run),
                    CompoundKind::Until(command) => self.loop_command(command, false, run),
                    CompoundKind::Case(command) => self.case_command(command, run),
                };
                self.restore(saved);
                result
            }
            Command::FunctionDefinition(definition) => {
                Err(unsupported(Unsupported::FunctionDefinition, definition.span).into())
            }
            Command::Unsupported(construct) => match construct.arithmetic.as_deref() {
                Some(parts) => self.arithmetic_command(construct, parts, run),
                None => Err(unsupported(Unsupported::Construct(construct.construct), construct.span).into()),
            },
        }
    }

    /// `if`: the first clause whose condition succeeds runs its body; otherwise `else`, or status 0.
    fn if_command(&mut self, command: &IfCommand, run: &Run<'_>) -> Flow<Status> {
        for clause in &command.clauses {
            if self.list(&clause.condition, run)?.is_success() {
                return self.list(&clause.body, run);
            }
        }
        match &command.else_clause {
            Some(otherwise) => self.list(&otherwise.body, run),
            None => Ok(Status::SUCCESS),
        }
    }

    /// `for name in words`: the body once per word (or per positional parameter without `in`), with `name` set.
    fn for_command(&mut self, command: &ForCommand, run: &Run<'_>) -> Flow<Status> {
        let name = self.string(&command.variable, run)?;
        if !is_name(&name) {
            self.report(
                command.variable.span,
                run,
                format_args!("`{name}': not a valid identifier"),
            );
            return Ok(Status::FAILURE);
        }
        let values: Vec<String> = match &command.items {
            Some(items) => self.arguments(&items.words, run)?,
            None => self.state.positional().to_vec(),
        };
        let mut status = Status::SUCCESS;
        for value in values {
            self.state.set_variable(&name, value);
            status = self.list(&command.body.body, run)?;
        }
        Ok(status)
    }

    /// `while` (`is_while`) or `until`: the condition, then the body while the condition succeeds (or fails).
    fn loop_command(&mut self, command: &LoopCommand, is_while: bool, run: &Run<'_>) -> Flow<Status> {
        let mut status = Status::SUCCESS;
        loop {
            let condition = self.list(&command.condition, run)?;
            if condition.is_success() != is_while {
                return Ok(status);
            }
            status = self.list(&command.body.body, run)?;
        }
    }

    /// `case`: the first arm with a matching pattern runs; `;&` runs the next arm's body too, `;;&` goes on testing.
    /// Patterns are expanded only when they are tried, as in bash.
    fn case_command(&mut self, command: &CaseCommand, run: &Run<'_>) -> Flow<Status> {
        let subject = self.string(&command.subject, run)?;
        let mut status = Status::SUCCESS;
        let mut fall_through = false;
        for clause in &command.clauses {
            if !fall_through && !self.clause_matches(clause, &subject, run)? {
                continue;
            }
            status = if clause.body.is_empty() {
                Status::SUCCESS
            } else {
                self.list(&clause.body, run)?
            };
            match clause.terminator.map(|terminator| terminator.kind) {
                None | Some(CaseTerminatorKind::Break) => return Ok(status),
                Some(CaseTerminatorKind::FallThrough) => fall_through = true,
                Some(CaseTerminatorKind::Continue) => fall_through = false,
            }
        }
        Ok(status)
    }

    /// Whether one of `clause`'s patterns matches `subject`.
    fn clause_matches(&mut self, clause: &CaseClause, subject: &str, run: &Run<'_>) -> Flow<bool> {
        for pattern_word in &clause.patterns {
            let parts = word::parts(&pattern_word.word.segments, run.source, 0)?;
            let mut expander = self.expander(run, &[]);
            let flags = expander.pattern_flags();
            let result = expander.pattern(&parts, pattern_word.span);
            let chars = self.expanded(result, pattern_word.span, run)?;
            if Pattern::new(&chars, flags).matches_str(subject) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// `(( expression ))` and `for (( init; test; update ))`.
    fn arithmetic_command(
        &mut self,
        construct: &UnsupportedCommand,
        parts: &ArithmeticParts,
        run: &Run<'_>,
    ) -> Flow<Status> {
        match parts {
            ArithmeticParts::Command { expression, close } => {
                if let Some(redirect) = trailing_redirection(run.source, close.end, construct.span) {
                    return Err(unsupported(Unsupported::Redirection, redirect).into());
                }
                Ok(match self.arithmetic_span(*expression, construct.span, run)? {
                    Some(value) if value != 0 => Status::SUCCESS,
                    Some(_) | None => Status::FAILURE,
                })
            }
            ArithmeticParts::For { expressions, body } => {
                if let Some(redirect) = trailing_redirection(run.source, body.close.end, construct.span) {
                    return Err(unsupported(Unsupported::Redirection, redirect).into());
                }
                let Some(header) = scan::arithmetic_for_header(run.source, *expressions) else {
                    return Err(unsupported(Unsupported::Construct(construct.construct), construct.span).into());
                };
                self.arithmetic_for(header, body, construct.span, run)
            }
        }
    }

    /// The loop of `for ((init; test; update))`: an empty test is true, as in bash; an arithmetic error ends the
    /// loop with status 1.
    fn arithmetic_for(&mut self, header: [Span; 3], body: &LoopBody, span: Span, run: &Run<'_>) -> Flow<Status> {
        let [init, test, update] = header;
        let blank = |part: Span| part.text(run.source).is_none_or(|text| text.trim().is_empty());
        if !blank(init) && self.arithmetic_span(init, span, run)?.is_none() {
            return Ok(Status::FAILURE);
        }
        let mut status = Status::SUCCESS;
        loop {
            if !blank(test) {
                match self.arithmetic_span(test, span, run)? {
                    None => return Ok(Status::FAILURE),
                    Some(0) => return Ok(status),
                    Some(_) => {}
                }
            }
            status = self.list(&body.body, run)?;
            if !blank(update) && self.arithmetic_span(update, span, run)?.is_none() {
                return Ok(Status::FAILURE);
            }
        }
    }

    /// `let expression…`: each argument evaluated in turn; 0 when the last is not zero, 1 when it is zero or an
    /// expression fails.
    fn let_builtin(&mut self, args: &[String], span: Span, run: &Run<'_>) -> Flow<Status> {
        if args.is_empty() {
            self.report(span, run, format_args!("let: expression expected"));
            return Ok(Status::FAILURE);
        }
        let mut last = 0;
        for arg in args {
            match self.arithmetic(arg, "let", span, run)? {
                Some(value) => last = value,
                None => return Ok(Status::FAILURE),
            }
        }
        Ok(if last == 0 { Status::FAILURE } else { Status::SUCCESS })
    }

    /// A simple command: its words are expanded, then its assignments, then its redirections are applied (left to
    /// right); assignments alone set shell variables; otherwise the command runs with them in its environment and
    /// the redirected descriptors. The redirections are undone afterwards, except for `exec` without a command.
    fn simple(&mut self, simple: &SimpleCommand, run: &Run<'_>) -> Flow<Status> {
        if let Some(span) = here_document(&simple.redirections) {
            return Err(unsupported(Unsupported::HereDocument, span).into());
        }
        let words = self.arguments(&simple.words, run)?;
        let mut assignments: Vec<(String, OsString)> = Vec::with_capacity(simple.assignments.len());
        for assignment in &simple.assignments {
            let parts = word::parts(&assignment.word.segments, run.source, assignment.value.start)?;
            let result = self
                .expander(run, &assignments)
                .assignment_value(&parts, assignment.span);
            let value = OsString::from(self.expanded(result, assignment.span, run)?);
            let value = if assignment.append {
                let mut prior = assignments
                    .iter()
                    .rev()
                    .find(|(name, _)| *name == assignment.name)
                    .map(|(_, value)| value.as_os_str())
                    .or_else(|| self.state.variable(&assignment.name))
                    .map(ToOwned::to_owned)
                    .unwrap_or_default();
                prior.push(value);
                prior
            } else {
                value
            };
            if words.is_empty() {
                // Without a command each assignment takes effect at once, so the next one sees it.
                self.state.set_variable(&assignment.name, value);
            } else {
                assignments.push((assignment.name.clone(), value));
            }
        }
        if let [name, args @ ..] = words.as_slice()
            && name == "exec"
            && !exec_redirects_only(args)
        {
            return Err(unsupported(Unsupported::Builtin, simple.span).into());
        }
        let Some(saved) = self.redirect(&simple.redirections, run)? else {
            return Ok(Status::FAILURE);
        };
        let result = self.simple_body(simple, &words, &assignments, run);
        match words.first() {
            // `exec` without a command: its redirections are the shell's from now on.
            Some(name) if name == "exec" && result.is_ok() => drop(saved),
            Some(_) | None => self.restore(saved),
        }
        result
    }

    /// The command of a simple command once its words, assignments and redirections are done.
    fn simple_body(
        &mut self,
        simple: &SimpleCommand,
        words: &[String],
        assignments: &[(String, OsString)],
        run: &Run<'_>,
    ) -> Flow<Status> {
        let Some((name, args)) = words.split_first() else {
            return Ok(Status::SUCCESS);
        };
        if name == ":" || name == "exec" {
            return Ok(Status::SUCCESS);
        }
        if let Some(result) = self.job_builtin(name, args, simple.span, run) {
            return result;
        }
        if name == "let" {
            // `a=1 let …` gives `let` a temporary scope bash's arithmetic reads and assigns in, and restores after:
            // not emulated, so refused rather than evaluated against the wrong variables.
            if !assignments.is_empty() {
                return Err(unsupported(Unsupported::Builtin, simple.span).into());
            }
            return self.let_builtin(args, simple.span, run);
        }
        if is_refused_builtin(name) || external_builtin_differs(name, args) {
            return Err(unsupported(Unsupported::Builtin, simple.span).into());
        }
        // A builtin is never searched on `PATH`. Any other name is looked up with the command's own `PATH=…`
        // assignment, if it has one, as bash does.
        let path = if EXTERNAL_BUILTINS.contains(&name.as_str()) {
            Some(OsStr::new(BUILTIN_PROGRAM_PATH))
        } else {
            assignments
                .iter()
                .rev()
                .find(|(assigned, _)| assigned == "PATH")
                .map(|(_, value)| value.as_os_str())
                .or_else(|| self.state.variable("PATH"))
        };
        match lookup::find(&*self.fs, name, path, self.state.cwd()) {
            Resolved::Program(program) => {
                let request = CommandRequest {
                    program,
                    argv0: name.into(),
                    args: args.iter().map(OsString::from).collect(),
                    env: self.state.environment(assignments),
                    cwd: self.state.cwd().to_path_buf(),
                    descriptors: self.fds.child_table(),
                };
                let outcome = match self.start_command(&request)? {
                    Started::Refused(outcome) => outcome,
                    // A pipeline stage: the pipeline waits for it with the others.
                    Started::Running(child) if self.sink == Sink::Open => {
                        self.sink = Sink::Started(child);
                        return Ok(Status::SUCCESS);
                    }
                    Started::Running(child) => self.wait_alone(child)?,
                };
                Ok(self.outcome_status(outcome, name, simple.span, run))
            }
            Resolved::NotFound(missing) => {
                let reason = match missing {
                    Missing::NotOnPath => "command not found",
                    Missing::NoSuchFile => "No such file or directory",
                };
                self.report(simple.span, run, format_args!("{name}: {reason}"));
                Ok(Status::NOT_FOUND)
            }
            Resolved::NotExecutable(refusal) => {
                let reason = match refusal {
                    Refusal::Directory => "Is a directory",
                    Refusal::PermissionDenied => "Permission denied",
                };
                self.report(simple.span, run, format_args!("{name}: {reason}"));
                Ok(Status::NOT_EXECUTABLE)
            }
        }
    }

    /// The status of a command that ran, reporting `exec` failures as bash does.
    fn outcome_status(&mut self, outcome: CommandOutcome, name: &str, span: Span, run: &Run<'_>) -> Status {
        match outcome {
            CommandOutcome::Finished(ExitStatus::Exited(code)) => Status::from_exit_code(code),
            CommandOutcome::Finished(ExitStatus::Signalled(signal)) => Status::from_signal(signal),
            CommandOutcome::NotFound => {
                self.report(span, run, format_args!("{name}: No such file or directory"));
                Status::NOT_FOUND
            }
            CommandOutcome::NotExecutable => {
                self.report(span, run, format_args!("{name}: cannot execute"));
                Status::NOT_EXECUTABLE
            }
        }
    }
}

/// What one run of a script reads besides the shell state.
struct Run<'a> {
    /// The text the script's spans index.
    source: &'a str,
}

const fn unsupported(feature: Unsupported, span: Span) -> InterpError {
    InterpError::Unsupported { feature, span }
}

/// The span of what follows `end` within an opaque construct spanning `span`, if anything but blanks: a redirection.
pub(crate) fn trailing_redirection(source: &str, end: usize, span: Span) -> Option<Span> {
    let rest = Span::new(end, span.end);
    match rest.text(source) {
        Some(text) if text.trim().is_empty() => None,
        Some(_) | None => Some(rest),
    }
}

#[cfg(test)]
mod tests;
