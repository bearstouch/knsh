//! The evaluator: walks the `knsh-bash` tree and runs it (KNSH-096; NFR-COMPAT-01, NFR-COMPAT-09).
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
//! External commands are found with [`crate::lookup`] through [`Fs`] and run through [`CommandSpawner`], the one
//! seam every command passes through (KNSH-108 wraps it to decide on each). The shell's own error messages go to
//! the injected diagnostics writer as `name: line n: message`, bash 5's format.
//!
//! Nesting is counted per list entered (each compound command body, condition and case arm, and later each function
//! call), against an explicit limit, so a deep tree ends in [`InterpError::DepthExceeded`] rather than a stack
//! overflow. Loops do not nest: a loop runs any number of iterations at the same depth.

use std::ffi::{OsStr, OsString};
use std::fmt;
use std::io::Write;
use std::sync::Arc;

use knsh_bash::{
    AndOr, AndOrOperator, CaseClause, CaseCommand, CaseTerminatorKind, Command, CompoundKind, ForCommand, IfCommand,
    ListItem, LoopCommand, Pipeline, Script, SimpleCommand, Span,
};
use knsh_platform::{CommandOutcome, CommandRequest, CommandSpawner, ExitStatus, Fs};

use crate::check;
use crate::error::{InterpError, Unsupported};
use crate::lookup::{self, Missing, Refusal, Resolved};
use crate::pattern;
use crate::state::{ShellState, is_name};
use crate::status::Status;
use crate::word::{self, Context};

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
    (knsh_bash::is_builtin(name) && !EXTERNAL_BUILTINS.contains(&name)) || LATER_BUILTINS.contains(&name)
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

/// The native interpreter: shell state plus the injected effects it runs commands through.
pub struct Interpreter {
    /// Variables, positional parameters, `$?`, options and the working directory.
    state: ShellState,
    /// Where commands are looked up.
    fs: Arc<dyn Fs>,
    /// Where external commands run.
    spawner: Arc<dyn CommandSpawner>,
    /// The shell's own error messages (bash's standard error).
    diagnostics: Box<dyn Write + Send>,
    /// The nesting limit.
    max_depth: usize,
    /// Lists currently entered.
    depth: usize,
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
    /// An interpreter over `state` that looks commands up through `fs`, runs them through `spawner` and writes its
    /// own error messages to `diagnostics`, with the default nesting limit [`MAX_EVAL_DEPTH`].
    #[must_use]
    pub fn new(
        state: ShellState,
        fs: Arc<dyn Fs>,
        spawner: Arc<dyn CommandSpawner>,
        diagnostics: Box<dyn Write + Send>,
    ) -> Self {
        Self {
            state,
            fs,
            spawner,
            diagnostics,
            max_depth: MAX_EVAL_DEPTH,
            depth: 0,
        }
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
    /// nothing. Evaluation runs on a thread of its own with an [`EVAL_STACK_SIZE`] stack, so the nesting limit, not
    /// the caller's stack, decides how deep it goes.
    ///
    /// # Errors
    ///
    /// [`InterpError::Unsupported`] before anything runs; [`InterpError::DepthExceeded`] past the nesting limit;
    /// [`InterpError::SourceMismatch`] if `script` was not parsed from `source`; [`InterpError::Platform`] if a
    /// command could not be started or waited for, which stops the script there; [`InterpError::EvaluationThread`]
    /// if the evaluation thread could not start.
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
        check::check(&script.items, source, self.max_depth)?;
        self.depth = 0;
        let run = Run { source };
        self.list(&script.items, &run)
    }

    /// Writes one of the shell's own error messages, as bash 5 does: `name: line n: message`. A failed write is
    /// ignored, as bash ignores it.
    fn report(&mut self, span: Span, run: &Run<'_>, message: fmt::Arguments<'_>) {
        let line = run
            .source
            .get(..span.start)
            .map_or(1, |before| before.matches('\n').count() + 1);
        let _ = writeln!(self.diagnostics, "{}: line {line}: {message}", self.state.name());
    }

    /// Enters one more list, or fails past the nesting limit.
    fn enter(&mut self) -> Result<(), InterpError> {
        if self.depth >= self.max_depth {
            return Err(InterpError::DepthExceeded { limit: self.max_depth });
        }
        self.depth += 1;
        Ok(())
    }

    /// Runs a list: each and-or list in turn. Its status is the last one's; an empty list leaves `$?` as it was.
    fn list(&mut self, items: &[ListItem], run: &Run<'_>) -> Result<Status, InterpError> {
        self.enter()?;
        let result = self.list_items(items, run);
        self.depth -= 1;
        result
    }

    fn list_items(&mut self, items: &[ListItem], run: &Run<'_>) -> Result<Status, InterpError> {
        let mut status = self.state.last_status();
        for item in items {
            if item.is_background()
                && let Some(separator) = item.separator
            {
                return Err(unsupported(Unsupported::Background, separator.span));
            }
            status = self.and_or(&item.and_or, run)?;
        }
        Ok(status)
    }

    /// `a && b || c`: left to right, each pipeline run or skipped on the status so far.
    fn and_or(&mut self, and_or: &AndOr, run: &Run<'_>) -> Result<Status, InterpError> {
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

    /// A pipeline of one command, possibly negated. Sets `$?`.
    fn pipeline(&mut self, pipeline: &Pipeline, run: &Run<'_>) -> Result<Status, InterpError> {
        if let Some(time) = pipeline.time {
            return Err(unsupported(Unsupported::Time, time.span()));
        }
        if let Some(part) = pipeline.rest.first() {
            return Err(unsupported(Unsupported::Pipeline, part.operator_span));
        }
        let status = self.command(&pipeline.first, run)?;
        let status = if pipeline.is_negated() {
            status.negated()
        } else {
            status
        };
        self.state.set_last_status(status);
        Ok(status)
    }

    fn command(&mut self, command: &Command, run: &Run<'_>) -> Result<Status, InterpError> {
        match command {
            Command::Simple(simple) => self.simple(simple, run),
            Command::Compound(compound) => {
                if let Some(redirect) = compound.redirections.first() {
                    return Err(unsupported(Unsupported::Redirection, redirect.span));
                }
                match &compound.kind {
                    CompoundKind::Group(group) => self.list(&group.body, run),
                    CompoundKind::Subshell(_) => Err(unsupported(Unsupported::Subshell, compound.span)),
                    CompoundKind::If(command) => self.if_command(command, run),
                    CompoundKind::For(command) => self.for_command(command, run),
                    CompoundKind::While(command) => self.loop_command(command, true, run),
                    CompoundKind::Until(command) => self.loop_command(command, false, run),
                    CompoundKind::Case(command) => self.case_command(command, run),
                }
            }
            Command::FunctionDefinition(definition) => {
                Err(unsupported(Unsupported::FunctionDefinition, definition.span))
            }
            Command::Unsupported(construct) => {
                Err(unsupported(Unsupported::Construct(construct.construct), construct.span))
            }
        }
    }

    /// `if`: the first clause whose condition succeeds runs its body; otherwise `else`, or status 0.
    fn if_command(&mut self, command: &IfCommand, run: &Run<'_>) -> Result<Status, InterpError> {
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
    fn for_command(&mut self, command: &ForCommand, run: &Run<'_>) -> Result<Status, InterpError> {
        let name = word::expand(&command.variable, run.source, Context::Plain)?;
        if !is_name(&name) {
            self.report(
                command.variable.span,
                run,
                format_args!("`{name}': not a valid identifier"),
            );
            return Ok(Status::FAILURE);
        }
        let values: Vec<String> = match &command.items {
            Some(items) => items
                .words
                .iter()
                .map(|item| word::expand(item, run.source, Context::Argument))
                .collect::<Result<_, _>>()?,
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
    fn loop_command(&mut self, command: &LoopCommand, is_while: bool, run: &Run<'_>) -> Result<Status, InterpError> {
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
    fn case_command(&mut self, command: &CaseCommand, run: &Run<'_>) -> Result<Status, InterpError> {
        let subject = word::expand(&command.subject, run.source, Context::Plain)?;
        let mut status = Status::SUCCESS;
        let mut fall_through = false;
        for clause in &command.clauses {
            if !fall_through && !clause_matches(clause, &subject, run.source)? {
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

    /// A simple command: assignments alone set shell variables; otherwise the command runs with them in its
    /// environment.
    fn simple(&mut self, simple: &SimpleCommand, run: &Run<'_>) -> Result<Status, InterpError> {
        if let Some(redirect) = simple.redirections.first() {
            return Err(unsupported(Unsupported::Redirection, redirect.span));
        }
        let mut assignments: Vec<(String, OsString)> = Vec::with_capacity(simple.assignments.len());
        for assignment in &simple.assignments {
            let value = word::assignment_value(assignment, run.source)?;
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
                OsString::from(value)
            };
            assignments.push((assignment.name.clone(), value));
        }
        let words: Vec<String> = simple
            .words
            .iter()
            .map(|command_word| word::expand(command_word, run.source, Context::Argument))
            .collect::<Result<_, _>>()?;
        let Some((name, args)) = words.split_first() else {
            for (name, value) in assignments {
                self.state.set_variable(&name, value);
            }
            return Ok(Status::SUCCESS);
        };
        if is_refused_builtin(name) || external_builtin_differs(name, args) {
            return Err(unsupported(Unsupported::Builtin, simple.span));
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
                    env: self.state.environment(&assignments),
                    cwd: self.state.cwd().to_path_buf(),
                };
                let outcome = self.spawner.run(&request)?;
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

/// Whether one of `clause`'s patterns matches `subject`.
fn clause_matches(clause: &CaseClause, subject: &str, source: &str) -> Result<bool, InterpError> {
    for pattern_word in &clause.patterns {
        let chars = word::characters(pattern_word, source, Context::Pattern)?;
        if pattern::matches(&chars, subject) {
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(test)]
mod tests;
