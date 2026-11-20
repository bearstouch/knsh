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
//! External commands are found with [`crate::lookup`] through [`Fs`] and run through [`CommandSpawner`], the one
//! seam every command passes through (KNSH-108 wraps it to decide on each). The shell's own error messages go to
//! the injected diagnostics writer as `name: line n: message`, bash 5's format.
//!
//! - `(( expression ))` is 0 when the expression is not zero, 1 when it is zero or fails; `let` likewise for its
//!   last argument. An arithmetic error there is reported and the script goes on, as in bash.
//!
//! Words are expanded when the command runs ([`crate::expand`]): the command's words first, then its assignments
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
use std::sync::Arc;

use knsh_bash::{
    AndOr, AndOrOperator, ArithmeticParts, CaseClause, CaseCommand, CaseTerminatorKind, Command, CommandWord,
    CompoundKind, ForCommand, IfCommand, ListItem, LoopBody, LoopCommand, Pipeline, Script, SimpleCommand, Span,
    UnsupportedCommand,
};
use knsh_platform::{CommandOutcome, CommandRequest, CommandSpawner, ExitStatus, Fs, UserHomes};

use crate::arith::Failure;
use crate::check;
use crate::error::{InterpError, Unsupported};
use crate::expand::{ExpandError, Expander};
use crate::lookup::{self, Missing, Refusal, Resolved};
use crate::pattern;
use crate::scan;
use crate::state::{ShellState, is_name};
use crate::status::Status;
use crate::word;

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

/// Builtins the interpreter runs itself: `let` (KNSH-097).
const NATIVE_BUILTINS: &[&str] = &["let"];

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

/// The evaluator's result.
type Flow<T> = Result<T, Stop>;

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
    /// An interpreter over `state` that looks commands up through `fs`, runs them through `spawner`, finds home
    /// directories for `~name` through `homes` and writes its own error messages to `diagnostics`, with the default
    /// nesting limit [`MAX_EVAL_DEPTH`].
    #[must_use]
    pub fn new(
        state: ShellState,
        fs: Arc<dyn Fs>,
        spawner: Arc<dyn CommandSpawner>,
        homes: Arc<dyn UserHomes>,
        diagnostics: Box<dyn Write + Send>,
    ) -> Self {
        Self {
            state,
            fs,
            spawner,
            homes,
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
        check::check(&script.items, source, self.max_depth)?;
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
        Expander::new(&mut self.state, &*self.homes, run.source, overlay)
    }

    /// The arguments `words` expand into.
    fn arguments(&mut self, words: &[CommandWord], run: &Run<'_>) -> Flow<Vec<String>> {
        let mut out = Vec::with_capacity(words.len());
        for command_word in words {
            let parts = word::parts(&command_word.word.segments, run.source, 0)?;
            let result = self.expander(run, &[]).arguments(&parts, command_word.span);
            out.extend(self.expanded(result, command_word.span, run)?);
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
            if item.is_background()
                && let Some(separator) = item.separator
            {
                return Err(unsupported(Unsupported::Background, separator.span).into());
            }
            match self.and_or(&item.and_or, run) {
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
            if item.is_background()
                && let Some(separator) = item.separator
            {
                return Err(unsupported(Unsupported::Background, separator.span).into());
            }
            status = self.and_or(&item.and_or, run)?;
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

    /// A pipeline of one command, possibly negated. Sets `$?`.
    fn pipeline(&mut self, pipeline: &Pipeline, run: &Run<'_>) -> Flow<Status> {
        if let Some(time) = pipeline.time {
            return Err(unsupported(Unsupported::Time, time.span()).into());
        }
        if let Some(part) = pipeline.rest.first() {
            return Err(unsupported(Unsupported::Pipeline, part.operator_span).into());
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

    fn command(&mut self, command: &Command, run: &Run<'_>) -> Flow<Status> {
        match command {
            Command::Simple(simple) => self.simple(simple, run),
            Command::Compound(compound) => {
                if let Some(redirect) = compound.redirections.first() {
                    return Err(unsupported(Unsupported::Redirection, redirect.span).into());
                }
                match &compound.kind {
                    CompoundKind::Group(group) => self.list(&group.body, run),
                    CompoundKind::Subshell(_) => Err(unsupported(Unsupported::Subshell, compound.span).into()),
                    CompoundKind::If(command) => self.if_command(command, run),
                    CompoundKind::For(command) => self.for_command(command, run),
                    CompoundKind::While(command) => self.loop_command(command, true, run),
                    CompoundKind::Until(command) => self.loop_command(command, false, run),
                    CompoundKind::Case(command) => self.case_command(command, run),
                }
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
            let result = self.expander(run, &[]).pattern(&parts, pattern_word.span);
            let chars = self.expanded(result, pattern_word.span, run)?;
            if pattern::matches(&chars, subject) {
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

    /// A simple command: its words are expanded, then its assignments; assignments alone set shell variables;
    /// otherwise the command runs with them in its environment.
    fn simple(&mut self, simple: &SimpleCommand, run: &Run<'_>) -> Flow<Status> {
        if let Some(redirect) = simple.redirections.first() {
            return Err(unsupported(Unsupported::Redirection, redirect.span).into());
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
        let Some((name, args)) = words.split_first() else {
            return Ok(Status::SUCCESS);
        };
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
                    env: self.state.environment(&assignments),
                    cwd: self.state.cwd().to_path_buf(),
                };
                let outcome = self.spawner.run(&request).map_err(InterpError::from)?;
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
