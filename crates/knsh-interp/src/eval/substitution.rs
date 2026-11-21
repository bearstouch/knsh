//! Command substitution, process substitution and coprocesses (KNSH-105; NFR-COMPAT-02, decision 6, decision 19).
//!
//! Each runs its commands in a subshell: a copy of the shell (decision 19: never a fork of this multithreaded
//! process), on a thread of its own, so every program it starts goes through the same
//! [`CommandSpawner`](knsh_platform::CommandSpawner) as the script's own, the seam KNSH-108 decides at.
//!
//! - `$(…)` and `` `…` ``: the body is parsed again from its text, as bash 5.2 parses it again when it runs it (a
//!   backtick's body un-escaped first), checked as a script, and run with its standard output a pipe the shell
//!   reads to the end. The output, NUL bytes dropped and trailing newlines removed, is the expansion's value, and
//!   `$?` becomes the substitution's status. `set -e` is off inside unless `inherit_errexit` is set, as in bash
//!   outside POSIX mode; traps are reset as in any subshell. `$(< file)` reads the file without running a command,
//!   as bash does. The output is bounded ([`MAX_SUBSTITUTION_OUTPUT`]).
//! - `<(…)` and `>(…)`: the body runs beside the command with its standard output (or input) a pipe whose other end
//!   the shell places at the highest free number below 64, as bash does, and the word is `/dev/fd/N`. A command
//!   receives that number in its table; the shell's redirections read it as its own descriptor (`< <(cmd)`). The
//!   shell's copy is closed once the command whose word made it is done; the body is not waited for, as in bash.
//! - `coproc [NAME] command`: the command runs as a background job with its standard input and output two pipes;
//!   the shell keeps the other ends close-on-exec (never given to a command), stores their numbers in the array
//!   `NAME` (`COPROC` by default) as `NAME[0]` (read from the coprocess) and `NAME[1]` (write to it), and its
//!   process id in `NAME_PID` and `$!`. A coprocess the shell runs itself (a compound command) has no process id:
//!   reading `NAME_PID` is then refused, as `$!` is.

use std::ffi::OsString;
use std::sync::Arc;

use knsh_bash::{
    Command, CoprocParts, ParseOptions, Pipeline, RedirectionOperator, Script, SimpleCommand, UnsupportedCommand,
};
use knsh_platform::{ChildDescriptor, SharedFd, StandardStream};

use super::job::{JobContext, Seed};
use super::nested::MAX_NESTED_TEXT;
use super::redirect::{FdTable, SUBSTITUTION_FD_TOP};
use super::{EVAL_STACK_SIZE, Flow, Interpreter, Run, unsupported, write_shared};
use crate::check::{self, substitution_text};
use crate::error::{InterpError, Unsupported};
use crate::expand::{ExpandError, Substitutions};
use crate::scan::{Subst, SubstKind};
use crate::state::{LastBackground, ShellState, is_name, refuses_assignment};
use crate::status::Status;
use crate::word;

/// Most bytes a command substitution's output may hold. Bash has no bound and grows until memory runs out; past
/// this the run fails with [`InterpError::ExpansionLimit`] rather than exhausting memory on untrusted output
/// (`x=$(yes)`). Far above what scripts capture.
pub(crate) const MAX_SUBSTITUTION_OUTPUT: usize = 64 * 1024 * 1024;

/// How much of a command substitution's output is read at once.
const READ_CHUNK: usize = 64 * 1024;

/// The default name of a coprocess's array.
const DEFAULT_COPROC_NAME: &str = "COPROC";

/// What runs the substitutions an expansion meets: the shell's parts besides its state, which the expansion holds.
pub(super) struct Host<'a> {
    /// What a subshell copies.
    pub(super) seed: Seed<'a>,
    /// The shell's descriptors: a subshell copies them; a process substitution places its end here.
    pub(super) fds: &'a mut FdTable,
    /// The process substitution descriptors placed so far, closed after their command.
    pub(super) substituted: &'a mut Vec<(u32, SharedFd)>,
    /// Where the status of the last command substitution is left for the command (`x=$(false)`).
    pub(super) status: &'a mut Option<Status>,
    /// The name messages start with, for text from a sourced file.
    pub(super) origin: Option<&'a str>,
    /// Lines before the text's first line.
    pub(super) line_base: usize,
}

/// A substitution's body, ready to run.
struct Body {
    /// Its text, which the script's spans index.
    text: Arc<str>,
    /// Its commands.
    script: Script,
    /// Lines before its first line, as messages number them.
    line_base: usize,
    /// What `nested_bytes` is while it runs.
    held: usize,
}

impl Substitutions for Host<'_> {
    fn substitute(&mut self, state: &mut ShellState, subst: &Subst, source: &str) -> Result<String, ExpandError> {
        match subst.kind {
            SubstKind::Command | SubstKind::Backtick { .. } => self.command(state, subst, source),
            SubstKind::Input | SubstKind::Output => self.process(state, subst, source),
        }
    }
}

impl Host<'_> {
    /// The body of `subst`, parsed with the options `state` reads lines with and checked as a script, within the
    /// nesting and nested-text bounds the shell has left.
    fn body(&self, state: &ShellState, subst: &Subst, source: &str) -> Result<Body, InterpError> {
        if self.seed.depth >= self.seed.max_depth {
            return Err(InterpError::DepthExceeded {
                limit: self.seed.max_depth,
            });
        }
        let text = substitution_text(subst, source)?;
        let held = self.seed.nested_bytes.saturating_add(text.len());
        if held > MAX_NESTED_TEXT {
            return Err(InterpError::ExpansionLimit {
                what: "bytes of eval, source, alias and substitution text running at once",
                limit: MAX_NESTED_TEXT,
            });
        }
        let mut options = ParseOptions::default()
            .with_redirection_variables(true)
            .with_arrays(true)
            .with_coproc(true);
        options.extglob = state.options().extglob;
        // The line already parsed with the substitution in it, so a body that does not parse alone is one the
        // parser reads differently from bash: refused rather than guessed at.
        let script =
            knsh_bash::parse_with(&text, options).map_err(|_| unsupported(Unsupported::Unparsed, subst.span))?;
        let budget = self.seed.max_depth.saturating_sub(self.seed.depth);
        check::check(&script.items, &text, budget, self.seed.times.is_some()).map_err(|error| match error {
            InterpError::DepthExceeded { .. } => InterpError::DepthExceeded {
                limit: self.seed.max_depth,
            },
            other => super::traps::at_command(other, subst.span),
        })?;
        let before = source.get(..subst.body.start).unwrap_or_default();
        Ok(Body {
            text: Arc::from(text),
            script,
            line_base: self.line_base + before.matches('\n').count(),
            held,
        })
    }

    /// A subshell of the shell as `state` stands, with `fds`, in `context`, for a substitution's `body`.
    fn subshell(&self, state: &ShellState, fds: FdTable, context: JobContext, body: &Body) -> Interpreter {
        let mut shell = self.seed.subshell(state, fds, context);
        // Bash reads the body as a string of its own (`parse_and_execute`): `set -x` repeats `PS4`'s first
        // character once more (KNSH-104).
        shell.trace_level += 1;
        shell.nested_bytes = body.held;
        shell
    }

    /// `$(…)` or `` `…` ``: the output of its body run in a subshell, NUL bytes dropped and trailing newlines
    /// removed; `$?` is its status.
    fn command(&mut self, state: &mut ShellState, subst: &Subst, source: &str) -> Result<String, ExpandError> {
        let body = self.body(state, subst, source)?;
        let (read, write) = self.seed.descriptors.pipe().map_err(InterpError::from)?;
        let mut fds = self.fds.clone();
        fds.set(1, Some(ChildDescriptor::Open(write)));
        let asynchronous = self.seed.placement.as_ref().is_some_and(JobContext::is_asynchronous);
        let mut shell = self.subshell(state, fds, JobContext::substitution(asynchronous), &body);
        // Bash clears `set -e` in a command substitution outside POSIX mode, unless `inherit_errexit` (KNSH-104).
        if !shell.state.options().inherit_errexit {
            shell.state.options_mut().errexit = false;
        }
        let origin: Option<Arc<str>> = self.origin.map(Arc::from);
        let worker = std::thread::Builder::new()
            .name("knsh-substitution".to_owned())
            .stack_size(EVAL_STACK_SIZE)
            .spawn(move || {
                // A panic must still end the substitution, or the shell would read its pipe forever.
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let run = Run::shared(&body.text, origin.as_deref(), body.line_base);
                    let result = shell.substitution_body(&body.script, &run);
                    let status = shell.finish_subshell(&result, &run);
                    // Its copies of the pipe close now, so the reader sees end of file.
                    drop(shell);
                    status
                }))
                .unwrap_or(Err(InterpError::EvaluationThread))
            })
            .map_err(|_| InterpError::EvaluationThread)?;
        let output = read_all(&**self.seed.descriptors, &read);
        // Nobody reads any more: a program writing past the bound sees a broken pipe and ends (a builtin loop does not:
        // the shell's builtins get no `SIGPIPE`, see compatibility).
        drop(read);
        let status = worker
            .join()
            .map_err(|_| InterpError::EvaluationThread)?
            .map_err(|error| super::traps::at_command(error, subst.span))?;
        let mut output = output?;
        *self.status = Some(status);
        state.set_last_status(status);
        output.retain(|&byte| byte != 0);
        let mut text = String::from_utf8(output).map_err(|_| unsupported(Unsupported::NonUtf8Value, subst.span))?;
        let kept = text.trim_end_matches('\n').len();
        text.truncate(kept);
        Ok(text)
    }

    /// `<(…)` or `>(…)`: its body started beside the command, reading or writing a pipe whose other end is placed in
    /// the shell's table; the word is `/dev/fd/N`.
    fn process(&mut self, state: &mut ShellState, subst: &Subst, source: &str) -> Result<String, ExpandError> {
        let body = self.body(state, subst, source)?;
        let Some(number) = self.fds.free_below(SUBSTITUTION_FD_TOP) else {
            return Err(ExpandError::Discard(
                "cannot make pipe for process substitution: Too many open files".to_owned(),
            ));
        };
        let (read, write) = self.seed.descriptors.pipe().map_err(InterpError::from)?;
        let input = subst.kind == SubstKind::Input;
        let (child_end, shell_end) = if input { (write, read) } else { (read, write) };
        let mut fds = self.fds.clone();
        // The ends of the command's other process substitutions are not this one's: holding a write end open would
        // keep its reader from ever seeing end of file.
        for (fd, _) in self.substituted.iter() {
            fds.set(*fd, None);
        }
        // `<(…)` writes its standard output into the pipe; `>(…)` reads its standard input from it.
        let child_fd = u32::from(input);
        fds.set(child_fd, Some(ChildDescriptor::Open(child_end)));
        let outer = self.seed.placement.as_ref().is_some_and(JobContext::is_asynchronous);
        let context = JobContext::substitution(outer || !state.options().monitor);
        let mut shell = self.subshell(state, fds, context, &body);
        let origin: Option<Arc<str>> = self.origin.map(Arc::from);
        let diagnostics = Arc::clone(self.seed.diagnostics);
        let name = state.name().to_owned();
        // Not waited for, as bash does not wait for it: it ends when its pipe does.
        std::thread::Builder::new()
            .name("knsh-process-substitution".to_owned())
            .stack_size(EVAL_STACK_SIZE)
            .spawn(move || {
                let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let run = Run::shared(&body.text, origin.as_deref(), body.line_base);
                    let result = shell.substitution_body(&body.script, &run);
                    shell.finish_subshell(&result, &run)
                }))
                .unwrap_or(Err(InterpError::EvaluationThread));
                drop(shell);
                // Nobody waits for it, so a refusal or failure that stopped it is reported here: what it would have
                // run did not run.
                if let Err(error) = outcome {
                    write_shared(
                        &diagnostics,
                        format!("{name}: process substitution: {error}\n").as_bytes(),
                    );
                }
            })
            .map_err(|_| InterpError::EvaluationThread)?;
        self.fds.set(number, Some(ChildDescriptor::Open(shell_end.clone())));
        self.substituted.push((number, shell_end));
        Ok(format!("/dev/fd/{number}"))
    }
}

/// Everything `fd` gives until end of file, within [`MAX_SUBSTITUTION_OUTPUT`].
fn read_all(descriptors: &dyn knsh_platform::Descriptors, fd: &SharedFd) -> Result<Vec<u8>, InterpError> {
    let mut output = Vec::new();
    let mut chunk = vec![0_u8; READ_CHUNK];
    loop {
        let count = descriptors.read(fd, &mut chunk)?;
        if count == 0 {
            return Ok(output);
        }
        if output.len() + count > MAX_SUBSTITUTION_OUTPUT {
            return Err(InterpError::ExpansionLimit {
                what: "bytes of command substitution output",
                limit: MAX_SUBSTITUTION_OUTPUT,
            });
        }
        output.extend_from_slice(&chunk[..count]);
    }
}

/// The redirection of `$(< file)`, if `script` is that form and nothing else: a command of one input redirection
/// on standard input, which bash reads itself instead of running a command.
fn read_file_form(script: &Script) -> Option<&SimpleCommand> {
    let [item] = script.items.as_slice() else {
        return None;
    };
    if item.is_background() || !item.and_or.rest.is_empty() {
        return None;
    }
    let pipeline = &item.and_or.first;
    if !pipeline.rest.is_empty() || pipeline.is_negated() || pipeline.time.is_some() {
        return None;
    }
    let Command::Simple(simple) = &pipeline.first else {
        return None;
    };
    let [redirect] = simple.redirections.as_slice() else {
        return None;
    };
    let on_input = redirect.fd.is_none_or(|fd| fd.value == Some(0)) && redirect.variable.is_none();
    (simple.words.is_empty()
        && simple.assignments.is_empty()
        && redirect.operator == RedirectionOperator::Input
        && on_input)
        .then_some(simple)
}

impl Interpreter {
    /// A substitution's body, in this subshell: run as a script (a discarded line ends only that line), or for
    /// `$(< file)` the file copied to standard output.
    fn substitution_body(&mut self, script: &Script, run: &Run<'_>) -> Flow<Status> {
        let Some(simple) = read_file_form(script) else {
            return self.script(&script.items, run);
        };
        let Some(saved) = self.redirect(&simple.redirections, run)? else {
            return Ok(Status::FAILURE);
        };
        let input = self.fds.get(0).cloned();
        let result = match input {
            Some(ChildDescriptor::Open(fd)) => self.copy_to_output(&fd, simple, run),
            Some(ChildDescriptor::Standard(StandardStream::Input)) => match self.standard.clone() {
                Some(standard) => self.copy_to_output(&standard[0], simple, run),
                None => Err(unsupported(Unsupported::StandardDescriptor, simple.span).into()),
            },
            Some(ChildDescriptor::Standard(StandardStream::Output | StandardStream::Error)) | None => {
                Err(unsupported(Unsupported::StandardDescriptor, simple.span).into())
            }
        };
        self.restore(saved);
        result
    }

    /// Copies what `fd` holds to standard output: `$(< file)`. A read error is reported as bash's `cat_file`
    /// reports it, naming the file as written, with status 1.
    fn copy_to_output(&mut self, fd: &SharedFd, simple: &SimpleCommand, run: &Run<'_>) -> Flow<Status> {
        match read_all(&*self.descriptors, fd) {
            Ok(output) => {
                let _ = self.write_out(1, &output);
                Ok(Status::SUCCESS)
            }
            Err(InterpError::Platform(error)) if error.errno().is_some() => {
                let file = simple.redirections[0].target.span.text(run.source).unwrap_or_default();
                let reason = super::redirect::strerror(error.errno().unwrap_or(5));
                self.report(simple.span, run, format_args!("{file}: {reason}"));
                Ok(Status::FAILURE)
            }
            Err(other) => Err(other.into()),
        }
    }

    /// Closes the descriptors process substitutions placed after the first `mark`, each only if the shell's table
    /// still holds it there (KNSH-105).
    pub(super) fn close_substituted(&mut self, mark: usize) {
        if self.substituted_fds.len() <= mark {
            return;
        }
        for (fd, held) in self.substituted_fds.split_off(mark) {
            if self.fds.get(fd) == Some(&ChildDescriptor::Open(held)) {
                self.fds.set(fd, None);
            }
        }
    }

    /// `coproc [NAME] command` (KNSH-105): `command` started as a background job reading one pipe and writing
    /// another, whose other ends the shell keeps in `NAME[1]` and `NAME[0]`; `NAME_PID` and `$!` name its process.
    pub(super) fn coproc(&mut self, construct: &UnsupportedCommand, run: &Run<'_>) -> Flow<Status> {
        let Some(parts) = construct.coproc.as_deref() else {
            return Err(unsupported(Unsupported::Construct(construct.construct), construct.span).into());
        };
        let name = coproc_name(parts, run)?;
        let pid_name = format!("{name}_PID");
        for variable in [name.as_str(), pid_name.as_str()] {
            if refuses_assignment(variable) {
                return Err(unsupported(Unsupported::ShellVariable, construct.span).into());
            }
            if self.state.is_readonly(variable) {
                self.report(construct.span, run, format_args!("{variable}: readonly variable"));
                return Ok(Status::FAILURE);
            }
        }
        let (Some(read_fd), Some(write_fd)) = (
            self.fds.free_below(SUBSTITUTION_FD_TOP),
            self.fds
                .free_below(SUBSTITUTION_FD_TOP)
                .and_then(|first| self.fds.free_below(first)),
        ) else {
            self.report(construct.span, run, format_args!("coproc: Too many open files"));
            return Ok(Status::FAILURE);
        };
        let (input_read, input_write) = self.descriptors.pipe().map_err(InterpError::from)?;
        let (output_read, output_write) = self.descriptors.pipe().map_err(InterpError::from)?;
        let mut fds = self.fds.clone();
        fds.set(0, Some(ChildDescriptor::Open(input_read)));
        fds.set(1, Some(ChildDescriptor::Open(output_write)));
        let pipeline = Pipeline {
            time: None,
            negation: None,
            first: parts.command.clone(),
            rest: Vec::new(),
            span: construct.span,
        };
        // The coprocess's ends are in its copy of the table only: the shell's own copies close with `fds`.
        let saved = std::mem::replace(&mut self.fds, fds);
        let launched = self.launch(&pipeline, true, run);
        self.fds = saved;
        let key = launched?;
        let last = self.started_in_background(key);
        self.fds.set_private(read_fd, ChildDescriptor::Open(output_read));
        self.fds.set_private(write_fd, ChildDescriptor::Open(input_write));
        let numbers = [read_fd, write_fd]
            .iter()
            .map(|fd| (None, OsString::from(fd.to_string()), false))
            .collect();
        // Bash's `coproc_setvars` makes a new array of the name, whatever it held.
        let assigned = self
            .state
            .unset(&name)
            .and_then(|()| self.state.assign_list(&name, numbers, false, false));
        if assigned.is_err() {
            return Err(unsupported(Unsupported::Coproc, construct.span).into());
        }
        match last {
            LastBackground::Process(pid) => {
                if self.state.assign(&pid_name, pid.to_string().into(), false).is_err() {
                    return Err(unsupported(Unsupported::Coproc, construct.span).into());
                }
            }
            // A compound coprocess runs in the shell itself: its process id does not exist (decision 19).
            LastBackground::InShell => {
                let _ = self.state.unset(&pid_name);
                self.state.mark_in_shell_pid(&pid_name);
            }
        }
        Ok(Status::SUCCESS)
    }
}

/// The name of a coprocess's array: the one written before its compound command, or `COPROC`.
fn coproc_name(parts: &CoprocParts, run: &Run<'_>) -> Flow<String> {
    let Some(span) = parts.name else {
        return Ok(DEFAULT_COPROC_NAME.to_owned());
    };
    let name = word::text(span, run.source)?;
    if !is_name(name) {
        return Err(unsupported(Unsupported::Coproc, span).into());
    }
    Ok(name.to_owned())
}
