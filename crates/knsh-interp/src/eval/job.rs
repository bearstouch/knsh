//! Pipelines, subshells, background jobs and `time` (KNSH-100; NFR-COMPAT-02, FR-SES-10).
//!
//! A pipeline's commands start one after the other, each with its standard input the previous one's pipe and its
//! standard output the next one's (`|&` adds standard error, after the command's own redirections, as bash does),
//! and only then does the shell wait: the commands run side by side, as in bash. Bash forks a subshell for every
//! command of a pipeline; the interpreter cannot fork its multithreaded process, so it gives each command a copy of
//! itself (a subshell: variables, options, the working directory and descriptors copied, so nothing it changes
//! reaches the shell):
//!
//! - A simple command is expanded in its copy on the shell's thread and, if it runs a program, started without
//!   waiting; the program is the pipeline's member.
//! - Any other command (a compound command, `( … )`) runs in its copy on a thread of its own, which reports its
//!   status when it ends.
//! - A pipeline of one simple command runs in the shell itself (its assignments and `exec` last), and so does the
//!   last command of a longer one under `lastpipe` without job control.
//!
//! The pipeline's status is its last command's (under `pipefail` its last failing command's), inverted by `!`;
//! `PIPESTATUS` keeps each command's. A compound command alone runs in the shell and leaves `PIPESTATUS` as its own
//! pipelines set it, as bash does; a subshell alone sets it.
//!
//! Without job control (every script, as in bash) every program stays in the shell's process group, so the
//! supervisor's pause of that group reaches them (FR-SES-10); a background job's programs ignore `SIGINT` and
//! `SIGQUIT`. Under job control (`set -m`) a job's programs share a process group led by its first one; an
//! interactive shell hands that group the terminal for a foreground job, takes it back when the job ends or stops,
//! and reports a stopped job as bash does.

use std::fmt::Write as _;
use std::sync::{Arc, PoisonError};

use knsh_bash::{AndOr, Command, CompoundKind, PipeOperator, Pipeline, Span, TimeKeyword};
use knsh_platform::{
    ChildDescriptor, ChildEvent, ChildHandle, ChildOptions, ChildSignals, CommandOutcome, CommandRequest,
    GroupMembership, PlatformError, SharedFd, Signal, Started, signals,
};

use super::{EVAL_STACK_SIZE, Flow, Interpreter, Run, Sink, Stop, unsupported};
use crate::error::{InterpError, Unsupported};
use crate::jobs::{GroupCell, Jobs, Key, Member, MemberState};
use crate::state::LastBackground;
use crate::status::Status;

/// Where the commands a shell starts belong: the job being started or run, as its stages and subshells see it.
#[derive(Debug, Clone)]
pub(crate) struct JobContext {
    /// The job's process group, set by its first program under job control.
    group: GroupCell,
    /// The job runs under job control: its programs share a process group of their own.
    controlled: bool,
    /// The terminal the job's first program takes: a foreground job of an interactive shell.
    terminal: Option<SharedFd>,
    /// Started with `&` without job control: its programs ignore `SIGINT` and `SIGQUIT`.
    asynchronous: bool,
}

impl JobContext {
    /// The context of the commands a command or process substitution runs (KNSH-105): never under job control, in
    /// the shell's own process group as bash places them; `asynchronous` for a process substitution started without
    /// job control, whose programs ignore `SIGINT` and `SIGQUIT` as a background job's do.
    pub(super) fn substitution(asynchronous: bool) -> Self {
        Self {
            group: GroupCell::default(),
            controlled: false,
            terminal: None,
            asynchronous,
        }
    }

    /// Started with `&` without job control, or inside such a job.
    pub(super) const fn is_asynchronous(&self) -> bool {
        self.asynchronous
    }
}

/// What a subshell copies from its shell besides the state and descriptors, borrowed: so a copy can be made while
/// the state is lent to an expansion (KNSH-105: a command substitution runs in a copy of the shell as its
/// expansion has left it). Built with [`seed!`].
pub(super) struct Seed<'a> {
    pub(super) fs: &'a Arc<dyn knsh_platform::Fs>,
    pub(super) spawner: &'a Arc<dyn knsh_platform::CommandSpawner>,
    pub(super) homes: &'a Arc<dyn knsh_platform::UserHomes>,
    pub(super) collation: &'a Arc<dyn knsh_platform::Collation>,
    pub(super) descriptors: &'a Arc<dyn knsh_platform::Descriptors>,
    pub(super) times: &'a Option<Arc<dyn knsh_platform::ShellTimes>>,
    pub(super) standard: &'a Option<Arc<[SharedFd; 3]>>,
    pub(super) local_time: &'a Option<(Arc<dyn knsh_platform::LocalTime>, i64)>,
    pub(super) diagnostics: &'a super::SharedWriter,
    pub(super) output: &'a super::SharedWriter,
    pub(super) max_depth: usize,
    pub(super) depth: usize,
    pub(super) registry: &'a Arc<crate::jobs::Registry>,
    pub(super) placement: &'a Option<JobContext>,
    pub(super) loops: usize,
    pub(super) sourcing: usize,
    pub(super) nested_bytes: usize,
    pub(super) visible_aliases: &'a Arc<std::collections::BTreeMap<String, String>>,
    pub(super) alias_guard: &'a [String],
    pub(super) errexit_ignored: usize,
    pub(super) traps_running: &'a [crate::trap::TrapId],
    pub(super) trace_level: usize,
}

/// The [`Seed`] of interpreter `$shell` (an expression of type `&Interpreter` or `&mut Interpreter`, usually
/// `self`), borrowing only the fields it names, so `$shell.state` and `$shell.fds` can be borrowed mutably beside it.
macro_rules! seed {
    ($shell:expr) => {
        $crate::eval::job::Seed {
            fs: &$shell.fs,
            spawner: &$shell.spawner,
            homes: &$shell.homes,
            collation: &$shell.collation,
            descriptors: &$shell.descriptors,
            times: &$shell.times,
            standard: &$shell.standard,
            local_time: &$shell.local_time,
            diagnostics: &$shell.diagnostics,
            output: &$shell.output,
            max_depth: $shell.max_depth,
            depth: $shell.depth,
            registry: &$shell.jobs.registry,
            placement: &$shell.placement,
            loops: $shell.loops,
            sourcing: $shell.sourcing,
            nested_bytes: $shell.nested_bytes,
            visible_aliases: &$shell.visible_aliases,
            alias_guard: &$shell.alias_guard,
            errexit_ignored: $shell.errexit_ignored,
            traps_running: &$shell.traps_running,
            trace_level: $shell.trace_level,
        }
    };
}
pub(super) use seed;

impl Seed<'_> {
    /// A subshell: a copy of `state` and of `fds`, in job `context`, sharing the shell's effects and writers. It has
    /// no jobs of its own yet and never does job control.
    pub(super) fn subshell(
        &self,
        state: &crate::state::ShellState,
        fds: super::FdTable,
        context: JobContext,
    ) -> Interpreter {
        let mut state = state.clone();
        state.set_interactive(false);
        // KNSH-104: bash's forked subshell resets its traps (ignored signals stay ignored).
        let (functrace, errtrace) = (state.options().functrace, state.options().errtrace);
        state.traps_mut().reset_for_subshell(functrace, errtrace);
        Interpreter {
            state,
            fs: Arc::clone(self.fs),
            spawner: Arc::clone(self.spawner),
            homes: Arc::clone(self.homes),
            collation: Arc::clone(self.collation),
            descriptors: Arc::clone(self.descriptors),
            times: self.times.clone(),
            standard: self.standard.clone(),
            local_time: self.local_time.clone(),
            terminal: None,
            diagnostics: Arc::clone(self.diagnostics),
            output: Arc::clone(self.output),
            fds,
            max_depth: self.max_depth,
            depth: self.depth,
            jobs: Jobs::new(Arc::clone(self.registry)),
            placement: Some(context),
            sink: Sink::Off,
            pipe_stderr: false,
            is_subshell: true,
            parent: None,
            loops: self.loops,
            sourcing: self.sourcing,
            nested_bytes: self.nested_bytes,
            observer: None,
            visible_aliases: Arc::clone(self.visible_aliases),
            alias_guard: self.alias_guard.to_vec(),
            exit_after_job: false,
            declaration_lists: Vec::new(),
            forked_stage: false,
            errexit_ignored: self.errexit_ignored,
            // A subshell started from a trap is still inside it, as bash's forked subshell keeps the trap's
            // `SIG_INPROGRESS` mark: `DEBUG` and `ERR` do not run again in it (or the trap would recurse).
            traps_running: self.traps_running.to_vec(),
            trace_level: self.trace_level,
            signals: None,
            terminating: None,
            skip_exit_trap: false,
            substituted_fds: Vec::new(),
            substitution_status: None,
        }
    }
}

/// The default output of the `time` keyword (bash's `TIMEFORMAT` when unset).
const DEFAULT_TIME_FORMAT: &str = "\nreal\t%3lR\nuser\t%3lU\nsys\t%3lS";

/// The output of `time -p` (POSIX), whatever `TIMEFORMAT` says.
const POSIX_TIME_FORMAT: &str = "real %2R\nuser %2U\nsys %2S";

/// The status of a command run in a subshell: an `exit` (or a fatal expansion error) ends only the subshell, with its
/// status; a discarded line ends it with 1.
/// `break`, `continue` and `return` end the subshell too, with their status, as bash's forked subshell ends (KNSH-101).
fn subshell_status(result: &Flow<Status>) -> Result<Status, InterpError> {
    match result {
        Ok(status)
        | Err(Stop::Exit(status) | Stop::Return(status) | Stop::Break { status, .. } | Stop::Continue { status, .. }) => {
            Ok(*status)
        }
        Err(Stop::Discard) => Ok(Status::FAILURE),
        Err(Stop::Error(error)) => Err(*error),
    }
}

/// The source text of `span`, trimmed: what `jobs` shows for a job.
fn job_text(span: Span, run: &Run<'_>) -> String {
    span.text(run.source)
        .map(|text| text.split_whitespace().collect::<Vec<_>>().join(" "))
        .unwrap_or_default()
}

impl Interpreter {
    /// Whether this shell does job control itself: `set -m`, and not a subshell (bash turns job control off in
    /// subshells).
    pub(super) fn job_control(&self) -> bool {
        self.state.options().monitor && !self.is_subshell
    }

    /// The context of a new job, started in the background when `background`: inside a job (a stage, a background
    /// list, a subshell) it is that job's; in the shell itself a new one.
    fn new_context(&self, background: bool) -> JobContext {
        if let Some(outer) = &self.placement {
            return JobContext {
                group: Arc::clone(&outer.group),
                controlled: outer.controlled,
                terminal: if background { None } else { outer.terminal.clone() },
                asynchronous: outer.asynchronous || (background && !outer.controlled),
            };
        }
        let controlled = self.job_control();
        JobContext {
            group: GroupCell::default(),
            controlled,
            terminal: if controlled && !background {
                self.terminal.as_ref().map(|terminal| terminal.descriptor())
            } else {
                None
            },
            asynchronous: background && !controlled,
        }
    }

    /// A subshell of this shell: a copy of its state and of `fds`, in job `context`, sharing its effects and
    /// writers. It has no jobs of its own yet and never does job control.
    fn subshell(&self, fds: super::FdTable, context: JobContext) -> Self {
        seed!(self).subshell(&self.state, fds, context)
    }

    /// A subshell (this shell) ends with `result`: its status, after its `EXIT` trap if it set one (KNSH-104).
    pub(super) fn finish_subshell(&mut self, result: &Flow<Status>, run: &Run<'_>) -> Result<Status, InterpError> {
        let status = subshell_status(result)?;
        let end = Span::new(run.source.len(), run.source.len());
        self.run_exit_trap(status, end, run)
    }

    /// Whether stops of this shell's programs concern it: it does job control, or it is a subshell inside a job
    /// under job control, which tells its parent when what it waits for stops ([`Parent`](crate::jobs::Parent)).
    pub(super) fn tracks_stops(&self) -> bool {
        self.job_control() || self.placement.as_ref().is_some_and(|context| context.controlled)
    }

    /// Starts `request` in the job the shell is placed in: under job control its first program leads the job's
    /// process group (taking the terminal for a foreground job) and the others join it; without job control it
    /// stays in the shell's group.
    pub(super) fn start_command(&mut self, request: &CommandRequest) -> Flow<Started> {
        // KNSH-104: what the shell ignores (`trap ''`, and signals ignored at entry), its commands start ignoring.
        let ignore = self.state.traps().ignored_signals();
        let Some(context) = self.placement.clone() else {
            let options = ChildOptions {
                ignore,
                ..ChildOptions::default()
            };
            return Ok(self.spawner.start(request, &options)?);
        };
        if !context.controlled {
            let options = ChildOptions {
                group: GroupMembership::Inherit,
                terminal: None,
                signals: if context.asynchronous {
                    ChildSignals::IgnoreInterrupt
                } else {
                    ChildSignals::Inherit
                },
                ignore,
            };
            return Ok(self.spawner.start(request, &options)?);
        }
        // Held while starting, so two stages starting at once agree on one leader.
        let mut group = context.group.lock().unwrap_or_else(PoisonError::into_inner);
        let lead = ChildOptions {
            group: GroupMembership::Lead,
            terminal: context.terminal.clone(),
            signals: ChildSignals::Default,
            ignore,
        };
        let started = match *group {
            Some(existing) => {
                let join = ChildOptions {
                    group: GroupMembership::Join(existing),
                    terminal: None,
                    signals: ChildSignals::Default,
                    ignore,
                };
                match self.spawner.start(request, &join) {
                    // Every member ended meanwhile: the group is gone, so this program leads a new one.
                    Err(PlatformError::UnknownProcessGroup) => {
                        self.jobs.registry.remove(existing);
                        *group = None;
                        self.spawner.start(request, &lead)?
                    }
                    other => other?,
                }
            }
            None => self.spawner.start(request, &lead)?,
        };
        if group.is_none()
            && let Started::Running(child) = started
            && let Some(led) = child.group()
        {
            *group = Some(led);
            self.jobs.registry.add(led);
        }
        Ok(started)
    }

    /// The status of `child`, started outside any pipeline stage: waited for here, stops ignored.
    pub(super) fn wait_alone(&mut self, child: ChildHandle) -> Flow<CommandOutcome> {
        loop {
            match self.spawner.wait(child)? {
                ChildEvent::Exited(status) => return Ok(CommandOutcome::Finished(status)),
                ChildEvent::Stopped(_) | ChildEvent::Continued => {}
            }
        }
    }

    /// A foreground pipeline, timed if it starts with `time`. Sets `$?` and, unless it is a compound command run in
    /// the shell, `PIPESTATUS`.
    ///
    /// KNSH-104: under `set -n` nothing runs (status 0); a `!` pipeline runs where `set -e` ignores failures; after
    /// the pipeline the signals handed over are acted on.
    pub(super) fn pipeline(&mut self, pipeline: &Pipeline, run: &Run<'_>) -> Flow<Status> {
        if self.state.options().noexec && !self.state.is_interactive() {
            return Ok(Status::SUCCESS);
        }
        let result = if pipeline.is_negated() {
            self.ignoring_errexit(|shell| shell.pipeline_body(pipeline, run))
        } else {
            self.pipeline_body(pipeline, run)
        };
        let status = result?;
        self.act_on_signals(pipeline.span, run)?;
        Ok(status)
    }

    fn pipeline_body(&mut self, pipeline: &Pipeline, run: &Run<'_>) -> Flow<Status> {
        match pipeline.time {
            Some(time) => self.timed(pipeline, time, run),
            None => self.untimed(pipeline, run),
        }
    }

    fn untimed(&mut self, pipeline: &Pipeline, run: &Run<'_>) -> Flow<Status> {
        if pipeline.rest.is_empty() {
            let alone = match &pipeline.first {
                Command::Compound(compound) => !matches!(compound.kind, CompoundKind::Subshell(_)),
                Command::FunctionDefinition(_) => true,
                // KNSH-105: `coproc` starts a background job of its own and sets the shell's variables.
                Command::Unsupported(unsupported) => unsupported.coproc.is_some(),
                Command::Simple(_) => false,
            };
            // Run in the shell itself, outside any job of its own: its commands are jobs each.
            if alone {
                let status = self.command(&pipeline.first, run)?;
                let status = if pipeline.is_negated() {
                    status.negated()
                } else {
                    status
                };
                self.state.set_last_status(status);
                return Ok(status);
            }
        }
        let key = self.launch(pipeline, false, run)?;
        let status = self.wait_foreground(key, run)?;
        // `exec cmd` in the shell itself: the shell was replaced by the program, and ends with it.
        if std::mem::take(&mut self.exit_after_job) {
            return Err(Stop::Exit(status));
        }
        // KNSH-104: a command, `( … )`, `[[ … ]]`, `(( … ))` or longer pipeline failed: the `ERR` trap, then `set -e`
        // (a compound command alone never triggers them itself, as in bash: its own commands do). A `!` pipeline's
        // inverted status never does.
        if !pipeline.is_negated() {
            self.command_failed(status, pipeline.span, run)?;
        }
        Ok(status)
    }

    /// `time pipeline`: the pipeline, then the real, user and system time it took on the shell's descriptor 2, in
    /// `TIMEFORMAT` (bash's default when unset, nothing when empty) or the POSIX format of `time -p`.
    fn timed(&mut self, pipeline: &Pipeline, time: TimeKeyword, run: &Run<'_>) -> Flow<Status> {
        let Some(times) = self.times.clone() else {
            return Err(unsupported(Unsupported::Time, time.span()).into());
        };
        let (real_start, cpu_start) = (times.elapsed(), times.cpu());
        let result = self.untimed(pipeline, run);
        let (real_end, cpu_end) = (times.elapsed(), times.cpu());
        let format = if time.posix.is_some() {
            Some(POSIX_TIME_FORMAT.to_owned())
        } else {
            match self.state.variable("TIMEFORMAT") {
                Some(format) => Some(format.to_string_lossy().into_owned()).filter(|format| !format.is_empty()),
                None => Some(DEFAULT_TIME_FORMAT.to_owned()),
            }
        };
        if let Some(format) = format {
            let cpu = cpu_end.since(cpu_start);
            let mut text = format_times(&format, real_end.saturating_sub(real_start), cpu.user, cpu.system);
            text.push('\n');
            self.write_shell(2, text.as_bytes());
        }
        result
    }

    /// Starts `pipeline` as a new job and returns its key: in the background when `background`, else to be waited
    /// for with [`Interpreter::wait_foreground`].
    pub(super) fn launch(&mut self, pipeline: &Pipeline, background: bool, run: &Run<'_>) -> Flow<Key> {
        let commands: Vec<&Command> = pipeline.commands().collect();
        let count = commands.len();
        let context = self.new_context(background);
        let span = Span::new(
            pipeline.first.span().start,
            commands.last().map_or(pipeline.span.end, |last| last.span().end),
        );
        let key = self.jobs.create(
            job_text(span, run),
            Arc::clone(&context.group),
            self.placement.is_none(),
            pipeline.is_negated(),
            self.state.options().pipefail,
        );
        let lastpipe = !background && count > 1 && self.state.options().lastpipe && !context.controlled;
        let mut input: Option<SharedFd> = None;
        for (index, command) in commands.iter().enumerate() {
            let last = index + 1 == count;
            let (next, output) = if last {
                (None, None)
            } else {
                let (read, write) = self.descriptors.pipe().map_err(InterpError::from)?;
                (Some(read), Some(write))
            };
            let pipe_all = pipeline
                .rest
                .get(index)
                .is_some_and(|part| part.operator == PipeOperator::PipeAll);
            // A subshell alone under job control runs on a thread of its own, so the shell keeps reading its events
            // and sees the job stop (Ctrl-Z) while the subshell waits for its stopped programs.
            let lone_subshell =
                matches!(command, Command::Compound(compound) if matches!(compound.kind, CompoundKind::Subshell(_)));
            let started = if last && !background && count == 1 && !(lone_subshell && context.controlled) {
                // A pipeline of one command in the foreground: the shell's own descriptors, changed for good by
                // `exec`.
                self.stage_here(key, command, None, &context, run)
            } else {
                let mut fds = self.fds.clone();
                if let Some(read) = input.take() {
                    fds.set(0, Some(ChildDescriptor::Open(read)));
                }
                if let Some(write) = &output {
                    fds.set(1, Some(ChildDescriptor::Open(write.clone())));
                }
                if last && lastpipe {
                    self.stage_here(key, command, Some(fds), &context, run)
                } else {
                    self.stage(key, command, fds, pipe_all, &context, run)
                }
            };
            // This shell's copy of the write end closes here, so the reader sees end of file once the writer ends.
            drop(output);
            if let Err(stop) = started {
                self.abandon(key);
                return Err(stop);
            }
            input = next;
        }
        Ok(key)
    }

    /// Forgets job `key` after its start failed part-way. Programs already started keep running, unwaited, as
    /// bash's would when the shell exits.
    fn abandon(&mut self, key: Key) {
        self.jobs.forget(key);
    }

    /// Runs `command`, a stage of job `key`, in the shell itself (with `fds` for its descriptors while it runs, or
    /// the shell's own), and adds it to the job: its program if it started one, else its status.
    fn stage_here(
        &mut self,
        key: Key,
        command: &Command,
        fds: Option<super::FdTable>,
        context: &JobContext,
        run: &Run<'_>,
    ) -> Flow<()> {
        let saved_fds = fds.map(|fds| std::mem::replace(&mut self.fds, fds));
        let saved_placement = self.placement.replace(context.clone());
        let result = match command {
            Command::Simple(simple) => {
                self.sink = Sink::Open;
                let result = self.simple(simple, run);
                let child = std::mem::take(&mut self.sink).started();
                result.map(|status| (status, child))
            }
            Command::Compound(compound) if matches!(compound.kind, CompoundKind::Subshell(_)) => {
                let mut subshell = self.subshell(self.fds.clone(), context.clone());
                let result = subshell.command(command, run);
                subshell
                    .finish_subshell(&result, run)
                    .map(|status| (status, None))
                    .map_err(Stop::Error)
            }
            other => self.command(other, run).map(|status| (status, None)),
        };
        self.placement = saved_placement;
        if let Some(fds) = saved_fds {
            self.fds = fds;
        }
        let (status, child) = result?;
        self.add_member(key, status, child)
    }

    /// Adds a member to job `key`: `child`, watched from now on, or a command that ended with `status`.
    fn add_member(&mut self, key: Key, status: Status, child: Option<ChildHandle>) -> Flow<()> {
        match child {
            Some(child) => {
                let index = self.jobs.push(key, Member::child(child));
                self.jobs.watch(&self.spawner, key, index, child)?;
            }
            None => {
                self.jobs.push(key, Member::done(status));
            }
        }
        Ok(())
    }

    /// Starts `command`, a stage of job `key`, in a subshell with `fds`: a simple command on this thread (its
    /// program started, not waited for), anything else on a thread of its own.
    fn stage(
        &mut self,
        key: Key,
        command: &Command,
        mut fds: super::FdTable,
        pipe_all: bool,
        context: &JobContext,
        run: &Run<'_>,
    ) -> Flow<()> {
        let applies_redirections = matches!(command, Command::Simple(_) | Command::Compound(_));
        if pipe_all && !applies_redirections {
            // No redirections of its own to come after: `|&` is `2>&1` now.
            let output = fds.get(1).cloned();
            fds.set(2, output);
        }
        let mut subshell = self.subshell(fds, context.clone());
        subshell.pipe_stderr = pipe_all && applies_redirections;
        // KNSH-103: a function runs beside the other stages, on a thread of its own, as a compound command does.
        let calls_function = matches!(command, Command::Simple(simple) if simple
            .words
            .first()
            .and_then(|first| super::alias::literal_text(first, run.source))
            .is_some_and(|name| self.state.function(name).is_some()));
        if let Command::Simple(simple) = command
            && !calls_function
        {
            subshell.forked_stage = true;
            subshell.sink = Sink::Open;
            let result = subshell.simple(simple, run);
            let child = std::mem::take(&mut subshell.sink).started();
            let status = subshell.finish_subshell(&result, run)?;
            // The subshell's copies of the pipe ends close now.
            drop(subshell);
            return self.add_member(key, status, child);
        }
        let command = command.clone();
        self.inside(key, subshell, run, move |shell, run| shell.command(&command, run))
    }

    /// Runs `task` in `subshell` on a thread of its own as a member of job `key`, which reports its status when it
    /// ends.
    fn inside<F>(&mut self, key: Key, mut subshell: Self, run: &Run<'_>, task: F) -> Flow<()>
    where
        F: FnOnce(&mut Self, &Run<'_>) -> Flow<Status> + Send + 'static,
    {
        let index = self.jobs.push(key, Member::inside());
        subshell.parent = Some(self.jobs.parent(key, index));
        let sender = self.jobs.sender();
        let source: Arc<str> = run.source_arc();
        let origin: Option<Arc<str>> = run.origin.map(Arc::from);
        let line_base = run.line_base;
        std::thread::Builder::new()
            .name("knsh-subshell".to_owned())
            .stack_size(EVAL_STACK_SIZE)
            .spawn(move || {
                let run = Run::shared(&source, origin.as_deref(), line_base);
                // A panic must still be reported, or the shell would wait for this member forever.
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let result = task(&mut subshell, &run);
                    subshell.finish_subshell(&result, &run)
                }))
                .unwrap_or(Err(InterpError::EvaluationThread));
                drop(subshell);
                // The shell may be gone (an error stopped the script): nobody to tell.
                let _ = sender.send(Jobs::inside_event(key, index, result));
            })
            .map_err(|_| InterpError::EvaluationThread)?;
        Ok(())
    }

    /// Waits for foreground job `key` to end (or, under job control, stop), then sets `PIPESTATUS` and `$?` and
    /// returns its status. An interactive shell takes the terminal back.
    pub(super) fn wait_foreground(&mut self, key: Key, run: &Run<'_>) -> Flow<Status> {
        let job_control = self.job_control();
        let stops = self.tracks_stops();
        // What this subshell last told its parent: its job stopped (by this signal), or runs.
        let mut told: Option<i32> = None;
        loop {
            let Some(job) = self.jobs.get(key) else {
                return Ok(self.state.last_status());
            };
            if job.is_done() {
                break;
            }
            let stopped = (stops && job.is_stopped()).then(|| job.stop_signal().unwrap_or(signals::SIGTSTP));
            if job_control && stopped.is_some() {
                return Ok(self.stopped(key, run));
            }
            // A subshell cannot stop itself: it tells its parent, whose job then counts as stopped, and keeps waiting
            // for its programs to be continued (`fg`, `bg`).
            if stopped != told
                && let Some(parent) = &self.parent
            {
                parent.tell(stopped);
                told = stopped;
            }
            self.jobs.next(stops)?;
        }
        if told.is_some()
            && let Some(parent) = &self.parent
        {
            parent.tell(None);
        }
        let Some(job) = self.jobs.forget(key) else {
            return Ok(self.state.last_status());
        };
        if job_control && job.group().is_some() {
            self.take_terminal();
        }
        if self.state.is_interactive() {
            self.report_signalled(&job);
        }
        let status = job.status();
        self.state.set_pipestatus(job.statuses());
        self.state.set_last_status(status);
        Ok(status)
    }

    /// After a foreground job a signal ended, an interactive bash ends the line Ctrl-C left (`SIGINT`) or names the
    /// signal (`Terminated: 15`); a broken pipe is not reported.
    fn report_signalled(&mut self, job: &crate::jobs::Job) {
        let Some(MemberState::Done(status)) = job.members.last().map(|member| member.state) else {
            return;
        };
        let Some(signal) = status.code().checked_sub(128).filter(|signal| *signal > 0) else {
            return;
        };
        let signal = i32::from(signal);
        let text = match signal {
            signals::SIGINT => "\n".to_owned(),
            signals::SIGPIPE => return,
            other => format!("{}\n", crate::jobs::signal_description(other)),
        };
        self.write_shell(2, text.as_bytes());
    }

    /// Gives the terminal back to the shell, if it has one. A failure is ignored, as bash ignores it.
    pub(super) fn take_terminal(&self) {
        if let Some(terminal) = &self.terminal {
            let _ = terminal.set_foreground(None);
        }
    }

    /// Foreground job `key` stopped: it joins the jobs table, the shell takes the terminal back and reports it as
    /// bash does, and its status is `128 + signal`.
    fn stopped(&mut self, key: Key, _run: &Run<'_>) -> Status {
        self.take_terminal();
        let number = self.jobs.number(key);
        let mark = self.jobs.mark(number);
        let Some(job) = self.jobs.get_mut(key) else {
            return self.state.last_status();
        };
        job.notified = true;
        let signal = job.stop_signal().unwrap_or(signals::SIGTSTP);
        let line = format!("\n{}\n", job.line(mark, false));
        let statuses = job.statuses();
        self.write_shell(2, line.as_bytes());
        let status = Status::from_signal(signal);
        self.state.set_pipestatus(statuses);
        self.state.set_last_status(status);
        status
    }

    /// `and_or &`: started as a background job, `$!` set. Its status (and `$?`) is 0; `PIPESTATUS` is left as it
    /// was, as in bash. An interactive shell prints `[n] pid`.
    pub(super) fn background(&mut self, and_or: &AndOr, run: &Run<'_>) -> Flow<Status> {
        if self.state.options().noexec && !self.state.is_interactive() {
            return Ok(Status::SUCCESS);
        }
        let key = if and_or.rest.is_empty() && and_or.first.time.is_none() {
            self.launch(&and_or.first, true, run)?
        } else {
            // A list or a timed pipeline runs whole in a subshell on a thread of its own.
            let context = self.new_context(true);
            let key = self.jobs.create(
                job_text(and_or.span, run),
                Arc::clone(&context.group),
                self.placement.is_none(),
                false,
                false,
            );
            let subshell = self.subshell(self.fds.clone(), context);
            let and_or = and_or.clone();
            if let Err(stop) = self.inside(key, subshell, run, move |shell, run| shell.and_or(&and_or, run)) {
                self.abandon(key);
                return Err(stop);
            }
            key
        };
        self.started_in_background(key);
        self.state.set_last_status(Status::SUCCESS);
        self.act_on_signals(and_or.span, run)?;
        Ok(Status::SUCCESS)
    }

    /// Job `key` was started in the background (`&`, `coproc`): `$!` names its last command, and an interactive
    /// shell announces it as bash does (`[n] pid`). Returns what `$!` names.
    pub(super) fn started_in_background(&mut self, key: Key) -> LastBackground {
        let last = self.jobs.get(key).and_then(|job| job.members.last()).cloned();
        let last = match last {
            Some(Member { pid: Some(pid), .. }) => LastBackground::Process(pid),
            Some(Member { pid: None, .. }) | None => LastBackground::InShell,
        };
        self.state.set_last_background(last);
        let number = self.jobs.number(key);
        if self.state.is_interactive() {
            // Bash announces `$!`, the last command's process id.
            let pid = match last {
                LastBackground::Process(pid) => format!(" {pid}"),
                LastBackground::InShell => String::new(),
            };
            self.write_shell(2, format!("[{number}]{pid}\n").as_bytes());
        }
        last
    }

    /// Continues job `key` (`fg`, `bg`): `SIGCONT` to its group if it is stopped; its stopped members run again.
    pub(super) fn continue_job(&mut self, key: Key) -> Flow<()> {
        let Some(job) = self.jobs.get_mut(key) else {
            return Ok(());
        };
        let stopped = job.is_stopped();
        job.notified = false;
        for member in &mut job.members {
            if let MemberState::Stopped(_) = member.state {
                member.state = MemberState::Running;
            }
        }
        if stopped && let Some(group) = job.group() {
            match self.spawner.signal_job(group, Signal::Continue) {
                Ok(()) | Err(PlatformError::UnknownProcessGroup) => {}
                Err(error) => return Err(InterpError::Platform(error).into()),
            }
        }
        Ok(())
    }
}

/// `format` (bash's `TIMEFORMAT`) with `%[p][l]R`, `%[p][l]U`, `%[p][l]S` replaced by the real, user and system
/// time (`p` decimals, 0 to 3, default 3, truncated; `l` as `MmS.FFFs`), `%P` by the CPU percentage and `%%` by `%`.
/// Anything else is kept as written.
pub(crate) fn format_times(
    format: &str,
    real: std::time::Duration,
    user: std::time::Duration,
    system: std::time::Duration,
) -> String {
    let mut out = String::new();
    let chars: Vec<char> = format.chars().collect();
    let mut at = 0;
    while let Some(&ch) = chars.get(at) {
        at += 1;
        if ch != '%' {
            out.push(ch);
            continue;
        }
        let start = at - 1;
        if chars.get(at) == Some(&'%') {
            out.push('%');
            at += 1;
            continue;
        }
        if chars.get(at) == Some(&'P') {
            let real_micros = real.as_micros();
            let cpu = (user + system).as_micros();
            let hundredths = (cpu * 10_000).checked_div(real_micros).unwrap_or(0);
            let _ = write!(out, "{}.{:02}", hundredths / 100, hundredths % 100);
            at += 1;
            continue;
        }
        let mut precision = 3;
        if let Some(digit) = chars.get(at).and_then(|ch| ch.to_digit(10)) {
            precision = digit.min(3);
            at += 1;
        }
        let long = chars.get(at) == Some(&'l');
        if long {
            at += 1;
        }
        let value = match chars.get(at) {
            Some('R') => real,
            Some('U') => user,
            Some('S') => system,
            _ => {
                out.extend(&chars[start..at]);
                continue;
            }
        };
        at += 1;
        out.push_str(&seconds(value, precision, long));
    }
    out
}

/// `value` in seconds with `precision` decimals (truncated), or as `MmS.FFFs` when `long`.
fn seconds(value: std::time::Duration, precision: u32, long: bool) -> String {
    let millis = value.as_millis();
    let (minutes, rest) = if long {
        (millis / 60_000, millis % 60_000)
    } else {
        (0, millis)
    };
    let whole = rest / 1000;
    let fraction = match precision {
        0 => String::new(),
        digits => {
            let scaled = (rest % 1000) / 10u128.pow(3 - digits);
            format!(".{scaled:0width$}", width = digits as usize)
        }
    };
    if long {
        format!("{minutes}m{whole}{fraction}s")
    } else {
        format!("{whole}{fraction}")
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    // The formats of `time`, as bash 3.2 prints them (compared by hand with `/bin/bash`).
    #[test]
    fn time_formats_follow_bash() {
        let ms = Duration::from_millis;
        assert_eq!(
            format_times(DEFAULT_TIME_FORMAT, ms(1234), ms(5), ms(61_002)),
            "\nreal\t0m1.234s\nuser\t0m0.005s\nsys\t1m1.002s"
        );
        assert_eq!(
            format_times(POSIX_TIME_FORMAT, ms(1239), ms(0), ms(10)),
            "real 1.23\nuser 0.00\nsys 0.01"
        );
        assert_eq!(
            format_times("%0R|%1U|%%|%x|%P%%", ms(2000), ms(500), ms(500)),
            "2|0.5|%|%x|50.00%"
        );
    }
}
