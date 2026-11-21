//! External commands whose outcome is scripted per program (KNSH-096, KNSH-100).

use std::collections::{BTreeMap, VecDeque};
use std::path::PathBuf;
use std::sync::{Condvar, Mutex, PoisonError};
use std::time::Duration;

use super::lock;
use crate::command::{CommandOutcome, CommandRequest, CommandSpawner, Started};
use crate::error::PlatformError;
use crate::process::{ChildEvent, ChildHandle, ChildOptions, ExitStatus, GroupMembership, ProcessGroupId, Signal};

/// First process id handed out: far from real low ids, so a fake id never looks like `init` or the test runner.
const FIRST_PID: i32 = 20_000;

/// What one run of a program does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Planned {
    /// How it ends.
    outcome: CommandOutcome,
    /// How long it runs before ending, counted by the thread waiting for it.
    delay: Duration,
    /// A signal that stops it first: the first wait reports the stop, the next ends only after a `SIGCONT`.
    stop: Option<i32>,
}

/// A started command not yet reaped.
#[derive(Debug)]
struct Child {
    planned: Planned,
    /// Its group, `None` for the caller's.
    group: Option<i32>,
    /// The stop was reported.
    stop_reported: bool,
    /// A `SIGCONT` (or a terminating signal) reached it after the stop.
    continued: bool,
}

#[derive(Debug, Default)]
struct State {
    /// Runs still to give, per program. The last one is repeated forever, so a loop can run a program any number of
    /// times.
    plans: BTreeMap<PathBuf, VecDeque<Planned>>,
    /// Every request run, in order, with the options it was started with.
    runs: Vec<(CommandRequest, ChildOptions)>,
    /// Started commands not yet reaped, by process id.
    children: BTreeMap<i32, Child>,
    /// Every signal sent to a job, in order.
    signals: Vec<(ProcessGroupId, Signal)>,
    /// The next process id.
    next_pid: i32,
}

/// A [`CommandSpawner`] that runs nothing: each program answers with the outcomes the test scripted for it, in
/// order, the last one repeated. A program with no script fails with [`PlatformError::NotScripted`], so a test
/// cannot pass by running something it did not expect.
///
/// Started commands get process ids from 20,000 and the groups their [`ChildOptions`] ask for; a group can be
/// joined while a member is unreaped, as on the real system. A run can be scripted to last a while
/// ([`ScriptedCommands::on_after`]) or to stop first ([`ScriptedCommands::on_stopping`]); a terminating signal sent to
/// its group ends it at once by that signal.
#[derive(Debug, Default)]
pub struct ScriptedCommands {
    state: Mutex<State>,
    /// Notified when a stopped child is continued or killed.
    changed: Condvar,
}

impl ScriptedCommands {
    /// No programs scripted.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn plan(&self, program: PathBuf, planned: Planned) {
        lock(&self.state).plans.entry(program).or_default().push_back(planned);
    }

    /// Queues `outcome` for `program`: the next run of `program` gives the first outcome queued and not yet given;
    /// once only one is left, every later run gives it.
    pub fn on(&self, program: impl Into<PathBuf>, outcome: CommandOutcome) {
        self.on_after(program, Duration::ZERO, outcome);
    }

    /// Queues a run of `program` that ends as `outcome` after `delay`, counted by the thread waiting for it.
    pub fn on_after(&self, program: impl Into<PathBuf>, delay: Duration, outcome: CommandOutcome) {
        self.plan(
            program.into(),
            Planned {
                outcome,
                delay,
                stop: None,
            },
        );
    }

    /// Queues a run of `program` that `signal` stops at once (as Ctrl-Z would) and that ends as `outcome` once its
    /// group is sent `SIGCONT`.
    pub fn on_stopping(&self, program: impl Into<PathBuf>, signal: i32, outcome: CommandOutcome) {
        self.plan(
            program.into(),
            Planned {
                outcome,
                delay: Duration::ZERO,
                stop: Some(signal),
            },
        );
    }

    /// Every request run, scripted or not, in order.
    #[must_use]
    pub fn runs(&self) -> Vec<CommandRequest> {
        lock(&self.state)
            .runs
            .iter()
            .map(|(request, _)| request.clone())
            .collect()
    }

    /// The options every request was started with, in order.
    #[must_use]
    pub fn options(&self) -> Vec<ChildOptions> {
        lock(&self.state)
            .runs
            .iter()
            .map(|(_, options)| options.clone())
            .collect()
    }

    /// The `argv[0]` of every request run, in order, as text: a compact trace for assertions.
    #[must_use]
    pub fn names(&self) -> Vec<String> {
        lock(&self.state)
            .runs
            .iter()
            .map(|(run, _)| run.argv0.to_string_lossy().into_owned())
            .collect()
    }

    /// Every signal sent to a job, in order.
    #[must_use]
    pub fn signals(&self) -> Vec<(ProcessGroupId, Signal)> {
        lock(&self.state).signals.clone()
    }

    /// The process ids of started commands not yet reaped.
    #[must_use]
    pub fn unreaped(&self) -> Vec<i32> {
        lock(&self.state).children.keys().copied().collect()
    }
}

impl CommandSpawner for ScriptedCommands {
    fn start(&self, request: &CommandRequest, options: &ChildOptions) -> Result<Started, PlatformError> {
        let mut state = lock(&self.state);
        state.runs.push((request.clone(), options.clone()));
        let queue = state
            .plans
            .get_mut(&request.program)
            .ok_or(PlatformError::NotScripted)?;
        let planned = if queue.len() > 1 {
            queue.pop_front()
        } else {
            queue.front().copied()
        }
        .ok_or(PlatformError::NotScripted)?;
        if !matches!(planned.outcome, CommandOutcome::Finished(_)) {
            return Ok(Started::Refused(planned.outcome));
        }
        if state.next_pid == 0 {
            state.next_pid = FIRST_PID;
        }
        let pid = state.next_pid;
        state.next_pid += 1;
        let group = match options.group {
            GroupMembership::Inherit => None,
            GroupMembership::Lead => Some(pid),
            GroupMembership::Join(group) => {
                if !state.children.values().any(|child| child.group == Some(group.as_raw())) {
                    return Err(PlatformError::UnknownProcessGroup);
                }
                Some(group.as_raw())
            }
        };
        state.children.insert(
            pid,
            Child {
                planned,
                group,
                stop_reported: false,
                continued: false,
            },
        );
        Ok(Started::Running(ChildHandle::new(
            pid,
            0,
            group.map(ProcessGroupId::from_raw),
        )))
    }

    fn wait(&self, handle: ChildHandle) -> Result<ChildEvent, PlatformError> {
        let pid = handle.pid();
        let mut state = lock(&self.state);
        let child = state.children.get_mut(&pid).ok_or(PlatformError::UnknownProcessGroup)?;
        if let Some(signal) = child.planned.stop {
            if !child.stop_reported {
                child.stop_reported = true;
                return Ok(ChildEvent::Stopped(signal));
            }
            while !state.children.get(&pid).is_some_and(|child| child.continued) {
                state = self.changed.wait(state).unwrap_or_else(PoisonError::into_inner);
            }
        }
        let delay = state
            .children
            .get(&pid)
            .map_or(Duration::ZERO, |child| child.planned.delay);
        drop(state);
        if !delay.is_zero() {
            std::thread::sleep(delay);
        }
        let child = lock(&self.state)
            .children
            .remove(&pid)
            .ok_or(PlatformError::UnknownProcessGroup)?;
        match child.planned.outcome {
            CommandOutcome::Finished(status) => Ok(ChildEvent::Exited(status)),
            CommandOutcome::NotFound | CommandOutcome::NotExecutable => Err(PlatformError::NotScripted),
        }
    }

    fn signal_job(&self, group: ProcessGroupId, signal: Signal) -> Result<(), PlatformError> {
        let mut state = lock(&self.state);
        let members: Vec<i32> = state
            .children
            .iter()
            .filter(|(_, child)| child.group == Some(group.as_raw()))
            .map(|(&pid, _)| pid)
            .collect();
        if members.is_empty() {
            return Err(PlatformError::UnknownProcessGroup);
        }
        state.signals.push((group, signal));
        for pid in members {
            let Some(child) = state.children.get_mut(&pid) else {
                continue;
            };
            match signal {
                Signal::Continue => child.continued = true,
                Signal::Stop => {}
                Signal::Interrupt | Signal::Terminate | Signal::Kill | Signal::Hangup => {
                    child.planned.outcome = CommandOutcome::Finished(ExitStatus::Signalled(signal.number()));
                    child.planned.delay = Duration::ZERO;
                    child.continued = true;
                }
            }
        }
        drop(state);
        self.changed.notify_all();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(program: &str) -> CommandRequest {
        CommandRequest {
            program: program.into(),
            argv0: "x".into(),
            args: Vec::new(),
            env: Vec::new(),
            cwd: "/".into(),
            descriptors: CommandRequest::standard_descriptors(),
        }
    }

    #[test]
    fn gives_outcomes_in_order_and_repeats_the_last() {
        let commands = ScriptedCommands::new();
        commands.on("/bin/x", CommandOutcome::Finished(ExitStatus::Exited(0)));
        commands.on("/bin/x", CommandOutcome::Finished(ExitStatus::Exited(1)));
        let outcomes: Vec<_> = (0..3).map(|_| commands.run(&request("/bin/x")).unwrap()).collect();
        assert_eq!(
            outcomes,
            [
                CommandOutcome::Finished(ExitStatus::Exited(0)),
                CommandOutcome::Finished(ExitStatus::Exited(1)),
                CommandOutcome::Finished(ExitStatus::Exited(1)),
            ]
        );
        assert_eq!(commands.runs().len(), 3);
        assert_eq!(commands.unreaped(), Vec::<i32>::new());
    }

    #[test]
    fn refuses_an_unscripted_program_but_records_it() {
        let commands = ScriptedCommands::new();
        assert_eq!(commands.run(&request("/bin/y")), Err(PlatformError::NotScripted));
        assert_eq!(commands.names(), ["x"]);
    }

    // KNSH-100: groups are joined only while a member is held; a stopped run ends after SIGCONT.
    #[test]
    fn places_groups_and_resumes_stopped_runs() {
        let commands = ScriptedCommands::new();
        commands.on_stopping("/bin/x", libc::SIGTSTP, CommandOutcome::Finished(ExitStatus::Exited(4)));
        let lead = ChildOptions {
            group: GroupMembership::Lead,
            ..ChildOptions::default()
        };
        let Started::Running(child) = commands.start(&request("/bin/x"), &lead).unwrap() else {
            panic!("refused");
        };
        let group = child.group().unwrap();
        assert_eq!(group.as_raw(), child.pid());
        assert_eq!(commands.wait(child), Ok(ChildEvent::Stopped(libc::SIGTSTP)));
        let resumer = std::thread::scope(|scope| {
            let waiter = scope.spawn(|| commands.wait(child));
            commands.signal_job(group, Signal::Continue).unwrap();
            waiter.join().unwrap()
        });
        assert_eq!(resumer, Ok(ChildEvent::Exited(ExitStatus::Exited(4))));
        assert_eq!(
            commands.signal_job(group, Signal::Continue),
            Err(PlatformError::UnknownProcessGroup)
        );
        let join = ChildOptions {
            group: GroupMembership::Join(group),
            ..ChildOptions::default()
        };
        assert_eq!(
            commands.start(&request("/bin/x"), &join),
            Err(PlatformError::UnknownProcessGroup)
        );
    }
}
