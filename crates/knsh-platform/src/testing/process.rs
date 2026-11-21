//! Processes whose outcome is scripted in advance.

use std::collections::{BTreeMap, VecDeque};
use std::path::PathBuf;
use std::sync::Mutex;

use super::lock;
use crate::error::{Operation, PlatformError};
use crate::process::{
    ChildEvent, ChildHandle, ChildOptions, ExitStatus, GroupMembership, ProcessGroupId, Processes, Signal, SpawnRequest,
};

/// First group id handed out; low ids are left alone so a fake id never looks like `init` or the test runner.
const FIRST_GROUP: i32 = 10_000;

/// What the next spawned process does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Script {
    /// It has already exited with this code when spawned; signals reach it but change nothing.
    Exits(i32),
    /// It runs until a terminating signal (anything but `Stop` and `Continue`) arrives, then ends by that signal.
    /// Waiting on it before such a signal fails with [`PlatformError::NotScripted`]: in a real system that wait
    /// would block forever, which is a bug in the test.
    RunsUntilSignalled,
    /// Spawning fails with this `errno` (for example `ENOENT`, `EACCES`).
    FailsToSpawn(i32),
}

#[derive(Debug)]
struct Running {
    script: Script,
    /// Set by the first terminating signal for [`Script::RunsUntilSignalled`].
    ended_by: Option<i32>,
    /// The group a child of [`Processes::spawn_child`] is in (`None` for the caller's); a [`Processes::spawn`] group
    /// is its own.
    group: Option<i32>,
}

#[derive(Debug)]
struct State {
    scripts: VecDeque<(PathBuf, Script)>,
    next_group: i32,
    /// Groups spawned and not yet reaped.
    running: BTreeMap<i32, Running>,
    spawned: Vec<SpawnRequest>,
    signals: Vec<(ProcessGroupId, Signal)>,
}

/// Scripted processes. Each [`Processes::spawn`] consumes the next script, which must name the same program;
/// anything unexpected fails with [`PlatformError::NotScripted`] so a test cannot pass by accident.
///
/// Like the real backend, it signals only groups it spawned and has not reaped.
#[derive(Debug)]
pub struct ScriptedProcesses {
    state: Mutex<State>,
}

impl Default for ScriptedProcesses {
    fn default() -> Self {
        Self::new()
    }
}

impl ScriptedProcesses {
    /// No scripts and no groups.
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: Mutex::new(State {
                scripts: VecDeque::new(),
                next_group: FIRST_GROUP,
                running: BTreeMap::new(),
                spawned: Vec::new(),
                signals: Vec::new(),
            }),
        }
    }

    /// Queues `script` for the next spawn, which must be of `program`.
    pub fn expect(&self, program: impl Into<PathBuf>, script: Script) {
        lock(&self.state).scripts.push_back((program.into(), script));
    }

    /// Every request passed to a successful or failed spawn that matched a script, in order.
    #[must_use]
    pub fn spawned(&self) -> Vec<SpawnRequest> {
        lock(&self.state).spawned.clone()
    }

    /// Every signal delivered, in order.
    #[must_use]
    pub fn signals(&self) -> Vec<(ProcessGroupId, Signal)> {
        lock(&self.state).signals.clone()
    }

    /// Scripts not yet consumed. Assert this is zero at the end of a test.
    #[must_use]
    pub fn remaining_scripts(&self) -> usize {
        lock(&self.state).scripts.len()
    }
}

/// The status of a scripted process, or `None` if it is still running.
fn status_of(running: &Running) -> Option<ExitStatus> {
    match (running.script, running.ended_by) {
        (Script::Exits(code), _) => Some(ExitStatus::Exited(code)),
        (Script::RunsUntilSignalled | Script::FailsToSpawn(_), Some(signal)) => Some(ExitStatus::Signalled(signal)),
        (Script::RunsUntilSignalled | Script::FailsToSpawn(_), None) => None,
    }
}

impl Processes for ScriptedProcesses {
    fn spawn(&self, request: &SpawnRequest) -> Result<ProcessGroupId, PlatformError> {
        if !request.program.is_absolute() {
            return Err(PlatformError::InvalidPath);
        }
        let mut state = lock(&self.state);
        let script = match state.scripts.front() {
            Some((program, script)) if *program == request.program => *script,
            Some(_) | None => return Err(PlatformError::NotScripted),
        };
        state.scripts.pop_front();
        state.spawned.push(request.clone());
        if let Script::FailsToSpawn(errno) = script {
            return Err(PlatformError::Os {
                operation: Operation::Spawn,
                errno,
            });
        }
        let id = state.next_group;
        state.next_group += 1;
        state.running.insert(
            id,
            Running {
                script,
                ended_by: None,
                group: Some(id),
            },
        );
        Ok(ProcessGroupId::from_raw(id))
    }

    fn spawn_child(&self, request: &SpawnRequest, options: &ChildOptions) -> Result<ChildHandle, PlatformError> {
        if let GroupMembership::Join(group) = options.group {
            let state = lock(&self.state);
            if !state
                .running
                .values()
                .any(|running| running.group == Some(group.as_raw()))
            {
                return Err(PlatformError::UnknownProcessGroup);
            }
        }
        let id = self.spawn(request)?.as_raw();
        let group = match options.group {
            GroupMembership::Inherit => None,
            GroupMembership::Lead => Some(id),
            GroupMembership::Join(group) => Some(group.as_raw()),
        };
        if let Some(running) = lock(&self.state).running.get_mut(&id) {
            running.group = group;
        }
        Ok(ChildHandle::new(id, 0, group.map(ProcessGroupId::from_raw)))
    }

    fn wait_child(&self, child: ChildHandle) -> Result<ChildEvent, PlatformError> {
        self.wait(ProcessGroupId::from_raw(child.pid())).map(ChildEvent::Exited)
    }

    fn signal_job(&self, group: ProcessGroupId, signal: Signal) -> Result<(), PlatformError> {
        let mut state = lock(&self.state);
        if !state
            .running
            .values()
            .any(|running| running.group == Some(group.as_raw()))
        {
            return Err(PlatformError::UnknownProcessGroup);
        }
        state.signals.push((group, signal));
        Ok(())
    }

    fn signal(&self, group: ProcessGroupId, signal: Signal) -> Result<(), PlatformError> {
        let mut state = lock(&self.state);
        let running = state
            .running
            .get_mut(&group.as_raw())
            .ok_or(PlatformError::UnknownProcessGroup)?;
        let terminates = match signal {
            Signal::Interrupt | Signal::Terminate | Signal::Kill | Signal::Hangup => true,
            Signal::Stop | Signal::Continue => false,
        };
        if terminates && running.script == Script::RunsUntilSignalled && running.ended_by.is_none() {
            running.ended_by = Some(signal.number());
        }
        state.signals.push((group, signal));
        Ok(())
    }

    fn wait(&self, group: ProcessGroupId) -> Result<ExitStatus, PlatformError> {
        let mut state = lock(&self.state);
        let running = state
            .running
            .get(&group.as_raw())
            .ok_or(PlatformError::UnknownProcessGroup)?;
        let status = status_of(running).ok_or(PlatformError::NotScripted)?;
        state.running.remove(&group.as_raw());
        Ok(status)
    }

    fn exited(&self, group: ProcessGroupId) -> Result<bool, PlatformError> {
        let state = lock(&self.state);
        let running = state
            .running
            .get(&group.as_raw())
            .ok_or(PlatformError::UnknownProcessGroup)?;
        Ok(status_of(running).is_some())
    }

    fn try_wait(&self, group: ProcessGroupId) -> Result<Option<ExitStatus>, PlatformError> {
        let mut state = lock(&self.state);
        let running = state
            .running
            .get(&group.as_raw())
            .ok_or(PlatformError::UnknownProcessGroup)?;
        let status = status_of(running);
        if status.is_some() {
            state.running.remove(&group.as_raw());
        }
        Ok(status)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // CLAUDE.md "Concurrency": the fake enforces the same rule as the real backend.
    #[test]
    fn signal_refuses_unknown_process_group() {
        let processes = ScriptedProcesses::new();
        assert_eq!(
            processes.signal(ProcessGroupId::from_raw(FIRST_GROUP), Signal::Kill),
            Err(PlatformError::UnknownProcessGroup)
        );
        processes.expect("/bin/true", Script::Exits(0));
        let group = processes.spawn(&SpawnRequest::new("/bin/true")).unwrap();
        assert_eq!(processes.wait(group), Ok(ExitStatus::Exited(0)));
        assert_eq!(
            processes.signal(group, Signal::Kill),
            Err(PlatformError::UnknownProcessGroup)
        );
        assert_eq!(processes.signals(), []);
    }

    #[test]
    fn scripted_process_ends_by_the_first_terminating_signal() {
        let processes = ScriptedProcesses::new();
        processes.expect("/bin/sleep", Script::RunsUntilSignalled);
        let group = processes.spawn(&SpawnRequest::new("/bin/sleep").arg("10")).unwrap();
        assert_eq!(processes.try_wait(group), Ok(None));
        assert_eq!(processes.wait(group), Err(PlatformError::NotScripted));
        processes.signal(group, Signal::Stop).unwrap();
        processes.signal(group, Signal::Terminate).unwrap();
        processes.signal(group, Signal::Kill).unwrap();
        assert_eq!(processes.wait(group), Ok(ExitStatus::Signalled(libc::SIGTERM)));
        assert_eq!(processes.signals().len(), 3);
        assert_eq!(processes.spawned()[0].args, ["10"]);
    }

    #[test]
    fn unexpected_or_failing_spawns_are_reported() {
        let processes = ScriptedProcesses::new();
        assert_eq!(
            processes.spawn(&SpawnRequest::new("/bin/ls")),
            Err(PlatformError::NotScripted)
        );
        processes.expect("/bin/ls", Script::FailsToSpawn(libc::EACCES));
        assert_eq!(
            processes.spawn(&SpawnRequest::new("/bin/ls")).unwrap_err().errno(),
            Some(libc::EACCES)
        );
        assert_eq!(processes.remaining_scripts(), 0);
    }
}
