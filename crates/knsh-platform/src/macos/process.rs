//! Process groups on the real system.
//!
//! # Why reuse-safe
//!
//! A group id equals its leader's pid. The kernel cannot hand that pid to a new process while the leader exists,
//! including as an unreaped zombie. So this module keeps every leader unreaped until it removes the group from its
//! table, and both `killpg` and the reaping happen under the same lock: a signal either finds the group in the table
//! (leader not yet reaped, id still ours) or is refused.
//!
//! Waiting must not hold that lock while it blocks, or nobody could signal a running group. [`SystemProcesses::wait`]
//! therefore blocks in `waitid(…, WNOWAIT)`, which reports the exit without reaping, and only then takes the lock,
//! removes the entry and reaps.

use std::collections::HashMap;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::process::{Child, Command};
use std::sync::{Mutex, MutexGuard, PoisonError};

use crate::error::{Operation, PlatformError};
use crate::process::{ExitStatus, ProcessGroupId, Processes, Signal, SpawnRequest, Stdio};

/// Starts processes in new process groups and signals only the groups it holds.
///
/// Dropping it neither kills nor reaps the remaining children: they keep running and are reaped when the engine
/// exits. The supervisor waits for every group it starts.
#[derive(Debug, Default)]
pub struct SystemProcesses {
    /// Groups spawned and not yet reaped, by group id. Lock order: this is the only lock in the type.
    groups: Mutex<Table>,
}

/// The groups held, each tagged with a spawn generation.
#[derive(Debug, Default)]
struct Table {
    /// Incremented on every spawn.
    next_generation: u64,
    /// Unreaped leaders by group id, with the generation they were spawned in.
    entries: HashMap<i32, (u64, Child)>,
}

impl SystemProcesses {
    /// An instance holding no groups.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Locks the table. A poisoned lock is still usable: the table holds no invariant that a panic can break
    /// halfway (each update is one insert or remove).
    fn table(&self) -> MutexGuard<'_, Table> {
        self.groups.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Converts the standard status of a reaped child.
fn convert(status: std::process::ExitStatus) -> ExitStatus {
    match (status.code(), status.signal()) {
        (Some(code), _) => ExitStatus::Exited(code),
        (None, Some(signal)) => ExitStatus::Signalled(signal),
        // Neither code nor signal only happens for a stopped or continued child, which `wait` never reports.
        (None, None) => ExitStatus::Signalled(0),
    }
}

/// Blocks until `pid` has exited, without reaping it (`WNOWAIT`), so its id stays reserved.
fn wait_exit_without_reaping(pid: i32) -> Result<(), PlatformError> {
    let id = libc::id_t::try_from(pid).map_err(|_| PlatformError::UnknownProcessGroup)?;
    loop {
        // SAFETY: an all-zero `siginfo_t` is a valid value (it is a plain C struct of integers and pointers).
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        // SAFETY: `info` is a valid, writable `siginfo_t` for the duration of the call. `waitid` touches no other
        // memory, and with `WNOWAIT` it does not change the child's state.
        let rc = unsafe { libc::waitid(libc::P_PID, id, &raw mut info, libc::WEXITED | libc::WNOWAIT) };
        if rc == 0 {
            return Ok(());
        }
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EINTR) {
            return Err(PlatformError::from_io(Operation::Wait, &error));
        }
    }
}

impl Processes for SystemProcesses {
    fn spawn(&self, request: &SpawnRequest) -> Result<ProcessGroupId, PlatformError> {
        if !request.program.is_absolute() {
            return Err(PlatformError::InvalidPath);
        }
        let mut command = Command::new(&request.program);
        command
            .args(&request.args)
            .env_clear()
            .envs(request.env.iter().map(|(k, v)| (k, v)))
            // A new group led by the child itself (`setpgid(0, 0)` in the child before exec).
            .process_group(0);
        if let Some(cwd) = &request.cwd {
            command.current_dir(cwd);
        }
        let descriptor: fn() -> std::process::Stdio = match request.stdio {
            Stdio::Null => std::process::Stdio::null,
            Stdio::Inherit => std::process::Stdio::inherit,
        };
        command.stdin(descriptor()).stdout(descriptor()).stderr(descriptor());
        let child = command
            .spawn()
            .map_err(|error| PlatformError::from_io(Operation::Spawn, &error))?;
        let pid = i32::try_from(child.id()).map_err(|_| PlatformError::Os {
            operation: Operation::Spawn,
            errno: libc::ERANGE,
        })?;
        let mut table = self.table();
        table.next_generation += 1;
        let generation = table.next_generation;
        table.entries.insert(pid, (generation, child));
        Ok(ProcessGroupId::from_raw(pid))
    }

    fn signal(&self, group: ProcessGroupId, signal: Signal) -> Result<(), PlatformError> {
        // Holding the lock across `killpg` is what makes this safe: the leader cannot be reaped (and its id freed)
        // until the lock is released.
        let table = self.table();
        if !table.entries.contains_key(&group.as_raw()) {
            return Err(PlatformError::UnknownProcessGroup);
        }
        // SAFETY: `killpg` takes plain integers and touches no memory. The group is in the table, so its leader is
        // unreaped and the id still names the group this instance created.
        let rc = unsafe { libc::killpg(group.as_raw(), signal.number()) };
        drop(table);
        if rc == 0 {
            Ok(())
        } else {
            Err(PlatformError::from_io(
                Operation::Signal,
                &std::io::Error::last_os_error(),
            ))
        }
    }

    fn wait(&self, group: ProcessGroupId) -> Result<ExitStatus, PlatformError> {
        let generation = match self.table().entries.get(&group.as_raw()) {
            Some((generation, _)) => *generation,
            None => return Err(PlatformError::UnknownProcessGroup),
        };
        match wait_exit_without_reaping(group.as_raw()) {
            Ok(()) => {}
            // Another thread reaped it while this one was blocked: same outcome as calling after the reap.
            Err(PlatformError::Os {
                errno: libc::ECHILD, ..
            }) => return Err(PlatformError::UnknownProcessGroup),
            Err(error) => return Err(error),
        }
        // Only the thread that removes the entry reaps it; a second concurrent waiter finds it gone. The generation
        // check covers the case where another thread reaped the original leader and this instance then spawned a
        // new child that the kernel gave the same id: that newer entry is not ours to reap.
        let mut table = self.table();
        if table.entries.get(&group.as_raw()).map(|(g, _)| *g) != Some(generation) {
            return Err(PlatformError::UnknownProcessGroup);
        }
        let Some((_, mut child)) = table.entries.remove(&group.as_raw()) else {
            return Err(PlatformError::UnknownProcessGroup);
        };
        drop(table);
        // The child has exited (reported above), so this returns at once.
        let status = child
            .wait()
            .map_err(|error| PlatformError::from_io(Operation::Wait, &error))?;
        Ok(convert(status))
    }

    fn try_wait(&self, group: ProcessGroupId) -> Result<Option<ExitStatus>, PlatformError> {
        let mut table = self.table();
        let (_, child) = table
            .entries
            .get_mut(&group.as_raw())
            .ok_or(PlatformError::UnknownProcessGroup)?;
        // Non-blocking, so reaping under the lock is fine.
        let status = child
            .try_wait()
            .map_err(|error| PlatformError::from_io(Operation::Wait, &error))?;
        if status.is_some() {
            table.entries.remove(&group.as_raw());
        }
        Ok(status.map(convert))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // CLAUDE.md "Concurrency": never signal a pid that may have been reused.
    #[test]
    fn signal_refuses_unknown_process_group() {
        let processes = SystemProcesses::new();
        // Our own process group: real, alive, and not created by this instance.
        // SAFETY: `getpgrp` has no preconditions and touches no memory.
        let own = ProcessGroupId::from_raw(unsafe { libc::getpgrp() });
        assert_eq!(
            processes.signal(own, Signal::Terminate),
            Err(PlatformError::UnknownProcessGroup)
        );
        assert_eq!(processes.wait(own), Err(PlatformError::UnknownProcessGroup));
        assert_eq!(processes.try_wait(own), Err(PlatformError::UnknownProcessGroup));
    }

    #[test]
    fn reaped_group_is_forgotten() {
        let processes = SystemProcesses::new();
        let group = processes.spawn(&SpawnRequest::new("/usr/bin/true")).unwrap();
        assert_eq!(processes.wait(group), Ok(ExitStatus::Exited(0)));
        assert_eq!(
            processes.signal(group, Signal::Kill),
            Err(PlatformError::UnknownProcessGroup)
        );
        assert_eq!(processes.wait(group), Err(PlatformError::UnknownProcessGroup));
    }

    #[test]
    fn spawn_passes_arguments_and_explicit_environment() {
        let processes = SystemProcesses::new();
        let request = SpawnRequest::new("/bin/sh")
            .arg("-c")
            .arg(r#"test -z "$HOME" && test "$K" = v && exit 3"#)
            .env("K", "v");
        let group = processes.spawn(&request).unwrap();
        assert_eq!(processes.wait(group), Ok(ExitStatus::Exited(3)));
    }

    #[test]
    fn spawn_refuses_relative_program_and_reports_missing_one() {
        let processes = SystemProcesses::new();
        assert_eq!(
            processes.spawn(&SpawnRequest::new("sh")),
            Err(PlatformError::InvalidPath)
        );
        let error = processes.spawn(&SpawnRequest::new("/nonexistent/knsh")).unwrap_err();
        assert!(error.is_not_found(), "{error:?}");
    }
}
