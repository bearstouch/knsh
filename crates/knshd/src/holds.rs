//! Pause, resume and human control: which agent sessions hold their lines, and the process groups a pause stops
//! (KNSH-054, `specs/03-functional-requirements/sessions.md#states`, FR-SES-10 – FR-SES-12).
//!
//! The session's state lives in the registry ([`crate::sessions::Sessions`]), which applies every transition and
//! publishes `session.state_changed` (FR-SES-14). This module keeps what the registry cannot: for each agent session,
//! a mirror of that state and the **kept handles** of its process groups, its envelope's and each running line's.
//! A handle is the group id together with the [`Processes`] instance that spawned it and still holds its unreaped
//! leader, so a signal can only ever reach that group, never a process that reused its id (CLAUDE.md
//! "Concurrency"). A line's handle is dropped ([`Kept`]) before its leader is reaped; from then on a pause no longer
//! names it.
//!
//! - **Pause** sends `SIGSTOP` to the envelope's group first, so the agent stops asking for new lines, then to every
//!   running line's group. **Resume** sends `SIGCONT` to the lines first, then to the envelope, so the agent wakes to
//!   find its lines running again.
//! - **Human control** stops nothing: lines already running go on; new ones are held by the supervisor.
//! - A group kept while the session is paused (a line that was decided just before the pause) is stopped as soon as
//!   it is kept. It may have run for the few microseconds between its spawn and that signal; the trampoline has not
//!   applied its sandbox yet at that point, so nothing of the line itself has run.
//! - A session that ends while paused gets `SIGCONT` on every group still kept, so nothing it started stays stopped
//!   forever after the session is gone.
//!
//! A process that left its group with `setsid` is out of reach of a group signal and keeps running while the session
//! is paused, still inside its sandbox (FR-SES-11): accepted behaviour, not a bug.
//!
//! Signals are best effort: a group whose members all exited answers `EPERM` or is already unknown, and nothing is
//! left to stop. A failed signal never undoes the transition, so new lines are held whatever the signals did.
//!
//! # Locks
//!
//! The map of sessions, then one session's [`Run`], then the [`Processes`] instance's own lock. The registry lock in
//! [`crate::sessions::Sessions`] comes before all of them. Signals are sent with the session's [`Run`] locked, so a
//! group is kept or dropped either wholly before a pause or wholly after it.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use knsh_core::{SessionId, SessionState};
use knsh_platform::{ProcessGroupId, Processes, Signal};

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// What a kept group belongs to: it decides the order of the signals.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GroupKind {
    /// The envelope's own group: the agent CLI and whatever it runs outside `knsh -c`.
    Envelope,
    /// One running line, started by the supervisor through `knsh-exec`.
    Line,
}

/// One kept group: its id, the instance that holds its leader, and what it is.
struct Handle {
    group: ProcessGroupId,
    processes: Arc<dyn Processes>,
    kind: GroupKind,
}

impl Handle {
    /// Best effort (module documentation): an error means nothing is left in the group to signal.
    fn signal(&self, signal: Signal) {
        let _ = self.processes.signal(self.group, signal);
    }
}

/// One agent session's mirror of its state and its kept groups.
struct RunState {
    state: SessionState,
    /// Kept groups by admission number: unique for the session's life, so dropping one handle can never remove
    /// another that happens to share its group id.
    groups: BTreeMap<u64, Handle>,
    next: u64,
}

impl RunState {
    /// Sends `signal` to every kept group of `kind`.
    fn signal_all(&self, kind: GroupKind, signal: Signal) {
        for handle in self.groups.values().filter(|handle| handle.kind == kind) {
            handle.signal(signal);
        }
    }

    /// The signals for a move from `self.state` to `to`, sent in the order the module documentation gives.
    fn signal_for(&self, to: SessionState) {
        use SessionState::{Active, Ended, HumanControl, Paused};
        match (self.state, to) {
            (Active, Paused) => {
                self.signal_all(GroupKind::Envelope, Signal::Stop);
                self.signal_all(GroupKind::Line, Signal::Stop);
            }
            // Ending while paused continues too: nothing the session started may stay stopped once it is gone.
            (Paused, Active | Ended) => {
                self.signal_all(GroupKind::Line, Signal::Continue);
                self.signal_all(GroupKind::Envelope, Signal::Continue);
            }
            // Human control stops nothing (FR-SES-12), and the other pairs are not moves between running and stopped.
            (Active | HumanControl | Ended, _) | (Paused, Paused | HumanControl) => {}
        }
    }
}

/// One agent session's runtime side. Shared by the registry of holds and every [`Kept`] handle of the session.
pub(crate) struct Run {
    inner: Mutex<RunState>,
}

impl Run {
    fn new(state: SessionState) -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(RunState {
                state,
                groups: BTreeMap::new(),
                next: 0,
            }),
        })
    }
}

/// A kept process group. Dropping it forgets the group: drop it **before** the group's leader is reaped, so no
/// signal can be sent to the id once it may be reused.
#[must_use = "dropping the handle at once forgets the group: a pause would no longer stop it"]
pub(crate) struct Kept {
    run: Arc<Run>,
    key: u64,
}

impl Kept {
    /// Whether the group's session is paused now. The spawner's watch loop reads it so that time spent paused does
    /// not count towards the line's `timeout_s`.
    pub(crate) fn paused(&self) -> bool {
        lock(&self.run.inner).state == SessionState::Paused
    }
}

impl Drop for Kept {
    fn drop(&mut self) {
        lock(&self.run.inner).groups.remove(&self.key);
    }
}

impl std::fmt::Debug for Kept {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Kept").field("key", &self.key).finish_non_exhaustive()
    }
}

/// Every live agent session's [`Run`], by session. One per `knshd`, owned by [`crate::sessions::Sessions`].
#[derive(Default)]
pub(crate) struct Holds {
    runs: Mutex<BTreeMap<SessionId, Arc<Run>>>,
}

impl Holds {
    /// No sessions.
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// The run of `session_id`, created in `state` if it has none yet. A session gets its run at its first
    /// transition or its first kept group, whichever comes first; `state` is then the registry's state for it.
    fn run(&self, session_id: SessionId, state: SessionState) -> Arc<Run> {
        Arc::clone(lock(&self.runs).entry(session_id).or_insert_with(|| Run::new(state)))
    }

    /// The session moved to `to` in the registry: mirrors it and sends the signals the move calls for (module
    /// documentation). `from` is the registry's state before the move, used if the session has no run yet. At
    /// `ended` the run is forgotten; handles still kept go on working but are never signalled again.
    pub(crate) fn moved(&self, session_id: SessionId, from: SessionState, to: SessionState) {
        let run = self.run(session_id, from);
        {
            let mut inner = lock(&run.inner);
            inner.signal_for(to);
            inner.state = to;
        }
        if to == SessionState::Ended {
            lock(&self.runs).remove(&session_id);
        }
    }

    /// Keeps `group` of `session_id`, whose registry state is `state`, until the returned handle is dropped. If the
    /// session is paused the group is stopped at once (module documentation).
    pub(crate) fn keep(
        &self,
        session_id: SessionId,
        state: SessionState,
        group: ProcessGroupId,
        processes: Arc<dyn Processes>,
        kind: GroupKind,
    ) -> Kept {
        let run = self.run(session_id, state);
        let key = {
            let mut inner = lock(&run.inner);
            let handle = Handle { group, processes, kind };
            if inner.state == SessionState::Paused {
                handle.signal(Signal::Stop);
            }
            let key = inner.next;
            inner.next += 1;
            inner.groups.insert(key, handle);
            key
        };
        Kept { run, key }
    }

    /// A handle for a group whose session is no longer live: kept by nobody, never signalled. The spawner still
    /// needs one to watch its line to the end.
    pub(crate) fn detached() -> Kept {
        Kept {
            run: Run::new(SessionState::Ended),
            key: 0,
        }
    }

    /// The number of groups kept for `session_id`.
    #[cfg(test)]
    pub(crate) fn kept(&self, session_id: SessionId) -> usize {
        lock(&self.runs)
            .get(&session_id)
            .map_or(0, |run| lock(&run.inner).groups.len())
    }
}

#[cfg(test)]
mod tests {
    use knsh_core::Ulid;
    use knsh_platform::testing::{Script, ScriptedProcesses};
    use knsh_platform::{Signal, SpawnRequest};

    use super::*;

    fn sid(n: u128) -> SessionId {
        SessionId::from_ulid(Ulid::from_u128(n))
    }

    /// `n` scripted groups that run until signalled.
    fn groups(processes: &ScriptedProcesses, n: usize) -> Vec<ProcessGroupId> {
        (0..n)
            .map(|_| {
                processes.expect("/bin/sleep", Script::RunsUntilSignalled);
                processes.spawn(&SpawnRequest::new("/bin/sleep")).unwrap()
            })
            .collect()
    }

    // FR-SES-10: the envelope is stopped before the lines and continued after them.
    #[test]
    fn pause_signals_envelope_first_and_resume_last() {
        let processes = Arc::new(ScriptedProcesses::new());
        let ids = groups(&processes, 2);
        let holds = Holds::new();
        let shared: Arc<dyn Processes> = processes.clone();
        let _line = holds.keep(
            sid(1),
            SessionState::Active,
            ids[0],
            Arc::clone(&shared),
            GroupKind::Line,
        );
        let _envelope = holds.keep(sid(1), SessionState::Active, ids[1], shared, GroupKind::Envelope);

        holds.moved(sid(1), SessionState::Active, SessionState::Paused);
        holds.moved(sid(1), SessionState::Paused, SessionState::Active);
        assert_eq!(
            processes.signals(),
            [
                (ids[1], Signal::Stop),
                (ids[0], Signal::Stop),
                (ids[0], Signal::Continue),
                (ids[1], Signal::Continue),
            ]
        );
    }

    // A dropped handle is never signalled again, and another session's groups are never touched.
    #[test]
    fn dropped_and_foreign_groups_are_not_signalled() {
        let processes = Arc::new(ScriptedProcesses::new());
        let ids = groups(&processes, 2);
        let holds = Holds::new();
        let shared: Arc<dyn Processes> = processes.clone();
        let gone = holds.keep(
            sid(1),
            SessionState::Active,
            ids[0],
            Arc::clone(&shared),
            GroupKind::Line,
        );
        let _other = holds.keep(sid(2), SessionState::Active, ids[1], shared, GroupKind::Line);
        drop(gone);
        assert_eq!(holds.kept(sid(1)), 0);

        holds.moved(sid(1), SessionState::Active, SessionState::Paused);
        assert_eq!(processes.signals(), []);
    }

    // A group kept while its session is paused is stopped at once; ending a paused session continues it.
    #[test]
    fn keeps_paused_groups_stopped_and_continues_them_at_the_end() {
        let processes = Arc::new(ScriptedProcesses::new());
        let ids = groups(&processes, 1);
        let holds = Holds::new();
        holds.moved(sid(1), SessionState::Active, SessionState::Paused);
        let kept = holds.keep(sid(1), SessionState::Paused, ids[0], processes.clone(), GroupKind::Line);
        assert!(kept.paused());
        assert_eq!(processes.signals(), [(ids[0], Signal::Stop)]);

        holds.moved(sid(1), SessionState::Paused, SessionState::Ended);
        assert_eq!(
            processes.signals(),
            [(ids[0], Signal::Stop), (ids[0], Signal::Continue)]
        );
        assert!(!kept.paused());
        // The run is forgotten: a later pause of a reused session id would start from nothing.
        assert_eq!(holds.kept(sid(1)), 0);
    }

    // FR-SES-12: taking control stops nothing.
    #[test]
    fn human_control_sends_no_signal() {
        let processes = Arc::new(ScriptedProcesses::new());
        let ids = groups(&processes, 1);
        let holds = Holds::new();
        let _kept = holds.keep(sid(1), SessionState::Active, ids[0], processes.clone(), GroupKind::Line);
        holds.moved(sid(1), SessionState::Active, SessionState::HumanControl);
        holds.moved(sid(1), SessionState::HumanControl, SessionState::Active);
        holds.moved(sid(1), SessionState::Active, SessionState::HumanControl);
        holds.moved(sid(1), SessionState::HumanControl, SessionState::Ended);
        assert_eq!(processes.signals(), []);
    }

    /// The `ps` state letters of process `pid`, for example `S` (sleeping) or `T` (stopped).
    #[cfg(target_os = "macos")]
    fn ps_state(pid: i32) -> String {
        let out = std::process::Command::new("/bin/ps")
            .args(["-o", "stat=", "-p", &pid.to_string()])
            .output()
            .unwrap();
        String::from_utf8(out.stdout).unwrap().trim().to_owned()
    }

    // FR-SES-10 on the real system: a pause stops a real process group (state `T`), a resume continues it, and the
    // group is still held (and killed) afterwards.
    #[cfg(target_os = "macos")]
    #[test]
    fn real_group_is_stopped_and_continued() {
        use knsh_platform::macos::SystemProcesses;

        let processes: Arc<dyn Processes> = Arc::new(SystemProcesses::new());
        let group = processes.spawn(&SpawnRequest::new("/bin/sleep").arg("30")).unwrap();
        let holds = Holds::new();
        let kept = holds.keep(
            sid(9),
            SessionState::Active,
            group,
            Arc::clone(&processes),
            GroupKind::Line,
        );
        let wait_for = |stopped: bool| {
            for _ in 0..200 {
                if ps_state(group.as_raw()).starts_with('T') == stopped {
                    return true;
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            false
        };

        holds.moved(sid(9), SessionState::Active, SessionState::Paused);
        assert!(wait_for(true), "stopped: {}", ps_state(group.as_raw()));
        holds.moved(sid(9), SessionState::Paused, SessionState::Active);
        assert!(wait_for(false), "continued: {}", ps_state(group.as_raw()));

        processes.signal(group, Signal::Kill).unwrap();
        drop(kept);
        assert_eq!(processes.wait(group).unwrap(), knsh_platform::ExitStatus::Signalled(9));
    }
}
