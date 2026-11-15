//! Lines started with `exec.start` and their handles for `exec.wait` and `exec.kill` (KNSH-053,
//! `specs/06-api/agent-socket.md#execstart-execwait-execkill`).
//!
//! Every forwarded line carries a [`LineControl`]: the supervisor marks it started once the line is spawned, the
//! spawner's watch loop reads its kill flag, and its result is set when the line has been recorded. `exec.run`
//! simply waits for its own line; `exec.start` returns at the start mark and leaves the line in [`Jobs`], keyed by
//! its record ID, for `exec.wait` and `exec.kill`.
//!
//! # Bounds
//!
//! A session holds at most [`MAX_JOBS_PER_SESSION`] started lines whose result nobody has collected. A result is
//! collected by the first `exec.wait` that returns it. When the bound is reached, the oldest finished line is
//! forgotten to make room; if every one is still running, `exec.start` is refused with `-32602` before the line is
//! decided, so a refused start never leaves a line running that nobody can wait for or kill.
//!
//! The lines of a session that has ended can no longer be named by anyone (its connections are unbound), so they
//! are forgotten at the next `exec.start` ([`Jobs::forget_ended`]): a finished line's result holds up to 1 MB per
//! stream, and ended sessions must not pin that memory for the daemon's lifetime.
//!
//! # Lock order
//!
//! [`Jobs`]' map, then a [`LineControl`]'s state. A control's state is never held while taking the map.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use knsh_core::{Caller, RecordId, SessionId};
use knsh_proto::{ErrorCode, OutputOptions, RpcError};

use crate::exec::Finished;

/// Started lines one session may hold before their results are collected.
pub(crate) const MAX_JOBS_PER_SESSION: usize = 64;

/// How often a waiting call checks whether its caller is still connected.
const CALLER_POLL: Duration = Duration::from_millis(100);

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// What is known of one line so far.
#[derive(Debug, Default)]
struct ControlState {
    /// Its record, once it was spawned.
    started: Option<RecordId>,
    /// Its answer, once it was recorded (or refused).
    finished: Option<Result<Finished, RpcError>>,
}

/// One line's handle, shared by the call that forwarded it, the supervisor and the spawner.
#[derive(Debug, Default)]
pub(crate) struct LineControl {
    kill: AtomicBool,
    state: Mutex<ControlState>,
    changed: Condvar,
}

/// How a wait for the start ended.
#[derive(Debug)]
pub(crate) enum StartWait {
    /// The line was spawned and is written to this record.
    Started(RecordId),
    /// The line ended without having been spawned (denied, held, cancelled, or it could not start).
    Ended(Box<Result<Finished, RpcError>>),
    /// The caller went away first.
    CallerGone,
}

impl LineControl {
    /// A fresh handle.
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// The line was spawned: called by the supervisor with its record (FR-LC-17).
    pub(crate) fn mark_started(&self, record_id: RecordId) {
        lock(&self.state).started = Some(record_id);
        self.changed.notify_all();
    }

    /// The line's answer: called once, after its record was written.
    pub(crate) fn finish(&self, result: Result<Finished, RpcError>) {
        lock(&self.state).finished = Some(result);
        self.changed.notify_all();
    }

    /// Asks the spawner to stop the line's process group. Returns whether the line was still running.
    pub(crate) fn request_kill(&self) -> bool {
        let running = lock(&self.state).finished.is_none();
        if running {
            self.kill.store(true, Ordering::SeqCst);
        }
        running
    }

    /// Whether `exec.kill` asked for the line to stop: read by the spawner's watch loop.
    pub(crate) fn kill_requested(&self) -> bool {
        self.kill.load(Ordering::SeqCst)
    }

    /// Waits until the line is spawned or has ended, or `caller` goes away.
    pub(crate) fn wait_started(&self, caller: &dyn Caller) -> StartWait {
        let mut state = lock(&self.state);
        loop {
            if let Some(record_id) = state.started {
                return StartWait::Started(record_id);
            }
            if let Some(result) = &state.finished {
                return StartWait::Ended(Box::new(result.clone()));
            }
            if caller.gone() {
                return StartWait::CallerGone;
            }
            state = self.wait(state);
        }
    }

    /// Waits for the line's answer; `None` if `caller` goes away first.
    pub(crate) fn wait_finished(&self, caller: &dyn Caller) -> Option<Result<Finished, RpcError>> {
        let mut state = lock(&self.state);
        loop {
            if let Some(result) = &state.finished {
                return Some(result.clone());
            }
            if caller.gone() {
                return None;
            }
            state = self.wait(state);
        }
    }

    /// Whether the line's answer is known.
    fn is_finished(&self) -> bool {
        lock(&self.state).finished.is_some()
    }

    fn wait<'a>(&'a self, state: MutexGuard<'a, ControlState>) -> MutexGuard<'a, ControlState> {
        self.changed
            .wait_timeout(state, CALLER_POLL)
            .unwrap_or_else(PoisonError::into_inner)
            .0
    }
}

/// A caller that is "gone" once its flag is set: the stand-in for an `exec.start` caller while the line it started
/// is decided on another thread. The handler sets the flag if its own caller leaves before the line starts, so the
/// line is cancelled (FR-LC-41); once `exec.start` has answered, the flag is never set and the line runs to its end.
#[derive(Debug, Default)]
pub(crate) struct FlagCaller(AtomicBool);

impl FlagCaller {
    /// Marks the caller gone: the line, if still undecided, is cancelled.
    pub(crate) fn leave(&self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

impl Caller for FlagCaller {
    fn gone(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

/// One started line.
struct Job {
    session_id: SessionId,
    control: Arc<LineControl>,
    /// The output the caller asked for at `exec.start`, applied at `exec.wait`.
    output: OutputOptions,
}

/// A started line looked up for `exec.wait`.
pub(crate) struct Waiting {
    /// Its handle.
    pub(crate) control: Arc<LineControl>,
    /// The output asked for at `exec.start`.
    pub(crate) output: OutputOptions,
}

/// The started lines of every session, by record ID.
#[derive(Default)]
pub(crate) struct Jobs {
    jobs: Mutex<BTreeMap<RecordId, Job>>,
}

impl Jobs {
    /// An empty registry.
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Forgets every line of a session for which `live` is false (module documentation). `live` is called without
    /// the map's lock held, so it may take any other lock.
    pub(crate) fn forget_ended(&self, live: impl Fn(SessionId) -> bool) {
        let sessions: std::collections::BTreeSet<SessionId> =
            lock(&self.jobs).values().map(|job| job.session_id).collect();
        let ended: std::collections::BTreeSet<SessionId> = sessions.into_iter().filter(|id| !live(*id)).collect();
        if !ended.is_empty() {
            lock(&self.jobs).retain(|_, job| !ended.contains(&job.session_id));
        }
    }

    /// Whether `session_id` can keep one more started line: below the bound, or one of its lines has finished and
    /// can be forgotten. Checked before a line is started; [`Jobs::insert`] checks again.
    pub(crate) fn has_room(&self, session_id: SessionId) -> bool {
        let jobs = lock(&self.jobs);
        let held: Vec<&Job> = jobs.values().filter(|job| job.session_id == session_id).collect();
        held.len() < MAX_JOBS_PER_SESSION || held.iter().any(|job| job.control.is_finished())
    }

    /// Keeps the line `record_id` of `session_id` for `exec.wait` and `exec.kill`.
    ///
    /// # Errors
    ///
    /// `-32602` when the session already holds [`MAX_JOBS_PER_SESSION`] running lines (module documentation).
    pub(crate) fn insert(
        &self,
        session_id: SessionId,
        record_id: RecordId,
        control: Arc<LineControl>,
        output: OutputOptions,
    ) -> Result<(), RpcError> {
        let mut jobs = lock(&self.jobs);
        let held: Vec<RecordId> = jobs
            .iter()
            .filter(|(_, job)| job.session_id == session_id)
            .map(|(id, _)| *id)
            .collect();
        if held.len() >= MAX_JOBS_PER_SESSION {
            // Record IDs sort in creation order: the first finished one is the oldest.
            let oldest_finished = held
                .into_iter()
                .find(|id| jobs.get(id).is_some_and(|job| job.control.is_finished()));
            match oldest_finished {
                Some(id) => {
                    jobs.remove(&id);
                }
                None => return Err(RpcError::new(ErrorCode::InvalidParams)),
            }
        }
        jobs.insert(
            record_id,
            Job {
                session_id,
                control,
                output,
            },
        );
        Ok(())
    }

    /// The line `record_id`, if `session_id` started it. Another session's line is indistinguishable from an
    /// unknown one.
    pub(crate) fn get(&self, session_id: SessionId, record_id: RecordId) -> Option<Waiting> {
        lock(&self.jobs)
            .get(&record_id)
            .filter(|job| job.session_id == session_id)
            .map(|job| Waiting {
                control: Arc::clone(&job.control),
                output: job.output,
            })
    }

    /// Forgets the line `record_id` once its result was collected.
    pub(crate) fn remove(&self, record_id: RecordId) {
        lock(&self.jobs).remove(&record_id);
    }

    /// How many lines are held.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        lock(&self.jobs).len()
    }
}

#[cfg(test)]
mod tests {
    use knsh_core::Ulid;

    use super::*;

    fn session(n: u128) -> SessionId {
        SessionId::from_ulid(Ulid::from_u128(n))
    }

    fn record(n: u128) -> RecordId {
        RecordId::from_ulid(Ulid::from_u128(n))
    }

    // A full session is refused before its line starts, and gets room back once one of its lines has finished.
    #[test]
    fn has_room_only_below_the_bound_or_with_a_finished_line() {
        let jobs = Jobs::new();
        let controls: Vec<Arc<LineControl>> = (0..MAX_JOBS_PER_SESSION).map(|_| LineControl::new()).collect();
        for (n, control) in controls.iter().enumerate() {
            assert!(jobs.has_room(session(1)));
            jobs.insert(
                session(1),
                record(n as u128 + 1),
                Arc::clone(control),
                OutputOptions::default(),
            )
            .unwrap();
        }
        assert!(!jobs.has_room(session(1)), "every line still running");
        assert!(jobs.has_room(session(2)), "the bound is per session");
        let error = jobs
            .insert(session(1), record(1000), LineControl::new(), OutputOptions::default())
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::InvalidParams);
        controls[3].finish(Err(RpcError::new(ErrorCode::Cancelled)));
        assert!(jobs.has_room(session(1)));
        jobs.insert(session(1), record(1000), LineControl::new(), OutputOptions::default())
            .unwrap();
        assert!(
            jobs.get(session(1), record(4)).is_none(),
            "the finished line was forgotten"
        );
        assert_eq!(jobs.len(), MAX_JOBS_PER_SESSION);
    }

    // The lines of an ended session are forgotten, running or not; other sessions keep theirs.
    #[test]
    fn forgets_the_lines_of_ended_sessions() {
        let jobs = Jobs::new();
        for (n, owner) in [(1, 1), (2, 2), (3, 1)] {
            jobs.insert(session(owner), record(n), LineControl::new(), OutputOptions::default())
                .unwrap();
        }
        jobs.forget_ended(|id| id == session(2));
        assert_eq!(jobs.len(), 1);
        assert!(jobs.get(session(2), record(2)).is_some());
    }
}
