//! The checkpoint history of the daemon and the `checkpoint.*` methods (KNSH-088, FR-CKP-21; `specs/06-api/
//! agent-socket.md`, `user-socket.md`, `control-service.md`, `specs/03-functional-requirements/checkpoints.md`).
//!
//! One [`HistoryService`] per `knshd` keeps the [`History`] (KNSH-084) behind one lock:
//!
//! - **Fed** with every finished checkpoint, through [`CheckpointSink`] (the shadows' capture, KNSH-082), before
//!   `checkpoint.created` is published. The sink never waits for the lock: a restore holds it while it flushes the
//!   watchers whose reports end in the sink, so finished checkpoints queue and are recorded by whoever holds or
//!   next takes the lock, in the order they finished. Every holder records the queue right after taking the lock and
//!   again before releasing it, then retries once the lock is free, so nothing waits in the queue past a call.
//! - **Marked.** A line that ran and is irreversible has its reasons noted on its checkpoint ([`IrreversibleMarks`],
//!   KNSH-093), so its undo restores its files and lists what it cannot take back (FR-IRR-06, FR-CKP-36). Marks join
//!   the same queue as finished checkpoints, never waiting for the lock, and are applied in order behind the
//!   checkpoint they name: a restore that takes the lock after the line's `command.finished` sees them.
//! - **Served** on each endpoint with the caller the endpoint implies: on `agent.sock` the agent session the
//!   connection was bound to (`Caller::Agent`), which sees and acts on its own session's changes only; on `user.sock`
//!   the user; on the control service the authority. `force` from `agent.sock` is refused before anything else is
//!   looked at (`-32003`, FR-CKP-21), and so is `checkpoint.restore` (the catalogue keeps it off `agent.sock` too).
//! - **Bracketed.** An undo, redo or restore writes files in roots that live sessions may watch, and those writes are
//!   nobody's change: each runs inside a [`RestoreWindows`] window over exactly the roots it may write in. Changes
//!   reported when the window opens are recorded before the history plans the operation, so it sees them.
//! - **Swept.** A retention thread runs [`History::retain`] at start, whenever its `next_due` comes (so sensitive
//!   pre-images never outlive 24 hours, FR-CKP-33), and soon after new checkpoints are recorded (the count and size
//!   limits, FR-CKP-32). `records.forget` with `with_checkpoints` calls [`History::forget`] (FR-CKP-34).
//!
//! # Errors on the wire
//!
//! A restore conflict is `-32004` with every conflicting path ([`undo_conflict`]); an older change overlapped by later
//! ones is `-32004` with the shared paths (FR-CKP-30, [`history_error`]); a change or state the history does not know
//! or can no longer act on is `-32602` with `data.reason`; a change of another session, or an external edit, asked
//! for by an agent is `-32003`; anything else is `-32603`, logged without paths (NFR-PRIV-02).
//!
//! # Locks
//!
//! The history lock, then (inside a window or a recorded checkpoint) the shadows' ledger lock. The pending queue is a
//! leaf. Nothing here is called with the ledger lock held.
//!
//! **Pending:** the history lives in memory, so a restarted `knshd` starts with an empty one (the checkpoints'
//! stored form does not exist yet); restore journals are recovered at start in the home store only.

use std::sync::{Arc, Condvar, Mutex, MutexGuard, OnceLock, PoisonError, TryLockError};
use std::thread;
use std::time::Duration;

use knsh_checkpoint::{
    Caller, Checkpoint, CheckpointError, DiffRequest, Forget, History, Request, RestoreEvents, Restored, Retention,
    StateRequest, StateRestored, Swept, Target,
};
use knsh_core::{
    CanonicalPath, CheckpointId, EdgeKind, EventData, HistoryEdge, RestoreOperation, SessionId, Timestamp,
};
use knsh_json::ToJson;
use knsh_platform::{Clock, Field, Level, PlatformError, SystemLog, Value};
use knsh_proto::{
    ByteTransport, ChangeTarget, CheckpointDiffParams, CheckpointListParams, CheckpointListResult,
    CheckpointRestoreParams, CheckpointRestoreResult, CheckpointUndoParams, CheckpointUndoResult, ErrorCode,
    ListedChange, ListedKind, ListedStatus, MAX_LISTED_CONFLICTS, RestoredChange, RpcError, diff_answer, history_error,
    undo_conflict,
};

use crate::dispatch::{Answer, Call, Endpoint, Handler, Handlers, Reply, answer, params};
use crate::events::EventHub;
use crate::shadows::{CheckpointSink, RestoreWindows};
use crate::supervisor::IrreversibleMarks;

/// The longest the retention thread sleeps when nothing is due: a backstop, so a sweep that was never requested
/// (a clock step, a missed wake-up) still happens.
const MAX_SWEEP_INTERVAL: Duration = Duration::from_hours(1);

/// How long the retention thread waits before trying again after a sweep failed (the clock could not be read).
const RETRY_AFTER_FAILURE: Duration = Duration::from_secs(60);

/// The most bytes the changes of one `checkpoint.list` answer may take as JSON: one frame, less room for the
/// response envelope and the other fields.
const LIST_RESULT_BUDGET: usize = knsh_json::MAX_PAYLOAD - 4096;

impl RestoreEvents for EventHub {
    fn restored(&self, session_id: SessionId, data: EventData) {
        // Best effort, like every event (FR-EVT-04): a session that ended meanwhile simply gets none.
        let _ = self.publish_for_session(session_id, data);
    }
}

/// What the retention thread is asked.
#[derive(Debug, Default)]
struct SweepState {
    /// Sweep again as soon as possible (new checkpoints were recorded).
    requested: bool,
    /// Stop (tests; the daemon's thread lives as long as the process).
    stopped: bool,
}

/// One item waiting for the history lock (module documentation, "Fed" and "Marked").
#[derive(Debug)]
enum Queued {
    /// A finished checkpoint, to record as a change.
    Checkpoint(Checkpoint),
    /// What the change held by this checkpoint did that cannot be undone (KNSH-093).
    Marks(CheckpointId, Vec<String>),
}

/// The daemon's checkpoint history (module documentation).
pub(crate) struct HistoryService {
    history: Mutex<History>,
    /// Finished checkpoints and irreversible marks not recorded yet, oldest first.
    pending: Mutex<Vec<Queued>>,
    events: Arc<dyn RestoreEvents + Send + Sync>,
    /// The shadows, once they exist: what brackets each restore. Without them no root is watched, so a restore needs
    /// no window.
    windows: OnceLock<Arc<dyn RestoreWindows>>,
    clock: Arc<dyn Clock>,
    log: Arc<dyn SystemLog>,
    retention: Retention,
    sweep: Mutex<SweepState>,
    wake: Condvar,
}

impl HistoryService {
    /// A service over `history` (normally empty), publishing `checkpoint.restored` to `events` and sweeping with
    /// `retention`.
    pub(crate) fn new(
        history: History,
        events: Arc<dyn RestoreEvents + Send + Sync>,
        clock: Arc<dyn Clock>,
        log: Arc<dyn SystemLog>,
        retention: Retention,
    ) -> Arc<Self> {
        Arc::new(Self {
            history: Mutex::new(history),
            pending: Mutex::new(Vec::new()),
            events,
            windows: OnceLock::new(),
            clock,
            log,
            retention,
            sweep: Mutex::new(SweepState::default()),
            wake: Condvar::new(),
        })
    }

    /// Brackets every later restore with `windows` (the shadows, created after this service).
    pub(crate) fn attach_windows(&self, windows: Arc<dyn RestoreWindows>) {
        // Set once at start; a second call would be a wiring mistake and is ignored.
        let _ = self.windows.set(windows);
    }

    /// Runs `operation` on the history, with every finished checkpoint recorded first and every one finished
    /// meanwhile recorded before the lock is released (module documentation).
    fn with_history<R>(&self, operation: impl FnOnce(&mut History) -> R) -> R {
        let result = {
            let mut history = self.history.lock().unwrap_or_else(PoisonError::into_inner);
            self.record_pending(&mut history);
            let result = operation(&mut history);
            self.record_pending(&mut history);
            result
        };
        self.record_if_free();
        result
    }

    /// Records every queued checkpoint and mark, oldest first. A checkpoint the history refuses (already there: a
    /// bug) is logged and dropped.
    fn record_pending(&self, history: &mut History) {
        let queued = std::mem::take(&mut *lock(&self.pending));
        if queued.is_empty() {
            return;
        }
        for item in queued {
            match item {
                Queued::Checkpoint(checkpoint) => {
                    if history.record(checkpoint).is_err() {
                        self.log
                            .log(Level::Error, "checkpoint not recorded in the history", &[]);
                    }
                }
                Queued::Marks(checkpoint, reasons) => history.mark_irreversible(checkpoint, reasons),
            }
        }
        self.request_sweep();
    }

    /// Records the queue if the history lock is free now; otherwise its holder will.
    fn record_if_free(&self) {
        while !lock(&self.pending).is_empty() {
            let mut history = match self.history.try_lock() {
                Ok(history) => history,
                Err(TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
                // The holder records the queue before it releases the lock, then retries here itself.
                Err(TryLockError::WouldBlock) => return,
            };
            self.record_pending(&mut history);
        }
    }

    /// Runs `operation` inside restore windows over the roots `roots_of` names, after recording what each window's
    /// opening reported. What is recorded may change those roots (a restore's way runs from a head that just moved),
    /// so they are asked again and any new one gets its own window, until none is missing: the operation never
    /// writes in a root outside a window.
    fn windowed<R>(
        &self,
        history: &mut History,
        roots_of: impl Fn(&History) -> Vec<CanonicalPath>,
        operation: impl FnOnce(&mut History) -> R,
    ) -> R {
        let mut open: Vec<Window<'_>> = Vec::new();
        let mut covered: Vec<CanonicalPath> = Vec::new();
        loop {
            // What was written before the restore closed an edge when a window opened: record it before planning.
            self.record_pending(history);
            let Some(windows) = self.windows.get() else {
                break;
            };
            let more: Vec<CanonicalPath> = roots_of(history)
                .into_iter()
                .filter(|root| !covered.contains(root))
                .collect();
            if more.is_empty() {
                break;
            }
            windows.begin(&more);
            covered.extend(more.iter().cloned());
            open.push(Window { windows, roots: more });
        }
        let result = operation(history);
        drop(open);
        result
    }

    /// The `checkpoint.*` handlers, by method name.
    pub(crate) fn handlers(self: &Arc<Self>) -> Handlers {
        let mut handlers = Handlers::new();
        let service = Arc::clone(self);
        let list: Handler = Arc::new(move |call: &Call<'_>| service.list(call));
        handlers.insert("checkpoint.list", list);
        let service = Arc::clone(self);
        let diff: Handler = Arc::new(move |call: &Call<'_>| service.diff(call));
        handlers.insert("checkpoint.diff", diff);
        let service = Arc::clone(self);
        let undo: Handler = Arc::new(move |call: &Call<'_>| service.step(call, RestoreOperation::Undo));
        handlers.insert("checkpoint.undo", undo);
        let service = Arc::clone(self);
        let redo: Handler = Arc::new(move |call: &Call<'_>| service.step(call, RestoreOperation::Redo));
        handlers.insert("checkpoint.redo", redo);
        let service = Arc::clone(self);
        let restore: Handler = Arc::new(move |call: &Call<'_>| service.restore(call));
        handlers.insert("checkpoint.restore", restore);
        handlers
    }

    /// `checkpoint.undo` or `checkpoint.redo`.
    fn step(&self, call: &Call<'_>, operation: RestoreOperation) -> Reply {
        let caller = caller_of(call)?;
        let params: CheckpointUndoParams = params(call)?;
        // FR-CKP-21: `force` never exists on agent.sock. Refused before the change is even looked up.
        if params.force && !caller.may_force() {
            return Err(RpcError::new(ErrorCode::NotAllowed));
        }
        let target = match params.target {
            ChangeTarget::Record(record) => Target::Record(record),
            ChangeTarget::Checkpoint(checkpoint) => Target::Checkpoint(checkpoint),
        };
        let request = Request {
            target,
            caller,
            force: params.force,
        };
        let events = Arc::clone(&self.events);
        let restored = self
            .with_history(|history| {
                let roots = |history: &History| history.target_roots(target);
                self.windowed(history, roots, |history| match operation {
                    RestoreOperation::Undo => history.undo(&request, events.as_ref()),
                    RestoreOperation::Redo => history.redo(&request, events.as_ref()),
                })
            })
            .map_err(|error| self.error(&error))?;
        answer(&undo_result(restored))
    }

    /// `checkpoint.restore`: the user and the authority only.
    fn restore(&self, call: &Call<'_>) -> Reply {
        let caller = caller_of(call)?;
        // The catalogue keeps it off agent.sock; checked again so a routing mistake never lets an agent restore.
        if !caller.may_force() {
            return Err(RpcError::new(ErrorCode::NotAllowed));
        }
        let params: CheckpointRestoreParams = params(call)?;
        let request = StateRequest {
            state: params.state_id,
            caller,
            force: params.force,
        };
        let events = Arc::clone(&self.events);
        let restored = self
            .with_history(|history| {
                let roots = |history: &History| history.state_roots(params.state_id);
                self.windowed(history, roots, |history| {
                    history.restore_state(&request, events.as_ref())
                })
            })
            .map_err(|error| self.error(&error))?;
        answer(&restore_result(&restored))
    }

    /// `checkpoint.diff`. On the control service, whose messages carry at most one data value, an answer in binary
    /// values lists one path at a time.
    fn diff(&self, call: &Call<'_>) -> Reply {
        let caller = caller_of(call)?;
        let params: CheckpointDiffParams = params(call)?;
        let limit = match (call.endpoint, call.bytes) {
            (Endpoint::Control, ByteTransport::BinaryFrames) => 1,
            (Endpoint::Control | Endpoint::User | Endpoint::Agent, _) => params.limit,
        };
        let request = DiffRequest {
            target: params.target,
            caller,
            after: params.cursor,
            limit: usize::try_from(limit).unwrap_or(usize::MAX),
        };
        let page = self
            .with_history(|history| history.diff(&request))
            .map_err(|error| self.error(&error))?;
        let built =
            diff_answer(&page.diff, page.more, call.bytes).map_err(|_| RpcError::new(ErrorCode::InternalError))?;
        Ok(Answer {
            result: built.result,
            bytes: None,
            streams: built
                .streams
                .into_iter()
                .map(|(stream, bytes)| (stream, bytes.to_vec()))
                .collect(),
        })
    }

    /// `checkpoint.list`.
    fn list(&self, call: &Call<'_>) -> Reply {
        let caller = caller_of(call)?;
        let params: CheckpointListParams = params(call)?;
        // On agent.sock a session filter may only name the caller's own session.
        if let (Caller::Agent(own), Some(asked)) = (caller, params.session_id)
            && asked != own
        {
            return Err(RpcError::new(ErrorCode::NotAllowed));
        }
        let result = self.with_history(|history| list_page(history, caller, &params));
        answer(&result)
    }

    /// Removes the changes `which` selects at once (FR-CKP-34): `records.forget` with `with_checkpoints`.
    pub(crate) fn forget(&self, which: &Forget) -> Swept {
        let swept = self.with_history(|history| history.forget(which));
        self.log.log(
            Level::Notice,
            "checkpoints forgotten",
            &[Field::new("removed", Value::U64(swept.removed.len() as u64))],
        );
        swept
    }

    /// One retention sweep (FR-CKP-32, FR-CKP-33): returns how long until the next is due, at most
    /// [`MAX_SWEEP_INTERVAL`].
    pub(crate) fn sweep_once(&self) -> Duration {
        let swept = self.with_history(|history| history.retain(&self.retention));
        let Ok(swept) = swept else {
            // A clock that cannot be read removes nothing; try again soon.
            self.log.log(Level::Error, "checkpoint retention sweep failed", &[]);
            return RETRY_AFTER_FAILURE;
        };
        if !swept.removed.is_empty() || swept.sensitive > 0 {
            self.log.log(
                Level::Notice,
                "checkpoint retention swept",
                &[
                    Field::new("removed", Value::U64(swept.removed.len() as u64)),
                    Field::new("sensitive", Value::U64(swept.sensitive as u64)),
                ],
            );
        }
        swept
            .next_due
            .map_or(MAX_SWEEP_INTERVAL, |due| self.until(due).min(MAX_SWEEP_INTERVAL))
    }

    /// How long from now until `due`; zero when it has passed or the clock cannot be read.
    fn until(&self, due: Timestamp) -> Duration {
        self.clock.now().map_or(Duration::ZERO, |now| {
            Duration::from_micros(due.as_unix_micros().saturating_sub(now.as_unix_micros()))
        })
    }

    /// Asks the retention thread to sweep again soon.
    fn request_sweep(&self) {
        lock(&self.sweep).requested = true;
        self.wake.notify_all();
    }

    /// Starts the retention thread: a sweep now, then whenever one is due or requested.
    ///
    /// # Errors
    ///
    /// The thread could not be started; no sweep then runs (logged by the caller).
    pub(crate) fn start_retention(self: &Arc<Self>) -> std::io::Result<()> {
        let service = Arc::clone(self);
        thread::Builder::new()
            .name("knshd-retention".to_owned())
            .spawn(move || service.retention_loop())
            .map(drop)
    }

    fn retention_loop(&self) {
        loop {
            let wait = self.sweep_once();
            let mut state = lock(&self.sweep);
            if !state.requested && !state.stopped {
                state = self
                    .wake
                    .wait_timeout_while(state, wait, |state| !state.requested && !state.stopped)
                    .unwrap_or_else(PoisonError::into_inner)
                    .0;
            }
            if state.stopped {
                return;
            }
            state.requested = false;
        }
    }

    /// Stops the retention thread at its next wake-up.
    #[cfg(test)]
    pub(crate) fn stop_retention(&self) {
        lock(&self.sweep).stopped = true;
        self.wake.notify_all();
    }

    /// The API error for `error`; the engine's own failures are logged, without paths.
    fn error(&self, error: &CheckpointError) -> RpcError {
        let kind = match error {
            CheckpointError::Conflicts(conflicts) => {
                let listed = &conflicts[..conflicts.len().min(MAX_LISTED_CONFLICTS)];
                return undo_conflict(listed);
            }
            CheckpointError::History(error) => return history_error(error),
            CheckpointError::ForceNotAllowed | CheckpointError::NotOwnChange | CheckpointError::RestoreNotAllowed => {
                return RpcError::new(ErrorCode::NotAllowed);
            }
            CheckpointError::RestoreStopped(_) => "restore_stopped",
            CheckpointError::RolledBack(_) => "rolled_back",
            CheckpointError::RollbackFailed(_) => "rollback_failed",
            CheckpointError::Platform(_) => "platform",
            CheckpointError::IdentityUnstable => "identity_unstable",
            CheckpointError::Threads => "threads",
            CheckpointError::NoStore => "no_store",
            CheckpointError::Journal => "journal",
        };
        let errno = match error {
            CheckpointError::Platform(PlatformError::Os { errno, .. })
            | CheckpointError::RolledBack(PlatformError::Os { errno, .. })
            | CheckpointError::RollbackFailed(PlatformError::Os { errno, .. }) => *errno,
            _ => 0,
        };
        self.log.log(
            Level::Error,
            "checkpoint operation failed",
            &[
                Field::new("reason", Value::Static(kind)),
                Field::new("errno", Value::Errno(errno)),
            ],
        );
        RpcError::new(ErrorCode::InternalError)
    }
}

impl CheckpointSink for HistoryService {
    fn finished(&self, finished: &[Checkpoint]) {
        lock(&self.pending).extend(finished.iter().cloned().map(Queued::Checkpoint));
        self.record_if_free();
    }
}

impl IrreversibleMarks for HistoryService {
    fn mark(&self, checkpoint: CheckpointId, reasons: &[String]) {
        lock(&self.pending).push(Queued::Marks(checkpoint, reasons.to_vec()));
        self.record_if_free();
    }
}

impl crate::records::ForgetCheckpoints for HistoryService {
    fn forget_checkpoints(&self, session: Option<SessionId>, since: Option<Timestamp>) {
        // `records.forget` always has a selector; without one nothing is removed rather than everything.
        if let Some(which) = Forget::new(session, since) {
            self.forget(&which);
        }
    }
}

/// An open restore window, closed when dropped (also when the restore panics).
struct Window<'a> {
    windows: &'a Arc<dyn RestoreWindows>,
    roots: Vec<CanonicalPath>,
}

impl Drop for Window<'_> {
    fn drop(&mut self) {
        self.windows.end(&self.roots);
    }
}

/// The caller the endpoint implies: the bound agent session on `agent.sock`, the user on `user.sock`, the authority
/// on the control service.
fn caller_of(call: &Call<'_>) -> Result<Caller, RpcError> {
    match call.endpoint {
        Endpoint::User => Ok(Caller::User),
        Endpoint::Control => Ok(Caller::Authority),
        Endpoint::Agent => call.binding.agent_session().map(Caller::Agent),
    }
}

/// The wire result of an undo or redo.
fn undo_result(restored: Restored) -> CheckpointUndoResult {
    CheckpointUndoResult {
        operation: restored.operation,
        checkpoint_id: restored.checkpoint,
        record_ids: restored.records,
        roots: restored.roots,
        state_id: restored.head,
        restored: restored.restored,
        not_restored: restored.not_restored,
        not_restored_incomplete: restored.not_restored_incomplete,
        irreversible: restored.irreversible,
        forced: restored.forced,
        skipped_torn: restored.skipped_torn,
        forced_torn: restored.forced_torn,
    }
}

/// The wire result of a restore to a state.
fn restore_result(restored: &StateRestored) -> CheckpointRestoreResult {
    CheckpointRestoreResult {
        from: restored.from,
        state_id: restored.head,
        changes: restored
            .steps
            .iter()
            .map(|step| RestoredChange {
                checkpoint_id: step.checkpoint,
                operation: step.operation,
                record_ids: step.records.clone(),
                files_restored: step.restored.len() as u64,
            })
            .collect(),
        restored: restored.restored(),
        not_restored: restored.not_restored(),
        not_restored_incomplete: restored.not_restored_incomplete(),
        irreversible: restored.irreversible(),
        forced: restored.forced(),
        skipped_torn: restored.skipped_torn(),
        forced_torn: restored.forced_torn(),
    }
}

/// One page of `checkpoint.list` for `caller`: the changes it may see, oldest first, after the cursor, filtered by
/// session, at most `limit` and at most [`LIST_RESULT_BUDGET`] bytes of JSON.
fn list_page(history: &History, caller: Caller, params: &CheckpointListParams) -> CheckpointListResult {
    let tree = history.tree();
    let mut edges: Vec<&HistoryEdge> = tree
        .edges()
        .filter(|edge| params.cursor.is_none_or(|cursor| edge.checkpoint > cursor))
        .filter(|edge| history.visible_to(caller, edge.checkpoint))
        .collect();
    edges.sort_by_key(|edge| edge.checkpoint);
    let limit = usize::try_from(params.limit).unwrap_or(usize::MAX);
    let mut changes = Vec::new();
    let mut used = 0usize;
    let mut next_cursor = None;
    for edge in edges {
        let sessions = edge_sessions(history, edge);
        if params.session_id.is_some_and(|session| !sessions.contains(&session)) {
            continue;
        }
        let listed = listed_change(history, caller, edge, sessions);
        let size = listed
            .to_json()
            .ok()
            .and_then(|value| knsh_json::write(&value).ok())
            .map_or(usize::MAX, |text| text.len().saturating_add(1));
        if changes.len() >= limit || (used.saturating_add(size) > LIST_RESULT_BUDGET && !changes.is_empty()) {
            next_cursor = changes.last().map(|change: &ListedChange| change.checkpoint_id);
            break;
        }
        used = used.saturating_add(size);
        changes.push(listed);
    }
    CheckpointListResult {
        head: tree.head(),
        changes,
        next_cursor,
    }
}

/// The sessions an edge belongs to: a change's own, or those of the change a revert reverted (empty once that is
/// gone).
fn edge_sessions(history: &History, edge: &HistoryEdge) -> Vec<SessionId> {
    let tree = history.tree();
    match &edge.kind {
        EdgeKind::Change { sessions, .. } => sessions.iter().copied().collect(),
        EdgeKind::Undo { of } => match tree.edge(*of).map(|reverted| &reverted.kind) {
            Some(EdgeKind::Change { sessions, .. }) => sessions.iter().copied().collect(),
            Some(EdgeKind::Undo { .. }) | None => Vec::new(),
        },
    }
}

/// One edge as `checkpoint.list` shows it to `caller`; an agent sees only its own session among its sessions.
fn listed_change(history: &History, caller: Caller, edge: &HistoryEdge, sessions: Vec<SessionId>) -> ListedChange {
    let tree = history.tree();
    let checkpoint = history.checkpoint(edge.checkpoint);
    let (kind, record_ids) = match &edge.kind {
        EdgeKind::Change {
            attribution, records, ..
        } => (ListedKind::Change(*attribution), records.iter().copied().collect()),
        EdgeKind::Undo { of } => (ListedKind::Revert(*of), Vec::new()),
    };
    let session_ids = match caller {
        Caller::Agent(own) => sessions.into_iter().filter(|session| *session == own).collect(),
        Caller::User | Caller::Authority => sessions,
    };
    let status = if edge.expired {
        ListedStatus::Expired
    } else if tree.is_in_effect(edge.checkpoint) {
        ListedStatus::InEffect
    } else if edge.saved.is_some() {
        ListedStatus::Undone
    } else {
        ListedStatus::Inactive
    };
    let roots: Vec<CanonicalPath> = checkpoint
        .map(|checkpoint| {
            let roots: std::collections::BTreeSet<&CanonicalPath> =
                checkpoint.paths.keys().chain(checkpoint.excluded.keys()).collect();
            roots.into_iter().cloned().collect()
        })
        .unwrap_or_default();
    ListedChange {
        checkpoint_id: edge.checkpoint,
        kind,
        record_ids,
        session_ids,
        roots,
        files_changed: checkpoint.map_or(edge.paths.len(), Checkpoint::path_count) as u64,
        uncertain: checkpoint.is_none_or(Checkpoint::is_uncertain) || edge.overflowed,
        from: edge.from,
        to: edge.to,
        status,
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

#[cfg(test)]
pub(crate) mod tests;
