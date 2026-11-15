//! The store thread: the single owner of the database connection (KNSH-016).
//!
//! [`RecordStore::open`] opens and migrates the database on the caller's thread, so a refused file is reported
//! before anything starts, then moves it to one dedicated thread. Every operation is a message to that thread and a
//! blocking wait for its answer: writes are serialised by construction (one writer), and a write is answered only
//! after its transaction committed (FR-REC-02, NFR-REL-05).
//!
//! Reads run on the same thread. Phase 1 has few readers, and one connection means one consistent view and no lock
//! order to document.
//!
//! The thread ends when the last [`RecordStore`] handle is dropped. It is never joined: every write that was
//! answered is already committed, so nothing can be lost by exiting while it is idle.
//!
//! # Retention (KNSH-017)
//!
//! Retention runs on this thread too, so deletes never race writes and the store keeps a single writer. A pass starts
//! when the store opens and then every [`StoreConfig::retention_interval`]. It reads the injected clock once, then
//! deletes in batches of at most [`RETENTION_BATCH`] records, each its own transaction: first records older than
//! their retention period, then the oldest records while the store is over its size limit. Between two batches the
//! thread serves every job already queued, so a large clean-up delays a record write by at most one batch.
//!
//! A pass that fails (SQLite error, unreadable clock) stops and deletes nothing more; the next pass retries. It is
//! never fatal: records are kept rather than lost.

use std::path::Path;
use std::sync::Arc;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender, SyncSender, TryRecvError};
use std::thread;
use std::time::Duration;

use knsh_core::{ExecutionRecord, RecordId, SandboxViolation, Session, SessionId, Timestamp};
use knsh_platform::{Clock, Fs, Monotonic};

use crate::db::{Database, RecordedOutput};
use crate::error::StoreError;
use crate::output::DEFAULT_OUTPUT_CAP;
use crate::query::{ForgetSelector, OutputRange, OutputRequest, Page, RecordQuery, Scope};
use crate::retention::{Cutoffs, RETENTION_BATCH, RETENTION_INTERVAL, Retention, RetentionReport};

/// Settings of a record store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreConfig {
    /// The most bytes stored per output stream; beyond it head and tail are kept (FR-REC-06).
    pub output_cap: usize,
    /// When records are deleted automatically (FR-REC-07).
    pub retention: Retention,
    /// How long between two automatic retention passes. A pass also runs when the store opens.
    pub retention_interval: Duration,
}

impl Default for StoreConfig {
    fn default() -> Self {
        Self {
            output_cap: DEFAULT_OUTPUT_CAP,
            retention: Retention::default(),
            retention_interval: RETENTION_INTERVAL,
        }
    }
}

/// One request to the store thread, with the channel its answer goes back on.
enum Job {
    WriteSession(Box<Session>, Timestamp, SyncSender<Result<(), StoreError>>),
    WriteRecord(
        Box<(ExecutionRecord, RecordedOutput)>,
        SyncSender<Result<(), StoreError>>,
    ),
    AppendViolations(
        Box<(SessionId, RecordId, Vec<SandboxViolation>)>,
        SyncSender<Result<bool, StoreError>>,
    ),
    Query(Scope, Box<RecordQuery>, SyncSender<Result<Page, StoreError>>),
    Output(Scope, OutputRequest, SyncSender<Result<OutputRange, StoreError>>),
    Forget(ForgetSelector, SyncSender<Result<u64, StoreError>>),
    Retention(SyncSender<Result<RetentionReport, StoreError>>),
    Sync(SyncSender<Result<(), StoreError>>),
}

/// A handle to the record store. Cheap to clone; every clone talks to the same single store thread.
#[derive(Debug, Clone)]
pub struct RecordStore {
    jobs: Sender<Job>,
    output_cap: usize,
}

impl RecordStore {
    /// Opens the record database at `path` (creating it with mode `0600` if missing), migrates it, and starts the
    /// store thread. The thread starts with a retention pass, then runs one every
    /// [`StoreConfig::retention_interval`]; `clock` gives the time retention judges records by.
    ///
    /// # Errors
    ///
    /// [`StoreError::NewerSchema`] or [`StoreError::ForeignDatabase`] for a file this build must not write (it is
    /// left untouched); [`StoreError::UnsafeFile`] for a file that is not a private regular file owned by
    /// `owner_uid`; [`StoreError::Platform`] if the file cannot be opened or migrated; [`StoreError::ThreadStart`].
    pub fn open(
        fs: &dyn Fs,
        path: &Path,
        owner_uid: u32,
        clock: Arc<dyn Clock>,
        config: StoreConfig,
    ) -> Result<Self, StoreError> {
        let output_cap = config.output_cap;
        let database = Database::open(fs, path, owner_uid, output_cap)?;
        let (jobs, inbox) = mpsc::channel();
        let worker = Worker {
            database,
            clock,
            retention: config.retention,
            interval: config.retention_interval,
        };
        thread::Builder::new()
            .name(String::from("knsh-store"))
            .spawn(move || worker.run(&inbox))
            .map_err(|_| StoreError::ThreadStart)?;
        Ok(Self { jobs, output_cap })
    }

    /// The most bytes stored per output stream ([`StoreConfig::output_cap`]): a capture that keeps no more than
    /// this is stored exactly as captured (KNSH-053).
    #[must_use]
    pub const fn output_cap(&self) -> usize {
        self.output_cap
    }

    /// Sends `job` built around a fresh answer channel and waits for the answer.
    fn ask<T>(&self, job: impl FnOnce(SyncSender<Result<T, StoreError>>) -> Job) -> Result<T, StoreError> {
        let (answer, answered) = mpsc::sync_channel(1);
        self.jobs.send(job(answer)).map_err(|_| StoreError::Closed)?;
        answered.recv().map_err(|_| StoreError::Closed)?
    }

    /// Writes or updates a session row, stamped `at`. Returns after it is committed.
    ///
    /// # Errors
    ///
    /// [`StoreError::Platform`] if SQLite fails; [`StoreError::Closed`] if the store thread has stopped.
    pub fn write_session(&self, session: &Session, at: Timestamp) -> Result<(), StoreError> {
        self.ask(|answer| Job::WriteSession(Box::new(session.clone()), at, answer))
    }

    /// Writes one record and its output. Returns only after the transaction committed, so the caller may answer
    /// its own client knowing the record is durable (FR-REC-02).
    ///
    /// A human record keeps only `command`, `cwd`, times and `exit_code`; its other fields and its output are
    /// dropped (FR-REC-09). Output is capped per stream, head and tail kept (FR-REC-06).
    ///
    /// # Errors
    ///
    /// [`StoreError::InvalidRecord`] for a field that cannot be stored; [`StoreError::Platform`] if SQLite fails
    /// (for example a duplicate `record_id`), in which case nothing was written; [`StoreError::Closed`].
    pub fn write_record(&self, record: ExecutionRecord, output: RecordedOutput) -> Result<(), StoreError> {
        self.ask(|answer| Job::WriteRecord(Box::new((record, output)), answer))
    }

    /// Appends sandbox violations reported after the agent record `record_id` of `session_id` was written
    /// (FR-SBX-08, KNSH-047). Repeats merge into the violations the record holds; at most
    /// [`MAX_VIOLATIONS_PER_RECORD`](crate::MAX_VIOLATIONS_PER_RECORD) distinct ones are kept. Returns whether the
    /// record exists: `false` (nothing written) for an unknown record, another session's, or a human one.
    ///
    /// # Errors
    ///
    /// [`StoreError::Corrupt`] if the stored list cannot be read; [`StoreError::Platform`] if SQLite fails, in
    /// which case nothing was written; [`StoreError::Closed`].
    pub fn append_sandbox_violations(
        &self,
        session_id: SessionId,
        record_id: RecordId,
        violations: Vec<SandboxViolation>,
    ) -> Result<bool, StoreError> {
        self.ask(|answer| Job::AppendViolations(Box::new((session_id, record_id, violations)), answer))
    }

    /// One page of records visible in `scope`, ordered by `record_id`.
    ///
    /// # Errors
    ///
    /// [`StoreError::OutOfScope`] if `query.session` is outside `scope`; [`StoreError::Corrupt`] for a row the
    /// engine could not have written; [`StoreError::Platform`]; [`StoreError::Closed`].
    pub fn query(&self, scope: Scope, query: RecordQuery) -> Result<Page, StoreError> {
        self.ask(|answer| Job::Query(scope, Box::new(query), answer))
    }

    /// A byte range of one stream of a record visible in `scope`, clamped to what is stored.
    ///
    /// # Errors
    ///
    /// [`StoreError::RecordNotFound`] if no such record is visible in `scope`; [`StoreError::Corrupt`];
    /// [`StoreError::Platform`]; [`StoreError::Closed`].
    pub fn output(&self, scope: Scope, request: OutputRequest) -> Result<OutputRange, StoreError> {
        self.ask(|answer| Job::Output(scope, request, answer))
    }

    /// Deletes every record matching `selector`, with its output, in one transaction (FR-REC-10, NFR-PRIV-03).
    /// Returns how many records were deleted.
    ///
    /// # Errors
    ///
    /// [`StoreError::Platform`] if SQLite fails, in which case nothing was deleted; [`StoreError::Closed`].
    pub fn forget(&self, selector: ForgetSelector) -> Result<u64, StoreError> {
        self.ask(|answer| Job::Forget(selector, answer))
    }

    /// Runs a retention pass now and waits for it to finish (FR-REC-07). If a pass is already running, waits for
    /// that one. Other jobs are still served between its batches.
    ///
    /// # Errors
    ///
    /// The first error of the pass: [`StoreError::Platform`] from SQLite or the clock (records deleted by earlier
    /// batches stay deleted; the rest are kept until the next pass); [`StoreError::Closed`].
    pub fn run_retention(&self) -> Result<RetentionReport, StoreError> {
        self.ask(Job::Retention)
    }

    /// Waits until every job sent before this one has finished. Writes are committed as they are answered, so this
    /// is all `knshd` needs before it exits.
    ///
    /// # Errors
    ///
    /// [`StoreError::Closed`] if the store thread has stopped.
    pub fn sync(&self) -> Result<(), StoreError> {
        self.ask(Job::Sync)
    }
}

/// A retention pass in progress.
struct Pass {
    /// The cutoffs, from one reading of the clock at the start of the pass.
    cutoffs: Cutoffs,
    /// Which deletes are left.
    phase: Phase,
    /// What was deleted so far.
    report: RetentionReport,
    /// Callers of [`RecordStore::run_retention`] waiting for this pass.
    waiters: Vec<SyncSender<Result<RetentionReport, StoreError>>>,
}

/// The two kinds of delete of a pass, in order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// Records older than their retention period.
    Expire,
    /// The oldest records, while the store is over its size limit.
    Shrink,
}

/// The store thread's state: the only owner of the database.
struct Worker {
    database: Database,
    clock: Arc<dyn Clock>,
    retention: Retention,
    interval: Duration,
}

impl Worker {
    /// The store thread's loop: jobs one at a time, in arrival order, with retention batches in between, until every
    /// handle is gone.
    fn run(mut self, inbox: &Receiver<Job>) {
        // A pass runs at start (FR-REC-07), then one every interval.
        let mut pass = self.start_pass(Vec::new());
        let mut next_pass = self.after_interval();
        loop {
            let job = if pass.is_some() {
                // Mid-pass: serve what is queued, but do not wait for it.
                match inbox.try_recv() {
                    Ok(job) => Some(job),
                    Err(TryRecvError::Empty) => None,
                    Err(TryRecvError::Disconnected) => return,
                }
            } else {
                let wait = next_pass.map_or(Duration::MAX, |due| {
                    due.saturating_duration_since(self.clock.monotonic())
                });
                // A due pass starts now even if jobs are queued: waiting for an idle moment could postpone it forever
                // on a busy store.
                let received = if wait.is_zero() {
                    Err(RecvTimeoutError::Timeout)
                } else {
                    inbox.recv_timeout(wait)
                };
                match received {
                    Ok(job) => Some(job),
                    Err(RecvTimeoutError::Timeout) => {
                        pass = self.start_pass(Vec::new());
                        next_pass = self.after_interval();
                        None
                    }
                    Err(RecvTimeoutError::Disconnected) => return,
                }
            };
            match job {
                Some(Job::Retention(answer)) => match &mut pass {
                    Some(running) => running.waiters.push(answer),
                    None => pass = self.start_pass(vec![answer]),
                },
                Some(job) => self.serve(job),
                None => {
                    if let Some(running) = pass.take() {
                        pass = self.step(running);
                    }
                }
            }
        }
    }

    /// Answers one job other than a retention request. A failed `send` means the caller stopped waiting; the job's
    /// effect (if any) stands either way.
    fn serve(&mut self, job: Job) {
        let database = &mut self.database;
        match job {
            Job::WriteSession(session, at, answer) => {
                let _ = answer.send(database.write_session(&session, at));
            }
            Job::WriteRecord(boxed, answer) => {
                let (record, output) = *boxed;
                let _ = answer.send(database.write_record(record, output));
            }
            Job::AppendViolations(boxed, answer) => {
                let (session_id, record_id, violations) = *boxed;
                let _ = answer.send(database.append_violations(session_id, record_id, violations));
            }
            Job::Query(scope, query, answer) => {
                let _ = answer.send(database.query(scope, &query));
            }
            Job::Output(scope, request, answer) => {
                let _ = answer.send(database.output(scope, &request));
            }
            Job::Forget(selector, answer) => {
                let _ = answer.send(database.forget(&selector));
            }
            Job::Retention(answer) => {
                // Handled by `run`, which owns the pass; never routed here.
                let _ = answer.send(Err(StoreError::Closed));
            }
            Job::Sync(answer) => {
                let _ = answer.send(Ok(()));
            }
        }
    }

    /// When the next automatic pass is due, or `None` if the interval overflows the clock (no more passes).
    fn after_interval(&self) -> Option<Monotonic> {
        self.clock.monotonic().checked_add(self.interval)
    }

    /// A new pass with the cutoffs of this instant. If the clock cannot be read, no pass runs: deleting by a wrong
    /// time could remove records that have not expired.
    fn start_pass(&self, waiters: Vec<SyncSender<Result<RetentionReport, StoreError>>>) -> Option<Pass> {
        match self.clock.now() {
            Ok(now) => Some(Pass {
                cutoffs: Cutoffs::at(&self.retention, now),
                phase: Phase::Expire,
                report: RetentionReport::default(),
                waiters,
            }),
            Err(error) => {
                for waiter in waiters {
                    let _ = waiter.send(Err(StoreError::Platform(error)));
                }
                None
            }
        }
    }

    /// Runs one batch of `pass`. Returns the pass if more is left, or `None` once it finished or failed (its waiters
    /// are then answered).
    fn step(&mut self, mut pass: Pass) -> Option<Pass> {
        let more_left = match pass.phase {
            Phase::Expire => self
                .database
                .expire_batch(&pass.cutoffs, RETENTION_BATCH)
                .map(|deleted| {
                    pass.report.expired += deleted;
                    // A short batch means nothing expired is left.
                    if deleted < u64::from(RETENTION_BATCH) {
                        pass.phase = Phase::Shrink;
                    }
                    true
                }),
            Phase::Shrink => self
                .database
                .shrink_batch(self.retention.max_bytes, RETENTION_BATCH)
                .map(|deleted| {
                    pass.report.trimmed += deleted;
                    // Under the limit, or nothing left to delete.
                    deleted > 0
                }),
        };
        let result = match more_left {
            Ok(true) => return Some(pass),
            Ok(false) => Ok(pass.report),
            Err(error) => Err(error),
        };
        for waiter in pass.waiters {
            let _ = waiter.send(result.clone());
        }
        None
    }
}
