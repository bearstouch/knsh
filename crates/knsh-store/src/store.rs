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

use std::path::Path;
use std::sync::mpsc::{self, Receiver, Sender, SyncSender};
use std::thread;

use knsh_core::{ExecutionRecord, Session, Timestamp};
use knsh_platform::Fs;

use crate::db::{Database, RecordedOutput};
use crate::error::StoreError;
use crate::output::DEFAULT_OUTPUT_CAP;
use crate::query::{OutputRange, OutputRequest, Page, RecordQuery, Scope};

/// Settings of a record store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoreConfig {
    /// The most bytes stored per output stream; beyond it head and tail are kept (FR-REC-06).
    pub output_cap: usize,
}

impl Default for StoreConfig {
    fn default() -> Self {
        Self {
            output_cap: DEFAULT_OUTPUT_CAP,
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
    Query(Scope, Box<RecordQuery>, SyncSender<Result<Page, StoreError>>),
    Output(Scope, OutputRequest, SyncSender<Result<OutputRange, StoreError>>),
    Sync(SyncSender<Result<(), StoreError>>),
}

/// A handle to the record store. Cheap to clone; every clone talks to the same single store thread.
#[derive(Debug, Clone)]
pub struct RecordStore {
    jobs: Sender<Job>,
}

impl RecordStore {
    /// Opens the record database at `path` (creating it with mode `0600` if missing), migrates it, and starts the
    /// store thread.
    ///
    /// # Errors
    ///
    /// [`StoreError::NewerSchema`] or [`StoreError::ForeignDatabase`] for a file this build must not write (it is
    /// left untouched); [`StoreError::UnsafeFile`] for a file that is not a private regular file owned by
    /// `owner_uid`; [`StoreError::Platform`] if the file cannot be opened or migrated; [`StoreError::ThreadStart`].
    pub fn open(fs: &dyn Fs, path: &Path, owner_uid: u32, config: StoreConfig) -> Result<Self, StoreError> {
        let database = Database::open(fs, path, owner_uid, config.output_cap)?;
        let (jobs, inbox) = mpsc::channel();
        thread::Builder::new()
            .name(String::from("knsh-store"))
            .spawn(move || run(database, &inbox))
            .map_err(|_| StoreError::ThreadStart)?;
        Ok(Self { jobs })
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

/// The store thread's loop: one job at a time, in arrival order, until every handle is gone.
fn run(mut database: Database, inbox: &Receiver<Job>) {
    // A failed `send` means the caller stopped waiting; the job's effect (if any) stands either way.
    for job in inbox {
        match job {
            Job::WriteSession(session, at, answer) => {
                let _ = answer.send(database.write_session(&session, at));
            }
            Job::WriteRecord(boxed, answer) => {
                let (record, output) = *boxed;
                let _ = answer.send(database.write_record(record, output));
            }
            Job::Query(scope, query, answer) => {
                let _ = answer.send(database.query(scope, &query));
            }
            Job::Output(scope, request, answer) => {
                let _ = answer.send(database.output(scope, &request));
            }
            Job::Sync(answer) => {
                let _ = answer.send(Ok(()));
            }
        }
    }
}
