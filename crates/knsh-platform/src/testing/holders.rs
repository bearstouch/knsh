//! A process table and held files set by the test (KNSH-085).

use std::collections::BTreeMap;
use std::sync::Mutex;

use super::lock;
use crate::ancestry::ProcessKey;
use crate::error::{Operation, PlatformError};
use crate::holders::{HeldFile, ProcessEntry, WriteHolders};

/// Processes and the files they hold for writing, as the test sets them. A process not listed is gone (`ESRCH`); a
/// failure can be set for the table or for one process. Every call to [`WriteHolders::held_for_writing`] is counted.
#[derive(Debug, Default)]
pub struct FakeWriteHolders {
    state: Mutex<State>,
}

#[derive(Debug, Default)]
struct State {
    processes: Vec<ProcessEntry>,
    held: BTreeMap<ProcessKey, Vec<HeldFile>>,
    table_error: Option<PlatformError>,
    process_errors: BTreeMap<ProcessKey, PlatformError>,
    asked: Vec<ProcessKey>,
}

impl FakeWriteHolders {
    /// No process.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds the live process `entry`, holding `files`.
    pub fn add(&self, entry: ProcessEntry, files: Vec<HeldFile>) {
        let mut state = lock(&self.state);
        state.processes.push(entry);
        state.held.insert(entry.key, files);
    }

    /// Makes [`WriteHolders::processes`] fail with `error` (`None`: succeed again).
    pub fn fail_table(&self, error: Option<PlatformError>) {
        lock(&self.state).table_error = error;
    }

    /// Makes [`WriteHolders::held_for_writing`] of `process` fail with `error`.
    pub fn fail_process(&self, process: ProcessKey, error: PlatformError) {
        lock(&self.state).process_errors.insert(process, error);
    }

    /// The processes asked for their files, in order.
    #[must_use]
    pub fn asked(&self) -> Vec<ProcessKey> {
        lock(&self.state).asked.clone()
    }
}

impl WriteHolders for FakeWriteHolders {
    fn processes(&self) -> Result<Vec<ProcessEntry>, PlatformError> {
        let state = lock(&self.state);
        match &state.table_error {
            Some(error) => Err(*error),
            None => Ok(state.processes.clone()),
        }
    }

    fn held_for_writing(&self, process: ProcessKey) -> Result<Vec<HeldFile>, PlatformError> {
        let mut state = lock(&self.state);
        state.asked.push(process);
        if let Some(error) = state.process_errors.get(&process) {
            return Err(*error);
        }
        state.held.get(&process).cloned().ok_or(PlatformError::Os {
            operation: Operation::ProcessInfo,
            errno: 3, // ESRCH
        })
    }
}
