//! A scripted supervisor for the interpreter's [`SupervisedSpawner`](crate::supervision::SupervisedSpawner)
//! (KNSH-108): it records every command submitted, denies the programs it was told to deny, and "runs" every other
//! one by answering at once with a scripted exit status. Nothing ever starts.

use std::collections::HashMap;
use std::ffi::OsString;
use std::os::fd::BorrowedFd;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, PoisonError};

use crate::process::ExitStatus;
use crate::supervision::{StartAnswer, Submission, SupervisionError, SupervisorLink};

/// The fake supervisor (module documentation).
#[derive(Debug, Default)]
pub struct FakeSupervisor {
    /// Every submission, in order, with how many descriptors came with it.
    submitted: Mutex<Vec<(Submission, usize)>>,
    /// Denied programs (by path) and the reason given.
    denied: Mutex<HashMap<PathBuf, String>>,
    /// Exit codes of allowed programs; 0 when not listed.
    exits: Mutex<HashMap<PathBuf, i32>>,
    /// Started commands not yet waited for, by channel number, with their exit code.
    running: Mutex<HashMap<u64, i32>>,
    next_child: Mutex<u64>,
    /// When set, the channel is gone: every call fails.
    unreachable: AtomicBool,
}

impl FakeSupervisor {
    /// A supervisor that allows everything, every program exiting 0.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Denies `program` with `reason`.
    #[must_use]
    pub fn denying(self, program: impl Into<PathBuf>, reason: &str) -> Self {
        self.denied
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(program.into(), reason.to_owned());
        self
    }

    /// Lets `program` exit with `code`.
    #[must_use]
    pub fn exiting(self, program: impl Into<PathBuf>, code: i32) -> Self {
        self.exits
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(program.into(), code);
        self
    }

    /// A supervisor whose channel is closed: every request fails (FR-LC-57).
    #[must_use]
    pub fn unreachable() -> Self {
        let supervisor = Self::default();
        supervisor.unreachable.store(true, Ordering::SeqCst);
        supervisor
    }

    /// Every command submitted so far, in order.
    #[must_use]
    pub fn submitted(&self) -> Vec<Submission> {
        self.submitted
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .map(|(submission, _)| submission.clone())
            .collect()
    }

    /// `(program, argv[1..])` of every command submitted so far, in order.
    #[must_use]
    pub fn argvs(&self) -> Vec<(PathBuf, Vec<OsString>)> {
        self.submitted()
            .into_iter()
            .map(|submission| (submission.program, submission.args))
            .collect()
    }

    /// How many descriptors came with each submission.
    #[must_use]
    pub fn descriptor_counts(&self) -> Vec<usize> {
        self.submitted
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .map(|(_, count)| *count)
            .collect()
    }

    fn exit_of(&self, program: &Path) -> i32 {
        self.exits
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(program)
            .copied()
            .unwrap_or(0)
    }
}

impl SupervisorLink for FakeSupervisor {
    fn start(&self, submission: &Submission, descriptors: &[BorrowedFd<'_>]) -> Result<StartAnswer, SupervisionError> {
        if self.unreachable.load(Ordering::SeqCst) {
            return Err(SupervisionError::Closed);
        }
        self.submitted
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push((submission.clone(), descriptors.len()));
        if let Some(reason) = self
            .denied
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&submission.program)
        {
            return Ok(StartAnswer::Denied(reason.clone()));
        }
        let child = {
            let mut next = self.next_child.lock().unwrap_or_else(PoisonError::into_inner);
            *next += 1;
            *next
        };
        let code = self.exit_of(&submission.program);
        self.running
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(child, code);
        Ok(StartAnswer::Running {
            child,
            pid: i32::try_from(1000 + child).unwrap_or(i32::MAX),
        })
    }

    fn wait(&self, child: u64) -> Result<ExitStatus, SupervisionError> {
        if self.unreachable.load(Ordering::SeqCst) {
            return Err(SupervisionError::Closed);
        }
        self.running
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&child)
            .map(ExitStatus::Exited)
            .ok_or(SupervisionError::Malformed)
    }
}
