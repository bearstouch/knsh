//! Possibly-torn detection (KNSH-085, FR-CKP-24, decision 17).
//!
//! A file is **possibly torn** when the version a checkpoint holds of it may mix writes from before and after the
//! capture, so restoring it could put back a file no program ever wrote. Undo and redo skip such a file unless the
//! user or the authority gives `force` ([`mod@crate::restore`]). Two sources mark a path:
//!
//! - **Held for writing at line end.** A store through a live shared mapping moves neither the file's size nor its
//!   time, file events say nothing while the writer lives, and a clone taken while a writer keeps storing was torn in
//!   195 of 200 tries (KNSH-077, decision 17). So when a line ends, the supervisor asks the processes that may still
//!   be writing, the members of the line's process group and every process of its session's envelopes (and their
//!   descendants), for the files they hold open for writing or mapped writable ([`WriteHolders`]); each such file
//!   inside one of the line's roots is possibly torn ([`held_in_roots`]). If the processes cannot be listed or one
//!   cannot be read, no file can be shown untorn, and every file of the change is marked [`TornReason::Unchecked`]
//!   (fail closed). A process that exited meanwhile holds nothing and is skipped.
//! - **SQLite databases with journals.** A database is consistent only together with its `-wal`, `-shm` or
//!   `-journal` file, which a restore of one file cannot keep. A changed file with such a file beside it, the
//!   sidecar file itself, and the database a changed sidecar belongs to are marked
//!   [`TornReason::SqliteJournal`] ([`sqlite_marks`]). The test is by name only, as FR-CKP-24 states: a file is
//!   never opened to see whether it is a database.
//!
//! # Limits
//!
//! The observation is at line end: a process that wrote through a mapping and unmapped before the line ended, or a
//! process outside the line's group and envelopes (a daemon the line asked to write, or a background process an
//! earlier line left running: lines are started by `knshd`, not by the envelope), is not seen. Such a write
//! still changes the file's contents, which the post-image hash catches for files under 64 MiB (FR-CKP-09); for larger
//! files the restore-time check of decision 17 (refuse while any process holds the file for writing) is pending. A
//! path the kernel names through a symlink, or after a rename, may not match its root and is then not marked.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::path::{Path, PathBuf};

use knsh_core::{CanonicalPath, TornReason};
use knsh_platform::{HoldKind, PlatformError, ProcessEntry, ProcessKey, WriteHolders};

use crate::shadow::ShadowFiles;

/// The suffixes of SQLite's journal files: write-ahead log, its shared-memory index, and the rollback journal.
pub const SQLITE_SIDECARS: [&str; 3] = ["-wal", "-shm", "-journal"];

/// The most possibly-torn paths one checkpoint lists by name; past it every file of the change is
/// [`TornReason::Unchecked`] instead, never a silent cut.
pub const MAX_TORN_PATHS: usize = 4096;

/// `ESRCH`: the process exited (or its pid names another process now). `libc` is reserved to `knsh-platform`.
const ESRCH: i32 = 3;

/// The processes a line's end asks for held files: whom to look at (module documentation).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LineProcesses {
    /// The line's process group: members that outlive its leader (`server &`) may still be writing.
    pub group: Option<i32>,
    /// The root processes of its session's envelopes: they and their descendants may be writing.
    pub envelopes: Vec<ProcessKey>,
}

/// What asking a line's processes found ([`held_in_roots`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeldScan {
    /// These paths, inside one of the roots, are held for writing, with why.
    Held(BTreeMap<CanonicalPath, TornReason>),
    /// The processes could not all be read: no file of the change can be shown untorn.
    Unchecked,
}

/// Asks the processes of `line` which files they hold for writing, and keeps those inside one of `roots`
/// (module documentation). Bounded by the platform's limits: at most [`knsh_platform::MAX_PROCESSES`] processes,
/// each with at most [`knsh_platform::MAX_HELD_FILES`] files.
#[must_use]
pub fn held_in_roots(holders: &dyn WriteHolders, line: &LineProcesses, roots: &[CanonicalPath]) -> HeldScan {
    if roots.is_empty() || (line.group.is_none() && line.envelopes.is_empty()) {
        return HeldScan::Held(BTreeMap::new());
    }
    let Ok(table) = holders.processes() else {
        return HeldScan::Unchecked;
    };
    let mut held = BTreeMap::new();
    for process in processes_to_ask(&table, line) {
        let files = match holders.held_for_writing(process) {
            Ok(files) => files,
            // Exited since the table was read: it holds nothing now.
            Err(PlatformError::Os { errno: ESRCH, .. }) => continue,
            Err(_) => return HeldScan::Unchecked,
        };
        for file in files {
            let Some(path) = in_roots(&file.path, roots) else {
                continue;
            };
            let reason = match file.how {
                HoldKind::OpenForWriting => TornReason::OpenForWriting,
                HoldKind::MappedWritable => TornReason::MappedWritable,
            };
            // A mapping is the stronger reason: its writes leave no trace at all.
            let entry = held.entry(path).or_insert(reason);
            *entry = (*entry).max(reason);
            if held.len() > MAX_TORN_PATHS {
                return HeldScan::Unchecked;
            }
        }
    }
    HeldScan::Held(held)
}

/// The members of `line`'s group, its envelope roots that are still alive, and every live descendant of them, each
/// once, in table order.
fn processes_to_ask(table: &[ProcessEntry], line: &LineProcesses) -> Vec<ProcessKey> {
    let mut children: BTreeMap<u64, Vec<&ProcessEntry>> = BTreeMap::new();
    for entry in table {
        children.entry(entry.parent_unique_id).or_default().push(entry);
    }
    let mut chosen: BTreeSet<ProcessKey> = BTreeSet::new();
    if let Some(group) = line.group {
        chosen.extend(table.iter().filter(|entry| entry.group == group).map(|entry| entry.key));
    }
    // By unique id, never a bare pid: a root that exited and whose pid was reused is not followed.
    let mut stack: Vec<ProcessKey> = table
        .iter()
        .map(|entry| entry.key)
        .filter(|key| line.envelopes.contains(key))
        .collect();
    let mut visited: BTreeSet<ProcessKey> = BTreeSet::new();
    while let Some(key) = stack.pop() {
        if !visited.insert(key) {
            continue;
        }
        chosen.insert(key);
        if let Some(kids) = children.get(&key.unique_id()) {
            stack.extend(kids.iter().map(|kid| kid.key));
        }
    }
    table
        .iter()
        .map(|entry| entry.key)
        .filter(|key| chosen.contains(key))
        .collect()
}

/// `path` as a canonical path, if it is strictly inside one of `roots`.
fn in_roots(path: &Path, roots: &[CanonicalPath]) -> Option<CanonicalPath> {
    let inside = roots
        .iter()
        .any(|root| path != root.as_path() && path.starts_with(root.as_path()));
    if inside { CanonicalPath::new(path).ok() } else { None }
}

/// The SQLite marks of a change to `path` (module documentation): if `path` is a journal file, its database and
/// itself, whatever happened to it (a journal that came and went still says the database was being written);
/// otherwise, if `path` is a file (`is_file`) with a journal file beside it now, `path`. Reads only whether the
/// journal files exist (`lstat`); one that cannot be read counts as present (fail closed).
#[must_use]
pub fn sqlite_marks(files: &dyn ShadowFiles, path: &CanonicalPath, is_file: bool) -> Vec<CanonicalPath> {
    if let Some(database) = database_of(path) {
        return vec![database, path.clone()];
    }
    if !is_file {
        return Vec::new();
    }
    let journaled = sidecars(path.as_path())
        .iter()
        .any(|sidecar| match files.identity(sidecar) {
            Ok(_) => true,
            Err(error) => !error.is_not_found(),
        });
    if journaled { vec![path.clone()] } else { Vec::new() }
}

/// The database a journal file `path` belongs to: `path` without its sidecar suffix, if it has one and something is
/// left of its name.
fn database_of(path: &CanonicalPath) -> Option<CanonicalPath> {
    let name = path.as_path().file_name()?.to_str()?;
    let stem = SQLITE_SIDECARS
        .iter()
        .find_map(|suffix| name.strip_suffix(suffix))
        .filter(|stem| !stem.is_empty())?;
    CanonicalPath::new(path.as_path().with_file_name(stem)).ok()
}

/// The journal files `path` would have beside it.
fn sidecars(path: &Path) -> Vec<PathBuf> {
    SQLITE_SIDECARS
        .iter()
        .map(|suffix| {
            let mut name = OsString::from(path.as_os_str());
            name.push(suffix);
            PathBuf::from(name)
        })
        .collect()
}

#[cfg(test)]
mod tests;
