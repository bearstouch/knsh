//! `checkpoint.diff` (KNSH-086): the paths that differ between two states of the history, with a unified diff of
//! each text file.
//!
//! [`History::diff`] compares the states a [`DiffTarget`] names: a line's change (the state before it and the state
//! after it) or a state and the current one (what `checkpoint.restore` to it would change). The paths compared are
//! those the changes on the way between them changed ([`knsh_core::Route`]); a path whose two versions hold the same
//! contents is left out (a change and its revert).
//!
//! **A path's version at a state** comes from the way from the current state to it: the version the last change on
//! that way restores, a copy in the store (a pre-image, or versions an undo saved), or, if no change on the way
//! touches the path, the live file. A version the history does not hold (never captured, its copy gone, or skipped as
//! possibly torn when its change was undone) is `unknown`.
//!
//! **Reading.** `knshd` is not sandboxed and live files are in roots agents write, so a live file is read only if
//! every folder from its root down is a real folder and through a descriptor that refuses a final symlink
//! ([`ShadowFiles::read_file`]): a file swapped for a symlink to a secret elsewhere is never read. Each version is
//! read up to [`MAX_DIFF_FILE`] bytes; files named like secrets (`.env*`, `*.pem`, `*.key`, `id_*`) are never read
//! ([`knsh_core::is_sensitive`]), nor are their contents sent. Binary files are reported as changed without a text
//! diff.
//!
//! **Pages.** Paths are sorted; one call returns at most [`MAX_DIFF_PAGE`] of them (the most binary streams one answer
//! may open, `MAX_OPEN_STREAMS`) and at most [`MAX_DIFF_PAGE_BYTES`] of diffs, and says whether more follow; the next
//! call starts after the last path returned.
//!
//! **Limits.** The live version is read when the diff is made, so an edit the engine has not recorded yet shows as
//! part of the current state. Symlink targets are not compared (both versions are listed as `symlink`). Contents are
//! not redacted yet: the redaction engine (KNSH-090) is pending; files named like secrets are withheld meanwhile.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use knsh_core::{
    CanonicalPath, CheckpointId, Diff, DiffTarget, EntryKind, FileChange, FileDiff, HistoryError, MAX_DIFF_FILE,
    NoTextDiff, StateId, TextDiff, is_binary, is_sensitive, unified,
};
use knsh_json::MAX_OPEN_STREAMS;
use knsh_platform::{FileKind, PlatformError};

use crate::capture::StoredPreImage;
use crate::error::CheckpointError;
use crate::restore::check_inside_root;
use crate::shadow::ShadowFiles;
use crate::undo::{Caller, History};

/// The most paths one `checkpoint.diff` call returns: each may open a binary stream, and a client may have at most
/// this many open at once (`specs/06-api/wire-format.md`).
pub const MAX_DIFF_PAGE: usize = MAX_OPEN_STREAMS;

/// The most diff bytes one call returns (8 MiB); the page ends after the path that reaches it. Bounds the memory one
/// call holds.
pub const MAX_DIFF_PAGE_BYTES: usize = 8 << 20;

/// A `checkpoint.diff` request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiffRequest {
    /// What to compare.
    pub target: DiffTarget,
    /// Who asks: an agent sees only diffs made of its own session's changes.
    pub caller: Caller,
    /// Only paths after this one (the last path of the previous page).
    pub after: Option<CanonicalPath>,
    /// At most this many paths, 1 to [`MAX_DIFF_PAGE`].
    pub limit: usize,
}

/// One page of a diff.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiffPage {
    /// The paths of this page, sorted.
    pub diff: Diff,
    /// More paths follow the last one of this page.
    pub more: bool,
}

/// A path's version at one state, as read.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Version {
    Absent,
    Folder,
    Symlink,
    Other,
    Unknown,
    /// A regular file: its contents, or why they were not read.
    File(Result<Vec<u8>, NoTextDiff>),
}

impl Version {
    const fn kind(&self) -> EntryKind {
        match self {
            Self::Absent => EntryKind::Absent,
            Self::Folder => EntryKind::Folder,
            Self::Symlink => EntryKind::Symlink,
            Self::Other => EntryKind::Other,
            Self::Unknown => EntryKind::Unknown,
            Self::File(_) => EntryKind::File,
        }
    }
}

/// Where a path's version at a state is.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Source {
    /// In the store, as a checkpoint lists it.
    Stored(StoredPreImage),
    /// Not held by the history.
    Lost,
}

impl History {
    /// One page of the diff `request` names (module documentation).
    ///
    /// # Errors
    ///
    /// [`CheckpointError::History`] for an unknown record or state ([`HistoryError::UnknownChange`],
    /// [`HistoryError::UnknownState`]), or one whose way crosses a removed checkpoint ([`HistoryError::Expired`],
    /// KNSH-087); [`CheckpointError::NotOwnChange`] when an agent asks for a diff that
    /// includes a change not its own session's. A file that cannot be read is not an error: it is reported
    /// `unavailable`.
    pub fn diff(&self, request: &DiffRequest) -> Result<DiffPage, CheckpointError> {
        let tree = self.tree();
        let (from, to) = match request.target {
            DiffTarget::Record(record) => {
                let edge = tree
                    .edge_for_record(record)
                    .ok_or_else(|| CheckpointError::History(self.missing_record(record)))?;
                // KNSH-087: an expired edge still in the tree makes the route below fail as expired; authorize the
                // line's own change first, so another session's agent learns nothing about it (as in undo).
                if let Caller::Agent(_) = request.caller {
                    self.authorize(request.caller, self.origin(edge.checkpoint)?)?;
                }
                (edge.from, edge.to)
            }
            DiffTarget::State(state) => (state, tree.head()),
        };
        let route = tree.route(from, to)?;
        let edges: Vec<CheckpointId> = route.back.iter().chain(&route.forward).copied().collect();
        if let Caller::Agent(_) = request.caller {
            for edge in &edges {
                self.authorize(request.caller, self.origin(*edge)?)?;
            }
        }
        // Each path a change on the way changed, with the root it is under.
        let mut paths: BTreeMap<CanonicalPath, CanonicalPath> = BTreeMap::new();
        for edge in &edges {
            let checkpoint = self
                .checkpoint(*edge)
                .ok_or(CheckpointError::History(HistoryError::UnknownChange))?;
            for (root, listed) in &checkpoint.paths {
                for path in listed.keys() {
                    paths.entry(path.clone()).or_insert_with(|| root.clone());
                }
            }
        }
        let before = self.sources_at(from)?;
        let after = self.sources_at(to)?;
        let limit = request.limit.clamp(1, MAX_DIFF_PAGE);
        let mut files = Vec::new();
        let mut bytes = 0usize;
        let mut remaining = paths
            .iter()
            .filter(|(path, _)| request.after.as_ref().is_none_or(|after| *path > after))
            .peekable();
        for (path, root) in remaining.by_ref() {
            let withheld = is_sensitive(path.as_path());
            let old = self.version(before.get(path), root, path, withheld);
            let new = self.version(after.get(path), root, path, withheld);
            if let Some(file) = compare(path, &old, &new, withheld) {
                if let TextDiff::Unified(text) = &file.text {
                    bytes = bytes.saturating_add(text.len());
                }
                files.push(file);
            }
            if files.len() >= limit || bytes >= MAX_DIFF_PAGE_BYTES {
                break;
            }
        }
        Ok(DiffPage {
            diff: Diff { from, to, files },
            more: remaining.peek().is_some(),
        })
    }

    /// Where each path changed on the way from the current state to `state` has its version at `state`: the last
    /// change on that way that restores it decides. Paths not listed are at their live version.
    fn sources_at(&self, state: StateId) -> Result<BTreeMap<CanonicalPath, Source>, CheckpointError> {
        let tree = self.tree();
        let route = tree.route(tree.head(), state)?;
        let mut sources = BTreeMap::new();
        // Back: an edge's own checkpoint holds each path's version at its parent state.
        for edge in &route.back {
            if let Some(checkpoint) = self.checkpoint(*edge) {
                for (path, captured) in checkpoint.paths.values().flat_map(BTreeMap::iter) {
                    sources.insert(path.clone(), Source::Stored(captured.pre.clone()));
                }
            }
        }
        // Forward: the versions an edge's undo saved are its paths' versions at its child state. A path it changed
        // that they do not list (skipped as possibly torn, or nothing saved) has no known version there.
        for edge in &route.forward {
            let saved = tree
                .edge(*edge)
                .and_then(|edge| edge.saved)
                .and_then(|saved| self.checkpoint(saved));
            let changed: BTreeSet<&CanonicalPath> = self
                .checkpoint(*edge)
                .map(|checkpoint| checkpoint.paths.values().flat_map(BTreeMap::keys).collect())
                .unwrap_or_default();
            for path in changed {
                let source = saved
                    .and_then(|saved| saved.paths.values().find_map(|listed| listed.get(path)))
                    .map_or(Source::Lost, |captured| Source::Stored(captured.pre.clone()));
                sources.insert(path.clone(), source);
            }
        }
        Ok(sources)
    }

    /// Reads the version `source` names (`None`: the live file at `path`, in `root`). A file `withheld` is not read.
    fn version(&self, source: Option<&Source>, root: &CanonicalPath, path: &CanonicalPath, withheld: bool) -> Version {
        let files = self.files();
        match source {
            Some(Source::Lost | Source::Stored(StoredPreImage::Lost)) => Version::Unknown,
            Some(Source::Stored(StoredPreImage::NotExisted)) => Version::Absent,
            Some(Source::Stored(StoredPreImage::Folder)) => Version::Folder,
            // The store is owner-only and denied to envelopes and commands: its copies are the engine's own.
            Some(Source::Stored(StoredPreImage::Kept(copy))) => match files.kind(copy) {
                Ok(FileKind::File) => Version::File(contents(files, copy, withheld)),
                Ok(FileKind::Symlink) => Version::Symlink,
                Ok(FileKind::Directory | FileKind::Other) | Err(_) => Version::Unknown,
            },
            None => match files.identity(path.as_path()) {
                Err(error) if error.is_not_found() => Version::Absent,
                Err(_) => Version::Unknown,
                Ok(live) => match live.kind {
                    FileKind::Directory => Version::Folder,
                    FileKind::Symlink => Version::Symlink,
                    FileKind::Other => Version::Other,
                    FileKind::File if withheld => Version::File(Err(NoTextDiff::Sensitive)),
                    // Never read through a folder an agent swapped for a symlink: `knshd` could read outside the root.
                    FileKind::File => match check_inside_root(files, root.as_path(), path.as_path()) {
                        Ok(()) => Version::File(contents(files, path.as_path(), withheld)),
                        Err(_) => Version::File(Err(NoTextDiff::Unavailable)),
                    },
                },
            },
        }
    }
}

/// The contents of the regular file `path`, refusing a final symlink, up to [`MAX_DIFF_FILE`] bytes.
fn contents(files: &dyn ShadowFiles, path: &Path, withheld: bool) -> Result<Vec<u8>, NoTextDiff> {
    if withheld {
        return Err(NoTextDiff::Sensitive);
    }
    match files.read_file(path, MAX_DIFF_FILE) {
        Ok(bytes) => Ok(bytes),
        Err(PlatformError::TooLarge { .. }) => Err(NoTextDiff::TooLarge),
        Err(_) => Err(NoTextDiff::Unavailable),
    }
}

/// How `path` differs from `old` to `new`, or `None` if it does not.
fn compare(path: &CanonicalPath, old: &Version, new: &Version, withheld: bool) -> Option<FileDiff> {
    let same = match (old, new) {
        (Version::Absent, Version::Absent) | (Version::Folder, Version::Folder) => true,
        (Version::File(Ok(a)), Version::File(Ok(b))) => a == b,
        _ => false,
    };
    if same {
        return None;
    }
    let change = match (old, new) {
        (Version::Absent, _) => FileChange::Created,
        (_, Version::Absent) => FileChange::Deleted,
        _ => FileChange::Modified,
    };
    Some(FileDiff {
        path: path.clone(),
        change,
        before: old.kind(),
        after: new.kind(),
        text: text_diff(path, old, new, withheld),
    })
}

/// One version as diff input: its bytes, `None` when absent, or why it has none.
fn side(version: &Version) -> Result<Option<&[u8]>, NoTextDiff> {
    match version {
        Version::Absent => Ok(None),
        Version::File(Ok(bytes)) => Ok(Some(bytes)),
        Version::File(Err(reason)) => Err(*reason),
        Version::Unknown => Err(NoTextDiff::Unavailable),
        Version::Folder | Version::Symlink | Version::Other => Err(NoTextDiff::NotAFile),
    }
}

/// The text diff of a changed path, or why there is none.
fn text_diff(path: &CanonicalPath, old: &Version, new: &Version, withheld: bool) -> TextDiff {
    if withheld {
        return TextDiff::Omitted(NoTextDiff::Sensitive);
    }
    match (side(old), side(new)) {
        (Ok(old), Ok(new)) => {
            if old.is_some_and(is_binary) || new.is_some_and(is_binary) {
                TextDiff::Omitted(NoTextDiff::Binary)
            } else {
                TextDiff::Unified(unified(path.as_path(), old, new))
            }
        }
        // A version that cannot be read says more than one that is not a file.
        (Err(NoTextDiff::NotAFile) | Ok(_), Err(reason)) | (Err(reason), _) => TextDiff::Omitted(reason),
    }
}

#[cfg(test)]
mod tests;
