//! Retention, sensitive pre-images and forget (KNSH-087, FR-CKP-32 to FR-CKP-34, NFR-PRIV-07).
//!
//! Checkpoints hold copies of files, including files an agent deleted, so they are bounded in space and time, and
//! secrets among them go quickly. [`History::retain`] applies the limits of [`Retention`]:
//!
//! 1. **Sensitive pre-images** (FR-CKP-33, NFR-PRIV-07): in every checkpoint created at least
//!    [`Retention::sensitive_age`] ago (24 hours), the kept copy of each path named like a secret file
//!    ([`knsh_core::is_sensitive`]: `.env*`, `*.pem`, `*.key`, `id_*`) is deleted and the path's pre-image becomes
//!    *lost*. The rest of the checkpoint stays; its undo then reports that path as `pre_image_lost`, a conflict
//!    `force` does not override (FR-CKP-20: no partial restore), so the change can no longer be undone as a whole.
//! 2. **Age** (FR-CKP-32): every change created at least [`Retention::max_age`] ago (7 days) is removed.
//! 3. **Count** (FR-CKP-32): while a checkpoint root has more than [`Retention::per_root`] changes (200), its oldest
//!    is removed. A change with paths in two roots counts in both.
//! 4. **Size** (FR-CKP-32): while the kept pre-images in one store (one per volume, KNSH-078) exceed
//!    [`Retention::bytes_per_volume`] (5 GB), the oldest change with bytes there is removed.
//!
//! So checkpoints are kept until the **first** limit is reached. "Oldest" is the order changes entered the history;
//! a change's age, and a checkpoint's for the sensitive limit, is the time in its identifier (a ULID, made when its
//! first change was captured, or when an undo saved the versions), so a copy is never kept longer than the limit
//! after it was taken. Removing a change removes its checkpoint and the versions its undo saved, and expires it in
//! the tree ([`knsh_core::HistoryTree::expire`]): its undo or redo is then refused as expired, never attempted.
//!
//! [`History::forget`] (`knsh forget --with-checkpoints`, FR-CKP-34) removes at once the changes of a session, or
//! made since an instant, or both, and scrubs their paths from the tree.
//!
//! Each sweep reports when the next one is due ([`Swept::next_due`]), the earliest time a kept checkpoint reaches an
//! age limit, so the caller can run it then and keep the 24-hour bound exact rather than late by its period.
//!
//! # Limits
//!
//! Sizes are the logical sizes of the kept copies: clones share blocks with the files they were taken from, so the
//! space really used is at most this. Only checkpoints in the history count: shadows, and pre-images of a change
//! still being captured, are not checkpoints yet. A copy that cannot be deleted stays listed, and the next sweep
//! (due at once) tries again. If the clock cannot be read, nothing is removed and the sweep fails.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::time::Duration;

use knsh_core::{CanonicalPath, CheckpointId, EdgeKind, HistoryEdge, SessionId, StateId, Timestamp, is_sensitive};

use crate::capture::{Checkpoint, StoredPreImage};
use crate::error::CheckpointError;
use crate::restore::remove_checkpoint_files;
use crate::undo::History;

/// Checkpoint data kept per volume: 5 GB, in the binary units the other storage limits use (5 × 2³⁰ bytes, like
/// MB meaning MiB in `specs/05-models/checkpoint.md`), FR-CKP-32.
pub const RETAINED_BYTES_PER_VOLUME: u64 = 5 << 30;

/// Changes kept per checkpoint root (FR-CKP-32).
pub const RETAINED_PER_ROOT: usize = 200;

/// How long a change is kept (FR-CKP-32): 7 days.
pub const RETAINED_AGE: Duration = Duration::from_hours(7 * 24);

/// How long a sensitive file's pre-image is kept (FR-CKP-33, NFR-PRIV-07): 24 hours.
pub const SENSITIVE_AGE: Duration = Duration::from_hours(24);

/// The limits [`History::retain`] applies. [`Retention::default`] is the specification's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Retention {
    /// Bytes of kept pre-images per store (volume).
    pub bytes_per_volume: u64,
    /// Changes per checkpoint root.
    pub per_root: usize,
    /// Age at which a change is removed.
    pub max_age: Duration,
    /// Age at which a sensitive file's pre-image is deleted.
    pub sensitive_age: Duration,
}

impl Default for Retention {
    fn default() -> Self {
        Self {
            bytes_per_volume: RETAINED_BYTES_PER_VOLUME,
            per_root: RETAINED_PER_ROOT,
            max_age: RETAINED_AGE,
            sensitive_age: SENSITIVE_AGE,
        }
    }
}

/// Which changes [`History::forget`] removes: a session's, those made at or after an instant, or both combined with
/// AND, as `knsh forget` selects records (FR-REC-10).
///
/// At least one is always set: no selector matches everything by accident.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Forget {
    session: Option<SessionId>,
    since: Option<Timestamp>,
}

impl Forget {
    /// A selector, or `None` when neither `session` nor `since` is given.
    #[must_use]
    pub const fn new(session: Option<SessionId>, since: Option<Timestamp>) -> Option<Self> {
        if session.is_none() && since.is_none() {
            None
        } else {
            Some(Self { session, since })
        }
    }
}

/// What a sweep removed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Swept {
    /// The checkpoints removed whole, sorted: changes and the versions their undos saved.
    pub removed: Vec<CheckpointId>,
    /// Sensitive pre-images deleted from checkpoints that stay (FR-CKP-33).
    pub sensitive: usize,
    /// When the next sweep is due: the earliest time a kept checkpoint reaches an age limit (possibly already
    /// passed, when a copy could not be deleted). `None` when nothing kept ever will, or after a forget.
    pub next_due: Option<Timestamp>,
}

/// When checkpoint `id` was created, in Unix milliseconds: the time in its ULID.
fn created(id: CheckpointId) -> u64 {
    id.ulid().millis()
}

/// `duration` in milliseconds, saturating.
fn millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

impl History {
    /// Applies `limits` (module documentation): deletes sensitive pre-images past their age, then removes changes
    /// past their age, beyond the count of their root, and beyond the size of their volume, oldest first.
    ///
    /// # Errors
    ///
    /// [`CheckpointError::Platform`] if the clock cannot be read; nothing is removed then.
    pub fn retain(&mut self, limits: &Retention) -> Result<Swept, CheckpointError> {
        let now = self.clock.now()?.as_unix_millis();
        let mut removed = BTreeSet::new();
        let sensitive = self.expire_sensitive(now.saturating_sub(millis(limits.sensitive_age)));
        // Age.
        let cutoff = now.saturating_sub(millis(limits.max_age));
        for edge in self.live_edges() {
            if created(edge) <= cutoff {
                removed.extend(self.expire_change(edge, false));
            }
        }
        // Count, per root.
        while let Some(edge) = self.over_count(limits.per_root) {
            removed.extend(self.expire_change(edge, false));
        }
        // Size, per volume.
        while let Some(edge) = self.over_size(limits.bytes_per_volume) {
            removed.extend(self.expire_change(edge, false));
        }
        Ok(Swept {
            removed: removed.into_iter().collect(),
            sensitive,
            next_due: self.next_due(limits),
        })
    }

    /// Removes at once every change `which` selects, with the versions their undos saved, and scrubs their paths
    /// from the tree (FR-CKP-34). Changes already expired that match are scrubbed too.
    pub fn forget(&mut self, which: &Forget) -> Swept {
        let matching: Vec<CheckpointId> = self
            .tree
            .edges()
            .filter(|edge| self.selects(which, edge))
            .map(|edge| edge.checkpoint)
            .collect();
        let mut removed = BTreeSet::new();
        for edge in matching {
            removed.extend(self.expire_change(edge, true));
        }
        Swept {
            removed: removed.into_iter().collect(),
            sensitive: 0,
            next_due: None,
        }
    }

    /// Whether `which` selects `edge`: the change's sessions (for a revert, those of the change it reverted,
    /// following reverts of reverts) hold the session, and it was made, or stepped back over, at or after the
    /// instant.
    ///
    /// A revert whose reverted change is gone from the tree (expired at the root while the revert stays, expired,
    /// on the head's path) still lists that change's paths, but its sessions are no longer known: it is selected by
    /// any session, so forget never leaves the paths behind (FR-CKP-34). Scrubbing it only makes FR-CKP-30 fail
    /// closed for the older changes it lies after.
    fn selects(&self, which: &Forget, edge: &HistoryEdge) -> bool {
        let session = which.session.is_none_or(|session| match &edge.kind {
            EdgeKind::Change { sessions, .. } => sessions.contains(&session),
            EdgeKind::Undo { of } => self.reverted_sessions(*of).map_or_else(
                || {
                    edge.expired
                        || self
                            .checkpoints
                            .get(&edge.checkpoint)
                            .is_some_and(|checkpoint| checkpoint.sessions.contains(&session))
                },
                |sessions| sessions.contains(&session),
            ),
        });
        // The versions a step back saved hold the files as they were at the undo: a change made before the instant
        // but stepped back over after it holds content from after the instant, so it is selected too.
        let since = which.since.is_none_or(|since| {
            let since = since.as_unix_millis();
            created(edge.checkpoint) >= since || edge.saved.is_some_and(|saved| created(saved) >= since)
        });
        session && since
    }

    /// The sessions of change `of`, or of the change it reverted when it is itself a revert (a redo of a revert is
    /// the undo of an undo); `None` once that change is gone from the tree. Each `undo` edge points at an older edge,
    /// so the walk is bounded by the tree's size.
    fn reverted_sessions(&self, of: CheckpointId) -> Option<&BTreeSet<SessionId>> {
        let mut of = of;
        for _ in 0..=self.tree.len() {
            match &self.tree.edge(of)?.kind {
                EdgeKind::Change { sessions, .. } => return Some(sessions),
                EdgeKind::Undo { of: older } => of = *older,
            }
        }
        None
    }

    /// Expires change `edge` in the tree and removes every checkpoint that releases, with its files. Returns them.
    fn expire_change(&mut self, edge: CheckpointId, scrub: bool) -> Vec<CheckpointId> {
        let Ok(released) = self.tree.expire(edge, scrub) else {
            return Vec::new();
        };
        for id in &released {
            if let Some(checkpoint) = self.checkpoints.remove(id) {
                remove_checkpoint_files(self.files.as_ref(), *id, &checkpoint.paths, &checkpoint.stores);
            }
            self.sizes.remove(id);
            self.irreversible.remove(id);
        }
        released
    }

    /// The changes not expired, oldest first (by the state they lead to: the order they entered the history).
    fn live_edges(&self) -> Vec<CheckpointId> {
        let mut edges: Vec<(StateId, CheckpointId)> = self
            .tree
            .edges()
            .filter(|edge| !edge.expired)
            .map(|edge| (edge.to, edge.checkpoint))
            .collect();
        edges.sort_unstable();
        edges.into_iter().map(|(_, checkpoint)| checkpoint).collect()
    }

    /// The oldest change of a root holding more than `per_root` changes, if any.
    fn over_count(&self, per_root: usize) -> Option<CheckpointId> {
        let mut by_root: BTreeMap<&CanonicalPath, Vec<CheckpointId>> = BTreeMap::new();
        for edge in self.live_edges() {
            let Some(checkpoint) = self.checkpoints.get(&edge) else {
                continue;
            };
            let roots: BTreeSet<&CanonicalPath> = checkpoint.paths.keys().chain(checkpoint.stores.keys()).collect();
            for root in roots {
                by_root.entry(root).or_default().push(edge);
            }
        }
        // `live_edges` is oldest first, so each list is too.
        by_root
            .into_values()
            .filter(|edges| edges.len() > per_root)
            .filter_map(|edges| edges.first().copied())
            .min_by_key(|edge| self.tree.edge(*edge).map(|edge| edge.to))
    }

    /// The oldest change with bytes in a store holding more than `limit` bytes, if any.
    fn over_size(&mut self, limit: u64) -> Option<CheckpointId> {
        let ids: Vec<CheckpointId> = self.checkpoints.keys().copied().collect();
        let mut totals: BTreeMap<PathBuf, u64> = BTreeMap::new();
        for id in ids {
            for (store, bytes) in self.measure(id) {
                let total = totals.entry(store).or_default();
                *total = total.saturating_add(bytes);
            }
        }
        let over: BTreeSet<PathBuf> = totals
            .into_iter()
            .filter(|(_, total)| *total > limit)
            .map(|(store, _)| store)
            .collect();
        if over.is_empty() {
            return None;
        }
        self.live_edges().into_iter().find(|edge| {
            let saved = self.tree.edge(*edge).and_then(|edge| edge.saved);
            [Some(*edge), saved].into_iter().flatten().any(|id| {
                self.sizes
                    .get(&id)
                    .is_some_and(|sizes| sizes.iter().any(|(store, bytes)| *bytes > 0 && over.contains(store)))
            })
        })
    }

    /// The bytes of checkpoint `id`'s kept copies by store, measured once and then cached.
    fn measure(&mut self, id: CheckpointId) -> BTreeMap<PathBuf, u64> {
        if let Some(sizes) = self.sizes.get(&id) {
            return sizes.clone();
        }
        let Some(checkpoint) = self.checkpoints.get(&id) else {
            return BTreeMap::new();
        };
        let mut sizes: BTreeMap<PathBuf, u64> = BTreeMap::new();
        for (root, paths) in &checkpoint.paths {
            let Some(store) = checkpoint.stores.get(root) else {
                continue;
            };
            for captured in paths.values() {
                if let StoredPreImage::Kept(copy) = &captured.pre {
                    // A copy that cannot be read counts as nothing: retention never removes a change on a guess.
                    let bytes = self.files.identity(copy).map_or(0, |identity| identity.size);
                    let total = sizes.entry(store.clone()).or_default();
                    *total = total.saturating_add(bytes);
                }
            }
        }
        self.sizes.insert(id, sizes.clone());
        sizes
    }

    /// Deletes the kept copy of every sensitive path in each checkpoint created at or before `cutoff` (Unix
    /// milliseconds), leaving the path's pre-image lost. Returns how many were deleted.
    fn expire_sensitive(&mut self, cutoff: u64) -> usize {
        let mut deleted = 0;
        let files = self.files.as_ref();
        for (id, checkpoint) in &mut self.checkpoints {
            if created(*id) > cutoff {
                continue;
            }
            let mut changed = false;
            for (path, captured) in checkpoint.paths.values_mut().flat_map(BTreeMap::iter_mut) {
                let StoredPreImage::Kept(copy) = &captured.pre else {
                    continue;
                };
                if !is_sensitive(path.as_path()) {
                    continue;
                }
                match files.remove(copy, false) {
                    Ok(()) => {}
                    // Already gone: nothing is kept, which is what is wanted.
                    Err(error) if error.is_not_found() => {}
                    // Kept as it is, so the next sweep (due at once) tries again.
                    Err(_) => continue,
                }
                captured.pre = StoredPreImage::Lost;
                changed = true;
                deleted += 1;
            }
            if changed {
                self.sizes.remove(id);
            }
        }
        deleted
    }

    /// When the next sweep is due: the earliest time a kept sensitive copy, or a change, reaches its age limit.
    fn next_due(&self, limits: &Retention) -> Option<Timestamp> {
        let sensitive = self
            .checkpoints
            .iter()
            .filter(|(_, checkpoint)| holds_sensitive(checkpoint))
            .map(|(id, _)| created(*id).saturating_add(millis(limits.sensitive_age)));
        let aged = self
            .live_edges()
            .into_iter()
            .map(|edge| created(edge).saturating_add(millis(limits.max_age)));
        let due = sensitive.chain(aged).min()?;
        Timestamp::from_unix_micros(due.saturating_mul(1000)).ok()
    }
}

/// Whether `checkpoint` keeps a copy of a sensitive file.
fn holds_sensitive(checkpoint: &Checkpoint) -> bool {
    checkpoint
        .paths
        .values()
        .flat_map(BTreeMap::iter)
        .any(|(path, captured)| matches!(captured.pre, StoredPreImage::Kept(_)) && is_sensitive(path.as_path()))
}

#[cfg(test)]
mod tests;
