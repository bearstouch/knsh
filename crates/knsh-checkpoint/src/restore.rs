//! Restore: putting a checkpoint's versions back on disk, for undo and redo (KNSH-084, FR-CKP-20 to FR-CKP-23).
//!
//! [`restore`] takes a [`Checkpoint`] and restores each path's pre-image wherever the live path still matches its
//! post-image identity. Undo restores a change's own checkpoint; redo restores the checkpoint its undo saved, whose
//! "pre-images" are the versions the undo replaced and whose "post-images" are what the undo left. One mechanism serves
//! both, and [`crate::History`] decides which checkpoint to restore.
//!
//! # Steps
//!
//! 1. **Check every path, change nothing.** The live path must match the recorded post-image: same kind, inode, size
//!    and modification time, and the same content hash where one was taken (FR-CKP-20). A folder is matched by kind
//!    and inode only, since its time moves with every entry added or removed. A mismatch is a [`RestoreConflict`];
//!    so is a version that was never captured, a folder that would be removed while it holds entries the change did
//!    not record, and a path whose folder will not exist. Any conflict refuses the whole restore, before anything is
//!    written (no partial restore). `force` overrides only identity mismatches ([`ConflictReason::forceable`]).
//!    Every folder from the root down to each path must be a real folder (not a symlink an agent swapped in), since
//!    `knshd` is not sandboxed and must never write outside the root; this is checked again before each change.
//! 2. **Save the current versions.** Each live file or symlink about to be replaced is cloned (copy-on-write, so
//!    cheap) into a new checkpoint's folder, `<store>/checkpoints/<saved id>/`, in the root's store; folders and
//!    absent paths are noted as such. These are the versions redo restores, and the copy a failed restore is rolled
//!    back from.
//! 3. **Write the journal** (below), one per store, before any live path is touched.
//! 4. **Restore**, in two passes over the paths in path order: first, deepest first, remove what must go (a path the
//!    change created, or an entry whose kind differs from the version to restore); then, shallowest first, put back
//!    folders, and write each file's old contents **into the existing file** (FR-CKP-22: same inode, so hard links
//!    and open descriptors see the restored contents), or clone it back where nothing is there. Every restored file's
//!    modification time is set to now (FR-CKP-23). A write in place checks again, on the descriptor it writes, that
//!    the file is still the one checked in step 1, so a file changed in between is never overwritten.
//! 5. **Remove the journal**, and read each restored path's identity: the saved checkpoint's post-images, which a
//!    later redo checks against.
//!
//! # Never mixed: the journal
//!
//! A write in place is not atomic, and several files cannot be replaced in one step even on one volume, so a restore
//! that fails or is interrupted part-way could leave some files new, some old, and one half-written. The journal
//! prevents that by making every failure end with every file **old** (as before the restore):
//!
//! - It is written atomically (temporary file, `fsync`, rename) to `<store>/restores/<saved id>.json` after the
//!   current versions are saved and before the first live path changes. It lists, in restore order, each path and its
//!   version before the restore: absent, a folder, or the saved copy.
//! - If a step fails while `knshd` runs, every path already touched is put back from the saved copies, with the same
//!   two passes (a half-written file is written over in full), and the journal is removed
//!   ([`CheckpointError::RolledBack`]). If putting back fails too, the journal stays
//!   ([`CheckpointError::RollbackFailed`]).
//! - If `knshd` stops part-way (a crash, a power cut), the journal is still there at the next start, and
//!   [`recover_restores`] puts **every** listed path back, then removes the journal and then the saved copies.
//!   Putting back is idempotent, so a recovery that is itself interrupted is simply run again.
//! - Only once every path is restored is the journal removed; if that removal fails, the restore is rolled back, so a
//!   later recovery can never undo a restore that was reported done.
//!
//! The journal costs one small file write per restore and per store; the saved copies are clones, which share blocks
//! with the files until either is written.
//!
//! # Limits
//!
//! The checks are by path (`lstat` of each folder, then the operation), so a folder swapped for a symlink in the
//! instant between them is still followed; an `openat` walk with `O_NOFOLLOW` closes this (the same pending fix as
//! the shadow builder's). Recovery writes the saved copies over whatever is at the listed paths: it runs before sessions start, but a human
//! edit made to such a path between the crash and the next start is overwritten. A path whose live entry is a special
//! file (socket, FIFO, device) can only be replaced under `force`, and then cannot be put back by a rollback.
//! Possibly-torn files (FR-CKP-24) are KNSH-085.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use knsh_core::{CanonicalPath, CheckpointId, ConflictReason, RestoreConflict};
use knsh_json::{Fields, Object, ToJson, Value};
use knsh_platform::{FileIdentity, FileKind, PlatformError};

use crate::capture::{CHECKPOINTS_DIR, CapturedPath, Checkpoint, PostImage, StoredPreImage};
use crate::error::CheckpointError;
use crate::identity::{HASH_LIMIT, post_image};
use crate::shadow::ShadowFiles;

/// The folder below a store that holds restore journals: `<store>/restores/<saved id>.json`.
pub const RESTORES_DIR: &str = "restores";

/// The version of the restore journal this engine writes and reads.
pub const JOURNAL_FORMAT: u64 = 1;

/// The largest journal [`recover_restores`] reads (64 MiB): far above the 65,536 paths a checkpoint can list.
const MAX_JOURNAL_LEN: u64 = 64 << 20;

/// The most journals one store is checked for at recovery.
const MAX_JOURNALS: usize = 4096;

/// The most entries a folder about to be removed is listed with, to check they are all removed too.
const MAX_FOLDER_ENTRIES: usize = 65_536;

/// `errno` values (macOS); `libc` is reserved to `knsh-platform` (NFR-SUP-02).
const EEXIST: i32 = 17;

/// What to restore and how.
#[derive(Debug, Clone, Copy)]
pub struct RestoreRequest<'a> {
    /// The checkpoint whose pre-images are restored, wherever the live path matches its post-image.
    pub from: &'a Checkpoint,
    /// The identifier of the checkpoint the current versions are saved in. It must be new.
    pub saved: CheckpointId,
    /// Restore paths whose identity no longer matches (user and authority only, FR-CKP-21; checked by the caller).
    pub force: bool,
}

/// A restore that happened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoreOutcome {
    /// The versions replaced, by root, as a checkpoint's paths: each path's pre-image is what it held before the
    /// restore (in `<store>/checkpoints/<saved>/`), its post-image what it holds after. Restoring them redoes.
    pub saved: BTreeMap<CanonicalPath, BTreeMap<CanonicalPath, CapturedPath>>,
    /// The paths restored, sorted.
    pub restored: Vec<CanonicalPath>,
    /// Whether `force` overrode at least one identity check.
    pub forced: bool,
}

/// What a path must hold after the restore (or after a rollback).
#[derive(Debug, Clone, PartialEq, Eq)]
enum Want {
    /// Nothing.
    Absent,
    /// A folder (its entries are paths of their own).
    Folder,
    /// The file or symlink `from`, a copy in the store, whose kind is `kind`.
    Copy { from: PathBuf, kind: FileKind },
    /// Unknown: what was there could not be saved (a special file, replaced under `force`). Left as it is.
    Unknown,
}

/// One path to restore.
#[derive(Debug, Clone)]
struct Step {
    root: CanonicalPath,
    want: Want,
    /// The live entry, as checked; `None` if nothing was there.
    live: Option<FileIdentity>,
    /// Write in place only while the live file is still `live` (not under `force`).
    checked: bool,
    /// What the path held before the restore: the rollback target, and the saved checkpoint's pre-image.
    before: Want,
}

/// Restores `request.from` (module documentation).
///
/// # Errors
///
/// [`CheckpointError::Conflicts`] if any path cannot be restored safely: nothing changed then.
/// [`CheckpointError::NoStore`] if a root's store is unknown, [`CheckpointError::Platform`] if a path could not be
/// checked or the current versions saved: nothing changed either. [`CheckpointError::RolledBack`] if the restore
/// failed part-way and every path was put back; [`CheckpointError::RollbackFailed`] if putting back failed too (the
/// journal is kept for [`recover_restores`]).
pub fn restore(files: &dyn ShadowFiles, request: &RestoreRequest<'_>) -> Result<RestoreOutcome, CheckpointError> {
    let (mut steps, forced) = check(files, request)?;
    let stores = stores_of(request.from, &steps)?;
    save(files, &stores, request.saved, &mut steps)?;
    if let Err(error) = write_journals(files, &stores, request.saved, &steps) {
        discard_saved(files, store_dirs(&stores), request.saved, &steps);
        return Err(error.into());
    }
    let mut touched = BTreeSet::new();
    let mut changed = None;
    let applied = apply(files, &steps, Target::Restore, &mut touched, &mut changed)
        .and_then(|()| remove_journals(files, &stores, request.saved));
    if let Err(error) = applied {
        return Err(roll_back(
            files,
            &stores,
            request.saved,
            &steps,
            &touched,
            error,
            changed,
        ));
    }
    Ok(outcome(files, steps, forced))
}

/// Puts back every restore a stopped `knshd` left part-way in `store` (module documentation, "Never mixed"): each
/// journal's paths get their version from before the restore, then the journal and the saved copies are removed.
/// Returns how many restores were put back. Call it before any session uses the store's roots.
///
/// # Errors
///
/// [`CheckpointError::Platform`] if the journals cannot be listed or a path cannot be put back (that journal stays,
/// for the next try); [`CheckpointError::Journal`] for a journal not in the engine's form (left as found).
pub fn recover_restores(files: &dyn ShadowFiles, store: &Path) -> Result<usize, CheckpointError> {
    let dir = store.join(RESTORES_DIR);
    let names = match files.list(&dir, MAX_JOURNALS) {
        Ok(names) => names,
        Err(error) if error.is_not_found() => return Ok(0),
        Err(error) => return Err(error.into()),
    };
    let mut recovered = 0;
    for name in names {
        // Only `<saved id>.json` is a journal. Anything else (such as the temporary file of a journal write a crash
        // interrupted, before any live path changed) is not, and must not block recovery.
        let is_journal = name
            .to_str()
            .and_then(|name| name.strip_suffix(".json"))
            .is_some_and(|id| id.parse::<CheckpointId>().is_ok());
        if !is_journal {
            continue;
        }
        let journal = dir.join(&name);
        let bytes = files.read_file(&journal, MAX_JOURNAL_LEN)?;
        let (saved, steps) = decode_journal(&bytes)?;
        // Which paths the stopped restore reached is unknown: every one is put back (idempotent).
        let mut touched: BTreeSet<CanonicalPath> = steps.keys().cloned().collect();
        let mut changed = None;
        apply(files, &steps, Target::Before, &mut touched, &mut changed)?;
        // The journal goes before the copies it points at: a stop in between must leave either both (recovery runs
        // again) or a leftover copy (retention removes it), never a journal whose copies are gone, which would fail
        // every later recovery.
        files.remove(&journal, false)?;
        discard_saved(files, [store], saved, &steps);
        recovered += 1;
    }
    Ok(recovered)
}

/// Removes the saved copies of checkpoint `id` (its files in `paths`) and its folder in each of `stores`, best effort:
/// a leftover is only a file in the owner-only store, which retention removes (KNSH-087).
pub(crate) fn remove_checkpoint_files(
    files: &dyn ShadowFiles,
    id: CheckpointId,
    paths: &BTreeMap<CanonicalPath, BTreeMap<CanonicalPath, CapturedPath>>,
    stores: &BTreeMap<CanonicalPath, PathBuf>,
) {
    for captured in paths.values().flat_map(BTreeMap::values) {
        if let StoredPreImage::Kept(copy) = &captured.pre {
            let _ = files.remove(copy, false);
        }
    }
    for store in store_dirs(stores) {
        let _ = files.remove(&checkpoint_dir(store, id), true);
    }
}

/// Each store of `stores` once: roots may share a store.
fn store_dirs(stores: &BTreeMap<CanonicalPath, PathBuf>) -> BTreeSet<&Path> {
    stores.values().map(PathBuf::as_path).collect()
}

/// The folder of checkpoint `id` in `store`: `<store>/checkpoints/<id>/`.
fn checkpoint_dir(store: &Path, id: CheckpointId) -> PathBuf {
    store.join(CHECKPOINTS_DIR).join(id.to_string())
}

/// The journal of the restore saving into checkpoint `saved`, in `store`: `<store>/restores/<saved>.json`.
fn journal_path(store: &Path, saved: CheckpointId) -> PathBuf {
    store.join(RESTORES_DIR).join(format!("{saved}.json"))
}

/// Step 1: every path's step, or every conflict. Changes nothing.
fn check(
    files: &dyn ShadowFiles,
    request: &RestoreRequest<'_>,
) -> Result<(BTreeMap<CanonicalPath, Step>, bool), CheckpointError> {
    let mut steps = BTreeMap::new();
    let mut conflicts = BTreeSet::new();
    let mut forced = false;
    for (root, paths) in &request.from.paths {
        for (path, captured) in paths {
            // Roots may nest: a path listed under two roots is restored once.
            if captured.change().is_none() || steps.contains_key(path) {
                continue;
            }
            let Some(want) = want_of(files, &captured.pre)? else {
                conflicts.insert(conflict(path, ConflictReason::PreImageLost));
                continue;
            };
            let live = read(files, path.as_path())?;
            if let Some(reason) = mismatch(files, path.as_path(), &captured.post, live.as_ref())? {
                if request.force && reason.forceable() {
                    forced = true;
                } else {
                    conflicts.insert(conflict(path, reason));
                    continue;
                }
            }
            // A folder that is still a folder: its entries are paths of their own, nothing to do here.
            if want == Want::Folder && live.is_some_and(|live| live.kind == FileKind::Directory) {
                continue;
            }
            steps.insert(
                path.clone(),
                Step {
                    root: root.clone(),
                    want,
                    live,
                    checked: !request.force,
                    before: Want::Unknown,
                },
            );
        }
    }
    check_structure(files, &steps, &mut conflicts)?;
    if conflicts.is_empty() {
        Ok((steps, forced))
    } else {
        Err(CheckpointError::Conflicts(conflicts.into_iter().collect()))
    }
}

/// What restoring the pre-image `pre` puts at its path, or `None` when that version is lost: never captured, or its
/// copy is gone or no longer a file or symlink, so there is nothing to restore.
fn want_of(files: &dyn ShadowFiles, pre: &StoredPreImage) -> Result<Option<Want>, CheckpointError> {
    let copy = match pre {
        StoredPreImage::NotExisted => return Ok(Some(Want::Absent)),
        StoredPreImage::Folder => return Ok(Some(Want::Folder)),
        StoredPreImage::Lost => return Ok(None),
        StoredPreImage::Kept(copy) => copy,
    };
    match files.kind(copy) {
        Ok(kind @ (FileKind::File | FileKind::Symlink)) => Ok(Some(Want::Copy {
            from: copy.clone(),
            kind,
        })),
        Ok(FileKind::Directory | FileKind::Other) => Ok(None),
        Err(error) if error.is_not_found() => Ok(None),
        Err(error) => Err(error.into()),
    }
}

/// Why the live entry does not match the post-image `post`, or `None` when it does (FR-CKP-20).
fn mismatch(
    files: &dyn ShadowFiles,
    path: &Path,
    post: &PostImage,
    live: Option<&FileIdentity>,
) -> Result<Option<ConflictReason>, CheckpointError> {
    let (expected, live) = match (post, live) {
        (PostImage::Unknown, _) => return Ok(Some(ConflictReason::Unverifiable)),
        (PostImage::Deleted, None) => return Ok(None),
        (PostImage::Deleted, Some(_)) => return Ok(Some(ConflictReason::Exists)),
        (PostImage::Present(_), None) => return Ok(Some(ConflictReason::Missing)),
        (PostImage::Present(expected), Some(live)) => (expected, live),
    };
    if expected.identity.kind != live.kind {
        return Ok(Some(ConflictReason::Changed));
    }
    // A folder's time and size move with its entries, which are checked as paths of their own.
    if live.kind == FileKind::Directory {
        return Ok((expected.identity.inode != live.inode).then_some(ConflictReason::Changed));
    }
    if expected.identity != *live {
        return Ok(Some(ConflictReason::Changed));
    }
    let Some(hash) = expected.hash else {
        return Ok(None);
    };
    // Writes through a mapping move neither size nor time (decision 17): the contents decide.
    match files.hash(path, HASH_LIMIT - 1) {
        Ok(now) => Ok((now != Some(hash)).then_some(ConflictReason::Changed)),
        Err(error) if error.is_not_found() => Ok(Some(ConflictReason::Missing)),
        Err(error) => Err(error.into()),
    }
}

/// The checks that need every step: a folder to remove must hold only entries removed too, and a path to put back
/// needs its folder (both not overridden by `force`).
fn check_structure(
    files: &dyn ShadowFiles,
    steps: &BTreeMap<CanonicalPath, Step>,
    conflicts: &mut BTreeSet<RestoreConflict>,
) -> Result<(), CheckpointError> {
    for (path, step) in steps {
        let removes_folder =
            step.live.is_some_and(|live| live.kind == FileKind::Directory) && step.want != Want::Folder;
        if removes_folder {
            let names = files.list(path.as_path(), MAX_FOLDER_ENTRIES)?;
            let all_removed = names.iter().all(|name| {
                CanonicalPath::new(path.as_path().join(name))
                    .ok()
                    .and_then(|child| steps.get(&child))
                    .is_some_and(|child| child.want == Want::Absent)
            });
            if !all_removed {
                conflicts.insert(conflict(path, ConflictReason::FolderNotEmpty));
            }
        }
        if !folders_ready(files, path, &step.root, steps)? {
            conflicts.insert(conflict(path, ConflictReason::ParentMissing));
        }
    }
    Ok(())
}

/// Whether every folder from `root` down to the one holding `path` is a real folder now (by `lstat`, so not a
/// symlink), or is put back as a folder by the restore. `knshd` is not sandboxed: a folder an agent swapped for a
/// symlink must never let a restore write, create or remove anything outside the root.
fn folders_ready(
    files: &dyn ShadowFiles,
    path: &CanonicalPath,
    root: &CanonicalPath,
    steps: &BTreeMap<CanonicalPath, Step>,
) -> Result<bool, CheckpointError> {
    let Some(folders) = folders_down_to(root.as_path(), path.as_path()) else {
        return Ok(false);
    };
    for folder in folders {
        let restored_as_folder = CanonicalPath::new(&folder)
            .ok()
            .and_then(|folder| steps.get(&folder))
            .is_some_and(|step| step.want == Want::Folder);
        if !restored_as_folder && !is_folder(files, &folder)? {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Whether every folder from `root` down to the one holding `path` is a real folder now: checked again right before
/// each change of `path` ([`folders_ready`]), since an agent may have swapped one for a symlink since step 1.
fn inside_root(files: &dyn ShadowFiles, root: &Path, path: &Path) -> Result<(), PlatformError> {
    let folders = folders_down_to(root, path).ok_or(PlatformError::UnexpectedKind)?;
    for folder in folders {
        if !is_folder(files, &folder)? {
            return Err(PlatformError::UnexpectedKind);
        }
    }
    Ok(())
}

/// Every folder from `root` down to the one holding `path`, shallowest first (`root` alone when `path` is `root` or
/// directly in it); `None` if `path` is not at or below `root`.
fn folders_down_to(root: &Path, path: &Path) -> Option<Vec<PathBuf>> {
    let relative = path.strip_prefix(root).ok()?;
    let mut names: Vec<_> = relative.components().collect();
    // The last name is `path` itself, not one of its folders.
    names.pop();
    let mut folder = root.to_path_buf();
    let mut folders = vec![folder.clone()];
    for name in names {
        folder.push(name);
        folders.push(folder.clone());
    }
    Some(folders)
}

/// Whether `path` itself is a folder (`lstat`: a symlink to one is not).
fn is_folder(files: &dyn ShadowFiles, path: &Path) -> Result<bool, PlatformError> {
    Ok(read(files, path)?.is_some_and(|live| live.kind == FileKind::Directory))
}

/// The store of each root that has steps.
fn stores_of(
    from: &Checkpoint,
    steps: &BTreeMap<CanonicalPath, Step>,
) -> Result<BTreeMap<CanonicalPath, PathBuf>, CheckpointError> {
    let roots: BTreeSet<&CanonicalPath> = steps.values().map(|step| &step.root).collect();
    roots
        .into_iter()
        .map(|root| {
            from.stores
                .get(root)
                .map(|store| (root.clone(), store.clone()))
                .ok_or(CheckpointError::NoStore)
        })
        .collect()
}

/// Step 2: saves what each path holds now into the saved checkpoint's folder (module documentation). On error,
/// whatever was saved is removed and nothing else changed.
fn save(
    files: &dyn ShadowFiles,
    stores: &BTreeMap<CanonicalPath, PathBuf>,
    saved: CheckpointId,
    steps: &mut BTreeMap<CanonicalPath, Step>,
) -> Result<(), CheckpointError> {
    let result = save_each(files, stores, saved, steps);
    if result.is_err() {
        discard_saved(files, store_dirs(stores), saved, steps);
    }
    result
}

/// Sets each step's `before` and clones each live file or symlink into the saved checkpoint's folder. Stops at the
/// first error, leaving what was saved for [`save`] to discard.
fn save_each(
    files: &dyn ShadowFiles,
    stores: &BTreeMap<CanonicalPath, PathBuf>,
    saved: CheckpointId,
    steps: &mut BTreeMap<CanonicalPath, Step>,
) -> Result<(), CheckpointError> {
    let mut made = BTreeSet::new();
    let mut count = 0u64;
    for (path, step) in steps.iter_mut() {
        step.before = match step.live.map(|live| live.kind) {
            None => Want::Absent,
            Some(FileKind::Directory) => Want::Folder,
            // Holds nothing that can be copied back; only `force` gets here (it never matches a post-image).
            Some(FileKind::Other) => Want::Unknown,
            Some(kind @ (FileKind::File | FileKind::Symlink)) => {
                let store = stores.get(&step.root).ok_or(CheckpointError::NoStore)?;
                let folder = checkpoint_dir(store, saved);
                if made.insert(folder.clone()) {
                    make_dirs(files, &[store.join(CHECKPOINTS_DIR), folder.clone()])?;
                }
                let copy = folder.join(count.to_string());
                count += 1;
                files.clone_file(path.as_path(), &copy)?;
                Want::Copy { from: copy, kind }
            }
        };
    }
    Ok(())
}

/// Removes the saved copies of `steps` and the saved checkpoint's folder in each of `stores`: the restore did not
/// happen, or was put back.
fn discard_saved<'a>(
    files: &dyn ShadowFiles,
    stores: impl IntoIterator<Item = &'a Path>,
    saved: CheckpointId,
    steps: &BTreeMap<CanonicalPath, Step>,
) {
    for step in steps.values() {
        if let Want::Copy { from, .. } = &step.before {
            let _ = files.remove(from, false);
        }
    }
    for store in stores {
        let _ = files.remove(&checkpoint_dir(store, saved), true);
    }
}

/// Which side of each step [`apply`] brings about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Target {
    /// The version restored (`want`).
    Restore,
    /// The version before the restore (`before`): a rollback or a recovery.
    Before,
}

/// Makes every path hold its `target` version, in the two passes of the module documentation. Each path is added to
/// `touched` before anything is done to it, so a rollback knows what may have changed; a path where nothing was
/// done after all (its write found it changed, its clone found something there) is taken out again, so a rollback
/// never puts back over what someone else left there. `changed` names the path a [`PlatformError::Changed`] came
/// from.
fn apply(
    files: &dyn ShadowFiles,
    steps: &BTreeMap<CanonicalPath, Step>,
    target: Target,
    touched: &mut BTreeSet<CanonicalPath>,
    changed: &mut Option<CanonicalPath>,
) -> Result<(), PlatformError> {
    let want = |step: &Step| match target {
        Target::Restore => step.want.clone(),
        Target::Before => step.before.clone(),
    };
    // Children sort after their folder: removals deepest first, so a folder is empty when its turn comes.
    for (path, step) in steps.iter().rev() {
        if target == Target::Before && !touched.contains(path) {
            continue;
        }
        let want = want(step);
        let Some(live) = read(files, path.as_path())? else {
            continue;
        };
        let keep = match &want {
            Want::Absent => false,
            Want::Folder => live.kind == FileKind::Directory,
            // Only a regular file over a regular file is written in place; a symlink cannot be.
            Want::Copy { kind, .. } => *kind == FileKind::File && live.kind == FileKind::File,
            Want::Unknown => true,
        };
        if !keep {
            inside_root(files, step.root.as_path(), path.as_path())?;
            touched.insert(path.clone());
            remove_if_present(files, path.as_path(), live.kind == FileKind::Directory)?;
        }
    }
    // Folders first: a path sorts after the folder holding it.
    for (path, step) in steps {
        if target == Target::Before && !touched.contains(path) {
            continue;
        }
        match want(step) {
            Want::Absent | Want::Unknown => {}
            Want::Folder => {
                if read(files, path.as_path())?.is_none() {
                    inside_root(files, step.root.as_path(), path.as_path())?;
                    touched.insert(path.clone());
                    make_dirs(files, std::slice::from_ref(&path.as_path().to_path_buf()))?;
                }
            }
            Want::Copy { from, .. } => {
                inside_root(files, step.root.as_path(), path.as_path())?;
                // Only a path this pass touches first may be taken out again below: one the first pass removed
                // must be put back by a rollback.
                let first = touched.insert(path.clone());
                if read(files, path.as_path())?.is_some() {
                    // Still the file checked in step 1, unless forced or rolling back.
                    let expect = step.live.as_ref().filter(|_| target == Target::Restore && step.checked);
                    match files.write_in_place(&from, path.as_path(), expect) {
                        Ok(()) => {}
                        Err(PlatformError::Changed) => {
                            // Nothing was written: the path is as someone else left it, not ours to put back.
                            if first {
                                touched.remove(path);
                            }
                            *changed = Some(path.clone());
                            return Err(PlatformError::Changed);
                        }
                        Err(error) => return Err(error),
                    }
                } else {
                    if let Err(error) = files.clone_file(&from, path.as_path()) {
                        // A failed clone leaves nothing at the path (`ShadowFiles::clone_file`): whatever is there
                        // now (something created since the check) is someone else's, never removed by a rollback.
                        if first {
                            touched.remove(path);
                        }
                        return Err(error);
                    }
                    // A clone keeps the copy's old time; build tools must see the file as changed (FR-CKP-23).
                    files.touch(path.as_path())?;
                }
            }
        }
    }
    Ok(())
}

/// After a failed restore: puts every touched path back, then removes the journals and the saved copies. `changed`
/// is the path whose write found it changed since its check, if that is why the restore failed.
fn roll_back(
    files: &dyn ShadowFiles,
    stores: &BTreeMap<CanonicalPath, PathBuf>,
    saved: CheckpointId,
    steps: &BTreeMap<CanonicalPath, Step>,
    touched: &BTreeSet<CanonicalPath>,
    error: PlatformError,
    changed: Option<CanonicalPath>,
) -> CheckpointError {
    let mut touched = touched.clone();
    if apply(files, steps, Target::Before, &mut touched, &mut None).is_err() {
        // The journal stays: recovery puts every path back.
        return CheckpointError::RollbackFailed(error);
    }
    if remove_journals(files, stores, saved).is_err() {
        // Every path is back; a recovery would put them back again, which changes nothing. The copies stay for it.
        return CheckpointError::RolledBack(error);
    }
    discard_saved(files, store_dirs(stores), saved, steps);
    // A file changed between its check and its write: report it like a conflict found in step 1. Named by the write
    // that found it: the paths put back by the rollback have new times too, so a fresh look would blame them.
    match changed {
        Some(path) if error == PlatformError::Changed => {
            CheckpointError::Conflicts(vec![conflict(&path, ConflictReason::Changed)])
        }
        Some(_) | None => CheckpointError::RolledBack(error),
    }
}

/// Step 5: the saved checkpoint (what each path held before, and holds now) and the paths restored.
fn outcome(files: &dyn ShadowFiles, steps: BTreeMap<CanonicalPath, Step>, forced: bool) -> RestoreOutcome {
    let restored = steps.keys().cloned().collect();
    let mut saved: BTreeMap<CanonicalPath, BTreeMap<CanonicalPath, CapturedPath>> = BTreeMap::new();
    for (path, step) in steps {
        // Unknown if it cannot be read: a redo then refuses the path as unverifiable rather than trust a guess.
        let post = post_image(files, path.as_path());
        let pre = match step.before {
            Want::Absent => StoredPreImage::NotExisted,
            Want::Folder => StoredPreImage::Folder,
            Want::Copy { from, .. } => StoredPreImage::Kept(from),
            Want::Unknown => StoredPreImage::Lost,
        };
        saved
            .entry(step.root)
            .or_default()
            .insert(path, CapturedPath { pre, post });
    }
    RestoreOutcome {
        saved,
        restored,
        forced,
    }
}

/// The identity at `path` (`lstat`), `None` if nothing is there.
fn read(files: &dyn ShadowFiles, path: &Path) -> Result<Option<FileIdentity>, PlatformError> {
    match files.identity(path) {
        Ok(identity) => Ok(Some(identity)),
        Err(error) if error.is_not_found() => Ok(None),
        Err(error) => Err(error),
    }
}

/// Removes `path` (a folder, and what it holds, if `recursive`); already gone is fine, since recovery and rollback
/// repeat removals a stopped restore may have done.
fn remove_if_present(files: &dyn ShadowFiles, path: &Path, recursive: bool) -> Result<(), PlatformError> {
    match files.remove(path, recursive) {
        Ok(()) => Ok(()),
        Err(error) if error.is_not_found() => Ok(()),
        Err(error) => Err(error),
    }
}

/// Creates each folder of `dirs` in order, accepting one that exists only if it is a real folder.
fn make_dirs(files: &dyn ShadowFiles, dirs: &[PathBuf]) -> Result<(), PlatformError> {
    for dir in dirs {
        match files.make_dir(dir) {
            Ok(()) => {}
            Err(PlatformError::Os { errno: EEXIST, .. }) if matches!(files.kind(dir), Ok(FileKind::Directory)) => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn conflict(path: &CanonicalPath, reason: ConflictReason) -> RestoreConflict {
    RestoreConflict {
        path: path.clone(),
        reason,
    }
}

/// Step 3: one journal per store, listing the steps of its roots.
fn write_journals(
    files: &dyn ShadowFiles,
    stores: &BTreeMap<CanonicalPath, PathBuf>,
    saved: CheckpointId,
    steps: &BTreeMap<CanonicalPath, Step>,
) -> Result<(), PlatformError> {
    let mut written: Vec<PathBuf> = Vec::new();
    for store in store_dirs(stores) {
        let mine = steps
            .iter()
            .filter(|(_, step)| stores.get(&step.root).map(PathBuf::as_path) == Some(store));
        let bytes = encode_journal(saved, mine).map_err(|_| PlatformError::InvalidPath)?;
        let dir = store.join(RESTORES_DIR);
        let journal = journal_path(store, saved);
        // Nothing is touched yet: a journal left behind would point recovery at saved copies about to be discarded.
        let result = make_dirs(files, std::slice::from_ref(&dir)).and_then(|()| files.write_file(&journal, &bytes));
        if let Err(error) = result {
            for journal in written {
                let _ = files.remove(&journal, false);
            }
            return Err(error);
        }
        written.push(journal);
    }
    Ok(())
}

/// Step 5: removes the journals; the restore is then done.
fn remove_journals(
    files: &dyn ShadowFiles,
    stores: &BTreeMap<CanonicalPath, PathBuf>,
    saved: CheckpointId,
) -> Result<(), PlatformError> {
    for store in store_dirs(stores) {
        remove_if_present(files, &journal_path(store, saved), false)?;
    }
    Ok(())
}

/// The journal: `{"format": 1, "checkpoint": "<saved id>", "steps": [{"root", "path", "before", "copy"}]}`, steps in path
/// order, `before` one of `absent`, `folder`, `file`, `symlink` (with `copy`, the saved copy) or `unknown`.
fn encode_journal<'a>(
    saved: CheckpointId,
    steps: impl Iterator<Item = (&'a CanonicalPath, &'a Step)>,
) -> Result<Vec<u8>, knsh_json::JsonError> {
    let mut list = Vec::new();
    for (path, step) in steps {
        let (before, copy) = match &step.before {
            Want::Absent => ("absent", Value::Null),
            Want::Folder => ("folder", Value::Null),
            Want::Unknown => ("unknown", Value::Null),
            Want::Copy { from, kind } => (
                if *kind == FileKind::Symlink { "symlink" } else { "file" },
                Value::String(text(from)?),
            ),
        };
        let entry = Object::new()
            .with("root", text(step.root.as_path())?)?
            .with("path", text(path.as_path())?)?
            .with("before", before)?
            .with("copy", copy)?;
        list.push(Value::Object(entry));
    }
    let journal = Object::new()
        .with("format", JOURNAL_FORMAT.to_json()?)?
        .with("checkpoint", saved.to_string())?
        .with("steps", Value::Array(list))?;
    knsh_json::write(&Value::Object(journal)).map(String::into_bytes)
}

/// `path` as journal text. APFS names are UTF-8; anything else cannot be written, and the restore does not start.
fn text(path: &Path) -> Result<String, knsh_json::JsonError> {
    path.to_str()
        .map(str::to_owned)
        .ok_or(knsh_json::JsonError::OutOfRange { field: Some("path") })
}

/// Reads a journal [`encode_journal`] wrote: the saved checkpoint and each path's version before the restore.
fn decode_journal(bytes: &[u8]) -> Result<(CheckpointId, BTreeMap<CanonicalPath, Step>), CheckpointError> {
    let corrupt = |_| CheckpointError::Journal;
    let len = usize::try_from(MAX_JOURNAL_LEN).unwrap_or(usize::MAX);
    let value = knsh_json::parse(bytes, len).map_err(corrupt)?;
    let mut fields = Fields::new(&value).map_err(corrupt)?;
    let format: u64 = fields.required("format").map_err(corrupt)?;
    if format != JOURNAL_FORMAT {
        // Newer or unknown: left as found, never guessed at.
        return Err(CheckpointError::Journal);
    }
    let saved: String = fields.required("checkpoint").map_err(corrupt)?;
    let saved: CheckpointId = saved.parse().map_err(|_| CheckpointError::Journal)?;
    let list: Vec<Value> = fields.required("steps").map_err(corrupt)?;
    fields.finish_closed().map_err(corrupt)?;
    let mut steps = BTreeMap::new();
    for entry in &list {
        let mut fields = Fields::new(entry).map_err(corrupt)?;
        let root: String = fields.required("root").map_err(corrupt)?;
        let path: String = fields.required("path").map_err(corrupt)?;
        let before: String = fields.required("before").map_err(corrupt)?;
        let copy: Option<String> = fields.required("copy").map_err(corrupt)?;
        fields.finish_closed().map_err(corrupt)?;
        let root = CanonicalPath::new(root).map_err(|_| CheckpointError::Journal)?;
        let path = CanonicalPath::new(path).map_err(|_| CheckpointError::Journal)?;
        if !path.as_path().starts_with(root.as_path()) {
            return Err(CheckpointError::Journal);
        }
        let before = match (before.as_str(), copy) {
            ("absent", None) => Want::Absent,
            ("folder", None) => Want::Folder,
            ("unknown", None) => Want::Unknown,
            ("file", Some(copy)) => Want::Copy {
                from: PathBuf::from(copy),
                kind: FileKind::File,
            },
            ("symlink", Some(copy)) => Want::Copy {
                from: PathBuf::from(copy),
                kind: FileKind::Symlink,
            },
            _ => return Err(CheckpointError::Journal),
        };
        let step = Step {
            root,
            want: Want::Unknown,
            live: None,
            checked: false,
            before,
        };
        if steps.insert(path, step).is_some() {
            return Err(CheckpointError::Journal);
        }
    }
    Ok((saved, steps))
}

#[cfg(test)]
pub(crate) mod tests;
