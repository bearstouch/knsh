//! An in-memory filesystem with symlinks and fault injection.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::{Cursor, Read};
use std::path::{Component, Path, PathBuf};
use std::sync::Mutex;

use knsh_core::CanonicalPath;

use super::lock;
use crate::error::{Operation, PlatformError};
use crate::fs::{FileKind, Fs, Metadata, require_absolute, split_target};

/// Symlinks followed per lookup before giving up with `ELOOP`, as `MAXSYMLINKS` on macOS.
const MAX_SYMLINKS: u32 = 32;

/// Name of the temporary file an atomic replace creates in the target's directory.
const TEMP_NAME: &str = ".knsh.fake.tmp";

/// User id the fake runs as unless [`MemFs::with_uid`] says otherwise (the first user account on macOS).
pub const DEFAULT_UID: u32 = 501;

#[derive(Debug, Clone)]
enum Node {
    File { data: Vec<u8>, mode: u32 },
    Directory { mode: u32 },
    Symlink { target: PathBuf },
}

#[derive(Debug)]
struct State {
    /// Every node by absolute path. `/` always exists.
    nodes: BTreeMap<PathBuf, Node>,
    /// Pending faults: the next time a call reaches the step, it fails with the `errno` (first match, used once).
    faults: Vec<(Operation, i32)>,
    /// The user the fake runs as: owner of every node it creates.
    uid: u32,
    /// Bits cleared from the mode of new files and directories by the calls the real backend applies a umask to.
    umask: u32,
    /// Owner of each node; a node missing here is owned by `uid`.
    owners: BTreeMap<PathBuf, u32>,
    /// Extended attributes of each node, by name.
    xattrs: BTreeMap<PathBuf, BTreeMap<String, Vec<u8>>>,
}

/// An in-memory filesystem.
///
/// Paths are resolved like the kernel does: symlinks in any component are followed (the final one only where the
/// real call follows it), `..` applies after resolution, and missing or non-directory components fail with `ENOENT`
/// or `ENOTDIR`. There is no umask unless [`MemFs::set_umask`] sets one.
///
/// Every node is owned by the fake's user ([`DEFAULT_UID`] or [`MemFs::with_uid`]) unless [`MemFs::set_owner`] says
/// otherwise; like the kernel, [`Fs::set_mode`] on a node owned by someone else fails with `EPERM`.
///
/// [`MemFs::inject_fault`] makes the next call that reaches a given step fail. [`Fs::atomic_replace`] goes through
/// the same steps as the real backend (`Write`, `SyncFile`, `Rename`, `SyncDirectory`), so a test can fail any one
/// of them and check what is left on "disk".
#[derive(Debug)]
pub struct MemFs {
    state: Mutex<State>,
}

impl Default for MemFs {
    fn default() -> Self {
        Self::new()
    }
}

impl MemFs {
    /// A filesystem holding only the root directory (mode `0o755`, owned by root), running as [`DEFAULT_UID`].
    #[must_use]
    pub fn new() -> Self {
        Self::with_uid(DEFAULT_UID)
    }

    /// A filesystem holding only the root directory (mode `0o755`, owned by root), running as `uid`.
    #[must_use]
    pub fn with_uid(uid: u32) -> Self {
        let mut nodes = BTreeMap::new();
        nodes.insert(PathBuf::from("/"), Node::Directory { mode: 0o755 });
        let mut owners = BTreeMap::new();
        owners.insert(PathBuf::from("/"), 0);
        Self {
            state: Mutex::new(State {
                nodes,
                faults: Vec::new(),
                uid,
                umask: 0,
                owners,
                xattrs: BTreeMap::new(),
            }),
        }
    }

    /// The user id the fake runs as.
    #[must_use]
    pub fn uid(&self) -> u32 {
        lock(&self.state).uid
    }

    /// Sets the umask applied by [`Fs::create_dir`] and [`Fs::write`] to new entries, as the real backend's
    /// `mkdir` and `open` do. Setup helper.
    pub fn set_umask(&self, umask: u32) {
        lock(&self.state).umask = umask & 0o777;
    }

    /// Makes `path` (exactly, no symlinks followed) owned by `uid`, as if another user had created it. Setup helper.
    ///
    /// # Errors
    ///
    /// [`PlatformError::Os`] with `ENOENT` if nothing exists at `path`.
    pub fn set_owner(&self, path: &Path, uid: u32) -> Result<(), PlatformError> {
        let mut state = lock(&self.state);
        if !state.nodes.contains_key(path) {
            return Err(os(Operation::Metadata, libc::ENOENT));
        }
        state.owners.insert(path.to_path_buf(), uid);
        Ok(())
    }

    /// Makes the next call that reaches `operation` fail with `errno`. Faults queue up and each is used once.
    pub fn inject_fault(&self, operation: Operation, errno: i32) {
        lock(&self.state).faults.push((operation, errno));
    }

    /// Adds a directory and any missing parents (mode `0o755`), bypassing faults. Setup helper.
    ///
    /// # Errors
    ///
    /// As [`Fs::create_dir`] when a component exists and is not a directory.
    pub fn add_dir_all(&self, path: &Path) -> Result<(), PlatformError> {
        let mut current = PathBuf::from("/");
        for component in path.components() {
            if let Component::Normal(name) = component {
                current.push(name);
                let mut state = lock(&self.state);
                match state.nodes.get(&current) {
                    Some(Node::Directory { .. }) => {}
                    Some(_) => return Err(os(Operation::CreateDirectory, libc::ENOTDIR)),
                    None => {
                        state.nodes.insert(current.clone(), Node::Directory { mode: 0o755 });
                    }
                }
            }
        }
        Ok(())
    }

    /// Adds a symlink at `path` pointing to `target` (absolute or relative to the link's directory). Setup helper.
    ///
    /// # Errors
    ///
    /// [`PlatformError::Os`] with `EEXIST` if something exists at `path`, `ENOENT` if its parent does not.
    pub fn add_symlink(&self, path: &Path, target: &Path) -> Result<(), PlatformError> {
        let mut state = lock(&self.state);
        let resolved = resolve(&state.nodes, path, false, Operation::Write)?;
        if state.nodes.contains_key(&resolved) {
            return Err(os(Operation::Write, libc::EEXIST));
        }
        state.nodes.insert(
            resolved,
            Node::Symlink {
                target: target.to_path_buf(),
            },
        );
        Ok(())
    }

    /// The contents of the regular file at exactly `path` (no symlinks followed), if there is one.
    #[must_use]
    pub fn contents(&self, path: &Path) -> Option<Vec<u8>> {
        match lock(&self.state).nodes.get(path) {
            Some(Node::File { data, .. }) => Some(data.clone()),
            Some(Node::Directory { .. } | Node::Symlink { .. }) | None => None,
        }
    }

    /// Every path that exists, in sorted order.
    #[must_use]
    pub fn paths(&self) -> Vec<PathBuf> {
        lock(&self.state).nodes.keys().cloned().collect()
    }
}

fn os(operation: Operation, errno: i32) -> PlatformError {
    PlatformError::Os { operation, errno }
}

impl State {
    /// Owner of the node at exactly `path`.
    fn owner(&self, path: &Path) -> u32 {
        self.owners.get(path).copied().unwrap_or(self.uid)
    }

    /// Inserts a node created by the fake's user, dropping any owner or attributes left by a node it replaces.
    fn insert_new(&mut self, path: PathBuf, node: Node) {
        self.owners.remove(&path);
        self.xattrs.remove(&path);
        self.nodes.insert(path, node);
    }

    /// Fails with the first pending fault for `operation`, consuming it.
    fn check_fault(&mut self, operation: Operation) -> Result<(), PlatformError> {
        match self.faults.iter().position(|(op, _)| *op == operation) {
            Some(index) => {
                let (_, errno) = self.faults.remove(index);
                Err(os(operation, errno))
            }
            None => Ok(()),
        }
    }
}

/// Resolves `path` to the absolute path of the node it names, following symlinks in every component and also in the
/// last one when `follow_final` is set. The final component need not exist; every earlier one must be a directory.
/// Errors are reported under `operation`.
fn resolve(
    nodes: &BTreeMap<PathBuf, Node>,
    path: &Path,
    follow_final: bool,
    operation: Operation,
) -> Result<PathBuf, PlatformError> {
    require_absolute(path)?;
    let mut pending: Vec<OsString> = components(path);
    // Stack order: the next component to process is at the end.
    pending.reverse();
    let mut current = PathBuf::from("/");
    let mut hops = 0;
    while let Some(name) = pending.pop() {
        if name == ".." {
            current.pop();
            continue;
        }
        let candidate = current.join(&name);
        let is_last = pending.is_empty();
        match nodes.get(&candidate) {
            Some(Node::Symlink { target }) if !is_last || follow_final => {
                hops += 1;
                if hops > MAX_SYMLINKS {
                    return Err(os(operation, libc::ELOOP));
                }
                if target.is_absolute() {
                    current = PathBuf::from("/");
                }
                // A relative target resolves from the link's directory, which is `current`.
                pending.extend(components(target).into_iter().rev());
            }
            Some(Node::Directory { .. }) => current = candidate,
            Some(Node::File { .. } | Node::Symlink { .. }) | None if is_last => current = candidate,
            Some(Node::File { .. } | Node::Symlink { .. }) => return Err(os(operation, libc::ENOTDIR)),
            None => return Err(os(operation, libc::ENOENT)),
        }
    }
    Ok(current)
}

/// The normal and `..` components of a path; `/` and `.` carry no information for resolution.
fn components(path: &Path) -> Vec<OsString> {
    path.components()
        .filter_map(|component| match component {
            Component::Normal(name) => Some(name.to_os_string()),
            Component::ParentDir => Some(OsString::from("..")),
            Component::RootDir | Component::CurDir | Component::Prefix(_) => None,
        })
        .collect()
}

impl Fs for MemFs {
    fn open_read(&self, path: &Path) -> Result<Box<dyn Read + Send>, PlatformError> {
        let mut state = lock(&self.state);
        require_absolute(path)?;
        state.check_fault(Operation::Open)?;
        let resolved = resolve(&state.nodes, path, true, Operation::Open)?;
        match state.nodes.get(&resolved) {
            Some(Node::File { data, .. }) => Ok(Box::new(Cursor::new(data.clone()))),
            Some(Node::Directory { .. }) => Err(os(Operation::Open, libc::EISDIR)),
            Some(Node::Symlink { .. }) | None => Err(os(Operation::Open, libc::ENOENT)),
        }
    }

    fn read(&self, path: &Path, limit: u64) -> Result<Vec<u8>, PlatformError> {
        let mut state = lock(&self.state);
        require_absolute(path)?;
        state.check_fault(Operation::Open)?;
        let resolved = resolve(&state.nodes, path, true, Operation::Open)?;
        let data = match state.nodes.get(&resolved) {
            Some(Node::File { data, .. }) => data.clone(),
            Some(Node::Directory { .. }) => return Err(os(Operation::Read, libc::EISDIR)),
            Some(Node::Symlink { .. }) | None => return Err(os(Operation::Open, libc::ENOENT)),
        };
        if data.len() as u64 > limit {
            return Err(PlatformError::TooLarge { limit });
        }
        state.check_fault(Operation::Read)?;
        Ok(data)
    }

    fn write(&self, path: &Path, data: &[u8], mode: u32) -> Result<(), PlatformError> {
        let mut state = lock(&self.state);
        require_absolute(path)?;
        state.check_fault(Operation::Write)?;
        let resolved = resolve(&state.nodes, path, false, Operation::Write)?;
        let mode = match state.nodes.get(&resolved) {
            None => mode & 0o7777 & !state.umask,
            Some(Node::File { mode, .. }) => *mode,
            Some(Node::Directory { .. }) => return Err(os(Operation::Write, libc::EISDIR)),
            // Like `O_NOFOLLOW`: a final symlink is refused, not followed.
            Some(Node::Symlink { .. }) => return Err(os(Operation::Write, libc::ELOOP)),
        };
        state.nodes.insert(
            resolved,
            Node::File {
                data: data.to_vec(),
                mode,
            },
        );
        Ok(())
    }

    fn create_new(&self, path: &Path, mode: u32) -> Result<(), PlatformError> {
        let mut state = lock(&self.state);
        require_absolute(path)?;
        state.check_fault(Operation::Write)?;
        let resolved = resolve(&state.nodes, path, false, Operation::Write)?;
        // Like `O_EXCL`: any existing node, a symlink included, is refused rather than followed or truncated.
        if state.nodes.contains_key(&resolved) {
            return Err(os(Operation::Write, libc::EEXIST));
        }
        state.insert_new(
            resolved,
            Node::File {
                data: Vec::new(),
                mode: mode & 0o7777,
            },
        );
        Ok(())
    }

    fn atomic_replace(&self, path: &Path, data: &[u8], mode: u32) -> Result<(), PlatformError> {
        split_target(path)?;
        let mut state = lock(&self.state);
        let target = resolve(&state.nodes, path, false, Operation::Write)?;
        let temp = target.parent().unwrap_or(Path::new("/")).join(TEMP_NAME);

        // Step 1: create and write the temporary file.
        state.check_fault(Operation::Write)?;
        if state.nodes.contains_key(&temp) {
            return Err(os(Operation::Write, libc::EEXIST));
        }
        state.nodes.insert(
            temp.clone(),
            Node::File {
                data: data.to_vec(),
                mode: mode & 0o7777,
            },
        );

        // Steps 2 and 3: flush, then rename over the target. On failure only the temporary file is removed.
        let renamed = state.check_fault(Operation::SyncFile).and_then(|()| {
            state.check_fault(Operation::Rename)?;
            match state.nodes.get(&target) {
                Some(Node::Directory { .. }) => Err(os(Operation::Rename, libc::EISDIR)),
                Some(Node::File { .. } | Node::Symlink { .. }) | None => Ok(()),
            }
        });
        let temp_node = state.nodes.remove(&temp);
        renamed?;
        if let Some(node) = temp_node {
            state.insert_new(target, node);
        }

        // Step 4: flush the directory. The new contents are already in place, as on a real disk.
        state.check_fault(Operation::SyncDirectory)
    }

    fn create_dir(&self, path: &Path, mode: u32) -> Result<(), PlatformError> {
        let mut state = lock(&self.state);
        require_absolute(path)?;
        state.check_fault(Operation::CreateDirectory)?;
        let resolved = resolve(&state.nodes, path, false, Operation::CreateDirectory)?;
        if state.nodes.contains_key(&resolved) {
            return Err(os(Operation::CreateDirectory, libc::EEXIST));
        }
        let mode = mode & 0o7777 & !state.umask;
        state.insert_new(resolved, Node::Directory { mode });
        Ok(())
    }

    fn metadata(&self, path: &Path) -> Result<Metadata, PlatformError> {
        let mut state = lock(&self.state);
        require_absolute(path)?;
        state.check_fault(Operation::Metadata)?;
        let resolved = resolve(&state.nodes, path, false, Operation::Metadata)?;
        let uid = state.owner(&resolved);
        match state.nodes.get(&resolved) {
            Some(Node::File { data, mode }) => Ok(Metadata {
                kind: FileKind::File,
                len: data.len() as u64,
                mode: *mode,
                uid,
            }),
            Some(Node::Directory { mode }) => Ok(Metadata {
                kind: FileKind::Directory,
                len: 0,
                mode: *mode,
                uid,
            }),
            Some(Node::Symlink { target }) => Ok(Metadata {
                kind: FileKind::Symlink,
                len: target.as_os_str().len() as u64,
                mode: 0o755,
                uid,
            }),
            None => Err(os(Operation::Metadata, libc::ENOENT)),
        }
    }

    fn canonicalise(&self, path: &Path) -> Result<CanonicalPath, PlatformError> {
        let mut state = lock(&self.state);
        require_absolute(path)?;
        state.check_fault(Operation::Canonicalise)?;
        let resolved = resolve(&state.nodes, path, true, Operation::Canonicalise)?;
        if !state.nodes.contains_key(&resolved) {
            return Err(os(Operation::Canonicalise, libc::ENOENT));
        }
        Ok(CanonicalPath::new(resolved)?)
    }

    fn set_mode(&self, path: &Path, mode: u32) -> Result<(), PlatformError> {
        let mut state = lock(&self.state);
        require_absolute(path)?;
        state.check_fault(Operation::SetMode)?;
        // Like `AT_SYMLINK_NOFOLLOW`: a final symlink is the node changed, never its target.
        let resolved = resolve(&state.nodes, path, false, Operation::SetMode)?;
        if !state.nodes.contains_key(&resolved) {
            return Err(os(Operation::SetMode, libc::ENOENT));
        }
        if state.owner(&resolved) != state.uid {
            return Err(os(Operation::SetMode, libc::EPERM));
        }
        match state.nodes.get_mut(&resolved) {
            Some(Node::File { mode: current, .. } | Node::Directory { mode: current }) => *current = mode & 0o7777,
            // Symlink modes are not modelled: `metadata` always reports `0o755` for them.
            Some(Node::Symlink { .. }) | None => {}
        }
        Ok(())
    }

    fn remove_file(&self, path: &Path) -> Result<(), PlatformError> {
        let mut state = lock(&self.state);
        require_absolute(path)?;
        state.check_fault(Operation::RemoveFile)?;
        // Like `unlink`: a final symlink is removed itself, and a directory is refused.
        let resolved = resolve(&state.nodes, path, false, Operation::RemoveFile)?;
        match state.nodes.get(&resolved) {
            Some(Node::File { .. } | Node::Symlink { .. }) => {
                state.nodes.remove(&resolved);
                state.owners.remove(&resolved);
                state.xattrs.remove(&resolved);
                Ok(())
            }
            Some(Node::Directory { .. }) => Err(os(Operation::RemoveFile, libc::EPERM)),
            None => Err(os(Operation::RemoveFile, libc::ENOENT)),
        }
    }

    fn remove_dir(&self, path: &Path) -> Result<(), PlatformError> {
        let mut state = lock(&self.state);
        require_absolute(path)?;
        state.check_fault(Operation::RemoveDirectory)?;
        // Like `rmdir`: a final symlink is not followed, so it is refused as not a directory.
        let resolved = resolve(&state.nodes, path, false, Operation::RemoveDirectory)?;
        match state.nodes.get(&resolved) {
            Some(Node::Directory { .. }) => {
                let has_entries = state
                    .nodes
                    .keys()
                    .any(|other| other.parent() == Some(resolved.as_path()) && other != &resolved);
                if has_entries {
                    return Err(os(Operation::RemoveDirectory, libc::ENOTEMPTY));
                }
                state.nodes.remove(&resolved);
                state.owners.remove(&resolved);
                state.xattrs.remove(&resolved);
                Ok(())
            }
            Some(Node::File { .. } | Node::Symlink { .. }) => Err(os(Operation::RemoveDirectory, libc::ENOTDIR)),
            None => Err(os(Operation::RemoveDirectory, libc::ENOENT)),
        }
    }

    fn rename_new(&self, from: &Path, to: &Path) -> Result<(), PlatformError> {
        split_target(from)?;
        split_target(to)?;
        let mut state = lock(&self.state);
        state.check_fault(Operation::Rename)?;
        // Like `renamex_np(RENAME_EXCL)`: neither final symlink is followed, and an existing `to` is refused.
        let source = resolve(&state.nodes, from, false, Operation::Rename)?;
        let target = resolve(&state.nodes, to, false, Operation::Rename)?;
        if !state.nodes.contains_key(&source) {
            return Err(os(Operation::Rename, libc::ENOENT));
        }
        if state.nodes.contains_key(&target) {
            return Err(os(Operation::Rename, libc::EEXIST));
        }
        // Like the kernel: the target's directory must exist.
        if !matches!(
            target.parent().and_then(|parent| state.nodes.get(parent)),
            Some(Node::Directory { .. })
        ) {
            return Err(os(Operation::Rename, libc::ENOENT));
        }
        if target.starts_with(&source) {
            return Err(os(Operation::Rename, libc::EINVAL));
        }
        // The entry and, for a directory, everything under it move together, with their owners and attributes.
        let moved: Vec<PathBuf> = state
            .nodes
            .keys()
            .filter(|path| path.starts_with(&source))
            .cloned()
            .collect();
        for path in moved {
            let suffix = path.strip_prefix(&source).map(Path::to_path_buf).unwrap_or_default();
            let renamed = if suffix.as_os_str().is_empty() {
                target.clone()
            } else {
                target.join(suffix)
            };
            if let Some(node) = state.nodes.remove(&path) {
                state.nodes.insert(renamed.clone(), node);
            }
            if let Some(owner) = state.owners.remove(&path) {
                state.owners.insert(renamed.clone(), owner);
            }
            if let Some(attrs) = state.xattrs.remove(&path) {
                state.xattrs.insert(renamed, attrs);
            }
        }
        Ok(())
    }

    fn list_dir(&self, path: &Path, limit: usize) -> Result<Vec<OsString>, PlatformError> {
        let mut state = lock(&self.state);
        require_absolute(path)?;
        state.check_fault(Operation::ReadDirectory)?;
        // Like `opendir`: a final symlink is followed.
        let resolved = resolve(&state.nodes, path, true, Operation::ReadDirectory)?;
        match state.nodes.get(&resolved) {
            Some(Node::Directory { .. }) => {}
            Some(_) => return Err(os(Operation::ReadDirectory, libc::ENOTDIR)),
            None => return Err(os(Operation::ReadDirectory, libc::ENOENT)),
        }
        // `nodes` is sorted by path, so the direct children come out sorted by name.
        let names: Vec<OsString> = state
            .nodes
            .keys()
            .filter(|child| child.parent() == Some(resolved.as_path()))
            .filter_map(|child| child.file_name().map(OsString::from))
            .collect();
        if names.len() > limit {
            return Err(PlatformError::TooLarge { limit: limit as u64 });
        }
        Ok(names)
    }

    fn xattr(&self, path: &Path, name: &str, limit: usize) -> Result<Option<Vec<u8>>, PlatformError> {
        let mut state = lock(&self.state);
        require_absolute(path)?;
        if name.contains('\0') {
            return Err(PlatformError::InvalidPath);
        }
        state.check_fault(Operation::ReadAttribute)?;
        let resolved = resolve(&state.nodes, path, false, Operation::ReadAttribute)?;
        if !state.nodes.contains_key(&resolved) {
            return Err(os(Operation::ReadAttribute, libc::ENOENT));
        }
        match state.xattrs.get(&resolved).and_then(|attrs| attrs.get(name)) {
            Some(value) if value.len() > limit => Err(PlatformError::TooLarge { limit: limit as u64 }),
            Some(value) => Ok(Some(value.clone())),
            None => Ok(None),
        }
    }

    fn set_xattr(&self, path: &Path, name: &str, value: &[u8]) -> Result<(), PlatformError> {
        let mut state = lock(&self.state);
        require_absolute(path)?;
        if name.contains('\0') {
            return Err(PlatformError::InvalidPath);
        }
        state.check_fault(Operation::WriteAttribute)?;
        let resolved = resolve(&state.nodes, path, false, Operation::WriteAttribute)?;
        if !state.nodes.contains_key(&resolved) {
            return Err(os(Operation::WriteAttribute, libc::ENOENT));
        }
        state
            .xattrs
            .entry(resolved)
            .or_default()
            .insert(name.to_owned(), value.to_vec());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fs_with_state_file() -> (MemFs, PathBuf) {
        let fs = MemFs::new();
        fs.add_dir_all(Path::new("/state")).unwrap();
        let target = PathBuf::from("/state/sessions.json");
        fs.atomic_replace(&target, b"old", 0o600).unwrap();
        (fs, target)
    }

    // Failure safety (CLAUDE.md "Persistence"): an error at any step before the rename keeps the previous file and
    // leaves no temporary file behind.
    #[test]
    fn atomic_replace_keeps_previous_file_on_write_error() {
        for step in [Operation::Write, Operation::SyncFile, Operation::Rename] {
            let (fs, target) = fs_with_state_file();
            let before = fs.paths();
            fs.inject_fault(step, libc::ENOSPC);
            let error = fs.atomic_replace(&target, b"new", 0o600).unwrap_err();
            assert_eq!(
                error,
                PlatformError::Os {
                    operation: step,
                    errno: libc::ENOSPC
                }
            );
            assert_eq!(fs.contents(&target).as_deref(), Some(&b"old"[..]), "{step:?}");
            assert_eq!(fs.paths(), before, "temporary file left after {step:?}");
            // The fault was used once: the next replace succeeds.
            fs.atomic_replace(&target, b"new", 0o600).unwrap();
            assert_eq!(fs.contents(&target).as_deref(), Some(&b"new"[..]));
        }
    }

    #[test]
    fn atomic_replace_reports_directory_sync_failure_after_rename() {
        let (fs, target) = fs_with_state_file();
        fs.inject_fault(Operation::SyncDirectory, libc::EIO);
        assert_eq!(
            fs.atomic_replace(&target, b"new", 0o600).unwrap_err().errno(),
            Some(libc::EIO)
        );
        assert_eq!(fs.contents(&target).as_deref(), Some(&b"new"[..]));
    }

    #[test]
    fn atomic_replace_needs_an_existing_parent_and_sets_mode() {
        let fs = MemFs::new();
        assert!(
            fs.atomic_replace(Path::new("/missing/f"), b"x", 0o600)
                .unwrap_err()
                .is_not_found()
        );
        fs.atomic_replace(Path::new("/f"), b"x", 0o640).unwrap();
        assert_eq!(fs.metadata(Path::new("/f")).unwrap().mode, 0o640);
    }

    // FR-POL-11: the fake resolves like the kernel, including the macOS `/var` symlink.
    #[test]
    fn canonicalise_follows_symlinks_in_memory() {
        let fs = MemFs::new();
        fs.add_dir_all(Path::new("/private/var/folders/x")).unwrap();
        fs.add_symlink(Path::new("/var"), Path::new("private/var")).unwrap();
        fs.add_symlink(Path::new("/private/var/up"), Path::new("../var/folders"))
            .unwrap();
        let canonical = fs.canonicalise(Path::new("/var/up/./x/../x")).unwrap();
        assert_eq!(canonical.as_path(), Path::new("/private/var/folders/x"));
        assert!(fs.canonicalise(Path::new("/var/nope")).unwrap_err().is_not_found());

        fs.add_symlink(Path::new("/loop"), Path::new("/loop")).unwrap();
        assert_eq!(
            fs.canonicalise(Path::new("/loop")).unwrap_err().errno(),
            Some(libc::ELOOP)
        );
    }

    #[test]
    fn write_read_metadata_and_limits() {
        let fs = MemFs::new();
        let file = Path::new("/f");
        fs.write(file, b"hello", 0o600).unwrap();
        assert_eq!(fs.read(file, 5).unwrap(), b"hello");
        assert_eq!(fs.read(file, 4), Err(PlatformError::TooLarge { limit: 4 }));
        let mut text = String::new();
        fs.open_read(file).unwrap().read_to_string(&mut text).unwrap();
        assert_eq!(text, "hello");
        assert_eq!(fs.metadata(file).unwrap().len, 5);
        assert_eq!(fs.read(Path::new("relative"), 1), Err(PlatformError::InvalidPath));

        fs.add_symlink(Path::new("/link"), file).unwrap();
        assert_eq!(
            fs.write(Path::new("/link"), b"x", 0o600).unwrap_err().errno(),
            Some(libc::ELOOP)
        );
        assert_eq!(fs.read(Path::new("/link"), 10).unwrap(), b"hello");

        fs.create_dir(Path::new("/d"), 0o700).unwrap();
        assert_eq!(
            fs.create_dir(Path::new("/d"), 0o700).unwrap_err().errno(),
            Some(libc::EEXIST)
        );
        assert_eq!(
            fs.write(Path::new("/f/x"), b"", 0o600).unwrap_err().errno(),
            Some(libc::ENOTDIR)
        );
        fs.inject_fault(Operation::Read, libc::EIO);
        assert_eq!(fs.read(file, 10).unwrap_err().errno(), Some(libc::EIO));
    }

    #[test]
    fn create_new_refuses_existing_entries() {
        let fs = MemFs::new();
        fs.add_dir_all(Path::new("/state")).unwrap();
        let file = Path::new("/state/records.db");
        fs.create_new(file, 0o600).unwrap();
        assert_eq!(fs.contents(file).unwrap(), b"");
        assert_eq!(fs.metadata(file).unwrap().mode, 0o600);
        assert_eq!(fs.create_new(file, 0o600).unwrap_err().errno(), Some(libc::EEXIST));
        fs.add_symlink(Path::new("/state/link"), Path::new("/state/target"))
            .unwrap();
        assert_eq!(
            fs.create_new(Path::new("/state/link"), 0o600).unwrap_err().errno(),
            Some(libc::EEXIST)
        );
        assert!(fs.contents(Path::new("/state/target")).is_none());
    }

    #[test]
    fn owners_umask_and_set_mode_behave_like_the_kernel() {
        let fs = MemFs::with_uid(600);
        assert_eq!(fs.uid(), 600);
        assert_eq!(fs.metadata(Path::new("/")).unwrap().uid, 0);
        fs.set_umask(0o077);
        fs.create_dir(Path::new("/d"), 0o755).unwrap();
        let meta = fs.metadata(Path::new("/d")).unwrap();
        assert_eq!((meta.mode, meta.uid), (0o700, 600));
        fs.set_mode(Path::new("/d"), 0o750).unwrap();
        assert_eq!(fs.metadata(Path::new("/d")).unwrap().mode, 0o750);

        fs.set_owner(Path::new("/d"), 0).unwrap();
        assert_eq!(
            fs.set_mode(Path::new("/d"), 0o700).unwrap_err().errno(),
            Some(libc::EPERM)
        );
        assert!(fs.set_owner(Path::new("/nope"), 0).unwrap_err().is_not_found());
    }

    #[test]
    fn xattrs_round_trip_without_following_symlinks() {
        let fs = MemFs::new();
        fs.add_dir_all(Path::new("/d")).unwrap();
        fs.add_symlink(Path::new("/link"), Path::new("/d")).unwrap();
        assert_eq!(fs.xattr(Path::new("/d"), "a", 8).unwrap(), None);
        fs.set_xattr(Path::new("/link"), "a", b"on-link").unwrap();
        assert_eq!(fs.xattr(Path::new("/d"), "a", 8).unwrap(), None, "followed the symlink");
        fs.set_xattr(Path::new("/d"), "a", b"value").unwrap();
        assert_eq!(
            fs.xattr(Path::new("/d"), "a", 8).unwrap().as_deref(),
            Some(&b"value"[..])
        );
        assert_eq!(
            fs.xattr(Path::new("/d"), "a", 4),
            Err(PlatformError::TooLarge { limit: 4 })
        );
        assert!(
            fs.set_xattr(Path::new("/missing"), "a", b"")
                .unwrap_err()
                .is_not_found()
        );
    }

    // KNSH-012: removal unlinks a file or the symlink itself, never a target or a directory.
    #[test]
    fn remove_file_unlinks_entries_but_not_directories() {
        let fs = MemFs::new();
        fs.write(Path::new("/f"), b"x", 0o600).unwrap();
        fs.add_symlink(Path::new("/link"), Path::new("/f")).unwrap();
        fs.remove_file(Path::new("/link")).unwrap();
        assert_eq!(fs.contents(Path::new("/f")).unwrap(), b"x");
        fs.remove_file(Path::new("/f")).unwrap();
        assert!(fs.remove_file(Path::new("/f")).unwrap_err().is_not_found());
        fs.create_dir(Path::new("/d"), 0o700).unwrap();
        assert_eq!(fs.remove_file(Path::new("/d")).unwrap_err().errno(), Some(libc::EPERM));
        assert_eq!(fs.remove_file(Path::new("rel")), Err(PlatformError::InvalidPath));
    }

    // KNSH-080: `rmdir` removes only an empty directory, never a file or a symlink.
    #[test]
    fn remove_dir_removes_only_empty_directories() {
        let fs = MemFs::new();
        fs.add_dir_all(Path::new("/d/sub")).unwrap();
        fs.add_symlink(Path::new("/link"), Path::new("/d")).unwrap();
        fs.write(Path::new("/f"), b"x", 0o600).unwrap();
        assert_eq!(
            fs.remove_dir(Path::new("/d")).unwrap_err().errno(),
            Some(libc::ENOTEMPTY)
        );
        assert_eq!(
            fs.remove_dir(Path::new("/link")).unwrap_err().errno(),
            Some(libc::ENOTDIR)
        );
        assert_eq!(fs.remove_dir(Path::new("/f")).unwrap_err().errno(), Some(libc::ENOTDIR));
        fs.remove_dir(Path::new("/d/sub")).unwrap();
        fs.remove_dir(Path::new("/d")).unwrap();
        assert!(fs.remove_dir(Path::new("/d")).unwrap_err().is_not_found());
        assert_eq!(fs.remove_dir(Path::new("rel")), Err(PlatformError::InvalidPath));
    }

    #[test]
    fn list_dir_names_direct_children_only() {
        let fs = MemFs::new();
        fs.add_dir_all(Path::new("/d/sub")).unwrap();
        fs.write(Path::new("/d/b"), b"x", 0o600).unwrap();
        fs.write(Path::new("/d/sub/deep"), b"x", 0o600).unwrap();
        assert_eq!(fs.list_dir(Path::new("/d"), 8).unwrap(), ["b", "sub"]);
        assert_eq!(
            fs.list_dir(Path::new("/d"), 1).unwrap_err(),
            PlatformError::TooLarge { limit: 1 }
        );
        assert_eq!(
            fs.list_dir(Path::new("/d/b"), 8).unwrap_err().errno(),
            Some(libc::ENOTDIR)
        );
        assert!(fs.list_dir(Path::new("/nope"), 8).unwrap_err().is_not_found());
        fs.inject_fault(Operation::ReadDirectory, libc::EIO);
        assert_eq!(fs.list_dir(Path::new("/d"), 8).unwrap_err().errno(), Some(libc::EIO));
    }

    // KNSH-074: like `renamex_np(RENAME_EXCL)`: an existing target is refused and nothing moves; a symlink moves
    // itself; a directory moves with what it holds; an injected fault fails before anything moves.
    #[test]
    fn rename_new_moves_without_replacing() {
        let fs = MemFs::new();
        fs.add_dir_all(Path::new("/d/sub")).unwrap();
        fs.write(Path::new("/d/a"), b"a", 0o600).unwrap();
        fs.write(Path::new("/d/b"), b"b", 0o644).unwrap();
        fs.write(Path::new("/d/sub/c"), b"c", 0o600).unwrap();
        fs.add_symlink(Path::new("/d/link"), Path::new("/d/a")).unwrap();

        let refused = fs.rename_new(Path::new("/d/a"), Path::new("/d/b")).unwrap_err();
        assert_eq!(refused.errno(), Some(libc::EEXIST));
        assert_eq!(fs.contents(Path::new("/d/a")).unwrap(), b"a");
        assert_eq!(fs.contents(Path::new("/d/b")).unwrap(), b"b");

        fs.rename_new(Path::new("/d/b"), Path::new("/d/b2")).unwrap();
        assert!(fs.contents(Path::new("/d/b")).is_none());
        assert_eq!(fs.metadata(Path::new("/d/b2")).unwrap().mode, 0o644);

        fs.rename_new(Path::new("/d/link"), Path::new("/d/link2")).unwrap();
        assert_eq!(fs.metadata(Path::new("/d/link2")).unwrap().kind, FileKind::Symlink);
        assert_eq!(fs.contents(Path::new("/d/a")).unwrap(), b"a");

        fs.rename_new(Path::new("/d/sub"), Path::new("/d/sub2")).unwrap();
        assert_eq!(fs.contents(Path::new("/d/sub2/c")).unwrap(), b"c");
        assert!(fs.metadata(Path::new("/d/sub")).unwrap_err().is_not_found());

        assert!(
            fs.rename_new(Path::new("/d/none"), Path::new("/d/x"))
                .unwrap_err()
                .is_not_found()
        );
        fs.inject_fault(Operation::Rename, libc::EIO);
        assert_eq!(
            fs.rename_new(Path::new("/d/a"), Path::new("/d/x")).unwrap_err().errno(),
            Some(libc::EIO)
        );
        assert_eq!(fs.contents(Path::new("/d/a")).unwrap(), b"a");
    }
}
