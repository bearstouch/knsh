//! Deterministic fakes for checkpoint tests (KNSH-079, KNSH-080, KNSH-082). Built only for tests and with the `testing` feature,
//! which other crates enable in their `[dev-dependencies]` alone, so no fake reaches a shipped binary.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::{Condvar, Mutex, MutexGuard, PoisonError};

use knsh_core::{Attribution, CanonicalPath, CheckpointId, RecordId, SessionId};
use knsh_platform::{ContentHash, FileIdentity, FileKind, ModifiedTime, Operation, PlatformError};

use crate::attribution::EdgeId;
use crate::capture::{CHECKPOINTS_DIR, CapturedPath, Checkpoint, StoredPreImage};
use crate::identity::post_image;
use crate::shadow::ShadowFiles;

/// `errno` values (macOS); `libc` is reserved to `knsh-platform` (NFR-SUP-02).
const EPERM: i32 = 1;
const ENOENT: i32 = 2;
const EEXIST: i32 = 17;
const ENOTDIR: i32 = 20;
const ENOTEMPTY: i32 = 66;

/// One entry of a [`FakeTree`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FakeNode {
    /// A folder.
    Dir,
    /// A regular file with its contents.
    File(Vec<u8>),
    /// A symlink with its target text.
    Symlink(PathBuf),
    /// A socket, FIFO or device.
    Special,
}

impl FakeNode {
    fn kind(&self) -> FileKind {
        match self {
            Self::Dir => FileKind::Directory,
            Self::File(_) => FileKind::File,
            Self::Symlink(_) => FileKind::Symlink,
            Self::Special => FileKind::Other,
        }
    }
}

#[derive(Debug, Default)]
struct State {
    nodes: BTreeMap<PathBuf, FakeNode>,
    /// Each node's modification "time": a counter bumped whenever the test writes a node, copied by a clone (as an
    /// APFS clone keeps `mtime`), so a changed live file differs from its shadow copy.
    modified: BTreeMap<PathBuf, i64>,
    /// The last modification counter handed out.
    tick: i64,
    /// Every path removed through [`ShadowFiles::remove`], in order.
    removed: Vec<PathBuf>,
    /// `errno` a clone of a path fails with.
    clone_failures: BTreeMap<PathBuf, i32>,
    /// Every folder listed, in order.
    listed: Vec<PathBuf>,
    clones: usize,
    /// `errno` a [`ShadowFiles::rename_new`] from a path fails with.
    rename_failures: BTreeMap<PathBuf, i32>,
    /// Every successful [`ShadowFiles::rename_new`], in order.
    renames: Vec<(PathBuf, PathBuf)>,
    /// Every path hashed, in order.
    hashed: Vec<PathBuf>,
    /// `errno` a hash of a path fails with.
    hash_failures: BTreeMap<PathBuf, i32>,
    /// While set, clones wait until [`FakeTree::release`].
    held: bool,
    /// Each entry's inode. Hard links ([`FakeTree::link`]) share one, and a write to any of them is seen by all.
    inodes: BTreeMap<PathBuf, u64>,
    /// The last inode handed out.
    next_inode: u64,
    /// `errno` a [`ShadowFiles::write_in_place`] into a path fails with, after writing part of the file (a torn
    /// write); also makes [`ShadowFiles::write_file`] of the path fail, without writing.
    write_failures: BTreeMap<PathBuf, (i32, bool)>,
    /// Every successful [`ShadowFiles::write_in_place`], `(src, dst)`, in order.
    writes: Vec<(PathBuf, PathBuf)>,
}

/// An in-memory file tree implementing [`ShadowFiles`]. `/` always exists. Clones copy the node and its modification
/// time (a symlink stays a symlink, its target is never resolved). [`FakeTree::hold`] makes clones wait, so a test can
/// observe a build in progress. [`FakeTree::remove_all`] and [`FakeTree::rename`] change the tree as another process
/// would.
#[derive(Debug)]
pub struct FakeTree {
    state: Mutex<State>,
    released: Condvar,
}

impl Default for FakeTree {
    fn default() -> Self {
        Self::new()
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

fn os(operation: Operation, errno: i32) -> PlatformError {
    PlatformError::Os { operation, errno }
}

impl State {
    /// Inserts `node` at `path` with a new modification time. An existing entry is written in place: it keeps its
    /// inode, and every hard link to it sees the write. A new entry gets a new inode.
    fn put(&mut self, path: &Path, node: FakeNode) {
        self.tick += 1;
        let tick = self.tick;
        let inode = match self.inodes.get(path) {
            Some(inode) if self.nodes.contains_key(path) => *inode,
            _ => self.new_inode(),
        };
        self.inodes.insert(path.to_path_buf(), inode);
        let links: Vec<PathBuf> = self
            .inodes
            .iter()
            .filter(|(link, other)| **other == inode && link.as_path() != path)
            .map(|(link, _)| link.clone())
            .collect();
        for link in links {
            self.modified.insert(link.clone(), tick);
            self.nodes.insert(link, node.clone());
        }
        self.modified.insert(path.to_path_buf(), tick);
        self.nodes.insert(path.to_path_buf(), node);
    }

    fn new_inode(&mut self) -> u64 {
        self.next_inode += 1;
        self.next_inode
    }

    /// Removes `path` and everything below it.
    fn drop_below(&mut self, path: &Path) {
        self.nodes.retain(|other, _| !other.starts_with(path));
        self.modified.retain(|other, _| !other.starts_with(path));
        self.inodes.retain(|other, _| !other.starts_with(path));
    }
}

impl FakeTree {
    /// A tree holding only `/`.
    #[must_use]
    pub fn new() -> Self {
        let mut nodes = BTreeMap::new();
        nodes.insert(PathBuf::from("/"), FakeNode::Dir);
        Self {
            state: Mutex::new(State {
                nodes,
                ..State::default()
            }),
            released: Condvar::new(),
        }
    }

    /// Adds `node` at `path`, creating missing parent folders.
    pub fn add(&self, path: impl AsRef<Path>, node: FakeNode) {
        let path = path.as_ref();
        let mut state = lock(&self.state);
        for ancestor in path.ancestors().skip(1) {
            if !state.nodes.contains_key(ancestor) {
                state.put(ancestor, FakeNode::Dir);
            }
        }
        state.put(path, node);
    }

    /// Removes `path` and everything below it, as another process would.
    pub fn remove_all(&self, path: impl AsRef<Path>) {
        lock(&self.state).drop_below(path.as_ref());
    }

    /// Moves `from` (and everything below it) to `to`, replacing whatever was there, keeping modification times, as
    /// `rename(2)` does.
    pub fn rename(&self, from: impl AsRef<Path>, to: impl AsRef<Path>) {
        let (from, to) = (from.as_ref(), to.as_ref());
        let mut state = lock(&self.state);
        state.drop_below(to);
        let moved: Vec<(PathBuf, FakeNode, i64, Option<u64>)> = state
            .nodes
            .iter()
            .filter(|(path, _)| path.starts_with(from))
            .map(|(path, node)| {
                let modified = state.modified.get(path).copied().unwrap_or_default();
                (path.clone(), node.clone(), modified, state.inodes.get(path).copied())
            })
            .collect();
        state.drop_below(from);
        for (path, node, modified, inode) in moved {
            let Ok(rest) = path.strip_prefix(from) else { continue };
            let target = if rest.as_os_str().is_empty() {
                to.to_path_buf()
            } else {
                to.join(rest)
            };
            state.modified.insert(target.clone(), modified);
            if let Some(inode) = inode {
                state.inodes.insert(target.clone(), inode);
            }
            state.nodes.insert(target, node);
        }
    }

    /// Every path removed through [`ShadowFiles::remove`] so far, in order.
    #[must_use]
    pub fn removed(&self) -> Vec<PathBuf> {
        lock(&self.state).removed.clone()
    }

    /// Every entry at or below `dir`, relative to it, with its node: what a test compares a shadow with its root by.
    #[must_use]
    pub fn snapshot(&self, dir: impl AsRef<Path>) -> BTreeMap<PathBuf, FakeNode> {
        let dir = dir.as_ref();
        lock(&self.state)
            .nodes
            .iter()
            .filter_map(|(path, node)| {
                let relative = path.strip_prefix(dir).ok()?;
                (!relative.as_os_str().is_empty()).then(|| (relative.to_path_buf(), node.clone()))
            })
            .collect()
    }

    /// Adds a folder at `path`.
    pub fn add_dir(&self, path: impl AsRef<Path>) {
        self.add(path, FakeNode::Dir);
    }

    /// Adds a file at `path` holding `contents`.
    pub fn add_file(&self, path: impl AsRef<Path>, contents: &[u8]) {
        self.add(path, FakeNode::File(contents.to_vec()));
    }

    /// The node at `path`, if any.
    #[must_use]
    pub fn node(&self, path: impl AsRef<Path>) -> Option<FakeNode> {
        lock(&self.state).nodes.get(path.as_ref()).cloned()
    }

    /// Every path at or below `dir`, sorted, relative to it ("" for `dir` itself).
    #[must_use]
    pub fn paths_below(&self, dir: impl AsRef<Path>) -> Vec<PathBuf> {
        let dir = dir.as_ref();
        lock(&self.state)
            .nodes
            .keys()
            .filter_map(|path| path.strip_prefix(dir).ok().map(Path::to_path_buf))
            .collect()
    }

    /// Makes a clone of `src` fail with `errno`.
    pub fn fail_clone(&self, src: impl AsRef<Path>, errno: i32) {
        lock(&self.state)
            .clone_failures
            .insert(src.as_ref().to_path_buf(), errno);
    }

    /// Every folder listed so far, in order.
    #[must_use]
    pub fn listed(&self) -> Vec<PathBuf> {
        lock(&self.state).listed.clone()
    }

    /// Successful clones so far.
    #[must_use]
    pub fn clones(&self) -> usize {
        lock(&self.state).clones
    }

    /// Makes a [`ShadowFiles::rename_new`] from `from` fail with `errno` (KNSH-082: a pre-image that cannot be moved).
    pub fn fail_rename(&self, from: impl AsRef<Path>, errno: i32) {
        lock(&self.state)
            .rename_failures
            .insert(from.as_ref().to_path_buf(), errno);
    }

    /// Makes a hash of `path` fail with `errno` (KNSH-082: a post-image identity that cannot be read).
    pub fn fail_hash(&self, path: impl AsRef<Path>, errno: i32) {
        lock(&self.state)
            .hash_failures
            .insert(path.as_ref().to_path_buf(), errno);
    }

    /// Every successful [`ShadowFiles::rename_new`] so far, `(from, to)`, in order.
    #[must_use]
    pub fn renames(&self) -> Vec<(PathBuf, PathBuf)> {
        lock(&self.state).renames.clone()
    }

    /// Every path hashed so far, in order.
    #[must_use]
    pub fn hashed(&self) -> Vec<PathBuf> {
        lock(&self.state).hashed.clone()
    }

    /// The digest [`ShadowFiles::hash`] gives `contents`: not SHA-256, but distinct for distinct test contents.
    #[must_use]
    pub fn digest_of(contents: &[u8]) -> ContentHash {
        // FNV-1a over the contents, spread over the 32 bytes with the length mixed in.
        let mut state: u64 = 0xcbf2_9ce4_8422_2325;
        for byte in contents {
            state = (state ^ u64::from(*byte)).wrapping_mul(0x0100_0000_01b3);
        }
        let mut digest = [0u8; 32];
        let len = contents.len() as u64;
        for (index, chunk) in digest.as_chunks_mut::<8>().0.iter_mut().enumerate() {
            let word = state.rotate_left(u32::try_from(index * 13).unwrap_or(0)) ^ len.wrapping_mul(index as u64 + 1);
            chunk.copy_from_slice(&word.to_le_bytes());
        }
        ContentHash::from_bytes(digest)
    }

    /// Makes later clones wait until [`FakeTree::release`].
    pub fn hold(&self) {
        lock(&self.state).held = true;
    }

    /// Lets waiting and later clones proceed.
    pub fn release(&self) {
        lock(&self.state).held = false;
        self.released.notify_all();
    }

    /// Replaces the entry at `path` with a new file holding `contents`, as an editor that writes a new file and
    /// renames it over the old one does (`sed -i`): a new inode, and the old one's hard links keep the old contents.
    pub fn replace_file(&self, path: impl AsRef<Path>, contents: &[u8]) {
        let path = path.as_ref();
        let mut state = lock(&self.state);
        state.inodes.remove(path);
        state.nodes.remove(path);
        state.put(path, FakeNode::File(contents.to_vec()));
    }

    /// Adds the hard link `new` to the existing entry `existing`: both share one inode and contents. Does nothing if
    /// `existing` does not exist.
    pub fn link(&self, existing: impl AsRef<Path>, new: impl AsRef<Path>) {
        let (existing, new) = (existing.as_ref(), new.as_ref());
        let mut state = lock(&self.state);
        let (Some(node), Some(inode)) = (state.nodes.get(existing).cloned(), state.inodes.get(existing).copied())
        else {
            return;
        };
        let modified = state.modified.get(existing).copied().unwrap_or_default();
        state.nodes.insert(new.to_path_buf(), node);
        state.inodes.insert(new.to_path_buf(), inode);
        state.modified.insert(new.to_path_buf(), modified);
    }

    /// Opens `path` as a process would: the descriptor names its inode, whatever later happens to the path. `None` if
    /// nothing is there.
    #[must_use]
    pub fn open(&self, path: impl AsRef<Path>) -> Option<FakeDescriptor> {
        lock(&self.state).inodes.get(path.as_ref()).copied().map(FakeDescriptor)
    }

    /// What a read through `descriptor` returns now: the contents of its inode while any path still names it, or
    /// `None` once none does (the fake keeps no unlinked inodes, so a test sees that the file was replaced).
    #[must_use]
    pub fn read(&self, descriptor: FakeDescriptor) -> Option<Vec<u8>> {
        let state = lock(&self.state);
        let path = state
            .inodes
            .iter()
            .find(|(_, inode)| **inode == descriptor.0)
            .map(|(path, _)| path.clone())?;
        match state.nodes.get(&path) {
            Some(FakeNode::File(contents)) => Some(contents.clone()),
            _ => None,
        }
    }

    /// Makes a [`ShadowFiles::write_in_place`] into `dst` fail with `errno` after writing part of it (a torn write),
    /// and a [`ShadowFiles::write_file`] of `dst` fail before writing anything.
    pub fn fail_write(&self, dst: impl AsRef<Path>, errno: i32) {
        lock(&self.state)
            .write_failures
            .insert(dst.as_ref().to_path_buf(), (errno, false));
    }

    /// As [`FakeTree::fail_write`], for the next write into `dst` only.
    pub fn fail_write_once(&self, dst: impl AsRef<Path>, errno: i32) {
        lock(&self.state)
            .write_failures
            .insert(dst.as_ref().to_path_buf(), (errno, true));
    }

    /// Lets writes into `dst` succeed again.
    pub fn allow_write(&self, dst: impl AsRef<Path>) {
        lock(&self.state).write_failures.remove(dst.as_ref());
    }

    /// Every successful [`ShadowFiles::write_in_place`] so far, `(src, dst)`, in order.
    #[must_use]
    pub fn writes(&self) -> Vec<(PathBuf, PathBuf)> {
        lock(&self.state).writes.clone()
    }
}

/// A descriptor [`FakeTree::open`] returned: it follows its inode, not its path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FakeDescriptor(u64);

impl ShadowFiles for FakeTree {
    fn kind(&self, path: &Path) -> Result<FileKind, PlatformError> {
        lock(&self.state)
            .nodes
            .get(path)
            .map(FakeNode::kind)
            .ok_or(os(Operation::Metadata, ENOENT))
    }

    fn list(&self, path: &Path, limit: usize) -> Result<Vec<OsString>, PlatformError> {
        let mut state = lock(&self.state);
        match state.nodes.get(path) {
            Some(FakeNode::Dir) => {}
            Some(_) => return Err(os(Operation::ReadDirectory, ENOTDIR)),
            None => return Err(os(Operation::ReadDirectory, ENOENT)),
        }
        state.listed.push(path.to_path_buf());
        let names: Vec<OsString> = state
            .nodes
            .keys()
            .filter(|child| child.parent() == Some(path) && child.as_path() != path)
            .filter_map(|child| child.file_name().map(OsString::from))
            .collect();
        if names.len() > limit {
            return Err(PlatformError::TooLarge { limit: limit as u64 });
        }
        Ok(names)
    }

    fn make_dir(&self, path: &Path) -> Result<(), PlatformError> {
        let mut state = lock(&self.state);
        if state.nodes.contains_key(path) {
            return Err(os(Operation::CreateDirectory, EEXIST));
        }
        let parent = path.parent().ok_or(os(Operation::CreateDirectory, ENOENT))?;
        if state.nodes.get(parent) != Some(&FakeNode::Dir) {
            return Err(os(Operation::CreateDirectory, ENOENT));
        }
        state.put(path, FakeNode::Dir);
        Ok(())
    }

    fn clone_file(&self, src: &Path, dst: &Path) -> Result<(), PlatformError> {
        let mut state = lock(&self.state);
        while state.held {
            state = self.released.wait(state).unwrap_or_else(PoisonError::into_inner);
        }
        if let Some(errno) = state.clone_failures.get(src) {
            return Err(os(Operation::Clone, *errno));
        }
        let node = match state.nodes.get(src) {
            Some(node @ (FakeNode::File(_) | FakeNode::Symlink(_))) => node.clone(),
            Some(_) => return Err(PlatformError::UnexpectedKind),
            None => return Err(os(Operation::Clone, ENOENT)),
        };
        if state.nodes.contains_key(dst) {
            return Err(os(Operation::Clone, EEXIST));
        }
        let parent_is_dir = dst
            .parent()
            .is_some_and(|parent| state.nodes.get(parent) == Some(&FakeNode::Dir));
        if !parent_is_dir {
            return Err(os(Operation::Clone, ENOENT));
        }
        let modified = state.modified.get(src).copied().unwrap_or_default();
        let inode = state.new_inode();
        state.nodes.insert(dst.to_path_buf(), node);
        state.modified.insert(dst.to_path_buf(), modified);
        state.inodes.insert(dst.to_path_buf(), inode);
        state.clones += 1;
        Ok(())
    }

    fn identity(&self, path: &Path) -> Result<FileIdentity, PlatformError> {
        let state = lock(&self.state);
        let node = state.nodes.get(path).ok_or(os(Operation::Metadata, ENOENT))?;
        let size = match node {
            FakeNode::File(contents) => contents.len() as u64,
            FakeNode::Symlink(target) => target.as_os_str().len() as u64,
            FakeNode::Dir | FakeNode::Special => 0,
        };
        Ok(FileIdentity {
            kind: node.kind(),
            inode: state.inodes.get(path).copied().unwrap_or_default(),
            size,
            modified: ModifiedTime {
                seconds: state.modified.get(path).copied().unwrap_or_default(),
                nanoseconds: 0,
            },
        })
    }

    fn remove(&self, path: &Path, folder: bool) -> Result<(), PlatformError> {
        let mut state = lock(&self.state);
        let operation = if folder {
            Operation::RemoveDirectory
        } else {
            Operation::RemoveFile
        };
        let Some(node) = state.nodes.get(path) else {
            return Err(os(operation, ENOENT));
        };
        // Like `rmdir(2)` and `unlink(2)`: each refuses the other's kind.
        match (folder, node) {
            (true, FakeNode::Dir) => {
                if state.nodes.keys().any(|other| other.parent() == Some(path)) {
                    return Err(os(operation, ENOTEMPTY));
                }
            }
            (false, FakeNode::File(_) | FakeNode::Symlink(_) | FakeNode::Special) => {}
            (true, _) => return Err(os(operation, ENOTDIR)),
            (false, FakeNode::Dir) => return Err(os(operation, EPERM)),
        }
        state.nodes.remove(path);
        state.modified.remove(path);
        state.inodes.remove(path);
        state.removed.push(path.to_path_buf());
        Ok(())
    }

    fn create_file(&self, path: &Path) -> Result<(), PlatformError> {
        let mut state = lock(&self.state);
        if state.nodes.contains_key(path) {
            return Err(os(Operation::Write, EEXIST));
        }
        let parent_is_dir = path
            .parent()
            .is_some_and(|parent| state.nodes.get(parent) == Some(&FakeNode::Dir));
        if !parent_is_dir {
            return Err(os(Operation::Write, ENOENT));
        }
        state.put(path, FakeNode::File(Vec::new()));
        Ok(())
    }

    fn rename_new(&self, from: &Path, to: &Path) -> Result<(), PlatformError> {
        {
            let state = lock(&self.state);
            if let Some(errno) = state.rename_failures.get(from) {
                return Err(os(Operation::Rename, *errno));
            }
            if !state.nodes.contains_key(from) {
                return Err(os(Operation::Rename, ENOENT));
            }
            if state.nodes.contains_key(to) {
                return Err(os(Operation::Rename, EEXIST));
            }
            let parent_is_dir = to
                .parent()
                .is_some_and(|parent| state.nodes.get(parent) == Some(&FakeNode::Dir));
            if !parent_is_dir {
                return Err(os(Operation::Rename, ENOENT));
            }
        }
        self.rename(from, to);
        lock(&self.state).renames.push((from.to_path_buf(), to.to_path_buf()));
        Ok(())
    }

    fn hash(&self, path: &Path, limit: u64) -> Result<Option<ContentHash>, PlatformError> {
        let mut state = lock(&self.state);
        state.hashed.push(path.to_path_buf());
        if let Some(errno) = state.hash_failures.get(path) {
            return Err(os(Operation::Read, *errno));
        }
        match state.nodes.get(path) {
            Some(FakeNode::File(contents)) if contents.len() as u64 > limit => Ok(None),
            Some(FakeNode::File(contents)) => Ok(Some(Self::digest_of(contents))),
            Some(_) => Err(PlatformError::UnexpectedKind),
            None => Err(os(Operation::Open, ENOENT)),
        }
    }

    fn write_in_place(&self, src: &Path, dst: &Path, expect: Option<&FileIdentity>) -> Result<(), PlatformError> {
        let current = self.identity(dst).map_err(|_| os(Operation::Open, ENOENT))?;
        let mut state = lock(&self.state);
        let contents = match (state.nodes.get(src), state.nodes.get(dst)) {
            (Some(FakeNode::File(contents)), Some(FakeNode::File(_))) => contents.clone(),
            (None, _) | (_, None) => return Err(os(Operation::Open, ENOENT)),
            _ => return Err(PlatformError::UnexpectedKind),
        };
        if expect.is_some_and(|expect| *expect != current) {
            return Err(PlatformError::Changed);
        }
        if let Some((errno, once)) = state.write_failures.get(dst).copied() {
            if once {
                state.write_failures.remove(dst);
            }
            // Torn: the first half of the new contents over the old.
            let Some(FakeNode::File(old)) = state.nodes.get(dst).cloned() else {
                return Err(os(Operation::Write, errno));
            };
            let mut torn = contents[..contents.len() / 2].to_vec();
            torn.extend(old.iter().skip(torn.len()));
            torn.push(b'~');
            state.put(dst, FakeNode::File(torn));
            return Err(os(Operation::Write, errno));
        }
        // In place: `put` keeps the inode (and every hard link sees it) and moves the time on, to "now".
        state.put(dst, FakeNode::File(contents));
        state.writes.push((src.to_path_buf(), dst.to_path_buf()));
        Ok(())
    }

    fn touch(&self, path: &Path) -> Result<(), PlatformError> {
        let mut state = lock(&self.state);
        if !state.nodes.contains_key(path) {
            return Err(os(Operation::Write, ENOENT));
        }
        state.tick += 1;
        let tick = state.tick;
        state.modified.insert(path.to_path_buf(), tick);
        Ok(())
    }

    fn write_file(&self, path: &Path, data: &[u8]) -> Result<(), PlatformError> {
        let mut state = lock(&self.state);
        if let Some((errno, once)) = state.write_failures.get(path).copied() {
            if once {
                state.write_failures.remove(path);
            }
            return Err(os(Operation::Write, errno));
        }
        let parent_is_dir = path
            .parent()
            .is_some_and(|parent| state.nodes.get(parent) == Some(&FakeNode::Dir));
        if !parent_is_dir {
            return Err(os(Operation::Write, ENOENT));
        }
        // An atomic replace: a new file renamed over the old one.
        state.inodes.remove(path);
        state.nodes.remove(path);
        state.put(path, FakeNode::File(data.to_vec()));
        Ok(())
    }

    fn read_file(&self, path: &Path, limit: u64) -> Result<Vec<u8>, PlatformError> {
        match lock(&self.state).nodes.get(path) {
            Some(FakeNode::File(contents)) if contents.len() as u64 > limit => Err(PlatformError::TooLarge { limit }),
            Some(FakeNode::File(contents)) => Ok(contents.clone()),
            Some(_) => Err(PlatformError::UnexpectedKind),
            None => Err(os(Operation::Open, ENOENT)),
        }
    }
}

/// A change for [`capture_change`] to take over a [`FakeTree`] (KNSH-088: other crates' tests of the history).
#[derive(Debug, Clone)]
pub struct TestChange<'a> {
    /// Its checkpoint.
    pub id: CheckpointId,
    /// How it was attributed.
    pub attribution: Attribution,
    /// Its lines.
    pub records: &'a [RecordId],
    /// The session it belongs to.
    pub session: SessionId,
    /// The checkpoint root it is in.
    pub root: &'a CanonicalPath,
    /// The root's store: its pre-images go in `<store>/checkpoints/<id>/`.
    pub store: &'a Path,
    /// The paths it changes, relative to `root`.
    pub paths: &'a [&'a str],
}

/// The checkpoint of `change`, made by `edit`, captured as the watcher would: each path's pre-image set aside first
/// (a clone into the checkpoint's folder, or a marker), its post-image identity read after the edit.
///
/// # Panics
///
/// If a path is not a valid canonical path below the root, or a pre-image cannot be cloned: test set-up mistakes.
#[allow(clippy::missing_panics_doc, clippy::unwrap_used, reason = "test-only helper")]
pub fn capture_change(tree: &FakeTree, change: &TestChange<'_>, edit: impl FnOnce(&FakeTree)) -> Checkpoint {
    let folder = change.store.join(CHECKPOINTS_DIR).join(change.id.to_string());
    tree.add_dir(&folder);
    let mut pres = Vec::new();
    for (index, relative) in change.paths.iter().enumerate() {
        let path = change.root.as_path().join(relative);
        let pre = match tree.node(&path) {
            None => StoredPreImage::NotExisted,
            Some(FakeNode::Dir) => StoredPreImage::Folder,
            Some(_) => {
                let copy = folder.join(index.to_string());
                tree.clone_file(&path, &copy).unwrap();
                StoredPreImage::Kept(copy)
            }
        };
        pres.push((CanonicalPath::new(path).unwrap(), pre));
    }
    edit(tree);
    let paths = pres
        .into_iter()
        .map(|(path, pre)| {
            let post = post_image(tree, path.as_path());
            (path, CapturedPath { pre, post })
        })
        .collect();
    Checkpoint {
        id: change.id,
        edge: EdgeId::for_tests(0),
        attribution: change.attribution,
        records: change.records.iter().copied().collect(),
        sessions: [change.session].into(),
        paths: [(change.root.clone(), paths)].into(),
        uncertain: std::collections::BTreeSet::new(),
        stores: [(change.root.clone(), change.store.to_path_buf())].into(),
        excluded: BTreeMap::new(),
        excluded_overflowed: false,
        possibly_torn: BTreeMap::new(),
    }
}
