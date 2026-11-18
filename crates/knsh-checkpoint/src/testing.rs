//! Deterministic fakes for checkpoint tests (KNSH-079, KNSH-080). Built only for tests and with the `testing` feature,
//! which other crates enable in their `[dev-dependencies]` alone, so no fake reaches a shipped binary.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::{Condvar, Mutex, MutexGuard, PoisonError};

use knsh_platform::{FileIdentity, FileKind, ModifiedTime, Operation, PlatformError};

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
    /// While set, clones wait until [`FakeTree::release`].
    held: bool,
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
    /// Inserts `node` at `path` with a new modification time.
    fn put(&mut self, path: &Path, node: FakeNode) {
        self.tick += 1;
        self.modified.insert(path.to_path_buf(), self.tick);
        self.nodes.insert(path.to_path_buf(), node);
    }

    /// Removes `path` and everything below it.
    fn drop_below(&mut self, path: &Path) {
        self.nodes.retain(|other, _| !other.starts_with(path));
        self.modified.retain(|other, _| !other.starts_with(path));
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
        let moved: Vec<(PathBuf, FakeNode, i64)> = state
            .nodes
            .iter()
            .filter(|(path, _)| path.starts_with(from))
            .map(|(path, node)| {
                let modified = state.modified.get(path).copied().unwrap_or_default();
                (path.clone(), node.clone(), modified)
            })
            .collect();
        state.drop_below(from);
        for (path, node, modified) in moved {
            let Ok(rest) = path.strip_prefix(from) else { continue };
            let target = if rest.as_os_str().is_empty() {
                to.to_path_buf()
            } else {
                to.join(rest)
            };
            state.modified.insert(target.clone(), modified);
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

    /// Makes later clones wait until [`FakeTree::release`].
    pub fn hold(&self) {
        lock(&self.state).held = true;
    }

    /// Lets waiting and later clones proceed.
    pub fn release(&self) {
        lock(&self.state).held = false;
        self.released.notify_all();
    }
}

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
        state.nodes.insert(dst.to_path_buf(), node);
        state.modified.insert(dst.to_path_buf(), modified);
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
            inode: 0,
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
}
