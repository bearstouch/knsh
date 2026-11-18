//! Deterministic fakes for checkpoint tests (KNSH-079). Built only for tests and with the `testing` feature, which
//! other crates enable in their `[dev-dependencies]` alone, so no fake reaches a shipped binary.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::{Condvar, Mutex, MutexGuard, PoisonError};

use knsh_platform::{FileKind, Operation, PlatformError};

use crate::shadow::ShadowFiles;

/// `errno` values (macOS); `libc` is reserved to `knsh-platform` (NFR-SUP-02).
const ENOENT: i32 = 2;
const EEXIST: i32 = 17;
const ENOTDIR: i32 = 20;

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
    /// `errno` a clone of a path fails with.
    clone_failures: BTreeMap<PathBuf, i32>,
    /// Every folder listed, in order.
    listed: Vec<PathBuf>,
    clones: usize,
    /// While set, clones wait until [`FakeTree::release`].
    held: bool,
}

/// An in-memory file tree implementing [`ShadowFiles`]. `/` always exists. Clones copy the node (a symlink stays a
/// symlink, its target is never resolved). [`FakeTree::hold`] makes clones wait, so a test can observe a build in
/// progress.
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
            state.nodes.entry(ancestor.to_path_buf()).or_insert(FakeNode::Dir);
        }
        state.nodes.insert(path.to_path_buf(), node);
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
        state.nodes.insert(path.to_path_buf(), FakeNode::Dir);
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
        state.nodes.insert(dst.to_path_buf(), node);
        state.clones += 1;
        Ok(())
    }
}
