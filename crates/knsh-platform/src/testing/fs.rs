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
}

/// An in-memory filesystem.
///
/// Paths are resolved like the kernel does: symlinks in any component are followed (the final one only where the
/// real call follows it), `..` applies after resolution, and missing or non-directory components fail with `ENOENT`
/// or `ENOTDIR`. There is no umask: modes are stored exactly as given.
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
    /// A filesystem holding only the root directory (mode `0o755`).
    #[must_use]
    pub fn new() -> Self {
        let mut nodes = BTreeMap::new();
        nodes.insert(PathBuf::from("/"), Node::Directory { mode: 0o755 });
        Self {
            state: Mutex::new(State {
                nodes,
                faults: Vec::new(),
            }),
        }
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
            None => mode & 0o7777,
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
            state.nodes.insert(target, node);
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
        state.nodes.insert(resolved, Node::Directory { mode: mode & 0o7777 });
        Ok(())
    }

    fn metadata(&self, path: &Path) -> Result<Metadata, PlatformError> {
        let mut state = lock(&self.state);
        require_absolute(path)?;
        state.check_fault(Operation::Metadata)?;
        let resolved = resolve(&state.nodes, path, false, Operation::Metadata)?;
        match state.nodes.get(&resolved) {
            Some(Node::File { data, mode }) => Ok(Metadata {
                kind: FileKind::File,
                len: data.len() as u64,
                mode: *mode,
            }),
            Some(Node::Directory { mode }) => Ok(Metadata {
                kind: FileKind::Directory,
                len: 0,
                mode: *mode,
            }),
            Some(Node::Symlink { target }) => Ok(Metadata {
                kind: FileKind::Symlink,
                len: target.as_os_str().len() as u64,
                mode: 0o755,
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
}
