//! Redirection files over [`MemFs`] (KNSH-099).

use std::collections::BTreeMap;
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use super::{MemFs, lock};
use crate::descriptor::{Descriptors, OpenMode, reaches_descriptor_table};
use crate::error::{Operation, PlatformError};
use crate::fs::{FileKind, Fs};
use crate::process::SharedFd;

/// What one descriptor [`FakeDescriptors`] handed out stands for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FakeOpened {
    /// A file of the [`MemFs`] (or `/dev/null`), opened as this mode.
    File {
        /// The path as given.
        path: PathBuf,
        /// How it was opened.
        mode: OpenMode,
    },
    /// A here-string holding these bytes.
    HereString(Vec<u8>),
}

/// Largest file the fake reads back when appending, far above anything a test writes.
const READ_LIMIT: u64 = 1 << 24;

/// [`Descriptors`] over a [`MemFs`]: opening creates or truncates the file there, and writes through a descriptor
/// append to it, so a test reads back what a redirection produced with [`MemFs::contents`]. `/dev/null` exists and
/// swallows writes. A path reaching `/dev/fd` is refused with `EPERM`, as the real backend refuses it.
///
/// Each descriptor handed out is a real descriptor of `/dev/null` (so it can travel in a
/// [`CommandRequest`](crate::CommandRequest)); [`FakeDescriptors::opened`] tells what it stands for. Nothing but
/// `/dev/null` is ever opened on the real system.
#[derive(Debug)]
pub struct FakeDescriptors {
    fs: Arc<MemFs>,
    /// What each live descriptor number stands for. A number is reused once its descriptor is closed; opening again
    /// replaces the entry.
    opened: Mutex<BTreeMap<i32, FakeOpened>>,
}

fn os(errno: i32) -> PlatformError {
    PlatformError::Os {
        operation: Operation::Open,
        errno,
    }
}

impl FakeDescriptors {
    /// Redirections into `fs`.
    #[must_use]
    pub fn new(fs: Arc<MemFs>) -> Self {
        Self {
            fs,
            opened: Mutex::new(BTreeMap::new()),
        }
    }

    /// What `fd` (handed out by this fake and still open) stands for.
    #[must_use]
    pub fn opened(&self, fd: &SharedFd) -> Option<FakeOpened> {
        lock(&self.opened).get(&fd.as_raw_fd()).cloned()
    }

    /// A fresh real descriptor standing for `what`.
    fn hand_out(&self, what: FakeOpened) -> Result<SharedFd, PlatformError> {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/null")
            .map_err(|error| PlatformError::from_io(Operation::Open, &error))?;
        let fd = SharedFd::new(OwnedFd::from(file));
        lock(&self.opened).insert(fd.as_raw_fd(), what);
        Ok(fd)
    }

    /// The kind of `path` in the filesystem, `None` if nothing is there.
    fn kind(&self, path: &Path) -> Result<Option<FileKind>, PlatformError> {
        match self.fs.metadata(path) {
            Ok(metadata) => Ok(Some(metadata.kind)),
            Err(error) if error.is_not_found() => Ok(None),
            Err(error) => Err(error),
        }
    }
}

impl Descriptors for FakeDescriptors {
    fn open(&self, path: &Path, mode: OpenMode) -> Result<SharedFd, PlatformError> {
        if !path.is_absolute() {
            return Err(PlatformError::InvalidPath);
        }
        if reaches_descriptor_table(path) {
            return Err(os(libc::EPERM));
        }
        let what = FakeOpened::File {
            path: path.to_path_buf(),
            mode,
        };
        if path == Path::new("/dev/null") {
            return self.hand_out(what);
        }
        let kind = self.kind(path)?;
        let create = |data: &[u8]| {
            self.fs
                .write(path, data, 0o666)
                .map_err(|error| os(error.errno().unwrap_or(libc::EIO)))
        };
        match (mode, kind) {
            (_, Some(FileKind::Directory)) if mode != OpenMode::Read => return Err(os(libc::EISDIR)),
            (OpenMode::Read, None) => return Err(os(libc::ENOENT)),
            (OpenMode::NoClobber, Some(FileKind::File)) => return Err(os(libc::EEXIST)),
            (OpenMode::Truncate | OpenMode::NoClobber, _) | (OpenMode::Append | OpenMode::ReadWrite, None) => {
                create(b"")?;
            }
            (OpenMode::Read | OpenMode::Append | OpenMode::ReadWrite, Some(_)) => {}
        }
        self.hand_out(what)
    }

    fn here_string(&self, text: &[u8]) -> Result<SharedFd, PlatformError> {
        self.hand_out(FakeOpened::HereString(text.to_vec()))
    }

    fn write_all(&self, fd: &SharedFd, bytes: &[u8]) -> Result<(), PlatformError> {
        let bad = PlatformError::Os {
            operation: Operation::Write,
            errno: libc::EBADF,
        };
        let Some(FakeOpened::File { path, mode }) = self.opened(fd) else {
            return Err(bad);
        };
        if mode == OpenMode::Read {
            return Err(bad);
        }
        if path == Path::new("/dev/null") {
            return Ok(());
        }
        let mut data = self.fs.read(&path, READ_LIMIT)?;
        data.extend_from_slice(bytes);
        self.fs.write(&path, &data, 0o666)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn errno(result: Result<SharedFd, PlatformError>) -> Option<i32> {
        result.err().and_then(|error| error.errno())
    }

    #[test]
    fn opens_and_writes_into_the_memory_filesystem() {
        let fs = Arc::new(MemFs::new());
        fs.add_dir_all(Path::new("/w")).unwrap();
        let descriptors = FakeDescriptors::new(fs.clone());
        let out = descriptors.open(Path::new("/w/f"), OpenMode::Truncate).unwrap();
        descriptors.write_all(&out, b"a").unwrap();
        descriptors.write_all(&out, b"b").unwrap();
        assert_eq!(fs.contents(Path::new("/w/f")).unwrap(), b"ab");
        assert_eq!(
            descriptors.opened(&out),
            Some(FakeOpened::File {
                path: "/w/f".into(),
                mode: OpenMode::Truncate
            })
        );
        assert_eq!(
            errno(descriptors.open(Path::new("/w/f"), OpenMode::NoClobber)),
            Some(libc::EEXIST)
        );
        assert_eq!(
            errno(descriptors.open(Path::new("/w/g"), OpenMode::Read)),
            Some(libc::ENOENT)
        );
        assert_eq!(
            errno(descriptors.open(Path::new("/w"), OpenMode::Append)),
            Some(libc::EISDIR)
        );
        assert_eq!(
            errno(descriptors.open(Path::new("/dev/fd/3"), OpenMode::Read)),
            Some(libc::EPERM)
        );
        let read = descriptors.open(Path::new("/w/f"), OpenMode::Read).unwrap();
        assert!(descriptors.write_all(&read, b"x").is_err());
        descriptors.open(Path::new("/w/f"), OpenMode::Truncate).unwrap();
        assert_eq!(fs.contents(Path::new("/w/f")).unwrap(), b"");
        let here = descriptors.here_string(b"text\n").unwrap();
        assert_eq!(
            descriptors.opened(&here),
            Some(FakeOpened::HereString(b"text\n".to_vec()))
        );
    }
}
