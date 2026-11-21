//! Redirection files over [`MemFs`] (KNSH-099).

use std::collections::{BTreeMap, BTreeSet};
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::{MemFs, lock};
use crate::descriptor::{Descriptors, OpenMode, TerminalInput, TerminalSettings, reaches_descriptor_table};
use crate::error::{Operation, PlatformError};
use crate::fs::{FileKind, FileStatus, FileTime, FileType, Fs};
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
    /// One end of the `n`th pipe made (from 0): the write end when `write`, else the read end (KNSH-100).
    Pipe {
        /// Which pipe.
        n: usize,
        /// Which end.
        write: bool,
    },
    /// Input made by [`FakeDescriptors::input`]: these bytes, then end of file, or (when `held_open`) input that
    /// never comes, as from a terminal nobody types at (KNSH-102).
    Input {
        /// What can be read.
        data: Vec<u8>,
        /// After `data`, reads wait forever instead of seeing end of file.
        held_open: bool,
    },
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
    /// Pipes made so far.
    pipes: Mutex<usize>,
    /// How far each live descriptor has been read (KNSH-102).
    offsets: Mutex<BTreeMap<i32, usize>>,
    /// Descriptors that are terminals (KNSH-102).
    terminals: Mutex<BTreeSet<i32>>,
    /// Each [`Descriptors::set_terminal_input`] call on a terminal, and each restore (`None`), in order.
    terminal_changes: Mutex<Vec<Option<TerminalInput>>>,
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
            pipes: Mutex::new(0),
            offsets: Mutex::new(BTreeMap::new()),
            terminals: Mutex::new(BTreeSet::new()),
            terminal_changes: Mutex::new(Vec::new()),
        }
    }

    /// A descriptor to read `data` from, then end of file, or (with `held_open`) a wait that never ends: a shell's
    /// standard input (KNSH-102).
    ///
    /// # Errors
    ///
    /// [`PlatformError::Os`] if `/dev/null` could not be opened to stand for it.
    pub fn input(&self, data: &[u8], held_open: bool) -> Result<SharedFd, PlatformError> {
        self.hand_out(FakeOpened::Input {
            data: data.to_vec(),
            held_open,
        })
    }

    /// Makes `fd` (handed out by this fake) a terminal (KNSH-102).
    pub fn set_terminal(&self, fd: &SharedFd) {
        lock(&self.terminals).insert(fd.as_raw_fd());
    }

    /// Each change [`Descriptors::set_terminal_input`] made to a terminal, and each restore (`None`), in order.
    #[must_use]
    pub fn terminal_changes(&self) -> Vec<Option<TerminalInput>> {
        lock(&self.terminal_changes).clone()
    }

    /// The bytes `fd` stands for, and whether reading past them waits forever.
    fn readable(&self, fd: &SharedFd) -> Result<(Vec<u8>, bool), PlatformError> {
        let bad = PlatformError::Os {
            operation: Operation::Read,
            errno: libc::EBADF,
        };
        match self.opened(fd) {
            Some(FakeOpened::File { path, mode }) => {
                if matches!(mode, OpenMode::Truncate | OpenMode::Append | OpenMode::NoClobber) {
                    return Err(bad);
                }
                if path == Path::new("/dev/null") {
                    return Ok((Vec::new(), false));
                }
                Ok((self.fs.read(&path, READ_LIMIT)?, false))
            }
            Some(FakeOpened::HereString(data)) => Ok((data, false)),
            Some(FakeOpened::Input { data, held_open }) => Ok((data, held_open)),
            // Fake pipes carry no data: the reader sees end of file.
            Some(FakeOpened::Pipe { write: false, .. }) => Ok((Vec::new(), false)),
            Some(FakeOpened::Pipe { write: true, .. }) | None => Err(bad),
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
        // A reused number is a new descriptor: unread, and not a terminal.
        lock(&self.offsets).remove(&fd.as_raw_fd());
        lock(&self.terminals).remove(&fd.as_raw_fd());
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
        self.open_masked(path, mode, 0)
    }

    /// Creates a missing file with mode `0666` less `umask` (and the [`MemFs`]'s own umask, as the kernel would).
    fn open_masked(&self, path: &Path, mode: OpenMode, umask: u32) -> Result<SharedFd, PlatformError> {
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
                .write(path, data, 0o666 & !umask & 0o777)
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

    fn pipe(&self) -> Result<(SharedFd, SharedFd), PlatformError> {
        let n = {
            let mut pipes = lock(&self.pipes);
            *pipes += 1;
            *pipes - 1
        };
        let read = self.hand_out(FakeOpened::Pipe { n, write: false })?;
        let write = self.hand_out(FakeOpened::Pipe { n, write: true })?;
        Ok((read, write))
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

    /// Reads on from where the last read of this descriptor stopped. Past the end of held-open input it fails with
    /// `EAGAIN` rather than block the test forever: a caller that waits with [`Descriptors::wait_readable`] first
    /// never gets there.
    fn read(&self, fd: &SharedFd, buffer: &mut [u8]) -> Result<usize, PlatformError> {
        let (data, held_open) = self.readable(fd)?;
        let mut offsets = lock(&self.offsets);
        let offset = offsets.entry(fd.as_raw_fd()).or_insert(0);
        let rest = data.get(*offset..).unwrap_or_default();
        if rest.is_empty() && held_open {
            return Err(PlatformError::Os {
                operation: Operation::Read,
                errno: libc::EAGAIN,
            });
        }
        let count = rest.len().min(buffer.len());
        buffer[..count].copy_from_slice(&rest[..count]);
        *offset += count;
        Ok(count)
    }

    /// Ready unless held-open input has nothing left; never waits.
    fn wait_readable(&self, fd: &SharedFd, _timeout: Duration) -> Result<bool, PlatformError> {
        let (data, held_open) = self.readable(fd)?;
        let offset = lock(&self.offsets).get(&fd.as_raw_fd()).copied().unwrap_or(0);
        Ok(!(held_open && offset >= data.len()))
    }

    fn is_terminal(&self, fd: &SharedFd) -> bool {
        lock(&self.terminals).contains(&fd.as_raw_fd())
    }

    /// A file's status from the [`MemFs`]; a terminal is a character device, a here-string, a pipe or other input
    /// a FIFO.
    fn status(&self, fd: &SharedFd) -> Result<FileStatus, PlatformError> {
        let fifo = |file_type| FileStatus {
            file_type,
            mode: 0o600,
            uid: self.fs.uid(),
            gid: super::DEFAULT_GID,
            len: 0,
            device: 0,
            inode: u64::try_from(fd.as_raw_fd()).unwrap_or(0),
            accessed: FileTime::default(),
            modified: FileTime::default(),
            owned_by_effective_user: true,
            owned_by_effective_group: true,
        };
        if self.is_terminal(fd) {
            return Ok(fifo(FileType::CharacterDevice));
        }
        match self.opened(fd) {
            Some(FakeOpened::File { path, .. }) if path == Path::new("/dev/null") => {
                Ok(fifo(FileType::CharacterDevice))
            }
            Some(FakeOpened::File { path, .. }) => self.fs.status(&path, true),
            Some(FakeOpened::HereString(_) | FakeOpened::Pipe { .. } | FakeOpened::Input { .. }) => {
                Ok(fifo(FileType::Fifo))
            }
            None => Err(PlatformError::Os {
                operation: Operation::Metadata,
                errno: libc::EBADF,
            }),
        }
    }

    fn set_terminal_input(
        &self,
        fd: &SharedFd,
        input: TerminalInput,
    ) -> Result<Option<TerminalSettings>, PlatformError> {
        if !self.is_terminal(fd) {
            return Ok(None);
        }
        lock(&self.terminal_changes).push(Some(input));
        Ok(Some(TerminalSettings::fake()))
    }

    fn restore_terminal(&self, _fd: &SharedFd, _saved: &TerminalSettings) -> Result<(), PlatformError> {
        lock(&self.terminal_changes).push(None);
        Ok(())
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
