//! Redirection files over [`MemFs`] (KNSH-099).

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex, Weak};
use std::time::{Duration, Instant};

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

/// The width [`FakeDescriptors`] reports for a descriptor marked as a terminal (KNSH-107).
pub const FAKE_TERMINAL_COLUMNS: u16 = 80;

/// How long a read of an empty data pipe whose writer is still alive waits before failing with `EIO`: far above any
/// test's own work, so a test that would wait forever fails instead of hanging.
const PIPE_WAIT_LIMIT: Duration = Duration::from_secs(20);

/// What a data pipe holds ([`FakeDescriptors::with_data_pipes`]).
#[derive(Debug)]
struct PipeBuffer {
    /// Written and not yet read.
    data: VecDeque<u8>,
    /// The write end: once every clone of it is gone, a reader that has taken everything sees end of file.
    writer: Weak<OwnedFd>,
    /// The read end: once it is gone, a write fails with `EPIPE`.
    reader: Weak<OwnedFd>,
}

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
    /// Pipes carry what is written to them ([`FakeDescriptors::with_data_pipes`]), by pipe number.
    data_pipes: Option<Mutex<BTreeMap<usize, PipeBuffer>>>,
    /// Notified when a data pipe is written.
    pipe_written: Condvar,
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
            data_pipes: None,
            pipe_written: Condvar::new(),
        }
    }

    /// The same fake with pipes that carry data (KNSH-105): what is written to a pipe's write end is read from its
    /// read end, a read waits while the pipe is empty and a clone of its write end is alive, and sees end of file
    /// once none is; a write after every read end is gone fails with `EPIPE`. Without it pipes carry nothing and
    /// their reader sees end of file at once, so a pipe a scripted command keeps open never blocks a test.
    #[must_use]
    pub fn with_data_pipes(mut self) -> Self {
        self.data_pipes = Some(Mutex::new(BTreeMap::new()));
        self
    }

    /// Reads from data pipe `n` into `buffer`, waiting while it is empty and written to.
    fn read_pipe(
        &self,
        pipes: &Mutex<BTreeMap<usize, PipeBuffer>>,
        n: usize,
        buffer: &mut [u8],
    ) -> Result<usize, PlatformError> {
        let deadline = Instant::now() + PIPE_WAIT_LIMIT;
        let mut held = lock(pipes);
        loop {
            let Some(pipe) = held.get_mut(&n) else {
                return Ok(0);
            };
            if !pipe.data.is_empty() {
                let count = pipe.data.len().min(buffer.len());
                for (slot, byte) in buffer.iter_mut().zip(pipe.data.drain(..count)) {
                    *slot = byte;
                }
                return Ok(count);
            }
            if pipe.writer.strong_count() == 0 || buffer.is_empty() {
                return Ok(0);
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(PlatformError::Os {
                    operation: Operation::Read,
                    errno: libc::EIO,
                });
            }
            // A writer's end going away is not announced: look again shortly.
            let wait = (deadline - now).min(Duration::from_millis(2));
            held = self
                .pipe_written
                .wait_timeout(held, wait)
                .map_or_else(|poisoned| poisoned.into_inner().0, |(guard, _)| guard);
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
        if let Some(pipes) = &self.data_pipes {
            lock(pipes).insert(
                n,
                PipeBuffer {
                    data: VecDeque::new(),
                    writer: write.downgrade(),
                    reader: read.downgrade(),
                },
            );
        }
        Ok((read, write))
    }

    fn write_all(&self, fd: &SharedFd, bytes: &[u8]) -> Result<(), PlatformError> {
        let bad = PlatformError::Os {
            operation: Operation::Write,
            errno: libc::EBADF,
        };
        if let (Some(pipes), Some(FakeOpened::Pipe { n, write: true })) = (&self.data_pipes, self.opened(fd)) {
            let mut held = lock(pipes);
            let Some(pipe) = held.get_mut(&n) else {
                return Err(bad);
            };
            if pipe.reader.strong_count() == 0 {
                return Err(PlatformError::Os {
                    operation: Operation::Write,
                    errno: libc::EPIPE,
                });
            }
            pipe.data.extend(bytes);
            drop(held);
            self.pipe_written.notify_all();
            return Ok(());
        }
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
        if let (Some(pipes), Some(FakeOpened::Pipe { n, write: false })) = (&self.data_pipes, self.opened(fd)) {
            return self.read_pipe(pipes, n, buffer);
        }
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
        if let (Some(pipes), Some(FakeOpened::Pipe { n, write: false })) = (&self.data_pipes, self.opened(fd)) {
            return Ok(lock(pipes)
                .get(&n)
                .is_none_or(|pipe| !pipe.data.is_empty() || pipe.writer.strong_count() == 0));
        }
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

    fn set_editor_input(&self, fd: &SharedFd) -> Result<Option<TerminalSettings>, PlatformError> {
        if !self.is_terminal(fd) {
            return Ok(None);
        }
        // Recorded as the settings `read -s -n` would ask for: no echo, not canonical.
        lock(&self.terminal_changes).push(Some(TerminalInput {
            echo: false,
            canonical: false,
        }));
        Ok(Some(TerminalSettings::fake()))
    }

    fn terminal_columns(&self, fd: &SharedFd) -> Option<u16> {
        self.is_terminal(fd).then_some(FAKE_TERMINAL_COLUMNS)
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

    // KNSH-105: data pipes carry what is written, wait while a writer lives, and end once none does.
    #[test]
    fn data_pipes_carry_data_until_every_writer_is_gone() {
        let fs = Arc::new(MemFs::new());
        let descriptors = Arc::new(FakeDescriptors::new(fs).with_data_pipes());
        let (read, write) = descriptors.pipe().unwrap();
        descriptors.write_all(&write, b"ab").unwrap();
        let mut buffer = [0_u8; 8];
        assert_eq!(descriptors.read(&read, &mut buffer).unwrap(), 2);
        assert_eq!(&buffer[..2], b"ab");
        let writer = {
            let descriptors = Arc::clone(&descriptors);
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(20));
                descriptors.write_all(&write, b"c").unwrap();
                drop(write);
            })
        };
        assert_eq!(descriptors.read(&read, &mut buffer).unwrap(), 1);
        writer.join().unwrap();
        assert_eq!(descriptors.read(&read, &mut buffer).unwrap(), 0);
        // Writing with no reader left is a broken pipe.
        let (read, write) = descriptors.pipe().unwrap();
        drop(read);
        assert!(matches!(
            descriptors.write_all(&write, b"x"),
            Err(PlatformError::Os { errno: libc::EPIPE, .. })
        ));
    }
}
