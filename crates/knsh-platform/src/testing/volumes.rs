//! In-memory volumes and files for checkpoint tests (KNSH-078): clone failures, volume boundaries and identity
//! changes, all deterministic.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use super::lock;
use crate::error::{Operation, PlatformError};
use crate::fs::{FileKind, require_absolute};
use crate::volume::{
    CONTENT_HASH_LEN, ContentHash, FileIdentity, FileSystemKind, ModifiedTime, Volume, VolumeId, Volumes, clone_error,
};

/// One file the fake holds.
#[derive(Debug, Clone)]
struct FakeFile {
    contents: Vec<u8>,
    inode: u64,
    modified: ModifiedTime,
}

#[derive(Debug, Default)]
struct State {
    /// Volumes by mount point. A path is on the volume with the longest mount point that contains it.
    volumes: BTreeMap<PathBuf, Volume>,
    files: BTreeMap<PathBuf, FakeFile>,
    next_volume: u64,
    next_inode: u64,
    /// Seconds of the next modification time; every write moves it on by one, so each write is distinguishable.
    clock: i64,
    /// `errno` every later clone fails with (mapped as the real backend maps it).
    clone_failure: Option<i32>,
    clones: usize,
    hashes: usize,
}

/// A [`Volumes`] over in-memory files on volumes the test declares. Never touches the real disk.
///
/// - [`FakeVolumes::add_volume`] declares a mount point; paths below it are on that volume. Nothing is on a volume
///   by default: `volume_of` a path outside every declared volume fails with `ENOENT`.
/// - [`FakeVolumes::add_file`] and [`FakeVolumes::write`] change a file's contents; [`FakeVolumes::replace`] gives it
///   a new inode as a rename over it would; [`FakeVolumes::set_modified`] moves only its time.
/// - Clones follow the real rules: only within one volume ([`PlatformError::CrossVolume`]) and only on APFS
///   ([`PlatformError::ClonesUnsupported`]). [`FakeVolumes::fail_clones`] makes every later clone fail.
/// - Hashes are **not SHA-256**: a deterministic digest of the contents (equal contents give equal digests), so the
///   fake needs no crypto library. Tests of the real digest use `macos::SystemVolumes`.
#[derive(Debug, Default)]
pub struct FakeVolumes {
    state: Mutex<State>,
}

impl FakeVolumes {
    /// No volumes and no files.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Declares a volume mounted at `mount_point` and returns its id. Ids are handed out in order from 1.
    ///
    /// # Panics
    ///
    /// If `mount_point` is relative (a test setup error).
    pub fn add_volume(&self, mount_point: &str, kind: FileSystemKind, read_only: bool) -> VolumeId {
        assert!(mount_point.starts_with('/'), "mount point must be absolute");
        let mut state = lock(&self.state);
        state.next_volume += 1;
        let id = VolumeId::from_raw(state.next_volume);
        let mount_point = PathBuf::from(mount_point);
        state.volumes.insert(
            mount_point.clone(),
            Volume {
                id,
                kind,
                mount_point,
                read_only,
                ignores_ownership: false,
            },
        );
        id
    }

    /// Marks the volume mounted at `mount_point` as ignoring ownership (`MNT_IGNORE_OWNERSHIP`, as external disks
    /// are by default). Does nothing if no volume is mounted there.
    pub fn set_ignores_ownership(&self, mount_point: &str, ignores: bool) {
        if let Some(volume) = lock(&self.state).volumes.get_mut(Path::new(mount_point)) {
            volume.ignores_ownership = ignores;
        }
    }

    /// Creates or overwrites the file at `path` with `contents`, as a write in place: an existing file keeps its
    /// inode, a new one gets the next. Either way its modification time moves on.
    pub fn add_file(&self, path: &str, contents: &[u8]) {
        self.write(Path::new(path), contents);
    }

    /// Writes `contents` into the file at `path` in place (same inode if it exists) and moves its modification
    /// time on.
    pub fn write(&self, path: &Path, contents: &[u8]) {
        self.put(path, contents, true);
    }

    /// Replaces the file at `path` with a new one holding `contents`, as a rename over it would: a new inode and a
    /// new modification time.
    pub fn replace(&self, path: &Path, contents: &[u8]) {
        self.put(path, contents, false);
    }

    /// Stores `contents` at `path` with the next modification time, keeping an existing file's inode only when
    /// `in_place`.
    fn put(&self, path: &Path, contents: &[u8], in_place: bool) {
        let mut state = lock(&self.state);
        let modified = tick(&mut state);
        let existing = state.files.get(path).map(|file| file.inode).filter(|_| in_place);
        let inode = match existing {
            Some(inode) => inode,
            None => next_inode(&mut state),
        };
        state.files.insert(
            path.to_path_buf(),
            FakeFile {
                contents: contents.to_vec(),
                inode,
                modified,
            },
        );
    }

    /// Sets only the modification time of the file at `path`, as `touch -t` would. Does nothing if it is missing.
    pub fn set_modified(&self, path: &Path, modified: ModifiedTime) {
        if let Some(file) = lock(&self.state).files.get_mut(path) {
            file.modified = modified;
        }
    }

    /// Removes the file at `path`, if any.
    pub fn remove(&self, path: &Path) {
        lock(&self.state).files.remove(path);
    }

    /// The contents of the file at `path`, if it exists.
    #[must_use]
    pub fn contents(&self, path: &Path) -> Option<Vec<u8>> {
        lock(&self.state).files.get(path).map(|file| file.contents.clone())
    }

    /// Makes every later clone fail with `errno`, mapped as the real backend maps it (`EXDEV` becomes
    /// [`PlatformError::CrossVolume`], `ENOTSUP` [`PlatformError::ClonesUnsupported`], anything else
    /// [`PlatformError::Os`] with [`Operation::Clone`]).
    pub fn fail_clones(&self, errno: i32) {
        lock(&self.state).clone_failure = Some(errno);
    }

    /// Lets clones succeed again.
    pub fn allow_clones(&self) {
        lock(&self.state).clone_failure = None;
    }

    /// Successful clones so far.
    #[must_use]
    pub fn clones(&self) -> usize {
        lock(&self.state).clones
    }

    /// Completed hashes so far (including those that stopped at the limit).
    #[must_use]
    pub fn hashes(&self) -> usize {
        lock(&self.state).hashes
    }

    /// The digest [`Volumes::hash`] reports for `contents`.
    #[must_use]
    pub fn digest_of(contents: &[u8]) -> ContentHash {
        fake_digest(contents)
    }
}

/// The next modification time: one second after the last.
fn tick(state: &mut State) -> ModifiedTime {
    state.clock += 1;
    ModifiedTime {
        seconds: state.clock,
        nanoseconds: 0,
    }
}

fn next_inode(state: &mut State) -> u64 {
    state.next_inode += 1;
    state.next_inode
}

/// The volume `path` is on: the declared volume with the longest mount point containing it.
fn volume_for(state: &State, path: &Path) -> Option<Volume> {
    state
        .volumes
        .values()
        .filter(|volume| path.starts_with(&volume.mount_point))
        .max_by_key(|volume| volume.mount_point.components().count())
        .cloned()
}

fn not_found(operation: Operation) -> PlatformError {
    PlatformError::Os {
        operation,
        errno: libc::ENOENT,
    }
}

/// A deterministic 32-byte digest of `contents` (FNV-1a in four lanes): not a cryptographic hash, only distinct
/// enough for tests to tell contents apart.
fn fake_digest(contents: &[u8]) -> ContentHash {
    let mut digest = [0u8; CONTENT_HASH_LEN];
    for (lane, chunk) in digest.chunks_mut(8).enumerate() {
        let mut hash: u64 = 0xcbf2_9ce4_8422_2325 ^ (lane as u64);
        for byte in contents {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
        hash ^= contents.len() as u64;
        chunk.copy_from_slice(&hash.to_be_bytes());
    }
    ContentHash::from_bytes(digest)
}

impl Volumes for FakeVolumes {
    fn clone_file(&self, src: &Path, dst: &Path) -> Result<(), PlatformError> {
        require_absolute(src)?;
        require_absolute(dst)?;
        let mut state = lock(&self.state);
        if let Some(errno) = state.clone_failure {
            return Err(clone_error(errno));
        }
        let source = state.files.get(src).cloned().ok_or(not_found(Operation::Clone))?;
        let from = volume_for(&state, src).ok_or(not_found(Operation::Clone))?;
        let to = volume_for(&state, dst).ok_or(not_found(Operation::Clone))?;
        if from.id != to.id {
            return Err(PlatformError::CrossVolume);
        }
        if !from.supports_clones() {
            return Err(PlatformError::ClonesUnsupported);
        }
        if from.read_only {
            return Err(PlatformError::Os {
                operation: Operation::Clone,
                errno: libc::EROFS,
            });
        }
        if state.files.contains_key(dst) {
            return Err(PlatformError::Os {
                operation: Operation::Clone,
                errno: libc::EEXIST,
            });
        }
        // A clone keeps the contents and modification time, with its own inode.
        let inode = next_inode(&mut state);
        state.files.insert(
            dst.to_path_buf(),
            FakeFile {
                contents: source.contents,
                inode,
                modified: source.modified,
            },
        );
        state.clones += 1;
        Ok(())
    }

    fn volume_of(&self, path: &Path) -> Result<Volume, PlatformError> {
        require_absolute(path)?;
        volume_for(&lock(&self.state), path).ok_or(not_found(Operation::VolumeInfo))
    }

    fn identity(&self, path: &Path) -> Result<FileIdentity, PlatformError> {
        require_absolute(path)?;
        let state = lock(&self.state);
        let file = state.files.get(path).ok_or(not_found(Operation::Metadata))?;
        Ok(FileIdentity {
            kind: FileKind::File,
            inode: file.inode,
            size: file.contents.len() as u64,
            modified: file.modified,
        })
    }

    fn hash(&self, path: &Path, limit: u64) -> Result<Option<ContentHash>, PlatformError> {
        require_absolute(path)?;
        let mut state = lock(&self.state);
        let file = state.files.get(path).ok_or(not_found(Operation::Open))?;
        let digest = if file.contents.len() as u64 > limit {
            None
        } else {
            Some(fake_digest(&file.contents))
        };
        state.hashes += 1;
        Ok(digest)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake() -> (FakeVolumes, VolumeId, VolumeId, VolumeId) {
        let volumes = FakeVolumes::new();
        let data = volumes.add_volume("/System/Volumes/Data", FileSystemKind::Apfs, false);
        let external = volumes.add_volume("/Volumes/External", FileSystemKind::Apfs, false);
        let stick = volumes.add_volume("/Volumes/Stick", FileSystemKind::Other, false);
        (volumes, data, external, stick)
    }

    // FR-CKP-35: a clone across volumes is a typed error, never a panic or a silent copy.
    #[test]
    fn clone_fails_with_cross_volume_error_in_fake() {
        let (volumes, ..) = fake();
        volumes.add_file("/System/Volumes/Data/u/a.txt", b"one");
        let error = volumes
            .clone_file(
                Path::new("/System/Volumes/Data/u/a.txt"),
                Path::new("/Volumes/External/.knsh-checkpoints/a"),
            )
            .unwrap_err();
        assert_eq!(error, PlatformError::CrossVolume);
        assert_eq!(
            volumes.contents(Path::new("/Volumes/External/.knsh-checkpoints/a")),
            None
        );
        assert_eq!(volumes.clones(), 0);
    }

    #[test]
    fn clone_on_a_volume_without_clones_is_a_typed_error() {
        let (volumes, ..) = fake();
        volumes.add_file("/Volumes/Stick/a", b"one");
        assert_eq!(
            volumes.clone_file(Path::new("/Volumes/Stick/a"), Path::new("/Volumes/Stick/b")),
            Err(PlatformError::ClonesUnsupported)
        );
    }

    #[test]
    fn clone_within_a_volume_copies_contents_with_a_new_inode() {
        let (volumes, ..) = fake();
        let (src, dst) = (Path::new("/Volumes/External/a"), Path::new("/Volumes/External/b"));
        volumes.write(src, b"one");
        volumes.clone_file(src, dst).unwrap();
        let (a, b) = (volumes.identity(src).unwrap(), volumes.identity(dst).unwrap());
        assert_ne!(a.inode, b.inode);
        assert_eq!((a.size, a.modified), (b.size, b.modified));
        assert_eq!(volumes.contents(dst).as_deref(), Some(&b"one"[..]));
        // The destination must be new.
        assert_eq!(volumes.clone_file(src, dst).unwrap_err().errno(), Some(libc::EEXIST));
    }

    #[test]
    fn injected_clone_failures_map_like_the_real_backend() {
        let (volumes, ..) = fake();
        let (src, dst) = (Path::new("/Volumes/External/a"), Path::new("/Volumes/External/b"));
        volumes.write(src, b"one");
        for (errno, expected) in [
            (libc::EXDEV, PlatformError::CrossVolume),
            (libc::ENOTSUP, PlatformError::ClonesUnsupported),
            (
                libc::ENOSPC,
                PlatformError::Os {
                    operation: Operation::Clone,
                    errno: libc::ENOSPC,
                },
            ),
        ] {
            volumes.fail_clones(errno);
            assert_eq!(volumes.clone_file(src, dst), Err(expected));
        }
        volumes.allow_clones();
        assert_eq!(volumes.clone_file(src, dst), Ok(()));
    }

    #[test]
    fn volume_of_picks_the_innermost_mount() {
        let volumes = FakeVolumes::new();
        let root = volumes.add_volume("/", FileSystemKind::Apfs, true);
        let data = volumes.add_volume("/System/Volumes/Data", FileSystemKind::Apfs, false);
        let external = volumes.add_volume("/Volumes/External", FileSystemKind::Apfs, false);
        let id = |path: &str| volumes.volume_of(Path::new(path)).unwrap().id;
        assert_eq!(id("/usr/bin"), root);
        assert_eq!(id("/System/Volumes/Data/Users/u"), data);
        assert_eq!(id("/Volumes/External/code"), external);
        assert!(
            FakeVolumes::new()
                .volume_of(Path::new("/x"))
                .unwrap_err()
                .is_not_found()
        );
    }

    #[test]
    fn identity_changes_are_deterministic() {
        let (volumes, ..) = fake();
        let path = Path::new("/Volumes/External/a");
        volumes.write(path, b"one");
        let first = volumes.identity(path).unwrap();
        volumes.write(path, b"two");
        let written = volumes.identity(path).unwrap();
        assert_eq!(written.inode, first.inode, "a write in place keeps the inode");
        assert!(written.modified > first.modified);
        volumes.replace(path, b"two");
        assert_ne!(
            volumes.identity(path).unwrap().inode,
            first.inode,
            "a replace gets a new inode"
        );
        let stamp = ModifiedTime {
            seconds: 7,
            nanoseconds: 9,
        };
        volumes.set_modified(path, stamp);
        assert_eq!(volumes.identity(path).unwrap().modified, stamp);
    }

    #[test]
    fn hash_respects_the_limit() {
        let (volumes, ..) = fake();
        let path = Path::new("/Volumes/External/a");
        volumes.write(path, b"four");
        assert_eq!(volumes.hash(path, 4).unwrap(), Some(FakeVolumes::digest_of(b"four")));
        assert_eq!(volumes.hash(path, 3).unwrap(), None);
        assert_ne!(FakeVolumes::digest_of(b"four"), FakeVolumes::digest_of(b"five"));
        assert_eq!(volumes.hashes(), 2);
    }
}
