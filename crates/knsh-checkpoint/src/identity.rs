//! Post-image identity (FR-CKP-09): what a changed path looked like right after the change, so that undo and redo
//! restore it only while the live file still matches (FR-CKP-20).
//!
//! An identity is the file's inode, size and modification time, plus a SHA-256 of its contents for regular files
//! under [`HASH_LIMIT`]. Larger files are not hashed (reading gigabytes at every line end would make checkpoint cost
//! grow with file size, FR-CKP-10), and the identity says so explicitly ([`PostImageIdentity::hash`] is `None`),
//! never with an empty or partial hash. Writes through a shared memory mapping move neither size nor modification
//! time (decision 17), which is why the hash matters where it can be taken.
//!
//! The hash is read between two identity reads that must agree, so the recorded hash belongs to the recorded
//! identity: a file that changes in between is read again, and one that keeps changing is an error rather than a
//! mismatched record.

use std::path::Path;

use knsh_platform::{ContentHash, FileIdentity, FileKind, PlatformError, Volumes};

use crate::capture::PostImage;
use crate::error::CheckpointError;
use crate::shadow::ShadowFiles;

/// Files of this many bytes or more get no content hash: 64 MiB (`specs/09-reference/defaults-and-limits.md`,
/// "under 64 MB").
pub const HASH_LIMIT: u64 = 64 * 1024 * 1024;

/// How many times the identity is read around the hash before the file is reported as unstable.
const ATTEMPTS: usize = 3;

/// A path's post-image identity (FR-CKP-09).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PostImageIdentity {
    /// Inode, size, modification time and kind.
    pub identity: FileIdentity,
    /// The SHA-256 of the contents, or `None` when no hash was taken: the file is [`HASH_LIMIT`] bytes or larger
    /// (or grew past it while being read), or is not a regular file.
    pub hash: Option<ContentHash>,
}

/// Reads the post-image identity of `path`, without following a final symlink.
///
/// # Errors
///
/// [`CheckpointError::Platform`] if the path cannot be read (for example `ENOENT` if it was removed);
/// [`CheckpointError::IdentityUnstable`] if it changed during every attempt.
pub fn post_image_identity(volumes: &dyn Volumes, path: &Path) -> Result<PostImageIdentity, CheckpointError> {
    read(
        path,
        |path| volumes.identity(path),
        |path, limit| volumes.hash(path, limit),
    )
}

/// [`post_image_identity`] through the watcher's file operations (KNSH-082): what capture records for a changed path
/// right after the shadow follows it.
///
/// # Errors
///
/// As [`post_image_identity`].
pub(crate) fn post_image_identity_of(
    files: &dyn ShadowFiles,
    path: &Path,
) -> Result<PostImageIdentity, CheckpointError> {
    read(path, |path| files.identity(path), |path, limit| files.hash(path, limit))
}

/// The post-image of `path` as capture and restore record it (FR-CKP-09, KNSH-082, KNSH-084): its identity,
/// [`PostImage::Deleted`] if nothing is there, or [`PostImage::Unknown`] if it cannot be read, never a guess.
pub(crate) fn post_image(files: &dyn ShadowFiles, path: &Path) -> PostImage {
    match post_image_identity_of(files, path) {
        Ok(identity) => PostImage::Present(identity),
        Err(CheckpointError::Platform(error)) if error.is_not_found() => PostImage::Deleted,
        // Only the first two are returned by an identity read; the rest are listed so a new kind of failure is never
        // mistaken for a deletion.
        Err(
            CheckpointError::Platform(_)
            | CheckpointError::IdentityUnstable
            | CheckpointError::Threads
            | CheckpointError::History(_)
            | CheckpointError::Conflicts(_)
            | CheckpointError::ForceNotAllowed
            | CheckpointError::NotOwnChange
            | CheckpointError::NoStore
            | CheckpointError::Journal
            | CheckpointError::RolledBack(_)
            | CheckpointError::RollbackFailed(_),
        ) => PostImage::Unknown,
    }
}

/// Reads an identity, and a hash between two identity reads that must agree (module documentation).
fn read(
    path: &Path,
    identity: impl Fn(&Path) -> Result<FileIdentity, PlatformError>,
    hash: impl Fn(&Path, u64) -> Result<Option<ContentHash>, PlatformError>,
) -> Result<PostImageIdentity, CheckpointError> {
    for _ in 0..ATTEMPTS {
        let before = identity(path)?;
        if before.kind != FileKind::File || before.size >= HASH_LIMIT {
            return Ok(PostImageIdentity {
                identity: before,
                hash: None,
            });
        }
        // `HASH_LIMIT - 1`: a file that grew to exactly 64 MiB while being read is not hashed either.
        let digest = hash(path, HASH_LIMIT - 1)?;
        let after = identity(path)?;
        if after == before {
            return Ok(PostImageIdentity {
                identity: after,
                hash: digest,
            });
        }
        // Changed while it was read: the hash may describe neither version. Read again.
    }
    Err(CheckpointError::IdentityUnstable)
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use knsh_platform::testing::FakeVolumes;
    use knsh_platform::{FileSystemKind, ModifiedTime, Volume, VolumeId};

    use super::*;

    const PATH: &str = "/Volumes/Code/app/data.bin";

    fn fake() -> FakeVolumes {
        let volumes = FakeVolumes::new();
        volumes.add_volume("/Volumes/Code", FileSystemKind::Apfs, false);
        volumes
    }

    /// Bytes of a given length, without a meaningful pattern.
    fn bytes(len: u64) -> Vec<u8> {
        vec![0x5a; usize::try_from(len).unwrap()]
    }

    // FR-CKP-09: the boundary is exactly 64 MiB — one byte under is hashed, 64 MiB and more are not, and the
    // identity says that no hash was taken.
    #[test]
    fn identity_without_hash_for_files_at_or_over_64_mib() {
        let volumes = fake();
        let path = Path::new(PATH);

        let under = bytes(HASH_LIMIT - 1);
        volumes.write(path, &under);
        let identity = post_image_identity(&volumes, path).unwrap();
        assert_eq!(identity.identity.size, HASH_LIMIT - 1);
        assert_eq!(identity.hash, Some(FakeVolumes::digest_of(&under)));

        for len in [HASH_LIMIT, HASH_LIMIT + 1] {
            volumes.write(path, &bytes(len));
            let hashes = volumes.hashes();
            let identity = post_image_identity(&volumes, path).unwrap();
            assert_eq!(identity.identity.size, len);
            assert_eq!(identity.hash, None, "no hash at {len} bytes");
            assert_eq!(volumes.hashes(), hashes, "the file is not even read");
        }
    }

    #[test]
    fn identity_records_inode_size_and_mtime() {
        let volumes = fake();
        let path = Path::new(PATH);
        volumes.write(path, b"hello");
        let stamp = ModifiedTime {
            seconds: 1_763_000_000,
            nanoseconds: 123_456_789,
        };
        volumes.set_modified(path, stamp);
        let identity = post_image_identity(&volumes, path).unwrap();
        assert_eq!(identity.identity, volumes.identity(path).unwrap());
        assert_eq!((identity.identity.size, identity.identity.modified), (5, stamp));
        assert_eq!(identity.hash, Some(FakeVolumes::digest_of(b"hello")));
    }

    #[test]
    fn missing_file_is_a_platform_error() {
        let error = post_image_identity(&fake(), Path::new(PATH)).unwrap_err();
        assert!(matches!(error, CheckpointError::Platform(e) if e.is_not_found()));
    }

    /// Wraps the fake and writes to the file during each of the first `writes` hashes, as a concurrent writer would.
    struct ChangingDuringHash {
        inner: FakeVolumes,
        writes: Mutex<usize>,
    }

    impl Volumes for ChangingDuringHash {
        fn clone_file(&self, src: &Path, dst: &Path) -> Result<(), PlatformError> {
            self.inner.clone_file(src, dst)
        }
        fn volume_of(&self, path: &Path) -> Result<Volume, PlatformError> {
            self.inner.volume_of(path)
        }
        fn identity(&self, path: &Path) -> Result<FileIdentity, PlatformError> {
            self.inner.identity(path)
        }
        fn hash(&self, path: &Path, limit: u64) -> Result<Option<ContentHash>, PlatformError> {
            let hash = self.inner.hash(path, limit);
            let mut writes = self.writes.lock().unwrap();
            if *writes > 0 {
                *writes -= 1;
                self.inner.write(path, b"changed meanwhile");
            }
            hash
        }
        fn write_in_place(&self, src: &Path, dst: &Path, expect: Option<&FileIdentity>) -> Result<(), PlatformError> {
            self.inner.write_in_place(src, dst, expect)
        }
        fn touch(&self, path: &Path) -> Result<(), PlatformError> {
            self.inner.touch(path)
        }
    }

    // FR-CKP-09: a hash is recorded only with the identity it was read under.
    #[test]
    fn hash_is_retaken_when_the_file_changes_while_read() {
        let volumes = ChangingDuringHash {
            inner: fake(),
            writes: Mutex::new(1),
        };
        let path = Path::new(PATH);
        volumes.inner.write(path, b"first");
        let identity = post_image_identity(&volumes, path).unwrap();
        assert_eq!(identity.hash, Some(FakeVolumes::digest_of(b"changed meanwhile")));
        assert_eq!(identity.identity, volumes.inner.identity(path).unwrap());

        let unstable = ChangingDuringHash {
            inner: fake(),
            writes: Mutex::new(usize::MAX),
        };
        unstable.inner.write(path, b"first");
        assert_eq!(
            post_image_identity(&unstable, path),
            Err(CheckpointError::IdentityUnstable)
        );
    }

    #[test]
    fn volume_ids_are_distinct_per_volume() {
        // Sanity check of the fake the store tests rely on.
        let volumes = fake();
        let other = volumes.add_volume("/Volumes/Other", FileSystemKind::Apfs, false);
        assert_ne!(volumes.volume_of(Path::new(PATH)).unwrap().id, other);
        assert_eq!(other, VolumeId::from_raw(2));
    }
}
