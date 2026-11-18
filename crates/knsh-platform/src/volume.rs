//! Volumes, copy-on-write clones, file identity and content hashes: the platform services behind checkpoints
//! (KNSH-078).
//!
//! The checkpoint engine decides *when* to clone, where its store lives and what goes into a checkpoint; this module
//! only performs the effects, behind [`Volumes`], so that logic stays pure and is tested against
//! [`FakeVolumes`](crate::testing::FakeVolumes):
//!
//! - [`Volumes::clone_file`] clones one file copy-on-write. A clone across volumes, or on a file system without
//!   clones, is a typed error ([`PlatformError::CrossVolume`], [`PlatformError::ClonesUnsupported`]), never a
//!   panic and never a silent copy: the caller chooses the fallback (FR-CKP-35).
//! - [`Volumes::volume_of`] names the volume a path is on ([`Volume`]): a [`VolumeId`] that two paths share exactly
//!   when they are on one volume, the file-system kind (whether clones work) and the mount point.
//! - [`Volumes::identity`] reads a path's [`FileIdentity`] (inode, size, modification time with nanoseconds), the
//!   part of a post-image identity that needs no reading of contents (FR-CKP-09).
//! - [`Volumes::hash`] streams a file through SHA-256 in chunks of [`HASH_CHUNK`] bytes and stops once it passes a
//!   caller's limit, so no file is ever loaded whole. The 64 MB rule of FR-CKP-09 is the caller's policy
//!   (`knsh-checkpoint`), not this module's.

use std::fmt;
use std::path::{Path, PathBuf};

use crate::error::PlatformError;
use crate::fs::FileKind;

/// Bytes read per step when hashing: the whole buffer a hash ever holds, whatever the file's size.
pub const HASH_CHUNK: usize = 64 * 1024;

/// Bytes in a SHA-256 digest.
pub const CONTENT_HASH_LEN: usize = 32;

/// Identifies one mounted volume. Two paths have the same id exactly when they are on the same volume.
///
/// Built from `statfs`'s `f_fsid` on macOS. It is stable while the volume stays mounted, which is what the storage
/// layout needs (choosing a store per root when a session starts); it is not meant to be persisted across reboots or
/// remounts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VolumeId(u64);

impl VolumeId {
    /// Wraps a raw id (backends and fakes only).
    #[must_use]
    pub const fn from_raw(raw: u64) -> Self {
        Self(raw)
    }

    /// The raw id, for logs and test assertions.
    #[must_use]
    pub const fn raw(self) -> u64 {
        self.0
    }
}

/// The file system a volume is formatted with, as far as checkpoints care.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FileSystemKind {
    /// APFS: copy-on-write clones work within the volume.
    Apfs,
    /// Anything else (HFS+, exFAT, SMB, NFS, …): no clones, so roots there fall back to plain copies (FR-CKP-35).
    Other,
}

/// The volume one path is on.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Volume {
    /// The volume's identity.
    pub id: VolumeId,
    /// Its file system.
    pub kind: FileSystemKind,
    /// Where it is mounted (`/` for the boot volume, `/System/Volumes/Data` for the data volume, `/Volumes/<name>`
    /// for others). A per-volume checkpoint store sits directly in it.
    pub mount_point: PathBuf,
    /// Mounted read-only (`MNT_RDONLY`): nothing, a store included, can be created on it.
    pub read_only: bool,
    /// Mounted with ownership ignored (`MNT_IGNORE_OWNERSHIP`, the default for external disks): every file appears
    /// owned by whichever user looks at it, so owner-only modes protect nothing there and a folder another user
    /// created looks like this user's own. No private store can live on it (NFR-PRIV-04).
    pub ignores_ownership: bool,
}

impl Volume {
    /// Whether files on this volume can be cloned copy-on-write within it.
    #[must_use]
    pub fn supports_clones(&self) -> bool {
        match self.kind {
            FileSystemKind::Apfs => true,
            FileSystemKind::Other => false,
        }
    }
}

/// A modification time with nanoseconds, as `stat` reports it (`st_mtimespec`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ModifiedTime {
    /// Whole seconds since 1970-01-01 UTC (negative before it).
    pub seconds: i64,
    /// Nanoseconds within the second, `0..1_000_000_000`.
    pub nanoseconds: u32,
}

/// What can be learnt about a path without reading its contents: the identity half of a post-image identity
/// (FR-CKP-09). Read without following a final symlink, so a symlink is identified as itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FileIdentity {
    /// What the path names.
    pub kind: FileKind,
    /// The inode number. A file replaced by a rename gets a new one, one written in place keeps it.
    pub inode: u64,
    /// Size in bytes.
    pub size: u64,
    /// Last modification time. Writes through a shared memory mapping do not move it (decision 17), which is why a
    /// post-image identity also carries a content hash where it can.
    pub modified: ModifiedTime,
}

/// A SHA-256 digest of a file's contents.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ContentHash([u8; CONTENT_HASH_LEN]);

impl ContentHash {
    /// Wraps a digest.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; CONTENT_HASH_LEN]) -> Self {
        Self(bytes)
    }

    /// The digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; CONTENT_HASH_LEN] {
        &self.0
    }

    /// The digest as 64 lower-case hexadecimal digits.
    #[must_use]
    pub fn to_hex(&self) -> String {
        const DIGITS: &[u8; 16] = b"0123456789abcdef";
        let mut text = String::with_capacity(CONTENT_HASH_LEN * 2);
        for byte in self.0 {
            text.push(char::from(DIGITS[usize::from(byte >> 4)]));
            text.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
        }
        text
    }
}

impl fmt::Debug for ContentHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ContentHash({})", self.to_hex())
    }
}

/// Clones, volumes, identities and hashes. Object safe: hold it as `Arc<dyn Volumes>`.
///
/// All paths must be absolute; a relative path is refused with [`PlatformError::InvalidPath`], as by [`Fs`](crate::Fs).
pub trait Volumes: Send + Sync {
    /// Clones the file `src` to the new path `dst` copy-on-write: the clone shares `src`'s blocks until either is
    /// written, and gets its own inode. A final symlink at `src` is cloned as a link, never followed. `dst` must not
    /// exist. The clone keeps `src`'s mode, owner, flags, extended attributes and times (except setuid and setgid,
    /// which are cleared); callers that need other modes set them afterwards.
    ///
    /// # Errors
    ///
    /// - [`PlatformError::CrossVolume`] if `src` and `dst` are on different volumes.
    /// - [`PlatformError::ClonesUnsupported`] if the volume cannot clone (not APFS).
    /// - [`PlatformError::InvalidPath`] for a relative path or one with a NUL byte.
    /// - [`PlatformError::Os`] with [`Operation::Clone`](crate::Operation::Clone) for anything else: `EEXIST` if
    ///   `dst` exists, `ENOENT` if `src` or `dst`'s folder does not.
    ///
    /// On error nothing is left at `dst`.
    fn clone_file(&self, src: &Path, dst: &Path) -> Result<(), PlatformError>;

    /// The volume `path` is on. `path` must exist; a final symlink is followed (the volume of a root is the volume
    /// of what it names).
    ///
    /// # Errors
    ///
    /// [`PlatformError::InvalidPath`]; [`PlatformError::Os`] with
    /// [`Operation::VolumeInfo`](crate::Operation::VolumeInfo) (`ENOENT` if nothing exists there).
    fn volume_of(&self, path: &Path) -> Result<Volume, PlatformError>;

    /// The identity of `path` itself, without following a final symlink.
    ///
    /// # Errors
    ///
    /// [`PlatformError::InvalidPath`]; [`PlatformError::Os`] with [`Operation::Metadata`](crate::Operation::Metadata)
    /// (`ENOENT` if nothing exists there).
    fn identity(&self, path: &Path) -> Result<FileIdentity, PlatformError>;

    /// The SHA-256 of the regular file at `path`, streamed in chunks of at most [`HASH_CHUNK`] bytes. Returns
    /// `None`, without reading further, once more than `limit` bytes have been read: a file larger than `limit` is
    /// never hashed, including one that grows past it while being read. A final symlink is not followed.
    ///
    /// # Errors
    ///
    /// [`PlatformError::InvalidPath`]; [`PlatformError::UnexpectedKind`] if `path` is not a regular file (a FIFO
    /// is refused without waiting for a writer); [`PlatformError::Os`] with
    /// [`Operation::Open`](crate::Operation::Open) (`ELOOP` for a symlink) or
    /// [`Operation::Read`](crate::Operation::Read).
    fn hash(&self, path: &Path, limit: u64) -> Result<Option<ContentHash>, PlatformError>;
}

/// Maps a `clonefile` `errno`, shared by the real backend and the fake so both report failures alike. The two
/// outcomes the storage layout branches on get their own variants (FR-CKP-35); everything else stays an OS error.
#[cfg(any(target_os = "macos", test, doc, feature = "testing"))]
pub(crate) fn clone_error(errno: i32) -> PlatformError {
    match errno {
        libc::EXDEV => PlatformError::CrossVolume,
        libc::ENOTSUP => PlatformError::ClonesUnsupported,
        errno => PlatformError::Os {
            operation: crate::error::Operation::Clone,
            errno,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_hash_renders_as_lower_case_hex() {
        let mut bytes = [0u8; CONTENT_HASH_LEN];
        bytes[0] = 0xab;
        bytes[31] = 0x0f;
        let hash = ContentHash::from_bytes(bytes);
        let hex = hash.to_hex();
        assert_eq!(hex.len(), 64);
        assert!(hex.starts_with("ab00") && hex.ends_with("000f"), "{hex}");
        assert_eq!(format!("{hash:?}"), format!("ContentHash({hex})"));
    }

    #[test]
    fn only_apfs_supports_clones() {
        let volume = |kind| Volume {
            id: VolumeId::from_raw(1),
            kind,
            mount_point: PathBuf::from("/"),
            read_only: false,
            ignores_ownership: false,
        };
        assert!(volume(FileSystemKind::Apfs).supports_clones());
        assert!(!volume(FileSystemKind::Other).supports_clones());
    }
}
