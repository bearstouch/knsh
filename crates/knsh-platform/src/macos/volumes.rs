//! The real [`Volumes`]: `clonefile(2)`, `statfs(2)`, `lstat(2)` and a streamed `CommonCrypto` SHA-256 (KNSH-078).

use std::ffi::{CStr, OsStr};
use std::fs::{self, OpenOptions};
use std::io;
use std::mem::MaybeUninit;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use crate::error::{Operation, PlatformError};
use crate::fs::require_absolute;
use crate::macos::digest::sha256_reader;
use crate::macos::fs::{c_path, kind_of};
use crate::volume::{ContentHash, FileIdentity, FileSystemKind, ModifiedTime, Volume, VolumeId, Volumes, clone_error};

/// `CLONE_NOFOLLOW` from `<sys/clonefile.h>`: clone a final symlink itself rather than its target. Not exported by
/// `libc`.
const CLONE_NOFOLLOW: u32 = 0x0001;

/// The `f_fstypename` APFS volumes report.
const APFS: &[u8] = b"apfs";

/// The real volume services.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemVolumes;

impl SystemVolumes {
    /// The real volume services.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

/// The bytes of a fixed-size, NUL-terminated `char` array from a system structure, up to the first NUL (the whole
/// array if it has none, so a missing terminator cannot read past it).
fn c_chars(chars: &[libc::c_char]) -> &[u8] {
    // SAFETY: `c_char` is `i8` or `u8`, both one byte with no invalid values, so the same region read as `u8` is
    // valid for the same length and lifetime.
    let bytes = unsafe { std::slice::from_raw_parts(chars.as_ptr().cast::<u8>(), chars.len()) };
    CStr::from_bytes_until_nul(bytes).map_or(bytes, CStr::to_bytes)
}

impl Volumes for SystemVolumes {
    fn clone_file(&self, src: &Path, dst: &Path) -> Result<(), PlatformError> {
        let (src, dst) = (c_path(src)?, c_path(dst)?);
        // SAFETY: both arguments are NUL-terminated C strings that live until the call returns; `clonefile` only
        // reads them. It creates `dst` atomically or not at all.
        let result = unsafe { libc::clonefile(src.as_ptr(), dst.as_ptr(), CLONE_NOFOLLOW) };
        if result == 0 {
            Ok(())
        } else {
            // `EXDEV` and `ENOTSUP` become typed errors so the caller can fall back to plain copies (FR-CKP-35).
            Err(clone_error(
                io::Error::last_os_error().raw_os_error().unwrap_or(libc::EIO),
            ))
        }
    }

    fn volume_of(&self, path: &Path) -> Result<Volume, PlatformError> {
        let c = c_path(path)?;
        let mut info = MaybeUninit::<libc::statfs>::uninit();
        // SAFETY: `c` is a NUL-terminated path alive for the call, and `info` is writable memory of exactly
        // `sizeof(struct statfs)` (the 64-bit-inode layout `libc` declares, which `statfs` uses on macOS 10.6+).
        if unsafe { libc::statfs(c.as_ptr(), info.as_mut_ptr()) } != 0 {
            return Err(PlatformError::from_io(
                Operation::VolumeInfo,
                &io::Error::last_os_error(),
            ));
        }
        // SAFETY: `statfs` returned 0, so it filled the whole structure.
        let info = unsafe { info.assume_init() };
        // SAFETY: `fsid_t` is `struct { int32_t val[2]; }` (`repr(C)`, 8 bytes, its field private in `libc`), so
        // reading it as `[i32; 2]` reads exactly its bytes, from a live, aligned local.
        let fsid: [i32; 2] = unsafe { std::ptr::read((&raw const info.f_fsid).cast::<[i32; 2]>()) };
        let high = u64::from(fsid[1].cast_unsigned());
        let low = u64::from(fsid[0].cast_unsigned());
        let kind = if c_chars(&info.f_fstypename) == APFS {
            FileSystemKind::Apfs
        } else {
            FileSystemKind::Other
        };
        Ok(Volume {
            id: VolumeId::from_raw((high << 32) | low),
            kind,
            mount_point: PathBuf::from(OsStr::from_bytes(c_chars(&info.f_mntonname))),
            read_only: info.f_flags & libc::MNT_RDONLY.cast_unsigned() != 0,
            ignores_ownership: info.f_flags & libc::MNT_IGNORE_OWNERSHIP.cast_unsigned() != 0,
        })
    }

    fn identity(&self, path: &Path) -> Result<FileIdentity, PlatformError> {
        require_absolute(path)?;
        let meta = fs::symlink_metadata(path).map_err(|error| PlatformError::from_io(Operation::Metadata, &error))?;
        Ok(identity_of(&meta))
    }

    fn hash(&self, path: &Path, limit: u64) -> Result<Option<ContentHash>, PlatformError> {
        require_absolute(path)?;
        // `O_NOFOLLOW`: a symlink is never hashed as its target. `O_NONBLOCK`: opening a FIFO does not wait for a
        // writer; it is refused below as not a regular file.
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)
            .map_err(|error| PlatformError::from_io(Operation::Open, &error))?;
        let meta = file
            .metadata()
            .map_err(|error| PlatformError::from_io(Operation::Metadata, &error))?;
        if !meta.file_type().is_file() {
            return Err(PlatformError::UnexpectedKind);
        }
        let digest =
            sha256_reader(&mut file, limit).map_err(|error| PlatformError::from_io(Operation::Read, &error))?;
        Ok(digest.map(ContentHash::from_bytes))
    }
}

/// The identity in `meta` (from `lstat`).
fn identity_of(meta: &fs::Metadata) -> FileIdentity {
    FileIdentity {
        kind: kind_of(meta.file_type()),
        inode: meta.ino(),
        size: meta.len(),
        modified: ModifiedTime {
            seconds: meta.mtime(),
            // `st_mtimespec.tv_nsec` is always within `0..1_000_000_000`.
            nanoseconds: u32::try_from(meta.mtime_nsec()).unwrap_or(0),
        },
    }
}
