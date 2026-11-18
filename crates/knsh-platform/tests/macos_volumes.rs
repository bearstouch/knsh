//! macOS integration test for the checkpoint platform services (KNSH-078) on the real home APFS volume.
//!
//! Files live in a temporary folder under this crate's directory (on the volume the checkout is on, normally the
//! home volume), never in the user's real data.

#![cfg(all(test, target_os = "macos"))]
// Setup helpers outside `#[test]` functions: a failed setup step should abort the test loudly.
#![allow(clippy::unwrap_used)]

use std::fs;
use std::os::unix::fs::{MetadataExt, symlink};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};

use knsh_platform::macos::{SystemVolumes, sha256};
use knsh_platform::{ContentHash, FileKind, FileSystemKind, PlatformError, Volumes};

static COUNTER: AtomicU32 = AtomicU32::new(0);

/// A temporary folder, removed on drop (also when a test panics).
struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(format!(".knsh-test-volumes-{}-{n}", std::process::id()));
        fs::create_dir(&path).unwrap();
        Self(fs::canonicalize(&path).unwrap())
    }

    fn join(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Contents larger than one hash chunk and not a multiple of it.
fn sample() -> Vec<u8> {
    (0..300_001u32).map(|i| u8::try_from(i % 251).unwrap()).collect()
}

// FR-CKP-01, FR-CKP-09: a clone on the home APFS volume has identical contents and its own inode, and both hash
// to the SHA-256 of the contents.
#[test]
fn clones_and_hashes_real_files_on_the_home_volume() {
    let dir = TempDir::new();
    let volumes = SystemVolumes::new();
    let volume = volumes.volume_of(&dir.0).unwrap();
    assert_eq!(
        volume.kind,
        FileSystemKind::Apfs,
        "the checkout must be on APFS for this test"
    );
    assert!(volume.supports_clones() && !volume.read_only && !volume.ignores_ownership);

    let (src, dst) = (dir.join("src.bin"), dir.join("clone.bin"));
    let data = sample();
    fs::write(&src, &data).unwrap();
    volumes.clone_file(&src, &dst).unwrap();

    assert_eq!(fs::read(&dst).unwrap(), data);
    let (a, b) = (volumes.identity(&src).unwrap(), volumes.identity(&dst).unwrap());
    assert_ne!(a.inode, b.inode, "a clone is a new file");
    assert_eq!(
        (a.kind, a.size, a.modified),
        (FileKind::File, b.size, b.modified),
        "clones keep size and mtime"
    );
    assert_eq!(a.inode, fs::metadata(&src).unwrap().ino());

    let expected = Some(ContentHash::from_bytes(sha256(&data)));
    assert_eq!(volumes.hash(&src, u64::MAX).unwrap(), expected);
    assert_eq!(volumes.hash(&dst, u64::MAX).unwrap(), expected);
    // A limit below the size stops the hash.
    assert_eq!(volumes.hash(&src, data.len() as u64 - 1).unwrap(), None);

    // The clone shares the volume, and writing it leaves the source alone (copy-on-write).
    assert_eq!(volumes.volume_of(&dst).unwrap().id, volume.id);
    fs::write(&dst, b"changed").unwrap();
    assert_eq!(fs::read(&src).unwrap(), data);
}

// FR-CKP-35: failures are typed errors, never panics, and leave nothing at the destination.
#[test]
fn clone_failures_are_typed() {
    let dir = TempDir::new();
    let volumes = SystemVolumes::new();
    let src = dir.join("a");
    fs::write(&src, b"a").unwrap();
    fs::write(dir.join("taken"), b"x").unwrap();

    let exists = volumes.clone_file(&src, &dir.join("taken")).unwrap_err();
    assert_eq!(exists.errno(), Some(libc::EEXIST));
    assert!(
        volumes
            .clone_file(&dir.join("missing"), &dir.join("b"))
            .unwrap_err()
            .is_not_found()
    );
    assert_eq!(
        volumes.clone_file(Path::new("relative"), &dir.join("b")),
        Err(PlatformError::InvalidPath)
    );

    // `/dev` is devfs: another volume, not APFS.
    let dev = volumes.volume_of(Path::new("/dev")).unwrap();
    assert_eq!(dev.kind, FileSystemKind::Other);
    assert_ne!(dev.id, volumes.volume_of(&dir.0).unwrap().id);
    // `clonefile` reports `EXDEV` here (observed on macOS 26.6.2), the typed cross-volume error.
    assert_eq!(
        volumes.clone_file(&src, Path::new("/dev/knsh-clone-test")),
        Err(PlatformError::CrossVolume)
    );
    assert!(!Path::new("/dev/knsh-clone-test").exists());
}

// A symlink is cloned and identified as itself, and never hashed as its target; a FIFO is refused without
// waiting for a writer.
#[test]
fn symlinks_and_fifos_are_not_followed_or_waited_on() {
    let dir = TempDir::new();
    let volumes = SystemVolumes::new();
    fs::write(dir.join("target"), b"secret").unwrap();
    symlink(dir.join("target"), dir.join("link")).unwrap();

    assert_eq!(volumes.identity(&dir.join("link")).unwrap().kind, FileKind::Symlink);
    assert_eq!(
        volumes.hash(&dir.join("link"), u64::MAX).unwrap_err().errno(),
        Some(libc::ELOOP)
    );
    volumes.clone_file(&dir.join("link"), &dir.join("link-clone")).unwrap();
    assert!(
        fs::symlink_metadata(dir.join("link-clone"))
            .unwrap()
            .file_type()
            .is_symlink()
    );

    let status = Command::new("/usr/bin/mkfifo").arg(dir.join("fifo")).status().unwrap();
    assert!(status.success());
    assert_eq!(
        volumes.hash(&dir.join("fifo"), u64::MAX),
        Err(PlatformError::UnexpectedKind)
    );
    assert_eq!(volumes.identity(&dir.join("fifo")).unwrap().kind, FileKind::Other);
}

#[test]
fn volume_of_reports_the_mount_point() {
    let volumes = SystemVolumes::new();
    let root = volumes.volume_of(Path::new("/")).unwrap();
    assert_eq!(root.mount_point, Path::new("/"));
    let dir = TempDir::new();
    let here = volumes.volume_of(&dir.0).unwrap();
    assert!(dir.0.starts_with(&here.mount_point) || here.mount_point == Path::new("/System/Volumes/Data"));
    // Stable while mounted.
    assert_eq!(volumes.volume_of(&dir.0).unwrap(), here);
    assert!(volumes.volume_of(&dir.join("missing")).unwrap_err().is_not_found());
}
