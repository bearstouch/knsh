//! Checkpoint storage layout: one store per volume, so clones always stay on the volume of the files they protect
//! (FR-CKP-35, KNSH-078; `specs/05-models/checkpoint.md#storage`, `specs/09-reference/file-locations.md`).
//!
//! [`place_roots`] chooses, for each checkpoint root, where its checkpoints go and how they are taken:
//!
//! | Root on | Store | Method |
//! | --- | --- | --- |
//! | The home volume (APFS) | Home store, `checkpoints/` in the engine data directory | [`Method::ApfsClone`] |
//! | Another APFS volume, writable | `.knsh-checkpoints/` at that volume's mount point | [`Method::ApfsClone`] |
//! | Another APFS volume whose store cannot be used | Home store | [`Method::PlainCopy`] |
//! | A non-APFS or read-only volume, or one that ignores ownership | Home store | [`Method::PlainCopy`] |
//! | A volume that cannot be read, or any root needing an unusable home store | — | [`Method::None`] |
//!
//! The home store is never placed on another volume, and a `.knsh-checkpoints/` store is never created on the home
//! volume. A volume store is used only after checking that it really is on the root's volume.
//!
//! # Every store
//!
//! - **Owner-only, out of Spotlight and Time Machine (NFR-PRIV-04).** The store directory is `0700`, its files
//!   `0600`; it carries the Spotlight marker and the Time Machine exclusion attribute, both verified after writing
//!   (the same steps as the engine directories, KNSH-011). A store owned by another user, or a symlink or file in
//!   its place, is never adopted: on a volume shared with other users that would hand them the checkpoints.
//! - **Denied to envelopes and commands.** The home store lies inside the engine data directory, a fixed deny. Every
//!   `.knsh-checkpoints` path is a fixed deny too, wherever it is mounted (`knsh_core::VOLUME_CHECKPOINT_DIR`; the
//!   sandbox compiler denies it by name in every profile).
//! - **Versioned.** A store holds a `format` file, `knsh-checkpoints <version>\n`, written by atomic replace when
//!   the store is new. A store of a newer format, or one whose format file is unreadable or malformed, or that holds
//!   entries but no format file, **triggers recovery and is never overwritten**: it is left exactly as found and not
//!   used. Its roots fall back (a volume store's roots to plain copies in the home store; the home store's roots to
//!   [`Method::None`]), and the reason is kept ([`StoreFault`]) for `knshd` to log.
//!
//! # Plain copies
//!
//! A root stored as plain copies ([`Method::PlainCopy`]) protects a change only up to [`PLAIN_COPY_LIMIT`] bytes;
//! a larger change is recorded as not protected ([`Protection::NotProtected`]), never truncated
//! ([`RootStore::protection_for_change`]). What goes into a checkpoint is KNSH-082.

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use knsh_core::{CanonicalPath, VOLUME_CHECKPOINT_DIR};
use knsh_platform::engine_dirs::{FILE_MODE, SPOTLIGHT_MARKER, ensure_private_dir, exclude_from_index_and_backup};
use knsh_platform::{EnginePaths, FileKind, Fs, PlatformError, Volume, VolumeId, Volumes};

/// The file in every store that names its on-disk format.
pub const FORMAT_FILE: &str = "format";

/// The store format this build reads and writes.
pub const FORMAT_VERSION: u32 = 1;

/// The largest change, in bytes, that a plain-copy root protects: 50 MiB (FR-CKP-35, "50 MB per change").
pub const PLAIN_COPY_LIMIT: u64 = 50 * 1024 * 1024;

/// What a format file starts with, before the version number.
const FORMAT_PREFIX: &str = "knsh-checkpoints ";

/// Bytes read from a format file at most: a valid one is about 30.
const FORMAT_READ_LIMIT: u64 = 64;

/// Entries read from a store without a format file when checking that it is empty: anything beyond the marker and
/// a temporary file means it is not.
const EMPTY_STORE_LIST_LIMIT: usize = 16;

/// How a root's checkpoints are taken: its entry in the capability report (`hello`'s `checkpoints`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Method {
    /// Copy-on-write clones in a store on the root's own APFS volume.
    ApfsClone,
    /// Plain copies in the home store, limited to [`PLAIN_COPY_LIMIT`] per change (FR-CKP-35).
    PlainCopy,
    /// The root cannot be checkpointed.
    None,
}

impl Method {
    /// The wire value in the capability report: `apfs-clone`, `plain-copy` or `none`
    /// (`specs/05-models/capabilities.md`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ApfsClone => "apfs-clone",
            Self::PlainCopy => "plain-copy",
            Self::None => "none",
        }
    }
}

/// Why a store was not used. The store is left exactly as found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreFault {
    /// Its format file names a newer format than [`FORMAT_VERSION`] (a newer `knsh` wrote it).
    NewerFormat {
        /// The version found.
        version: u32,
    },
    /// Its format file is malformed, not a regular file, too long or names version 0; or the store holds entries
    /// but no format file.
    Corrupt,
    /// Preparing or reading it failed: a foreign owner, a symlink in its place, an unverified exclusion, or an I/O
    /// error (for example `EACCES` or `EROFS` on a volume the user cannot write).
    Platform(PlatformError),
}

/// Why a root does not use clones in a store on its own volume.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fallback {
    /// The root's volume is not APFS, so it cannot clone.
    NoClones,
    /// The root's volume is mounted read-only, so no store can be created on it.
    ReadOnlyVolume,
    /// The root's volume ignores ownership (`MNT_IGNORE_OWNERSHIP`, the default for external disks): every user
    /// would be the store's owner, so it could be neither private nor shown to be this user's (NFR-PRIV-04).
    OwnershipIgnored,
    /// The store on the root's volume cannot be used.
    VolumeStore(StoreFault),
    /// The home store cannot be used (or its volume cannot be read), and the root needs it.
    HomeStore(StoreFault),
    /// The root's volume cannot be read (for example the root does not exist).
    VolumeUnknown(PlatformError),
}

/// Where one root's checkpoints go.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootStore {
    /// The checkpoint root.
    pub root: CanonicalPath,
    /// How its checkpoints are taken.
    pub method: Method,
    /// The store directory: on the root's volume for [`Method::ApfsClone`], the home store for
    /// [`Method::PlainCopy`], `None` for [`Method::None`].
    pub store: Option<PathBuf>,
    /// Why the root is not on clones in a store on its own volume; `None` when it is.
    pub fallback: Option<Fallback>,
}

/// Whether one change in a root is protected by a checkpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protection {
    /// The change's pre-images can be kept.
    Protected,
    /// The change is recorded as not protected.
    NotProtected(Unprotected),
}

/// Why a change is not protected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unprotected {
    /// A plain-copy change larger than [`PLAIN_COPY_LIMIT`] (FR-CKP-35). Nothing of it is kept: a truncated copy
    /// would restore a wrong file.
    OverPlainCopyLimit {
        /// The change's size in bytes.
        bytes: u64,
    },
    /// The root has no store ([`Method::None`]).
    NoStore,
}

impl RootStore {
    /// Whether a change of `bytes` bytes (the pre-images it would keep) in this root is protected.
    #[must_use]
    pub fn protection_for_change(&self, bytes: u64) -> Protection {
        match self.method {
            Method::ApfsClone => Protection::Protected,
            Method::PlainCopy if bytes <= PLAIN_COPY_LIMIT => Protection::Protected,
            Method::PlainCopy => Protection::NotProtected(Unprotected::OverPlainCopyLimit { bytes }),
            Method::None => Protection::NotProtected(Unprotected::NoStore),
        }
    }
}

/// The capability report's `checkpoints` object: each root's path with its [`Method`]. Paths that are not UTF-8
/// are written lossily (roots come from profile text, which is UTF-8).
#[must_use]
pub fn capability_report(stores: &[RootStore]) -> BTreeMap<String, Method> {
    stores
        .iter()
        .map(|store| (store.root.as_path().to_string_lossy().into_owned(), store.method))
        .collect()
}

/// Chooses and prepares the store of each root in `roots` (module documentation), creating stores that do not
/// exist yet. Never fails as a whole: a root whose store cannot be used falls back, and the reason is in its
/// [`RootStore::fallback`]. The engine directories must already exist (`ensure_engine_dirs`); `uid` is the user the
/// engine runs as.
#[must_use]
pub fn place_roots(
    fs: &dyn Fs,
    volumes: &dyn Volumes,
    paths: &EnginePaths,
    uid: u32,
    roots: &[CanonicalPath],
) -> Vec<RootStore> {
    let home_dir = paths.checkpoints_dir();
    // The home store and its volume. Either failing makes the home store unusable: without its volume, no root can
    // be shown to be elsewhere, so no volume store is tried either.
    let home = open_store(fs, &home_dir, uid)
        .and_then(|()| volumes.volume_of(&home_dir).map_err(StoreFault::Platform))
        .map(|volume| (home_dir, volume.id));

    let mut volume_stores: BTreeMap<VolumeId, Result<PathBuf, StoreFault>> = BTreeMap::new();
    roots
        .iter()
        .map(|root| {
            let (method, store, fallback) = match &home {
                Err(fault) => (Method::None, None, Some(Fallback::HomeStore(*fault))),
                Ok((home_dir, home_volume)) => match volumes.volume_of(root.as_path()) {
                    // Without its volume the root cannot be shown to share one with any store: no checkpoints.
                    Err(error) => (Method::None, None, Some(Fallback::VolumeUnknown(error))),
                    Ok(volume) if !volume.supports_clones() => plain_copies(home_dir, Fallback::NoClones),
                    // The home store already sits on this volume, so a `.knsh-checkpoints/` folder is never made here.
                    Ok(volume) if volume.id == *home_volume => (Method::ApfsClone, Some(home_dir.clone()), None),
                    Ok(volume) if volume.read_only => plain_copies(home_dir, Fallback::ReadOnlyVolume),
                    // Owner checks and `0700` mean nothing there: another user's folder would be adopted and the
                    // checkpoints readable by everyone.
                    Ok(volume) if volume.ignores_ownership => plain_copies(home_dir, Fallback::OwnershipIgnored),
                    // One store per volume, opened once however many roots share it.
                    Ok(volume) => {
                        let opened = volume_stores
                            .entry(volume.id)
                            .or_insert_with(|| open_volume_store(fs, volumes, &volume, uid));
                        match opened {
                            Ok(store) => (Method::ApfsClone, Some(store.clone()), None),
                            Err(fault) => plain_copies(home_dir, Fallback::VolumeStore(*fault)),
                        }
                    }
                },
            };
            RootStore {
                root: root.clone(),
                method,
                store,
                fallback,
            }
        })
        .collect()
}

/// A root kept as plain copies in the home store, and why.
fn plain_copies(home_dir: &Path, why: Fallback) -> (Method, Option<PathBuf>, Option<Fallback>) {
    (Method::PlainCopy, Some(home_dir.to_path_buf()), Some(why))
}

/// Opens (creating if needed) the `.knsh-checkpoints/` store at `volume`'s mount point, and checks that it is on
/// that volume: a mount point the volume does not own (another volume mounted over it, a symlink) must not receive
/// clones that would then fail or, worse, land elsewhere.
fn open_volume_store(fs: &dyn Fs, volumes: &dyn Volumes, volume: &Volume, uid: u32) -> Result<PathBuf, StoreFault> {
    let dir = volume.mount_point.join(VOLUME_CHECKPOINT_DIR);
    open_store(fs, &dir, uid)?;
    let actual = volumes.volume_of(&dir).map_err(StoreFault::Platform)?;
    if actual.id == volume.id {
        Ok(dir)
    } else {
        Err(StoreFault::Platform(PlatformError::CrossVolume))
    }
}

/// Prepares the store directory `dir` and checks its format, in an order that never changes a store this build
/// cannot use. An existing store is first checked as it is (a directory of this user, with this build's format),
/// and only then tightened to owner-only; a new one is created owner-only and given a format file. The Spotlight
/// marker and Time Machine exclusion come last, so a newer or corrupt store is left exactly as found.
fn open_store(fs: &dyn Fs, dir: &Path, uid: u32) -> Result<(), StoreFault> {
    match fs.metadata(dir) {
        Ok(meta) => {
            // Refused before reading anything in it: a symlink could point the store anywhere, and another user's
            // folder is never adopted.
            if meta.kind != FileKind::Directory {
                return Err(StoreFault::Platform(PlatformError::UnexpectedKind));
            }
            if meta.uid != uid {
                return Err(StoreFault::Platform(PlatformError::ForeignOwner));
            }
            check_format(fs, dir, uid)?;
            ensure_private_dir(fs, dir, uid).map_err(StoreFault::Platform)?;
        }
        Err(error) if error.is_not_found() => {
            ensure_private_dir(fs, dir, uid).map_err(StoreFault::Platform)?;
            check_format(fs, dir, uid)?;
        }
        Err(error) => return Err(StoreFault::Platform(error)),
    }
    exclude_from_index_and_backup(fs, dir, uid).map_err(StoreFault::Platform)
}

/// Checks the store's format file, writing it if the store is new (empty).
fn check_format(fs: &dyn Fs, dir: &Path, uid: u32) -> Result<(), StoreFault> {
    let path = dir.join(FORMAT_FILE);
    let meta = match fs.metadata(&path) {
        Ok(meta) => meta,
        Err(error) if error.is_not_found() => return initialise(fs, dir, &path),
        Err(error) => return Err(StoreFault::Platform(error)),
    };
    // Checked before reading, without following a symlink: a link here could make the store read anything.
    if meta.kind != FileKind::File {
        return Err(StoreFault::Corrupt);
    }
    if meta.uid != uid {
        return Err(StoreFault::Platform(PlatformError::ForeignOwner));
    }
    let text = match fs.read(&path, FORMAT_READ_LIMIT) {
        Ok(text) => text,
        Err(PlatformError::TooLarge { .. }) => return Err(StoreFault::Corrupt),
        Err(error) => return Err(StoreFault::Platform(error)),
    };
    match parse_format(&text) {
        Some(FORMAT_VERSION) => {}
        Some(version) if version > FORMAT_VERSION => return Err(StoreFault::NewerFormat { version }),
        // Version 0 never existed; anything unparseable is corrupt.
        Some(_) | None => return Err(StoreFault::Corrupt),
    }
    if meta.mode != FILE_MODE {
        fs.set_mode(&path, FILE_MODE).map_err(StoreFault::Platform)?;
    }
    Ok(())
}

/// Writes the format file of a store that has none, but only if the store is empty: entries without a format file
/// are data this build did not write, and are never adopted.
fn initialise(fs: &dyn Fs, dir: &Path, path: &Path) -> Result<(), StoreFault> {
    let entries = match fs.list_dir(dir, EMPTY_STORE_LIST_LIMIT) {
        Ok(entries) => entries,
        Err(PlatformError::TooLarge { .. }) => return Err(StoreFault::Corrupt),
        Err(error) => return Err(StoreFault::Platform(error)),
    };
    if !entries.iter().all(|name| is_expected_in_new_store(name)) {
        return Err(StoreFault::Corrupt);
    }
    let text = format!("{FORMAT_PREFIX}{FORMAT_VERSION}\n");
    fs.atomic_replace(path, text.as_bytes(), FILE_MODE)
        .map_err(StoreFault::Platform)
}

/// Entries a store may hold before its format file exists: the Spotlight marker (from an earlier run that stopped
/// between the two steps) and a temporary file left by an interrupted atomic replace of the format file.
fn is_expected_in_new_store(name: &OsStr) -> bool {
    let bytes = name.as_encoded_bytes();
    bytes == SPOTLIGHT_MARKER.as_bytes() || (bytes.starts_with(b".knsh.") && bytes.ends_with(b".tmp"))
}

/// The version in a format file's text: exactly `knsh-checkpoints <digits>\n`, no sign, no spaces, at most nine
/// digits.
fn parse_format(text: &[u8]) -> Option<u32> {
    let digits = text.strip_prefix(FORMAT_PREFIX.as_bytes())?.strip_suffix(b"\n")?;
    if digits.is_empty() || digits.len() > 9 || !digits.iter().all(u8::is_ascii_digit) {
        return None;
    }
    std::str::from_utf8(digits).ok()?.parse().ok()
}

#[cfg(test)]
mod tests {
    use knsh_platform::engine_dirs::{BACKUP_EXCLUDE_ATTRIBUTE, BACKUP_EXCLUDE_VALUE, DIR_MODE};
    use knsh_platform::testing::{FakeVolumes, MemFs};
    use knsh_platform::{FileSystemKind, Operation, ensure_engine_dirs};

    use super::*;

    // macOS `errno` values: no crate but `knsh-platform` may depend on `libc` (NFR-SUP-02).
    const EEXIST: i32 = 17;
    const EACCES: i32 = 13;

    const HOME: &str = "/Users/u";
    const EXTERNAL_STORE: &str = "/Volumes/External/.knsh-checkpoints";

    /// The home store, from the one place engine paths are built.
    fn home_store() -> PathBuf {
        EnginePaths::for_home(Path::new(HOME)).unwrap().checkpoints_dir()
    }

    /// A home on an APFS data volume (mounted at `/`, like a firmlinked home seen from the root), with the engine
    /// directories ready, plus an external APFS volume, a non-APFS stick and a read-only APFS disk image.
    struct Machine {
        fs: MemFs,
        volumes: FakeVolumes,
        paths: EnginePaths,
    }

    impl Machine {
        fn new() -> Self {
            let fs = MemFs::new();
            fs.set_umask(0o022);
            for dir in [
                HOME,
                "/Volumes/External/code",
                "/Volumes/Stick/code",
                "/Volumes/Image/code",
            ] {
                fs.add_dir_all(Path::new(dir)).unwrap();
            }
            let paths = EnginePaths::for_home(Path::new(HOME)).unwrap();
            ensure_engine_dirs(&fs, &paths, fs.uid()).unwrap();
            let volumes = FakeVolumes::new();
            volumes.add_volume("/", FileSystemKind::Apfs, false);
            volumes.add_volume("/Volumes/External", FileSystemKind::Apfs, false);
            volumes.add_volume("/Volumes/Stick", FileSystemKind::Other, false);
            volumes.add_volume("/Volumes/Image", FileSystemKind::Apfs, true);
            Self { fs, volumes, paths }
        }

        fn place(&self, roots: &[&str]) -> Vec<RootStore> {
            let roots: Vec<CanonicalPath> = roots.iter().map(|root| CanonicalPath::new(*root).unwrap()).collect();
            place_roots(&self.fs, &self.volumes, &self.paths, self.fs.uid(), &roots)
        }

        fn place_one(&self, root: &str) -> RootStore {
            self.place(&[root]).remove(0)
        }

        fn assert_private_store(&self, dir: impl AsRef<Path>) {
            let dir = dir.as_ref();
            let meta = self.fs.metadata(dir).unwrap();
            assert_eq!((meta.kind, meta.mode), (FileKind::Directory, DIR_MODE));
            let format = self.fs.metadata(&dir.join(FORMAT_FILE)).unwrap();
            assert_eq!((format.kind, format.mode), (FileKind::File, FILE_MODE));
            assert_eq!(
                self.fs.contents(&dir.join(FORMAT_FILE)).as_deref(),
                Some(&b"knsh-checkpoints 1\n"[..])
            );
            let marker = self.fs.metadata(&dir.join(SPOTLIGHT_MARKER)).unwrap();
            assert_eq!((marker.kind, marker.mode), (FileKind::File, FILE_MODE));
            assert_eq!(
                self.fs.xattr(dir, BACKUP_EXCLUDE_ATTRIBUTE, 256).unwrap().as_deref(),
                Some(BACKUP_EXCLUDE_VALUE)
            );
        }
    }

    // FR-CKP-35, NFR-PRIV-04: a root on the home volume uses the owner-only, excluded home store, with clones.
    #[test]
    fn home_volume_root_uses_home_store() {
        let machine = Machine::new();
        let store = machine.place_one("/Users/u/src/app");
        assert_eq!(store.method, Method::ApfsClone);
        assert_eq!(store.store.as_deref(), Some(home_store().as_path()));
        assert_eq!(store.fallback, None);
        machine.assert_private_store(home_store());
        // Never a `.knsh-checkpoints` folder on the home volume.
        assert!(machine.fs.metadata(Path::new("/.knsh-checkpoints")).is_err());
    }

    // FR-CKP-35: a root on another writable APFS volume gets `.knsh-checkpoints/` at that volume's root.
    #[test]
    fn other_apfs_volume_uses_local_checkpoint_folder() {
        let machine = Machine::new();
        let stores = machine.place(&["/Volumes/External/code/a", "/Volumes/External/code/b"]);
        for store in &stores {
            assert_eq!(store.method, Method::ApfsClone);
            assert_eq!(store.store.as_deref(), Some(Path::new(EXTERNAL_STORE)));
            assert_eq!(store.fallback, None);
        }
        machine.assert_private_store(EXTERNAL_STORE);
    }

    // FR-CKP-35: no clones on a non-APFS volume, so plain copies in the home store.
    #[test]
    fn non_apfs_root_falls_back_to_plain_copies() {
        let machine = Machine::new();
        let store = machine.place_one("/Volumes/Stick/code");
        assert_eq!(store.method, Method::PlainCopy);
        assert_eq!(store.store.as_deref(), Some(home_store().as_path()));
        assert_eq!(store.fallback, Some(Fallback::NoClones));
        assert!(
            machine
                .fs
                .metadata(Path::new("/Volumes/Stick/.knsh-checkpoints"))
                .is_err()
        );
    }

    // FR-CKP-35: an APFS volume that is read-only, or whose store cannot be created, falls back to plain copies.
    #[test]
    fn unwritable_apfs_volume_falls_back_to_plain_copies() {
        let machine = Machine::new();
        let store = machine.place_one("/Volumes/Image/code");
        assert_eq!(
            (store.method, store.fallback),
            (Method::PlainCopy, Some(Fallback::ReadOnlyVolume))
        );

        // Writable by the mount flags, but the user may not create anything at its root.
        let machine = Machine::new();
        // The home store is created first: it sees "already exists" (as it does, harmlessly); the volume store's
        // creation is then refused.
        machine.fs.inject_fault(Operation::CreateDirectory, EEXIST);
        machine.fs.inject_fault(Operation::CreateDirectory, EACCES);
        let store = machine.place_one("/Volumes/External/code");
        assert_eq!(store.method, Method::PlainCopy, "{store:?}");
        assert_eq!(store.store.as_deref(), Some(home_store().as_path()));
        assert!(matches!(
            store.fallback,
            Some(Fallback::VolumeStore(StoreFault::Platform(error))) if error.errno() == Some(EACCES)
        ));
    }

    // NFR-PRIV-04: on a volume that ignores ownership (external disks by default), `0700` and owner checks protect
    // nothing, so no store is created or adopted there; its roots use plain copies in the home store.
    #[test]
    fn volume_ignoring_ownership_gets_no_store() {
        let machine = Machine::new();
        machine.volumes.set_ignores_ownership("/Volumes/External", true);
        // Even a store that looks like this build's own (another user's, seen as ours) is not adopted.
        machine.fs.add_dir_all(Path::new(EXTERNAL_STORE)).unwrap();
        let store = machine.place_one("/Volumes/External/code");
        assert_eq!(
            (store.method, store.store.as_deref(), store.fallback),
            (
                Method::PlainCopy,
                Some(home_store().as_path()),
                Some(Fallback::OwnershipIgnored)
            )
        );
        assert!(
            machine
                .fs
                .metadata(&Path::new(EXTERNAL_STORE).join(FORMAT_FILE))
                .is_err(),
            "the folder is left as found"
        );
    }

    // FR-CKP-35: a change over the plain-copy limit is recorded as not protected, never truncated; exactly the
    // limit is still protected; clone roots have no limit.
    #[test]
    fn plain_copy_change_over_50_mb_is_marked_unprotected() {
        let machine = Machine::new();
        let plain = machine.place_one("/Volumes/Stick/code");
        assert_eq!(plain.protection_for_change(PLAIN_COPY_LIMIT), Protection::Protected);
        assert_eq!(
            plain.protection_for_change(PLAIN_COPY_LIMIT + 1),
            Protection::NotProtected(Unprotected::OverPlainCopyLimit {
                bytes: PLAIN_COPY_LIMIT + 1
            })
        );
        let clone = machine.place_one("/Users/u/src/app");
        assert_eq!(
            clone.protection_for_change(10 * PLAIN_COPY_LIMIT),
            Protection::Protected
        );
        let none = RootStore {
            method: Method::None,
            store: None,
            ..clone
        };
        assert_eq!(
            none.protection_for_change(1),
            Protection::NotProtected(Unprotected::NoStore)
        );
    }

    // Persistence rule: a store of a newer format is used by nobody here and is left byte for byte as it was.
    #[test]
    fn newer_store_version_is_not_overwritten() {
        let machine = Machine::new();
        let format = Path::new(EXTERNAL_STORE).join(FORMAT_FILE);
        machine.fs.add_dir_all(Path::new(EXTERNAL_STORE)).unwrap();
        machine.fs.write(&format, b"knsh-checkpoints 2\n", FILE_MODE).unwrap();
        let in_store = || -> Vec<PathBuf> {
            machine
                .fs
                .paths()
                .into_iter()
                .filter(|path| path.starts_with(EXTERNAL_STORE))
                .collect()
        };
        let before = in_store();

        let store = machine.place_one("/Volumes/External/code");
        assert_eq!(store.method, Method::PlainCopy);
        assert_eq!(
            store.fallback,
            Some(Fallback::VolumeStore(StoreFault::NewerFormat { version: 2 }))
        );
        assert_eq!(
            machine.fs.contents(&format).as_deref(),
            Some(&b"knsh-checkpoints 2\n"[..])
        );
        assert_eq!(in_store(), before, "nothing added to the newer store");
        assert_eq!(
            machine.fs.metadata(Path::new(EXTERNAL_STORE)).unwrap().mode,
            0o755,
            "not even its mode is changed"
        );
        assert_eq!(
            machine
                .fs
                .xattr(Path::new(EXTERNAL_STORE), BACKUP_EXCLUDE_ATTRIBUTE, 256)
                .unwrap(),
            None,
            "not even its attributes are changed"
        );

        // The same for the home store: its roots cannot be checkpointed at all.
        let home_format = home_store().as_path().join(FORMAT_FILE);
        machine
            .fs
            .write(&home_format, b"knsh-checkpoints 7\n", FILE_MODE)
            .unwrap();
        let store = machine.place_one("/Users/u/src/app");
        assert_eq!(
            (store.method, store.store, store.fallback),
            (
                Method::None,
                None,
                Some(Fallback::HomeStore(StoreFault::NewerFormat { version: 7 }))
            )
        );
        assert_eq!(
            machine.fs.contents(&home_format).as_deref(),
            Some(&b"knsh-checkpoints 7\n"[..])
        );
    }

    // Persistence rule: a corrupt store, or unknown data without a format file, is never overwritten.
    #[test]
    fn corrupt_store_is_not_overwritten() {
        for (name, contents) in [
            (FORMAT_FILE, &b"garbage"[..]),
            (FORMAT_FILE, b"knsh-checkpoints 0\n"),
            (FORMAT_FILE, b"knsh-checkpoints +1\n"),
            (FORMAT_FILE, b"knsh-checkpoints 1"),
            (FORMAT_FILE, &[b'x'; 100]),
            ("someone-elses-data", b"keep me"),
        ] {
            let machine = Machine::new();
            let dir = Path::new(EXTERNAL_STORE);
            machine.fs.add_dir_all(dir).unwrap();
            machine.fs.write(&dir.join(name), contents, FILE_MODE).unwrap();
            let store = machine.place_one("/Volumes/External/code");
            assert_eq!(
                store.fallback,
                Some(Fallback::VolumeStore(StoreFault::Corrupt)),
                "{name}: {contents:?}"
            );
            assert_eq!(machine.fs.contents(&dir.join(name)).as_deref(), Some(contents));
            if name != FORMAT_FILE {
                assert!(
                    machine.fs.metadata(&dir.join(FORMAT_FILE)).is_err(),
                    "no format file added"
                );
            }
        }
    }

    // A format file that is a symlink is never followed; a store owned by someone else is never adopted.
    #[test]
    fn foreign_or_linked_stores_are_refused() {
        let machine = Machine::new();
        let dir = Path::new(EXTERNAL_STORE);
        machine.fs.add_dir_all(dir).unwrap();
        machine
            .fs
            .add_symlink(&dir.join(FORMAT_FILE), Path::new("/Users/u/secret"))
            .unwrap();
        assert_eq!(
            machine.place_one("/Volumes/External/code").fallback,
            Some(Fallback::VolumeStore(StoreFault::Corrupt))
        );

        let machine = Machine::new();
        machine.fs.add_dir_all(dir).unwrap();
        machine.fs.set_owner(dir, 501_000).unwrap();
        assert_eq!(
            machine.place_one("/Volumes/External/code").fallback,
            Some(Fallback::VolumeStore(StoreFault::Platform(PlatformError::ForeignOwner)))
        );
    }

    // A store with this build's format is reused as it is, and its mode tightened back to owner-only.
    #[test]
    fn existing_store_is_reused_and_tightened() {
        let machine = Machine::new();
        machine.place_one("/Volumes/External/code");
        let format = Path::new(EXTERNAL_STORE).join(FORMAT_FILE);
        machine.fs.set_mode(&format, 0o644).unwrap();
        machine.fs.set_mode(Path::new(EXTERNAL_STORE), 0o755).unwrap();
        let store = machine.place_one("/Volumes/External/code");
        assert_eq!(store.method, Method::ApfsClone);
        machine.assert_private_store(EXTERNAL_STORE);
    }

    // A root whose volume cannot be read, and every root when the home store cannot be prepared, reports `none`.
    #[test]
    fn unreadable_volumes_and_home_store_report_none() {
        let machine = Machine::new();
        let volumes = FakeVolumes::new();
        volumes.add_volume("/Users", FileSystemKind::Apfs, false);
        let root = CanonicalPath::new("/opt/elsewhere").unwrap();
        let stores = place_roots(&machine.fs, &volumes, &machine.paths, machine.fs.uid(), &[root]);
        assert_eq!(stores[0].method, Method::None);
        assert!(matches!(stores[0].fallback, Some(Fallback::VolumeUnknown(_))));

        let machine = Machine::new();
        machine.fs.set_owner(home_store().as_path(), 501_000).unwrap();
        for store in machine.place(&["/Users/u/src/app", "/Volumes/External/code", "/Volumes/Stick/code"]) {
            assert_eq!(store.method, Method::None);
            assert_eq!(
                store.fallback,
                Some(Fallback::HomeStore(StoreFault::Platform(PlatformError::ForeignOwner)))
            );
        }
        assert!(
            machine.fs.metadata(Path::new(EXTERNAL_STORE)).is_err(),
            "no volume store without a home store"
        );
    }

    // FR-CKP-35, `specs/05-models/capabilities.md`: the report lists every root with its method.
    #[test]
    fn capability_report_lists_method_per_root() {
        let machine = Machine::new();
        let mut stores = machine.place(&["/Users/u/src/app", "/Volumes/External/code", "/Volumes/Stick/code"]);
        stores.push(RootStore {
            root: CanonicalPath::new("/Volumes/Gone/code").unwrap(),
            method: Method::None,
            store: None,
            fallback: None,
        });
        let report = capability_report(&stores);
        let entries: Vec<(&str, &str)> = report
            .iter()
            .map(|(root, method)| (root.as_str(), method.as_str()))
            .collect();
        assert_eq!(
            entries,
            [
                ("/Users/u/src/app", "apfs-clone"),
                ("/Volumes/External/code", "apfs-clone"),
                ("/Volumes/Gone/code", "none"),
                ("/Volumes/Stick/code", "plain-copy"),
            ]
        );
    }

    #[test]
    fn format_parsing_is_strict() {
        assert_eq!(parse_format(b"knsh-checkpoints 1\n"), Some(1));
        assert_eq!(parse_format(b"knsh-checkpoints 42\n"), Some(42));
        for bad in [
            &b""[..],
            b"knsh-checkpoints \n",
            b"knsh-checkpoints 1",
            b"knsh-checkpoints 1\n\n",
            b"knsh-checkpoints -1\n",
            b"knsh-checkpoints 1 \n",
            b"knsh-checkpoints 9999999999\n",
            b"KNSH-CHECKPOINTS 1\n",
        ] {
            assert_eq!(parse_format(bad), None, "{bad:?}");
        }
    }
}
