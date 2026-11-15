//! Compiled profile files (KNSH-045; FR-SBX-07, decision 1).
//!
//! `knsh-exec` applies a profile with `sandbox-exec -f <file>`, so every compiled profile ([`SbplText`]) is written
//! to a private file before its envelope or line starts: `<sha256 of the bytes>.sb` in the engine's profiles
//! directory (`EnginePaths::profiles_dir`, `0700`, prepared with the other engine directories).
//!
//! - **Private and atomic.** Files are written with [`Fs::atomic_replace`] (temporary file, flush, rename) with mode
//!   `0600`, then checked: a regular file of this user with exactly that mode, holding exactly the compiled bytes.
//!   The directory itself must be a `0700` directory of this user, checked before every write. Anything else is an
//!   error.
//! - **Named by hash.** The same profile text always lands in the same file, so concurrent lines with one profile
//!   share it, and the record's `sandbox_profile` names exactly what ran: `<profile name>@<first 16 hex digits of
//!   the SHA-256>` ([`sandbox_profile`], `specs/05-models/execution-record.md`).
//! - **Collected when unused.** [`ProfileFiles::write`] returns a [`CompiledProfile`] that holds a reference to its
//!   file; while any is alive the file stays. When the last one is dropped (its line or envelope has ended) the file
//!   is removed, and [`ProfileFiles::sweep`] (run at start) removes profile files and temporary files no running
//!   line references, such as those left by a crash.
//! - **Fail closed.** Any error from [`ProfileFiles::write`] means the line must not start: the supervisor denies
//!   it (KNSH-050). No path to a file that was not fully written and checked is ever returned.
//!
//! Lock order: only [`Inner::in_use`] is locked here, never while holding another lock; filesystem calls happen
//! under it, so a sweep cannot remove a file between its write and the reference being counted.

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use knsh_core::ProfileName;
use knsh_platform::engine_dirs::{DIR_MODE, FILE_MODE};
use knsh_platform::{FileKind, Fs, PlatformError};
use knsh_sandbox::SbplText;

/// Extension of every compiled profile file.
const EXTENSION: &str = ".sb";

/// Hex digits of the SHA-256 in a file name.
const HASH_HEX_LEN: usize = 64;

/// Hex digits of the SHA-256 in a record's `sandbox_profile` (64 bits: enough to tell profiles apart in records,
/// while the file itself is named by the whole hash).
pub(crate) const SANDBOX_PROFILE_HASH_LEN: usize = 16;

/// Entries the sweep reads from the profiles directory at most. Only `knshd` writes there (every profile denies
/// engine paths), so more means something is wrong; the sweep then refuses rather than reads without bound.
const MAX_ENTRIES: usize = 65_536;

/// Prefix and suffix of the temporary files [`Fs::atomic_replace`] leaves behind if `knshd` dies mid-write.
const TEMP_PREFIX: &str = ".knsh.";
const TEMP_SUFFIX: &str = ".tmp";

/// SHA-256 of profile bytes. The real one is `CommonCrypto`'s (`knsh_platform::macos::sha256`); tests may pass any
/// function, the store only relies on it being deterministic.
pub(crate) type Hasher = fn(&[u8]) -> [u8; 32];

/// Why a profile file could not be provided. Each one denies the line (module documentation).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ProfileFileError {
    /// The profiles directory is missing, not a directory, not this user's, or not `0700`.
    UnsafeDirectory,
    /// A filesystem call failed.
    Io(PlatformError),
    /// The written file did not read back as a `0600` regular file of this user holding the compiled bytes.
    NotVerified,
}

impl fmt::Display for ProfileFileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsafeDirectory => f.write_str("the sandbox profile directory is not private"),
            Self::Io(error) => write!(f, "cannot write the sandbox profile: {error}"),
            Self::NotVerified => f.write_str("the sandbox profile file did not verify"),
        }
    }
}

impl std::error::Error for ProfileFileError {}

impl From<PlatformError> for ProfileFileError {
    fn from(error: PlatformError) -> Self {
        Self::Io(error)
    }
}

/// The record value naming a compiled profile: `<profile name>@<first 16 hex digits of its SHA-256>`, for example
/// `web-app@3f9a0c1d2b4e6f70` (FR-SBX-07).
pub(crate) fn sandbox_profile(name: &ProfileName, hash_hex: &str) -> String {
    let prefix = hash_hex.get(..SANDBOX_PROFILE_HASH_LEN).unwrap_or(hash_hex);
    format!("{name}@{prefix}")
}

/// Writes compiled profiles to private files and removes them once unused (module documentation).
#[derive(Clone)]
pub(crate) struct ProfileFiles {
    inner: Arc<Inner>,
}

struct Inner {
    fs: Arc<dyn Fs>,
    /// The profiles directory (`EnginePaths::profiles_dir`).
    dir: PathBuf,
    /// The user `knshd` runs as: owner of the directory and every file.
    uid: u32,
    hash: Hasher,
    /// Live [`CompiledProfile`]s per file, by the hash in its name. A file is absent here when none is alive.
    in_use: Mutex<BTreeMap<String, usize>>,
}

/// A compiled profile written to its file. The file stays while this value (or a clone of its reference) is alive,
/// and is removed when the last one for it is dropped.
pub(crate) struct CompiledProfile {
    inner: Arc<Inner>,
    hash_hex: String,
    path: PathBuf,
    sandbox_profile: String,
}

impl CompiledProfile {
    /// The private file `knsh-exec` passes to `sandbox-exec -f`.
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    /// The record's `sandbox_profile` value ([`sandbox_profile`]).
    pub(crate) fn sandbox_profile(&self) -> &str {
        &self.sandbox_profile
    }
}

impl Drop for CompiledProfile {
    fn drop(&mut self) {
        let mut in_use = lock(&self.inner.in_use);
        let Some(count) = in_use.get_mut(&self.hash_hex) else {
            return;
        };
        *count -= 1;
        if *count == 0 {
            in_use.remove(&self.hash_hex);
            // Best effort: a file that cannot be removed now is removed by the next sweep. Removed under the lock,
            // so a concurrent write of the same profile cannot have its fresh file taken away.
            let _ = self.inner.fs.remove_file(&self.path);
        }
    }
}

impl ProfileFiles {
    /// A store writing into `dir` (already prepared `0700` by `ensure_engine_dirs`), as `uid`.
    pub(crate) fn new(fs: Arc<dyn Fs>, dir: PathBuf, uid: u32, hash: Hasher) -> Self {
        Self {
            inner: Arc::new(Inner {
                fs,
                dir,
                uid,
                hash,
                in_use: Mutex::new(BTreeMap::new()),
            }),
        }
    }

    /// Writes `text`, the compiled profile named `name`, to its file and returns it, referenced until dropped.
    ///
    /// A file already referenced by a live [`CompiledProfile`] was written and checked by this store, so it is
    /// shared without touching the disk. Otherwise the file is (re)written atomically, whatever was there, and
    /// checked.
    ///
    /// # Errors
    ///
    /// Any [`ProfileFileError`]: the line or envelope must then be denied. Nothing is referenced on error.
    pub(crate) fn write(&self, name: &ProfileName, text: &SbplText) -> Result<CompiledProfile, ProfileFileError> {
        let inner = &self.inner;
        let bytes = text.as_bytes();
        let hash_hex = hex(&(inner.hash)(bytes));
        let path = inner.dir.join(format!("{hash_hex}{EXTENSION}"));
        let mut in_use = lock(&inner.in_use);
        if !in_use.contains_key(&hash_hex) {
            inner.check_directory()?;
            let written = inner
                .fs
                .atomic_replace(&path, bytes, FILE_MODE)
                .map_err(ProfileFileError::from)
                .and_then(|()| inner.verify(&path, bytes));
            if let Err(error) = written {
                // Never leave a file that was not confirmed (a failed directory sync comes after the rename) or did
                // not verify for a later line to find. Nothing references it: this is the first writer.
                let _ = inner.fs.remove_file(&path);
                return Err(error);
            }
        }
        *in_use.entry(hash_hex.clone()).or_insert(0) += 1;
        Ok(CompiledProfile {
            inner: Arc::clone(inner),
            sandbox_profile: sandbox_profile(name, &hash_hex),
            hash_hex,
            path,
        })
    }

    /// Removes every profile file no live [`CompiledProfile`] references, and leftover temporary files. Other
    /// entries are left alone. Returns how many files were removed.
    ///
    /// # Errors
    ///
    /// [`ProfileFileError::UnsafeDirectory`] if the directory is not private (nothing is removed), or
    /// [`ProfileFileError::Io`] if it cannot be listed or a file cannot be removed (the sweep stops there; the files
    /// already removed stay removed).
    pub(crate) fn sweep(&self) -> Result<usize, ProfileFileError> {
        let inner = &self.inner;
        let in_use = lock(&inner.in_use);
        inner.check_directory()?;
        let mut removed = 0;
        for name in inner.fs.list_dir(&inner.dir, MAX_ENTRIES)? {
            let collectable = match profile_hash(&name) {
                Some(hash_hex) => !in_use.contains_key(hash_hex),
                None => is_temporary(&name),
            };
            if collectable {
                match inner.fs.remove_file(&inner.dir.join(&name)) {
                    Ok(()) => removed += 1,
                    // Gone already: what the sweep wanted.
                    Err(error) if error.is_not_found() => {}
                    Err(error) => return Err(error.into()),
                }
            }
        }
        Ok(removed)
    }
}

impl Inner {
    /// The directory must be this user's `0700` directory, not a symlink: otherwise another user could read or
    /// swap the profiles that confine agents.
    fn check_directory(&self) -> Result<(), ProfileFileError> {
        match self.fs.metadata(&self.dir) {
            Ok(meta) if meta.kind == FileKind::Directory && meta.uid == self.uid && meta.mode == DIR_MODE => Ok(()),
            Ok(_) => Err(ProfileFileError::UnsafeDirectory),
            Err(error) if error.is_not_found() => Err(ProfileFileError::UnsafeDirectory),
            Err(error) => Err(error.into()),
        }
    }

    /// The file just written is a `0600` regular file of this user holding exactly `bytes`.
    fn verify(&self, path: &Path, bytes: &[u8]) -> Result<(), ProfileFileError> {
        let meta = self.fs.metadata(path)?;
        if meta.kind != FileKind::File || meta.uid != self.uid || meta.mode != FILE_MODE {
            return Err(ProfileFileError::NotVerified);
        }
        // One byte over the expected length, so a longer file is told apart from an exact one.
        let limit = u64::try_from(bytes.len()).map_or(u64::MAX, |len| len.saturating_add(1));
        match self.fs.read(path, limit) {
            Ok(read) if read == bytes => Ok(()),
            Ok(_) | Err(PlatformError::TooLarge { .. }) => Err(ProfileFileError::NotVerified),
            Err(error) => Err(error.into()),
        }
    }
}

/// The hash of a profile file name `<64 lower-case hex digits>.sb`, or `None` for any other name.
fn profile_hash(name: &OsStr) -> Option<&str> {
    let hash = name.to_str()?.strip_suffix(EXTENSION)?;
    let valid = hash.len() == HASH_HEX_LEN && hash.bytes().all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'));
    valid.then_some(hash)
}

/// Whether `name` is a temporary file of an interrupted atomic replace.
fn is_temporary(name: &OsStr) -> bool {
    name.to_str()
        .is_some_and(|name| name.starts_with(TEMP_PREFIX) && name.ends_with(TEMP_SUFFIX))
}

/// Lower-case hex of `bytes`.
fn hex(bytes: &[u8]) -> String {
    use fmt::Write as _;
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        // Writing to a `String` cannot fail.
        let _ = write!(text, "{byte:02x}");
    }
    text
}

/// Takes the lock even if a thread panicked while holding it: each update under it is one map operation and one
/// filesystem call, which a panic cannot leave half done in a way that lets an unchecked file be used (a missing
/// count only makes the next write rewrite and recheck the file).
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU16;

    use knsh_core::{
        CanonicalPath, LookupError, PathContext, PolicyFs, ProfileSource, RecordId, SessionId, Ulid, load_profile_text,
    };
    use knsh_platform::Operation;
    use knsh_platform::testing::MemFs;
    use knsh_sandbox::{CommandTag, ProfileInput, compile};

    use super::*;

    const UID: u32 = knsh_platform::testing::DEFAULT_UID;
    /// macOS `errno` values (only `knsh-platform` may depend on `libc`).
    const ENOSPC: i32 = 28;
    const EIO: i32 = 5;

    /// The profiles directory of the test home, from the one place engine paths are built.
    fn dir() -> PathBuf {
        knsh_platform::EnginePaths::for_home(Path::new("/Users/u"))
            .unwrap()
            .profiles_dir()
    }

    /// A stand-in digest: the length and first bytes, enough to give different texts different names.
    fn fake_hash(bytes: &[u8]) -> [u8; 32] {
        let mut digest = [0u8; 32];
        digest[..8].copy_from_slice(&(bytes.len() as u64).to_be_bytes());
        for (slot, byte) in digest[8..].iter_mut().zip(bytes.iter().rev()) {
            *slot = *byte;
        }
        digest
    }

    fn store() -> (Arc<MemFs>, ProfileFiles) {
        let fs = Arc::new(MemFs::new());
        fs.add_dir_all(dir().as_path()).unwrap();
        fs.set_mode(dir().as_path(), DIR_MODE).unwrap();
        let files = ProfileFiles::new(fs.clone(), dir(), UID, fake_hash);
        (fs, files)
    }

    /// Every path exists and is already canonical.
    struct Canonical;

    impl PolicyFs for Canonical {
        fn canonicalise(&self, path: &Path) -> Result<CanonicalPath, LookupError> {
            CanonicalPath::new(path).map_err(|_| LookupError::Failed)
        }
    }

    struct NoParents;

    impl ProfileSource for NoParents {
        fn read_profile(&self, _name: &ProfileName) -> Result<Vec<u8>, LookupError> {
            Err(LookupError::NotFound)
        }
    }

    /// A real compiled profile, distinct per `record` (the record is in every tag).
    fn text(record: u128) -> SbplText {
        let context = PathContext {
            home: PathBuf::from("/Users/u"),
            tmpdir: PathBuf::from("/private/tmp"),
            start_dir: PathBuf::from("/Users/u/app"),
        };
        let profile = load_profile_text(b"name = \"web-app\"\n", &NoParents, &context, &Canonical).unwrap();
        let home = CanonicalPath::new("/Users/u").unwrap();
        compile(&ProfileInput {
            session: SessionId::from_ulid(Ulid::from_u128(1)),
            command: CommandTag::Line(RecordId::from_ulid(Ulid::from_u128(record))),
            profile: &profile,
            home: &home,
            executables: &[],
            proxy_port: NonZeroU16::new(41_000),
        })
    }

    fn name() -> ProfileName {
        ProfileName::new("web-app").unwrap()
    }

    fn profile_files(fs: &MemFs) -> Vec<PathBuf> {
        fs.paths()
            .into_iter()
            .filter(|path| path.parent() == Some(dir().as_path()))
            .collect()
    }

    // FR-SBX-07: the file is named by the full hash of its bytes, holds exactly them, and `sandbox_profile` is the
    // profile name and the first 16 hex digits of the hash.
    #[test]
    fn profile_file_named_by_content_hash() {
        let (fs, files) = store();
        let text = text(2);
        let compiled = files.write(&name(), &text).unwrap();
        let hash_hex = hex(&fake_hash(text.as_bytes()));
        assert_eq!(compiled.path(), dir().as_path().join(format!("{hash_hex}.sb")));
        assert_eq!(fs.contents(compiled.path()).unwrap(), text.as_bytes());
        assert_eq!(compiled.sandbox_profile(), format!("web-app@{}", &hash_hex[..16]));
        // The same text is the same file; another text another file.
        let again = files.write(&name(), &text).unwrap();
        assert_eq!(again.path(), compiled.path());
        let other = files.write(&name(), &self::text(3)).unwrap();
        assert_ne!(other.path(), compiled.path());
        assert_eq!(profile_files(&fs).len(), 2);
    }

    // The record format with the real digest: `<name>@<16 lower-case hex digits>`.
    #[test]
    fn sandbox_profile_format_uses_sha256_prefix() {
        let digest = knsh_platform::macos::sha256(b"abc");
        assert_eq!(sandbox_profile(&name(), &hex(&digest)), "web-app@ba7816bf8f01cfea");
    }

    // NFR-SEC-08: the file is `0600`, written in one atomic replace, inside a `0700` directory; any other directory
    // is refused before anything is written.
    #[test]
    fn profile_file_mode_is_0600() {
        let (fs, files) = store();
        // A wide umask cannot widen the file: the replace sets the mode exactly.
        fs.set_umask(0);
        let compiled = files.write(&name(), &text(2)).unwrap();
        let meta = fs.metadata(compiled.path()).unwrap();
        assert_eq!((meta.kind, meta.mode, meta.uid), (FileKind::File, 0o600, UID));

        for mode in [0o755, 0o750, 0o500] {
            let (fs, files) = store();
            fs.set_mode(dir().as_path(), mode).unwrap();
            assert_eq!(
                files.write(&name(), &text(2)).err(),
                Some(ProfileFileError::UnsafeDirectory)
            );
            assert_eq!(profile_files(&fs), Vec::<PathBuf>::new());
        }
        let (fs, files) = store();
        fs.set_owner(dir().as_path(), 0).unwrap();
        assert_eq!(
            files.write(&name(), &text(2)).err(),
            Some(ProfileFileError::UnsafeDirectory)
        );
    }

    // FR-SBX-07, fail closed: when any step of the write fails, no profile is returned (the line is denied),
    // nothing is left in the directory, and a later write starts over.
    #[test]
    fn write_failure_denies() {
        for operation in [
            Operation::Write,
            Operation::SyncFile,
            Operation::Rename,
            Operation::SyncDirectory,
        ] {
            let (fs, files) = store();
            fs.inject_fault(operation, ENOSPC);
            let result = files.write(&name(), &text(2));
            assert!(
                matches!(
                    result,
                    Err(ProfileFileError::Io(PlatformError::Os { errno: ENOSPC, .. }))
                ),
                "{operation:?}"
            );
            // A failed directory sync comes after the rename: the file existed but was not confirmed durable, so it
            // is removed too. Nothing is referenced.
            assert_eq!(lock(&files.inner.in_use).len(), 0, "{operation:?}");
            assert_eq!(profile_files(&fs), Vec::<PathBuf>::new(), "{operation:?}");
            assert!(files.write(&name(), &text(2)).is_ok(), "{operation:?}");
        }
        // A missing directory denies too.
        let fs = Arc::new(MemFs::new());
        let files = ProfileFiles::new(fs, dir(), UID, fake_hash);
        assert_eq!(
            files.write(&name(), &text(2)).err(),
            Some(ProfileFileError::UnsafeDirectory)
        );
    }

    // A file whose read-back differs is never handed out, and is removed.
    #[test]
    fn unverified_file_is_removed_and_denied() {
        let (fs, files) = store();
        fs.inject_fault(Operation::Read, EIO);
        assert!(matches!(files.write(&name(), &text(2)), Err(ProfileFileError::Io(_))));
        assert_eq!(profile_files(&fs), Vec::<PathBuf>::new());
    }

    // FR-SBX-07: a file stays while a line references it and is removed with the last reference; the sweep removes
    // stale profile and temporary files but keeps referenced ones and anything it does not recognise.
    #[test]
    fn unused_profiles_are_collected() {
        let (fs, files) = store();
        let first = files.write(&name(), &text(2)).unwrap();
        let second = files.write(&name(), &text(2)).unwrap();
        let path = first.path().to_path_buf();
        drop(first);
        assert!(fs.contents(&path).is_some(), "still referenced by the second line");
        drop(second);
        assert!(fs.contents(&path).is_none(), "removed with the last reference");

        // Left behind by an earlier run: a profile file, a temporary file, and an unrelated file.
        let stale = dir().as_path().join(format!("{}.sb", "a".repeat(64)));
        let temp = dir().as_path().join(".knsh.123.0.tmp");
        let other = dir().as_path().join("README");
        for path in [&stale, &temp, &other] {
            fs.write(path, b"x", 0o600).unwrap();
        }
        let live = files.write(&name(), &text(3)).unwrap();
        assert_eq!(files.sweep().unwrap(), 2);
        assert!(fs.contents(&stale).is_none() && fs.contents(&temp).is_none());
        assert!(fs.contents(&other).is_some(), "unrecognised entries are left alone");
        assert!(fs.contents(live.path()).is_some(), "a referenced profile is kept");
    }

    #[test]
    fn profile_names_are_recognised_exactly() {
        let hash = "0123456789abcdef".repeat(4);
        assert_eq!(profile_hash(OsStr::new(&format!("{hash}.sb"))), Some(hash.as_str()));
        for name in [
            format!("{}.sb", hash.to_uppercase()),
            format!("{hash}.sbx"),
            format!("{}.sb", &hash[1..]),
            format!("x{hash}.sb"),
            hash.clone(),
        ] {
            assert_eq!(profile_hash(OsStr::new(&name)), None, "{name}");
        }
    }
}
