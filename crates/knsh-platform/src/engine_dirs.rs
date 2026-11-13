//! Engine directories: where engine data lives, and preparing it owner-only and out of Spotlight and Time Machine.
//!
//! This module is the only place engine path literals may appear (KNSH-011). Everything else asks [`EnginePaths`],
//! so the sandbox compiler can deny the whole set ([`EnginePaths::fixed_denies`]) without a path being missed.
//! Layout: `specs/09-reference/file-locations.md`.
//!
//! [`ensure_engine_dirs`] creates the directories on first use and re-checks them on every start:
//!
//! - **Owner-only (NFR-SEC-08, NFR-PRIV-04).** Directories are `0700` and files `0600`. Wider (or narrower) modes
//!   on an existing entry are reset to exactly those bits. An entry owned by another user, or a symlink or file
//!   where a directory belongs, is refused: whoever controls it could read or redirect engine data, so it is never
//!   adopted or repaired (fail closed).
//! - **Time Machine.** Each directory gets the extended attribute `com.apple.metadata:com_apple_backup_excludeItem`
//!   holding the binary property list for the string `com.apple.backupd`. These are the exact bytes
//!   `tmutil addexclusion` writes for a "sticky" item exclusion; unlike `tmutil addexclusion -p` (a path exclusion
//!   in the system preferences) it needs no admin rights, and the exclusion moves with the directory.
//! - **Spotlight.** Each directory gets an empty `.metadata_never_index` marker file. Observed on macOS 26.6
//!   (KNSH-011 review): Spotlight still indexes a directory holding this marker below the volume root, so the marker
//!   alone does not exclude anything there. The engine directories are out of the index today only because of where
//!   they sit (`~/.config` is hidden; `~/Library/Application Support` was not indexed). Claim C11 in
//!   `specs/07-testing/verification-claims.md` tracks a mechanism that works.
//! - **Verified.** After writing, the attribute is read back and must match byte for byte, and the marker must be
//!   an owner-only regular file. Anything else is an error, not a warning. This checks that the marker is present,
//!   not that Spotlight honours it (see above).
//!
//! Every step is idempotent and tolerates a concurrent run of itself in another process: "already exists" from a
//! create is expected, and the entry is then checked like any pre-existing one. A directory is created with mode
//! `0700` (the umask can only narrow that), so no other user can ever reach it, even between the create and the
//! check.
//!
//! Out of scope (phase 3): `.knsh-checkpoints/` on other volumes.

use std::path::{Path, PathBuf};

use crate::error::{Operation, PlatformError};
use crate::fs::{FileKind, Fs, Metadata};

/// Mode of every engine directory: owner-only (NFR-SEC-08).
pub const DIR_MODE: u32 = 0o700;

/// Mode of every engine file: owner read and write only (NFR-SEC-08).
pub const FILE_MODE: u32 = 0o600;

/// Name of the file whose presence tells Spotlight not to index a directory (NFR-PRIV-04).
pub const SPOTLIGHT_MARKER: &str = ".metadata_never_index";

/// Extended attribute that excludes an item from Time Machine backups (NFR-PRIV-04).
pub const BACKUP_EXCLUDE_ATTRIBUTE: &str = "com.apple.metadata:com_apple_backup_excludeItem";

/// Value of [`BACKUP_EXCLUDE_ATTRIBUTE`]: a binary property list (`bplist00`) holding the single string
/// `com.apple.backupd`, byte for byte what `tmutil addexclusion` writes on macOS 14 and later.
pub const BACKUP_EXCLUDE_VALUE: &[u8] =
    b"bplist00_\x10\x11com.apple.backupd\x08\0\0\0\0\0\0\x01\x01\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x1c";

/// Records, grants and pushed policy, relative to the home directory.
const DATA_DIR: [&str; 3] = ["Library", "Application Support", "knsh"];
/// Configuration, hooks and policy files, relative to the home directory.
const CONFIG_DIR: [&str; 2] = [".config", "knsh"];
/// Socket directory, inside the data directory.
const RUN_DIR: &str = "run";
/// Checkpoints for the home volume, inside the data directory.
const CHECKPOINTS_DIR: &str = "checkpoints";
/// Policy files, inside the configuration directory.
const POLICIES_DIR: &str = "policies";
/// The zsh startup directory of integration mode, below the data directory (KNSH-019).
const ZSH_STARTUP_DIR: [&str; 2] = ["shell", "zsh"];
/// Agent socket, inside the run directory.
const AGENT_SOCKET: &str = "agent.sock";
/// User socket, inside the run directory.
const USER_SOCKET: &str = "user.sock";

/// Every engine path for one home directory (`specs/09-reference/file-locations.md`).
///
/// Invariant: every path is absolute, lies under [`EnginePaths::home`], and lies under one of
/// [`EnginePaths::fixed_denies`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnginePaths {
    home: PathBuf,
    data: PathBuf,
    config: PathBuf,
}

impl EnginePaths {
    /// The engine paths under `home`, the user's home directory.
    ///
    /// # Errors
    ///
    /// [`PlatformError::InvalidPath`] if `home` is relative, is `/`, or contains `.` or `..` components: engine
    /// paths must be stable spellings that sandbox profiles can deny exactly.
    pub fn for_home(home: &Path) -> Result<Self, PlatformError> {
        // Checked on the raw bytes: `Path::components` silently drops a `.` in the middle (`/Users/./u`).
        let lexically_clean = home
            .as_os_str()
            .as_encoded_bytes()
            .split(|byte| *byte == b'/')
            .all(|segment| segment != b"." && segment != b"..");
        if !home.is_absolute() || home.parent().is_none() || !lexically_clean {
            return Err(PlatformError::InvalidPath);
        }
        Ok(Self {
            home: home.to_path_buf(),
            data: join_all(home, &DATA_DIR),
            config: join_all(home, &CONFIG_DIR),
        })
    }

    /// The home directory these paths were derived from. Not itself an engine path.
    #[must_use]
    pub fn home(&self) -> &Path {
        &self.home
    }

    /// `~/Library/Application Support/knsh/`: records, grants and pushed policy.
    #[must_use]
    pub fn data_dir(&self) -> &Path {
        &self.data
    }

    /// `~/Library/Application Support/knsh/run/`: the endpoint sockets.
    #[must_use]
    pub fn run_dir(&self) -> PathBuf {
        self.data.join(RUN_DIR)
    }

    /// `~/Library/Application Support/knsh/checkpoints/`: checkpoints of files on the home volume.
    #[must_use]
    pub fn checkpoints_dir(&self) -> PathBuf {
        self.data.join(CHECKPOINTS_DIR)
    }

    /// `~/Library/Application Support/knsh/run/agent.sock`.
    #[must_use]
    pub fn agent_socket(&self) -> PathBuf {
        self.run_dir().join(AGENT_SOCKET)
    }

    /// `~/Library/Application Support/knsh/run/user.sock`.
    #[must_use]
    pub fn user_socket(&self) -> PathBuf {
        self.run_dir().join(USER_SOCKET)
    }

    /// `~/.config/knsh/`: configuration, hooks and policy files.
    #[must_use]
    pub fn config_dir(&self) -> &Path {
        &self.config
    }

    /// `~/.config/knsh/policies/`. Created by the policy stories, not by [`ensure_engine_dirs`].
    #[must_use]
    pub fn policies_dir(&self) -> PathBuf {
        self.config.join(POLICIES_DIR)
    }

    /// `~/Library/Application Support/knsh/shell/zsh/`: the startup directory `knsh` points `ZDOTDIR` at when it
    /// hosts zsh in integration mode (KNSH-019). Created by `knsh`, not by [`ensure_engine_dirs`].
    #[must_use]
    pub fn zsh_startup_dir(&self) -> PathBuf {
        join_all(&self.data, &ZSH_STARTUP_DIR)
    }

    /// The directories [`ensure_engine_dirs`] creates, each listed after its parent.
    #[must_use]
    pub fn private_dirs(&self) -> [PathBuf; 4] {
        [
            self.data.clone(),
            self.run_dir(),
            self.checkpoints_dir(),
            self.config.clone(),
        ]
    }

    /// The roots that every envelope and command profile must deny (NFR-PRIV-04, "fixed denies"). Every engine path
    /// lies under one of them, so denying these subtrees denies them all.
    #[must_use]
    pub fn fixed_denies(&self) -> [PathBuf; 2] {
        [self.data.clone(), self.config.clone()]
    }
}

/// `base` joined with each component in turn.
fn join_all(base: &Path, components: &[&str]) -> PathBuf {
    components.iter().fold(base.to_path_buf(), |path, part| path.join(part))
}

/// Creates the engine directories under `paths` if missing, makes them owner-only and excludes them from
/// Spotlight and Time Machine, verifying each step. Safe to call on every start and from several processes at once.
///
/// `uid` is the user the engine runs as (the effective uid); every engine entry must be owned by it. Missing
/// ancestors that are not engine directories (for example `~/.config` on a fresh account) are created with
/// [`DIR_MODE`]; existing ones are left as they are, since they belong to the user, not the engine.
///
/// # Errors
///
/// - [`PlatformError::ForeignOwner`] if an engine directory or marker is owned by another user. Nothing in or
///   below it is touched.
/// - [`PlatformError::UnexpectedKind`] if a symlink, file or other entry sits where an engine directory or marker
///   belongs. The entry is not followed or changed.
/// - [`PlatformError::ExclusionNotVerified`] if the Time Machine attribute does not read back as written.
/// - [`PlatformError::Os`] if any filesystem call fails, for example `ENOTSUP` from a filesystem without extended
///   attributes, or `ENOENT` if the home directory does not exist.
///
/// On error, directories already prepared stay prepared; a retry resumes where it failed.
pub fn ensure_engine_dirs(fs: &dyn Fs, paths: &EnginePaths, uid: u32) -> Result<(), PlatformError> {
    for root in paths.fixed_denies() {
        create_missing_ancestors(fs, paths.home(), &root)?;
    }
    // Parents come first in `private_dirs`, so a child is only created inside a directory already checked.
    for dir in paths.private_dirs() {
        ensure_private_dir(fs, &dir, uid)?;
        exclude_from_index_and_backup(fs, &dir, uid)?;
    }
    Ok(())
}

/// Creates each missing directory strictly between `home` and `dir`, shallowest first.
fn create_missing_ancestors(fs: &dyn Fs, home: &Path, dir: &Path) -> Result<(), PlatformError> {
    let mut ancestors: Vec<&Path> = dir
        .ancestors()
        .skip(1)
        .take_while(|ancestor| *ancestor != home)
        .collect();
    ancestors.reverse();
    for ancestor in ancestors {
        create_tolerating_existing(fs.create_dir(ancestor, DIR_MODE))?;
    }
    Ok(())
}

/// Creates `dir` as an owner-only directory, or adopts an existing one after checking it.
fn ensure_private_dir(fs: &dyn Fs, dir: &Path, uid: u32) -> Result<(), PlatformError> {
    create_tolerating_existing(fs.create_dir(dir, DIR_MODE))?;
    adopt(fs, dir, FileKind::Directory, DIR_MODE, uid)
}

/// Adds the Spotlight marker to `dir` and sets its Time Machine exclusion, then verifies both.
fn exclude_from_index_and_backup(fs: &dyn Fs, dir: &Path, uid: u32) -> Result<(), PlatformError> {
    let marker = dir.join(SPOTLIGHT_MARKER);
    create_tolerating_existing(fs.create_new(&marker, FILE_MODE))?;
    adopt(fs, &marker, FileKind::File, FILE_MODE, uid)?;

    // Written unconditionally: rewriting the same bytes is harmless, and it also replaces a stale or foreign value.
    fs.set_xattr(dir, BACKUP_EXCLUDE_ATTRIBUTE, BACKUP_EXCLUDE_VALUE)?;
    match fs.xattr(dir, BACKUP_EXCLUDE_ATTRIBUTE, BACKUP_EXCLUDE_VALUE.len()) {
        Ok(Some(value)) if value == BACKUP_EXCLUDE_VALUE => Ok(()),
        // Missing, different, or longer than what was written: the exclusion did not take.
        Ok(_) | Err(PlatformError::TooLarge { .. }) => Err(PlatformError::ExclusionNotVerified),
        Err(error) => Err(error),
    }
}

/// Treats "already exists" from a create as success: another run of this function (here or in another process)
/// got there first, and the caller checks the entry next like any pre-existing one.
fn create_tolerating_existing(result: Result<(), PlatformError>) -> Result<(), PlatformError> {
    match result {
        Err(error) if error.errno() == Some(libc::EEXIST) => Ok(()),
        other => other,
    }
}

/// Checks that `path` is a `kind` entry owned by `uid` and sets its mode to exactly `mode` if it differs.
fn adopt(fs: &dyn Fs, path: &Path, kind: FileKind, mode: u32, uid: u32) -> Result<(), PlatformError> {
    let meta = fs.metadata(path)?;
    check_kind_and_owner(&meta, kind, uid)?;
    if meta.mode == mode {
        return Ok(());
    }
    // NFR-SEC-08: reset to exactly the engine mode, whether the old one was wider or narrower.
    fs.set_mode(path, mode)?;
    // Re-read rather than trust the call: the entry could have been replaced in between, and a mode that did not
    // stick must not be reported as owner-only.
    let after = fs.metadata(path)?;
    check_kind_and_owner(&after, kind, uid)?;
    if after.mode == mode {
        Ok(())
    } else {
        Err(PlatformError::Os {
            operation: Operation::SetMode,
            errno: libc::EPERM,
        })
    }
}

/// Refuses an entry of the wrong kind (checked first, so a symlink is reported as such whoever owns it) or owned by
/// anyone but `uid`.
fn check_kind_and_owner(meta: &Metadata, kind: FileKind, uid: u32) -> Result<(), PlatformError> {
    if meta.kind != kind {
        Err(PlatformError::UnexpectedKind)
    } else if meta.uid != uid {
        Err(PlatformError::ForeignOwner)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::io::Read;

    use knsh_core::CanonicalPath;

    use super::*;
    use crate::testing::MemFs;

    const HOME: &str = "/Users/u";

    /// A fake filesystem holding only the home directory, with the common `022` umask.
    fn fake_home() -> (MemFs, EnginePaths) {
        let fs = MemFs::new();
        fs.set_umask(0o022);
        fs.add_dir_all(Path::new(HOME)).unwrap();
        (fs, EnginePaths::for_home(Path::new(HOME)).unwrap())
    }

    fn assert_prepared(fs: &MemFs, paths: &EnginePaths) {
        for dir in paths.private_dirs() {
            let meta = fs.metadata(&dir).unwrap();
            assert_eq!(
                (meta.kind, meta.mode, meta.uid),
                (FileKind::Directory, DIR_MODE, fs.uid()),
                "{}",
                dir.display()
            );
            let marker = fs.metadata(&dir.join(SPOTLIGHT_MARKER)).unwrap();
            assert_eq!(
                (marker.kind, marker.mode, marker.uid),
                (FileKind::File, FILE_MODE, fs.uid())
            );
            assert_eq!(
                fs.xattr(&dir, BACKUP_EXCLUDE_ATTRIBUTE, 256).unwrap().as_deref(),
                Some(BACKUP_EXCLUDE_VALUE)
            );
        }
    }

    // NFR-SEC-08, NFR-PRIV-04: fresh account, every directory created 0700 with a 0600 marker and both exclusions.
    #[test]
    fn creates_engine_dirs_owner_only() {
        let (fs, paths) = fake_home();
        ensure_engine_dirs(&fs, &paths, fs.uid()).unwrap();
        assert_prepared(&fs, &paths);
        // Ancestors that did not exist are created owner-only too; the home directory is untouched.
        for ancestor in [
            "/Users/u/Library",
            "/Users/u/Library/Application Support",
            "/Users/u/.config",
        ] {
            assert_eq!(fs.metadata(Path::new(ancestor)).unwrap().mode, DIR_MODE, "{ancestor}");
        }
        assert_eq!(fs.metadata(Path::new(HOME)).unwrap().mode, 0o755);
    }

    // NFR-SEC-08: wider (and narrower) modes left by an older version or the user are reset exactly.
    #[test]
    fn tightens_existing_wide_permissions() {
        let (fs, paths) = fake_home();
        for dir in paths.private_dirs() {
            fs.add_dir_all(&dir).unwrap();
            fs.set_mode(&dir, 0o755).unwrap();
            fs.write(&dir.join(SPOTLIGHT_MARKER), b"", 0o644).unwrap();
        }
        fs.set_mode(&paths.run_dir(), 0o500).unwrap();
        ensure_engine_dirs(&fs, &paths, fs.uid()).unwrap();
        assert_prepared(&fs, &paths);
    }

    // Existing user directories above the engine root are not the engine's to change.
    #[test]
    fn leaves_existing_ancestors_alone() {
        let (fs, paths) = fake_home();
        fs.add_dir_all(Path::new("/Users/u/.config")).unwrap();
        ensure_engine_dirs(&fs, &paths, fs.uid()).unwrap();
        assert_eq!(fs.metadata(Path::new("/Users/u/.config")).unwrap().mode, 0o755);
    }

    // Fail closed: a directory owned by another user is never used, and nothing inside it is created.
    #[test]
    fn refuses_directory_owned_by_other_user() {
        let (fs, paths) = fake_home();
        fs.add_dir_all(paths.data_dir()).unwrap();
        fs.set_owner(paths.data_dir(), 0).unwrap();
        let before = fs.paths();
        assert_eq!(
            ensure_engine_dirs(&fs, &paths, fs.uid()),
            Err(PlatformError::ForeignOwner)
        );
        let created: Vec<_> = fs.paths().into_iter().filter(|p| !before.contains(p)).collect();
        assert!(
            created.iter().all(|p| !p.starts_with(paths.data_dir())),
            "created inside a foreign directory: {created:?}"
        );
        assert_eq!(
            fs.metadata(paths.data_dir()).unwrap().mode,
            0o755,
            "foreign mode was changed"
        );
    }

    #[test]
    fn refuses_nested_directory_or_marker_owned_by_other_user() {
        let (fs, paths) = fake_home();
        fs.add_dir_all(&paths.checkpoints_dir()).unwrap();
        fs.set_owner(&paths.checkpoints_dir(), 0).unwrap();
        assert_eq!(
            ensure_engine_dirs(&fs, &paths, fs.uid()),
            Err(PlatformError::ForeignOwner)
        );

        let (fs, paths) = fake_home();
        fs.add_dir_all(paths.config_dir()).unwrap();
        let marker = paths.config_dir().join(SPOTLIGHT_MARKER);
        fs.write(&marker, b"", 0o644).unwrap();
        fs.set_owner(&marker, 0).unwrap();
        assert_eq!(
            ensure_engine_dirs(&fs, &paths, fs.uid()),
            Err(PlatformError::ForeignOwner)
        );
    }

    // A symlink at an engine path could redirect engine data anywhere: refused, and its target is untouched.
    #[test]
    fn refuses_symlink_or_file_at_engine_path() {
        let (fs, paths) = fake_home();
        fs.add_dir_all(Path::new("/elsewhere")).unwrap();
        fs.add_dir_all(Path::new("/Users/u/Library/Application Support"))
            .unwrap();
        fs.add_symlink(paths.data_dir(), Path::new("/elsewhere")).unwrap();
        assert_eq!(
            ensure_engine_dirs(&fs, &paths, fs.uid()),
            Err(PlatformError::UnexpectedKind)
        );
        assert_eq!(fs.metadata(Path::new("/elsewhere")).unwrap().mode, 0o755);
        assert_eq!(
            fs.paths().iter().filter(|p| p.starts_with("/elsewhere")).count(),
            1,
            "created inside the symlink target"
        );

        let (fs, paths) = fake_home();
        fs.add_dir_all(paths.data_dir()).unwrap();
        fs.write(&paths.run_dir(), b"", 0o600).unwrap();
        assert_eq!(
            ensure_engine_dirs(&fs, &paths, fs.uid()),
            Err(PlatformError::UnexpectedKind)
        );

        let (fs, paths) = fake_home();
        fs.add_dir_all(&paths.config_dir().join(SPOTLIGHT_MARKER)).unwrap();
        assert_eq!(
            ensure_engine_dirs(&fs, &paths, fs.uid()),
            Err(PlatformError::UnexpectedKind)
        );
    }

    // Idempotent: a second run changes nothing.
    #[test]
    fn second_run_is_a_no_op() {
        let (fs, paths) = fake_home();
        ensure_engine_dirs(&fs, &paths, fs.uid()).unwrap();
        let before = fs.paths();
        ensure_engine_dirs(&fs, &paths, fs.uid()).unwrap();
        assert_eq!(fs.paths(), before);
        assert_prepared(&fs, &paths);
    }

    // Race: when another process created everything first, every create reports "already exists" and the entries
    // are checked and adopted instead. The real multi-thread race is in `tests/macos_engine_dirs.rs`.
    #[test]
    fn adopts_entries_created_by_a_concurrent_run() {
        let (fs, paths) = fake_home();
        fs.add_dir_all(Path::new("/Users/u/Library/Application Support"))
            .unwrap();
        fs.add_dir_all(Path::new("/Users/u/.config")).unwrap();
        for dir in paths.private_dirs() {
            fs.create_dir(&dir, DIR_MODE).unwrap();
            fs.create_new(&dir.join(SPOTLIGHT_MARKER), FILE_MODE).unwrap();
        }
        ensure_engine_dirs(&fs, &paths, fs.uid()).unwrap();
        assert_prepared(&fs, &paths);
    }

    // Other failures are reported, never treated as success.
    #[test]
    fn reports_filesystem_failures() {
        for (operation, errno) in [
            (Operation::CreateDirectory, libc::EACCES),
            (Operation::Metadata, libc::EIO),
            (Operation::WriteAttribute, libc::ENOTSUP),
            (Operation::ReadAttribute, libc::EIO),
        ] {
            let (fs, paths) = fake_home();
            fs.inject_fault(operation, errno);
            assert_eq!(
                ensure_engine_dirs(&fs, &paths, fs.uid()),
                Err(PlatformError::Os { operation, errno }),
                "{operation:?}"
            );
        }
        let (fs, paths) = fake_home();
        fs.add_dir_all(paths.data_dir()).unwrap();
        fs.set_mode(paths.data_dir(), 0o755).unwrap();
        fs.inject_fault(Operation::SetMode, libc::EPERM);
        assert_eq!(
            ensure_engine_dirs(&fs, &paths, fs.uid()).unwrap_err().errno(),
            Some(libc::EPERM)
        );
        assert_eq!(fs.metadata(paths.data_dir()).unwrap().mode, 0o755);

        let fs = MemFs::new();
        let paths = EnginePaths::for_home(Path::new("/Users/missing")).unwrap();
        assert!(ensure_engine_dirs(&fs, &paths, fs.uid()).unwrap_err().is_not_found());
    }

    // NFR-PRIV-04: an exclusion that does not read back is an error ("verified after creation").
    #[test]
    fn fails_when_exclusion_does_not_read_back() {
        let (fs, paths) = fake_home();
        let dropping = DropsAttributes(fs);
        assert_eq!(
            ensure_engine_dirs(&dropping, &paths, dropping.0.uid()),
            Err(PlatformError::ExclusionNotVerified)
        );
    }

    // The fixed-deny set covers every engine path, so a profile denying it misses none (NFR-PRIV-04).
    #[test]
    fn engine_paths_listed_in_one_place() {
        let paths = EnginePaths::for_home(Path::new(HOME)).unwrap();
        let denies = paths.fixed_denies();
        assert_eq!(
            denies,
            [
                PathBuf::from("/Users/u/Library/Application Support/knsh"),
                PathBuf::from("/Users/u/.config/knsh"),
            ]
        );
        let every_path = [
            paths.data_dir().to_path_buf(),
            paths.run_dir(),
            paths.checkpoints_dir(),
            paths.agent_socket(),
            paths.user_socket(),
            paths.config_dir().to_path_buf(),
            paths.policies_dir(),
            paths.zsh_startup_dir(),
        ];
        for path in every_path.iter().chain(&paths.private_dirs()) {
            assert!(
                denies.iter().any(|deny| path.starts_with(deny)),
                "{} is not under a fixed deny",
                path.display()
            );
        }
        assert_eq!(
            paths.agent_socket(),
            Path::new("/Users/u/Library/Application Support/knsh/run/agent.sock")
        );
        assert_eq!(paths.policies_dir(), Path::new("/Users/u/.config/knsh/policies"));
        assert_eq!(
            paths.zsh_startup_dir(),
            Path::new("/Users/u/Library/Application Support/knsh/shell/zsh")
        );
    }

    // "No path literals elsewhere": engine path components appear in no other Rust source of the workspace.
    #[test]
    fn engine_path_literals_appear_only_in_this_module() {
        let crates = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        let this_file = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/engine_dirs.rs");
        let literals = [
            "\"Application Support\"",
            "Library/Application Support",
            "Application Support/knsh",
            ".config/knsh",
            "\"agent.sock\"",
            "\"user.sock\"",
        ];
        let mut offenders = Vec::new();
        let mut pending = vec![crates.to_path_buf()];
        while let Some(dir) = pending.pop() {
            for entry in std::fs::read_dir(&dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    pending.push(path);
                } else if path.extension().is_some_and(|ext| ext == "rs") && path != this_file {
                    let text = std::fs::read_to_string(&path).unwrap();
                    if literals.iter().any(|literal| text.contains(literal)) {
                        offenders.push(path);
                    }
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "engine path literals outside engine_dirs.rs: {offenders:?}"
        );
    }

    #[test]
    fn for_home_refuses_unusable_homes() {
        for bad in ["relative/home", "/", "/Users/u/../v", "/Users/./u", ""] {
            assert_eq!(
                EnginePaths::for_home(Path::new(bad)),
                Err(PlatformError::InvalidPath),
                "{bad}"
            );
        }
        assert_eq!(EnginePaths::for_home(Path::new(HOME)).unwrap().home(), Path::new(HOME));
    }

    // The attribute value is the binary plist `tmutil addexclusion` writes (captured on macOS 26).
    #[test]
    fn backup_exclusion_value_matches_tmutil() {
        let hex = "62706c6973743030 5f1011636f6d2e6170706c652e6261636b757064 08 \
                   000000000000 0101 0000000000000001 0000000000000000 000000000000001c";
        let expected: Vec<u8> = hex
            .split_whitespace()
            .flat_map(|chunk| {
                (0..chunk.len())
                    .step_by(2)
                    .map(move |i| u8::from_str_radix(&chunk[i..i + 2], 16).unwrap())
            })
            .collect();
        assert_eq!(BACKUP_EXCLUDE_VALUE, expected.as_slice());
    }

    /// A filesystem whose extended-attribute writes silently do nothing, to prove the read-back check.
    struct DropsAttributes(MemFs);

    impl Fs for DropsAttributes {
        fn open_read(&self, path: &Path) -> Result<Box<dyn Read + Send>, PlatformError> {
            self.0.open_read(path)
        }
        fn read(&self, path: &Path, limit: u64) -> Result<Vec<u8>, PlatformError> {
            self.0.read(path, limit)
        }
        fn write(&self, path: &Path, data: &[u8], mode: u32) -> Result<(), PlatformError> {
            self.0.write(path, data, mode)
        }
        fn create_new(&self, path: &Path, mode: u32) -> Result<(), PlatformError> {
            self.0.create_new(path, mode)
        }
        fn atomic_replace(&self, path: &Path, data: &[u8], mode: u32) -> Result<(), PlatformError> {
            self.0.atomic_replace(path, data, mode)
        }
        fn create_dir(&self, path: &Path, mode: u32) -> Result<(), PlatformError> {
            self.0.create_dir(path, mode)
        }
        fn metadata(&self, path: &Path) -> Result<Metadata, PlatformError> {
            self.0.metadata(path)
        }
        fn canonicalise(&self, path: &Path) -> Result<CanonicalPath, PlatformError> {
            self.0.canonicalise(path)
        }
        fn set_mode(&self, path: &Path, mode: u32) -> Result<(), PlatformError> {
            self.0.set_mode(path, mode)
        }
        fn xattr(&self, path: &Path, name: &str, limit: usize) -> Result<Option<Vec<u8>>, PlatformError> {
            self.0.xattr(path, name, limit)
        }
        fn set_xattr(&self, _: &Path, _: &str, _: &[u8]) -> Result<(), PlatformError> {
            Ok(())
        }
        fn remove_file(&self, path: &Path) -> Result<(), PlatformError> {
            self.0.remove_file(path)
        }
    }
}
