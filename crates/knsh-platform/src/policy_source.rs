//! Profile loading over the filesystem trait (KNSH-039; FR-POL-01, FR-POL-10, FR-POL-11).
//!
//! [`knsh_core::load_profile`] is pure and reaches the filesystem only through [`knsh_core::PolicyFs`] (path
//! canonicalisation) and [`knsh_core::ProfileSource`] (profile text by name). This module implements the first for
//! every [`Fs`] and the second as [`PolicyDirectory`], so the supervisor loads profiles from
//! the policies directory on the real filesystem and tests do so on `MemFs`, with the same code.
//!
//! Every file is checked against its signature ([`PolicySigner`], KNSH-065, FR-POL-40 to FR-POL-42) before its text
//! reaches the loader: a file with a missing or bad signature is [`LookupError::SignatureInvalid`], never parsed. The
//! same type reads a profile for `knsh policy edit` ([`PolicyDirectory::read_for_edit`]) and writes the signed file
//! back ([`PolicyDirectory::save`]), which needs the user's [`Authenticated`] proof (FR-POL-41).

use std::path::PathBuf;

use knsh_core::{CanonicalPath, LookupError, MAX_PROFILE_LEN, PolicyFs, ProfileName, ProfileSource};

use crate::engine_dirs::{DIR_MODE, FILE_MODE};
use crate::error::PlatformError;
use crate::fs::Fs;
use crate::presence::Authenticated;
use crate::signing::{PolicySigner, SIGNATURE_LINE_LEN, SignatureFault, strip_signature};

/// The extension of profile files in the policies directory.
const PROFILE_EXTENSION: &str = "toml";

/// Maps a platform error to the loader's view: "not found" only for `ENOENT` and `ENOTDIR` (a path through a file),
/// so the loader may treat the path as not existing yet; everything else is a failure that refuses the profile.
fn lookup_error(error: &PlatformError) -> LookupError {
    match error.errno() {
        Some(libc::ENOENT | libc::ENOTDIR) => LookupError::NotFound,
        _ => LookupError::Failed,
    }
}

/// The longest profile file read: the parser's limit for the body plus the signature trailer and the newline a save
/// may add, so an oversized file is refused before it is read into memory.
fn file_limit() -> u64 {
    u64::try_from(MAX_PROFILE_LEN + 1 + SIGNATURE_LINE_LEN).unwrap_or(u64::MAX)
}

impl PolicyFs for dyn Fs + '_ {
    fn canonicalise(&self, path: &std::path::Path) -> Result<CanonicalPath, LookupError> {
        Fs::canonicalise(self, path).map_err(|error| match lookup_error(&error) {
            // A dangling symlink also makes `realpath` report `ENOENT`, but the loader must not then resolve the
            // path through its parent: the sandbox matches the link's target, so a deny written on the link's own
            // path would not cover the target once it is created. Something exists at `path` itself when `lstat`
            // finds it, so the lookup failed rather than found nothing (FR-POL-11, fail closed).
            LookupError::NotFound => match self.metadata(path) {
                Ok(_) => LookupError::Failed,
                Err(error) => lookup_error(&error),
            },
            LookupError::Failed | LookupError::SignatureInvalid => LookupError::Failed,
        })
    }
}

/// The policies directory ([`EnginePaths::policies_dir`](crate::EnginePaths::policies_dir)): the
/// profile `name` is the file `<name>.toml`.
///
/// Profile names are 1 to 64 characters from `[A-Za-z0-9._-]` ([`ProfileName`]), so a name never holds `/` and
/// always maps to a file directly in the directory.
pub struct PolicyDirectory<'a> {
    dir: PathBuf,
    fs: &'a dyn Fs,
    signer: &'a PolicySigner,
}

/// The state of a profile's file, as `knsh policy edit` shows it before editing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileState {
    /// No file yet: saving creates the profile.
    New,
    /// The signature verifies.
    Valid,
    /// The file is ignored (FR-POL-42): the user should review its text before signing it.
    Invalid(SignatureFault),
}

/// A profile's current text for editing: the body without its signature trailer, and whether the file verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EditableProfile {
    /// The text the user edits: empty for a new profile.
    pub body: Vec<u8>,
    /// Whether that text is what the engine currently uses.
    pub state: FileState,
}

impl<'a> PolicyDirectory<'a> {
    /// Profiles in `dir`, which must be absolute, read through `fs` and checked by `signer`.
    #[must_use]
    pub fn new(dir: PathBuf, fs: &'a dyn Fs, signer: &'a PolicySigner) -> Self {
        Self { dir, fs, signer }
    }

    /// The file of profile `name`.
    fn path(&self, name: &ProfileName) -> PathBuf {
        self.dir.join(format!("{}.{PROFILE_EXTENSION}", name.as_str()))
    }

    /// The profile's file as it is, at most the profile limit plus a trailer; `None` if it does not exist.
    fn read_file(&self, name: &ProfileName) -> Result<Option<Vec<u8>>, PlatformError> {
        match self.fs.read(&self.path(name), file_limit()) {
            Ok(file) => Ok(Some(file)),
            Err(error) if lookup_error(&error) == LookupError::NotFound => Ok(None),
            Err(error) => Err(error),
        }
    }

    /// The text of profile `name` for editing, with its signature state (FR-POL-41). Reading needs no
    /// authentication: the file is the user's own and readable anyway; only saving does.
    ///
    /// # Errors
    ///
    /// A [`PlatformError`] if the file exists but cannot be read.
    pub fn read_for_edit(&self, name: &ProfileName) -> Result<EditableProfile, PlatformError> {
        let Some(file) = self.read_file(name)? else {
            return Ok(EditableProfile {
                body: Vec::new(),
                state: FileState::New,
            });
        };
        let state = match self.signer.verify(name, &file) {
            Ok(_) => FileState::Valid,
            Err(fault) => FileState::Invalid(fault),
        };
        Ok(EditableProfile {
            body: strip_signature(&file).to_vec(),
            state,
        })
    }

    /// Signs `body` as profile `name` and writes it in one atomic replace (owner-only, `0600`), after the user
    /// authenticated (FR-POL-41): `proof` is spent on this one save. Returns the file as written.
    ///
    /// # Errors
    ///
    /// A [`PlatformError`] if the key cannot be read or created (nothing is written) or the write fails (the previous
    /// file is kept, CLAUDE.md "Persistence").
    pub fn save(&self, name: &ProfileName, body: &[u8], proof: Authenticated) -> Result<Vec<u8>, PlatformError> {
        let file = self.signer.sign(name, body, proof)?;
        // `ensure_engine_dirs` creates the configuration directory but not the policies directory in it, so the first
        // `knsh policy edit` on a fresh install creates it (owner-only). One that already exists is the user's and left
        // as it is; a non-directory there makes the write below fail (FR-POL-41).
        match self.fs.create_dir(&self.dir, DIR_MODE) {
            Err(error) if error.errno() != Some(libc::EEXIST) => return Err(error),
            Ok(()) | Err(_) => {}
        }
        self.fs.atomic_replace(&self.path(name), &file, FILE_MODE)?;
        Ok(file)
    }
}

impl ProfileSource for PolicyDirectory<'_> {
    fn read_profile(&self, name: &ProfileName) -> Result<Vec<u8>, LookupError> {
        let file = self
            .fs
            .read(&self.path(name), file_limit())
            .map_err(|error| lookup_error(&error))?;
        // FR-POL-42: only a body whose signature verified is handed to the loader.
        let body = self
            .signer
            .verify(name, &file)
            .map_err(|_| LookupError::SignatureInvalid)?;
        // The parser's own limit applies to the body as before.
        if body.len() > MAX_PROFILE_LEN {
            return Err(LookupError::Failed);
        }
        Ok(body.to_vec())
    }
}

// The signer's MAC is CommonCrypto's, so these tests run where the macOS backend is built. `cfg(test)` stays its
// own attribute so clippy treats the module as test code (`allow-unwrap-in-tests`).
#[cfg(test)]
#[cfg(target_os = "macos")]
mod tests {
    use std::path::Path;
    use std::sync::Arc;

    use knsh_core::{PathContext, ProfileErrorKind, ReadScope, load_profile};

    use super::*;
    use crate::Operation;
    use crate::testing::{MemFs, MemKeyStore};

    /// The policies directory for the fake home, from `EnginePaths` so no engine path literal is repeated here.
    fn policies() -> PathBuf {
        crate::EnginePaths::for_home(Path::new("/Users/u"))
            .unwrap()
            .policies_dir()
    }

    fn fs() -> MemFs {
        let fs = MemFs::new();
        fs.add_dir_all(&policies()).unwrap();
        for dir in ["/Users/u/src/app/.git", "/private/var/folders/xy/T"] {
            fs.add_dir_all(Path::new(dir)).unwrap();
        }
        fs.add_symlink(Path::new("/var"), Path::new("private/var")).unwrap();
        fs
    }

    fn context() -> PathContext {
        PathContext {
            home: PathBuf::from("/Users/u"),
            tmpdir: PathBuf::from("/var/folders/xy/T"),
            start_dir: PathBuf::from("/Users/u/src/app"),
        }
    }

    fn signer() -> PolicySigner {
        crate::signing::tests::signer(&Arc::new(MemKeyStore::new()))
    }

    /// Writes `text` as profile `name`, signed by `signer` as `knsh policy edit` would.
    fn write_profile(fs: &MemFs, signer: &PolicySigner, name: &str, text: &str) {
        let file = signer
            .sign(&ProfileName::new(name).unwrap(), text.as_bytes(), Authenticated::new())
            .unwrap();
        fs.write(&policies().join(format!("{name}.toml")), &file, 0o600)
            .unwrap();
    }

    fn name(text: &str) -> ProfileName {
        ProfileName::new(text).unwrap()
    }

    // FR-POL-01, FR-POL-10, FR-POL-11: a profile and its parent load from the policies directory, with `${TMPDIR}`
    // canonicalised through the `/var` symlink and `${PROJECT}` at the git root.
    #[test]
    fn loads_profiles_from_the_policies_directory() {
        let fs = fs();
        let signer = signer();
        write_profile(&fs, &signer, "base", "name = \"base\"\n[fs]\ndeny = [\"~/.ssh\"]\n");
        write_profile(
            &fs,
            &signer,
            "web",
            "name = \"web\"\nextends = \"base\"\n[fs]\nwrite = [\"${PROJECT}\", \"${TMPDIR}\"]\n",
        );
        let dyn_fs: &dyn Fs = &fs;
        let source = PolicyDirectory::new(policies(), dyn_fs, &signer);
        let profile = load_profile(&name("web"), &source, &context(), dyn_fs).unwrap();
        assert_eq!(profile.fs.read, ReadScope::All);
        assert_eq!(
            profile.fs.write,
            [
                CanonicalPath::new("/Users/u/src/app").unwrap(),
                CanonicalPath::new("/private/var/folders/xy/T").unwrap(),
            ]
        );
        assert_eq!(profile.fs.deny, [CanonicalPath::new("/Users/u/.ssh").unwrap()]);
    }

    #[test]
    fn missing_and_unreadable_profiles_are_distinguished() {
        let fs = fs();
        let signer = signer();
        let dyn_fs: &dyn Fs = &fs;
        let source = PolicyDirectory::new(policies(), dyn_fs, &signer);
        let error = load_profile(&name("absent"), &source, &context(), dyn_fs).unwrap_err();
        assert_eq!(error.kind(), &ProfileErrorKind::ProfileNotFound);

        write_profile(&fs, &signer, "p", "name = \"p\"\n");
        fs.inject_fault(Operation::Open, libc::EACCES);
        let error = load_profile(&name("p"), &source, &context(), dyn_fs).unwrap_err();
        assert_eq!(error.kind(), &ProfileErrorKind::ProfileUnreadable);
    }

    // FR-POL-11: only "not found" lets a path resolve through its existing ancestor; other failures refuse it.
    #[test]
    fn canonicalisation_errors_map_to_lookup_errors() {
        let fs = fs();
        let dyn_fs: &dyn Fs = &fs;
        assert_eq!(
            PolicyFs::canonicalise(dyn_fs, Path::new("/Users/u/none")),
            Err(LookupError::NotFound)
        );
        fs.add_symlink(Path::new("/loop"), Path::new("/loop")).unwrap();
        assert_eq!(
            PolicyFs::canonicalise(dyn_fs, Path::new("/loop")),
            Err(LookupError::Failed)
        );
    }

    // FR-POL-11: a dangling symlink is not "not found": resolving through its parent would put a deny on the link's
    // own path, which the sandbox never matches, so the profile is refused instead.
    #[test]
    fn dangling_symlinks_refuse_the_profile() {
        let fs = fs();
        fs.add_symlink(Path::new("/Users/u/.aws"), Path::new("/Volumes/gone/aws"))
            .unwrap();
        let dyn_fs: &dyn Fs = &fs;
        assert_eq!(
            PolicyFs::canonicalise(dyn_fs, Path::new("/Users/u/.aws")),
            Err(LookupError::Failed)
        );
        // Below the link, the walk up to the deepest existing ancestor meets the link and fails there too.
        assert_eq!(
            PolicyFs::canonicalise(dyn_fs, Path::new("/Users/u/.aws/credentials")),
            Err(LookupError::NotFound)
        );
        let signer = signer();
        write_profile(
            &fs,
            &signer,
            "p",
            "name = \"p\"\n[fs]\ndeny = [\"~/.aws/credentials\"]\n",
        );
        let source = PolicyDirectory::new(policies(), dyn_fs, &signer);
        let error = load_profile(&name("p"), &source, &context(), dyn_fs).unwrap_err();
        assert_eq!(error.kind(), &ProfileErrorKind::PathUnresolvable);
        assert_eq!(error.key(), Some("fs.deny[0]"));
    }

    // FR-POL-42: an unsigned file, a file changed after signing, and a parent in the `extends` chain with a bad
    // signature are all ignored; the loader reports the profile at fault and returns nothing.
    #[test]
    fn unsigned_or_changed_files_are_never_loaded() {
        let fs = fs();
        let signer = signer();
        let dyn_fs: &dyn Fs = &fs;
        let source = PolicyDirectory::new(policies(), dyn_fs, &signer);

        fs.write(&policies().join("plain.toml"), b"name = \"plain\"\n", 0o600)
            .unwrap();
        let error = load_profile(&name("plain"), &source, &context(), dyn_fs).unwrap_err();
        assert_eq!(error.kind(), &ProfileErrorKind::SignatureInvalid);
        assert_eq!(error.origin(), Some(&knsh_core::ProfileOrigin::Profile(name("plain"))));

        write_profile(&fs, &signer, "base", "name = \"base\"\n[fs]\ndeny = [\"~/.ssh\"]\n");
        write_profile(&fs, &signer, "web", "name = \"web\"\nextends = \"base\"\n");
        assert!(load_profile(&name("web"), &source, &context(), dyn_fs).is_ok());
        // An agent-style edit of the parent: drop the deny, keep the old trailer.
        let path = policies().join("base.toml");
        let file = fs.read(&path, 1 << 20).unwrap();
        let tampered = String::from_utf8(file)
            .unwrap()
            .replace("deny = [\"~/.ssh\"]", "deny = []");
        fs.write(&path, tampered.as_bytes(), 0o600).unwrap();
        let error = load_profile(&name("web"), &source, &context(), dyn_fs).unwrap_err();
        assert_eq!(error.kind(), &ProfileErrorKind::SignatureInvalid);
        assert_eq!(error.origin(), Some(&knsh_core::ProfileOrigin::Profile(name("base"))));
    }

    // FR-POL-41: editing reads the body without its trailer and the file's state; saving writes one signed,
    // owner-only file that the loader then accepts.
    #[test]
    fn read_for_edit_and_save_round_trip() {
        let fs = fs();
        let signer = signer();
        let dyn_fs: &dyn Fs = &fs;
        let source = PolicyDirectory::new(policies(), dyn_fs, &signer);
        assert_eq!(
            source.read_for_edit(&name("web")).unwrap(),
            EditableProfile {
                body: Vec::new(),
                state: FileState::New
            }
        );

        let written = source
            .save(&name("web"), b"name = \"web\"\n", Authenticated::new())
            .unwrap();
        let path = policies().join("web.toml");
        assert_eq!(fs.read(&path, 1 << 20).unwrap(), written);
        assert_eq!(fs.metadata(&path).unwrap().mode & 0o7777, 0o600);
        let editable = source.read_for_edit(&name("web")).unwrap();
        assert_eq!(editable.body, b"name = \"web\"\n");
        assert_eq!(editable.state, FileState::Valid);
        assert!(load_profile(&name("web"), &source, &context(), dyn_fs).is_ok());

        fs.write(&path, b"name = \"web\"\n", 0o600).unwrap();
        let editable = source.read_for_edit(&name("web")).unwrap();
        assert_eq!(editable.state, FileState::Invalid(SignatureFault::Missing));
        assert_eq!(editable.body, b"name = \"web\"\n");

        // A failed write keeps the previous file (CLAUDE.md "Persistence").
        fs.inject_fault(Operation::Rename, libc::EIO);
        assert!(
            source
                .save(&name("web"), b"name = \"web\"\n# new\n", Authenticated::new())
                .is_err()
        );
        assert_eq!(fs.read(&path, 1 << 20).unwrap(), b"name = \"web\"\n");
    }

    // FR-POL-41: on a fresh install only the configuration directory exists; the first save creates the policies
    // directory, owner-only.
    #[test]
    fn first_save_creates_the_policies_directory() {
        let fs = MemFs::new();
        let config = policies().parent().unwrap().to_path_buf();
        fs.add_dir_all(&config).unwrap();
        let signer = signer();
        let dyn_fs: &dyn Fs = &fs;
        let source = PolicyDirectory::new(policies(), dyn_fs, &signer);
        source
            .save(&name("web"), b"name = \"web\"\n", Authenticated::new())
            .unwrap();
        assert_eq!(fs.metadata(&policies()).unwrap().mode & 0o7777, DIR_MODE);
        assert_eq!(source.read_for_edit(&name("web")).unwrap().state, FileState::Valid);
        // A second save finds the directory in place.
        source
            .save(&name("web"), b"name = \"web\"\n# again\n", Authenticated::new())
            .unwrap();
    }
}
