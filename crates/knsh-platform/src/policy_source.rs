//! Profile loading over the filesystem trait (KNSH-039; FR-POL-01, FR-POL-10, FR-POL-11).
//!
//! [`knsh_core::load_profile`] is pure and reaches the filesystem only through [`knsh_core::PolicyFs`] (path
//! canonicalisation) and [`knsh_core::ProfileSource`] (profile text by name). This module implements the first for
//! every [`Fs`] and the second as [`PolicyDirectory`], so the supervisor loads profiles from
//! the policies directory on the real filesystem and tests do so on `MemFs`, with the same code.
//!
//! Signature checks (FR-POL-40 to FR-POL-42) are KNSH-065's and will sit in [`PolicyDirectory`], so that the loader
//! only ever sees accepted text.

use std::path::PathBuf;

use knsh_core::{CanonicalPath, LookupError, MAX_PROFILE_LEN, PolicyFs, ProfileName, ProfileSource};

use crate::error::PlatformError;
use crate::fs::Fs;

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
            LookupError::Failed => LookupError::Failed,
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
}

impl<'a> PolicyDirectory<'a> {
    /// Profiles in `dir`, which must be absolute, read through `fs`.
    #[must_use]
    pub fn new(dir: PathBuf, fs: &'a dyn Fs) -> Self {
        Self { dir, fs }
    }
}

impl ProfileSource for PolicyDirectory<'_> {
    fn read_profile(&self, name: &ProfileName) -> Result<Vec<u8>, LookupError> {
        let path = self.dir.join(format!("{}.{PROFILE_EXTENSION}", name.as_str()));
        // The parser's own limit, so an oversized file is refused before it is read into memory.
        let limit = u64::try_from(MAX_PROFILE_LEN).unwrap_or(u64::MAX);
        self.fs.read(&path, limit).map_err(|error| lookup_error(&error))
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use knsh_core::{PathContext, ProfileErrorKind, ReadScope, load_profile};

    use super::*;
    use crate::Operation;
    use crate::testing::MemFs;

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

    fn write_profile(fs: &MemFs, name: &str, text: &str) {
        fs.write(&policies().join(format!("{name}.toml")), text.as_bytes(), 0o600)
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
        write_profile(&fs, "base", "name = \"base\"\n[fs]\ndeny = [\"~/.ssh\"]\n");
        write_profile(
            &fs,
            "web",
            "name = \"web\"\nextends = \"base\"\n[fs]\nwrite = [\"${PROJECT}\", \"${TMPDIR}\"]\n",
        );
        let dyn_fs: &dyn Fs = &fs;
        let source = PolicyDirectory::new(policies(), dyn_fs);
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
        let dyn_fs: &dyn Fs = &fs;
        let source = PolicyDirectory::new(policies(), dyn_fs);
        let error = load_profile(&name("absent"), &source, &context(), dyn_fs).unwrap_err();
        assert_eq!(error.kind(), &ProfileErrorKind::ProfileNotFound);

        write_profile(&fs, "p", "name = \"p\"\n");
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
        write_profile(&fs, "p", "name = \"p\"\n[fs]\ndeny = [\"~/.aws/credentials\"]\n");
        let source = PolicyDirectory::new(policies(), dyn_fs);
        let error = load_profile(&name("p"), &source, &context(), dyn_fs).unwrap_err();
        assert_eq!(error.kind(), &ProfileErrorKind::PathUnresolvable);
        assert_eq!(error.key(), Some("fs.deny[0]"));
    }
}
