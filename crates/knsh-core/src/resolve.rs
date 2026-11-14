//! Binary resolution and trusted folders (KNSH-035; FR-LC-03, FR-POL-11, FR-POL-13, FR-POL-14).
//!
//! The supervisor resolves every simple command's name the way bash would run it, and tags the result so that name
//! rules match only binaries from trusted folders:
//!
//! 1. A call the parser marked as reaching a function defined earlier in the line is a [`Resolution::Function`].
//! 2. A name without `/` that bash runs itself ([`knsh_bash::is_builtin`]) is a [`Resolution::Builtin`].
//! 3. A name with `/` is a path, taken relative to the working directory unless absolute, and canonicalised.
//! 4. Any other name is searched in the caller's `PATH`: the first entry holding an executable regular file wins.
//!
//! A found binary is classified by its **canonical** path, with every symlink followed (FR-POL-11): it is
//! [`Resolution::Trusted`] only if it sits directly in a trusted folder (FR-POL-13), and otherwise a
//! [`Resolution::ProjectExecutable`] (FR-POL-14), however it was invoked. So `git` found in `./node_modules/.bin`
//! through `PATH`, or `/usr/local/bin/x` linking to `~/project/x`, never matches a name rule. Nothing found is
//! [`Resolution::NotFound`], which the caller carries through so the line fails with 127 as bash would, rather than
//! being allowed as unknown.
//!
//! This module is pure: the filesystem is reached only through the [`BinaryLookup`] trait, which `knsh-platform`
//! implements over its `Fs` trait. Lookup failures (missing files, permission errors, symlink loops) make a candidate
//! not found, as bash skips a `PATH` entry it cannot use. That never lets anything through: the supervisor runs the
//! line with the resolved absolute paths (FR-LC-13), so what runs is what was resolved here, and `NotFound` fails the
//! line. The resolution is an intent filter, not a boundary: the sandbox's executable rules (FR-LC-15) stop a binary
//! swapped after this check.

use std::path::{Path, PathBuf};

use crate::path::CanonicalPath;

/// The trusted folders every profile starts with (FR-POL-13, `specs/09-reference/defaults-and-limits.md`).
pub const DEFAULT_TRUSTED_FOLDERS: &[&str] = &["/usr/bin", "/bin", "/usr/sbin", "/opt/homebrew/bin", "/usr/local/bin"];

/// `PATH` entries searched at most. The caller's `PATH` comes from the agent, so the number of filesystem lookups is
/// bounded; a binary only reachable past this many entries is [`Resolution::NotFound`] and the line fails closed.
pub const MAX_PATH_ENTRIES: usize = 1024;

/// The filesystem queries resolution needs. Implemented by `knsh-platform` over its `Fs` trait (and so by its
/// in-memory fake in tests); kept here so resolution stays a pure function of its inputs.
pub trait BinaryLookup {
    /// The canonical form of the absolute path `path`, with every symlink followed and no `.` or `..`, or `None` if
    /// it does not exist or cannot be resolved.
    fn canonicalise(&self, path: &Path) -> Option<CanonicalPath>;

    /// Whether `path` names a regular file with at least one execute permission bit. `false` if it cannot be read.
    fn is_executable_file(&self, path: &CanonicalPath) -> bool;
}

/// The command name of one simple command, after quote removal, and what the parser knows about it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandName<'a> {
    /// A name bash looks up itself: as a builtin, then on `PATH`, or as a path if it contains `/`.
    Lookup(&'a str),
    /// A call the parser marked as certainly reaching a function defined earlier in the line
    /// ([`knsh_bash::SimpleCommand::function_call`]). It runs the function's body, which policy decides separately.
    Function(&'a str),
}

impl<'a> From<&'a str> for CommandName<'a> {
    fn from(name: &'a str) -> Self {
        Self::Lookup(name)
    }
}

/// What a command name resolves to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolution {
    /// A binary sitting directly in a trusted folder, by canonical path. Only these match name rules (FR-POL-13).
    Trusted(CanonicalPath),
    /// A binary anywhere else, by canonical path: governed by `project_executables`, never by name rules
    /// (FR-POL-14).
    ProjectExecutable(CanonicalPath),
    /// A bash builtin, run by the shell itself.
    Builtin,
    /// A function defined earlier in the line.
    Function,
    /// Nothing to run: the line must fail with exit status 127, as bash would.
    NotFound,
}

/// The folders whose binaries name rules may match (FR-POL-13): the defaults plus any the profile adds.
///
/// # Invariants
///
/// Each folder is a [`CanonicalPath`] and appears once. A binary is trusted only if its canonical path's parent is
/// exactly one of them: subfolders are not trusted, so `/usr/local/bin/sub/x` is not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedFolders(Vec<CanonicalPath>);

impl TrustedFolders {
    /// No trusted folders at all: every binary is a project executable.
    #[must_use]
    pub fn none() -> Self {
        Self(Vec::new())
    }

    /// The [`DEFAULT_TRUSTED_FOLDERS`].
    #[must_use]
    pub fn defaults() -> Self {
        let mut folders = Self::none();
        // The defaults are canonical literals, so `new` cannot fail; a failure would only leave a folder untrusted,
        // which fails closed.
        for folder in DEFAULT_TRUSTED_FOLDERS {
            if let Ok(folder) = CanonicalPath::new(*folder) {
                folders.add(folder);
            }
        }
        folders
    }

    /// Adds a folder named by the profile. It must already be canonical (resolved at the edge, FR-POL-11), or the
    /// canonical paths of its binaries would never match it. Adding a folder twice keeps one copy.
    pub fn add(&mut self, folder: CanonicalPath) {
        if !self.0.contains(&folder) {
            self.0.push(folder);
        }
    }

    /// The folders, defaults first, then profile additions in the order added.
    #[must_use]
    pub fn folders(&self) -> &[CanonicalPath] {
        &self.0
    }

    /// Whether `binary` sits directly in one of the folders.
    #[must_use]
    pub fn contains_binary(&self, binary: &CanonicalPath) -> bool {
        binary
            .as_path()
            .parent()
            .is_some_and(|parent| self.0.iter().any(|folder| folder.as_path() == parent))
    }
}

impl Default for TrustedFolders {
    fn default() -> Self {
        Self::defaults()
    }
}

/// Resolves one simple command's name as bash would run it, and classifies the result (see the module
/// documentation).
///
/// `env_path` is the caller's `PATH` value. Each `:`-separated entry is searched in order; an empty entry or a
/// relative one is taken relative to `cwd`, as bash does, so `PATH=.:/usr/bin` finds `./x` first, and a binary found
/// that way is classified by where it really is. Only the first [`MAX_PATH_ENTRIES`] entries are searched.
///
/// Differences from bash, all failing closed:
///
/// - A name found only as a non-executable file on `PATH` is `NotFound` (127), where bash tries it and reports 126.
/// - A path name (with `/`) that exists is classified even if it is not executable or is a directory: running it then
///   fails with 126, as in bash.
/// - Bash's command hash table (`hash -p`) and `enable -n` are not modelled; the classifier treats `hash` and
///   `enable` lines as it does any builtin call (KNSH-036).
#[must_use]
pub fn resolve<L: BinaryLookup + ?Sized>(
    name: CommandName<'_>,
    env_path: &str,
    cwd: &CanonicalPath,
    trusted: &TrustedFolders,
    fs: &L,
) -> Resolution {
    let name = match name {
        CommandName::Function(_) => return Resolution::Function,
        CommandName::Lookup(name) => name,
    };
    // Bash reports `""` as "command not found" rather than searching for it.
    if name.is_empty() {
        return Resolution::NotFound;
    }
    let found = if name.contains('/') {
        // Bash runs a name with `/` directly, never through PATH; `Path::join` keeps an absolute name as it is.
        fs.canonicalise(&cwd.as_path().join(name))
    } else if knsh_bash::is_builtin(name) {
        return Resolution::Builtin;
    } else {
        search_path(name, env_path, cwd, fs)
    };
    match found {
        Some(binary) if trusted.contains_binary(&binary) => Resolution::Trusted(binary),
        Some(binary) => Resolution::ProjectExecutable(binary),
        None => Resolution::NotFound,
    }
}

/// The canonical path of the first executable regular file named `name` in the entries of `env_path`.
fn search_path<L: BinaryLookup + ?Sized>(
    name: &str,
    env_path: &str,
    cwd: &CanonicalPath,
    fs: &L,
) -> Option<CanonicalPath> {
    env_path
        .split(':')
        .take(MAX_PATH_ENTRIES)
        .map(|entry| candidate(entry, name, cwd))
        .find_map(|candidate| {
            // Canonicalise first: the executable check must see the symlink's target, not the link itself.
            fs.canonicalise(&candidate)
                .filter(|binary| fs.is_executable_file(binary))
        })
}

/// The path bash tries for `name` in one `PATH` entry: an empty entry means the working directory, and a relative
/// one is relative to it.
fn candidate(entry: &str, name: &str, cwd: &CanonicalPath) -> PathBuf {
    let directory = if entry.is_empty() {
        Path::new(".")
    } else {
        Path::new(entry)
    };
    cwd.as_path().join(directory).join(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_trusted_folders_are_all_present_and_canonical() {
        let folders = TrustedFolders::defaults();
        let paths: Vec<_> = folders.folders().iter().map(CanonicalPath::as_path).collect();
        let expected: Vec<_> = DEFAULT_TRUSTED_FOLDERS.iter().map(Path::new).collect();
        assert_eq!(paths, expected);
        assert_eq!(TrustedFolders::default(), folders);
    }

    // FR-POL-13: only binaries directly in a trusted folder are trusted, not ones in subfolders or look-alikes.
    #[test]
    fn trusted_means_directly_inside_a_trusted_folder() {
        let folders = TrustedFolders::defaults();
        let path = |p: &str| CanonicalPath::new(p).unwrap();
        assert!(folders.contains_binary(&path("/usr/bin/git")));
        assert!(folders.contains_binary(&path("/opt/homebrew/bin/rg")));
        assert!(!folders.contains_binary(&path("/usr/bin/sub/git")));
        assert!(!folders.contains_binary(&path("/usr/binx/git")));
        assert!(!folders.contains_binary(&path("/usr/bin")));
        assert!(!folders.contains_binary(&path("/")));
        assert!(!TrustedFolders::none().contains_binary(&path("/usr/bin/git")));
    }

    #[test]
    fn adding_a_folder_twice_keeps_one_copy() {
        let mut folders = TrustedFolders::none();
        folders.add(CanonicalPath::new("/nix/bin").unwrap());
        folders.add(CanonicalPath::new("/nix/bin").unwrap());
        assert_eq!(folders.folders().len(), 1);
    }

    #[test]
    fn empty_and_relative_path_entries_are_relative_to_cwd() {
        let cwd = CanonicalPath::new("/p").unwrap();
        assert_eq!(candidate("", "x", &cwd), Path::new("/p/./x"));
        assert_eq!(candidate("bin", "x", &cwd), Path::new("/p/bin/x"));
        assert_eq!(candidate("/usr/bin", "x", &cwd), Path::new("/usr/bin/x"));
    }
}
