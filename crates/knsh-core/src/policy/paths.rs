//! Path variables and canonicalisation for profiles (FR-POL-10, FR-POL-11).
//!
//! A profile path is written as an absolute path, or starts with `~`, `${PROJECT}`, `${HOME}` or `${TMPDIR}`. It is
//! parsed once into a [`PathTemplate`] (so a bad path is refused while the file is read, naming its key), and
//! expanded after the `extends` chain is merged, against [`Variables`] that were themselves canonicalised.
//!
//! Every expanded path is resolved to canonical form with symlinks followed (`/var/…` becomes `/private/var/…`),
//! because the sandbox and policy matching see canonical paths only. A profile may name a path that does not exist
//! yet (`~/.aws` on a machine without it): its deepest existing ancestor is canonicalised and the missing
//! components are appended, so a deny still covers the folder if it is created later. Only "not found" is handled
//! that way; any other lookup failure refuses the whole profile (fail closed).
//!
//! The filesystem is reached only through [`PolicyFs`], which `knsh-platform` implements over its `Fs` trait.

use std::path::{Component, Path, PathBuf};

use crate::error::{ProfileError, ProfileErrorKind};
use crate::path::CanonicalPath;

/// Why a filesystem or profile-source lookup failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LookupError {
    /// Nothing exists there (`ENOENT`, or `ENOTDIR` for a path through a file).
    NotFound,
    /// Something may exist but could not be read (permissions, I/O, symlink loops, oversized files).
    Failed,
    /// A profile file exists but its signature is missing or does not verify (FR-POL-42, KNSH-065). Only a
    /// [`ProfileSource`](crate::ProfileSource) reports it; the file's text is never handed to the loader.
    SignatureInvalid,
}

/// The filesystem queries the profile loader needs. Implemented by `knsh-platform` over its `Fs` trait (and so by
/// its in-memory fake in tests); kept here so loading stays a pure function of its inputs.
pub trait PolicyFs {
    /// The canonical form of the absolute path `path`, with every symlink followed and no `.` or `..`.
    ///
    /// # Errors
    ///
    /// [`LookupError::NotFound`] if `path` or a component of it does not exist; [`LookupError::Failed`] for any
    /// other failure. A dangling symlink at `path` itself is [`LookupError::Failed`], not `NotFound`: the loader
    /// resolves a missing path through its parent, which for a link would name the link instead of its target.
    fn canonicalise(&self, path: &Path) -> Result<CanonicalPath, LookupError>;
}

/// The raw inputs the path variables come from, as the session reports them (FR-POL-10).
///
/// Each must be absolute; the loader canonicalises them before use, so `TMPDIR=/var/folders/…/T/` becomes
/// `/private/var/folders/…/T`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathContext {
    /// The user's home directory (`$HOME`).
    pub home: PathBuf,
    /// The temporary directory (`$TMPDIR`).
    pub tmpdir: PathBuf,
    /// The session's start directory: `${PROJECT}` is its git root, or itself when there is none.
    pub start_dir: PathBuf,
}

/// The canonical values of the path variables for one session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Variables {
    pub(crate) home: CanonicalPath,
    pub(crate) tmpdir: CanonicalPath,
    pub(crate) project: CanonicalPath,
}

impl Variables {
    /// Canonicalises the context and finds the project root.
    ///
    /// Each directory must exist: a variable that cannot be resolved would make every path built on it guesswork.
    pub(crate) fn resolve<F: PolicyFs + ?Sized>(context: &PathContext, fs: &F) -> Result<Self, ProfileError> {
        let existing = |path: &Path, key: &str| {
            fs.canonicalise(path)
                .map_err(|_| ProfileError::new(ProfileErrorKind::VariableUnresolvable).at_key(key))
        };
        let home = existing(&context.home, "${HOME}")?;
        let tmpdir = existing(&context.tmpdir, "${TMPDIR}")?;
        let start = existing(&context.start_dir, "${PROJECT}")?;
        let project = project_root(&start, fs)
            .map_err(|_| ProfileError::new(ProfileErrorKind::VariableUnresolvable).at_key("${PROJECT}"))?;
        Ok(Self { home, tmpdir, project })
    }
}

/// The value of `${PROJECT}` for a session that starts in `start` (FR-POL-10): the nearest directory, from `start`
/// up to `/`, holding a `.git` entry (a directory, or the file a worktree or submodule has), else `start` itself.
///
/// This is the directory `git rev-parse --show-toplevel` reports. Note that a git repository at a high level (a
/// dotfiles repository in the home directory) makes that directory the project for every folder below it, as it
/// does for git.
///
/// # Errors
///
/// [`LookupError::Failed`] if looking for a `.git` entry fails for a reason other than "not found": guessing the
/// project would grant write access to the wrong tree.
pub fn project_root<F: PolicyFs + ?Sized>(start: &CanonicalPath, fs: &F) -> Result<CanonicalPath, LookupError> {
    for dir in start.as_path().ancestors() {
        match fs.canonicalise(&dir.join(".git")) {
            // `dir` is an ancestor of a canonical path, so it is canonical too.
            Ok(_) => return CanonicalPath::new(dir).map_err(|_| LookupError::Failed),
            Err(LookupError::NotFound) => {}
            // A path lookup never reports a signature; any such answer is a failure all the same.
            Err(LookupError::Failed | LookupError::SignatureInvalid) => return Err(LookupError::Failed),
        }
    }
    Ok(start.clone())
}

/// Longest profile path accepted as written, in bytes (Linux's `PATH_MAX`; macOS's is shorter and its resolver
/// refuses longer paths itself).
const MAX_PATH_LEN: usize = 4096;

/// What a profile path starts from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Base {
    /// `/`: the path was written absolute.
    Root,
    /// `~` or `${HOME}`.
    Home,
    /// `${TMPDIR}`.
    Tmpdir,
    /// `${PROJECT}`.
    Project,
}

/// A profile path as written, checked but not yet expanded: a base and the normal components after it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct PathTemplate {
    base: Base,
    components: Vec<String>,
}

impl PathTemplate {
    /// Parses one profile path.
    ///
    /// Empty and `.` components are dropped (`~/a//b/.` is `~/a/b`), which is exact; `..` is refused, because
    /// resolving it lexically is wrong where a component is a symlink, and a profile never needs it.
    pub(crate) fn parse(text: &str) -> Result<Self, ProfileErrorKind> {
        // The length bound also bounds the lookups `expand` makes while walking up to an existing ancestor.
        if text.len() > MAX_PATH_LEN || text.contains('\0') {
            return Err(ProfileErrorKind::InvalidPath);
        }
        let (base, rest) = if let Some(rest) = text.strip_prefix('~') {
            // `~user` would need the user database; profiles name their own user's home only.
            if !(rest.is_empty() || rest.starts_with('/')) {
                return Err(ProfileErrorKind::InvalidPath);
            }
            (Base::Home, rest)
        } else if let Some(rest) = text.strip_prefix("${") {
            let (name, rest) = rest.split_once('}').ok_or(ProfileErrorKind::UnknownVariable)?;
            let base = match name {
                "PROJECT" => Base::Project,
                "HOME" => Base::Home,
                "TMPDIR" => Base::Tmpdir,
                _ => return Err(ProfileErrorKind::UnknownVariable),
            };
            // `${PROJECT}x` is not a path below the project; refuse it rather than guess.
            if !(rest.is_empty() || rest.starts_with('/')) {
                return Err(ProfileErrorKind::UnknownVariable);
            }
            (base, rest)
        } else if text.starts_with('/') {
            (Base::Root, text)
        } else {
            return Err(ProfileErrorKind::InvalidPath);
        };
        // A variable anywhere but the start (`/opt/${HOME}`) is refused: only the forms above are defined. Any `$`
        // counts, so a misspelt `$HOME/x` is an error rather than a folder literally named `$HOME`.
        if rest.contains('$') {
            return Err(ProfileErrorKind::UnknownVariable);
        }
        let mut components = Vec::new();
        for component in rest.split('/') {
            match component {
                "" | "." => {}
                ".." => return Err(ProfileErrorKind::InvalidPath),
                normal => components.push(normal.to_owned()),
            }
        }
        Ok(Self { base, components })
    }

    /// Expands the template against `variables` and resolves it to canonical form (module documentation).
    pub(crate) fn expand<F: PolicyFs + ?Sized>(
        &self,
        variables: &Variables,
        fs: &F,
    ) -> Result<CanonicalPath, ProfileErrorKind> {
        let mut path = self.base_path(variables).to_path_buf();
        path.extend(&self.components);
        canonicalise_allowing_missing(&path, fs).map_err(|_| ProfileErrorKind::PathUnresolvable)
    }

    /// Like [`expand`](Self::expand), but refuses the path unless its canonical form is the written one: no
    /// component after the variable is a symlink (the variable itself is already canonical). For a folder the
    /// engine creates and then grants (a preset's `[env]`, FR-AGT-33), where following a link would grant its target.
    pub(crate) fn expand_without_links<F: PolicyFs + ?Sized>(
        &self,
        variables: &Variables,
        fs: &F,
    ) -> Result<CanonicalPath, ProfileErrorKind> {
        let expanded = self.expand(variables, fs)?;
        let mut written = self.base_path(variables).to_path_buf();
        written.extend(&self.components);
        if expanded.as_path() != written {
            return Err(ProfileErrorKind::InvalidValue {
                expected: "a path with no symlink after its variable",
            });
        }
        Ok(expanded)
    }

    /// The canonical folder the template starts from.
    fn base_path<'v>(&self, variables: &'v Variables) -> &'v Path {
        match self.base {
            Base::Root => Path::new("/"),
            Base::Home => variables.home.as_path(),
            Base::Tmpdir => variables.tmpdir.as_path(),
            Base::Project => variables.project.as_path(),
        }
    }
}

/// Canonicalises `path`, which is absolute with normal components only. When it does not exist, its deepest
/// existing ancestor is canonicalised and the missing components are appended unchanged.
fn canonicalise_allowing_missing<F: PolicyFs + ?Sized>(path: &Path, fs: &F) -> Result<CanonicalPath, LookupError> {
    let mut existing = path;
    let mut missing: Vec<&std::ffi::OsStr> = Vec::new();
    loop {
        match fs.canonicalise(existing) {
            Ok(found) => {
                let mut resolved = found.into_path_buf();
                resolved.extend(missing.iter().rev());
                return CanonicalPath::new(resolved).map_err(|_| LookupError::Failed);
            }
            Err(LookupError::NotFound) => {
                // The root always exists; failing to find it means the filesystem view is broken.
                let Some(Component::Normal(name)) = existing.components().next_back() else {
                    return Err(LookupError::Failed);
                };
                missing.push(name);
                existing = existing.parent().ok_or(LookupError::Failed)?;
            }
            // A path lookup never reports a signature; any such answer is a failure all the same.
            Err(LookupError::Failed | LookupError::SignatureInvalid) => return Err(LookupError::Failed),
        }
    }
}

#[cfg(test)]
pub(crate) mod testing {
    //! A tiny in-memory filesystem for the loader's unit tests: a set of existing paths and a map of symlinks.

    use std::collections::{BTreeMap, BTreeSet};
    use std::path::{Component, Path, PathBuf};

    use super::{LookupError, PolicyFs};
    use crate::path::CanonicalPath;

    #[derive(Debug, Default)]
    pub(crate) struct FakeFs {
        existing: BTreeSet<PathBuf>,
        links: BTreeMap<PathBuf, PathBuf>,
        failing: BTreeSet<PathBuf>,
    }

    impl FakeFs {
        pub(crate) fn new() -> Self {
            let mut fs = Self::default();
            fs.existing.insert(PathBuf::from("/"));
            fs
        }

        /// Adds `path` and all its ancestors.
        pub(crate) fn add(&mut self, path: &str) -> &mut Self {
            for ancestor in Path::new(path).ancestors() {
                self.existing.insert(ancestor.to_path_buf());
            }
            self
        }

        /// Makes `link` (whose parent must exist) an absolute symlink to `target`.
        pub(crate) fn link(&mut self, link: &str, target: &str) -> &mut Self {
            self.links.insert(PathBuf::from(link), PathBuf::from(target));
            self
        }

        /// Makes every lookup through `path` fail with something other than "not found".
        pub(crate) fn fail(&mut self, path: &str) -> &mut Self {
            self.failing.insert(PathBuf::from(path));
            self
        }
    }

    impl PolicyFs for FakeFs {
        fn canonicalise(&self, path: &Path) -> Result<CanonicalPath, LookupError> {
            let mut resolved = PathBuf::from("/");
            let mut pending: Vec<PathBuf> = path
                .components()
                .rev()
                .filter_map(|c| match c {
                    Component::Normal(name) => Some(PathBuf::from(name)),
                    _ => None,
                })
                .collect();
            let mut hops = 0;
            while let Some(name) = pending.pop() {
                let next = resolved.join(&name);
                if self.failing.contains(&next) {
                    return Err(LookupError::Failed);
                }
                if let Some(target) = self.links.get(&next) {
                    hops += 1;
                    if hops > 32 {
                        return Err(LookupError::Failed);
                    }
                    resolved = PathBuf::from("/");
                    for c in target.components().rev() {
                        if let Component::Normal(n) = c {
                            pending.push(PathBuf::from(n));
                        }
                    }
                    continue;
                }
                if !self.existing.contains(&next) {
                    return Err(LookupError::NotFound);
                }
                resolved = next;
            }
            CanonicalPath::new(resolved).map_err(|_| LookupError::Failed)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testing::FakeFs;
    use super::*;

    fn canonical(path: &str) -> CanonicalPath {
        CanonicalPath::new(path).unwrap()
    }

    fn variables() -> Variables {
        Variables {
            home: canonical("/Users/u"),
            tmpdir: canonical("/private/var/folders/t/T"),
            project: canonical("/Users/u/src/app"),
        }
    }

    #[test]
    fn templates_accept_the_documented_forms() {
        for ok in [
            "/",
            "/etc",
            "~",
            "~/",
            "~/.ssh",
            "${HOME}/x",
            "${PROJECT}",
            "${TMPDIR}/a/./b//c/",
        ] {
            assert!(PathTemplate::parse(ok).is_ok(), "{ok}");
        }
        assert_eq!(PathTemplate::parse("~/a"), PathTemplate::parse("${HOME}//a/."));
    }

    #[test]
    fn templates_refuse_relative_dotdot_and_unknown_variables() {
        for bad in ["", "rel", "./x", "~root/x", "/a/../b", "${PROJECT}/..", "/a\0b"] {
            assert_eq!(PathTemplate::parse(bad), Err(ProfileErrorKind::InvalidPath), "{bad:?}");
        }
        let long = format!("/{}", "a/".repeat(MAX_PATH_LEN / 2));
        assert_eq!(PathTemplate::parse(&long), Err(ProfileErrorKind::InvalidPath));
        for bad in [
            "${USER}/x",
            "${PROJECT",
            "${PROJECT}x",
            "/opt/${HOME}",
            "${}",
            "/$HOME",
            "~/$x",
        ] {
            assert_eq!(
                PathTemplate::parse(bad),
                Err(ProfileErrorKind::UnknownVariable),
                "{bad:?}"
            );
        }
    }

    // FR-POL-11: a missing path keeps its canonical ancestor and appends the rest.
    #[test]
    fn missing_paths_resolve_through_their_deepest_existing_ancestor() {
        let mut fs = FakeFs::new();
        fs.add("/Users/u").add("/private/var").link("/var", "/private/var");
        let template = PathTemplate::parse("~/.aws/credentials").unwrap();
        assert_eq!(
            template.expand(&variables(), &fs).unwrap(),
            canonical("/Users/u/.aws/credentials")
        );
        let through_link = PathTemplate::parse("/var/new/dir").unwrap();
        assert_eq!(
            through_link.expand(&variables(), &fs).unwrap(),
            canonical("/private/var/new/dir")
        );
    }

    #[test]
    fn lookup_failures_other_than_not_found_refuse_the_path() {
        let mut fs = FakeFs::new();
        fs.add("/Users/u").fail("/Users/u/locked");
        let template = PathTemplate::parse("~/locked/x").unwrap();
        assert_eq!(
            template.expand(&variables(), &fs),
            Err(ProfileErrorKind::PathUnresolvable)
        );
    }

    #[test]
    fn project_root_stops_at_the_nearest_git_entry() {
        let mut fs = FakeFs::new();
        fs.add("/w/outer/.git")
            .add("/w/outer/inner/.git")
            .add("/w/outer/inner/src");
        let start = canonical("/w/outer/inner/src");
        assert_eq!(project_root(&start, &fs), Ok(canonical("/w/outer/inner")));
        fs.fail("/w/outer/inner/src/.git");
        assert_eq!(project_root(&start, &fs), Err(LookupError::Failed));
    }
}
