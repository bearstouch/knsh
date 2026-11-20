//! Pathname expansion (KNSH-098; NFR-COMPAT-02): matching a word against file names, as bash 5.2 does after word
//! splitting. Directories are read only through the injected [`Fs`], so tests run against an in-memory tree.
//!
//! The pattern is split at each `/` into components. A component without pattern characters is taken as written (the
//! last one must exist, as `lstat` sees it); a component with them is matched against the entries of each directory
//! reached so far; any component but the last keeps only directories (a symlink to one counts). A pattern ending in
//! `/` matches only directories, and each result keeps the slash.
//!
//! - Names starting with `.` match only a component that starts with `.` (or, with `extglob`, a group with an
//!   alternative that does), unless `dotglob` is set; `.` and `..` never match (bash 5.2's `globskipdots`, on by
//!   default).
//! - `nocaseglob` matches letters of either case; `extglob` reads the groups `?(…)`, `*(…)`, `+(…)`, `@(…)` and
//!   `!(…)`.
//! - With `globstar`, a component that is exactly `**` matches any number of directories (none included) below the
//!   ones reached, without following symlinks or entering hidden directories (unless `dotglob`); as the last
//!   component it matches every file and directory below, and the directory itself with a trailing `/`.
//! - A non-empty `GLOBIGNORE` removes every result matching one of its `:`-separated patterns, and turns `dotglob`
//!   on, as in bash.
//!
//! Results come back sorted by their bytes (the C locale's order); the expander then sorts them in the collation
//! of the shell's locale through [`knsh_platform::Collation`], as bash sorts with `strcoll`.
//!
//! Bounds (CLAUDE.md "Untrusted input"): one directory may hold at most [`MAX_DIRECTORY_ENTRIES`] entries, one word
//! may read at most [`MAX_VISITED`] entries in all and match at most [`MAX_MATCHES`]; past a bound the word fails
//! with [`InterpError::ExpansionLimit`] instead of returning part of the matches. A matching name that is not UTF-8
//! is refused ([`Unsupported::NonUtf8FileName`]): words are strings here, and dropping it would differ from bash.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use knsh_bash::Span;
use knsh_platform::{FileKind, Fs, PlatformError};

use crate::error::{InterpError, Unsupported};
use crate::pattern::{self, Flags, GroupKind, Pattern};
use crate::word::WordChar;

/// Most entries one directory may hold for pathname expansion to read it.
pub(crate) const MAX_DIRECTORY_ENTRIES: usize = 1 << 20;

/// Most directory entries pathname expansion of one word may read in all (a bound on `**` over a large tree).
pub(crate) const MAX_VISITED: usize = 1 << 22;

/// Most file names one word may expand into.
pub(crate) const MAX_MATCHES: usize = 1 << 20;

/// What changes how names are matched: the `shopt` options of the same names, each independent of the others.
#[derive(Debug, Clone, Default)]
#[allow(clippy::struct_excessive_bools)]
pub(crate) struct Options {
    /// `dotglob`.
    pub(crate) dotglob: bool,
    /// `nocaseglob`.
    pub(crate) nocaseglob: bool,
    /// `globstar`.
    pub(crate) globstar: bool,
    /// `extglob`.
    pub(crate) extglob: bool,
    /// The patterns of a non-empty `GLOBIGNORE`, compiled.
    pub(crate) ignore: Vec<Pattern>,
}

/// A path reached so far.
#[derive(Debug, Clone)]
struct Reached {
    /// As it will be printed: relative to the working directory unless the pattern was absolute.
    display: String,
    /// Set for the empty path `**` reaches by matching no directory at the start of a relative pattern: the slash
    /// written after the `**` is dropped, so `**/x` matches `x` and not `/x`.
    absorb: bool,
}

/// The file names `pattern` matches, sorted; empty when none does.
///
/// # Errors
///
/// [`InterpError::ExpansionLimit`] past a bound; [`InterpError::Unsupported`] (at `span`, the word's) for a matching
/// name that is not UTF-8.
pub(crate) fn glob(
    fs: &dyn Fs,
    cwd: &Path,
    pattern: &[WordChar],
    options: &Options,
    span: Span,
) -> Result<Vec<String>, InterpError> {
    let mut globber = Globber {
        fs,
        cwd,
        options,
        visited: 0,
        span,
    };
    let components = components(pattern);
    let mut reached = vec![Reached {
        display: String::new(),
        absorb: false,
    }];
    let count = components.len();
    for (index, (separator, component)) in components.iter().enumerate() {
        let last = index + 1 == count;
        reached = globber.step(&reached, separator, component, last)?;
        if reached.is_empty() {
            break;
        }
    }
    let mut out: Vec<String> = reached
        .into_iter()
        .map(|path| path.display)
        .filter(|display| !display.is_empty())
        .filter(|display| !options.ignore.iter().any(|ignore| ignore.matches_str(display)))
        .collect();
    if out.len() > MAX_MATCHES {
        return Err(limit("pathname expansion matches", MAX_MATCHES));
    }
    out.sort_unstable();
    Ok(out)
}

fn limit(what: &'static str, limit: usize) -> InterpError {
    InterpError::ExpansionLimit { what, limit }
}

/// The components of `pattern`, each with the run of slashes written before it (empty for the first of a relative
/// pattern). A trailing run of slashes gives a last, empty component.
fn components(pattern: &[WordChar]) -> Vec<(String, Vec<WordChar>)> {
    let mut out = Vec::new();
    let mut separator = String::new();
    let mut component = Vec::new();
    for &c in pattern {
        if c.ch == '/' {
            if !component.is_empty() {
                out.push((std::mem::take(&mut separator), std::mem::take(&mut component)));
            }
            separator.push('/');
        } else {
            component.push(c);
        }
    }
    if !component.is_empty() || !separator.is_empty() {
        out.push((separator, component));
    }
    out
}

/// Reads directories for one word.
struct Globber<'a> {
    fs: &'a dyn Fs,
    cwd: &'a Path,
    options: &'a Options,
    /// Directory entries read so far, against [`MAX_VISITED`].
    visited: usize,
    /// The word's span, for a refusal.
    span: Span,
}

impl Globber<'_> {
    /// The absolute path of a displayed one.
    fn absolute(&self, display: &str) -> PathBuf {
        if display.is_empty() {
            self.cwd.to_path_buf()
        } else {
            self.cwd.join(display)
        }
    }

    /// `path` followed by `separator` and `name`.
    fn join(path: &Reached, separator: &str, name: &str) -> Reached {
        let separator = if path.absorb { "" } else { separator };
        Reached {
            display: format!("{}{separator}{name}", path.display),
            absorb: false,
        }
    }

    /// Whether anything exists at `display`, without following a final symlink (bash's `lstat`).
    fn exists(&self, display: &str) -> bool {
        self.fs.metadata(&self.absolute(display)).is_ok()
    }

    /// Whether `display` is a directory, following a final symlink.
    fn is_dir(&self, display: &str) -> bool {
        let path = self.absolute(display);
        match self.fs.metadata(&path) {
            Ok(metadata) => match metadata.kind {
                FileKind::Directory => true,
                FileKind::Symlink => self
                    .fs
                    .canonicalise(&path)
                    .and_then(|canonical| self.fs.metadata(canonical.as_path()))
                    .is_ok_and(|metadata| metadata.kind == FileKind::Directory),
                FileKind::File | FileKind::Other => false,
            },
            Err(_) => false,
        }
    }

    /// The entries of the directory `display`, or none if it cannot be read (bash skips such a directory).
    fn entries(&mut self, display: &str) -> Result<Vec<OsString>, InterpError> {
        match self.fs.list_dir(&self.absolute(display), MAX_DIRECTORY_ENTRIES) {
            Ok(entries) => {
                self.visited = self.visited.saturating_add(entries.len());
                if self.visited > MAX_VISITED {
                    return Err(limit("pathname expansion entries read", MAX_VISITED));
                }
                Ok(entries)
            }
            Err(PlatformError::TooLarge { .. }) => Err(limit("directory entries", MAX_DIRECTORY_ENTRIES)),
            Err(_) => Ok(Vec::new()),
        }
    }

    fn non_utf8(&self) -> InterpError {
        InterpError::Unsupported {
            feature: Unsupported::NonUtf8FileName,
            span: self.span,
        }
    }

    fn dotglob(&self) -> bool {
        self.options.dotglob || !self.options.ignore.is_empty()
    }

    fn flags(&self) -> Flags {
        Flags {
            extglob: self.options.extglob,
            nocase: self.options.nocaseglob,
        }
    }

    /// The paths one component reaches from `reached`.
    fn step(
        &mut self,
        reached: &[Reached],
        separator: &str,
        component: &[WordChar],
        last: bool,
    ) -> Result<Vec<Reached>, InterpError> {
        // A trailing slash: only directories, each keeping the slash.
        if component.is_empty() {
            return Ok(reached
                .iter()
                .filter(|path| !path.display.is_empty() && self.is_dir(&path.display))
                .map(|path| Self::join(path, separator, ""))
                .collect());
        }
        let is_globstar =
            self.options.globstar && component.len() == 2 && component.iter().all(|c| c.ch == '*' && !c.quoted);
        if is_globstar {
            return self.globstar(reached, separator, last);
        }
        if !pattern::has_glob(component, self.options.extglob) {
            let name: String = component.iter().map(|c| c.ch).collect();
            let mut out = Vec::new();
            for path in reached {
                let next = Self::join(path, separator, &name);
                if !last || self.exists(&next.display) {
                    out.push(next);
                }
            }
            return Ok(out);
        }
        let matcher = Pattern::new(component, self.flags());
        let hidden_ok = self.dotglob() || may_match_hidden(component);
        let mut out = Vec::new();
        for path in reached {
            let directory = Self::join(path, separator, "").display;
            for entry in self.entries(&directory)? {
                let lossy = entry.to_string_lossy();
                if lossy.starts_with('.') && !hidden_ok {
                    continue;
                }
                if !matcher.matches_str(&lossy) {
                    continue;
                }
                let Some(name) = entry.to_str() else {
                    return Err(self.non_utf8());
                };
                let next = Self::join(path, separator, name);
                if last || self.is_dir(&next.display) {
                    out.push(next);
                }
                if out.len() > MAX_MATCHES {
                    return Err(limit("pathname expansion matches", MAX_MATCHES));
                }
            }
        }
        Ok(out)
    }

    /// `**` with `globstar`: below each reached directory, every directory (or, as the last component, every entry,
    /// and the directory itself with the slash).
    fn globstar(&mut self, reached: &[Reached], separator: &str, last: bool) -> Result<Vec<Reached>, InterpError> {
        let mut out = Vec::new();
        for path in reached {
            if !path.display.is_empty() && !self.is_dir(&path.display) {
                continue;
            }
            if last {
                if !path.display.is_empty() {
                    out.push(Self::join(path, separator, ""));
                }
            } else {
                // No directory at all: the next component follows directly, without a second slash.
                out.push(Reached {
                    absorb: true,
                    ..Self::join(path, separator, "")
                });
            }
            let start = Self::join(path, separator, "").display;
            self.walk(&start, last, &mut out)?;
            if out.len() > MAX_MATCHES {
                return Err(limit("pathname expansion matches", MAX_MATCHES));
            }
        }
        Ok(out)
    }

    /// Every entry below the directory `start` (displayed ending with its separator, or empty), depth first, without
    /// following symlinks or entering hidden directories unless `dotglob`: all of them with `files`, otherwise only
    /// the directories.
    fn walk(&mut self, start: &str, files: bool, out: &mut Vec<Reached>) -> Result<(), InterpError> {
        let mut pending = vec![start.to_owned()];
        while let Some(prefix) = pending.pop() {
            for entry in self.entries(&prefix)? {
                let lossy = entry.to_string_lossy();
                if lossy.starts_with('.') && !self.dotglob() {
                    continue;
                }
                // A directory itself, not a symlink to one: what `**` descends into.
                let directory = self
                    .fs
                    .metadata(&self.absolute(&prefix).join(&entry))
                    .is_ok_and(|metadata| metadata.kind == FileKind::Directory);
                if !directory && !files {
                    // Neither reached nor entered: its name does not matter, UTF-8 or not.
                    continue;
                }
                let Some(name) = entry.to_str() else {
                    return Err(self.non_utf8());
                };
                let display = format!("{prefix}{name}");
                if directory || files {
                    out.push(Reached {
                        display: display.clone(),
                        absorb: false,
                    });
                    if out.len() > MAX_MATCHES {
                        return Err(limit("pathname expansion matches", MAX_MATCHES));
                    }
                }
                if directory {
                    pending.push(format!("{display}/"));
                }
            }
        }
        Ok(())
    }
}

/// Whether a component may match a name starting with `.` without `dotglob`: it starts with a `.` (quoted or not),
/// or with an extended glob group (other than `!(…)`) one of whose alternatives does.
fn may_match_hidden(component: &[WordChar]) -> bool {
    if component.first().is_some_and(|c| c.ch == '.') {
        return true;
    }
    match pattern::leading_group(component) {
        Some((GroupKind::Not, _)) | None => false,
        Some((_, alternatives)) => alternatives
            .iter()
            .any(|alternative| alternative.first().is_some_and(|c| c.ch == '.')),
    }
}

#[cfg(test)]
mod tests;
