//! `cd` and `pwd` (KNSH-101; NFR-COMPAT-02, NFR-COMPAT-10), following bash 5.2's `cd.def`.
//!
//! The shell's working directory is [`ShellState::cwd`](crate::ShellState::cwd), the directory bash keeps as
//! `the_current_working_directory`; the process never changes its own (it may run other shells' work), and each
//! command is started there. `cd` checks the target through [`Fs`] as `chdir` would:
//!
//! - **Logical** (`-L`, the default): the target is made absolute from the working directory and `.`, `..` and
//!   repeated slashes are removed as text (bash's `sh_canonpath`: each `..` only after a directory, the result an
//!   existing directory), so `cd link/..` comes back where it started. If that fails, bash tries the operand as the
//!   kernel resolves it from the real directory, and the new directory is then the physical one.
//! - **Physical** (`-P`, or `set -o physical`): every symbolic link is resolved.
//!
//! On success `OLDPWD` gets the old `PWD`, `PWD` the new directory, and the host is told (OSC 7, `cwd.changed`). A
//! read-only `PWD` or `OLDPWD` makes the status 1 although the directory changed, as in bash. Searching a directory
//! needs an execute bit: the interpreter does not know the user it runs as, so it accepts a directory any execute
//! bit allows, as bash's `executable_file` reads modes.

use std::ffi::OsString;
use std::path::{Component, Path, PathBuf};

use knsh_bash::Span;
use knsh_platform::{FileKind, Fs};

use super::{Interpreter, Run};
use crate::status::Status;

/// `ENOENT`, `ENOTDIR` and `EACCES` on macOS: the reasons `chdir` gives that `cd` reports.
const ENOENT: i32 = 2;
const ENOTDIR: i32 = 20;
const EACCES: i32 = 13;

/// Bash's usage line for `cd`.
const CD_USAGE: &str = "[-L|[-P [-e]] [-@]] [dir]";

/// Whether `path` (absolute) names a directory, symbolic links followed.
pub(crate) fn is_directory(fs: &dyn Fs, path: &Path) -> bool {
    enterable(fs, path).is_ok() || matches!(enterable(fs, path), Err(EACCES))
}

/// Whether `chdir(path)` would succeed: `Ok` with the physical directory, or the `errno` it would fail with.
fn enterable(fs: &dyn Fs, path: &Path) -> Result<PathBuf, i32> {
    let canonical = fs.canonicalise(path).map_err(|error| error.errno().unwrap_or(ENOENT))?;
    let metadata = fs
        .metadata(canonical.as_path())
        .map_err(|error| error.errno().unwrap_or(ENOENT))?;
    match metadata.kind {
        FileKind::Directory if metadata.mode & 0o111 != 0 => Ok(canonical.as_path().to_path_buf()),
        FileKind::Directory => Err(EACCES),
        FileKind::File | FileKind::Symlink | FileKind::Other => Err(ENOTDIR),
    }
}

/// Bash's `sh_canonpath` with `PATH_CHECKDOTDOT | PATH_CHECKEXISTS`: `path` (absolute) without `.`, `..` or
/// repeated slashes, each `..` removing a component only after checking that what it leaves is a directory, and
/// the result an existing directory; `None` when a check fails.
fn canonical_text(fs: &dyn Fs, path: &Path) -> Option<PathBuf> {
    let text = path.as_os_str().as_encoded_bytes();
    // POSIX leaves a path starting with exactly two slashes to the system; bash keeps them.
    let double = text.starts_with(b"//") && !text.starts_with(b"///");
    let mut parts: Vec<&std::ffi::OsStr> = Vec::new();
    let joined = |parts: &[&std::ffi::OsStr]| {
        let mut out = OsString::from(if double { "//" } else { "/" });
        for (index, part) in parts.iter().enumerate() {
            if index > 0 {
                out.push("/");
            }
            out.push(part);
        }
        PathBuf::from(out)
    };
    for component in path.components() {
        match component {
            Component::RootDir | Component::CurDir | Component::Prefix(_) => {}
            Component::ParentDir => {
                if !parts.is_empty() && !is_directory(fs, &joined(&parts)) {
                    return None;
                }
                parts.pop();
            }
            Component::Normal(name) => parts.push(name),
        }
    }
    let result = joined(&parts);
    is_directory(fs, &result).then_some(result)
}

impl Interpreter {
    /// `cd [-L|-P [-e]] [dir]`.
    pub(super) fn cd_builtin(&mut self, args: &[String], span: Span, run: &Run<'_>) -> Status {
        let (options, operands) = match self.options("cd", CD_USAGE, "eLP", args, span, run) {
            Ok(parsed) => parsed,
            Err(status) => return status,
        };
        // The last of `-L` and `-P` wins, as bash's option loop sets one flag.
        let physical = options
            .chars()
            .rev()
            .find_map(|letter| match letter {
                'L' => Some(false),
                'P' => Some(true),
                _ => None,
            })
            .unwrap_or(self.state.options().physical);
        let (dirname, print) = match operands {
            [] => {
                if let Some(home) = self.variable_text("HOME") {
                    (home, false)
                } else {
                    self.report(span, run, format_args!("cd: HOME not set"));
                    return Status::FAILURE;
                }
            }
            [_, _, ..] => {
                self.report(span, run, format_args!("cd: too many arguments"));
                return Status::FAILURE;
            }
            [dash] if dash == "-" => {
                if let Some(old) = self.variable_text("OLDPWD") {
                    (old, true)
                } else {
                    self.report(span, run, format_args!("cd: OLDPWD not set"));
                    return Status::FAILURE;
                }
            }
            [dir] => (dir.clone(), false),
        };
        if !names_from_here(&dirname)
            && let Some(cdpath) = self.variable_text("CDPATH")
        {
            for entry in cdpath.split(':') {
                let candidate = if entry.is_empty() {
                    format!("./{dirname}")
                } else if entry.ends_with('/') {
                    format!("{entry}{dirname}")
                } else {
                    format!("{entry}/{dirname}")
                };
                if let Ok(new) = self.change_directory(&candidate, physical) {
                    // POSIX: a directory found through a non-empty `CDPATH` entry is printed.
                    let shown = if physical { candidate } else { new.display().to_string() };
                    return self.entered(&new, (!entry.is_empty()).then_some(shown), span, run);
                }
            }
        }
        match self.change_directory(&dirname, physical) {
            Ok(new) => self.entered(&new, print.then_some(dirname), span, run),
            Err(errno) => {
                let reason = super::redirect::strerror(errno);
                self.report(span, run, format_args!("cd: {dirname}: {reason}"));
                Status::FAILURE
            }
        }
    }

    /// The value of `name` as text, if it is set (a value that is not UTF-8 counts as unset here).
    fn variable_text(&self, name: &str) -> Option<String> {
        self.state
            .variable(name)
            .and_then(|value| value.to_str())
            .map(str::to_owned)
    }

    /// Bash's `change_to_directory`: the directory `newdir` changes to, as `PWD` will hold it, or the `errno`.
    fn change_directory(&self, newdir: &str, physical: bool) -> Result<PathBuf, i32> {
        let absolute = self.state.cwd().join(newdir);
        if physical {
            return enterable(&*self.fs, &absolute);
        }
        let canonical = canonical_text(&*self.fs, &absolute);
        let target = canonical.clone().unwrap_or_else(|| absolute.clone());
        match enterable(&*self.fs, &target) {
            // Canonicalisation failed but `chdir` worked: bash then takes the directory from `getcwd`.
            Ok(physical_dir) => Ok(canonical.unwrap_or(physical_dir)),
            Err(errno) => {
                // Bash then tries the operand as written, from the real directory.
                let real = self.fs.canonicalise(self.state.cwd()).map_err(|_| errno)?;
                enterable(&*self.fs, &real.as_path().join(newdir)).map_err(|_| errno)
            }
        }
    }

    /// After `cd` entered `new`: `OLDPWD` and `PWD` set, `shown` printed, the host told. 1 if `PWD` or `OLDPWD`
    /// could not be set.
    fn entered(&mut self, new: &Path, shown: Option<String>, span: Span, run: &Run<'_>) -> Status {
        let mut status = Status::SUCCESS;
        self.state.set_cwd(new.to_path_buf());
        let old = self.state.variable("PWD").map(ToOwned::to_owned);
        let oldpwd = match old {
            Some(old) => self.state.assign("OLDPWD", old, false),
            None if self.state.is_readonly("OLDPWD") => Err(crate::state::AssignError::Readonly),
            None => {
                self.state.change_attributes("OLDPWD", true, |_| {});
                self.state.clear_value("OLDPWD");
                Ok(())
            }
        };
        if oldpwd.is_err() {
            self.report(span, run, format_args!("OLDPWD: readonly variable"));
            status = Status::FAILURE;
        }
        if self.state.assign("PWD", new.as_os_str().to_owned(), false).is_err() {
            self.report(span, run, format_args!("PWD: readonly variable"));
            status = Status::FAILURE;
        }
        if let Some(shown) = shown {
            let line = format!("{shown}\n");
            if self.print("cd", line.as_bytes(), span, run) != Status::SUCCESS {
                status = Status::FAILURE;
            }
        }
        if !self.is_subshell
            && let Some(observer) = &self.observer
        {
            observer.changed(new);
        }
        status
    }

    /// `pwd [-LP]`: the working directory, with symbolic links resolved for `-P` (or `set -o physical`).
    pub(super) fn pwd_builtin(&mut self, args: &[String], span: Span, run: &Run<'_>) -> Status {
        let (options, _) = match self.options("pwd", "[-LP]", "LP", args, span, run) {
            Ok(parsed) => parsed,
            Err(status) => return status,
        };
        let physical = options
            .chars()
            .rev()
            .find_map(|letter| match letter {
                'L' => Some(false),
                'P' => Some(true),
                _ => None,
            })
            .unwrap_or(self.state.options().physical);
        let shown = if physical {
            match self.fs.canonicalise(self.state.cwd()) {
                Ok(canonical) => canonical.as_path().to_path_buf(),
                Err(error) => {
                    let reason = super::redirect::strerror(error.errno().unwrap_or(ENOENT));
                    self.report(
                        span,
                        run,
                        format_args!(
                            "pwd: error retrieving current directory: getcwd: cannot access parent directories: {reason}"
                        ),
                    );
                    return Status::FAILURE;
                }
            }
        } else {
            self.state.cwd().to_path_buf()
        };
        let line = format!("{}\n", shown.display());
        self.print("pwd", line.as_bytes(), span, run)
    }
}

/// Bash's `absolute_pathname` for `cd`: names `CDPATH` is not searched for (`/…`, `.`, `..`, `./…`, `../…`).
fn names_from_here(dirname: &str) -> bool {
    dirname.starts_with('/') || matches!(dirname, "." | "..") || dirname.starts_with("./") || dirname.starts_with("../")
}

#[cfg(test)]
mod tests {
    use knsh_platform::testing::MemFs;

    use super::*;

    fn fs() -> MemFs {
        let fs = MemFs::new();
        fs.add_dir_all(Path::new("/work/real/sub")).unwrap();
        fs.add_symlink(Path::new("/work/link"), Path::new("/work/real"))
            .unwrap();
        fs.write(Path::new("/work/file"), b"", 0o644).unwrap();
        fs
    }

    #[test]
    fn logical_canonicalisation_removes_dots_as_text() {
        let fs = fs();
        assert_eq!(
            canonical_text(&fs, Path::new("/work/link/../link/./sub/")),
            Some(PathBuf::from("/work/link/sub"))
        );
        assert_eq!(
            canonical_text(&fs, Path::new("/work//real")),
            Some(PathBuf::from("/work/real"))
        );
        // `..` after something that is not a directory fails, as bash's `PATH_CHECKDOTDOT` does.
        assert_eq!(canonical_text(&fs, Path::new("/work/file/..")), None);
        assert_eq!(canonical_text(&fs, Path::new("/work/missing")), None);
    }

    #[test]
    fn entering_reports_chdir_errors() {
        let fs = fs();
        assert_eq!(enterable(&fs, Path::new("/work/link")), Ok(PathBuf::from("/work/real")));
        assert_eq!(enterable(&fs, Path::new("/work/missing")), Err(ENOENT));
        assert_eq!(enterable(&fs, Path::new("/work/file")), Err(ENOTDIR));
    }

    #[test]
    fn cdpath_skips_names_relative_to_here() {
        for name in ["/x", ".", "..", "./x", "../x"] {
            assert!(names_from_here(name), "{name}");
        }
        for name in ["x", ".x", "..x", "x/y"] {
            assert!(!names_from_here(name), "{name}");
        }
    }
}
