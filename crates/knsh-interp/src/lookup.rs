//! Finding the program a command name runs, as bash's `search_for_command` does, through the [`Fs`] trait
//! (KNSH-096; NFR-COMPAT-09).
//!
//! - A name holding `/` names a file, relative to the working directory: missing is 127, a directory or a file that
//!   is not executable is 126.
//! - Any other name is searched in each `PATH` entry in turn (an empty entry is the working directory). The first
//!   executable regular file wins. Bash remembers the first match that exists but is not executable and runs it when
//!   nothing better is found, which fails with 126; directories are skipped. Nothing found is 127.
//! - With `PATH` unset, bash looks for the name in the working directory only.
//!
//! "Executable" means any execute bit, as [`knsh_platform`]'s binary lookup reads it. Bash asks the kernel for the
//! current user; for a file executable only by others the two differ, and `exec` then fails, which still gives 126.
//! Bash's command hash table is kept by the interpreter (KNSH-101): a name found here is remembered and run from
//! the table afterwards, until `PATH` changes or `hash -r`.

use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use knsh_platform::{FileKind, Fs};

/// Any execute bit (owner, group or other).
const ANY_EXECUTE: u32 = 0o111;

/// What a command name resolves to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Resolved {
    /// The program to run, as an absolute path.
    Program(PathBuf),
    /// Nothing to run: status 127.
    NotFound(Missing),
    /// Something that cannot run: status 126.
    NotExecutable(Refusal),
}

/// Why a name was not found, which decides bash's message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Missing {
    /// A name searched on `PATH`: "command not found".
    NotOnPath,
    /// A path, or a name with `PATH` unset: "No such file or directory".
    NoSuchFile,
}

/// Why a match cannot run, which decides bash's message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Refusal {
    /// "Is a directory".
    Directory,
    /// "Permission denied".
    PermissionDenied,
}

/// What one candidate path holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Probe {
    Missing,
    Directory,
    NotExecutable,
    Executable,
}

/// Resolves `name` with `path` (the value of `PATH`, `None` if unset) from the working directory `cwd`.
pub(crate) fn find(fs: &dyn Fs, name: &str, path: Option<&OsStr>, cwd: &Path) -> Resolved {
    // Bash reports an empty name as not found rather than searching for it.
    if name.is_empty() {
        return Resolved::NotFound(Missing::NotOnPath);
    }
    if name.contains('/') {
        return direct(fs, cwd.join(name));
    }
    let Some(path) = path else {
        return direct(fs, cwd.join(name));
    };
    let mut fallback = None;
    for entry in path.as_bytes().split(|&byte| byte == b':') {
        let dir = if entry.is_empty() {
            cwd.to_path_buf()
        } else {
            cwd.join(OsStr::from_bytes(entry))
        };
        let candidate = dir.join(name);
        match probe(fs, &candidate) {
            Probe::Executable => return Resolved::Program(candidate),
            Probe::NotExecutable if fallback.is_none() => fallback = Some(candidate),
            Probe::NotExecutable | Probe::Missing | Probe::Directory => {}
        }
    }
    match fallback {
        Some(_) => Resolved::NotExecutable(Refusal::PermissionDenied),
        None => Resolved::NotFound(Missing::NotOnPath),
    }
}

/// Every executable regular file `name` names in the entries of `path` (the value of `PATH`), in order: what
/// `type -a` lists (bash's `user_command_matches`). Empty when `name` holds a `/` or `PATH` is unset.
pub(crate) fn all_on_path(fs: &dyn Fs, name: &str, path: Option<&OsStr>, cwd: &Path) -> Vec<PathBuf> {
    let Some(path) = path.filter(|_| !name.is_empty() && !name.contains('/')) else {
        return Vec::new();
    };
    path.as_bytes()
        .split(|&byte| byte == b':')
        .map(|entry| {
            let dir = if entry.is_empty() {
                cwd.to_path_buf()
            } else {
                cwd.join(OsStr::from_bytes(entry))
            };
            dir.join(name)
        })
        .filter(|candidate| probe(fs, candidate) == Probe::Executable)
        .collect()
}

/// Whether `path` is an executable regular file, symlinks followed (bash's `executable_file`).
pub(crate) fn is_executable(fs: &dyn Fs, path: &Path) -> bool {
    probe(fs, path) == Probe::Executable
}

/// Resolves a path named directly.
fn direct(fs: &dyn Fs, path: PathBuf) -> Resolved {
    match probe(fs, &path) {
        Probe::Executable => Resolved::Program(path),
        Probe::Missing => Resolved::NotFound(Missing::NoSuchFile),
        Probe::Directory => Resolved::NotExecutable(Refusal::Directory),
        Probe::NotExecutable => Resolved::NotExecutable(Refusal::PermissionDenied),
    }
}

/// What `path` holds, symlinks followed. Every error counts as missing: bash skips what it cannot read.
fn probe(fs: &dyn Fs, path: &Path) -> Probe {
    // `metadata` does not follow a final symlink; the canonical path has none.
    let Ok(canonical) = fs.canonicalise(path) else {
        return Probe::Missing;
    };
    match fs.metadata(canonical.as_path()) {
        Ok(metadata) => match metadata.kind {
            FileKind::Directory => Probe::Directory,
            FileKind::File if metadata.mode & ANY_EXECUTE != 0 => Probe::Executable,
            FileKind::File | FileKind::Other => Probe::NotExecutable,
            // A canonical path has no symlink left; seeing one means it changed under us.
            FileKind::Symlink => Probe::Missing,
        },
        Err(_) => Probe::Missing,
    }
}

#[cfg(test)]
mod tests {
    use knsh_platform::testing::MemFs;

    use super::*;

    fn fs() -> MemFs {
        let fs = MemFs::new();
        for dir in ["/bin", "/usr/bin", "/work/sub", "/opt/tool"] {
            fs.add_dir_all(Path::new(dir)).unwrap();
        }
        fs.write(Path::new("/bin/ls"), b"", 0o755).unwrap();
        fs.write(Path::new("/usr/bin/ls"), b"", 0o755).unwrap();
        fs.write(Path::new("/bin/data"), b"", 0o644).unwrap();
        fs.write(Path::new("/usr/bin/data"), b"", 0o755).unwrap();
        fs.write(Path::new("/bin/plain"), b"", 0o644).unwrap();
        fs.write(Path::new("/work/run.sh"), b"", 0o755).unwrap();
        fs.write(Path::new("/work/notes"), b"", 0o644).unwrap();
        fs
    }

    fn find_in(name: &str, path: Option<&str>) -> Resolved {
        let fs = fs();
        let fs: &dyn Fs = &fs;
        find(fs, name, path.map(OsStr::new), Path::new("/work"))
    }

    #[test]
    fn first_executable_on_path_wins() {
        assert_eq!(
            find_in("ls", Some("/bin:/usr/bin")),
            Resolved::Program("/bin/ls".into())
        );
        assert_eq!(
            find_in("ls", Some("/usr/bin:/bin")),
            Resolved::Program("/usr/bin/ls".into())
        );
    }

    // NFR-COMPAT-09: a non-executable match is skipped for a later executable one, and is 126 when it is the only one.
    #[test]
    fn non_executable_match_is_skipped_then_refused() {
        assert_eq!(
            find_in("data", Some("/bin:/usr/bin")),
            Resolved::Program("/usr/bin/data".into())
        );
        assert_eq!(
            find_in("plain", Some("/bin:/usr/bin")),
            Resolved::NotExecutable(Refusal::PermissionDenied)
        );
    }

    // NFR-COMPAT-09: nothing on PATH is 127; directories on PATH are skipped.
    #[test]
    fn missing_names_and_directories_are_not_found() {
        assert_eq!(find_in("nope", Some("/bin")), Resolved::NotFound(Missing::NotOnPath));
        assert_eq!(find_in("tool", Some("/opt")), Resolved::NotFound(Missing::NotOnPath));
        assert_eq!(find_in("", Some("/bin")), Resolved::NotFound(Missing::NotOnPath));
    }

    #[test]
    fn names_with_a_slash_are_paths_from_the_working_directory() {
        assert_eq!(
            find_in("./run.sh", Some("/bin")),
            Resolved::Program("/work/./run.sh".into())
        );
        assert_eq!(find_in("/bin/ls", Some("")), Resolved::Program("/bin/ls".into()));
        assert_eq!(
            find_in("./missing", Some("/bin")),
            Resolved::NotFound(Missing::NoSuchFile)
        );
        assert_eq!(
            find_in("sub/", Some("/bin")),
            Resolved::NotExecutable(Refusal::Directory)
        );
        assert_eq!(
            find_in("./notes", Some("/bin")),
            Resolved::NotExecutable(Refusal::PermissionDenied)
        );
    }

    #[test]
    fn empty_path_entries_and_unset_path_mean_the_working_directory() {
        assert_eq!(
            find_in("run.sh", Some("/bin:")),
            Resolved::Program("/work/run.sh".into())
        );
        assert_eq!(find_in("run.sh", None), Resolved::Program("/work/run.sh".into()));
        assert_eq!(find_in("ls", None), Resolved::NotFound(Missing::NoSuchFile));
    }
}
