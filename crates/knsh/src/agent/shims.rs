//! The `sh`, `bash` and `zsh` shims (KNSH-049, FR-AGT-10, FR-LC-14, FR-AGT-31).
//!
//! An agent CLI that runs `bash -c '…'` by name, instead of `$SHELL -c`, must be supervised too. The shim directory
//! ([`knsh_platform::EnginePaths::shim_dir`]) holds three symbolic links, `sh`, `bash` and `zsh`, each to the `knsh`
//! binary, and only the envelope's `PATH` names it, first (KNSH-057). A shim is `knsh` started under another name, so
//! [`interpreter`] reads the name back from `argv[0]` and `knsh` forwards the line with that interpreter recorded: `sh`
//! later runs `/bin/sh`, `zsh` runs zsh and `bash` the profile's bash, while policy is the same for all three
//! (FR-LC-14).
//!
//! Shims are found only through `PATH` lookup. `/bin/bash` by absolute path is the system's bash and is not
//! intercepted: it runs inside the envelope, confined by it, without per-command decisions (FR-AGT-31). Supervised
//! lines run without the shim directory in `PATH` (FR-LC-16, stripped by `knshd`), so a shell a line starts is a real
//! shell under the line's own profile.
//!
//! The links are not a security boundary (the envelope is): they only route. [`install`] (re)creates them, each
//! replaced atomically, so a concurrent `bash` lookup sees the old link or the new one, never none.

use std::ffi::OsStr;
use std::fs;
use std::io;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::Path;

use knsh_proto::Interpreter;

/// The shims, by the program name each stands in for.
pub const SHIMS: [Interpreter; 3] = [Interpreter::Sh, Interpreter::Bash, Interpreter::Zsh];

/// Mode of the shim directory: owner-only, like every directory the engine creates (it holds nothing secret, but no
/// other user has any business there).
const DIR_MODE: u32 = 0o700;

/// The interpreter `knsh` stands in for when started as `argv0`: `sh`, `bash` or `zsh` by its last path component
/// (a login shell's leading `-` ignored), [`Interpreter::Knsh`] for anything else.
#[must_use]
pub fn interpreter(argv0: Option<&OsStr>) -> Interpreter {
    let Some(argv0) = argv0 else {
        return Interpreter::Knsh;
    };
    let name = Path::new(argv0).file_name().and_then(OsStr::to_str).unwrap_or_default();
    let name = name.strip_prefix('-').unwrap_or(name);
    SHIMS
        .into_iter()
        .find(|shim| shim.as_str() == name)
        .unwrap_or(Interpreter::Knsh)
}

/// Creates `dir` (owner-only) if missing and makes `sh`, `bash` and `zsh` in it symbolic links to `knsh`, an
/// absolute path to the `knsh` binary. A link that already points there is left alone; anything else under one of
/// those names (a link elsewhere, a file) is replaced atomically.
///
/// # Errors
///
/// [`io::ErrorKind::InvalidInput`] if `knsh` is not absolute; [`io::ErrorKind::InvalidData`] if `dir` exists but is
/// not a directory, or a shim name is taken by a directory; otherwise the filesystem error. A failure leaves each
/// shim as it was or as it should be, never missing.
pub fn install(dir: &Path, knsh: &Path) -> io::Result<()> {
    if !knsh.is_absolute() {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    ensure_dir(dir)?;
    for shim in SHIMS {
        let path = dir.join(shim.as_str());
        match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_symlink() && fs::read_link(&path)? == knsh => continue,
            Ok(metadata) if metadata.is_dir() => return Err(io::ErrorKind::InvalidData.into()),
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        // Made beside the shim and renamed over it: `rename` replaces the old entry atomically.
        let temporary = dir.join(format!(".{}.{}.tmp", shim.as_str(), std::process::id()));
        let _ = fs::remove_file(&temporary);
        std::os::unix::fs::symlink(knsh, &temporary)?;
        if let Err(error) = fs::rename(&temporary, &path) {
            let _ = fs::remove_file(&temporary);
            return Err(error);
        }
    }
    Ok(())
}

/// Creates `dir` (and missing parents) if needed; an existing `dir` must be a real directory, and is made
/// owner-only.
fn ensure_dir(dir: &Path) -> io::Result<()> {
    if let Some(parent) = dir.parent() {
        fs::create_dir_all(parent)?;
    }
    match fs::DirBuilder::new().mode(DIR_MODE).create(dir) {
        Ok(()) => return Ok(()),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error),
    }
    // Not followed: a link where the directory belongs is refused, not adopted.
    let metadata = fs::symlink_metadata(dir)?;
    if !metadata.is_dir() {
        return Err(io::ErrorKind::InvalidData.into());
    }
    if metadata.permissions().mode() & 0o777 != DIR_MODE {
        fs::set_permissions(dir, fs::Permissions::from_mode(DIR_MODE))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    /// A temporary directory, removed on drop.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new(tag: &str) -> Self {
            let path = std::env::temp_dir().join(format!("knsh-shims-{tag}-{}", std::process::id()));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    // FR-LC-14: a shim keeps the name it was called by; anything else is `knsh -c` itself.
    #[test]
    fn shim_preserves_requested_interpreter() {
        for (argv0, expected) in [
            ("sh", Interpreter::Sh),
            ("bash", Interpreter::Bash),
            ("zsh", Interpreter::Zsh),
            ("/Users/u/Library/shims/bash", Interpreter::Bash),
            ("-zsh", Interpreter::Zsh),
            ("knsh", Interpreter::Knsh),
            ("/usr/local/bin/knsh", Interpreter::Knsh),
            ("-knsh", Interpreter::Knsh),
            ("bash5", Interpreter::Knsh),
            ("dash", Interpreter::Knsh),
            ("", Interpreter::Knsh),
        ] {
            assert_eq!(interpreter(Some(OsStr::new(argv0))), expected, "{argv0}");
        }
        assert_eq!(interpreter(None), Interpreter::Knsh);
    }

    // The three links point at knsh, the directory is owner-only, and installing again repairs a wrong link.
    #[test]
    fn install_links_each_shim_to_knsh() {
        let temp = TempDir::new("install");
        let dir = temp.0.join("parent").join("shims");
        let knsh = Path::new("/opt/knsh/bin/knsh");
        install(&dir, knsh).unwrap();
        for shim in SHIMS {
            assert_eq!(fs::read_link(dir.join(shim.as_str())).unwrap(), knsh);
        }
        assert_eq!(fs::metadata(&dir).unwrap().permissions().mode() & 0o777, DIR_MODE);
        // A stale link and a stray file are replaced; nothing else in the directory changes.
        fs::remove_file(dir.join("sh")).unwrap();
        std::os::unix::fs::symlink("/bin/sh", dir.join("sh")).unwrap();
        fs::remove_file(dir.join("zsh")).unwrap();
        fs::write(dir.join("zsh"), b"#!/bin/sh\n").unwrap();
        fs::write(dir.join("other"), b"x").unwrap();
        install(&dir, knsh).unwrap();
        for shim in SHIMS {
            assert_eq!(fs::read_link(dir.join(shim.as_str())).unwrap(), knsh);
        }
        assert!(dir.join("other").exists());
        let leftovers = fs::read_dir(&dir)
            .unwrap()
            .filter(|entry| entry.as_ref().unwrap().file_name().to_string_lossy().ends_with(".tmp"))
            .count();
        assert_eq!(leftovers, 0);
    }

    // Refused: a relative knsh, a file where the directory belongs, a directory where a shim belongs.
    #[test]
    fn install_refuses_what_it_cannot_own() {
        let temp = TempDir::new("refuse");
        assert_eq!(
            install(&temp.0.join("a"), Path::new("knsh")).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        let file = temp.0.join("file");
        fs::write(&file, b"").unwrap();
        assert_eq!(
            install(&file, Path::new("/bin/knsh")).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        let dir = temp.0.join("shims");
        fs::create_dir_all(dir.join("bash")).unwrap();
        assert_eq!(
            install(&dir, Path::new("/bin/knsh")).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }
}
