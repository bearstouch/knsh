//! Which start-up files an interactive shell reads, as bash's `run_startup_files` (KNSH-107).
//!
//! - A login shell reads `/etc/profile`, then the first of `~/.bash_profile`, `~/.bash_login` and `~/.profile`
//!   that exists and is readable (none with `--noprofile`), and `~/.bash_logout` when it exits.
//! - An interactive shell that is not a login shell reads `~/.bashrc` (the `--rcfile` file instead; none with
//!   `--norc`).
//! - In POSIX mode an interactive shell reads the file `$ENV` names instead, and a login shell `/etc/profile` and
//!   `~/.profile` only.
//!
//! macOS's `/etc/profile` itself sources `/etc/bashrc` for bash; the files run unchanged.

use std::path::{Path, PathBuf};

/// The system-wide profile of login shells.
pub const SYSTEM_PROFILE: &str = "/etc/profile";

/// How the shell was started.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)] // Bash's start-up flags.
pub struct Startup {
    /// A login shell (`-l`, `--login`, `argv[0]` starting with `-`).
    pub login: bool,
    /// An interactive shell.
    pub interactive: bool,
    /// `--noprofile`.
    pub no_profile: bool,
    /// `--norc`.
    pub no_rc: bool,
    /// `--rcfile file`.
    pub rc_file: Option<PathBuf>,
    /// POSIX mode.
    pub posix: bool,
}

/// The files to source, in order, with `home` (`$HOME`), `env` (`$ENV`, already expanded) and `readable` telling
/// whether a file exists and can be read.
#[must_use]
pub fn startup_files(
    startup: &Startup,
    home: Option<&Path>,
    env: Option<&Path>,
    readable: &dyn Fn(&Path) -> bool,
) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let in_home = |name: &str| home.map(|home| home.join(name));
    if startup.login && !startup.no_profile {
        files.push(PathBuf::from(SYSTEM_PROFILE));
        let personal: &[&str] = if startup.posix {
            &[".profile"]
        } else {
            &[".bash_profile", ".bash_login", ".profile"]
        };
        if let Some(found) = personal
            .iter()
            .filter_map(|name| in_home(name))
            .find(|path| readable(path))
        {
            files.push(found);
        }
    } else if startup.interactive && startup.posix {
        files.extend(env.map(Path::to_path_buf));
    } else if startup.interactive && !startup.no_rc {
        files.extend(startup.rc_file.clone().or_else(|| in_home(".bashrc")));
    }
    files.retain(|path| readable(path));
    files
}

/// The file a login shell sources as it exits (`~/.bash_logout`), if it is readable.
#[must_use]
pub fn logout_file(startup: &Startup, home: Option<&Path>, readable: &dyn Fn(&Path) -> bool) -> Option<PathBuf> {
    if !startup.login || startup.posix {
        return None;
    }
    home.map(|home| home.join(".bash_logout")).filter(|path| readable(path))
}

#[cfg(test)]
mod tests {
    use super::*;

    // KNSH-107: `.bashrc` for an interactive shell, the profiles for a login shell, as bash.
    #[test]
    fn startup_files_follow_bash() {
        let home = Path::new("/Users/ana");
        let present = |names: &'static [&'static str]| {
            move |path: &Path| path == Path::new(SYSTEM_PROFILE) || names.iter().any(|name| path == home.join(name))
        };
        let interactive = Startup {
            interactive: true,
            ..Startup::default()
        };
        let readable = present(&[".bashrc", ".profile"]);
        assert_eq!(
            startup_files(&interactive, Some(home), None, &readable),
            [home.join(".bashrc")]
        );
        let login = Startup {
            login: true,
            ..interactive.clone()
        };
        assert_eq!(
            startup_files(&login, Some(home), None, &readable),
            [PathBuf::from(SYSTEM_PROFILE), home.join(".profile")]
        );
        let both = present(&[".bash_profile", ".profile"]);
        assert_eq!(
            startup_files(&login, Some(home), None, &both),
            [PathBuf::from(SYSTEM_PROFILE), home.join(".bash_profile")]
        );
        let none = Startup {
            no_rc: true,
            ..interactive.clone()
        };
        assert_eq!(startup_files(&none, Some(home), None, &readable), Vec::<PathBuf>::new());
        let rc = Startup {
            rc_file: Some(PathBuf::from("/Users/ana/.bashrc")),
            ..interactive.clone()
        };
        assert_eq!(startup_files(&rc, Some(home), None, &readable), [home.join(".bashrc")]);
        let posix = Startup {
            posix: true,
            ..interactive
        };
        assert_eq!(
            startup_files(&posix, Some(home), Some(&home.join(".profile")), &readable),
            [home.join(".profile")]
        );
        assert_eq!(
            logout_file(&login, Some(home), &present(&[".bash_logout"])),
            Some(home.join(".bash_logout"))
        );
        assert_eq!(logout_file(&posix, Some(home), &present(&[".bash_logout"])), None);
    }
}
