//! `knsh daemon install` and `knsh daemon uninstall`: the `knshd` launch agent (KNSH-012,
//! `specs/06-api/cli.md` "Daemon installation").
//!
//! The steps themselves live in `knsh-platform` ([`install_agent`], [`uninstall_agent`]); this module resolves what
//! they need from the running `knsh` (where `knshd` is, which home) and reports the outcome. Every effect is
//! injected, so both commands are tested against fakes, never the user's real launchd.

use std::ffi::OsStr;
use std::fmt;
use std::path::{Path, PathBuf};

use knsh_json::{Object, Value};
use knsh_platform::launchd::AGENT_LABEL;
use knsh_platform::{
    EnginePaths, FileKind, Fs, LaunchAgent, PlatformError, ServiceManager, install_agent, uninstall_agent,
};

/// File name of the daemon binary, expected next to `knsh`.
pub const KNSHD: &str = "knshd";

/// The superuser's uid.
const ROOT_UID: u32 = 0;

/// Why a `knsh daemon` command failed. Messages name no path, so they are safe to print anywhere.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DaemonError {
    /// `HOME` is not set.
    NoHome,
    /// `HOME` is not usable as a home directory.
    BadHome(PlatformError),
    /// There is no `knshd` regular file next to the running `knsh`.
    MissingKnshd,
    /// Run as root (for example under `sudo`, which keeps `HOME`): `knshd` runs as the logged-in user, never root,
    /// and root-owned engine directories in the user's home would lock that user out of them.
    Root,
    /// A platform step failed (engine directories, the property list or `launchctl`).
    Platform(PlatformError),
}

impl fmt::Display for DaemonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoHome => f.write_str("HOME is not set"),
            Self::BadHome(error) => write!(f, "unusable HOME: {error}"),
            Self::MissingKnshd => write!(f, "no '{KNSHD}' binary next to knsh"),
            Self::Root => f.write_str("run as the logged-in user, not as root"),
            Self::Platform(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for DaemonError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::BadHome(error) | Self::Platform(error) => Some(error),
            Self::NoHome | Self::MissingKnshd | Self::Root => None,
        }
    }
}

impl From<PlatformError> for DaemonError {
    fn from(error: PlatformError) -> Self {
        Self::Platform(error)
    }
}

/// What the running `knsh` provides to the daemon commands.
#[derive(Debug, Clone, Copy)]
pub struct Environment<'a> {
    /// The value of `HOME`, if set.
    pub home: Option<&'a OsStr>,
    /// The path of the running `knsh` executable.
    pub knsh_exe: &'a Path,
    /// The effective uid: whose GUI domain the job is loaded into.
    pub uid: u32,
}

/// Installs the `knshd` launch agent for the current user, using the `knshd` next to `knsh`. Returns the installed
/// job.
///
/// # Errors
///
/// [`DaemonError::Root`] when run as root; [`DaemonError::NoHome`] or [`DaemonError::BadHome`] without a usable home;
/// [`DaemonError::MissingKnshd`] if no `knshd` regular file sits next to the resolved `knsh`; [`DaemonError::Platform`] if
/// [`install_agent`] fails (for example a socket path too long, or launchd refusing the job).
pub fn install(fs: &dyn Fs, manager: &dyn ServiceManager, env: Environment<'_>) -> Result<LaunchAgent, DaemonError> {
    // KNSH-012: `knshd` runs as the logged-in user, never root. Checked before anything is created.
    if env.uid == ROOT_UID {
        return Err(DaemonError::Root);
    }
    let paths = engine_paths(env.home)?;
    let program = knshd_beside(fs, env.knsh_exe)?;
    let agent = LaunchAgent::new(AGENT_LABEL, &program, &paths)?;
    install_agent(fs, manager, &agent, env.uid)?;
    Ok(agent)
}

/// Uninstalls the `knshd` launch agent of the current user. Returns whether anything was installed.
///
/// # Errors
///
/// [`DaemonError::NoHome`] or [`DaemonError::BadHome`] without a usable home; [`DaemonError::Platform`] if
/// [`uninstall_agent`] fails.
pub fn uninstall(fs: &dyn Fs, manager: &dyn ServiceManager, env: Environment<'_>) -> Result<bool, DaemonError> {
    let paths = engine_paths(env.home)?;
    Ok(uninstall_agent(fs, manager, paths.home(), AGENT_LABEL, env.uid)?)
}

/// The text `knsh daemon install` prints: one line, or a JSON object with `--json`.
#[must_use]
pub fn installed_report(agent: &LaunchAgent, json: bool) -> String {
    if json {
        report_json(&[("label", Value::from(agent.label())), ("installed", Value::from(true))])
    } else {
        format!("knsh: installed launch agent {}\n", agent.label())
    }
}

/// The text `knsh daemon uninstall` prints, given whether anything was installed.
#[must_use]
pub fn uninstalled_report(removed: bool, json: bool) -> String {
    if json {
        report_json(&[("label", Value::from(AGENT_LABEL)), ("removed", Value::from(removed))])
    } else if removed {
        format!("knsh: uninstalled launch agent {AGENT_LABEL}\n")
    } else {
        format!("knsh: launch agent {AGENT_LABEL} was not installed\n")
    }
}

/// One JSON object per line. The keys are distinct literals, so building it cannot fail; if it ever did, an empty
/// object is printed rather than a panic.
fn report_json(fields: &[(&'static str, Value)]) -> String {
    let mut object = Object::new();
    for (key, value) in fields {
        if object.insert(*key, value.clone()).is_err() {
            object = Object::new();
            break;
        }
    }
    let mut text = knsh_json::write(&Value::from(object)).unwrap_or_else(|_| "{}".to_owned());
    text.push('\n');
    text
}

/// The engine paths for `home`.
fn engine_paths(home: Option<&OsStr>) -> Result<EnginePaths, DaemonError> {
    let home = home.ok_or(DaemonError::NoHome)?;
    EnginePaths::for_home(Path::new(home)).map_err(DaemonError::BadHome)
}

/// `knshd` in the directory of `knsh_exe` after resolving symlinks, so a `knsh` linked into `/usr/local/bin` finds
/// the `knshd` installed beside the real binary. It must be a regular file.
fn knshd_beside(fs: &dyn Fs, knsh_exe: &Path) -> Result<PathBuf, DaemonError> {
    let knsh = fs.canonicalise(knsh_exe).map_err(|_| DaemonError::MissingKnshd)?;
    let dir = knsh.as_path().parent().ok_or(DaemonError::MissingKnshd)?;
    let knshd = dir.join(KNSHD);
    match fs.metadata(&knshd) {
        Ok(meta) if meta.kind == FileKind::File => Ok(knshd),
        Ok(_) | Err(_) => Err(DaemonError::MissingKnshd),
    }
}

#[cfg(test)]
mod tests {
    use knsh_platform::testing::{MemFs, RecordingServiceManager, ServiceCall};

    use super::*;

    const UID: u32 = knsh_platform::testing::DEFAULT_UID;

    /// A filesystem with a home and `knsh` and `knshd` installed in `/opt/knsh/bin`, linked from `/usr/local/bin`.
    fn installed_fs() -> MemFs {
        let fs = MemFs::new();
        fs.add_dir_all(Path::new("/Users/alice")).unwrap();
        fs.add_dir_all(Path::new("/opt/knsh/bin")).unwrap();
        fs.add_dir_all(Path::new("/usr/local/bin")).unwrap();
        fs.write(Path::new("/opt/knsh/bin/knsh"), b"", 0o755).unwrap();
        fs.write(Path::new("/opt/knsh/bin/knshd"), b"", 0o755).unwrap();
        fs.add_symlink(Path::new("/usr/local/bin/knsh"), Path::new("/opt/knsh/bin/knsh"))
            .unwrap();
        fs
    }

    fn env(knsh_exe: &Path) -> Environment<'_> {
        Environment {
            home: Some(OsStr::new("/Users/alice")),
            knsh_exe,
            uid: UID,
        }
    }

    // KNSH-012: install writes the property list for the knshd beside knsh, then loads it.
    #[test]
    fn install_uses_knshd_beside_the_resolved_knsh() {
        let fs = installed_fs();
        let manager = RecordingServiceManager::new();
        let agent = install(&fs, &manager, env(Path::new("/usr/local/bin/knsh"))).unwrap();

        let plist = String::from_utf8(fs.contents(agent.plist_path()).unwrap()).unwrap();
        assert!(plist.contains("<string>/opt/knsh/bin/knshd</string>"), "{plist}");
        assert_eq!(
            manager.calls().last(),
            Some(&ServiceCall::Bootstrap {
                uid: UID,
                plist: agent.plist_path().to_path_buf()
            })
        );
        assert_eq!(
            installed_report(&agent, false),
            "knsh: installed launch agent knsh.knshd\n"
        );
        assert_eq!(
            installed_report(&agent, true),
            "{\"label\":\"knsh.knshd\",\"installed\":true}\n"
        );
    }

    // Failure safety: nothing is written or loaded when knshd is missing or HOME is unusable.
    #[test]
    fn install_refuses_without_knshd_or_home() {
        let fs = installed_fs();
        fs.remove_file(Path::new("/opt/knsh/bin/knshd")).unwrap();
        let manager = RecordingServiceManager::new();
        let exe = Path::new("/opt/knsh/bin/knsh");
        assert_eq!(install(&fs, &manager, env(exe)).unwrap_err(), DaemonError::MissingKnshd);

        // A directory named knshd is not the daemon.
        fs.create_dir(Path::new("/opt/knsh/bin/knshd"), 0o755).unwrap();
        assert_eq!(install(&fs, &manager, env(exe)).unwrap_err(), DaemonError::MissingKnshd);

        let no_home = Environment { home: None, ..env(exe) };
        assert_eq!(install(&fs, &manager, no_home).unwrap_err(), DaemonError::NoHome);
        let relative = Environment {
            home: Some(OsStr::new("relative")),
            ..env(exe)
        };
        assert!(matches!(install(&fs, &manager, relative), Err(DaemonError::BadHome(_))));
        // KNSH-012: never as root (`sudo` keeps HOME, so root would own the user's engine directories).
        let root = Environment { uid: 0, ..env(exe) };
        assert_eq!(install(&fs, &manager, root).unwrap_err(), DaemonError::Root);
        assert_eq!(manager.calls(), Vec::new());
        assert!(fs.metadata(Path::new("/Users/alice/Library")).is_err());
    }

    #[test]
    fn uninstall_reports_whether_anything_was_installed() {
        let fs = installed_fs();
        let manager = RecordingServiceManager::new();
        let exe = Path::new("/opt/knsh/bin/knsh");
        let agent = install(&fs, &manager, env(exe)).unwrap();

        assert_eq!(uninstall(&fs, &manager, env(exe)), Ok(true));
        assert!(fs.contents(agent.plist_path()).is_none());
        assert_eq!(uninstall(&fs, &manager, env(exe)), Ok(false));

        assert_eq!(
            uninstalled_report(true, false),
            "knsh: uninstalled launch agent knsh.knshd\n"
        );
        assert_eq!(
            uninstalled_report(false, false),
            "knsh: launch agent knsh.knshd was not installed\n"
        );
        assert_eq!(
            uninstalled_report(false, true),
            "{\"label\":\"knsh.knshd\",\"removed\":false}\n"
        );
    }
}
