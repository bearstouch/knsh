//! The launchd user agent that runs `knshd`: its property list, socket activation, peer credentials, and install and
//! uninstall (KNSH-012).
//!
//! launchd, not `knshd`, owns the endpoints (`specs/02-architecture/process-model.md`). The agent's property list
//! declares `user.sock` and `agent.sock` in the run directory, owner-only (`0600`), and launchd creates and listens
//! on them before `knshd` exists, then starts `knshd` on the first connection. Because launchd holds the names, no
//! other process can squat them (`specs/04-non-functional-requirements/security.md`, "squats its endpoints"), and a
//! client that connects while `knshd` is restarting waits in the listen backlog instead of failing.
//!
//! - [`LaunchAgent`] is the job definition; [`LaunchAgent::render`] writes it as an XML property list. Rendering is
//!   pure, so the generated text is unit tested.
//! - [`SocketActivation`] hands `knshd` the sockets launchd created. There is deliberately no way to bind one
//!   instead: without launchd's sockets `knshd` refuses to start.
//! - [`PeerCredentials`] reports who is at the other end of a connection, so `knshd` serves only its own user
//!   (`specs/02-architecture/process-model.md`, "One process per user").
//! - [`ServiceManager`] loads and unloads the job (`launchctl bootstrap` and `bootout` in the user's GUI domain);
//!   [`install_agent`] and [`uninstall_agent`] are the steps `knsh daemon install` and `uninstall` run.
//!
//! The `knshd` binary must not sit under `~/Desktop`, `~/Documents` or `~/Downloads`: a process launchd starts needs
//! the user's consent (TCC) to open files there, and blocks in the dynamic loader waiting for it (observed on macOS
//! 26.6 with a build in `~/Desktop`).
//!
//! The XPC control service is declared too (`MachServices`), so launchd reserves its name from the start, but it is
//! served only from phase 2 (KNSH-067). `agent.sock` is likewise declared now and served in phase 2 (KNSH-048).

use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};

use crate::engine_dirs::{EnginePaths, ensure_engine_dirs};
use crate::error::PlatformError;
use crate::fs::{FileKind, Fs};

/// The launchd label of the `knshd` job, and the name of its property list in `~/Library/LaunchAgents/`.
pub const AGENT_LABEL: &str = "knsh.knshd";

/// The `Sockets` entry for `user.sock`: the name `knshd` passes to [`SocketActivation::listeners`].
pub const USER_SOCKET_NAME: &str = "user";

/// The `Sockets` entry for `agent.sock`.
pub const AGENT_SOCKET_NAME: &str = "agent";

/// The XPC Mach service of the control endpoint (`specs/09-reference/file-locations.md`; the final name is tied to
/// the signing identity). Defined in `knsh-core`, which lists it among the fixed denies (FR-POL-30).
pub const CONTROL_SERVICE: &str = knsh_core::CONTROL_SERVICE;

/// Mode launchd gives each socket file: owner read and write only, so no other user can connect (NFR-SEC-08).
pub const SOCKET_MODE: u32 = 0o600;

/// Mode of the property list file. launchd refuses a property list that others can write; owner-only also keeps the
/// home path in it private, like every other engine file.
pub const PLIST_MODE: u32 = 0o600;

/// Mode for `~/Library/LaunchAgents/` when install has to create it, matching what macOS creates. The directory
/// belongs to the user, not the engine, so an existing one is left as it is.
const LAUNCH_AGENTS_MODE: u32 = 0o755;

/// Longest socket path, in bytes, that fits a Unix socket address (`sun_path` holds 104 bytes with the NUL).
/// launchd would accept a longer path in the property list and then fail to create the socket, out of sight.
pub const MAX_SOCKET_PATH: usize = 103;

/// Longest label accepted. launchd has no documented limit; this keeps the property list file name well under
/// `NAME_MAX`.
const MAX_LABEL: usize = 128;

/// The launchd job that runs `knshd` for one user.
///
/// Invariant: every string it renders is valid UTF-8 without control characters, the label and control service
/// consist of `[A-Za-z0-9._-]`, the program path is absolute, and both socket paths fit [`MAX_SOCKET_PATH`]. So
/// [`LaunchAgent::render`] cannot fail and always produces a property list launchd can act on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchAgent {
    label: String,
    program: String,
    home: String,
    user_socket: String,
    agent_socket: String,
    control_service: String,
    plist_path: PathBuf,
    paths: EnginePaths,
}

impl LaunchAgent {
    /// The job labelled `label` that runs the `knshd` binary at `program` with the engine paths of `paths`, and
    /// declares the control service [`CONTROL_SERVICE`].
    ///
    /// The job sets `HOME` to `paths.home()`, so `knshd` derives exactly the socket paths launchd was told to
    /// create. Tests use their own label and a temporary home, so they never touch the user's real agent.
    ///
    /// # Errors
    ///
    /// [`PlatformError::InvalidLaunchAgent`] if the label has a character outside `[A-Za-z0-9._-]` (or is empty or
    /// too long), if `program` is relative or any path is not UTF-8 or holds a control character, or if a socket path
    /// is longer than [`MAX_SOCKET_PATH`] bytes.
    pub fn new(label: &str, program: &Path, paths: &EnginePaths) -> Result<Self, PlatformError> {
        check_name(label)?;
        if !program.is_absolute() {
            return Err(PlatformError::InvalidLaunchAgent);
        }
        let user_socket = plist_text(&paths.user_socket())?;
        let agent_socket = plist_text(&paths.agent_socket())?;
        if user_socket.len() > MAX_SOCKET_PATH || agent_socket.len() > MAX_SOCKET_PATH {
            return Err(PlatformError::InvalidLaunchAgent);
        }
        Ok(Self {
            label: label.to_owned(),
            program: plist_text(program)?,
            home: plist_text(paths.home())?,
            user_socket,
            agent_socket,
            control_service: CONTROL_SERVICE.to_owned(),
            plist_path: plist_path(paths.home(), label)?,
            paths: paths.clone(),
        })
    }

    /// The same job declaring the Mach service `name` instead of [`CONTROL_SERVICE`]. For tests, which must not take
    /// the real control service name while a real agent may be loaded.
    ///
    /// # Errors
    ///
    /// [`PlatformError::InvalidLaunchAgent`] if `name` has a character outside `[A-Za-z0-9._-]`.
    pub fn with_control_service(mut self, name: &str) -> Result<Self, PlatformError> {
        check_name(name)?;
        name.clone_into(&mut self.control_service);
        Ok(self)
    }

    /// The launchd label.
    #[must_use]
    pub fn label(&self) -> &str {
        &self.label
    }

    /// Where the property list is installed: `~/Library/LaunchAgents/<label>.plist`.
    #[must_use]
    pub fn plist_path(&self) -> &Path {
        &self.plist_path
    }

    /// The engine paths the job serves.
    #[must_use]
    pub fn paths(&self) -> &EnginePaths {
        &self.paths
    }

    /// The job as an XML property list.
    ///
    /// - `Sockets` declares `user.sock` and `agent.sock` as owner-only Unix stream sockets, so launchd creates them
    ///   and starts `knshd` on demand. `knshd` never binds them itself.
    /// - `MachServices` reserves the control service name (served from phase 2).
    /// - `KeepAlive` → `Crashed` restarts `knshd` after a crash (NFR-REL-03), without starting it at load:
    ///   `SuccessfulExit` would imply `RunAtLoad`. Observed on macOS 26.6: launchd restarts after `SIGABRT` (after
    ///   its 10-second throttle) but not after `SIGKILL`, which it does not count as a crash; the next connection
    ///   then starts `knshd` on demand, so either way a client is served once `knshd` is back.
    /// - `RunAtLoad` is false: launchd starts `knshd` only on first contact.
    /// - `EnvironmentVariables` → `HOME` pins the home the socket paths were derived from.
    #[must_use]
    pub fn render(&self) -> String {
        // `SockPathMode` is a plain integer in the property list: `SOCKET_MODE` (0o600) is written as 384.
        let socket = |path: &str| {
            format!(
                "\t\t<dict>\n\
                 \t\t\t<key>SockFamily</key>\n\t\t\t<string>Unix</string>\n\
                 \t\t\t<key>SockType</key>\n\t\t\t<string>stream</string>\n\
                 \t\t\t<key>SockPathName</key>\n\t\t\t<string>{}</string>\n\
                 \t\t\t<key>SockPathMode</key>\n\t\t\t<integer>{SOCKET_MODE}</integer>\n\
                 \t\t</dict>\n",
                escape(path)
            )
        };
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
             <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
             <plist version=\"1.0\">\n\
             <dict>\n\
             \t<key>Label</key>\n\t<string>{label}</string>\n\
             \t<key>ProgramArguments</key>\n\t<array>\n\t\t<string>{program}</string>\n\t</array>\n\
             \t<key>EnvironmentVariables</key>\n\t<dict>\n\t\t<key>HOME</key>\n\t\t<string>{home}</string>\n\t</dict>\n\
             \t<key>RunAtLoad</key>\n\t<false/>\n\
             \t<key>KeepAlive</key>\n\t<dict>\n\t\t<key>Crashed</key>\n\t\t<true/>\n\t</dict>\n\
             \t<key>Sockets</key>\n\t<dict>\n\
             \t\t<key>{USER_SOCKET_NAME}</key>\n{user}\
             \t\t<key>{AGENT_SOCKET_NAME}</key>\n{agent}\
             \t</dict>\n\
             \t<key>MachServices</key>\n\t<dict>\n\t\t<key>{control}</key>\n\t\t<true/>\n\t</dict>\n\
             </dict>\n\
             </plist>\n",
            label = escape(&self.label),
            program = escape(&self.program),
            home = escape(&self.home),
            user = socket(&self.user_socket),
            agent = socket(&self.agent_socket),
            control = escape(&self.control_service),
        )
    }
}

/// `~/Library/LaunchAgents/<label>.plist` under `home`.
///
/// # Errors
///
/// [`PlatformError::InvalidLaunchAgent`] if the label has a character outside `[A-Za-z0-9._-]`, which also rules out
/// a `/` or `..` that could place the file elsewhere.
pub fn plist_path(home: &Path, label: &str) -> Result<PathBuf, PlatformError> {
    check_name(label)?;
    Ok(launch_agents_dir(home).join(format!("{label}.plist")))
}

/// `~/Library/LaunchAgents/`, where per-user launchd jobs live and are loaded from at login.
fn launch_agents_dir(home: &Path) -> PathBuf {
    home.join("Library").join("LaunchAgents")
}

/// Accepts a launchd label or Mach service name: `[A-Za-z0-9._-]`, not empty, not starting with `.`, at most
/// [`MAX_LABEL`] bytes. Narrow on purpose: it is also a file name and is written into XML.
fn check_name(name: &str) -> Result<(), PlatformError> {
    let valid = !name.is_empty()
        && name.len() <= MAX_LABEL
        && !name.starts_with('.')
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'));
    if valid {
        Ok(())
    } else {
        Err(PlatformError::InvalidLaunchAgent)
    }
}

/// A path as property list text: UTF-8 without control characters, which XML 1.0 cannot carry.
fn plist_text(path: &Path) -> Result<String, PlatformError> {
    let text = path.to_str().ok_or(PlatformError::InvalidLaunchAgent)?;
    if text.chars().any(char::is_control) {
        return Err(PlatformError::InvalidLaunchAgent);
    }
    Ok(text.to_owned())
}

/// Escapes the XML special characters of a property list string.
fn escape(text: &str) -> String {
    let mut escaped = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&apos;"),
            other => escaped.push(other),
        }
    }
    escaped
}

/// Receives the listening sockets launchd created for this job. Object safe: hold it as `Arc<dyn SocketActivation>`.
///
/// There is no method to bind a socket: `knshd` only ever serves sockets launchd owns (KNSH-012).
pub trait SocketActivation: Send + Sync {
    /// Takes the listening sockets of the `Sockets` entry `name` (for example [`USER_SOCKET_NAME`]). They can be
    /// taken once per process; each is close-on-exec, so no child process inherits an endpoint.
    ///
    /// # Errors
    ///
    /// [`PlatformError::Os`] with [`Operation::ActivateSocket`](crate::Operation::ActivateSocket): `ESRCH` if this
    /// process was not started by launchd, `ENOENT` if the job declares no socket called `name` (or launchd
    /// provided none), `EALREADY` if they were already taken.
    fn listeners(&self, name: &str) -> Result<Vec<UnixListener>, PlatformError>;
}

/// Reports who is at the other end of a Unix-socket connection. Object safe: hold it as `Arc<dyn PeerCredentials>`.
pub trait PeerCredentials: Send + Sync {
    /// The effective user id of the peer process, as the kernel recorded it when the connection was made.
    ///
    /// # Errors
    ///
    /// [`PlatformError::Os`] with [`Operation::PeerCredentials`](crate::Operation::PeerCredentials) if the kernel
    /// cannot report it (for example on a connection already closed). Callers refuse the connection then.
    fn peer_uid(&self, stream: &UnixStream) -> Result<u32, PlatformError>;
}

/// Loads and unloads launchd jobs in a user's GUI domain (`gui/<uid>`). Object safe.
pub trait ServiceManager: Send + Sync {
    /// Loads the job defined by the property list at `plist` into the GUI domain of `uid`.
    ///
    /// # Errors
    ///
    /// [`PlatformError::Launchctl`] if launchd refuses, for example when the job is already loaded or the user has
    /// no GUI session.
    fn bootstrap(&self, uid: u32, plist: &Path) -> Result<(), PlatformError>;

    /// Unloads the job `label` from the GUI domain of `uid`, stopping it if it runs. Returns `false` if it was not
    /// loaded, which is not an error.
    ///
    /// # Errors
    ///
    /// [`PlatformError::Launchctl`] for any other failure.
    fn bootout(&self, uid: u32, label: &str) -> Result<bool, PlatformError>;
}

/// Installs the launch agent for user `uid` (`knsh daemon install`).
///
/// Steps, each needed by the next:
///
/// 1. Prepare the engine directories ([`ensure_engine_dirs`]): launchd creates the sockets in the run directory but
///    does not create the directory itself. The `0700` directory also covers a window launchd leaves: it binds each
///    socket with the default mode and applies `SockPathMode` just after (observed on macOS 26.6).
/// 2. Create `~/Library/LaunchAgents/` if missing.
/// 3. Write the property list atomically, owner-only.
/// 4. Unload any loaded job with the same label, so a reinstall takes the new definition.
/// 5. Load the job. launchd now owns the sockets; `knshd` starts on the first connection.
///
/// Safe to run again: a second install replaces the definition and reloads it.
///
/// # Errors
///
/// - Any error of [`ensure_engine_dirs`]; nothing else is changed.
/// - [`PlatformError::ForeignOwner`] or [`PlatformError::UnexpectedKind`] if `~/Library/LaunchAgents` is owned by
///   another user or is not a directory: a job written there could be replaced by its owner.
/// - [`PlatformError::Os`] if the property list cannot be written; a previously installed job keeps running.
/// - [`PlatformError::Launchctl`] if unloading or loading fails. The new property list is already in place, so
///   launchd loads it at the next login, and running install again retries.
pub fn install_agent(
    fs: &dyn Fs,
    manager: &dyn ServiceManager,
    agent: &LaunchAgent,
    uid: u32,
) -> Result<(), PlatformError> {
    ensure_engine_dirs(fs, agent.paths(), uid)?;
    ensure_launch_agents_dir(fs, &launch_agents_dir(agent.paths().home()), uid)?;
    fs.atomic_replace(agent.plist_path(), agent.render().as_bytes(), PLIST_MODE)?;
    manager.bootout(uid, agent.label())?;
    manager.bootstrap(uid, agent.plist_path())
}

/// Uninstalls the launch agent `label` of user `uid` (`knsh daemon uninstall`): unloads the job (stopping `knshd`,
/// after which launchd removes the socket names it held) and removes its property list from `home`. Returns whether
/// anything was installed.
///
/// Safe to run when nothing is installed. Engine data (records, checkpoints, configuration) is kept: uninstalling
/// the agent is not `knsh forget`.
///
/// # Errors
///
/// - [`PlatformError::InvalidLaunchAgent`] for a label outside `[A-Za-z0-9._-]`.
/// - [`PlatformError::Launchctl`] if unloading fails; the property list is then kept, so the state stays consistent.
/// - [`PlatformError::Os`] if the property list exists but cannot be removed.
pub fn uninstall_agent(
    fs: &dyn Fs,
    manager: &dyn ServiceManager,
    home: &Path,
    label: &str,
    uid: u32,
) -> Result<bool, PlatformError> {
    let plist = plist_path(home, label)?;
    let was_loaded = manager.bootout(uid, label)?;
    let had_plist = match fs.remove_file(&plist) {
        Ok(()) => true,
        Err(error) if error.is_not_found() => false,
        Err(error) => return Err(error),
    };
    Ok(was_loaded || had_plist)
}

/// Creates `~/Library/LaunchAgents/` if missing, and checks that it is a real directory owned by `uid`.
fn ensure_launch_agents_dir(fs: &dyn Fs, dir: &Path, uid: u32) -> Result<(), PlatformError> {
    match fs.create_dir(dir, LAUNCH_AGENTS_MODE) {
        Ok(()) => {}
        // Normal case: the directory exists. It is checked below like a new one.
        Err(error) if error.errno() == Some(libc::EEXIST) => {}
        Err(error) => return Err(error),
    }
    let meta = fs.metadata(dir)?;
    if meta.kind != FileKind::Directory {
        return Err(PlatformError::UnexpectedKind);
    }
    if meta.uid != uid {
        return Err(PlatformError::ForeignOwner);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Operation;
    use crate::testing::{MemFs, RecordingServiceManager, ServiceCall};

    const UID: u32 = crate::testing::DEFAULT_UID;

    fn agent(home: &str) -> LaunchAgent {
        let paths = EnginePaths::for_home(Path::new(home)).unwrap();
        LaunchAgent::new(AGENT_LABEL, Path::new("/opt/knsh/bin/knshd"), &paths).unwrap()
    }

    /// The `<dict>` that follows `<key>{key}</key>` in `plist`, up to its closing tag.
    fn dict_after<'a>(plist: &'a str, key: &str) -> &'a str {
        let start = plist.find(&format!("<key>{key}</key>")).unwrap();
        let rest = &plist[start..];
        &rest[..rest.find("</dict>").unwrap()]
    }

    // KNSH-012: the property list declares both sockets at the engine run directory, owner-only, on demand.
    #[test]
    fn plist_declares_both_sockets_owner_only() {
        let job = agent("/Users/alice");
        let plist = job.render();
        let path = |socket: PathBuf| format!("<string>{}</string>", socket.to_str().unwrap());

        let user = dict_after(&plist, USER_SOCKET_NAME);
        assert!(user.contains(&path(job.paths().user_socket())), "{user}");
        let agent_sock = dict_after(&plist, AGENT_SOCKET_NAME);
        assert!(agent_sock.contains(&path(job.paths().agent_socket())), "{agent_sock}");
        // The sockets live in the engine run directory, which every envelope denies.
        assert!(job.paths().user_socket().starts_with(job.paths().run_dir()));
        for socket in [user, agent_sock] {
            // 384 is 0o600: owner read and write only.
            assert!(
                socket.contains("<key>SockPathMode</key>\n\t\t\t<integer>384</integer>"),
                "{socket}"
            );
            assert!(socket.contains("<string>Unix</string>") && socket.contains("<string>stream</string>"));
        }
        assert_eq!(SOCKET_MODE, 384);

        // On demand: never at load, restarted after a crash (NFR-REL-03).
        assert!(plist.contains("<key>RunAtLoad</key>\n\t<false/>"));
        assert!(plist.contains("<key>KeepAlive</key>\n\t<dict>\n\t\t<key>Crashed</key>\n\t\t<true/>"));
        assert!(!plist.contains("SuccessfulExit"), "SuccessfulExit implies RunAtLoad");

        assert!(plist.contains("<key>Label</key>\n\t<string>knsh.knshd</string>"));
        assert!(plist.contains("<string>/opt/knsh/bin/knshd</string>"));
        assert!(plist.contains("<key>HOME</key>\n\t\t<string>/Users/alice</string>"));
        assert!(plist.contains("<key>knsh.control</key>"));
        assert!(plist.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist"));
    }

    #[test]
    fn plist_escapes_xml_in_paths() {
        let plist = agent("/Users/a&b<c>").render();
        assert!(plist.contains("<string>/Users/a&amp;b&lt;c&gt;</string>"), "{plist}");
        assert!(!plist.contains("a&b"));
    }

    // launchd would accept these definitions and then fail out of sight, so they are refused up front.
    #[test]
    fn refuses_definitions_launchd_cannot_act_on() {
        let paths = EnginePaths::for_home(Path::new("/Users/alice")).unwrap();
        let program = Path::new("/opt/knshd");
        for label in ["", ".hidden", "a/b", "../x", "a b", "a\nb", &"x".repeat(129)] {
            assert_eq!(
                LaunchAgent::new(label, program, &paths),
                Err(PlatformError::InvalidLaunchAgent),
                "{label:?}"
            );
        }
        assert_eq!(
            LaunchAgent::new(AGENT_LABEL, Path::new("relative/knshd"), &paths),
            Err(PlatformError::InvalidLaunchAgent)
        );
        assert_eq!(
            LaunchAgent::new(AGENT_LABEL, Path::new("/opt/knsh\u{7}d"), &paths),
            Err(PlatformError::InvalidLaunchAgent)
        );
        // The agent socket adds 48 bytes below the home: a 56-byte home exceeds 103.
        let long_home = format!("/{}", "h".repeat(55));
        let long = EnginePaths::for_home(Path::new(&long_home)).unwrap();
        assert_eq!(long.agent_socket().as_os_str().len(), MAX_SOCKET_PATH + 1);
        assert_eq!(
            LaunchAgent::new(AGENT_LABEL, program, &long),
            Err(PlatformError::InvalidLaunchAgent)
        );
        let fits = EnginePaths::for_home(Path::new(&long_home[..55])).unwrap();
        assert!(LaunchAgent::new(AGENT_LABEL, program, &fits).is_ok());

        let agent = LaunchAgent::new(AGENT_LABEL, program, &paths).unwrap();
        assert_eq!(
            agent.clone().with_control_service("x/y"),
            Err(PlatformError::InvalidLaunchAgent)
        );
        let renamed = agent.with_control_service("knsh.test.control").unwrap();
        assert!(renamed.render().contains("<key>knsh.test.control</key>"));
    }

    #[test]
    fn install_prepares_directories_writes_plist_then_reloads() {
        let fs = MemFs::new();
        fs.add_dir_all(Path::new("/Users/alice")).unwrap();
        let manager = RecordingServiceManager::new();
        let agent = agent("/Users/alice");

        install_agent(&fs, &manager, &agent, UID).unwrap();

        let plist = Path::new("/Users/alice/Library/LaunchAgents/knsh.knshd.plist");
        assert_eq!(agent.plist_path(), plist);
        assert_eq!(fs.contents(plist).unwrap(), agent.render().as_bytes());
        assert_eq!(fs.metadata(plist).unwrap().mode, PLIST_MODE);
        // launchd creates the sockets in the run directory, so it must exist first, owner-only.
        assert_eq!(fs.metadata(&agent.paths().run_dir()).unwrap().mode, 0o700);
        assert_eq!(
            manager.calls(),
            vec![
                ServiceCall::Bootout {
                    uid: UID,
                    label: AGENT_LABEL.to_owned()
                },
                ServiceCall::Bootstrap {
                    uid: UID,
                    plist: plist.to_path_buf()
                },
            ]
        );

        // Reinstalling replaces the definition and reloads it.
        install_agent(&fs, &manager, &agent, UID).unwrap();
        assert_eq!(manager.calls().len(), 4);
    }

    // Failure safety: if the definition cannot be written, the running job is left alone.
    #[test]
    fn install_leaves_loaded_job_alone_when_plist_cannot_be_written() {
        let fs = MemFs::new();
        fs.add_dir_all(Path::new("/Users/alice/Library/LaunchAgents")).unwrap();
        fs.inject_fault(Operation::Rename, libc::EIO);
        let manager = RecordingServiceManager::new();
        let error = install_agent(&fs, &manager, &agent("/Users/alice"), UID).unwrap_err();
        assert_eq!(error.errno(), Some(libc::EIO));
        assert_eq!(manager.calls(), Vec::new());
    }

    #[test]
    fn install_refuses_launch_agents_dir_it_does_not_own() {
        let fs = MemFs::new();
        let dir = Path::new("/Users/alice/Library/LaunchAgents");
        fs.add_dir_all(dir).unwrap();
        fs.set_owner(dir, 0).unwrap();
        let manager = RecordingServiceManager::new();
        assert_eq!(
            install_agent(&fs, &manager, &agent("/Users/alice"), UID),
            Err(PlatformError::ForeignOwner)
        );

        let fs = MemFs::new();
        fs.add_dir_all(Path::new("/Users/alice/Library")).unwrap();
        fs.add_symlink(dir, Path::new("/tmp")).unwrap();
        assert_eq!(
            install_agent(&fs, &manager, &agent("/Users/alice"), UID),
            Err(PlatformError::UnexpectedKind)
        );
        assert_eq!(manager.calls(), Vec::new());
    }

    #[test]
    fn install_reports_load_failure() {
        let fs = MemFs::new();
        fs.add_dir_all(Path::new("/Users/alice")).unwrap();
        let manager = RecordingServiceManager::new();
        manager.fail_bootstrap(5);
        assert_eq!(
            install_agent(&fs, &manager, &agent("/Users/alice"), UID),
            Err(PlatformError::Launchctl { status: Some(5) })
        );
    }

    #[test]
    fn uninstall_unloads_then_removes_plist_and_is_idempotent() {
        let fs = MemFs::new();
        fs.add_dir_all(Path::new("/Users/alice")).unwrap();
        let manager = RecordingServiceManager::new();
        let agent = agent("/Users/alice");
        install_agent(&fs, &manager, &agent, UID).unwrap();

        let home = Path::new("/Users/alice");
        assert_eq!(uninstall_agent(&fs, &manager, home, AGENT_LABEL, UID), Ok(true));
        assert!(fs.contents(agent.plist_path()).is_none());
        assert!(matches!(manager.calls().last(), Some(ServiceCall::Bootout { .. })));
        // Engine data stays.
        assert!(fs.metadata(agent.paths().data_dir()).is_ok());

        assert_eq!(uninstall_agent(&fs, &manager, home, AGENT_LABEL, UID), Ok(false));
        assert_eq!(
            uninstall_agent(&fs, &manager, home, "../evil", UID),
            Err(PlatformError::InvalidLaunchAgent)
        );
    }

    // Failure safety: if launchd cannot unload the job, its definition stays so the state remains consistent.
    #[test]
    fn uninstall_keeps_plist_when_unload_fails() {
        let fs = MemFs::new();
        fs.add_dir_all(Path::new("/Users/alice")).unwrap();
        let manager = RecordingServiceManager::new();
        let agent = agent("/Users/alice");
        install_agent(&fs, &manager, &agent, UID).unwrap();
        manager.fail_bootout(5);
        assert_eq!(
            uninstall_agent(&fs, &manager, Path::new("/Users/alice"), AGENT_LABEL, UID),
            Err(PlatformError::Launchctl { status: Some(5) })
        );
        assert!(fs.contents(agent.plist_path()).is_some());
    }
}
