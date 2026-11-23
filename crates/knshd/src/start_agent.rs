//! `session.start_agent`: `knsh agent` starts an agent CLI in a new agent session and waits for it
//! (`specs/06-api/user-socket.md#sessionstart_agent`, KNSH-056; FR-AGT-01, FR-AGT-02, FR-AGT-06, FR-SES-02,
//! FR-SES-03).
//!
//! # Where it is served
//!
//! On `user.sock` only (FR-SES-02). The method catalogue keeps it off `agent.sock` (it is not even listed there, and a
//! call is `-32601`), and the handler checks the endpoint again. It requires the sandbox: when the capability probe
//! reports `sandbox: none` the dispatcher answers `-32005` naming `sandbox` and this handler never runs (FR-AGT-06).
//!
//! # Steps
//!
//! 1. **Params** ([`SessionStartAgentParams`]) and exactly three passed descriptors, the caller's stdin, stdout and
//!    stderr; anything else is `-32602`.
//! 2. **Actor (FR-AGT-02).** `--agent` if given, else derived from the program ([`AgentId::derive_from_program`]:
//!    `claude` becomes `claude-code`); a program that gives no valid name is `-32602`.
//! 3. **Parent (FR-SES-03).** The live agent session the caller runs inside, found as `hello` on `agent.sock` finds
//!    one: by the session token in the caller's environment, else by the caller's audit token descending from a
//!    registered envelope ([`Sessions::enclosing`]). Inside an envelope `user.sock` is denied by the sandbox, so
//!    this is a second line: if a caller in an envelope reaches it anyway, its session can only be as strict.
//! 4. **Profile.** `--profile` if given; else the parent's profile; else `default`. It is loaded as the supervisor
//!    loads profiles (a missing named profile is `-32602`, a broken one `-32603`). With a parent, the child is
//!    compared with the parent's profile as it runs, resolved when the parent started (never reloaded from the
//!    child's `cwd`, which would move the parent's `${PROJECT}`), and must be at least as strict
//!    ([`knsh_core::at_least_as_strict`]); a looser one is `-32003` and nothing is started. Without `--profile` the
//!    child runs that same resolved profile.
//! 5. **Program.** `argv[0]` is found as a shell would: a path with `/` is taken relative to `cwd`, a name is looked
//!    up on the `PATH` of the caller's environment (absolute entries only, the shim directory skipped). It must be
//!    an executable file; otherwise `-32602`.
//! 6. **Session.** Opened with its parent ([`Sessions::open_agent_in`]): row written, `session.started` published,
//!    token issued. Its checkpoint roots' shadows start building in the background (KNSH-079,
//!    [`Sessions::start_shadows`]); nothing waits for them here.
//! 7. **Launch (KNSH-057).** With the Endpoint Security layer (`hello` reports `sandbox:
//!    "seatbelt+endpoint_security"`, KNSH-094), the envelope's descendant client is created first
//!    ([`ExecLayer::watch`]), so every exec in it is decided by the supervisor from its first one; if it cannot be
//!    created nothing starts and the call is `-32603` (fail closed: `hello` promised the layer). Without the layer
//!    (macOS 14 to 26, no entitlement) no client is tried and nothing about it reaches the caller. The proxy issues the envelope's credentials ([`ProxyIssuer`]; none if no proxy
//!    runs), revoked with the session's lines' when the envelope ends. The [`Launcher`] compiles the envelope profile ([`envelope_profile`]) and starts the CLI through
//!    `knsh-exec`, in a new process group, on the caller's descriptors, with the envelope environment
//!    ([`envelope_env`]). The group's leader is registered as the session's envelope (FR-AGT-23) and its group kept
//!    for pause and resume (FR-SES-10).
//! 8. **Wait.** Until the CLI exits. If the caller disconnects first (`knsh agent` was killed), the envelope's
//!    group gets `SIGTERM`, then `SIGKILL` after [`KILL_GRACE`]: nobody is left to answer for it. When the CLI exits
//!    on its own, what is left of its group gets `SIGTERM`: the envelope ends with its CLI.
//! 9. **End.** The envelope's proxy credentials are revoked, the session ends (`session.state_changed` to `ended`,
//!    then `session.ended`), its token and envelope revoked, and the call is answered with how the CLI ended
//!    ([`SessionStartAgentResult`]).
//!
//! Every failure after step 6 ends the session before answering, so no session outlives its envelope.
//!
//! # The envelope (KNSH-057)
//!
//! - **Profile (FR-AGT-04, FR-SBX-01).** The session's profile as the loader resolved it, so with its preset's
//!   grants (the CLI's configuration folder, the project) already merged in, compiled deny-by-default for an
//!   envelope ([`CommandTag::Envelope`]): `agent.sock` is the one Unix socket it may connect to; `user.sock`, the
//!   control service and every engine path are fixed denies no profile can lift (FR-SBX-05, FR-AUTH-16); outbound
//!   network goes only to the proxy's port and the profile's `network.loopback` ports. The CLI and `knsh` (the
//!   shims' target) are the binaries it may run besides the trusted and system folders.
//! - **Environment (FR-AGT-03).** [`envelope_env`]: `SHELL=knsh`, the shims first on `PATH`, the session's token,
//!   and the proxy settings with the envelope's own credentials (decision 14). Inherited proxy settings and the
//!   dynamic linker's variables never reach it.
//! - **Confinement (FR-AGT-11, FR-AGT-12, FR-AGT-20).** Seatbelt profiles are inherited by every child and cannot
//!   be replaced from inside (an already sandboxed process cannot apply another), so nothing the envelope starts
//!   directly exceeds its profile; only lines the supervisor spawns, outside the envelope, run under profiles of
//!   their own. Every process of the tree is the agent: `knshd` binds it by the session token or by audit-token
//!   ancestry, and `knsh` inside an envelope never hosts a human shell, so a command typed into the envelope's
//!   terminal is forwarded as an agent line.
//!
//! # Known limits
//!
//! - The proxy (KNSH-059) refuses every destination until host rules exist (KNSH-060), so the envelope still reaches
//!   only its loopback ports (fail closed); if the proxy could not start, `knshd` wires [`crate::proxy::NoProxy`]
//!   and the envelope gets no proxy settings at all. The preset's model API host is the proxy's to allow.
//! - The CLI runs in a process group of `knshd`'s session, not the terminal's: it is never the terminal's foreground
//!   group. Terminal signals (Ctrl-C with `ISIG` on, `SIGWINCH`) go to `knsh agent`, not to the CLI; a CLI in raw
//!   mode (as agent CLIs are) reads Ctrl-C as input. `knsh agent` dying ends the envelope (step 8).

use std::collections::BTreeMap;
use std::num::NonZeroU16;
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError};
use std::time::Duration;

use knsh_core::{
    Actor, AgentId, BinaryLookup, CanonicalPath, EqualProfileOnly, LoadedProfiles, Profile, ProfileErrorKind,
    ProfileName, ProfileOrder, ProfileOrigin, Redacted, SessionId,
};
use knsh_platform::{Clock, FileKind, Fs, ProcessGroupId, Processes, SharedFd, Signal, SpawnRequest};
use knsh_proto::{
    ErrorCode, LineStatus, RpcError, SESSION_TOKEN_VAR, SessionStartAgentParams, SessionStartAgentResult,
};
use knsh_sandbox::{CommandTag, ProfileInput, SbplText, compile};

use crate::agents::SessionToken;
use crate::dispatch::{Call, Endpoint, Handler, Handlers, Reply, START_AGENT, answer, capability_unavailable, params};
use crate::endpoint_security::ExecLayer;
use crate::exec::{PATH_VAR, without_shims};
use crate::holds::GroupKind;
use crate::policy::ProfileLoader;
use crate::profiles::{CompiledProfile, ProfileFiles};
use crate::proxy::{ProxyCredential, ProxyIssuer, is_proxy_var, proxy_env};
use crate::sessions::Sessions;
use crate::spawn::{line_status, passed, read_by_dynamic_linker, read_status};

/// The profile of a top-level agent session started without `--profile`.
pub(crate) const DEFAULT_PROFILE: &str = "default";

/// After `SIGTERM`, how long an abandoned envelope has before `SIGKILL` (the lines' grace, FR-LC-40).
pub(crate) const KILL_GRACE: Duration = Duration::from_secs(2);

/// The variable the envelope's `SHELL` is (FR-AGT-03).
const SHELL_VAR: &str = "SHELL";

/// The line `knsh-exec` runs in the envelope: the CLI itself, by the absolute path in `$0`, with its arguments. The
/// trampoline only runs lines through an interpreter; `exec` replaces that shell at once.
const EXEC_PROGRAM: &str = "exec \"$0\" \"$@\"";

/// First pause between checks on a running envelope, doubled up to [`POLL_MAX`].
const POLL_FIRST: Duration = Duration::from_millis(1);
/// Longest pause between checks: how late `knsh agent` hears that its CLI exited, or `knshd` that the caller left.
const POLL_MAX: Duration = Duration::from_millis(100);

/// Everything one envelope launch needs (module documentation, step 7).
pub(crate) struct Launch<'a> {
    /// The new session, named in the envelope's sandbox tag.
    pub(crate) session_id: SessionId,
    /// Its profile: the baseline of the envelope's sandbox profile.
    pub(crate) profile: &'a Profile,
    /// The CLI, canonical.
    pub(crate) program: &'a CanonicalPath,
    /// Its arguments after `argv[0]`.
    pub(crate) args: &'a [String],
    /// The complete environment ([`envelope_env`]).
    pub(crate) env: Vec<(String, String)>,
    /// The proxy's loopback port when a proxy serves the envelope: the profile allows outbound TCP to it.
    pub(crate) proxy_port: Option<NonZeroU16>,
    /// The working directory.
    pub(crate) cwd: &'a CanonicalPath,
    /// The caller's stdin, stdout and stderr.
    pub(crate) stdio: [OwnedFd; 3],
}

/// A launched envelope, until its leader is reaped.
pub(crate) trait Envelope: Send {
    /// Its process group: the leader's pid, held unreaped by the launcher's [`Processes`].
    fn group(&self) -> ProcessGroupId;

    /// Called once the leader is reaped: whether the CLI was ever started. `false` when the trampoline reported a
    /// failure (the sandbox was never applied, so the CLI never ran) or that could not be read.
    fn ran(self: Box<Self>) -> bool;
}

/// Starts an agent CLI in its envelope (module documentation, step 7). Object safe, so tests can launch nothing.
pub(crate) trait Launcher: Send + Sync {
    /// The processes the envelopes are started, signalled and reaped through.
    fn processes(&self) -> Arc<dyn Processes>;

    /// Starts `launch` as the leader of a new process group.
    ///
    /// # Errors
    ///
    /// Nothing was started: the profile file could not be written, or the spawn failed.
    fn launch(&self, launch: Launch<'_>) -> Result<Box<dyn Envelope>, LaunchError>;
}

/// Why an envelope did not start. Never shown to the caller (`-32603`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LaunchError {
    /// The compiled profile could not be written and checked.
    ProfileFile,
    /// The status pipe or the spawn failed.
    Spawn,
}

/// The `session.start_agent` service. One per `knshd`.
pub(crate) struct AgentStarter {
    sessions: Arc<Sessions>,
    profiles: ProfileLoader,
    launcher: Arc<dyn Launcher>,
    /// Issues and revokes each envelope's proxy credentials (FR-NET-01).
    proxy: Arc<dyn ProxyIssuer>,
    clock: Arc<dyn Clock>,
    /// The shim directory, put first on the envelope's `PATH` (FR-AGT-03) and skipped when finding the program.
    shim_dir: PathBuf,
    /// The `knsh` binary: the envelope's `SHELL` (FR-AGT-03).
    knsh: PathBuf,
    /// The user `knshd` runs as: the owner a preset's `[env]` folder must have (FR-AGT-33).
    uid: u32,
    /// The Endpoint Security layer, attached when `hello` reports it (KNSH-094); unset, envelopes start without a
    /// descendant client.
    exec_layer: OnceLock<Arc<ExecLayer>>,
    /// The profile each live session this service started runs under, exactly as it was resolved for its envelope
    /// (with that session's `${PROJECT}`). A nested session is compared with this, never with the parent's profile
    /// loaded again: reloaded from the child's `cwd`, which the caller chooses, the parent's project-relative paths
    /// would follow the child anywhere (FR-SES-03).
    running: Mutex<BTreeMap<SessionId, Arc<Profile>>>,
}

impl AgentStarter {
    /// The service over `sessions`, loading profiles with `profiles`, starting envelopes with `launcher` and
    /// getting their proxy credentials from `proxy`, as the user `uid`.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        sessions: Arc<Sessions>,
        profiles: ProfileLoader,
        launcher: Arc<dyn Launcher>,
        proxy: Arc<dyn ProxyIssuer>,
        clock: Arc<dyn Clock>,
        shim_dir: PathBuf,
        knsh: PathBuf,
        uid: u32,
    ) -> Arc<Self> {
        Arc::new(Self {
            sessions,
            profiles,
            launcher,
            proxy,
            clock,
            shim_dir,
            knsh,
            uid,
            exec_layer: OnceLock::new(),
            running: Mutex::new(BTreeMap::new()),
        })
    }

    /// Creates a descendant client with `layer` for every later envelope, before it starts (KNSH-094). Set once at
    /// start, and only when the probe reported the layer; a second call is a wiring mistake and is ignored.
    pub(crate) fn attach_exec_layer(&self, layer: Arc<ExecLayer>) {
        let _ = self.exec_layer.set(layer);
    }

    /// The live sessions' profiles. A poisoned lock is taken over: the map is only ever inserted into or removed
    /// from, so it is never left half-changed.
    fn running(&self) -> MutexGuard<'_, BTreeMap<SessionId, Arc<Profile>>> {
        self.running.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Records `profile` as the one `session_id` runs under, as if this service had started it: for tests whose
    /// parent session is opened directly.
    #[cfg(test)]
    pub(crate) fn adopt(&self, session_id: SessionId, profile: Profile) {
        self.running().insert(session_id, Arc::new(profile));
    }

    /// The `session.start_agent` handler.
    pub(crate) fn handlers(self: &Arc<Self>) -> Handlers {
        let service = Arc::clone(self);
        let handler: Handler = Arc::new(move |call: &Call<'_>| service.start(call));
        [(START_AGENT, handler)].into_iter().collect()
    }

    /// `session.start_agent` (module documentation, "Steps").
    fn start(&self, call: &Call<'_>) -> Reply {
        // FR-SES-02: the catalogue already keeps this off agent.sock; checked again so no table mistake opens it.
        if call.endpoint != Endpoint::User {
            return Err(RpcError::new(ErrorCode::NotAllowed));
        }
        // Step 1.
        let params: SessionStartAgentParams = params(call)?;
        let stdio = stdio(call.descriptors.take())?;
        // Step 2.
        let agent_id = match &params.agent {
            Some(agent_id) => agent_id.clone(),
            None => AgentId::derive_from_program(&params.command[0]).map_err(|_| invalid_params())?,
        };
        // Step 3. The caller's own token names its session; it never reaches the envelope (step 7 replaces it).
        let token = params
            .env
            .iter()
            .find(|(name, _)| name == SESSION_TOKEN_VAR)
            .map(|(_, value)| Redacted::new(value.clone()));
        let parent = self.sessions.enclosing(token.as_ref(), call.binding.peer());
        // Step 4.
        let (profile, parent_profile) = self.profiles(&params, parent)?;
        let order: &dyn ProfileOrder = match &parent_profile {
            Some(parent_profile) => &LoadedProfiles {
                child: &profile,
                parent: parent_profile.as_ref(),
            },
            // No parent: the registry checks no ordering at all.
            None => &EqualProfileOnly,
        };
        // Step 5.
        let program = self.program(&params).ok_or_else(invalid_params)?;
        // Step 6.
        let opened =
            self.sessions
                .open_agent_in(Actor::Agent(agent_id.clone()), profile.name.clone(), parent, order)?;
        let session_id = opened.session_id;
        let profile = Arc::new(profile);
        self.running().insert(session_id, Arc::clone(&profile));
        // FR-CKP-01: one background shadow build per checkpoint root, from the profile exactly as the session runs
        // it; the envelope starts without waiting for them. They stop when the session ends.
        self.sessions.start_shadows(session_id, &profile);
        // Steps 7 to 9. Whatever happens, the session ends before the answer.
        let ran = self.run(session_id, &opened.token, &profile, &program, &params, stdio, call);
        // Revoked first: once the envelope is gone, nothing may use its credentials (FR-NET-01).
        self.proxy.revoke(session_id);
        self.sessions.end_agent(session_id);
        self.running().remove(&session_id);
        let status = ran?;
        answer(&SessionStartAgentResult {
            session_id,
            agent_id,
            profile: profile.name.clone(),
            parent_session_id: parent,
            status,
        })
    }

    /// The new session's profile and, for a nested session, its parent's as it runs (module documentation, step 4).
    fn profiles(
        &self,
        params: &SessionStartAgentParams,
        parent: Option<SessionId>,
    ) -> Result<(Profile, Option<Arc<Profile>>), RpcError> {
        let parent_profile = parent
            .map(|parent| {
                // `-32006` if the parent ended meanwhile; a parent this service holds no profile for cannot be
                // compared, so it is refused, never assumed comparable.
                self.sessions.profile_of(parent)?;
                self.running().get(&parent).cloned().ok_or_else(internal_error)
            })
            .transpose()?;
        let name = match (&params.profile, &parent_profile) {
            (Some(name), _) => name.clone(),
            // Without `--profile` the child runs exactly the parent's resolved profile, not a reload of it.
            (None, Some(parent_profile)) => {
                return Ok((Profile::clone(parent_profile), Some(Arc::clone(parent_profile))));
            }
            (None, None) => ProfileName::new(DEFAULT_PROFILE).map_err(|_| internal_error())?,
        };
        let profile = self.profiles.load(&name, params.cwd.as_path()).map_err(|error| {
            // Only the asked-for profile itself being absent is the caller's mistake; anything else is broken.
            let missing = *error.kind() == ProfileErrorKind::ProfileNotFound
                && error.origin() == Some(&ProfileOrigin::Profile(name.clone()));
            if missing { invalid_params() } else { internal_error() }
        })?;
        Ok((profile, parent_profile))
    }

    /// The CLI's canonical path (module documentation, step 5), or `None` if it is not an executable file.
    fn program(&self, params: &SessionStartAgentParams) -> Option<CanonicalPath> {
        let program = params.command.first()?;
        let fs: &dyn knsh_platform::Fs = self.profiles.fs();
        let candidate = |path: &Path| {
            BinaryLookup::canonicalise(fs, path).filter(|path| BinaryLookup::is_executable_file(fs, path))
        };
        if program.contains('/') {
            return candidate(&params.cwd.as_path().join(program));
        }
        let (_, path) = params.env.iter().find(|(name, _)| name == PATH_VAR)?;
        let shims = CanonicalPath::new(&self.shim_dir).ok();
        let shim_dir = BinaryLookup::canonicalise(fs, &self.shim_dir);
        path.split(':')
            // Relative entries would depend on `knshd`'s directory, not the caller's: never searched.
            .filter(|entry| entry.starts_with('/'))
            // The shims are symbolic links to `knsh`, so what they resolve to is not below the shim directory: the
            // directory itself is skipped, or `knsh agent -- bash` inside an envelope would start `knsh`.
            .filter(|entry| {
                shim_dir.is_none() || BinaryLookup::canonicalise(fs, Path::new(entry)) != shim_dir
            })
            .filter_map(|entry| candidate(&Path::new(entry).join(program)))
            // A shim is `knsh` under another name: never the agent CLI.
            .find(|found| shims.as_ref().is_none_or(|shims| !found.as_path().starts_with(shims.as_path())))
    }

    /// Steps 7 and 8: launches the envelope and waits for it, returning how the CLI ended. The caller ends the
    /// session whatever this returns.
    #[allow(clippy::too_many_arguments)]
    fn run(
        &self,
        session_id: SessionId,
        token: &SessionToken,
        profile: &Profile,
        program: &CanonicalPath,
        params: &SessionStartAgentParams,
        stdio: [OwnedFd; 3],
        call: &Call<'_>,
    ) -> Result<LineStatus, RpcError> {
        let processes = self.launcher.processes();
        // FR-AGT-33: the session's own folders exist, owner-only, before the CLI starts, and only this session's
        // envelope (and lines, `Supervisor::load_profile`) is granted them; one that cannot be made safe stops the
        // launch rather than leave the CLI failing on a folder it may not use.
        let folders = profile.session_folders(session_id);
        if !env_folders_ready(self.profiles.fs(), &folders, self.uid) {
            return Err(internal_error());
        }
        let profile = &profile.with_session_folders(session_id);
        // A proxy that runs but cannot issue credentials stops the launch: no envelope runs untied to its session.
        let proxy = self
            .proxy
            .issue(session_id, &profile.network)
            .map_err(|_| internal_error())?;
        // KNSH-094: the descendant client exists before the envelope does, so no exec in it goes undecided; it is
        // deleted only once the leader has been reaped (below).
        let exec_client = match self.exec_layer.get() {
            Some(layer) => Some(
                layer
                    .watch(session_id, &profile.exec.bash, program)
                    .map_err(|_| internal_error())?,
            ),
            None => None,
        };
        let envelope = self
            .launcher
            .launch(Launch {
                session_id,
                profile,
                program,
                args: &params.command[1..],
                env: envelope_env(&params.env, token, &self.shim_dir, &self.knsh, &folders, proxy.as_ref()),
                proxy_port: proxy.as_ref().map(ProxyCredential::port),
                cwd: &params.cwd,
                stdio,
            })
            .map_err(|_| internal_error())?;
        let group = envelope.group();
        // Registered before anything waits on it: callers without the token are matched to the session from now on
        // (FR-AGT-23). The leader is unreaped, so its pid still names it. An envelope that cannot be registered is
        // not run on: it is stopped and the session refused.
        let registered = self.sessions.register_envelope_leader(session_id, group.as_raw());
        let kept = self
            .sessions
            .keep_group(session_id, group, Arc::clone(&processes), GroupKind::Envelope);
        let abandoned = registered.is_err() || self.watch(processes.as_ref(), group, call.caller);
        if abandoned {
            terminate(processes.as_ref(), self.clock.as_ref(), group);
        } else {
            // The CLI exited on its own: whatever it left running in its group ends with the envelope.
            let _ = processes.signal(group, Signal::Terminate);
        }
        // Dropped before the leader is reaped, so a pause never signals a group id that may be reused.
        drop(kept);
        let exit = processes.wait(group).map_err(|_| internal_error());
        drop(exec_client);
        let exit = exit?;
        if !envelope.ran() {
            return Err(internal_error());
        }
        registered?;
        if abandoned {
            // Nobody is left to answer; the session still ends.
            return Err(internal_error());
        }
        line_status(exit).ok_or_else(internal_error)
    }

    /// Polls `group` until its leader exits (`false`) or the caller disconnects first (`true`). A leader that
    /// cannot be checked counts as abandoned: it is stopped rather than waited on blindly.
    fn watch(&self, processes: &dyn Processes, group: ProcessGroupId, caller: &dyn knsh_core::Caller) -> bool {
        let mut pause = POLL_FIRST;
        loop {
            match processes.exited(group) {
                Ok(true) => return false,
                Ok(false) => {}
                Err(_) => return true,
            }
            if caller.gone() {
                return true;
            }
            self.clock.sleep(pause);
            pause = (pause * 2).min(POLL_MAX);
        }
    }
}

/// `SIGTERM` to the whole group, then `SIGKILL` if the leader is still running after [`KILL_GRACE`].
fn terminate(processes: &dyn Processes, clock: &dyn Clock, group: ProcessGroupId) {
    let _ = processes.signal(group, Signal::Terminate);
    let start = clock.monotonic();
    while clock.monotonic().saturating_duration_since(start) < KILL_GRACE {
        if processes.exited(group).unwrap_or(true) {
            break;
        }
        clock.sleep(POLL_MAX);
    }
    // Once more even if the leader exited: members that outlived it must not stay behind.
    let _ = processes.signal(group, Signal::Kill);
}

/// The caller's stdin, stdout and stderr.
fn stdio(descriptors: Vec<OwnedFd>) -> Result<[OwnedFd; 3], RpcError> {
    <[OwnedFd; 3]>::try_from(descriptors).map_err(|_| invalid_params())
}

/// The environment the CLI starts with (FR-AGT-03): the caller's, minus any session token it carried, its proxy
/// settings ([`is_proxy_var`]) and the dynamic linker's variables (`knsh-exec` runs unsandboxed until it becomes
/// `sandbox-exec`); then the preset's variables (`session_folders`: the session's own folders, FR-AGT-33), each
/// replacing the caller's of that name; then `SHELL` set to `knsh`, the shim directory first on `PATH` (once), the new session's token and, when a proxy
/// serves the envelope, its proxy settings with the envelope's own credentials ([`proxy_env`]). A preset never sets a
/// variable `knshd` sets itself or the dynamic linker reads. Each name appears once; order is kept otherwise.
pub(crate) fn envelope_env(
    caller: &[(String, String)],
    token: &SessionToken,
    shim_dir: &Path,
    knsh: &Path,
    session_folders: &BTreeMap<String, CanonicalPath>,
    proxy: Option<&ProxyCredential>,
) -> Vec<(String, String)> {
    let shims = shim_dir.to_string_lossy().into_owned();
    let caller_path = caller
        .iter()
        .find(|(name, _)| name == PATH_VAR)
        .map(|(_, value)| without_shims(value, shim_dir));
    let path = match caller_path.as_deref() {
        Some("") | None => shims,
        Some(rest) => format!("{shims}:{rest}"),
    };
    let mut own = vec![
        (PATH_VAR.to_owned(), path),
        (SHELL_VAR.to_owned(), knsh.to_string_lossy().into_owned()),
        (SESSION_TOKEN_VAR.to_owned(), token.encode().expose().clone()),
    ];
    own.extend(proxy_env(proxy));
    let reserved = |name: &str| {
        name == SESSION_TOKEN_VAR
            || is_proxy_var(name)
            || read_by_dynamic_linker(name)
            || own.iter().any(|(own_name, _)| own_name == name)
    };
    let preset = session_folders
        .iter()
        .filter(|(name, _)| !reserved(name))
        .map(|(name, folder)| (name.clone(), folder.as_path().to_string_lossy().into_owned()));
    let mut env: Vec<(String, String)> = caller
        .iter()
        .filter(|(name, _)| !reserved(name) && !session_folders.contains_key(name))
        .cloned()
        .collect();
    env.extend(preset);
    env.extend(own);
    env
}

/// Permission bits of a preset's `[env]` folder: owner-only, as the CLIs ask of their temporary folders.
const ENV_FOLDER_MODE: u32 = 0o700;

/// Whether every session folder (FR-AGT-33, [`Profile::session_folders`]) is ready: created `0700` if missing, and
/// otherwise a directory (not a symlink) owned by `uid`, its mode set to `0700`. Only the folder itself is created,
/// never its parents: the loader already resolved the parent below an existing variable with no symlink on the way.
fn env_folders_ready(fs: &dyn Fs, folders: &BTreeMap<String, CanonicalPath>, uid: u32) -> bool {
    folders
        .values()
        .all(|folder| env_folder_ready(fs, folder.as_path(), uid))
}

fn env_folder_ready(fs: &dyn Fs, folder: &Path, uid: u32) -> bool {
    if matches!(fs.metadata(folder), Err(error) if error.is_not_found()) {
        // A racing creator is fine: what is there is checked below either way.
        let _ = fs.create_dir(folder, ENV_FOLDER_MODE);
    }
    match fs.metadata(folder) {
        // `metadata` does not follow a final symlink, so a link put in the folder's place is refused here.
        Ok(meta) if meta.kind == FileKind::Directory && meta.uid == uid => {
            meta.mode == ENV_FOLDER_MODE || fs.set_mode(folder, ENV_FOLDER_MODE).is_ok()
        }
        Ok(_) | Err(_) => false,
    }
}

/// The envelope profile (module documentation, "The envelope"): `profile`, as resolved with its preset, compiled for
/// the envelope of `session_id`. Besides the trusted and system folders it may run exactly the CLI (`program`) and
/// `knsh`, which the shims link to; with `proxy_port`, it may also connect to the proxy. Pure: the same input gives
/// the same bytes.
pub(crate) fn envelope_profile(
    session_id: SessionId,
    profile: &Profile,
    home: &CanonicalPath,
    program: &CanonicalPath,
    knsh: &CanonicalPath,
    proxy_port: Option<NonZeroU16>,
) -> SbplText {
    let executables = [program.clone(), knsh.clone()];
    compile(&ProfileInput {
        session: session_id,
        command: CommandTag::Envelope,
        profile,
        home,
        executables: &executables,
        proxy_port,
    })
}

/// `-32602`.
fn invalid_params() -> RpcError {
    RpcError::new(ErrorCode::InvalidParams)
}

/// `-32603`, with no reason: failures inside the engine never reach the caller.
fn internal_error() -> RpcError {
    RpcError::new(ErrorCode::InternalError)
}

/// The real [`Launcher`]: compiles the envelope profile and starts the CLI through `knsh-exec` (FR-AGT-03,
/// FR-SBX-01), as lines are started (`spawn.rs`), with the profile compiled for an envelope
/// ([`CommandTag::Envelope`]: it may connect to `agent.sock`, never to `user.sock`).
pub(crate) struct TrampolineLauncher {
    /// Starts, signals and reaps envelopes.
    pub(crate) processes: Arc<dyn Processes>,
    /// Where compiled profiles are written.
    pub(crate) files: ProfileFiles,
    /// The `knsh-exec` binary.
    pub(crate) trampoline: PathBuf,
    /// The user's canonical home: fixed denies and endpoint sockets are below it.
    pub(crate) home: CanonicalPath,
    /// The `knsh` binary, canonical: the envelope's `SHELL` and the shims' target, so the envelope may run it.
    pub(crate) knsh: CanonicalPath,
}

/// A started [`TrampolineLauncher`] envelope.
struct TrampolineEnvelope {
    group: ProcessGroupId,
    /// The trampoline's status pipe (`spawn.rs`, step 5).
    status: std::io::PipeReader,
    /// The profile file, kept until the envelope ends.
    _compiled: CompiledProfile,
}

impl Envelope for TrampolineEnvelope {
    fn group(&self) -> ProcessGroupId {
        self.group
    }

    fn ran(mut self: Box<Self>) -> bool {
        matches!(read_status(&mut self.status), Ok(None))
    }
}

impl Launcher for TrampolineLauncher {
    fn processes(&self) -> Arc<dyn Processes> {
        Arc::clone(&self.processes)
    }

    fn launch(&self, launch: Launch<'_>) -> Result<Box<dyn Envelope>, LaunchError> {
        let text = envelope_profile(
            launch.session_id,
            launch.profile,
            &self.home,
            launch.program,
            &self.knsh,
            launch.proxy_port,
        );
        let compiled = self
            .files
            .write(&launch.profile.name, &text)
            .map_err(|_| LaunchError::ProfileFile)?;
        let (status, status_writer) = std::io::pipe().map_err(|_| LaunchError::Spawn)?;
        let status_writer = SharedFd::new(OwnedFd::from(status_writer));
        let [stdin, stdout, stderr] = launch.stdio;
        let mut request = SpawnRequest::new(&self.trampoline)
            .arg("--status-fd")
            .arg(status_writer.as_raw_fd().to_string())
            .arg("--profile")
            .arg(compiled.path())
            .arg("--interpreter")
            .arg(launch.profile.exec.bash.as_path())
            .arg("--line")
            .arg(EXEC_PROGRAM)
            .arg("--arg")
            .arg(launch.program.as_path());
        for arg in launch.args {
            request = request.arg("--arg").arg(arg);
        }
        request.env = launch
            .env
            .into_iter()
            .map(|(name, value)| (name.into(), value.into()))
            .collect();
        request.cwd = Some(launch.cwd.as_path().to_path_buf());
        request.inherit = vec![status_writer];
        request.stdio = passed(stdin, stdout, stderr);
        let spawned = self.processes.spawn(&request);
        // This process's copies of the caller's descriptors and of the status pipe's write end close here, so the
        // status read sees end of file once the trampoline has exec'd or exited.
        drop(request);
        let group = spawned.map_err(|_| LaunchError::Spawn)?;
        Ok(Box::new(TrampolineEnvelope {
            group,
            status,
            _compiled: compiled,
        }))
    }
}

/// `session.start_agent` when no launcher could be built (no `knsh-exec` beside `knshd`, no usable home): every call
/// is `-32005` for the sandbox and its descriptors are closed unused, as for `exec.*` (fail closed, FR-AGT-06).
pub(crate) fn unserved_handlers() -> Handlers {
    let handler: Handler = Arc::new(|call: &Call<'_>| {
        drop(call.descriptors.take());
        Err(capability_unavailable("sandbox"))
    });
    [(START_AGENT, handler)].into_iter().collect()
}

#[cfg(test)]
mod tests;
