//! Per-user daemon and supervisor.
//!
//! Endpoints, the supervisor, the event bus and the wiring between services.
//!
//! # Boundaries
//!
//! Thin: logic lives in the library crates. The supervisor is the only process that starts agent commands, always
//! through `knsh-exec`.
//!
//! # Specification
//!
//! - `specs/02-architecture/process-model.md`
//! - `specs/02-architecture/endpoints.md`
//! - `specs/02-architecture/system-overview.md`
//! - `specs/09-reference/file-locations.md`, NFR-PRIV-04, NFR-SEC-08 (engine directories, KNSH-011)
//! - NFR-REL-03, `specs/04-non-functional-requirements/security.md` "squats its endpoints" (launchd agent, KNSH-012)
//! - `specs/06-api/README.md`, `specs/06-api/wire-format.md`, NFR-SEC-07 (connection server and dispatcher, KNSH-013)
//! - `specs/06-api/handshake.md`, `specs/05-models/capabilities.md`, NFR-SEC-10, NFR-REL-08 (`hello`, method
//!   catalogue and capability probe, KNSH-014; the sandbox probe through `knsh-exec`, FR-AGT-06, KNSH-046)
//! - `specs/06-api/user-socket.md#records`, FR-REC-02, FR-REC-08, NFR-REL-05 (record store, `records.query` and
//!   `records.output`, KNSH-016)
//! - FR-REC-07, FR-REC-10, NFR-PRIV-03 (record retention and `records.forget`, KNSH-017)
//! - `specs/05-models/event.md`, FR-EVT-01 to FR-EVT-04, FR-EVT-07, `specs/06-api/user-socket.md#events` (event bus,
//!   `events.subscribe` and `events.unsubscribe`, KNSH-018)
//! - `specs/06-api/user-socket.md#human-sessions`, FR-SES-21, FR-SES-24, FR-SES-25, FR-REC-09, NFR-PRIV-05 (human
//!   sessions, telemetry and `session.info`, KNSH-021)
//! - `specs/06-api/agent-socket.md#policycheck`, FR-POL-70 (`policy.check` dry runs, KNSH-043)
//! - FR-POL-40 to FR-POL-42, NFR-SEC-04, `specs/06-api/user-socket.md#policyedit` (signed policy files,
//!   `policy.invalid`, and `policy.read` and `policy.edit` for `knsh policy edit`, KNSH-065)
//! - FR-SBX-07 (compiled profile files named by hash, collected when unused, KNSH-045)
//! - FR-SBX-06, FR-SBX-08, decision 9 (sandbox violation reader, KNSH-047)
//! - FR-AGT-23, FR-SES-02, NFR-SEC-02, `specs/06-api/agent-socket.md` (`agent.sock`: session tokens, the envelope
//!   registry and the audit-token fallback, KNSH-048)
//! - FR-LC-01, FR-LC-14, FR-LC-16, FR-OUT-04, `specs/06-api/agent-socket.md#execrun`, `specs/06-api/wire-format.md`
//!   (receiving `exec.run` from `knsh -c` with its stdio passed as descriptors, KNSH-049)
//! - FR-AUTH-40 to FR-AUTH-43, `specs/06-api/user-socket.md#approvals` (`approval.list`, `approval.approve` and
//!   `approval.deny`, KNSH-066)
//! - FR-AUTH-12 – FR-AUTH-14, NFR-SEC-01, `specs/06-api/control-service.md` (the XPC control service with peer
//!   verification, KNSH-067)
//! - FR-AUTH-01, FR-AUTH-02, FR-AUTH-10, FR-AUTH-11 (`authority.trust` and `authority.register`, KNSH-068)
//! - FR-AUTH-20 – FR-AUTH-24, FR-EVT-06, FR-LC-41, FR-POL-62, `specs/06-api/control-service.md#decision-protocol`
//!   (the decision protocol with the authority, KNSH-069)
//!
//! On start it prepares the engine directories (KNSH-011) and takes its sockets from launchd ([`endpoints`],
//! KNSH-012). It then serves them ([`server`], KNSH-013): a kqueue accept loop hands each connection to its own
//! thread, which reads frames ([`connection`]) and dispatches JSON-RPC methods through per-endpoint tables
//! ([`dispatch`]), generated from the method catalogue and the capabilities probed once at start ([`probe`],
//! [`hello`], KNSH-014). It opens the record store in the engine data directory and answers `records.query` and
//! `records.output` from it ([`records`], KNSH-016), and `records.forget` on `user.sock`; the store applies record
//! retention on its own thread, at start and hourly (KNSH-017). The event bus ([`events`], KNSH-018) numbers and
//! buffers each session's events and serves `events.subscribe` and `events.unsubscribe`; a subscribed connection
//! gets a second thread that writes its events as notifications. The session registry ([`sessions`], KNSH-021) holds
//! recorded human sessions, each bound to the `knsh` connection that started it and ended when it closes; their
//! telemetry becomes records and events, and a recording session keeps `knshd` alive. `policy.check` ([`policy`],
//! KNSH-043) answers what a profile would decide for a line, reading profiles and binaries but writing, publishing and
//! running nothing. Compiled sandbox profiles are written to private files named by their hash ([`profiles`],
//! KNSH-045), and the ones an earlier run left behind are removed at start. The sandbox violation reader
//! ([`violations`], KNSH-047) streams the system's sandbox denials, publishes them as `sandbox.violation` and
//! attaches them to the records their tags name; `hello` reports whether it is live. `agent.sock` is served too
//! ([`agents`], KNSH-048): each connection is bound at `hello` to one agent session, by its session token or, without
//! one, by the caller's audit token and the envelope it descends from, and every later call acts for that session
//! only. Descriptors passed with a request (`SCM_RIGHTS`) reach that request's call, and only `exec.run` takes them
//! ([`exec`], KNSH-049): it checks the forwarded line and hands it, without the shims in `PATH`, to the supervisor,
//! which later stories provide. It exits after ten idle minutes ([`lifetime`]) or when launchd stops it, finishing
//! in-flight requests and committing pending writes first. A session can be paused or taken over by a human
//! ([`holds`], KNSH-054): its new lines are held with `-32007`, and a pause stops its envelope's and running lines'
//! process groups. Policy files are accepted only with `knshd`'s signature, made with a Keychain key after Touch ID or
//! the password ([`policy_edit`], KNSH-065). Without an authority, an ask waits for `knsh approve` (after Touch ID or
//! the password, shown by `knshd`) or `knsh deny` from another terminal, and is denied at the timeout otherwise
//! ([`approvals`], KNSH-066). The XPC control service ([`control`], KNSH-067) is served on the Mach name the launch
//! agent declares: every peer must meet the trusted authority's code-signing requirement, and every message's sender
//! is checked again (hardened runtime, not debuggable, minimum version) before the message is read; with no trusted
//! authority every connection is refused. Verified messages are served like socket messages, through the same
//! dispatcher on the control endpoint. The user trusts an authority with `knsh authority trust` (`authority.trust`,
//! after Touch ID or the password; [`authority`], KNSH-068): the record is a Keychain item only `knshd` reads, and the
//! running control service switches to it at once. One verified connection at a time may register as the authority,
//! publishing `authority.connected` and, when it ends, `authority.disconnected`. While one is registered, every ask
//! is sent to it as `decision.requested` and waits for its `decision.respond`, the 90 s timeout or the caller leaving
//! ([`decisions`], KNSH-069); requests still pending when it reconnects are sent again, and a `grant` in an answer
//! becomes a live grant ([`grants`]) that later lines are evaluated with.

#![deny(missing_docs, unsafe_op_in_unsafe_fn, rust_2018_idioms)]
#![warn(clippy::pedantic)]
#![forbid(unsafe_code)]

// Platform-neutral, but only the macOS server uses them until the Linux backend exists.
// Owned by the session registry, so built where it is.
#[cfg(target_os = "macos")]
mod agents;
// Standalone approvals (KNSH-066): pending asks answered with `knsh approve` after the LocalAuthentication prompt.
#[cfg(target_os = "macos")]
mod approvals;
// The authority (KNSH-068): `authority.trust` after Touch ID or the password, and the single `authority.register`.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
mod authority;
// Reading a line's output (KNSH-053): platform-neutral, used by the macOS spawner.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
mod capture;
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
mod connection;
// The XPC control service's JSON-RPC side (KNSH-067): verified messages served through the shared dispatcher.
#[cfg(target_os = "macos")]
mod control;
// The decision protocol with the authority (KNSH-069): `decision.requested`, `decision.respond`, cancellation and
// re-sending on reconnection.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
mod decisions;
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
mod dispatch;
#[cfg(target_os = "macos")]
mod endpoints;
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
mod events;
// The live grants (KNSH-042 model), created by the authority's answers (KNSH-069) and consulted for every agent line.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
mod grants;
// Reads the session binding, so built where the session registry is. Served with the supervisor (KNSH-051).
#[cfg(target_os = "macos")]
mod exec;
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
mod hello;
// Policy the authority pushes (KNSH-071), read by the profile loader in place of files.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
mod pushed;
// The authority's policy and grant methods on the control service (KNSH-071).
#[cfg(target_os = "macos")]
mod policy_admin;
// The state store (KNSH-071): grants and pushed policy, saved atomically and owner-only.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
mod state;
// The authority's session and recording methods on the control service (KNSH-071).
#[cfg(target_os = "macos")]
mod supervise;
// Pause, resume and human control (KNSH-054): owned by the session registry.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
mod holds;
// The user's `command.proposed` hooks (KNSH-062), run by the supervisor.
#[cfg(target_os = "macos")]
mod hooks;
// Lines started with exec.start (KNSH-053), built with `exec`.
#[cfg(target_os = "macos")]
mod jobs;
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
mod lifetime;
// Reads the session registry, so built where it is.
#[cfg(target_os = "macos")]
mod policy;
// `knsh policy edit` (KNSH-065): signs with the Keychain key after the LocalAuthentication prompt, both macOS only.
#[cfg(target_os = "macos")]
mod policy_edit;
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
mod probe;
// Hashes with CommonCrypto, so built on macOS: the start-up sweep and each supervised line's profile (KNSH-051).
#[cfg(target_os = "macos")]
mod profiles;
// The lifecycle orchestrator (KNSH-050), served with `exec.run` (KNSH-051).
// Envelope and line proxy credentials (KNSH-057, KNSH-059), used by `start_agent` and the spawner.
#[cfg(target_os = "macos")]
mod proxy;
#[cfg(target_os = "macos")]
mod supervisor;
// The spawner behind the orchestrator (KNSH-051): lines through `knsh-exec`, process groups, timeouts.
#[cfg(target_os = "macos")]
mod spawn;
#[cfg(target_os = "macos")]
mod start_agent;
// The record store is built on macOS only until the Linux SQLite backend exists.
#[cfg(target_os = "macos")]
mod records;
#[cfg(target_os = "macos")]
mod server;
// Writes records, so built where the record store is.
#[cfg(target_os = "macos")]
mod sessions;
// The reader is platform-neutral; its record sink is built where the record store is.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
mod violations;

use std::fmt;
use std::process::ExitCode;

use knsh_platform::PlatformError;

/// Why `knshd` could not start. Messages never name a path (`PlatformError` messages carry no input), so they are
/// safe to print and log.
#[derive(Debug)]
enum StartError {
    /// `HOME` is not set.
    NoHome,
    /// `HOME` is not a usable home directory (relative, `/`, or with `.` or `..`).
    BadHome(PlatformError),
    /// The engine directories cannot be made private and excluded (NFR-PRIV-04).
    EngineDirs(PlatformError),
    /// launchd provided no socket: `knshd` was not started through its launch agent.
    NoLaunchdSockets(PlatformError),
    /// The method catalogue and the implemented handlers disagree (a build defect).
    Dispatch(dispatch::BuildError),
    /// The connection server failed to start, failed while serving, or could not commit pending writes on exit.
    #[cfg(target_os = "macos")]
    Serve(server::ServeError),
    /// This platform has no backend yet.
    #[cfg_attr(target_os = "macos", allow(dead_code))]
    Unsupported,
}

impl fmt::Display for StartError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoHome => f.write_str("HOME is not set"),
            Self::BadHome(error) => write!(f, "unusable HOME: {error}"),
            Self::EngineDirs(error) => write!(f, "cannot prepare engine directories: {error}"),
            Self::NoLaunchdSockets(error) => write!(
                f,
                "no sockets from launchd ({error}); knshd only runs from its launch agent, see 'knsh daemon install'"
            ),
            Self::Dispatch(error) => write!(f, "cannot build dispatch tables: {error}"),
            #[cfg(target_os = "macos")]
            Self::Serve(error) => write!(f, "{error}"),
            Self::Unsupported => f.write_str("this platform is not supported yet"),
        }
    }
}

impl StartError {
    /// A fixed name for the failure, for the system log (which accepts only static text).
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    fn kind(&self) -> &'static str {
        match self {
            Self::NoHome => "no_home",
            Self::BadHome(_) => "bad_home",
            Self::EngineDirs(_) => "engine_dirs",
            Self::NoLaunchdSockets(_) => "no_launchd_sockets",
            Self::Dispatch(_) => "dispatch",
            #[cfg(target_os = "macos")]
            Self::Serve(error) => error.kind(),
            Self::Unsupported => "unsupported",
        }
    }
}

/// Entry point. Exits with status 1 and the reason on stderr if `knshd` cannot start: without private engine
/// directories (NFR-PRIV-04) or without launchd's sockets (KNSH-012) it must not run at all.
fn main() -> ExitCode {
    match start() {
        Ok(()) => ExitCode::SUCCESS,
        Err(reason) => {
            // Under launchd stderr is discarded; the reason is also in the system log (see `start`).
            eprintln!("knshd: {reason}");
            ExitCode::FAILURE
        }
    }
}

/// Everything `knshd` does: prepare its directories, take its sockets from launchd, then serve until idle or
/// stopped. Returns `Ok` on an orderly exit, which launchd does not count as a crash: the next connection starts
/// `knshd` again.
#[cfg(target_os = "macos")]
fn start() -> Result<(), StartError> {
    use std::path::Path;
    use std::sync::Arc;

    use knsh_platform::macos::{
        LaunchdSockets, RealFs, SystemClock, SystemPeerCredentials, SystemProcessTree, SystemRandom, UnifiedLog,
        effective_uid,
    };
    use knsh_platform::{EnginePaths, Field, Level, SystemLog, Value, ensure_engine_dirs};

    use crate::events::EventHub;
    use crate::policy::PolicyCheck;
    use crate::records::Records;
    use crate::server::{Config, Exit, Server, Services};
    use crate::sessions::Sessions;
    use crate::violations::{Reader, ReaderStatus};

    let log: Arc<dyn SystemLog> = Arc::new(UnifiedLog::new(c"daemon"));
    let uid = effective_uid();
    let fail = |error: StartError| {
        log.log(
            Level::Error,
            "knshd failed",
            &[Field::new("reason", Value::Static(error.kind()))],
        );
        error
    };

    let prepare = || {
        // `HOME` rather than the password database: the launch agent sets it, and tests point it at an isolated home.
        let home = std::env::var_os("HOME").ok_or(StartError::NoHome)?;
        let paths = EnginePaths::for_home(Path::new(&home)).map_err(StartError::BadHome)?;
        ensure_engine_dirs(&RealFs::new(), &paths, uid).map_err(StartError::EngineDirs)?;
        sweep_profiles(&paths, uid, log.as_ref());
        // Never a fallback bind: without launchd's sockets, knshd does not run (KNSH-012).
        let listeners = endpoints::activate(&LaunchdSockets::new()).map_err(StartError::NoLaunchdSockets)?;
        let clock = Arc::new(SystemClock::new());
        let store = open_store(&paths, uid, &clock, log.as_ref());
        let records = Records::new(store.clone());
        // The event bus with the specified limits (10,000 events per session).
        let random = Arc::new(SystemRandom::new());
        let events = EventHub::new(knsh_core::EventBus::default(), clock.clone(), random.clone());
        // Sandbox denials the system reports, attributed by tag to sessions and records (KNSH-047). Best effort: a
        // reader that cannot start is reported as `sandbox_violations: none` and never blocks anything.
        let reader = start_violation_reader(&paths, clock.clone(), random.clone(), &log, store.clone(), &events);
        // `agent.sock` callers without a token are matched to their envelope through the process table (KNSH-048).
        let processes = Arc::new(SystemProcessTree::new());
        let sessions = Sessions::new(
            store.clone(),
            Arc::clone(&events),
            clock.clone(),
            random.clone(),
            processes,
        );
        let authority = authority_supervision(&paths, uid, &log, &clock, &random, &sessions, &events);
        let mut handlers = records.handlers();
        handlers.extend(events.handlers());
        handlers.extend(sessions.handlers());
        handlers.extend(PolicyCheck::new(Arc::clone(&sessions), authority.profiles.clone()).handlers());
        handlers.extend(policy_editor(&authority.profiles, &log).handlers());
        handlers.extend(authority.handlers);
        let (approvals, decisions) = ask_services(&clock, &random, &log, authority.grants, &mut handlers);
        let (trust, registration) = authority_services(&events, &log, &decisions, &mut handlers);
        // `exec.run` (KNSH-051), listed only when the sandbox probe passes; without `knsh-exec` nothing can run.
        let supervision = Supervision {
            paths: &paths,
            uid,
            log: &log,
            sessions: &sessions,
            profiles: authority.profiles,
            events: &events,
            store,
            clock: clock.clone(),
            random,
            approvals,
            decisions: Arc::clone(&decisions),
        };
        handlers.extend(supervision.handlers());
        // Probed once before serving: every hello reports the same result; a restarted knshd probes again (KNSH-014).
        let probed = probe_this_machine(&paths, clock.clone(), Arc::clone(&log));
        let violation_status = reader.as_ref().map_or_else(ReaderStatus::stopped, Reader::status);
        let dispatcher = hello::dispatcher_with_violations(probed, handlers, violation_status, Arc::clone(&sessions));
        let dispatcher = Arc::new(dispatcher.map_err(StartError::Dispatch)?);
        let (control, control_service) = serve_control(&dispatcher, &log, &trust, registration, &decisions);
        let services = Services {
            dispatcher,
            credentials: Arc::new(SystemPeerCredentials::new()),
            log: Arc::clone(&log),
            own_uid: uid,
            clock,
            // Recording sessions and open connections (sockets or control) keep knshd alive; records commit as written.
            activity: Arc::new(lifetime::AnyActivity(vec![sessions, control])),
            pending: Arc::new(records),
        };
        let server = Server::new(listeners, services, Config::DEFAULT).map_err(StartError::Serve)?;
        server.stop_on_termination_signals().map_err(StartError::Serve)?;
        Ok((server, reader, control_service))
    };
    // `_control` serves the control service until `start` returns; dropping it cancels every control connection.
    let (server, mut reader, _control) = prepare().map_err(fail)?;

    log.log(Level::Notice, "knshd started", &[]);
    let exit = server.run().map_err(|error| fail(StartError::Serve(error)));
    // The `log stream` child must not outlive knshd; pending violations are released to the store first.
    if let Some(reader) = reader.as_mut() {
        reader.stop();
    }
    let reason = match exit? {
        Exit::Idle => "idle",
        Exit::Stopped => "stopped",
    };
    log.log(
        Level::Notice,
        "knshd exiting",
        &[Field::new("reason", Value::Static(reason))],
    );
    Ok(())
}

/// Serves the XPC control service (KNSH-067) on the Mach name the launch agent declares (FR-AUTH-12), verifying every
/// peer against the trusted authority, and dispatching verified messages through the shared `dispatcher`. Without a
/// trust record every connection is refused, but the name is still served: launchd would otherwise keep queueing (and
/// relaunching `knshd` for) messages nobody reads.
///
/// The gate starts from the record in the Keychain (KNSH-068). When the user trusts another authority, `trust`
/// switches the running service to it, closing every connection verified under the old record. A record that cannot
/// be read means nothing is trusted (decision 11).
///
/// Returns the endpoint (its open connections keep `knshd` alive) and the listener, `None`, logged, if it cannot be
/// created: the engine works fully without an authority.
#[cfg(target_os = "macos")]
fn serve_control(
    dispatcher: &std::sync::Arc<dispatch::Dispatcher>,
    log: &std::sync::Arc<dyn knsh_platform::SystemLog>,
    trust: &std::sync::Arc<authority::AuthorityTrust>,
    registration: std::sync::Arc<authority::Registration>,
    decisions: &std::sync::Arc<decisions::Decisions>,
) -> (
    std::sync::Arc<control::ControlEndpoint>,
    Option<std::sync::Arc<knsh_platform::macos::XpcControlService>>,
) {
    use std::sync::Arc;

    use knsh_platform::launchd::CONTROL_SERVICE;
    use knsh_platform::macos::XpcControlService;
    use knsh_platform::{Level, PeerGate};

    let control = control::ControlEndpoint::new(Arc::clone(dispatcher), Arc::clone(log), registration);
    // `decision.requested` and `decision.cancelled` reach the authority through the control service (KNSH-069). A
    // courier that cannot start is logged; requests then time out and are denied (fail closed).
    let link: Arc<dyn decisions::AuthorityLink> = control.clone();
    let _ = decisions.attach(Arc::downgrade(&link));
    let gate = PeerGate::new(trust.current());
    let handler: Arc<dyn knsh_platform::ControlHandler> = control.clone();
    let service = XpcControlService::listen(CONTROL_SERVICE, gate, handler)
        .ok()
        .map(Arc::new);
    match &service {
        Some(service) => {
            // Weak: the callback must not keep the listener alive after `start` returns and drops it.
            let service = Arc::downgrade(service);
            let log = Arc::clone(log);
            trust.when_trusted(Arc::new(move |record| {
                let Some(service) = service.upgrade() else {
                    return;
                };
                if service.set_gate(PeerGate::new(Some(record.clone()))).is_err() {
                    // Fail closed: the user replaced the old record, so the old gate must not stay in force. A gate
                    // with no trust compiles nothing and cannot fail; every connection is refused until a restart.
                    let _ = service.set_gate(PeerGate::new(None));
                    log.log(
                        Level::Error,
                        "new authority trust not applied until knshd restarts: no authority is trusted",
                        &[],
                    );
                }
            }));
        }
        None => log.log(Level::Error, "control service unavailable", &[]),
    }
    (control, service)
}

/// The trusted authority (KNSH-068), with its methods added to `handlers`: `authority.trust` on `user.sock`
/// stores the record as a Keychain item only knshd can read (FR-AUTH-11) after knshd's own Touch ID or password
/// prompt (FR-AUTH-10); `authority.register` on the control service admits one authority at a time and publishes
/// its arrival and departure on `events` (FR-AUTH-01, FR-AUTH-02); `decision.respond` answers the requests
/// `decisions` sends it (KNSH-069), which is told of every registration so it can re-send them (FR-AUTH-24).
#[cfg(target_os = "macos")]
fn authority_services(
    events: &std::sync::Arc<events::EventHub>,
    log: &std::sync::Arc<dyn knsh_platform::SystemLog>,
    decisions: &std::sync::Arc<decisions::Decisions>,
    handlers: &mut dispatch::Handlers,
) -> (
    std::sync::Arc<authority::AuthorityTrust>,
    std::sync::Arc<authority::Registration>,
) {
    use std::sync::Arc;

    use knsh_platform::macos::{KeychainTrustStore, LocalAuthentication};

    let trust = authority::AuthorityTrust::new(
        Arc::new(KeychainTrustStore::new()),
        Arc::new(LocalAuthentication::new()),
        Arc::clone(log),
    );
    let registration = authority::Registration::new(Arc::clone(events), Arc::clone(log));
    registration.watch(decisions.clone());
    handlers.extend(trust.handlers());
    handlers.extend(registration.handlers());
    handlers.extend(decisions.handlers());
    (trust, registration)
}

/// Runs the capability probe on this machine (KNSH-014). The sandbox check runs the `knsh-exec` installed next to
/// this binary, the same one agent lines will use, and keeps its files in the private run directory (KNSH-046).
#[cfg(target_os = "macos")]
fn probe_this_machine(
    paths: &knsh_platform::EnginePaths,
    clock: std::sync::Arc<knsh_platform::macos::SystemClock>,
    log: std::sync::Arc<dyn knsh_platform::SystemLog>,
) -> probe::Probed {
    use std::sync::Arc;

    use knsh_platform::macos::{RealFs, SystemProbes, SystemProcesses, SystemRandom};

    use crate::probe::{PROBE_TIMEOUT, Probes, SandboxProbe};

    probe::probe(&Probes {
        processes: Arc::new(SystemProcesses::new()),
        system: Arc::new(SystemProbes::new()),
        clock,
        log,
        timeout: PROBE_TIMEOUT,
        sandbox: SandboxProbe {
            trampoline: std::env::current_exe()
                .ok()
                .and_then(|exe| SandboxProbe::trampoline_beside(&exe)),
            dir: paths.run_dir(),
            fs: Arc::new(RealFs::new()),
            random: Arc::new(SystemRandom::new()),
        },
    })
}

/// Starts the sandbox violation reader (KNSH-047): `log stream` as this user, its canary file in the private run
/// directory, violations published to `events` and attached to records in `store`. `None`, logged, if it cannot
/// start; `hello` then reports `sandbox_violations: none`.
#[cfg(target_os = "macos")]
fn start_violation_reader(
    paths: &knsh_platform::EnginePaths,
    clock: std::sync::Arc<knsh_platform::macos::SystemClock>,
    random: std::sync::Arc<knsh_platform::macos::SystemRandom>,
    log: &std::sync::Arc<dyn knsh_platform::SystemLog>,
    store: Option<knsh_store::RecordStore>,
    events: &std::sync::Arc<events::EventHub>,
) -> Option<violations::Reader> {
    use std::sync::Arc;

    use knsh_platform::macos::UnifiedLogDenials;

    let unavailable = || log.log(knsh_platform::Level::Error, "sandbox violation reader unavailable", &[]);
    let Ok(source) = UnifiedLogDenials::new(&paths.run_dir()) else {
        unavailable();
        return None;
    };
    let effects = violations::Effects {
        source: Arc::new(source),
        clock,
        random,
        log: Arc::clone(log),
    };
    let sink = violations::RecordViolations::new(store, Arc::clone(events), Arc::clone(log));
    let reader = violations::Reader::start(effects, sink, violations::Config::DEFAULT).ok();
    if reader.is_none() {
        unavailable();
    }
    reader
}

/// The profile loader `policy.check`, `policy.edit` and the supervisor share. Profiles and binaries are read through
/// the real filesystem. `TMPDIR` is set by launchd for the agent; without it `${TMPDIR}` is the system's `/tmp`.
///
/// Policy files are accepted only with knshd's signature (KNSH-065, FR-POL-40): the key lives in the login keychain
/// and is read once, then kept in memory; it is created on the first `knsh policy edit`.
#[cfg(target_os = "macos")]
fn profile_loader(
    paths: &knsh_platform::EnginePaths,
    random: std::sync::Arc<knsh_platform::macos::SystemRandom>,
    log: &std::sync::Arc<dyn knsh_platform::SystemLog>,
) -> crate::policy::ProfileLoader {
    use std::sync::Arc;

    use knsh_platform::macos::{KeychainSigningKey, RealFs, hmac_sha256};

    let tmpdir = std::env::var_os("TMPDIR").map_or_else(|| "/tmp".into(), std::path::PathBuf::from);
    let signer = Arc::new(knsh_platform::PolicySigner::new(
        Arc::new(KeychainSigningKey::new()),
        random,
        hmac_sha256,
    ));
    crate::policy::ProfileLoader::new(
        Arc::new(RealFs::new()),
        paths.policies_dir(),
        paths.home().to_path_buf(),
        tmpdir,
        signer,
        Arc::clone(log),
    )
}

/// What [`authority_supervision`] builds.
#[cfg(target_os = "macos")]
struct AuthoritySupervision {
    /// The profile loader, reading pushed snapshots in place of files.
    profiles: crate::policy::ProfileLoader,
    /// The live grants, saved in the state store; every line is evaluated with them.
    grants: std::sync::Arc<grants::GrantStore>,
    /// The control service's `session.*`, `recording.set` and `policy.*` handlers.
    handlers: dispatch::Handlers,
}

/// The state store and what the authority supervises agents with (KNSH-071): the store's grants and pushed policy,
/// restored from the last run and saved on every change (FR-POL-60); the profile loader, reading pushed snapshots
/// before files; and the control service's session, recording, policy and grant methods.
#[cfg(target_os = "macos")]
fn authority_supervision(
    paths: &knsh_platform::EnginePaths,
    uid: u32,
    log: &std::sync::Arc<dyn knsh_platform::SystemLog>,
    clock: &std::sync::Arc<knsh_platform::macos::SystemClock>,
    random: &std::sync::Arc<knsh_platform::macos::SystemRandom>,
    sessions: &std::sync::Arc<sessions::Sessions>,
    events: &std::sync::Arc<events::EventHub>,
) -> AuthoritySupervision {
    use std::sync::Arc;

    use knsh_platform::Clock;
    use knsh_platform::macos::RealFs;

    let (state, restored) = state::StateStore::open(Arc::new(RealFs::new()), paths.state_file(), uid, Arc::clone(log));
    let pushed = pushed::PushedPolicies::new(Arc::clone(&state), clock.clone(), restored.snapshots);
    let grants = grants::GrantStore::persisted(state, Arc::clone(log), restored.grants, clock.now().ok());
    let profiles = profile_loader(paths, random.clone(), log).with_pushed(Arc::clone(&pushed));
    let mut handlers = supervise::Supervise::new(Arc::clone(sessions), profiles.clone()).handlers();
    handlers.extend(
        policy_admin::PolicyAdmin::new(policy_admin::PolicyAdminParts {
            profiles: profiles.clone(),
            pushed,
            grants: Arc::clone(&grants),
            sessions: Arc::clone(sessions),
            events: Arc::clone(events),
            clock: clock.clone(),
            random: random.clone(),
            log: Arc::clone(log),
        })
        .handlers(),
    );
    AuthoritySupervision {
        profiles,
        grants,
        handlers,
    }
}

/// `policy.read` and `policy.edit` for `knsh policy edit`: knshd shows the Touch ID or password prompt itself before
/// signing (FR-POL-41).
#[cfg(target_os = "macos")]
fn policy_editor(
    profiles: &crate::policy::ProfileLoader,
    log: &std::sync::Arc<dyn knsh_platform::SystemLog>,
) -> std::sync::Arc<crate::policy_edit::PolicyEditor> {
    use std::sync::Arc;

    use knsh_platform::macos::{LocalAuthentication, sha256};

    crate::policy_edit::PolicyEditor::new(
        profiles.clone(),
        Arc::new(LocalAuthentication::new()),
        sha256,
        Arc::clone(log),
    )
}

/// Where asks go. Standalone approvals (KNSH-066): asks wait there when no authority is connected, and
/// `knsh approve` answers them after knshd's own Touch ID or password prompt (FR-AUTH-41). The decision protocol
/// (KNSH-069): asks go to the registered authority, and a grant in its answer joins `grants`, the live grants saved in
/// the state store (KNSH-071). The approval
/// methods are added to `handlers`; `decision.respond` is added with the authority's ([`authority_services`]).
#[cfg(target_os = "macos")]
fn ask_services(
    clock: &std::sync::Arc<knsh_platform::macos::SystemClock>,
    random: &std::sync::Arc<knsh_platform::macos::SystemRandom>,
    log: &std::sync::Arc<dyn knsh_platform::SystemLog>,
    grants: std::sync::Arc<grants::GrantStore>,
    handlers: &mut dispatch::Handlers,
) -> (
    std::sync::Arc<crate::approvals::Approvals>,
    std::sync::Arc<crate::decisions::Decisions>,
) {
    use std::sync::Arc;

    let approvals = crate::approvals::Approvals::with_default_timeout(
        clock.clone(),
        random.clone(),
        Arc::new(knsh_platform::macos::LocalAuthentication::new()),
        Arc::clone(log),
    );
    let decisions =
        crate::decisions::Decisions::with_default_timeout(clock.clone(), random.clone(), Arc::clone(log), grants);
    handlers.extend(approvals.handlers());
    (approvals, decisions)
}

/// The record store. One that cannot be opened (newer schema, foreign or unsafe file) is reported and left
/// untouched; knshd still serves, so a human session is never blocked by it, and the record methods answer -32603.
/// Retention uses the defaults (30 days or 2 GB); per-profile periods arrive with profile loading.
#[cfg(target_os = "macos")]
fn open_store(
    paths: &knsh_platform::EnginePaths,
    uid: u32,
    clock: &std::sync::Arc<knsh_platform::macos::SystemClock>,
    log: &dyn knsh_platform::SystemLog,
) -> Option<knsh_store::RecordStore> {
    use knsh_platform::{Field, Level, Value};
    use knsh_store::{DATABASE_FILE, RecordStore, StoreConfig};

    let opened = RecordStore::open(
        &knsh_platform::macos::RealFs::new(),
        &paths.data_dir().join(DATABASE_FILE),
        uid,
        clock.clone(),
        StoreConfig::default(),
    );
    match opened {
        Ok(store) => Some(store),
        Err(error) => {
            log.log(
                Level::Error,
                "record store unavailable",
                &[Field::new("reason", Value::Static(error.kind()))],
            );
            None
        }
    }
}

/// What the lifecycle orchestrator and its spawner are built from (KNSH-050, KNSH-051).
#[cfg(target_os = "macos")]
struct Supervision<'a> {
    paths: &'a knsh_platform::EnginePaths,
    uid: u32,
    log: &'a std::sync::Arc<dyn knsh_platform::SystemLog>,
    sessions: &'a std::sync::Arc<sessions::Sessions>,
    profiles: policy::ProfileLoader,
    events: &'a std::sync::Arc<events::EventHub>,
    store: Option<knsh_store::RecordStore>,
    clock: std::sync::Arc<knsh_platform::macos::SystemClock>,
    random: std::sync::Arc<knsh_platform::macos::SystemRandom>,
    /// Standalone approvals (KNSH-066), shared with the `approval.*` handlers.
    approvals: std::sync::Arc<approvals::Approvals>,
    /// The authority, asked whenever one is registered (KNSH-069), shared with `decision.respond`; also holds the
    /// live grants every line is evaluated with.
    decisions: std::sync::Arc<decisions::Decisions>,
}

/// Starts the network proxy (KNSH-059) on a loopback port with the host rules, the system resolver and address
/// checks as its gate (KNSH-060), reporting refusals to the system log and as `proxy.denied` on `events`. One that
/// cannot start is logged, and envelopes and lines then get no proxy settings and no proxy port
/// ([`proxy::NoProxy`]): they reach only their loopback ports (fail closed).
#[cfg(target_os = "macos")]
fn start_proxy(
    clock: std::sync::Arc<knsh_platform::macos::SystemClock>,
    random: std::sync::Arc<knsh_platform::macos::SystemRandom>,
    log: &std::sync::Arc<dyn knsh_platform::SystemLog>,
    events: &std::sync::Arc<events::EventHub>,
) -> std::sync::Arc<dyn proxy::ProxyIssuer> {
    use std::sync::Arc;

    use knsh_platform::macos::SystemResolver;
    use knsh_platform::{Field, Level, Value};
    use knsh_proxy::{Config, HostRules, Parts, Proxy};

    let rules = Arc::new(HostRules::new(Arc::new(SystemResolver::new())));
    let report = proxy::NetworkReport::new(Arc::clone(log), Arc::clone(events));
    let started = Proxy::start(
        Config::DEFAULT,
        Parts {
            gate: Arc::clone(&rules) as Arc<dyn knsh_proxy::ConnectionGate>,
            report: Arc::clone(&report) as Arc<dyn knsh_proxy::ProxyReport>,
            random,
            clock,
        },
    );
    match started {
        Ok(running) => Arc::new(proxy::LiveProxy::new(running, rules, report)),
        Err(error) => {
            log.log(
                Level::Error,
                "network proxy unavailable",
                &[Field::new("reason", Value::Static(error.kind()))],
            );
            Arc::new(proxy::NoProxy)
        }
    }
}

#[cfg(target_os = "macos")]
impl Supervision<'_> {
    /// The `exec.run` handler: the orchestrator over the real spawner, the `knsh-exec` installed next to this binary
    /// (the one the sandbox probe checked), with the user's hooks ([`hooks::HookRunner`], KNSH-062). A line policy
    /// asks about goes to the registered authority ([`decisions::Decisions`], KNSH-069), or, with none registered,
    /// waits for `knsh approve` or `knsh deny` ([`approvals::Approvals`], KNSH-066); either way it is denied at the
    /// timeout. When `knsh-exec` or a canonical home cannot be found it is logged, and every call is `-32005`
    /// ([`exec::unserved_handlers`]).
    fn exec_run_handlers(self, proxy: std::sync::Arc<dyn proxy::ProxyIssuer>) -> dispatch::Handlers {
        use std::sync::Arc;

        use knsh_core::CanonicalPath;
        use knsh_platform::macos::{RealFs, SystemProcesses, sha256};

        use crate::probe::SandboxProbe;
        use crate::spawn::{Limits, TrampolineSpawner};
        use crate::supervisor::{Lifecycle, Parts};

        let trampoline = std::env::current_exe()
            .ok()
            .and_then(|exe| SandboxProbe::trampoline_beside(&exe));
        let home = std::fs::canonicalize(self.paths.home())
            .ok()
            .and_then(|home| CanonicalPath::new(home).ok());
        let (Some(trampoline), Some(home)) = (trampoline, home) else {
            self.log.log(
                knsh_platform::Level::Error,
                "supervisor unavailable: exec.run not served",
                &[],
            );
            return exec::unserved_handlers();
        };
        // KNSH-062: the user's hooks, read from the configuration file for every agent line.
        let hook_runner = hooks::HookRunner::new(
            Arc::new(RealFs::new()),
            Arc::new(SystemProcesses::new()),
            self.paths.config_file(),
            home.as_path().to_path_buf(),
            self.uid,
        );
        let files = profiles::ProfileFiles::new(Arc::new(RealFs::new()), self.paths.profiles_dir(), self.uid, sha256);
        let spawner = TrampolineSpawner {
            processes: Arc::new(SystemProcesses::new()),
            clock: self.clock.clone(),
            files,
            log: Arc::clone(self.log),
            trampoline,
            home,
            limits: Limits::DEFAULT,
            proxy,
        };
        let lifecycle = Lifecycle::new(Parts {
            sessions: Arc::clone(self.sessions),
            profiles: self.profiles,
            events: Arc::clone(self.events),
            store: self.store,
            clock: self.clock,
            random: self.random,
            hooks: Arc::new(hook_runner),
            grants: self.decisions.grants(),
            authority: self.decisions,
            approvals: self.approvals,
            spawner: Arc::new(spawner),
            // Secret redaction arrives with KNSH-091; the hook is already on the capture path.
            redaction: Arc::new(knsh_core::NoOutputRedaction),
        });
        exec::ExecRun::new(lifecycle, self.paths.shim_dir()).handlers()
    }
}

#[cfg(target_os = "macos")]
impl Supervision<'_> {
    /// `session.start_agent` (KNSH-056) and `exec.*` (KNSH-050 to KNSH-053), over the same paths, sessions,
    /// profiles and clock.
    fn handlers(self) -> dispatch::Handlers {
        // One proxy issues every envelope's and line's credentials (KNSH-059).
        let proxy = start_proxy(self.clock.clone(), self.random.clone(), self.log, self.events);
        let mut handlers = self.start_agent_handlers(&proxy);
        handlers.extend(self.exec_run_handlers(proxy));
        handlers
    }

    /// The `session.start_agent` handler (KNSH-056), launching envelopes through the `knsh-exec` beside `knshd`
    /// with the `knsh` beside it as their `SHELL`. Without either binary or a canonical home it is logged, and every
    /// call is `-32005` for the sandbox ([`start_agent::unserved_handlers`]).
    fn start_agent_handlers(&self, proxy: &std::sync::Arc<dyn proxy::ProxyIssuer>) -> dispatch::Handlers {
        use std::sync::Arc;

        use knsh_core::CanonicalPath;
        use knsh_platform::macos::{RealFs, SystemProcesses, sha256};

        use crate::probe::SandboxProbe;
        use crate::start_agent::{AgentStarter, TrampolineLauncher};

        let exe = std::env::current_exe().ok();
        let trampoline = exe.as_deref().and_then(SandboxProbe::trampoline_beside);
        let canonical = |path: &std::path::Path| {
            std::fs::canonicalize(path)
                .ok()
                .and_then(|path| CanonicalPath::new(path).ok())
        };
        let knsh = exe
            .as_deref()
            .and_then(std::path::Path::parent)
            .and_then(|dir| canonical(&dir.join("knsh")));
        let home = canonical(self.paths.home());
        let (Some(trampoline), Some(knsh), Some(home)) = (trampoline, knsh, home) else {
            self.log.log(
                knsh_platform::Level::Error,
                "envelope launcher unavailable: session.start_agent not served",
                &[],
            );
            return start_agent::unserved_handlers();
        };
        let launcher = TrampolineLauncher {
            processes: Arc::new(SystemProcesses::new()),
            files: profiles::ProfileFiles::new(Arc::new(RealFs::new()), self.paths.profiles_dir(), self.uid, sha256),
            trampoline,
            home,
            knsh: knsh.clone(),
        };
        AgentStarter::new(
            Arc::clone(self.sessions),
            self.profiles.clone(),
            Arc::new(launcher),
            Arc::clone(proxy),
            self.clock.clone(),
            self.paths.shim_dir(),
            knsh.into_path_buf(),
        )
        .handlers()
    }
}

/// Removes the compiled profile files an earlier run left behind: no line runs yet, so none is in use (FR-SBX-07). A
/// failed sweep only leaves files behind and never blocks a human session, so it is logged, not fatal.
#[cfg(target_os = "macos")]
fn sweep_profiles(paths: &knsh_platform::EnginePaths, uid: u32, log: &dyn knsh_platform::SystemLog) {
    use std::sync::Arc;

    use knsh_platform::macos::{RealFs, sha256};

    let files = profiles::ProfileFiles::new(Arc::new(RealFs::new()), paths.profiles_dir(), uid, sha256);
    if files.sweep().is_err() {
        log.log(knsh_platform::Level::Error, "stale sandbox profiles not removed", &[]);
    }
}

/// Everything `knshd` does. Only macOS has a backend so far (Linux later).
#[cfg(not(target_os = "macos"))]
fn start() -> Result<(), StartError> {
    Err(StartError::Unsupported)
}
