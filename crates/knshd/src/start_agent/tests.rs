//! `session.start_agent` tests (KNSH-056), over a fake launcher: scripted processes and a fake process table, so
//! nothing is really started.

use std::path::Path;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use knsh_core::{Caller, StillWaiting};
use knsh_json::{FromJson, Value};
use knsh_platform::testing::{FakeClock, MemFs, Script, ScriptedProcesses};
use knsh_platform::{AuditToken, EnginePaths, Fs, ProcessIdentity};
use knsh_proto::{ByteTransport, MethodName, Request, RequestId};

use super::*;
use crate::dispatch::Passed;
use crate::dispatch::tests::{stream, subscriber};
use crate::sessions::SessionBinding;
use crate::sessions::tests::{Fixture, event_names, fixture, watch};

const HOME: &str = "/Users/u";
const PROJECT: &str = "/Users/u/app";
const CLAUDE: &str = "/opt/bin/claude";
const KNSH: &str = "/opt/bin/knsh";
/// What the fake launcher spawns in place of `knsh-exec`.
const ENVELOPE: &str = "/fake/envelope";

/// A profile, and a stricter one (one allow fewer, one deny more), and a looser one (one allow more).
const WEB: &str = "name = \"web\"\n[exec]\nallow = [\"git status\", \"ls\"]\ndeny = [\"rm\"]\n";
const STRICT: &str = "name = \"strict\"\n[exec]\nallow = [\"ls\"]\ndeny = [\"rm\", \"curl\"]\n";
const LOOSE: &str = "name = \"loose\"\n[exec]\nallow = [\"git status\", \"ls\", \"curl\"]\ndeny = [\"rm\"]\n";
const DEFAULT: &str = "name = \"default\"\n";
/// A profile that writes only its own project.
const PROJ: &str = "name = \"proj\"\n[fs]\nwrite = [\"${PROJECT}\"]\n";
/// Another project, outside [`PROJECT`].
const OTHER: &str = "/Users/u/other";

/// A launcher that spawns [`ENVELOPE`] through scripted processes and adds its leader to the fake process table, as
/// a real spawn would appear there. It records what it was asked to launch.
struct FakeLauncher {
    processes: Arc<ScriptedProcesses>,
    tree: Arc<knsh_platform::testing::FakeProcessTree>,
    launched: Mutex<Vec<Launched>>,
}

/// What one launch was asked for.
#[derive(Debug, Clone)]
struct Launched {
    profile: String,
    /// The profile's write roots, as resolved.
    write: Vec<CanonicalPath>,
    program: CanonicalPath,
    args: Vec<String>,
    env: Vec<(String, String)>,
}

struct FakeEnvelope(ProcessGroupId);

impl Envelope for FakeEnvelope {
    fn group(&self) -> ProcessGroupId {
        self.0
    }

    fn ran(self: Box<Self>) -> bool {
        true
    }
}

impl Launcher for FakeLauncher {
    fn processes(&self) -> Arc<dyn Processes> {
        self.processes.clone()
    }

    fn launch(&self, launch: Launch<'_>) -> Result<Box<dyn Envelope>, LaunchError> {
        self.launched.lock().unwrap().push(Launched {
            profile: launch.profile.name.to_string(),
            write: launch.profile.fs.write.clone(),
            program: launch.program.clone(),
            args: launch.args.to_vec(),
            env: launch.env.clone(),
        });
        let group = self
            .processes
            .spawn(&SpawnRequest::new(ENVELOPE))
            .map_err(|_| LaunchError::Spawn)?;
        self.tree.spawn(ProcessIdentity::new(group.as_raw(), 1), None);
        Ok(Box::new(FakeEnvelope(group)))
    }
}

/// The service under test, with its session fixture and fake launcher.
struct Harness {
    fixture: Fixture,
    launcher: Arc<FakeLauncher>,
    starter: Arc<AgentStarter>,
}

fn policies() -> std::path::PathBuf {
    EnginePaths::for_home(Path::new(HOME)).unwrap().policies_dir()
}

fn shim_dir() -> std::path::PathBuf {
    EnginePaths::for_home(Path::new(HOME)).unwrap().shim_dir()
}

/// A filesystem with the project, the agent CLI, the shims and the profiles.
fn filesystem() -> MemFs {
    let fs = MemFs::new();
    for dir in [PROJECT, OTHER, "/opt/bin", "/bin", "/tmp"] {
        fs.add_dir_all(Path::new(dir)).unwrap();
    }
    fs.add_dir_all(&policies()).unwrap();
    fs.add_dir_all(&shim_dir()).unwrap();
    for binary in [CLAUDE, KNSH, "/bin/bash"] {
        fs.write(Path::new(binary), b"#!/bin/sh\n", 0o755).unwrap();
    }
    // A shim that shadows the CLI's name must never be taken for it.
    fs.write(&shim_dir().join("claude"), b"#!/bin/sh\n", 0o755).unwrap();
    // The real shims are symbolic links to `knsh`: `bash` found through them must not be taken for bash.
    fs.add_symlink(&shim_dir().join("bash"), Path::new(KNSH)).unwrap();
    fs.write(Path::new("/bin/zsh"), b"#!/bin/sh\n", 0o755).unwrap();
    for (name, text) in [
        ("web", WEB),
        ("strict", STRICT),
        ("loose", LOOSE),
        ("default", DEFAULT),
        ("proj", PROJ),
    ] {
        fs.write(&policies().join(format!("{name}.toml")), text.as_bytes(), 0o600)
            .unwrap();
    }
    fs
}

fn harness() -> Harness {
    let fixture = fixture();
    let launcher = Arc::new(FakeLauncher {
        processes: Arc::new(ScriptedProcesses::new()),
        tree: fixture.processes.clone(),
        launched: Mutex::new(Vec::new()),
    });
    let starter = AgentStarter::new(
        Arc::clone(&fixture.sessions),
        crate::policy::tests::loader(filesystem()),
        launcher.clone(),
        Arc::new(FakeClock::new(knsh_core::Timestamp::UNIX_EPOCH)),
        shim_dir(),
        Path::new(KNSH).to_path_buf(),
    );
    Harness {
        fixture,
        launcher,
        starter,
    }
}

/// Three descriptors standing in for the caller's stdio.
fn caller_stdio() -> Vec<OwnedFd> {
    let (_read, write) = std::io::pipe().unwrap();
    let write = OwnedFd::from(write);
    (0..3).map(|_| write.try_clone().unwrap()).collect()
}

/// `session.start_agent` params: `command` and any extra members, in the project, with a `PATH` that puts the shim
/// directory first (as inside an envelope) and finds the CLI after it.
fn params(command: &str, extra: &str) -> String {
    let shims = shim_dir().display().to_string();
    format!(
        r#"{{"command":{command},"cwd":"{PROJECT}","stdio":"passed",
            "env":{{"HOME":"{HOME}","PATH":"{shims}:/opt/bin:/bin","SHELL":"/bin/zsh","DYLD_INSERT_LIBRARIES":"/x"}}
            {extra}}}"#
    )
}

fn call(harness: &Harness, endpoint: Endpoint, binding: &SessionBinding, params: &str, caller: &dyn Caller) -> Reply {
    let request = Request {
        id: RequestId::from(1u32),
        method: MethodName::new(START_AGENT).unwrap(),
        params: knsh_json::parse(params.as_bytes(), 1 << 20)
            .unwrap()
            .as_object()
            .cloned(),
    };
    let passed = Passed::new(caller_stdio());
    harness.starter.handlers()[START_AGENT](&Call {
        endpoint,
        bytes: ByteTransport::BinaryFrames,
        stream: stream(),
        request: &request,
        subscriber: subscriber(),
        binding,
        descriptors: &passed,
        caller,
    })
}

fn start(harness: &Harness, params: &str) -> Result<SessionStartAgentResult, RpcError> {
    let binding = SessionBinding::new();
    let answer = call(harness, Endpoint::User, &binding, params, &StillWaiting)?;
    Ok(SessionStartAgentResult::from_json(&answer.result).unwrap())
}

/// The `parent_session_id` of every `session.started` event `watcher` received, in order.
fn session_started_parents(watcher: &crate::events::Subscriber) -> Vec<Option<SessionId>> {
    watcher
        .take(100)
        .into_iter()
        .filter_map(|(_, delivery)| match delivery {
            knsh_core::Delivery::Event(event) => match &event.data {
                knsh_core::EventData::SessionStarted { parent_session_id, .. } => Some(*parent_session_id),
                _ => None,
            },
            knsh_core::Delivery::Lost(_) => None,
        })
        .collect()
}

// FR-AGT-02: without `--agent`, `claude` runs as the `claude-code` actor.
#[test]
fn derives_claude_code_actor_from_claude() {
    let harness = harness();
    harness.launcher.processes.expect(ENVELOPE, Script::Exits(0));
    let result = start(&harness, &params(r#"["claude"]"#, r#","profile":"web""#)).unwrap();
    assert_eq!(result.agent_id.as_str(), "claude-code");
}

// FR-AGT-02: `--agent` names the actor, whatever the command.
#[test]
fn uses_explicit_agent_name() {
    let harness = harness();
    harness.launcher.processes.expect(ENVELOPE, Script::Exits(0));
    let result = start(
        &harness,
        &params(r#"["claude"]"#, r#","profile":"web","agent":"my-agent""#),
    )
    .unwrap();
    assert_eq!(result.agent_id.as_str(), "my-agent");
}

// FR-AGT-01, FR-AGT-03: the CLI is found on the caller's PATH past the shims and started with its arguments, the
// session's profile, `SHELL=knsh`, the shims first on `PATH`, the session token, and no dynamic-linker variables;
// `knsh agent` gets the CLI's exit code, and the session ends with it (`session.ended`).
#[test]
fn launches_the_cli_and_answers_its_exit_code_once_the_session_ended() {
    let harness = harness();
    let watcher = watch(&harness.fixture.hub);
    harness.launcher.processes.expect(ENVELOPE, Script::Exits(3));
    let result = start(
        &harness,
        &params(r#"["claude","--resume","x y"]"#, r#","profile":"web""#),
    )
    .unwrap();

    assert_eq!(result.status, LineStatus::Exited(3));
    assert_eq!(result.profile.as_str(), "web");
    assert_eq!(result.parent_session_id, None);
    let launched = harness.launcher.launched.lock().unwrap()[0].clone();
    assert_eq!(launched.program.as_path(), Path::new(CLAUDE));
    assert_eq!(launched.args, ["--resume", "x y"]);
    assert_eq!(launched.profile, "web");
    let env = |name: &str| launched.env.iter().find(|(n, _)| n == name).map(|(_, v)| v.clone());
    assert_eq!(env("SHELL").as_deref(), Some(KNSH));
    assert_eq!(
        env("PATH").unwrap(),
        format!("{}:/opt/bin:/bin", shim_dir().display()),
        "shims first, once"
    );
    assert_eq!(env(SESSION_TOKEN_VAR).map(|token| token.len()), Some(64));
    assert_eq!(env("DYLD_INSERT_LIBRARIES"), None);
    assert_eq!(env("HOME").as_deref(), Some(HOME));

    assert_eq!(harness.fixture.sessions.live(), 0);
    assert_eq!(
        event_names(&watcher),
        ["session.started", "session.state_changed", "session.ended"]
    );
    // Once ended, the token binds nothing.
    let token = Redacted::new(env(SESSION_TOKEN_VAR).unwrap());
    assert_eq!(harness.fixture.sessions.enclosing(Some(&token), None), None);
}

// A caller that disconnects (`knsh agent` killed) leaves nobody to answer for the envelope: it is stopped with
// SIGTERM and its session ends.
#[test]
fn caller_leaving_stops_the_envelope_and_ends_the_session() {
    let harness = harness();
    harness.launcher.processes.expect(ENVELOPE, Script::RunsUntilSignalled);
    // The caller leaves at once: the envelope gets SIGTERM, which ends the scripted CLI.
    let gone = Gone(AtomicBool::new(true));
    let binding = SessionBinding::new();
    let error = call(
        &harness,
        Endpoint::User,
        &binding,
        &params(r#"["claude"]"#, r#","profile":"web""#),
        &gone,
    )
    .unwrap_err();
    // Nobody is left to answer; the envelope was stopped and the session ended all the same.
    assert_eq!(error.code, ErrorCode::InternalError);
    let signals = harness.launcher.processes.signals();
    assert_eq!(signals.first().map(|(_, signal)| *signal), Some(Signal::Terminate));
    assert_eq!(harness.fixture.sessions.live(), 0);
}

struct Gone(AtomicBool);

impl Caller for Gone {
    fn gone(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

/// Opens a live agent session running `profile` (resolved in [`PROJECT`]) as if the starter had started it.
fn open_parent(harness: &Harness, profile: &str) -> crate::sessions::OpenedAgent {
    let name = ProfileName::new(profile).unwrap();
    let opened = harness
        .fixture
        .sessions
        .open_agent(
            knsh_core::Actor::Agent(AgentId::new("claude-code").unwrap()),
            name.clone(),
        )
        .unwrap();
    let resolved = crate::policy::tests::loader(filesystem())
        .load(&name, Path::new(PROJECT))
        .unwrap();
    harness.starter.adopt(opened.session_id, resolved);
    opened
}

/// A live parent agent session running `profile`, whose envelope root is pid 200, and the audit token of a process
/// inside it (pid 201).
fn parent_session(harness: &Harness, profile: &str) -> (SessionId, AuditToken) {
    let opened = open_parent(harness, profile);
    let root = ProcessIdentity::new(200, 1);
    let inside = ProcessIdentity::new(201, 1);
    harness.fixture.processes.spawn(root, None);
    harness.fixture.processes.spawn(inside, Some(root));
    harness
        .fixture
        .sessions
        .register_envelope(opened.session_id, root)
        .unwrap();
    (opened.session_id, AuditToken::for_process(inside, 501))
}

// FR-SES-03: a session started from inside another records it as its parent and, without `--profile`, inherits
// its profile.
#[test]
fn nested_session_records_parent_and_inherits_its_profile() {
    let harness = harness();
    let (parent, peer) = parent_session(&harness, "web");
    let watcher = watch(&harness.fixture.hub);
    harness.launcher.processes.expect(ENVELOPE, Script::Exits(0));
    let binding = SessionBinding::for_peer(Some(peer));
    let answer = call(
        &harness,
        Endpoint::User,
        &binding,
        &params(r#"["claude"]"#, ""),
        &StillWaiting,
    )
    .unwrap();
    let result = SessionStartAgentResult::from_json(&answer.result).unwrap();
    assert_eq!(result.parent_session_id, Some(parent));
    assert_eq!(result.profile.as_str(), "web");
    assert_eq!(session_started_parents(&watcher), [Some(parent)]);
}

// FR-SES-03: the parent is also found by the session token in the caller's environment, and a stricter profile is
// accepted.
#[test]
fn nested_session_by_token_may_be_stricter() {
    let harness = harness();
    let opened = open_parent(&harness, "web");
    let token = opened.token.encode().expose().clone();
    harness.launcher.processes.expect(ENVELOPE, Script::Exits(0));
    let shims = shim_dir().display().to_string();
    let params = format!(
        r#"{{"command":["claude"],"cwd":"{PROJECT}","stdio":"passed","profile":"strict",
            "env":{{"PATH":"{shims}:/opt/bin","{SESSION_TOKEN_VAR}":"{token}"}}}}"#
    );
    let result = start(&harness, &params).unwrap();
    assert_eq!(result.parent_session_id, Some(opened.session_id));
    assert_eq!(result.profile.as_str(), "strict");
    // The child's envelope carries its own token, never the parent's.
    let launched = harness.launcher.launched.lock().unwrap()[0].clone();
    let child_token = launched.env.iter().find(|(name, _)| name == SESSION_TOKEN_VAR).unwrap();
    assert_ne!(child_token.1, token);
}

// FR-SES-03: a session started from inside another cannot choose a looser profile: refused, nothing launched, no
// session left behind.
#[test]
fn nested_session_cannot_loosen_profile() {
    let harness = harness();
    let (_, peer) = parent_session(&harness, "web");
    let binding = SessionBinding::for_peer(Some(peer));
    let error = call(
        &harness,
        Endpoint::User,
        &binding,
        &params(r#"["claude"]"#, r#","profile":"loose""#),
        &StillWaiting,
    )
    .unwrap_err();
    assert_eq!(error.code, ErrorCode::NotAllowed);
    assert!(harness.launcher.launched.lock().unwrap().is_empty());
    // Only the parent is live.
    assert_eq!(harness.fixture.sessions.live(), 1);
}

/// `params` run from `cwd` instead of the project.
fn params_in(cwd: &str, command: &str, extra: &str) -> String {
    params(command, extra).replace(&format!(r#""cwd":"{PROJECT}""#), &format!(r#""cwd":"{cwd}""#))
}

// FR-SES-03: the parent is compared as it runs. Its `${PROJECT}` is where it started, so a nested call that names
// another directory as its `cwd` cannot take the parent's project-relative write access there, with the same
// profile by name or by inheriting it.
#[test]
fn nested_session_cannot_move_the_parents_project() {
    let harness = harness();
    let (_, peer) = parent_session(&harness, "proj");
    let binding = SessionBinding::for_peer(Some(peer));
    let error = call(
        &harness,
        Endpoint::User,
        &binding,
        &params_in(OTHER, r#"["claude"]"#, r#","profile":"proj""#),
        &StillWaiting,
    )
    .unwrap_err();
    assert_eq!(error.code, ErrorCode::NotAllowed);
    assert!(harness.launcher.launched.lock().unwrap().is_empty());

    // Inherited, it is the parent's resolved profile: still writing the parent's project only.
    harness.launcher.processes.expect(ENVELOPE, Script::Exits(0));
    call(
        &harness,
        Endpoint::User,
        &binding,
        &params_in(OTHER, r#"["claude"]"#, ""),
        &StillWaiting,
    )
    .unwrap();
    let launched = harness.launcher.launched.lock().unwrap()[0].clone();
    assert_eq!(launched.write, [CanonicalPath::new(PROJECT).unwrap()]);
    // The child's entry went with its session; only the parent's is left.
    assert_eq!(harness.starter.running().len(), 1);
}

// FR-AGT-03: the shims are links to `knsh`; a name found through them (here `bash`) is never `knsh`, but the next
// match on `PATH`.
#[test]
fn program_lookup_skips_shim_links() {
    let harness = harness();
    harness.launcher.processes.expect(ENVELOPE, Script::Exits(0));
    let fs = filesystem();
    fs.write(Path::new("/opt/bin/bash"), b"#!/bin/sh\n", 0o755).unwrap();
    let starter = AgentStarter::new(
        Arc::clone(&harness.fixture.sessions),
        crate::policy::tests::loader(fs),
        harness.launcher.clone(),
        Arc::new(FakeClock::new(knsh_core::Timestamp::UNIX_EPOCH)),
        shim_dir(),
        Path::new(KNSH).to_path_buf(),
    );
    let request = Request {
        id: RequestId::from(1u32),
        method: MethodName::new(START_AGENT).unwrap(),
        params: knsh_json::parse(params(r#"["bash"]"#, r#","profile":"web""#).as_bytes(), 1 << 20)
            .unwrap()
            .as_object()
            .cloned(),
    };
    let binding = SessionBinding::new();
    let passed = Passed::new(caller_stdio());
    starter.handlers()[START_AGENT](&Call {
        endpoint: Endpoint::User,
        bytes: ByteTransport::BinaryFrames,
        stream: stream(),
        request: &request,
        subscriber: subscriber(),
        binding: &binding,
        descriptors: &passed,
        caller: &StillWaiting,
    })
    .unwrap();
    let launched = harness.launcher.launched.lock().unwrap()[0].clone();
    assert_eq!(launched.program.as_path(), Path::new("/opt/bin/bash"));
}

// Without `--profile` and without a parent, the session runs `default`.
#[test]
fn top_level_session_defaults_to_the_default_profile() {
    let harness = harness();
    harness.launcher.processes.expect(ENVELOPE, Script::Exits(0));
    let result = start(&harness, &params(r#"["claude"]"#, "")).unwrap();
    assert_eq!(result.profile.as_str(), "default");
}

// Malformed requests start nothing: an unknown profile, a CLI that cannot be found (a shim is never the CLI), an
// actor that cannot be derived, and stdio that is not three descriptors.
#[test]
fn refuses_what_cannot_start() {
    let harness = harness();
    for bad in [
        params(r#"["claude"]"#, r#","profile":"missing""#),
        params(r#"["no-such-cli"]"#, r#","profile":"web""#),
        params(r#"["./claude"]"#, r#","profile":"web""#),
        params(r#"["/opt/bin/"]"#, r#","profile":"web""#),
    ] {
        let error = start(&harness, &bad).unwrap_err();
        assert_eq!(error.code, ErrorCode::InvalidParams, "{bad}");
    }
    let request = Request {
        id: RequestId::from(1u32),
        method: MethodName::new(START_AGENT).unwrap(),
        params: knsh_json::parse(params(r#"["claude"]"#, r#","profile":"web""#).as_bytes(), 1 << 20)
            .unwrap()
            .as_object()
            .cloned(),
    };
    let binding = SessionBinding::new();
    let one = Passed::new(caller_stdio().into_iter().take(1).collect());
    let error = harness.starter.handlers()[START_AGENT](&Call {
        endpoint: Endpoint::User,
        bytes: ByteTransport::BinaryFrames,
        stream: stream(),
        request: &request,
        subscriber: subscriber(),
        binding: &binding,
        descriptors: &one,
        caller: &StillWaiting,
    })
    .unwrap_err();
    assert_eq!(error.code, ErrorCode::InvalidParams);
    assert!(harness.launcher.launched.lock().unwrap().is_empty());
    assert_eq!(harness.fixture.sessions.live(), 0);
}

// FR-SES-02: the handler itself refuses agent.sock, should a table ever route it there.
#[test]
fn handler_refuses_agent_socket() {
    let harness = harness();
    let binding = SessionBinding::new();
    let error = call(
        &harness,
        Endpoint::Agent,
        &binding,
        &params(r#"["claude"]"#, ""),
        &StillWaiting,
    )
    .unwrap_err();
    assert_eq!(error.code, ErrorCode::NotAllowed);
}

/// `knshd`'s dispatcher on a machine probed as `machine`, with this service's handler.
fn dispatcher(harness: &Harness, machine: &crate::probe::tests::Machine) -> crate::dispatch::Dispatcher {
    let mut handlers = crate::hello::tests::handlers();
    handlers.extend(harness.starter.handlers());
    crate::hello::phase1_dispatcher(crate::probe::probe(&machine.probes()), handlers).unwrap()
}

fn dispatch(dispatcher: &crate::dispatch::Dispatcher, endpoint: Endpoint) -> Reply {
    let request = Request {
        id: RequestId::from(1u32),
        method: MethodName::new(START_AGENT).unwrap(),
        params: knsh_json::parse(params(r#"["claude"]"#, "").as_bytes(), 1 << 20)
            .unwrap()
            .as_object()
            .cloned(),
    };
    let binding = SessionBinding::new();
    let passed = Passed::new(caller_stdio());
    dispatcher.call(&Call {
        endpoint,
        bytes: ByteTransport::BinaryFrames,
        stream: stream(),
        request: &request,
        subscriber: subscriber(),
        binding: &binding,
        descriptors: &passed,
        caller: &StillWaiting,
    })
}

// FR-AGT-06: when the capability probe reports `sandbox: none`, no agent session starts: `-32005` naming `sandbox`.
#[test]
fn refuses_start_when_sandbox_none() {
    let harness = harness();
    let dispatcher = dispatcher(&harness, &crate::probe::tests::Machine::failing());
    let error = dispatch(&dispatcher, Endpoint::User).unwrap_err();
    assert_eq!(error.code, ErrorCode::CapabilityUnavailable);
    let capability = error
        .data
        .as_ref()
        .and_then(Value::as_object)
        .and_then(|data| data.get("capability"))
        .and_then(Value::as_str);
    assert_eq!(capability, Some("sandbox"));
    assert!(harness.launcher.launched.lock().unwrap().is_empty());
    assert_eq!(harness.fixture.sessions.live(), 0);
}

// FR-SES-02: `session.start_agent` does not exist on agent.sock: unknown there (`-32601`), never routed, even on a
// machine with the sandbox; on user.sock it is served.
#[test]
fn start_agent_absent_from_agent_socket() {
    let harness = harness();
    let dispatcher = dispatcher(&harness, &crate::probe::tests::Machine::working());
    assert!(!dispatcher.methods(Endpoint::Agent).contains(&START_AGENT));
    assert!(dispatcher.methods(Endpoint::User).contains(&START_AGENT));
    let error = dispatch(&dispatcher, Endpoint::Agent).unwrap_err();
    assert_eq!(error.code, ErrorCode::MethodNotFound);
    assert!(harness.launcher.launched.lock().unwrap().is_empty());
}

// FR-AGT-03: the envelope environment replaces a caller's token, `SHELL` and shim entries instead of adding to them.
#[test]
fn envelope_env_replaces_token_shell_and_shims() {
    let token = SessionToken::generate(&knsh_platform::testing::SeededRandom::new(9)).unwrap();
    let shims = shim_dir().display().to_string();
    let caller = vec![
        ("A".to_owned(), "1".to_owned()),
        ("PATH".to_owned(), format!("{shims}/:/usr/bin:{shims}")),
        ("SHELL".to_owned(), "/bin/zsh".to_owned()),
        (SESSION_TOKEN_VAR.to_owned(), "parent".to_owned()),
        ("DYLD_LIBRARY_PATH".to_owned(), "/x".to_owned()),
    ];
    let env = envelope_env(&caller, &token, &shim_dir(), Path::new(KNSH));
    let names: Vec<&str> = env.iter().map(|(name, _)| name.as_str()).collect();
    assert_eq!(names, ["A", "PATH", "SHELL", SESSION_TOKEN_VAR]);
    assert_eq!(env[1].1, format!("{shims}:/usr/bin"));
    assert_eq!(env[2].1, KNSH);
    assert_eq!(&env[3].1, token.encode().expose());
    // No PATH at all: the shims alone.
    let env = envelope_env(&[], &token, &shim_dir(), Path::new(KNSH));
    assert_eq!(env[0], ("PATH".to_owned(), shims));
}

/// Against the real `knsh-exec`, `sandbox-exec` and process table on this machine.
mod platform {
    use std::io::Read;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    use knsh_platform::macos::{RealFs, SystemClock, SystemProcessTree, SystemProcesses, effective_uid, sha256};

    use super::*;
    use crate::sessions::tests::fixture_on;

    /// The `knsh-exec` built beside this test binary, or `None` when only this crate was built.
    fn trampoline() -> Option<PathBuf> {
        let exe = std::env::current_exe().ok()?;
        let path = exe.parent()?.parent()?.join("knsh-exec");
        path.is_file().then_some(path)
    }

    /// A private, canonical temporary directory, removed on drop.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(name: &str) -> Self {
            let dir = std::env::temp_dir().join(format!("knshd-agent-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir(&dir).unwrap();
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
            Self(std::fs::canonicalize(&dir).unwrap())
        }

        fn dir(&self, name: &str) -> PathBuf {
            let dir = self.0.join(name);
            std::fs::create_dir(&dir).unwrap();
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
            dir
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    // FR-AGT-01, FR-AGT-03, FR-SBX-01: the real launcher starts the CLI through `knsh-exec` under the envelope
    // profile, with `SHELL` and the session token set; the CLI's exit code comes back and the session ends. A write
    // outside the profile's write roots is denied, so the sandbox really was applied.
    #[test]
    fn real_envelope_runs_sandboxed_and_reports_its_exit_code() {
        let Some(trampoline) = trampoline() else {
            eprintln!("knsh-exec is not built beside this test: run `cargo test --workspace`; skipped");
            return;
        };
        let scratch = Scratch::new("launch");
        let (policies, profiles, work, outside) = (
            scratch.dir("policies"),
            scratch.dir("profiles"),
            scratch.dir("work"),
            scratch.dir("outside"),
        );
        std::fs::write(
            policies.join("it.toml"),
            format!("name = \"it\"\n[fs]\nwrite = [\"{}\"]\n", work.display()),
        )
        .unwrap();
        let home = std::fs::canonicalize(std::env::var_os("HOME").unwrap()).unwrap();
        let knsh = CanonicalPath::new("/usr/bin/true").unwrap();
        let fixture = fixture_on(Some(Arc::new(SystemProcessTree::new())));
        let processes = Arc::new(SystemProcesses::new());
        let launcher = TrampolineLauncher {
            processes,
            files: ProfileFiles::new(Arc::new(RealFs::new()), profiles, effective_uid(), sha256),
            trampoline,
            home: CanonicalPath::new(&home).unwrap(),
            knsh: knsh.clone(),
        };
        let loader = ProfileLoader::new(
            Arc::new(RealFs::new()),
            policies,
            home.clone(),
            PathBuf::from("/private/tmp"),
        );
        let starter = AgentStarter::new(
            Arc::clone(&fixture.sessions),
            loader,
            Arc::new(launcher),
            Arc::new(SystemClock::new()),
            scratch.0.join("shims"),
            knsh.as_path().to_path_buf(),
        );
        let script = format!(
            "echo inside > {work}/ok && echo ok=$?; (echo x > {outside}/denied) 2>/dev/null; echo denied=$?; \
             echo shell=$SHELL; echo token=${{#KNSH_SESSION_TOKEN}}; exit 7",
            work = work.display(),
            outside = outside.display(),
        );
        let command = knsh_json::write(
            &knsh_json::ToJson::to_json(&vec!["/bin/sh".to_owned(), "-c".to_owned(), script]).unwrap(),
        )
        .unwrap();
        let params = format!(
            r#"{{"command":{command},"cwd":"{}","stdio":"passed","profile":"it",
                "env":{{"PATH":"/usr/bin:/bin","HOME":"{}"}}}}"#,
            work.display(),
            home.display()
        );
        let request = Request {
            id: RequestId::from(1u32),
            method: MethodName::new(START_AGENT).unwrap(),
            params: knsh_json::parse(params.as_bytes(), 1 << 20)
                .unwrap()
                .as_object()
                .cloned(),
        };
        let (mut read, write) = std::io::pipe().unwrap();
        let write = OwnedFd::from(write);
        let null = OwnedFd::from(std::fs::File::open("/dev/null").unwrap());
        let passed = Passed::new(vec![null, write.try_clone().unwrap(), write]);
        let binding = SessionBinding::new();
        let answer = starter.handlers()[START_AGENT](&Call {
            endpoint: Endpoint::User,
            bytes: ByteTransport::BinaryFrames,
            stream: stream(),
            request: &request,
            subscriber: subscriber(),
            binding: &binding,
            descriptors: &passed,
            caller: &StillWaiting,
        })
        .unwrap();
        drop(passed);
        let result = SessionStartAgentResult::from_json(&answer.result).unwrap();
        let mut out = String::new();
        read.read_to_string(&mut out).unwrap();

        assert_eq!(result.status, LineStatus::Exited(7), "{out}");
        assert_eq!(result.agent_id.as_str(), "sh");
        assert_eq!(
            out,
            format!("ok=0\ndenied=1\nshell={}\ntoken=64\n", knsh.as_path().display())
        );
        assert!(!outside.join("denied").exists());
        assert_eq!(fixture.sessions.live(), 0);
    }
}
