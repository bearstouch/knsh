//! `session.start_agent` tests (KNSH-056, KNSH-057), over a fake launcher and a fake proxy: scripted processes and a
//! fake process table, so nothing is really started. The `platform` module launches real envelopes.

use std::collections::BTreeMap;
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
use crate::proxy::tests::FakeProxy;
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
/// A profile with the `claude-code` preset (FR-AGT-04) and one loopback port.
const CLAUDE_PRESET: &str = "name = \"claude\"\npreset = \"claude-code\"\n[network]\nloopback = [3000]\n";

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
    proxy_port: Option<NonZeroU16>,
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
            proxy_port: launch.proxy_port,
        });
        let group = self
            .processes
            .spawn(&SpawnRequest::new(ENVELOPE))
            .map_err(|_| LaunchError::Spawn)?;
        self.tree.spawn(ProcessIdentity::new(group.as_raw(), 1), None);
        Ok(Box::new(FakeEnvelope(group)))
    }
}

/// The service under test, with its session fixture, fake launcher and fake proxy.
struct Harness {
    fixture: Fixture,
    launcher: Arc<FakeLauncher>,
    proxy: Arc<FakeProxy>,
    starter: Arc<AgentStarter>,
}

/// The port [`FakeProxy`] listens on in [`harness`].
const PROXY_PORT: u16 = 41_000;

fn policies() -> std::path::PathBuf {
    EnginePaths::for_home(Path::new(HOME)).unwrap().policies_dir()
}

fn shim_dir() -> std::path::PathBuf {
    EnginePaths::for_home(Path::new(HOME)).unwrap().shim_dir()
}

/// A filesystem with the project, the agent CLI, the shims and the profiles.
fn filesystem() -> MemFs {
    let fs = MemFs::new();
    // `~/.claude`: the `claude-code` preset's configuration folder, which must exist to be resolved.
    for dir in [PROJECT, OTHER, "/opt/bin", "/bin", "/tmp", "/Users/u/.claude"] {
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
        ("claude", CLAUDE_PRESET),
    ] {
        fs.write(
            &policies().join(format!("{name}.toml")),
            &crate::policy::tests::signed(name, text),
            0o600,
        )
        .unwrap();
    }
    fs
}

fn harness() -> Harness {
    harness_with(FakeProxy::new(PROXY_PORT))
}

fn harness_with(proxy: FakeProxy) -> Harness {
    let fixture = fixture();
    let launcher = Arc::new(FakeLauncher {
        processes: Arc::new(ScriptedProcesses::new()),
        tree: fixture.processes.clone(),
        launched: Mutex::new(Vec::new()),
    });
    let proxy = Arc::new(proxy);
    let starter = AgentStarter::new(
        Arc::clone(&fixture.sessions),
        crate::policy::tests::loader(filesystem()),
        launcher.clone(),
        proxy.clone(),
        Arc::new(FakeClock::new(knsh_core::Timestamp::UNIX_EPOCH)),
        shim_dir(),
        Path::new(KNSH).to_path_buf(),
        knsh_platform::testing::DEFAULT_UID,
    );
    Harness {
        fixture,
        launcher,
        proxy,
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
        control: None,
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
            knsh_core::Delivery::Lost(_) | knsh_core::Delivery::Engine(_) | knsh_core::Delivery::EngineLost(_) => None,
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
        harness.proxy.clone(),
        Arc::new(FakeClock::new(knsh_core::Timestamp::UNIX_EPOCH)),
        shim_dir(),
        Path::new(KNSH).to_path_buf(),
        knsh_platform::testing::DEFAULT_UID,
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
        control: None,
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
        control: None,
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
        control: None,
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
    let env = envelope_env(&caller, &token, &shim_dir(), Path::new(KNSH), &BTreeMap::new(), None);
    let names: Vec<&str> = env.iter().map(|(name, _)| name.as_str()).collect();
    assert_eq!(names, ["A", "PATH", "SHELL", SESSION_TOKEN_VAR]);
    assert_eq!(env[1].1, format!("{shims}:/usr/bin"));
    assert_eq!(env[2].1, KNSH);
    assert_eq!(&env[3].1, token.encode().expose());
    // No PATH at all: the shims alone.
    let env = envelope_env(&[], &token, &shim_dir(), Path::new(KNSH), &BTreeMap::new(), None);
    assert_eq!(env[0], ("PATH".to_owned(), shims));
}

// FR-AGT-03, FR-NET-01, decision 14: the envelope starts with `SHELL=knsh`, the shims first on `PATH`, its session's
// token, and proxy settings carrying credentials issued for its session alone; the caller's own proxy settings are
// gone, the profile allows the proxy's port, and the credentials are revoked once the envelope ended.
#[test]
fn envelope_env_sets_shell_path_token_and_proxy() {
    let harness = harness();
    harness.launcher.processes.expect(ENVELOPE, Script::Exits(0));
    let shims = shim_dir().display().to_string();
    let params = format!(
        r#"{{"command":["claude"],"cwd":"{PROJECT}","stdio":"passed","profile":"web",
            "env":{{"HOME":"{HOME}","PATH":"/opt/bin:/bin","HTTPS_PROXY":"http://me:pw@corp:8080",
                    "no_proxy":"*","ALL_PROXY":"socks5h://corp:1080","NODE_USE_ENV_PROXY":"0"}}}}"#
    );
    let result = start(&harness, &params).unwrap();

    let launched = harness.launcher.launched.lock().unwrap()[0].clone();
    let env = |name: &str| launched.env.iter().find(|(n, _)| n == name).map(|(_, v)| v.clone());
    let count = |name: &str| launched.env.iter().filter(|(n, _)| n == name).count();
    assert_eq!(env("SHELL").as_deref(), Some(KNSH));
    assert_eq!(env("PATH").unwrap(), format!("{shims}:/opt/bin:/bin"));
    assert_eq!(env(SESSION_TOKEN_VAR).map(|token| token.len()), Some(64));
    let url = format!("http://knsh-1:{}@127.0.0.1:{PROXY_PORT}", FakeProxy::TOKEN);
    for name in ["HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"] {
        assert_eq!(env(name).as_deref(), Some(url.as_str()), "{name}");
        assert_eq!(count(name), 1, "{name} once, the caller's replaced");
    }
    assert_eq!(env("NODE_USE_ENV_PROXY").as_deref(), Some("1"));
    assert_eq!(count("NODE_USE_ENV_PROXY"), 1);
    assert_eq!(env("GIT_HTTP_PROXY_AUTHMETHOD").as_deref(), Some("basic"));
    // Settings that would send a tool around the envelope's proxy, or to the caller's, are gone.
    assert_eq!(env("no_proxy"), None);
    assert_eq!(env("ALL_PROXY"), None);
    assert!(launched.env.iter().all(|(_, value)| !value.contains("corp")));
    assert_eq!(launched.proxy_port, NonZeroU16::new(PROXY_PORT));

    assert_eq!(*harness.proxy.issued.lock().unwrap(), [result.session_id]);
    assert_eq!(*harness.proxy.revoked.lock().unwrap(), [result.session_id]);
}

// FR-AGT-03, fail closed: a proxy that cannot issue credentials starts no envelope; the session still ends and
// whatever the proxy holds for it is revoked.
#[test]
fn proxy_failure_starts_nothing_and_ends_the_session() {
    let mut proxy = FakeProxy::new(PROXY_PORT);
    proxy.broken = true;
    let harness = harness_with(proxy);
    let error = start(&harness, &params(r#"["claude"]"#, r#","profile":"web""#)).unwrap_err();
    assert_eq!(error.code, ErrorCode::InternalError);
    assert!(harness.launcher.launched.lock().unwrap().is_empty());
    assert_eq!(harness.fixture.sessions.live(), 0);
    assert_eq!(harness.proxy.revoked.lock().unwrap().len(), 1);
}

// Without a proxy (`network_filter: none`, before KNSH-059): no proxy settings and no proxy port, so the envelope
// reaches only its loopback ports; inherited proxy settings are still removed.
#[test]
fn no_proxy_means_no_proxy_settings() {
    let token = SessionToken::generate(&knsh_platform::testing::SeededRandom::new(3)).unwrap();
    let caller = vec![
        ("HTTPS_PROXY".to_owned(), "http://corp:8080".to_owned()),
        ("PIP_PROXY".to_owned(), "http://corp:8080".to_owned()),
    ];
    let env = envelope_env(&caller, &token, &shim_dir(), Path::new(KNSH), &BTreeMap::new(), None);
    let names: Vec<&str> = env.iter().map(|(name, _)| name.as_str()).collect();
    assert_eq!(names, ["PATH", "SHELL", SESSION_TOKEN_VAR]);
    let session = session_id(5);
    let network = knsh_core::NetworkPolicy {
        mode: knsh_core::NetworkMode::None,
        hosts: Vec::new(),
        approval_hosts: Vec::new(),
        class_hosts: knsh_core::ClassHosts::default(),
        loopback: Vec::new(),
        non_tls_hosts: Vec::new(),
    };
    assert!(crate::proxy::NoProxy.issue(session, &network).unwrap().is_none());
}

/// A fixed session id, numbered `n`.
fn session_id(n: u128) -> SessionId {
    SessionId::from_ulid(knsh_core::Ulid::from_u128(n))
}

/// `name` loaded as the starter loads it, in the project, and compiled for an envelope of `session` running
/// [`CLAUDE`], with the proxy on [`PROXY_PORT`].
fn envelope_text(name: &str, session: SessionId) -> String {
    let profile = crate::policy::tests::loader(filesystem())
        .load(&ProfileName::new(name).unwrap(), Path::new(PROJECT))
        .unwrap();
    let text = envelope_profile(
        session,
        &profile,
        &CanonicalPath::new(HOME).unwrap(),
        &CanonicalPath::new(CLAUDE).unwrap(),
        &CanonicalPath::new(KNSH).unwrap(),
        NonZeroU16::new(PROXY_PORT),
    );
    String::from_utf8(text.into_bytes()).unwrap()
}

/// The profile's lines that start with `prefix`.
fn rules<'a>(text: &'a str, prefix: &str) -> Vec<&'a str> {
    text.lines().filter(|line| line.starts_with(prefix)).collect()
}

/// Where the last allow of `text` is: every fixed deny must come after it to win.
fn last_allow(text: &str) -> usize {
    text.rfind("\n(allow").unwrap()
}

// FR-SBX-05, FR-AGT-03: the envelope may connect to `agent.sock` and no other Unix socket; `user.sock` is denied
// after every allow; outbound network goes to the proxy's port and the profile's loopback ports only.
#[test]
fn envelope_profile_allows_agent_socket_only() {
    let session = session_id(7);
    let text = envelope_text("claude", session);
    let run = format!("{HOME}/Library/Application Support/knsh/run");
    let sockets: Vec<&str> = rules(&text, "(allow network-outbound")
        .into_iter()
        .filter(|rule| rule.contains("unix-socket"))
        .collect();
    assert_eq!(
        sockets,
        [format!(
            r#"(allow network-outbound (remote unix-socket (path-literal "{run}/agent.sock")))"#
        )]
    );
    let user = format!(r#"(deny network-outbound (remote unix-socket (path-literal "{run}/user.sock"))"#);
    let denied_at = text.find(&user).unwrap();
    assert!(
        denied_at > last_allow(&text),
        "the user.sock deny wins over every allow"
    );
    assert!(text[denied_at..].contains(&format!("knsh:{session}:env:fixed.user-sock")));
    // Network: the proxy and loopback 3000, nothing else.
    let ips: Vec<&str> = rules(&text, "(allow network-outbound")
        .into_iter()
        .filter(|rule| rule.contains("remote ip"))
        .collect();
    assert_eq!(
        ips,
        [format!(
            r#"(allow network-outbound (remote ip "localhost:{PROXY_PORT}") (remote ip "localhost:3000"))"#
        )]
    );
    // Deny by default, and the engine paths denied last of all (FR-SBX-01, FR-SBX-10).
    assert!(text.contains(&format!("(deny default (with message \"knsh:{session}:env:default\"))")));
    let engine = text.lines().last().unwrap();
    assert!(
        engine.starts_with("(deny file-read* file-write* process-exec*"),
        "{engine}"
    );
    assert!(engine.contains(&format!("knsh:{session}:env:fixed.engine")));
}

// FR-AUTH-16: the envelope cannot look up the control service, whatever the broad Mach-service allow before it
// says; the deny is tagged for the envelope.
#[test]
fn envelope_profile_denies_control_service_lookup() {
    let session = session_id(7);
    let text = envelope_text("web", session);
    let deny = format!(
        r#"(deny mach-lookup (global-name "{}") (with message "knsh:{session}:env:fixed.control"))"#,
        knsh_core::CONTROL_SERVICE
    );
    let denied_at = text.find(&deny).unwrap();
    assert!(denied_at > text.find("(allow mach-lookup)").unwrap());
    assert!(
        !rules(&text, "(allow mach-lookup")
            .iter()
            .any(|rule| rule.contains(knsh_core::CONTROL_SERVICE))
    );
}

// FR-AGT-04: the envelope profile is the session's profile with its preset: `claude-code` adds `~/.claude` and the
// project as write roots, and the CLI and `knsh` (the shims' target) are the binaries it may run by name.
#[test]
fn envelope_profile_includes_preset_grants() {
    let session = session_id(7);
    let with_preset = envelope_text("claude", session);
    let writes = rules(&with_preset, "(allow file-write* (subpath");
    assert_eq!(writes.len(), 1, "{writes:?}");
    assert!(
        writes[0].contains(&format!(r#"(subpath "{PROJECT}")"#)),
        "{}",
        writes[0]
    );
    assert!(writes[0].contains(r#"(subpath "/Users/u/.claude")"#), "{}", writes[0]);
    let exec = rules(&with_preset, "(allow process-exec")[0];
    assert!(exec.contains(&format!(r#"(literal "{CLAUDE}")"#)) && exec.contains(&format!(r#"(literal "{KNSH}")"#)));
    // The same CLI under a profile without the preset gets neither.
    let without = envelope_text("web", session);
    assert!(!without.contains("/Users/u/.claude"));
    assert_eq!(rules(&without, "(allow file-write* (subpath"), Vec::<&str>::new());
}

// FR-AGT-33: under the `claude-code` preset the CLI starts with `CLAUDE_CODE_TMPDIR` at its own folder below
// `${TMPDIR}` (replacing the caller's value), the folder exists owner-only before launch, and it is a write root.
#[test]
fn claude_code_preset_points_its_temporary_folder_inside_the_envelope() {
    let harness = harness();
    harness.launcher.processes.expect(ENVELOPE, Script::Exits(0));
    let params = format!(
        r#"{{"command":["claude"],"cwd":"{PROJECT}","stdio":"passed","profile":"claude",
            "env":{{"HOME":"{HOME}","PATH":"/opt/bin:/bin","CLAUDE_CODE_TMPDIR":"/tmp"}}}}"#
    );
    start(&harness, &params).unwrap();

    let launched = harness.launcher.launched.lock().unwrap()[0].clone();
    let folder = Path::new("/tmp/knsh-claude-code");
    let values: Vec<&str> = launched
        .env
        .iter()
        .filter(|(name, _)| name == "CLAUDE_CODE_TMPDIR")
        .map(|(_, value)| value.as_str())
        .collect();
    assert_eq!(values, ["/tmp/knsh-claude-code"]);
    assert!(launched.write.iter().any(|root| root.as_path() == folder));
    let meta = harness.starter.profiles.fs().metadata(folder).unwrap();
    assert_eq!(meta.kind, knsh_platform::FileKind::Directory);
    assert_eq!(meta.mode, 0o700);
}

// FR-AGT-33: a preset variable never replaces one `knshd` sets itself or one the dynamic linker reads.
#[test]
fn envelope_env_keeps_its_own_variables_over_a_preset() {
    let token = SessionToken::generate(&knsh_platform::testing::SeededRandom::new(4)).unwrap();
    let folder = CanonicalPath::new("/tmp/knsh-x").unwrap();
    let preset: BTreeMap<String, CanonicalPath> = ["SHELL", "PATH", "DYLD_INSERT_LIBRARIES", "HTTPS_PROXY", "X_TMP"]
        .into_iter()
        .map(|name| (name.to_owned(), folder.clone()))
        .collect();
    let env = envelope_env(&[], &token, &shim_dir(), Path::new(KNSH), &preset, None);
    let names: Vec<&str> = env.iter().map(|(name, _)| name.as_str()).collect();
    assert_eq!(names, ["X_TMP", "PATH", "SHELL", SESSION_TOKEN_VAR]);
    assert_eq!(env[0].1, "/tmp/knsh-x");
    assert_eq!(env[2].1, KNSH);
}

// FR-AGT-33: the folder is created `0700` when missing and its mode tightened when present; a symlink, a file or a
// folder another user owns is refused, so no envelope starts on a folder it cannot safely use.
#[test]
fn env_folder_must_be_an_owned_directory() {
    let fs = MemFs::new();
    let uid = fs.uid();
    fs.add_dir_all(Path::new("/tmp")).unwrap();
    assert!(env_folder_ready(&fs, Path::new("/tmp/new"), uid));
    assert_eq!(fs.metadata(Path::new("/tmp/new")).unwrap().mode, 0o700);

    fs.create_dir(Path::new("/tmp/open"), 0o777).unwrap();
    assert!(env_folder_ready(&fs, Path::new("/tmp/open"), uid));
    assert_eq!(fs.metadata(Path::new("/tmp/open")).unwrap().mode, 0o700);

    fs.add_dir_all(Path::new("/Users/u/.ssh")).unwrap();
    fs.add_symlink(Path::new("/tmp/link"), Path::new("/Users/u/.ssh"))
        .unwrap();
    assert!(!env_folder_ready(&fs, Path::new("/tmp/link"), uid));
    fs.write(Path::new("/tmp/file"), b"", 0o600).unwrap();
    assert!(!env_folder_ready(&fs, Path::new("/tmp/file"), uid));
    fs.create_dir(Path::new("/tmp/theirs"), 0o700).unwrap();
    fs.set_owner(Path::new("/tmp/theirs"), uid + 1).unwrap();
    assert!(!env_folder_ready(&fs, Path::new("/tmp/theirs"), uid));
    // No parent: only the folder itself is ever created.
    assert!(!env_folder_ready(&fs, Path::new("/nowhere/x"), uid));
}

/// Against the real `knsh-exec`, `sandbox-exec` and process table on this machine.
mod platform {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::PathBuf;
    use std::process::Command;

    use knsh_json::{Frame, FrameReader, FrameWriter, Object, ToJson};
    use knsh_platform::macos::{
        RealFs, SystemClock, SystemProcessTree, SystemProcesses, effective_uid, recv_with_descriptors, sha256,
    };
    use knsh_proto::{ErrorResponse, ExecRunResult, Message, SuccessResponse, decode};

    use super::*;
    use crate::sessions::tests::fixture_on;

    /// The binary `name` built beside this test binary (`target/<profile>/<name>`), or `None` when only this crate
    /// was built.
    fn built(name: &str) -> Option<PathBuf> {
        let exe = std::env::current_exe().ok()?;
        let path = exe.parent()?.parent()?.join(name);
        path.is_file().then_some(path)
    }

    /// A private, canonical temporary directory, removed on drop. Short and under `/private/tmp`, so the engine
    /// sockets below it fit in a socket address (104 bytes).
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(name: &str) -> Self {
            let dir = PathBuf::from(format!("/private/tmp/knshd-{name}-{}", std::process::id()));
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

    /// One real envelope launch: the starter over the real launcher, with `home` as the user's home.
    struct Real {
        starter: Arc<AgentStarter>,
        fixture: Fixture,
    }

    impl Real {
        /// Profiles from `policies`, compiled profiles written to `profiles`, `knsh` as the envelope's `SHELL`.
        fn new(
            trampoline: PathBuf,
            home: &Path,
            policies: PathBuf,
            profiles: PathBuf,
            knsh: &CanonicalPath,
            proxy: Arc<dyn ProxyIssuer>,
        ) -> Self {
            let fixture = fixture_on(Some(Arc::new(SystemProcessTree::new())));
            let launcher = TrampolineLauncher {
                processes: Arc::new(SystemProcesses::new()),
                files: ProfileFiles::new(Arc::new(RealFs::new()), profiles, effective_uid(), sha256),
                trampoline,
                home: CanonicalPath::new(home).unwrap(),
                knsh: knsh.clone(),
            };
            let loader = ProfileLoader::new(
                Arc::new(RealFs::new()),
                policies,
                home.to_path_buf(),
                PathBuf::from("/private/tmp"),
                crate::policy::tests::test_signer(),
                Arc::new(knsh_platform::testing::RecordingLog::new()),
            );
            let starter = AgentStarter::new(
                Arc::clone(&fixture.sessions),
                loader,
                Arc::new(launcher),
                proxy,
                Arc::new(SystemClock::new()),
                home.join("shims"),
                knsh.as_path().to_path_buf(),
                effective_uid(),
            );
            Self { starter, fixture }
        }

        /// Runs `script` with `/bin/sh -c` as the agent CLI under `profile`, in `cwd`, with `HOME` at `home`. Answers
        /// the result and everything the CLI wrote to stdout and stderr.
        fn run(&self, profile: &str, cwd: &Path, home: &Path, script: &str) -> (SessionStartAgentResult, String) {
            let command = knsh_json::write(
                &ToJson::to_json(&vec!["/bin/sh".to_owned(), "-c".to_owned(), script.to_owned()]).unwrap(),
            )
            .unwrap();
            let params = format!(
                r#"{{"command":{command},"cwd":"{}","stdio":"passed","profile":"{profile}",
                    "env":{{"PATH":"/usr/bin:/bin","HOME":"{}"}}}}"#,
                cwd.display(),
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
            let answer = self.starter.handlers()[START_AGENT](&Call {
                endpoint: Endpoint::User,
                bytes: ByteTransport::BinaryFrames,
                stream: stream(),
                request: &request,
                subscriber: subscriber(),
                binding: &binding,
                descriptors: &passed,
                caller: &StillWaiting,
                control: None,
            })
            .unwrap();
            drop(passed);
            let result = SessionStartAgentResult::from_json(&answer.result).unwrap();
            let mut out = String::new();
            read.read_to_string(&mut out).unwrap();
            (result, out)
        }
    }

    // FR-AGT-01, FR-AGT-03, FR-SBX-01: the real launcher starts the CLI through `knsh-exec` under the envelope
    // profile, with `SHELL` and the session token set; the CLI's exit code comes back and the session ends. A write
    // outside the profile's write roots is denied, so the sandbox really was applied.
    #[test]
    fn real_envelope_runs_sandboxed_and_reports_its_exit_code() {
        let Some(trampoline) = built("knsh-exec") else {
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
            crate::policy::tests::signed(
                "it",
                &format!("name = \"it\"\n[fs]\nwrite = [\"{}\"]\n", work.display()),
            ),
        )
        .unwrap();
        let home = std::fs::canonicalize(std::env::var_os("HOME").unwrap()).unwrap();
        let knsh = CanonicalPath::new("/usr/bin/true").unwrap();
        let real = Real::new(
            trampoline,
            &home,
            policies,
            profiles,
            &knsh,
            Arc::new(crate::proxy::NoProxy),
        );
        let script = format!(
            "echo inside > {work}/ok && echo ok=$?; (echo x > {outside}/denied) 2>/dev/null; echo denied=$?; \
             echo shell=$SHELL; echo token=${{#KNSH_SESSION_TOKEN}}; echo proxy=${{HTTPS_PROXY-unset}}; exit 7",
            work = work.display(),
            outside = outside.display(),
        );
        let (result, out) = real.run("it", &work, &home, &script);

        assert_eq!(result.status, LineStatus::Exited(7), "{out}");
        assert_eq!(result.agent_id.as_str(), "sh");
        assert_eq!(
            out,
            format!(
                "ok=0\ndenied=1\nshell={}\ntoken=64\nproxy=unset\n",
                knsh.as_path().display()
            )
        );
        assert!(!outside.join("denied").exists());
        assert_eq!(real.fixture.sessions.live(), 0);
    }

    /// A one-line C program: `bootstrap_look_up` of `argv[1]`, printing the kernel result (KNSH-025's probe).
    const LOOKUP_C: &str = "#include <servers/bootstrap.h>\n#include <stdio.h>\n\
        int main(int argc, char **argv) { mach_port_t port; if (argc < 2) return 2;\n\
        printf(\"%d\\n\", bootstrap_look_up(bootstrap_port, argv[1], &port)); return 0; }\n";

    /// `bootstrap_look_up`'s answer when the sandbox refuses the lookup.
    const BOOTSTRAP_NOT_PRIVILEGED: &str = "1100";

    /// A stand-in supervisor on `agent.sock`: answers `hello` and runs nothing for `exec.run`, answering exit 0, so
    /// `knsh -c true` in the envelope succeeds exactly when it can reach `agent.sock` and talk to it. Every line it
    /// was asked to run is counted.
    fn serve_agent_socket(listener: UnixListener, lines: Arc<Mutex<Vec<String>>>) {
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { return };
                let lines = Arc::clone(&lines);
                std::thread::spawn(move || answer_client(&stream, &lines));
            }
        });
    }

    /// Reads through `recvmsg`, dropping (closing) the descriptors the client passes.
    struct Descriptors<'a>(&'a UnixStream);

    impl Read for Descriptors<'_> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            recv_with_descriptors(self.0, buf, &mut Vec::new())
        }
    }

    /// Answers one client of [`serve_agent_socket`] until it hangs up or sends something that is not a request.
    fn answer_client(stream: &UnixStream, lines: &Mutex<Vec<String>>) {
        let mut reader = FrameReader::new(Descriptors(stream));
        let mut writer = FrameWriter::new(stream.try_clone().unwrap());
        while let Ok(Some(Frame::Json(payload))) = reader.read_frame() {
            let Ok(Message::Request(request)) = decode(&payload) else {
                return;
            };
            let result = match request.method.as_str() {
                "hello" => Some(Value::Object(
                    Object::new()
                        .with("protocol", 1)
                        .unwrap()
                        .with("session_id", "01JCZ0000000000000000000CD")
                        .unwrap(),
                )),
                "exec.run" => {
                    let command = request
                        .params
                        .as_ref()
                        .and_then(|params| params.get("command"))
                        .and_then(Value::as_str)
                        .unwrap_or_default();
                    lines.lock().unwrap().push(command.to_owned());
                    let result = ExecRunResult {
                        record_id: None,
                        status: LineStatus::Exited(0),
                    };
                    Some(result.to_json().unwrap())
                }
                _ => None,
            };
            let message = match result {
                Some(result) => Message::Success(SuccessResponse { id: request.id, result }),
                None => Message::Error(ErrorResponse {
                    id: Some(request.id),
                    error: RpcError::new(ErrorCode::MethodNotFound),
                }),
            };
            writer.write_json(&message.to_value().unwrap()).unwrap();
            writer.flush().unwrap();
        }
    }

    /// A TCP listener on a free loopback port that answers every connection with `200`, keeping the first request
    /// it received.
    fn http_listener(requests: Arc<Mutex<Vec<String>>>) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { return };
                let mut request = Vec::new();
                let mut buf = [0u8; 1024];
                // Up to the end of the headers.
                while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                    match stream.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => request.extend_from_slice(&buf[..n]),
                    }
                }
                requests
                    .lock()
                    .unwrap()
                    .push(String::from_utf8_lossy(&request).into_owned());
                let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
            }
        });
        port
    }

    /// Standard base64, for the `Proxy-Authorization` the proxy should receive.
    fn base64(bytes: &[u8]) -> String {
        const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for chunk in bytes.chunks(3) {
            let n = chunk
                .iter()
                .enumerate()
                .fold(0u32, |n, (i, byte)| n | u32::from(*byte) << (16 - 8 * i));
            for i in 0..4 {
                if i <= chunk.len() {
                    out.push(char::from(ALPHABET[(n >> (18 - 6 * i) & 63) as usize]));
                } else {
                    out.push('=');
                }
            }
        }
        out
    }

    /// The value `key=` has in `out`, one `key=value` per line.
    fn field<'a>(out: &'a str, key: &str) -> Option<&'a str> {
        out.lines().find_map(|line| line.strip_prefix(key)?.strip_prefix('='))
    }

    /// Builds the lookup probe ([`LOOKUP_C`]) into `tools`, a folder the test profile trusts (not a write root).
    fn build_lookup(tools: &Path) -> PathBuf {
        let lookup = tools.join("lookup");
        std::fs::write(tools.join("lookup.c"), LOOKUP_C).unwrap();
        let built = Command::new("/usr/bin/cc")
            .arg("-o")
            .arg(&lookup)
            .arg(tools.join("lookup.c"))
            .status()
            .unwrap();
        assert!(built.success(), "cc is needed to build the lookup probe");
        lookup
    }

    /// Outside any envelope the probes succeed: `user.sock` accepts, the control service is merely unregistered
    /// (or registered), and the unlisted port answers. So a refusal inside the envelope is the sandbox's.
    fn assert_probes_succeed_outside(probes: &str) {
        let free = Command::new("/bin/sh").arg("-c").arg(probes).output().unwrap();
        let free = String::from_utf8_lossy(&free.stdout).into_owned();
        assert_eq!(field(&free, "user_sock"), Some("0"), "{free}");
        assert_ne!(field(&free, "control"), Some(BOOTSTRAP_NOT_PRIVILEGED), "{free}");
        assert_eq!(field(&free, "unlisted"), Some("0"), "{free}");
    }

    // KNSH-057 integration (FR-AUTH-16, FR-SBX-05, FR-AGT-03, FR-AGT-11, FR-NET-01): from inside a real envelope,
    // connecting to `user.sock` fails, a lookup of `knsh.control` is refused by the sandbox, a direct `curl` that
    // ignores the proxy fails (to a loopback port the profile does not list, and to an outside address), while
    // `$SHELL -c true` (`knsh -c true`) reaches `agent.sock` and succeeds, the profile's loopback port is reachable,
    // and a `curl` that follows the proxy settings reaches the proxy's port with the envelope's own credentials. Every
    // refused probe is first run outside the envelope, where it succeeds, so each refusal is the sandbox's. A child of
    // the CLI (`sh -c` again) is confined the same way.
    #[test]
    fn envelope_confines_sockets_services_and_network() {
        let (Some(trampoline), Some(knsh)) = (built("knsh-exec"), built("knsh")) else {
            eprintln!("knsh-exec or knsh is not built beside this test: run `cargo test --workspace`; skipped");
            return;
        };
        let knsh = CanonicalPath::new(std::fs::canonicalize(knsh).unwrap()).unwrap();
        let scratch = Scratch::new("env");
        let home = scratch.dir("h");
        let paths = EnginePaths::for_home(&home).unwrap();
        knsh_platform::ensure_engine_dirs(&RealFs::new(), &paths, effective_uid()).unwrap();
        let (policies, profiles, work, tools) = (
            scratch.dir("policies"),
            scratch.dir("profiles"),
            scratch.dir("work"),
            scratch.dir("tools"),
        );

        let lookup = build_lookup(&tools);

        // The sockets: user.sock bound (so a connection would succeed), agent.sock served by the stand-in.
        let _user = UnixListener::bind(paths.user_socket()).unwrap();
        let lines = Arc::new(Mutex::new(Vec::new()));
        serve_agent_socket(UnixListener::bind(paths.agent_socket()).unwrap(), Arc::clone(&lines));
        // The network: a listed loopback port, an unlisted one, and the proxy's.
        let (listed_seen, unlisted_seen, proxy_seen) = (
            Arc::new(Mutex::new(Vec::new())),
            Arc::new(Mutex::new(Vec::new())),
            Arc::new(Mutex::new(Vec::new())),
        );
        let listed = http_listener(Arc::clone(&listed_seen));
        let unlisted = http_listener(Arc::clone(&unlisted_seen));
        let proxy_port = http_listener(Arc::clone(&proxy_seen));

        let profile = format!(
            "name = \"it\"\n[fs]\nwrite = [\"{}\"]\n[exec]\ntrusted_folders = [\"{}\"]\n[network]\nloopback = \
             [{listed}]\n",
            work.display(),
            tools.display()
        );
        std::fs::write(policies.join("it.toml"), crate::policy::tests::signed("it", &profile)).unwrap();

        let user_sock = paths.user_socket();
        let probes = format!(
            "nc -U -w 1 '{user}' </dev/null >/dev/null 2>&1; echo user_sock=$?\n\
             echo control=$('{lookup}' {control})\n\
             echo unknown=$('{lookup}' com.knsh.test.unregistered)\n\
             curl --noproxy '*' -s -m 3 -o /dev/null http://127.0.0.1:{unlisted}/; echo unlisted=$?\n\
             curl --noproxy '*' -s -m 3 -o /dev/null http://127.0.0.1:{listed}/; echo listed=$?\n\
             curl --noproxy '*' -s -m 3 -o /dev/null http://1.1.1.1/; echo outside=$?\n",
            user = user_sock.display(),
            lookup = lookup.display(),
            control = knsh_core::CONTROL_SERVICE,
        );

        assert_probes_succeed_outside(&probes);
        assert_eq!(unlisted_seen.lock().unwrap().len(), 1);

        let real = Real::new(
            trampoline,
            &home,
            policies,
            profiles,
            &knsh,
            Arc::new(FakeProxy::new(proxy_port)),
        );
        // Through the proxy settings: an `http://` URL goes to the proxy as an absolute-form request.
        let script = format!(
            "{probes}curl -s -m 3 -o /dev/null http://example.invalid/; echo proxied=$?\n\
             /bin/sh -c \"nc -U -w 1 '{user}' </dev/null >/dev/null 2>&1\"; echo child_user_sock=$?\n\
             \"$SHELL\" -c true; echo knsh=$?\n",
            user = user_sock.display(),
        );
        let (result, out) = real.run("it", &work, &home, &script);
        assert_eq!(result.status, LineStatus::Exited(0), "{out}");

        assert_eq!(field(&out, "user_sock"), Some("1"), "user.sock denied: {out}");
        assert_eq!(
            field(&out, "child_user_sock"),
            Some("1"),
            "a child is confined too: {out}"
        );
        assert_eq!(field(&out, "control"), Some(BOOTSTRAP_NOT_PRIVILEGED), "{out}");
        // The broad Mach allow stays: an unregistered name is unknown (1102), not refused.
        assert_eq!(field(&out, "unknown"), Some("1102"), "{out}");
        assert_ne!(field(&out, "unlisted"), Some("0"), "{out}");
        assert_eq!(
            unlisted_seen.lock().unwrap().len(),
            1,
            "nothing new reached the unlisted port"
        );
        assert_eq!(field(&out, "listed"), Some("0"), "{out}");
        assert_ne!(field(&out, "outside"), Some("0"), "{out}");
        assert_eq!(field(&out, "proxied"), Some("0"), "{out}");
        let proxied = proxy_seen.lock().unwrap().clone();
        assert_eq!(proxied.len(), 1, "{proxied:?}");
        assert!(
            proxied[0].starts_with("GET http://example.invalid/ HTTP/1.1\r\n"),
            "{}",
            proxied[0]
        );
        let credentials = base64(format!("knsh-1:{}", FakeProxy::TOKEN).as_bytes());
        assert!(
            proxied[0].contains(&format!("\r\nProxy-Authorization: Basic {credentials}\r\n")),
            "{}",
            proxied[0]
        );
        assert_eq!(field(&out, "knsh"), Some("0"), "{out}");
        assert_eq!(*lines.lock().unwrap(), ["true"]);
        assert_eq!(real.fixture.sessions.live(), 0);
    }
}

/// A policy that denies every exec; envelope tests never deliver one.
struct DenyExecs;

impl crate::endpoint_security::ExecPolicy for DenyExecs {
    fn decide_exec(
        &self,
        _request: &crate::endpoint_security::ExecRequest,
        _gate: &crate::endpoint_security::ExecGate,
    ) -> knsh_platform::ExecVerdict {
        knsh_platform::ExecVerdict::Deny
    }
}

/// The Endpoint Security layer over `clients`, attached to `harness`'s starter.
fn attach_layer(harness: &Harness, clients: &Arc<knsh_platform::testing::ScriptedDescendantClients>) {
    use crate::endpoint_security::{ExecAuthoriser, ExecLayer};

    let authoriser = ExecAuthoriser::new(
        Arc::new(DenyExecs),
        Arc::new(FakeClock::new(knsh_core::Timestamp::UNIX_EPOCH)),
    );
    harness.starter.attach_exec_layer(Arc::new(ExecLayer::new(
        clients.clone(),
        Arc::new(authoriser),
        CanonicalPath::new("/opt/knsh/bin/knsh-exec").unwrap(),
        CanonicalPath::new(KNSH).unwrap(),
        shim_dir(),
    )));
}

// KNSH-094 (FR-AGT-13): with the Endpoint Security layer, each envelope gets its own descendant client before it starts,
// deleted once the envelope has ended.
#[test]
fn envelope_gets_a_descendant_client_with_the_layer() {
    let harness = harness();
    let clients = Arc::new(knsh_platform::testing::ScriptedDescendantClients::new());
    attach_layer(&harness, &clients);
    harness.launcher.processes.expect(ENVELOPE, Script::Exits(0));
    let result = start(&harness, &params(r#"["claude"]"#, r#","profile":"web""#)).unwrap();
    assert_eq!(result.status, LineStatus::Exited(0));
    assert_eq!(clients.watched(), 1);
    assert_eq!(clients.live(), 0, "deleted with the envelope");
    assert_eq!(harness.launcher.launched.lock().unwrap().len(), 1);
}

// KNSH-094 (fail closed): when `hello` reports the layer but an envelope's client cannot be created, nothing starts and
// the session ends: no envelope runs undecided under a promise that it is decided.
#[test]
fn envelope_without_its_client_never_starts() {
    let harness = harness();
    let clients = Arc::new(knsh_platform::testing::ScriptedDescendantClients::failing(
        knsh_platform::PlatformError::EndpointSecurityUnavailable,
    ));
    attach_layer(&harness, &clients);
    let error = start(&harness, &params(r#"["claude"]"#, r#","profile":"web""#)).unwrap_err();
    assert_eq!(error.code, ErrorCode::InternalError);
    assert!(harness.launcher.launched.lock().unwrap().is_empty());
    assert_eq!(harness.fixture.sessions.live(), 0);
    // The envelope's credentials were issued and revoked again.
    assert_eq!(
        *harness.proxy.issued.lock().unwrap(),
        *harness.proxy.revoked.lock().unwrap()
    );
}

// KNSH-094 (decision 3): without the layer (macOS 14 to 26, no entitlement) no client is tried and the envelope starts
// as before, with nothing about Endpoint Security reaching the caller.
#[test]
fn envelope_starts_without_a_client_when_the_layer_is_absent() {
    let harness = harness();
    harness.launcher.processes.expect(ENVELOPE, Script::Exits(0));
    let result = start(&harness, &params(r#"["claude"]"#, r#","profile":"web""#)).unwrap();
    assert_eq!(result.status, LineStatus::Exited(0));
    assert_eq!(harness.launcher.launched.lock().unwrap().len(), 1);
}
