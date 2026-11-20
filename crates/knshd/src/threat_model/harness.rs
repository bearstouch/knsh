//! A real `knshd` in miniature for the threat-model suite (KNSH-075), wired as `main` wires it.
//!
//! [`Stack`] holds, in a private temporary directory under `/private/tmp`:
//!
//! - a home with real engine directories (owner-only), its policies directory holding profiles signed with the test
//!   key, and a project;
//! - sessions over a real record store, matched against the real process table;
//! - the real network proxy (`knsh-proxy`) behind the real host rules, over a [`FakeResolver`] so no name is
//!   resolved on the network and every address is chosen by the case;
//! - the supervisor ([`Lifecycle`]) with the real [`TrampolineSpawner`]: every line runs through the `knsh-exec` built
//!   beside this test binary, under its compiled profile, with its own proxy credentials;
//! - the envelope launcher ([`AgentStarter`] over [`TrampolineLauncher`]);
//! - the connection [`Server`] on the home's real `user.sock` and `agent.sock`, with the dispatcher `knshd` serves
//!   (`exec.*` and `session.start_agent` included).
//!
//! Stand-ins: no hooks, no authority, approvals nobody answers (an ask is denied at a short timeout), and the
//! resolver. Probes the cases need (`bootstrap_look_up`, `KERN_PROCARGS2`) are built with `cc` into a folder the
//! case's profile trusts, as an agent CLI's own folder would be.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, UdpSocket};
use std::os::fd::OwnedFd;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use knsh_core::{
    Actor, AgentId, CanonicalPath, ExecutionRecord, NoAuthority, NoHooks, ProfileName, SessionId, StillWaiting,
};
use knsh_json::FromJson;
use knsh_platform::macos::{
    RealFs, SystemClock, SystemPeerCredentials, SystemProcessTree, SystemProcesses, SystemRandom, effective_uid, sha256,
};
use knsh_platform::testing::{FakeResolver, RecordingLog};
use knsh_platform::{EnginePaths, SystemLog};
use knsh_proto::{
    ByteTransport, Interpreter, LineStatus, MethodName, Request, RequestId, RpcError, SessionStartAgentResult,
};
use knsh_proxy::{Config, HostRules, Parts as ProxyParts, Proxy};
use knsh_store::{PageSize, RecordQuery, Scope};

use super::report::Case;
use crate::dispatch::tests::{stream, subscriber};
use crate::dispatch::{Call, Endpoint, Passed, START_AGENT};
use crate::endpoints::Listeners;
use crate::exec::{ExecRun, Finished, ForwardedLine, Proposal};
use crate::grants::GrantStore;
use crate::hooks::HookRunner;
use crate::policy::ProfileLoader;
use crate::profiles::ProfileFiles;
use crate::proxy::{LiveProxy, NetworkReport, ProxyIssuer};
use crate::server::{Config as ServerConfig, Server, Services, StopHandle};
use crate::sessions::SessionBinding;
use crate::sessions::tests::{Fixture, fixture_on, fixture_with};
use crate::spawn::{Limits, TrampolineSpawner};
use crate::start_agent::{AgentStarter, TrampolineLauncher};
use crate::supervisor::{Lifecycle, Parts, Spawner};

/// The `PATH` lines and envelopes run with.
pub(crate) const PATH: &str = "/usr/bin:/bin:/usr/sbin:/sbin";

/// How long an ask waits before it is denied: nobody answers in these cases.
const ASK_TIMEOUT: Duration = Duration::from_millis(300);

/// How long [`Stack::line`] lets a line run before it is killed, in seconds.
pub(crate) const LINE_TIMEOUT_S: u64 = 60;

/// The binaries a case needs beside this test binary.
pub(crate) struct Binaries {
    /// `knsh-exec`.
    pub(crate) trampoline: PathBuf,
    /// `knsh`, canonical: the envelope's `SHELL` and the client inside it.
    pub(crate) knsh: CanonicalPath,
}

/// `knsh-exec` and `knsh` built beside this test binary (`target/<profile>/`), or `None` after marking `case`
/// blocked: `cargo test -p knshd` alone does not build them.
pub(super) fn binaries(case: Case) -> Option<(Case, Binaries)> {
    if let Some(binaries) = built_binaries() {
        return Some((case, binaries));
    }
    case.blocked("knsh-exec or knsh is not built beside the test binary: run `cargo test --workspace`");
    None
}

/// `knsh-exec` and `knsh` built beside this test binary, or `None` when either is missing.
pub(crate) fn built_binaries() -> Option<Binaries> {
    let trampoline = built("knsh-exec")?;
    let knsh = CanonicalPath::new(std::fs::canonicalize(built("knsh")?).ok()?).ok()?;
    Some(Binaries { trampoline, knsh })
}

/// The workspace binary `name` built beside this test binary (`target/<profile>/<name>`), if it was built.
pub(crate) fn built(name: &str) -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let path = exe.parent()?.parent()?.join(name);
    path.is_file().then_some(path)
}

/// A private, canonical temporary directory, removed on drop. Short and under `/private/tmp`, so the engine sockets
/// below it fit in a socket address (104 bytes).
pub(crate) struct Scratch(pub(crate) PathBuf);

impl Scratch {
    /// A new directory for `tag` (at most 8 characters).
    pub(crate) fn new(tag: &str) -> Self {
        let dir = PathBuf::from(format!("/private/tmp/knsh-tm-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        Self(std::fs::canonicalize(&dir).unwrap())
    }

    /// A new owner-only directory `name` inside.
    pub(crate) fn dir(&self, name: &str) -> PathBuf {
        let dir = self.0.join(name);
        owner_only_dir(&dir);
        dir
    }
}

/// Creates `dir` (and its parents) and makes it owner-only, as engine directories are.
fn owner_only_dir(dir: &Path) {
    std::fs::create_dir_all(dir).unwrap();
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).unwrap();
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The real `knshd` parts, running (module documentation).
pub(crate) struct Stack {
    /// The user's home: engine directories, sockets and policies below it.
    pub(crate) home: PathBuf,
    /// The engine paths of [`Stack::home`].
    pub(crate) paths: EnginePaths,
    /// The project lines run in: `${PROJECT}`.
    pub(crate) project: PathBuf,
    /// A folder the cases' profiles trust (`exec.trusted_folders`) and never make writable: probes go here.
    pub(crate) tools: PathBuf,
    /// A folder no profile can write.
    pub(crate) outside: PathBuf,
    fixture: Fixture,
    /// The names the proxy resolves, and to what.
    pub(crate) resolver: Arc<FakeResolver>,
    /// The live grants every line is evaluated with.
    pub(crate) grants: Arc<GrantStore>,
    lifecycle: Arc<Lifecycle>,
    starter: Arc<AgentStarter>,
    /// The server's stop handle and thread, taken once when `knshd` goes away.
    stop: Mutex<Option<(StopHandle, JoinHandle<()>)>>,
    /// Holds every path above. The last field, so it is removed after everything that uses it has stopped.
    _scratch: Scratch,
}

/// What [`Stack::start_with`] wires differently from the threat-model cases. The default is what they use.
#[derive(Default)]
pub(crate) struct Wiring {
    /// Replaces the real [`TrampolineSpawner`]: lines are decided and recorded but this spawner runs them. The phase
    /// 2 qualification (KNSH-076) times the decision with one that starts nothing.
    pub(crate) spawner: Option<Arc<dyn Spawner>>,
    /// Runs the hooks registered in the home's configuration file through the real [`HookRunner`], instead of none.
    pub(crate) hooks: bool,
    /// Stamps events with the system clock instead of the fixture's fake one, so an event's `ts` is the time it was
    /// published.
    pub(crate) real_clock: bool,
}

impl Wiring {
    /// The sessions, record store and event hub over the real process table, the hub stamping events with the
    /// system clock when `real_clock`.
    fn fixture(real_clock: bool) -> Fixture {
        let processes: Arc<dyn knsh_platform::ProcessTree> = Arc::new(SystemProcessTree::new());
        if !real_clock {
            return fixture_on(Some(processes));
        }
        let hub = crate::events::EventHub::new(
            knsh_core::EventBus::new(knsh_core::BusLimits::default()),
            Arc::new(SystemClock::new()),
            Arc::new(SystemRandom::new()),
        );
        fixture_with(Some(processes), hub)
    }

    /// The hooks the supervisor runs: when `real`, as `main` wires them (the configuration file under `paths` read
    /// for every line, hooks started as real processes); otherwise none.
    fn hooks(real: bool, paths: &EnginePaths, home: &Path) -> Arc<dyn knsh_core::Hooks + Send + Sync> {
        if !real {
            return Arc::new(NoHooks);
        }
        Arc::new(HookRunner::new(
            Arc::new(RealFs::new()),
            Arc::new(SystemProcesses::new()),
            paths.config_file(),
            home.to_path_buf(),
            effective_uid(),
        ))
    }
}

impl Stack {
    /// Starts the parts. `tag` names the scratch directory (at most 8 characters: socket paths are short).
    pub(crate) fn start(tag: &str, binaries: &Binaries) -> Self {
        Self::start_with(tag, binaries, Wiring::default())
    }

    /// [`Stack::start`], wired as `wiring` says.
    pub(crate) fn start_with(tag: &str, binaries: &Binaries, wiring: Wiring) -> Self {
        let scratch = Scratch::new(tag);
        let home = scratch.dir("h");
        let paths = EnginePaths::for_home(&home).unwrap();
        knsh_platform::ensure_engine_dirs(&RealFs::new(), &paths, effective_uid()).unwrap();
        // `knsh policy edit` makes the policies directory on first save; profiles are written here directly.
        owner_only_dir(&paths.policies_dir());
        let project = home.join("app");
        std::fs::create_dir_all(&project).unwrap();
        let (tools, outside) = (scratch.dir("tools"), scratch.dir("out"));

        let fixture = Wiring::fixture(wiring.real_clock);
        let log: Arc<dyn SystemLog> = Arc::new(RecordingLog::new());
        let clock = Arc::new(SystemClock::new());
        let random = Arc::new(SystemRandom::new());
        let canonical_home = CanonicalPath::new(&home).unwrap();

        let (resolver, proxy) = start_proxy(&log, &fixture);

        let loader = ProfileLoader::new(
            Arc::new(RealFs::new()),
            paths.policies_dir(),
            home.clone(),
            PathBuf::from("/private/tmp"),
            crate::policy::tests::test_signer(),
            Arc::clone(&log),
        );
        let files = || ProfileFiles::new(Arc::new(RealFs::new()), paths.profiles_dir(), effective_uid(), sha256);
        let spawner = TrampolineSpawner {
            processes: Arc::new(SystemProcesses::new()),
            clock: clock.clone(),
            files: files(),
            log: Arc::clone(&log),
            trampoline: binaries.trampoline.clone(),
            home: canonical_home.clone(),
            limits: Limits::DEFAULT,
            proxy: Arc::clone(&proxy),
        };
        let grants = GrantStore::new();
        let spawner: Arc<dyn Spawner> = wiring.spawner.unwrap_or_else(|| Arc::new(spawner));
        let hooks = Wiring::hooks(wiring.hooks, &paths, &home);
        let lifecycle = Lifecycle::new(Parts {
            sessions: Arc::clone(&fixture.sessions),
            profiles: loader.clone(),
            events: Arc::clone(&fixture.hub),
            store: Some(fixture.store.clone()),
            clock: clock.clone(),
            random: random.clone(),
            hooks,
            authority: Arc::new(NoAuthority),
            approvals: crate::approvals::tests::unanswered(ASK_TIMEOUT),
            grants: Arc::clone(&grants),
            spawner,
            redactors: crate::redaction::Redactors::none(),
        });
        let launcher = TrampolineLauncher {
            processes: Arc::new(SystemProcesses::new()),
            files: files(),
            trampoline: binaries.trampoline.clone(),
            home: canonical_home,
            knsh: binaries.knsh.clone(),
        };
        let starter = AgentStarter::new(
            Arc::clone(&fixture.sessions),
            loader.clone(),
            Arc::new(launcher),
            proxy,
            clock.clone(),
            paths.shim_dir(),
            binaries.knsh.as_path().to_path_buf(),
        );

        // The dispatcher `knshd` serves, as `agents::endpoint_tests::dispatcher` builds it, with the real `exec.*`
        // and `session.start_agent` in place of the unserved ones.
        let mut handlers = crate::records::Records::new(Some(fixture.store.clone())).handlers();
        handlers.extend(fixture.hub.handlers());
        handlers.extend(fixture.sessions.handlers());
        handlers.extend(crate::policy::PolicyCheck::new(Arc::clone(&fixture.sessions), loader).handlers());
        handlers.extend(crate::policy_edit::tests::idle_handlers());
        handlers.extend(crate::approvals::tests::idle_handlers());
        handlers.extend(crate::authority::tests::idle_handlers());
        handlers.extend(ExecRun::new(Arc::clone(&lifecycle) as _, paths.shim_dir()).handlers());
        handlers.extend(starter.handlers());
        handlers.extend(crate::checkpoints::tests::idle_handlers());
        let server = serve(&paths, &fixture, handlers, log);

        Self {
            home,
            paths,
            project,
            tools,
            outside,
            fixture,
            resolver,
            grants,
            lifecycle,
            starter,
            stop: Mutex::new(Some(server)),
            _scratch: scratch,
        }
    }

    /// Writes profile `name` (`text` without its `name` key) into the policies directory, signed as `knsh policy
    /// edit` signs it. Profiles are read for every line, so it takes effect at once.
    pub(crate) fn profile(&self, name: &str, text: &str) {
        std::fs::write(
            self.policy_file(name),
            crate::policy::tests::signed(name, &format!("name = \"{name}\"\n{text}")),
        )
        .unwrap();
    }

    /// The file profile `name` is read from.
    pub(crate) fn policy_file(&self, name: &str) -> PathBuf {
        self.paths.policies_dir().join(format!("{name}.toml"))
    }

    /// `knshd` goes away: the server stops and its listeners close, as when the process dies. The socket files
    /// stay, as launchd's would.
    pub(crate) fn stop_knshd(&self) {
        let taken = self.stop.lock().unwrap().take();
        if let Some((stop, server)) = taken {
            let _ = stop.stop();
            let _ = server.join();
        }
    }

    /// Every event published from now on, for every session.
    pub(crate) fn watch(&self) -> crate::events::Subscriber {
        crate::sessions::tests::watch(&self.fixture.hub)
    }

    /// Opens an agent session under `profile`, as `session.start_agent` would before its envelope starts.
    pub(crate) fn session(&self, profile: &str) -> SessionId {
        self.fixture
            .sessions
            .open_agent(
                Actor::Agent(AgentId::new("claude-code").unwrap()),
                ProfileName::new(profile).unwrap(),
            )
            .unwrap()
            .session_id
    }

    /// Forwards `command` for `session` as `knsh -c` would (`exec.run`, captured output), in the project, with
    /// `env` on top of `HOME` and `PATH`, and waits for the answer.
    pub(crate) fn line(&self, session: SessionId, command: &str, env: &[(&str, &str)]) -> Result<Finished, RpcError> {
        self.line_with(session, command, env, PATH, Some(LINE_TIMEOUT_S))
    }

    /// As [`Stack::line`], with names resolved on `path`, and killed after `timeout_s`.
    pub(crate) fn line_with(
        &self,
        session: SessionId,
        command: &str,
        env: &[(&str, &str)],
        path: &str,
        timeout_s: Option<u64>,
    ) -> Result<Finished, RpcError> {
        let mut vars = vec![
            ("HOME".to_owned(), self.home.display().to_string()),
            ("PATH".to_owned(), path.to_owned()),
        ];
        vars.extend(
            env.iter()
                .map(|(name, value)| ((*name).to_owned(), (*value).to_owned())),
        );
        let line = ForwardedLine {
            session_id: session,
            proposal: Proposal {
                command: command.to_owned(),
                cwd: CanonicalPath::new(&self.project).unwrap(),
                path: path.to_owned(),
            },
            interpreter: Interpreter::Bash,
            args: Vec::new(),
            env: vars,
            stdio: None,
            timeout_s,
            checkpoint_wait: true,
            control: crate::jobs::LineControl::new(),
        };
        crate::exec::Supervisor::run(&*self.lifecycle, line, &StillWaiting)
    }

    /// The record `finished` was written to.
    pub(crate) fn record_of(&self, session: SessionId, finished: &Finished) -> ExecutionRecord {
        let id = finished.record_id.expect("the line was recorded");
        self.records(session)
            .into_iter()
            .find(|record| record.record_id == id)
            .expect("the record is stored")
    }

    /// Every record of `session`, page after page.
    pub(crate) fn records(&self, session: SessionId) -> Vec<ExecutionRecord> {
        let mut records = Vec::new();
        let mut after = None;
        loop {
            let page = self
                .fixture
                .store
                .query(
                    Scope::All,
                    RecordQuery {
                        session: Some(session),
                        since: None,
                        until: None,
                        text: None,
                        after,
                        limit: PageSize::new(100).unwrap(),
                    },
                )
                .unwrap();
            records.extend(page.records.into_iter().map(|stored| stored.record));
            match page.next_cursor {
                Some(cursor) => after = Some(cursor),
                None => return records,
            }
        }
    }

    /// Starts `/bin/sh -c script` as the agent CLI through `session.start_agent` on `user.sock`'s handler, under
    /// `profile`, in the project, with `HOME` at the stack's home. Answers how it ended and everything it wrote to
    /// stdout and stderr.
    pub(crate) fn envelope(&self, profile: &str, script: &str) -> (LineStatus, String) {
        let command = knsh_json::write(
            &knsh_json::ToJson::to_json(&vec!["/bin/sh".to_owned(), "-c".to_owned(), script.to_owned()]).unwrap(),
        )
        .unwrap();
        let params = format!(
            r#"{{"command":{command},"cwd":"{}","stdio":"passed","profile":"{profile}",
                "env":{{"PATH":"{PATH}","HOME":"{}"}}}}"#,
            self.project.display(),
            self.home.display()
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
        (result.status, out)
    }

    /// Builds the C program `source` with `cc` into [`Stack::tools`] as `name`.
    pub(crate) fn build_probe(&self, name: &str, source: &str) -> PathBuf {
        let program = self.tools.join(name);
        compile_c(source, &program);
        program
    }
}

/// Builds the C program `source` with `cc` into `program`. The linker signs it ad hoc, as it signs any program
/// built here.
pub(crate) fn compile_c(source: &str, program: &Path) {
    let mut cc = Command::new("/usr/bin/cc")
        .args(["-x", "c", "-", "-o"])
        .arg(program)
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    cc.stdin.take().unwrap().write_all(source.as_bytes()).unwrap();
    assert!(cc.wait().unwrap().success(), "cc failed to build {}", program.display());
}

/// The proxy `main` starts (`start_proxy`), with the gate `knshd` runs (host rules), over a stand-in resolver the
/// case fills: the resolver, and the issuer envelopes and lines get their credentials from.
fn start_proxy(log: &Arc<dyn SystemLog>, fixture: &Fixture) -> (Arc<FakeResolver>, Arc<dyn ProxyIssuer>) {
    let resolver = Arc::new(FakeResolver::new());
    let rules = Arc::new(HostRules::new(resolver.clone()));
    let report = NetworkReport::new(
        Arc::clone(log),
        Arc::clone(&fixture.hub),
        crate::redaction::Redactors::none(),
    );
    let proxy = Proxy::start(
        Config::DEFAULT,
        ProxyParts {
            gate: Arc::clone(&rules) as Arc<dyn knsh_proxy::ConnectionGate>,
            report: Arc::clone(&report) as Arc<dyn knsh_proxy::ProxyReport>,
            random: Arc::new(SystemRandom::new()),
            clock: Arc::new(SystemClock::new()),
        },
    )
    .unwrap();
    (resolver, Arc::new(LiveProxy::new(proxy, rules, report)))
}

/// Serves `handlers` (plus `hello`, with every backend reported available) on the real `user.sock` and `agent.sock`
/// of `paths`, as `knshd` does once launchd hands it the sockets: peers are checked by their real credentials and
/// agent connections bound by their audit tokens against the real process table.
fn serve(
    paths: &EnginePaths,
    fixture: &Fixture,
    handlers: crate::dispatch::Handlers,
    log: Arc<dyn SystemLog>,
) -> (StopHandle, JoinHandle<()>) {
    let dispatcher = crate::hello::dispatcher_with_violations(
        crate::probe::probe(&crate::probe::tests::Machine::working().probes()),
        handlers,
        crate::violations::ReaderStatus::stopped(),
        Arc::clone(&fixture.sessions),
    )
    .unwrap();
    let services = Services {
        dispatcher: Arc::new(dispatcher),
        credentials: Arc::new(SystemPeerCredentials::new()),
        log,
        own_uid: effective_uid(),
        clock: Arc::new(SystemClock::new()),
        activity: Arc::clone(&fixture.sessions) as _,
        pending: Arc::new(crate::records::Records::new(Some(fixture.store.clone()))),
    };
    let listeners = Listeners {
        user: vec![UnixListener::bind(paths.user_socket()).unwrap()],
        agent: vec![UnixListener::bind(paths.agent_socket()).unwrap()],
    };
    let server = Server::new(listeners, services, ServerConfig::DEFAULT).unwrap();
    let stop = server.stop_handle();
    let thread = std::thread::spawn(move || {
        let _ = server.run();
    });
    (stop, thread)
}

impl Drop for Stack {
    fn drop(&mut self) {
        self.stop_knshd();
    }
}

/// The text of a captured stream of `finished`: stdout and stderr.
pub(crate) fn output(finished: &Finished) -> (String, String) {
    let text = |stream: &knsh_core::CapturedStream| {
        let (data, _) = stream.output.clone().into_parts();
        String::from_utf8_lossy(data.expose()).into_owned()
    };
    finished
        .output
        .as_ref()
        .map_or_else(Default::default, |output| (text(&output.stdout), text(&output.stderr)))
}

/// The value `key=` has in `out`, one `key=value` per line.
pub(crate) fn field<'a>(out: &'a str, key: &str) -> Option<&'a str> {
    out.lines().find_map(|line| line.strip_prefix(key)?.strip_prefix('='))
}

/// The active developer directory (`xcode-select -p`), canonical: `/usr/bin` stubs (`git`, `python3`) run its
/// tools, so profiles that run them trust it, as a user's profile would.
pub(crate) fn developer_dir() -> PathBuf {
    let output = Command::new("/usr/bin/xcode-select").arg("-p").output().unwrap();
    assert!(
        output.status.success(),
        "no developer directory: install the Command Line Tools"
    );
    std::fs::canonicalize(String::from_utf8(output.stdout).unwrap().trim()).unwrap()
}

/// What a local server received, connection by connection.
pub(crate) type Received = Arc<Mutex<Vec<Vec<u8>>>>;

/// A TCP server on loopback that records each connection's first bytes (for up to two seconds) and closes. Speaks
/// no TLS: a TLS client fails after its hello, which is all a case needs to see where its bytes went.
pub(crate) fn recording_tcp() -> (SocketAddr, Received) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let received: Received = Arc::default();
    let sink = Arc::clone(&received);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { return };
            let sink = Arc::clone(&sink);
            std::thread::spawn(move || {
                stream.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
                let mut data = Vec::new();
                let mut buf = [0; 4096];
                while let Ok(read) = stream.read(&mut buf) {
                    if read == 0 {
                        break;
                    }
                    data.extend_from_slice(&buf[..read]);
                }
                sink.lock().unwrap().push(data);
            });
        }
    });
    (address, received)
}

/// A UDP socket on loopback that records every datagram it receives: a DNS server a line might query directly.
pub(crate) fn recording_udp() -> (SocketAddr, Received) {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let address = socket.local_addr().unwrap();
    let received: Received = Arc::default();
    let sink = Arc::clone(&received);
    std::thread::spawn(move || {
        let mut buf = [0; 1500];
        while let Ok((read, _)) = socket.recv_from(&mut buf) {
            sink.lock().unwrap().push(buf[..read].to_vec());
        }
    });
    (address, received)
}

/// Waits up to `limit` for `condition`.
pub(crate) fn wait_for(limit: Duration, mut condition: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + limit;
    while !condition() {
        if Instant::now() > deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    true
}

/// `bootstrap_look_up` of `argv[1]`, printing the kernel result (KNSH-025's probe).
pub(crate) const LOOKUP_C: &str = "#include <servers/bootstrap.h>\n#include <stdio.h>\n\
    int main(int argc, char **argv) { mach_port_t port; if (argc < 2) return 2;\n\
    printf(\"%d\\n\", bootstrap_look_up(bootstrap_port, argv[1], &port)); return 0; }\n";

/// `bootstrap_look_up`'s answer when the sandbox refuses the lookup.
pub(crate) const BOOTSTRAP_NOT_PRIVILEGED: &str = "1100";

/// Reads process `argv[1]`'s arguments and environment (`KERN_PROCARGS2`) and looks for `argv[2]` in them: prints
/// `found`, `absent`, or `refused <errno>` when the kernel will not tell.
pub(crate) const PROCARGS_C: &str = "#include <sys/sysctl.h>\n#include <stdio.h>\n#include <stdlib.h>\n\
    #include <string.h>\n#include <errno.h>\n\
    int main(int argc, char **argv) { if (argc < 3) return 2;\n\
    int mib[3] = { CTL_KERN, KERN_PROCARGS2, atoi(argv[1]) }; static char buf[1 << 18]; size_t size = sizeof buf;\n\
    if (sysctl(mib, 3, buf, &size, NULL, 0) != 0) { printf(\"refused %d\\n\", errno); return 1; }\n\
    size_t needle = strlen(argv[2]);\n\
    for (size_t i = 0; i + needle <= size; i++) if (memcmp(buf + i, argv[2], needle) == 0) { puts(\"found\"); \
    return 0; }\n\
    puts(\"absent\"); return 0; }\n";

/// Whether `path` (a directory or file) exists, as the test process (outside any sandbox) sees it.
pub(crate) fn exists(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok()
}
