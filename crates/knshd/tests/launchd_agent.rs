//! launchd lifecycle integration test (KNSH-012, KNSH-013): install the agent, connect to `user.sock` and complete
//! `hello`, observe launchd start `knshd`; crash it, observe launchd restart it, and reconnect; kill it, and observe
//! the next connection start it; stop it with `SIGTERM`, observe an orderly exit without a restart, and reconnect.
//!
//! Ignored by default because it loads a job into the logged-in user's GUI domain (`gui/<uid>`), which CI runners
//! and SSH sessions may not have. Run it with:
//!
//! ```sh
//! cargo test -p knshd --test launchd_agent -- --ignored
//! ```
//!
//! It never touches the real agent: it uses its own label and Mach service name and a temporary home under
//! `/private/tmp` (short, because socket paths are limited to 103 bytes), so the property list, the sockets, the
//! engine directories and a copy of `knshd` all live there. The job is unloaded and the home removed on drop, also
//! when the test fails.

#![cfg(all(test, target_os = "macos"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fs;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use knsh_json::{Frame, FrameReader, FrameWriter};
use knsh_platform::macos::{Launchctl, RealFs, effective_uid};
use knsh_platform::{EnginePaths, LaunchAgent, ServiceManager, install_agent};
use knsh_proto::Message;

/// How long to wait for launchd to (re)start `knshd`. Its default throttle between launches is 10 seconds.
const LAUNCH_TIMEOUT: Duration = Duration::from_secs(30);

/// An installed test agent: unloaded and its home removed on drop.
struct TestAgent {
    agent: LaunchAgent,
    home: PathBuf,
    uid: u32,
}

impl TestAgent {
    fn install() -> Self {
        let pid = std::process::id();
        let home = PathBuf::from(format!("/private/tmp/knsh-it-{pid}"));
        let _ = fs::remove_dir_all(&home);
        fs::create_dir(&home).unwrap();
        let paths = EnginePaths::for_home(&home).unwrap();
        // A copy outside the source tree: launchd-started processes need consent (TCC) to open files under
        // `~/Desktop`, `~/Documents` or `~/Downloads`, and a binary there blocks in dyld instead of starting.
        let program = home.join("knshd");
        fs::copy(env!("CARGO_BIN_EXE_knshd"), &program).unwrap();
        let agent = LaunchAgent::new(&format!("knsh.test.{pid}"), &program, &paths)
            .unwrap()
            .with_control_service(&format!("knsh.test.{pid}.control"))
            .unwrap();
        let uid = effective_uid();
        let installed = Self { agent, home, uid };
        install_agent(&RealFs::new(), &Launchctl::new(), &installed.agent, uid)
            .expect("install failed: is there a GUI login session for this user?");
        installed
    }

    fn user_socket(&self) -> PathBuf {
        self.agent.paths().user_socket()
    }

    /// The pid of the running `knshd`, if launchd reports one.
    fn pid(&self) -> Option<u32> {
        let target = format!("gui/{}/{}", self.uid, self.agent.label());
        let output = Command::new("/bin/launchctl")
            .args(["print", &target])
            .output()
            .unwrap();
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .find_map(|line| line.trim().strip_prefix("pid = ")?.parse().ok())
    }

    /// Waits until launchd reports a running `knshd` other than `previous`.
    fn wait_for_pid(&self, previous: Option<u32>) -> u32 {
        let deadline = Instant::now() + LAUNCH_TIMEOUT;
        loop {
            if let Some(pid) = self.pid().filter(|pid| Some(*pid) != previous) {
                return pid;
            }
            assert!(Instant::now() < deadline, "launchd did not start knshd");
            std::thread::sleep(Duration::from_millis(200));
        }
    }
}

impl Drop for TestAgent {
    fn drop(&mut self) {
        let _ = Launchctl::new().bootout(self.uid, self.agent.label());
        let _ = fs::remove_dir_all(&self.home);
    }
}

/// Sends signal `name` (as `kill -<name>` spells it) to `pid`.
fn signal(name: &str, pid: u32) {
    let status = Command::new("/bin/kill")
        .args([format!("-{name}"), pid.to_string()])
        .status()
        .unwrap();
    assert!(status.success(), "kill -{name} {pid}");
}

/// Connects to `user.sock`, sends `hello` and waits for its answer (KNSH-013). A connection nobody accepts would
/// time out instead.
fn connect_and_get_served(socket: &Path) {
    let stream = UnixStream::connect(socket).expect("connect to user.sock");
    stream.set_read_timeout(Some(LAUNCH_TIMEOUT)).unwrap();
    let mut writer = FrameWriter::new(&stream);
    let hello = knsh_json::parse(
        br#"{"jsonrpc":"2.0","id":1,"method":"hello","params":{"client":"launchd-test","client_version":"0","protocols":[1]}}"#,
        1024,
    )
    .unwrap();
    writer.write_json(&hello).unwrap();
    writer.flush().unwrap();
    let Some(Frame::Json(payload)) = FrameReader::new(&stream)
        .read_frame()
        .expect("knshd did not serve the connection")
    else {
        panic!("knshd closed the connection without answering hello");
    };
    let Ok(Message::Success(success)) = knsh_proto::decode(&payload) else {
        panic!("hello failed");
    };
    // KNSH-014 on the real machine: protocol 1, advisory in phase 1, and every backend reported (never omitted).
    let result = success.result.as_object().expect("hello result is an object");
    assert_eq!(result.get("protocol").and_then(knsh_json::Value::as_i64), Some(1));
    assert_eq!(result.get("advisory").and_then(knsh_json::Value::as_bool), Some(true));
    let capabilities = result
        .get("capabilities")
        .and_then(knsh_json::Value::as_object)
        .expect("capabilities");
    for field in [
        "sandbox",
        "network_filter",
        "file_events",
        "secrets",
        "checkpoints",
        "methods",
    ] {
        assert!(capabilities.contains_key(field), "{field} missing");
    }
}

/// Waits until launchd reports no running `knshd`.
fn wait_for_exit(agent: &TestAgent) {
    let deadline = Instant::now() + LAUNCH_TIMEOUT;
    while agent.pid().is_some() {
        assert!(Instant::now() < deadline, "knshd did not exit");
        std::thread::sleep(Duration::from_millis(200));
    }
}

// KNSH-012 acceptance: on-demand start, owner-only sockets made by launchd, restart after a crash (NFR-REL-03), and
// a successful reconnect.
#[test]
#[ignore = "loads a launchd job into the user's GUI domain; run with --ignored"]
fn launchd_starts_knshd_on_demand_and_restarts_it_after_a_crash() {
    let agent = TestAgent::install();

    // launchd created both sockets, owner-only, before knshd ever ran. launchd binds first and applies
    // `SockPathMode` just after, so the mode is polled briefly; in between, the 0700 run directory keeps others out.
    for socket in [agent.user_socket(), agent.agent.paths().agent_socket()] {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let meta = fs::symlink_metadata(&socket).unwrap();
            assert!(meta.file_type().is_socket(), "{}", socket.display());
            if meta.permissions().mode() & 0o777 == 0o600 {
                break;
            }
            assert!(Instant::now() < deadline, "{} is not 0600", socket.display());
            std::thread::sleep(Duration::from_millis(50));
        }
    }
    let run_dir = fs::symlink_metadata(agent.agent.paths().run_dir()).unwrap();
    assert_eq!(run_dir.permissions().mode() & 0o777, 0o700);
    assert_eq!(agent.pid(), None, "knshd must not run before first contact");

    // First contact starts knshd.
    connect_and_get_served(&agent.user_socket());
    let first = agent.wait_for_pid(None);

    // Crash it. launchd restarts it on its own (KeepAlive → Crashed), without a client asking. SIGABRT is what a
    // panic or `abort` produces. (An external SIGSEGV would not do: Rust's stack-overflow handler catches it and,
    // with no faulting instruction to re-run, returns.)
    signal("ABRT", first);
    let second = agent.wait_for_pid(Some(first));

    // A client connecting after the restart is served.
    connect_and_get_served(&agent.user_socket());
    assert_eq!(agent.pid(), Some(second));

    // SIGKILL is not a crash to launchd, so there is no eager restart; the next connection starts knshd on demand.
    signal("KILL", second);
    connect_and_get_served(&agent.user_socket());
    let third = agent.wait_for_pid(Some(second));
    assert_ne!(third, first);

    // KNSH-013: SIGTERM (launchd stopping the job) is an orderly exit, not a crash: knshd finishes, commits and
    // exits 0, launchd does not restart it, and the next connection starts it on demand.
    signal("TERM", third);
    wait_for_exit(&agent);
    connect_and_get_served(&agent.user_socket());
    let fourth = agent.wait_for_pid(Some(third));
    assert_ne!(fourth, third);
}
