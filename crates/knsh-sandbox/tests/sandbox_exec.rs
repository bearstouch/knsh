//! Compiled profiles under the real kernel (KNSH-044 and KNSH-045 integration tests; FR-SBX-01, FR-SBX-02,
//! FR-SBX-04, FR-SBX-05, FR-SBX-10, FR-LC-15, FR-NET-08).
//!
//! A test home and project live in a temporary directory. In the file test it is the profile's only write root, so
//! every write refused there is refused by a fixed or `fs.deny` rule, not by the default deny. The commands run
//! through `/usr/bin/sandbox-exec -f`, as `knsh-exec` will run them, and only from the trusted folders the compiled
//! profile allows (`/bin`, `/usr/bin`).

#![cfg(target_os = "macos")]
// Test helpers outside `#[test]` functions: a failed step should stop the test.
#![allow(clippy::unwrap_used, clippy::panic)]

use std::io::Read as _;
use std::net::TcpListener;
use std::num::NonZeroU16;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use knsh_core::{
    CanonicalPath, FixedDenies, LookupError, PathContext, PolicyFs, ProfileName, ProfileSource, RecordId, SessionId,
    Ulid, load_profile_text,
};
use knsh_sandbox::{CommandTag, ProfileInput, compile};

/// The real filesystem, as the loader sees it.
struct RealPaths;

impl PolicyFs for RealPaths {
    fn canonicalise(&self, path: &Path) -> Result<CanonicalPath, LookupError> {
        let resolved = std::fs::canonicalize(path).map_err(|_| LookupError::NotFound)?;
        CanonicalPath::new(resolved).map_err(|_| LookupError::Failed)
    }
}

struct NoParents;

impl ProfileSource for NoParents {
    fn read_profile(&self, _name: &ProfileName) -> Result<Vec<u8>, LookupError> {
        Err(LookupError::NotFound)
    }
}

/// A temporary directory, canonical, removed on drop.
struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        Self::at(std::env::temp_dir().join(format!("knsh-sandbox-{}", std::process::id())))
    }

    /// Under `/private/tmp`, with a short name: Unix socket paths are limited to 104 bytes, and the per-user
    /// temporary directory is already half of that.
    fn short(name: &str) -> Self {
        Self::at(PathBuf::from(format!(
            "/private/tmp/knsh-{name}-{}",
            std::process::id()
        )))
    }

    fn at(base: PathBuf) -> Self {
        std::fs::create_dir_all(&base).unwrap();
        Self(std::fs::canonicalize(base).unwrap())
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Runs `script` under `profile` with `/bin/sh`, its operands as `$1`, `$2`, …; whether it succeeded.
fn run(profile: &Path, script: &str, operands: &[&Path]) -> bool {
    Command::new("/usr/bin/sandbox-exec")
        .arg("-f")
        .arg(profile)
        .args(["/bin/sh", "-c", script, "sh"])
        .args(operands)
        .output()
        .unwrap()
        .status
        .success()
}

// KNSH-044: under the compiled profile, writing `${PROJECT}/.git/hooks/pre-commit` and `~/.zshrc` fails, writing
// `${PROJECT}/src/x` succeeds; so do the other fixed denies, the engine paths and `fs.deny`.
#[test]
fn compiled_file_rules_hold_under_sandbox_exec() {
    let dir = TempDir::new();
    let home = dir.0.join("home");
    let project = home.join("app");
    // The engine directories, from the one source of their location (no path literals here).
    let canonical_home = CanonicalPath::new(home.clone()).unwrap();
    let denies = FixedDenies::for_home(&canonical_home);
    let [engine_data, engine_config] = denies.paths() else {
        panic!("two engine directories");
    };
    let (engine_data, engine_config) = (engine_data.as_path(), engine_config.as_path());
    for path in [
        project.join("src"),
        project.join(".git/hooks"),
        home.join(".ssh"),
        home.join("Library/LaunchAgents"),
        engine_data.to_path_buf(),
        engine_config.to_path_buf(),
    ] {
        std::fs::create_dir_all(path).unwrap();
    }
    std::fs::write(engine_config.join("policy.toml"), "engine").unwrap();
    std::fs::write(home.join("secret"), "secret").unwrap();

    let write_root = dir.0.to_str().unwrap();
    let text = format!("name = \"t\"\n[fs]\nwrite = [\"{write_root}\"]\ndeny = [\"~/secret\"]\n");
    let context = PathContext {
        home: home.clone(),
        tmpdir: dir.0.clone(),
        start_dir: project.clone(),
    };
    let profile = load_profile_text(text.as_bytes(), &NoParents, &context, &RealPaths).unwrap();
    let sbpl = compile(&ProfileInput {
        session: SessionId::from_ulid(Ulid::from_u128(1)),
        command: CommandTag::Line(RecordId::from_ulid(Ulid::from_u128(2))),
        profile: &profile,
        home: &canonical_home,
        executables: &[],
        proxy_port: None,
    });
    let profile_file = dir.0.join("profile.sb");
    std::fs::write(&profile_file, sbpl.as_bytes()).unwrap();

    let write = "echo x > \"$1\"";
    let allowed = |path: PathBuf| assert!(run(&profile_file, write, &[&path]), "{} not writable", path.display());
    let refused = |path: PathBuf| assert!(!run(&profile_file, write, &[&path]), "{} writable", path.display());

    allowed(project.join("src/x"));
    allowed(project.join(".git/HEAD"));
    refused(project.join(".git/hooks/pre-commit"));
    refused(project.join(".git/config"));
    refused(home.join(".zshrc"));
    refused(home.join(".zshenv"));
    refused(home.join(".ssh/authorized_keys"));
    refused(home.join("Library/LaunchAgents/evil.plist"));
    refused(engine_config.join("policy.toml"));
    refused(engine_data.join("records.db"));

    // A planted git directory cannot be renamed into place, and the real one cannot be moved away.
    let plant = "mkdir -p \"$1/hooks\" && echo x > \"$1/hooks/pre-commit\" && mkdir -p \"$2\" && mv \"$1\" \"$2/.git\"";
    assert!(!run(
        &profile_file,
        plant,
        &[&project.join("evil"), &project.join("sub")]
    ));
    assert!(!run(
        &profile_file,
        "mv \"$1\" \"$2\"",
        &[&project.join(".git"), &project.join(".git-old")]
    ));

    // Git takes hooks and configuration from the directory `commondir` names and from submodule git directories;
    // neither can be written, and a submodule git directory cannot be renamed out of `.git` and back.
    refused(project.join(".git/commondir"));
    std::fs::create_dir_all(project.join(".git/modules/lib/hooks")).unwrap();
    refused(project.join(".git/modules/lib/config"));
    refused(project.join(".git/modules/lib/hooks/post-checkout"));
    allowed(project.join(".git/modules/lib/index"));
    assert!(!run(
        &profile_file,
        "mv \"$1\" \"$2\"",
        &[&project.join(".git/modules/lib"), &project.join("lib-git")]
    ));

    // A directory above an engine path, a fixed deny or `fs.deny` cannot be renamed away (and its contents edited
    // at the new place); files inside it can still be created.
    let engine_parent = engine_config.parent().unwrap();
    for ancestor in [engine_parent, &home.join("Library"), &home] {
        let moved = ancestor.with_extension("moved");
        assert!(
            !run(&profile_file, "mv \"$1\" \"$2\"", &[ancestor, &moved]),
            "{} renamable",
            ancestor.display()
        );
    }
    allowed(engine_parent.join("other"));
    allowed(home.join("Library/other"));

    // Engine files and `fs.deny` are unreadable too; other files are readable.
    let read = "cat \"$1\" > /dev/null";
    assert!(!run(&profile_file, read, &[&engine_config.join("policy.toml")]));
    assert!(!run(&profile_file, read, &[&home.join("secret")]));
    assert!(run(&profile_file, read, &[&project.join("src/x")]));
}

/// Runs `program` with `args` under `profile`, killing it after `limit`; whether it exited successfully in time.
/// `osascript` hangs instead of failing when Apple Events are denied (KNSH-025, C8), so a time-out is a refusal.
fn run_within(profile: &Path, limit: Duration, program: &str, args: &[&str]) -> bool {
    let mut child = Command::new("/usr/bin/sandbox-exec")
        .arg("-f")
        .arg(profile)
        .arg(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + limit;
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return status.success();
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            return false;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Compiles a profile with `[exec] project_executables = <setting>` for `command`, the project as write root and
/// the proxy at `proxy_port`, into `<dir>/<name>.sb`.
fn compiled_profile(dir: &TempDir, name: &str, setting: &str, command: CommandTag, proxy_port: u16) -> PathBuf {
    let home = dir.0.join("home");
    let project = home.join("app");
    let text = format!("name = \"t\"\n[fs]\nwrite = [\"${{PROJECT}}\"]\n[exec]\nproject_executables = \"{setting}\"\n");
    let context = PathContext {
        home: home.clone(),
        tmpdir: dir.0.clone(),
        start_dir: project,
    };
    let profile = load_profile_text(text.as_bytes(), &NoParents, &context, &RealPaths).unwrap();
    let canonical_home = CanonicalPath::new(home).unwrap();
    let sbpl = compile(&ProfileInput {
        session: SessionId::from_ulid(Ulid::from_u128(1)),
        command,
        profile: &profile,
        home: &canonical_home,
        executables: &[],
        proxy_port: NonZeroU16::new(proxy_port),
    });
    let file = dir.0.join(format!("{name}.sb"));
    std::fs::write(&file, sbpl.as_bytes()).unwrap();
    file
}

/// A test home with a project and fake endpoint sockets, a proxy listening on loopback, and compiled profiles: a
/// command with project executables denied (`deny`) and allowed (`allow`), and an envelope.
struct Fixture {
    dir: TempDir,
    fixed: FixedDenies,
    proxy_port: u16,
    deny: PathBuf,
    allow: PathBuf,
    envelope: PathBuf,
    _proxy: TcpListener,
}

impl Fixture {
    fn new(name: &str) -> Self {
        let dir = TempDir::short(name);
        let home = dir.0.join("home");
        std::fs::create_dir_all(home.join("app/bin")).unwrap();
        let fixed = FixedDenies::for_home(&CanonicalPath::new(home).unwrap());
        std::fs::create_dir_all(fixed.user_socket().as_path().parent().unwrap()).unwrap();
        // Fake endpoints, served by this (unsandboxed) test process: each accepts and closes connections, so a
        // client that got through (`nc -U`) sees end of file and exits 0, and one the sandbox refused exits 1.
        for socket in [fixed.user_socket(), fixed.agent_socket()] {
            let listener = UnixListener::bind(socket.as_path()).unwrap();
            std::thread::spawn(move || listener.incoming().for_each(drop));
        }
        let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_port = proxy.local_addr().unwrap().port();
        let line = CommandTag::Line(RecordId::from_ulid(Ulid::from_u128(2)));
        Self {
            deny: compiled_profile(&dir, "deny", "deny", line, proxy_port),
            allow: compiled_profile(&dir, "allow", "allow", line, proxy_port),
            envelope: compiled_profile(&dir, "envelope", "deny", CommandTag::Envelope, proxy_port),
            dir,
            fixed,
            proxy_port,
            _proxy: proxy,
        }
    }

    fn project(&self) -> PathBuf {
        self.dir.0.join("home/app")
    }
}

/// Whether `program` succeeds under `profile` within ten seconds.
fn succeeds(profile: &Path, program: &str, args: &[&str]) -> bool {
    run_within(profile, Duration::from_secs(10), program, args)
}

/// Whether `nc -U` connects to `socket` under `profile`.
fn connects(profile: &Path, socket: &Path) -> bool {
    succeeds(
        profile,
        "/bin/sh",
        &[
            "-c",
            "/usr/bin/nc -U \"$1\" < /dev/null",
            "sh",
            socket.to_str().unwrap(),
        ],
    )
}

// KNSH-045, FR-NET-08: under a compiled command profile, `open -a Safari` fails and an Apple Event to another
// application fails (`osascript -e 1` sends none, so the test sends one to Finder).
#[test]
fn launch_services_and_apple_events_denied_under_sandbox_exec() {
    let fixture = Fixture::new("045-svc");
    assert!(
        !succeeds(&fixture.deny, "/usr/bin/open", &["-g", "-a", "Safari"]),
        "open -a Safari ran"
    );
    let event = ["-e", "tell application \"Finder\" to get version"];
    assert!(
        !run_within(&fixture.deny, Duration::from_secs(5), "/usr/bin/osascript", &event),
        "an Apple Event reached Finder"
    );
}

// KNSH-045: outbound network reaches the proxy's port only: `nc` to a non-loopback address fails, and so does a
// loopback port the profile does not list.
#[test]
fn network_limited_to_proxy_port_under_sandbox_exec() {
    let fixture = Fixture::new("045-net");
    let port = fixture.proxy_port.to_string();
    assert!(
        succeeds(&fixture.deny, "/usr/bin/nc", &["-z", "127.0.0.1", &port]),
        "proxy port unreachable"
    );
    assert!(
        !succeeds(&fixture.deny, "/usr/bin/nc", &["-z", "-G", "3", "1.1.1.1", "443"]),
        "reached a non-loopback address"
    );
    let other = TcpListener::bind("127.0.0.1:0").unwrap();
    let other_port = other.local_addr().unwrap().port().to_string();
    assert!(
        !succeeds(&fixture.deny, "/usr/bin/nc", &["-z", "127.0.0.1", &other_port]),
        "reached a loopback port the profile does not list"
    );
}

// KNSH-045, FR-SBX-05: a command connects to no Unix socket, `user.sock` included; an envelope reaches `agent.sock`
// but never `user.sock`.
#[test]
fn unix_sockets_limited_under_sandbox_exec() {
    let fixture = Fixture::new("045-sock");
    let (agent, user) = (
        fixture.fixed.agent_socket().as_path(),
        fixture.fixed.user_socket().as_path(),
    );
    assert!(!connects(&fixture.deny, user), "a command reached user.sock");
    assert!(!connects(&fixture.deny, agent), "a command reached agent.sock");
    assert!(
        connects(&fixture.envelope, agent),
        "the envelope cannot reach agent.sock"
    );
    assert!(!connects(&fixture.envelope, user), "the envelope reached user.sock");
}

// KNSH-045, FR-SBX-04, FR-LC-15, decision 8: a binary copied into the project, and a script there, run only when
// project executables are allowed, also when started by a child; another process cannot be signalled; and git from
// the developer directory runs through the `/usr/bin` stub.
#[test]
fn executables_and_signals_limited_under_sandbox_exec() {
    let fixture = Fixture::new("045-exec");
    // A copy of a platform binary is killed by the system unless re-signed, so it is signed ad hoc.
    let copied = fixture.project().join("bin/echo");
    std::fs::copy("/bin/echo", &copied).unwrap();
    let signed = Command::new("/usr/bin/codesign")
        .args(["-s", "-", "-f"])
        .arg(&copied)
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(signed.success());
    let script = fixture.project().join("bin/build.sh");
    std::fs::write(&script, "#!/bin/sh\necho built\n").unwrap();
    std::fs::set_permissions(&script, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
    for program in [copied.to_str().unwrap(), script.to_str().unwrap()] {
        assert!(!succeeds(&fixture.deny, program, &[]), "{program} ran under deny");
        assert!(
            !succeeds(&fixture.deny, "/bin/sh", &["-c", "\"$1\"", "sh", program]),
            "a child ran {program} under deny"
        );
        assert!(
            succeeds(&fixture.allow, program, &[]),
            "{program} did not run under allow"
        );
    }

    // Decision 8: another process (unsandboxed, outside this sandbox) cannot be signalled.
    let mut sleeper = Command::new("/bin/sleep").arg("30").spawn().unwrap();
    let pid = sleeper.id().to_string();
    assert!(
        !succeeds(&fixture.deny, "/bin/kill", &["-0", &pid]),
        "signalled another process"
    );
    let _ = sleeper.kill();
    let _ = sleeper.wait();

    // Trusted and system tool folders: `/usr/bin/git` runs the developer directory's git.
    let mut git = Command::new("/usr/bin/sandbox-exec")
        .arg("-f")
        .arg(&fixture.deny)
        .args(["/usr/bin/git", "--version"])
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut version = String::new();
    git.stdout.take().unwrap().read_to_string(&mut version).unwrap();
    assert!(
        git.wait().unwrap().success() && version.starts_with("git version"),
        "{version}"
    );
}
