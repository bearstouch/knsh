//! The hook runner with real processes: shell scripts in a temporary directory (KNSH-062).

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use knsh_bash::{Classification, Interpreters, Lookup, Program, SourceFile, classify, parse_line};
use knsh_core::{
    Actor, AgentId, CanonicalPath, HookOutcome, HookResult, HookVerdict, Hooks, Proposal, Redacted, SessionId, Ulid,
};
use knsh_platform::macos::{RealFs, SystemProcesses};

use super::HookRunner;

/// A temporary directory holding the configuration file and the hook scripts, removed on drop.
struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("knshd-hooks-{}-{n}", std::process::id()));
        std::fs::create_dir(&path).unwrap();
        // Canonical, so paths the runner resolves compare equal (`/var` is `/private/var` on macOS).
        Self(std::fs::canonicalize(path).unwrap())
    }

    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }

    /// Writes an executable `/bin/sh` script named `name` with `body`.
    fn script(&self, name: &str, body: &str) -> PathBuf {
        let path = self.path(name);
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    /// Writes the configuration file with `text`.
    fn config(&self, text: &str) {
        std::fs::write(self.path("config.toml"), text).unwrap();
    }

    /// Registers one hook running `program`, with `timeout_ms`.
    fn register(&self, program: &Path, timeout_ms: u64) {
        self.config(&format!(
            "[[hooks]]\nevent = \"command.proposed\"\nrun = \"{}\"\ntimeout_ms = {timeout_ms}\n",
            program.display()
        ));
    }

    fn runner(&self) -> HookRunner {
        HookRunner::new(
            Arc::new(RealFs::new()),
            Arc::new(SystemProcesses::new()),
            self.path("config.toml"),
            self.0.clone(),
            effective_uid(),
        )
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The test process's user: the owner of the scripts it writes.
fn effective_uid() -> u32 {
    let output = std::process::Command::new("/usr/bin/id").arg("-u").output().unwrap();
    String::from_utf8(output.stdout).unwrap().trim().parse().unwrap()
}

/// Resolves every name to `/bin/<name>`.
struct Resolver;

impl knsh_bash::Resolver for Resolver {
    fn resolve(&self, name: &str, _lookup: Lookup) -> Program {
        Program::Trusted(Path::new("/bin").join(name))
    }

    fn source_file(&self, _path: &str) -> SourceFile {
        SourceFile::Unresolved
    }
}

fn agent() -> Actor {
    Actor::Agent(AgentId::new("claude-code").unwrap())
}

/// Runs the hooks of `dir` on `line` for `actor`.
fn run_as(dir: &TempDir, actor: &Actor, line: &str) -> HookOutcome {
    let classification: Classification = classify(&parse_line(line), line, &Resolver, &Interpreters::defaults());
    let command = Redacted::new(line.to_owned());
    let cwd = CanonicalPath::new("/Users/me/app").unwrap();
    let proposal = Proposal {
        session_id: SessionId::from_ulid(Ulid::from_u128(7)),
        actor,
        command: &command,
        cwd: &cwd,
        rewritten_from: None,
        classification: &classification,
    };
    dir.runner().run(&proposal)
}

fn run(dir: &TempDir, line: &str) -> HookOutcome {
    run_as(dir, &agent(), line)
}

/// Whether process `pid` still exists (`kill -0`).
fn alive(pid: &str) -> bool {
    std::process::Command::new("/bin/kill")
        .args(["-0", pid])
        .stderr(std::process::Stdio::null())
        .status()
        .unwrap()
        .success()
}

// FR-HOOK-02: the hook receives the `command.proposed` event as JSON on stdin, with nothing of `knshd`'s environment.
#[test]
fn passes_event_json_on_stdin() {
    let dir = TempDir::new();
    let stdin = dir.path("stdin.json");
    let env = dir.path("env.txt");
    let hook = dir.script(
        "capture.sh",
        &format!(
            "cat > '{}'\n/usr/bin/env > '{}'\nexit 0",
            stdin.display(),
            env.display()
        ),
    );
    dir.register(&hook, 5000);
    let outcome = run(&dir, "rm -rf build");
    assert_eq!(outcome.verdict, HookVerdict::Allow);
    let received = std::fs::read_to_string(&stdin).unwrap();
    assert_eq!(
        received,
        format!(
            r#"{{"event":"command.proposed","session_id":"{}","actor":{{"kind":"agent","agent_id":"claude-code"}},"data":{{"command":"rm -rf build","cwd":"/Users/me/app","rewritten_from":null}}}}"#,
            SessionId::from_ulid(Ulid::from_u128(7))
        )
    );
    let env = std::fs::read_to_string(&env).unwrap();
    assert!(env.contains("PATH=/usr/bin:/bin:/usr/sbin:/sbin\n"), "{env}");
    assert!(env.contains(&format!("HOME={}\n", dir.0.display())), "{env}");
    assert!(
        !env.contains("CARGO"),
        "the engine's environment is not passed on: {env}"
    );
}

// FR-HOOK-03: a hook that prints nothing and exits 0 allows.
#[test]
fn exit_zero_without_output_allows() {
    let dir = TempDir::new();
    dir.register(&dir.script("ok.sh", "exit 0"), 5000);
    let outcome = run(&dir, "ls");
    assert_eq!(outcome.verdict, HookVerdict::Allow);
    assert_eq!(outcome.runs[0].result, HookResult::Allow);
}

// FR-HOOK-03: a hook that prints nothing and exits 2 denies.
#[test]
fn exit_two_without_output_denies() {
    let dir = TempDir::new();
    dir.register(&dir.script("no.sh", "exit 2"), 5000);
    let outcome = run(&dir, "ls");
    assert_eq!(outcome.verdict, HookVerdict::Deny { reason: None });
    assert_eq!(outcome.hook.as_deref(), Some("hooks[0]"));
}

// FR-HOOK-04: any other exit code is an error, which denies.
#[test]
fn other_exit_code_denies() {
    let dir = TempDir::new();
    dir.register(&dir.script("broken.sh", "exit 1"), 5000);
    let outcome = run(&dir, "ls");
    assert_eq!(outcome.verdict, HookVerdict::Failed);
    assert_eq!(outcome.runs[0].result, HookResult::Error);
}

// FR-HOOK-04: a hook still running at its timeout denies, and its whole process group is killed.
#[test]
fn timeout_denies_and_kills_hook() {
    let dir = TempDir::new();
    let pid_file = dir.path("child.pid");
    let hook = dir.script(
        "slow.sh",
        &format!("/bin/sleep 30 &\necho $! > '{}'\nwait", pid_file.display()),
    );
    // Long enough for the system's first-run check of a new executable, far shorter than the `sleep`.
    dir.register(&hook, 2000);
    let started = Instant::now();
    let outcome = run(&dir, "ls");
    assert!(started.elapsed() < Duration::from_secs(10), "the timeout was enforced");
    assert_eq!(outcome.verdict, HookVerdict::Failed);
    assert_eq!(outcome.runs[0].result, HookResult::Timeout);
    assert_eq!(outcome.runs[0].duration_ms, 2000, "reported up to its timeout");
    let pid = std::fs::read_to_string(&pid_file).unwrap();
    let pid = pid.trim();
    // The orphaned `sleep` is reaped by launchd shortly after the kill.
    let deadline = Instant::now() + Duration::from_secs(5);
    while alive(pid) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(!alive(pid), "the hook's child {pid} was killed with its group");
}

// FR-HOOK-04: output that is not a verdict object denies.
#[test]
fn unparsable_output_denies() {
    let dir = TempDir::new();
    dir.register(&dir.script("chatty.sh", "echo 'looks fine to me'"), 5000);
    let outcome = run(&dir, "ls");
    assert_eq!(outcome.verdict, HookVerdict::Failed);
    assert_eq!(outcome.runs[0].result, HookResult::Error);
}

// FR-HOOK-02: a verdict object on stdout is read.
#[test]
fn verdict_object_on_stdout_is_read() {
    let dir = TempDir::new();
    let body = r#"echo '{"verdict":"deny","reason":"no deletes today"}'"#;
    dir.register(&dir.script("deny.sh", body), 5000);
    let outcome = run(&dir, "rm x");
    assert_eq!(
        outcome.verdict,
        HookVerdict::Deny {
            reason: Some("no deletes today".to_owned())
        }
    );
}

// FR-HOOK-05: each hook's run time is kept for the record.
#[test]
fn records_hook_duration() {
    let dir = TempDir::new();
    dir.register(&dir.script("pause.sh", "/bin/sleep 0.2"), 5000);
    let outcome = run(&dir, "ls");
    assert_eq!(outcome.verdict, HookVerdict::Allow);
    let duration = outcome.runs[0].duration_ms;
    assert!((200..5000).contains(&duration), "{duration} ms");
}

// FR-HOOK-01: human sessions run no hooks.
#[test]
fn no_hooks_run_for_human_sessions() {
    let dir = TempDir::new();
    let marker = dir.path("ran");
    dir.register(&dir.script("mark.sh", &format!("touch '{}'", marker.display())), 5000);
    let outcome = run_as(&dir, &Actor::Human, "ls");
    assert_eq!(outcome.verdict, HookVerdict::Allow);
    assert_eq!(outcome.runs.len(), 0);
    assert!(!marker.exists(), "no hook ran");
    // The same hook does run for an agent.
    run(&dir, "ls");
    assert!(marker.exists());
}

// FR-HOOK-04: a `run` that is missing or not executable denies the lines the hook matches; a broken file denies all.
#[test]
fn invalid_configuration_fails_closed() {
    let dir = TempDir::new();
    // No configuration file: no hooks.
    assert_eq!(run(&dir, "ls").verdict, HookVerdict::Allow);

    dir.register(&dir.path("missing.sh"), 5000);
    let outcome = run(&dir, "ls");
    assert_eq!(outcome.verdict, HookVerdict::Failed);
    assert_eq!(outcome.runs[0].result, HookResult::Invalid);

    let plain = dir.path("plain.sh");
    std::fs::write(&plain, "#!/bin/sh\nexit 0\n").unwrap();
    std::fs::set_permissions(&plain, std::fs::Permissions::from_mode(0o644)).unwrap();
    dir.register(&plain, 5000);
    assert_eq!(run(&dir, "ls").verdict, HookVerdict::Failed);

    dir.register(&dir.0, 5000);
    assert_eq!(
        run(&dir, "ls").verdict,
        HookVerdict::Failed,
        "a directory is not a hook"
    );

    dir.config("[[hooks]\n");
    let outcome = run(&dir, "ls");
    assert_eq!(outcome.verdict, HookVerdict::Failed);
    assert_eq!(outcome.hook.as_deref(), Some("hooks"));

    // A symlink to an executable runs the file it points at.
    let target = dir.script("target.sh", "exit 2");
    let link = dir.path("link.sh");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    dir.register(&link, 5000);
    assert_eq!(run(&dir, "ls").verdict, HookVerdict::Deny { reason: None });
}

// A hook runs outside any sandbox, so its executable must be where no envelope can write: inside the configuration
// directory, owned by the user and writable by no one else. Otherwise it denies every line it matches.
#[test]
fn hook_outside_configuration_directory_denies() {
    let dir = TempDir::new();
    let elsewhere = TempDir::new();
    dir.register(&elsewhere.script("planted.sh", "exit 0"), 5000);
    let outcome = run(&dir, "ls");
    assert_eq!(outcome.verdict, HookVerdict::Failed);
    assert_eq!(outcome.runs[0].result, HookResult::Invalid);

    // A symlink inside the directory to a file outside it is judged by the file it points at.
    let link = dir.path("link.sh");
    std::os::unix::fs::symlink(elsewhere.path("planted.sh"), &link).unwrap();
    dir.register(&link, 5000);
    assert_eq!(run(&dir, "ls").verdict, HookVerdict::Failed);

    // Group-writable inside the directory is refused too.
    let shared = dir.script("shared.sh", "exit 0");
    std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o775)).unwrap();
    dir.register(&shared, 5000);
    assert_eq!(run(&dir, "ls").verdict, HookVerdict::Failed);

    // Owned by someone else (`/bin/sh` is root's, and outside the directory as well).
    dir.register(Path::new("/bin/sh"), 5000);
    assert_eq!(run(&dir, "ls").verdict, HookVerdict::Failed);
}

// The hook's stdout is bounded: past the limit it is an error, and the runner does not wait for the rest.
#[test]
fn oversized_output_denies() {
    let dir = TempDir::new();
    dir.register(&dir.script("flood.sh", "/usr/bin/yes '{\"verdict\":\"allow\"}'"), 5000);
    let started = Instant::now();
    let outcome = run(&dir, "ls");
    assert_eq!(outcome.verdict, HookVerdict::Failed);
    assert!(started.elapsed() < Duration::from_secs(5));
}
