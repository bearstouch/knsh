//! The hook runner: the user's `command.proposed` hooks, run by the supervisor before policy (KNSH-062;
//! `specs/05-models/hook.md`, FR-HOOK-01 to FR-HOOK-07, NFR-SEC-09).
//!
//! [`HookRunner`] is the supervisor's [`Hooks`]. For each evaluation pass of an agent line it:
//!
//! 1. reads the user's configuration file (`EnginePaths::config_file`; read again for every pass, so an edit
//!    applies to the next line) and its `[[hooks]]` through [`parse_hooks`]; a file that cannot be read or parsed
//!    denies every agent line, since whether hooks are registered cannot be known (FR-HOOK-04);
//! 2. checks that each registration's `run` names an executable regular file inside the configuration directory,
//!    owned by the user and writable by no one else, and runs the canonical path it checked; a hook that fails the
//!    check denies every line it matches. A hook runs outside any sandbox, so a hook file an envelope could write
//!    would let an agent plant code that runs unsandboxed (`specs/04-non-functional-requirements/security.md`); the
//!    configuration directory is a fixed deny of every envelope profile, so a file inside it cannot be planted;
//! 3. hands the chain to [`run_hooks`], with [`ProcessExecutor`] running each matching hook.
//!
//! The configuration directory is a fixed deny of every envelope profile (FR-HOOK-07), so an agent can neither read
//! nor change what runs here.
//!
//! # Running one hook
//!
//! The executable is spawned directly through [`Processes`], never through a shell (NFR-SEC-09), as the leader of a
//! new process group, outside any sandbox (FR-HOOK-06). Its stdin is a pipe fed with the `command.proposed` event
//! ([`hook_input`]) by a writer thread, so a hook that never reads cannot stall the supervisor; its stdout is a pipe
//! read by a reader thread up to [`MAX_HOOK_OUTPUT`] plus one byte; its stderr is `/dev/null`, so hook output is
//! never logged. Its environment is only `PATH` and `HOME`, and it starts in `/`.
//!
//! The leader is polled until it exits or its `timeout_ms` passes. Either way its process group is then killed
//! (`SIGKILL`): on a timeout that is the hook itself (FR-HOOK-04), after an exit it is anything the hook left behind,
//! which could otherwise hold the stdout pipe open. Only then is the leader reaped, so the group id is never
//! signalled after it could have been reused. The run time is measured on the monotonic clock (FR-HOOK-05).
//!
//! Every failure (no pipe, no spawn, a stdout that does not reach end of file shortly after the group was killed) is
//! [`Ended::Failed`], which denies the line.

use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use knsh_core::{
    ConfigProblem, Ended, Execution, HookConfig, HookExecutor, HookExit, HookOutcome, HookSpec, Hooks, MAX_HOOK_OUTPUT,
    Proposal, parse_hooks, run_hooks,
};
use knsh_platform::{ExitStatus, FileKind, Fs, Processes, SharedFd, Signal, SpawnRequest, Stdio};
use knsh_proto::hook_input;

/// The only `PATH` a hook gets: the system folders, never the engine's own environment.
const HOOK_PATH: &str = "/usr/bin:/bin:/usr/sbin:/sbin";

/// How often a running hook's leader is checked for exit. Small next to any useful `timeout_ms`.
const POLL_INTERVAL: Duration = Duration::from_millis(2);

/// How long the stdout reader may take to reach end of file once the hook's process group was killed. Only a process
/// that left the group could still hold the pipe; its hook is then an error.
const DRAIN_TIMEOUT: Duration = Duration::from_millis(250);

/// The supervisor's hooks: the registrations of the user's configuration file, run as processes.
pub(crate) struct HookRunner {
    fs: Arc<dyn Fs>,
    processes: Arc<dyn Processes>,
    /// The user's configuration file (`EnginePaths::config_file`).
    config_file: PathBuf,
    /// The user's home, for `~` in `run` and as the hooks' `HOME`.
    home: PathBuf,
    /// The user `knshd` runs as: a hook executable must be owned by them.
    uid: u32,
}

impl HookRunner {
    /// Hooks registered in `config_file`, with `~` meaning `home`, started through `processes`.
    pub(crate) fn new(
        fs: Arc<dyn Fs>,
        processes: Arc<dyn Processes>,
        config_file: PathBuf,
        home: PathBuf,
        uid: u32,
    ) -> Self {
        Self {
            fs,
            processes,
            config_file,
            home,
            uid,
        }
    }

    /// The current registrations, each valid one checked against the filesystem (module documentation, steps 1
    /// and 2).
    fn load(&self) -> HookConfig {
        let bytes = match self.fs.read(&self.config_file, knsh_toml::MAX_INPUT_LEN as u64) {
            Ok(bytes) => bytes,
            // No configuration file: no hooks.
            Err(error) if error.is_not_found() => return HookConfig::none(),
            Err(_) => return HookConfig::Invalid(ConfigProblem::Unreadable),
        };
        let Ok(root) = knsh_toml::parse(&bytes) else {
            return HookConfig::Invalid(ConfigProblem::InvalidToml);
        };
        let mut config = parse_hooks(&root, &self.home);
        // The directory the configuration file is in, canonical, which every hook executable must be inside.
        let config_dir = self
            .config_file
            .parent()
            .and_then(|dir| self.fs.canonicalise(dir).ok())
            .map(knsh_core::CanonicalPath::into_path_buf);
        if let HookConfig::Hooks(entries) = &mut config {
            for entry in entries {
                let Ok(spec) = &entry.registration else {
                    continue;
                };
                let checked = config_dir
                    .as_deref()
                    .and_then(|dir| self.executable(&spec.program, dir));
                match checked {
                    Some(program) => entry.set_program(program),
                    None => entry.mark_not_executable(),
                }
            }
        }
        config
    }

    /// `program` with symlinks resolved, if it names a regular file inside `config_dir`, owned by the user,
    /// writable by no one else, with an execute bit set (module documentation, step 2).
    fn executable(&self, program: &Path, config_dir: &Path) -> Option<PathBuf> {
        let canonical = self.fs.canonicalise(program).ok()?;
        let metadata = self.fs.metadata(canonical.as_path()).ok()?;
        let usable = canonical.as_path().starts_with(config_dir)
            && canonical.as_path() != config_dir
            && metadata.kind == FileKind::File
            && metadata.uid == self.uid
            && metadata.mode & 0o022 == 0
            && metadata.mode & 0o111 != 0;
        usable.then(|| canonical.into_path_buf())
    }
}

impl Hooks for HookRunner {
    fn run(&self, proposal: &Proposal<'_>) -> HookOutcome {
        // FR-HOOK-01: a human line never reaches the hooks; checked again in `run_hooks`.
        if proposal.actor.agent_id().is_none() {
            return HookOutcome::ALLOW;
        }
        let config = self.load();
        // Without its input no hook can judge the line: `run_hooks` then fails the first matching hook.
        let input = hook_input(proposal).ok();
        let executor = ProcessExecutor {
            processes: &*self.processes,
            home: &self.home,
        };
        run_hooks(&config, proposal, input.as_deref(), &executor)
    }
}

/// Runs one hook as a process (module documentation, "Running one hook").
pub(crate) struct ProcessExecutor<'a> {
    pub(crate) processes: &'a dyn Processes,
    pub(crate) home: &'a Path,
}

impl HookExecutor for ProcessExecutor<'_> {
    fn execute(&self, hook: &HookSpec, input: &[u8]) -> Execution {
        let started = Instant::now();
        let ended = self.run(hook, input, started).unwrap_or(Ended::Failed);
        Execution {
            ended,
            duration: started.elapsed(),
        }
    }
}

impl ProcessExecutor<'_> {
    /// Spawns `hook`, feeds it `input`, and waits for it until `started` plus its timeout. `None` is a failure.
    fn run(&self, hook: &HookSpec, input: &[u8], started: Instant) -> Option<Ended> {
        let (stdin_read, stdin_write) = std::io::pipe().ok()?;
        let (mut stdout_read, stdout_write) = std::io::pipe().ok()?;
        let null = OpenOptions::new().write(true).open("/dev/null").ok()?;
        let request = SpawnRequest {
            program: hook.program.clone(),
            argv0: None,
            args: Vec::new(),
            env: vec![
                ("PATH".into(), HOOK_PATH.into()),
                ("HOME".into(), self.home.as_os_str().to_owned()),
            ],
            cwd: Some(PathBuf::from("/")),
            stdio: Stdio::Passed(Box::new([
                SharedFd::new(OwnedFd::from(stdin_read)),
                SharedFd::new(OwnedFd::from(stdout_write)),
                SharedFd::new(OwnedFd::from(null)),
            ])),
            inherit: Vec::new(),
            placements: Vec::new(),
        };
        let group = self.processes.spawn(&request).ok()?;
        // The child has its own copies now. Dropping ours lets the hook see end of file on stdin once the writer is
        // done, and lets the reader see end of file once the hook's group has closed stdout.
        drop(request);

        // The writer ends on its own: when it has written everything, or with `EPIPE` once the hook's group is gone.
        let input = input.to_vec();
        thread::spawn(move || {
            let mut stdin = stdin_write;
            let _ = stdin.write_all(&input);
        });
        let (sender, receiver) = mpsc::channel();
        thread::spawn(move || {
            let mut stdout = Vec::new();
            // One byte past the limit, so too long an output is seen as such and refused (`judge`).
            let limit = MAX_HOOK_OUTPUT as u64 + 1;
            let read = (&mut stdout_read).take(limit).read_to_end(&mut stdout);
            let _ = sender.send(read.map(|_| stdout));
        });

        let deadline = started + hook.timeout;
        let timed_out = loop {
            match self.processes.exited(group) {
                Ok(true) => break false,
                Ok(false) if Instant::now() >= deadline => break true,
                Ok(false) => thread::sleep(POLL_INTERVAL),
                // The group cannot be watched: stop it rather than leave it running unbounded.
                Err(_) => {
                    let _ = self.processes.signal(group, Signal::Kill);
                    let _ = self.processes.wait(group);
                    return None;
                }
            }
        };
        // FR-HOOK-04: the whole group is killed, the hook on a timeout and its leftovers after an exit. An error here
        // only means nothing was left to kill (the unreaped leader alone answers `EPERM`).
        let _ = self.processes.signal(group, Signal::Kill);
        let status = self.processes.wait(group).ok()?;
        if timed_out {
            return Some(Ended::TimedOut);
        }
        let stdout = receiver.recv_timeout(DRAIN_TIMEOUT).ok()?.ok()?;
        let exit = match status {
            ExitStatus::Exited(code) => HookExit::Exited(code),
            ExitStatus::Signalled(_) => HookExit::Signalled,
        };
        Some(Ended::Finished { stdout, exit })
    }
}

#[cfg(test)]
mod tests;
