//! Exec decisions through the Endpoint Security descendant client (FR-AGT-13, decision 3, KNSH-094).
//!
//! On macOS 27 and later, with Apple's entitlement, the capability probe reports `sandbox:
//! "seatbelt+endpoint_security"` and `session.start_agent` creates one descendant client per envelope
//! ([`ExecLayer::watch`]) before the envelope starts. Every exec inside the envelope reaches [`EnvelopeExecs`], which
//! decides it through the supervisor's own pipeline ([`ExecPolicy`], implemented by the lifecycle orchestrator), so
//! `/bin/bash -c 'git push'` by absolute path is decided like `knsh -c 'git push'`. On macOS 14 to 26, or without
//! the entitlement, no client exists and the envelope alone confines direct execution (FR-AGT-31).
//!
//! # What is decided
//!
//! - **The launch chain is not.** The envelope starts as `knsh-exec`, which becomes `sandbox-exec`, which runs the
//!   profile's bash, which `exec`s the CLI. Those four execs, by the envelope's leader (the one process whose pid is
//!   its process group), in that order, are the envelope itself, not the agent: they are allowed
//!   ([`LaunchChain`]). Once the CLI has been reached nothing more is exempt that way.
//! - **`knsh` is not.** The shims and `$SHELL` are `knsh`, which forwards its line over `agent.sock` to the
//!   supervisor, where it is decided and recorded (FR-AGT-10). Deciding the exec of `knsh` too would decide every
//!   forwarded line twice.
//! - **Everything else is.** The exec becomes a line: the executable's canonical path, then `argv[1..]`, each quoted
//!   as one shell word (`argv[0]` is the caller's choice and never trusted). It is decided in the session with the
//!   exec's working directory and its environment's `PATH` (without the shims), like a forwarded line: parsing,
//!   classification, `command.proposed`, hooks, policy with grants, asks, and its record.
//!
//! # Deadlines (fail closed)
//!
//! Endpoint Security gives each exec a deadline. [`ExecAuthoriser`] answers [`DEADLINE_MARGIN`] before it whatever
//! the decision is doing: the decision runs on a thread of its own, and when the time is up the exec is denied
//! ([`ExecGate`]). The gate is also the decision's [`Caller`]: an ask waiting on the authority or `knsh approve` sees
//! it gone and is cancelled. An allow counts only if it was claimed on the gate before the deadline; a decision that
//! allows after it is recorded as a deny, so the record never says an exec ran that the kernel refused.
//!
//! Every other failure denies too: an exec event that cannot be read (a working directory the kernel did not report,
//! arguments that are not UTF-8, a line longer than `exec.run` accepts), a session that has ended or is paused, a
//! decision thread that cannot start or panics, and a rewrite, which cannot be applied to an exec already under way.

use std::panic::{self, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread;
use std::time::Duration;

use knsh_core::{Caller, CanonicalPath, MAX_LINE_LEN, SessionId};
use knsh_platform::probe::SANDBOX_EXEC;
use knsh_platform::{
    Clock, DescendantClient, DescendantClients, ExecEvent, ExecHandler, ExecVerdict, Monotonic, PlatformError,
};
use knsh_proto::DEFAULT_POLICY_CHECK_PATH;

use crate::exec::without_shims;

/// How long before Endpoint Security's deadline the answer is sent. The kernel's deadline is absolute; this leaves
/// room for the answer to reach it.
pub(crate) const DEADLINE_MARGIN: Duration = Duration::from_millis(250);

/// How often the authoriser checks the clock while a decision runs.
const POLL: Duration = Duration::from_millis(5);

/// One exec inside an envelope, as the supervisor's pipeline decides it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExecRequest {
    /// The envelope's session.
    pub(crate) session_id: SessionId,
    /// The exec as a line: the executable's canonical path and `argv[1..]`, each one quoted shell word.
    pub(crate) command: String,
    /// The calling process's working directory.
    pub(crate) cwd: CanonicalPath,
    /// The `PATH` names in the line resolve on: the exec's, without the shims, or the system default.
    pub(crate) path: String,
}

/// Decides one exec through the supervisor's pipeline: the lifecycle orchestrator (`supervisor.rs`).
pub(crate) trait ExecPolicy: Send + Sync {
    /// Decides `request` in its session and records it with source `endpoint_security`. Returns
    /// [`ExecVerdict::Allow`] only after [`ExecGate::claim_allow`] succeeded; `gate` is the decision's caller.
    fn decide_exec(&self, request: &ExecRequest, gate: &ExecGate) -> ExecVerdict;
}

/// No answer yet.
const PENDING: u8 = 0;
/// The decision claimed an allow in time.
const ALLOWED: u8 = 1;
/// The deadline passed first: the exec is denied whatever the decision says later.
const EXPIRED: u8 = 2;

/// The deadline of one exec decision, and the one place its allow is claimed (module documentation, "Deadlines").
pub(crate) struct ExecGate {
    clock: Arc<dyn Clock>,
    /// When the answer must be sent.
    answer_by: Monotonic,
    state: AtomicU8,
}

impl ExecGate {
    /// A gate that expires at `answer_by` on `clock`.
    pub(crate) fn new(clock: Arc<dyn Clock>, answer_by: Monotonic) -> Self {
        Self {
            clock,
            answer_by,
            state: AtomicU8::new(PENDING),
        }
    }

    /// Claims the allow: `true` if the deadline has not passed and nothing expired the gate, after which the exec is
    /// allowed whatever happens next. `false` means the exec is denied, and must be recorded so.
    pub(crate) fn claim_allow(&self) -> bool {
        if self.clock.monotonic() >= self.answer_by {
            self.expire();
            return false;
        }
        self.state
            .compare_exchange(PENDING, ALLOWED, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
    }

    /// Ends the wait: `true` if an allow was claimed first (the exec is allowed), `false` if it is now denied.
    fn expire(&self) -> bool {
        match self
            .state
            .compare_exchange(PENDING, EXPIRED, Ordering::SeqCst, Ordering::SeqCst)
        {
            Ok(_) => false,
            Err(current) => current == ALLOWED,
        }
    }

    /// Whether an allow was claimed.
    fn allowed(&self) -> bool {
        self.state.load(Ordering::SeqCst) == ALLOWED
    }
}

impl Caller for ExecGate {
    /// Gone once the deadline has passed or the gate expired: a pending ask is cancelled (FR-LC-41).
    fn gone(&self) -> bool {
        self.state.load(Ordering::SeqCst) == EXPIRED || self.clock.monotonic() >= self.answer_by
    }
}

/// Answers exec events by their deadline (module documentation, "Deadlines").
pub(crate) struct ExecAuthoriser {
    policy: Arc<dyn ExecPolicy>,
    clock: Arc<dyn Clock>,
    margin: Duration,
}

impl ExecAuthoriser {
    /// Decides through `policy`, answering [`DEADLINE_MARGIN`] before each deadline on `clock`.
    pub(crate) fn new(policy: Arc<dyn ExecPolicy>, clock: Arc<dyn Clock>) -> Self {
        Self {
            policy,
            clock,
            margin: DEADLINE_MARGIN,
        }
    }

    /// The verdict for `request`, answered by `deadline` less the margin. Total: anything but an allow claimed in
    /// time is [`ExecVerdict::Deny`].
    pub(crate) fn authorise(&self, request: ExecRequest, deadline: Monotonic) -> ExecVerdict {
        let now = self.clock.monotonic();
        let budget = deadline.saturating_duration_since(now).saturating_sub(self.margin);
        // No time left to decide anything: denied without starting a decision that could only be late.
        let Some(answer_by) = now.checked_add(budget).filter(|_| !budget.is_zero()) else {
            return ExecVerdict::Deny;
        };
        let gate = Arc::new(ExecGate::new(Arc::clone(&self.clock), answer_by));
        // Capacity 1: a decision that answers after the deadline still completes its send and ends.
        let (sender, receiver) = mpsc::sync_channel(1);
        let policy = Arc::clone(&self.policy);
        let deciding = Arc::clone(&gate);
        let started = thread::Builder::new()
            .name("knsh-exec-decision".to_owned())
            .spawn(move || {
                // A panic is a deny (NFR-REL-07); only shared references cross.
                let verdict = panic::catch_unwind(AssertUnwindSafe(|| policy.decide_exec(&request, &deciding)))
                    .unwrap_or(ExecVerdict::Deny);
                let _ = sender.send(verdict);
            });
        if started.is_err() {
            return ExecVerdict::Deny;
        }
        loop {
            match receiver.recv_timeout(POLL) {
                // An allow counts only if it was claimed: a policy that answers allow without the gate is denied.
                Ok(ExecVerdict::Allow) if gate.allowed() => return ExecVerdict::Allow,
                Ok(ExecVerdict::Allow | ExecVerdict::Deny) | Err(RecvTimeoutError::Disconnected) => {
                    return ExecVerdict::Deny;
                }
                Err(RecvTimeoutError::Timeout) => {}
            }
            if self.clock.monotonic() >= answer_by {
                // The decision is abandoned; it sees its caller gone and records a deny unless it already claimed.
                return if gate.expire() {
                    ExecVerdict::Allow
                } else {
                    ExecVerdict::Deny
                };
            }
        }
    }
}

/// The four execs that start an envelope (module documentation, "What is decided"), matched in order.
pub(crate) struct LaunchChain {
    steps: [CanonicalPath; 4],
    /// How many steps have been seen; the chain is over at 4.
    next: usize,
    /// The pid of the process that made the first admitted step: the envelope's leader. Any process can make itself
    /// a group leader (`setpgid`, a shell's job control), so `pid == group` alone does not name the envelope's
    /// leader; every later step must come from this same pid (an exec keeps its pid).
    leader: Option<i32>,
}

impl LaunchChain {
    /// The chain `knsh-exec` (`trampoline`), `sandbox-exec`, `bash`, `program`.
    pub(crate) fn new(
        trampoline: CanonicalPath,
        sandbox_exec: CanonicalPath,
        bash: CanonicalPath,
        program: CanonicalPath,
    ) -> Self {
        Self {
            steps: [trampoline, sandbox_exec, bash, program],
            next: 0,
            leader: None,
        }
    }

    /// Whether `executable`, exec'd by `event`'s process, is the envelope's next launch step: only from the
    /// envelope's leader (a group leader, and the same pid as every earlier step), only while the CLI has not been
    /// reached, and only a step at or after the next one (a step the backend did not report is skipped, never
    /// revisited).
    fn admits(&mut self, event: &ExecEvent, executable: &CanonicalPath) -> bool {
        if event.pid != event.group
            || self.next >= self.steps.len()
            || self.leader.is_some_and(|leader| leader != event.pid)
        {
            return false;
        }
        match self.steps[self.next..].iter().position(|step| step == executable) {
            Some(offset) => {
                self.next += offset + 1;
                self.leader = Some(event.pid);
                true
            }
            None => false,
        }
    }
}

/// The exec handler of one envelope: exempts its launch chain and `knsh`, and decides everything else
/// (module documentation).
pub(crate) struct EnvelopeExecs {
    session_id: SessionId,
    authoriser: Arc<ExecAuthoriser>,
    chain: Mutex<LaunchChain>,
    /// The `knsh` binary: its lines are forwarded and decided by the supervisor.
    knsh: CanonicalPath,
    /// Removed from the exec's `PATH`, as for a forwarded line (FR-LC-16).
    shim_dir: PathBuf,
}

impl EnvelopeExecs {
    /// The handler for `session_id`'s envelope.
    pub(crate) fn new(
        session_id: SessionId,
        authoriser: Arc<ExecAuthoriser>,
        chain: LaunchChain,
        knsh: CanonicalPath,
        shim_dir: PathBuf,
    ) -> Self {
        Self {
            session_id,
            authoriser,
            chain: Mutex::new(chain),
            knsh,
            shim_dir,
        }
    }
}

impl ExecHandler for EnvelopeExecs {
    fn exec(&self, event: ExecEvent) -> ExecVerdict {
        let Ok(executable) = CanonicalPath::new(&event.executable) else {
            return ExecVerdict::Deny;
        };
        // The chain's lock is a leaf: nothing else is called while it is held.
        let launching = self
            .chain
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .admits(&event, &executable);
        if launching || executable == self.knsh {
            return ExecVerdict::Allow;
        }
        match exec_request(self.session_id, &executable, &event, &self.shim_dir) {
            Some(request) => self.authoriser.authorise(request, event.deadline),
            None => ExecVerdict::Deny,
        }
    }
}

/// `event` as a line to decide in `session_id`, or `None` if it cannot be read as one (module documentation,
/// "Deadlines": denied).
pub(crate) fn exec_request(
    session_id: SessionId,
    executable: &CanonicalPath,
    event: &ExecEvent,
    shim_dir: &Path,
) -> Option<ExecRequest> {
    let cwd = CanonicalPath::new(event.cwd.as_ref()?).ok()?;
    let mut command = shell_word(executable.as_path().to_str()?);
    // Checked before any argument too: an exec with none must still fit (`exec.run`'s limit).
    if command.len() > MAX_LINE_LEN {
        return None;
    }
    for arg in event.argv.iter().skip(1) {
        command.push(' ');
        command.push_str(&shell_word(arg.to_str()?));
        if command.len() > MAX_LINE_LEN {
            return None;
        }
    }
    let path = match &event.path {
        Some(path) => without_shims(path.to_str()?, shim_dir),
        None => DEFAULT_POLICY_CHECK_PATH.to_owned(),
    };
    Some(ExecRequest {
        session_id,
        command,
        cwd,
        path,
    })
}

/// `text` as one shell word that reads as `text` after quote removal: as it is when every byte is in
/// `[A-Za-z0-9/._+=:,@%-]`, which bash never expands or splits, otherwise in single quotes, with each `'` closed,
/// escaped and reopened (`'\''`). The empty word is `''`.
pub(crate) fn shell_word(text: &str) -> String {
    let plain = !text.is_empty()
        && text.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'/' | b'.' | b'_' | b'+' | b'=' | b':' | b',' | b'@' | b'%' | b'-'
                )
        });
    if plain {
        return text.to_owned();
    }
    let mut quoted = String::with_capacity(text.len() + 2);
    quoted.push('\'');
    for c in text.chars() {
        if c == '\'' {
            quoted.push_str("'\\''");
        } else {
            quoted.push(c);
        }
    }
    quoted.push('\'');
    quoted
}

/// Creates each envelope's descendant client when `hello` reports the Endpoint Security layer. One per `knshd`.
pub(crate) struct ExecLayer {
    clients: Arc<dyn DescendantClients>,
    authoriser: Arc<ExecAuthoriser>,
    /// The `knsh-exec` envelopes start through.
    trampoline: CanonicalPath,
    /// The `knsh` binary the shims link to.
    knsh: CanonicalPath,
    /// The shim directory.
    shim_dir: PathBuf,
}

impl ExecLayer {
    /// The layer over `clients`, deciding through `authoriser`.
    pub(crate) fn new(
        clients: Arc<dyn DescendantClients>,
        authoriser: Arc<ExecAuthoriser>,
        trampoline: CanonicalPath,
        knsh: CanonicalPath,
        shim_dir: PathBuf,
    ) -> Self {
        Self {
            clients,
            authoriser,
            trampoline,
            knsh,
            shim_dir,
        }
    }

    /// Creates the descendant client for `session_id`'s envelope, which starts `program` through `bash` next. The
    /// client lives as long as the returned value; the envelope must be started only after this succeeded.
    ///
    /// # Errors
    ///
    /// No client was created. The caller refuses the session: `hello` promised that every exec in an envelope is
    /// decided, so an envelope without a client never starts (fail closed).
    pub(crate) fn watch(
        &self,
        session_id: SessionId,
        bash: &CanonicalPath,
        program: &CanonicalPath,
    ) -> Result<Box<dyn DescendantClient>, PlatformError> {
        let sandbox_exec = CanonicalPath::new(SANDBOX_EXEC)?;
        let chain = LaunchChain::new(self.trampoline.clone(), sandbox_exec, bash.clone(), program.clone());
        let handler = EnvelopeExecs::new(
            session_id,
            Arc::clone(&self.authoriser),
            chain,
            self.knsh.clone(),
            self.shim_dir.clone(),
        );
        self.clients.watch(Arc::new(handler))
    }
}

#[cfg(test)]
pub(crate) mod tests;
