//! Native-mode lines (KNSH-108, FR-LC-50 to FR-LC-58,
//! `specs/03-functional-requirements/command-lifecycle.md#native-mode-knsh-108`).
//!
//! A session whose profile sets `exec.mode = "native"` has its lines run by `knsh`'s own interpreter, and every simple
//! command the interpreter would start is decided here, one by one, with its real argv.
//!
//! - **The line** is admitted without a decision of its own (FR-LC-51): the checks before any decision
//!   ([`Lifecycle::context`]) and the checkpoint gate. Its record, the **line record**, has `decision.source =
//!   "native"`, its exit status, output, checkpoint and file changes, and it publishes `command.started` and
//!   `command.finished`.
//! - **The interpreter** is spawned through [`Spawner::spawn_native`] under the interpreter profile, holding one end of
//!   a socket pair made for the line (FR-LC-52). This module serves the other end: [`Native::serve`] reads each
//!   request ([`RequestReader`]) and answers it on a thread of its own, so a command waiting for an ask never holds up
//!   the line's other commands, and the interpreter's threads wait for theirs side by side.
//! - **Each command** ([`Native::start`]) is decided as the line `<canonical path> <argument>…` through
//!   [`Lifecycle::evaluate`], the phase 2 pipeline, resolving names on its own `PATH` without the shims (FR-LC-53).
//!   Its **command record** names the line record as `parent_record_id`, as do its `command.denied`,
//!   `command.started` and `command.finished` (FR-LC-54). A denial is answered with its reason, which the interpreter
//!   prints before the command fails with 126 (FR-LC-55). An allowed command is started by the supervisor through
//!   [`Spawner::run_command`], in the line's process group (FR-LC-56); its thread waits for it, writes its record, and
//!   then tells whoever waits for it ([`Native::wait`]).
//! - **Fail closed** (FR-LC-57): a request that cannot be read breaks the channel (both directions are shut down, so
//!   the interpreter denies everything from then on); a command arriving while its session is held waits until the
//!   session runs again, and one whose session ended, or whose line's caller has gone, is denied; a panic while
//!   deciding is a denial.
//! - **The end** (FR-LC-58): once the interpreter has exited, no command starts any more ([`Native::close`]), and the
//!   members of the line's group still running are killed, so every command thread ends and the line is answered.
//!
//! # Known limits
//!
//! - A command that leaves the line's process group (`setsid`) and keeps running is not killed with the line, and
//!   the line is answered only once it ends.
//! - The line's caller leaving does not stop the line once it runs (as for a phase 2 line); it cancels the commands
//!   still waiting for a decision, and denies every later one.

use std::collections::HashMap;
use std::ffi::OsString;
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::panic::{self, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use knsh_core::{
    Actor, Allowed, BinaryLookup, Caller, CanonicalPath, Decision, DecisionSource, DecisionVerdict, EventData,
    ExecutionRecord, MAX_LINE_LEN, Outcome, OutputMode, RecordDetails, RecordId, Redacted, Redactor, Refusal,
    RefusalKind, SessionId, Timestamp, UnprotectedRoot,
};
use knsh_platform::macos::{RequestReader, write_frame};
use knsh_platform::supervision::{Reply, Request, Submission};
use knsh_platform::{ExitStatus, ProcessGroupId};
use knsh_proto::{DEFAULT_POLICY_CHECK_PATH, ErrorCode, LineStatus, RpcError};
use knsh_store::RecordedOutput;

use super::{
    Blocked, Context, ENDED_AFTER_DECISION, Evaluated, FsLookup, GONE_BEFORE_SPAWN, HELD_AFTER_DECISION, Lifecycle,
    NO_SHADOW, NativePlan, Origin, Ran, RunningEvents, SHADOW_NOT_READY, SpawnReport, Spawner, not_ready, not_started,
    record_error, signal_name,
};
use crate::exec::{Finished, ForwardedLine, PATH_VAR, Proposal, supervised_env};
use crate::jobs::LineControl;
use crate::shadows::ClosedLine;
use crate::spawn::{CommandEvents, CommandPlan};

/// Most commands of one line running (or being decided) at once; more are denied
/// (`specs/09-reference/defaults-and-limits.md`).
pub(crate) const MAX_RUNNING_COMMANDS: usize = 256;

/// Most descriptors above 2 one command may hold: what `knsh-exec --keep-fd` accepts.
const MAX_KEPT_DESCRIPTORS: usize = 16;

/// How often the line's caller is checked while its interpreter runs: how late a pending decision learns that the
/// caller has gone.
const CALLER_POLL: Duration = Duration::from_millis(50);

/// How long a command whose session is held waits before the session and the line are checked again.
const HELD_SLICE: Duration = Duration::from_millis(100);

/// Reasons for denials made here. Fixed texts.
const NO_CHANNEL: &str = "the supervision channel of the line could not be set up, so it was denied (fail closed)";
const TOO_MANY_RUNNING: &str = "the line runs too many commands at once, so the command was denied";
const TOO_MANY_DESCRIPTORS: &str = "the command holds too many open descriptors, so it was denied";
const NOT_UTF8: &str = "the command's path, arguments or environment are not UTF-8, so it was denied";
const NO_DIRECTORY: &str = "the command's working directory could not be resolved, so it was denied";
const TOO_LONG: &str = "the command is longer than a line may be, so it was denied";
const LINE_ENDED: &str = "the line ended before the command could start, so it was denied";
const SESSION_ENDED: &str = "the session ended, so the command was denied";
const NATIVE_REWRITE: &str = "a rewrite cannot be applied to one command of a native-mode line, so it was denied";
const INTERNAL: &str = "the command could not be decided, so it was denied (fail closed)";

/// One native-mode line while its interpreter runs: what its commands' threads share.
struct Native<'a> {
    lifecycle: &'a Lifecycle,
    session_id: SessionId,
    /// The line record: every command record's `parent_record_id`.
    line_record: RecordId,
    /// The line's `PATH` source of truth for shims: removed from every command's `PATH` (FR-LC-16).
    shim_dir: &'a std::path::Path,
    /// Set once the line's caller has gone or the line ended: pending decisions are cancelled (FR-LC-41).
    gone: AtomicBool,
    /// Whether commands may still be started; false once the interpreter has exited (FR-LC-58). A command is spawned
    /// while this lock is held, so closing waits for a spawn in progress to be in the group.
    open: Mutex<bool>,
    /// The line's process group, once its interpreter runs: what each command joins.
    group: &'a Mutex<Option<ProcessGroupId>>,
    /// Writes replies, one frame at a time.
    writer: Mutex<UnixStream>,
    /// Each started command by its channel number, with how it ended once it has (and its record is written).
    children: Mutex<HashMap<u64, Option<ExitStatus>>>,
    /// Notified whenever a command ends.
    ended: Condvar,
    next_child: AtomicU64,
    /// Commands being decided or running.
    running: AtomicUsize,
}

impl Caller for Native<'_> {
    fn gone(&self) -> bool {
        self.gone.load(Ordering::SeqCst)
    }
}

impl Lifecycle {
    /// Runs a native-mode `line` admitted with `context` (module documentation): the checkpoint gate, the line record,
    /// the interpreter and the channel's server, then the line's answer as for a phase 2 line.
    pub(super) fn run_native(
        &self,
        line: ForwardedLine,
        caller: &dyn Caller,
        context: Context,
    ) -> Result<Finished, RpcError> {
        let Context {
            record_id,
            received_at,
            actor,
            profile,
            redactor,
        } = context;
        let session_id = line.session_id;
        let record = (record_id, received_at);
        // FR-CKP-02: the line's checkpoint roots, as for a phase 2 line; its commands' changes are the line's.
        let (unprotected, protected) = match self.checkpoint_gate(&line, &profile, caller) {
            Ok(gate) => gate,
            Err(blocked) => return Err(self.native_blocked(&line, &actor, &redactor, record, blocked)),
        };
        if caller.gone() {
            return Err(self.native_blocked(&line, &actor, &redactor, record, Blocked::CallerGone));
        }
        let Ok((server, client)) = UnixStream::pair() else {
            return Err(self.native_denied(&line, &actor, &redactor, record, NO_CHANNEL, RefusalKind::Denied));
        };
        let (Ok(writer), Ok(shutdown)) = (server.try_clone(), server.try_clone()) else {
            return Err(self.native_denied(&line, &actor, &redactor, record, NO_CHANNEL, RefusalKind::Denied));
        };
        let latency_ms = self.since(received_at);
        let decision = admitted();
        let record_output = self.records_output(session_id, &profile);
        let default_mode = profile.output.mode;
        let capture = self.capture_plan(&line, record_output, &actor, record_id, &redactor);
        let started_at = self.parts.clock.now().unwrap_or(received_at);
        let command = redactor.redact_text(&line.proposal.command);
        let cwd = line.proposal.cwd.clone();
        let control = Arc::clone(&line.control);
        let events = RunningEvents {
            events: &self.parts.events,
            session_id,
            actor: &actor,
            record_id,
            command: command.clone(),
            cwd: &cwd,
            started_at,
            control: &control,
            sessions: &self.parts.sessions,
            group: Mutex::new(None),
            secrets: Vec::new(),
            spawned: AtomicBool::new(false),
            parent_record_id: None,
        };
        let checkpoint_line = self
            .parts
            .sessions
            .open_checkpoint_lines(session_id, record_id, &protected);
        let native = Native {
            lifecycle: self,
            session_id,
            line_record: record_id,
            shim_dir: &self.parts.shim_dir,
            gone: AtomicBool::new(false),
            open: Mutex::new(true),
            group: &events.group,
            writer: Mutex::new(writer),
            children: Mutex::new(HashMap::new()),
            ended: Condvar::new(),
            next_child: AtomicU64::new(1),
            running: AtomicUsize::new(0),
        };
        let plan = NativePlan {
            record_id,
            line,
            profile: profile.clone(),
            capture,
            channel: OwnedFd::from(client),
        };
        let spawner: &dyn Spawner = &*self.parts.spawner;
        let report = drive(&native, spawner, plan, &events, server, &shutdown, caller);
        let group = *events.group.lock().unwrap_or_else(PoisonError::into_inner);
        let processes = self.parts.sessions.line_processes(session_id, group);
        let closed = crate::sessions::Sessions::close_checkpoint_lines(checkpoint_line, &processes);
        self.native_answer(LineEnd {
            session_id,
            actor: &actor,
            record_id,
            command,
            cwd,
            started_at,
            decision,
            latency_ms,
            unprotected,
            record_output,
            default_mode,
            report,
            closed,
        })
    }

    /// Step 11 for a native-mode line once its interpreter has ended: its line record (with its output when the
    /// session records it), `command.finished`, the uncertain checkpoints, and the answer, as for a phase 2 line.
    fn native_answer(&self, end: LineEnd<'_>) -> Result<Finished, RpcError> {
        let LineEnd {
            session_id,
            actor,
            record_id,
            command,
            cwd,
            started_at,
            decision,
            latency_ms,
            unprotected,
            record_output,
            default_mode,
            report,
            closed,
        } = end;
        let files_changed = closed
            .protected
            .then(|| closed.checkpoint.as_ref().map_or(0, |checkpoint| checkpoint.count));
        let checkpoint_id = closed.checkpoint.as_ref().map(|checkpoint| checkpoint.id);
        let ended_at = self.parts.clock.now().unwrap_or(started_at);
        let (exit_code, signal) = exit_and_signal(&report);
        let line_record = ExecutionRecord {
            record_id,
            session_id,
            actor: actor.clone(),
            command: command.clone(),
            cwd: cwd.clone(),
            started_at,
            ended_at: Some(ended_at),
            exit_code,
            details: RecordDetails {
                decision: Some(decision.to_record(latency_ms)),
                signal,
                sandbox_profile: report.sandbox_profile.clone(),
                unprotected,
                attribution: Some(closed.attribution),
                checkpoint_id,
                files_changed: closed.protected.then(|| {
                    closed
                        .checkpoint
                        .as_ref()
                        .map(|checkpoint| checkpoint.files.clone())
                        .unwrap_or_default()
                }),
                ..RecordDetails::default()
            },
        };
        let output = match &report.output {
            Some(output) if record_output => RecordedOutput {
                stdout: Some(output.stdout.output.clone()),
                stderr: Some(output.stderr.output.clone()),
            },
            Some(_) | None => RecordedOutput::default(),
        };
        let written = self.write(line_record, output);
        if written {
            let data = EventData::CommandFinished {
                record_id,
                command: command.clone(),
                cwd,
                started_at,
                ended_at,
                exit_code,
                parent_record_id: None,
            };
            let _ = self.parts.events.publish(session_id, actor, data);
        }
        let record_id = written.then_some(record_id);
        for (root, reason) in closed.uncertain {
            let data = EventData::CheckpointUncertain {
                root,
                record_id,
                reason,
            };
            let _ = self.parts.events.publish(session_id, actor, data);
        }
        match report.outcome {
            Ok(Ran {
                timed_out: false,
                status,
            }) => Ok(Finished {
                record_id,
                status,
                files_changed,
                checkpoint_id,
                executed_command: command,
                decision,
                duration_ms: ended_at.as_unix_micros().saturating_sub(started_at.as_unix_micros()) / 1000,
                default_mode,
                output: report.output,
            }),
            Ok(Ran { timed_out: true, .. }) => Err(record_error(ErrorCode::LineTimedOut, record_id)),
            Err(_) => Err(RpcError::new(ErrorCode::InternalError)),
        }
    }

    /// A native-mode line stopped before its interpreter started, as `blocked` says: recorded as a deny (it was never
    /// decided, so with no classification) and answered as a phase 2 line stopped there.
    fn native_blocked(
        &self,
        line: &ForwardedLine,
        actor: &Actor,
        redactor: &Redactor,
        record: (RecordId, Timestamp),
        blocked: Blocked,
    ) -> RpcError {
        let (reason, kind) = match &blocked {
            Blocked::NotReady { .. } => (SHADOW_NOT_READY, RefusalKind::Denied),
            Blocked::NoShadow => (NO_SHADOW, RefusalKind::Denied),
            Blocked::CallerGone => (GONE_BEFORE_SPAWN, RefusalKind::Cancelled { request_id: None }),
            Blocked::Held(hold) if hold.code == ErrorCode::SessionHeld => (HELD_AFTER_DECISION, RefusalKind::Denied),
            Blocked::Held(_) => (ENDED_AFTER_DECISION, RefusalKind::Denied),
            Blocked::Secret(reason) => (reason.as_str(), RefusalKind::Denied),
        };
        let error = self.native_denied(line, actor, redactor, record, reason, kind);
        match blocked {
            Blocked::NotReady { root, progress } => not_ready(&root, progress),
            Blocked::Held(hold) => hold,
            Blocked::NoShadow | Blocked::CallerGone | Blocked::Secret(_) => error,
        }
    }

    /// Records and reports a native-mode line refused with `reason` before its interpreter started.
    fn native_denied(
        &self,
        line: &ForwardedLine,
        actor: &Actor,
        redactor: &Redactor,
        (record_id, received_at): (RecordId, Timestamp),
        reason: &str,
        kind: RefusalKind,
    ) -> RpcError {
        let refusal = Refusal {
            decision: Decision::deny(DecisionSource::Standalone, None, None),
            command: line.proposal.command.clone(),
            rewritten_from: None,
            reason: Some(reason.to_owned()),
            kind,
            classification: None,
            line_key: None,
            irreversible: None,
        };
        let latency_ms = self.since(received_at);
        self.refused(
            line,
            actor,
            Some(redactor),
            (record_id, received_at, latency_ms),
            &refusal,
        )
    }
}

/// What a native-mode line's answer is made of once its interpreter has ended ([`Lifecycle::native_answer`]).
struct LineEnd<'a> {
    session_id: SessionId,
    actor: &'a Actor,
    record_id: RecordId,
    /// The line, redacted.
    command: Redacted<String>,
    cwd: CanonicalPath,
    started_at: Timestamp,
    /// Its admission: `allow` with source `native`.
    decision: Decision,
    latency_ms: u64,
    unprotected: Vec<UnprotectedRoot>,
    record_output: bool,
    default_mode: OutputMode,
    report: SpawnReport,
    closed: ClosedLine,
}

/// Runs the interpreter of `plan` while `native` serves its channel (`server`), handing the caller's departure to the
/// commands, and once the interpreter has ended closes the line ([`Native::close`]) and the channel (`shutdown`).
fn drive(
    native: &Native<'_>,
    spawner: &dyn Spawner,
    plan: NativePlan,
    events: &RunningEvents<'_>,
    server: UnixStream,
    shutdown: &UnixStream,
    caller: &dyn Caller,
) -> SpawnReport {
    std::thread::scope(|scope| {
        let serving = scope.spawn(|| native.serve(server));
        let (done, finished) = mpsc::channel();
        let running = scope.spawn(move || {
            let report = spawner.spawn_native(plan, events);
            let _ = done.send(());
            report
        });
        // The caller is checked here, on the thread it belongs to, and its departure handed to the commands.
        while let Err(RecvTimeoutError::Timeout) = finished.recv_timeout(CALLER_POLL) {
            if caller.gone() {
                native.gone.store(true, Ordering::SeqCst);
            }
        }
        // A panic in the spawner is a line that did not run to its end.
        let report = running.join().unwrap_or_else(|_| not_started());
        native.close(spawner);
        let _ = shutdown.shutdown(std::net::Shutdown::Both);
        let _ = serving.join();
        report
    })
}

/// The line record's decision (FR-LC-51): admitted, not decided; each of its commands has a decision of its own.
fn admitted() -> Decision {
    Decision {
        verdict: DecisionVerdict::Allow,
        source: DecisionSource::Native,
        rule_id: None,
        decided_by: None,
        hooks: Vec::new(),
    }
}

/// A line's exit code and signal for its record, from how its spawn went (as [`Lifecycle::finished`] records them).
fn exit_and_signal(report: &SpawnReport) -> (Option<i32>, Option<String>) {
    match report.outcome.as_ref().ok() {
        Some(Ran {
            status: LineStatus::Exited(code),
            timed_out,
        }) => (Some(i32::from(*code)), timed_out.then(|| signal_name(15))),
        Some(Ran {
            status: LineStatus::Signalled(number),
            ..
        }) => (None, Some(signal_name(*number))),
        None => (None, None),
    }
}

/// The reason a denied command's interpreter prints (FR-LC-55): the refusal's own, or who denied it and by which rule.
fn refusal_text(refusal: &Refusal) -> String {
    let by = match &refusal.decision.rule_id {
        Some(rule) => format!("denied by {} ({rule})", refusal.decision.source.code()),
        None => format!("denied by {}", refusal.decision.source.code()),
    };
    match &refusal.reason {
        Some(reason) => format!("{by}: {reason}"),
        None => by,
    }
}

/// The reason for a command refused before its decision, from the answer a phase 2 line would have had.
fn error_text(error: &RpcError) -> String {
    let field = |name: &str| {
        error
            .data
            .as_ref()
            .and_then(knsh_json::Value::as_object)
            .and_then(|data| data.get(name))
            .and_then(knsh_json::Value::as_str)
            .map(str::to_owned)
    };
    match error.code {
        ErrorCode::Denied => field("reason").unwrap_or_else(|| "denied".to_owned()),
        ErrorCode::SessionHeld => HELD_AFTER_DECISION.to_owned(),
        _ => error.code.meaning().to_owned(),
    }
}

/// The text of `value`, or `None` when it is not UTF-8.
fn utf8(value: &std::ffi::OsStr) -> Option<&str> {
    value.to_str()
}

/// An allowed command with what its record needs ([`Native::start`]).
struct Decided {
    /// The command as a line, its record naming the line record.
    line: ForwardedLine,
    /// Its canonical program.
    program: CanonicalPath,
    record_id: RecordId,
    received_at: Timestamp,
    latency_ms: u64,
    actor: Actor,
    profile: knsh_core::Profile,
    redactor: Redactor,
    allowed: Box<Allowed>,
}

/// What tells the interpreter its command started, and publishes `command.started` (FR-LC-56, FR-LC-17).
struct Started<'n, 'a> {
    native: &'n Native<'a>,
    /// The request answered once the command runs.
    id: u64,
    /// The command's channel number.
    child: u64,
    /// The `open` lock held from before the spawn until the command is in the line's group.
    open: Mutex<Option<MutexGuard<'n, bool>>>,
    /// Its `command.started` and `secret.injected`.
    events: RunningEvents<'n>,
}

impl CommandEvents for Started<'_, '_> {
    fn started(&self, pid: i32) {
        self.native
            .children
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(self.child, None);
        self.native.reply(&Reply::Running {
            id: self.id,
            child: self.child,
            pid,
        });
        super::LineEvents::started(&self.events);
        // The command is in the group now: closing may go ahead.
        drop(self.open.lock().unwrap_or_else(PoisonError::into_inner).take());
    }
}

impl Native<'_> {
    /// Serves the channel until the interpreter closes it or it breaks (module documentation).
    fn serve(&self, stream: UnixStream) {
        let mut reader = RequestReader::new(stream);
        std::thread::scope(|scope| {
            loop {
                match reader.next_request() {
                    Ok(Some((Request::Start { id, submission }, descriptors))) => {
                        if self.running.fetch_add(1, Ordering::SeqCst) >= MAX_RUNNING_COMMANDS {
                            self.running.fetch_sub(1, Ordering::SeqCst);
                            self.deny_now(id, TOO_MANY_RUNNING);
                            continue;
                        }
                        let started = std::thread::Builder::new()
                            .name("knshd-native-command".to_owned())
                            .spawn_scoped(scope, move || {
                                let decided =
                                    panic::catch_unwind(AssertUnwindSafe(|| self.start(id, &submission, descriptors)));
                                if decided.is_err() {
                                    // Defence in depth (NFR-REL-07): a panic while deciding is a denial.
                                    self.deny_now(id, INTERNAL);
                                }
                                self.running.fetch_sub(1, Ordering::SeqCst);
                            });
                        if started.is_err() {
                            self.running.fetch_sub(1, Ordering::SeqCst);
                            self.deny_now(id, INTERNAL);
                        }
                    }
                    Ok(Some((Request::Wait { id, child }, _))) => {
                        let started = std::thread::Builder::new()
                            .name("knshd-native-wait".to_owned())
                            .spawn_scoped(scope, move || self.wait(id, child));
                        if started.is_err() {
                            self.reply(&Reply::Failed { id });
                        }
                    }
                    Ok(None) => break,
                    Err(_) => {
                        // FR-LC-57: a channel that cannot be read is broken both ways, so the interpreter denies every
                        // later command rather than waiting for an answer.
                        let writer = self.writer.lock().unwrap_or_else(PoisonError::into_inner);
                        let _ = writer.shutdown(std::net::Shutdown::Both);
                        break;
                    }
                }
            }
        });
    }

    /// Writes `reply`. Best effort: an interpreter that has gone needs no answer.
    fn reply(&self, reply: &Reply) {
        let Ok(payload) = reply.encode() else { return };
        let writer = self.writer.lock().unwrap_or_else(PoisonError::into_inner);
        let _ = write_frame(&writer, &payload, &[]);
    }

    /// Denies request `id` with `reason` before anything was decided or recorded about it.
    fn deny_now(&self, id: u64, reason: &str) {
        self.reply(&Reply::Denied {
            id,
            reason: reason.to_owned(),
        });
    }

    /// Answers a wait for command `child` once it has ended (and its record is written).
    fn wait(&self, id: u64, child: u64) {
        let mut children = self.children.lock().unwrap_or_else(PoisonError::into_inner);
        let status = loop {
            match children.get(&child) {
                None => {
                    drop(children);
                    self.reply(&Reply::Failed { id });
                    return;
                }
                Some(Some(status)) => break *status,
                Some(None) => children = self.ended.wait(children).unwrap_or_else(PoisonError::into_inner),
            }
        };
        children.remove(&child);
        drop(children);
        self.reply(&Reply::Exited { id, status });
    }

    /// No command starts from now on, and the ones still running are killed (FR-LC-58). Waits for a spawn in progress
    /// to finish, so nothing started after this escapes the kill.
    fn close(&self, spawner: &dyn Spawner) {
        self.gone.store(true, Ordering::SeqCst);
        *self.open.lock().unwrap_or_else(PoisonError::into_inner) = false;
        if let Some(group) = *self.group.lock().unwrap_or_else(PoisonError::into_inner) {
            spawner.kill_members(group);
        }
    }

    /// Waits while the session is held (FR-SES-10, FR-SES-12). `Err` with the reason when the session ended or the line
    /// is gone.
    fn wait_runnable(&self) -> Result<(), &'static str> {
        loop {
            match self.lifecycle.parts.sessions.runnable(self.session_id) {
                Ok(_) => return Ok(()),
                Err(hold) if hold.code == ErrorCode::SessionHeld => {
                    if self.gone() {
                        return Err(LINE_ENDED);
                    }
                    self.lifecycle.parts.clock.sleep(HELD_SLICE);
                }
                Err(_) => return Err(SESSION_ENDED),
            }
        }
    }

    /// Decides one command and, if allowed, runs it to its end (module documentation). Every path answers `id`.
    fn start(&self, id: u64, submission: &Submission, descriptors: Vec<OwnedFd>) {
        if let Err(reason) = self.wait_runnable() {
            return self.deny_now(id, reason);
        }
        let Some((line, program)) = self.command_line(id, submission) else {
            return;
        };
        // A deny made before the pipeline ran was recorded there (with the line as parent).
        let evaluated = match self.lifecycle.evaluate(&line, self, Origin::Line) {
            Ok(evaluated) => evaluated,
            Err(error) => return self.deny_now(id, &error_text(&error)),
        };
        let Evaluated {
            record_id,
            received_at,
            latency_ms,
            actor,
            profile,
            redactor,
            outcome,
        } = evaluated;
        let allowed = match outcome {
            Outcome::Refused(refusal) => {
                let record = (record_id, received_at, latency_ms);
                self.lifecycle.refused(&line, &actor, Some(&redactor), record, &refusal);
                return self.deny_now(id, redactor.redact_text(&refusal_text(&refusal)).expose());
            }
            Outcome::Run(allowed) => allowed,
        };
        let decided = Decided {
            line,
            program,
            record_id,
            received_at,
            latency_ms,
            actor,
            profile,
            redactor,
            allowed,
        };
        // FR-LC-56: the interpreter has already expanded the command; another one cannot take its place.
        if decided.allowed.rewritten_from.is_some() {
            return self.refuse(id, &decided, NATIVE_REWRITE, RefusalKind::Denied);
        }
        if self.gone() {
            return self.refuse(
                id,
                &decided,
                GONE_BEFORE_SPAWN,
                RefusalKind::Cancelled { request_id: None },
            );
        }
        if self.lifecycle.parts.sessions.runnable(self.session_id).is_err() {
            return self.refuse(id, &decided, HELD_AFTER_DECISION, RefusalKind::Denied);
        }
        // KNSH-092: the secrets its decision gives it, as for a phase 2 line.
        let secrets =
            self.lifecycle
                .secrets_for(self.session_id, &decided.allowed, &decided.profile, &decided.redactor);
        match secrets {
            Ok(secrets) => self.run_allowed(id, &decided, &secrets, submission, descriptors),
            Err(Blocked::Secret(reason)) => self.refuse(id, &decided, &reason, RefusalKind::Denied),
            Err(_) => self.refuse(id, &decided, INTERNAL, RefusalKind::Denied),
        }
    }

    /// The line `submission` is decided as, with its canonical program (FR-LC-53), or `None` once `id` was answered:
    /// not found, or denied before any decision (a limit, text that is not UTF-8, a directory that cannot be
    /// resolved).
    fn command_line(&self, id: u64, submission: &Submission) -> Option<(ForwardedLine, CanonicalPath)> {
        let lookup = FsLookup(self.lifecycle.parts.profiles.fs());
        // Decided, and run, as the binary it really is. A program that cannot be resolved does not exist.
        let Some(program) = lookup.canonicalise(&submission.program) else {
            self.reply(&Reply::NotFound { id });
            return None;
        };
        let refused = |reason| {
            self.deny_now(id, reason);
            None
        };
        let Some(cwd) = lookup.canonicalise(&submission.cwd) else {
            return refused(NO_DIRECTORY);
        };
        if submission.descriptors.iter().filter(|number| **number > 2).count() > MAX_KEPT_DESCRIPTORS {
            return refused(TOO_MANY_DESCRIPTORS);
        }
        let Some(command) = command_text(&program, &submission.args) else {
            return refused(NOT_UTF8);
        };
        if command.len() > MAX_LINE_LEN {
            return refused(TOO_LONG);
        }
        let Some(env) = submission
            .env
            .iter()
            .map(|(name, value)| Some((utf8(name)?.to_owned(), utf8(value)?.to_owned())))
            .collect::<Option<Vec<_>>>()
        else {
            return refused(NOT_UTF8);
        };
        // FR-LC-16: no shims and no session token, whatever the script put back.
        let env = supervised_env(env, self.shim_dir);
        let path = env
            .iter()
            .find(|(name, _)| name == PATH_VAR)
            .map_or_else(|| DEFAULT_POLICY_CHECK_PATH.to_owned(), |(_, value)| value.clone());
        let line = ForwardedLine {
            session_id: self.session_id,
            proposal: Proposal { command, cwd, path },
            interpreter: knsh_proto::Interpreter::Bash,
            args: Vec::new(),
            env,
            stdio: None,
            timeout_s: None,
            checkpoint_wait: false,
            control: LineControl::new(),
            parent_record_id: Some(self.line_record),
        };
        Some((line, program))
    }

    /// Records an allowed command that may not start as a deny with `reason`, so its decision is not lost, and denies
    /// request `id`.
    fn refuse(&self, id: u64, decided: &Decided, reason: &str, kind: RefusalKind) {
        let allowed = &decided.allowed;
        let refusal = Refusal {
            decision: Decision::deny(DecisionSource::Standalone, None, None),
            command: allowed.command.clone(),
            rewritten_from: allowed.rewritten_from.clone(),
            reason: Some(reason.to_owned()),
            kind,
            classification: Some(allowed.classification.clone()),
            line_key: None,
            irreversible: Some(allowed.irreversible.clone()),
        };
        let record = (decided.record_id, decided.received_at, decided.latency_ms);
        self.lifecycle
            .refused(&decided.line, &decided.actor, Some(&decided.redactor), record, &refusal);
        self.deny_now(id, decided.redactor.redact_text(reason).expose());
    }

    /// Starts the allowed command in the line's group and waits for it (FR-LC-56): `id` is answered once it runs, its
    /// record written once it ended, then its waiter told how it ended.
    fn run_allowed(
        &self,
        id: u64,
        decided: &Decided,
        secrets: &[crate::injection::Injected],
        submission: &Submission,
        descriptors: Vec<OwnedFd>,
    ) {
        let parts = &self.lifecycle.parts;
        let Decided {
            line,
            program,
            record_id,
            received_at,
            latency_ms,
            actor,
            profile,
            redactor,
            allowed,
        } = decided;
        let open = self.open.lock().unwrap_or_else(PoisonError::into_inner);
        let group = *self.group.lock().unwrap_or_else(PoisonError::into_inner);
        let (true, Some(group)) = (*open, group) else {
            drop(open);
            return self.refuse(id, decided, LINE_ENDED, RefusalKind::Denied);
        };
        let child = self.next_child.fetch_add(1, Ordering::SeqCst);
        // However this thread leaves (a panic while recording included), a waiter of a started command is answered,
        // so the channel's server, and with it the line's answer, never waits for it forever (FR-LC-57, FR-LC-58).
        let mut ending = Ending {
            native: self,
            child,
            status: ExitStatus::Exited(126),
        };
        let started_at = parts.clock.now().unwrap_or(*received_at);
        let started = Started {
            native: self,
            id,
            child,
            open: Mutex::new(Some(open)),
            events: RunningEvents {
                events: &parts.events,
                session_id: self.session_id,
                actor,
                record_id: *record_id,
                command: redactor.redact_text(&allowed.command),
                cwd: &line.proposal.cwd,
                started_at,
                control: &line.control,
                sessions: &parts.sessions,
                group: Mutex::new(None),
                secrets: crate::injection::injected_names(secrets),
                spawned: AtomicBool::new(false),
                parent_record_id: Some(self.line_record),
            },
        };
        let descriptors: Vec<(i32, OwnedFd)> = submission.descriptors.iter().copied().zip(descriptors).collect();
        let plan = CommandPlan {
            record_id: *record_id,
            session_id: self.session_id,
            profile,
            allowed,
            program,
            args: &submission.args,
            env: &line.env,
            cwd: &line.proposal.cwd,
            umask: submission.umask,
            descriptors,
            group,
            secrets,
        };
        let report = parts.spawner.run_command(&plan, &started);
        // Released if the spawn failed before the command was in the group.
        drop(started.open.lock().unwrap_or_else(PoisonError::into_inner).take());
        let ran = started.events.spawned.load(Ordering::SeqCst);
        let (_, _) = self.lifecycle.finished(
            self.session_id,
            actor,
            redactor,
            *record_id,
            &line.proposal.cwd,
            started_at,
            allowed,
            *latency_ms,
            &report,
            false,
            Vec::new(),
            None,
            started.events.secrets_injected(),
            profile,
            Some(self.line_record),
        );
        if !ran {
            // Never started: the interpreter reports it as a program that cannot run (126).
            return self.reply(&Reply::NotExecutable { id });
        }
        ending.status = match report.outcome {
            Ok(Ran {
                status: LineStatus::Exited(code),
                ..
            }) => ExitStatus::Exited(i32::from(code)),
            Ok(Ran {
                status: LineStatus::Signalled(signal),
                ..
            }) => ExitStatus::Signalled(i32::from(signal)),
            // Started but not run to its end (its profile was never applied, it could not be waited for): 126.
            Err(_) => ExitStatus::Exited(126),
        };
        // `ending` is dropped here: the command's waiter is told how it ended, now that its record is written.
    }
}

/// Marks a started command as ended when dropped ([`Native::run_allowed`]): with `status` once its record is written,
/// or 126 if its thread unwound before that. A command that never started (no entry) is left alone.
struct Ending<'n, 'a> {
    native: &'n Native<'a>,
    child: u64,
    status: ExitStatus,
}

impl Drop for Ending<'_, '_> {
    fn drop(&mut self) {
        let mut children = self.native.children.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(entry @ None) = children.get_mut(&self.child) {
            *entry = Some(self.status);
        }
        drop(children);
        self.native.ended.notify_all();
    }
}

/// The line a command is decided as: its canonical path and arguments, each one quoted shell word (FR-LC-53).
/// `None` when the path or an argument is not UTF-8.
fn command_text(program: &CanonicalPath, args: &[OsString]) -> Option<String> {
    let mut command = crate::endpoint_security::shell_word(program.as_path().to_str()?);
    for arg in args {
        command.push(' ');
        command.push_str(&crate::endpoint_security::shell_word(arg.to_str()?));
    }
    Some(command)
}
