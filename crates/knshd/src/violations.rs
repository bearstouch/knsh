//! The sandbox violation reader as `knshd` runs it (KNSH-047; FR-SBX-06, FR-SBX-08; decision 9).
//!
//! # Threads
//!
//! [`Reader::start`] starts two threads, off every request and command path, so a reader that fails, hangs or
//! floods never blocks or fails a command:
//!
//! - **reader** (`knsh-violations`): opens the [`DenialLog`] stream, parses each entry with the pure
//!   [`parse_entry`], and hands knsh denials to the merger through a bounded queue ([`MAX_QUEUED`]; past it, entries
//!   are dropped and counted). When the stream ends or cannot be opened, it waits and opens it again, with a delay
//!   that doubles from [`Config::restart_min`] to [`Config::restart_max`] while no stream proves live.
//! - **canary** (`knsh-violation-canary`, one per stream): causes a canary denial every [`Config::canary_interval`]
//!   until the reader sees it come back, at most [`Config::canary_attempts`] times, then checks again every
//!   [`Config::recheck_interval`]. `log stream` delivers nothing until it is attached, and the system drops entries
//!   now and then, so "no entries" means "no denials" only while a canary has come back (decision 9).
//! - **merger** (`knsh-violation-merge`): folds repeats with [`ViolationMerger`] and hands each merged violation to
//!   the [`ViolationSink`] once its window has passed.
//!
//! # Status
//!
//! [`ReaderStatus`] is `unified_log` only from the moment a canary came back until the stream ends or a recheck
//! fails; otherwise `none`. `hello` reports it live as `capabilities.sandbox_violations`, so a reader failure is
//! visible to every client (`specs/05-models/capabilities.md`).
//!
//! # Sink
//!
//! [`RecordViolations`] publishes each violation as `sandbox.violation` for the session its tag names, if that
//! session is live, and attaches it to the record its tag names: held in memory while the line runs, appended to
//! the stored record once it is written, including denials that arrive after the line finished (FR-SBX-08). A
//! denial whose tag names an envelope has no record. Nothing is attached anywhere the tag does not name exactly.
//!
//! # Lock order
//!
//! [`Shared::state`], then nothing: the stream's stopper is called under it, and it only kills the `log` process.
//! [`RecordViolations::running`] is never held across a store or event call.
//!
//! Waits use the real time of condition variables; the injected clock only stamps and times violations.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use knsh_core::{
    DenialReport, EventData, RecordId, SandboxViolation, SessionId, Timestamp, ViolationMerger, merge_into,
};
use knsh_platform::violation::parse_entry;
use knsh_platform::{
    CanaryNonce, Clock, DenialLog, DenialStream, Field, Level, LogEntry, Random, StreamStopper, SystemLog, Value,
};
use knsh_proto::SandboxViolations;

/// Denials queued between the reader and the merger. One noisy process can log hundreds in a fraction of a second
/// (KNSH-025); past this bound they are dropped rather than held.
pub(crate) const MAX_QUEUED: usize = 4096;

/// The longest the merger sleeps while violations are pending, so it notices their windows passing promptly.
const MERGE_POLL: Duration = Duration::from_millis(100);

/// Takes a lock even if a thread panicked while holding it: every critical section below is one assignment or one
/// map operation.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// How the reader paces itself.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Config {
    /// Between two canaries while waiting for one to come back.
    pub(crate) canary_interval: Duration,
    /// Canaries per round before the stream is reported as not delivering.
    pub(crate) canary_attempts: u32,
    /// Between two rounds once a canary came back.
    pub(crate) recheck_interval: Duration,
    /// The first delay before reopening a stream that ended or failed.
    pub(crate) restart_min: Duration,
    /// The longest delay between two reopenings.
    pub(crate) restart_max: Duration,
}

impl Config {
    /// The pacing `knshd` uses. Attaching took from 0.27 s to over 2 s in KNSH-025, so one round allows 10 s.
    pub(crate) const DEFAULT: Self = Self {
        canary_interval: Duration::from_millis(250),
        canary_attempts: 40,
        recheck_interval: Duration::from_secs(300),
        restart_min: Duration::from_secs(1),
        restart_max: Duration::from_secs(60),
    };
}

/// Whether the reader currently receives denials. Shared with `hello`.
#[derive(Debug, Default)]
pub(crate) struct ReaderStatus {
    live: AtomicBool,
}

impl ReaderStatus {
    /// A status that is `none` and stays so: no reader runs.
    pub(crate) fn stopped() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// The capability value to report now.
    pub(crate) fn current(&self) -> SandboxViolations {
        if self.live.load(Ordering::Acquire) {
            SandboxViolations::UnifiedLog
        } else {
            SandboxViolations::None
        }
    }

    /// Records whether a canary has proved the current stream live.
    pub(crate) fn set(&self, live: bool) {
        self.live.store(live, Ordering::Release);
    }
}

/// Where merged violations go.
pub(crate) trait ViolationSink: Send + Sync {
    /// Handles one merged violation. Must not block for long: it runs on the merger thread.
    fn report(&self, violation: SandboxViolation);
}

/// The effects the reader uses.
pub(crate) struct Effects {
    /// The system's denials.
    pub(crate) source: Arc<dyn DenialLog>,
    /// Stamps (`at`) and times (merging) violations.
    pub(crate) clock: Arc<dyn Clock>,
    /// Canary nonces.
    pub(crate) random: Arc<dyn Random>,
    /// Where the reader reports its own failures, with fixed messages only.
    pub(crate) log: Arc<dyn SystemLog>,
}

/// Why the reader could not start.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ThreadStartFailed;

/// State shared by the reader's threads and [`Reader::stop`].
#[derive(Default)]
struct Shared {
    state: Mutex<StopState>,
    changed: Condvar,
}

/// Whether the reader is stopping, and how to end the stream it has open.
#[derive(Default)]
struct StopState {
    stopped: bool,
    /// Ends the open stream, if one is open.
    stopper: Option<Box<dyn StreamStopper>>,
}

impl Shared {
    /// Whether [`Shared::stop`] has been called.
    fn is_stopped(&self) -> bool {
        lock(&self.state).stopped
    }

    /// Stops everything: no new stream opens, the open one ends, and every wait returns.
    fn stop(&self) {
        let mut state = lock(&self.state);
        state.stopped = true;
        if let Some(stopper) = state.stopper.take() {
            stopper.stop();
        }
        self.changed.notify_all();
    }

    /// Remembers how to end the stream just opened. `false` (the stream is ended at once) if already stopped.
    fn register(&self, stopper: Box<dyn StreamStopper>) -> bool {
        let mut state = lock(&self.state);
        if state.stopped {
            stopper.stop();
            return false;
        }
        state.stopper = Some(stopper);
        true
    }

    /// Forgets the stopper of a stream that has ended.
    fn unregister(&self) {
        lock(&self.state).stopper = None;
    }

    /// Wakes every wait, so it rechecks its own condition.
    fn wake(&self) {
        let _state = lock(&self.state);
        self.changed.notify_all();
    }

    /// Waits up to `duration`. Returns `true` as soon as the reader is stopped or `done` is set.
    fn wait(&self, duration: Duration, done: &AtomicBool) -> bool {
        let deadline = Instant::now().checked_add(duration);
        let mut state = lock(&self.state);
        loop {
            if state.stopped || done.load(Ordering::Acquire) {
                return true;
            }
            let now = Instant::now();
            let left = match deadline {
                Some(deadline) if deadline > now => deadline - now,
                Some(_) => return false,
                // A duration too long to add is as good as forever.
                None => Duration::from_secs(3600),
            };
            state = self
                .changed
                .wait_timeout(state, left)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
    }
}

/// One denial on its way from the reader to the merger.
struct Queued {
    report: DenialReport,
    at: Timestamp,
}

/// The running reader (module documentation). Dropping it stops it without waiting; [`Reader::stop`] also waits.
pub(crate) struct Reader {
    status: Arc<ReaderStatus>,
    shared: Arc<Shared>,
    threads: Vec<JoinHandle<()>>,
}

impl Reader {
    /// Starts reading `effects.source` and handing merged violations to `sink`.
    ///
    /// # Errors
    ///
    /// [`ThreadStartFailed`] if a thread cannot be started; nothing keeps running then.
    pub(crate) fn start(
        effects: Effects,
        sink: Arc<dyn ViolationSink>,
        config: Config,
    ) -> Result<Self, ThreadStartFailed> {
        let status = ReaderStatus::stopped();
        let shared = Arc::new(Shared::default());
        let (queue, inbox) = mpsc::sync_channel(MAX_QUEUED);
        let clock = Arc::clone(&effects.clock);
        let merger = thread::Builder::new()
            .name(String::from("knsh-violation-merge"))
            .spawn(move || merge_loop(&inbox, sink.as_ref(), clock.as_ref()))
            .map_err(|_| ThreadStartFailed)?;
        let reader = {
            let status = Arc::clone(&status);
            let shared = Arc::clone(&shared);
            // On failure the queue's sender went with the closure, so the merger sees it closed, drains and ends.
            thread::Builder::new()
                .name(String::from("knsh-violations"))
                .spawn(move || read_loop(&effects, &shared, &status, &queue, config))
                .map_err(|_| ThreadStartFailed)?
        };
        Ok(Self {
            status,
            shared,
            threads: vec![reader, merger],
        })
    }

    /// The status `hello` reports.
    pub(crate) fn status(&self) -> Arc<ReaderStatus> {
        Arc::clone(&self.status)
    }

    /// Stops reading and waits for the threads to end. Violations still pending are released to the sink first.
    pub(crate) fn stop(&mut self) {
        self.shared.stop();
        for thread in self.threads.drain(..) {
            let _ = thread.join();
        }
        self.status.set(false);
    }
}

impl Drop for Reader {
    /// Never joins: a drop must not block on a thread stuck in a read; the stopper ends that read.
    fn drop(&mut self) {
        self.shared.stop();
    }
}

/// The reader thread: one stream after another until stopped (module documentation).
fn read_loop(
    effects: &Effects,
    shared: &Arc<Shared>,
    status: &Arc<ReaderStatus>,
    queue: &SyncSender<Queued>,
    config: Config,
) {
    let never = AtomicBool::new(false);
    let mut delay = config.restart_min;
    while !shared.is_stopped() {
        match effects.source.open() {
            Err(error) => {
                status.set(false);
                effects.log.log(
                    Level::Error,
                    "sandbox violation reader unavailable",
                    &[Field::new("errno", Value::Errno(error.errno().unwrap_or(0)))],
                );
            }
            Ok(stream) => {
                if !shared.register(stream.stopper()) {
                    break;
                }
                let confirmed = run_stream(stream, effects, shared, status, queue, config);
                shared.unregister();
                status.set(false);
                if shared.is_stopped() {
                    break;
                }
                effects.log.log(Level::Error, "sandbox violation reader stopped", &[]);
                if confirmed {
                    delay = config.restart_min;
                }
            }
        }
        if shared.wait(delay, &never) {
            break;
        }
        delay = delay.saturating_mul(2).min(config.restart_max);
    }
    status.set(false);
}

/// Reads one stream until it ends. Returns whether a canary came back through it.
fn run_stream(
    mut stream: Box<dyn DenialStream>,
    effects: &Effects,
    shared: &Arc<Shared>,
    status: &Arc<ReaderStatus>,
    queue: &SyncSender<Queued>,
    config: Config,
) -> bool {
    let mut bytes = [0; 16];
    if effects.random.fill(&mut bytes).is_err() {
        // Without a secret nonce a canary could be forged, so this stream can never be confirmed; reopen later.
        effects
            .log
            .log(Level::Error, "sandbox violation canary unavailable", &[]);
        return false;
    }
    let nonce = CanaryNonce::new(bytes);
    let seen = Arc::new(AtomicBool::new(false));
    let done = Arc::new(AtomicBool::new(false));
    let canary = {
        let (source, log) = (Arc::clone(&effects.source), Arc::clone(&effects.log));
        let (shared, status, seen, done) = (
            Arc::clone(shared),
            Arc::clone(status),
            Arc::clone(&seen),
            Arc::clone(&done),
        );
        thread::Builder::new()
            .name(String::from("knsh-violation-canary"))
            .spawn(move || {
                canary_loop(
                    source.as_ref(),
                    log.as_ref(),
                    &nonce,
                    &shared,
                    &status,
                    &seen,
                    &done,
                    config,
                );
            })
            .ok()
    };
    if canary.is_none() {
        effects
            .log
            .log(Level::Error, "sandbox violation canary unavailable", &[]);
    }
    let mut confirmed = false;
    let mut dropped: u64 = 0;
    // Ends at the end of the stream, on a read error, or when the reader is stopped (the stopper ends the stream).
    while let Ok(Some(entry)) = stream.next_entry() {
        match parse_entry(&entry) {
            Some(LogEntry::Canary(found)) if found == nonce => {
                confirmed = true;
                seen.store(true, Ordering::Release);
                status.set(true);
            }
            // Another stream's canary, or a forgery: proves nothing about this one.
            Some(LogEntry::Canary(_)) | None => {}
            Some(LogEntry::Denial(report)) => {
                let Ok(at) = effects.clock.now() else {
                    continue;
                };
                match queue.try_send(Queued { report, at }) {
                    Ok(()) => {}
                    Err(TrySendError::Full(_)) => dropped += 1,
                    // The merger is gone (it never ends before the reader); nothing left to report to.
                    Err(TrySendError::Disconnected(_)) => break,
                }
            }
        }
    }
    done.store(true, Ordering::Release);
    shared.wake();
    if let Some(canary) = canary {
        let _ = canary.join();
    }
    if dropped > 0 {
        effects.log.log(
            Level::Error,
            "sandbox violations dropped",
            &[Field::new("count", Value::U64(dropped))],
        );
    }
    drop(stream);
    confirmed
}

/// The canary thread of one stream (module documentation).
#[allow(clippy::too_many_arguments)]
fn canary_loop(
    source: &dyn DenialLog,
    log: &dyn SystemLog,
    nonce: &CanaryNonce,
    shared: &Shared,
    status: &ReaderStatus,
    seen: &AtomicBool,
    done: &AtomicBool,
    config: Config,
) {
    loop {
        seen.store(false, Ordering::Release);
        let mut confirmed = false;
        for _ in 0..config.canary_attempts {
            if source.trigger_canary(nonce).is_err() {
                log.log(Level::Error, "sandbox violation canary failed", &[]);
            }
            if shared.wait(config.canary_interval, done) {
                return;
            }
            if seen.load(Ordering::Acquire) {
                confirmed = true;
                break;
            }
        }
        if !confirmed {
            // The stream may still deliver some entries, but it has not shown that it does: report `none`.
            status.set(false);
            log.log(Level::Error, "sandbox violation reader not confirmed", &[]);
        }
        if shared.wait(config.recheck_interval, done) {
            return;
        }
    }
}

/// The merger thread: folds repeats and releases each violation once its window has passed. Ends when the reader
/// is gone, after releasing everything still pending.
fn merge_loop(inbox: &Receiver<Queued>, sink: &dyn ViolationSink, clock: &dyn Clock) {
    let start = clock.monotonic();
    let elapsed = || clock.monotonic().saturating_duration_since(start);
    let mut merger = ViolationMerger::new();
    loop {
        for violation in merger.due(elapsed()) {
            sink.report(violation);
        }
        let received = match merger.next_due() {
            None => inbox.recv().map_err(|_| RecvTimeoutError::Disconnected),
            Some(due) => inbox.recv_timeout(due.saturating_sub(elapsed()).min(MERGE_POLL)),
        };
        match received {
            Ok(Queued { report, at }) => {
                if let Some(evicted) = merger.push(report, at, elapsed()) {
                    sink.report(evicted);
                }
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => break,
        }
    }
    for violation in merger.drain() {
        sink.report(violation);
    }
}

/// The sink `knshd` uses: events and records (module documentation).
#[cfg(target_os = "macos")]
pub(crate) struct RecordViolations {
    store: Option<knsh_store::RecordStore>,
    events: Arc<crate::events::EventHub>,
    log: Arc<dyn SystemLog>,
    /// Violations of lines that are running, kept until their record is written.
    /// Each is keyed by its record, with the session the record belongs to.
    running: Mutex<BTreeMap<RecordId, (SessionId, Vec<SandboxViolation>)>>,
}

#[cfg(target_os = "macos")]
impl RecordViolations {
    /// A sink publishing to `events` and attaching to records in `store` (absent when it could not be opened:
    /// violations are then only published).
    pub(crate) fn new(
        store: Option<knsh_store::RecordStore>,
        events: Arc<crate::events::EventHub>,
        log: Arc<dyn SystemLog>,
    ) -> Arc<Self> {
        Arc::new(Self {
            store,
            events,
            log,
            running: Mutex::new(BTreeMap::new()),
        })
    }

    /// A line is about to run: its violations are held until [`RecordViolations::line_recorded`]. Called by the
    /// supervisor (KNSH-050) before it spawns the line.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn line_started(&self, session_id: SessionId, record_id: RecordId) {
        lock(&self.running)
            .entry(record_id)
            .or_insert_with(|| (session_id, Vec::new()));
    }

    /// The record of a finished line is written: the violations held for it are appended, and any that arrive from
    /// now on are appended as they come (FR-SBX-08). Only violations whose tag names `session_id` are attached.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn line_recorded(&self, session_id: SessionId, record_id: RecordId) {
        let Some((started_in, held)) = lock(&self.running).remove(&record_id) else {
            return;
        };
        // Held violations were already filtered by session on arrival; a record reported for another session than
        // it started in attaches nothing.
        if started_in == session_id && !held.is_empty() {
            self.append(session_id, record_id, held);
        }
    }

    /// Appends `violations` to the stored record. Failures are logged, never propagated: violations are
    /// informational and must not fail the merger thread.
    fn append(&self, session_id: SessionId, record_id: RecordId, violations: Vec<SandboxViolation>) {
        let Some(store) = &self.store else {
            return;
        };
        // `false` means the tag named no agent record of that session: nothing is attached, by design.
        if let Err(error) = store.append_sandbox_violations(session_id, record_id, violations) {
            self.log.log(
                Level::Error,
                "sandbox violation not recorded",
                &[Field::new("reason", Value::Static(error.kind()))],
            );
        }
    }
}

#[cfg(target_os = "macos")]
impl ViolationSink for RecordViolations {
    fn report(&self, violation: SandboxViolation) {
        let session_id = violation.report.tag.session_id;
        let record_id = violation.report.tag.command.record_id();
        // Best effort: a session that is not live (ended, or not this engine's) gets no event.
        let _ = self
            .events
            .publish_for_session(session_id, EventData::SandboxViolation(Box::new(violation.clone())));
        let Some(record_id) = record_id else {
            return;
        };
        // Scoped so `running` is released before the store call (module documentation, "Lock order").
        {
            let mut running = lock(&self.running);
            if let Some((started_in, held)) = running.get_mut(&record_id) {
                // Checked here, not only when written: forged tags naming another session must not take the
                // running line's bounded slots.
                if *started_in == session_id {
                    merge_into(held, vec![violation], knsh_store::MAX_VIOLATIONS_PER_RECORD);
                }
                return;
            }
        }
        self.append(session_id, record_id, vec![violation]);
    }
}

#[cfg(test)]
mod tests {
    use knsh_core::{TaggedCommand, Ulid};
    use knsh_platform::testing::{FakeClock, RecordingLog, ScriptedDenialLog, SeededRandom, kernel_entry};

    use super::*;

    /// Fast pacing, so tests wait milliseconds.
    const FAST: Config = Config {
        canary_interval: Duration::from_millis(5),
        canary_attempts: 4,
        recheck_interval: Duration::from_secs(3600),
        restart_min: Duration::from_millis(5),
        restart_max: Duration::from_millis(20),
    };

    /// How long a test waits for a thread to do something before failing.
    const PATIENCE: Duration = Duration::from_secs(10);

    fn session(n: u128) -> SessionId {
        SessionId::from_ulid(Ulid::from_u128(n))
    }

    fn record(n: u128) -> RecordId {
        RecordId::from_ulid(Ulid::from_u128(1_000 + n))
    }

    /// A denial entry as the kernel logs it, tagged for record `n` of session `s` (or the envelope).
    fn denial_entry(s: u128, command: TaggedCommand, pid: u32, path: &str) -> Vec<u8> {
        let command = match command {
            TaggedCommand::Envelope => String::from("env"),
            TaggedCommand::Line(record_id) => record_id.to_string(),
        };
        kernel_entry(&format!(
            "Sandbox: cat({pid}) deny(1) file-read-data {path}\nknsh:{}:{command}:fs.deny[0]",
            session(s)
        ))
    }

    /// Keeps every violation it is given.
    #[derive(Default)]
    struct Collecting {
        seen: Mutex<Vec<SandboxViolation>>,
    }

    impl ViolationSink for Collecting {
        fn report(&self, violation: SandboxViolation) {
            lock(&self.seen).push(violation);
        }
    }

    impl Collecting {
        fn seen(&self) -> Vec<SandboxViolation> {
            lock(&self.seen).clone()
        }
    }

    struct Running {
        reader: Reader,
        source: Arc<ScriptedDenialLog>,
        sink: Arc<Collecting>,
        clock: Arc<FakeClock>,
        log: Arc<RecordingLog>,
    }

    fn run(source: ScriptedDenialLog) -> Running {
        let source = Arc::new(source);
        let sink = Arc::new(Collecting::default());
        let clock = Arc::new(FakeClock::new(
            Timestamp::from_unix_micros(1_800_000_000_000_000).unwrap(),
        ));
        let log = Arc::new(RecordingLog::new());
        let effects = Effects {
            source: source.clone(),
            clock: clock.clone(),
            random: Arc::new(SeededRandom::new(5)),
            log: log.clone(),
        };
        let reader = Reader::start(effects, sink.clone(), FAST).unwrap();
        Running {
            reader,
            source,
            sink,
            clock,
            log,
        }
    }

    /// Waits until `condition` holds, failing the test after [`PATIENCE`].
    fn eventually(what: &str, condition: impl Fn() -> bool) {
        let start = Instant::now();
        while !condition() {
            assert!(start.elapsed() < PATIENCE, "timed out waiting for {what}");
            thread::sleep(Duration::from_millis(2));
        }
    }

    fn logged(log: &RecordingLog, message: &str) -> bool {
        log.entries().iter().any(|entry| entry.message == message)
    }

    // KNSH-047, decision 9: the reader is live only once its own canary came back through the stream.
    #[test]
    fn live_once_the_canary_comes_back() {
        let mut running = run(ScriptedDenialLog::new());
        let status = running.reader.status();
        eventually("the canary", || status.current() == SandboxViolations::UnifiedLog);
        running.reader.stop();
        assert_eq!(status.current(), SandboxViolations::None);
        assert!(!running.source.is_open(), "stopping ends the stream");
    }

    // KNSH-047: a stream that never delivers the canary is reported as `none`, with a reason in the log.
    #[test]
    fn unconfirmed_stream_is_reported_as_none() {
        let source = ScriptedDenialLog::new();
        source.echo_canaries(false);
        let mut running = run(source);
        eventually("the canaries to run out", || {
            logged(&running.log, "sandbox violation reader not confirmed")
        });
        assert_eq!(
            running.source.canaries(),
            usize::try_from(FAST.canary_attempts).unwrap()
        );
        assert_eq!(running.reader.status().current(), SandboxViolations::None);
        running.reader.stop();
    }

    // KNSH-047: reader failure is reported (status `none`, system log) and the reader recovers by reopening.
    #[test]
    fn failed_or_ended_stream_is_reported_and_reopened() {
        let source = ScriptedDenialLog::new();
        source.fail_opens(2);
        let mut running = run(source);
        let status = running.reader.status();
        eventually("a stream after two failed opens", || {
            status.current() == SandboxViolations::UnifiedLog
        });
        assert!(running.source.opens() >= 3);
        assert!(logged(&running.log, "sandbox violation reader unavailable"));

        running.source.end_stream();
        eventually("the stopped stream to be noticed", || {
            logged(&running.log, "sandbox violation reader stopped")
        });
        eventually("the stream to be reopened and confirmed", || {
            running.source.opens() >= 4 && status.current() == SandboxViolations::UnifiedLog
        });
        running.reader.stop();
    }

    // KNSH-047: tagged denials reach the sink merged; untagged and spike-tagged entries never do.
    #[test]
    fn merges_repeats_and_ignores_untagged_entries() {
        let running = run(ScriptedDenialLog::new());
        let line = TaggedCommand::Line(record(1));
        running.source.push(b"Filtering the log data using ...".to_vec());
        running.source.push(kernel_entry(
            "Sandbox: cat(1) deny(1) file-read-data /x\nknsh:c8:canary",
        ));
        running
            .source
            .push(kernel_entry("Sandbox: launchctl(2) deny(1) job-creation"));
        running.source.push(denial_entry(1, line, 7, "/private/etc/hosts"));
        running.source.push(denial_entry(1, line, 7, "/private/etc/hosts"));
        running.source.push(kernel_entry(&format!(
            "8 duplicate reports for Sandbox: cat(7) deny(1) file-read-data /private/etc/hosts\nknsh:{}:{}:fs.deny[0]",
            session(1),
            record(1)
        )));
        running
            .source
            .push(denial_entry(1, TaggedCommand::Envelope, 9, "/private/etc/passwd"));
        // Held for the merge window on the fake clock, then released once it has passed.
        thread::sleep(Duration::from_millis(50));
        assert!(running.sink.seen().is_empty(), "released before its window passed");
        running.clock.advance(knsh_core::MERGE_WINDOW);
        eventually("two merged violations", || running.sink.seen().len() == 2);
        let seen = running.sink.seen();
        assert_eq!(seen[0].report.tag.command, line);
        assert_eq!(seen[0].report.count, 10);
        assert_eq!(seen[1].report.tag.command, TaggedCommand::Envelope);
        assert_eq!(seen[1].report.count, 1);
    }

    // KNSH-047: stopping releases what is still pending instead of losing it.
    #[test]
    fn stopping_releases_pending_violations() {
        let mut running = run(ScriptedDenialLog::new());
        running
            .source
            .push(denial_entry(1, TaggedCommand::Line(record(1)), 7, "/x"));
        thread::sleep(Duration::from_millis(50));
        running.reader.stop();
        assert_eq!(running.sink.seen().len(), 1);
    }

    #[cfg(target_os = "macos")]
    mod records {
        use knsh_core::{ExecutionRecord, Redacted};
        use knsh_platform::macos::{RealFs, effective_uid};
        use knsh_store::{RecordQuery, RecordStore, RecordedOutput, Scope, StoreConfig};

        use super::*;
        use crate::events::tests::{agent, hub, start};

        struct TempDir(std::path::PathBuf);

        impl TempDir {
            fn new() -> Self {
                use std::sync::atomic::{AtomicU64, Ordering};
                static COUNTER: AtomicU64 = AtomicU64::new(0);
                let n = COUNTER.fetch_add(1, Ordering::Relaxed);
                let path = std::env::temp_dir().join(format!("knshd-violations-{}-{n}", std::process::id()));
                std::fs::create_dir(&path).unwrap();
                Self(path)
            }
        }

        impl Drop for TempDir {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }

        struct Fixture {
            _dir: TempDir,
            store: RecordStore,
            hub: Arc<crate::events::EventHub>,
            sink: Arc<RecordViolations>,
        }

        fn fixture() -> Fixture {
            let dir = TempDir::new();
            let clock = Arc::new(FakeClock::new(
                Timestamp::from_unix_micros(1_800_000_000_000_000).unwrap(),
            ));
            let store = RecordStore::open(
                &RealFs::new(),
                &dir.0.join("records.db"),
                effective_uid(),
                clock,
                StoreConfig::default(),
            )
            .unwrap();
            let hub = hub();
            let sink = RecordViolations::new(Some(store.clone()), Arc::clone(&hub), Arc::new(RecordingLog::new()));
            Fixture {
                _dir: dir,
                store,
                hub,
                sink,
            }
        }

        fn write_record(store: &RecordStore, s: u128, n: u128) {
            let at = Timestamp::from_unix_micros(1_800_000_000_000_000).unwrap();
            store
                .write_record(
                    ExecutionRecord {
                        record_id: record(n),
                        session_id: session(s),
                        actor: agent(),
                        command: Redacted::new(String::from("cat x")),
                        cwd: knsh_core::CanonicalPath::new("/tmp").unwrap(),
                        started_at: at,
                        ended_at: Some(at),
                        exit_code: Some(1),
                        details: knsh_core::RecordDetails::default(),
                    },
                    RecordedOutput::default(),
                )
                .unwrap();
        }

        fn violation(s: u128, command: TaggedCommand, pid: u32) -> SandboxViolation {
            let LogEntry::Denial(report) =
                knsh_platform::violation::parse_entry(&denial_entry(s, command, pid, "/x")).unwrap()
            else {
                panic!("not a denial");
            };
            SandboxViolation {
                at: Timestamp::from_unix_micros(1_800_000_000_000_000).unwrap(),
                report,
            }
        }

        fn stored(store: &RecordStore, n: u128) -> Vec<SandboxViolation> {
            store
                .query(Scope::All, RecordQuery::default())
                .unwrap()
                .records
                .into_iter()
                .find(|stored| stored.record.record_id == record(n))
                .map(|stored| stored.record.details.sandbox_violations)
                .unwrap()
        }

        // KNSH-047 attaches_late_denial_to_finished_record (FR-SBX-08): a denial that arrives after the line's
        // record was written is appended to that record, and published for its live session.
        #[test]
        fn attaches_late_denial_to_finished_record() {
            let fixture = fixture();
            start(&fixture.hub, 1);
            write_record(&fixture.store, 1, 1);
            fixture.sink.report(violation(1, TaggedCommand::Line(record(1)), 7));
            let kept = stored(&fixture.store, 1);
            assert_eq!(kept.len(), 1);
            assert_eq!(kept[0].report.pid, 7);
            // `session.started` was 1, the violation 2.
            assert_eq!(
                fixture
                    .hub
                    .publish(session(1), &agent(), EventData::SessionIdle)
                    .unwrap(),
                3
            );
        }

        // FR-SBX-08: while a line runs its violations are held, then written with its record.
        #[test]
        fn holds_violations_of_a_running_line_until_it_is_recorded() {
            let fixture = fixture();
            fixture.sink.line_started(session(1), record(2));
            fixture.sink.report(violation(1, TaggedCommand::Line(record(2)), 7));
            fixture.sink.report(violation(1, TaggedCommand::Line(record(2)), 7));
            // A tag naming the record but another session is not attached.
            fixture.sink.report(violation(9, TaggedCommand::Line(record(2)), 8));
            write_record(&fixture.store, 1, 2);
            assert!(stored(&fixture.store, 2).is_empty(), "held, not yet written");
            fixture.sink.line_recorded(session(1), record(2));
            let kept = stored(&fixture.store, 2);
            assert_eq!(kept.len(), 1);
            assert_eq!(kept[0].report.count, 2);
            // From now on, late ones are appended directly.
            fixture.sink.report(violation(1, TaggedCommand::Line(record(2)), 7));
            assert_eq!(stored(&fixture.store, 2)[0].report.count, 3);
        }

        // KNSH-047: never mis-attributed: an envelope denial has no record, and a tag naming another session's
        // record attaches nothing. Neither session is live here, so no event is published either.
        #[test]
        fn attaches_nothing_the_tag_does_not_name() {
            let fixture = fixture();
            write_record(&fixture.store, 1, 3);
            fixture.sink.report(violation(1, TaggedCommand::Envelope, 7));
            fixture.sink.report(violation(2, TaggedCommand::Line(record(3)), 7));
            assert!(stored(&fixture.store, 3).is_empty());
        }
    }
}
