//! A sandbox denial log whose entries the test writes (KNSH-047).

use std::collections::VecDeque;
use std::sync::{Arc, Condvar, Mutex, PoisonError};

use knsh_json::{Object, Value};

use super::lock;
use crate::error::{Operation, PlatformError};
use crate::violation::{CanaryNonce, DenialLog, DenialStream, StreamStopper};

/// A [`DenialLog`] fed by the test.
///
/// Entries pushed with [`ScriptedDenialLog::push`] reach the stream that is open, or the next one to open. A
/// canary is echoed back as a kernel entry when [`ScriptedDenialLog::echo_canaries`] is on (the default), as the
/// real log does once attached. Opens can be made to fail, and the open stream can be ended, to test restarts.
#[derive(Debug, Default)]
pub struct ScriptedDenialLog {
    state: Mutex<State>,
}

/// What the test has scripted and what the reader has done so far.
#[derive(Debug, Default)]
struct State {
    /// The stream open now, if any.
    current: Option<Arc<Channel>>,
    /// Entries pushed while no stream was open.
    waiting: VecDeque<Vec<u8>>,
    /// Opens still to fail.
    failing_opens: usize,
    /// Whether canaries are swallowed instead of coming back through the stream.
    silent: bool,
    /// How many opens were attempted.
    opens: usize,
    /// How many canaries were triggered.
    canaries: usize,
}

/// What one open stream reads from.
#[derive(Debug, Default)]
struct Channel {
    queue: Mutex<ChannelState>,
    changed: Condvar,
}

/// The lines of one stream not yet read, and whether it has ended.
#[derive(Debug, Default)]
struct ChannelState {
    lines: VecDeque<Vec<u8>>,
    ended: bool,
}

impl Channel {
    /// Queues one line and wakes the reader.
    fn push(&self, line: Vec<u8>) {
        lock(&self.queue).lines.push_back(line);
        self.changed.notify_all();
    }

    /// Ends the stream: the reader drains what is queued, then sees the end.
    fn end(&self) {
        lock(&self.queue).ended = true;
        self.changed.notify_all();
    }
}

impl ScriptedDenialLog {
    /// A log with no entries, whose opens succeed and whose canaries come back.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Delivers `line` (one raw entry) to the open stream, or to the next one opened.
    pub fn push(&self, line: impl Into<Vec<u8>>) {
        let mut state = lock(&self.state);
        match &state.current {
            Some(channel) => channel.push(line.into()),
            None => state.waiting.push_back(line.into()),
        }
    }

    /// Whether canaries come back through the stream. Off models a log that never delivers.
    pub fn echo_canaries(&self, echo: bool) {
        lock(&self.state).silent = !echo;
    }

    /// Makes the next `count` opens fail.
    pub fn fail_opens(&self, count: usize) {
        lock(&self.state).failing_opens = count;
    }

    /// Ends the open stream, as if `log stream` had exited.
    pub fn end_stream(&self) {
        if let Some(channel) = lock(&self.state).current.take() {
            channel.end();
        }
    }

    /// How many times a stream was opened (successfully or not).
    #[must_use]
    pub fn opens(&self) -> usize {
        lock(&self.state).opens
    }

    /// How many canaries were triggered.
    #[must_use]
    pub fn canaries(&self) -> usize {
        lock(&self.state).canaries
    }

    /// Whether a stream is open now: opened, and neither ended by the test nor stopped.
    #[must_use]
    pub fn is_open(&self) -> bool {
        lock(&self.state)
            .current
            .as_ref()
            .is_some_and(|channel| !lock(&channel.queue).ended)
    }
}

impl DenialLog for ScriptedDenialLog {
    fn open(&self) -> Result<Box<dyn DenialStream>, PlatformError> {
        let mut state = lock(&self.state);
        state.opens += 1;
        if state.failing_opens > 0 {
            state.failing_opens -= 1;
            return Err(PlatformError::Os {
                operation: Operation::SandboxLog,
                errno: libc::ENOENT,
            });
        }
        let channel = Arc::new(Channel::default());
        for line in state.waiting.drain(..) {
            channel.push(line);
        }
        if let Some(previous) = state.current.replace(Arc::clone(&channel)) {
            previous.end();
        }
        Ok(Box::new(ScriptedStream { channel }))
    }

    fn trigger_canary(&self, nonce: &CanaryNonce) -> Result<(), PlatformError> {
        let mut state = lock(&self.state);
        state.canaries += 1;
        if !state.silent
            && let Some(channel) = &state.current
        {
            let message = format!("Sandbox: cat(1) deny(1) file-read-data /canary\n{}", nonce.tag());
            channel.push(kernel_entry(&message));
        }
        Ok(())
    }
}

/// One stream of a [`ScriptedDenialLog`].
struct ScriptedStream {
    channel: Arc<Channel>,
}

impl DenialStream for ScriptedStream {
    fn next_entry(&mut self) -> Result<Option<Vec<u8>>, PlatformError> {
        let mut queue = lock(&self.channel.queue);
        loop {
            if let Some(line) = queue.lines.pop_front() {
                return Ok(Some(line));
            }
            if queue.ended {
                return Ok(None);
            }
            queue = self.channel.changed.wait(queue).unwrap_or_else(PoisonError::into_inner);
        }
    }

    fn stopper(&self) -> Box<dyn StreamStopper> {
        Box::new(ScriptedStopper {
            channel: Arc::clone(&self.channel),
        })
    }
}

/// Ends one [`ScriptedStream`].
struct ScriptedStopper {
    channel: Arc<Channel>,
}

impl StreamStopper for ScriptedStopper {
    fn stop(&self) {
        self.channel.end();
    }
}

/// One `log stream --style ndjson` line as the kernel writes it, carrying `message` as its `eventMessage`.
#[must_use]
pub fn kernel_entry(message: &str) -> Vec<u8> {
    let entry = Object::new()
        .with("processID", Value::int(0).unwrap_or(Value::Null))
        .and_then(|entry| entry.with("processImagePath", "/kernel"))
        .and_then(|entry| entry.with("eventMessage", message))
        .map(Value::Object)
        .and_then(|entry| knsh_json::write(&entry));
    entry.map(String::into_bytes).unwrap_or_default()
}
