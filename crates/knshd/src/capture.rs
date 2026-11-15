//! Lifecycle step 10: reading a running line's stdout and stderr (KNSH-053, FR-LC-18, FR-REC-06, FR-EVT-07).
//!
//! When a line's output is captured, its stdout and stderr are pipes whose read ends `knshd` holds, one reader
//! thread per stream. Each chunk read is:
//!
//! 1. **Forwarded unchanged** to the caller's own descriptor first, when there is one (`knsh -c` in a session that
//!    records output: the capture tees, so what the caller sees does not change). If that write fails (the caller
//!    closed its end), the reader stops and closes the pipe, so the line gets `EPIPE`/`SIGPIPE` exactly as it would
//!    have writing to the caller directly.
//! 2. **Redacted** through the [`OutputRedaction`] hook. Everything after this sees only the redacted chunk.
//! 3. **Kept** in an [`OutputCapture`]: head and tail within the cap, with the stream's size and line count.
//! 4. **Published** as `command.output` through the [`OutputSink`], only when the session records output, and
//!    only while the stream is within the cap: a line writing gigabytes cannot flood the event bus.
//!
//! # Ending
//!
//! A pipe reaches end of file only when every process holding its write end has closed it, and a line may leave a
//! background process behind (`server &`). So once the line's leader has been reaped, [`LineCapture::finish`] waits
//! at most [`DRAIN_GRACE`] for the readers, then *seals* the captures: what was read is final, and a reader that is
//! still going keeps forwarding and draining (so the leftover process never blocks on a full pipe) but captures
//! and publishes nothing more. Nothing is published for the line after its record is written.
//!
//! # Lock order
//!
//! A stream's state, then the event hub (inside [`OutputSink::chunk`]). The state is held while a chunk is captured
//! and published, so a sealed capture never gains a chunk or publishes one afterwards. Nothing else takes a
//! stream's state while holding the hub.

use std::fs::File;
use std::io::{ErrorKind, PipeReader, Read, Write};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

use knsh_core::{CapturedStream, OutputCapture, OutputRedaction, OutputStream, Redacted};

/// The most bytes read (and so published in one `command.output`) at a time. Each chunk is buffered by the event
/// bus, so small chunks bound its memory: at most [`knsh_core::EVENT_BUFFER_LEN`] chunks per session.
pub(crate) const OUTPUT_CHUNK: usize = 8 * 1024;

/// How long the readers may still run once the line's leader has been reaped (module documentation, "Ending").
pub(crate) const DRAIN_GRACE: Duration = Duration::from_millis(250);

/// Where captured chunks go as `command.output` events (FR-LC-18). Best effort: publishing never fails a line.
pub(crate) trait OutputSink: Send + Sync {
    /// One redacted chunk of `stream`, starting at byte `offset` of the stream as captured.
    fn chunk(&self, stream: OutputStream, offset: u64, bytes: &Redacted<Vec<u8>>);
}

/// How a line's output is captured.
#[derive(Clone)]
pub(crate) struct CapturePlan {
    /// The hook every chunk passes through before it is kept or published (FR-EVT-07).
    pub(crate) redaction: Arc<dyn OutputRedaction>,
    /// Bytes kept per stream (FR-REC-06): the record store's cap, so the record holds exactly what was captured.
    pub(crate) cap: usize,
    /// Where `command.output` goes; `None` when the session does not record output.
    pub(crate) sink: Option<Arc<dyn OutputSink>>,
}

impl std::fmt::Debug for CapturePlan {
    /// The cap and whether chunks are published; the hook and sink are trait objects with nothing to show.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CapturePlan")
            .field("cap", &self.cap)
            .field("publishes", &self.sink.is_some())
            .finish_non_exhaustive()
    }
}

/// Both streams of a line once it ended.
#[derive(Debug, Clone, Default)]
pub(crate) struct LineOutput {
    /// Standard output.
    pub(crate) stdout: CapturedStream,
    /// Standard error.
    pub(crate) stderr: CapturedStream,
}

/// What one reader shares with the spawner.
struct StreamState {
    capture: OutputCapture,
    /// The capture is final: nothing more is kept or published.
    sealed: bool,
    /// The reader has finished: end of file, a read error, or a failed forward.
    done: bool,
}

struct Shared {
    state: Mutex<StreamState>,
    changed: Condvar,
}

/// Takes the lock even if a reader panicked while holding it: a capture is only ever appended to whole chunks.
fn lock(shared: &Shared) -> MutexGuard<'_, StreamState> {
    shared.state.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The two readers of one line.
pub(crate) struct LineCapture {
    stdout: Arc<Shared>,
    stderr: Arc<Shared>,
}

/// One stream's pipe read end and, when teeing, the caller's descriptor it is copied to.
pub(crate) struct Source {
    /// The pipe the line writes the stream to.
    pub(crate) pipe: PipeReader,
    /// The caller's own descriptor for the stream (`knsh -c`), written first and unchanged.
    pub(crate) forward: Option<File>,
}

impl LineCapture {
    /// Starts one reader thread per stream.
    ///
    /// # Errors
    ///
    /// A thread could not be started. Readers already started end by themselves once their pipe's write ends
    /// close, which happens when the caller drops them without spawning anything.
    pub(crate) fn start(stdout: Source, stderr: Source, plan: &CapturePlan) -> std::io::Result<Self> {
        Ok(Self {
            stdout: reader(OutputStream::Stdout, stdout, plan)?,
            stderr: reader(OutputStream::Stderr, stderr, plan)?,
        })
    }

    /// Waits at most `grace` for both readers to finish, then seals both captures and returns them (module
    /// documentation, "Ending").
    pub(crate) fn finish(self, grace: Duration) -> LineOutput {
        let deadline = Instant::now() + grace;
        LineOutput {
            stdout: seal(&self.stdout, deadline),
            stderr: seal(&self.stderr, deadline),
        }
    }
}

/// Waits until `shared`'s reader is done or `deadline` passes, then seals its capture and takes it.
fn seal(shared: &Shared, deadline: Instant) -> CapturedStream {
    let mut state = lock(shared);
    while !state.done {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            break;
        }
        state = shared
            .changed
            .wait_timeout(state, left)
            .unwrap_or_else(PoisonError::into_inner)
            .0;
    }
    state.sealed = true;
    std::mem::replace(&mut state.capture, OutputCapture::new(0)).finish()
}

/// Starts the reader of `stream`.
fn reader(stream: OutputStream, source: Source, plan: &CapturePlan) -> std::io::Result<Arc<Shared>> {
    let shared = Arc::new(Shared {
        state: Mutex::new(StreamState {
            capture: OutputCapture::new(plan.cap),
            sealed: false,
            done: false,
        }),
        changed: Condvar::new(),
    });
    let thread_shared = Arc::clone(&shared);
    let plan = plan.clone();
    thread::Builder::new().name(format!("knshd-{stream}")).spawn(move || {
        read_stream(stream, source, &plan, &thread_shared);
        lock(&thread_shared).done = true;
        thread_shared.changed.notify_all();
    })?;
    Ok(shared)
}

/// The reader loop: steps 1 to 4 of the module documentation for each chunk, until end of file.
fn read_stream(stream: OutputStream, source: Source, plan: &CapturePlan, shared: &Shared) {
    let Source { mut pipe, mut forward } = source;
    let cap = u64::try_from(plan.cap).unwrap_or(u64::MAX);
    let mut buffer = vec![0u8; OUTPUT_CHUNK];
    loop {
        let read = match pipe.read(&mut buffer) {
            Ok(0) => return,
            Ok(read) => read,
            Err(error) if error.kind() == ErrorKind::Interrupted => continue,
            // An unreadable pipe ends the capture; the line sees its end closed, as with a closed descriptor.
            Err(_) => return,
        };
        let raw = &buffer[..read];
        // Step 1: the caller sees exactly what the line wrote, before (and whatever) the capture keeps.
        if let Some(out) = forward.as_mut()
            && out.write_all(raw).is_err()
        {
            // Returning drops the pipe: the line's next write fails as it would have on the caller's descriptor.
            return;
        }
        let mut state = lock(shared);
        if state.sealed {
            // The record is written: keep draining (and forwarding) so a leftover process never blocks.
            continue;
        }
        let chunk = plan.redaction.redact_chunk(raw);
        let offset = state.capture.written();
        state.capture.push(chunk.expose());
        if let Some(sink) = &plan.sink
            && offset < cap
        {
            sink.chunk(stream, offset, &chunk);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use knsh_core::NoOutputRedaction;

    use super::*;

    /// Counts chunks and replaces every `s` with `*`, so redacted bytes can be told from raw ones.
    #[derive(Default)]
    struct Starring(AtomicUsize);

    impl OutputRedaction for Starring {
        fn redact_chunk(&self, chunk: &[u8]) -> Redacted<Vec<u8>> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Redacted::new(
                chunk
                    .iter()
                    .map(|&byte| if byte == b's' { b'*' } else { byte })
                    .collect(),
            )
        }
    }

    #[derive(Default)]
    struct Chunks(Mutex<Vec<(OutputStream, u64, Vec<u8>)>>);

    impl OutputSink for Chunks {
        fn chunk(&self, stream: OutputStream, offset: u64, bytes: &Redacted<Vec<u8>>) {
            self.0.lock().unwrap().push((stream, offset, bytes.expose().clone()));
        }
    }

    fn plan(redaction: Arc<dyn OutputRedaction>, sink: Option<Arc<dyn OutputSink>>, cap: usize) -> CapturePlan {
        CapturePlan { redaction, cap, sink }
    }

    // FR-EVT-07: every chunk passes the hook once, before it is kept or published; the caller's copy is raw.
    #[test]
    fn every_chunk_passes_redaction_hook() {
        let redaction = Arc::new(Starring::default());
        let sink = Arc::new(Chunks::default());
        let (out_read, mut out_write) = std::io::pipe().unwrap();
        let (err_read, err_write) = std::io::pipe().unwrap();
        let (mut tee_read, tee_write) = std::io::pipe().unwrap();
        let capture = LineCapture::start(
            Source {
                pipe: out_read,
                forward: Some(File::from(std::os::fd::OwnedFd::from(tee_write))),
            },
            Source {
                pipe: err_read,
                forward: None,
            },
            &plan(redaction.clone(), Some(sink.clone()), 1 << 20),
        )
        .unwrap();
        // The caller reads its end as the line writes, as a terminal or pipe reader would.
        let caller = thread::spawn(move || {
            let mut teed = Vec::new();
            tee_read.read_to_end(&mut teed).unwrap();
            teed
        });
        let written: Vec<u8> = b"secrets stay shown to the caller\n".repeat(2000);
        out_write.write_all(&written).unwrap();
        drop(out_write);
        drop(err_write);
        let output = capture.finish(Duration::from_secs(10));
        let teed = caller.join().unwrap();
        assert!(teed == written, "the caller sees the line's bytes unchanged");

        let starred: Vec<u8> = written.iter().map(|&b| if b == b's' { b'*' } else { b }).collect();
        assert!(output.stdout.output.data().expose() == &starred, "kept redacted");
        assert_eq!(output.stdout.lines, 2000);
        let chunks = sink.0.lock().unwrap().clone();
        assert!(chunks.len() > 1, "read in several chunks");
        assert_eq!(
            chunks.len(),
            redaction.0.load(Ordering::SeqCst),
            "one hook call per chunk"
        );
        // In order, contiguous, and each redacted.
        let mut offset = 0u64;
        let mut published = Vec::new();
        for (stream, at, bytes) in chunks {
            assert_eq!(stream, OutputStream::Stdout);
            assert_eq!(at, offset);
            assert!(bytes.len() <= OUTPUT_CHUNK);
            offset += bytes.len() as u64;
            published.extend(bytes);
        }
        assert!(published == starred, "published redacted");
    }

    // FR-LC-18: chunks are published only through a sink (none when output is not recorded), and only within the
    // cap, while the capture still counts everything.
    #[test]
    fn publishes_only_within_the_cap() {
        let sink = Arc::new(Chunks::default());
        let (out_read, mut out_write) = std::io::pipe().unwrap();
        let (err_read, err_write) = std::io::pipe().unwrap();
        let capture = LineCapture::start(
            Source {
                pipe: out_read,
                forward: None,
            },
            Source {
                pipe: err_read,
                forward: None,
            },
            &plan(Arc::new(NoOutputRedaction), Some(sink.clone()), 64),
        )
        .unwrap();
        out_write.write_all(&[b'x'; 10_000]).unwrap();
        drop(out_write);
        drop(err_write);
        let output = capture.finish(Duration::from_secs(10));
        assert_eq!(output.stdout.output.info().original, 10_000);
        assert_eq!(output.stdout.output.info().stored, 64);
        let published: u64 = sink
            .0
            .lock()
            .unwrap()
            .iter()
            .map(|(_, _, bytes)| bytes.len() as u64)
            .sum();
        assert!(published >= 64 && published < 64 + OUTPUT_CHUNK as u64, "{published}");
    }

    // A leftover process still holding the pipe cannot hold the line's answer: the capture is sealed after the
    // grace, and later bytes are drained but neither kept nor published.
    #[test]
    fn seals_after_grace_when_a_writer_lingers() {
        let sink = Arc::new(Chunks::default());
        let (out_read, mut out_write) = std::io::pipe().unwrap();
        let (err_read, err_write) = std::io::pipe().unwrap();
        let capture = LineCapture::start(
            Source {
                pipe: out_read,
                forward: None,
            },
            Source {
                pipe: err_read,
                forward: None,
            },
            &plan(Arc::new(NoOutputRedaction), Some(sink.clone()), 1024),
        )
        .unwrap();
        out_write.write_all(b"before\n").unwrap();
        drop(err_write);
        // Let the reader take the first chunk before sealing.
        let deadline = Instant::now() + Duration::from_secs(10);
        while sink.0.lock().unwrap().is_empty() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(1));
        }
        let started = Instant::now();
        let output = capture.finish(Duration::from_millis(50));
        assert!(started.elapsed() < Duration::from_secs(5));
        assert_eq!(output.stdout.output.data().expose(), b"before\n");
        out_write.write_all(b"after\n").unwrap();
        drop(out_write);
        thread::sleep(Duration::from_millis(20));
        assert_eq!(sink.0.lock().unwrap().len(), 1, "nothing published after sealing");
    }
}
