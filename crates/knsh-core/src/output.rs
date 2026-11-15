//! Output capture and output modes (KNSH-053, `specs/03-functional-requirements/output-modes.md`, FR-REC-06,
//! FR-OUT-01, FR-OUT-05).
//!
//! Three pure building blocks, used by the supervisor in `knshd`:
//!
//! - [`OutputRedaction`]: the hook every captured chunk passes through before it is stored, emitted or returned
//!   (FR-EVT-07, FR-OUT-06). Phase 2 has no secret redaction yet ([`NoOutputRedaction`]); KNSH-091 adds it behind
//!   the same hook.
//! - [`OutputCapture`]: a streaming accumulator that keeps at most a cap of one stream, the head and the tail, and
//!   counts what it dropped and how many lines the stream had. A command can write gigabytes; memory stays at the
//!   cap.
//! - [`shape`]: what an `exec.run` caller gets back in each [`OutputMode`]. It only selects bytes; the engine never
//!   rewrites or summarises output (FR-OUT-05).

use std::collections::VecDeque;

use crate::{OutputInfo, OutputMode, Redacted};

/// The cap per stream: 1 MB, then head and tail (`specs/09-reference/defaults-and-limits.md`, FR-REC-06).
pub const DEFAULT_OUTPUT_CAP: usize = 1 << 20;

/// `truncate` without `max_bytes`: the first 64 KiB of each stream.
pub const DEFAULT_TRUNCATE_BYTES: usize = 64 * 1024;

/// The largest `max_bytes` a caller may ask for: the cap.
pub const MAX_TRUNCATE_BYTES: usize = DEFAULT_OUTPUT_CAP;

/// `head_tail` without `lines`: the first and last 20 lines of each stream.
pub const DEFAULT_HEAD_TAIL_LINES: usize = 20;

/// The largest `lines` a caller may ask for.
pub const MAX_HEAD_TAIL_LINES: usize = 10_000;

/// `errors_only`: the last 20 lines of stdout.
pub const ERRORS_ONLY_STDOUT_LINES: usize = 20;

/// The hook every output chunk passes through before it is stored, emitted or returned (FR-EVT-07, FR-OUT-06).
///
/// It sees each chunk once, in order, per stream. Chunks are cut where the pipe's reads happen to end, so a secret
/// split across two chunks is not seen whole; KNSH-091 must account for that when it adds real redaction.
pub trait OutputRedaction: Send + Sync {
    /// `chunk` as it may leave the engine.
    fn redact_chunk(&self, chunk: &[u8]) -> Redacted<Vec<u8>>;
}

/// Phase 2's redaction: none (secret redaction is KNSH-091). The hook point exists so the capture path never
/// changes when it arrives.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoOutputRedaction;

impl OutputRedaction for NoOutputRedaction {
    fn redact_chunk(&self, chunk: &[u8]) -> Redacted<Vec<u8>> {
        Redacted::new(chunk.to_vec())
    }
}

/// One stream as kept: at most a cap of bytes, the head and the tail of what the command wrote, and where the
/// dropped bytes were.
///
/// Invariants (those of [`OutputInfo`]): `info.stored` is the length of `data`, `stored + skipped == original`,
/// `skipped_at <= stored`, and `skipped == 0` implies `skipped_at == stored`.
#[derive(Debug, Clone, Default)]
pub struct CappedOutput {
    data: Redacted<Vec<u8>>,
    info: OutputInfo,
}

impl CappedOutput {
    /// All of `data`, nothing dropped.
    #[must_use]
    pub fn whole(data: Redacted<Vec<u8>>) -> Self {
        let size = len_u64(data.expose().len());
        Self {
            data,
            info: OutputInfo {
                stored: size,
                original: size,
                skipped: 0,
                skipped_at: size,
            },
        }
    }

    /// The kept bytes: the head, then the tail.
    #[must_use]
    pub const fn data(&self) -> &Redacted<Vec<u8>> {
        &self.data
    }

    /// Sizes and where the dropped bytes were.
    #[must_use]
    pub const fn info(&self) -> OutputInfo {
        self.info
    }

    /// The kept bytes and their description.
    #[must_use]
    pub fn into_parts(self) -> (Redacted<Vec<u8>>, OutputInfo) {
        (self.data, self.info)
    }

    /// The same stream kept within `cap` bytes: unchanged if it already fits; otherwise the first `cap / 2` and the
    /// last `cap - cap / 2` bytes of what is kept, never reaching across an earlier gap, so every kept byte is still
    /// at its place in the original stream.
    #[must_use]
    pub fn recap(self, cap: usize) -> Self {
        let data = self.data.expose();
        if data.len() <= cap {
            return self;
        }
        let mut head_end = cap / 2;
        let mut tail_start = data.len() - (cap - cap / 2);
        if self.has_gap() {
            // The new head ends before the earlier gap and the new tail starts after it.
            let gap = self.gap_index();
            head_end = head_end.min(gap);
            tail_start = tail_start.max(gap);
        }
        let mut kept = Vec::with_capacity(cap);
        kept.extend_from_slice(data.get(..head_end).unwrap_or_default());
        kept.extend_from_slice(data.get(tail_start..).unwrap_or_default());
        let stored = len_u64(kept.len());
        Self {
            data: Redacted::new(kept),
            info: OutputInfo {
                stored,
                original: self.info.original,
                skipped: self.info.original - stored,
                skipped_at: len_u64(head_end),
            },
        }
    }

    /// Where the gap sits in `data`: `skipped_at`, clamped to `data`'s length so a malformed [`OutputInfo`] can
    /// never index past the kept bytes.
    fn gap_index(&self) -> usize {
        let len = self.data.expose().len();
        usize::try_from(self.info.skipped_at).unwrap_or(len).min(len)
    }

    /// The bytes before the gap: the whole stream when nothing was dropped, otherwise its head.
    fn before_gap(&self) -> &[u8] {
        self.data.expose().get(..self.gap_index()).unwrap_or_default()
    }

    /// The bytes after the gap: empty when nothing was dropped, otherwise the tail.
    fn after_gap(&self) -> &[u8] {
        self.data.expose().get(self.gap_index()..).unwrap_or_default()
    }

    /// Whether bytes were dropped between head and tail.
    const fn has_gap(&self) -> bool {
        self.info.skipped > 0
    }
}

/// One stream once its command ended: what is kept of it and how many lines it had.
#[derive(Debug, Clone, Default)]
pub struct CapturedStream {
    /// The kept bytes and their description.
    pub output: CappedOutput,
    /// The lines the command wrote: newlines, plus one for a last line without one.
    pub lines: u64,
}

/// A streaming accumulator for one stream (module documentation): head and tail within a cap, totals counted.
#[derive(Debug, Clone)]
pub struct OutputCapture {
    head_cap: usize,
    tail_cap: usize,
    head: Vec<u8>,
    tail: VecDeque<u8>,
    written: u64,
    newlines: u64,
    ends_with_newline: bool,
}

impl OutputCapture {
    /// An empty capture keeping at most `cap` bytes: `cap / 2` of head and the rest of tail, the split of
    /// [`CappedOutput::recap`].
    #[must_use]
    pub fn new(cap: usize) -> Self {
        let head_cap = cap / 2;
        Self {
            head_cap,
            tail_cap: cap - head_cap,
            head: Vec::new(),
            tail: VecDeque::new(),
            written: 0,
            newlines: 0,
            ends_with_newline: false,
        }
    }

    /// Bytes pushed so far: the offset the next chunk starts at.
    #[must_use]
    pub const fn written(&self) -> u64 {
        self.written
    }

    /// Appends `chunk`.
    pub fn push(&mut self, chunk: &[u8]) {
        let Some(&last) = chunk.last() else {
            return;
        };
        self.written = self.written.saturating_add(len_u64(chunk.len()));
        // No third-party crates (supply-chain policy): a plain count, which the compiler vectorises well enough.
        #[allow(clippy::naive_bytecount)]
        let newlines = chunk.iter().filter(|&&byte| byte == b'\n').count();
        self.newlines = self.newlines.saturating_add(len_u64(newlines));
        self.ends_with_newline = last == b'\n';
        let room = self.head_cap.saturating_sub(self.head.len()).min(chunk.len());
        let (to_head, rest) = chunk.split_at(room);
        self.head.extend_from_slice(to_head);
        if rest.len() >= self.tail_cap {
            self.tail.clear();
            self.tail.extend(&rest[rest.len() - self.tail_cap..]);
        } else {
            // The ring keeps the last `tail_cap` bytes: drop just enough of the oldest to make room.
            let over = (self.tail.len() + rest.len()).saturating_sub(self.tail_cap);
            self.tail.drain(..over);
            self.tail.extend(rest);
        }
    }

    /// The stream as kept.
    #[must_use]
    pub fn finish(self) -> CapturedStream {
        let head_len = self.head.len();
        let mut data = self.head;
        data.extend(self.tail);
        let stored = len_u64(data.len());
        let skipped = self.written - stored;
        let lines = self.newlines + u64::from(self.written > 0 && !self.ends_with_newline);
        CapturedStream {
            output: CappedOutput {
                data: Redacted::new(data),
                info: OutputInfo {
                    stored,
                    original: self.written,
                    skipped,
                    // Without a gap the head and the tail are one contiguous run.
                    skipped_at: if skipped > 0 { len_u64(head_len) } else { stored },
                },
            },
            lines,
        }
    }
}

/// What a caller asked for (`output` of `exec.run`), with the defaults applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutputRequest {
    /// The mode.
    pub mode: OutputMode,
    /// `truncate`: bytes from the start of each stream, 1 to [`MAX_TRUNCATE_BYTES`].
    pub max_bytes: usize,
    /// `head_tail`: lines from each end of each stream, 1 to [`MAX_HEAD_TAIL_LINES`].
    pub lines: usize,
}

impl OutputRequest {
    /// `mode` with the default `max_bytes` and `lines`.
    #[must_use]
    pub const fn new(mode: OutputMode) -> Self {
        Self {
            mode,
            max_bytes: DEFAULT_TRUNCATE_BYTES,
            lines: DEFAULT_HEAD_TAIL_LINES,
        }
    }
}

/// A run of one stream's bytes, and how many bytes of the stream it leaves out.
#[derive(Debug, Clone, Default)]
pub struct Excerpt {
    /// The bytes, already redacted.
    pub bytes: Redacted<Vec<u8>>,
    /// Bytes of the stream not in `bytes`.
    pub skipped: u64,
}

/// The first and last lines of one stream.
#[derive(Debug, Clone, Default)]
pub struct HeadTail {
    /// The first lines, each with its newline.
    pub head: Redacted<Vec<u8>>,
    /// The last lines.
    pub tail: Redacted<Vec<u8>>,
    /// Lines in neither.
    pub skipped_lines: u64,
}

/// The output an `exec.run` caller gets back (`specs/03-functional-requirements/output-modes.md`). Sizes and line
/// counts of both streams are returned in every mode beside it.
#[derive(Debug, Clone)]
pub enum ShapedOutput {
    /// Each stream as kept: everything up to the cap.
    Full {
        /// Standard output.
        stdout: Excerpt,
        /// Standard error.
        stderr: Excerpt,
    },
    /// The first `max_bytes` of each stream.
    Truncate {
        /// Standard output.
        stdout: Excerpt,
        /// Standard error.
        stderr: Excerpt,
    },
    /// The first and last `lines` lines of each stream.
    HeadTail {
        /// Standard output.
        stdout: HeadTail,
        /// Standard error.
        stderr: HeadTail,
    },
    /// stderr as kept, and the last [`ERRORS_ONLY_STDOUT_LINES`] lines of stdout.
    ErrorsOnly {
        /// Standard error.
        stderr: Excerpt,
        /// The last lines of standard output.
        stdout_tail: Redacted<Vec<u8>>,
        /// Lines of standard output not in `stdout_tail`.
        stdout_skipped_lines: u64,
    },
    /// No output: sizes and line counts only; the caller reads ranges with `records.output`.
    Ref,
}

/// The output `request` selects from the two captured streams. Pure selection: bytes are returned as they were
/// captured (and redacted), never rewritten (FR-OUT-05).
#[must_use]
pub fn shape(request: OutputRequest, stdout: &CapturedStream, stderr: &CapturedStream) -> ShapedOutput {
    match request.mode {
        OutputMode::Full => ShapedOutput::Full {
            stdout: whole(stdout),
            stderr: whole(stderr),
        },
        OutputMode::Truncate => ShapedOutput::Truncate {
            stdout: first_bytes(stdout, request.max_bytes),
            stderr: first_bytes(stderr, request.max_bytes),
        },
        OutputMode::HeadTail => ShapedOutput::HeadTail {
            stdout: head_tail(stdout, request.lines),
            stderr: head_tail(stderr, request.lines),
        },
        OutputMode::ErrorsOnly => {
            let tail = last_lines(&stdout.output, ERRORS_ONLY_STDOUT_LINES);
            ShapedOutput::ErrorsOnly {
                stderr: whole(stderr),
                stdout_skipped_lines: stdout.lines.saturating_sub(tail.lines),
                stdout_tail: Redacted::new(tail.bytes.to_vec()),
            }
        }
        OutputMode::Ref => ShapedOutput::Ref,
    }
}

/// Everything kept of `stream`.
fn whole(stream: &CapturedStream) -> Excerpt {
    let info = stream.output.info();
    Excerpt {
        bytes: stream.output.data().clone(),
        skipped: info.skipped,
    }
}

/// The first `max_bytes` of `stream`, never reaching past a gap: the stream is contiguous only up to it.
fn first_bytes(stream: &CapturedStream, max_bytes: usize) -> Excerpt {
    let prefix = stream.output.before_gap();
    let taken = prefix.get(..max_bytes.min(prefix.len())).unwrap_or_default();
    Excerpt {
        skipped: stream.output.info().original - len_u64(taken.len()),
        bytes: Redacted::new(taken.to_vec()),
    }
}

/// The first and last `lines` lines of `stream`. Without a gap, a stream of at most `2 * lines` lines is returned
/// whole in `head`. With one, lines come from the head before it and the tail after it; a line cut by the gap
/// counts on each side it shows on, so the skipped count never goes below zero but may undercount by one.
fn head_tail(stream: &CapturedStream, lines: usize) -> HeadTail {
    let output = &stream.output;
    if !output.has_gap() && stream.lines <= len_u64(lines).saturating_mul(2) {
        return HeadTail {
            head: output.data().clone(),
            tail: Redacted::default(),
            skipped_lines: 0,
        };
    }
    let first = first_lines(output.before_gap(), lines);
    let tail_source = if output.has_gap() {
        output.after_gap()
    } else {
        // No gap: the tail starts after the head's lines, so no line is returned twice.
        output.before_gap().get(first.bytes.len()..).unwrap_or_default()
    };
    let last = last_lines_of(tail_source, lines);
    HeadTail {
        head: Redacted::new(first.bytes.to_vec()),
        tail: Redacted::new(last.bytes.to_vec()),
        skipped_lines: stream.lines.saturating_sub(first.lines + last.lines),
    }
}

/// Some lines of a byte run and how many there are.
struct Lines<'a> {
    bytes: &'a [u8],
    lines: u64,
}

/// The first `count` lines of `bytes`, each with its newline; a last line without one counts too.
fn first_lines(bytes: &[u8], count: usize) -> Lines<'_> {
    let mut taken = 0;
    let mut end = 0;
    while taken < count && end < bytes.len() {
        end = bytes[end..]
            .iter()
            .position(|&byte| byte == b'\n')
            .map_or(bytes.len(), |at| end + at + 1);
        taken += 1;
    }
    Lines {
        bytes: &bytes[..end],
        lines: len_u64(taken),
    }
}

/// The last `count` lines of everything kept of `output` (the tail when there is a gap).
fn last_lines(output: &CappedOutput, count: usize) -> Lines<'_> {
    let source = if output.has_gap() {
        output.after_gap()
    } else {
        output.before_gap()
    };
    last_lines_of(source, count)
}

/// The last `count` lines of `bytes`; a last line without a newline counts as one.
fn last_lines_of(bytes: &[u8], count: usize) -> Lines<'_> {
    if count == 0 || bytes.is_empty() {
        return Lines { bytes: &[], lines: 0 };
    }
    // The final newline ends the last line rather than starting an empty one.
    let body = bytes.strip_suffix(b"\n").unwrap_or(bytes);
    // The `count`-th newline from the end of `body` ends the line just before the ones taken.
    let mut newlines = 0;
    for (at, &byte) in body.iter().enumerate().rev() {
        if byte == b'\n' {
            newlines += 1;
            if newlines == count {
                return Lines {
                    bytes: &bytes[at + 1..],
                    lines: len_u64(count),
                };
            }
        }
    }
    // Fewer lines than asked: all of them.
    Lines {
        bytes,
        lines: len_u64(newlines + 1),
    }
}

/// A byte length as `u64`. In-memory lengths always fit.
fn len_u64(len: usize) -> u64 {
    u64::try_from(len).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests;
