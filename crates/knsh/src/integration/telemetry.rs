//! The telemetry line format between the hosted shell's hooks and `knsh` (KNSH-019, FR-SES-21).
//!
//! The hooks run inside the user's shell, so the format is chosen to be cheap to produce with zsh builtins alone
//! (no external process, no module beyond `zsh/system`): one line per event, fields separated by a tab.
//!
//! ```text
//! knsh1 TAB preexec TAB <cwd> TAB <command> LF     a command line is about to run
//! knsh1 TAB precmd  TAB <status> TAB <cwd> LF      the prompt is back; <status> is $? (0-255) of that line
//! ```
//!
//! `<cwd>` and `<command>` are raw bytes (not necessarily UTF-8) with five escapes, so that a field can never hold
//! a separator: `\\` for a backslash, `\n` line feed, `\t` tab, `\r` carriage return, `\0` NUL. Every other byte is
//! itself. `<status>` is decimal without leading zeros.
//!
//! Decoding is strict (CLAUDE.md "Untrusted input"): any other tag, kind, field count, escape or status is
//! rejected, and the line is dropped. A line torn by a partial non-blocking write runs into the next one and
//! is rejected too, since the hooks' separators never appear inside a field. Lines longer than
//! [`MAX_LINE_LEN`] are dropped without being buffered whole ([`LineReader`]).
//!
//! The hooks send no timestamps: `knsh` reads the pipe as lines arrive and stamps them on receipt (KNSH-021).

use std::fmt;
use std::io::{self, BufRead};

/// The first field of every line: the format and its version.
const TAG: &[u8] = b"knsh1";
/// The kind of a [`TelemetryLine::CommandStarted`] line (zsh `preexec`).
const PREEXEC: &[u8] = b"preexec";
/// The kind of a [`TelemetryLine::CommandFinished`] line (zsh `precmd`).
const PRECMD: &[u8] = b"precmd";
/// The field separator.
const SEPARATOR: u8 = b'\t';
/// The line terminator.
const TERMINATOR: u8 = b'\n';

/// The longest line accepted, terminator excluded: the frame payload limit, which no record can exceed anyway
/// (`specs/09-reference/defaults-and-limits.md`).
pub const MAX_LINE_LEN: usize = 1024 * 1024;

/// One event reported by the hosted shell's hooks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TelemetryLine {
    /// A command line typed at the prompt is about to run (`preexec`).
    CommandStarted {
        /// The working directory when it started (`$PWD`).
        cwd: Vec<u8>,
        /// The command line as typed.
        command: Vec<u8>,
    },
    /// The prompt is back after a command line (`precmd`, only after a `preexec`).
    CommandFinished {
        /// Its exit status (`$?`): 0 to 255, `128 + n` when signal `n` ended it.
        exit_code: u8,
        /// The working directory now, which differs from the start after `cd`.
        cwd: Vec<u8>,
    },
}

/// Why a telemetry line was rejected. The line is dropped; the session is never affected (FR-SES-22).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TelemetryError {
    /// The line is longer than [`MAX_LINE_LEN`].
    TooLong,
    /// The first field is not `knsh1`: another format, or a torn line.
    UnknownTag,
    /// The second field is neither `preexec` nor `precmd`.
    UnknownKind,
    /// The line does not have exactly four fields.
    FieldCount,
    /// A backslash is not followed by one of `\ n t r 0`, or a raw CR or NUL appears in a field.
    BadEscape,
    /// The status is not a decimal number from 0 to 255 without leading zeros.
    BadStatus,
}

impl fmt::Display for TelemetryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::TooLong => "telemetry line too long",
            Self::UnknownTag => "telemetry line has an unknown tag",
            Self::UnknownKind => "telemetry line has an unknown kind",
            Self::FieldCount => "telemetry line has the wrong number of fields",
            Self::BadEscape => "telemetry line has a malformed escape",
            Self::BadStatus => "telemetry line has a malformed exit status",
        })
    }
}

impl std::error::Error for TelemetryError {}

impl TelemetryLine {
    /// The line exactly as the hooks write it, terminator included.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let (kind, second, third) = match self {
            Self::CommandStarted { cwd, command } => (PREEXEC, escape(cwd), escape(command)),
            Self::CommandFinished { exit_code, cwd } => (PRECMD, exit_code.to_string().into_bytes(), escape(cwd)),
        };
        let mut line = Vec::with_capacity(TAG.len() + kind.len() + second.len() + third.len() + 4);
        for field in [TAG, kind, &second, &third] {
            if !line.is_empty() {
                line.push(SEPARATOR);
            }
            line.extend_from_slice(field);
        }
        line.push(TERMINATOR);
        line
    }

    /// Parses one line, without its terminator.
    ///
    /// # Errors
    ///
    /// A [`TelemetryError`] naming the first problem found; see the module docs for the format.
    pub fn decode(line: &[u8]) -> Result<Self, TelemetryError> {
        if line.len() > MAX_LINE_LEN {
            return Err(TelemetryError::TooLong);
        }
        let fields: Vec<&[u8]> = line.split(|byte| *byte == SEPARATOR).collect();
        let [tag, kind, second, third] = fields.as_slice() else {
            // Checked before the kind so that a torn line (more fields) is reported as such, but a wrong tag first.
            return Err(if fields.first() == Some(&TAG) {
                TelemetryError::FieldCount
            } else {
                TelemetryError::UnknownTag
            });
        };
        if *tag != TAG {
            return Err(TelemetryError::UnknownTag);
        }
        match *kind {
            PREEXEC => Ok(Self::CommandStarted {
                cwd: unescape(second)?,
                command: unescape(third)?,
            }),
            PRECMD => Ok(Self::CommandFinished {
                exit_code: parse_status(second)?,
                cwd: unescape(third)?,
            }),
            _ => Err(TelemetryError::UnknownKind),
        }
    }
}

/// `field` with the five escapes applied.
fn escape(field: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(field.len());
    for &byte in field {
        match byte {
            b'\\' => out.extend_from_slice(b"\\\\"),
            b'\n' => out.extend_from_slice(b"\\n"),
            b'\t' => out.extend_from_slice(b"\\t"),
            b'\r' => out.extend_from_slice(b"\\r"),
            0 => out.extend_from_slice(b"\\0"),
            other => out.push(other),
        }
    }
    out
}

/// Reverses [`escape`]. Raw CR and NUL are refused: the hooks always escape them, so they mean a corrupt line.
fn unescape(field: &[u8]) -> Result<Vec<u8>, TelemetryError> {
    let mut out = Vec::with_capacity(field.len());
    let mut bytes = field.iter();
    while let Some(&byte) = bytes.next() {
        out.push(match byte {
            b'\\' => match bytes.next() {
                Some(b'\\') => b'\\',
                Some(b'n') => b'\n',
                Some(b't') => b'\t',
                Some(b'r') => b'\r',
                Some(b'0') => 0,
                _ => return Err(TelemetryError::BadEscape),
            },
            b'\r' | 0 => return Err(TelemetryError::BadEscape),
            other => other,
        });
    }
    Ok(out)
}

/// Parses `$?` as zsh prints it: `0`, or 1 to 3 digits without a leading zero, at most 255.
fn parse_status(field: &[u8]) -> Result<u8, TelemetryError> {
    let well_formed = !field.is_empty()
        && field.len() <= 3
        && field.iter().all(u8::is_ascii_digit)
        && (field == b"0" || field[0] != b'0');
    if !well_formed {
        return Err(TelemetryError::BadStatus);
    }
    // Only ASCII digits remain, so the text is valid UTF-8; `parse` rejects anything above 255.
    std::str::from_utf8(field)
        .ok()
        .and_then(|text| text.parse::<u8>().ok())
        .ok_or(TelemetryError::BadStatus)
}

/// Splits a byte stream into lines without ever buffering more than [`MAX_LINE_LEN`] bytes of one line.
///
/// The hooks write into a pipe that anything holding the descriptor could also write to, so the stream is
/// untrusted: an over-long line is reported once as [`TelemetryError::TooLong`] and its remaining bytes are skipped
/// up to the next terminator. Bytes after the last terminator at end of stream are a torn line and are dropped.
#[derive(Debug)]
pub struct LineReader<R> {
    inner: R,
    line: Vec<u8>,
    /// Whether the current line already exceeded the limit and is being skipped.
    skipping: bool,
}

impl<R: BufRead> LineReader<R> {
    /// Reads lines from `inner`.
    pub fn new(inner: R) -> Self {
        Self {
            inner,
            line: Vec::new(),
            skipping: false,
        }
    }

    /// The next line, decoded; `Ok(None)` at end of stream.
    ///
    /// # Errors
    ///
    /// The outer error is a read failure (the stream is unusable); the inner one a rejected line, after which
    /// reading may continue.
    pub fn next_line(&mut self) -> io::Result<Option<Result<TelemetryLine, TelemetryError>>> {
        loop {
            let available = match self.inner.fill_buf() {
                Ok(available) => available,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            };
            if available.is_empty() {
                return Ok(None);
            }
            let (chunk, complete) = match available.iter().position(|byte| *byte == TERMINATOR) {
                Some(end) => (&available[..end], true),
                None => (available, false),
            };
            let consumed = chunk.len() + usize::from(complete);
            let mut over_limit = false;
            if !self.skipping {
                if self.line.len() + chunk.len() > MAX_LINE_LEN {
                    // Report once, then discard the rest of this line instead of growing the buffer.
                    over_limit = true;
                    self.line.clear();
                } else {
                    self.line.extend_from_slice(chunk);
                }
            }
            self.inner.consume(consumed);
            if over_limit {
                self.skipping = !complete;
                return Ok(Some(Err(TelemetryError::TooLong)));
            }
            if complete {
                if self.skipping {
                    // The tail of an over-long line already reported: resume with the next one.
                    self.skipping = false;
                } else {
                    let decoded = TelemetryLine::decode(&self.line);
                    self.line.clear();
                    return Ok(Some(decoded));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn started(cwd: &[u8], command: &[u8]) -> TelemetryLine {
        TelemetryLine::CommandStarted {
            cwd: cwd.to_vec(),
            command: command.to_vec(),
        }
    }

    fn count(bytes: &[u8], wanted: u8) -> usize {
        bytes.split(|byte| *byte == wanted).count() - 1
    }

    fn decode(line: &[u8]) -> Result<TelemetryLine, TelemetryError> {
        TelemetryLine::decode(line.strip_suffix(b"\n").unwrap_or(line))
    }

    // KNSH-019 unit test: the line format between hooks and knsh round-trips every byte, including separators,
    // escapes, non-UTF-8 bytes and empty fields.
    #[test]
    fn telemetry_line_encoding_round_trips() {
        let every_byte: Vec<u8> = (0..=255).collect();
        let lines = [
            started(b"/Users/u", b"ls -la"),
            started(b"", b""),
            started(b"/tmp/a\tb\nc", b"printf 'a\\tb\\n' \\\r\0 | cat"),
            started(&every_byte, &every_byte),
            TelemetryLine::CommandFinished {
                exit_code: 0,
                cwd: b"/".to_vec(),
            },
            TelemetryLine::CommandFinished {
                exit_code: 255,
                cwd: b"/caf\xc3\xa9/\xff".to_vec(),
            },
        ];
        for line in lines {
            let encoded = line.encode();
            assert_eq!(encoded.last(), Some(&b'\n'));
            assert_eq!(count(&encoded, b'\n'), 1, "{encoded:?}");
            assert_eq!(count(&encoded, b'\t'), 3, "{encoded:?}");
            assert_eq!(decode(&encoded), Ok(line));
        }
    }

    #[test]
    fn encoding_matches_the_documented_format() {
        assert_eq!(
            started(b"/a", b"echo \\ x").encode(),
            b"knsh1\tpreexec\t/a\techo \\\\ x\n"
        );
        let finished = TelemetryLine::CommandFinished {
            exit_code: 130,
            cwd: b"/b".to_vec(),
        };
        assert_eq!(finished.encode(), b"knsh1\tprecmd\t130\t/b\n");
    }

    #[test]
    fn malformed_lines_are_rejected() {
        let cases: &[(&[u8], TelemetryError)] = &[
            (b"knsh2\tpreexec\t/\tls", TelemetryError::UnknownTag),
            (b"", TelemetryError::UnknownTag),
            (b"knsh1\tpostexec\t/\tls", TelemetryError::UnknownKind),
            (b"knsh1\tpreexec\t/", TelemetryError::FieldCount),
            // Torn line: a partial write ran into the next line.
            (b"knsh1\tpreexec\t/\tlknsh1\tprecmd\t0\t/", TelemetryError::FieldCount),
            (b"knsh1\tpreexec\t/\tbad\\x", TelemetryError::BadEscape),
            (b"knsh1\tpreexec\t/\ttrailing\\", TelemetryError::BadEscape),
            (b"knsh1\tpreexec\t/\traw\rcr", TelemetryError::BadEscape),
            (b"knsh1\tpreexec\t/\traw\0nul", TelemetryError::BadEscape),
            (b"knsh1\tprecmd\t256\t/", TelemetryError::BadStatus),
            (b"knsh1\tprecmd\t007\t/", TelemetryError::BadStatus),
            (b"knsh1\tprecmd\t-1\t/", TelemetryError::BadStatus),
            (b"knsh1\tprecmd\t\t/", TelemetryError::BadStatus),
            (b"knsh1\tprecmd\t1000\t/", TelemetryError::BadStatus),
        ];
        for (line, expected) in cases {
            assert_eq!(TelemetryLine::decode(line), Err(*expected), "{line:?}");
        }
        let long = vec![b'x'; MAX_LINE_LEN + 1];
        assert_eq!(TelemetryLine::decode(&long), Err(TelemetryError::TooLong));
    }

    fn read_all(input: &[u8], capacity: usize) -> Vec<Result<TelemetryLine, TelemetryError>> {
        let mut reader = LineReader::new(io::BufReader::with_capacity(capacity, input));
        let mut lines = Vec::new();
        while let Some(line) = reader.next_line().expect("in-memory read") {
            lines.push(line);
        }
        lines
    }

    #[test]
    fn line_reader_splits_lines_across_buffer_boundaries() {
        let mut stream = started(b"/", b"one").encode();
        stream.extend(b"garbage\n");
        stream.extend(started(b"/", b"two").encode());
        stream.extend(b"knsh1\tpreexec\t/\ttorn-at-eof");
        for capacity in [1, 3, 64, 8192] {
            assert_eq!(
                read_all(&stream, capacity),
                [
                    Ok(started(b"/", b"one")),
                    Err(TelemetryError::UnknownTag),
                    Ok(started(b"/", b"two")),
                ],
                "capacity {capacity}"
            );
        }
    }

    // Untrusted input: an over-long line is reported once and skipped without buffering it whole; the next line
    // still decodes.
    #[test]
    fn line_reader_skips_over_long_lines() {
        let mut stream = vec![b'x'; MAX_LINE_LEN * 2 + 10];
        stream.push(b'\n');
        stream.extend(started(b"/", b"after").encode());
        for capacity in [4096, MAX_LINE_LEN + 100] {
            assert_eq!(
                read_all(&stream, capacity),
                [Err(TelemetryError::TooLong), Ok(started(b"/", b"after"))],
                "capacity {capacity}"
            );
        }
    }
}
