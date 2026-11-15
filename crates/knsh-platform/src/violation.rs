//! Reading sandbox denials from the system log (KNSH-047; FR-SBX-06, FR-SBX-08; decision 9).
//!
//! # Source
//!
//! Seatbelt denials are logged by the kernel's Sandbox extension. [`DenialLog`] streams them: on macOS the
//! `macos::UnifiedLogDenials` backend runs [`LOG_TOOL`] `stream --style ndjson` with [`STREAM_PREDICATE`] as the
//! user, without admin rights, and yields one entry per line ([`DenialStream`]). It also causes a **canary**
//! denial on request: `log stream` delivers nothing until it is attached, and the system drops entries now and
//! then, so the reader only reports itself live once a denial it caused has come back through its own stream
//! (KNSH-025, C2).
//!
//! # Format (macOS 26.6, KNSH-025)
//!
//! Each entry is a JSON object. Denials come from the kernel (`processID` 0, `processImagePath` `/kernel`), and
//! their `eventMessage` is
//!
//! ```text
//! [<N> duplicate report[s] for ]Sandbox: <process>(<pid>) deny(<n>) <operation>[ <argument>]\n<tag>
//! ```
//!
//! where `<tag>` is the `(with message …)` text of the matching rule, verbatim. Captured samples for each macOS
//! version are kept under `crates/knsh-platform/fixtures/sandbox-log/<version>/` and tested here; the format may
//! change between versions.
//!
//! # Parsing
//!
//! [`parse_entry`] and [`parse_message`] are pure. They are strict, because the text is partly chosen by the
//! denied process (its name, the path it asked for) and an entry must never be attributed to a command it does not
//! belong to. An entry is ignored (`None`) unless:
//!
//! - it is a JSON object of at most [`MAX_ENTRY_LEN`] bytes, from the kernel (a user process can log with any
//!   sender name, but not as process 0 from `/kernel`);
//! - its message has exactly two lines: the report and the tag. A path holding a newline would make the tag
//!   ambiguous, so such a report is ignored;
//! - the tag is a [`DenialTag`] (`knsh:<session>:<command>:<rule>`) or the canary tag of [`CanaryNonce`];
//! - the report has the shape above, with bounded fields and no control characters.
//!
//! The header line `log stream` prints first ("Filtering the log data using …") is not JSON and is ignored too.
//! Integers beyond ±2^53 in fields the parser does not read (`machTimestamp`, `traceID`) are kept as decimal text
//! rather than failing the whole entry.

use std::fmt;

use knsh_core::{CanonicalPath, DenialReport, DenialTag, Redacted};
use knsh_json::Value;

use crate::error::PlatformError;

/// The unified-log command-line tool.
pub const LOG_TOOL: &str = "/usr/bin/log";

/// What `log stream` is asked for: sandbox reports that mention knsh (a knsh tag or the canary's). The parser checks
/// every entry again; the predicate only keeps the stream small.
pub const STREAM_PREDICATE: &str = r#"sender == "Sandbox" AND eventMessage CONTAINS "knsh""#;

/// The longest log entry read, in bytes. Real entries are about 1 KiB; a longer line is skipped whole.
pub const MAX_ENTRY_LEN: usize = 64 * 1024;

/// The longest process name accepted. The kernel logs at most `MAXCOMLEN` (16) or the 32-byte `p_name`.
pub const MAX_PROCESS_LEN: usize = 64;

/// The longest operation name accepted (`process-info-pidinfo` is 20).
pub const MAX_OPERATION_LEN: usize = 64;

/// The longest argument accepted: a canonical path (`PATH_MAX` is 1024) or a service name, with room to spare.
pub const MAX_ARGUMENT_LEN: usize = 4096;

/// The prefix of the canary's tag. It is not `knsh:`, so a canary can never be read as a denial of a session.
pub const CANARY_PREFIX: &str = "knsh-canary:";

/// The image every kernel log entry names as its process.
const KERNEL_IMAGE: &str = "/kernel";

/// The prefix of every Seatbelt report.
const REPORT_PREFIX: &str = "Sandbox: ";

/// The system's own summary of one repeat: "`<N>` duplicate report for ".
const DUPLICATE_SINGULAR: &str = " duplicate report for ";

/// The system's own summary of several repeats: "`<N>` duplicate reports for ".
const DUPLICATE_PLURAL: &str = " duplicate reports for ";

/// A source of the system's sandbox denial reports. Object safe: hold it as `Arc<dyn DenialLog>`.
pub trait DenialLog: Send + Sync {
    /// Starts a stream of denial entries, as the user, without admin rights.
    ///
    /// # Errors
    ///
    /// [`PlatformError::Os`] with [`Operation::SandboxLog`](crate::Operation::SandboxLog) if the stream cannot be
    /// started.
    fn open(&self) -> Result<Box<dyn DenialStream>, PlatformError>;

    /// Causes one denial whose tag is `nonce`'s canary tag ([`CanaryNonce::tag`]), and waits for the denied process
    /// to end. Whether the denial reaches the stream is for the reader to observe.
    ///
    /// # Errors
    ///
    /// [`PlatformError::Os`] if the canary cannot be set up or run.
    fn trigger_canary(&self, nonce: &CanaryNonce) -> Result<(), PlatformError>;
}

/// One open stream of denial entries.
pub trait DenialStream: Send {
    /// Blocks until the next entry, without its newline. An entry longer than [`MAX_ENTRY_LEN`] is skipped and
    /// returned empty, so the caller still sees that something arrived. `Ok(None)` when the stream has ended (the
    /// tool exited or was stopped).
    ///
    /// # Errors
    ///
    /// [`PlatformError::Os`] with [`Operation::SandboxLog`](crate::Operation::SandboxLog) if reading fails.
    fn next_entry(&mut self) -> Result<Option<Vec<u8>>, PlatformError>;

    /// A handle that ends this stream from another thread: a blocked [`DenialStream::next_entry`] then returns
    /// `Ok(None)`. Stopping twice, or after the stream ended, does nothing.
    fn stopper(&self) -> Box<dyn StreamStopper>;
}

/// Ends a [`DenialStream`] from another thread.
pub trait StreamStopper: Send + Sync {
    /// Ends the stream (module documentation of [`DenialStream::stopper`]).
    fn stop(&self);
}

/// The secret that identifies one canary denial: 16 random bytes, written as 32 lower-case hex digits.
///
/// Only `knshd` knows it, so no other process can make the reader believe it is live.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct CanaryNonce([u8; 16]);

impl CanaryNonce {
    /// The nonce made of `bytes`, which must come from the injected random source.
    #[must_use]
    pub const fn new(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// The canary's tag: [`CANARY_PREFIX`] then the hex digits.
    #[must_use]
    pub fn tag(&self) -> String {
        format!("{CANARY_PREFIX}{self}")
    }

    /// Parses exactly 32 lower-case hex digits; `None` for anything else.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        let digits = text.as_bytes();
        if digits.len() != 32 {
            return None;
        }
        let (pairs, _) = digits.as_chunks::<2>();
        let mut bytes = [0; 16];
        for (byte, &[high, low]) in bytes.iter_mut().zip(pairs) {
            *byte = hex_digit(high)? << 4 | hex_digit(low)?;
        }
        Some(Self(bytes))
    }
}

impl fmt::Display for CanaryNonce {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.iter().try_for_each(|byte| write!(f, "{byte:02x}"))
    }
}

impl fmt::Debug for CanaryNonce {
    /// Not printed: the nonce is what proves a canary came back through the real stream.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CanaryNonce(..)")
    }
}

/// The value of one lower-case hex digit.
const fn hex_digit(digit: u8) -> Option<u8> {
    match digit {
        b'0'..=b'9' => Some(digit - b'0'),
        b'a'..=b'f' => Some(digit - b'a' + 10),
        _ => None,
    }
}

/// What one log entry turned out to be.
#[derive(Debug, Clone)]
pub enum LogEntry {
    /// A knsh denial, attributed by its tag.
    Denial(DenialReport),
    /// A canary denial carrying this nonce.
    Canary(CanaryNonce),
}

/// Parses one line of `log stream --style ndjson` (module documentation). `None` means "not a knsh entry": it is
/// ignored, never attributed.
#[must_use]
pub fn parse_entry(line: &[u8]) -> Option<LogEntry> {
    if line.len() > MAX_ENTRY_LEN {
        return None;
    }
    let line = widen_large_integers(line);
    let Ok(Value::Object(entry)) = knsh_json::parse(&line, MAX_ENTRY_LEN + line.len()) else {
        return None;
    };
    // Only the kernel logs as process 0 from `/kernel`; a user process cannot, whatever sender name it uses.
    let from_kernel = entry.get("processID").and_then(Value::as_i64) == Some(0)
        && entry.get("processImagePath").and_then(Value::as_str) == Some(KERNEL_IMAGE);
    if !from_kernel {
        return None;
    }
    parse_message(entry.get("eventMessage")?.as_str()?)
}

/// Integer literals longer than this many digits may exceed the strict profile's ±2^53 (`9007199254740992` has 16).
const MAX_PLAIN_INTEGER_DIGITS: usize = 15;

/// Rewrites every integer literal outside a string that may exceed ±2^53 as the same digits followed by `e0`, so the
/// strict JSON reader keeps it as decimal text instead of refusing the whole entry. Entries carry such integers in
/// fields the parser never reads (`machTimestamp` counts nanoseconds on Intel Macs and passes 2^53 after about 104
/// days of uptime; `traceID` and the activity identifiers are 64-bit), and refusing them would silently drop every
/// denial, canaries included. Strings are copied untouched, and text that is not JSON stays not JSON, so the reader
/// still rejects it. Borrowed when nothing needs rewriting; otherwise at most an eighth longer.
fn widen_large_integers(line: &[u8]) -> std::borrow::Cow<'_, [u8]> {
    let mut widened: Option<Vec<u8>> = None;
    let mut in_string = false;
    let mut escaped = false;
    let mut start = 0;
    while let Some(&byte) = line.get(start) {
        let is_number_start = !in_string && (byte == b'-' || byte.is_ascii_digit());
        if !is_number_start {
            if in_string {
                if escaped {
                    escaped = false;
                } else if byte == b'\\' {
                    escaped = true;
                } else if byte == b'"' {
                    in_string = false;
                }
            } else if byte == b'"' {
                in_string = true;
            }
            if let Some(widened) = &mut widened {
                widened.push(byte);
            }
            start += 1;
            continue;
        }
        let rest = line.get(start..).unwrap_or_default();
        let len = rest
            .iter()
            .position(|byte| !matches!(byte, b'0'..=b'9' | b'-' | b'+' | b'.' | b'e' | b'E'))
            .unwrap_or(rest.len());
        let token = rest.get(..len).unwrap_or_default();
        let digits = token.strip_prefix(b"-").unwrap_or(token);
        if digits.len() > MAX_PLAIN_INTEGER_DIGITS && digits.iter().all(u8::is_ascii_digit) {
            let widened = widened.get_or_insert_with(|| line.get(..start).unwrap_or_default().to_vec());
            widened.extend_from_slice(token);
            widened.extend_from_slice(b"e0");
        } else if let Some(widened) = &mut widened {
            widened.extend_from_slice(token);
        }
        start += len;
    }
    widened.map_or(std::borrow::Cow::Borrowed(line), std::borrow::Cow::Owned)
}

/// Parses the `eventMessage` of one Seatbelt report (module documentation). Pure; `None` means ignored.
#[must_use]
pub fn parse_message(message: &str) -> Option<LogEntry> {
    let (report, tag) = message.split_once('\n')?;
    // Exactly two lines. The tag is appended by the system as the last line; if the report held a newline (a path
    // with one), a forged tag could sit in front of the real one, so the entry is ignored instead of guessed at.
    if tag.contains('\n') {
        return None;
    }
    if let Some(nonce) = tag.strip_prefix(CANARY_PREFIX) {
        return CanaryNonce::parse(nonce).map(LogEntry::Canary);
    }
    let tag: DenialTag = tag.parse().ok()?;
    parse_report(report, tag).map(LogEntry::Denial)
}

/// Parses `[<N> duplicate report[s] for ]Sandbox: <process>(<pid>) deny(<n>) <operation>[ <argument>]`.
fn parse_report(report: &str, tag: DenialTag) -> Option<DenialReport> {
    if report.chars().any(char::is_control) {
        return None;
    }
    let (count, report) = split_duplicates(report)?;
    let report = report.strip_prefix(REPORT_PREFIX)?;
    // The process name is chosen by whoever named the executable and may itself hold `(` or spaces, so the first
    // `) deny(` ends it. A name that holds `) deny(` would misparse the informational fields only, never the tag.
    let (process_and_pid, rest) = report.split_once(") deny(")?;
    let (process, pid) = process_and_pid.rsplit_once('(')?;
    let pid = digits(pid)?;
    // The kernel's own per-report count is checked for shape only; repeats are counted by the duplicate prefix.
    let (deny_count, rest) = rest.split_once(") ")?;
    digits(deny_count)?;
    let (operation, argument) = match rest.split_once(' ') {
        Some((operation, argument)) => (operation, Some(argument)),
        None => (rest, None),
    };
    let operation_ok = !operation.is_empty()
        && operation.len() <= MAX_OPERATION_LEN
        && operation
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'*'));
    if process.is_empty() || process.len() > MAX_PROCESS_LEN || !operation_ok {
        return None;
    }
    if argument.is_some_and(|argument| argument.is_empty() || argument.len() > MAX_ARGUMENT_LEN) {
        return None;
    }
    Some(DenialReport {
        tag,
        process: Redacted::new(process.to_owned()),
        pid,
        operation: operation.to_owned(),
        argument: argument.map(|argument| Redacted::new(argument.to_owned())),
        count,
    })
}

/// Splits off the system's "N duplicate reports for " prefix: the report stands for N denials, or 1 without it.
fn split_duplicates(report: &str) -> Option<(u32, &str)> {
    // A report that does not start with a number is a single denial; one that does must carry the exact prefix.
    let Some(space) = report.find(' ') else {
        return Some((1, report));
    };
    let (number, rest) = report.split_at(space);
    let Some(count) = digits(number) else {
        return Some((1, report));
    };
    let rest = rest
        .strip_prefix(DUPLICATE_PLURAL)
        .or_else(|| rest.strip_prefix(DUPLICATE_SINGULAR))?;
    // "0 duplicate reports" stands for nothing, so it is malformed rather than a count.
    (count > 0).then_some((count, rest))
}

/// A decimal number of 1 to 10 ASCII digits that fits `u32`.
fn digits(text: &str) -> Option<u32> {
    if text.is_empty() || text.len() > 10 || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

/// The Seatbelt profile of the canary: everything allowed except reading `file`, which is denied with `nonce`'s
/// tag. Pure, so the backend only writes and runs it.
///
/// The path is written as an SBPL string literal, in which only `\` and `"` need escaping (KNSH-044). It must be
/// canonical: Seatbelt matches the resolved path (KNSH-025).
#[must_use]
pub fn canary_profile(file: &CanonicalPath, nonce: &CanaryNonce) -> Vec<u8> {
    let mut profile = b"(version 1)\n(allow default)\n(deny file-read-data (literal \"".to_vec();
    for &byte in file.as_path().as_os_str().as_encoded_bytes() {
        if matches!(byte, b'\\' | b'"') {
            profile.push(b'\\');
        }
        profile.push(byte);
    }
    profile.extend_from_slice(b"\") (with message \"");
    profile.extend_from_slice(nonce.tag().as_bytes());
    profile.extend_from_slice(b"\"))\n");
    profile
}

#[cfg(test)]
mod tests {
    use knsh_core::{RecordId, SessionId, TaggedCommand};

    use super::*;

    const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/sandbox-log");
    const SESSION: &str = "01JC0000000000000000000000";
    const RECORD: &str = "01JC1111111111111111111111";

    fn fixture(version: &str, name: &str) -> Vec<Vec<u8>> {
        let text = std::fs::read(format!("{FIXTURES}/{version}/{name}")).unwrap();
        text.split(|&byte| byte == b'\n')
            .filter(|line| !line.is_empty())
            .map(<[u8]>::to_vec)
            .collect()
    }

    fn denial(entry: Option<LogEntry>) -> DenialReport {
        match entry {
            Some(LogEntry::Denial(report)) => report,
            other => panic!("expected a denial, got {other:?}"),
        }
    }

    fn session() -> SessionId {
        SESSION.parse().unwrap()
    }

    fn record() -> RecordId {
        RECORD.parse().unwrap()
    }

    fn argument(report: &DenialReport) -> Option<&str> {
        report.argument.as_ref().map(|argument| argument.expose().as_str())
    }

    // KNSH-047 parses_tagged_denial_message, over real samples captured on macOS 26.6.2 with the compiler's tag
    // form (`fixtures/sandbox-log/macos-26.6.2/production-tags.ndjson`).
    #[test]
    fn parses_tagged_denial_message() {
        let entries = fixture("macos-26.6.2", "production-tags.ndjson");
        let parsed: Vec<Option<LogEntry>> = entries.iter().map(|line| parse_entry(line)).collect();
        // The first line is `log stream`'s own header, not JSON.
        assert!(parsed[0].is_none());

        let first = denial(parsed[1].clone());
        assert_eq!(first.tag.session_id, session());
        assert_eq!(first.tag.command, TaggedCommand::Line(record()));
        assert_eq!(first.tag.rule.as_str(), "fs.deny[0]");
        assert_eq!(first.process.expose(), "cat");
        assert_eq!(first.pid, 71_295);
        assert_eq!(first.operation, "file-read-data");
        assert_eq!(
            argument(&first),
            Some("/private/var/folders/XX/XXXXXXXX/T/tmp.sbmF2c0R6h/secret")
        );
        assert_eq!(first.count, 1);

        // The system's summary of 8 repeats in one process.
        let repeats = denial(parsed[3].clone());
        assert_eq!((repeats.process.expose().as_str(), repeats.pid), ("bash", 71_298));
        assert_eq!(repeats.count, 8);

        // An envelope's tag names only the session; IP denials name only the port.
        let dns = denial(parsed[4].clone());
        assert_eq!(dns.tag.command, TaggedCommand::Envelope);
        assert_eq!(dns.tag.rule.as_str(), "services.dns");
        assert_eq!(dns.operation, "network-outbound");
        assert_eq!(argument(&dns), Some("remote:*:53"));
        assert_eq!(denial(parsed[5].clone()).count, 1, "\"1 duplicate report\", singular");

        // No argument at all.
        let job = denial(parsed[6].clone());
        assert_eq!((job.operation.as_str(), argument(&job)), ("job-creation", None));

        // A path with a space and a quote is kept whole.
        let odd = denial(parsed[7].clone());
        assert_eq!(
            argument(&odd),
            Some("/private/var/folders/XX/XXXXXXXX/T/tmp.sbmF2c0R6h/we ird/a\"b c")
        );
        assert_eq!(parsed.len(), 8);
    }

    // KNSH-047 ignores_untagged_message: the KNSH-025 samples carry spike tags (`knsh:c8:…`) or none at all
    // (`forbidden-exec-sugid`, `job-creation` through the default), so none of them may be attributed; every
    // report shape in them still parses once given a real tag.
    #[test]
    fn ignores_untagged_message() {
        let entries = fixture("macos-26.6.2", "knsh-025-spike-tags.ndjson");
        assert_eq!(entries.len(), 28);
        let real_tag = format!("knsh:{SESSION}:{RECORD}:default");
        for line in &entries {
            assert!(parse_entry(line).is_none(), "{}", String::from_utf8_lossy(line));
            let Ok(Value::Object(entry)) = knsh_json::parse(line, MAX_ENTRY_LEN) else {
                panic!("fixture is not JSON");
            };
            let message = entry.get("eventMessage").and_then(Value::as_str).unwrap();
            let report = message.split_once('\n').map_or(message, |(report, _)| report);
            let retagged = format!("{report}\n{real_tag}");
            let parsed = denial(parse_message(&retagged));
            assert!(parsed.pid > 0 && !parsed.operation.is_empty(), "{report}");
        }
        assert!(parse_message("Sandbox: cat(1) deny(1) file-read-data /etc/hosts").is_none());
    }

    #[test]
    fn report_shapes_from_knsh_025() {
        let tag = format!("knsh:{SESSION}:env:process.info");
        let parse = |report: &str| denial(parse_message(&format!("{report}\n{tag}")));
        let pinfo = parse("Sandbox: probe(48846) deny(1) process-info-pidinfo others [sleep(48736)]");
        assert_eq!(argument(&pinfo), Some("others [sleep(48736)]"));
        let listpids = parse("Sandbox: probe(48867) deny(1) process-info-listpids");
        assert_eq!(argument(&listpids), None);
        let many = parse("409 duplicate reports for Sandbox: probe(49023) deny(1) mach-lookup com.apple.lsd.modifydb");
        assert_eq!((many.count, argument(&many)), (409, Some("com.apple.lsd.modifydb")));
        let register = parse("Sandbox: osascript(49045) deny(1) mach-register com.apple.axserver (per-pid)");
        assert_eq!(argument(&register), Some("com.apple.axserver (per-pid)"));
        let named = parse("Sandbox: my (odd) name(12) deny(1) file-read-data /x");
        assert_eq!((named.process.expose().as_str(), named.pid), ("my (odd) name", 12));
    }

    // KNSH-047: anything that could put a denial on the wrong command is ignored, never guessed at.
    #[test]
    fn ignores_ambiguous_or_malformed_reports() {
        let tag = format!("knsh:{SESSION}:{RECORD}:default");
        let other = format!("knsh:{SESSION}:env:default");
        for message in [
            // A path holding a newline and a forged tag in front of the real one.
            format!("Sandbox: cat(1) deny(1) file-read-data /tmp/x\n{other}\n{tag}"),
            format!("Sandbox: cat(1) deny(1) file-read-data /tmp/\tx\n{tag}"),
            format!("Sandbox: cat(1) deny(1) file-read-data /tmp/x\r\n{tag}"),
            format!("Sandbox: cat(1) deny(1) file-read-data /tmp/x\n{tag}\n"),
            format!("Sandbox: cat(1) deny(1) file-read-data /tmp/x\n {tag}"),
            format!("Sandbox: cat() deny(1) file-read-data /x\n{tag}"),
            format!("Sandbox: (1) deny(1) file-read-data /x\n{tag}"),
            format!("Sandbox: cat(-1) deny(1) file-read-data /x\n{tag}"),
            format!("Sandbox: cat(99999999999) deny(1) file-read-data /x\n{tag}"),
            format!("Sandbox: cat(1) deny(x) file-read-data /x\n{tag}"),
            format!("Sandbox: cat(1) deny(1) File-Read /x\n{tag}"),
            format!("Sandbox: cat(1) deny(1) file-read-data \n{tag}"),
            format!("Sandbox: cat(1) deny(1)\n{tag}"),
            format!("Sandbox: cat(1) allow(1) file-read-data /x\n{tag}"),
            format!("sandbox: cat(1) deny(1) file-read-data /x\n{tag}"),
            format!("0 duplicate reports for Sandbox: cat(1) deny(1) file-read-data /x\n{tag}"),
            format!("2 duplicates for Sandbox: cat(1) deny(1) file-read-data /x\n{tag}"),
            format!(
                "Sandbox: {}(1) deny(1) file-read-data /x\n{tag}",
                "p".repeat(MAX_PROCESS_LEN + 1)
            ),
            format!(
                "Sandbox: cat(1) deny(1) file-read-data /{}\n{tag}",
                "a".repeat(MAX_ARGUMENT_LEN)
            ),
            format!(
                "Sandbox: cat(1) deny(1) file-read-data /x\n{}",
                tag.replace(SESSION, "01JC")
            ),
            String::new(),
            String::from("\n"),
        ] {
            assert!(parse_message(&message).is_none(), "{message:?}");
        }
    }

    // A user process can log any sender name, but not as the kernel: such entries are ignored.
    #[test]
    fn ignores_entries_not_from_the_kernel() {
        let message = format!("Sandbox: cat(1) deny(1) file-read-data /x\\nknsh:{SESSION}:{RECORD}:default");
        let entry = |pid: &str, image: &str| {
            format!(r#"{{"processID":{pid},"processImagePath":"{image}","eventMessage":"{message}"}}"#)
        };
        assert!(parse_entry(entry("0", "/kernel").as_bytes()).is_some());
        assert!(parse_entry(entry("501", "/kernel").as_bytes()).is_none());
        assert!(parse_entry(entry("0", "/usr/local/bin/forger").as_bytes()).is_none());
        assert!(parse_entry(br#"{"processID":0,"processImagePath":"/kernel"}"#).is_none());
        assert!(parse_entry(b"[1]").is_none());
        let long = vec![b' '; MAX_ENTRY_LEN + 1];
        assert!(parse_entry(&long).is_none());
    }

    // KNSH-047: an entry carrying a 64-bit integer the strict profile cannot hold as a number (an Intel Mac's
    // nanosecond `machTimestamp` after about 104 days of uptime, a large `traceID`) is still read, not dropped.
    #[test]
    fn reads_entries_with_integers_beyond_2_pow_53() {
        let message = format!("Sandbox: cat(7) deny(1) file-read-data /x\\nknsh:{SESSION}:{RECORD}:default");
        let entry = format!(
            r#"{{"machTimestamp":9007199254740993,"traceID":18446744073709551615,"activityIdentifier":-9223372036854775808,"note":"12345678901234567890 \"x\" 99999999999999999","processID":0,"processImagePath":"\/kernel","eventMessage":"{message}"}}"#
        );
        let report = denial(parse_entry(entry.as_bytes()));
        assert_eq!((report.pid, report.tag.session_id), (7, session()));
        assert_eq!(
            widen_large_integers(b"{\"a\":123456789012345}").as_ref(),
            b"{\"a\":123456789012345}"
        );
        assert_eq!(
            widen_large_integers(br#"{"a":"1234567890123456","b":1234567890123456}"#).as_ref(),
            br#"{"a":"1234567890123456","b":1234567890123456e0}"#
        );
        // Not JSON stays not JSON.
        assert!(parse_entry(b"12345678901234567890").is_none());
        assert!(parse_entry(br#"{"processID":00000000000000000,"processImagePath":"/kernel"}"#).is_none());
    }

    #[test]
    fn canary_round_trips() {
        let nonce = CanaryNonce::new([0xab; 16]);
        assert_eq!(nonce.to_string(), "ab".repeat(16));
        assert_eq!(format!("{nonce:?}"), "CanaryNonce(..)");
        let message = format!("Sandbox: cat(9) deny(1) file-read-data /x\n{}", nonce.tag());
        assert!(matches!(parse_message(&message), Some(LogEntry::Canary(seen)) if seen == nonce));
        for bad in ["AB".repeat(16), "ab".repeat(15), "zz".repeat(16)] {
            assert!(CanaryNonce::parse(&bad).is_none(), "{bad}");
            let message = format!("Sandbox: cat(9) deny(1) file-read-data /x\n{CANARY_PREFIX}{bad}");
            assert!(parse_message(&message).is_none());
        }
    }

    #[test]
    fn canary_profile_escapes_the_path() {
        let path = CanonicalPath::new(r#"/tmp/a"b\c/canary"#).unwrap();
        let nonce = CanaryNonce::new([1; 16]);
        let profile = String::from_utf8(canary_profile(&path, &nonce)).unwrap();
        assert_eq!(
            profile,
            format!(
                "(version 1)\n(allow default)\n(deny file-read-data (literal \"/tmp/a\\\"b\\\\c/canary\") \
                 (with message \"{}\"))\n",
                nonce.tag()
            )
        );
    }
}
