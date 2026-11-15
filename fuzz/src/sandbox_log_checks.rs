//! The properties of the `sandbox_log` fuzz target (KNSH-047; `specs/07-testing/fuzzing.md`, NFR-SUP-06).
//!
//! Also compiled on stable by `crates/knsh-platform/tests/fuzz_regressions.rs`, which includes it by path, so it
//! depends only on `knsh-platform`, `knsh-core` and `std`. A failed property panics, which libFuzzer records as a
//! crash.

use knsh_core::DenialTag;
use knsh_platform::LogEntry;
use knsh_platform::violation::{
    MAX_ARGUMENT_LEN, MAX_ENTRY_LEN, MAX_OPERATION_LEN, MAX_PROCESS_LEN, parse_entry, parse_message,
};

/// `sandbox_log`: neither parser panics, both are deterministic, and whatever they attribute is safe to keep: the
/// entry is within its size limit, the tag is the message's last line and reads back to itself, and the
/// informational fields are bounded, free of control characters and with a count of at least 1. The same bytes
/// are also tried as a bare `eventMessage`.
pub fn sandbox_log(data: &[u8]) {
    let entry = parse_entry(data);
    assert_eq!(
        format!("{entry:?}"),
        format!("{:?}", parse_entry(data)),
        "parse_entry is not deterministic"
    );
    if entry.is_some() {
        assert!(data.len() <= MAX_ENTRY_LEN, "accepted an entry over the size limit");
    }
    if let Ok(message) = std::str::from_utf8(data) {
        let parsed = parse_message(message);
        assert_eq!(
            format!("{parsed:?}"),
            format!("{:?}", parse_message(message)),
            "parse_message is not deterministic"
        );
        check(message, parsed);
    }
}

fn check(message: &str, parsed: Option<LogEntry>) {
    let Some(LogEntry::Denial(report)) = parsed else {
        return;
    };
    let lines: Vec<&str> = message.split('\n').collect();
    assert_eq!(
        lines.len(),
        2,
        "attributed a message that is not exactly report and tag"
    );
    let tag: DenialTag = lines[1].parse().expect("attributed by a tag that does not parse");
    assert_eq!(tag, report.tag, "attributed to another tag than the last line");
    assert_eq!(report.tag.to_string(), lines[1], "tag does not read back to itself");
    let process = report.process.expose();
    assert!(
        !process.is_empty() && process.len() <= MAX_PROCESS_LEN,
        "process name out of bounds"
    );
    assert!(
        !process.chars().any(char::is_control),
        "control character in process name"
    );
    assert!(
        !report.operation.is_empty() && report.operation.len() <= MAX_OPERATION_LEN,
        "operation out of bounds"
    );
    if let Some(argument) = &report.argument {
        let argument = argument.expose();
        assert!(
            !argument.is_empty() && argument.len() <= MAX_ARGUMENT_LEN,
            "argument out of bounds"
        );
        assert!(!argument.chars().any(char::is_control), "control character in argument");
    }
    assert!(report.count >= 1, "count below 1");
}
