//! `knsh forget`: delete records, and with `--with-checkpoints` their checkpoints (FR-REC-10, NFR-PRIV-03, KNSH-017).
//!
//! `knsh forget --session <id>` and `--since <date>` build one `records.forget` call on `user.sock` and report how many
//! records were deleted. At least one selector is required; with both, a record must match both. The checks here
//! run before connecting, so a mistyped command never reaches `knshd`:
//!
//! - no selector is a usage error (exit 2), so `knsh forget` alone can never delete everything;
//! - `--session` must be a canonical session ID;
//! - `--since` is a UTC date, `YYYY-MM-DD` (from midnight UTC), or an engine timestamp `YYYY-MM-DDTHH:MM:SS[.ffffff]Z`.
//!
//! `--with-checkpoints` is sent as asked. Phase 1 has no checkpoints, so `knshd` answers `-32005` and deletes nothing;
//! that is reported as an error, never ignored ([`failure_message`]).

use std::fmt;
use std::io::{Read, Write};

use knsh_core::{SessionId, Timestamp};
use knsh_json::{FromJson, ToJson, Value};
use knsh_proto::{ErrorCode, RecordsForgetParams, RecordsForgetResult};

use crate::cli::args::ParsedCommand;
use crate::cli::client::{Client, ClientError};

/// The method `knsh forget` calls.
pub const METHOD: &str = "records.forget";

/// Why a `knsh forget` command line was refused before anything was sent. Exits with 2, like other usage errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UsageError {
    /// Neither `--session` nor `--since` was given.
    NoSelector,
    /// `--session` is not a canonical session ID.
    BadSession,
    /// `--since` is neither a date nor an engine timestamp.
    BadSince,
}

impl fmt::Display for UsageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoSelector => f.write_str("forget needs --session <id>, --since <date>, or both"),
            Self::BadSession => f.write_str("--session must be a session ID (26 characters, as shown by knsh history)"),
            Self::BadSince => {
                f.write_str("--since must be a UTC date (YYYY-MM-DD) or timestamp (YYYY-MM-DDTHH:MM:SSZ)")
            }
        }
    }
}

impl std::error::Error for UsageError {}

/// The `records.forget` parameters for a parsed `knsh forget` command line.
///
/// # Errors
///
/// A [`UsageError`] when no selector is given or a value is malformed.
pub fn params(parsed: &ParsedCommand) -> Result<RecordsForgetParams, UsageError> {
    let session_id = parsed
        .value("session")
        .map(|text| text.parse::<SessionId>().map_err(|_| UsageError::BadSession))
        .transpose()?;
    let since = parsed.value("since").map(parse_since).transpose()?;
    if session_id.is_none() && since.is_none() {
        return Err(UsageError::NoSelector);
    }
    Ok(RecordsForgetParams {
        session_id,
        since,
        with_checkpoints: parsed.flag("with-checkpoints"),
    })
}

/// Reads `--since`: see [`parse_instant`].
fn parse_since(text: &str) -> Result<Timestamp, UsageError> {
    parse_instant(text).ok_or(UsageError::BadSince)
}

/// Reads a date-or-time option of the CLI (`--since`, `--until`): a date `YYYY-MM-DD` means midnight UTC of that day;
/// otherwise the engine's strict timestamp form `YYYY-MM-DDTHH:MM:SS[.ffffff]Z`. `None` for anything else.
pub(crate) fn parse_instant(text: &str) -> Option<Timestamp> {
    let is_date = text.len() == 10
        && text.bytes().enumerate().all(|(index, byte)| {
            if index == 4 || index == 7 {
                byte == b'-'
            } else {
                byte.is_ascii_digit()
            }
        });
    let full = if is_date {
        format!("{text}T00:00:00Z")
    } else {
        text.to_owned()
    };
    full.parse().ok()
}

/// Sends `params` as `records.forget` on a connected client and returns how many records were deleted.
///
/// # Errors
///
/// Any [`ClientError`]; [`ClientError::Protocol`] if the result is not a count.
pub fn run<R: Read, W: Write>(client: &mut Client<R, W>, params: &RecordsForgetParams) -> Result<u64, ClientError> {
    let Value::Object(object) = params.to_json()? else {
        return Err(ClientError::Protocol);
    };
    let result = client.call(METHOD, Some(object))?;
    let result = RecordsForgetResult::from_json(&result).map_err(|_| ClientError::Protocol)?;
    Ok(result.deleted)
}

/// What `knsh forget` prints on success: a sentence, or `{"deleted": n}` with `--json`.
#[must_use]
pub fn report(deleted: u64, json: bool) -> String {
    if json {
        // A count always fits the JSON integer range; the fallback keeps the output valid JSON regardless.
        let text = RecordsForgetResult { deleted }
            .to_json()
            .and_then(|value| knsh_json::write(&value))
            .unwrap_or_else(|_| String::from(r#"{"deleted":null}"#));
        format!("{text}\n")
    } else {
        let noun = if deleted == 1 { "record" } else { "records" };
        format!("Deleted {deleted} {noun}.\n")
    }
}

/// What `knsh forget` prints on stderr when the call failed.
#[must_use]
pub fn failure_message(error: &ClientError) -> String {
    match error {
        // The only capability `forget` can lack: say what it means rather than echo the code.
        ClientError::Rpc(rpc) if rpc.code == ErrorCode::CapabilityUnavailable => String::from(
            "knsh: forget: checkpoints are not available on this machine yet; nothing was deleted \
             (run again without --with-checkpoints to delete records only)\n",
        ),
        ClientError::Rpc(rpc) if rpc.code == ErrorCode::InvalidParams => {
            String::from("knsh: forget: knshd refused the selectors; nothing was deleted\n")
        }
        other => format!("knsh: forget failed: {other}\n"),
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;
    use crate::cli::args::{self, Invocation};
    use crate::cli::client::tests::{HELLO_OK, frames, sent};
    use crate::cli::commands::KNSH;

    const SESSION: &str = "01JCZ0000000000000000000CD";

    fn parsed(argv: &[&str]) -> ParsedCommand {
        let argv = std::iter::once("knsh").chain(argv.iter().copied()).map(Into::into);
        match args::parse(&KNSH, argv).unwrap() {
            Invocation::Command(parsed) => parsed,
            other => panic!("{other:?}"),
        }
    }

    // CLI validation: at least one selector, and well-formed values, before anything is sent.
    #[test]
    fn forget_requires_a_selector() {
        assert_eq!(params(&parsed(&["forget"])), Err(UsageError::NoSelector));
        assert_eq!(
            params(&parsed(&["forget", "--with-checkpoints"])),
            Err(UsageError::NoSelector)
        );
        assert_eq!(
            params(&parsed(&["forget", "--session", "abc"])),
            Err(UsageError::BadSession)
        );
        for bad in ["yesterday", "2026-13-01", "2026-1-01", "2026-11-01 10:00"] {
            assert_eq!(
                params(&parsed(&["forget", "--since", bad])),
                Err(UsageError::BadSince),
                "{bad}"
            );
        }

        let both = params(&parsed(&["forget", "--session", SESSION, "--since", "2026-11-01"])).unwrap();
        assert_eq!(both.session_id, Some(SESSION.parse().unwrap()));
        assert_eq!(
            both.since,
            Some("2026-11-01T00:00:00Z".parse().unwrap()),
            "a date is midnight UTC"
        );
        assert!(!both.with_checkpoints);
        let precise = params(&parsed(&[
            "forget",
            "--since=2026-11-01T10:30:00.5Z",
            "--with-checkpoints",
        ]))
        .unwrap();
        assert_eq!(precise.since, Some("2026-11-01T10:30:00.5Z".parse().unwrap()));
        assert!(precise.with_checkpoints);
    }

    // FR-REC-10: the command calls records.forget with its selectors and reports the count.
    #[test]
    fn forget_calls_the_api_and_reports_the_count() {
        let answers = frames(&[HELLO_OK, r#"{"jsonrpc":"2.0","id":2,"result":{"deleted":3}}"#]);
        let mut written = Vec::new();
        let mut client = Client::new(Cursor::new(answers), &mut written);
        client.hello().unwrap();
        let request = params(&parsed(&["forget", "--session", SESSION])).unwrap();
        let deleted = run(&mut client, &request).unwrap();
        assert_eq!(deleted, 3);
        let texts = sent(&written);
        assert!(texts[1].contains(r#""method":"records.forget""#), "{}", texts[1]);
        assert!(
            texts[1].contains(&format!(r#""params":{{"session_id":"{SESSION}"}}"#)),
            "{}",
            texts[1]
        );
        assert_eq!(report(3, false), "Deleted 3 records.\n");
        assert_eq!(report(1, false), "Deleted 1 record.\n");
        assert_eq!(report(3, true), "{\"deleted\":3}\n");
    }

    // Honest capabilities: the flag is sent, and the -32005 answer is reported as a failure, not ignored.
    #[test]
    fn with_checkpoints_reports_capability_unavailable() {
        let answers = frames(&[
            HELLO_OK,
            r#"{"jsonrpc":"2.0","id":2,"error":{"code":-32005,"message":"Capability not available on this machine","data":{"capability":"checkpoints"}}}"#,
        ]);
        let mut written = Vec::new();
        let mut client = Client::new(Cursor::new(answers), &mut written);
        client.hello().unwrap();
        let request = params(&parsed(&["forget", "--session", SESSION, "--with-checkpoints"])).unwrap();
        let error = run(&mut client, &request).unwrap_err();
        assert!(sent(&written)[1].contains(r#""with_checkpoints":true"#));
        let message = failure_message(&error);
        assert!(message.contains("checkpoints are not available"), "{message}");
        assert!(message.contains("nothing was deleted"), "{message}");
    }
}
