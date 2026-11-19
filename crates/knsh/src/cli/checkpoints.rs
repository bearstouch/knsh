//! `knsh undo`, `knsh redo` and `knsh checkpoints` (KNSH-088; `specs/06-api/cli.md#undo-redo-and-checkpoints`).
//!
//! - `knsh undo [--checkpoint] [--force] <id>` and `knsh redo …` call `checkpoint.undo` and `checkpoint.redo` on
//!   `user.sock`: `<id>` is a record ID (a line's change; for a line of a concurrent set, the whole set), or with
//!   `--checkpoint` a checkpoint ID (a change without a line, such as a run of agent edits, from `knsh checkpoints`).
//!   `--force` restores paths whose identity no longer matches, and possibly-torn files (FR-CKP-21: the user may).
//! - `knsh checkpoints [--session <id>]` reads every page of `checkpoint.list` and prints each change oldest first,
//!   then the current state.
//!
//! IDs are checked before connecting (usage error, exit 2). Output is terminal-safe ([`crate::cli::terminal`]): paths
//! come from the agent's tree and may hold any character. `--json` prints the API's objects unchanged, one per line:
//! the undo or redo result, or each listed change.

use std::fmt::{self, Write as _};
use std::io::{Read, Write};

use knsh_core::{CheckpointId, RecordId, SessionId};
use knsh_json::{Object, ToJson, Value};
use knsh_proto::{ChangeTarget, CheckpointListParams, CheckpointUndoParams, ErrorCode, MAX_LIST_PAGE};

use crate::cli::args::ParsedCommand;
use crate::cli::client::{Client, ClientError};
use crate::cli::terminal::{escape_text, write_json_line};

/// The method `knsh undo` calls.
pub const UNDO_METHOD: &str = "checkpoint.undo";
/// The method `knsh redo` calls.
pub const REDO_METHOD: &str = "checkpoint.redo";
/// The method `knsh checkpoints` calls.
pub const LIST_METHOD: &str = "checkpoint.list";

/// The most pages `knsh checkpoints` reads: far more than retention keeps (200 per root), so only a cursor that never
/// ends stops it.
const MAX_PAGES: usize = 10_000;

/// Undo or redo.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    /// `knsh undo`.
    Undo,
    /// `knsh redo`.
    Redo,
}

impl Step {
    /// The method sent.
    #[must_use]
    pub const fn method(self) -> &'static str {
        match self {
            Self::Undo => UNDO_METHOD,
            Self::Redo => REDO_METHOD,
        }
    }

    /// The command's name, for messages.
    #[must_use]
    pub const fn command(self) -> &'static str {
        match self {
            Self::Undo => "undo",
            Self::Redo => "redo",
        }
    }
}

/// A command line refused before anything was sent (exit 2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UsageError {
    /// The ID is not a canonical record or checkpoint ID.
    BadId,
    /// `--session` is not a canonical session ID.
    BadSession,
}

impl fmt::Display for UsageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadId => f.write_str(
                "the ID must be 26 characters: a record ID (knsh history), or with --checkpoint a checkpoint ID \
                 (knsh checkpoints)",
            ),
            Self::BadSession => f.write_str("--session must be a session ID (26 characters, as shown by knsh history)"),
        }
    }
}

impl std::error::Error for UsageError {}

/// The `checkpoint.undo` or `checkpoint.redo` parameters of a parsed command line.
///
/// # Errors
///
/// [`UsageError::BadId`] for an ID that is not canonical.
pub fn step_params(parsed: &ParsedCommand) -> Result<CheckpointUndoParams, UsageError> {
    let text = parsed.positionals.first().ok_or(UsageError::BadId)?;
    let target = if parsed.flag("checkpoint") {
        ChangeTarget::Checkpoint(text.parse::<CheckpointId>().map_err(|_| UsageError::BadId)?)
    } else {
        ChangeTarget::Record(text.parse::<RecordId>().map_err(|_| UsageError::BadId)?)
    };
    Ok(CheckpointUndoParams {
        target,
        force: parsed.flag("force"),
    })
}

/// The session `knsh checkpoints` lists, if `--session` is given.
///
/// # Errors
///
/// [`UsageError::BadSession`] for a malformed ID.
pub fn list_session(parsed: &ParsedCommand) -> Result<Option<SessionId>, UsageError> {
    parsed
        .value("session")
        .map(|text| text.parse().map_err(|_| UsageError::BadSession))
        .transpose()
}

/// Sends `checkpoint.undo` or `checkpoint.redo` and returns the result object as `knshd` sent it.
///
/// # Errors
///
/// Any [`ClientError`]; [`ClientError::Protocol`] if the result is not an object.
pub fn step<R: Read, W: Write>(
    client: &mut Client<R, W>,
    how: Step,
    params: &CheckpointUndoParams,
) -> Result<Object, ClientError> {
    let Value::Object(params) = params.to_json()? else {
        return Err(ClientError::Protocol);
    };
    match client.call(how.method(), Some(params))? {
        Value::Object(result) => Ok(result),
        _ => Err(ClientError::Protocol),
    }
}

/// Every change `checkpoint.list` returns for `session` (all when `None`), oldest first, and the current state.
///
/// # Errors
///
/// Any [`ClientError`]; [`ClientError::Protocol`] for a malformed page, or a cursor that does not advance.
pub fn list<R: Read, W: Write>(
    client: &mut Client<R, W>,
    session: Option<SessionId>,
) -> Result<(Vec<Object>, i64), ClientError> {
    let mut changes = Vec::new();
    let mut cursor: Option<CheckpointId> = None;
    for _ in 0..MAX_PAGES {
        let params = CheckpointListParams {
            session_id: session,
            cursor,
            limit: MAX_LIST_PAGE,
        };
        let Value::Object(params) = params.to_json()? else {
            return Err(ClientError::Protocol);
        };
        let Value::Object(page) = client.call(LIST_METHOD, Some(params))? else {
            return Err(ClientError::Protocol);
        };
        let head = page.get("head").and_then(Value::as_i64).ok_or(ClientError::Protocol)?;
        let listed = page
            .get("changes")
            .and_then(Value::as_array)
            .ok_or(ClientError::Protocol)?;
        for change in listed {
            changes.push(change.as_object().cloned().ok_or(ClientError::Protocol)?);
        }
        let next = match page.get("next_cursor") {
            None | Some(Value::Null) => return Ok((changes, head)),
            Some(Value::String(text)) => text.parse::<CheckpointId>().map_err(|_| ClientError::Protocol)?,
            Some(_) => return Err(ClientError::Protocol),
        };
        // A cursor that does not advance would loop forever: a protocol error, never a loop.
        if cursor.is_some_and(|cursor| next <= cursor) {
            return Err(ClientError::Protocol);
        }
        cursor = Some(next);
    }
    Err(ClientError::Protocol)
}

/// What `knsh undo` or `knsh redo` prints: the API's result as one JSON line with `--json`, otherwise what was
/// restored, what was not, and where the history is now.
///
/// # Errors
///
/// The result cannot be written as JSON (never for a parsed answer).
pub fn step_report(how: Step, result: &Object, json: bool) -> Result<String, knsh_json::JsonError> {
    if json {
        return write_json_line(&Value::Object(result.clone()));
    }
    let text = |key: &str| result.get(key).and_then(Value::as_str).unwrap_or("?");
    let count = |key: &str| result.get(key).and_then(Value::as_i64).unwrap_or(0);
    let done = match how {
        Step::Undo => "Undid",
        Step::Redo => "Redid",
    };
    let files = count("files_restored");
    let noun = if files == 1 { "file" } else { "files" };
    let mut out = format!(
        "{done} change {}: restored {files} {noun}; now at state {}.\n",
        escape_text(text("checkpoint_id")),
        count("state_id")
    );
    if result.get("forced").and_then(Value::as_bool) == Some(true) {
        out.push_str("  forced: checks were overridden\n");
    }
    for path in strings(result, "not_restored") {
        let _ = writeln!(out, "  not restored (excluded): {}", escape_text(path));
    }
    for (path, reason) in torn(result, "skipped_torn") {
        let _ = writeln!(
            out,
            "  skipped (possibly torn, {}): {} (use --force to restore it)",
            escape_text(reason),
            escape_text(path)
        );
    }
    for (path, reason) in torn(result, "forced_torn") {
        let _ = writeln!(out, "  restored despite {}: {}", escape_text(reason), escape_text(path));
    }
    for reason in strings(result, "irreversible") {
        let _ = writeln!(out, "  cannot be undone: {}", escape_text(reason));
    }
    Ok(out)
}

/// What `knsh checkpoints` prints: one JSON line per change with `--json`; otherwise one line per change
/// (`created_at  checkpoint_id  status  kind  files  from->to  records`), then the current state.
///
/// # Errors
///
/// A change cannot be written as JSON (never for a parsed answer).
pub fn list_report(changes: &[Object], head: i64, json: bool) -> Result<String, knsh_json::JsonError> {
    let mut out = String::new();
    if json {
        for change in changes {
            out.push_str(&write_json_line(&Value::Object(change.clone()))?);
        }
        return Ok(out);
    }
    if changes.is_empty() {
        out.push_str("No checkpoints.\n");
    }
    for change in changes {
        let text = |key: &str| change.get(key).and_then(Value::as_str).unwrap_or("-");
        let number = |key: &str| change.get(key).and_then(Value::as_i64).unwrap_or(0);
        let kind = match change.get("reverts").and_then(Value::as_str) {
            Some(reverted) => format!("revert of {reverted}"),
            None => text("attribution").to_owned(),
        };
        let records = strings(change, "record_ids").collect::<Vec<_>>().join(",");
        let uncertain = if change.get("uncertain").and_then(Value::as_bool) == Some(true) {
            " (uncertain)"
        } else {
            ""
        };
        let _ = writeln!(
            out,
            "{}  {}  {}  {}  {} files{uncertain}  {}->{}  {}",
            escape_text(text("created_at")),
            escape_text(text("checkpoint_id")),
            escape_text(text("status")),
            escape_text(&kind),
            number("files_changed"),
            number("from"),
            number("to"),
            escape_text(if records.is_empty() { "-" } else { &records }),
        );
    }
    let _ = writeln!(out, "Current state: {head}.");
    Ok(out)
}

/// What the command prints on stderr when the call failed: why, in words, with each conflicting path.
#[must_use]
pub fn failure_message(command: &str, error: &ClientError) -> String {
    let ClientError::Rpc(rpc) = error else {
        return format!("knsh: {command} failed: {error}\n");
    };
    let data = rpc.data.as_ref().and_then(Value::as_object);
    match rpc.code {
        ErrorCode::UndoConflict => {
            let mut out = format!("knsh: {command}: nothing was restored; these paths conflict:\n");
            let conflicts = data
                .and_then(|data| data.get("conflicts"))
                .and_then(Value::as_array)
                .map(Vec::as_slice)
                .unwrap_or_default();
            for conflict in conflicts.iter().filter_map(Value::as_object) {
                let path = conflict.get("path").and_then(Value::as_str).unwrap_or("?");
                let reason = conflict.get("reason").and_then(Value::as_str).unwrap_or("?");
                let _ = writeln!(out, "  {} ({})", escape_text(path), escape_text(reason));
            }
            out
        }
        ErrorCode::InvalidParams => {
            let reason = data.and_then(|data| data.get("reason")).and_then(Value::as_str);
            let why = match reason {
                Some("unknown") => "no change in the history has that ID",
                Some("expired") => "that change's checkpoint has expired and was removed",
                Some("not_in_effect") => "that change is not in effect (already undone, or on another branch)",
                Some("not_undone") => "that change was not undone, so there is nothing to redo",
                Some("redo_blocked") => "later changes started another branch; restore the state instead",
                _ => "knshd refused the request",
            };
            format!("knsh: {command}: {why}\n")
        }
        ErrorCode::CapabilityUnavailable => {
            format!("knsh: {command}: checkpoints are not available on this machine\n")
        }
        _ => format!("knsh: {command} failed: {error}\n"),
    }
}

/// The strings of the array `key` of `object`.
fn strings<'a>(object: &'a Object, key: &str) -> impl Iterator<Item = &'a str> {
    object
        .get(key)
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default()
        .iter()
        .filter_map(Value::as_str)
}

/// The `(path, reason)` pairs of the possibly-torn list `key`.
fn torn<'a>(object: &'a Object, key: &str) -> impl Iterator<Item = (&'a str, &'a str)> {
    object
        .get(key)
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default()
        .iter()
        .filter_map(Value::as_object)
        .filter_map(|entry| Some((entry.get("path")?.as_str()?, entry.get("reason")?.as_str()?)))
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;
    use crate::cli::args::{self, Invocation};
    use crate::cli::client::tests::{HELLO_OK, frames, sent};
    use crate::cli::commands::KNSH;

    const RECORD: &str = "01JCZ0000000000000000000AB";
    const CHECKPOINT: &str = "01JCZ0000000000000000000CK";
    const UNDONE: &str = r#"{"operation":"undo","checkpoint_id":"01JCZ0000000000000000000CK","record_ids":["01JCZ0000000000000000000AB"],"roots":["/Users/u/app"],"state_id":0,"files_restored":1,"restored":["/Users/u/app/a\u001b[31m.txt"],"restored_incomplete":false,"not_restored":["/Users/u/app/node_modules"],"not_restored_incomplete":false,"irreversible":[],"forced":false,"skipped_torn":[{"path":"/Users/u/app/db","reason":"sqlite_journal"}],"forced_torn":[]}"#;

    fn parsed(argv: &[&str]) -> Result<ParsedCommand, args::ArgsError> {
        let argv = std::iter::once("knsh").chain(argv.iter().copied()).map(Into::into);
        match args::parse(&KNSH, argv)? {
            Invocation::Command(parsed) => Ok(parsed),
            other => panic!("{other:?}"),
        }
    }

    fn client_answering(result: &str) -> (Vec<u8>, Vec<u8>) {
        let answer = format!(r#"{{"jsonrpc":"2.0","id":2,"result":{result}}}"#);
        (frames(&[HELLO_OK, &answer]), Vec::new())
    }

    // KNSH-088: an ID is a record ID, or with --checkpoint a checkpoint ID; --force is passed on; nothing malformed is
    // sent.
    #[test]
    fn undo_and_redo_take_one_valid_id() {
        let by_record = step_params(&parsed(&["undo", RECORD]).unwrap()).unwrap();
        assert_eq!(by_record.target, ChangeTarget::Record(RECORD.parse().unwrap()));
        assert!(!by_record.force);
        let by_checkpoint = step_params(&parsed(&["redo", "--checkpoint", "--force", CHECKPOINT]).unwrap()).unwrap();
        assert_eq!(
            by_checkpoint.target,
            ChangeTarget::Checkpoint(CHECKPOINT.parse().unwrap())
        );
        assert!(by_checkpoint.force);
        assert_eq!(step_params(&parsed(&["undo", "nope"]).unwrap()), Err(UsageError::BadId));
        assert!(parsed(&["undo"]).is_err(), "the ID is required");
        assert!(parsed(&["undo", RECORD, RECORD]).is_err(), "one ID");
        assert_eq!(
            list_session(&parsed(&["checkpoints", "--session", "x"]).unwrap()),
            Err(UsageError::BadSession)
        );
    }

    // KNSH-088 AC: `knsh undo` calls checkpoint.undo on user.sock, and `--json` prints the API's result unchanged.
    #[test]
    fn cli_undo_json_output_matches_api_result() {
        let (answers, mut written) = client_answering(UNDONE);
        let mut client = Client::new(Cursor::new(answers), &mut written);
        client.hello().unwrap();
        let params = step_params(&parsed(&["undo", RECORD]).unwrap()).unwrap();
        let result = step(&mut client, Step::Undo, &params).unwrap();
        let texts = sent(&written);
        assert!(texts[1].contains(r#""method":"checkpoint.undo""#), "{}", texts[1]);
        assert!(
            texts[1].contains(&format!(r#""params":{{"record_id":"{RECORD}"}}"#)),
            "{}",
            texts[1]
        );
        let printed = step_report(Step::Undo, &result, true).unwrap();
        assert!(printed.ends_with('\n') && printed.lines().count() == 1);
        let api = knsh_json::parse(UNDONE.as_bytes(), 1 << 16).unwrap();
        assert_eq!(
            knsh_json::parse(printed.trim_end().as_bytes(), 1 << 16).unwrap(),
            api,
            "the API's result, unchanged"
        );
        assert!(!printed.contains('\u{1b}'), "escaped for the terminal: {printed}");
    }

    #[test]
    fn undo_text_says_what_was_and_was_not_restored() {
        let result = knsh_json::parse(UNDONE.as_bytes(), 1 << 16).unwrap();
        let text = step_report(Step::Undo, result.as_object().unwrap(), false).unwrap();
        assert!(
            text.starts_with(&format!(
                "Undid change {CHECKPOINT}: restored 1 file; now at state 0.\n"
            )),
            "{text}"
        );
        assert!(
            text.contains("not restored (excluded): /Users/u/app/node_modules"),
            "{text}"
        );
        assert!(
            text.contains("skipped (possibly torn, sqlite_journal): /Users/u/app/db"),
            "{text}"
        );
    }

    #[test]
    fn checkpoints_reads_every_page_and_lists_changes() {
        let change = |id: &str, status: &str| {
            format!(
                r#"{{"checkpoint_id":"{id}","created_at":"2026-11-19T10:00:00Z","kind":"change","attribution":"command","reverts":null,"record_ids":["{RECORD}"],"session_ids":[],"roots":[],"files_changed":2,"uncertain":false,"from":0,"to":1,"status":"{status}"}}"#
            )
        };
        let first = format!(
            r#"{{"jsonrpc":"2.0","id":2,"result":{{"head":1,"changes":[{}],"next_cursor":"{CHECKPOINT}"}}}}"#,
            change(CHECKPOINT, "in_effect")
        );
        let second = format!(
            r#"{{"jsonrpc":"2.0","id":3,"result":{{"head":1,"changes":[{}],"next_cursor":null}}}}"#,
            change("01JCZ0000000000000000000CM", "undone")
        );
        let mut written = Vec::new();
        let mut client = Client::new(Cursor::new(frames(&[HELLO_OK, &first, &second])), &mut written);
        client.hello().unwrap();
        let (changes, head) = list(&mut client, None).unwrap();
        assert_eq!((changes.len(), head), (2, 1));
        assert!(sent(&written)[2].contains(&format!(r#""cursor":"{CHECKPOINT}""#)));
        let text = list_report(&changes, head, false).unwrap();
        assert!(
            text.starts_with(&format!(
                "2026-11-19T10:00:00Z  {CHECKPOINT}  in_effect  command  2 files  0->1  {RECORD}\n"
            )),
            "{text}"
        );
        assert!(text.ends_with("Current state: 1.\n"), "{text}");
        assert_eq!(list_report(&changes, head, true).unwrap().lines().count(), 2);
        assert_eq!(
            list_report(&[], 0, false).unwrap(),
            "No checkpoints.\nCurrent state: 0.\n"
        );
    }

    // A cursor that does not advance is a protocol error, never a loop.
    #[test]
    fn a_cursor_that_does_not_advance_is_refused() {
        let page =
            format!(r#"{{"jsonrpc":"2.0","id":2,"result":{{"head":0,"changes":[],"next_cursor":"{CHECKPOINT}"}}}}"#);
        let again = page.replace(r#""id":2"#, r#""id":3"#);
        let mut written = Vec::new();
        let mut client = Client::new(Cursor::new(frames(&[HELLO_OK, &page, &again])), &mut written);
        client.hello().unwrap();
        assert!(matches!(list(&mut client, None), Err(ClientError::Protocol)));
    }

    #[test]
    fn refusals_are_explained() {
        let refused = |code: ErrorCode, data: &str| {
            let data = knsh_json::parse(data.as_bytes(), 1 << 16).unwrap();
            failure_message(
                "undo",
                &ClientError::Rpc(knsh_proto::RpcError::new(code).with_data(data)),
            )
        };
        let conflict = refused(
            ErrorCode::UndoConflict,
            r#"{"conflicts":[{"path":"/r/a\n","reason":"changed"}]}"#,
        );
        assert!(conflict.contains("nothing was restored"), "{conflict}");
        assert!(conflict.contains("/r/a\\n (changed)"), "{conflict}");
        let expired = refused(ErrorCode::InvalidParams, r#"{"reason":"expired"}"#);
        assert!(expired.contains("expired"), "{expired}");
        let unavailable = refused(ErrorCode::CapabilityUnavailable, r#"{"capability":"checkpoints"}"#);
        assert!(unavailable.contains("not available"), "{unavailable}");
    }
}
