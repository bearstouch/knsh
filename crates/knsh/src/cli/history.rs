//! `knsh history`: search the recorded commands, newest first (FR-REC-08, KNSH-023).
//!
//! The command reads records through `records.query` on `user.sock`, the only way to read them. The API pages in
//! creation order (oldest first) and has no reverse order, so the command reads every matching page and keeps only
//! the newest `--limit` records in memory, then prints them newest first. The filters are the API's own:
//!
//! - `--session <id>`: one session's records;
//! - `--since <date>` / `--until <date>`: records started at or after / before an instant, each a UTC date
//!   `YYYY-MM-DD` (midnight UTC) or an engine timestamp;
//! - `--text <text>`: records whose command contains the text (case-sensitive, no wildcards);
//! - `--limit <n>`: how many of the newest matching records to print, 1 to [`MAX_LIMIT`]; [`DEFAULT_LIMIT`] when
//!   absent.
//!
//! Values are checked before connecting, so a mistyped command never reaches `knshd` (usage error, exit 2).
//!
//! Output is terminal-safe ([`crate::cli::terminal`]): a recorded command can hold any bytes, including escape
//! sequences, and is never printed raw. The human form is one line per record; `--json` prints each record object
//! exactly as the API returns it (same field names), one per line.

use std::collections::VecDeque;
use std::fmt;
use std::io::{Read, Write};

use knsh_core::{RecordId, SessionId, Timestamp};
use knsh_json::{JsonError, ToJson, Value};
use knsh_proto::{ErrorCode, MAX_RECORDS_PAGE, MAX_RECORDS_TEXT_LEN, RecordsQueryParams};

use crate::cli::args::ParsedCommand;
use crate::cli::client::{Client, ClientError};
use crate::cli::forget::parse_instant;
use crate::cli::terminal::{escape_text, write_json_line};

/// The method `knsh history` calls.
pub const METHOD: &str = "records.query";

/// How many records `knsh history` prints without `--limit`.
pub const DEFAULT_LIMIT: usize = 100;

/// The largest `--limit`: bounds how many records the command holds in memory at once.
pub const MAX_LIMIT: usize = 100_000;

/// Why a `knsh history` command line was refused before anything was sent. Exits with 2, like other usage errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UsageError {
    /// `--session` is not a canonical session ID.
    BadSession,
    /// `--since` is neither a date nor an engine timestamp.
    BadSince,
    /// `--until` is neither a date nor an engine timestamp.
    BadUntil,
    /// `--text` is longer than the API accepts.
    TextTooLong,
    /// `--limit` is not a whole number from 1 to [`MAX_LIMIT`].
    BadLimit,
}

impl fmt::Display for UsageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadSession => f.write_str("--session must be a session ID (26 characters, as shown by knsh history)"),
            Self::BadSince => {
                f.write_str("--since must be a UTC date (YYYY-MM-DD) or timestamp (YYYY-MM-DDTHH:MM:SSZ)")
            }
            Self::BadUntil => {
                f.write_str("--until must be a UTC date (YYYY-MM-DD) or timestamp (YYYY-MM-DDTHH:MM:SSZ)")
            }
            Self::TextTooLong => write!(f, "--text must be at most {MAX_RECORDS_TEXT_LEN} bytes"),
            Self::BadLimit => write!(f, "--limit must be a whole number from 1 to {MAX_LIMIT}"),
        }
    }
}

impl std::error::Error for UsageError {}

/// A validated `knsh history` command line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Query {
    /// The filters, as sent on every page. `limit` is the page size and `cursor` is advanced by [`run`].
    pub filters: RecordsQueryParams,
    /// How many of the newest matching records to print.
    pub limit: usize,
}

/// The query for a parsed `knsh history` command line.
///
/// # Errors
///
/// A [`UsageError`] when a value is malformed or out of range.
pub fn query(parsed: &ParsedCommand) -> Result<Query, UsageError> {
    let session_id = parsed
        .value("session")
        .map(|text| text.parse::<SessionId>().map_err(|_| UsageError::BadSession))
        .transpose()?;
    let since = instant(parsed.value("since"), UsageError::BadSince)?;
    let until = instant(parsed.value("until"), UsageError::BadUntil)?;
    let text = parsed.value("text").map(str::to_owned);
    if text.as_ref().is_some_and(|text| text.len() > MAX_RECORDS_TEXT_LEN) {
        return Err(UsageError::TextTooLong);
    }
    let limit = match parsed.value("limit") {
        None => DEFAULT_LIMIT,
        // Plain decimal digits only: `+5`, `0x10` and whitespace are refused rather than guessed at.
        Some(text) if !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit()) => {
            text.parse::<usize>().map_err(|_| UsageError::BadLimit)?
        }
        Some(_) => return Err(UsageError::BadLimit),
    };
    if !(1..=MAX_LIMIT).contains(&limit) {
        return Err(UsageError::BadLimit);
    }
    Ok(Query {
        filters: RecordsQueryParams {
            session_id,
            since,
            until,
            text,
            // The fewest round trips: the newest records are on the last pages.
            limit: MAX_RECORDS_PAGE,
            cursor: None,
        },
        limit,
    })
}

/// An optional date-or-time value; `error` if it is given but malformed.
fn instant(text: Option<&str>, error: UsageError) -> Result<Option<Timestamp>, UsageError> {
    text.map(|text| parse_instant(text).ok_or(error)).transpose()
}

/// Reads every page of `query` on a connected client and returns the newest `query.limit` records, newest first, as
/// the API's record objects.
///
/// # Errors
///
/// Any [`ClientError`]; [`ClientError::Protocol`] if a page is malformed or its cursor does not move forward (which
/// would otherwise loop forever).
pub fn run<R: Read, W: Write>(client: &mut Client<R, W>, query: &Query) -> Result<Vec<Value>, ClientError> {
    let mut params = query.filters.clone();
    // A ring of the newest records seen so far: pages arrive oldest first, so older ones fall off the front.
    let mut newest: VecDeque<Value> = VecDeque::with_capacity(query.limit.min(DEFAULT_LIMIT));
    loop {
        let Value::Object(object) = params.to_json()? else {
            return Err(ClientError::Protocol);
        };
        let page = client.call(METHOD, Some(object))?;
        let page = page.as_object().ok_or(ClientError::Protocol)?;
        let records = page
            .get("records")
            .and_then(Value::as_array)
            .ok_or(ClientError::Protocol)?;
        for record in records {
            // Records are objects; anything else is a malformed answer, not something to print.
            if record.as_object().is_none() {
                return Err(ClientError::Protocol);
            }
            if newest.len() == query.limit {
                newest.pop_front();
            }
            newest.push_back(record.clone());
        }
        match page.get("next_cursor") {
            Some(Value::Null) => break,
            Some(Value::String(text)) => {
                let next = text.parse::<RecordId>().map_err(|_| ClientError::Protocol)?;
                // Cursors are record IDs and pages follow creation order: a cursor that does not advance would
                // return the same page again forever.
                if params.cursor.is_some_and(|previous| next <= previous) {
                    return Err(ClientError::Protocol);
                }
                params.cursor = Some(next);
            }
            _ => return Err(ClientError::Protocol),
        }
    }
    Ok(newest.into_iter().rev().collect())
}

/// What `knsh history` prints for `records` (already newest first): one line per record.
///
/// The human form is `started_at  session_id  actor  status  command`, where `actor` is `human` or
/// `agent:<agent_id>` and `status` is `exit <n>`, `signal <n>`, or `-` while unknown (still running, or killed before
/// an exit status was recorded). With `--json` each record is the API's object, unchanged except for escaping.
///
/// # Errors
///
/// [`JsonError::TooDeep`] if a record nests deeper than the strict profile allows (it cannot, coming from the API).
pub fn report(records: &[Value], json: bool) -> Result<String, JsonError> {
    let mut out = String::new();
    for record in records {
        if json {
            out.push_str(&write_json_line(record)?);
        } else {
            out.push_str(&human_line(record));
        }
    }
    Ok(out)
}

/// One record in the human form, every field escaped ([`escape_text`]). A field missing from the record shows as `?`.
fn human_line(record: &Value) -> String {
    let field = |name: &str| record.as_object().and_then(|object| object.get(name));
    let text = |name: &str| {
        field(name)
            .and_then(Value::as_str)
            .map_or_else(|| String::from("?"), escape_text)
    };
    let actor = match field("actor").and_then(Value::as_object) {
        Some(actor) => match (
            actor.get("kind").and_then(Value::as_str),
            actor.get("agent_id").and_then(Value::as_str),
        ) {
            (Some(kind), Some(agent_id)) => format!("{}:{}", escape_text(kind), escape_text(agent_id)),
            (Some(kind), None) => escape_text(kind),
            (None, _) => String::from("?"),
        },
        None => String::from("?"),
    };
    let status = if let Some(code) = field("exit_code").and_then(Value::as_i64) {
        format!("exit {code}")
    } else if let Some(signal) = field("signal").and_then(Value::as_i64) {
        format!("signal {signal}")
    } else {
        String::from("-")
    };
    format!(
        "{}  {}  {actor}  {status}  {}\n",
        text("started_at"),
        text("session_id"),
        text("command")
    )
}

/// What `knsh history` prints on stderr when the query failed.
#[must_use]
pub fn failure_message(error: &ClientError) -> String {
    match error {
        ClientError::Rpc(rpc) if rpc.code == ErrorCode::InvalidParams => {
            String::from("knsh: history: knshd refused the filters\n")
        }
        other => format!("knsh: history failed: {other}\n"),
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

    /// A record as `records.query` returns it (a human record: no agent-only fields).
    fn record(id: &str, command: &str) -> String {
        let command = knsh_json::write(&Value::from(command)).unwrap();
        format!(
            r#"{{"record_id":"{id}","session_id":"{SESSION}","actor":{{"kind":"human"}},"command":{command},
                "cwd":"/tmp","started_at":"2026-11-12T18:02:11.204913Z","ended_at":"2026-11-12T18:02:12.000000Z",
                "exit_code":0,"stdout":null,"stderr":null}}"#
        )
    }

    fn page(id: u32, records: &[String], next: Option<&str>) -> String {
        let next = next.map_or_else(|| String::from("null"), |cursor| format!(r#""{cursor}""#));
        format!(
            r#"{{"jsonrpc":"2.0","id":{id},"result":{{"records":[{}],"next_cursor":{next}}}}}"#,
            records.join(",")
        )
    }

    /// Runs `argv` against `answers` (after the handshake) and returns the records and the requests sent.
    fn history(argv: &[&str], answers: &[String]) -> (Result<Vec<Value>, ClientError>, Vec<String>) {
        let mut texts: Vec<&str> = vec![HELLO_OK];
        texts.extend(answers.iter().map(String::as_str));
        let mut written = Vec::new();
        let mut client = Client::new(Cursor::new(frames(&texts)), &mut written);
        client.hello().unwrap();
        let outcome = run(&mut client, &query(&parsed(argv)).unwrap());
        (outcome, sent(&written))
    }

    // KNSH-023: values are checked before anything is sent.
    #[test]
    fn history_validates_filters_before_sending() {
        assert_eq!(
            query(&parsed(&["history", "--session", "x"])),
            Err(UsageError::BadSession)
        );
        assert_eq!(
            query(&parsed(&["history", "--since", "today"])),
            Err(UsageError::BadSince)
        );
        assert_eq!(
            query(&parsed(&["history", "--until", "2026-13-01"])),
            Err(UsageError::BadUntil)
        );
        for bad in ["0", "-1", "+5", "abc", "100001", "99999999999999999999999"] {
            let argv = format!("--limit={bad}");
            assert_eq!(query(&parsed(&["history", &argv])), Err(UsageError::BadLimit), "{bad}");
        }
        let long = "a".repeat(MAX_RECORDS_TEXT_LEN + 1);
        assert_eq!(
            query(&parsed(&["history", "--text", &long])),
            Err(UsageError::TextTooLong)
        );

        let all = query(&parsed(&[
            "history",
            "--session",
            SESSION,
            "--since",
            "2026-11-01",
            "--until=2026-11-02T10:00:00Z",
            "--text",
            "git",
            "--limit",
            "5",
        ]))
        .unwrap();
        assert_eq!(all.limit, 5);
        assert_eq!(all.filters.session_id, Some(SESSION.parse().unwrap()));
        assert_eq!(all.filters.since, Some("2026-11-01T00:00:00Z".parse().unwrap()));
        assert_eq!(all.filters.until, Some("2026-11-02T10:00:00Z".parse().unwrap()));
        assert_eq!(all.filters.text.as_deref(), Some("git"));
        assert_eq!(query(&parsed(&["history"])).unwrap().limit, DEFAULT_LIMIT);
    }

    // KNSH-023: every page is read with the filters, and the newest records are printed first.
    #[test]
    fn history_lists_newest_first_across_pages() {
        let ids = [
            "01JCZ0000000000000000000A1",
            "01JCZ0000000000000000000A2",
            "01JCZ0000000000000000000A3",
        ];
        let (records, requests) = history(
            &["history", "--session", SESSION, "--text", "echo", "--limit", "2"],
            &[
                page(2, &[record(ids[0], "echo 1"), record(ids[1], "echo 2")], Some(ids[1])),
                page(3, &[record(ids[2], "echo 3")], None),
            ],
        );
        let records = records.unwrap();
        let commands: Vec<_> = records
            .iter()
            .map(|r| r.as_object().unwrap().get("command").unwrap().as_str().unwrap())
            .collect();
        assert_eq!(commands, ["echo 3", "echo 2"], "newest first, at most --limit");
        assert!(requests[1].contains(r#""method":"records.query""#), "{}", requests[1]);
        assert!(
            requests[1].contains(&format!(r#""session_id":"{SESSION}","text":"echo","limit":1000"#)),
            "{}",
            requests[1]
        );
        assert!(!requests[1].contains("cursor"), "{}", requests[1]);
        assert!(
            requests[2].contains(&format!(r#""cursor":"{}""#, ids[1])),
            "{}",
            requests[2]
        );
    }

    // A cursor that does not advance would loop forever; it is a protocol error instead.
    #[test]
    fn history_rejects_a_cursor_that_does_not_advance() {
        let id = "01JCZ0000000000000000000A1";
        let (outcome, _) = history(
            &["history"],
            &[
                page(2, &[record(id, "a")], Some(id)),
                page(3, &[record(id, "a")], Some(id)),
            ],
        );
        assert!(matches!(outcome, Err(ClientError::Protocol)), "{outcome:?}");
        let (outcome, _) = history(
            &["history"],
            &[String::from(
                r#"{"jsonrpc":"2.0","id":2,"result":{"records":[1],"next_cursor":null}}"#,
            )],
        );
        assert!(matches!(outcome, Err(ClientError::Protocol)), "{outcome:?}");
    }

    // KNSH-023, FR-REC-08: --json prints each record with the API's field names, one object per line.
    #[test]
    fn history_json_uses_api_field_names() {
        let ids = ["01JCZ0000000000000000000A1", "01JCZ0000000000000000000A2"];
        let (records, _) = history(
            &["history", "--json"],
            &[page(2, &[record(ids[0], "ls"), record(ids[1], "pwd")], None)],
        );
        let text = report(&records.unwrap(), true).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2, "{text}");
        for (line, id) in lines.iter().zip([ids[1], ids[0]]) {
            let value = knsh_json::parse(line.as_bytes(), 1 << 16).unwrap();
            let object = value.as_object().unwrap();
            let keys: Vec<&str> = object.iter().map(|(key, _)| key).collect();
            assert_eq!(
                keys,
                [
                    "record_id",
                    "session_id",
                    "actor",
                    "command",
                    "cwd",
                    "started_at",
                    "ended_at",
                    "exit_code",
                    "stdout",
                    "stderr"
                ]
            );
            assert_eq!(object.get("record_id").unwrap().as_str(), Some(id));
        }
    }

    // KNSH-023: a recorded command holding terminal sequences is never printed raw, in either form.
    #[test]
    fn history_escapes_control_characters() {
        let id = "01JCZ0000000000000000000A1";
        let hostile = "echo hi\u{1b}]52;c;cm0gLXJmIH4=\u{7}\u{1b}[2J\rrm\u{9b}0m\u{202e}\nnext";
        let (records, _) = history(&["history"], &[page(2, &[record(id, hostile)], None)]);
        let records = records.unwrap();

        let human = report(&records, false).unwrap();
        assert_eq!(human.lines().count(), 1, "one record, one line: {human:?}");
        assert!(human.chars().all(|c| c == '\n' || !c.is_control()), "{human:?}");
        assert!(!human.contains('\u{202e}'), "{human:?}");
        assert_eq!(
            human,
            format!(
                "2026-11-12T18:02:11.204913Z  {SESSION}  human  exit 0  \
                 echo hi\\e]52;c;cm0gLXJmIH4=\\x07\\e[2J\\rrm\\u{{9b}}0m\\u{{202e}}\\nnext\n"
            )
        );

        let json = report(&records, true).unwrap();
        let body = json.strip_suffix('\n').unwrap();
        assert!(body.chars().all(|c| !c.is_control() && c != '\u{202e}'), "{json:?}");
        let value = knsh_json::parse(body.as_bytes(), 1 << 16).unwrap();
        assert_eq!(
            value.as_object().unwrap().get("command").unwrap().as_str(),
            Some(hostile),
            "escaping loses nothing"
        );
    }

    #[test]
    fn history_human_form_shows_agents_and_status() {
        let agent = Value::from(
            knsh_json::Object::new()
                .with("record_id", "01JCZ0000000000000000000A1")
                .unwrap()
                .with("session_id", SESSION)
                .unwrap()
                .with(
                    "actor",
                    knsh_json::Object::new()
                        .with("kind", "agent")
                        .unwrap()
                        .with("agent_id", "claude-code")
                        .unwrap(),
                )
                .unwrap()
                .with("command", "sleep 9")
                .unwrap()
                .with("started_at", "2026-11-12T18:02:11.204913Z")
                .unwrap()
                .with("exit_code", Value::Null)
                .unwrap()
                .with("signal", 9)
                .unwrap(),
        );
        assert_eq!(
            report(&[agent], false).unwrap(),
            format!("2026-11-12T18:02:11.204913Z  {SESSION}  agent:claude-code  signal 9  sleep 9\n")
        );
        assert_eq!(human_line(&Value::Null), "?  ?  ?  -  ?\n");
    }
}
