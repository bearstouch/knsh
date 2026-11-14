//! `knsh events`: follow the engine's events live (FR-EVT, KNSH-023).
//!
//! The command subscribes with `events.subscribe` on `user.sock` and prints every event notification until it is
//! interrupted or `knshd` closes the connection. `--session <id>` follows one session; `--since <seq>` (which needs
//! `--session`, since `seq` counts one session's events) first replays that session's buffered events after `seq`.
//! Values are checked before connecting, so a mistyped command never reaches `knshd` (usage error, exit 2).
//!
//! - The human form is one line per event: `ts  session_id  #seq  event  summary`, the summary chosen per event.
//! - `--json` prints each notification's `params` (the event envelope plus `subscription_id`, the API's field names)
//!   as one JSON object per line.
//! - Events the subscription will never receive (it fell behind, FR-EVT-04) are reported in the stream itself, in
//!   order: as `{"event":"events.lost", …}` with `--json`, as a `lost` line otherwise. A resume older than the
//!   buffer (`gap`) is reported once on stderr before the events.
//!
//! Every text that came from the engine is escaped before it is printed ([`crate::cli::terminal`]).

use std::convert::Infallible;
use std::fmt;
use std::io::{self, Read, Write};

use knsh_core::SessionId;
use knsh_json::{FromJson, JsonError, Object, ToJson, Value};
use knsh_proto::{EVENTS_LOST, ErrorCode, EventsSubscribeParams, EventsSubscribeResult, Notification};

use crate::cli::args::ParsedCommand;
use crate::cli::client::{Client, ClientError};
use crate::cli::terminal::{escape_text, write_json_line};

/// The method `knsh events` calls.
pub const METHOD: &str = "events.subscribe";

/// Why a `knsh events` command line was refused before anything was sent. Exits with 2, like other usage errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UsageError {
    /// `--session` is not a canonical session ID.
    BadSession,
    /// `--since` is not a whole number.
    BadSince,
    /// `--since` was given without `--session`.
    SinceNeedsSession,
}

impl fmt::Display for UsageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadSession => f.write_str("--session must be a session ID (26 characters, as shown by knsh history)"),
            Self::BadSince => f.write_str("--since must be an event sequence number (0 or more)"),
            Self::SinceNeedsSession => {
                f.write_str("--since needs --session: sequence numbers count one session's events")
            }
        }
    }
}

impl std::error::Error for UsageError {}

/// The `events.subscribe` parameters for a parsed `knsh events` command line.
///
/// # Errors
///
/// A [`UsageError`] when a value is malformed, or `--since` comes without `--session`.
pub fn params(parsed: &ParsedCommand) -> Result<EventsSubscribeParams, UsageError> {
    let session_id = parsed
        .value("session")
        .map(|text| text.parse::<SessionId>().map_err(|_| UsageError::BadSession))
        .transpose()?;
    let since_seq = match parsed.value("since") {
        None => None,
        // Plain decimal digits only: `+5` or `-1` are refused rather than guessed at.
        Some(text) if !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit()) => {
            Some(text.parse::<u64>().map_err(|_| UsageError::BadSince)?)
        }
        Some(_) => return Err(UsageError::BadSince),
    };
    if since_seq.is_some() && session_id.is_none() {
        return Err(UsageError::SinceNeedsSession);
    }
    Ok(EventsSubscribeParams { session_id, since_seq })
}

/// Subscribes on a connected client.
///
/// # Errors
///
/// Any [`ClientError`]; [`ClientError::Protocol`] if the result is malformed.
pub fn subscribe<R: Read, W: Write>(
    client: &mut Client<R, W>,
    params: &EventsSubscribeParams,
) -> Result<EventsSubscribeResult, ClientError> {
    let Value::Object(object) = params.to_json()? else {
        return Err(ClientError::Protocol);
    };
    let result = client.call(METHOD, Some(object))?;
    EventsSubscribeResult::from_json(&result).map_err(|_| ClientError::Protocol)
}

/// The stderr notice for a resume older than the buffer: the events between `--since` and `oldest_seq` are no longer
/// buffered, so the stream cannot show them (the record store still holds their records). `None` when nothing was
/// skipped.
#[must_use]
pub fn gap_notice(params: &EventsSubscribeParams, result: &EventsSubscribeResult) -> Option<String> {
    if !result.gap {
        return None;
    }
    let after = params.since_seq.unwrap_or(0);
    Some(match result.oldest_seq {
        Some(oldest) => format!(
            "knsh: events: events after #{after} and before #{oldest} are no longer buffered; \
             see 'knsh history' for their records\n"
        ),
        None => format!("knsh: events: events after #{after} are no longer buffered\n"),
    })
}

/// Why following stopped. Following only stops on an error: the stream has no end of its own.
#[derive(Debug)]
pub enum FollowError {
    /// The connection to `knshd` failed or ended ([`ClientError::Closed`] when `knshd` stopped).
    Client(ClientError),
    /// Writing the output failed; [`io::ErrorKind::BrokenPipe`] when the reader went away (`knsh events | head`).
    Output(io::Error),
}

impl fmt::Display for FollowError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Client(error) => write!(f, "{error}"),
            Self::Output(error) => write!(f, "cannot write output: {error}"),
        }
    }
}

impl std::error::Error for FollowError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Client(error) => Some(error),
            Self::Output(error) => Some(error),
        }
    }
}

/// Prints every notification that arrives on `client` to `out`, flushing after each, until the connection or the
/// output fails. Call after [`subscribe`].
///
/// # Errors
///
/// Always, eventually: a [`FollowError`] saying why the stream stopped.
pub fn follow<R: Read, W: Write, O: Write>(
    client: &mut Client<R, W>,
    json: bool,
    out: &mut O,
) -> Result<Infallible, FollowError> {
    loop {
        let notification = client.next_notification().map_err(FollowError::Client)?;
        let line = render(&notification, json).map_err(FollowError::Client)?;
        out.write_all(line.as_bytes()).map_err(FollowError::Output)?;
        // Each event is shown as soon as it arrives, even when stdout is a pipe.
        out.flush().map_err(FollowError::Output)?;
    }
}

/// One notification as one line of output.
///
/// # Errors
///
/// [`ClientError::Protocol`] if the notification has no object `params`: every event and `events.lost` has one.
fn render(notification: &Notification, json: bool) -> Result<String, ClientError> {
    let params = notification.params.as_ref().ok_or(ClientError::Protocol)?;
    let lost = notification.method.as_str() == EVENTS_LOST;
    if json {
        let value = if lost {
            lost_json(params)?
        } else {
            Value::Object(params.clone())
        };
        Ok(write_json_line(&value)?)
    } else if lost {
        Ok(lost_line(params))
    } else {
        Ok(event_line(notification.method.as_str(), params))
    }
}

/// `events.lost` in the `--json` stream: its params with an `event` member first, so every line of the stream can be
/// told apart by the same field.
fn lost_json(params: &Object) -> Result<Value, JsonError> {
    let mut object = Object::new().with("event", EVENTS_LOST)?;
    for (key, value) in params.iter() {
        // A duplicate `event` member would make an invalid object; the engine never sends one, so it is dropped.
        if key != "event" {
            object.insert(key, value.clone())?;
        }
    }
    Ok(Value::Object(object))
}

/// `events.lost` in the human stream: which session and which `seq` range will never arrive.
fn lost_line(params: &Object) -> String {
    format!(
        "lost  {}  #{}..#{}  events this subscriber fell too far behind to receive\n",
        text(params, "session_id"),
        number(params, "from_seq"),
        number(params, "to_seq")
    )
}

/// An event in the human stream: `ts  session_id  #seq  event  summary`.
fn event_line(method: &str, params: &Object) -> String {
    let data = params.get("data").and_then(Value::as_object);
    let summary = data.map_or_else(String::new, |data| summary(method, data));
    let mut line = format!(
        "{}  {}  #{}  {}",
        text(params, "ts"),
        text(params, "session_id"),
        number(params, "seq"),
        escape_text(method)
    );
    if !summary.is_empty() {
        line.push_str("  ");
        line.push_str(&summary);
    }
    line.push('\n');
    line
}

/// The most telling part of an event's `data`, escaped. Events without a specific summary show their `data` as
/// compact JSON (nothing when it is empty), so a newer engine's events are still shown in full.
fn summary(method: &str, data: &Object) -> String {
    match method {
        "command.finished" => {
            let status = data
                .get("exit_code")
                .and_then(Value::as_i64)
                .map_or_else(|| String::from("exit -"), |code| format!("exit {code}"));
            format!("{status}  {}", text(data, "command"))
        }
        "cwd.changed" => text(data, "cwd"),
        "session.state_changed" => format!("{} -> {}", text(data, "from"), text(data, "to")),
        "session.started" => format!("profile {}", text(data, "profile")),
        _ if data.is_empty() => String::new(),
        _ => {
            knsh_json::write(&Value::Object(data.clone())).map_or_else(|_| String::from("?"), |json| escape_text(&json))
        }
    }
}

/// A string member, escaped, or `?` when missing.
fn text(object: &Object, key: &str) -> String {
    object
        .get(key)
        .and_then(Value::as_str)
        .map_or_else(|| String::from("?"), escape_text)
}

/// An integer member, or `?` when missing.
fn number(object: &Object, key: &str) -> String {
    object
        .get(key)
        .and_then(Value::as_i64)
        .map_or_else(|| String::from("?"), |n| n.to_string())
}

/// What `knsh events` prints on stderr when subscribing failed.
#[must_use]
pub fn failure_message(error: &ClientError) -> String {
    match error {
        ClientError::Rpc(rpc) if rpc.code == ErrorCode::SessionNotFound => {
            String::from("knsh: events: that session has no buffered events (never started, or ended long ago)\n")
        }
        ClientError::Rpc(rpc) if rpc.code == ErrorCode::InvalidParams => String::from(
            "knsh: events: knshd refused the subscription (--since newer than the session's latest event?)\n",
        ),
        other => format!("knsh: events failed: {other}\n"),
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

    fn event(seq: u32, name: &str, data: &str) -> String {
        format!(
            r#"{{"jsonrpc":"2.0","method":"{name}","params":{{"event":"{name}","id":"01JCZ00000000000000000E{seq:03}",
                "seq":{seq},"ts":"2026-11-12T18:02:11.204913Z","session_id":"{SESSION}",
                "actor":{{"kind":"agent","agent_id":"claude-code"}},"data":{data},"subscription_id":1}}}}"#
        )
    }

    const SUBSCRIBED: &str =
        r#"{"jsonrpc":"2.0","id":2,"result":{"subscription_id":1,"oldest_seq":1,"latest_seq":3,"gap":false}}"#;

    /// Subscribes with `argv` and follows `answers` until the connection ends; returns the output and requests.
    fn events(argv: &[&str], answers: &[String]) -> (String, Vec<String>, FollowError) {
        let mut texts: Vec<&str> = vec![HELLO_OK, SUBSCRIBED];
        texts.extend(answers.iter().map(String::as_str));
        let mut written = Vec::new();
        let mut client = Client::new(Cursor::new(frames(&texts)), &mut written);
        client.hello().unwrap();
        let parsed = parsed(argv);
        subscribe(&mut client, &params(&parsed).unwrap()).unwrap();
        let mut out = Vec::new();
        let Err(error) = follow(&mut client, parsed.json(), &mut out);
        (String::from_utf8(out).unwrap(), sent(&written), error)
    }

    // KNSH-023: values are checked before anything is sent.
    #[test]
    fn events_validates_options_before_sending() {
        assert_eq!(
            params(&parsed(&["events", "--session", "x"])),
            Err(UsageError::BadSession)
        );
        assert_eq!(
            params(&parsed(&["events", "--since", "3"])),
            Err(UsageError::SinceNeedsSession)
        );
        for bad in ["-1", "+1", "x", "99999999999999999999999"] {
            let since = format!("--since={bad}");
            assert_eq!(
                params(&parsed(&["events", "--session", SESSION, &since])),
                Err(UsageError::BadSince),
                "{bad}"
            );
        }
        assert_eq!(
            params(&parsed(&["events", "--session", SESSION, "--since", "0"])),
            Ok(EventsSubscribeParams {
                session_id: Some(SESSION.parse().unwrap()),
                since_seq: Some(0)
            })
        );
        assert_eq!(
            params(&parsed(&["events"])),
            Ok(EventsSubscribeParams {
                session_id: None,
                since_seq: None
            })
        );
    }

    // KNSH-023: --json prints one event per line, each the notification's params with the API's field names, in the
    // order they arrive, with lost events in the same stream.
    #[test]
    fn events_json_one_event_per_line() {
        let (out, requests, error) = events(
            &["events", "--session", SESSION, "--since", "1", "--json"],
            &[
                event(2, "cwd.changed", r#"{"cwd":"/tmp/a\nb"}"#),
                format!(
                    r#"{{"jsonrpc":"2.0","method":"events.lost","params":{{"subscription_id":1,"session_id":"{SESSION}","from_seq":3,"to_seq":9}}}}"#
                ),
                event(10, "session.idle", "{}"),
            ],
        );
        assert!(matches!(error, FollowError::Client(ClientError::Closed)), "{error:?}");
        assert!(
            requests[1].contains(&format!(
                r#""method":"events.subscribe","params":{{"session_id":"{SESSION}","since_seq":1}}"#
            )),
            "{}",
            requests[1]
        );
        let lines: Vec<&str> = out.split_terminator('\n').collect();
        assert_eq!(lines.len(), 3, "{out}");
        let values: Vec<Value> = lines
            .iter()
            .map(|line| knsh_json::parse(line.as_bytes(), 1 << 16).unwrap())
            .collect();
        let field = |value: &Value, key: &str| value.as_object().unwrap().get(key).cloned();
        assert_eq!(field(&values[0], "event"), Some(Value::from("cwd.changed")));
        assert_eq!(field(&values[0], "seq"), Some(Value::from(2)));
        assert_eq!(field(&values[0], "subscription_id"), Some(Value::from(1)));
        let keys: Vec<&str> = values[0].as_object().unwrap().iter().map(|(key, _)| key).collect();
        assert_eq!(
            keys,
            [
                "event",
                "id",
                "seq",
                "ts",
                "session_id",
                "actor",
                "data",
                "subscription_id"
            ]
        );
        assert_eq!(field(&values[1], "event"), Some(Value::from("events.lost")));
        assert_eq!(field(&values[1], "from_seq"), Some(Value::from(3)));
        assert_eq!(field(&values[2], "event"), Some(Value::from("session.idle")));
    }

    #[test]
    fn events_human_form_is_one_escaped_line_per_event() {
        let (out, _, _) = events(
            &["events"],
            &[
                event(
                    1,
                    "session.started",
                    r#"{"profile":"dev","envelope":true,"recording":true,"parent_session_id":null}"#,
                ),
                event(
                    2,
                    "command.finished",
                    r#"{"record_id":"01JCZ0000000000000000000A1","command":"echo \u001b[2J\u009b","cwd":"/","started_at":"2026-11-12T18:02:11Z","ended_at":"2026-11-12T18:02:11Z","exit_code":1}"#,
                ),
                event(3, "session.state_changed", r#"{"from":"active","to":"paused"}"#),
                event(4, "session.ended", "{}"),
                event(5, "future.thing", r#"{"x":"\u2066y"}"#),
            ],
        );
        let ts = "2026-11-12T18:02:11.204913Z";
        assert_eq!(
            out,
            format!(
                "{ts}  {SESSION}  #1  session.started  profile dev\n\
                 {ts}  {SESSION}  #2  command.finished  exit 1  echo \\e[2J\\u{{9b}}\n\
                 {ts}  {SESSION}  #3  session.state_changed  active -> paused\n\
                 {ts}  {SESSION}  #4  session.ended\n\
                 {ts}  {SESSION}  #5  future.thing  {{\"x\":\"\\u{{2066}}y\"}}\n"
            )
        );
        assert!(out.chars().all(|c| c == '\n' || !c.is_control()), "{out:?}");
    }

    // FR-EVT-04: lost events are reported in the human stream too, in order.
    #[test]
    fn events_human_form_reports_lost_events() {
        let (out, _, _) = events(
            &["events"],
            &[format!(
                r#"{{"jsonrpc":"2.0","method":"events.lost","params":{{"subscription_id":1,"session_id":"{SESSION}","from_seq":3,"to_seq":9}}}}"#
            )],
        );
        assert_eq!(
            out,
            format!("lost  {SESSION}  #3..#9  events this subscriber fell too far behind to receive\n")
        );
    }

    #[test]
    fn events_reports_gaps_and_failures() {
        let params = EventsSubscribeParams {
            session_id: Some(SESSION.parse().unwrap()),
            since_seq: Some(2),
        };
        let mut result = EventsSubscribeResult {
            subscription_id: knsh_core::SubscriptionId::new(1),
            oldest_seq: Some(40),
            latest_seq: Some(90),
            gap: false,
        };
        assert_eq!(gap_notice(&params, &result), None);
        result.gap = true;
        let notice = gap_notice(&params, &result).unwrap();
        assert!(notice.contains("after #2 and before #40"), "{notice}");

        // An answer instead of a notification while following is a protocol error, not an event.
        let (out, _, error) = events(&["events"], &[String::from(r#"{"jsonrpc":"2.0","id":7,"result":{}}"#)]);
        assert_eq!(out, "");
        assert!(matches!(error, FollowError::Client(ClientError::Protocol)), "{error:?}");
    }
}
