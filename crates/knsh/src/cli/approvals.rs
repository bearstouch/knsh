//! `knsh approvals`, `knsh approve <request_id>` and `knsh deny <request_id>`: answer pending asks from a terminal when
//! no authority app is connected (KNSH-066; FR-AUTH-40 to FR-AUTH-43, `specs/06-api/cli.md#approvals`).
//!
//! - `knsh approvals` lists every pending ask through `approval.list` on `user.sock`: one block per request with its
//!   ID, session, agent, matched rule, when it times out, and the redacted command and its directory.
//! - `knsh approve <id>` sends `approval.approve`. `knshd` then shows the system Touch ID or password prompt itself,
//!   naming the exact command; the CLI only says so on stderr and waits. It has no way to claim the user is present
//!   (FR-AUTH-42): no option, no answer of its own.
//! - `knsh deny <id>` sends `approval.deny`; no prompt.
//!
//! None of these ever asks a yes/no question on a terminal (FR-AUTH-43): the decision is the system prompt's, and an
//! agent inside an envelope cannot reach `user.sock` at all.
//!
//! The request ID is checked before connecting (usage error, exit 2). Output is terminal-safe
//! ([`crate::cli::terminal`]): a command can hold any characters, including escape sequences, and is never printed
//! raw. `--json` prints the API's objects, one per line.

use std::fmt::{self, Write as _};
use std::io::{Read, Write};

use knsh_core::RequestId;
use knsh_json::{FromJson, ToJson, Value};
use knsh_proto::{
    ApprovalAnswerParams, ApprovalAnswerResult, ApprovalListParams, ApprovalListResult, ApprovalVerdict, Denial,
    ErrorCode, PendingApproval,
};

use crate::cli::args::ParsedCommand;
use crate::cli::client::{Client, ClientError};
use crate::cli::terminal::{escape_text, write_json_line};

/// The method `knsh approvals` calls.
pub const LIST_METHOD: &str = "approval.list";
/// The method `knsh approve` calls.
pub const APPROVE_METHOD: &str = "approval.approve";
/// The method `knsh deny` calls.
pub const DENY_METHOD: &str = "approval.deny";

/// How a request is answered from the command line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Answer {
    /// `knsh approve`: after `knshd`'s prompt.
    Approve,
    /// `knsh deny`.
    Deny,
}

impl Answer {
    /// The method sent.
    #[must_use]
    pub const fn method(self) -> &'static str {
        match self {
            Self::Approve => APPROVE_METHOD,
            Self::Deny => DENY_METHOD,
        }
    }

    /// The command's name, for messages.
    #[must_use]
    pub const fn command(self) -> &'static str {
        match self {
            Self::Approve => "approve",
            Self::Deny => "deny",
        }
    }
}

/// A `knsh approve` or `knsh deny` command line refused before anything was sent (exit 2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UsageError {
    /// The request ID is not a canonical ULID.
    BadRequestId,
}

impl fmt::Display for UsageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadRequestId => f.write_str("the request ID must be 26 characters, as shown by 'knsh approvals'"),
        }
    }
}

impl std::error::Error for UsageError {}

/// The request named on the command line.
///
/// # Errors
///
/// [`UsageError::BadRequestId`] for anything but a canonical request ID.
pub fn request_id(parsed: &ParsedCommand) -> Result<RequestId, UsageError> {
    parsed
        .positionals
        .first()
        .and_then(|text| text.parse().ok())
        .ok_or(UsageError::BadRequestId)
}

/// Sends `approval.list` and returns the pending requests.
///
/// # Errors
///
/// Any [`ClientError`]; [`ClientError::Protocol`] if the answer is not a list.
pub fn list<R: Read, W: Write>(client: &mut Client<R, W>) -> Result<ApprovalListResult, ClientError> {
    let Value::Object(params) = ApprovalListParams.to_json()? else {
        return Err(ClientError::Protocol);
    };
    let result = client.call(LIST_METHOD, Some(params))?;
    ApprovalListResult::from_json(&result).map_err(|_| ClientError::Protocol)
}

/// Sends `approval.approve` or `approval.deny` for `request_id`. An approval blocks while `knshd` shows its prompt.
///
/// # Errors
///
/// Any [`ClientError`]; [`ClientError::Protocol`] if the answer is not an answer result.
pub fn answer<R: Read, W: Write>(
    client: &mut Client<R, W>,
    how: Answer,
    request_id: RequestId,
) -> Result<ApprovalAnswerResult, ClientError> {
    let Value::Object(params) = ApprovalAnswerParams { request_id }.to_json()? else {
        return Err(ClientError::Protocol);
    };
    let result = client.call(how.method(), Some(params))?;
    ApprovalAnswerResult::from_json(&result).map_err(|_| ClientError::Protocol)
}

/// What `knsh approvals` prints: a block per request, or one JSON object per line with `--json`.
///
/// # Errors
///
/// A request that cannot be written as JSON (never for a parsed answer).
pub fn list_report(result: &ApprovalListResult, json: bool) -> Result<String, knsh_json::JsonError> {
    if json {
        let mut out = String::new();
        for request in &result.requests {
            out.push_str(&write_json_line(&request.to_json()?)?);
        }
        return Ok(out);
    }
    if result.requests.is_empty() {
        return Ok(String::from("No pending asks.\n"));
    }
    Ok(result.requests.iter().map(entry).collect())
}

/// One request, for people: what is asked, by whom, why, and until when; then the line itself.
fn entry(request: &PendingApproval) -> String {
    let agent = request.actor.agent_id().map_or("human", |id| id.as_str());
    let why = match (&request.matched_rule, &request.hook) {
        (Some(rule), _) => format!("rule {}", escape_text(rule)),
        (None, Some(hook)) => format!("hook {}", escape_text(hook)),
        (None, None) => String::from("policy"),
    };
    let irreversible = match &request.irreversible {
        Some(flag) if flag.value => "  irreversible",
        Some(_) | None => "",
    };
    let mut text = format!(
        "{}  session {}  agent {}  {why}  times out {}{irreversible}\n    $ {}\n    in {}\n",
        request.request_id,
        request.session_id,
        escape_text(agent),
        request.timeout_at,
        escape_text(&request.command),
        escape_text(&request.cwd)
    );
    if let Some(from) = &request.rewritten_from {
        // Writing to a String cannot fail.
        let _ = writeln!(text, "    rewritten from: {}", escape_text(from));
    }
    text
}

/// The line printed before `approval.approve` is sent: where to confirm. Never a question on this terminal
/// (FR-AUTH-43).
#[must_use]
pub fn confirm_notice(request_id: RequestId) -> String {
    format!(
        "knsh: approve: confirm with Touch ID or your password on the Mac's screen; the prompt names the command \
         of request {request_id}\n"
    )
}

/// What `knsh approve` and `knsh deny` print on success: a sentence, or the result object with `--json`.
#[must_use]
pub fn answer_report(result: &ApprovalAnswerResult, json: bool) -> String {
    if json {
        let text = result
            .to_json()
            .and_then(|value| knsh_json::write(&value))
            .unwrap_or_else(|_| String::from(r#"{"request_id":null,"verdict":null}"#));
        return format!("{text}\n");
    }
    match result.verdict {
        ApprovalVerdict::Allow => format!("Approved request {}.\n", result.request_id),
        ApprovalVerdict::Deny => format!("Denied request {}.\n", result.request_id),
    }
}

/// What the commands print on stderr when a call failed.
#[must_use]
pub fn failure_message(command: &str, error: &ClientError) -> String {
    match error {
        ClientError::Rpc(rpc) if rpc.code == ErrorCode::Denied => {
            let reason = Denial::from_error(rpc)
                .and_then(|denial| denial.reason)
                .unwrap_or_else(|| String::from("not authenticated"));
            format!("knsh: {command}: not approved: {}\n", escape_text(&reason))
        }
        ClientError::Rpc(rpc) if rpc.code == ErrorCode::DecisionTimeout => {
            format!("knsh: {command}: the request has already timed out and was denied\n")
        }
        ClientError::Rpc(rpc) if rpc.code == ErrorCode::Cancelled => {
            format!("knsh: {command}: the request was cancelled: the agent's command is no longer waiting\n")
        }
        ClientError::Rpc(rpc) if rpc.code == ErrorCode::InvalidParams => {
            let reason = rpc
                .data
                .as_ref()
                .and_then(Value::as_object)
                .and_then(|data| data.get("reason"))
                .and_then(Value::as_str)
                .unwrap_or("knshd refused the request ID");
            format!("knsh: {command}: {}\n", escape_text(reason))
        }
        other => format!("knsh: {command} failed: {other}\n"),
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use knsh_core::{Actor, AgentId, SessionId, Timestamp, Ulid};
    use knsh_proto::RpcError;

    use super::*;
    use crate::cli::args::{self, Invocation};
    use crate::cli::client::tests::{HELLO_OK, frames, sent};
    use crate::cli::commands::KNSH;

    const ID: &str = "01MCC5RM00040G2081040G2081";

    fn parsed(argv: &[&str]) -> Result<ParsedCommand, args::ArgsError> {
        let argv = std::iter::once("knsh").chain(argv.iter().copied()).map(Into::into);
        args::parse(&KNSH, argv).map(|invocation| match invocation {
            Invocation::Command(parsed) => parsed,
            other => panic!("{other:?}"),
        })
    }

    fn pending(command: &str) -> PendingApproval {
        PendingApproval {
            request_id: ID.parse().unwrap(),
            session_id: SessionId::from_ulid(Ulid::from_u128(7)),
            actor: Actor::Agent(AgentId::new("claude-code").unwrap()),
            command: command.to_owned(),
            rewritten_from: None,
            cwd: "/Users/me/app".to_owned(),
            matched_rule: Some("exec.ask[0]".to_owned()),
            hook: None,
            irreversible: None,
            timeout_at: Timestamp::from_unix_micros(1_800_000_090_000_000).unwrap(),
        }
    }

    // FR-AUTH-41: approve and deny take exactly one request ID, checked before anything is sent.
    #[test]
    fn approve_and_deny_take_one_valid_request_id() {
        for command in ["approve", "deny"] {
            let ok = parsed(&[command, ID]).unwrap();
            assert_eq!(ok.path, [command]);
            assert_eq!(request_id(&ok).unwrap().to_string(), ID);
            assert!(parsed(&[command]).is_err(), "the request ID is required");
            let bad = parsed(&[command, "not-an-id"]).unwrap();
            assert_eq!(request_id(&bad), Err(UsageError::BadRequestId));
        }
        assert_eq!(parsed(&["approvals"]).unwrap().positionals, Vec::<String>::new());
    }

    // FR-AUTH-42: the approval names only the request; nothing claims the user is present.
    #[test]
    fn approve_sends_only_the_request_id() {
        let answer_frame = format!(r#"{{"jsonrpc":"2.0","id":2,"result":{{"request_id":"{ID}","verdict":"allow"}}}}"#);
        let mut written = Vec::new();
        let mut client = Client::new(Cursor::new(frames(&[HELLO_OK, &answer_frame])), &mut written);
        client.hello().unwrap();
        let result = answer(&mut client, Answer::Approve, ID.parse().unwrap()).unwrap();
        assert_eq!(result.verdict, ApprovalVerdict::Allow);
        let texts = sent(&written);
        assert!(
            texts[1].contains(&format!(
                r#""method":"approval.approve","params":{{"request_id":"{ID}"}}"#
            )),
            "{}",
            texts[1]
        );
        assert_eq!(answer_report(&result, false), format!("Approved request {ID}.\n"));
    }

    // FR-AUTH-40: the listing shows the ID, session, agent, rule, timeout and the command, escaped for the terminal.
    #[test]
    fn lists_pending_requests_safely() {
        let list = ApprovalListResult {
            requests: vec![pending("git push\u{1b}[2J")],
        };
        let text = list_report(&list, false).unwrap();
        assert!(text.starts_with(ID), "{text}");
        for part in [
            "agent claude-code",
            "rule exec.ask[0]",
            "times out 2027-01-15T08:01:30.000000Z",
            "in /Users/me/app",
        ] {
            assert!(text.contains(part), "{part} in {text}");
        }
        assert!(!text.contains('\u{1b}'), "never printed raw: {text:?}");
        assert_eq!(
            list_report(&ApprovalListResult::default(), false).unwrap(),
            "No pending asks.\n"
        );
        let json = list_report(&list, true).unwrap();
        assert_eq!(json.lines().count(), 1);
        assert!(json.contains(r#""matched_rule":"exec.ask[0]""#), "{json}");
    }

    #[test]
    fn explains_refusals() {
        let denied = Denial {
            rule_id: None,
            reason: Some("not authenticated: cancelled".to_owned()),
            source: Some("user".to_owned()),
        }
        .to_error()
        .unwrap();
        assert_eq!(
            failure_message("approve", &ClientError::Rpc(denied)),
            "knsh: approve: not approved: not authenticated: cancelled\n"
        );
        let timed_out = ClientError::Rpc(RpcError::new(ErrorCode::DecisionTimeout));
        assert!(failure_message("approve", &timed_out).contains("timed out"));
        let cancelled = ClientError::Rpc(RpcError::new(ErrorCode::Cancelled));
        assert!(failure_message("deny", &cancelled).contains("cancelled"));
        assert!(confirm_notice(ID.parse().unwrap()).contains("on the Mac's screen"));
    }
}
