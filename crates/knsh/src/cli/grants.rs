//! `knsh policy grant`, `knsh policy grants` and `knsh policy revoke`: make, list and revoke grants from a terminal,
//! without an authority app (KNSH-073; FR-POL-60 to FR-POL-62, NFR-SEC-04, `specs/06-api/cli.md#grants`).
//!
//! - `knsh policy grant (--session <id> | --profile <name>) --for <duration> <rule>` sends `policy.grant` on
//!   `user.sock`. `knshd` checks the grant, then shows the Touch ID or password prompt itself, naming the rule, the
//!   scope and the duration; the CLI only says so on stderr and waits. It has no way to claim the user is present:
//!   no option, no answer of its own.
//! - `knsh policy grants` lists every live grant (`policy.grants`), the authority's and the user's alike.
//! - `knsh policy revoke <grant_id>` removes one at once (`policy.revoke`). No prompt: a revocation only removes a
//!   permission.
//!
//! Everything `knshd` would refuse for its shape is checked here first, so a mistyped command is a usage error (exit
//! 2) and no prompt appears for it: exactly one of `--session` and `--profile`, a canonical session or grant ID, a
//! valid profile name, a rule of 1 to 4096 bytes, and a duration of 1 s to 30 days. Whether the rule is a command
//! pattern is `knshd`'s to decide (`-32602`). Rules are printed terminal-safe ([`crate::cli::terminal`]).

use std::fmt::{self, Write as _};
use std::io::{Read, Write};

use knsh_core::{GrantId, ProfileName, SessionId};
use knsh_json::{FromJson, ToJson, Value};
use knsh_proto::{
    Denial, ErrorCode, GrantEntry, GrantTargetParam, MAX_GRANT_DURATION_S, MAX_GRANT_RULE_LEN, NoParams,
    PolicyGrantParams, PolicyGrantResult, PolicyGrantsResult, PolicyRevokeParams, PolicyRevokeResult,
    grant_duration_text,
};

use crate::cli::args::ParsedCommand;
use crate::cli::client::{Client, ClientError};
use crate::cli::terminal::{escape_text, write_json_line};

/// The method `knsh policy grant` calls.
pub const GRANT_METHOD: &str = "policy.grant";
/// The method `knsh policy grants` calls.
pub const LIST_METHOD: &str = "policy.grants";
/// The method `knsh policy revoke` calls.
pub const REVOKE_METHOD: &str = "policy.revoke";

/// A `knsh policy grant` or `knsh policy revoke` command line refused before anything was sent (exit 2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UsageError {
    /// Neither or both of `--session` and `--profile`.
    Scope,
    /// `--session` is not a canonical session ID.
    BadSession,
    /// `--profile` is not a valid profile name.
    BadProfile,
    /// `--for` is not a duration of 1 s to 30 days.
    BadDuration,
    /// The rule is empty or longer than 4096 bytes.
    BadRule,
    /// The grant ID is not a canonical ULID.
    BadGrantId,
}

impl fmt::Display for UsageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Scope => f.write_str("grant needs exactly one of --session <id> and --profile <name>"),
            Self::BadSession => f.write_str("--session must be a session ID (26 characters, as shown by knsh history)"),
            Self::BadProfile => f.write_str("the profile name must be 1 to 64 characters from A-Z a-z 0-9 . _ -"),
            Self::BadDuration => {
                f.write_str("--for must be a duration from 1s to 30d: a number with s, m, h or d (seconds if none)")
            }
            Self::BadRule => f.write_str("the rule must be 1 to 4096 bytes, quoted as one argument"),
            Self::BadGrantId => f.write_str("the grant ID must be 26 characters, as shown by 'knsh policy grants'"),
        }
    }
}

impl std::error::Error for UsageError {}

/// The `policy.grant` parameters for a parsed `knsh policy grant` command line.
///
/// # Errors
///
/// A [`UsageError`] for anything `knshd` would refuse for its shape.
pub fn grant_params(parsed: &ParsedCommand) -> Result<PolicyGrantParams, UsageError> {
    let target = match (parsed.value("session"), parsed.value("profile")) {
        (Some(session), None) => {
            GrantTargetParam::Session(session.parse::<SessionId>().map_err(|_| UsageError::BadSession)?)
        }
        (None, Some(profile)) => {
            GrantTargetParam::Profile(ProfileName::new(profile).map_err(|_| UsageError::BadProfile)?)
        }
        _ => return Err(UsageError::Scope),
    };
    let duration_s = parsed
        .value("for")
        .and_then(parse_duration)
        .ok_or(UsageError::BadDuration)?;
    let rule = parsed.positionals.first().ok_or(UsageError::BadRule)?;
    if rule.is_empty() || rule.len() > MAX_GRANT_RULE_LEN {
        return Err(UsageError::BadRule);
    }
    Ok(PolicyGrantParams {
        target,
        rule: rule.clone(),
        duration_s,
    })
}

/// Reads `--for`: a whole number of seconds (`90`, `90s`), minutes (`m`), hours (`h`) or days (`d`), from 1 s to
/// 30 days. `None` for anything else, including a sign, a space or a fraction.
#[must_use]
pub fn parse_duration(text: &str) -> Option<u64> {
    let (digits, unit) = match text.char_indices().last()? {
        (at, unit @ ('s' | 'm' | 'h' | 'd')) => (&text[..at], unit),
        _ => (text, 's'),
    };
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let scale = match unit {
        'm' => 60,
        'h' => 3_600,
        'd' => 86_400,
        _ => 1,
    };
    let seconds = digits.parse::<u64>().ok()?.checked_mul(scale)?;
    (1..=MAX_GRANT_DURATION_S).contains(&seconds).then_some(seconds)
}

/// The grant named on a `knsh policy revoke` command line.
///
/// # Errors
///
/// [`UsageError::BadGrantId`] for anything but a canonical grant ID.
pub fn grant_id(parsed: &ParsedCommand) -> Result<GrantId, UsageError> {
    parsed
        .positionals
        .first()
        .and_then(|text| text.parse().ok())
        .ok_or(UsageError::BadGrantId)
}

/// Sends `policy.grant`. Blocks while `knshd` shows its prompt.
///
/// # Errors
///
/// Any [`ClientError`]; [`ClientError::Protocol`] if the answer is not a grant result.
pub fn grant<R: Read, W: Write>(
    client: &mut Client<R, W>,
    params: &PolicyGrantParams,
) -> Result<PolicyGrantResult, ClientError> {
    let Value::Object(params) = params.to_json()? else {
        return Err(ClientError::Protocol);
    };
    let result = client.call(GRANT_METHOD, Some(params))?;
    PolicyGrantResult::from_json(&result).map_err(|_| ClientError::Protocol)
}

/// Sends `policy.grants`.
///
/// # Errors
///
/// Any [`ClientError`]; [`ClientError::Protocol`] if the answer is not a list.
pub fn list<R: Read, W: Write>(client: &mut Client<R, W>) -> Result<PolicyGrantsResult, ClientError> {
    let Value::Object(params) = NoParams.to_json()? else {
        return Err(ClientError::Protocol);
    };
    let result = client.call(LIST_METHOD, Some(params))?;
    PolicyGrantsResult::from_json(&result).map_err(|_| ClientError::Protocol)
}

/// Sends `policy.revoke` for `grant_id`.
///
/// # Errors
///
/// Any [`ClientError`]; [`ClientError::Protocol`] if the answer is not a revoke result.
pub fn revoke<R: Read, W: Write>(
    client: &mut Client<R, W>,
    grant_id: GrantId,
) -> Result<PolicyRevokeResult, ClientError> {
    let Value::Object(params) = PolicyRevokeParams { grant_id }.to_json()? else {
        return Err(ClientError::Protocol);
    };
    let result = client.call(REVOKE_METHOD, Some(params))?;
    PolicyRevokeResult::from_json(&result).map_err(|_| ClientError::Protocol)
}

/// The line printed before `policy.grant` is sent: where to confirm. Never a question on this terminal.
#[must_use]
pub fn confirm_notice(params: &PolicyGrantParams) -> String {
    format!(
        "knsh: policy grant: confirm with Touch ID or your password on the Mac's screen; the prompt names the rule {} \
         ({}, for {})\n",
        escape_text(&params.rule),
        target_text(&params.target),
        // The same text as the prompt, so the user can match the dialog to this command.
        grant_duration_text(params.duration_s)
    )
}

/// What `knsh policy grant` prints on success, or the result object with `--json`.
#[must_use]
pub fn grant_report(result: &PolicyGrantResult, json: bool) -> String {
    if json {
        return json_line(result);
    }
    format!("Granted {} until {}.\n", result.grant_id, result.expires_at)
}

/// What `knsh policy grants` prints: a line per grant, or one JSON object per line with `--json`.
///
/// # Errors
///
/// A grant that cannot be written as JSON (never for a parsed answer).
pub fn list_report(result: &PolicyGrantsResult, json: bool) -> Result<String, knsh_json::JsonError> {
    let mut out = String::new();
    if json {
        for grant in &result.grants {
            out.push_str(&write_json_line(&grant.to_json()?)?);
        }
        return Ok(out);
    }
    if result.grants.is_empty() {
        return Ok(String::from("No live grants.\n"));
    }
    for grant in &result.grants {
        out.push_str(&entry_line(grant));
    }
    Ok(out)
}

/// One grant: `<id>  <scope>  until <expires_at>  [exact]  <rule>`, the rule escaped for the terminal.
fn entry_line(grant: &GrantEntry) -> String {
    let mut line = format!(
        "{}  {}  until {}  ",
        grant.grant_id,
        target_text(&grant.target),
        grant.expires_at
    );
    if grant.exact {
        line.push_str("exact  ");
    }
    let _ = writeln!(line, "{}", escape_text(&grant.rule));
    line
}

/// What `knsh policy revoke` prints, or the result object with `--json`.
#[must_use]
pub fn revoke_report(result: &PolicyRevokeResult, grant_id: GrantId, json: bool) -> String {
    if json {
        return json_line(result);
    }
    if result.revoked {
        format!("Revoked grant {grant_id}.\n")
    } else {
        format!("No live grant {grant_id}; it is unknown, already revoked or expired.\n")
    }
}

/// `session <id>` or `profile <name>`: neither needs escaping (a ULID, `[A-Za-z0-9._-]`).
fn target_text(target: &GrantTargetParam) -> String {
    match target {
        GrantTargetParam::Session(session_id) => format!("session {session_id}"),
        GrantTargetParam::Profile(profile) => format!("profile {profile}"),
    }
}

/// `value` as one JSON line; `{}` if it cannot be written (never for a parsed answer).
fn json_line(value: &impl ToJson) -> String {
    value
        .to_json()
        .and_then(|value| write_json_line(&value))
        .unwrap_or_else(|_| String::from("{}\n"))
}

/// What `knsh policy grant` prints on stderr when the call failed: why nothing was granted.
#[must_use]
pub fn grant_failure_message(error: &ClientError) -> String {
    match error {
        ClientError::Rpc(rpc) if rpc.code == ErrorCode::Denied => {
            let reason = Denial::from_error(rpc)
                .and_then(|denial| denial.reason)
                .unwrap_or_else(|| String::from("not authenticated"));
            format!("knsh: policy grant: nothing granted: {}\n", escape_text(&reason))
        }
        ClientError::Rpc(rpc) if rpc.code == ErrorCode::InvalidParams => String::from(
            "knsh: policy grant: nothing granted: the rule is not a command pattern, or too many grants are live\n",
        ),
        ClientError::Rpc(rpc) if rpc.code == ErrorCode::SessionNotFound => {
            String::from("knsh: policy grant: nothing granted: the session is not a live agent session\n")
        }
        ClientError::Rpc(rpc) if rpc.code == ErrorCode::NotAllowed => {
            String::from("knsh: policy grant: nothing granted: the session is not an agent session\n")
        }
        other => failure_message("grant", other),
    }
}

/// What `knsh policy grants` or `knsh policy revoke` (`command`) prints on stderr when the call failed.
#[must_use]
pub fn failure_message(command: &str, error: &ClientError) -> String {
    format!("knsh: policy {command} failed: {error}\n")
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use knsh_proto::RpcError;

    use super::*;
    use crate::cli::args::{self, Invocation};
    use crate::cli::client::tests::{HELLO_OK, frames, sent};
    use crate::cli::commands::KNSH;

    const SESSION: &str = "01J0000000000000000000000A";

    fn parsed(command: &str, argv: &[&str]) -> Result<ParsedCommand, args::ArgsError> {
        let argv = ["knsh", "policy", command]
            .into_iter()
            .chain(argv.iter().copied())
            .map(Into::into);
        args::parse(&KNSH, argv).map(|invocation| match invocation {
            Invocation::Command(parsed) => parsed,
            other => panic!("{other:?}"),
        })
    }

    fn grant_from(argv: &[&str]) -> Result<PolicyGrantParams, UsageError> {
        grant_params(&parsed("grant", argv).unwrap())
    }

    // KNSH-073: what knshd would refuse for its shape is a usage error, so no prompt ever appears for it.
    #[test]
    fn checks_grant_command_lines_before_sending() {
        let params = grant_from(&["--profile", "web", "--for", "2h", "git push"]).unwrap();
        assert_eq!(
            params.target,
            GrantTargetParam::Profile(ProfileName::new("web").unwrap())
        );
        assert_eq!((params.rule.as_str(), params.duration_s), ("git push", 7200));
        let params = grant_from(&["--session", SESSION, "--for", "90", "npm test"]).unwrap();
        assert_eq!(params.target, GrantTargetParam::Session(SESSION.parse().unwrap()));
        assert_eq!(params.duration_s, 90);

        for (argv, error) in [
            (&["--for", "1h", "ls"][..], UsageError::Scope),
            (
                &["--profile", "web", "--session", SESSION, "--for", "1h", "ls"],
                UsageError::Scope,
            ),
            (&["--session", "abc", "--for", "1h", "ls"], UsageError::BadSession),
            (&["--profile", "../web", "--for", "1h", "ls"], UsageError::BadProfile),
            (&["--profile", "web", "--for", "31d", "ls"], UsageError::BadDuration),
            (&["--profile", "web", "--for", "0s", "ls"], UsageError::BadDuration),
            (&["--profile", "web", "--for", "1h", ""], UsageError::BadRule),
        ] {
            assert_eq!(grant_from(argv), Err(error), "{argv:?}");
        }
        let long = "a".repeat(MAX_GRANT_RULE_LEN + 1);
        assert_eq!(
            grant_from(&["--profile", "web", "--for", "1h", &long]),
            Err(UsageError::BadRule)
        );
        assert!(
            parsed("grant", &["--profile", "web", "ls"]).is_err(),
            "--for is required"
        );
    }

    #[test]
    fn reads_durations_strictly() {
        assert_eq!(parse_duration("1"), Some(1));
        assert_eq!(parse_duration("45s"), Some(45));
        assert_eq!(parse_duration("15m"), Some(900));
        assert_eq!(parse_duration("1h"), Some(3600));
        assert_eq!(parse_duration("30d"), Some(MAX_GRANT_DURATION_S));
        for bad in ["", "h", "0", "-1h", "1.5h", "1 h", "1w", "+5", "99999999999999999999d"] {
            assert_eq!(parse_duration(bad), None, "{bad}");
        }
    }

    // FR-POL-62: the request names the scope, rule and duration only; nothing claims the user is present.
    #[test]
    fn sends_the_grant_and_reports_it() {
        let answer = r#"{"jsonrpc":"2.0","id":2,"result":{"grant_id":"01J0000000000000000000000B","expires_at":"2026-11-17T12:00:00.000000Z"}}"#;
        let mut written = Vec::new();
        let mut client = Client::new(Cursor::new(frames(&[HELLO_OK, answer])), &mut written);
        client.hello().unwrap();
        let params = grant_from(&["--profile", "web", "--for", "1h", "git push"]).unwrap();
        let result = grant(&mut client, &params).unwrap();
        let texts = sent(&written);
        assert!(
            texts[1].contains(
                r#""method":"policy.grant","params":{"scope":"profile","profile":"web","rule":"git push","duration_s":3600}"#
            ),
            "{}",
            texts[1]
        );
        assert_eq!(
            grant_report(&result, false),
            "Granted 01J0000000000000000000000B until 2026-11-17T12:00:00.000000Z.\n"
        );
        assert_eq!(
            grant_report(&result, true),
            "{\"grant_id\":\"01J0000000000000000000000B\",\"expires_at\":\"2026-11-17T12:00:00.000000Z\"}\n"
        );
        let notice = confirm_notice(&params);
        assert!(notice.contains("Touch ID"), "{notice}");
        assert!(notice.contains("git push (profile web, for 1h)"), "{notice}");
    }

    // FR-POL-61: the list shows every grant, its rule terminal-safe; revoke reports whether anything was removed.
    #[test]
    fn lists_and_revokes() {
        let list_answer = format!(
            r#"{{"jsonrpc":"2.0","id":2,"result":{{"grants":[{{"grant_id":"{SESSION}","scope":"session","session_id":"{SESSION}","profile":null,"rule":"rm -r build\u001b[2J","exact":true,"expires_at":"2026-11-17T12:00:00.000000Z"}}]}}}}"#
        );
        let revoke_answer = r#"{"jsonrpc":"2.0","id":3,"result":{"revoked":false}}"#;
        let mut written = Vec::new();
        let mut client = Client::new(
            Cursor::new(frames(&[HELLO_OK, &list_answer, revoke_answer])),
            &mut written,
        );
        client.hello().unwrap();
        let listed = list(&mut client).unwrap();
        let text = list_report(&listed, false).unwrap();
        assert!(
            text.starts_with(&format!(
                "{SESSION}  session {SESSION}  until 2026-11-17T12:00:00.000000Z  exact  rm -r build"
            )),
            "{text}"
        );
        assert!(!text.contains('\u{1b}'), "{text}");
        assert_eq!(list_report(&listed, true).unwrap().lines().count(), 1);
        assert_eq!(
            list_report(&PolicyGrantsResult { grants: Vec::new() }, false).unwrap(),
            "No live grants.\n"
        );

        let id = grant_id(&parsed("revoke", &[SESSION]).unwrap()).unwrap();
        let revoked = revoke(&mut client, id).unwrap();
        assert!(sent(&written)[2].contains(&format!(
            r#""method":"policy.revoke","params":{{"grant_id":"{SESSION}"}}"#
        )));
        assert!(revoke_report(&revoked, id, false).starts_with("No live grant"));
        assert_eq!(
            grant_id(&parsed("revoke", &["nope"]).unwrap()),
            Err(UsageError::BadGrantId)
        );
    }

    // Refusals say why, escaped for the terminal.
    #[test]
    fn failure_messages_name_the_refusal() {
        let denied = Denial {
            rule_id: None,
            reason: Some(String::from("not authenticated: cancelled\u{1b}[2J")),
            source: Some(String::from("user")),
        }
        .to_error()
        .unwrap();
        let message = grant_failure_message(&ClientError::Rpc(denied));
        assert!(
            message.contains("nothing granted: not authenticated: cancelled"),
            "{message}"
        );
        assert!(!message.contains('\u{1b}'));
        let invalid = RpcError::new(ErrorCode::InvalidParams);
        assert!(grant_failure_message(&ClientError::Rpc(invalid.clone())).contains("not a command pattern"));
        // Not the grant's wording for the other commands.
        assert!(!failure_message("revoke", &ClientError::Rpc(invalid)).contains("command pattern"));
    }
}
