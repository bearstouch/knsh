//! `knsh profile use <profile>`: run the agent sessions paused by expired pushed policy under a signed local profile
//! (KNSH-072, FR-POL-51, `specs/06-api/cli.md#profile-use`).
//!
//! The name is checked here first, by the type `knshd` uses, so a malformed name is a usage error (exit 2) and nothing
//! is sent. Then `profile.use` goes to `user.sock`. `knshd` checks that the profile is a signed local one and shows
//! the Touch ID or password prompt itself; the CLI only says so on stderr and waits. It has no way to claim the user
//! is present: no option, no answer of its own.

use std::fmt::Write as _;
use std::io::{Read, Write};

use knsh_core::ProfileName;
use knsh_json::{FromJson, ToJson, Value};
use knsh_proto::{Denial, ErrorCode, ProfileUseParams, ProfileUseResult};

use crate::cli::args::ParsedCommand;
use crate::cli::client::{Client, ClientError};
use crate::cli::policy::UsageError;
use crate::cli::terminal::escape_text;

/// The method `knsh profile use` calls.
pub const USE_METHOD: &str = "profile.use";

/// The profile named on the command line.
///
/// # Errors
///
/// [`UsageError::BadProfile`] for a name `knshd` would refuse.
pub fn params(parsed: &ParsedCommand) -> Result<ProfileUseParams, UsageError> {
    let name = parsed.positionals.first().ok_or(UsageError::BadProfile)?;
    let profile = ProfileName::new(name).map_err(|_| UsageError::BadProfile)?;
    Ok(ProfileUseParams { profile })
}

/// Sends `profile.use`. Blocks while `knshd` shows its prompt.
///
/// # Errors
///
/// Any [`ClientError`]; [`ClientError::Protocol`] if the answer is not a `profile.use` result.
pub fn use_profile<R: Read, W: Write>(
    client: &mut Client<R, W>,
    params: &ProfileUseParams,
) -> Result<ProfileUseResult, ClientError> {
    let Value::Object(params) = params.to_json()? else {
        return Err(ClientError::Protocol);
    };
    let result = client.call(USE_METHOD, Some(params))?;
    ProfileUseResult::from_json(&result).map_err(|_| ClientError::Protocol)
}

/// The line printed before `profile.use` is sent: where to confirm. Never a question on this terminal.
#[must_use]
pub fn confirm_notice(params: &ProfileUseParams) -> String {
    format!(
        "knsh: profile use: if agent sessions are paused by expired pushed policy, confirm with Touch ID or your \
         password on the Mac's screen; the prompt names {}\n",
        params.profile
    )
}

/// What `knsh profile use` prints on success: a sentence per outcome, or the result object with `--json`.
#[must_use]
pub fn report(result: &ProfileUseResult, json: bool) -> String {
    if json {
        let text = result
            .to_json()
            .and_then(|value| knsh_json::write(&value))
            .unwrap_or_else(|_| String::from(r#"{"profile":null}"#));
        return format!("{text}\n");
    }
    if result.sessions.is_empty() {
        return String::from("No agent session is paused by expired pushed policy; nothing changed.\n");
    }
    let mut text = format!(
        "Resumed {} agent session{} under the local profile {}:\n",
        result.sessions.len(),
        if result.sessions.len() == 1 { "" } else { "s" },
        result.profile
    );
    for session_id in &result.sessions {
        let _ = writeln!(text, "  {session_id}");
    }
    text
}

/// What the command prints on stderr when the call failed.
#[must_use]
pub fn failure_message(error: &ClientError) -> String {
    match error {
        ClientError::Rpc(rpc) if rpc.code == ErrorCode::Denied => {
            let reason = Denial::from_error(rpc)
                .and_then(|denial| denial.reason)
                .unwrap_or_else(|| String::from("not authenticated"));
            format!("knsh: profile use: nothing changed: {}\n", escape_text(&reason))
        }
        ClientError::Rpc(rpc) if rpc.code == ErrorCode::InvalidParams => {
            let reason = rpc
                .data
                .as_ref()
                .and_then(Value::as_object)
                .and_then(|data| data.get("reason"))
                .and_then(Value::as_str)
                .unwrap_or("knshd refused the profile");
            format!(
                "knsh: profile use: not a signed local profile: {}\n",
                escape_text(reason)
            )
        }
        other => format!("knsh: profile use failed: {other}\n"),
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use knsh_proto::RpcError;

    use super::*;
    use crate::cli::args::{self, Invocation};
    use crate::cli::client::tests::{HELLO_OK, frames, sent};
    use crate::cli::commands::KNSH;

    fn parsed(argv: &[&str]) -> Result<ParsedCommand, args::ArgsError> {
        let argv = ["knsh", "profile", "use"]
            .into_iter()
            .chain(argv.iter().copied())
            .map(Into::into);
        args::parse(&KNSH, argv).map(|invocation| match invocation {
            Invocation::Command(parsed) => parsed,
            other => panic!("{other:?}"),
        })
    }

    // A malformed name is refused before anything is sent, so no prompt can appear for it.
    #[test]
    fn validates_the_profile_name_before_sending() {
        assert_eq!(params(&parsed(&["local"]).unwrap()).unwrap().profile.as_str(), "local");
        assert_eq!(params(&parsed(&["../web"]).unwrap()), Err(UsageError::BadProfile));
        assert!(parsed(&[]).is_err(), "the profile is required");
    }

    // FR-POL-51: the request names only the profile; nothing claims the user is present. The report names every
    // session moved.
    #[test]
    fn sends_only_the_profile_and_reports_the_sessions() {
        let answer =
            r#"{"jsonrpc":"2.0","id":2,"result":{"profile":"local","sessions":["01J00000000000000000000001"]}}"#;
        let mut written = Vec::new();
        let mut client = Client::new(Cursor::new(frames(&[HELLO_OK, answer])), &mut written);
        client.hello().unwrap();
        let request = params(&parsed(&["local"]).unwrap()).unwrap();
        let result = use_profile(&mut client, &request).unwrap();
        let texts = sent(&written);
        assert!(
            texts[1].contains(r#""method":"profile.use","params":{"profile":"local"}"#),
            "{}",
            texts[1]
        );
        assert_eq!(
            report(&result, false),
            "Resumed 1 agent session under the local profile local:\n  01J00000000000000000000001\n"
        );
        assert_eq!(
            report(&result, true),
            "{\"profile\":\"local\",\"sessions\":[\"01J00000000000000000000001\"]}\n"
        );
        let none = ProfileUseResult {
            profile: result.profile,
            sessions: Vec::new(),
        };
        assert!(report(&none, false).starts_with("No agent session is paused"));
        assert!(confirm_notice(&request).contains("Touch ID"));
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
        let message = failure_message(&ClientError::Rpc(denied));
        assert!(
            message.contains("nothing changed: not authenticated: cancelled"),
            "{message}"
        );
        assert!(!message.contains('\u{1b}'));
        let invalid = RpcError::new(ErrorCode::InvalidParams);
        assert!(failure_message(&ClientError::Rpc(invalid)).contains("not a signed local profile"));
    }
}
