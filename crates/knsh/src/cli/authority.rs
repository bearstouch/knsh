//! `knsh authority trust --team-id <id> --identifier <bundle-id> --min-version <v>`: trust one authority app (KNSH-068,
//! FR-AUTH-10, `specs/06-api/cli.md#authority-trust`).
//!
//! The three options are checked here first, by the same types `knshd` uses, so a malformed team ID, identifier or
//! version is a usage error (exit 2) and nothing is sent: no prompt appears for a command that could never succeed.
//! Then `authority.trust` goes to `user.sock`. `knshd` shows the Touch ID or password prompt itself, naming the
//! authority (and the one it replaces, if any); the CLI only says so on stderr and waits. It has no way to claim the
//! user is present: no option, no answer of its own.

use std::fmt;
use std::io::{Read, Write};

use knsh_core::{BundleVersion, SigningIdentifier, TeamId, TrustedAuthority};
use knsh_json::{FromJson, ToJson, Value};
use knsh_proto::{AuthorityTrustParams, AuthorityTrustResult, Denial, ErrorCode};

use crate::cli::args::ParsedCommand;
use crate::cli::client::{Client, ClientError};
use crate::cli::terminal::escape_text;

/// The method `knsh authority trust` calls.
pub const TRUST_METHOD: &str = "authority.trust";

/// A `knsh authority trust` command line refused before anything was sent (exit 2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsageError {
    /// `--team-id` is not ten characters from `A-Z` and `0-9`.
    BadTeamId,
    /// `--identifier` is not a valid bundle identifier.
    BadIdentifier,
    /// `--min-version` is not one to three dot-separated numbers.
    BadVersion,
}

impl fmt::Display for UsageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::BadTeamId => "--team-id must be ten characters from A-Z and 0-9, such as ABCDE12345",
            Self::BadIdentifier => {
                "--identifier must be a bundle identifier: 1 to 255 characters from A-Z a-z 0-9 . -, \
                 such as com.example.authority"
            }
            Self::BadVersion => "--min-version must be one to three dot-separated numbers, such as 1.4.2",
        })
    }
}

impl std::error::Error for UsageError {}

/// The authority named on the command line, every part validated.
///
/// # Errors
///
/// The [`UsageError`] of the first option `knshd` would refuse. The argument parser already requires all three.
pub fn params(parsed: &ParsedCommand) -> Result<AuthorityTrustParams, UsageError> {
    let option = |name| parsed.value(name).unwrap_or_default();
    Ok(AuthorityTrustParams {
        authority: TrustedAuthority {
            team_id: TeamId::new(option("team-id")).map_err(|_| UsageError::BadTeamId)?,
            identifier: SigningIdentifier::new(option("identifier")).map_err(|_| UsageError::BadIdentifier)?,
            min_version: BundleVersion::parse(option("min-version")).map_err(|_| UsageError::BadVersion)?,
        },
    })
}

/// Sends `authority.trust`. Blocks while `knshd` shows its prompt.
///
/// # Errors
///
/// Any [`ClientError`]; [`ClientError::Protocol`] if the answer is not a trust result.
pub fn trust<R: Read, W: Write>(
    client: &mut Client<R, W>,
    params: &AuthorityTrustParams,
) -> Result<AuthorityTrustResult, ClientError> {
    let Value::Object(params) = params.to_json()? else {
        return Err(ClientError::Protocol);
    };
    let result = client.call(TRUST_METHOD, Some(params))?;
    AuthorityTrustResult::from_json(&result).map_err(|_| ClientError::Protocol)
}

/// The line printed before `authority.trust` is sent: where to confirm. Never a question on this terminal.
#[must_use]
pub fn confirm_notice(params: &AuthorityTrustParams) -> String {
    format!(
        "knsh: authority trust: if knshd asks, confirm with Touch ID or your password on the Mac's screen; the prompt \
         names {}\n",
        params.authority.describe()
    )
}

/// What `knsh authority trust` prints on success: a sentence, or the result object with `--json`.
#[must_use]
pub fn report(result: &AuthorityTrustResult, json: bool) -> String {
    if json {
        let text = result
            .to_json()
            .and_then(|value| knsh_json::write(&value))
            .unwrap_or_else(|_| String::from(r#"{"changed":null}"#));
        return format!("{text}\n");
    }
    let authority = result.authority.describe();
    match (result.changed, result.replaced) {
        (false, _) => format!("Already trusted: {authority}.\n"),
        (true, true) => format!("Trusted {authority}, replacing the previous authority.\n"),
        (true, false) => format!("Trusted {authority}.\n"),
    }
}

/// What the command prints on stderr when the call failed.
#[must_use]
pub fn failure_message(error: &ClientError) -> String {
    match error {
        ClientError::Rpc(rpc) if rpc.code == ErrorCode::Denied => {
            let reason = Denial::from_error(rpc)
                .and_then(|denial| denial.reason)
                .unwrap_or_else(|| String::from("not authenticated"));
            format!("knsh: authority trust: not trusted: {}\n", escape_text(&reason))
        }
        ClientError::Rpc(rpc) if rpc.code == ErrorCode::InternalError => String::from(
            "knsh: authority trust failed: knshd could not read or write the trust record (see the system log); \
             nothing was changed\n",
        ),
        other => format!("knsh: authority trust failed: {other}\n"),
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
        let argv = ["knsh", "authority", "trust"]
            .into_iter()
            .chain(argv.iter().copied())
            .map(Into::into);
        args::parse(&KNSH, argv).map(|invocation| match invocation {
            Invocation::Command(parsed) => parsed,
            other => panic!("{other:?}"),
        })
    }

    fn line(team: &str, identifier: &str, version: &str) -> ParsedCommand {
        parsed(&["--team-id", team, "--identifier", identifier, "--min-version", version]).unwrap()
    }

    // FR-AUTH-10, AC "invalid arguments are rejected before the prompt": each malformed option is a usage error, so
    // nothing is sent and no prompt appears.
    #[test]
    fn validates_team_id_identifier_and_version_before_sending() {
        let ok = params(&line("ABCDE12345", "com.example.authority", "1.4")).unwrap();
        assert_eq!(ok.authority.min_version.to_string(), "1.4.0");
        assert_eq!(
            params(&line("abcde12345", "com.example.authority", "1")),
            Err(UsageError::BadTeamId)
        );
        assert_eq!(
            params(&line("ABCDE12345", "com.example\"x", "1")),
            Err(UsageError::BadIdentifier)
        );
        assert_eq!(
            params(&line("ABCDE12345", "com.example.authority", "v1")),
            Err(UsageError::BadVersion)
        );
        // All three options are required by the parser itself.
        assert!(parsed(&["--team-id", "ABCDE12345", "--identifier", "com.example.authority"]).is_err());
    }

    // FR-AUTH-10: the request names only the authority; nothing claims the user is present.
    #[test]
    fn sends_only_the_authority() {
        let answer = r#"{"jsonrpc":"2.0","id":2,"result":{"team_id":"ABCDE12345","identifier":"com.example.authority","min_version":"1.4.0","changed":true,"replaced":false}}"#;
        let mut written = Vec::new();
        let mut client = Client::new(Cursor::new(frames(&[HELLO_OK, answer])), &mut written);
        client.hello().unwrap();
        let request = params(&line("ABCDE12345", "com.example.authority", "1.4")).unwrap();
        let result = trust(&mut client, &request).unwrap();
        let texts = sent(&written);
        assert!(
            texts[1].contains(
                r#""method":"authority.trust","params":{"team_id":"ABCDE12345","identifier":"com.example.authority","min_version":"1.4.0"}"#
            ),
            "{}",
            texts[1]
        );
        assert_eq!(
            report(&result, false),
            "Trusted com.example.authority (team ABCDE12345, version 1.4.0 or later).\n"
        );
        assert!(report(&result, true).starts_with(r#"{"team_id":"ABCDE12345""#));
        assert!(confirm_notice(&request).contains("com.example.authority (team ABCDE12345"));
    }

    #[test]
    fn explains_refusals() {
        let denied = Denial {
            rule_id: None,
            reason: Some(String::from("not authenticated: the prompt was cancelled")),
            source: Some(String::from("user")),
        }
        .to_error()
        .unwrap();
        assert_eq!(
            failure_message(&ClientError::Rpc(denied)),
            "knsh: authority trust: not trusted: not authenticated: the prompt was cancelled\n"
        );
        assert!(
            failure_message(&ClientError::Rpc(RpcError::new(ErrorCode::InternalError))).contains("nothing was changed")
        );
    }
}
