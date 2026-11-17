//! `knsh policy edit <profile>`: edit a policy file; `knshd` signs it after Touch ID or the password (KNSH-065,
//! FR-POL-41, `specs/06-api/cli.md#policy-edit`).
//!
//! 1. `policy.read` on `user.sock` returns the profile's text (without its signature trailer) and whether the engine
//!    accepts the file now. A file the engine ignores (missing or bad signature) is announced on stderr before the
//!    editor opens, so the user reviews text they did not necessarily write before signing it.
//! 2. The text is written to a private temporary file (`0600`, created new) and opened with `$VISUAL`, else
//!    `$EDITOR`, else `vi`, run through `/bin/sh` so an editor with arguments (`code --wait`) works.
//! 3. If the editor fails, nothing is sent. If the text is unchanged and the file already verifies, nothing is sent
//!    either.
//! 4. Otherwise `policy.edit` sends the text. `knshd` checks it loads, shows the Touch ID or password prompt itself,
//!    and signs and writes the file. The CLI prints the size and SHA-256 prefix the prompt shows, so the user can
//!    match the dialog to this edit. The CLI cannot sign: it never sees the key, and no parameter skips the prompt.
//!
//! On any refusal the edited text is kept in its temporary file and its path printed, so no work is lost.
//!
//! The pure parts (parameters, messages, the editor command) are here and tested; the process and file effects are
//! in `main.rs`.

use std::fmt::{self, Write as _};
use std::io::{Read, Write};

use knsh_core::ProfileName;
use knsh_json::{FromJson, ToJson, Value};
use knsh_proto::{
    Denial, ErrorCode, PolicyEditParams, PolicyEditResult, PolicyFileState, PolicyReadParams, PolicyReadResult,
};

use crate::cli::args::ParsedCommand;
use crate::cli::client::{Client, ClientError};

/// The method that reads the profile for editing.
pub const READ_METHOD: &str = "policy.read";
/// The method that saves it.
pub const EDIT_METHOD: &str = "policy.edit";

/// The editor when neither `VISUAL` nor `EDITOR` is set: always installed on macOS.
pub const DEFAULT_EDITOR: &str = "vi";

/// Hex digits of the SHA-256 printed before the prompt: the same prefix `knshd` shows in it.
const HASH_PREFIX_BYTES: usize = 8;

/// A `knsh policy edit` or `knsh profile use` command line refused before anything was sent (exit 2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UsageError {
    /// The profile name is not 1 to 64 characters from `[A-Za-z0-9._-]`.
    BadProfile,
}

impl fmt::Display for UsageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadProfile => f.write_str("the profile name must be 1 to 64 characters from A-Z a-z 0-9 . _ -"),
        }
    }
}

impl std::error::Error for UsageError {}

/// The profile named on the command line.
///
/// # Errors
///
/// [`UsageError::BadProfile`] for a name `knshd` would refuse.
pub fn profile(parsed: &ParsedCommand) -> Result<ProfileName, UsageError> {
    let name = parsed.positionals.first().ok_or(UsageError::BadProfile)?;
    ProfileName::new(name).map_err(|_| UsageError::BadProfile)
}

/// Sends `policy.read` for `profile`.
///
/// # Errors
///
/// Any [`ClientError`]; [`ClientError::Protocol`] if the answer is not a read result.
pub fn read<R: Read, W: Write>(
    client: &mut Client<R, W>,
    profile: &ProfileName,
) -> Result<PolicyReadResult, ClientError> {
    let params = PolicyReadParams {
        profile: profile.clone(),
    };
    let Value::Object(object) = params.to_json()? else {
        return Err(ClientError::Protocol);
    };
    let result = client.call(READ_METHOD, Some(object))?;
    PolicyReadResult::from_json(&result).map_err(|_| ClientError::Protocol)
}

/// Sends `policy.edit` with `text` for `profile`. Blocks while `knshd` shows its prompt.
///
/// # Errors
///
/// Any [`ClientError`]: `-32001` when the user did not authenticate, `-32602` when the text does not load.
pub fn save<R: Read, W: Write>(
    client: &mut Client<R, W>,
    profile: &ProfileName,
    text: String,
) -> Result<PolicyEditResult, ClientError> {
    let params = PolicyEditParams {
        profile: profile.clone(),
        text,
    };
    let Value::Object(object) = params.to_json()? else {
        return Err(ClientError::Protocol);
    };
    let result = client.call(EDIT_METHOD, Some(object))?;
    PolicyEditResult::from_json(&result).map_err(|_| ClientError::Protocol)
}

/// The editor to run: `VISUAL`, else `EDITOR` (each only when set and not blank), else [`DEFAULT_EDITOR`].
#[must_use]
pub fn editor(visual: Option<&str>, editor: Option<&str>) -> String {
    [visual, editor]
        .into_iter()
        .flatten()
        .find(|value| !value.trim().is_empty())
        .unwrap_or(DEFAULT_EDITOR)
        .to_owned()
}

/// The `/bin/sh -c` script that runs `editor` on the file passed as `$1`. The editor text is the user's own setting
/// and is interpreted by the shell as a command with arguments, like git does; the path is passed as an argument, so
/// it is never parsed.
#[must_use]
pub fn editor_script(editor: &str) -> String {
    format!("{editor} \"$1\"")
}

/// What to say on stderr before editing, for a file the engine does not accept now; `None` for a valid or new one.
#[must_use]
pub fn state_warning(read: &PolicyReadResult) -> Option<String> {
    match read.state {
        PolicyFileState::New | PolicyFileState::Valid => None,
        PolicyFileState::Invalid => {
            let why = match read.reason.as_deref() {
                Some("signature_missing") => "it has no signature",
                Some("signature_bad") => "its signature does not match its text (it was changed outside knsh)",
                Some("key_unavailable") => "the signing key could not be read from the Keychain",
                _ => "its signature is not valid",
            };
            Some(format!(
                "knsh: policy edit: warning: profile {} is ignored by knshd because {why}.\n\
                 knsh: policy edit: review the whole text before saving: saving signs it.\n",
                read.profile
            ))
        }
    }
}

/// Whether there is nothing to send: the text is unchanged and the file already verifies.
#[must_use]
pub fn unchanged(read: &PolicyReadResult, edited: &str) -> bool {
    read.state == PolicyFileState::Valid && read.text == edited
}

/// The line printed before `policy.edit` is sent: what the prompt on the Mac's screen will name. `sha256` is the
/// digest of `text` as `knshd` will sign it (with a final newline).
#[must_use]
pub fn confirm_notice(profile: &ProfileName, text_len: usize, sha256: &[u8; 32]) -> String {
    let mut hash = String::new();
    for byte in &sha256[..HASH_PREFIX_BYTES] {
        let _ = write!(hash, "{byte:02x}");
    }
    format!(
        "knsh: policy edit: confirm with Touch ID or your password on the Mac's screen to sign profile {profile} \
         ({text_len} bytes, sha256 {hash})\n"
    )
}

/// `text` as `knshd` signs it: with a final newline when it has none.
#[must_use]
pub fn as_signed(text: &str) -> String {
    let mut text = text.to_owned();
    if !text.is_empty() && !text.ends_with('\n') {
        text.push('\n');
    }
    text
}

/// What `knsh policy edit` prints on success: a sentence, or `{"profile","changed"}` with `--json`.
#[must_use]
pub fn report(result: &PolicyEditResult, json: bool) -> String {
    if json {
        let text = result
            .to_json()
            .and_then(|value| knsh_json::write(&value))
            .unwrap_or_else(|_| String::from(r#"{"profile":null,"changed":null}"#));
        return format!("{text}\n");
    }
    if result.changed {
        format!("Signed and saved profile {}.\n", result.profile)
    } else {
        format!("No changes to profile {}.\n", result.profile)
    }
}

/// What `knsh policy edit` prints on stderr when a call failed.
#[must_use]
pub fn failure_message(error: &ClientError) -> String {
    match error {
        ClientError::Rpc(rpc) if rpc.code == ErrorCode::Denied => {
            let reason = Denial::from_error(rpc)
                .and_then(|denial| denial.reason)
                .unwrap_or_else(|| String::from("not authenticated"));
            format!(
                "knsh: policy edit: not saved: {}\n",
                crate::cli::terminal::escape_text(&reason)
            )
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
                "knsh: policy edit: not saved: the profile does not load: {}\n",
                crate::cli::terminal::escape_text(reason)
            )
        }
        other => format!("knsh: policy edit failed: {other}\n"),
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;
    use crate::cli::args::{self, Invocation};
    use crate::cli::client::tests::{HELLO_OK, frames, sent};
    use crate::cli::commands::KNSH;

    fn parsed(argv: &[&str]) -> Result<ParsedCommand, args::ArgsError> {
        let argv = std::iter::once("knsh").chain(argv.iter().copied()).map(Into::into);
        args::parse(&KNSH, argv).map(|invocation| match invocation {
            Invocation::Command(parsed) => parsed,
            other => panic!("{other:?}"),
        })
    }

    // FR-POL-41: the command takes exactly one profile name, checked before anything is sent.
    #[test]
    fn edit_takes_one_valid_profile() {
        let command = parsed(&["policy", "edit", "web-app"]).unwrap();
        assert_eq!(command.path, ["policy", "edit"]);
        assert_eq!(profile(&command).unwrap().as_str(), "web-app");
        assert!(parsed(&["policy", "edit"]).is_err(), "the profile is required");
        let bad = parsed(&["policy", "edit", "../x"]).unwrap();
        assert_eq!(profile(&bad), Err(UsageError::BadProfile));
    }

    #[test]
    fn editor_prefers_visual_then_editor_then_vi() {
        assert_eq!(editor(Some("code --wait"), Some("nano")), "code --wait");
        assert_eq!(editor(Some("  "), Some("nano")), "nano");
        assert_eq!(editor(None, None), DEFAULT_EDITOR);
        assert_eq!(editor_script("code --wait"), "code --wait \"$1\"");
    }

    // FR-POL-42: an ignored file is announced before editing, with why; valid and new files are not.
    #[test]
    fn warns_before_editing_an_ignored_file() {
        let mut read = PolicyReadResult {
            profile: ProfileName::new("web").unwrap(),
            text: String::from("name = \"web\"\n"),
            state: PolicyFileState::Invalid,
            reason: Some(String::from("signature_bad")),
        };
        let warning = state_warning(&read).unwrap();
        assert!(warning.contains("profile web is ignored"), "{warning}");
        assert!(warning.contains("changed outside knsh"), "{warning}");
        assert!(
            !unchanged(&read, "name = \"web\"\n"),
            "an invalid file is always sent to be signed"
        );
        read.state = PolicyFileState::Valid;
        assert_eq!(state_warning(&read), None);
        assert!(unchanged(&read, "name = \"web\"\n"));
        assert!(!unchanged(&read, "name = \"web\"\n# more\n"));
    }

    // The read and the save are the two calls, with the profile and the text as given.
    #[test]
    fn reads_then_saves_over_the_socket() {
        let answers = frames(&[
            HELLO_OK,
            r#"{"jsonrpc":"2.0","id":2,"result":{"profile":"web","text":"","state":"new","reason":null}}"#,
            r#"{"jsonrpc":"2.0","id":3,"result":{"profile":"web","changed":true}}"#,
        ]);
        let mut written = Vec::new();
        let mut client = Client::new(Cursor::new(answers), &mut written);
        client.hello().unwrap();
        let name = ProfileName::new("web").unwrap();
        let current = read(&mut client, &name).unwrap();
        assert_eq!(current.state, PolicyFileState::New);
        let result = save(&mut client, &name, String::from("name = \"web\"\n")).unwrap();
        assert!(result.changed);
        let texts = sent(&written);
        assert!(texts[1].contains(r#""method":"policy.read""#), "{}", texts[1]);
        assert!(texts[2].contains(r#""method":"policy.edit""#), "{}", texts[2]);
        assert!(texts[2].contains(r#""text":"name = \"web\"\n""#), "{}", texts[2]);
        assert_eq!(report(&result, false), "Signed and saved profile web.\n");
        assert_eq!(report(&result, true), "{\"profile\":\"web\",\"changed\":true}\n");
    }

    // FR-POL-41: a refused prompt is reported as not saved, with knshd's reason.
    #[test]
    fn refusal_says_nothing_was_saved() {
        let answers = frames(&[
            HELLO_OK,
            r#"{"jsonrpc":"2.0","id":2,"error":{"code":-32001,"message":"Denied by policy, hook, authority or rate limit","data":{"rule_id":null,"reason":"not authenticated: cancelled","source":"user"}}}"#,
        ]);
        let mut written = Vec::new();
        let mut client = Client::new(Cursor::new(answers), &mut written);
        client.hello().unwrap();
        let error = save(&mut client, &ProfileName::new("web").unwrap(), String::new()).unwrap_err();
        assert_eq!(
            failure_message(&error),
            "knsh: policy edit: not saved: not authenticated: cancelled\n"
        );
    }

    #[test]
    fn notice_names_what_the_prompt_shows() {
        let notice = confirm_notice(&ProfileName::new("web").unwrap(), 13, &[0xab; 32]);
        assert!(
            notice.contains("profile web (13 bytes, sha256 abababababababab)"),
            "{notice}"
        );
        assert_eq!(as_signed("a"), "a\n");
        assert_eq!(as_signed(""), "");
    }
}
