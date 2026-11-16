//! User presence: the system authentication prompt, shown by `knshd` itself (KNSH-064).
//!
//! Every security-changing action from a user process (approval, grant, policy edit, profile selection, authority
//! trust) needs Touch ID or the user's password, checked inside `knshd` (NFR-SEC-04). `knshd` shows the prompt with
//! the exact command or change in it (FR-AUTH-41), so no client can claim that the user is present (FR-AUTH-42).
//!
//! The interface makes that hard to get wrong:
//!
//! - [`UserPresence`] has one operation, [`authenticate`](UserPresence::authenticate), whose only inputs are the
//!   reason text and how long to wait. There is no flag, cached result or token that skips or pre-satisfies the
//!   prompt: each call shows a new one.
//! - Success is an [`Authenticated`] proof that only this crate can make, so code elsewhere cannot forge one.
//! - Every other outcome is a [`NotAuthenticated`] refusal: cancellation, failure, lockout, no usable session, no
//!   answer in time, or any error. The caller refuses the action (fail closed, decision 12).
//! - The reason is a [`PromptReason`], built only from the command or change itself, with control and invisible
//!   characters escaped, so the dialog shows exactly what will run and nothing can hide in it.
//!
//! The macOS backend is `macos::LocalAuthentication`; the fake is [`crate::testing::ScriptedPresence`].

use std::fmt::{self, Write as _};
use std::os::unix::ffi::OsStrExt;
use std::time::Duration;

use knsh_core::{CanonicalPath, SessionId};

/// Asks the person at the Mac to prove they are there. Object safe: hold it as `Arc<dyn UserPresence>`.
pub trait UserPresence: Send + Sync {
    /// Shows the system authentication prompt (Touch ID, with the user's password as fallback) with `reason` in it,
    /// and waits for the answer for at most `timeout`. Blocks the calling thread meanwhile.
    ///
    /// Each call shows a new prompt: nothing from an earlier call is reused (FR-AUTH-42).
    ///
    /// # Errors
    ///
    /// A [`NotAuthenticated`] for every outcome other than success, including no answer within `timeout` (the
    /// pending prompt is then withdrawn). The caller must refuse the action.
    fn authenticate(&self, reason: &PromptReason, timeout: Duration) -> Result<Authenticated, NotAuthenticated>;
}

/// Proof that the user authenticated at a prompt. Only this crate can make one (the field is private), so holding it
/// means a [`UserPresence`] backend saw the user succeed. Not `Clone`: one proof per prompt.
///
/// ```compile_fail
/// // Code outside knsh-platform cannot forge a proof (FR-AUTH-42).
/// let forged = knsh_platform::Authenticated { _private: () };
/// ```
#[derive(Debug, PartialEq, Eq)]
#[must_use = "an authentication that is not acted on is wasted; refuse the action on error"]
pub struct Authenticated {
    _private: (),
}

impl Authenticated {
    /// A proof. Called only by [`UserPresence`] backends in this crate after the system reported success.
    pub(crate) const fn new() -> Self {
        Self { _private: () }
    }
}

/// Why the user was not authenticated. Every variant means the action is refused (NFR-SEC-04, decision 12).
///
/// The [`Display`](fmt::Display) text is for the record and stderr. It never contains the reason text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotAuthenticated {
    /// The prompt was cancelled: by the user, by the system (another prompt, the screen locked) or by `knshd`.
    Cancelled,
    /// The fingerprint or password was not accepted.
    Failed,
    /// Too many failed attempts: biometrics are locked out.
    Lockout,
    /// Authentication cannot run here: no password set, no usable session, or the system service is missing.
    Unavailable,
    /// Nobody answered before the timeout. The prompt was withdrawn.
    TimedOut,
    /// Any other error the system reported, with its code. Unknown means refused.
    Error {
        /// The system's error code (`LAError` on macOS, or another domain's code).
        code: i64,
    },
}

impl fmt::Display for NotAuthenticated {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("not authenticated: ")?;
        match self {
            Self::Cancelled => f.write_str("the prompt was cancelled"),
            Self::Failed => f.write_str("the fingerprint or password was not accepted"),
            Self::Lockout => f.write_str("too many failed attempts"),
            Self::Unavailable => f.write_str("user authentication is not available on this Mac"),
            Self::TimedOut => f.write_str("no answer at the Mac's screen before the timeout"),
            Self::Error { code } => write!(f, "the system reported error {code}"),
        }
    }
}

impl std::error::Error for NotAuthenticated {}

/// The text of the prompt. The system dialog reads `knshd is trying to <reason>`, so each reason starts with a verb
/// (decision 12).
///
/// Built only from the command or change being approved: the text names it in full, never shortened. Characters that
/// would not show, or would show something else, are escaped so the user reads exactly what runs (FR-AUTH-41):
///
/// - a backslash is shown doubled (`\\`), so every escape below is unambiguous;
/// - newline, tab and carriage return are shown as `\n`, `\t`, `\r`; any other control character, and invisible or
///   direction-changing characters (bidirectional overrides and isolates, zero-width characters, line and paragraph
///   separators, the byte-order mark, tag characters, variation selectors, fillers, and spaces other than the ASCII
///   space), as `\u{XXXX}`. A right-to-left override could otherwise display
///   `rm -rf ~` reversed, and a newline could push a second command below the visible text;
/// - bytes of a path that are not UTF-8 are shown as `\xNN`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PromptReason(String);

impl PromptReason {
    /// The reason for approving an agent's command line: `approve the agent command: <command> (cwd <dir>, session
    /// <id>)` (decision 12, FR-AUTH-41).
    #[must_use]
    pub fn agent_command(command: &str, cwd: &CanonicalPath, session: SessionId) -> Self {
        let mut text = String::from("approve the agent command: ");
        push_escaped(&mut text, command);
        text.push_str(" (cwd ");
        push_escaped_bytes(&mut text, cwd.as_path().as_os_str().as_bytes());
        // A `SessionId` displays as a ULID: letters and digits only, so it needs no escaping.
        let _ = write!(text, ", session {session})");
        Self(text)
    }

    /// The reason for any other security-changing action (NFR-SEC-04): `<action>: <detail>`, for example
    /// `change the policy: allow network to github.com`. The action is engine text, fixed at compile time and
    /// starting with a verb; the detail names the exact change and is escaped.
    #[must_use]
    pub fn change(action: &'static str, detail: &str) -> Self {
        let mut text = String::from(action);
        text.push_str(": ");
        push_escaped(&mut text, detail);
        Self(text)
    }

    /// The prompt text, as the dialog shows it.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for PromptReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Appends `bytes`, escaped as [`PromptReason`] describes. Bytes that are not UTF-8 become `\xNN`.
fn push_escaped_bytes(out: &mut String, bytes: &[u8]) {
    for chunk in bytes.utf8_chunks() {
        push_escaped(out, chunk.valid());
        for byte in chunk.invalid() {
            let _ = write!(out, "\\x{byte:02X}");
        }
    }
}

/// Appends `text`, escaped as [`PromptReason`] describes.
fn push_escaped(out: &mut String, text: &str) {
    for c in text.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            '\r' => out.push_str("\\r"),
            c if c.is_control() || is_invisible(c) => {
                let _ = write!(out, "\\u{{{:04X}}}", u32::from(c));
            }
            c => out.push(c),
        }
    }
}

/// Characters that display as nothing, look like an ASCII space without being one (bash does not split words on
/// them), or change how the text around them displays: the Unicode format characters (category `Cf`), invisible
/// fillers and selectors, non-ASCII spaces, and the line and paragraph separators.
fn is_invisible(c: char) -> bool {
    matches!(
        c,
        '\u{00A0}'                      // no-break space
            | '\u{00AD}'                // soft hyphen
            | '\u{034F}'                // combining grapheme joiner
            | '\u{0600}'..='\u{0605}'   // Arabic number signs
            | '\u{061C}'                // Arabic letter mark
            | '\u{06DD}'                // Arabic end of ayah
            | '\u{070F}'                // Syriac abbreviation mark
            | '\u{0890}'..='\u{0891}'   // Arabic pound and piastre marks above
            | '\u{08E2}'                // Arabic disputed end of ayah
            | '\u{115F}'..='\u{1160}'   // Hangul fillers
            | '\u{1680}'                // Ogham space mark
            | '\u{17B4}'..='\u{17B5}'   // Khmer inherent vowels
            | '\u{180B}'..='\u{180F}'   // Mongolian variation selectors and vowel separator
            | '\u{2000}'..='\u{200F}'   // typographic spaces, zero-width space, joiners, LRM, RLM
            | '\u{2028}'..='\u{202F}'   // separators, bidirectional embeddings and overrides, narrow no-break space
            | '\u{205F}'..='\u{206F}'   // medium space, word joiner, invisible operators, bidirectional isolates
            | '\u{2800}'                // braille blank
            | '\u{3000}'                // ideographic space
            | '\u{3164}'                // Hangul filler
            | '\u{FE00}'..='\u{FE0F}'   // variation selectors
            | '\u{FEFF}'                // byte-order mark, zero-width no-break space
            | '\u{FFA0}'                // halfwidth Hangul filler
            | '\u{FFF9}'..='\u{FFFB}'   // interlinear annotation
            | '\u{110BD}' | '\u{110CD}' // Kaithi number signs
            | '\u{13430}'..='\u{1343F}' // Egyptian hieroglyph format controls
            | '\u{1BCA0}'..='\u{1BCA3}' // shorthand format controls
            | '\u{1D173}'..='\u{1D17A}' // musical symbol format controls
            | '\u{E0000}'..='\u{E007F}' // tag characters: invisible copies of ASCII
            | '\u{E0100}'..='\u{E01EF}' // variation selectors supplement
    )
}

#[cfg(test)]
mod tests {
    use knsh_core::Ulid;

    use super::*;
    use crate::testing::ScriptedPresence;

    fn session() -> SessionId {
        SessionId::from_ulid("01JD3Q9ZKX8M4T2V6B7N5C1H0E".parse::<Ulid>().unwrap())
    }

    fn cwd(path: &str) -> CanonicalPath {
        CanonicalPath::new(path).unwrap()
    }

    // NFR-SEC-04: every outcome other than success refuses the action.
    #[test]
    fn refuses_action_when_authentication_cancelled() {
        let presence = ScriptedPresence::new();
        presence.refuse_next(NotAuthenticated::Cancelled);
        let reason = PromptReason::agent_command("git push --force origin main", &cwd("/src/app"), session());

        let mut performed = false;
        let outcome = presence
            .authenticate(&reason, Duration::from_secs(60))
            .map(|_proof| performed = true);

        assert_eq!(outcome, Err(NotAuthenticated::Cancelled));
        assert!(!performed, "the action ran without authentication");
        assert_eq!(presence.prompts().len(), 1, "the prompt was shown");
    }

    // NFR-SEC-04, decision 12: with nothing scripted (nobody at the screen) the fake refuses, as the backend does.
    #[test]
    fn refuses_when_nobody_answers() {
        let presence = ScriptedPresence::new();
        let reason = PromptReason::change("change the policy", "allow network to github.com");
        assert_eq!(
            presence.authenticate(&reason, Duration::from_secs(1)),
            Err(NotAuthenticated::TimedOut)
        );
    }

    // FR-AUTH-41: the reason contains the exact command, cwd and session, readable after "knshd is trying to".
    #[test]
    fn prompt_reason_contains_exact_command() {
        let command = "git push --force origin main && rm -rf ~/build (\"quoted\")";
        let reason = PromptReason::agent_command(command, &cwd("/Users/me/src/app"), session());
        assert_eq!(
            reason.as_str(),
            "approve the agent command: git push --force origin main && rm -rf ~/build (\"quoted\") \
             (cwd /Users/me/src/app, session 01JD3Q9ZKX8M4T2V6B7N5C1H0E)"
        );
        assert!(reason.as_str().contains(command));

        // The backend shows exactly this text.
        let presence = ScriptedPresence::new();
        presence.approve_next();
        let _proof = presence.authenticate(&reason, Duration::from_secs(5)).unwrap();
        assert_eq!(presence.prompts()[0].reason, reason.as_str());
    }

    // FR-AUTH-41: long commands are never shortened.
    #[test]
    fn prompt_reason_keeps_long_commands_in_full() {
        let command = format!("echo {}", "x".repeat(10_000));
        let reason = PromptReason::agent_command(&command, &cwd("/"), session());
        assert!(reason.as_str().contains(&command));
    }

    // FR-AUTH-41: nothing in the command can hide or disguise part of it.
    #[test]
    fn prompt_reason_escapes_hidden_characters() {
        let reason = PromptReason::change(
            "change the policy",
            "a\\nb\nc\td\r\u{1b}[2J\u{202E}~ fr- mr\u{200B}\u{0}",
        );
        assert_eq!(
            reason.as_str(),
            "change the policy: a\\\\nb\\nc\\td\\r\\u{001B}[2J\\u{202E}~ fr- mr\\u{200B}\\u{0000}"
        );
        // Invisible tag characters (an ASCII copy hidden in the text), selectors, fillers and look-alike spaces.
        assert_eq!(
            PromptReason::change("trust", "ls\u{E0072}\u{E006D}\u{FE0F}\u{3164}a\u{00A0}b\u{2003}c").as_str(),
            "trust: ls\\u{E0072}\\u{E006D}\\u{FE0F}\\u{3164}a\\u{00A0}b\\u{2003}c"
        );
        // Printable non-ASCII text is kept as it is.
        assert_eq!(
            PromptReason::change("trust", "café ✓ 日本").as_str(),
            "trust: café ✓ 日本"
        );
    }

    // FR-AUTH-41: a cwd that is not UTF-8 is shown byte for byte.
    #[test]
    fn prompt_reason_escapes_non_utf8_paths() {
        use std::ffi::OsStr;
        let path = CanonicalPath::new(OsStr::from_bytes(b"/tmp/a\xFFb\n")).unwrap();
        let reason = PromptReason::agent_command("ls", &path, session());
        assert!(reason.as_str().contains("(cwd /tmp/a\\xFFb\\n, session"), "{reason}");
    }

    // FR-AUTH-42: the only inputs are the reason and the timeout, and each call shows a new prompt: an earlier
    // success, an identical reason or a long timeout never pre-satisfies the next one.
    #[test]
    fn no_parameter_bypasses_prompt() {
        let presence = ScriptedPresence::new();
        let reason = PromptReason::agent_command("make deploy", &cwd("/src/app"), session());

        presence.approve_next();
        assert_eq!(
            presence.authenticate(&reason, Duration::from_secs(60)),
            Ok(Authenticated::new())
        );
        // Same reason again, straight after a success: a new prompt, and with nobody answering it, a refusal.
        assert_eq!(
            presence.authenticate(&reason, Duration::MAX),
            Err(NotAuthenticated::TimedOut)
        );
        assert_eq!(presence.prompts().len(), 2);

        // The trait's whole surface: one method, taking only the reason and the timeout. Adding a parameter (a skip
        // flag, a cached proof) breaks this line.
        let _: fn(&ScriptedPresence, &PromptReason, Duration) -> Result<Authenticated, NotAuthenticated> =
            <ScriptedPresence as UserPresence>::authenticate;
    }

    #[test]
    fn refusals_explain_without_echoing_the_reason() {
        let all = [
            NotAuthenticated::Cancelled,
            NotAuthenticated::Failed,
            NotAuthenticated::Lockout,
            NotAuthenticated::Unavailable,
            NotAuthenticated::TimedOut,
            NotAuthenticated::Error { code: -1004 },
        ];
        for refusal in all {
            assert!(refusal.to_string().starts_with("not authenticated: "), "{refusal}");
        }
        assert_eq!(
            NotAuthenticated::TimedOut.to_string(),
            "not authenticated: no answer at the Mac's screen before the timeout"
        );
        assert_eq!(
            NotAuthenticated::Error { code: -1004 }.to_string(),
            "not authenticated: the system reported error -1004"
        );
    }
}
