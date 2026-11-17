//! `policy.read` and `policy.edit`: `knsh policy edit` on `user.sock` (KNSH-065; FR-POL-40, FR-POL-41, NFR-SEC-04,
//! `specs/06-api/user-socket.md#policyedit`).
//!
//! `knsh policy edit <profile>` reads the profile's text with `policy.read`, opens it in `$EDITOR`, and sends the
//! saved text with `policy.edit`. `knshd` alone signs and writes policy files:
//!
//! 1. **Read.** `policy.read` returns the file's text without its signature trailer, and its state: `new` (no file),
//!    `valid`, or `invalid` with why (`signature_missing`, `signature_bad`, `key_unavailable`), so the user reviews a
//!    file the engine ignores before signing it. No authentication: the file is the user's own and readable anyway.
//! 2. **Unchanged.** If the text is the file's current text and its signature verifies, nothing is asked or written
//!    (`changed: false`).
//! 3. **Valid.** The text must load as a profile called `<profile>` (with its `extends` chain, which must be signed),
//!    or the edit is `-32602` with the loader's reason in `data.reason`. Nothing broken is ever signed.
//! 4. **Authenticate.** `knshd` shows the Touch ID or password prompt itself (FR-POL-41, decision 12):
//!    `change the policy profile: <profile> (<n> bytes, sha256 <first 16 hex digits>)`, so the prompt names the exact
//!    content the CLI showed. Any outcome but success is `-32001` with `source: "user"` and the refusal in `data.reason`;
//!    nothing is written. No parameter skips the prompt.
//! 5. **Sign and write.** The signed file replaces the old one atomically (`0600`). The key is created in the
//!    Keychain on the first signature. A key that cannot be read (tampering, a locked keychain) or a failed write is
//!    `-32603`, and the previous file is kept.
//!
//! `unattended` is built in (its integrity is the binary's signature), so it is never read or written here
//! (`-32602`). Saves are serialised: lock order is only [`PolicyEditor::saving`], held across the prompt so two edits
//! cannot interleave their check and write.

use std::fmt::Write as _;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use knsh_core::{ProfileName, UNATTENDED_PROFILE, load_profile_text};
use knsh_json::{Object, Value};
use knsh_platform::{FileState, Level, NotAuthenticated, PromptReason, SystemLog, UserPresence};
use knsh_proto::{
    Denial, ErrorCode, PolicyEditParams, PolicyEditResult, PolicyFileState, PolicyReadParams, PolicyReadResult,
    RpcError,
};

use crate::dispatch::{Call, Endpoint, Handler, Handlers, Reply, answer, params};
use crate::policy::ProfileLoader;
use crate::profiles::Hasher;

/// The method that reads a profile for editing.
const POLICY_READ: &str = "policy.read";
/// The method that saves an edited profile.
const POLICY_EDIT: &str = "policy.edit";

/// How long the prompt waits for the user. Shorter than the CLI's read timeout (300 s), so the CLI always gets the
/// answer.
pub(crate) const EDIT_PROMPT_TIMEOUT: Duration = Duration::from_secs(120);

/// Hex digits of the text's SHA-256 shown in the prompt and printed by the CLI (64 bits: enough to tell edits apart
/// at a glance; the signature covers every byte).
pub(crate) const PROMPT_HASH_LEN: usize = 16;

/// The `policy.read` and `policy.edit` service. One per `knshd`.
pub(crate) struct PolicyEditor {
    /// The policies directory, with the signer.
    profiles: ProfileLoader,
    /// The Touch ID or password prompt, shown by `knshd` itself.
    presence: Arc<dyn UserPresence>,
    /// SHA-256 for the prompt text.
    hasher: Hasher,
    /// Edits are logged without their content.
    log: Arc<dyn SystemLog>,
    /// Serialises saves (module documentation).
    saving: Mutex<()>,
}

impl PolicyEditor {
    /// The service over `profiles`, prompting through `presence`.
    pub(crate) fn new(
        profiles: ProfileLoader,
        presence: Arc<dyn UserPresence>,
        hasher: Hasher,
        log: Arc<dyn SystemLog>,
    ) -> Arc<Self> {
        Arc::new(Self {
            profiles,
            presence,
            hasher,
            log,
            saving: Mutex::new(()),
        })
    }

    /// The two handlers.
    pub(crate) fn handlers(self: &Arc<Self>) -> Handlers {
        let reader = Arc::clone(self);
        let read: Handler = Arc::new(move |call: &Call<'_>| reader.read(call));
        let editor = Arc::clone(self);
        let edit: Handler = Arc::new(move |call: &Call<'_>| editor.edit(call));
        [(POLICY_READ, read), (POLICY_EDIT, edit)].into_iter().collect()
    }

    /// `policy.read` (module documentation, step 1).
    fn read(&self, call: &Call<'_>) -> Reply {
        user_only(call)?;
        let PolicyReadParams { profile } = params(call)?;
        editable(&profile)?;
        let current = self
            .profiles
            .directory()
            .read_for_edit(&profile)
            .map_err(|_| RpcError::new(ErrorCode::InternalError))?;
        // TOML is UTF-8; a file that is not cannot be edited as text (and never loads either).
        let text = String::from_utf8(current.body).map_err(|_| RpcError::new(ErrorCode::InternalError))?;
        let (state, reason) = match current.state {
            FileState::New => (PolicyFileState::New, None),
            FileState::Valid => (PolicyFileState::Valid, None),
            FileState::Invalid(fault) => (PolicyFileState::Invalid, Some(fault.code().to_owned())),
        };
        answer(&PolicyReadResult {
            profile,
            text,
            state,
            reason,
        })
    }

    /// `policy.edit` (module documentation, steps 2 to 5).
    fn edit(&self, call: &Call<'_>) -> Reply {
        user_only(call)?;
        let PolicyEditParams { profile, text } = params(call)?;
        editable(&profile)?;
        let body = with_final_newline(text);
        let _saving = self.saving.lock().unwrap_or_else(PoisonError::into_inner);
        let directory = self.profiles.directory();

        let current = directory
            .read_for_edit(&profile)
            .map_err(|_| RpcError::new(ErrorCode::InternalError))?;
        if current.state == FileState::Valid && current.body == body.as_bytes() {
            return answer(&PolicyEditResult {
                profile,
                changed: false,
            });
        }

        self.validate(&profile, body.as_bytes())?;

        let reason = PromptReason::change("change the policy profile", &self.summary(&profile, body.as_bytes()));
        let proof = self
            .presence
            .authenticate(&reason, EDIT_PROMPT_TIMEOUT)
            .map_err(|refusal| {
                self.log
                    .log(Level::Notice, "policy edit refused: not authenticated", &[]);
                not_authenticated(&refusal)
            })?;

        directory.save(&profile, body.as_bytes(), proof).map_err(|_| {
            self.log.log(
                Level::Error,
                "policy edit failed: could not sign or write the file",
                &[],
            );
            RpcError::new(ErrorCode::InternalError)
        })?;
        self.log.log(Level::Notice, "policy profile signed and saved", &[]);
        answer(&PolicyEditResult { profile, changed: true })
    }

    /// Step 3: the text loads as profile `profile`, from the user's home, with its signed parents. `-32602` with the
    /// loader's reason otherwise.
    fn validate(&self, profile: &ProfileName, body: &[u8]) -> Result<(), RpcError> {
        let directory = self.profiles.directory();
        let context = self.profiles.context(self.profiles.home());
        let loaded = load_profile_text(body, &directory, &context, self.profiles.fs())
            .map_err(|error| invalid_text(&error.to_string()))?;
        if &loaded.name != profile {
            return Err(invalid_text("name: name does not match the profile being edited"));
        }
        Ok(())
    }

    /// `<profile> (<n> bytes, sha256 <first 16 hex digits>)`: what the prompt names.
    fn summary(&self, profile: &ProfileName, body: &[u8]) -> String {
        let mut text = format!("{profile} ({} bytes, sha256 ", body.len());
        for byte in &(self.hasher)(body)[..PROMPT_HASH_LEN / 2] {
            let _ = write!(text, "{byte:02x}");
        }
        text.push(')');
        text
    }
}

/// `-32003` unless the call came on `user.sock`. The catalogue lists both methods only there; this is the second
/// lock on the door.
pub(crate) fn user_only(call: &Call<'_>) -> Result<(), RpcError> {
    match call.endpoint {
        Endpoint::User => Ok(()),
        // Signed policy files are edited by the user only (FR-POL-41); the authority pushes policy with
        // `policy.set` instead (KNSH-071).
        Endpoint::Agent | Endpoint::Control => Err(RpcError::new(ErrorCode::NotAllowed)),
    }
}

/// `-32602` for the built-in `unattended` profile, which has no file.
fn editable(profile: &ProfileName) -> Result<(), RpcError> {
    if profile.as_str() == UNATTENDED_PROFILE {
        Err(invalid_text("profile: unattended is built in and has no file to edit"))
    } else {
        Ok(())
    }
}

/// The text as it will be signed: a final newline added when missing, as the signer would.
fn with_final_newline(mut text: String) -> String {
    if !text.is_empty() && !text.ends_with('\n') {
        text.push('\n');
    }
    text
}

/// `-32602` with `data.reason`.
pub(crate) fn invalid_text(reason: &str) -> RpcError {
    let error = RpcError::new(ErrorCode::InvalidParams);
    match Object::new().with("reason", reason) {
        Ok(data) => error.with_data(Value::Object(data)),
        Err(_) => error,
    }
}

/// `-32001` from the user: the prompt did not succeed, so nothing was signed (decision 12).
pub(crate) fn not_authenticated(refusal: &NotAuthenticated) -> RpcError {
    Denial {
        rule_id: None,
        reason: Some(format!("not authenticated: {refusal}")),
        source: Some(String::from("user")),
    }
    .to_error()
    .unwrap_or_else(|_| RpcError::new(ErrorCode::Denied))
}

#[cfg(test)]
pub(crate) mod tests;
