//! `policy.read` and `policy.edit`: `knsh policy edit` on `user.sock` (KNSH-065, FR-POL-40 to FR-POL-42,
//! `specs/06-api/user-socket.md#policyedit`).
//!
//! `policy.read` returns a profile's text without its signature trailer, and whether the engine currently accepts the
//! file, so the user sees what they are about to sign. `policy.edit` sends the edited text back; `knshd` shows the
//! Touch ID or password prompt itself and signs and writes the file only after the user passed it.
//!
//! The parameters come from a client, so each is bounded and parsed strictly: a profile name from `[A-Za-z0-9._-]`
//! (at most 64 characters) and text of at most [`MAX_POLICY_TEXT_LEN`] bytes. Anything else is `-32602`.

use knsh_core::{MAX_PROFILE_LEN, ProfileName};
use knsh_json::{Fields, FromJson, JsonError, Object, ToJson, Value};

use crate::session::out_of_range;

/// The longest profile text `policy.edit` accepts, in bytes: the profile parser's own limit.
pub const MAX_POLICY_TEXT_LEN: usize = MAX_PROFILE_LEN;

/// Reads a profile name field strictly.
fn profile(fields: &mut Fields<'_>) -> Result<ProfileName, JsonError> {
    let text: String = fields.required("profile")?;
    ProfileName::new(&text).map_err(|_| out_of_range("profile"))
}

/// The parameters of `policy.read`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyReadParams {
    /// The profile to read.
    pub profile: ProfileName,
}

impl FromJson for PolicyReadParams {
    fn from_json(value: &Value) -> Result<Self, JsonError> {
        let mut fields = Fields::new(value)?;
        let profile = profile(&mut fields)?;
        fields.finish()?;
        Ok(Self { profile })
    }
}

impl ToJson for PolicyReadParams {
    fn to_json(&self) -> Result<Value, JsonError> {
        Object::new().with("profile", self.profile.as_str()).map(Value::Object)
    }
}

/// Whether the engine accepts a profile's file as it is now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyFileState {
    /// `new`: no file yet; saving creates the profile.
    New,
    /// `valid`: the signature verifies.
    Valid,
    /// `invalid`: the signature is missing or bad, or the key cannot be read, so the file is ignored (FR-POL-42).
    Invalid,
}

impl PolicyFileState {
    /// The wire value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::New => "new",
            Self::Valid => "valid",
            Self::Invalid => "invalid",
        }
    }

    fn parse(text: &str) -> Result<Self, JsonError> {
        match text {
            "new" => Ok(Self::New),
            "valid" => Ok(Self::Valid),
            "invalid" => Ok(Self::Invalid),
            _ => Err(out_of_range("state")),
        }
    }
}

/// The result of `policy.read`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyReadResult {
    /// The profile read.
    pub profile: ProfileName,
    /// Its text without the signature trailer; empty for a new profile.
    pub text: String,
    /// Whether the engine accepts the file now.
    pub state: PolicyFileState,
    /// Why it is `invalid`: `signature_missing`, `signature_bad` or `key_unavailable`; `None` otherwise.
    pub reason: Option<String>,
}

impl FromJson for PolicyReadResult {
    fn from_json(value: &Value) -> Result<Self, JsonError> {
        let mut fields = Fields::new(value)?;
        let profile = profile(&mut fields)?;
        let text: String = fields.required("text")?;
        let state: String = fields.required("state")?;
        let reason: Option<String> = fields.optional("reason")?;
        fields.finish()?;
        Ok(Self {
            profile,
            text,
            state: PolicyFileState::parse(&state)?,
            reason,
        })
    }
}

impl ToJson for PolicyReadResult {
    fn to_json(&self) -> Result<Value, JsonError> {
        Object::new()
            .with("profile", self.profile.as_str())?
            .with("text", self.text.as_str())?
            .with("state", self.state.as_str())?
            .with("reason", self.reason.to_json()?)
            .map(Value::Object)
    }
}

/// The parameters of `policy.edit`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyEditParams {
    /// The profile to write.
    pub profile: ProfileName,
    /// The new text, without a signature trailer, at most [`MAX_POLICY_TEXT_LEN`] bytes.
    pub text: String,
}

impl FromJson for PolicyEditParams {
    fn from_json(value: &Value) -> Result<Self, JsonError> {
        let mut fields = Fields::new(value)?;
        let profile = profile(&mut fields)?;
        let text: String = fields.required("text")?;
        fields.finish()?;
        if text.len() > MAX_POLICY_TEXT_LEN {
            return Err(out_of_range("text"));
        }
        Ok(Self { profile, text })
    }
}

impl ToJson for PolicyEditParams {
    fn to_json(&self) -> Result<Value, JsonError> {
        Object::new()
            .with("profile", self.profile.as_str())?
            .with("text", self.text.as_str())
            .map(Value::Object)
    }
}

/// The result of `policy.edit`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyEditResult {
    /// The profile written.
    pub profile: ProfileName,
    /// `false` when the text was already the file's and its signature verified: nothing was asked or written.
    pub changed: bool,
}

impl FromJson for PolicyEditResult {
    fn from_json(value: &Value) -> Result<Self, JsonError> {
        let mut fields = Fields::new(value)?;
        let profile = profile(&mut fields)?;
        let changed = fields.required("changed")?;
        fields.finish()?;
        Ok(Self { profile, changed })
    }
}

impl ToJson for PolicyEditResult {
    fn to_json(&self) -> Result<Value, JsonError> {
        Object::new()
            .with("profile", self.profile.as_str())?
            .with("changed", self.changed)
            .map(Value::Object)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn value(text: &str) -> Value {
        knsh_json::parse(text.as_bytes(), 1 << 24).unwrap()
    }

    #[test]
    fn params_are_parsed_strictly() {
        let read = PolicyReadParams::from_json(&value(r#"{"profile":"web-app"}"#)).unwrap();
        assert_eq!(read.profile.as_str(), "web-app");
        for bad in ["{}", r#"{"profile":"a/b"}"#, r#"{"profile":""}"#, r#"{"profile":7}"#] {
            assert!(PolicyReadParams::from_json(&value(bad)).is_err(), "{bad}");
        }
        let edit = PolicyEditParams::from_json(&value(r#"{"profile":"web","text":"name = \"web\"\n"}"#)).unwrap();
        assert_eq!(edit.text, "name = \"web\"\n");
        assert!(PolicyEditParams::from_json(&value(r#"{"profile":"web"}"#)).is_err());
        let long = format!(
            r#"{{"profile":"web","text":"{}"}}"#,
            "a".repeat(MAX_POLICY_TEXT_LEN + 1)
        );
        assert!(PolicyEditParams::from_json(&value(&long)).is_err());
    }

    #[test]
    fn results_round_trip() {
        let read = PolicyReadResult {
            profile: ProfileName::new("web").unwrap(),
            text: String::from("name = \"web\"\n"),
            state: PolicyFileState::Invalid,
            reason: Some(String::from("signature_bad")),
        };
        let json = read.to_json().unwrap();
        assert_eq!(
            knsh_json::write(&json).unwrap(),
            r#"{"profile":"web","text":"name = \"web\"\n","state":"invalid","reason":"signature_bad"}"#
        );
        assert_eq!(PolicyReadResult::from_json(&json).unwrap(), read);
        let edit = PolicyEditResult {
            profile: ProfileName::new("web").unwrap(),
            changed: true,
        };
        assert_eq!(PolicyEditResult::from_json(&edit.to_json().unwrap()).unwrap(), edit);
        let params = PolicyEditParams {
            profile: ProfileName::new("web").unwrap(),
            text: String::from("x"),
        };
        assert_eq!(PolicyEditParams::from_json(&params.to_json().unwrap()).unwrap(), params);
    }
}
