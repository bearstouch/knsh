//! `secrets.provide` and `secrets.revoke` on the control service (KNSH-089; FR-SEC-07,
//! `specs/06-api/control-service.md#secretsprovide`).
//!
//! The authority supplies a named secret for a limited time ([`SecretsProvideParams`]) and may remove it at once
//! ([`SecretsRevokeParams`]). Neither result carries a value: no method ever returns a secret value to any client.
//!
//! Params are parsed as strictly as every other method's: a missing member, a wrong type, an invalid name, an empty
//! or oversized value, or a duration out of range is `-32602`, and nothing is stored.

use knsh_core::{MAX_SECRET_VALUE_LEN, Redacted, SecretName, Timestamp};
use knsh_json::{Fields, FromJson, JsonError, Object, ToJson, Value};

use crate::session::out_of_range;

/// Longest time a provided secret lasts, in seconds (24 hours). Authority-supplied secrets are meant to be
/// short-lived tokens (`specs/03-functional-requirements/secrets.md`); a longer `duration_s` is `-32602`.
pub const MAX_SECRET_DURATION_S: u64 = 24 * 60 * 60;

/// A `name` member: a valid secret name.
fn secret_name(text: &str) -> Result<SecretName, JsonError> {
    SecretName::new(text).map_err(|_| out_of_range("name"))
}

/// The params of `secrets.provide` (FR-SEC-07).
///
/// # Invariants
///
/// Checked while parsing: `name` is a valid [`SecretName`]; `value` is 1 to [`MAX_SECRET_VALUE_LEN`] bytes;
/// `duration_s` is 1 to [`MAX_SECRET_DURATION_S`].
///
/// `Debug` never prints the value ([`Redacted`]). There is deliberately no `ToJson`: the engine never writes a secret
/// value into a message.
#[derive(Debug)]
pub struct SecretsProvideParams {
    /// The secret's name, as profiles refer to it in `[secrets.env]`.
    pub name: SecretName,
    /// The value. Taken out once, by `knshd`, into a buffer that is zeroed on drop.
    pub value: Redacted<String>,
    /// How long it lasts, in seconds.
    pub duration_s: u64,
}

impl FromJson for SecretsProvideParams {
    fn from_json(value: &Value) -> Result<Self, JsonError> {
        let mut fields = Fields::new(value)?;
        let name: String = fields.required("name")?;
        // The member's length is checked before the copy below, so an oversized value is never duplicated.
        if value
            .as_object()
            .and_then(|object| object.get("value"))
            .and_then(Value::as_str)
            .is_some_and(|text| text.is_empty() || text.len() > MAX_SECRET_VALUE_LEN)
        {
            return Err(out_of_range("value"));
        }
        let secret = Redacted::new(fields.required::<String>("value")?);
        let duration_s: u64 = fields.required("duration_s")?;
        fields.finish()?;
        if !(1..=MAX_SECRET_DURATION_S).contains(&duration_s) {
            return Err(out_of_range("duration_s"));
        }
        Ok(Self {
            name: secret_name(&name)?,
            value: secret,
            duration_s,
        })
    }
}

/// The result of `secrets.provide`: when the secret stops being available. Never the value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretsProvideResult {
    /// The secret's name.
    pub name: SecretName,
    /// When it expires and is dropped from memory.
    pub expires_at: Timestamp,
    /// Whether a provided secret of the same name was replaced (its value and expiry).
    pub replaced: bool,
}

impl ToJson for SecretsProvideResult {
    fn to_json(&self) -> Result<Value, JsonError> {
        Object::new()
            .with("name", self.name.as_str())?
            .with("expires_at", self.expires_at.to_string())?
            .with("replaced", self.replaced)
            .map(Value::Object)
    }
}

/// The params of `secrets.revoke`: the provided secret to remove (FR-SEC-07).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretsRevokeParams {
    /// The secret's name.
    pub name: SecretName,
}

impl FromJson for SecretsRevokeParams {
    fn from_json(value: &Value) -> Result<Self, JsonError> {
        let mut fields = Fields::new(value)?;
        let name: String = fields.required("name")?;
        fields.finish()?;
        Ok(Self {
            name: secret_name(&name)?,
        })
    }
}

impl ToJson for SecretsRevokeParams {
    fn to_json(&self) -> Result<Value, JsonError> {
        Object::new().with("name", self.name.as_str()).map(Value::Object)
    }
}

/// The result of `secrets.revoke`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecretsRevokeResult {
    /// Whether a live provided secret of that name was removed. `false` when there was none (never provided,
    /// already expired or revoked); revoking is idempotent. Keychain items are never touched.
    pub revoked: bool,
}

impl ToJson for SecretsRevokeResult {
    fn to_json(&self) -> Result<Value, JsonError> {
        Object::new().with("revoked", self.revoked).map(Value::Object)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn provide(text: &str) -> Result<SecretsProvideParams, JsonError> {
        SecretsProvideParams::from_json(&knsh_json::parse(text.as_bytes(), 4 << 20).unwrap())
    }

    #[test]
    fn parses_provide_params_and_hides_the_value() {
        let params = provide(r#"{"name":"npm-token","value":"s3cr3t","duration_s":600}"#).unwrap();
        assert_eq!(params.name.as_str(), "npm-token");
        assert_eq!(params.value.expose(), "s3cr3t");
        assert_eq!(params.duration_s, 600);
        assert!(!format!("{params:?}").contains("s3cr3t"));
    }

    #[test]
    fn refuses_invalid_provide_params() {
        let oversized = format!(
            r#"{{"name":"t","value":"{}","duration_s":1}}"#,
            "a".repeat(MAX_SECRET_VALUE_LEN + 1)
        );
        let too_long = format!(
            r#"{{"name":"t","value":"v","duration_s":{}}}"#,
            MAX_SECRET_DURATION_S + 1
        );
        for text in [
            r#"{"value":"v","duration_s":1}"#,
            r#"{"name":"t","duration_s":1}"#,
            r#"{"name":"t","value":"v"}"#,
            r#"{"name":"bad name","value":"v","duration_s":1}"#,
            r#"{"name":"","value":"v","duration_s":1}"#,
            r#"{"name":"t","value":"","duration_s":1}"#,
            r#"{"name":"t","value":"v","duration_s":0}"#,
            r#"{"name":"t","value":"v","duration_s":-1}"#,
            r#"{"name":"t","value":42,"duration_s":1}"#,
            r#"{"name":"t","value":"v","duration_s":"1"}"#,
            oversized.as_str(),
            too_long.as_str(),
        ] {
            let refused = provide(text);
            assert!(refused.is_err(), "{}", &text[..text.len().min(80)]);
        }
        // At the limits.
        let largest = format!(
            r#"{{"name":"t","value":"{}","duration_s":{MAX_SECRET_DURATION_S}}}"#,
            "a".repeat(MAX_SECRET_VALUE_LEN)
        );
        assert!(provide(&largest).is_ok());
    }

    #[test]
    fn results_never_carry_a_value() {
        let provided = SecretsProvideResult {
            name: SecretName::new("npm-token").unwrap(),
            expires_at: "2026-11-19T10:00:00Z".parse().unwrap(),
            replaced: false,
        };
        let text = knsh_json::write(&provided.to_json().unwrap()).unwrap();
        assert_eq!(
            text,
            r#"{"name":"npm-token","expires_at":"2026-11-19T10:00:00.000000Z","replaced":false}"#
        );
        let revoked = knsh_json::write(&SecretsRevokeResult { revoked: true }.to_json().unwrap()).unwrap();
        assert_eq!(revoked, r#"{"revoked":true}"#);
    }

    #[test]
    fn parses_revoke_params() {
        let value = knsh_json::parse(br#"{"name":"npm-token"}"#, 4 << 20).unwrap();
        assert_eq!(
            SecretsRevokeParams::from_json(&value).unwrap().name.as_str(),
            "npm-token"
        );
        for text in [r"{}", r#"{"name":"a/b"}"#, r#"{"name":1}"#] {
            let value = knsh_json::parse(text.as_bytes(), 4 << 20).unwrap();
            assert!(SecretsRevokeParams::from_json(&value).is_err(), "{text}");
        }
    }
}
