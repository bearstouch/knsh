//! `authority.trust` on `user.sock` and `authority.register` on the control service (KNSH-068; FR-AUTH-01,
//! FR-AUTH-10, `specs/06-api/user-socket.md#authoritytrust`, `specs/06-api/control-service.md#authorityregister`).
//!
//! `authority.trust` carries the three parts of a trust record. Each is parsed by its `knsh-core` type
//! ([`TeamId`], [`SigningIdentifier`], [`BundleVersion`]), so a malformed one is `-32602` before `knshd` shows any
//! prompt (FR-AUTH-10), and nothing that could inject a code-signing requirement clause reaches the engine.
//! `authority.register` takes no parameters: the connection it arrives on is the authority.

use knsh_core::{BundleVersion, SigningIdentifier, TeamId, TrustedAuthority};
use knsh_json::{Fields, FromJson, JsonError, Object, ToJson, Value};

use crate::session::out_of_range;

/// The parameters of `authority.trust`: the authority to trust.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityTrustParams {
    /// The record to store, every part already validated.
    pub authority: TrustedAuthority,
}

impl FromJson for AuthorityTrustParams {
    fn from_json(value: &Value) -> Result<Self, JsonError> {
        let mut fields = Fields::new(value)?;
        let authority = read_authority(&mut fields)?;
        fields.finish()?;
        Ok(Self { authority })
    }
}

impl ToJson for AuthorityTrustParams {
    fn to_json(&self) -> Result<Value, JsonError> {
        authority_object(&self.authority).map(Value::Object)
    }
}

/// The result of `authority.trust`: the record now trusted, and what happened to the previous one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityTrustResult {
    /// The record now stored, as stored (the version in its three-part form).
    pub authority: TrustedAuthority,
    /// `false` when exactly this record was already trusted: nothing was asked or written.
    pub changed: bool,
    /// `true` when a different record was replaced (after the prompt).
    pub replaced: bool,
}

impl FromJson for AuthorityTrustResult {
    fn from_json(value: &Value) -> Result<Self, JsonError> {
        let mut fields = Fields::new(value)?;
        let authority = read_authority(&mut fields)?;
        let changed = fields.required("changed")?;
        let replaced = fields.required("replaced")?;
        fields.finish()?;
        Ok(Self {
            authority,
            changed,
            replaced,
        })
    }
}

/// Reads `{team_id, identifier, min_version}`, each part checked by its `knsh-core` type, so a malformed one is an
/// out-of-range error naming that member (FR-AUTH-10).
fn read_authority(fields: &mut Fields<'_>) -> Result<TrustedAuthority, JsonError> {
    let team_id: String = fields.required("team_id")?;
    let identifier: String = fields.required("identifier")?;
    let min_version: String = fields.required("min_version")?;
    Ok(TrustedAuthority {
        team_id: TeamId::new(&team_id).map_err(|_| out_of_range("team_id"))?,
        identifier: SigningIdentifier::new(&identifier).map_err(|_| out_of_range("identifier"))?,
        min_version: BundleVersion::parse(&min_version).map_err(|_| out_of_range("min_version"))?,
    })
}

impl ToJson for AuthorityTrustResult {
    fn to_json(&self) -> Result<Value, JsonError> {
        authority_object(&self.authority)?
            .with("changed", self.changed)?
            .with("replaced", self.replaced)
            .map(Value::Object)
    }
}

/// `{team_id, identifier, min_version}`.
fn authority_object(authority: &TrustedAuthority) -> Result<Object, JsonError> {
    Object::new()
        .with("team_id", authority.team_id.as_str())?
        .with("identifier", authority.identifier.as_str())?
        .with("min_version", authority.min_version.to_string())
}

/// The parameters of `authority.register`: none (`{}` or absent).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AuthorityRegisterParams;

impl FromJson for AuthorityRegisterParams {
    fn from_json(value: &Value) -> Result<Self, JsonError> {
        Fields::new(value)?.finish()?;
        Ok(Self)
    }
}

impl ToJson for AuthorityRegisterParams {
    fn to_json(&self) -> Result<Value, JsonError> {
        Ok(Value::Object(Object::new()))
    }
}

/// The result of `authority.register`: `{"registered": true}`. A refusal is an error, never `false`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthorityRegisterResult;

impl FromJson for AuthorityRegisterResult {
    fn from_json(value: &Value) -> Result<Self, JsonError> {
        let mut fields = Fields::new(value)?;
        let registered: bool = fields.required("registered")?;
        fields.finish()?;
        if registered {
            Ok(Self)
        } else {
            Err(out_of_range("registered"))
        }
    }
}

impl ToJson for AuthorityRegisterResult {
    fn to_json(&self) -> Result<Value, JsonError> {
        Object::new().with("registered", true).map(Value::Object)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn value(text: &str) -> Value {
        knsh_json::parse(text.as_bytes(), 1 << 20).unwrap()
    }

    // FR-AUTH-10: a malformed team ID, identifier or version is refused while parsing, before any prompt.
    #[test]
    fn trust_params_are_parsed_strictly() {
        let good = r#"{"team_id":"ABCDE12345","identifier":"com.example.authority","min_version":"1.4"}"#;
        let params = AuthorityTrustParams::from_json(&value(good)).unwrap();
        assert_eq!(params.authority.team_id.as_str(), "ABCDE12345");
        assert_eq!(params.authority.min_version.to_string(), "1.4.0");
        assert_eq!(
            knsh_json::write(&params.to_json().unwrap()).unwrap(),
            r#"{"team_id":"ABCDE12345","identifier":"com.example.authority","min_version":"1.4.0"}"#
        );
        for bad in [
            r#"{"team_id":"abcde12345","identifier":"com.example.authority","min_version":"1.4"}"#,
            r#"{"team_id":"ABCDE12345","identifier":"com.example\"x","min_version":"1.4"}"#,
            r#"{"team_id":"ABCDE12345","identifier":"com.example.authority","min_version":"1.4-beta"}"#,
            r#"{"team_id":"ABCDE12345","identifier":"com.example.authority"}"#,
            r#"{"team_id":7,"identifier":"com.example.authority","min_version":"1"}"#,
        ] {
            assert!(AuthorityTrustParams::from_json(&value(bad)).is_err(), "{bad}");
        }
    }

    #[test]
    fn results_round_trip() {
        let result = AuthorityTrustResult {
            authority: AuthorityTrustParams::from_json(&value(
                r#"{"team_id":"ABCDE12345","identifier":"com.example.authority","min_version":"2"}"#,
            ))
            .unwrap()
            .authority,
            changed: true,
            replaced: false,
        };
        assert_eq!(
            AuthorityTrustResult::from_json(&result.to_json().unwrap()).unwrap(),
            result
        );
        assert_eq!(
            knsh_json::write(&AuthorityRegisterResult.to_json().unwrap()).unwrap(),
            r#"{"registered":true}"#
        );
        assert!(AuthorityRegisterParams::from_json(&value("{}")).is_ok());
    }
}
