//! `profile.use`: `knsh profile use <profile>` on `user.sock` (KNSH-072, FR-POL-51, FR-POL-52,
//! `specs/06-api/user-socket.md#profileuse`).
//!
//! When pushed policy expires, the agent sessions using it are paused. The user may then select a signed local
//! profile for them: `knshd` shows the Touch ID or password prompt itself, and only after it succeeded do those
//! sessions run under the local profile and resume. The result names every session that was moved.
//!
//! The profile name comes from a client, so it is parsed strictly (`[A-Za-z0-9._-]`, at most 64 characters); anything
//! else is `-32602`.

use knsh_core::{ProfileName, SessionId};
use knsh_json::{Fields, FromJson, JsonError, Object, ToJson, Value};

use crate::session::{out_of_range, parse};

/// Reads the `profile` field strictly.
fn profile(fields: &mut Fields<'_>) -> Result<ProfileName, JsonError> {
    let text: String = fields.required("profile")?;
    ProfileName::new(&text).map_err(|_| out_of_range("profile"))
}

/// The parameters of `profile.use`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileUseParams {
    /// The signed local profile to run the paused sessions under.
    pub profile: ProfileName,
}

impl FromJson for ProfileUseParams {
    fn from_json(value: &Value) -> Result<Self, JsonError> {
        let mut fields = Fields::new(value)?;
        let profile = profile(&mut fields)?;
        fields.finish()?;
        Ok(Self { profile })
    }
}

impl ToJson for ProfileUseParams {
    fn to_json(&self) -> Result<Value, JsonError> {
        Object::new().with("profile", self.profile.as_str()).map(Value::Object)
    }
}

/// The result of `profile.use`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileUseResult {
    /// The profile selected.
    pub profile: ProfileName,
    /// The sessions now running under it and resumed, in ID (start) order. Empty when no session was paused by
    /// expired pushed policy: nothing was asked or changed.
    pub sessions: Vec<SessionId>,
}

impl FromJson for ProfileUseResult {
    fn from_json(value: &Value) -> Result<Self, JsonError> {
        let mut fields = Fields::new(value)?;
        let profile = profile(&mut fields)?;
        let ids: Vec<String> = fields.required("sessions")?;
        fields.finish()?;
        let sessions = ids.iter().map(|id| parse(id, "sessions")).collect::<Result<_, _>>()?;
        Ok(Self { profile, sessions })
    }
}

impl ToJson for ProfileUseResult {
    fn to_json(&self) -> Result<Value, JsonError> {
        let ids: Vec<String> = self.sessions.iter().map(ToString::to_string).collect();
        Object::new()
            .with("profile", self.profile.as_str())?
            .with("sessions", ids.to_json()?)
            .map(Value::Object)
    }
}

#[cfg(test)]
mod tests {
    use knsh_core::Ulid;

    use super::*;

    fn value(text: &str) -> Value {
        knsh_json::parse(text.as_bytes(), 1 << 20).unwrap()
    }

    #[test]
    fn params_are_parsed_strictly() {
        let params = ProfileUseParams::from_json(&value(r#"{"profile":"web-app"}"#)).unwrap();
        assert_eq!(params.profile.as_str(), "web-app");
        for bad in ["{}", r#"{"profile":"a/b"}"#, r#"{"profile":""}"#, r#"{"profile":7}"#] {
            assert!(ProfileUseParams::from_json(&value(bad)).is_err(), "{bad}");
        }
    }

    #[test]
    fn result_round_trips() {
        let result = ProfileUseResult {
            profile: ProfileName::new("local").unwrap(),
            sessions: vec![SessionId::from_ulid(Ulid::new(1, [7; 10]).unwrap())],
        };
        let json = result.to_json().unwrap();
        assert_eq!(ProfileUseResult::from_json(&json).unwrap(), result);
        assert!(ProfileUseResult::from_json(&value(r#"{"profile":"local","sessions":["nope"]}"#)).is_err());
    }
}
