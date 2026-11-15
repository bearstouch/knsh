//! `policy.check`: what policy would decide for a line, without running it (`specs/06-api/agent-socket.md#policycheck`,
//! KNSH-043, FR-POL-70).
//!
//! The parameters come from a client (an agent inside an envelope, or the user's CLI), so each field is bounded and
//! parsed strictly: a line of at most [`MAX_POLICY_CHECK_COMMAND_LEN`] bytes, a working directory that is absolute
//! and already resolved, an optional `PATH` of at most [`MAX_POLICY_CHECK_PATH_LEN`] bytes, and at most one of
//! `session_id` and `profile`. Anything else is `-32602`, never repaired, and never a partial answer.
//!
//! The result is the decision ([`knsh_core::LineDecision`]) with the classification it was made from
//! ([`knsh_core::LineCheck`]): the verdict, its source and deciding rule, every matched rule, each command's class and
//! dynamic reason, the line's dynamic parts and its network classes.

use knsh_core::{CanonicalPath, LineCheck, ProfileName, SessionId};
use knsh_json::{Fields, FromJson, JsonError, Object, ToJson, Value};

use crate::session::{cwd, out_of_range, parse, path_text};

/// The longest line one `policy.check` may carry, in bytes: the same bound as a recorded human line.
pub const MAX_POLICY_CHECK_COMMAND_LEN: usize = 64 * 1024;

/// The longest `PATH` one `policy.check` may carry, in bytes. Only its first
/// [`MAX_PATH_ENTRIES`](knsh_core::MAX_PATH_ENTRIES) entries are ever searched.
pub const MAX_POLICY_CHECK_PATH_LEN: usize = 64 * 1024;

/// The `PATH` names are resolved on when the caller gives none: the system's default search path, holding only
/// trusted folders.
pub const DEFAULT_POLICY_CHECK_PATH: &str = "/usr/bin:/bin:/usr/sbin:/sbin";

/// Whose policy a line is checked against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyCheckTarget {
    /// Neither `session_id` nor `profile`: the caller's own session (`agent.sock`).
    Caller,
    /// `session_id`: that session's profile (`user.sock`).
    Session(SessionId),
    /// `profile`: the named profile (`user.sock`).
    Profile(ProfileName),
}

/// The parameters of `policy.check`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyCheckParams {
    /// The line, at most [`MAX_POLICY_CHECK_COMMAND_LEN`] bytes.
    pub command: String,
    /// The working directory names are resolved from, and `${PROJECT}` is found from.
    pub cwd: CanonicalPath,
    /// The `PATH` names are resolved on; [`DEFAULT_POLICY_CHECK_PATH`] when absent.
    pub path: Option<String>,
    /// Whose policy applies.
    pub target: PolicyCheckTarget,
}

impl FromJson for PolicyCheckParams {
    fn from_json(value: &Value) -> Result<Self, JsonError> {
        let mut fields = Fields::new(value)?;
        let command: String = fields.required("command")?;
        let cwd = cwd(fields.required("cwd")?)?;
        let path: Option<String> = fields.optional("path")?;
        let session_id: Option<String> = fields.optional("session_id")?;
        let profile: Option<String> = fields.optional("profile")?;
        fields.finish()?;
        if command.len() > MAX_POLICY_CHECK_COMMAND_LEN {
            return Err(out_of_range("command"));
        }
        if path.as_ref().is_some_and(|path| path.len() > MAX_POLICY_CHECK_PATH_LEN) {
            return Err(out_of_range("path"));
        }
        let target = match (session_id, profile) {
            (None, None) => PolicyCheckTarget::Caller,
            (Some(session_id), None) => PolicyCheckTarget::Session(parse(&session_id, "session_id")?),
            (None, Some(profile)) => {
                PolicyCheckTarget::Profile(ProfileName::new(&profile).map_err(|_| out_of_range("profile"))?)
            }
            // Two targets would leave the answer's profile ambiguous: refused, never guessed.
            (Some(_), Some(_)) => return Err(out_of_range("profile")),
        };
        Ok(Self {
            command,
            cwd,
            path,
            target,
        })
    }
}

impl ToJson for PolicyCheckParams {
    fn to_json(&self) -> Result<Value, JsonError> {
        let mut object = Object::new()
            .with("command", self.command.as_str())?
            .with("cwd", path_text(&self.cwd))?;
        if let Some(path) = &self.path {
            object.insert("path", Value::from(path.as_str()))?;
        }
        match &self.target {
            PolicyCheckTarget::Caller => {}
            PolicyCheckTarget::Session(session_id) => {
                object.insert("session_id", Value::from(session_id.to_string()))?;
            }
            PolicyCheckTarget::Profile(profile) => {
                object.insert("profile", Value::from(profile.as_str()))?;
            }
        }
        Ok(Value::Object(object))
    }
}

/// The result of `policy.check`: the profile the line was checked against, and the check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyCheckResult {
    /// The profile that decided.
    pub profile: ProfileName,
    /// The classification and the decision.
    pub check: LineCheck,
}

impl ToJson for PolicyCheckResult {
    /// `profile`, `verdict`, `source`, `rule_id`, `reason`, `matched_rules`, `commands`, `dynamic` and
    /// `network_classes` (`specs/06-api/agent-socket.md#policycheck`).
    fn to_json(&self) -> Result<Value, JsonError> {
        let decision = &self.check.decision;
        let classification = &self.check.classification;
        let matched_rules = array(&decision.matched_rules, |part| {
            Object::new()
                .with("command", part.command.to_json()?)?
                .with("verdict", part.verdict.as_str())?
                .with("rule_id", part.rule_id.to_string())
        })?;
        let commands = array(classification.commands(), |command| {
            let program = command
                .program
                .as_ref()
                .and_then(|program| program.path())
                .map(|path| path.to_string_lossy().into_owned());
            let dynamic_reason = command.class.dynamic_reason().map(|reason| reason.code().to_owned());
            Object::new()
                .with("name", command.name.to_json()?)?
                .with("program", program.to_json()?)?
                .with("class", command.class.code())?
                .with("dynamic_reason", dynamic_reason.to_json()?)?
                .with("wrapper", command.wrapper.to_json()?)
        })?;
        let dynamic = array(classification.dynamic_parts(), |part| {
            Object::new()
                .with("reason", part.reason.code())?
                .with("start", part.span.start.to_json()?)?
                .with("end", part.span.end.to_json()?)
        })?;
        let network_classes: Vec<Value> = decision
            .capabilities
            .classes
            .iter()
            .map(|class| Value::from(class.code()))
            .collect();
        Ok(Value::Object(
            Object::new()
                .with("profile", self.profile.as_str())?
                .with("verdict", decision.verdict.as_str())?
                .with("source", decision.source.code())?
                .with("rule_id", decision.rule_id.map(|rule| rule.to_string()).to_json()?)?
                .with("reason", decision.reason.as_ref().map(ToString::to_string).to_json()?)?
                .with("matched_rules", matched_rules)?
                .with("commands", commands)?
                .with("dynamic", dynamic)?
                .with("network_classes", network_classes)?,
        ))
    }
}

/// `items` as a JSON array of objects, each written by `entry`. The first entry that cannot be written fails the
/// whole array, so an answer never carries part of a list.
fn array<T>(items: &[T], entry: impl Fn(&T) -> Result<Object, JsonError>) -> Result<Vec<Value>, JsonError> {
    items.iter().map(|item| entry(item).map(Value::Object)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn object(text: &str) -> Value {
        knsh_json::parse(text.as_bytes(), 1 << 20).unwrap()
    }

    fn params(text: &str) -> Result<PolicyCheckParams, JsonError> {
        PolicyCheckParams::from_json(&object(text))
    }

    #[test]
    fn params_round_trip_for_every_target() {
        for text in [
            r#"{"command":"git push","cwd":"/Users/u/app"}"#,
            r#"{"command":"git push","cwd":"/Users/u/app","path":"/usr/bin","session_id":"01JD0000000000000000000000"}"#,
            r#"{"command":"git push","cwd":"/Users/u/app","profile":"web"}"#,
        ] {
            let parsed = params(text).unwrap();
            assert_eq!(PolicyCheckParams::from_json(&parsed.to_json().unwrap()), Ok(parsed));
        }
        assert_eq!(
            params(r#"{"command":"ls","cwd":"/","profile":"web"}"#).unwrap().target,
            PolicyCheckTarget::Profile(ProfileName::new("web").unwrap())
        );
    }

    // KNSH-043: malformed params are refused whole, never repaired.
    #[test]
    fn params_reject_malformed_fields() {
        let long_command = format!(
            r#"{{"command":"{}","cwd":"/"}}"#,
            "x".repeat(MAX_POLICY_CHECK_COMMAND_LEN + 1)
        );
        let long_path = format!(
            r#"{{"command":"ls","cwd":"/","path":"{}"}}"#,
            "x".repeat(MAX_POLICY_CHECK_PATH_LEN + 1)
        );
        for text in [
            "[]",
            r#"{"cwd":"/"}"#,
            r#"{"command":"ls"}"#,
            r#"{"command":7,"cwd":"/"}"#,
            r#"{"command":"ls","cwd":"relative"}"#,
            r#"{"command":"ls","cwd":"/a/../b"}"#,
            r#"{"command":"ls","cwd":"/","path":3}"#,
            r#"{"command":"ls","cwd":"/","session_id":"not-a-ulid"}"#,
            r#"{"command":"ls","cwd":"/","profile":"../etc"}"#,
            r#"{"command":"ls","cwd":"/","profile":""}"#,
            r#"{"command":"ls","cwd":"/","profile":"web","session_id":"01JD0000000000000000000000"}"#,
            &long_command,
            &long_path,
        ] {
            assert!(params(text).is_err(), "{text}");
        }
        let longest = format!(
            r#"{{"command":"{}","cwd":"/"}}"#,
            "x".repeat(MAX_POLICY_CHECK_COMMAND_LEN)
        );
        assert!(params(&longest).is_ok());
    }
}
