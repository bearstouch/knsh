//! The decision protocol between the engine and the authority (KNSH-069; FR-AUTH-20 to FR-AUTH-24, FR-EVT-06,
//! `specs/06-api/control-service.md#decision-protocol`).
//!
//! - **`decision.requested`** (engine → authority, a notification): one pending ask, with the same members
//!   `approval.list` shows ([`PendingApproval`], FR-AUTH-20). Sent only to the registered authority (FR-EVT-06),
//!   never published as an event.
//! - **`decision.cancelled`** (engine → authority, a notification): a request the engine sent ended without an
//!   answer, because its caller left (FR-AUTH-22) or it timed out (FR-AUTH-23) ([`DecisionCancelledParams`]).
//! - **`decision.respond`** (authority → engine, a call): the answer to one request ([`DecisionRespondParams`]),
//!   answered with whether it was applied ([`DecisionRespondResult`]).
//!
//! The authority is trusted but its messages are still parsed strictly: an answer that is not well formed is
//! `-32602` and is not applied, so the request keeps waiting and is denied at its timeout (fail closed).

use knsh_core::{CancelReason, GrantId, RequestId};
use knsh_json::{Fields, FromJson, JsonError, Object, ToJson, Value};

use crate::approval::PendingApproval;
use crate::session::{out_of_range, parse};

/// The notification that asks the authority to decide a line.
pub const DECISION_REQUESTED: &str = "decision.requested";
/// The notification that withdraws a request the authority was sent.
pub const DECISION_CANCELLED: &str = "decision.cancelled";

/// Longest `reason` in an answer, in bytes: the limit on a hook's reason, since both are shown to the agent.
pub const MAX_DECISION_REASON_LEN: usize = 1024;

/// Longest `command` in a `rewrite` answer, in bytes: the limit on a line the agent sends (`exec.run`), so a
/// rewritten line is never larger than one the agent could have sent.
pub const MAX_REWRITE_COMMAND_LEN: usize = knsh_core::MAX_LINE_LEN;

/// Longest grant an answer may create: 30 days, in seconds. A grant is meant to save repeated approvals for a
/// while, not to change a profile for good (the profile is the place for that).
pub const MAX_GRANT_DURATION_S: u64 = 30 * 24 * 60 * 60;

/// The params of `decision.requested`: exactly what `approval.list` shows for a pending request (FR-AUTH-20).
pub type DecisionRequestedParams = PendingApproval;

/// The params of `decision.cancelled` sent to the authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecisionCancelledParams {
    /// The request that ended.
    pub request_id: RequestId,
    /// Why: its caller left (`caller_gone`) or nobody answered in time (`timed_out`).
    pub reason: CancelReason,
}

impl ToJson for DecisionCancelledParams {
    fn to_json(&self) -> Result<Value, JsonError> {
        Object::new()
            .with("request_id", self.request_id.to_string())?
            .with("reason", self.reason.as_str())
            .map(Value::Object)
    }
}

impl FromJson for DecisionCancelledParams {
    fn from_json(value: &Value) -> Result<Self, JsonError> {
        let mut fields = Fields::new(value)?;
        let request_id = parse(&fields.required::<String>("request_id")?, "request_id")?;
        let reason = match fields.required::<String>("reason")?.as_str() {
            "caller_gone" => CancelReason::CallerGone,
            "timed_out" => CancelReason::TimedOut,
            _ => return Err(out_of_range("reason")),
        };
        fields.finish()?;
        Ok(Self { request_id, reason })
    }
}

/// The authority's verdict on a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecisionAnswer {
    /// `allow`: run the line.
    Allow,
    /// `deny`: refuse it.
    Deny,
    /// `rewrite`: evaluate this line instead, once (FR-AUTH-30, FR-AUTH-31).
    Rewrite {
        /// The new line: non-empty, at most [`MAX_REWRITE_COMMAND_LEN`] bytes.
        command: String,
    },
}

impl DecisionAnswer {
    /// The wire spelling of the verdict.
    #[must_use]
    pub const fn verdict(&self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
            Self::Rewrite { .. } => "rewrite",
        }
    }
}

/// What a grant in an answer applies to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantRequestScope {
    /// `session`: the asking session only.
    Session,
    /// `profile`: every session running under the asking session's profile.
    Profile,
}

impl GrantRequestScope {
    /// The wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Session => "session",
            Self::Profile => "profile",
        }
    }
}

/// A `grant` in an answer: "allow this again, here, for this long" (FR-AUTH-21, FR-POL-62).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GrantRequest {
    /// What the grant applies to.
    pub scope: GrantRequestScope,
    /// How long it lasts: 1 to [`MAX_GRANT_DURATION_S`] seconds.
    pub duration_s: u64,
}

impl FromJson for GrantRequest {
    fn from_json(value: &Value) -> Result<Self, JsonError> {
        let mut fields = Fields::new(value)?;
        let scope = match fields.required::<String>("scope")?.as_str() {
            "session" => GrantRequestScope::Session,
            "profile" => GrantRequestScope::Profile,
            _ => return Err(out_of_range("scope")),
        };
        let duration_s: u64 = fields.required("duration_s")?;
        fields.finish()?;
        if !(1..=MAX_GRANT_DURATION_S).contains(&duration_s) {
            return Err(out_of_range("duration_s"));
        }
        Ok(Self { scope, duration_s })
    }
}

impl ToJson for GrantRequest {
    fn to_json(&self) -> Result<Value, JsonError> {
        Object::new()
            .with("scope", self.scope.as_str())?
            .with("duration_s", self.duration_s.to_json()?)
            .map(Value::Object)
    }
}

/// The params of `decision.respond`.
///
/// # Invariants
///
/// Checked while parsing: `command` is present exactly for `rewrite`; a `grant` comes only with `allow` (a grant
/// means "allow this again", which a deny or a rewrite does not say); `reason` is at most
/// [`MAX_DECISION_REASON_LEN`] bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecisionRespondParams {
    /// The request answered.
    pub request_id: RequestId,
    /// The verdict, with the new line for a rewrite.
    pub answer: DecisionAnswer,
    /// A grant to create with an `allow`.
    pub grant: Option<GrantRequest>,
    /// Shown to the agent on a deny.
    pub reason: Option<String>,
}

impl FromJson for DecisionRespondParams {
    fn from_json(value: &Value) -> Result<Self, JsonError> {
        let mut fields = Fields::new(value)?;
        let request_id = parse(&fields.required::<String>("request_id")?, "request_id")?;
        let verdict: String = fields.required("verdict")?;
        let command: Option<String> = fields.optional("command")?;
        let grant: Option<GrantRequest> = fields.optional("grant")?;
        let reason: Option<String> = fields.optional("reason")?;
        fields.finish()?;
        let answer = match (verdict.as_str(), command) {
            ("allow", None) => DecisionAnswer::Allow,
            ("deny", None) => DecisionAnswer::Deny,
            ("rewrite", Some(command)) if !command.is_empty() && command.len() <= MAX_REWRITE_COMMAND_LEN => {
                DecisionAnswer::Rewrite { command }
            }
            ("rewrite", _) | ("allow" | "deny", Some(_)) => return Err(out_of_range("command")),
            _ => return Err(out_of_range("verdict")),
        };
        if grant.is_some() && answer != DecisionAnswer::Allow {
            return Err(out_of_range("grant"));
        }
        if reason
            .as_ref()
            .is_some_and(|reason| reason.len() > MAX_DECISION_REASON_LEN)
        {
            return Err(out_of_range("reason"));
        }
        Ok(Self {
            request_id,
            answer,
            grant,
            reason,
        })
    }
}

impl ToJson for DecisionRespondParams {
    fn to_json(&self) -> Result<Value, JsonError> {
        let command = match &self.answer {
            DecisionAnswer::Rewrite { command } => Some(command.as_str()),
            DecisionAnswer::Allow | DecisionAnswer::Deny => None,
        };
        let mut object = Object::new()
            .with("request_id", self.request_id.to_string())?
            .with("verdict", self.answer.verdict())?;
        if let Some(command) = command {
            object = object.with("command", command)?;
        }
        if let Some(grant) = &self.grant {
            object = object.with("grant", grant.to_json()?)?;
        }
        if let Some(reason) = &self.reason {
            object = object.with("reason", reason.as_str())?;
        }
        Ok(Value::Object(object))
    }
}

/// The result of `decision.respond`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecisionRespondResult {
    /// `true` when the answer was given to its pending request; `false` when it was ignored because the request is
    /// unknown, already answered, timed out or cancelled (FR-AUTH-22).
    pub applied: bool,
    /// The grant the answer created, to revoke it with `policy.revoke`; `null` when none was asked for or none could
    /// be made (the line cannot be written as a rule, or the grant store refused it).
    pub grant_id: Option<GrantId>,
}

impl ToJson for DecisionRespondResult {
    fn to_json(&self) -> Result<Value, JsonError> {
        Object::new()
            .with("applied", self.applied)?
            .with("grant_id", self.grant_id.map(|id| id.to_string()).to_json()?)
            .map(Value::Object)
    }
}

impl FromJson for DecisionRespondResult {
    fn from_json(value: &Value) -> Result<Self, JsonError> {
        let mut fields = Fields::new(value)?;
        let applied: bool = fields.required("applied")?;
        let grant_id: Option<String> = fields.optional("grant_id")?;
        fields.finish()?;
        let grant_id = grant_id.map(|id| parse(&id, "grant_id")).transpose()?;
        Ok(Self { applied, grant_id })
    }
}

#[cfg(test)]
mod tests {
    use knsh_core::Ulid;

    use super::*;

    const ID: &str = "01J0000000000000000000000A";

    fn value(text: &str) -> Value {
        knsh_json::parse(text.as_bytes(), 1 << 20).unwrap()
    }

    fn respond(text: &str) -> Result<DecisionRespondParams, JsonError> {
        DecisionRespondParams::from_json(&value(text))
    }

    // FR-AUTH-21: `allow`, `deny` and `rewrite` (with `command`), an optional grant and reason.
    #[test]
    fn reads_each_verdict() {
        let allow = respond(&format!(
            r#"{{"request_id":"{ID}","verdict":"allow","grant":{{"scope":"session","duration_s":3600}},"reason":"ok"}}"#
        ))
        .unwrap();
        assert_eq!(allow.answer, DecisionAnswer::Allow);
        assert_eq!(
            allow.grant,
            Some(GrantRequest {
                scope: GrantRequestScope::Session,
                duration_s: 3600
            })
        );
        assert_eq!(allow.reason.as_deref(), Some("ok"));
        let deny = respond(&format!(r#"{{"request_id":"{ID}","verdict":"deny"}}"#)).unwrap();
        assert_eq!(
            (deny.answer, deny.grant, deny.reason),
            (DecisionAnswer::Deny, None, None)
        );
        let rewrite = respond(&format!(
            r#"{{"request_id":"{ID}","verdict":"rewrite","command":"git push --dry-run"}}"#
        ))
        .unwrap();
        assert_eq!(
            rewrite.answer,
            DecisionAnswer::Rewrite {
                command: "git push --dry-run".to_owned()
            }
        );
        for params in [allow, rewrite] {
            assert_eq!(DecisionRespondParams::from_json(&params.to_json().unwrap()), Ok(params));
        }
    }

    // A malformed answer is refused while parsing, so it is never applied.
    #[test]
    fn refuses_malformed_answers() {
        let long_reason = "r".repeat(MAX_DECISION_REASON_LEN + 1);
        let long_command = "a".repeat(MAX_REWRITE_COMMAND_LEN + 1);
        for bad in [
            format!(r#"{{"request_id":"{ID}","verdict":"maybe"}}"#),
            format!(r#"{{"request_id":"{ID}","verdict":"rewrite"}}"#),
            format!(r#"{{"request_id":"{ID}","verdict":"rewrite","command":""}}"#),
            format!(r#"{{"request_id":"{ID}","verdict":"rewrite","command":"{long_command}"}}"#),
            format!(r#"{{"request_id":"{ID}","verdict":"allow","command":"ls"}}"#),
            format!(r#"{{"request_id":"{ID}","verdict":"deny","grant":{{"scope":"session","duration_s":60}}}}"#),
            format!(r#"{{"request_id":"{ID}","verdict":"allow","grant":{{"scope":"forever","duration_s":60}}}}"#),
            format!(r#"{{"request_id":"{ID}","verdict":"allow","grant":{{"scope":"session","duration_s":0}}}}"#),
            format!(
                r#"{{"request_id":"{ID}","verdict":"allow","grant":{{"scope":"session","duration_s":{}}}}}"#,
                MAX_GRANT_DURATION_S + 1
            ),
            format!(r#"{{"request_id":"{ID}","verdict":"deny","reason":"{long_reason}"}}"#),
            r#"{"request_id":"nope","verdict":"deny"}"#.to_owned(),
            r#"{"verdict":"deny"}"#.to_owned(),
        ] {
            assert!(respond(&bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn cancelled_and_result_round_trip() {
        let cancelled = DecisionCancelledParams {
            request_id: RequestId::from_ulid(Ulid::from_u128(5)),
            reason: CancelReason::CallerGone,
        };
        let json = cancelled.to_json().unwrap();
        assert_eq!(
            knsh_json::write(&json).unwrap(),
            format!(r#"{{"request_id":"{}","reason":"caller_gone"}}"#, cancelled.request_id)
        );
        assert_eq!(DecisionCancelledParams::from_json(&json), Ok(cancelled));
        let result = DecisionRespondResult {
            applied: true,
            grant_id: Some(GrantId::from_ulid(Ulid::from_u128(9))),
        };
        assert_eq!(DecisionRespondResult::from_json(&result.to_json().unwrap()), Ok(result));
        let ignored = DecisionRespondResult {
            applied: false,
            grant_id: None,
        };
        assert_eq!(
            knsh_json::write(&ignored.to_json().unwrap()).unwrap(),
            r#"{"applied":false,"grant_id":null}"#
        );
    }
}
