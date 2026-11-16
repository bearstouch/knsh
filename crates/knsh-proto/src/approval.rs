//! `approval.list`, `approval.approve` and `approval.deny`: pending asks answered from `user.sock` when no authority
//! is connected (KNSH-066; FR-AUTH-40 to FR-AUTH-43, `specs/06-api/user-socket.md#approvals`).
//!
//! `approval.list` shows each pending ask as the authority would see it in `decision.requested` (FR-AUTH-20): request
//! ID, session, actor, redacted command, working directory, matched rule and `timeout_at`. `approval.approve` and
//! `approval.deny` name one request by its ID. Nothing here says the user is present: `knshd` shows its own prompt
//! before an approval counts (FR-AUTH-42), and no parameter can skip it.
//!
//! Parameters come from a client and are parsed strictly: a request ID must be a canonical ULID, or the call is
//! `-32602`.

use knsh_core::{Actor, ActorKind, AgentId, RequestId, SessionId, Timestamp};
use knsh_json::{Fields, FromJson, JsonError, Object, ToJson, Value};

use crate::events::actor as actor_to_json;
use crate::session::{out_of_range, parse};

/// The parameters of `approval.list`: none.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ApprovalListParams;

impl FromJson for ApprovalListParams {
    fn from_json(value: &Value) -> Result<Self, JsonError> {
        Fields::new(value)?.finish()?;
        Ok(Self)
    }
}

impl ToJson for ApprovalListParams {
    fn to_json(&self) -> Result<Value, JsonError> {
        Ok(Value::Object(Object::new()))
    }
}

/// Whether a line is irreversible, and why (`irreversible` in `decision.requested`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Irreversible {
    /// Whether the line is classified as irreversible.
    pub value: bool,
    /// Why, for example `network` or `git push`.
    pub reasons: Vec<String>,
}

impl FromJson for Irreversible {
    fn from_json(value: &Value) -> Result<Self, JsonError> {
        let mut fields = Fields::new(value)?;
        let flag: bool = fields.required("value")?;
        let reasons: Vec<String> = fields.required("reasons")?;
        fields.finish()?;
        Ok(Self { value: flag, reasons })
    }
}

impl ToJson for Irreversible {
    fn to_json(&self) -> Result<Value, JsonError> {
        Object::new()
            .with("value", self.value)?
            .with("reasons", self.reasons.to_json()?)
            .map(Value::Object)
    }
}

/// One pending ask, as `approval.list` shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingApproval {
    /// The request, to name in `approval.approve` or `approval.deny`.
    pub request_id: RequestId,
    /// The session whose line it is.
    pub session_id: SessionId,
    /// The session's actor.
    pub actor: Actor,
    /// The line, redacted (FR-REC-05).
    pub command: String,
    /// The line before a rewrite, redacted, when this line is a rewrite (FR-AUTH-30).
    pub rewritten_from: Option<String>,
    /// The working directory. Lossy UTF-8: bytes that are not UTF-8 are shown as U+FFFD.
    pub cwd: String,
    /// The rule that asked, e.g. `exec.ask[0]`; `None` when only a hook asked.
    pub matched_rule: Option<String>,
    /// The hook that asked, when one did.
    pub hook: Option<String>,
    /// Whether the line is irreversible; `None` until lines are classified for it (KNSH-093).
    pub irreversible: Option<Irreversible>,
    /// When the request will be denied if nobody answers (FR-AUTH-23).
    pub timeout_at: Timestamp,
}

impl FromJson for PendingApproval {
    fn from_json(value: &Value) -> Result<Self, JsonError> {
        let mut fields = Fields::new(value)?;
        let request_id = parse(&fields.required::<String>("request_id")?, "request_id")?;
        let session_id = parse(&fields.required::<String>("session_id")?, "session_id")?;
        let actor = actor_from_json(&fields.required::<Value>("actor")?)?;
        let command: String = fields.required("command")?;
        let rewritten_from: Option<String> = fields.optional("rewritten_from")?;
        let cwd: String = fields.required("cwd")?;
        let matched_rule: Option<String> = fields.optional("matched_rule")?;
        let hook: Option<String> = fields.optional("hook")?;
        let irreversible: Option<Irreversible> = fields.optional("irreversible")?;
        let timeout_at = parse(&fields.required::<String>("timeout_at")?, "timeout_at")?;
        fields.finish()?;
        Ok(Self {
            request_id,
            session_id,
            actor,
            command,
            rewritten_from,
            cwd,
            matched_rule,
            hook,
            irreversible,
            timeout_at,
        })
    }
}

impl ToJson for PendingApproval {
    fn to_json(&self) -> Result<Value, JsonError> {
        Object::new()
            .with("request_id", self.request_id.to_string())?
            .with("session_id", self.session_id.to_string())?
            .with("actor", Value::Object(actor_to_json(&self.actor)?))?
            .with("command", self.command.as_str())?
            .with("rewritten_from", self.rewritten_from.to_json()?)?
            .with("cwd", self.cwd.as_str())?
            .with("matched_rule", self.matched_rule.to_json()?)?
            .with("hook", self.hook.to_json()?)?
            .with("irreversible", self.irreversible.to_json()?)?
            .with("timeout_at", self.timeout_at.to_string())
            .map(Value::Object)
    }
}

/// Reads `{kind, agent_id?}`; an agent without an ID, or a human with one, is out of range.
fn actor_from_json(value: &Value) -> Result<Actor, JsonError> {
    let mut fields = Fields::new(value)?;
    let kind: String = fields.required("kind")?;
    let agent_id: Option<String> = fields.optional("agent_id")?;
    fields.finish()?;
    let kind = match kind.as_str() {
        "human" => ActorKind::Human,
        "agent" => ActorKind::Agent,
        _ => return Err(out_of_range("kind")),
    };
    let agent_id = agent_id
        .map(|id| AgentId::new(&id).map_err(|_| out_of_range("agent_id")))
        .transpose()?;
    Actor::from_parts(kind, agent_id).map_err(|_| out_of_range("actor"))
}

/// The result of `approval.list`: every pending ask, oldest first.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ApprovalListResult {
    /// The pending asks, in request ID (creation) order.
    pub requests: Vec<PendingApproval>,
}

impl FromJson for ApprovalListResult {
    fn from_json(value: &Value) -> Result<Self, JsonError> {
        let mut fields = Fields::new(value)?;
        let requests: Vec<PendingApproval> = fields.required("requests")?;
        fields.finish()?;
        Ok(Self { requests })
    }
}

impl ToJson for ApprovalListResult {
    fn to_json(&self) -> Result<Value, JsonError> {
        Object::new()
            .with("requests", self.requests.to_json()?)
            .map(Value::Object)
    }
}

/// The parameters of `approval.approve` and `approval.deny`: the request to answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApprovalAnswerParams {
    /// The pending request, as `approval.list` showed it.
    pub request_id: RequestId,
}

impl FromJson for ApprovalAnswerParams {
    fn from_json(value: &Value) -> Result<Self, JsonError> {
        let mut fields = Fields::new(value)?;
        let request_id = parse(&fields.required::<String>("request_id")?, "request_id")?;
        fields.finish()?;
        Ok(Self { request_id })
    }
}

impl ToJson for ApprovalAnswerParams {
    fn to_json(&self) -> Result<Value, JsonError> {
        Object::new()
            .with("request_id", self.request_id.to_string())
            .map(Value::Object)
    }
}

/// How a request was answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalVerdict {
    /// `allow`: the line runs.
    Allow,
    /// `deny`: the line is refused.
    Deny,
}

impl ApprovalVerdict {
    /// The wire value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
        }
    }
}

/// The result of `approval.approve` and `approval.deny`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApprovalAnswerResult {
    /// The request answered.
    pub request_id: RequestId,
    /// The answer given.
    pub verdict: ApprovalVerdict,
}

impl FromJson for ApprovalAnswerResult {
    fn from_json(value: &Value) -> Result<Self, JsonError> {
        let mut fields = Fields::new(value)?;
        let request_id = parse(&fields.required::<String>("request_id")?, "request_id")?;
        let verdict: String = fields.required("verdict")?;
        fields.finish()?;
        let verdict = match verdict.as_str() {
            "allow" => ApprovalVerdict::Allow,
            "deny" => ApprovalVerdict::Deny,
            _ => return Err(out_of_range("verdict")),
        };
        Ok(Self { request_id, verdict })
    }
}

impl ToJson for ApprovalAnswerResult {
    fn to_json(&self) -> Result<Value, JsonError> {
        Object::new()
            .with("request_id", self.request_id.to_string())?
            .with("verdict", self.verdict.as_str())
            .map(Value::Object)
    }
}

#[cfg(test)]
mod tests {
    use knsh_core::Ulid;

    use super::*;

    fn object(text: &str) -> Value {
        knsh_json::parse(text.as_bytes(), 1 << 16).unwrap()
    }

    fn entry() -> PendingApproval {
        PendingApproval {
            request_id: RequestId::from_ulid(Ulid::new(1_800_000_000_000, [1; 10]).unwrap()),
            session_id: SessionId::from_ulid(Ulid::new(1_800_000_000_000, [2; 10]).unwrap()),
            actor: Actor::Agent(AgentId::new("claude-code").unwrap()),
            command: "git push origin main".to_owned(),
            rewritten_from: None,
            cwd: "/Users/me/code/app".to_owned(),
            matched_rule: Some("exec.ask[0]".to_owned()),
            hook: None,
            irreversible: None,
            timeout_at: Timestamp::from_unix_micros(1_800_000_090_000_000).unwrap(),
        }
    }

    // FR-AUTH-40, FR-AUTH-20: each pending ask carries the fields the authority would see, and survives a round trip.
    #[test]
    fn pending_requests_round_trip_with_every_field() {
        let list = ApprovalListResult {
            requests: vec![entry()],
        };
        let text = knsh_json::write(&list.to_json().unwrap()).unwrap();
        for field in [
            "\"request_id\":",
            "\"session_id\":",
            r#""actor":{"kind":"agent","agent_id":"claude-code"}"#,
            r#""command":"git push origin main""#,
            r#""matched_rule":"exec.ask[0]""#,
            r#""irreversible":null"#,
            r#""timeout_at":"2027-01-15T08:01:30.000000Z""#,
        ] {
            assert!(text.contains(field), "{field} in {text}");
        }
        assert_eq!(ApprovalListResult::from_json(&object(&text)).unwrap(), list);

        let mut flagged = entry();
        flagged.irreversible = Some(Irreversible {
            value: true,
            reasons: vec!["network".to_owned()],
        });
        let value = flagged.to_json().unwrap();
        assert_eq!(PendingApproval::from_json(&value).unwrap(), flagged);
    }

    // FR-AUTH-42: the answer names only the request; a malformed ID is refused (-32602 at the dispatcher).
    #[test]
    fn answer_params_take_only_a_canonical_request_id() {
        let id = entry().request_id;
        let params = ApprovalAnswerParams { request_id: id };
        assert_eq!(
            ApprovalAnswerParams::from_json(&params.to_json().unwrap()).unwrap(),
            params
        );
        assert!(ApprovalAnswerParams::from_json(&object("{}")).is_err());
        assert!(ApprovalAnswerParams::from_json(&object(r#"{"request_id":"nope"}"#)).is_err());
        assert!(ApprovalAnswerParams::from_json(&object(r#"{"request_id":7}"#)).is_err());
        assert!(ApprovalListParams::from_json(&object("{}")).is_ok());

        let answered = ApprovalAnswerResult {
            request_id: id,
            verdict: ApprovalVerdict::Deny,
        };
        let value = answered.to_json().unwrap();
        assert_eq!(ApprovalAnswerResult::from_json(&value).unwrap(), answered);
        assert!(ApprovalAnswerResult::from_json(&object(r#"{"request_id":"x","verdict":"maybe"}"#)).is_err());
    }

    #[test]
    fn actor_parts_must_agree() {
        assert_eq!(actor_from_json(&object(r#"{"kind":"human"}"#)).unwrap(), Actor::Human);
        assert!(actor_from_json(&object(r#"{"kind":"agent"}"#)).is_err());
        assert!(actor_from_json(&object(r#"{"kind":"human","agent_id":"x"}"#)).is_err());
        assert!(actor_from_json(&object(r#"{"kind":"robot"}"#)).is_err());
    }
}
