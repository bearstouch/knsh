//! The authority's supervision methods on the control service (KNSH-071; FR-SES-02, FR-POL-01, FR-POL-50,
//! FR-POL-53, FR-POL-60 to FR-POL-62; `specs/06-api/control-service.md`).
//!
//! - **Sessions:** `session.create` makes an agent session for an agent the authority starts itself
//!   ([`SessionCreateParams`]); `session.end`, `session.pause`, `session.resume`, `session.take_control` and
//!   `session.release_control` move any live agent session ([`SessionTargetParams`], [`SessionStateResult`]);
//!   `session.list` lists every live session ([`SessionListResult`]).
//! - **Policy:** `policy.set` pushes a snapshot ([`PolicySetParams`]), which must carry `expires_at` (FR-POL-50);
//!   `policy.get` reads what a profile name loads from ([`PolicyGetParams`], [`PolicyGetResult`]).
//! - **Grants:** `policy.grant` ([`PolicyGrantParams`]), `policy.grants` ([`PolicyGrantsResult`]) and
//!   `policy.revoke` ([`PolicyRevokeParams`]).
//! - **Recording:** `recording.set` ([`RecordingSetParams`]), answered with the session as `session.info` shows it.
//!
//! The authority is trusted, but its params are parsed as strictly as an agent's: missing members, wrong types and
//! values out of range are `-32602`, and nothing is applied. Unknown members are ignored, as everywhere (the protocol
//! is additive, `specs/06-api/handshake.md#rules`).

use knsh_core::{AgentId, GrantId, MAX_PROFILE_LEN, ProfileName, SessionId, SessionState, Timestamp};
use knsh_json::{Fields, FromJson, JsonError, Object, ToJson, Value};

use crate::decision::{GrantRequestScope, MAX_GRANT_DURATION_S};
use crate::session::{SessionInfoResult, out_of_range, parse};

/// Longest grant rule `policy.grant` accepts, in bytes: a rule is one command pattern, like an `exec.allow` entry.
pub const MAX_GRANT_RULE_LEN: usize = 4096;

/// A `profile` member: a valid profile name.
fn profile_name(text: &str) -> Result<ProfileName, JsonError> {
    ProfileName::new(text).map_err(|_| out_of_range("profile"))
}

/// The params of `session.list` and `policy.grants`: none.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct NoParams;

impl FromJson for NoParams {
    fn from_json(value: &Value) -> Result<Self, JsonError> {
        Fields::new(value)?.finish()?;
        Ok(Self)
    }
}

impl ToJson for NoParams {
    fn to_json(&self) -> Result<Value, JsonError> {
        Ok(Value::Object(Object::new()))
    }
}

/// The params of `session.create`: an agent session the authority starts an agent in itself (FR-SES-02).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionCreateParams {
    /// The actor's `agent_id`.
    pub agent: AgentId,
    /// The session's profile.
    pub profile: ProfileName,
}

impl FromJson for SessionCreateParams {
    fn from_json(value: &Value) -> Result<Self, JsonError> {
        let mut fields = Fields::new(value)?;
        let agent: String = fields.required("agent")?;
        let profile: String = fields.required("profile")?;
        fields.finish()?;
        Ok(Self {
            agent: AgentId::new(&agent).map_err(|_| out_of_range("agent"))?,
            profile: profile_name(&profile)?,
        })
    }
}

impl ToJson for SessionCreateParams {
    fn to_json(&self) -> Result<Value, JsonError> {
        Object::new()
            .with("agent", self.agent.as_str())?
            .with("profile", self.profile.as_str())
            .map(Value::Object)
    }
}

/// The result of `session.create`: the new session and the token its agent binds with on `agent.sock`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionCreateResult {
    /// The new session.
    pub session_id: SessionId,
    /// Its session token: what the agent passes in `hello` (or as `KNSH_SESSION_TOKEN`) to act for the session.
    /// Sent only to the authority, which hands it to the agent it starts.
    pub session_token: String,
}

impl ToJson for SessionCreateResult {
    fn to_json(&self) -> Result<Value, JsonError> {
        Object::new()
            .with("session_id", self.session_id.to_string())?
            .with("session_token", self.session_token.as_str())
            .map(Value::Object)
    }
}

/// The params of `session.end`, `session.pause`, `session.resume`, `session.take_control` and
/// `session.release_control`: the session to act on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionTargetParams {
    /// Any live session.
    pub session_id: SessionId,
}

impl FromJson for SessionTargetParams {
    fn from_json(value: &Value) -> Result<Self, JsonError> {
        let mut fields = Fields::new(value)?;
        let session_id = parse(&fields.required::<String>("session_id")?, "session_id")?;
        fields.finish()?;
        Ok(Self { session_id })
    }
}

impl ToJson for SessionTargetParams {
    fn to_json(&self) -> Result<Value, JsonError> {
        Object::new()
            .with("session_id", self.session_id.to_string())
            .map(Value::Object)
    }
}

/// The result of a session state change: the session and the state it is now in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionStateResult {
    /// The session.
    pub session_id: SessionId,
    /// Its state after the call.
    pub state: SessionState,
}

impl ToJson for SessionStateResult {
    fn to_json(&self) -> Result<Value, JsonError> {
        Object::new()
            .with("session_id", self.session_id.to_string())?
            .with("state", self.state.as_str())
            .map(Value::Object)
    }
}

/// The result of `session.list`: every live session, each as `session.info` shows one, in ID (start) order.
#[derive(Debug, Clone)]
pub struct SessionListResult {
    /// The live sessions.
    pub sessions: Vec<SessionInfoResult>,
}

impl ToJson for SessionListResult {
    fn to_json(&self) -> Result<Value, JsonError> {
        Object::new()
            .with("sessions", self.sessions.to_json()?)
            .map(Value::Object)
    }
}

/// The params of `policy.set`: one profile's snapshot.
///
/// # Invariants
///
/// Checked while parsing: `expires_at` is present (FR-POL-50) and `policy` is at most [`MAX_PROFILE_LEN`] bytes.
/// Whether it is a valid profile is checked by `knshd` with the loader files go through (FR-POL-01).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicySetParams {
    /// The profile the snapshot defines.
    pub profile: ProfileName,
    /// Its text: a profile in the TOML subset of `specs/05-models/policy-profile.md`, as a file would hold.
    pub policy: String,
    /// When it stops applying (FR-POL-50).
    pub expires_at: Timestamp,
}

impl FromJson for PolicySetParams {
    fn from_json(value: &Value) -> Result<Self, JsonError> {
        let mut fields = Fields::new(value)?;
        let profile: String = fields.required("profile")?;
        let policy: String = fields.required("policy")?;
        // FR-POL-50: a snapshot without `expires_at` is refused, never given a default lifetime.
        let expires_at = parse(&fields.required::<String>("expires_at")?, "expires_at")?;
        fields.finish()?;
        if policy.len() > MAX_PROFILE_LEN {
            return Err(out_of_range("policy"));
        }
        Ok(Self {
            profile: profile_name(&profile)?,
            policy,
            expires_at,
        })
    }
}

impl ToJson for PolicySetParams {
    fn to_json(&self) -> Result<Value, JsonError> {
        Object::new()
            .with("profile", self.profile.as_str())?
            .with("policy", self.policy.as_str())?
            .with("expires_at", self.expires_at.to_string())
            .map(Value::Object)
    }
}

/// The result of `policy.set`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolicySetResult {
    /// Whether a snapshot of the same profile was replaced.
    pub replaced: bool,
}

impl ToJson for PolicySetResult {
    fn to_json(&self) -> Result<Value, JsonError> {
        Object::new().with("replaced", self.replaced).map(Value::Object)
    }
}

/// The params of `policy.get`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyGetParams {
    /// The profile to read.
    pub profile: ProfileName,
}

impl FromJson for PolicyGetParams {
    fn from_json(value: &Value) -> Result<Self, JsonError> {
        let mut fields = Fields::new(value)?;
        let profile: String = fields.required("profile")?;
        fields.finish()?;
        Ok(Self {
            profile: profile_name(&profile)?,
        })
    }
}

impl ToJson for PolicyGetParams {
    fn to_json(&self) -> Result<Value, JsonError> {
        Object::new().with("profile", self.profile.as_str()).map(Value::Object)
    }
}

/// Where a profile name's text comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicySource {
    /// A snapshot pushed with `policy.set`.
    Pushed,
    /// A signed file in the policies directory.
    File,
    /// Compiled into the engine (`unattended`).
    Builtin,
}

impl PolicySource {
    /// The wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pushed => "pushed",
            Self::File => "file",
            Self::Builtin => "builtin",
        }
    }
}

/// The result of `policy.get`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyGetResult {
    /// The profile read.
    pub profile: ProfileName,
    /// Where its text comes from.
    pub source: PolicySource,
    /// The text as the loader reads it: the snapshot, or the file's body once its signature verified; `None` for a
    /// built-in profile.
    pub policy: Option<String>,
    /// The snapshot's expiry; `None` for a file or built-in profile.
    pub expires_at: Option<Timestamp>,
    /// Whether the snapshot has expired: its profile then loads for nothing until replaced (FR-POL-52).
    pub expired: bool,
}

impl ToJson for PolicyGetResult {
    fn to_json(&self) -> Result<Value, JsonError> {
        Object::new()
            .with("profile", self.profile.as_str())?
            .with("source", self.source.as_str())?
            .with("policy", self.policy.to_json()?)?
            .with("expires_at", self.expires_at.map(|at| at.to_string()).to_json()?)?
            .with("expired", self.expired)
            .map(Value::Object)
    }
}

/// What a grant made with `policy.grant` applies to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GrantTargetParam {
    /// `scope: "session"` with `session_id`.
    Session(SessionId),
    /// `scope: "profile"` with `profile`.
    Profile(ProfileName),
}

/// The params of `policy.grant` on the control service (FR-POL-62).
///
/// # Invariants
///
/// Checked while parsing: `session_id` comes exactly with `scope: "session"`, `profile` exactly with
/// `scope: "profile"`; `rule` is non-empty and at most [`MAX_GRANT_RULE_LEN`] bytes; `duration_s` is 1 to
/// [`MAX_GRANT_DURATION_S`]. Whether `rule` is a command pattern is checked when the grant is made.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyGrantParams {
    /// What the grant applies to.
    pub target: GrantTargetParam,
    /// The command pattern it allows, read like an `exec.allow` entry.
    pub rule: String,
    /// How long it lasts, in seconds.
    pub duration_s: u64,
}

impl FromJson for PolicyGrantParams {
    fn from_json(value: &Value) -> Result<Self, JsonError> {
        let mut fields = Fields::new(value)?;
        let scope: String = fields.required("scope")?;
        let session_id: Option<String> = fields.optional("session_id")?;
        let profile: Option<String> = fields.optional("profile")?;
        let rule: String = fields.required("rule")?;
        let duration_s: u64 = fields.required("duration_s")?;
        fields.finish()?;
        let target = match (scope.as_str(), session_id, profile) {
            ("session", Some(session_id), None) => GrantTargetParam::Session(parse(&session_id, "session_id")?),
            ("profile", None, Some(profile)) => GrantTargetParam::Profile(profile_name(&profile)?),
            ("session", ..) => return Err(out_of_range("session_id")),
            ("profile", ..) => return Err(out_of_range("profile")),
            _ => return Err(out_of_range("scope")),
        };
        if rule.is_empty() || rule.len() > MAX_GRANT_RULE_LEN {
            return Err(out_of_range("rule"));
        }
        if !(1..=MAX_GRANT_DURATION_S).contains(&duration_s) {
            return Err(out_of_range("duration_s"));
        }
        Ok(Self {
            target,
            rule,
            duration_s,
        })
    }
}

impl ToJson for PolicyGrantParams {
    fn to_json(&self) -> Result<Value, JsonError> {
        let object = match &self.target {
            GrantTargetParam::Session(session_id) => Object::new()
                .with("scope", GrantRequestScope::Session.as_str())?
                .with("session_id", session_id.to_string())?,
            GrantTargetParam::Profile(profile) => Object::new()
                .with("scope", GrantRequestScope::Profile.as_str())?
                .with("profile", profile.as_str())?,
        };
        object
            .with("rule", self.rule.as_str())?
            .with("duration_s", self.duration_s.to_json()?)
            .map(Value::Object)
    }
}

/// The result of `policy.grant`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolicyGrantResult {
    /// The new grant, for `policy.revoke`.
    pub grant_id: GrantId,
    /// When it stops applying.
    pub expires_at: Timestamp,
}

impl ToJson for PolicyGrantResult {
    fn to_json(&self) -> Result<Value, JsonError> {
        Object::new()
            .with("grant_id", self.grant_id.to_string())?
            .with("expires_at", self.expires_at.to_string())
            .map(Value::Object)
    }
}

/// One live grant, as `policy.grants` lists it (`specs/05-models/grant.md`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantEntry {
    /// Its ID.
    pub grant_id: GrantId,
    /// What it applies to.
    pub target: GrantTargetParam,
    /// The command pattern it allows.
    pub rule: String,
    /// Whether the rule covers the command with exactly its arguments only (a grant from an answer, KNSH-069).
    pub exact: bool,
    /// When it stops applying.
    pub expires_at: Timestamp,
}

impl ToJson for GrantEntry {
    /// `grant_id`, `scope`, `session_id` (or `null`), `profile` (or `null`), `rule`, `exact`, `expires_at`.
    fn to_json(&self) -> Result<Value, JsonError> {
        let (scope, session_id, profile) = match &self.target {
            GrantTargetParam::Session(session_id) => ("session", Some(session_id.to_string()), None),
            GrantTargetParam::Profile(profile) => ("profile", None, Some(profile.as_str().to_owned())),
        };
        Object::new()
            .with("grant_id", self.grant_id.to_string())?
            .with("scope", scope)?
            .with("session_id", session_id.to_json()?)?
            .with("profile", profile.to_json()?)?
            .with("rule", self.rule.as_str())?
            .with("exact", self.exact)?
            .with("expires_at", self.expires_at.to_string())
            .map(Value::Object)
    }
}

/// The result of `policy.grants`: every live grant, in ID (creation) order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyGrantsResult {
    /// The grants.
    pub grants: Vec<GrantEntry>,
}

impl ToJson for PolicyGrantsResult {
    fn to_json(&self) -> Result<Value, JsonError> {
        Object::new().with("grants", self.grants.to_json()?).map(Value::Object)
    }
}

/// The params of `policy.revoke`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolicyRevokeParams {
    /// The grant to remove.
    pub grant_id: GrantId,
}

impl FromJson for PolicyRevokeParams {
    fn from_json(value: &Value) -> Result<Self, JsonError> {
        let mut fields = Fields::new(value)?;
        let grant_id = parse(&fields.required::<String>("grant_id")?, "grant_id")?;
        fields.finish()?;
        Ok(Self { grant_id })
    }
}

impl ToJson for PolicyRevokeParams {
    fn to_json(&self) -> Result<Value, JsonError> {
        Object::new()
            .with("grant_id", self.grant_id.to_string())
            .map(Value::Object)
    }
}

/// The result of `policy.revoke`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolicyRevokeResult {
    /// `true` when a live grant was removed; `false` for an unknown or already expired one
    /// (`specs/05-models/grant.md`: an expired grant is reported as not found).
    pub revoked: bool,
}

impl ToJson for PolicyRevokeResult {
    fn to_json(&self) -> Result<Value, JsonError> {
        Object::new().with("revoked", self.revoked).map(Value::Object)
    }
}

/// The params of `recording.set`: at least one of `commands` and `output`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordingSetParams {
    /// The agent session.
    pub session_id: SessionId,
    /// Command recording, the session's `recording`.
    pub commands: Option<bool>,
    /// Output recording, in place of the profile's `recording.output`.
    pub output: Option<bool>,
}

impl FromJson for RecordingSetParams {
    fn from_json(value: &Value) -> Result<Self, JsonError> {
        let mut fields = Fields::new(value)?;
        let session_id = parse(&fields.required::<String>("session_id")?, "session_id")?;
        let commands: Option<bool> = fields.optional("commands")?;
        let output: Option<bool> = fields.optional("output")?;
        fields.finish()?;
        if commands.is_none() && output.is_none() {
            // A call that changes nothing is a mistake, not a no-op to answer quietly.
            return Err(out_of_range("commands"));
        }
        Ok(Self {
            session_id,
            commands,
            output,
        })
    }
}

impl ToJson for RecordingSetParams {
    fn to_json(&self) -> Result<Value, JsonError> {
        let mut object = Object::new().with("session_id", self.session_id.to_string())?;
        if let Some(commands) = self.commands {
            object = object.with("commands", commands)?;
        }
        if let Some(output) = self.output {
            object = object.with("output", output)?;
        }
        Ok(Value::Object(object))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SESSION: &str = "01J0000000000000000000000A";

    fn value(text: &str) -> Value {
        knsh_json::parse(text.as_bytes(), 4 << 20).unwrap()
    }

    fn text(value: &impl ToJson) -> String {
        knsh_json::write(&value.to_json().unwrap()).unwrap()
    }

    // FR-POL-50: a snapshot without `expires_at` is refused; a complete one round-trips.
    #[test]
    fn policy_set_requires_expires_at() {
        let without = r#"{"profile":"web-app","policy":"name = \"web-app\"\n"}"#;
        assert!(PolicySetParams::from_json(&value(without)).is_err());
        let with =
            r#"{"profile":"web-app","policy":"name = \"web-app\"\n","expires_at":"2026-11-18T00:00:00.000000Z"}"#;
        let params = PolicySetParams::from_json(&value(with)).unwrap();
        assert_eq!(params.profile.as_str(), "web-app");
        assert_eq!(PolicySetParams::from_json(&params.to_json().unwrap()).unwrap(), params);
        for bad in [
            r#"{"profile":"web app","policy":"","expires_at":"2026-11-18T00:00:00.000000Z"}"#,
            r#"{"profile":"web-app","policy":"","expires_at":"tomorrow"}"#,
        ] {
            assert!(PolicySetParams::from_json(&value(bad)).is_err(), "{bad}");
        }
        let long = format!(
            r#"{{"profile":"web-app","policy":"{}","expires_at":"2026-11-18T00:00:00.000000Z"}}"#,
            "#".repeat(MAX_PROFILE_LEN + 1)
        );
        assert!(PolicySetParams::from_json(&value(&long)).is_err());
    }

    // FR-POL-60, FR-POL-62: a grant names its scope with exactly the matching target, a rule and a bounded
    // duration.
    #[test]
    fn reads_grant_params_strictly() {
        let session = format!(r#"{{"scope":"session","session_id":"{SESSION}","rule":"git push","duration_s":60}}"#);
        let params = PolicyGrantParams::from_json(&value(&session)).unwrap();
        assert!(matches!(params.target, GrantTargetParam::Session(_)));
        assert_eq!(
            PolicyGrantParams::from_json(&params.to_json().unwrap()).unwrap(),
            params
        );
        let profile = r#"{"scope":"profile","profile":"web-app","rule":"npm test","duration_s":3600}"#;
        let params = PolicyGrantParams::from_json(&value(profile)).unwrap();
        assert_eq!(
            params.target,
            GrantTargetParam::Profile(ProfileName::new("web-app").unwrap())
        );
        for bad in [
            r#"{"scope":"session","profile":"web-app","rule":"ls","duration_s":60}"#.to_owned(),
            format!(r#"{{"scope":"session","session_id":"{SESSION}","profile":"x","rule":"ls","duration_s":60}}"#),
            r#"{"scope":"profile","rule":"ls","duration_s":60}"#.to_owned(),
            r#"{"scope":"engine","rule":"ls","duration_s":60}"#.to_owned(),
            format!(r#"{{"scope":"session","session_id":"{SESSION}","rule":"","duration_s":60}}"#),
            format!(r#"{{"scope":"session","session_id":"{SESSION}","rule":"ls","duration_s":0}}"#),
            format!(
                r#"{{"scope":"session","session_id":"{SESSION}","rule":"ls","duration_s":{}}}"#,
                MAX_GRANT_DURATION_S + 1
            ),
        ] {
            assert!(PolicyGrantParams::from_json(&value(&bad)).is_err(), "{bad}");
        }
    }

    // KNSH-071: `recording.set` changes at least one setting.
    #[test]
    fn recording_set_needs_a_setting() {
        let output = format!(r#"{{"session_id":"{SESSION}","output":true}}"#);
        let params = RecordingSetParams::from_json(&value(&output)).unwrap();
        assert_eq!((params.commands, params.output), (None, Some(true)));
        assert_eq!(
            RecordingSetParams::from_json(&params.to_json().unwrap()).unwrap(),
            params
        );
        assert!(RecordingSetParams::from_json(&value(&format!(r#"{{"session_id":"{SESSION}"}}"#))).is_err());
        assert!(
            RecordingSetParams::from_json(&value(&format!(r#"{{"session_id":"{SESSION}","output":"yes"}}"#))).is_err()
        );
    }

    // The results' wire shapes.
    #[test]
    fn writes_results() {
        let grant_id: GrantId = SESSION.parse().unwrap();
        let at = Timestamp::from_unix_micros(0).unwrap();
        let entry = GrantEntry {
            grant_id,
            target: GrantTargetParam::Profile(ProfileName::new("web-app").unwrap()),
            rule: "git push".to_owned(),
            exact: false,
            expires_at: at,
        };
        assert_eq!(
            text(&PolicyGrantsResult { grants: vec![entry] }),
            format!(
                r#"{{"grants":[{{"grant_id":"{SESSION}","scope":"profile","session_id":null,"profile":"web-app","rule":"git push","exact":false,"expires_at":"1970-01-01T00:00:00.000000Z"}}]}}"#
            )
        );
        let got = PolicyGetResult {
            profile: ProfileName::new("unattended").unwrap(),
            source: PolicySource::Builtin,
            policy: None,
            expires_at: None,
            expired: false,
        };
        assert_eq!(
            text(&got),
            r#"{"profile":"unattended","source":"builtin","policy":null,"expires_at":null,"expired":false}"#
        );
        let state = SessionStateResult {
            session_id: SESSION.parse().unwrap(),
            state: SessionState::Paused,
        };
        assert_eq!(
            text(&state),
            format!(r#"{{"session_id":"{SESSION}","state":"paused"}}"#)
        );
    }
}
