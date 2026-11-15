//! `session.start_agent`: `knsh agent` asks `knshd` to start an agent CLI in a new agent session
//! (`specs/06-api/user-socket.md#sessionstart_agent`, KNSH-056, FR-AGT-01, FR-AGT-02, FR-SES-03).
//!
//! The request carries the CLI's argv (what followed `--`), the working directory, the caller's environment, the
//! optional `--profile` and `--agent`, and `"stdio": "passed"`: the caller's stdin, stdout and stderr ride on the
//! same message as descriptors (`SCM_RIGHTS`), so the CLI talks to the user's terminal directly. The call is
//! answered when the CLI exits, with the session and how the CLI ended; `knsh agent` then exits the same way.
//!
//! It is sent on `user.sock` only (FR-SES-02), but the fields still come from a client and are bounded and parsed
//! strictly like `exec.run`'s: a malformed value is `-32602`, never repaired.

use knsh_core::{AgentId, CanonicalPath, ProfileName, SessionId};
use knsh_json::{Fields, FromJson, JsonError, Object, ToJson, Value};

use crate::exec::{LineStatus, MAX_EXEC_ARGS, environment, environment_value};
use crate::session::{cwd, out_of_range, parse, path_text};

/// The parameters of `session.start_agent`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionStartAgentParams {
    /// The agent CLI's argv, `argv[0]` first: 1 to [`MAX_EXEC_ARGS`] entries, none holding NUL, `argv[0]` not
    /// empty. `knshd` finds `argv[0]` on the `PATH` of `env` when it has no `/`.
    pub command: Vec<String>,
    /// The working directory the CLI starts in: absolute and resolved.
    pub cwd: CanonicalPath,
    /// The caller's whole environment, in the order sent; the envelope's is built from it. Absent is empty.
    pub env: Vec<(String, String)>,
    /// `--profile`. Absent: the parent session's profile for a nested session, `default` otherwise.
    pub profile: Option<ProfileName>,
    /// `--agent`: the actor's identifier. Absent: derived from `argv[0]` (FR-AGT-02).
    pub agent: Option<AgentId>,
}

impl FromJson for SessionStartAgentParams {
    fn from_json(value: &Value) -> Result<Self, JsonError> {
        let mut fields = Fields::new(value)?;
        let command: Vec<String> = fields.required("command")?;
        let cwd = cwd(fields.required("cwd")?)?;
        let env: Option<Value> = fields.optional("env")?;
        let profile: Option<String> = fields.optional("profile")?;
        let agent: Option<String> = fields.optional("agent")?;
        let stdio: String = fields.required("stdio")?;
        fields.finish()?;
        let program_ok = command.first().is_some_and(|program| !program.is_empty());
        if !program_ok || command.len() > MAX_EXEC_ARGS || command.iter().any(|arg| arg.contains('\0')) {
            return Err(out_of_range("command"));
        }
        // The CLI is interactive: it always runs on the caller's own streams, never on captured ones.
        if stdio != "passed" {
            return Err(out_of_range("stdio"));
        }
        let env = env.map(|env| environment(&env)).transpose()?.unwrap_or_default();
        let profile = profile
            .map(|name| ProfileName::new(&name).map_err(|_| out_of_range("profile")))
            .transpose()?;
        let agent = agent
            .map(|name| AgentId::new(&name).map_err(|_| out_of_range("agent")))
            .transpose()?;
        Ok(Self {
            command,
            cwd,
            env,
            profile,
            agent,
        })
    }
}

impl ToJson for SessionStartAgentParams {
    fn to_json(&self) -> Result<Value, JsonError> {
        let mut object = Object::new()
            .with("command", self.command.to_json()?)?
            .with("cwd", path_text(&self.cwd))?
            .with("env", environment_value(&self.env)?)?
            .with("stdio", "passed")?;
        if let Some(profile) = &self.profile {
            object.insert("profile", Value::from(profile.as_str()))?;
        }
        if let Some(agent) = &self.agent {
            object.insert("agent", Value::from(agent.as_str()))?;
        }
        Ok(Value::Object(object))
    }
}

/// The result of `session.start_agent`, once the CLI has exited and its session has ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionStartAgentResult {
    /// The session the CLI ran in.
    pub session_id: SessionId,
    /// Its actor's identifier.
    pub agent_id: AgentId,
    /// The profile it ran under.
    pub profile: ProfileName,
    /// The session it was started from inside, if any (FR-SES-03).
    pub parent_session_id: Option<SessionId>,
    /// How the CLI ended: `exit_code` or `signal`, exactly one of them.
    pub status: LineStatus,
}

impl ToJson for SessionStartAgentResult {
    /// Every field; `parent_session_id` and the one of `exit_code` and `signal` that does not apply are `null`.
    fn to_json(&self) -> Result<Value, JsonError> {
        let (exit_code, signal) = self.status.fields();
        Ok(Value::Object(
            Object::new()
                .with("session_id", self.session_id.to_string())?
                .with("agent_id", self.agent_id.as_str())?
                .with("profile", self.profile.as_str())?
                .with(
                    "parent_session_id",
                    self.parent_session_id.map(|id| id.to_string()).to_json()?,
                )?
                .with("exit_code", exit_code.to_json()?)?
                .with("signal", signal.to_json()?)?,
        ))
    }
}

impl FromJson for SessionStartAgentResult {
    fn from_json(value: &Value) -> Result<Self, JsonError> {
        let mut fields = Fields::new(value)?;
        let session_id = parse(&fields.required::<String>("session_id")?, "session_id")?;
        let agent_id: String = fields.required("agent_id")?;
        let profile: String = fields.required("profile")?;
        let parent: Option<String> = fields.optional("parent_session_id")?;
        let exit_code: Option<u8> = fields.optional("exit_code")?;
        let signal: Option<u8> = fields.optional("signal")?;
        fields.finish()?;
        let status = LineStatus::from_fields(exit_code, signal)?;
        Ok(Self {
            session_id,
            agent_id: AgentId::new(&agent_id).map_err(|_| out_of_range("agent_id"))?,
            profile: ProfileName::new(&profile).map_err(|_| out_of_range("profile"))?,
            parent_session_id: parent.map(|text| parse(&text, "parent_session_id")).transpose()?,
            status,
        })
    }
}

#[cfg(test)]
mod tests {
    use knsh_core::Ulid;

    use super::*;

    fn json(text: &str) -> Value {
        knsh_json::parse(text.as_bytes(), knsh_json::MAX_PAYLOAD).unwrap()
    }

    fn read(text: &str) -> Result<SessionStartAgentParams, JsonError> {
        SessionStartAgentParams::from_json(&json(text))
    }

    #[test]
    fn params_round_trip() {
        let params = SessionStartAgentParams {
            command: vec!["claude".to_owned(), "--resume".to_owned()],
            cwd: CanonicalPath::new("/Users/u/app").unwrap(),
            env: vec![("PATH".to_owned(), "/usr/bin".to_owned())],
            profile: Some(ProfileName::new("web-app").unwrap()),
            agent: None,
        };
        let value = params.to_json().unwrap();
        assert_eq!(SessionStartAgentParams::from_json(&value).unwrap(), params);
    }

    #[test]
    fn refuses_malformed_params() {
        let good = r#"{"command":["claude"],"cwd":"/tmp","stdio":"passed"}"#;
        assert!(read(good).is_ok());
        for bad in [
            r#"{"command":[],"cwd":"/tmp","stdio":"passed"}"#,
            r#"{"command":[""],"cwd":"/tmp","stdio":"passed"}"#,
            r#"{"command":["a\u0000b"],"cwd":"/tmp","stdio":"passed"}"#,
            r#"{"command":["claude"],"cwd":"tmp","stdio":"passed"}"#,
            r#"{"command":["claude"],"cwd":"/tmp"}"#,
            r#"{"command":["claude"],"cwd":"/tmp","stdio":"captured"}"#,
            r#"{"command":["claude"],"cwd":"/tmp","stdio":"passed","profile":"a b"}"#,
            r#"{"command":["claude"],"cwd":"/tmp","stdio":"passed","agent":""}"#,
            r#"{"command":["claude"],"cwd":"/tmp","stdio":"passed","env":{"A=B":"c"}}"#,
        ] {
            assert!(read(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn result_round_trips_and_needs_one_outcome() {
        let result = SessionStartAgentResult {
            session_id: SessionId::from_ulid(Ulid::from_u128(7)),
            agent_id: AgentId::new("claude-code").unwrap(),
            profile: ProfileName::new("web-app").unwrap(),
            parent_session_id: None,
            status: LineStatus::Signalled(15),
        };
        let value = result.to_json().unwrap();
        assert_eq!(SessionStartAgentResult::from_json(&value).unwrap(), result);
        let base = r#""session_id":"00000000000000000000000007","agent_id":"a","profile":"p""#;
        for outcome in [
            r#""exit_code":0,"signal":9"#,
            r#""exit_code":null,"signal":null"#,
            r#""signal":0"#,
        ] {
            let text = format!("{{{base},{outcome}}}");
            assert!(SessionStartAgentResult::from_json(&json(&text)).is_err(), "{text}");
        }
    }
}
