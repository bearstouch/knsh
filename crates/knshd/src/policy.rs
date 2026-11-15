//! `policy.check`: what policy would decide for a line, without running it (`specs/06-api/agent-socket.md#policycheck`,
//! KNSH-043, FR-POL-70).
//!
//! The handler picks the profile, loads it, and hands the line to [`knsh_core::check_line`], which parses, resolves,
//! classifies and decides it. Nothing else happens: no record is written, no event is published and no process is
//! started. The handler holds no record store, event hub or process handle, so it cannot do any of these; the
//! filesystem is only read (the profile files, and binary lookups for name resolution). Hooks, the authority and
//! grants are not consulted, so a line the rules ask about is answered `ask`.
//!
//! # Whose policy
//!
//! - `agent.sock`: the profile of the session the connection was bound to at `hello` (KNSH-048), so neither
//!   `session_id` nor `profile` may be given (`-32003`, as for any other session). A connection whose session has
//!   ended is refused with `-32009`.
//! - `user.sock`: exactly one of `session_id` (a live session's profile; `-32006` when it is not live) and `profile`
//!   (by name); neither is `-32602`.
//!
//! The profile is loaded as the supervisor will load it: `unattended` is the built-in profile, any other name is
//! `<name>.toml` in the policies directory with its `extends` chain. Paths are expanded with `knshd`'s `HOME` and
//! `TMPDIR`, and `${PROJECT}` is found from the line's `cwd`. A `profile` that does not exist is `-32602`; a profile
//! that cannot be loaded (invalid, unreadable, a missing parent, or the session's own profile missing) is `-32603`,
//! with no reason in the answer.
//!
//! Every error is a whole error: an answer is either the full result or an error, never part of a result.

use std::path::PathBuf;
use std::sync::Arc;

use knsh_core::{
    PathContext, Profile, ProfileError, ProfileErrorKind, ProfileName, ProfileOrigin, UNATTENDED_PROFILE, check_line,
    load_profile, load_unattended,
};
use knsh_platform::{Fs, PolicyDirectory};
use knsh_proto::{
    DEFAULT_POLICY_CHECK_PATH, ErrorCode, PolicyCheckParams, PolicyCheckResult, PolicyCheckTarget, RpcError,
};

use crate::dispatch::{Call, Endpoint, Handler, Handlers, Reply, answer, params};
use crate::sessions::Sessions;

/// The method name.
const POLICY_CHECK: &str = "policy.check";

/// The `policy.check` service. One per `knshd`, shared by every connection.
pub(crate) struct PolicyCheck {
    /// The live sessions, read for a session's profile name.
    sessions: Arc<Sessions>,
    /// Read only: profile files and binary lookups.
    fs: Arc<dyn Fs>,
    /// The policies directory ([`knsh_platform::EnginePaths::policies_dir`]).
    policies: PathBuf,
    /// `knshd`'s `HOME`, for `~` and `${HOME}`.
    home: PathBuf,
    /// `knshd`'s `TMPDIR`, for `${TMPDIR}`.
    tmpdir: PathBuf,
}

impl PolicyCheck {
    /// The service over `sessions`, reading profiles from `policies` through `fs` and expanding paths with `home` and
    /// `tmpdir`.
    pub(crate) fn new(
        sessions: Arc<Sessions>,
        fs: Arc<dyn Fs>,
        policies: PathBuf,
        home: PathBuf,
        tmpdir: PathBuf,
    ) -> Arc<Self> {
        Arc::new(Self {
            sessions,
            fs,
            policies,
            home,
            tmpdir,
        })
    }

    /// The `policy.check` handler.
    pub(crate) fn handlers(self: &Arc<Self>) -> Handlers {
        let service = Arc::clone(self);
        let handler: Handler = Arc::new(move |call: &Call<'_>| service.check(call));
        [(POLICY_CHECK, handler)].into_iter().collect()
    }

    /// `policy.check` (module documentation).
    fn check(&self, call: &Call<'_>) -> Reply {
        // Params first: malformed params are -32602 on either socket, before anything else is looked at.
        let PolicyCheckParams {
            command,
            cwd,
            path,
            target,
        } = params(call)?;
        let name = self.profile_name(call, &target)?;
        let context = PathContext {
            home: self.home.clone(),
            tmpdir: self.tmpdir.clone(),
            start_dir: cwd.as_path().to_path_buf(),
        };
        let profile = self
            .load(&name, &context)
            .map_err(|error| load_error(&error, &name, &target))?;
        let fs: &dyn Fs = &*self.fs;
        let check = check_line(
            &profile,
            &command,
            path.as_deref().unwrap_or(DEFAULT_POLICY_CHECK_PATH),
            &cwd,
            fs,
        );
        answer(&PolicyCheckResult { profile: name, check })
    }

    /// The profile `target` names on the call's endpoint (module documentation, "Whose policy").
    fn profile_name(&self, call: &Call<'_>, target: &PolicyCheckTarget) -> Result<ProfileName, RpcError> {
        match (call.endpoint, target) {
            // The session the connection was bound to at hello (KNSH-048): its profile, never another.
            (Endpoint::Agent, PolicyCheckTarget::Caller) => self.sessions.profile_of(call.binding.agent_session()?),
            // An agent may check only its own session's policy, never another session's or a named profile.
            (Endpoint::Agent, PolicyCheckTarget::Session(_) | PolicyCheckTarget::Profile(_)) => {
                Err(RpcError::new(ErrorCode::NotAllowed))
            }
            // user.sock names the policy explicitly: the connection's own session is not a default.
            (Endpoint::User, PolicyCheckTarget::Caller) => Err(RpcError::new(ErrorCode::InvalidParams)),
            (Endpoint::User, PolicyCheckTarget::Session(session_id)) => self.sessions.profile_of(*session_id),
            (Endpoint::User, PolicyCheckTarget::Profile(name)) => Ok(name.clone()),
        }
    }

    /// Loads `name` as the supervisor will: `unattended` is built in, anything else comes from the policies
    /// directory.
    fn load(&self, name: &ProfileName, context: &PathContext) -> Result<Profile, ProfileError> {
        let fs: &dyn Fs = &*self.fs;
        if name.as_str() == UNATTENDED_PROFILE {
            return load_unattended(context, fs);
        }
        load_profile(name, &PolicyDirectory::new(self.policies.clone(), fs), context, fs)
    }
}

/// The answer for a profile that could not be loaded: `-32602` when the caller named a profile that does not exist,
/// `-32603` otherwise (module documentation). The reason never reaches the answer.
fn load_error(error: &ProfileError, name: &ProfileName, target: &PolicyCheckTarget) -> RpcError {
    // Only the named profile itself being absent is the caller's mistake; a missing parent is a broken profile.
    let named_missing = matches!(target, PolicyCheckTarget::Profile(_))
        && *error.kind() == ProfileErrorKind::ProfileNotFound
        && error.origin() == Some(&ProfileOrigin::Profile(name.clone()));
    if named_missing {
        RpcError::new(ErrorCode::InvalidParams)
    } else {
        RpcError::new(ErrorCode::InternalError)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::path::Path;

    use knsh_core::{Actor, EventData, SessionId};
    use knsh_json::Object;
    use knsh_platform::EnginePaths;
    use knsh_platform::testing::MemFs;
    use knsh_proto::{ByteTransport, MethodName, Request, RequestId};
    use knsh_store::{RecordQuery, Scope};

    use super::*;
    use crate::dispatch::tests::{stream, subscriber};
    use crate::sessions::SessionBinding;
    use crate::sessions::tests::fixture;

    const HOME: &str = "/Users/u";
    const PROJECT: &str = "/Users/u/app";

    /// The policies directory of the fake home, from `EnginePaths` so no engine path literal is repeated here.
    fn policies() -> PathBuf {
        EnginePaths::for_home(Path::new(HOME)).unwrap().policies_dir()
    }

    /// The service over `sessions` and `fs`, with the fake home's policies directory, `HOME` and `TMPDIR`.
    pub(crate) fn service(sessions: Arc<Sessions>, fs: MemFs) -> Arc<PolicyCheck> {
        PolicyCheck::new(
            sessions,
            Arc::new(fs),
            policies(),
            PathBuf::from(HOME),
            PathBuf::from("/tmp"),
        )
    }

    /// A Mac-like filesystem: trusted binaries, a project, the policies directory and the profiles given.
    fn fs(profiles: &[(&str, &str)]) -> MemFs {
        let fs = MemFs::new();
        for dir in ["/usr/bin", "/bin", "/tmp", PROJECT] {
            fs.add_dir_all(Path::new(dir)).unwrap();
        }
        fs.add_dir_all(&policies()).unwrap();
        for binary in ["/usr/bin/git", "/bin/bash", "/bin/ls"] {
            fs.write(Path::new(binary), b"#!/bin/sh\n", 0o755).unwrap();
        }
        for (name, text) in profiles {
            fs.write(&policies().join(format!("{name}.toml")), text.as_bytes(), 0o600)
                .unwrap();
        }
        fs
    }

    /// A profile asking for `git push`, allowing `git status`, and allowing `bash` (whose `-c` code is dynamic).
    const WEB: &str = "name = \"web\"\n[exec]\nallow = [\"git status\", \"bash\", \"ls\"]\nask = [\"git push\"]\n";

    fn request(method: &'static str, params: &str) -> Request {
        Request {
            id: RequestId::from(1u32),
            method: MethodName::new(method).unwrap(),
            params: knsh_json::parse(params.as_bytes(), 1 << 20)
                .unwrap()
                .as_object()
                .cloned(),
        }
    }

    fn call_with(
        handlers: &Handlers,
        endpoint: Endpoint,
        binding: &SessionBinding,
        method: &'static str,
        params: &str,
    ) -> Reply {
        let request = request(method, params);
        handlers[method](&Call {
            endpoint,
            bytes: ByteTransport::BinaryFrames,
            stream: stream(),
            request: &request,
            subscriber: subscriber(),
            binding,
        })
    }

    /// `policy.check` with `params` on `endpoint`, against `service`.
    fn check_on(service: &Arc<PolicyCheck>, endpoint: Endpoint, params: &str) -> Reply {
        call_with(
            &service.handlers(),
            endpoint,
            &SessionBinding::new(),
            POLICY_CHECK,
            params,
        )
    }

    fn check(service: &Arc<PolicyCheck>, params: &str) -> Object {
        check_on(service, Endpoint::User, params)
            .unwrap()
            .result
            .as_object()
            .cloned()
            .unwrap()
    }

    fn code(reply: Reply) -> ErrorCode {
        reply.unwrap_err().code
    }

    fn text(object: &Object, name: &str) -> String {
        knsh_json::write(object.get(name).unwrap()).unwrap()
    }

    fn web() -> Arc<PolicyCheck> {
        service(fixture().sessions, fs(&[("web", WEB)]))
    }

    // KNSH-043, FR-POL-70: `git push` asked by the profile is answered `ask`, with its rule, every matched rule and
    // the command's class; nothing ran, so nothing was decided by a hook or the authority.
    #[test]
    fn policy_check_returns_ask_for_git_push() {
        let result = check(
            &web(),
            r#"{"command":"git push origin main","cwd":"/Users/u/app","path":"/usr/bin:/bin","profile":"web"}"#,
        );
        assert_eq!(text(&result, "profile"), r#""web""#);
        assert_eq!(text(&result, "verdict"), r#""ask""#);
        assert_eq!(text(&result, "source"), r#""rule""#);
        assert_eq!(text(&result, "rule_id"), r#""exec.ask[0]""#);
        assert_eq!(text(&result, "reason"), "null");
        assert_eq!(
            text(&result, "matched_rules"),
            r#"[{"command":0,"verdict":"ask","rule_id":"exec.ask[0]"}]"#
        );
        assert_eq!(
            text(&result, "commands"),
            r#"[{"name":"git","program":"/usr/bin/git","class":"static","dynamic_reason":null,"wrapper":null}]"#
        );
        assert_eq!(text(&result, "dynamic"), "[]");
        // FR-LC-06: the line's network classes are those of its normalised command.
        assert_eq!(text(&result, "network_classes"), r#"["network:publish"]"#);
    }

    // KNSH-043: a dry run writes no record, publishes no event and changes no file. The service holds no record
    // store, event hub or process handle (see `PolicyCheck`), so it cannot spawn anything: the fakes below check
    // the rest.
    #[test]
    fn policy_check_spawns_nothing_and_writes_no_record() {
        let fixture = fixture();
        let fs = fs(&[("default", "name = \"default\"\n[exec]\nask = [\"git push\"]\n")]);
        let binding = SessionBinding::new();
        let started = call_with(
            &fixture.sessions.handlers(),
            Endpoint::User,
            &binding,
            "session.start_human",
            "{}",
        )
        .unwrap();
        let session_id: SessionId = started
            .result
            .as_object()
            .unwrap()
            .get("session_id")
            .unwrap()
            .as_str()
            .unwrap()
            .parse()
            .unwrap();
        let files_before: Vec<_> = fs
            .paths()
            .into_iter()
            .map(|path| {
                let contents = fs.contents(&path);
                (path, contents)
            })
            .collect();
        let service = service(Arc::clone(&fixture.sessions), fs);

        let params =
            format!(r#"{{"command":"git push && ls > out.txt","cwd":"/Users/u/app","session_id":"{session_id}"}}"#);
        let result = check(&service, &params);
        assert_eq!(text(&result, "verdict"), r#""ask""#);
        assert_eq!(text(&result, "profile"), r#""default""#);

        let page = fixture
            .store
            .query(
                Scope::All,
                RecordQuery {
                    session: Some(session_id),
                    limit: knsh_store::PageSize::new(100).unwrap(),
                    ..RecordQuery::default()
                },
            )
            .unwrap();
        assert!(page.records.is_empty(), "no record is written");
        // Only `session.started` was published: the next event of the session is the second.
        let next = fixture
            .hub
            .publish(session_id, &Actor::Human, EventData::SessionIdle)
            .unwrap();
        assert_eq!(next, 2, "no event is emitted");
        let fs_after = &service.fs;
        for (path, contents) in &files_before {
            assert_eq!(&fs_after.read(path, 1 << 20).ok(), contents, "{}", path.display());
        }
        assert!(
            fs_after.metadata(&Path::new(PROJECT).join("out.txt")).is_err(),
            "nothing ran"
        );
        binding.release();
    }

    // KNSH-043, FR-POL-20: interpreter code is reported with its dynamic reason, per command and per part.
    #[test]
    fn policy_check_reports_dynamic_reason() {
        let result = check(
            &web(),
            r#"{"command":"bash -c \"$x\"","cwd":"/Users/u/app","profile":"web"}"#,
        );
        assert_eq!(
            text(&result, "commands"),
            r#"[{"name":"bash","program":"/bin/bash","class":"dynamic","dynamic_reason":"interpreter_code","wrapper":null}]"#
        );
        let dynamic = result.get("dynamic").unwrap().as_array().unwrap();
        assert_eq!(dynamic.len(), 1);
        assert_eq!(
            knsh_json::write(dynamic[0].as_object().unwrap().get("reason").unwrap()).unwrap(),
            r#""interpreter_code""#
        );
        assert_eq!(result.get("network_classes").unwrap().as_array().unwrap().len(), 0);
    }

    // KNSH-043: malformed params are -32602 on both sockets, before the endpoint's own rules; never a partial answer.
    #[test]
    fn malformed_params_are_invalid_params() {
        let service = web();
        for endpoint in Endpoint::ALL {
            for params in [
                "{}",
                r#"{"command":"ls"}"#,
                r#"{"command":"ls","cwd":"relative","profile":"web"}"#,
                r#"{"command":["ls"],"cwd":"/","profile":"web"}"#,
                r#"{"command":"ls","cwd":"/","profile":"web","session_id":"01JD0000000000000000000000"}"#,
                r#"{"command":"ls","cwd":"/","profile":"no/slash"}"#,
            ] {
                assert_eq!(
                    code(check_on(&service, endpoint, params)),
                    ErrorCode::InvalidParams,
                    "{params}"
                );
            }
        }
        // user.sock must name a session or a profile.
        assert_eq!(
            code(check_on(&service, Endpoint::User, r#"{"command":"ls","cwd":"/"}"#)),
            ErrorCode::InvalidParams
        );
    }

    // KNSH-048: agent.sock checks only the caller's own session. A connection without a bound agent session is
    // refused, as is naming any session or profile.
    #[test]
    fn agent_sock_without_a_bound_session_is_refused() {
        let service = web();
        for params in [
            r#"{"command":"ls","cwd":"/Users/u/app"}"#,
            r#"{"command":"ls","cwd":"/Users/u/app","profile":"web"}"#,
            r#"{"command":"ls","cwd":"/Users/u/app","session_id":"01JD0000000000000000000000"}"#,
        ] {
            assert_eq!(
                code(check_on(&service, Endpoint::Agent, params)),
                ErrorCode::NotAllowed,
                "{params}"
            );
        }
    }

    // KNSH-048: a bound agent connection is checked against its own session's profile, and may name neither
    // another session nor a profile; once its session ends it is -32009.
    #[test]
    fn agent_sock_checks_the_bound_sessions_profile() {
        let fixture = fixture();
        let service = service(Arc::clone(&fixture.sessions), fs(&[("web", WEB)]));
        let opened = fixture
            .sessions
            .open_agent(
                knsh_core::Actor::Agent(knsh_core::AgentId::new("claude-code").unwrap()),
                ProfileName::new("web").unwrap(),
            )
            .unwrap();
        let binding = SessionBinding::for_peer(None);
        fixture
            .sessions
            .bind_agent(&binding, Some(&opened.token.encode()))
            .unwrap();
        let on_agent = |params: &str| call_with(&service.handlers(), Endpoint::Agent, &binding, POLICY_CHECK, params);
        let result = on_agent(r#"{"command":"git push origin main","cwd":"/Users/u/app","path":"/usr/bin:/bin"}"#)
            .unwrap()
            .result;
        let result = result.as_object().unwrap();
        assert_eq!(text(result, "profile"), r#""web""#);
        assert_eq!(text(result, "verdict"), r#""ask""#);
        for params in [
            r#"{"command":"ls","cwd":"/Users/u/app","profile":"web"}"#,
            &format!(
                r#"{{"command":"ls","cwd":"/Users/u/app","session_id":"{}"}}"#,
                opened.session_id
            ),
        ] {
            assert_eq!(code(on_agent(params)), ErrorCode::NotAllowed, "{params}");
        }
        fixture.sessions.end_agent(opened.session_id);
        assert_eq!(
            code(on_agent(r#"{"command":"ls","cwd":"/Users/u/app"}"#)),
            ErrorCode::InvalidSessionToken
        );
    }

    #[test]
    fn unknown_session_and_missing_or_broken_profiles_are_errors() {
        let service = service(
            fixture().sessions,
            fs(&[
                ("web", WEB),
                ("broken", "name = \"broken\"\n[exec]\nallow = 3\n"),
                ("orphan", "name = \"orphan\"\nextends = \"gone\"\n"),
            ]),
        );
        let session = r#"{"command":"ls","cwd":"/Users/u/app","session_id":"01JD0000000000000000000000"}"#;
        let reply = check_on(&service, Endpoint::User, session);
        assert_eq!(code(reply), ErrorCode::SessionNotFound);
        let missing = r#"{"command":"ls","cwd":"/Users/u/app","profile":"nope"}"#;
        assert_eq!(
            code(check_on(&service, Endpoint::User, missing)),
            ErrorCode::InvalidParams
        );
        for name in ["broken", "orphan"] {
            let params = format!(r#"{{"command":"ls","cwd":"/Users/u/app","profile":"{name}"}}"#);
            assert_eq!(
                code(check_on(&service, Endpoint::User, &params)),
                ErrorCode::InternalError,
                "{name}"
            );
        }
    }

    // FR-AGT-21: `unattended` is the built-in profile, whatever the policies directory holds; its asks are denies.
    #[test]
    fn unattended_is_the_built_in_profile() {
        let service = service(fixture().sessions, fs(&[]));
        let result = check(
            &service,
            r#"{"command":"git push","cwd":"/Users/u/app","profile":"unattended"}"#,
        );
        assert_eq!(text(&result, "verdict"), r#""deny""#);
        assert_eq!(text(&result, "source"), r#""standalone""#);
        assert_ne!(text(&result, "reason"), "null");
    }

    // The answer is the full result: an allowed read-only line names every part's rule.
    #[test]
    fn allowed_line_reports_every_matched_rule() {
        let result = check(
            &web(),
            r#"{"command":"git status; ls","cwd":"/Users/u/app","profile":"web"}"#,
        );
        assert_eq!(text(&result, "verdict"), r#""allow""#);
        assert_eq!(
            text(&result, "matched_rules"),
            r#"[{"command":0,"verdict":"allow","rule_id":"exec.allow[0]"},{"command":1,"verdict":"allow","rule_id":"exec.allow[2]"}]"#
        );
    }
}
