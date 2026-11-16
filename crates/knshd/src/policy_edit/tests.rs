use std::path::{Path, PathBuf};

use knsh_core::ProfileErrorKind;
use knsh_json::FromJson;
use knsh_platform::testing::{MemFs, RecordingLog, ScriptedPresence};
use knsh_platform::{EnginePaths, Fs, NotAuthenticated, macos::sha256};
use knsh_proto::{ByteTransport, MethodName, Request, RequestId};

use super::*;
use crate::dispatch::tests::{stream, subscriber};
use crate::policy::tests::{loader_on, signed};
use crate::sessions::SessionBinding;

const HOME: &str = "/Users/u";
const WEB: &str = "name = \"web\"\n[exec]\nallow = [\"ls\"]\n";

fn policies() -> PathBuf {
    EnginePaths::for_home(Path::new(HOME)).unwrap().policies_dir()
}

fn file(name: &str) -> PathBuf {
    policies().join(format!("{name}.toml"))
}

/// `policy.read` and `policy.edit` over an empty filesystem, with a prompt nobody answers: for dispatcher tests
/// that need every catalogued handler.
pub(crate) fn idle_handlers() -> Handlers {
    harness(&[]).editor.handlers()
}

struct Harness {
    fs: Arc<MemFs>,
    presence: Arc<ScriptedPresence>,
    editor: Arc<PolicyEditor>,
}

/// An editor over a home with the policies directory and the given files, written as they are.
fn harness(files: &[(&str, &[u8])]) -> Harness {
    let fs = MemFs::new();
    fs.add_dir_all(&policies()).unwrap();
    // `${TMPDIR}` (the loader's `/tmp`) must exist for any profile to load.
    fs.add_dir_all(Path::new("/tmp")).unwrap();
    for (name, bytes) in files {
        fs.write(&file(name), bytes, 0o600).unwrap();
    }
    let fs = Arc::new(fs);
    let presence = Arc::new(ScriptedPresence::new());
    let editor = PolicyEditor::new(
        loader_on(Arc::clone(&fs), Arc::new(RecordingLog::new())),
        presence.clone(),
        sha256,
        Arc::new(RecordingLog::new()),
    );
    Harness { fs, presence, editor }
}

impl Harness {
    fn call_on(&self, endpoint: Endpoint, method: &'static str, params: &str) -> Reply {
        let request = Request {
            id: RequestId::from(1u32),
            method: MethodName::new(method).unwrap(),
            params: knsh_json::parse(params.as_bytes(), 1 << 20)
                .unwrap()
                .as_object()
                .cloned(),
        };
        self.editor.handlers()[method](&Call {
            endpoint,
            bytes: ByteTransport::BinaryFrames,
            stream: stream(),
            request: &request,
            subscriber: subscriber(),
            binding: &SessionBinding::new(),
            descriptors: crate::dispatch::tests::no_descriptors(),
            caller: &knsh_core::StillWaiting,
            control: None,
        })
    }

    fn read(&self, profile: &str) -> PolicyReadResult {
        let answer = self
            .call_on(Endpoint::User, POLICY_READ, &format!(r#"{{"profile":"{profile}"}}"#))
            .unwrap();
        PolicyReadResult::from_json(&answer.result).unwrap()
    }

    fn edit(&self, profile: &str, text: &str) -> Reply {
        let params = PolicyEditParams {
            profile: ProfileName::new(profile).unwrap(),
            text: text.to_owned(),
        };
        let params = knsh_json::write(&knsh_json::ToJson::to_json(&params).unwrap()).unwrap();
        self.call_on(Endpoint::User, POLICY_EDIT, &params)
    }

    fn file(&self, name: &str) -> Option<Vec<u8>> {
        self.fs.read(&file(name), 1 << 20).ok()
    }

    /// Whether the policy loader accepts profile `name` now.
    fn loads(&self, name: &str) -> Result<(), ProfileErrorKind> {
        loader_on(Arc::clone(&self.fs), Arc::new(RecordingLog::new()))
            .load(&ProfileName::new(name).unwrap(), Path::new(HOME))
            .map(|_| ())
            .map_err(|error| error.kind().clone())
    }
}

fn changed(reply: Reply) -> bool {
    PolicyEditResult::from_json(&reply.unwrap().result).unwrap().changed
}

// FR-POL-41: without a successful prompt nothing is signed or written: a refusal, a cancel, and no answer at all
// (the fake's default, like nobody at the Mac) each deny with source `user`, and the old file stays as it was.
#[test]
fn refuses_to_sign_without_authentication() {
    let original = signed("web", WEB);
    let harness = harness(&[("web", &original)]);
    harness.presence.refuse_next(NotAuthenticated::Failed);
    harness.presence.refuse_next(NotAuthenticated::Cancelled);
    for _ in 0..3 {
        let error = harness
            .edit("web", "name = \"web\"\n[exec]\nallow = [\"rm\"]\n")
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::Denied);
        let denial = Denial::from_error(&error).unwrap();
        assert_eq!(denial.source.as_deref(), Some("user"));
        assert!(denial.reason.unwrap().starts_with("not authenticated: "));
        assert_eq!(harness.file("web"), Some(original.clone()));
    }
    assert_eq!(harness.presence.prompts().len(), 3, "every attempt prompts afresh");

    // A new profile is not created either.
    let error = harness.edit("fresh", "name = \"fresh\"\n").unwrap_err();
    assert_eq!(error.code, ErrorCode::Denied);
    assert_eq!(harness.file("fresh"), None);
}

// FR-POL-40, FR-POL-41: after the prompt succeeds the file is signed and accepted; the prompt names the profile, the
// size and the start of the text's SHA-256, and waits a bounded time.
#[test]
fn signs_after_authentication_and_the_loader_accepts_it() {
    let harness = harness(&[]);
    assert_eq!(harness.read("web").state, PolicyFileState::New);
    harness.presence.approve_next();
    assert!(changed(harness.edit("web", "name = \"web\"\n[exec]\nallow = [\"ls\"]")));
    let prompts = harness.presence.prompts();
    assert_eq!(prompts.len(), 1);
    let hash = sha256(WEB.as_bytes());
    let expected = format!(
        "change the policy profile: web ({} bytes, sha256 {})",
        WEB.len(),
        hash[..8].iter().fold(String::new(), |mut hex, byte| {
            let _ = write!(hex, "{byte:02x}");
            hex
        })
    );
    assert_eq!(prompts[0].reason, expected);
    assert_eq!(prompts[0].timeout, EDIT_PROMPT_TIMEOUT);

    // The final newline was added before signing; the body round-trips without the trailer.
    let read = harness.read("web");
    assert_eq!(read.state, PolicyFileState::Valid);
    assert_eq!(read.text, WEB);
    assert_eq!(harness.loads("web"), Ok(()));
    assert_eq!(harness.fs.metadata(&file("web")).unwrap().mode & 0o777, 0o600);
}

// Re-saving the text the file already holds, with a valid signature, asks nothing and writes nothing.
#[test]
fn unchanged_valid_text_needs_no_prompt() {
    let original = signed("web", WEB);
    let harness = harness(&[("web", &original)]);
    assert!(!changed(harness.edit("web", WEB)));
    assert_eq!(harness.presence.prompts(), []);
    assert_eq!(harness.file("web"), Some(original));
}

// FR-POL-42: a file the engine ignores is shown with why, so the user reviews it; saving the same text then signs it
// (after the prompt), which is how an unsigned or tampered file is adopted.
#[test]
fn read_reports_invalid_files_and_saving_signs_them() {
    let mut tampered = signed("web", WEB);
    tampered[0] = b'#';
    let harness = harness(&[("web", WEB.as_bytes()), ("other", &tampered)]);
    let read = harness.read("web");
    assert_eq!(read.state, PolicyFileState::Invalid);
    assert_eq!(read.reason.as_deref(), Some("signature_missing"));
    assert_eq!(read.text, WEB);
    let other = harness.read("other");
    assert_eq!(other.reason.as_deref(), Some("signature_bad"));
    assert!(
        !other.text.contains("knsh-signature"),
        "the trailer is never shown for editing"
    );
    assert_eq!(harness.loads("web"), Err(ProfileErrorKind::SignatureInvalid));

    harness.presence.approve_next();
    assert!(changed(harness.edit("web", WEB)));
    assert_eq!(harness.loads("web"), Ok(()));
}

// Nothing broken is signed: text that does not load as this profile is refused before any prompt, with the reason.
#[test]
fn invalid_text_is_refused_before_prompting() {
    let harness = harness(&[]);
    for (text, fragment) in [
        ("name = \"web\"\n[exec\n", "invalid TOML"),
        ("name = \"other\"\n", "does not match"),
        ("name = \"web\"\nbogus = 1\n", "unknown key"),
        ("name = \"web\"\nextends = \"missing\"\n", "profile not found"),
    ] {
        let error = harness.edit("web", text).unwrap_err();
        assert_eq!(error.code, ErrorCode::InvalidParams, "{text}");
        let data = error.data.unwrap();
        let reason = data
            .as_object()
            .unwrap()
            .get("reason")
            .unwrap()
            .as_str()
            .unwrap()
            .to_owned();
        assert!(reason.contains(fragment), "{text}: {reason}");
    }
    assert_eq!(harness.presence.prompts(), []);
    assert_eq!(harness.file("web"), None);
}

// The built-in profile has no file, and agents never reach either method.
#[test]
fn unattended_and_agent_endpoint_are_refused() {
    let harness = harness(&[]);
    let error = harness
        .call_on(Endpoint::User, POLICY_READ, r#"{"profile":"unattended"}"#)
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::InvalidParams);
    let error = harness.edit("unattended", "name = \"unattended\"\n").unwrap_err();
    assert_eq!(error.code, ErrorCode::InvalidParams);
    for method in [POLICY_READ, POLICY_EDIT] {
        let error = harness
            .call_on(Endpoint::Agent, method, r#"{"profile":"web","text":""}"#)
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::NotAllowed, "{method}");
    }
    assert_eq!(harness.presence.prompts(), []);
}
