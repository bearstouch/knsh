//! Irreversible classification, policy and post-run marking tests (KNSH-093; FR-IRR-01 to FR-IRR-05).

use std::path::PathBuf;

use knsh_bash::{Lookup, Program, Resolver, SourceFile, classify, parse_line};
use knsh_json::ToJson;

use super::*;
use crate::policy::paths::testing::FakeFs;
use crate::policy::{
    LineDecision, LookupError, PathContext, ProfileSource, RuleAction, RuleId, evaluate_line, load_profile_text,
};
use crate::redacted::Redacted;
use crate::session::ProfileName;

struct NoParents;

impl ProfileSource for NoParents {
    fn read_profile(&self, _name: &ProfileName) -> Result<Vec<u8>, LookupError> {
        Err(LookupError::NotFound)
    }
}

/// Names resolve to `/usr/bin`, except `./…` names (project executables).
struct Session;

impl Resolver for Session {
    fn resolve(&self, name: &str, _lookup: Lookup) -> Program {
        if knsh_bash::is_builtin(name) {
            Program::Builtin
        } else if name.starts_with("./") {
            Program::ProjectExecutable(PathBuf::from("/Users/u/app").join(name))
        } else {
            Program::Trusted(PathBuf::from("/usr/bin").join(name))
        }
    }

    fn source_file(&self, _path: &str) -> SourceFile {
        SourceFile::Unresolved
    }
}

fn profile(text: &str) -> Profile {
    let mut fs = FakeFs::new();
    fs.add("/Users/u/app").add("/tmp").add("/bin/bash");
    let context = PathContext {
        home: PathBuf::from("/Users/u"),
        tmpdir: PathBuf::from("/tmp"),
        start_dir: PathBuf::from("/Users/u/app"),
    };
    let text = format!("name = \"t\"\n{text}");
    load_profile_text(text.as_bytes(), &NoParents, &context, &fs).unwrap()
}

fn classification(profile: &Profile, line: &str) -> Classification {
    classify(&parse_line(line), line, &Session, &profile.exec.interpreters)
}

fn reasons(profile: &Profile, line: &str) -> Vec<String> {
    classify_irreversible(profile, &classification(profile, line))
        .reasons()
        .to_vec()
}

fn decide(profile: &Profile, line: &str) -> LineDecision {
    evaluate_line(profile, &classification(profile, line))
}

/// No reason.
const NONE: [&str; 0] = [];

const ALLOW_ALL: &str = "[exec]\nallow = [\"git\", \"curl\", \"rsync\", \"ssh\", \"ls\", \"terraform\", \"env\"]\n";

// FR-IRR-02: matching uses normalised subcommands, so global options do not hide `git push`.
#[test]
fn git_push_with_global_options_is_irreversible() {
    let p = profile(ALLOW_ALL);
    assert_eq!(reasons(&p, "git push origin main"), ["git push"]);
    assert_eq!(reasons(&p, "git -c x=y push"), ["git push"]);
    assert_eq!(reasons(&p, "git -C /tmp --no-pager push"), ["git push"]);
    // Through a wrapper, and with an unknown option before the subcommand (fail closed).
    assert_eq!(reasons(&p, "env A=1 git push"), ["git push"]);
    assert_eq!(reasons(&p, "git --unknown push"), ["git push"]);
    // An expansion may be `push`.
    assert_eq!(reasons(&p, "git $X"), ["git push"]);
    assert_eq!(reasons(&p, "git status"), NONE);
    assert_eq!(reasons(&p, "git log --grep push"), NONE);
}

// FR-IRR-02: every built-in entry of the requirement is flagged.
#[test]
fn builtin_list_flags_each_fr_irr_02_command() {
    let p = profile(ALLOW_ALL);
    for (line, reason) in [
        ("npm publish", "npm publish"),
        ("docker push img", "docker push"),
        ("kubectl -n prod apply -f x.yaml", "kubectl apply"),
        ("terraform -chdir=infra apply", "terraform apply"),
        ("gh pr merge 12", "gh pr merge"),
        ("ssh host uptime", "ssh"),
        ("scp a host:b", "scp"),
    ] {
        assert_eq!(reasons(&p, line), [reason], "{line}");
    }
}

// FR-IRR-02: `curl` with POST, PUT, PATCH or DELETE is irreversible; without a method flag (GET) it is not.
#[test]
fn curl_post_is_irreversible_and_get_is_not() {
    let p = profile(ALLOW_ALL);
    assert_eq!(reasons(&p, "curl -X POST https://api.example.com"), ["curl POST"]);
    assert_eq!(reasons(&p, "curl -d a=1 https://x"), ["curl POST"]);
    assert_eq!(reasons(&p, "curl --request DELETE https://x"), ["curl DELETE"]);
    assert_eq!(reasons(&p, "curl -XPATCH https://x"), ["curl PATCH"]);
    assert_eq!(reasons(&p, "curl -T f https://x"), ["curl PUT"]);
    assert_eq!(reasons(&p, "curl https://example.com"), NONE);
    assert_eq!(reasons(&p, "curl -sSL -o out https://example.com"), NONE);
    assert_eq!(reasons(&p, "curl -X GET https://example.com"), NONE);
}

// FR-IRR-02: `rsync` to a remote host is irreversible; with only local paths it is not.
#[test]
fn rsync_local_only_is_not_irreversible() {
    let p = profile(ALLOW_ALL);
    assert_eq!(reasons(&p, "rsync -av src/ dst/"), NONE);
    assert_eq!(reasons(&p, "rsync -a ./a:b /tmp/x"), NONE);
    assert_eq!(reasons(&p, "rsync -av src/ host:dst/"), ["rsync to a remote host"]);
    assert_eq!(reasons(&p, "rsync -av src/ u@host:/dst"), ["rsync to a remote host"]);
}

// FR-IRR-01: the profile's list adds to the built-in one; it never removes from it.
#[test]
fn profile_list_extends_builtin_list() {
    let p = profile(&format!(
        "{ALLOW_ALL}[approvals]\nirreversible_commands = [\"terraform state rm\", \"ls -R\"]\n"
    ));
    assert_eq!(reasons(&p, "terraform state rm x"), ["terraform state rm"]);
    assert_eq!(reasons(&p, "ls -R /"), ["ls -R"]);
    assert_eq!(reasons(&p, "git push"), ["git push"]);
    assert_eq!(reasons(&p, "ls -l"), NONE);
}

// A project executable is never named by a rule, so it is not flagged by name; `exec.project_executables` decides it.
#[test]
fn project_executable_named_like_a_tool_is_not_matched() {
    let p = profile(ALLOW_ALL);
    assert_eq!(reasons(&p, "./ssh host"), NONE);
}

// FR-IRR-04: the reasons of every command are kept, each once, in order, with the value set.
#[test]
fn reasons_are_recorded() {
    let p = profile(ALLOW_ALL);
    let flag = classify_irreversible(
        &p,
        &classification(&p, "git push && curl -X POST https://x && git push"),
    );
    assert!(flag.value());
    assert_eq!(flag.reasons(), ["git push", "curl POST"]);
    let json = knsh_json::write(&flag.to_json().unwrap()).unwrap();
    assert_eq!(json, r#"{"value":true,"reasons":["git push","curl POST"]}"#);
    let back = crate::record::decode_irreversible(&json).unwrap();
    assert_eq!(back, flag);
    let none = classify_irreversible(&p, &classification(&p, "ls"));
    assert_eq!(
        knsh_json::write(&none.to_json().unwrap()).unwrap(),
        r#"{"value":false,"reasons":[]}"#
    );
    // The decision carries the same reasons, whatever its verdict.
    assert_eq!(decide(&p, "git push && curl -X POST https://x").irreversible, flag);
}

// A stored object whose value disagrees with its reasons is not one the engine wrote.
#[test]
fn stored_flag_must_be_consistent() {
    assert!(crate::record::decode_irreversible(r#"{"value":true,"reasons":[]}"#).is_err());
    assert!(crate::record::decode_irreversible(r#"{"value":false,"reasons":["x"]}"#).is_err());
    assert!(crate::record::decode_irreversible(r#"{"value":true,"reasons":["x","x"]}"#).is_err());
    assert!(crate::record::decode_irreversible(r#"{"value":true,"reasons":["x"],"more":1}"#).is_err());
}

// FR-IRR-05: with `approvals.irreversible = "ask"` (the default) a flagged line asks even when the rules allow it.
#[test]
fn irreversible_line_asks_when_profile_says_ask() {
    let p = profile(ALLOW_ALL);
    assert_eq!(p.approvals.irreversible, RuleAction::Ask);
    let decision = decide(&p, "git status && git -c x=y push");
    assert_eq!(decision.verdict, RuleAction::Ask);
    assert_eq!(decision.rule_id, Some(RuleId::Irreversible));
    assert_eq!(
        decision.rule_id.map(|rule| rule.to_string()).as_deref(),
        Some("approvals.irreversible")
    );
    assert_eq!(decide(&p, "git status").verdict, RuleAction::Allow);
    // A deny rule still wins over the irreversible ask.
    let denying = profile("[exec]\nallow = [\"git\"]\ndeny = [\"git push\"]\n");
    let decision = decide(&denying, "git push");
    assert_eq!(decision.verdict, RuleAction::Deny);
    assert_eq!(decision.rule_id, Some(RuleId::Deny(0)));
    assert_eq!(decision.irreversible.reasons(), ["git push"]);
}

// FR-IRR-05: `deny` refuses flagged lines; `allow` leaves them to the rules, still flagged for the record.
#[test]
fn approvals_setting_decides_flagged_lines() {
    let deny = profile(&format!("{ALLOW_ALL}[approvals]\nirreversible = \"deny\"\n"));
    let decision = decide(&deny, "curl -d x https://x");
    assert_eq!(
        (decision.verdict, decision.rule_id),
        (RuleAction::Deny, Some(RuleId::Irreversible))
    );
    let allow = profile(&format!("{ALLOW_ALL}[approvals]\nirreversible = \"allow\"\n"));
    let decision = decide(&allow, "git push");
    assert_eq!(decision.verdict, RuleAction::Allow);
    assert_eq!(decision.irreversible.reasons(), ["git push"]);
}

fn contacted(host: &str) -> NetworkEntry {
    NetworkEntry::new(Redacted::new(host.to_owned()), 443, NetworkResult::Contacted)
}

const NETWORKED: &str = "[network]\nmode = \"allowlist\"\nhosts = [\"example.com\", \"0x0.st\", \"drop.example.org\"]\n\
                         approval_hosts = [\"*.github.com\"]\n[checkpoints]\nroots = [\"/Users/u/app\"]\n";

// FR-IRR-03: reaching an `approval_hosts` destination marks the line with `network` and the host.
#[test]
fn approval_host_contact_marks_irreversible() {
    let p = profile(NETWORKED);
    let mut flag = Irreversibility::none();
    mark_observed(
        &p,
        &mut flag,
        &[contacted("example.com"), contacted("api.github.com")],
        &[],
    );
    assert_eq!(flag.reasons(), ["network", "api.github.com"]);
    // A refused connection reached nothing.
    let mut refused = Irreversibility::none();
    let entry = NetworkEntry::new(
        Redacted::new("api.github.com".to_owned()),
        443,
        NetworkResult::Refused("approval_required".to_owned()),
    );
    mark_observed(&p, &mut refused, &[entry], &[]);
    assert!(!refused.value());
}

// FR-IRR-03: an upload-capable host marks the line: built-in ones and the profile's `approvals.upload_hosts`.
#[test]
fn upload_host_contact_marks_irreversible() {
    let p = profile(&format!(
        "{NETWORKED}[approvals]\nupload_hosts = [\"drop.example.org\"]\n"
    ));
    let mut flag = Irreversibility::none();
    mark_observed(
        &p,
        &mut flag,
        &[contacted("0x0.st"), contacted("drop.example.org")],
        &[],
    );
    assert_eq!(flag.reasons(), ["network", "0x0.st", "drop.example.org"]);
}

// FR-IRR-03: a write outside every checkpoint root is marked with its path; one inside is not.
#[test]
fn write_outside_roots_marks_irreversible() {
    let p = profile(NETWORKED);
    let mut flag = Irreversibility::none();
    let writes = [
        CanonicalPath::new("/Users/u/app/src/main.rs").unwrap(),
        CanonicalPath::new("/Users/u/.bashrc").unwrap(),
        CanonicalPath::new("/Users/u/application").unwrap(),
    ];
    mark_observed(&p, &mut flag, &[], &writes);
    assert_eq!(flag.reasons(), ["/Users/u/.bashrc", "/Users/u/application"]);
}

// The record stays bounded: reasons beyond the cap are dropped, the flag stays set.
#[test]
fn reasons_are_capped() {
    let mut flag = Irreversibility::none();
    for index in 0..1000 {
        flag.add(format!("/tmp/{index}"));
    }
    flag.add("");
    flag.add("x".repeat(5000));
    assert_eq!(flag.reasons().len(), crate::record::MAX_IRREVERSIBLE_REASONS);
    assert!(flag.value());
}
