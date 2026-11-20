//! Grant tests (KNSH-042; FR-POL-60, FR-POL-61): the model, the set's operations, and how grants change a line's
//! verdict through `evaluate_line_with_grants`.

use std::path::PathBuf;

use knsh_bash::{Lookup, Program, Resolver, SourceFile, classify, parse_line};

use super::*;
use crate::policy::paths::testing::FakeFs;
use crate::policy::{
    DecisionSource, LineCapabilities, LineDecision, LookupError, PathContext, Profile, ProfileSource, RuleAction,
    RuleId, evaluate_line_with_grants, load_profile_text, load_unattended,
};
use crate::ulid::Ulid;

/// No parents: every test profile stands alone.
struct NoParents;

impl ProfileSource for NoParents {
    fn read_profile(&self, _name: &ProfileName) -> Result<Vec<u8>, LookupError> {
        Err(LookupError::NotFound)
    }
}

/// A session whose `PATH` finds every name in `/usr/bin`, builtins aside.
struct Session;

impl Resolver for Session {
    fn resolve(&self, name: &str, _lookup: Lookup) -> Program {
        if knsh_bash::is_builtin(name) {
            Program::Builtin
        } else {
            Program::Trusted(PathBuf::from("/usr/bin").join(name))
        }
    }

    fn source_file(&self, _path: &str) -> SourceFile {
        SourceFile::Unresolved
    }
}

fn context() -> PathContext {
    PathContext {
        home: PathBuf::from("/Users/u"),
        tmpdir: PathBuf::from("/tmp"),
        start_dir: PathBuf::from("/Users/u/app"),
    }
}

fn fs() -> FakeFs {
    let mut fs = FakeFs::new();
    fs.add("/Users/u/app").add("/tmp").add("/bin/bash");
    fs
}

/// A profile called `t`, read through the real loader.
fn profile(text: &str) -> Profile {
    let text = format!("name = \"t\"\n{text}");
    load_profile_text(text.as_bytes(), &NoParents, &context(), &fs()).unwrap()
}

/// Asks for `git push` and `npm publish`, denies forced pushes, allows the rest of git and npm.
const RULES: &str = "[exec]
allow = [\"git\", \"npm\", \"env\"]
ask = [\"git push\", \"npm publish\", \"python3\"]
deny = [\"git push --force\"]
";

fn at(seconds: u64) -> Timestamp {
    Timestamp::from_unix_micros(seconds * 1_000_000).unwrap()
}

fn grant_id(n: u128) -> GrantId {
    GrantId::from_ulid(Ulid::from_u128(n))
}

fn session_id(n: u128) -> SessionId {
    SessionId::from_ulid(Ulid::from_u128(n))
}

fn profile_name(name: &str) -> ProfileName {
    ProfileName::new(name).unwrap()
}

/// A grant `n` in session 1 for `rule`, expiring at second 100.
fn session_grant(n: u128, rule: &str) -> Grant {
    Grant::new(grant_id(n), GrantScope::Session(session_id(1)), rule, at(100)).unwrap()
}

fn set_of(grants: impl IntoIterator<Item = Grant>) -> GrantSet {
    let mut set = GrantSet::new();
    for grant in grants {
        set.insert(grant, at(0)).unwrap();
    }
    set
}

/// The decision for `line` in `session` at second `now`.
fn decide(profile: &Profile, grants: &GrantSet, session: SessionId, now: u64, line: &str) -> LineDecision {
    let classification = classify(&parse_line(line), line, &Session, &profile.exec.interpreters);
    evaluate_line_with_grants(profile, &classification, grants, session, at(now))
}

// FR-POL-60: a matching unexpired grant turns an ask into an allow, with source `grant` naming the grant.
#[test]
fn grant_turns_ask_into_allow() {
    let p = profile(RULES);
    let grants = set_of([session_grant(7, "git push")]);
    let decision = decide(&p, &grants, session_id(1), 10, "git push origin main");
    assert_eq!(decision.verdict, RuleAction::Allow);
    assert_eq!(decision.source, DecisionSource::Grant);
    assert_eq!(decision.grant, Some(grant_id(7)));
    // The rule the grant answered is still named, and the parts keep what the profile said.
    assert_eq!(decision.rule_id, Some(RuleId::Ask(0)));
    assert_eq!(decision.matched_rules[0].verdict, RuleAction::Ask);
    // Normalised options, wrappers and other allowed parts do not stop the grant.
    for line in ["git -c x=y push", "env A=1 git push", "git status && git push"] {
        assert_eq!(
            decide(&p, &grants, session_id(1), 10, line).verdict,
            RuleAction::Allow,
            "{line}"
        );
    }
    // Without grants the same line asks, by rule.
    let decision = decide(&p, &GrantSet::new(), session_id(1), 10, "git push");
    assert_eq!(
        (decision.verdict, decision.source, decision.grant),
        (RuleAction::Ask, DecisionSource::Rule, None)
    );
}

// A grant must cover every part that asks, and must match whatever unknown arguments become.
#[test]
fn grant_must_cover_every_asking_part() {
    let p = profile(RULES);
    let grants = set_of([session_grant(1, "git push")]);
    let decision = decide(&p, &grants, session_id(1), 10, "git push && npm publish");
    assert_eq!(
        (decision.verdict, decision.source, decision.grant),
        (RuleAction::Ask, DecisionSource::Rule, None)
    );
    // Two grants together cover both; the decision names the one covering the first asking part.
    let grants = set_of([session_grant(1, "npm publish"), session_grant(2, "git push")]);
    let decision = decide(&p, &grants, session_id(1), 10, "git push && npm publish");
    assert_eq!(
        (decision.verdict, decision.grant),
        (RuleAction::Allow, Some(grant_id(2)))
    );
    // `git $X` may be `git push`, but a grant for `git push` must hold whatever `$X` becomes, as an allow rule must.
    let p_plain = profile("[exec]\nallow = [\"git\"]\nask = [\"git push\"]");
    let grants = set_of([session_grant(1, "git push")]);
    assert_eq!(
        decide(&p_plain, &grants, session_id(1), 10, "git $X").verdict,
        RuleAction::Ask
    );
    assert_eq!(
        decide(&p_plain, &grants, session_id(1), 10, "git push $X").verdict,
        RuleAction::Allow
    );
    // A grant for another command covers nothing here.
    let grants = set_of([session_grant(1, "npm publish")]);
    assert_eq!(
        decide(&p, &grants, session_id(1), 10, "git push").verdict,
        RuleAction::Ask
    );
}

// A grant never overrides a deny, whether the denied part is another command or the granted one itself.
#[test]
fn grant_never_overrides_deny() {
    let p = profile(RULES);
    let grants = set_of([session_grant(1, "git push"), session_grant(2, "git push --force")]);
    for line in [
        "git push --force",
        "git push && git push --force",
        "git push --force origin",
    ] {
        let decision = decide(&p, &grants, session_id(1), 10, line);
        assert_eq!(decision.verdict, RuleAction::Deny, "{line}");
        assert_eq!(decision.source, DecisionSource::Rule, "{line}");
        assert_eq!(decision.grant, None, "{line}");
        assert_eq!(decision.capabilities, LineCapabilities::default(), "{line}");
    }
    // A default deny, too.
    let p = profile("[exec]\ndefault = \"deny\"");
    let grants = set_of([session_grant(1, "curl")]);
    assert_eq!(
        decide(&p, &grants, session_id(1), 10, "curl x").verdict,
        RuleAction::Deny
    );
}

// Expiry uses the time passed in from the injected clock: from `expires_at` on, a grant never matches.
#[test]
fn expired_grant_does_not_match() {
    let p = profile(RULES);
    let grants = set_of([session_grant(1, "git push")]);
    assert_eq!(
        decide(&p, &grants, session_id(1), 99, "git push").verdict,
        RuleAction::Allow
    );
    for now in [100, 101, 10_000] {
        let decision = decide(&p, &grants, session_id(1), now, "git push");
        assert_eq!(
            (decision.verdict, decision.source),
            (RuleAction::Ask, DecisionSource::Rule),
            "{now}"
        );
    }
    // Nor is it listed, and the set drops it on the next change.
    assert_eq!(grants.list(at(99)).count(), 1);
    assert_eq!(grants.list(at(100)).count(), 0);
    let mut grants = grants;
    assert_eq!(grants.prune(at(100)), 1);
    assert_eq!(grants, GrantSet::new());
}

// FR-POL-60: a session grant applies to its session only; a profile grant to every session using that profile.
#[test]
fn session_grant_does_not_apply_to_other_session() {
    let p = profile(RULES);
    let grants = set_of([session_grant(1, "git push")]);
    assert_eq!(
        decide(&p, &grants, session_id(1), 10, "git push").verdict,
        RuleAction::Allow
    );
    assert_eq!(
        decide(&p, &grants, session_id(2), 10, "git push").verdict,
        RuleAction::Ask
    );

    let by_profile = |name: &str| {
        let grant = Grant::new(
            grant_id(5),
            GrantScope::Profile(profile_name(name)),
            "git push",
            at(100),
        )
        .unwrap();
        set_of([grant])
    };
    // The test profile is called `t`: any of its sessions is covered, and a grant for another profile covers none.
    for session in [session_id(1), session_id(2)] {
        let decision = decide(&p, &by_profile("t"), session, 10, "git push");
        assert_eq!(
            (decision.verdict, decision.grant),
            (RuleAction::Allow, Some(grant_id(5)))
        );
        assert_eq!(
            decide(&p, &by_profile("other"), session, 10, "git push").verdict,
            RuleAction::Ask
        );
    }
}

// FR-POL-61: revoking removes the grant at once; an unknown, revoked or expired ID is an error.
#[test]
fn revoked_grant_stops_matching() {
    let p = profile(RULES);
    let mut grants = set_of([session_grant(1, "git push"), session_grant(2, "npm publish")]);
    assert_eq!(
        decide(&p, &grants, session_id(1), 10, "git push").verdict,
        RuleAction::Allow
    );
    assert_eq!(grants.revoke(grant_id(1), at(10)), Ok(session_grant(1, "git push")));
    assert_eq!(
        decide(&p, &grants, session_id(1), 10, "git push").verdict,
        RuleAction::Ask
    );
    // The other grant is untouched.
    let listed: Vec<_> = grants.list(at(10)).map(Grant::id).collect();
    assert_eq!(listed, [grant_id(2)]);
    assert_eq!(grants.revoke(grant_id(1), at(10)), Err(CoreError::GrantNotFound));
    assert_eq!(grants.revoke(grant_id(9), at(10)), Err(CoreError::GrantNotFound));
    // An expired grant is already gone.
    assert_eq!(grants.revoke(grant_id(2), at(100)), Err(CoreError::GrantNotFound));
    assert_eq!(grants, GrantSet::new());
}

// FR-POL-20, FR-POL-21: a grant may answer the ask of a line holding dynamic code, but its clamps stay.
#[test]
fn grant_does_not_lift_dynamic_clamp() {
    let p = profile(&format!(
        "{RULES}[network]
mode = \"allowlist\"
hosts = [\"registry.npmjs.org\"]
approval_hosts = [\"github.com\"]
[secrets.env]
TOKEN = {{ secret = \"t\", inject_for = [\"python3\"] }}
"
    ));
    let grants = set_of([session_grant(1, "python3")]);
    let decision = decide(&p, &grants, session_id(1), 10, "python3 -c 'import os'");
    assert_eq!(
        (decision.verdict, decision.source),
        (RuleAction::Allow, DecisionSource::Grant)
    );
    let capabilities = &decision.capabilities;
    assert!(capabilities.dynamic);
    assert_eq!(capabilities.hosts, ["registry.npmjs.org"]);
    assert_eq!(capabilities.approval_hosts, Vec::<String>::new());
    assert_eq!(capabilities.secrets, Vec::<String>::new());
    assert_eq!(capabilities.classes, []);
    // The same capabilities as without the grant: a grant only changes the verdict.
    let ungranted = decide(&p, &GrantSet::new(), session_id(1), 10, "python3 -c 'import os'");
    assert_eq!(ungranted.verdict, RuleAction::Ask);
    assert_eq!(&ungranted.capabilities, capabilities);
    // A dynamic part with no command of its own (here, `[[ … ]]`) has nothing a grant could match.
    let p = profile("[exec]\nallow = [\"git\"]\ndefault = \"ask\"");
    let grants = set_of([session_grant(1, "git")]);
    assert_eq!(
        decide(&p, &grants, session_id(1), 10, "[[ -n x ]] && git status").verdict,
        RuleAction::Ask
    );
}

// FR-AGT-21: under `unattended`, a grant may answer a plain ask, but granted dynamic code is still denied.
#[test]
fn unattended_still_denies_granted_dynamic_code() {
    let p = load_unattended(&context(), &fs()).unwrap();
    let scope = GrantScope::Profile(p.name.clone());
    let grants = set_of([
        Grant::new(grant_id(1), scope.clone(), "make", at(100)).unwrap(),
        Grant::new(grant_id(2), scope, "git", at(100)).unwrap(),
    ]);
    let decision = decide(&p, &grants, session_id(1), 10, "make");
    assert_eq!(
        (decision.verdict, decision.source),
        (RuleAction::Allow, DecisionSource::Grant)
    );
    let decision = decide(&p, &grants, session_id(1), 10, "GIT_EXTERNAL_DIFF=./x git diff");
    assert_eq!(
        (decision.verdict, decision.source),
        (RuleAction::Deny, DecisionSource::Standalone)
    );
    assert_eq!(decision.grant, None);
}

// The rule is checked like an `exec.allow` entry: a grant that could never match is refused.
#[test]
fn grant_rule_must_be_a_command_pattern() {
    for rule in ["", "   ", "/usr/bin/git push", "./x", "git\npush", &"a".repeat(5000)] {
        assert_eq!(
            Grant::new(grant_id(1), GrantScope::Session(session_id(1)), rule, at(100)),
            Err(CoreError::InvalidGrantRule),
            "{rule:?}"
        );
    }
    let grant = session_grant(3, "git push *");
    assert_eq!(grant.id(), grant_id(3));
    assert_eq!(grant.scope(), &GrantScope::Session(session_id(1)));
    assert_eq!(grant.scope().code(), "session");
    assert_eq!(GrantScope::Profile(profile_name("t")).code(), "profile");
    assert_eq!(grant.rule(), "git push *");
    assert_eq!(grant.expires_at(), at(100));
}

// Inserting refuses a duplicate ID, an already-expired grant and more than `MAX_GRANTS`, leaving the set unchanged.
#[test]
fn insert_refuses_duplicates_expired_and_overflow() {
    let mut grants = set_of([session_grant(1, "git push")]);
    let before = grants.clone();
    assert_eq!(
        grants.insert(session_grant(1, "npm publish"), at(10)),
        Err(CoreError::GrantExists)
    );
    assert_eq!(
        grants.insert(session_grant(2, "npm publish"), at(100)),
        Err(CoreError::GrantExpired)
    );
    assert_eq!(grants, before);
    // An expired grant no longer holds its ID.
    let renewed = Grant::new(grant_id(1), GrantScope::Session(session_id(1)), "git push", at(300)).unwrap();
    assert_eq!(grants.insert(renewed, at(200)), Ok(()));

    let mut grants = GrantSet::new();
    for n in 0..MAX_GRANTS {
        grants.insert(session_grant(n as u128, "git push"), at(0)).unwrap();
    }
    let full = grants.clone();
    let extra = session_grant(MAX_GRANTS as u128, "git push");
    assert_eq!(grants.insert(extra.clone(), at(0)), Err(CoreError::TooManyGrants));
    assert_eq!(grants, full);
    // Room comes back once grants expire.
    let later = Grant::new(extra.id(), extra.scope().clone(), "git push", at(200)).unwrap();
    assert_eq!(grants.insert(later, at(100)), Ok(()));
    assert_eq!(grants.list(at(100)).count(), 1);
}

/// The rule a grant from an answer to `line` would get.
fn answer_rule(line: &str) -> Option<String> {
    let p = profile(RULES);
    line_grant_rule(
        &classify(&parse_line(line), line, &Session, &p.exec.interpreters),
        &crate::Redactor::default(),
    )
}

// KNSH-069, FR-POL-62: a grant in `decision.respond` covers the asked line itself: one simple command whose every
// word is known becomes the rule, and the rule then turns the same line's ask into an allow.
#[test]
fn answer_grant_rule_is_the_asked_command() {
    assert_eq!(
        answer_rule("git push origin main").as_deref(),
        Some("git push origin main")
    );
    assert_eq!(
        answer_rule("'git'  push   \"origin\"").as_deref(),
        Some("git push origin")
    );
    let p = profile(RULES);
    let rule = answer_rule("npm publish --tag next").unwrap();
    let exact = Grant::exact(grant_id(1), GrantScope::Session(session_id(1)), &rule, at(100)).unwrap();
    assert!(exact.is_exact());
    let grants = set_of([exact]);
    let decision = decide(&p, &grants, session_id(1), 10, "npm publish --tag next");
    assert_eq!(decision.verdict, RuleAction::Allow);
    assert_eq!(decision.source, DecisionSource::Grant);
    // It covers that command, not its siblings, nor the same command with more arguments the authority never saw.
    for other in [
        "npm publish --tag latest",
        "npm publish --tag next --access public",
        "npm publish --tag next $X",
    ] {
        assert_eq!(
            decide(&p, &grants, session_id(1), 10, other).verdict,
            RuleAction::Ask,
            "{other}"
        );
    }
    // A grant made with `Grant::new` keeps the FR-POL-16 extension.
    assert!(!session_grant(2, "npm publish").is_exact());
}

// A line that cannot be written as a rule gets no grant, never a broader one: several commands, a wrapper, an
// expansion, a substitution, a word with a space or a `*`, a path as the name, or a line the parser cannot read.
#[test]
fn answer_grant_rule_refuses_lines_it_cannot_express() {
    for line in [
        "git push origin main && npm publish",
        "git push | cat",
        "env git push",
        "git push $REMOTE",
        "git push $(cat remote)",
        "git commit -m 'two words'",
        "rm *.txt",
        "rm '*'",
        "./deploy.sh",
        "/usr/bin/git push",
        "git push origin main )",
        "",
    ] {
        assert_eq!(answer_rule(line), None, "{line:?}");
    }
}

// FR-SEC-10 (KNSH-070): a line holding a redaction marker, plain or named, gets no grant: the marker stands for a value
// that was taken out, and a grant would write it down as if it were the real line.
#[test]
fn answer_grant_rule_refuses_lines_with_redaction_markers() {
    for line in ["npm publish «redacted»", "npm publish --token=«redacted:npm-token»"] {
        assert_eq!(answer_rule(line), None, "{line:?}");
    }
}

// FR-REC-05 (KNSH-091): a line holding one of the session's secrets gets no grant, since grants are listed and
// stored; the same line without the secret does.
#[test]
fn answer_grant_rule_refuses_lines_holding_a_secret() {
    let p = profile(RULES);
    let name = crate::SecretName::new("npm-token").unwrap();
    let redactor = Redactor::new([(name, crate::Redacted::new(&b"tok-123456"[..]))]).unwrap();
    let rule = |line: &str| {
        line_grant_rule(
            &classify(&parse_line(line), line, &Session, &p.exec.interpreters),
            &redactor,
        )
    };
    assert_eq!(rule("npm publish --token=tok-123456"), None);
    assert_eq!(
        answer_rule("npm publish --token=tok-123456").as_deref(),
        Some("npm publish --token=tok-123456")
    );
}
