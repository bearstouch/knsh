//! Line verdict tests (KNSH-041): aggregation, dynamic-code limits, failure safety and the `unattended` profile.

use std::path::PathBuf;

use knsh_bash::{Interpreters, Lookup, Resolver, SourceFile, classify, parse_line};

use super::*;
use crate::policy::paths::testing::FakeFs;
use crate::policy::{LookupError, PathContext, ProfileSource, load_profile_text, load_unattended};

/// No parents: every test profile stands alone.
struct NoParents;

impl ProfileSource for NoParents {
    fn read_profile(&self, _name: &ProfileName) -> Result<Vec<u8>, LookupError> {
        Err(LookupError::NotFound)
    }
}

/// A session whose `PATH` finds names in `/usr/bin`, except `./…` names, which are project executables, and
/// `missing`, which is not found.
struct Session;

impl Resolver for Session {
    fn resolve(&self, name: &str, _lookup: Lookup) -> Program {
        if knsh_bash::is_builtin(name) {
            Program::Builtin
        } else if name == "missing" {
            Program::NotFound
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

fn fs() -> FakeFs {
    let mut fs = FakeFs::new();
    fs.add("/Users/u/app").add("/tmp").add("/bin/bash");
    fs
}

fn context() -> PathContext {
    PathContext {
        home: PathBuf::from("/Users/u"),
        tmpdir: PathBuf::from("/tmp"),
        start_dir: PathBuf::from("/Users/u/app"),
    }
}

/// A profile read through the real loader.
fn profile(text: &str) -> Profile {
    let text = format!("name = \"t\"\n{text}");
    load_profile_text(text.as_bytes(), &NoParents, &context(), &fs()).unwrap()
}

fn unattended() -> Profile {
    load_unattended(&context(), &fs()).unwrap()
}

fn decide_line(profile: &Profile, line: &str) -> LineDecision {
    let classification = classify(&parse_line(line), line, &Session, &profile.exec.interpreters);
    evaluate_line(profile, &classification)
}

/// A profile with network allowlists and an npm secret, for the capability tests.
const NETWORKED: &str = "[exec]
allow = [\"git\", \"npm\", \"python3\", \"cd\", \"eval\", \"curl\"]
[network]
mode = \"allowlist\"
hosts = [\"registry.npmjs.org\"]
approval_hosts = [\"github.com\"]
loopback = [3000]
[secrets.env]
NPM_TOKEN = { secret = \"npm-token\", inject_for = [\"npm publish\"], hosts = [\"registry.npmjs.org\"] }
";

// FR-POL-18, FR-LC-09: one denied part denies the whole line, and it receives nothing.
#[test]
fn one_denied_part_denies_line() {
    let p = profile("[exec]\nallow = [\"git\", \"ls\"]\nask = [\"git push\"]\ndeny = [\"rm -rf *\"]");
    let decision = decide_line(&p, "ls && git push; rm -rf build | cat");
    assert_eq!(decision.verdict, RuleAction::Deny);
    assert_eq!(decision.source, DecisionSource::Rule);
    assert_eq!(decision.rule_id, Some(RuleId::Deny(0)));
    assert_eq!(decision.reason, None);
    assert_eq!(decision.capabilities, LineCapabilities::default());
    // Every part is reported, in source order: `ls`, `git push`, `rm`, then `cat` (the default, ask).
    let parts: Vec<_> = decision
        .matched_rules
        .iter()
        .map(|part| (part.command, part.verdict))
        .collect();
    assert_eq!(
        parts,
        [
            (Some(0), RuleAction::Allow),
            (Some(1), RuleAction::Ask),
            (Some(2), RuleAction::Deny),
            (Some(3), RuleAction::Ask),
        ]
    );
    // A part inside a substitution counts too.
    assert_eq!(decide_line(&p, "ls $(rm -rf /)").verdict, RuleAction::Deny);
}

// FR-POL-18: with nothing denied, one asking part asks for the whole line; the first asking part is named.
#[test]
fn one_ask_part_asks_line() {
    let p = profile("[exec]\nallow = [\"git\", \"ls\"]\nask = [\"git push\", \"git tag\"]");
    let decision = decide_line(&p, "ls; git tag v1 && git push");
    assert_eq!(decision.verdict, RuleAction::Ask);
    assert_eq!(decision.source, DecisionSource::Rule);
    assert_eq!(decision.rule_id, Some(RuleId::Ask(1)));
    // Only allowed parts: allowed, by the first part's rule.
    let decision = decide_line(&p, "ls && git status");
    assert_eq!(decision.verdict, RuleAction::Allow);
    assert_eq!(decision.rule_id, Some(RuleId::Allow(1)));
    // A line with no parts runs nothing.
    let decision = decide_line(&p, "# nothing");
    assert_eq!((decision.verdict, decision.rule_id), (RuleAction::Allow, None));
}

// FR-POL-21: `python3 -c "…git push…"` keeps `network.hosts` but cannot reach `approval_hosts`, has no classes, and
// one dynamic part clamps the whole line, even when the line is allowed.
#[test]
fn dynamic_part_clamps_network_to_hosts() {
    let p = profile(NETWORKED);
    let decision = decide_line(&p, "python3 -c \"import subprocess; subprocess.run(['git','push'])\"");
    assert_eq!(decision.verdict, RuleAction::Allow);
    let clamped = LineCapabilities {
        hosts: vec!["registry.npmjs.org".to_owned()],
        approval_hosts: Vec::new(),
        loopback: vec![3000],
        classes: Vec::new(),
        secrets: Vec::new(),
        dynamic: true,
    };
    assert_eq!(decision.capabilities, clamped);
    assert_eq!(decide_line(&p, "git push && python3 -c 'x'").capabilities, clamped);
    assert_eq!(decide_line(&p, "eval git push").capabilities, clamped);
    // The same command without dynamic code may reach approval hosts on the strength of its class.
    let decision = decide_line(&p, "cd repo && git push origin main");
    assert_eq!(decision.capabilities.approval_hosts, ["github.com"]);
    assert_eq!(decision.capabilities.classes, [NetworkClass::Publish]);
    assert!(!decision.capabilities.dynamic);
}

// FR-POL-21, FR-SEC-04: a line holding dynamic code receives no secrets, even when a part matches `inject_for`.
#[test]
fn dynamic_part_gets_no_secrets() {
    let p = profile(NETWORKED);
    assert_eq!(decide_line(&p, "npm publish").capabilities.secrets, ["NPM_TOKEN"]);
    assert_eq!(decide_line(&p, "npm install").capabilities.secrets.len(), 0);
    assert_eq!(decide_line(&p, "npm publish && eval x").capabilities.secrets.len(), 0);
    assert_eq!(
        decide_line(&p, "npm publish; sh -c 'curl x'")
            .capabilities
            .secrets
            .len(),
        0
    );
    // Only a certain match counts: the arguments `xargs` gives are not known.
    assert_eq!(decide_line(&p, "xargs npm publish").capabilities.secrets.len(), 0);
}

// FR-NET-03: a line presents classes only if every command that can connect has them.
#[test]
fn line_classes_need_every_connecting_command_classified() {
    let p = profile(NETWORKED);
    assert_eq!(
        decide_line(&p, "git fetch && npm install").capabilities.classes,
        [NetworkClass::Fetch]
    );
    // `curl` has no classes, so `git fetch` lends it none.
    assert_eq!(
        decide_line(&p, "git fetch && curl https://github.com")
            .capabilities
            .classes
            .len(),
        0
    );
    assert_eq!(decide_line(&p, "git --frobnicate fetch").capabilities.classes.len(), 0);
    assert_eq!(decide_line(&p, "./deploy && git fetch").capabilities.classes.len(), 0);
    // Under `network.mode = "none"` nothing is reachable.
    let p = profile("[exec]\nallow = [\"git\"]\n[network]\nhosts = [\"a.example\"]\napproval_hosts = [\"b.example\"]");
    let capabilities = decide_line(&p, "git fetch").capabilities;
    assert!(capabilities.hosts.is_empty() && capabilities.approval_hosts.is_empty());
}

// FR-POL-20: dynamic code nothing else decides is decided by `exec.default`.
#[test]
fn dynamic_part_without_entry_uses_default() {
    for (setting, action) in [
        ("allow", RuleAction::Allow),
        ("ask", RuleAction::Ask),
        ("deny", RuleAction::Deny),
    ] {
        let p = profile(&format!("[exec]\nallow = [\"ls\", \"echo\"]\ndefault = \"{setting}\""));
        // The parser could not read the line: it has no entries at all.
        let decision = decide_line(&p, "echo 'unterminated");
        assert_eq!(decision.verdict, action, "{setting}");
        assert_eq!(
            decision.matched_rules,
            [MatchedRule {
                command: None,
                verdict: action,
                rule_id: RuleId::Default
            }]
        );
        assert!(decision.capabilities.dynamic || action == RuleAction::Deny);
        // A construct kept whole, next to an allowed command.
        assert_eq!(decide_line(&p, "[[ -f x ]] && ls").verdict, action, "{setting}");
    }
    // A construct kept whole inside an allowed dynamic command is still decided by the default: the interpreter's
    // allow rule says nothing of the `rm` hidden in it.
    let p = profile("[exec]\nallow = [\"python3\"]\ndeny = [\"rm\"]");
    for line in [
        "python3 -c x \"$([[ $(rm -rf /) ]])\"",
        "python3 -c x `[[ $(rm -rf /) ]]`",
        "python3 -c x \"$(coproc rm -rf /)\"",
    ] {
        let decision = decide_line(&p, line);
        assert_eq!(decision.verdict, RuleAction::Ask, "{line}");
        assert_eq!(decision.rule_id, Some(RuleId::Default), "{line}");
    }
    // A code variable or here-document belongs to its command, whose rule decides it.
    assert_eq!(decide_line(&p, "python3 - <<< 'x'").verdict, RuleAction::Allow);
}

// Fail closed: an error or a panic during evaluation is a deny by rule, with a reason, receiving nothing.
#[test]
fn evaluation_error_denies() {
    let failed = LineDecision {
        verdict: RuleAction::Deny,
        source: DecisionSource::Rule,
        rule_id: None,
        grant: None,
        reason: Some(LineReason::EvaluationFailed),
        matched_rules: Vec::new(),
        capabilities: LineCapabilities::default(),
    };
    assert_eq!(fail_closed(|| Err(EvaluationError::InconsistentClassification)), failed);
    assert_eq!(fail_closed(|| panic!("a bug in matching")), failed);
    assert!(failed.reason.unwrap().to_string().contains("denied"));
    // A successful evaluation passes through unchanged.
    let p = profile("[exec]\nallow = [\"ls\"]");
    let classification = classify(&parse_line("ls"), "ls", &Session, &Interpreters::defaults());
    let decision = decide(&p, &classification, None).unwrap();
    assert_eq!(fail_closed(|| Ok(decision.clone())), decision);
}

// FR-AGT-21: under `unattended`, an ask becomes a deny by the standalone rules, with a reason naming the profile.
#[test]
fn unattended_turns_ask_into_deny() {
    let p = unattended();
    for (line, rule_id) in [
        ("curl https://example.com", RuleId::Default),
        ("ls && npm install", RuleId::Default),
        ("./scripts/build.sh", RuleId::ProjectExecutables),
        ("bash -c 'ls'", RuleId::Default),
    ] {
        let decision = decide_line(&p, line);
        assert_eq!(decision.verdict, RuleAction::Deny, "{line}");
        assert_eq!(decision.source, DecisionSource::Standalone, "{line}");
        assert_eq!(decision.rule_id, Some(rule_id), "{line}");
        let reason = decision.reason.unwrap();
        assert_eq!(
            reason,
            LineReason::Unattended {
                profile: p.name.clone(),
                rule_id
            }
        );
        assert!(reason.to_string().contains("unattended"), "{reason}");
        assert_eq!(decision.capabilities, LineCapabilities::default());
    }
    // An allowed tool running dynamic code (a code variable runs any program) needs approval too.
    // The rule named is the allow rule of the dynamic part, found by pattern so the list can be reordered.
    let allow_rule = |pattern: &str| RuleId::Allow(p.exec.allow.iter().position(|rule| rule == pattern).unwrap());
    for (line, rule_id) in [
        ("GIT_EXTERNAL_DIFF=./x git diff", allow_rule("git diff")),
        ("ls && PAGER=./x git log", allow_rule("git log")),
    ] {
        let decision = decide_line(&p, line);
        assert_eq!(decision.verdict, RuleAction::Deny, "{line}");
        assert_eq!(decision.source, DecisionSource::Standalone, "{line}");
        assert_eq!(decision.rule_id, Some(rule_id), "{line}");
        assert_eq!(
            decision.reason,
            Some(LineReason::Unattended {
                profile: p.name.clone(),
                rule_id
            })
        );
        assert_eq!(decision.capabilities, LineCapabilities::default());
    }
    // A deny rule still denies as a rule.
    let decision = decide_line(&p, "git -c core.fsmonitor=x status");
    assert_eq!(
        (decision.verdict, decision.source),
        (RuleAction::Deny, DecisionSource::Rule)
    );
    // Any other profile keeps its asks for the supervisor (FR-LC-10).
    let decision = decide_line(&profile(""), "curl https://example.com");
    assert_eq!(
        (decision.verdict, decision.source),
        (RuleAction::Ask, DecisionSource::Rule)
    );
}

// FR-AGT-21: plain read-only commands run under `unattended`, without network; their risky options do not.
#[test]
fn unattended_allows_plain_read_only_command() {
    let p = unattended();
    for line in [
        "ls",
        "ls -la src",
        "cat README.md | grep -n TODO | head -5",
        "cd src && rg needle",
        "find . -name '*.rs'",
        "git status && git log --oneline -5 && git diff HEAD~1",
    ] {
        let decision = decide_line(&p, line);
        assert_eq!(decision.verdict, RuleAction::Allow, "{line}");
        assert_eq!(decision.source, DecisionSource::Rule, "{line}");
        assert!(decision.capabilities.hosts.is_empty() && decision.capabilities.approval_hosts.is_empty());
    }
    for line in [
        "find . -exec rm {} ;",
        "find . -name x -delete",
        "rg --pre ./x needle",
        "git -c diff.external=./x diff",
        "rm -rf build",
        "git push",
        "sudo ls",
    ] {
        assert_eq!(decide_line(&p, line).verdict, RuleAction::Deny, "{line}");
    }
}

#[test]
fn decision_sources_use_record_spellings() {
    let codes: Vec<_> = [
        DecisionSource::Rule,
        DecisionSource::Hook,
        DecisionSource::Authority,
        DecisionSource::User,
        DecisionSource::Standalone,
        DecisionSource::RateLimit,
        DecisionSource::Grant,
    ]
    .iter()
    .map(|source| source.code())
    .collect();
    assert_eq!(
        codes,
        ["rule", "hook", "authority", "user", "standalone", "rate_limit", "grant"]
    );
}
