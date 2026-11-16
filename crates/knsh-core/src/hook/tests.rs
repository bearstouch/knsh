//! Hook configuration, verdicts and the chain, with a scripted executor (KNSH-062).

use std::cell::RefCell;
use std::path::{Path, PathBuf};
use std::time::Duration;

use knsh_bash::{Classification, Interpreters, Lookup, Program, SourceFile, classify, parse_line};

use super::*;
use crate::id::SessionId;
use crate::lifecycle::{HookVerdict, Proposal};
use crate::path::CanonicalPath;
use crate::record::HookResult;
use crate::redacted::Redacted;
use crate::session::{Actor, AgentId};
use crate::ulid::Ulid;

const HOME: &str = "/Users/u";

/// Resolves every name to `/usr/bin/<name>`, and `./tool` to a project executable.
struct Resolver;

impl knsh_bash::Resolver for Resolver {
    fn resolve(&self, name: &str, _lookup: Lookup) -> Program {
        match name {
            "./tool" => Program::ProjectExecutable("/p/tool".into()),
            "cd" => Program::Builtin,
            _ => Program::Trusted(Path::new("/usr/bin").join(name)),
        }
    }

    fn source_file(&self, _path: &str) -> SourceFile {
        SourceFile::Unresolved
    }
}

fn classified(line: &str) -> Classification {
    classify(&parse_line(line), line, &Resolver, &Interpreters::defaults())
}

fn config(text: &str) -> HookConfig {
    let root = knsh_toml::parse(text.as_bytes()).unwrap();
    parse_hooks(&root, Path::new(HOME))
}

fn entries(text: &str) -> Vec<HookEntry> {
    match config(text) {
        HookConfig::Hooks(entries) => entries,
        HookConfig::Invalid(problem) => panic!("invalid configuration: {problem:?}"),
    }
}

/// One valid hook entry for `run`, with optional extra keys.
fn hook(run: &str, extra: &str) -> String {
    format!("[[hooks]]\nevent = \"command.proposed\"\nrun = \"{run}\"\ntimeout_ms = 2000\n{extra}")
}

/// The answers a scripted executor gives, in order, and the programs it was asked to run.
struct Scripted {
    answers: RefCell<Vec<Ended>>,
    ran: RefCell<Vec<(PathBuf, Vec<u8>)>>,
}

impl Scripted {
    fn new(answers: Vec<Ended>) -> Self {
        Self {
            answers: RefCell::new(answers),
            ran: RefCell::new(Vec::new()),
        }
    }

    fn ran(&self) -> Vec<PathBuf> {
        self.ran.borrow().iter().map(|(program, _)| program.clone()).collect()
    }
}

impl HookExecutor for Scripted {
    fn execute(&self, hook: &HookSpec, input: &[u8]) -> Execution {
        self.ran.borrow_mut().push((hook.program.clone(), input.to_vec()));
        let ended = self.answers.borrow_mut().remove(0);
        let duration = if ended == Ended::TimedOut {
            // A timed-out hook ran a little past its timeout before it was killed.
            hook.timeout + Duration::from_millis(30)
        } else {
            Duration::from_millis(12)
        };
        Execution { ended, duration }
    }
}

fn printed(stdout: &str) -> Ended {
    Ended::Finished {
        stdout: stdout.as_bytes().to_vec(),
        exit: HookExit::Exited(0),
    }
}

fn exited(code: i32) -> Ended {
    Ended::Finished {
        stdout: Vec::new(),
        exit: HookExit::Exited(code),
    }
}

/// Runs `config` on `line` for an agent (or a human) session.
fn run_for(actor: &Actor, config: &HookConfig, line: &str, executor: &Scripted) -> crate::lifecycle::HookOutcome {
    let classification = classified(line);
    let command = Redacted::new(line.to_owned());
    let cwd = CanonicalPath::new("/Users/u/app").unwrap();
    let proposal = Proposal {
        session_id: SessionId::from_ulid(Ulid::from_u128(1)),
        actor,
        command: &command,
        cwd: &cwd,
        rewritten_from: None,
        classification: &classification,
    };
    run_hooks(config, &proposal, Some(b"{}"), executor)
}

fn agent() -> Actor {
    Actor::Agent(AgentId::new("claude-code").unwrap())
}

fn run(config: &HookConfig, line: &str, executor: &Scripted) -> crate::lifecycle::HookOutcome {
    run_for(&agent(), config, line, executor)
}

// ---- Configuration ----

// FR-HOOK-10: hooks are kept, and run, in the order they are declared.
#[test]
fn loads_hooks_in_declared_order() {
    let text = [hook("/h/first", ""), hook("~/h/second", ""), hook("/h/third", "")].concat();
    let loaded = entries(&text);
    let programs: Vec<_> = loaded
        .iter()
        .map(|entry| entry.registration.as_ref().unwrap().program.clone())
        .collect();
    assert_eq!(
        programs,
        [
            PathBuf::from("/h/first"),
            PathBuf::from("/Users/u/h/second"),
            PathBuf::from("/h/third")
        ]
    );
    assert_eq!(
        loaded.iter().map(|entry| entry.id.to_string()).collect::<Vec<_>>(),
        ["hooks[0]", "hooks[1]", "hooks[2]"]
    );
    assert_eq!(
        loaded[0].registration.as_ref().unwrap().timeout,
        Duration::from_millis(2000)
    );

    let executor = Scripted::new(vec![exited(0), exited(0), exited(0)]);
    let outcome = run(&HookConfig::Hooks(loaded), "ls", &executor);
    assert_eq!(outcome.verdict, HookVerdict::Allow);
    assert_eq!(
        executor.ran(),
        [
            PathBuf::from("/h/first"),
            PathBuf::from("/Users/u/h/second"),
            PathBuf::from("/h/third")
        ]
    );
    assert_eq!(
        outcome.runs.iter().map(|run| run.hook.as_str()).collect::<Vec<_>>(),
        ["hooks[0]", "hooks[1]", "hooks[2]"]
    );
}

// Hook model: only `command.proposed` is accepted; unknown keys and bad values make the hook invalid.
#[test]
fn rejects_unknown_event() {
    let other_event = "[[hooks]]\nevent = \"command.finished\"\nrun = \"/h\"\ntimeout_ms = 1\n";
    assert_eq!(entries(other_event)[0].registration, Err(HookProblem::UnsupportedEvent));
    for (text, problem) in [
        ("[[hooks]]\nrun = \"/h\"\ntimeout_ms = 1\n", HookProblem::MissingEvent),
        (
            "[[hooks]]\nevent = 1\nrun = \"/h\"\ntimeout_ms = 1\n",
            HookProblem::UnsupportedEvent,
        ),
        (hook("/h", "colour = \"red\"\n").as_str(), HookProblem::UnknownKey),
        (
            "[[hooks]]\nevent = \"command.proposed\"\ntimeout_ms = 1\n",
            HookProblem::MissingRun,
        ),
        (hook("relative/hook.sh", "").as_str(), HookProblem::InvalidRun),
        (hook("~other/hook.sh", "").as_str(), HookProblem::InvalidRun),
        (
            "[[hooks]]\nevent = \"command.proposed\"\nrun = \"/h\"\n",
            HookProblem::MissingTimeout,
        ),
        (
            "[[hooks]]\nevent = \"command.proposed\"\nrun = \"/h\"\ntimeout_ms = 0\n",
            HookProblem::InvalidTimeout,
        ),
        (
            "[[hooks]]\nevent = \"command.proposed\"\nrun = \"/h\"\ntimeout_ms = 60001\n",
            HookProblem::InvalidTimeout,
        ),
        (
            "[[hooks]]\nevent = \"command.proposed\"\nrun = \"/h\"\ntimeout_ms = \"2000\"\n",
            HookProblem::InvalidTimeout,
        ),
        (
            hook("/h", "match = { binary = [] }\n").as_str(),
            HookProblem::InvalidMatch,
        ),
        (
            hook("/h", "match = { binary = [\"bin/rm\"] }\n").as_str(),
            HookProblem::InvalidMatch,
        ),
        (
            hook("/h", "match = { name = [\"rm\"] }\n").as_str(),
            HookProblem::InvalidMatch,
        ),
        (hook("/h", "match = \"rm\"\n").as_str(), HookProblem::InvalidMatch),
    ] {
        assert_eq!(entries(text)[0].registration, Err(problem), "{text}");
    }
    // A malformed `match` is read as matching every line; a valid one is kept even when the rest is invalid.
    assert_eq!(entries(&hook("/h", "match = \"rm\"\n"))[0].matcher, HookMatch::Every);
    let broken_with_match = "[[hooks]]\nevent = \"x\"\nmatch = { binary = [\"rm\"] }\nrun = \"/h\"\ntimeout_ms = 1\n";
    assert_eq!(
        entries(broken_with_match)[0].matcher,
        HookMatch::Binaries(vec!["rm".to_owned()])
    );
    // The configuration as a whole.
    assert_eq!(config("hooks = 3\n"), HookConfig::Invalid(ConfigProblem::NotAnArray));
    assert_eq!(config("[recording]\nhuman = true\n"), HookConfig::none());
    let too_many = (0..=MAX_HOOKS).map(|_| hook("/h", "")).collect::<String>();
    assert_eq!(config(&too_many), HookConfig::Invalid(ConfigProblem::TooManyHooks));
    assert_eq!(entries("hooks = [1]\n")[0].registration, Err(HookProblem::NotATable));
}

// Hook model: `binary` matches the basename of the resolved binary or of the name as written, at any depth.
#[test]
fn matches_by_binary_basename() {
    let matcher = HookMatch::Binaries(vec!["rm".to_owned(), "git".to_owned()]);
    for line in [
        "rm -rf build",
        "/bin/rm x",
        "ls && git push",
        "nice -n 5 rm x",
        "echo $(rm x)",
        // Dynamic code could run anything, so it matches every list.
        "eval \"$cmd\"",
        "bash -c 'ls'",
        "if then fi (",
    ] {
        assert!(matcher.matches(&classified(line)), "{line}");
    }
    for line in ["ls -l", "echo rm", "grep git file", "rmdir x"] {
        assert!(!matcher.matches(&classified(line)), "{line}");
    }
    assert!(HookMatch::Every.matches(&classified("ls")));

    // Only matching hooks run.
    let text = [
        hook("/h/rm-guard", "match = { binary = [\"rm\"] }\n"),
        hook("/h/all", ""),
    ]
    .concat();
    let executor = Scripted::new(vec![exited(0)]);
    let outcome = run(&config(&text), "ls", &executor);
    assert_eq!(executor.ran(), [PathBuf::from("/h/all")]);
    assert_eq!(outcome.runs.len(), 1);
}

// FR-HOOK-04: an invalid hook is never dropped: it denies every line it would match, and only those.
#[test]
fn invalid_hook_denies_matching_lines() {
    let text = [
        hook("/h/ok", ""),
        "[[hooks]]\nevent = \"command.finished\"\nmatch = { binary = [\"rm\"] }\nrun = \"/h/bad\"\ntimeout_ms = 1\n"
            .to_owned(),
    ]
    .concat();
    let loaded = config(&text);

    let executor = Scripted::new(vec![exited(0)]);
    let outcome = run(&loaded, "rm -rf build", &executor);
    assert_eq!(outcome.verdict, HookVerdict::Failed);
    assert_eq!(outcome.hook.as_deref(), Some("hooks[1]"));
    assert_eq!(outcome.runs[1].result, HookResult::Invalid);
    assert_eq!(outcome.runs[1].duration_ms, 0);

    // A line the invalid hook would not match is unaffected.
    let executor = Scripted::new(vec![exited(0)]);
    assert_eq!(run(&loaded, "ls", &executor).verdict, HookVerdict::Allow);

    // A registration found not executable denies too.
    let mut entries = entries(&hook("/h/missing", ""));
    entries[0].mark_not_executable();
    let executor = Scripted::new(Vec::new());
    let outcome = run(&HookConfig::Hooks(entries), "ls", &executor);
    assert_eq!(outcome.verdict, HookVerdict::Failed);
    assert!(executor.ran().is_empty(), "an invalid hook is never started");

    // A configuration that cannot be used denies every agent line.
    let executor = Scripted::new(Vec::new());
    let outcome = run(&HookConfig::Invalid(ConfigProblem::InvalidToml), "ls", &executor);
    assert_eq!(outcome.verdict, HookVerdict::Failed);
    assert_eq!(outcome.hook.as_deref(), Some("hooks"));
    assert_eq!(outcome.runs[0].result, HookResult::Invalid);
}

// ---- Verdicts ----

// FR-HOOK-03: no output means the exit code decides; 0 allows, 2 denies.
#[test]
fn exit_codes_without_output() {
    assert_eq!(judge(b"", HookExit::Exited(0)), Some(HookReply::Allow));
    assert_eq!(judge(b" \n", HookExit::Exited(0)), Some(HookReply::Allow));
    assert_eq!(judge(b"", HookExit::Exited(2)), Some(HookReply::Deny { reason: None }));
    assert_eq!(judge(b"", HookExit::Exited(1)), None);
    assert_eq!(judge(b"", HookExit::Signalled), None);
}

// FR-HOOK-02: the documented object, strictly.
#[test]
fn reads_verdict_objects() {
    let ok = |text: &str| judge(text.as_bytes(), HookExit::Exited(0));
    assert_eq!(ok(r#"{"verdict":"allow"}"#), Some(HookReply::Allow));
    assert_eq!(
        ok("\n {\"verdict\":\"deny\",\"reason\":\"no force pushes\"}\n"),
        Some(HookReply::Deny {
            reason: Some("no force pushes".to_owned())
        })
    );
    assert_eq!(ok(r#"{"verdict":"ask"}"#), Some(HookReply::Ask { reason: None }));
    assert_eq!(
        ok(r#"{"verdict":"rewrite","command":"git push --dry-run"}"#),
        Some(HookReply::Rewrite {
            command: "git push --dry-run".to_owned()
        })
    );
    assert_eq!(
        ok(r#"{"verdict":"annotate","labels":["reviewed","team:infra"]}"#),
        Some(HookReply::Annotate {
            labels: vec!["reviewed".to_owned(), "team:infra".to_owned()]
        })
    );
    // A verdict from a hook that then failed is not trusted.
    assert_eq!(judge(br#"{"verdict":"allow"}"#, HookExit::Exited(1)), None);
}

// FR-HOOK-04: anything outside the documented object is an error.
#[test]
fn unparsable_output_is_an_error() {
    let long_reason = format!(
        r#"{{"verdict":"deny","reason":"{}"}}"#,
        "x".repeat(MAX_HOOK_REASON_LEN + 1)
    );
    let many_labels = format!(r#"{{"verdict":"annotate","labels":[{}]}}"#, vec!["\"a\""; 17].join(","));
    for text in [
        "allow",
        "{",
        r#"{"verdict":"maybe"}"#,
        r#"{"verdict":"allow","extra":1}"#,
        r#"{"verdict":"allow","command":"ls"}"#,
        r#"{"verdict":"rewrite"}"#,
        r#"{"verdict":"rewrite","command":""}"#,
        r#"{"verdict":"annotate"}"#,
        r#"{"verdict":"annotate","labels":[]}"#,
        r#"{"verdict":"annotate","labels":["has space"]}"#,
        r#"{"verdict":"deny","reason":"\u001b[2J"}"#,
        r#"{"verdict":"allow"}{"verdict":"deny"}"#,
        r#"["allow"]"#,
        long_reason.as_str(),
        many_labels.as_str(),
    ] {
        assert_eq!(judge(text.as_bytes(), HookExit::Exited(0)), None, "{text}");
    }
    let huge = vec![b' '; MAX_HOOK_OUTPUT + 1];
    assert_eq!(judge(&huge, HookExit::Exited(0)), None, "over the limit, even if blank");
}

// ---- The chain ----

// FR-HOOK-10: the first deny stops the chain; asks are remembered; annotate decides nothing; rewrite ends the pass.
#[test]
fn chain_combines_verdicts_in_order() {
    let three = [hook("/h/0", ""), hook("/h/1", ""), hook("/h/2", "")].concat();
    let loaded = config(&three);

    let executor = Scripted::new(vec![
        printed(r#"{"verdict":"annotate","labels":["seen"]}"#),
        printed(r#"{"verdict":"deny","reason":"nope"}"#),
    ]);
    let outcome = run(&loaded, "ls", &executor);
    assert_eq!(
        outcome.verdict,
        HookVerdict::Deny {
            reason: Some("nope".to_owned())
        }
    );
    assert_eq!(outcome.hook.as_deref(), Some("hooks[1]"));
    assert_eq!(executor.ran().len(), 2, "the deny stopped the chain");
    assert_eq!(outcome.runs[0].labels, ["seen"]);
    assert_eq!(outcome.runs[0].result, HookResult::Annotate);

    let executor = Scripted::new(vec![
        exited(0),
        printed(r#"{"verdict":"ask"}"#),
        printed(r#"{"verdict":"ask"}"#),
    ]);
    let outcome = run(&loaded, "ls", &executor);
    assert_eq!(outcome.verdict, HookVerdict::Ask);
    assert_eq!(
        outcome.hook.as_deref(),
        Some("hooks[1]"),
        "the first asking hook is named"
    );
    assert_eq!(outcome.runs.len(), 3);

    let executor = Scripted::new(vec![printed(r#"{"verdict":"rewrite","command":"ls -a"}"#)]);
    let outcome = run(&loaded, "ls", &executor);
    assert_eq!(
        outcome.verdict,
        HookVerdict::Rewrite {
            command: "ls -a".to_owned()
        }
    );
    assert_eq!(executor.ran().len(), 1);
}

// FR-HOOK-04: errors, unreadable output and timeouts deny; FR-HOOK-05: run times are kept, capped at the timeout.
#[test]
fn failures_deny_and_durations_are_recorded() {
    let one = config(&hook("/h/0", ""));
    for (ended, result) in [
        (exited(1), HookResult::Error),
        (printed("not json"), HookResult::Error),
        (Ended::Failed, HookResult::Error),
        (Ended::TimedOut, HookResult::Timeout),
    ] {
        let executor = Scripted::new(vec![ended]);
        let outcome = run(&one, "ls", &executor);
        assert_eq!(outcome.verdict, HookVerdict::Failed);
        assert_eq!(outcome.hook.as_deref(), Some("hooks[0]"));
        assert_eq!(outcome.runs[0].result, result);
    }
    let executor = Scripted::new(vec![Ended::TimedOut]);
    assert_eq!(
        run(&one, "ls", &executor).runs[0].duration_ms,
        2000,
        "capped at the timeout"
    );
    let executor = Scripted::new(vec![exited(0)]);
    assert_eq!(run(&one, "ls", &executor).runs[0].duration_ms, 12);

    // No input to give the hook: it is not started, and the line is denied.
    let executor = Scripted::new(Vec::new());
    let classification = classified("ls");
    let command = Redacted::new("ls".to_owned());
    let cwd = CanonicalPath::new("/").unwrap();
    let actor = agent();
    let proposal = Proposal {
        session_id: SessionId::from_ulid(Ulid::from_u128(1)),
        actor: &actor,
        command: &command,
        cwd: &cwd,
        rewritten_from: None,
        classification: &classification,
    };
    let outcome = run_hooks(&one, &proposal, None, &executor);
    assert_eq!(outcome.verdict, HookVerdict::Failed);
    assert_eq!(executor.ran().len(), 0);
}

// FR-HOOK-01: human sessions run no hooks, even a broken configuration.
#[test]
fn no_hooks_run_for_human_sessions() {
    let executor = Scripted::new(Vec::new());
    let outcome = run_for(&Actor::Human, &config(&hook("/h/0", "")), "rm -rf /", &executor);
    assert_eq!(outcome.verdict, HookVerdict::Allow);
    assert_eq!(executor.ran().len(), 0);
    assert_eq!(outcome.runs.len(), 0);
    let outcome = run_for(
        &Actor::Human,
        &HookConfig::Invalid(ConfigProblem::Unreadable),
        "ls",
        &executor,
    );
    assert_eq!(outcome.verdict, HookVerdict::Allow);
}

// ---- Combining verdicts (KNSH-063) ----

// FR-HOOK-10: the first deny stops the chain: no later hook runs, an earlier ask cannot soften it, and the denying
// hook is named.
#[test]
fn first_deny_stops_chain() {
    let three = [hook("/h/0", ""), hook("/h/1", ""), hook("/h/2", "")].concat();
    let loaded = config(&three);

    let executor = Scripted::new(vec![exited(0), exited(2)]);
    let outcome = run(&loaded, "ls", &executor);
    assert_eq!(outcome.verdict, HookVerdict::Deny { reason: None });
    assert_eq!(outcome.hook.as_deref(), Some("hooks[1]"));
    assert_eq!(
        executor.ran(),
        [PathBuf::from("/h/0"), PathBuf::from("/h/1")],
        "hooks[2] never ran"
    );
    assert_eq!(outcome.runs.len(), 2);

    // An ask before the deny is outranked by it.
    let executor = Scripted::new(vec![
        printed(r#"{"verdict":"ask"}"#),
        printed(r#"{"verdict":"deny","reason":"no"}"#),
    ]);
    let outcome = run(&loaded, "ls", &executor);
    assert_eq!(
        outcome.verdict,
        HookVerdict::Deny {
            reason: Some("no".to_owned())
        }
    );
    assert_eq!(outcome.hook.as_deref(), Some("hooks[1]"));
    assert_eq!(executor.ran().len(), 2);

    // The first hook denying runs nothing after it.
    let executor = Scripted::new(vec![exited(2)]);
    assert_eq!(run(&loaded, "ls", &executor).runs.len(), 1);
    assert_eq!(executor.ran().len(), 1);
}

// Hook model (`annotate`): labels go to the record and the chain's verdict is whatever the other hooks say.
#[test]
fn annotate_does_not_change_verdict() {
    let two = [hook("/h/0", ""), hook("/h/1", "")].concat();
    let loaded = config(&two);
    let annotate = || printed(r#"{"verdict":"annotate","labels":["build","ci:1"]}"#);

    for (second, verdict, decider) in [
        (exited(0), HookVerdict::Allow, None),
        (printed(r#"{"verdict":"ask"}"#), HookVerdict::Ask, Some("hooks[1]")),
        (exited(2), HookVerdict::Deny { reason: None }, Some("hooks[1]")),
    ] {
        let executor = Scripted::new(vec![annotate(), second]);
        let outcome = run(&loaded, "ls", &executor);
        assert_eq!(outcome.verdict, verdict);
        assert_eq!(outcome.hook.as_deref(), decider, "an annotating hook never decides");
        assert_eq!(outcome.runs[0].result, HookResult::Annotate);
        assert_eq!(outcome.runs[0].labels, ["build", "ci:1"]);
        assert_eq!(outcome.runs[1].labels, Vec::<String>::new());
    }

    // Annotations alone are an allow, and every hook still runs.
    let executor = Scripted::new(vec![annotate(), annotate()]);
    let outcome = run(&loaded, "ls", &executor);
    assert_eq!(outcome.verdict, HookVerdict::Allow);
    assert_eq!(outcome.hook, None);
    assert_eq!(executor.ran().len(), 2);
}
