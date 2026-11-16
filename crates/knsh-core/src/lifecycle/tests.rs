//! The decision pipeline with fake hooks, authority, approvals, observer and caller (KNSH-050).

use std::cell::{Cell, RefCell};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use super::*;
use crate::policy::paths::testing::FakeFs;
use crate::policy::{LookupError, PathContext, ProfileSource, load_profile_text, load_unattended};
use crate::record::HookResult;
use crate::resolve::BinaryLookup;
use crate::session::AgentId;
use crate::ulid::Ulid;

/// Executable files by canonical path.
struct Binaries(BTreeSet<PathBuf>);

impl BinaryLookup for Binaries {
    fn canonicalise(&self, path: &Path) -> Option<CanonicalPath> {
        self.0.contains(path).then(|| CanonicalPath::new(path).ok()).flatten()
    }

    fn is_executable_file(&self, path: &CanonicalPath) -> bool {
        self.0.contains(path.as_path())
    }
}

fn binaries() -> Binaries {
    Binaries(
        ["/usr/bin/git", "/bin/ls", "/bin/echo", "/bin/rm", "/usr/bin/curl"]
            .into_iter()
            .map(PathBuf::from)
            .collect(),
    )
}

struct NoParents;

impl ProfileSource for NoParents {
    fn read_profile(&self, _name: &ProfileName) -> Result<Vec<u8>, LookupError> {
        Err(LookupError::NotFound)
    }
}

fn context() -> (PathContext, FakeFs) {
    let mut fs = FakeFs::new();
    fs.add("/Users/u/app").add("/tmp").add("/bin/bash");
    let context = PathContext {
        home: PathBuf::from("/Users/u"),
        tmpdir: PathBuf::from("/tmp"),
        start_dir: PathBuf::from("/Users/u/app"),
    };
    (context, fs)
}

/// `git status` and `ls` allowed, `git push` asked, `rm` denied, anything else asked.
fn profile() -> Profile {
    let (context, fs) = context();
    let text = "name = \"web\"\n[exec]\nallow = [\"git status\", \"ls\", \"echo\"]\nask = [\"git push\"]\n\
                deny = [\"rm\"]\n";
    load_profile_text(text.as_bytes(), &NoParents, &context, &fs).unwrap()
}

fn unattended() -> Profile {
    let (context, fs) = context();
    load_unattended(&context, &fs).unwrap()
}

/// What happened, in order.
#[derive(Default)]
struct Journal(RefCell<Vec<String>>);

impl Journal {
    fn push(&self, entry: String) {
        self.0.borrow_mut().push(entry);
    }

    fn entries(&self) -> Vec<String> {
        self.0.borrow().clone()
    }
}

/// An observer writing `proposed <line>` (and `from <line>` after a rewrite) to the journal.
struct Events<'a>(&'a Journal);

impl Observer for Events<'_> {
    fn proposed(&self, proposal: &Proposal<'_>) {
        let entry = match proposal.rewritten_from {
            Some(from) => format!("proposed {} from {}", proposal.command.expose(), from.expose()),
            None => format!("proposed {}", proposal.command.expose()),
        };
        self.0.push(entry);
    }
}

/// Hooks answering each pass from a script, in order; `allow` once the script runs out. `None` panics.
struct ScriptedHooks<'a> {
    journal: &'a Journal,
    script: RefCell<Vec<Option<HookVerdict>>>,
    /// Whether each answer lists one hook run, `guard`, taking 5 ms.
    report_runs: bool,
}

impl Hooks for ScriptedHooks<'_> {
    fn run(&self, proposal: &Proposal<'_>) -> HookOutcome {
        self.journal.push(format!("hooks {}", proposal.command.expose()));
        let mut script = self.script.borrow_mut();
        let next = if script.is_empty() {
            Some(HookVerdict::Allow)
        } else {
            script.remove(0)
        };
        let Some(verdict) = next else {
            panic!("hook runner bug");
        };
        let hook = (verdict != HookVerdict::Allow).then(|| "guard".to_owned());
        let result = match &verdict {
            HookVerdict::Allow => HookResult::Allow,
            HookVerdict::Ask => HookResult::Ask,
            HookVerdict::Deny { .. } => HookResult::Deny,
            HookVerdict::Rewrite { .. } => HookResult::Rewrite,
            HookVerdict::Failed => HookResult::Error,
        };
        let runs = if self.report_runs {
            vec![HookRun {
                hook: "guard".to_owned(),
                result,
                duration_ms: 5,
                labels: Vec::new(),
            }]
        } else {
            Vec::new()
        };
        HookOutcome { verdict, hook, runs }
    }
}

/// An asker (authority or local approvals) answering from a script; `None` panics.
struct ScriptedAsker<'a> {
    name: &'static str,
    journal: &'a Journal,
    connected: bool,
    script: RefCell<Vec<Option<AskReply>>>,
}

impl ScriptedAsker<'_> {
    fn answer(&self, request: &AskRequest<'_>) -> AskAnswer {
        self.journal.push(format!(
            "ask {} {} rule={}",
            self.name,
            request.proposal.command.expose(),
            request.rule_id.unwrap_or("-")
        ));
        let reply = self.script.borrow_mut().remove(0);
        let Some(reply) = reply else {
            panic!("authority bug");
        };
        AskAnswer {
            request_id: Some(RequestId::from_ulid(Ulid::from_u128(9))),
            reply,
            decided_by: Some(self.name.to_owned()),
        }
    }
}

impl Authority for ScriptedAsker<'_> {
    fn connected(&self) -> bool {
        self.connected
    }

    fn ask(&self, request: &AskRequest<'_>, _caller: &dyn Caller) -> AskAnswer {
        self.answer(request)
    }
}

impl LocalApprovals for ScriptedAsker<'_> {
    fn ask(&self, request: &AskRequest<'_>, _caller: &dyn Caller) -> AskAnswer {
        self.answer(request)
    }
}

/// A caller that goes away after `checks` liveness checks.
struct LeavingCaller {
    checks: Cell<usize>,
}

impl Caller for LeavingCaller {
    fn gone(&self) -> bool {
        let left = self.checks.get();
        self.checks.set(left.saturating_sub(1));
        left == 0
    }
}

/// One pipeline set-up: scripts for hooks, the authority (connected or not) and local approvals.
struct Harness {
    journal: Journal,
    hooks: Vec<Option<HookVerdict>>,
    authority: Option<Vec<Option<AskReply>>>,
    approvals: Vec<Option<AskReply>>,
    caller_checks: usize,
    profile: Profile,
    limited: Vec<LineKey>,
    report_runs: bool,
}

/// Rate limits that limit exactly the listed lines, in any session.
struct Limited<'a>(&'a [LineKey]);

impl RateLimits for Limited<'_> {
    fn limited(&self, _session_id: SessionId, line: LineKey) -> bool {
        self.0.contains(&line)
    }
}

impl Harness {
    fn new() -> Self {
        Self {
            journal: Journal::default(),
            hooks: Vec::new(),
            authority: None,
            approvals: Vec::new(),
            caller_checks: usize::MAX,
            profile: profile(),
            limited: Vec::new(),
            report_runs: false,
        }
    }

    fn report_runs(mut self) -> Self {
        self.report_runs = true;
        self
    }

    fn hooks(mut self, script: Vec<Option<HookVerdict>>) -> Self {
        self.hooks = script;
        self
    }

    fn authority(mut self, script: Vec<Option<AskReply>>) -> Self {
        self.authority = Some(script);
        self
    }

    fn approvals(mut self, script: Vec<Option<AskReply>>) -> Self {
        self.approvals = script;
        self
    }

    fn caller_leaves_after(mut self, checks: usize) -> Self {
        self.caller_checks = checks;
        self
    }

    fn limited(mut self, lines: &[&str]) -> Self {
        self.limited = lines.iter().map(|line| LineKey::of(line)).collect();
        self
    }

    fn profile(mut self, profile: Profile) -> Self {
        self.profile = profile;
        self
    }

    fn decide(&self, line: &str) -> Outcome {
        let actor = Actor::Agent(AgentId::new("claude-code").unwrap());
        let cwd = CanonicalPath::new("/Users/u/app").unwrap();
        let input = LineInput {
            session_id: SessionId::from_ulid(Ulid::from_u128(1)),
            actor: &actor,
            profile: &self.profile,
            grants: None,
            command: line,
            cwd: &cwd,
            env_path: "/usr/bin:/bin",
        };
        let hooks = ScriptedHooks {
            journal: &self.journal,
            script: RefCell::new(self.hooks.clone()),
            report_runs: self.report_runs,
        };
        let authority = ScriptedAsker {
            name: "authority",
            journal: &self.journal,
            connected: self.authority.is_some(),
            script: RefCell::new(self.authority.clone().unwrap_or_default()),
        };
        let approvals = ScriptedAsker {
            name: "user",
            journal: &self.journal,
            connected: false,
            script: RefCell::new(self.approvals.clone()),
        };
        let caller = LeavingCaller {
            checks: Cell::new(self.caller_checks),
        };
        let effects = Effects {
            lookup: &binaries(),
            observer: &Events(&self.journal),
            hooks: &hooks,
            authority: &authority,
            approvals: &approvals,
            caller: &caller,
            limits: &Limited(&self.limited),
        };
        decide(&input, &effects)
    }
}

fn allowed(outcome: Outcome) -> Allowed {
    match outcome {
        Outcome::Run(allowed) => *allowed,
        Outcome::Refused(refusal) => panic!("refused: {refusal:?}"),
    }
}

fn refused(outcome: Outcome) -> Refusal {
    match outcome {
        Outcome::Refused(refusal) => *refusal,
        Outcome::Run(allowed) => panic!("allowed: {allowed:?}"),
    }
}

fn decision(verdict: DecisionVerdict, source: DecisionSource, rule_id: Option<&str>, by: Option<&str>) -> Decision {
    Decision {
        verdict,
        source,
        rule_id: rule_id.map(str::to_owned),
        decided_by: by.map(str::to_owned),
        hooks: Vec::new(),
    }
}

// FR-LC-09, FR-LC-13: only a final allow yields a line to run, and it is re-serialised with absolute paths.
#[test]
fn never_spawns_before_final_allow() {
    let harness = Harness::new();
    let run = allowed(harness.decide("git status && ls"));
    assert_eq!(run.executed, "/usr/bin/git status && /bin/ls");
    assert_eq!(run.command, "git status && ls");
    assert_eq!(
        run.decision,
        decision(
            DecisionVerdict::Allow,
            DecisionSource::Rule,
            Some("exec.allow[0]"),
            None
        )
    );
    assert_eq!(run.profile.profile.as_str(), "web");
    assert!(!run.profile.approved);
    // Asked and not answered yes, denied: no line to run.
    for reply in [
        AskReply::Deny { reason: None },
        AskReply::TimedOut,
        AskReply::Failed,
        AskReply::CallerGone,
    ] {
        let outcome = Harness::new().authority(vec![Some(reply.clone())]).decide("git push");
        assert!(matches!(outcome, Outcome::Refused(_)), "{reply:?}");
    }
}

// FR-LC-07: `command.proposed` precedes the hooks of its pass.
#[test]
fn emits_command_proposed_before_hooks() {
    let harness = Harness::new();
    allowed(harness.decide("ls"));
    assert_eq!(harness.journal.entries(), ["proposed ls", "hooks ls"]);
}

// FR-POL-18: one denied part denies the whole line, whatever the others say; the denying rule is named.
#[test]
fn denies_whole_line_when_any_part_denied() {
    for line in ["ls && rm -rf build", "rm x; git status", "echo hi | rm -i y"] {
        let harness = Harness::new().authority(vec![]);
        let refusal = refused(harness.decide(line));
        assert_eq!(
            refusal.decision,
            decision(DecisionVerdict::Deny, DecisionSource::Rule, Some("exec.deny[0]"), None),
            "{line}"
        );
        assert_eq!(refusal.kind, RefusalKind::Denied);
        assert!(
            !harness.journal.entries().iter().any(|entry| entry.starts_with("ask")),
            "a deny is never asked about"
        );
    }
}

// FR-POL-18: one asking part asks about the whole line, once, naming the asking rule.
#[test]
fn asks_whole_line_when_any_part_asks() {
    let harness = Harness::new().authority(vec![Some(AskReply::Allow)]);
    let run = allowed(harness.decide("git status && git push origin main"));
    assert_eq!(
        harness.journal.entries().last().unwrap(),
        "ask authority git status && git push origin main rule=exec.ask[0]"
    );
    assert_eq!(
        run.decision,
        decision(
            DecisionVerdict::Allow,
            DecisionSource::Authority,
            Some("exec.ask[0]"),
            Some("authority")
        )
    );
    assert!(run.profile.approved);
    assert_eq!(run.executed, "/usr/bin/git status && /usr/bin/git push origin main");
}

// FR-HOOK-12: a hook's ask escalates a line the rules allow; the strictest verdict wins.
#[test]
fn hook_ask_escalates_an_allowed_line() {
    let harness = Harness::new()
        .hooks(vec![Some(HookVerdict::Ask)])
        .authority(vec![Some(AskReply::Deny {
            reason: Some("no".to_owned()),
        })]);
    let refusal = refused(harness.decide("ls"));
    assert_eq!(
        refusal.decision,
        decision(
            DecisionVerdict::Deny,
            DecisionSource::Authority,
            None,
            Some("authority")
        )
    );
    assert_eq!(refusal.reason.as_deref(), Some("no"));
}

// FR-LC-10, NFR-REL-09: without an authority, an ask goes to local approval: the user's yes allows (source
// `user`), the timeout denies (source `standalone`, -32002).
#[test]
fn ask_without_authority_goes_to_standalone_handling() {
    let harness = Harness::new().approvals(vec![Some(AskReply::Allow)]);
    let run = allowed(harness.decide("git push"));
    assert_eq!(run.decision.source, DecisionSource::User);
    assert!(harness.journal.entries().last().unwrap().starts_with("ask user"));

    let refusal = refused(
        Harness::new()
            .approvals(vec![Some(AskReply::TimedOut)])
            .decide("git push"),
    );
    assert_eq!(
        refusal.decision,
        decision(
            DecisionVerdict::Deny,
            DecisionSource::Standalone,
            Some("exec.ask[0]"),
            None
        )
    );
    assert_eq!(
        refusal.kind,
        RefusalKind::TimedOut {
            request_id: Some(RequestId::from_ulid(Ulid::from_u128(9)))
        }
    );
}

// FR-AGT-21: under `unattended`, nobody is asked; a hook's ask is denied by standalone rules too.
#[test]
fn unattended_never_asks() {
    let harness = Harness::new()
        .profile(unattended())
        .hooks(vec![Some(HookVerdict::Ask)])
        .authority(vec![]);
    let refusal = refused(harness.decide("ls"));
    assert_eq!(refusal.decision.source, DecisionSource::Standalone);
    assert!(!harness.journal.entries().iter().any(|entry| entry.starts_with("ask")));
}

// FR-LC-11, FR-AUTH-30, FR-HOOK-11: a rewrite runs steps 2 to 5 once more, on the new line, which is what runs; the
// record keeps the original.
#[test]
fn reevaluates_rewritten_line_once() {
    let harness = Harness::new().authority(vec![Some(AskReply::Rewrite {
        command: "git status".to_owned(),
    })]);
    let run = allowed(harness.decide("git push --force"));
    assert_eq!(
        harness.journal.entries(),
        [
            "proposed git push --force",
            "hooks git push --force",
            "ask authority git push --force rule=exec.ask[0]",
            "proposed git status from git push --force",
            "hooks git status",
        ]
    );
    assert_eq!(run.command, "git status");
    assert_eq!(run.rewritten_from.as_deref(), Some("git push --force"));
    assert_eq!(run.executed, "/usr/bin/git status");
    // The rewritten line is decided by its own rule; the verdict says a rewrite was applied.
    assert_eq!(
        run.decision,
        decision(
            DecisionVerdict::Rewrite,
            DecisionSource::Rule,
            Some("exec.allow[0]"),
            None
        )
    );

    // A hook's rewrite is evaluated by policy on the new line (FR-HOOK-11): here, denied.
    let harness = Harness::new().hooks(vec![Some(HookVerdict::Rewrite {
        command: "rm -rf /".to_owned(),
    })]);
    let refusal = refused(harness.decide("ls"));
    assert_eq!(refusal.command, "rm -rf /");
    assert_eq!(refusal.rewritten_from.as_deref(), Some("ls"));
    assert_eq!(refusal.decision.rule_id.as_deref(), Some("exec.deny[0]"));
}

// FR-HOOK-05 (KNSH-062): the decision lists every hook run of every pass, whichever way it went, for the record.
#[test]
fn decision_lists_hook_runs_of_every_pass() {
    let rewrite = Some(HookVerdict::Rewrite {
        command: "ls -a".to_owned(),
    });
    let outcome = Harness::new()
        .report_runs()
        .hooks(vec![rewrite, Some(HookVerdict::Allow)])
        .decide("ls");
    let results: Vec<_> = outcome.decision().hooks.iter().map(|run| run.result).collect();
    assert_eq!(results, [HookResult::Rewrite, HookResult::Allow]);
    let record = outcome.decision().to_record(9);
    assert_eq!(record.hooks.len(), 2);
    assert_eq!(record.hooks[0].duration_ms, 5);

    let refusal = refused(
        Harness::new()
            .report_runs()
            .hooks(vec![Some(HookVerdict::Failed)])
            .decide("ls"),
    );
    assert_eq!(refusal.decision.hooks[0].result, HookResult::Error);

    // A rate-limited line runs no hooks, so it lists none.
    let refusal = refused(Harness::new().report_runs().limited(&["/bin/ls"]).decide("ls"));
    assert_eq!(refusal.decision.hooks.len(), 0);
}

// FR-AUTH-31: a second rewrite, by a hook or the authority, denies the line.
#[test]
fn denies_on_second_rewrite() {
    let rewrite = |command: &str| AskReply::Rewrite {
        command: command.to_owned(),
    };
    let harness = Harness::new().authority(vec![Some(rewrite("git push origin")), Some(rewrite("git status"))]);
    let refusal = refused(harness.decide("git push --force"));
    assert_eq!(
        refusal.decision,
        decision(
            DecisionVerdict::Deny,
            DecisionSource::Authority,
            None,
            Some("authority")
        )
    );
    assert_eq!(refusal.command, "git push origin");
    assert_eq!(refusal.rewritten_from.as_deref(), Some("git push --force"));

    let harness = Harness::new().hooks(vec![
        Some(HookVerdict::Rewrite {
            command: "echo one".to_owned(),
        }),
        Some(HookVerdict::Rewrite {
            command: "echo two".to_owned(),
        }),
    ]);
    let refusal = refused(harness.decide("ls"));
    assert_eq!(refusal.decision.source, DecisionSource::Hook);
    assert_eq!(refusal.decision.decided_by.as_deref(), Some("guard"));
}

// FR-AUTH-32: a rewrite carrying a redaction marker is refused; so is one the API could not have sent.
#[test]
fn refuses_rewrites_it_cannot_trust() {
    for command in [
        format!("curl -H 'token: {REDACTED_MARKER}' x"),
        "ls\0".to_owned(),
        "l".repeat(MAX_LINE_LEN + 1),
    ] {
        let harness = Harness::new().authority(vec![Some(AskReply::Rewrite { command })]);
        let refusal = refused(harness.decide("git push"));
        assert_eq!(refusal.decision.verdict, DecisionVerdict::Deny);
        assert_eq!(refusal.command, "git push");
        assert_eq!(refusal.rewritten_from, None);
    }
}

// NFR-REL-07, FR-HOOK-04: every failure in any step is a deny, never a run, panics included.
#[test]
fn denies_on_internal_error_in_any_step() {
    let cases: Vec<(&str, Harness)> = vec![
        ("hook failed", Harness::new().hooks(vec![Some(HookVerdict::Failed)])),
        ("hook panicked", Harness::new().hooks(vec![None])),
        ("ask failed", Harness::new().authority(vec![Some(AskReply::Failed)])),
        ("authority panicked", Harness::new().authority(vec![None])),
        ("approvals panicked", Harness::new().approvals(vec![None])),
    ];
    for (case, harness) in cases {
        let line = if case.starts_with("hook") { "ls" } else { "git push" };
        let refusal = refused(harness.decide(line));
        assert_eq!(refusal.decision.verdict, DecisionVerdict::Deny, "{case}");
        assert_eq!(refusal.kind, RefusalKind::Denied, "{case}");
        assert!(refusal.reason.is_some(), "{case}");
    }
    // A hook failure is attributed to the hook.
    let refusal = refused(Harness::new().hooks(vec![Some(HookVerdict::Failed)]).decide("ls"));
    assert_eq!(refusal.decision.source, DecisionSource::Hook);
    assert_eq!(refusal.decision.decided_by.as_deref(), Some("guard"));
    // A line that cannot be re-serialised (a function shadowing a resolved path) is denied after being allowed.
    let refusal = refused(Harness::new().decide("/bin/ls() { :; }; ls"));
    assert_eq!(refusal.decision.verdict, DecisionVerdict::Deny);
}

// FR-LC-41: a caller that leaves while the decision is pending cancels it; nothing runs.
#[test]
fn cancels_and_skips_spawn_when_caller_disconnects() {
    // Gone during the hooks: no request was made.
    let harness = Harness::new().caller_leaves_after(0).authority(vec![]);
    let refusal = refused(harness.decide("git push"));
    assert_eq!(refusal.kind, RefusalKind::Cancelled { request_id: None });
    assert!(!harness.journal.entries().iter().any(|entry| entry.starts_with("ask")));
    // Gone while waiting for the authority: the request is named, even though an allow arrived.
    let harness = Harness::new()
        .caller_leaves_after(1)
        .authority(vec![Some(AskReply::Allow)]);
    let refusal = refused(harness.decide("git push"));
    assert_eq!(
        refusal.kind,
        RefusalKind::Cancelled {
            request_id: Some(RequestId::from_ulid(Ulid::from_u128(9)))
        }
    );
    // The asker itself saw the caller go.
    let refusal = refused(
        Harness::new()
            .authority(vec![Some(AskReply::CallerGone)])
            .decide("git push"),
    );
    assert!(matches!(refusal.kind, RefusalKind::Cancelled { .. }));
}

// Record model: the source and decider name the component that made the final decision.
#[test]
fn decision_source_matches_deciding_component() {
    let cases: Vec<(Harness, &str, DecisionSource, Option<&str>)> = vec![
        (Harness::new(), "ls", DecisionSource::Rule, None),
        (
            Harness::new().hooks(vec![Some(HookVerdict::Deny { reason: None })]),
            "ls",
            DecisionSource::Hook,
            Some("guard"),
        ),
        (
            Harness::new().authority(vec![Some(AskReply::Allow)]),
            "git push",
            DecisionSource::Authority,
            Some("authority"),
        ),
        (
            Harness::new().approvals(vec![Some(AskReply::Deny { reason: None })]),
            "git push",
            DecisionSource::User,
            Some("user"),
        ),
        (
            Harness::new().approvals(vec![Some(AskReply::TimedOut)]),
            "git push",
            DecisionSource::Standalone,
            None,
        ),
        (
            Harness::new().profile(unattended()),
            "git push",
            DecisionSource::Standalone,
            None,
        ),
    ];
    for (harness, line, source, by) in cases {
        let outcome = harness.decide(line);
        assert_eq!(outcome.decision().source, source, "{line}");
        assert_eq!(outcome.decision().decided_by.as_deref(), by, "{line}");
        let record = outcome.decision().to_record(7);
        assert_eq!(
            (
                record.verdict,
                record.source,
                record.rule_id.clone(),
                record.decided_by.clone()
            ),
            (
                outcome.decision().verdict,
                outcome.decision().source,
                outcome.decision().rule_id.clone(),
                outcome.decision().decided_by.clone()
            )
        );
        assert_eq!(record.latency_ms, 7);
    }
}

// FR-HOOK-20: a limited line is denied with source `rate_limit` before anything is published, any hook runs or anyone
// is asked; the key is the line with absolute paths, so `git push` reached through `PATH` is the limited
// `/usr/bin/git push`.
#[test]
fn denies_limited_line_without_hooks_or_asks() {
    let harness = Harness::new()
        .hooks(vec![Some(HookVerdict::Ask)])
        .authority(vec![Some(AskReply::Allow)])
        .limited(&["/usr/bin/git push"]);
    let refusal = refused(harness.decide("git push"));
    assert_eq!(
        refusal.decision,
        decision(DecisionVerdict::Deny, DecisionSource::RateLimit, None, None)
    );
    assert_eq!(refusal.kind, RefusalKind::Denied);
    assert_eq!(refusal.line_key, Some(LineKey::of("/usr/bin/git push")));
    assert!(refusal.reason.is_some());
    assert!(refusal.classification.is_some());
    assert_eq!(harness.journal.entries(), Vec::<String>::new());
    // Another line is decided as usual.
    allowed(harness.decide("git status"));
}

// FR-HOOK-20: every refusal after the parse carries its line's key, so the driver can count it.
#[test]
fn refusals_carry_the_normalised_line_key() {
    let harness = Harness::new().authority(vec![Some(AskReply::Deny { reason: None })]);
    let refusal = refused(harness.decide("  git push "));
    assert_eq!(refusal.decision.source, DecisionSource::Authority);
    assert_eq!(refusal.line_key, Some(LineKey::of("/usr/bin/git push")));
}
