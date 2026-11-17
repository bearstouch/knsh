//! The decision pipeline with fake hooks, authority, approvals, observer and caller (KNSH-050).

use std::cell::{Cell, RefCell};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use super::*;
use crate::hook::{Ended, Execution, HookConfig, HookExecutor, HookExit, HookSpec, parse_hooks, run_hooks};
use crate::policy::paths::testing::FakeFs;
use crate::policy::{LookupError, PathContext, ProfileSource, load_profile_text, load_unattended};
use crate::record::HookResult;
use crate::redacted::REDACTED_MARKER;
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
        // The asking hook is journalled only when one is named, so the asks of hook-less tests read as before.
        let hook = request.hook.map(|hook| format!(" hook={hook}")).unwrap_or_default();
        // The line a rewritten line replaced, as the asker sees it (FR-AUTH-30); only after a rewrite.
        let from = request
            .proposal
            .rewritten_from
            .map(|from| format!(" from {}", from.expose()))
            .unwrap_or_default();
        self.journal.push(format!(
            "ask {} {} rule={}{hook}{from}",
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
        let hooks = ScriptedHooks {
            journal: &self.journal,
            script: RefCell::new(self.hooks.clone()),
            report_runs: self.report_runs,
        };
        self.decide_with(line, &hooks)
    }

    /// Decides `line` with `hooks` in place of the scripted ones.
    fn decide_with(&self, line: &str, hooks: &dyn Hooks) -> Outcome {
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
            hooks,
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

// FR-AUTH-30 (KNSH-070): the authority's rewrite is parsed and evaluated once more (steps 2 to 5) on the new line,
// which is what runs; the authority is not asked again about a line the rules allow.
#[test]
fn reevaluates_authority_rewrite_once() {
    let harness = Harness::new().authority(vec![Some(AskReply::Rewrite {
        command: "ls -a".to_owned(),
    })]);
    let run = allowed(harness.decide("git push"));
    assert_eq!(
        harness.journal.entries(),
        [
            "proposed git push",
            "hooks git push",
            "ask authority git push rule=exec.ask[0]",
            "proposed ls -a from git push",
            "hooks ls -a",
        ],
        "one more pass, and one only"
    );
    assert_eq!(run.command, "ls -a");
    assert_eq!(run.rewritten_from.as_deref(), Some("git push"));
    assert_eq!(run.executed, "/bin/ls -a");
    assert_eq!(run.decision.verdict, DecisionVerdict::Rewrite);
    assert_eq!(run.decision.rule_id.as_deref(), Some("exec.allow[1]"));
    // The rewritten line was allowed by a rule, not approved: it gets no approval hosts (KNSH-060).
    assert!(!run.profile.approved);

    // Policy decides the new line on its own: a rewrite into a denied line is denied by its rule, not run.
    let harness = Harness::new().authority(vec![Some(AskReply::Rewrite {
        command: "rm -rf build".to_owned(),
    })]);
    let refusal = refused(harness.decide("git push"));
    assert_eq!(refusal.decision.source, DecisionSource::Rule);
    assert_eq!(refusal.decision.rule_id.as_deref(), Some("exec.deny[0]"));
    assert_eq!(refusal.command, "rm -rf build");
    assert_eq!(refusal.rewritten_from.as_deref(), Some("git push"));
}

// FR-AUTH-30 (KNSH-070): a rewritten line that asks again reaches the authority with `rewritten_from`, the line it
// replaced, and the authority's answer to that second ask decides it.
#[test]
fn second_ask_carries_rewritten_from() {
    let harness = Harness::new().authority(vec![
        Some(AskReply::Rewrite {
            command: "git push --dry-run".to_owned(),
        }),
        Some(AskReply::Allow),
    ]);
    let run = allowed(harness.decide("git push --force"));
    let asks: Vec<_> = harness
        .journal
        .entries()
        .into_iter()
        .filter(|entry| entry.starts_with("ask"))
        .collect();
    assert_eq!(
        asks,
        [
            "ask authority git push --force rule=exec.ask[0]",
            "ask authority git push --dry-run rule=exec.ask[0] from git push --force",
        ]
    );
    assert_eq!(run.command, "git push --dry-run");
    assert_eq!(run.rewritten_from.as_deref(), Some("git push --force"));
    assert_eq!(
        run.decision,
        decision(
            DecisionVerdict::Rewrite,
            DecisionSource::Authority,
            Some("exec.ask[0]"),
            Some("authority")
        )
    );
    assert!(run.profile.approved, "the second ask approved the rewritten line");

    // Without an authority, local approvals see the same `rewritten_from` (a hook's rewrite, then a rule's ask).
    let harness = Harness::new()
        .hooks(vec![Some(HookVerdict::Rewrite {
            command: "git push".to_owned(),
        })])
        .approvals(vec![Some(AskReply::Deny { reason: None })]);
    refused(harness.decide("git push --force"));
    assert!(
        harness
            .journal
            .entries()
            .contains(&"ask user git push rule=exec.ask[0] from git push --force".to_owned())
    );
}

// FR-AUTH-31 (KNSH-070): a second rewrite is refused and the line denied, whoever sends it, in either order. Nothing
// runs, and the refused line is the first rewrite's, recorded with the received line as `rewritten_from`.
#[test]
fn refuses_second_rewrite() {
    let rewrite_reply = |command: &str| {
        Some(AskReply::Rewrite {
            command: command.to_owned(),
        })
    };
    let rewrite_hook = |command: &str| {
        Some(HookVerdict::Rewrite {
            command: command.to_owned(),
        })
    };
    let cases = [
        // The authority rewrites, then rewrites its own rewrite again.
        (
            Harness::new().authority(vec![rewrite_reply("git push origin"), rewrite_reply("ls")]),
            DecisionSource::Authority,
            "git push origin",
        ),
        // A hook rewrites, then the authority rewrites the hook's line.
        (
            Harness::new()
                .hooks(vec![rewrite_hook("git push origin")])
                .authority(vec![rewrite_reply("ls")]),
            DecisionSource::Authority,
            "git push origin",
        ),
        // The authority rewrites, then a hook rewrites the authority's line.
        (
            Harness::new()
                .hooks(vec![Some(HookVerdict::Allow), rewrite_hook("ls")])
                .authority(vec![rewrite_reply("echo hi")]),
            DecisionSource::Hook,
            "echo hi",
        ),
    ];
    for (harness, source, refused_line) in cases {
        let refusal = refused(harness.decide("git push --force"));
        assert_eq!(refusal.decision.verdict, DecisionVerdict::Deny);
        assert_eq!(refusal.decision.source, source);
        assert_eq!(refusal.kind, RefusalKind::Denied);
        assert_eq!(refusal.reason.as_deref(), Some(SECOND_REWRITE));
        assert_eq!(refusal.command, refused_line);
        assert_eq!(refusal.rewritten_from.as_deref(), Some("git push --force"));
        // The second rewrite's line is never proposed, evaluated or asked about.
        assert!(
            !harness.journal.entries().iter().any(|entry| entry.contains(" ls")),
            "{:?}",
            harness.journal.entries()
        );
    }
}

// FR-AUTH-32 (KNSH-070): a line holding a redaction marker, plain or named (`«redacted:<name>»`, FR-SEC-10), cannot
// be rewritten, and a rewrite carrying one is refused: the marker stands for a value the rewriter never saw.
#[test]
fn refuses_rewrite_of_line_with_redaction_marker() {
    let named = "«redacted:npm-token»";
    // The received line holds the marker: the authority's (or a hook's) rewrite of it is refused.
    for (harness, source) in [
        (
            Harness::new().authority(vec![Some(AskReply::Rewrite {
                command: "git push origin".to_owned(),
            })]),
            DecisionSource::Authority,
        ),
        (
            Harness::new().hooks(vec![Some(HookVerdict::Rewrite {
                command: "git push origin".to_owned(),
            })]),
            DecisionSource::Hook,
        ),
    ] {
        for marker in [named, REDACTED_MARKER] {
            let line = format!("git push https://{marker}@example.com");
            let refusal = refused(harness.decide(&line));
            assert_eq!(refusal.decision.verdict, DecisionVerdict::Deny);
            assert_eq!(refusal.decision.source, source);
            assert_eq!(refusal.reason.as_deref(), Some(REWRITE_OF_REDACTED));
            assert_eq!(refusal.command, line, "refused as received");
            assert_eq!(refusal.rewritten_from, None, "no rewrite was applied");
        }
    }
    // The rewrite itself carries a named marker.
    let harness = Harness::new().authority(vec![Some(AskReply::Rewrite {
        command: format!("npm publish --token {named}"),
    })]);
    let refusal = refused(harness.decide("git push"));
    assert_eq!(refusal.reason.as_deref(), Some(REWRITE_OF_REDACTED));
    assert_eq!(refusal.command, "git push");
    assert!(!harness.journal.entries().iter().any(|entry| entry.contains("npm")));

    // Without a rewrite, a line holding a marker is decided like any other.
    let harness = Harness::new().authority(vec![Some(AskReply::Allow)]);
    allowed(harness.decide(&format!("git push https://{named}@example.com")));
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

// ---- Combining verdicts and the rewrite chain (KNSH-063) ----

/// Hook processes that answer from a function of their file name and the line they are given, recording both.
struct LineExecutor {
    /// `(hook file name, line)` for every run, in order.
    seen: RefCell<Vec<(String, String)>>,
    answer: fn(&str, &str) -> &'static str,
}

impl HookExecutor for LineExecutor {
    fn execute(&self, hook: &HookSpec, input: &[u8]) -> Execution {
        let name = hook.program.file_name().unwrap().to_str().unwrap().to_owned();
        let line = String::from_utf8(input.to_vec()).unwrap();
        let stdout = (self.answer)(&name, &line).as_bytes().to_vec();
        self.seen.borrow_mut().push((name, line));
        Execution {
            ended: Ended::Finished {
                stdout,
                exit: HookExit::Exited(0),
            },
            duration: std::time::Duration::from_millis(1),
        }
    }
}

/// The real chain ([`run_hooks`]) over `config`, each hook given the pass's line as its input.
struct Chain<'a> {
    config: HookConfig,
    executor: &'a LineExecutor,
}

impl Hooks for Chain<'_> {
    fn run(&self, proposal: &Proposal<'_>) -> HookOutcome {
        let input = proposal.command.expose().as_bytes();
        run_hooks(&self.config, proposal, Some(input), self.executor)
    }
}

/// Hooks `first`, `rewriter` and `last`, declared in that order.
fn three_hooks() -> HookConfig {
    let text = ["first", "rewriter", "last"]
        .iter()
        .map(|name| {
            format!(
                "[[hooks]]\nevent = \"command.proposed\"\nrun = \"~/.config/knsh/hooks/{name}\"\ntimeout_ms = 100\n"
            )
        })
        .collect::<Vec<_>>()
        .concat();
    parse_hooks(&knsh_toml::parse(text.as_bytes()).unwrap(), Path::new("/Users/u"))
}

// FR-HOOK-10: a rewrite replaces the line for the hooks after the rewriting one: they never see the old line, and in
// the new line's pass every hook judges the new line.
#[test]
fn later_hooks_see_rewritten_line() {
    let executor = LineExecutor {
        seen: RefCell::new(Vec::new()),
        answer: |hook, line| match (hook, line) {
            ("rewriter", "rm -rf build") => r#"{"verdict":"rewrite","command":"ls build"}"#,
            _ => r#"{"verdict":"allow"}"#,
        },
    };
    let chain = Chain {
        config: three_hooks(),
        executor: &executor,
    };
    let harness = Harness::new();
    let run = allowed(harness.decide_with("rm -rf build", &chain));

    let seen: Vec<_> = executor
        .seen
        .borrow()
        .iter()
        .map(|(hook, line)| format!("{hook}: {line}"))
        .collect();
    assert_eq!(
        seen,
        [
            "first: rm -rf build",
            "rewriter: rm -rf build",
            // The rewrite ended the first pass: `last` never saw the old line.
            "first: ls build",
            "rewriter: ls build",
            "last: ls build",
        ]
    );
    assert_eq!(run.command, "ls build");
    assert_eq!(run.rewritten_from.as_deref(), Some("rm -rf build"));
    assert_eq!(run.executed, "/bin/ls build");
    assert_eq!(run.decision.verdict, DecisionVerdict::Rewrite);
    let results: Vec<_> = run.decision.hooks.iter().map(|run| run.result).collect();
    assert_eq!(
        results,
        [
            HookResult::Allow,
            HookResult::Rewrite,
            HookResult::Allow,
            HookResult::Allow,
            HookResult::Allow
        ]
    );
}

// FR-HOOK-11: policy judges the rewritten line, never the received one: a denied line rewritten to an allowed one
// runs, and an allowed line rewritten to one that asks is asked about as rewritten.
#[test]
fn policy_evaluates_rewritten_line() {
    let rewrite = |command: &str| {
        Some(HookVerdict::Rewrite {
            command: command.to_owned(),
        })
    };

    // `rm` is denied by the rules, but only `ls` is evaluated.
    let harness = Harness::new().hooks(vec![rewrite("ls")]);
    let run = allowed(harness.decide("rm -rf build"));
    assert_eq!(
        run.decision,
        decision(
            DecisionVerdict::Rewrite,
            DecisionSource::Rule,
            Some("exec.allow[1]"),
            None
        )
    );
    assert_eq!(run.executed, "/bin/ls");

    // `ls` is allowed, but its rewrite asks, and the ask is about the rewritten line.
    let harness = Harness::new()
        .hooks(vec![rewrite("git push")])
        .authority(vec![Some(AskReply::Allow)]);
    let run = allowed(harness.decide("ls"));
    assert_eq!(
        harness.journal.entries(),
        [
            "proposed ls",
            "hooks ls",
            "proposed git push from ls",
            "hooks git push",
            "ask authority git push rule=exec.ask[0] from ls",
        ]
    );
    assert_eq!(run.decision.rule_id.as_deref(), Some("exec.ask[0]"));
    assert_eq!(run.decision.verdict, DecisionVerdict::Rewrite);

    // `ls` is allowed, but its rewrite is denied by the rules.
    let refusal = refused(Harness::new().hooks(vec![rewrite("rm x")]).decide("ls"));
    assert_eq!(refusal.decision.rule_id.as_deref(), Some("exec.deny[0]"));
}

// FR-HOOK-12: the final verdict is the most restrictive of the hooks' and policy's: deny, then ask, then allow.
#[test]
fn final_verdict_is_most_restrictive() {
    assert_eq!(most_restrictive([]), Strictness::Allow);
    for (verdicts, expected) in [
        (vec![Strictness::Allow, Strictness::Allow], Strictness::Allow),
        (vec![Strictness::Allow, Strictness::Ask], Strictness::Ask),
        (vec![Strictness::Ask, Strictness::Allow], Strictness::Ask),
        (vec![Strictness::Ask, Strictness::Deny], Strictness::Deny),
        (
            vec![Strictness::Deny, Strictness::Allow, Strictness::Ask],
            Strictness::Deny,
        ),
    ] {
        assert_eq!(most_restrictive(verdicts.clone()), expected, "{verdicts:?}");
    }

    // Every hook verdict against every policy verdict, through the pipeline. An ask is answered `allow` by the
    // authority, so an asked line runs with source `authority` and an unasked one with source `rule`.
    let hook_verdicts = [
        (HookVerdict::Allow, Strictness::Allow),
        (HookVerdict::Ask, Strictness::Ask),
        (HookVerdict::Deny { reason: None }, Strictness::Deny),
    ];
    let lines = [
        ("ls", Strictness::Allow),
        ("git push", Strictness::Ask),
        ("rm x", Strictness::Deny),
    ];
    for (hook, hook_strictness) in &hook_verdicts {
        for (line, policy_strictness) in lines {
            let harness = Harness::new()
                .hooks(vec![Some(hook.clone())])
                .authority(vec![Some(AskReply::Allow)]);
            let outcome = harness.decide(line);
            let case = format!("hook {hook:?}, line {line}");
            let asks: Vec<_> = harness
                .journal
                .entries()
                .into_iter()
                .filter(|entry| entry.starts_with("ask"))
                .collect();
            match (*hook_strictness).max(policy_strictness) {
                Strictness::Deny => {
                    let refusal = refused(outcome);
                    assert!(asks.is_empty(), "{case}: a deny asks no one");
                    // The hook's deny comes first: policy never ran (FR-HOOK-11).
                    let source = if *hook_strictness == Strictness::Deny {
                        DecisionSource::Hook
                    } else {
                        DecisionSource::Rule
                    };
                    assert_eq!(refusal.decision.source, source, "{case}");
                }
                Strictness::Ask => {
                    let run = allowed(outcome);
                    assert_eq!(run.decision.source, DecisionSource::Authority, "{case}");
                    // The ask names the rule only when the rule asked, and the hook only when the hook asked.
                    let rule = if policy_strictness == Strictness::Ask {
                        "exec.ask[0]"
                    } else {
                        "-"
                    };
                    let hook = if *hook_strictness == Strictness::Ask {
                        " hook=guard"
                    } else {
                        ""
                    };
                    assert_eq!(asks, [format!("ask authority {line} rule={rule}{hook}")], "{case}");
                }
                Strictness::Allow => {
                    let run = allowed(outcome);
                    assert_eq!(run.decision.source, DecisionSource::Rule, "{case}");
                    assert!(asks.is_empty(), "{case}");
                }
            }
        }
    }
}

// FR-HOOK-13: a rewrite applies only when the final verdict is not deny. A rewritten line its own pass denies (by a
// hook, a failing hook, policy or the authority) never runs and is recorded as a deny, not a rewrite.
#[test]
fn rewrite_discarded_when_final_verdict_deny() {
    let rewrite = || {
        Some(HookVerdict::Rewrite {
            command: "echo hi".to_owned(),
        })
    };
    let deny = || AskReply::Deny { reason: None };

    for (case, harness, line) in [
        (
            "hook denies",
            Harness::new().hooks(vec![rewrite(), Some(HookVerdict::Deny { reason: None })]),
            "echo hi",
        ),
        (
            "hook fails",
            Harness::new().hooks(vec![rewrite(), Some(HookVerdict::Failed)]),
            "echo hi",
        ),
        (
            "policy denies",
            Harness::new().hooks(vec![Some(HookVerdict::Rewrite {
                command: "rm -rf build".to_owned(),
            })]),
            "rm -rf build",
        ),
        (
            "authority denies",
            Harness::new()
                .hooks(vec![rewrite(), Some(HookVerdict::Ask)])
                .authority(vec![Some(deny())]),
            "echo hi",
        ),
    ] {
        let refusal = refused(harness.decide("ls"));
        assert_eq!(refusal.decision.verdict, DecisionVerdict::Deny, "{case}");
        // The record explains the denial by the line it applied to, and keeps the received one.
        assert_eq!(refusal.command, line, "{case}");
        assert_eq!(refusal.rewritten_from.as_deref(), Some("ls"), "{case}");
    }

    // The same rewrite on a line its pass allows is applied.
    let run = allowed(Harness::new().hooks(vec![rewrite()]).decide("ls"));
    assert_eq!(run.decision.verdict, DecisionVerdict::Rewrite);
    assert_eq!(run.command, "echo hi");
    assert_eq!(run.rewritten_from.as_deref(), Some("ls"));
}
