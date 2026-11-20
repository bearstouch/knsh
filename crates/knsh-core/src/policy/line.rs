//! Line verdicts and dynamic-code limits (KNSH-041; FR-POL-18, FR-POL-20, FR-POL-21, FR-LC-09, FR-AGT-21).
//!
//! [`evaluate_line`] gives one decision for a whole classified line, before any of it runs (FR-LC-09): the verdict,
//! every rule that matched, and the capabilities the line may receive if it runs.
//!
//! # Verdict
//!
//! Every entry of the classification (each simple command, each wrapper and each command a wrapper runs, in source
//! order) is decided by [`evaluate_command`]. A dynamic part with no entry of its own (a line the parser could not
//! read, a construct kept whole such as `[[ … ]]`) is decided by `exec.default`, as the profile says (FR-POL-20). The
//! line is then denied if any part is denied, asked if any part asks, and allowed otherwise (FR-POL-18); the deciding
//! rule is the first part with that verdict. A line with no parts at all runs nothing and is allowed.
//!
//! # Capabilities
//!
//! What the line may receive when it runs ([`LineCapabilities`]): the hosts open to it, the approval hosts it may
//! reach once its classes or an approval allow (KNSH-060 decides each connection), the approval hosts its classes
//! alone open under `network.class_hosts` (FR-NET-03, KNSH-058), the loopback ports, the network classes it may
//! present to host rules, the secrets it is eligible for, and those secrets' hosts, to which the proxy narrows its
//! network (FR-SEC-03, FR-NET-10). A denied line receives nothing.
//!
//! # Secrets (KNSH-092)
//!
//! A command that certainly matches a `[secrets.env]` variable's `inject_for` would receive that secret (FR-SEC-01).
//! If the rules allow it, it asks instead, named [`RuleId::Secret`] (FR-SEC-02): the line runs with the secret only
//! once approved, or allowed by a grant covering that command. A line holding dynamic code receives no secret
//! (FR-SEC-04), so none of its commands asks for this reason.
//!
//! If **any** part of the line is dynamic, the whole line is clamped (FR-POL-20, FR-POL-21): network is limited to
//! `network.hosts` (and the loopback ports, which are open to every command alike), no approval hosts, no secrets and
//! no classes, even if the line is later approved. The proxy identifies a line, not a command within it, so one
//! dynamic part limits every part.
//!
//! A line's classes are those of its normalised commands (FR-LC-06), but only when every command that can open a
//! connection through the proxy has classes: a line such as `git fetch && curl …` presents none, or `curl` would reach
//! an approval host on the strength of `git fetch`. Builtins, function calls (whose bodies are entries of their own),
//! names not found and wrappers (whose commands are entries of their own) are skipped.
//!
//! # Grants
//!
//! [`evaluate_line_with_grants`] also applies the live grants of the line's session and profile (KNSH-042, the
//! [`grant`](super::grant) module): a line the rules ask about is allowed, with source [`DecisionSource::Grant`] and
//! [`LineDecision::grant`] naming the grant, when every part that asks is a command a grant covers. A grant never
//! changes a deny, and never changes the capabilities: they are computed from the classification alone, so dynamic
//! code stays clamped. The `unattended` step below runs after grants, so a granted line holding dynamic code is still
//! denied there.
//!
//! # `unattended`
//!
//! Under the built-in [`unattended`](super::unattended) profile no one can answer an ask (FR-AGT-21): an `ask` verdict
//! becomes `deny`, with source [`DecisionSource::Standalone`] and a reason naming the profile. So does an allowed line
//! holding dynamic code (named by the rule of its first dynamic part): an allowed tool given a code variable
//! (`GIT_EXTERNAL_DIFF=./x git diff`) runs any program, which is never a plain read-only command.
//!
//! # Fail closed
//!
//! The evaluation is pure and total. Should it still fail (a classification that breaks its own invariants, or a bug
//! that panics), the line is denied with source [`DecisionSource::Rule`] and [`LineReason::EvaluationFailed`]; nothing
//! of a failed evaluation is returned.

use std::fmt;
use std::panic::{self, AssertUnwindSafe};

use knsh_bash::{
    Classification, ClassifiedCommand, CommandClass, DynamicReason, NetworkClass, Normalisation, Program,
    SUBCOMMAND_TABLE, Span, normalise,
};

use super::grant::GrantSet;
use super::model::{NetworkMode, Profile, RuleAction};
use super::rules::{RuleId, evaluate_command, matches_certainly};
use super::unattended::UNATTENDED_PROFILE;
use crate::id::{GrantId, SessionId};
use crate::session::ProfileName;
use crate::time::Timestamp;

/// Who made a line's final decision: the record's `decision.source`
/// (`specs/05-models/execution-record.md#decision`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DecisionSource {
    /// The profile's rules (also every evaluation failure).
    Rule,
    /// A `pre_exec` hook.
    Hook,
    /// The connected authority.
    Authority,
    /// The user, with `knsh approve`.
    User,
    /// Standalone rules: no one could be asked (no authority connected, or the `unattended` profile).
    Standalone,
    /// Rate limiting of repeated denials.
    RateLimit,
    /// A live grant answered the rules' ask (KNSH-042).
    Grant,
}

impl DecisionSource {
    /// The record spelling: `rule`, `hook`, `authority`, `user`, `standalone`, `rate_limit` or `grant`.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Rule => "rule",
            Self::Hook => "hook",
            Self::Authority => "authority",
            Self::User => "user",
            Self::Standalone => "standalone",
            Self::RateLimit => "rate_limit",
            Self::Grant => "grant",
        }
    }

    /// The source spelled `code` ([`code`](Self::code)), or `None` for any other text.
    #[must_use]
    pub fn from_code(code: &str) -> Option<Self> {
        [
            Self::Rule,
            Self::Hook,
            Self::Authority,
            Self::User,
            Self::Standalone,
            Self::RateLimit,
            Self::Grant,
        ]
        .into_iter()
        .find(|source| source.code() == code)
    }
}

/// The decision for one part of a line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MatchedRule {
    /// The entry's index in [`Classification::commands`], or `None` for a dynamic part with no entry of its own,
    /// decided by `exec.default`.
    pub command: Option<usize>,
    /// What the part's rule says.
    pub verdict: RuleAction,
    /// The rule or setting that decided the part.
    pub rule_id: RuleId,
}

/// Why a line was decided the way it was, when the deciding rule alone does not say.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum LineReason {
    /// The line would ask, or holds dynamic code, but runs under the `unattended` profile, where no one can answer
    /// (FR-AGT-21).
    Unattended {
        /// The profile, named in the reason.
        profile: ProfileName,
        /// The rule or setting that asked, or that decided the first dynamic part.
        rule_id: RuleId,
    },
    /// The evaluation failed, and the line is denied (fail closed).
    EvaluationFailed,
}

impl fmt::Display for LineReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unattended { profile, rule_id } => write!(
                f,
                "{rule_id} would need approval (or decides dynamic code), which the {profile} profile cannot ask for, so \
                 the line is denied"
            ),
            Self::EvaluationFailed => f.write_str("policy evaluation failed, so the line is denied (fail closed)"),
        }
    }
}

/// What a line may receive when it runs (module documentation, "Capabilities"). The default receives nothing: no
/// hosts, no loopback ports, no classes and no secrets.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct LineCapabilities {
    /// Hosts open to the line: `network.hosts`, or none under `network.mode = "none"`.
    pub hosts: Vec<String>,
    /// Hosts the line may reach only once its classes or an approval allow: `network.approval_hosts`; none for
    /// dynamic code (FR-POL-21) and under `network.mode = "none"`.
    pub approval_hosts: Vec<String>,
    /// The approval hosts the line reaches by its classes alone, without an approval: those every class it presents
    /// that connects lists under `network.class_hosts` (FR-NET-03). A subset of
    /// [`approval_hosts`](Self::approval_hosts), in its order; none when that is empty or the line presents no
    /// class that connects.
    pub class_hosts: Vec<String>,
    /// Loopback ports open to the line: `network.loopback`.
    pub loopback: Vec<u16>,
    /// The network classes the line may present to host rules, in order of first appearance; none for dynamic code
    /// (FR-POL-20) or when any command that can connect has none.
    pub classes: Vec<NetworkClass>,
    /// The `secrets.env` variables whose `inject_for` patterns certainly match a command of the line, sorted; none for
    /// dynamic code (FR-POL-21, FR-SEC-04). Each command that matches asks (FR-SEC-02, [`RuleId::Secret`]), so the
    /// line receives them only once approved or granted.
    pub secrets: Vec<String>,
    /// The `hosts` of each secret in [`secrets`](Self::secrets), in its order: the line may reach only a host that
    /// an entry of **every** list matches (FR-SEC-03, FR-NET-10). Empty when the line receives no secret.
    pub secret_hosts: Vec<Vec<String>>,
    /// Whether any part of the line is dynamic code, so the limits above are clamped.
    pub dynamic: bool,
}

/// One decision for a whole line (module documentation).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LineDecision {
    /// Run it, ask, or refuse it.
    pub verdict: RuleAction,
    /// Who decided: [`DecisionSource::Rule`], [`DecisionSource::Grant`] for an ask a grant answered, or
    /// [`DecisionSource::Standalone`] for an ask (or granted dynamic code) the `unattended` profile denied.
    pub source: DecisionSource,
    /// The rule or setting that decided the line: the first part with the line's verdict (before an `unattended`
    /// ask is turned into a deny), or for an allowed line holding dynamic code that `unattended` denies, its first
    /// dynamic part's. For a line a grant allowed, the first rule that asked, which the grant answered. `None` for a
    /// line with no parts, and for a failed evaluation.
    pub rule_id: Option<RuleId>,
    /// The grant that allowed the line, when [`source`](Self::source) is [`DecisionSource::Grant`]: the one covering
    /// the first part that asked. `None` otherwise.
    pub grant: Option<GrantId>,
    /// Why, when the rule alone does not say: an `unattended` deny or a failed evaluation.
    pub reason: Option<LineReason>,
    /// The decision of every part of the line, entries in source order, then any dynamic part without an entry.
    pub matched_rules: Vec<MatchedRule>,
    /// What the line may receive; nothing when it is denied.
    pub capabilities: LineCapabilities,
}

impl LineDecision {
    /// The decision when evaluation failed: deny, by rule, nothing matched and nothing received.
    fn failed() -> Self {
        Self {
            verdict: RuleAction::Deny,
            source: DecisionSource::Rule,
            rule_id: None,
            grant: None,
            reason: Some(LineReason::EvaluationFailed),
            matched_rules: Vec::new(),
            capabilities: LineCapabilities::default(),
        }
    }
}

/// Why an evaluation could not be completed. Never leaves this module: it becomes a deny.
#[derive(Debug)]
enum EvaluationError {
    /// An entry names a wrapper that does not come before it, so the classification breaks its own invariants and
    /// cannot be trusted.
    InconsistentClassification,
}

/// Decides a whole classified line against `profile` (module documentation).
///
/// `classification` must come from the same line, classified with the profile's interpreter table. Pure and total:
/// any failure inside is a deny with [`LineReason::EvaluationFailed`].
#[must_use]
pub fn evaluate_line(profile: &Profile, classification: &Classification) -> LineDecision {
    fail_closed(|| decide(profile, classification, None))
}

/// The live grants a line is evaluated with: those of its session and profile at one instant.
#[derive(Clone, Copy)]
struct GrantContext<'a> {
    grants: &'a GrantSet,
    session: SessionId,
    now: Timestamp,
}

/// Decides a whole classified line of `session` against `profile` and the grants in `grants` live at `now`
/// (module documentation, "Grants"). `profile` must be the session's own: profile-scoped grants match its name.
///
/// `now` comes from the injected clock; a caller that cannot read the clock must call [`evaluate_line`] instead, so
/// no grant applies (fail closed). Pure and total, like [`evaluate_line`].
#[must_use]
pub fn evaluate_line_with_grants(
    profile: &Profile,
    classification: &Classification,
    grants: &GrantSet,
    session: SessionId,
    now: Timestamp,
) -> LineDecision {
    let context = GrantContext { grants, session, now };
    fail_closed(|| decide(profile, classification, Some(context)))
}

/// Runs `evaluate`, turning an error or a panic into [`LineDecision::failed`] (fail closed).
fn fail_closed(evaluate: impl FnOnce() -> Result<LineDecision, EvaluationError>) -> LineDecision {
    // Only shared references cross the boundary, and nothing is used after a panic, so no broken state can be seen.
    match panic::catch_unwind(AssertUnwindSafe(evaluate)) {
        Ok(Ok(decision)) => decision,
        Ok(Err(EvaluationError::InconsistentClassification)) | Err(_) => LineDecision::failed(),
    }
}

/// The evaluation proper; see the module documentation.
fn decide(
    profile: &Profile,
    classification: &Classification,
    grants: Option<GrantContext<'_>>,
) -> Result<LineDecision, EvaluationError> {
    let commands = classification.commands();
    let mut matched_rules: Vec<MatchedRule> = Vec::with_capacity(commands.len() + 1);
    for (index, command) in commands.iter().enumerate() {
        // The classifier records each wrapper before the command it runs.
        if command.wrapper.is_some_and(|wrapper| wrapper >= index) {
            return Err(EvaluationError::InconsistentClassification);
        }
        let verdict = evaluate_command(profile, command);
        matched_rules.push(MatchedRule {
            command: Some(index),
            verdict: verdict.verdict,
            rule_id: verdict.rule_id,
        });
    }
    // FR-SEC-02 (KNSH-092): a command that would receive a secret asks even when the rules allow it, so only an
    // approval or a grant covering it lets the secret out. A line holding dynamic code receives none (FR-SEC-04), so
    // nothing of it asks for this reason.
    if !is_dynamic(classification) {
        for part in &mut matched_rules {
            let Some(command) = part.command.and_then(|index| commands.get(index)) else {
                continue;
            };
            if part.verdict == RuleAction::Allow
                && let Some(index) = secret_of(profile, command)
            {
                part.verdict = RuleAction::Ask;
                part.rule_id = RuleId::Secret(index);
            }
        }
    }
    // FR-POL-20: dynamic code nothing else decides is "allowed or asked as the profile says": its default.
    if has_dynamic_part_without_entry(classification) {
        matched_rules.push(MatchedRule {
            command: None,
            verdict: profile.exec.default,
            rule_id: RuleId::Default,
        });
    }

    // FR-POL-18: the strictest part decides (`RuleAction` orders allow < ask < deny); the first such part is named.
    let verdict = matched_rules
        .iter()
        .map(|part| part.verdict)
        .max()
        .unwrap_or(RuleAction::Allow);
    let rule_id = matched_rules
        .iter()
        .find(|part| part.verdict == verdict)
        .map(|part| part.rule_id);

    // KNSH-042: a grant only answers an ask, and only when it covers every part that asks; a deny is never touched.
    let grant = match (verdict, grants) {
        (RuleAction::Ask, Some(context)) => covering_grant(profile, commands, &matched_rules, context),
        (RuleAction::Allow | RuleAction::Ask | RuleAction::Deny, _) => None,
    };
    let (verdict, source) = match grant {
        Some(_) => (RuleAction::Allow, DecisionSource::Grant),
        None => (verdict, DecisionSource::Rule),
    };

    // FR-AGT-21: under `unattended` no one can answer, so an ask is a deny made by the standalone rules. Dynamic code
    // is too: an allowed tool given a code variable (`GIT_EXTERNAL_DIFF=./x git diff`) runs any program, which only
    // an approval could allow, so it is never a plain read-only command.
    let unattended = profile.name.as_str() == UNATTENDED_PROFILE;
    let dynamic_rule = matched_rules
        .iter()
        .find(|part| {
            part.command
                .is_none_or(|index| commands.get(index).is_none_or(|command| command.class.is_dynamic()))
        })
        .map(|part| part.rule_id);
    // A granted line holding dynamic code is denied here too: a grant never relaxes the dynamic-code limits.
    let (verdict, rule_id, source, grant, reason) = match (verdict, rule_id, dynamic_rule) {
        (RuleAction::Ask, Some(rule_id), _) | (RuleAction::Allow, _, Some(rule_id)) if unattended => (
            RuleAction::Deny,
            Some(rule_id),
            DecisionSource::Standalone,
            None,
            Some(LineReason::Unattended {
                profile: profile.name.clone(),
                rule_id,
            }),
        ),
        (verdict, rule_id, _) => (verdict, rule_id, source, grant, None),
    };

    let capabilities = match verdict {
        RuleAction::Deny => LineCapabilities::default(),
        RuleAction::Allow | RuleAction::Ask => capabilities(profile, classification),
    };
    Ok(LineDecision {
        verdict,
        source,
        rule_id,
        grant,
        reason,
        matched_rules,
        capabilities,
    })
}

/// The grant covering the first part that asks, if a live grant covers **every** part that asks; `None` as soon as
/// one asking part is not covered. A part with no entry of its own has no command for a grant rule to match, so it is
/// never covered.
fn covering_grant(
    profile: &Profile,
    commands: &[ClassifiedCommand],
    matched_rules: &[MatchedRule],
    context: GrantContext<'_>,
) -> Option<GrantId> {
    let mut first = None;
    for part in matched_rules.iter().filter(|part| part.verdict == RuleAction::Ask) {
        let command = commands.get(part.command?)?;
        let grant = context
            .grants
            .covering(context.session, &profile.name, command, context.now)?;
        first.get_or_insert(grant.id());
    }
    first
}

/// Whether the line has a dynamic part that no dynamic entry covers, so no rule decided it: a line the parser could
/// not read, or a part such as an unsupported construct that the classifier gives no entry.
///
/// A part of a kind that never has an entry (`[[ … ]]`, `coproc`, …) is never covered, even inside the span of a
/// dynamic entry: `python3 -c x "$([[ $(rm -rf /) ]])"` hides `rm` inside the construct, and the interpreter's allow
/// rule must not decide it.
fn has_dynamic_part_without_entry(classification: &Classification) -> bool {
    classification.is_whole_line()
        || classification.dynamic_parts().iter().any(|part| {
            !belongs_to_a_command(part.reason)
                || !classification
                    .commands()
                    .iter()
                    .any(|command| command.class.is_dynamic() && contains(command.span, part.span))
        })
}

/// Whether a dynamic part of this kind belongs to a simple command, which the classifier gives an entry of its own
/// (and so a rule). The others are constructs no entry stands for, decided by `exec.default` wherever they are.
const fn belongs_to_a_command(reason: DynamicReason) -> bool {
    match reason {
        DynamicReason::Eval
        | DynamicReason::Source
        | DynamicReason::ExpandedCommandName
        | DynamicReason::InterpreterInput
        | DynamicReason::InterpreterCode
        | DynamicReason::InterpreterStdin
        | DynamicReason::ExpandedArgument
        | DynamicReason::UnknownWrapperOption
        | DynamicReason::CodeVariable => true,
        DynamicReason::InputTooLarge
        | DynamicReason::TooManyTokens
        | DynamicReason::NestingTooDeep
        | DynamicReason::SyntaxError
        | DynamicReason::AmbiguousSyntax
        | DynamicReason::HereDocumentDelimiter
        | DynamicReason::Unsupported(_)
        | DynamicReason::Coproc => false,
    }
}

/// Whether `outer` contains `inner`.
fn contains(outer: Span, inner: Span) -> bool {
    outer.start <= inner.start && inner.end <= outer.end
}

/// The capabilities of a line that may run (module documentation, "Capabilities").
fn capabilities(profile: &Profile, classification: &Classification) -> LineCapabilities {
    let commands = classification.commands();
    let dynamic = is_dynamic(classification);
    let network = &profile.network;
    let (hosts, approval_hosts) = match network.mode {
        NetworkMode::None => (Vec::new(), Vec::new()),
        // FR-POL-21: dynamic code keeps only the hosts open to every command.
        NetworkMode::Allowlist if dynamic => (network.hosts.clone(), Vec::new()),
        NetworkMode::Allowlist => (network.hosts.clone(), network.approval_hosts.clone()),
    };
    // FR-POL-20, FR-POL-21, FR-SEC-04: no classes and no secrets for a line holding dynamic code.
    let (classes, secrets) = if dynamic {
        (Vec::new(), Vec::new())
    } else {
        (line_classes(commands), eligible_secrets(profile, commands))
    };
    // FR-SEC-03, FR-NET-10: each secret's `hosts`, which the proxy narrows the line's network to.
    let secret_hosts = secrets
        .iter()
        .map(|variable| {
            profile
                .secrets
                .get(variable)
                .map(|injection| injection.hosts.clone())
                .unwrap_or_default()
        })
        .collect();
    // FR-NET-03: dynamic code has no approval hosts and no classes above, so it never reaches one by class.
    let class_hosts = approval_hosts
        .iter()
        .filter(|host| network.class_hosts.allows(&classes, host))
        .cloned()
        .collect();
    LineCapabilities {
        hosts,
        approval_hosts,
        class_hosts,
        loopback: network.loopback.clone(),
        classes,
        secrets,
        secret_hosts,
        dynamic,
    }
}

/// Whether any part of the line is dynamic code, so its capabilities are clamped (FR-POL-20, FR-POL-21).
fn is_dynamic(classification: &Classification) -> bool {
    classification.is_dynamic()
        || classification
            .commands()
            .iter()
            .any(|command| command.class.is_dynamic())
}

/// The index, in variable order, of the first `[secrets.env]` variable `command` certainly matches through
/// `inject_for`: the command would receive it (FR-SEC-01).
fn secret_of(profile: &Profile, command: &ClassifiedCommand) -> Option<usize> {
    profile.secrets.values().position(|injection| {
        injection
            .inject_for
            .iter()
            .any(|pattern| matches_certainly(pattern, command))
    })
}

/// The classes of the line's commands, or none if a command that can connect has none (module documentation).
fn line_classes(commands: &[ClassifiedCommand]) -> Vec<NetworkClass> {
    let mut classes = Vec::new();
    for command in commands {
        match (command.class, &command.program) {
            // The command a wrapper runs, and a function's body, are entries of their own; a builtin or a name not
            // found opens no proxy connection.
            (CommandClass::Wrapper, _)
            | (CommandClass::Static, Some(Program::Builtin | Program::Function | Program::NotFound)) => {}
            (CommandClass::Static, Some(Program::Trusted(_))) => match normalise(command, SUBCOMMAND_TABLE) {
                Normalisation::Normalised(normalised) => {
                    for class in normalised.classes {
                        if !classes.contains(class) {
                            classes.push(*class);
                        }
                    }
                }
                Normalisation::Raw(_) => return Vec::new(),
            },
            // Anything else may connect and has no classes: a project executable, a program not known from the
            // line, and dynamic code (already excluded by the caller).
            (CommandClass::Static, Some(Program::ProjectExecutable(_)) | None)
            | (CommandClass::ProjectExecutable | CommandClass::Dynamic { .. }, _) => return Vec::new(),
        }
    }
    classes
}

/// The `secrets.env` variables a command of the line certainly matches through `inject_for`, in variable order.
fn eligible_secrets(profile: &Profile, commands: &[ClassifiedCommand]) -> Vec<String> {
    profile
        .secrets
        .iter()
        .filter(|(_, injection)| {
            commands.iter().any(|command| {
                injection
                    .inject_for
                    .iter()
                    .any(|pattern| matches_certainly(pattern, command))
            })
        })
        .map(|(variable, _)| variable.clone())
        .collect()
}

#[cfg(test)]
mod tests;
