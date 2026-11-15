//! The supervisor's decision pipeline: lifecycle steps 2 to 8 for one agent line (KNSH-050;
//! `specs/03-functional-requirements/command-lifecycle.md`).
//!
//! [`decide`] takes a received line and returns what to do with it: [`Outcome::Run`] with the line to spawn and its
//! profile, or [`Outcome::Refused`]. The whole line is decided before any of it runs (FR-LC-09); nothing here can
//! spawn, and the driver in `knshd` spawns only on [`Outcome::Run`].
//!
//! # Steps
//!
//! Each evaluation pass works on one line:
//!
//! 2. **Parse and classify** (FR-LC-02 to FR-LC-06): [`parse_line`], names resolved on the caller's `PATH` from its
//!    working directory ([`LineResolver`]), [`classify`] with the profile's interpreter table. A line the parser cannot
//!    read is dynamic code and decided as such (decision 6).
//! 3. **Emit** `command.proposed` through [`Observer::proposed`] (FR-LC-07), before any hook runs.
//! 4. **Hooks** (FR-LC-08) through [`Hooks::run`]: the chain's combined verdict. A failed or timed-out hook denies
//!    (FR-HOOK-04, NFR-REL-07); a hook `deny` denies with source `hook`.
//! 5. **Policy** (FR-LC-09, FR-HOOK-11): the profile's rules (and live grants) on the whole line of this pass. Deny if
//!    any part is denied, ask if any part asks (FR-POL-18); the hooks' `ask` joins in, the strictest wins
//!    (FR-HOOK-12).
//! 6. **Ask** (FR-LC-10): through the [`Authority`] when one is connected, otherwise through [`LocalApprovals`]
//!    (standalone mode: `knsh approve` with Touch ID, or deny at the timeout). Under the `unattended` profile no one
//!    can answer, so an ask is a deny with source `standalone` (FR-AGT-21).
//! 7. **Rewrite** (FR-LC-11): a rewrite from a hook or the authority starts one more pass, steps 2 to 5 (and 6 if it
//!    asks), on the new line. A second rewrite denies the line (FR-AUTH-31), and so does a rewrite of a line holding a
//!    redaction marker (FR-AUTH-32).
//! 8. **Profile** (FR-LC-12): the session's profile with what the line's decision lets it receive
//!    ([`LineProfile`]), and the line re-serialised with every command's absolute path (FR-LC-13). A line that cannot
//!    be re-serialised is denied.
//!
//! # Failing closed (NFR-REL-07)
//!
//! Every error is a [`Outcome::Refused`], never a run: a hook that fails, an ask that fails or times out, a rewrite
//! that is refused, a line that cannot be re-serialised, and a panic anywhere inside, hooks and authority included
//! (caught at the boundary of [`decide`] as defence in depth: panics are denied by lint outside tests).
//!
//! # Cancellation (FR-LC-41)
//!
//! A decision is pending from the moment the line is received until [`decide`] returns. The [`Caller`] is checked
//! after the hooks and after the ask, and the ask itself watches it while it waits: once the caller is gone the line
//! is refused as [`RefusalKind::Cancelled`] and never runs. The driver checks once more right before spawning.
//!
//! # Redaction
//!
//! Hooks, the authority and events see one redacted text of the line ([`redact`], FR-REC-05). The spawned line is
//! the real one.

#[cfg(test)]
mod tests;

use std::panic::{self, AssertUnwindSafe};

use knsh_bash::{Classification, ParseOutcome, classify, parse_line, reserialise};

use crate::id::{RequestId, SessionId};
use crate::path::CanonicalPath;
use crate::policy::{
    DecisionSource, GrantSet, LineCapabilities, LineDecision, LineResolver, Profile, RuleAction, UNATTENDED_PROFILE,
    evaluate_line, evaluate_line_with_grants,
};
use crate::record::{DecisionVerdict, RecordDecision};
use crate::redacted::{REDACTED_MARKER, Redacted};
use crate::resolve::BinaryLookup;
use crate::session::{Actor, ProfileName};
use crate::time::Timestamp;

/// Most rewrites one line may receive (FR-LC-11): one more evaluation pass, never two (FR-AUTH-31).
pub const MAX_REWRITES: usize = 1;

/// Longest line a rewrite may produce, in bytes: the `exec.run` limit on a received line
/// (`specs/06-api/agent-socket.md#execrun`), so a rewritten line is never larger than the agent could have sent.
pub const MAX_LINE_LEN: usize = 65_536;

/// Whether the client that sent the line is still waiting for its answer (FR-LC-41).
pub trait Caller {
    /// `true` once the caller has disconnected: the pending decision is cancelled and the line must not run.
    fn gone(&self) -> bool;
}

/// A caller that never goes away: a line decided with nobody waiting on a connection.
#[derive(Debug, Clone, Copy, Default)]
pub struct StillWaiting;

impl Caller for StillWaiting {
    fn gone(&self) -> bool {
        false
    }
}

/// Where `command.proposed` goes (lifecycle step 3).
pub trait Observer {
    /// Emits `command.proposed` for `proposal`. Called once per evaluation pass, before that pass's hooks run.
    /// Publishing is best effort, like every event: it never decides anything.
    fn proposed(&self, proposal: &Proposal<'_>);
}

/// One line as hooks and the authority see it in one evaluation pass, and as `command.proposed` describes it.
#[derive(Debug, Clone, Copy)]
pub struct Proposal<'a> {
    /// The session the line belongs to.
    pub session_id: SessionId,
    /// The session's actor.
    pub actor: &'a Actor,
    /// The line of this pass, redacted (FR-REC-05).
    pub command: &'a Redacted<String>,
    /// The working directory.
    pub cwd: &'a CanonicalPath,
    /// The line before the rewrite, redacted, when this pass evaluates a rewritten line (FR-AUTH-30).
    pub rewritten_from: Option<&'a Redacted<String>>,
    /// How the line was classified: resolved binaries, wrappers and dynamic parts, for hook matches.
    pub classification: &'a Classification,
}

/// The combined verdict of a hook chain (`specs/03-functional-requirements/hooks.md#verdicts`). `annotate` decides
/// nothing, so it is [`HookVerdict::Allow`] here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HookVerdict {
    /// No objection (also: no hook matched).
    Allow,
    /// Escalate to the authority.
    Ask,
    /// Refuse the line.
    Deny {
        /// Shown to the agent.
        reason: Option<String>,
    },
    /// Replace the line; it is evaluated again (FR-LC-11).
    Rewrite {
        /// The new line.
        command: String,
    },
    /// A hook failed, printed something unreadable, or timed out: a deny that no hook can turn off (FR-HOOK-04).
    Failed,
}

/// What the hooks of one pass said.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HookOutcome {
    /// The chain's combined verdict.
    pub verdict: HookVerdict,
    /// The hook that decided it (the first `deny`, the failing hook, the rewriting or asking hook), if any.
    pub hook: Option<String>,
}

impl HookOutcome {
    /// No hook objected, or none matched.
    pub const ALLOW: Self = Self {
        verdict: HookVerdict::Allow,
        hook: None,
    };
}

/// The `command.proposed` hooks (KNSH-062 runs them, KNSH-063 combines them).
pub trait Hooks {
    /// Runs every hook matching `proposal`, in order, and combines their verdicts (FR-HOOK-10). Never fails: a
    /// failure is [`HookVerdict::Failed`].
    fn run(&self, proposal: &Proposal<'_>) -> HookOutcome;
}

/// Hooks when none are configured: every line passes them.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoHooks;

impl Hooks for NoHooks {
    fn run(&self, _proposal: &Proposal<'_>) -> HookOutcome {
        HookOutcome::ALLOW
    }
}

/// One ask (lifecycle step 6): the line and why it is asked about.
#[derive(Debug, Clone, Copy)]
pub struct AskRequest<'a> {
    /// The line, as hooks saw it.
    pub proposal: &'a Proposal<'a>,
    /// The rule that asked, or `None` when only a hook asked.
    pub rule_id: Option<&'a str>,
    /// The hook that asked, when one did.
    pub hook: Option<&'a str>,
}

/// How an ask ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AskReply {
    /// Run the line.
    Allow,
    /// Refuse it.
    Deny {
        /// Shown to the agent.
        reason: Option<String>,
    },
    /// Run this line instead, once it has been evaluated again (FR-AUTH-21, FR-AUTH-30).
    Rewrite {
        /// The new line.
        command: String,
    },
    /// No answer before the timeout (FR-AUTH-23): denied.
    TimedOut,
    /// The caller disconnected while waiting (FR-LC-41): cancelled.
    CallerGone,
    /// The ask could not be made or answered: denied.
    Failed,
}

/// The answer to one ask.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AskAnswer {
    /// The pending request's ID, once one was made.
    pub request_id: Option<RequestId>,
    /// How it ended.
    pub reply: AskReply,
    /// Who answered: the authority's or the user's name, when known.
    pub decided_by: Option<String>,
}

/// The connected authority (KNSH-069).
pub trait Authority {
    /// Whether an authority is connected now. When none is, asks go to [`LocalApprovals`].
    fn connected(&self) -> bool;

    /// Sends `request` as `decision.requested` and waits for the answer, the timeout, or `caller` going away.
    fn ask(&self, request: &AskRequest<'_>, caller: &dyn Caller) -> AskAnswer;
}

/// No authority: standalone mode for every ask (NFR-REL-09).
#[derive(Debug, Clone, Copy, Default)]
pub struct NoAuthority;

impl Authority for NoAuthority {
    fn connected(&self) -> bool {
        false
    }

    fn ask(&self, _request: &AskRequest<'_>, _caller: &dyn Caller) -> AskAnswer {
        AskAnswer {
            request_id: None,
            reply: AskReply::Failed,
            decided_by: None,
        }
    }
}

/// Standalone handling of an ask when no authority is connected (KNSH-066,
/// `specs/04-non-functional-requirements/reliability.md#standalone-mode`): the request waits for `knsh approve`
/// (Touch ID inside `knshd`) and is denied at the timeout.
pub trait LocalApprovals {
    /// Holds `request` for local approval until it is approved, refused, timed out or `caller` goes away.
    fn ask(&self, request: &AskRequest<'_>, caller: &dyn Caller) -> AskAnswer;
}

/// A line received by the supervisor, with everything its decision depends on. Deliberately without the interpreter
/// it will run with (FR-LC-14).
#[derive(Debug, Clone, Copy)]
pub struct LineInput<'a> {
    /// The bound session.
    pub session_id: SessionId,
    /// Its actor.
    pub actor: &'a Actor,
    /// Its profile, loaded.
    pub profile: &'a Profile,
    /// The live grants and the time to judge them at; `None` applies no grant (fail closed).
    pub grants: Option<(&'a GrantSet, Timestamp)>,
    /// The line, as received.
    pub command: &'a str,
    /// Its working directory.
    pub cwd: &'a CanonicalPath,
    /// The `PATH` names resolve on (without the shims, FR-LC-16).
    pub env_path: &'a str,
}

/// The effects the pipeline reaches through traits, so it is tested with fakes.
#[derive(Clone, Copy)]
pub struct Effects<'a> {
    /// Read-only binary lookups for name resolution.
    pub lookup: &'a dyn BinaryLookup,
    /// Receives `command.proposed`.
    pub observer: &'a dyn Observer,
    /// The hook chain.
    pub hooks: &'a dyn Hooks,
    /// The authority, when one is connected.
    pub authority: &'a dyn Authority,
    /// Standalone approvals.
    pub approvals: &'a dyn LocalApprovals,
    /// The client waiting for the answer.
    pub caller: &'a dyn Caller,
}

/// Who made a decision and on what grounds: the record's `decision` object without its latency, which the driver
/// measures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    /// The final effective verdict.
    pub verdict: DecisionVerdict,
    /// Which component decided.
    pub source: DecisionSource,
    /// The rule that decided or asked, if one did.
    pub rule_id: Option<String>,
    /// The hook, authority or user that decided, when not a rule.
    pub decided_by: Option<String>,
}

impl Decision {
    /// A deny by `source`, naming the rule and the hook, authority or user behind it when there is one. Every
    /// refusal, whatever its kind, is recorded with this verdict (FR-LC-30).
    #[must_use]
    pub const fn deny(source: DecisionSource, rule_id: Option<String>, decided_by: Option<String>) -> Self {
        Self {
            verdict: DecisionVerdict::Deny,
            source,
            rule_id,
            decided_by,
        }
    }

    /// The record's `decision` object, with `latency_ms` (FR-REC-03).
    #[must_use]
    pub fn to_record(&self, latency_ms: u64) -> RecordDecision {
        RecordDecision {
            verdict: self.verdict,
            source: self.source,
            rule_id: self.rule_id.clone(),
            decided_by: self.decided_by.clone(),
            latency_ms,
        }
    }
}

/// What the line may use when it runs (FR-LC-12): the session's profile, with what this line's decision adds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LineProfile {
    /// The session's profile: the per-command baseline.
    pub profile: ProfileName,
    /// What the decision lets the line receive (hosts, classes, secrets), already clamped for dynamic code.
    pub capabilities: LineCapabilities,
    /// Whether the line was asked about and approved (by the authority or the user), which unlocks approval hosts
    /// for it (KNSH-060).
    pub approved: bool,
}

/// An allowed line, ready to spawn.
#[derive(Debug, Clone)]
pub struct Allowed {
    /// The decision: `allow`, or `rewrite` when a rewrite was applied.
    pub decision: Decision,
    /// The line that was allowed (after any rewrite), as the record's `command` holds it (FR-REC-04).
    pub command: String,
    /// The line before the rewrite, if one was applied.
    pub rewritten_from: Option<String>,
    /// The line to spawn: [`command`](Self::command) with every command's canonical absolute path (FR-LC-13).
    pub executed: String,
    /// How the allowed line was classified.
    pub classification: Classification,
    /// Its profile.
    pub profile: LineProfile,
}

/// Why a refused line was refused, beyond its decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefusalKind {
    /// Denied by a rule, a hook, the authority, the user or standalone rules, or because a step failed (`-32001`).
    Denied,
    /// No answer before the ask timed out (`-32002`, FR-AUTH-23).
    TimedOut {
        /// The request that timed out.
        request_id: Option<RequestId>,
    },
    /// The caller went away while the decision was pending (`-32011`, FR-LC-41).
    Cancelled {
        /// The pending request, if the line had reached the ask step.
        request_id: Option<RequestId>,
    },
}

/// A line that must not run (FR-LC-30).
#[derive(Debug, Clone)]
pub struct Refusal {
    /// The decision: always [`DecisionVerdict::Deny`].
    pub decision: Decision,
    /// The line that was refused: the received one, or the rewritten one if the refusal came after a rewrite.
    pub command: String,
    /// The line before the rewrite, if one was applied.
    pub rewritten_from: Option<String>,
    /// Why, in words, for the agent's stderr (FR-LC-31).
    pub reason: Option<String>,
    /// How the refusal is answered.
    pub kind: RefusalKind,
    /// How the refused line was classified (step 2), for the record's `argv` (KNSH-052); `None` when it was refused
    /// before it was parsed.
    pub classification: Option<Classification>,
}

/// What [`decide`] returns.
#[derive(Debug, Clone)]
pub enum Outcome {
    /// Spawn this line (lifecycle step 9).
    Run(Box<Allowed>),
    /// Do not run it.
    Refused(Box<Refusal>),
}

impl Outcome {
    /// The decision, whichever way it went.
    #[must_use]
    pub fn decision(&self) -> &Decision {
        match self {
            Self::Run(allowed) => &allowed.decision,
            Self::Refused(refusal) => &refusal.decision,
        }
    }
}

/// The one place the line becomes the text hooks, the authority and events see (FR-REC-05).
///
/// The redaction engine (KNSH-090) plugs in here; until it exists the text is passed on as it is.
#[must_use]
pub fn redact(line: &str) -> Redacted<String> {
    Redacted::new(line.to_owned())
}

/// Decides `input` (module documentation). Total: every failure, panics included, is a [`Outcome::Refused`].
#[must_use]
pub fn decide(input: &LineInput<'_>, effects: &Effects<'_>) -> Outcome {
    // Only shared references cross the boundary, and nothing they point at is used after a panic.
    panic::catch_unwind(AssertUnwindSafe(|| Pipeline::new(input, effects).run())).unwrap_or_else(|_| {
        Outcome::Refused(Box::new(Refusal {
            decision: Decision::deny(DecisionSource::Rule, None, None),
            command: input.command.to_owned(),
            rewritten_from: None,
            reason: Some(INTERNAL_ERROR.to_owned()),
            kind: RefusalKind::Denied,
            // Nothing of the pipeline's work survives a panic.
            classification: None,
        }))
    })
}

/// Reason given for a line refused because the engine itself failed. Fixed text; the driver gives the same one for a
/// panic caught outside [`decide`].
pub const INTERNAL_ERROR: &str = "the supervisor failed while deciding the line, so it was denied (fail closed)";

/// One evaluation pass: the line, its parse and classification.
struct Pass {
    command: String,
    redacted: Redacted<String>,
    outcome: ParseOutcome,
    classification: Classification,
}

/// Who asked to rewrite a line.
#[derive(Clone)]
struct Rewriter {
    source: DecisionSource,
    by: Option<String>,
}

/// What one pass ended with.
enum Step {
    /// The pipeline's answer.
    Done(Outcome),
    /// Lifecycle step 7: `from`, the line of the pass, is to be replaced by `to`.
    Rewrite {
        from: String,
        /// How `from` was classified: its record's `argv` if the rewrite is refused.
        classification: Classification,
        to: String,
        rewriter: Rewriter,
    },
}

/// The pipeline over one received line.
struct Pipeline<'i, 'e> {
    input: &'i LineInput<'i>,
    effects: &'e Effects<'e>,
    /// The received line, once a rewrite has replaced it (the record's `rewritten_from`, FR-REC-04).
    rewritten_from: Option<String>,
}

impl<'i, 'e> Pipeline<'i, 'e> {
    const fn new(input: &'i LineInput<'i>, effects: &'e Effects<'e>) -> Self {
        Self {
            input,
            effects,
            rewritten_from: None,
        }
    }

    /// Passes until one decides: the received line, then at most [`MAX_REWRITES`] rewritten ones.
    fn run(mut self) -> Outcome {
        let mut line = self.input.command.to_owned();
        loop {
            match self.pass(line) {
                Step::Done(outcome) => return outcome,
                Step::Rewrite {
                    from,
                    classification,
                    to,
                    rewriter,
                } => match self.accept_rewrite(from, classification, to, &rewriter) {
                    Ok(next) => line = next,
                    Err(refusal) => return refusal,
                },
            }
        }
    }

    /// Steps 2 to 8 on `command`.
    fn pass(&self, command: String) -> Step {
        let pass = self.classify(command);
        let redacted_from = self.rewritten_from.as_deref().map(redact);
        let proposal = Proposal {
            session_id: self.input.session_id,
            actor: self.input.actor,
            command: &pass.redacted,
            cwd: self.input.cwd,
            rewritten_from: redacted_from.as_ref(),
            classification: &pass.classification,
        };

        // Step 3, before any hook sees the line (FR-LC-07).
        self.effects.observer.proposed(&proposal);

        // Step 4. The first deny stops the chain inside the runner; here a deny or a failure ends the pass.
        let hooks = self.effects.hooks.run(&proposal);
        if self.effects.caller.gone() {
            return Step::Done(self.cancelled(&pass, None));
        }
        let hook_asks = match hooks.verdict {
            HookVerdict::Allow => false,
            HookVerdict::Ask => true,
            HookVerdict::Deny { reason } => {
                return Step::Done(self.refuse(&pass, DecisionSource::Hook, None, hooks.hook, reason));
            }
            // FR-HOOK-04: a failed hook denies, and the failing hook is named.
            HookVerdict::Failed => {
                let reason = Some(HOOK_FAILED.to_owned());
                return Step::Done(self.refuse(&pass, DecisionSource::Hook, None, hooks.hook, reason));
            }
            // FR-HOOK-11: policy is evaluated on the rewritten line, in a pass of its own.
            HookVerdict::Rewrite { command } => {
                let rewriter = Rewriter {
                    source: DecisionSource::Hook,
                    by: hooks.hook,
                };
                return Step::Rewrite {
                    from: pass.command.clone(),
                    classification: pass.classification.clone(),
                    to: command,
                    rewriter,
                };
            }
        };

        // Step 5: the whole line (FR-LC-09, FR-POL-18).
        let policy = self.evaluate(&pass.classification);
        let rule_id = policy.rule_id.map(|rule| rule.to_string());
        // The ask names the hook only when a hook asked; a hook that allowed has no part in it.
        let asking_hook = if hook_asks { hooks.hook } else { None };
        match policy.verdict {
            RuleAction::Deny => {
                let reason = policy.reason.as_ref().map(ToString::to_string);
                Step::Done(self.refuse(&pass, policy.source, rule_id, None, reason))
            }
            RuleAction::Ask => self.ask(&pass, &proposal, rule_id, asking_hook, policy.capabilities),
            // The rules allow, but a hook asked: the strictest wins (FR-HOOK-12). No rule asked, so none is named.
            RuleAction::Allow if hook_asks => self.ask(&pass, &proposal, None, asking_hook, policy.capabilities),
            RuleAction::Allow => {
                let decision = Decision {
                    verdict: self.allowed_verdict(),
                    source: policy.source,
                    rule_id,
                    decided_by: None,
                };
                Step::Done(self.allow(&pass, decision, policy.capabilities, false))
            }
        }
    }

    /// Step 2: parse, resolve and classify `command`.
    fn classify(&self, command: String) -> Pass {
        let profile = self.input.profile;
        let resolver = LineResolver::new(
            self.input.env_path,
            self.input.cwd,
            &profile.exec.trusted_folders,
            self.effects.lookup,
        );
        let outcome = parse_line(&command);
        let classification = classify(&outcome, &command, &resolver, &profile.exec.interpreters);
        Pass {
            redacted: redact(&command),
            command,
            outcome,
            classification,
        }
    }

    /// Step 5: the profile's rules, with the live grants when the driver could read its clock.
    fn evaluate(&self, classification: &Classification) -> LineDecision {
        match self.input.grants {
            Some((grants, now)) => {
                evaluate_line_with_grants(self.input.profile, classification, grants, self.input.session_id, now)
            }
            None => evaluate_line(self.input.profile, classification),
        }
    }

    /// Step 6: asks about the line, and turns the answer into the pass's end.
    fn ask(
        &self,
        pass: &Pass,
        proposal: &Proposal<'_>,
        rule_id: Option<String>,
        hook: Option<String>,
        capabilities: LineCapabilities,
    ) -> Step {
        // FR-AGT-21: under `unattended` no one can answer. Rule asks were already turned into denies by policy; this
        // covers a hook's ask.
        if self.input.profile.name.as_str() == UNATTENDED_PROFILE {
            let reason = Some(UNATTENDED_ASK.to_owned());
            return Step::Done(self.refuse(pass, DecisionSource::Standalone, rule_id, hook, reason));
        }
        let request = AskRequest {
            proposal,
            rule_id: rule_id.as_deref(),
            hook: hook.as_deref(),
        };
        // `answered_by` is the source of an answer: the authority, or the user through `knsh approve`.
        // `unanswered` is the source of a deny nobody gave (a timeout or a failed ask): the authority's when it was
        // asked, standalone rules otherwise (NFR-REL-09).
        let (answer, answered_by, unanswered) = if self.effects.authority.connected() {
            let answer = self.effects.authority.ask(&request, self.effects.caller);
            (answer, DecisionSource::Authority, DecisionSource::Authority)
        } else {
            let answer = self.effects.approvals.ask(&request, self.effects.caller);
            (answer, DecisionSource::User, DecisionSource::Standalone)
        };
        let request_id = answer.request_id;
        // A caller that left while the answer arrived still never gets a line run for it (FR-LC-41).
        if answer.reply == AskReply::CallerGone || self.effects.caller.gone() {
            return Step::Done(self.cancelled(pass, request_id));
        }
        match answer.reply {
            AskReply::Allow => {
                let decision = Decision {
                    verdict: self.allowed_verdict(),
                    source: answered_by,
                    rule_id,
                    decided_by: answer.decided_by,
                };
                Step::Done(self.allow(pass, decision, capabilities, true))
            }
            AskReply::Deny { reason } => Step::Done(self.refuse(pass, answered_by, rule_id, answer.decided_by, reason)),
            AskReply::Rewrite { command } => Step::Rewrite {
                from: pass.command.clone(),
                classification: pass.classification.clone(),
                to: command,
                rewriter: Rewriter {
                    source: answered_by,
                    by: answer.decided_by,
                },
            },
            AskReply::TimedOut => Step::Done(self.refusal(
                pass.command.clone(),
                Some(pass.classification.clone()),
                Decision::deny(unanswered, rule_id, None),
                Some(ASK_TIMED_OUT.to_owned()),
                RefusalKind::TimedOut { request_id },
            )),
            AskReply::Failed => {
                let reason = Some(ASK_FAILED.to_owned());
                Step::Done(self.refuse(pass, unanswered, rule_id, answer.decided_by, reason))
            }
            // Already cancelled above; kept so the match stays exhaustive.
            AskReply::CallerGone => Step::Done(self.cancelled(pass, request_id)),
        }
    }

    /// Step 7: accepts `to` as the next pass's line in place of `from`, or refuses the line (FR-AUTH-31,
    /// FR-AUTH-32).
    fn accept_rewrite(
        &mut self,
        from: String,
        classification: Classification,
        to: String,
        rewriter: &Rewriter,
    ) -> Result<String, Outcome> {
        let refused = if self.rewritten_from.is_some() {
            Some(SECOND_REWRITE)
        } else if redact(&from).expose().contains(REDACTED_MARKER) || to.contains(REDACTED_MARKER) {
            // The rewriter saw a marker in place of a value, so its line cannot hold the real one.
            Some(REWRITE_OF_REDACTED)
        } else if to.len() > MAX_LINE_LEN || to.contains('\0') {
            Some(REWRITE_INVALID)
        } else {
            None
        };
        if let Some(reason) = refused {
            // Refused as the line that was being evaluated when the rewrite came.
            return Err(self.refusal(
                from,
                Some(classification),
                Decision::deny(rewriter.source, None, rewriter.by.clone()),
                Some(reason.to_owned()),
                RefusalKind::Denied,
            ));
        }
        // Only the first rewrite gets here, so `from` is the received line.
        self.rewritten_from = Some(from);
        Ok(to)
    }

    /// The verdict of an allowed line: `rewrite` once a rewrite was applied (`execution-record.md#decision`).
    const fn allowed_verdict(&self) -> DecisionVerdict {
        if self.rewritten_from.is_some() {
            DecisionVerdict::Rewrite
        } else {
            DecisionVerdict::Allow
        }
    }

    /// Step 8: the line to spawn and its profile, or a deny if it cannot be re-serialised (FR-LC-13).
    fn allow(&self, pass: &Pass, decision: Decision, capabilities: LineCapabilities, approved: bool) -> Outcome {
        let Ok(executed) = reserialise(&pass.command, &pass.outcome, &pass.classification) else {
            let reason = Some(RESERIALISE_FAILED.to_owned());
            return self.refuse(pass, DecisionSource::Rule, None, None, reason);
        };
        Outcome::Run(Box::new(Allowed {
            decision,
            command: pass.command.clone(),
            rewritten_from: self.rewritten_from.clone(),
            executed,
            classification: pass.classification.clone(),
            profile: LineProfile {
                profile: self.input.profile.name.clone(),
                capabilities,
                approved,
            },
        }))
    }

    /// A deny of the pass's line by `source`.
    fn refuse(
        &self,
        pass: &Pass,
        source: DecisionSource,
        rule_id: Option<String>,
        decided_by: Option<String>,
        reason: Option<String>,
    ) -> Outcome {
        let decision = Decision::deny(source, rule_id, decided_by);
        self.refusal(
            pass.command.clone(),
            Some(pass.classification.clone()),
            decision,
            reason,
            RefusalKind::Denied,
        )
    }

    /// The pass's line, cancelled because its caller went away (FR-LC-41). Recorded as a deny by standalone rules:
    /// nobody decided, and the line never runs.
    fn cancelled(&self, pass: &Pass, request_id: Option<RequestId>) -> Outcome {
        self.refusal(
            pass.command.clone(),
            Some(pass.classification.clone()),
            Decision::deny(DecisionSource::Standalone, None, None),
            Some(CALLER_GONE.to_owned()),
            RefusalKind::Cancelled { request_id },
        )
    }

    /// A refusal of `command` (classified as `classification`), carrying the received line as `rewritten_from` once
    /// a rewrite was accepted.
    fn refusal(
        &self,
        command: String,
        classification: Option<Classification>,
        decision: Decision,
        reason: Option<String>,
        kind: RefusalKind,
    ) -> Outcome {
        Outcome::Refused(Box::new(Refusal {
            decision,
            command,
            rewritten_from: self.rewritten_from.clone(),
            reason,
            kind,
            classification,
        }))
    }
}

/// Reasons given to the agent (FR-LC-31). Fixed texts: no line content, which could carry a secret.
const HOOK_FAILED: &str = "a hook failed or timed out, so the line was denied (fail closed)";
const UNATTENDED_ASK: &str =
    "a hook asked for approval, which the unattended profile cannot give, so the line was denied";
const ASK_TIMED_OUT: &str = "no decision before the timeout, so the line was denied";
const ASK_FAILED: &str = "the approval request failed, so the line was denied (fail closed)";
const SECOND_REWRITE: &str = "a rewritten line may not be rewritten again, so the line was denied";
const REWRITE_OF_REDACTED: &str = "a line holding redacted text cannot be rewritten, so the line was denied";
const REWRITE_INVALID: &str = "the rewritten line is too long or holds a NUL byte, so the line was denied";
const RESERIALISE_FAILED: &str = "the line could not be re-serialised with absolute paths, so it was denied";
const CALLER_GONE: &str = "the caller disconnected while the line was being decided, so it was cancelled";
