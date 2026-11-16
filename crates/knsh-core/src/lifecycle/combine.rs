//! How the verdicts of one evaluation pass combine (KNSH-063; FR-HOOK-10 to FR-HOOK-13,
//! `specs/03-functional-requirements/hooks.md#combining-verdicts`).
//!
//! The rules, and where each one is enforced:
//!
//! - **Within the chain** ([`run_hooks`](crate::hook::run_hooks), FR-HOOK-10): hooks run in declared order. The first
//!   `deny` (or failure) stops the chain. A `rewrite` ends the chain too: the new line gets a pass of its own in which
//!   every hook runs again, so the hooks after the rewriting one see only the new line. An `ask` is remembered and
//!   the chain goes on. `annotate` adds labels to the record and decides nothing.
//! - **Hooks, then policy** (FR-HOOK-11): policy is evaluated only on a pass whose hooks neither denied nor rewrote,
//!   so a rewritten line is judged by policy as rewritten, never as received.
//! - **Most restrictive wins** (FR-HOOK-12): [`Strictness`] orders the verdicts, and the pass ends with the
//!   [`most_restrictive`] of the hooks' and policy's.
//! - **A rewrite applies only if not denied** (FR-HOOK-13): a rewritten line that its own pass denies is refused; the
//!   decision is `deny`, never `rewrite`, and nothing runs. Only an allowed line carries the `rewrite` verdict.

use crate::policy::RuleAction;

/// How restrictive a verdict is, least to most: the order in which verdicts win (FR-HOOK-12). A `rewrite` has no
/// strictness of its own: it replaces the line, which is then judged on its own pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Strictness {
    /// No objection.
    Allow,
    /// Someone must be asked.
    Ask,
    /// Refused.
    Deny,
}

impl Strictness {
    /// The strictness of a policy verdict.
    pub(crate) const fn of_rule(action: RuleAction) -> Self {
        match action {
            RuleAction::Allow => Self::Allow,
            RuleAction::Ask => Self::Ask,
            RuleAction::Deny => Self::Deny,
        }
    }
}

/// The most restrictive of `verdicts`: deny, then ask, then allow (FR-HOOK-12). Nothing to combine is an allow.
pub(crate) fn most_restrictive(verdicts: impl IntoIterator<Item = Strictness>) -> Strictness {
    verdicts.into_iter().max().unwrap_or(Strictness::Allow)
}
