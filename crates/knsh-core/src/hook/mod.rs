//! Hooks: the user's own checks on agent lines (KNSH-062; `specs/05-models/hook.md`,
//! `specs/03-functional-requirements/hooks.md`).
//!
//! - `config`: the `[[hooks]]` registrations of the user's configuration file ([`parse_hooks`]), read strictly and
//!   failing closed: a registration that cannot be used is kept as invalid and denies every line it matches
//!   (FR-HOOK-04). Which lines a hook runs for is [`HookMatch`].
//! - `output`: a hook's stdout and exit read as a verdict ([`judge`], FR-HOOK-02, FR-HOOK-03).
//! - `chain`: the chain for one evaluation pass ([`run_hooks`]), over a [`HookExecutor`] that runs the processes,
//!   with every hook's run time for the record (FR-HOOK-05, FR-HOOK-10).
//!
//! Everything here is pure: reading the file, checking the executables and running them are `knshd`'s
//! (`crates/knshd/src/hooks.rs`).

mod chain;
mod config;
mod output;

#[cfg(test)]
mod tests;

pub use chain::{Ended, Execution, HookExecutor, run_hooks};
pub use config::{
    ConfigProblem, HOOK_EVENT, HOOKS_KEY, HookConfig, HookEntry, HookId, HookMatch, HookProblem, HookSpec,
    MAX_HOOK_TIMEOUT_MS, MAX_HOOKS, MAX_MATCH_BINARIES, parse_hooks,
};
pub use output::{
    HookExit, HookReply, MAX_HOOK_LABEL_LEN, MAX_HOOK_LABELS, MAX_HOOK_OUTPUT, MAX_HOOK_REASON_LEN, judge,
};
