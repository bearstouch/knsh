//! Running the hook chain for one evaluation pass (FR-HOOK-01, FR-HOOK-04, FR-HOOK-05, FR-HOOK-10).
//!
//! [`run_hooks`] walks the registrations in declared order, runs each matching one through a [`HookExecutor`] (the
//! process side lives in `knshd`), and folds the answers into one [`HookOutcome`]:
//!
//! - an invalid registration, an error or a timeout ends the chain as [`HookVerdict::Failed`];
//! - the first `deny` ends it as [`HookVerdict::Deny`];
//! - a `rewrite` ends it as [`HookVerdict::Rewrite`]: the pipeline evaluates the new line in a pass of its own, where
//!   every hook runs again, so later hooks see the rewritten line;
//! - an `ask` is remembered and the chain goes on; the pass asks if any hook asked;
//! - `allow` and `annotate` decide nothing.
//!
//! Every hook that ran (or was invalid) is listed in [`HookOutcome::runs`] with its run time.

use std::time::Duration;

use crate::lifecycle::{HookOutcome, HookVerdict, Proposal};
use crate::record::{HookResult, HookRun};
use crate::session::Actor;

use super::config::{HOOKS_KEY, HookConfig, HookEntry, HookSpec};
use super::output::{HookExit, HookReply, judge};

/// How one hook process ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ended {
    /// It exited (or was signalled) before its timeout.
    Finished {
        /// What it printed, at most [`MAX_HOOK_OUTPUT`](super::MAX_HOOK_OUTPUT) bytes plus one, so a longer output
        /// is still seen as too long.
        stdout: Vec<u8>,
        /// How it exited.
        exit: HookExit,
    },
    /// It was still running at its timeout; its process group was killed.
    TimedOut,
    /// It could not be started, or its output could not be read.
    Failed,
}

/// One hook run: how it ended and how long it took.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Execution {
    /// How it ended.
    pub ended: Ended,
    /// Its run time.
    pub duration: Duration,
}

/// Runs one hook process (`knshd` spawns it directly, never through a shell, FR-HOOK-02).
pub trait HookExecutor {
    /// Runs `hook` with `input` on its stdin, killing its process group at its timeout. Never fails: a failure is
    /// [`Ended::Failed`].
    fn execute(&self, hook: &HookSpec, input: &[u8]) -> Execution;
}

/// Runs the hooks of `config` that match `proposal`, in declared order, and combines their verdicts (module
/// documentation). `input` is the `command.proposed` event every hook receives on stdin, or `None` if it could not
/// be written, which fails the first matching hook.
///
/// Human sessions run no hooks (FR-HOOK-01): their lines are observed, never decided.
#[must_use]
pub fn run_hooks(
    config: &HookConfig,
    proposal: &Proposal<'_>,
    input: Option<&[u8]>,
    executor: &dyn HookExecutor,
) -> HookOutcome {
    if matches!(proposal.actor, Actor::Human) {
        return HookOutcome::ALLOW;
    }
    let entries = match config {
        HookConfig::Hooks(entries) => entries,
        // Whether any hook should run cannot be known, so every line is denied.
        HookConfig::Invalid(_) => {
            return HookOutcome {
                verdict: HookVerdict::Failed,
                hook: Some(HOOKS_KEY.to_owned()),
                runs: vec![not_run(HOOKS_KEY.to_owned())],
            };
        }
    };
    let mut runs = Vec::new();
    // The first hook that asked: the pass asks if any did, and names it.
    let mut asked: Option<String> = None;
    for entry in entries
        .iter()
        .filter(|entry| entry.matcher.matches(proposal.classification))
    {
        let (run, verdict) = run_one(entry, input, executor);
        let name = run.hook.clone();
        let result = run.result;
        runs.push(run);
        if let Some(verdict) = verdict {
            return HookOutcome {
                verdict,
                hook: Some(name),
                runs,
            };
        }
        if result == HookResult::Ask && asked.is_none() {
            asked = Some(name);
        }
    }
    let verdict = if asked.is_some() {
        HookVerdict::Ask
    } else {
        HookVerdict::Allow
    };
    HookOutcome {
        verdict,
        hook: asked,
        runs,
    }
}

/// Runs `entry` and returns its run for the record, with the verdict that ends the chain, if it does.
fn run_one(entry: &HookEntry, input: Option<&[u8]>, executor: &dyn HookExecutor) -> (HookRun, Option<HookVerdict>) {
    let name = entry.id.to_string();
    // FR-HOOK-04: an invalid registration denies every line it matches; it is never silently skipped.
    let Ok(spec) = &entry.registration else {
        return (not_run(name), Some(HookVerdict::Failed));
    };
    // Without its input the hook cannot judge the line, so it is not started and the line is denied.
    let Some(input) = input else {
        let run = HookRun {
            result: HookResult::Error,
            ..not_run(name)
        };
        return (run, Some(HookVerdict::Failed));
    };
    let execution = executor.execute(spec, input);
    // FR-HOOK-05: the run time is reported up to the timeout, never beyond it.
    let duration_ms = u64::try_from(execution.duration.min(spec.timeout).as_millis()).unwrap_or(u64::MAX);
    let reply = match execution.ended {
        Ended::Finished { stdout, exit } => judge(&stdout, exit).ok_or(HookResult::Error),
        Ended::TimedOut => Err(HookResult::Timeout),
        Ended::Failed => Err(HookResult::Error),
    };
    let (result, verdict, labels) = match reply {
        // FR-HOOK-04: an error, unreadable output or a timeout is a deny no hook can turn off.
        Err(result) => (result, Some(HookVerdict::Failed), Vec::new()),
        Ok(HookReply::Allow) => (HookResult::Allow, None, Vec::new()),
        Ok(HookReply::Ask { .. }) => (HookResult::Ask, None, Vec::new()),
        Ok(HookReply::Annotate { labels }) => (HookResult::Annotate, None, labels),
        // FR-HOOK-10: the first deny stops the chain.
        Ok(HookReply::Deny { reason }) => (HookResult::Deny, Some(HookVerdict::Deny { reason }), Vec::new()),
        Ok(HookReply::Rewrite { command }) => (HookResult::Rewrite, Some(HookVerdict::Rewrite { command }), Vec::new()),
    };
    let run = HookRun {
        hook: name,
        result,
        duration_ms,
        labels,
    };
    (run, verdict)
}

/// The run of a hook that was not started because its registration (or the whole configuration) is invalid.
fn not_run(hook: String) -> HookRun {
    HookRun {
        hook,
        result: HookResult::Invalid,
        duration_ms: 0,
        labels: Vec::new(),
    }
}
