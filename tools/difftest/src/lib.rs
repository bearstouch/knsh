//! Dev-only differential harness for the phase 2 parser exit criterion (KNSH-034). Never shipped.
//!
//! For every line of the agent-command corpus (`tests/corpus/`), the harness compares our accept or reject verdict
//! ([`knsh_bash::parse_line`]) with real bash's (`bash -n -c`), and reports how many lines parse
//! [`Exact`](knsh_bash::ParseOutcome::Exact). The phase 2 exit criterion is then measured, not assumed:
//!
//! - **exact gate:** at least [`MIN_EXACT_PERCENT`] of corpus lines parse `Exact`;
//! - **verdict gate:** no line where bash and we disagree on accept or reject. In particular, no line we parse
//!   `Exact` is rejected by bash (so every line bash rejects is not `Exact` in ours).
//!
//! The verdict gate fails every run. The exact gate is always measured and reported, and fails release runs
//! ([`ExactGate`]), which the phase 2 release waits for.
//!
//! The pieces:
//!
//! - [`oracle`]: the [`Oracle`](oracle::Oracle) trait and the shell implementation that runs `bash -n` (bash 3.2 at
//!   `/bin/bash`, and 5.x when one is installed), plus non-gating reference shells such as brush;
//! - [`harness`]: loads the corpus, classifies our verdict and compares it with each oracle's;
//! - [`report`]: the gates and the Markdown report, which records every oracle's version.
//!
//! # Boundaries
//!
//! A dev-only tool with one binary, `knsh-difftest`. It depends only on `knsh-bash` and `knsh-corpus`, and nothing
//! may depend on it (enforced by `xtask/tests/dependency_policy.rs`). It runs bash only with `-n` (read, never
//! execute), with a cleared environment and no standard streams, so a corpus line cannot run or print anything.
//!
//! # Specification
//!
//! - `specs/07-testing/conformance.md` ("Phase 2 parser", exit criterion)
//! - `specs/09-reference/decisions.md`, decision 6
//! - `specs/04-non-functional-requirements/compatibility.md`, NFR-COMPAT-04, NFR-COMPAT-05, NFR-COMPAT-07
//! - `specs/00-stories/KNSH-034-differential-parser-tests-against-bash-phase-2-exit.md`

#![deny(missing_docs, unsafe_op_in_unsafe_fn, rust_2018_idioms)]
#![warn(clippy::pedantic)]
#![forbid(unsafe_code)]

mod error;
pub mod harness;
pub mod oracle;
pub mod report;

#[cfg(test)]
pub(crate) mod testing;

pub use error::DiffError;
pub use report::{ExactGate, MIN_EXACT_PERCENT, Summary};
