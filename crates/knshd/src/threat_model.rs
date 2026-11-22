//! The threat-model end-to-end suite (KNSH-075; NFR-SEC-01 to NFR-SEC-10).
//!
//! One end-to-end case or more per row of the threat model (`specs/04-non-functional-requirements/security.md`),
//! run against real envelopes and real compiled profiles, so phase 2 ships with evidence that every mitigation
//! holds (`specs/07-testing/test-strategy.md`, "Security test focus"). These are not unit tests: each case drives a
//! miniature `knshd` ([`harness::Stack`]) built from the same parts `main` wires: the connection server on real
//! `user.sock` and `agent.sock`, the policy loader over signed files, the real network proxy with its host rules,
//! the supervisor spawning every line through the real `knsh-exec` and `sandbox-exec`, and the envelope launcher.
//! Only the name resolver, the authority and the hooks are stand-ins, so nothing leaves the machine and no person is
//! asked.
//!
//! Every case runs in a temporary directory under `/private/tmp` with its own home, engine directories, sockets,
//! record store and policies: never the user's real ones.
//!
//! # Rows and cases
//!
//! [`report::CASES`] maps each case to its row, and [`report::every_threat_row_has_a_case`] checks that the rows
//! are exactly the specification's, so a row added to the threat model without a case fails the build.
//!
//! # Pending, never skipped
//!
//! What cannot be observed here (a Developer ID signature, Touch ID, a macOS version without a runner) is recorded
//! as **pending** with its reason ([`report::Case::pending`]), printed, and listed in the report. A case whose
//! binaries were not built (`cargo test -p knshd` alone does not build `knsh-exec`) is pending as a whole, unless
//! `KNSH_THREAT_MODEL_STRICT=1` is set, which `scripts/check.sh threat-model` (and CI) does: then it fails.
//!
//! # The report
//!
//! Each case that finishes writes its result to `target/threat-model/results/`; [`report::write_report`] (run by
//! `scripts/check.sh threat-model`) turns them into `target/threat-model/report.md`, the report the phase 2 release
//! gate references (`specs/01-overview/roadmap.md`). A case that failed leaves no result and the report fails.

mod cases;
pub(crate) mod harness;
mod native;
mod report;
