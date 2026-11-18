//! Phase 2 qualification (KNSH-076): the performance targets measured on the release machine, and the developer-tool
//! compatibility list checked inside real envelopes and command profiles.
//!
//! - [`perf`]: NFR-PERF-01, NFR-PERF-02, NFR-PERF-03, NFR-PERF-07 and NFR-PERF-08
//!   (`specs/07-testing/performance-validation.md`). Writes `performance.md` and `performance-samples.csv`.
//! - [`compat`]: FR-SBX-09, FR-NET-12 (`specs/08-integrations/developer-tools.md`). Writes `tools.md`.
//! - [`stats`] and [`report`]: the pure arithmetic and rendering both rest on, unit tested.
//!
//! The runs are `#[ignore]`d tests: their results depend on the machine, the build and (for the tools) the network,
//! so they run on purpose through `scripts/qualify-phase2.sh`, in release, and are stored with the release. They
//! drive the threat-model suite's miniature `knshd` ([`crate::threat_model::harness::Stack`]): `knshd` is a binary
//! without a library, and a real `knshd` runs agent lines only for profiles signed after Touch ID, so its parts are
//! wired here as `main` wires them. Idle memory alone needs the real process, started by launchd under a test job.
//!
//! Honesty rule (CLAUDE.md): a miss is reported with the figure as measured, and anything that could not be observed
//! is **not measured** or **pending** with its reason, never a pass.

mod compat;
mod perf;
mod report;
mod stats;
