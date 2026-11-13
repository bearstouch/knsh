//! Fuzz targets for knsh's hand-written parsers of untrusted input (KNSH-005; NFR-SUP-05, NFR-SUP-06;
//! `specs/07-testing/fuzzing.md`). Test-only: never part of the shipped workspace.
//!
//! The targets in `fuzz_targets/` are one-line wrappers around [`checks`], which holds the properties so that the
//! stable test suite can replay saved crashes without libFuzzer.

pub mod checks;
