//! Fuzz targets for knsh's hand-written parsers of untrusted input (KNSH-005; NFR-SUP-05, NFR-SUP-06;
//! `specs/07-testing/fuzzing.md`). Test-only: never part of the shipped workspace.
//!
//! The targets in `fuzz_targets/` are one-line wrappers around [`checks`] (JSON), [`toml_checks`] (TOML),
//! [`bash_checks`] (bash lexer) and [`sandbox_log_checks`] (sandbox denial log entries) and [`proxy_checks`] (proxy
//! handshakes), which hold the properties so that the stable test suite can replay saved crashes
//! without libFuzzer.

pub mod bash_checks;
pub mod checks;
pub mod proxy_checks;
pub mod sandbox_log_checks;
pub mod toml_checks;
