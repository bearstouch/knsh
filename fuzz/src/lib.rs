//! Fuzz targets for knsh's hand-written parsers of untrusted input (KNSH-005; NFR-SUP-05, NFR-SUP-06;
//! `specs/07-testing/fuzzing.md`). Test-only: never part of the shipped workspace.
//!
//! The targets in `fuzz_targets/` are one-line wrappers around [`checks`] (JSON), [`toml_checks`] (TOML),
//! [`bash_checks`] (bash lexer), [`sandbox_log_checks`] (sandbox denial log entries), [`proxy_checks`] (proxy
//! handshakes), [`tls_checks`] (TLS ClientHello reader) and [`redaction_checks`] (the secret redactor),
//! [`arith_checks`] (arithmetic evaluation of the native interpreter), which hold
//! the properties so that the stable test suite can replay saved crashes without libFuzzer.

pub mod arith_checks;
pub mod bash_checks;
pub mod checks;
pub mod proxy_checks;
pub mod redaction_checks;
pub mod sandbox_log_checks;
pub mod tls_checks;
pub mod toml_checks;
