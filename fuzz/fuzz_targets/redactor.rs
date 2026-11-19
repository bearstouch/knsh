//! Fuzz target `redactor`: see [`knsh_fuzz::redaction_checks::redactor`] for the properties it checks.

#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| knsh_fuzz::redaction_checks::redactor(data));
