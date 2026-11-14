//! Fuzz target `bash_lex`: see [`knsh_fuzz::bash_checks::bash_lex`] for the properties it checks.

#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| knsh_fuzz::bash_checks::bash_lex(data));
