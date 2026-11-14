//! Fuzz target `bash_parse`: see [`knsh_fuzz::bash_checks::bash_parse`] for the properties it checks.

#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| knsh_fuzz::bash_checks::bash_parse(data));
