//! Fuzz target `word_expansion`: see [`knsh_fuzz::word_checks::word_expansion`] for the properties it checks.

#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| knsh_fuzz::word_checks::word_expansion(data));
