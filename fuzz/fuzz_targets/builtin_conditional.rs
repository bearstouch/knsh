//! Fuzz target `builtin_conditional`: see [`knsh_fuzz::builtin_checks::builtin_conditional`] for the properties it
//! checks.

#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| knsh_fuzz::builtin_checks::builtin_conditional(data));
