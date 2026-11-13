//! Fuzz target `json_reader`: see [`knsh_fuzz::checks::json_reader`] for the properties it checks.

#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| knsh_fuzz::checks::json_reader(data));
