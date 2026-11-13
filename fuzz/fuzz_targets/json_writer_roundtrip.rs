//! Fuzz target `json_writer_roundtrip`: see [`knsh_fuzz::checks::json_writer_roundtrip`] for the properties it checks.

#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| knsh_fuzz::checks::json_writer_roundtrip(data));
