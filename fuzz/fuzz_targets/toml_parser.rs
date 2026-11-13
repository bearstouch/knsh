//! Fuzz target `toml_parser`: see [`knsh_fuzz::toml_checks::toml_parser`] for the properties it checks.

#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| knsh_fuzz::toml_checks::toml_parser(data));
