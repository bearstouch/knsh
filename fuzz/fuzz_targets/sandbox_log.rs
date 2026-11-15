//! Fuzz target `sandbox_log`: see [`knsh_fuzz::sandbox_log_checks::sandbox_log`] for the properties it checks.

#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| knsh_fuzz::sandbox_log_checks::sandbox_log(data));
