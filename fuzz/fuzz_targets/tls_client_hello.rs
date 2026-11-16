//! Fuzz target `tls_client_hello`: see [`knsh_fuzz::tls_checks::tls_client_hello`] for the properties it checks.

#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| knsh_fuzz::tls_checks::tls_client_hello(data));
