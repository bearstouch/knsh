//! Fuzz target `proxy_handshake`: see [`knsh_fuzz::proxy_checks::proxy_handshake`] for the properties it checks.

#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| knsh_fuzz::proxy_checks::proxy_handshake(data));
