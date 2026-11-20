//! Fuzz target `arith_expr`: see [`knsh_fuzz::arith_checks::arith_expr`] for the properties it checks.

#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| knsh_fuzz::arith_checks::arith_expr(data));
