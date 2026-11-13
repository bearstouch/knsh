# Strict-profile conformance samples

Hand-written accept (`accept/`) and reject (`reject/`) samples for the strict JSON profile
(`specs/06-api/wire-format.md#strict-json-profile`): RFC 8259 grammar plus the I-JSON (RFC 7493) restrictions.
Each file holds exactly one input, byte for byte; no trailing newline unless the sample is about whitespace.
They are read by `tests/conformance.rs` (`parses_rfc8259_conformance_samples`). Add a file to add a case.
