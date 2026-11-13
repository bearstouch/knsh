# KNSH-003 — Strict JSON reader and writer

[Phase 0](README.md#phase-0--foundations) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 0 | Wire protocol | XL (8) | [KNSH-001](KNSH-001-workspace-toolchain-lint-baseline-and-ci.md) | `knsh-json` | NFR-SEC-05, NFR-SEC-06, NFR-SUP-06, [wire format](../06-api/wire-format.md#strict-json-profile), [wire format](../06-api/wire-format.md#strict-json-profile) ("everything the engine sends conforms") |

**Description.** Merged from *Strict JSON reader (I-JSON profile)* and *JSON value model and writer*: they are done and validated together because round-trip tests validate reader and writer together.

*Strict JSON reader (I-JSON profile).* As the engine, I want a JSON parser that accepts only the strict profile, so that input from
untrusted processes can never be read two ways or exhaust memory. Hand-written, no dependencies. Out of scope: the
value model's writer (covered in this story) and framing (KNSH-004).

*JSON value model and writer.* As an engine developer, I want a JSON value model with typed accessors and a writer that only
emits strict-profile JSON, so that every message the engine sends is readable by any strict client. Includes small
`ToJson`/`FromJson` traits (no `serde`) that typed protocol structs implement by hand. Out of scope: protocol types.

**Acceptance criteria**
*Strict JSON reader (I-JSON profile)*

- [ ] Rejects invalid UTF-8 and unpaired surrogate escapes (`"\ud800"`).
- [ ] Rejects objects with duplicate keys, compared after unescaping (`{"a":1,"a":2}` is rejected).
- [ ] Rejects integers outside ±2^53 and numbers that cannot be represented exactly as such where an integer is
      required; non-integer numbers are kept as decimal text, not silently rounded.
- [ ] Rejects nesting deeper than 32 levels without recursion beyond that depth.
- [ ] Rejects trailing data, comments, trailing commas, NaN/Infinity, leading zeros and control characters in
      strings.
- [ ] Every rejection returns a typed error that `knsh-proto` maps to `-32700`; the parser never attempts recovery.
- [ ] Never panics on any input (enforced by KNSH-005 fuzzing).
- [ ] Input larger than a caller-provided limit is rejected before parsing.

*JSON value model and writer*

- [ ] Objects preserve insertion order and cannot hold duplicate keys (insertion of an existing key is an error).
- [ ] The writer escapes control characters and emits valid UTF-8; output contains no insignificant whitespace.
- [ ] Integers outside ±2^53 cannot be written as numbers; the API forces a string representation.
- [ ] `FromJson` helpers report missing fields, wrong types and unknown required fields as typed errors; unknown
      optional fields are ignored (additive protocol, per [handshake](../06-api/handshake.md#rules)).
- [ ] Round trip: `parse(write(v)) == v` for every value.

**Unit tests**
*Strict JSON reader (I-JSON profile)*

- `rejects_duplicate_keys_after_unescaping` — NFR-SEC-06.
- `rejects_unpaired_surrogate_escape` — strict profile.
- `rejects_invalid_utf8` — strict profile.
- `rejects_integer_beyond_2_pow_53` — strict profile.
- `accepts_integer_at_2_pow_53_boundary` — boundary.
- `rejects_depth_33_accepts_depth_32` — nesting limit.
- `rejects_trailing_comma_comment_and_trailing_data` — no recovery.
- `parses_rfc8259_conformance_samples` — a vendored set of accept/reject samples.

*JSON value model and writer*

- `writer_output_is_accepted_by_strict_reader` — round trip.
- `object_insert_rejects_duplicate_key` — no duplicates by construction.
- `large_integer_must_be_written_as_string` — ±2^53 rule.
- `from_json_reports_missing_field_by_name` — typed errors.
- `from_json_ignores_unknown_optional_fields` — additive protocol.
