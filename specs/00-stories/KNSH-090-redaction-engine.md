# KNSH-090 — Redaction engine

[Phase 3](README.md#phase-3--reverse-and-protect) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 3 | Secrets | L (5) | [KNSH-002](KNSH-002-core-value-types-ulids-canonical-paths-redacted-text.md) | `knsh-core` | FR-SEC-10 |

**Description.** As the engine, I want a streaming redactor that replaces secret values and their encodings with a
marker, so that nothing stored or emitted contains them. Scope: exact value, base64 (standard and URL-safe, with and
without padding), URL-encoded and hex (lower and upper) forms; matching across chunk boundaries with bounded
look-behind; marker `«redacted:<name>»`; integration with the `Redacted<T>` type. Out of scope: transformed values
and files written to disk (documented limit).

**Acceptance criteria**
- [ ] The exact value and its base64, URL-encoded and hex forms are replaced with `«redacted:<name>»` (FR-SEC-10).
- [ ] A value split across two or more chunks is still redacted; held-back bytes are bounded by the longest encoded
      form.
- [ ] Overlapping secrets are both redacted, with the longest match winning.
- [ ] The redactor never outputs partial secret bytes when a stream ends mid-match.
- [ ] Throughput is measured and documented.

**Unit tests**
- `redacts_exact_value` (FR-SEC-10)
- `redacts_base64_and_url_safe_forms` (FR-SEC-10)
- `redacts_url_encoded_form` (FR-SEC-10)
- `redacts_hex_upper_and_lower` (FR-SEC-10)
- `redacts_value_split_across_chunks` (FR-SEC-10)
- `stream_end_mid_match_emits_no_partial_secret`

**Notes**
- Property test: for random chunkings of a stream containing a secret, the output never contains the secret.
- Add a fuzz target for the redactor in `fuzz/`.
