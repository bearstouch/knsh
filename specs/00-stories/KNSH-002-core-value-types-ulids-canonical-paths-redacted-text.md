# KNSH-002 — Core value types: ULIDs, canonical paths, redacted text, timestamps

[Phase 0](README.md#phase-0--foundations) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 0 | Foundations | M (3) | [KNSH-001](KNSH-001-workspace-toolchain-lint-baseline-and-ci.md) | `knsh-core` | [session model](../05-models/session.md), [execution record](../05-models/execution-record.md), FR-POL-11, NFR-PRIV-02 |

**Description.** As an engine developer, I want typed identifiers, canonical paths, redacted text and UTC
timestamps, so that mixing a session ID with a record ID, a raw path with a canonical one, or a secret with
redacted text fails to compile. Includes an in-house ULID implementation (Crockford base32, 48-bit millisecond time,
80-bit randomness) whose time and randomness are passed in, not read from the system. Out of scope: path
canonicalisation against the real filesystem (that is a platform effect; this story defines the type and its
invariants).

**Acceptance criteria**
- [ ] `SessionId`, `RecordId`, `EventId`, `RequestId`, `CheckpointId`, `GrantId` are distinct newtypes over a
      `Ulid`; there is no implicit conversion between them.
- [ ] `Ulid::new(millis, random_bytes)` is pure; formatting yields 26 uppercase Crockford characters; parsing
      rejects wrong length, invalid characters and overflow of the first character.
- [ ] ULIDs created with increasing time sort in creation order (sortable by start time, per session model).
- [ ] `CanonicalPath` can only be constructed through a constructor that takes an already-resolved absolute path
      and rejects relative paths, `.`/`..` components and empty paths.
- [ ] `Redacted<T>` has no `Display` or `Debug` that prints the inner value; it prints `«redacted»`.
- [ ] `Timestamp` holds UTC microseconds and formats as RFC 3339 with 6 fractional digits and `Z`
      (e.g. `2026-11-12T18:02:11.204913Z`).
- [ ] All public items have `///` docs with invariants.

**Unit tests**
- `ulid_formats_as_26_crockford_chars` — encoding.
- `ulid_parse_rejects_invalid_chars_and_length` — strict parsing.
- `ulid_sorts_by_time` — sortable by start time.
- `canonical_path_rejects_relative_and_dot_components` — FR-POL-11 invariant.
- `redacted_debug_never_prints_inner_value` — NFR-PRIV-02.
- `timestamp_formats_utc_microseconds` — record and event timestamp format.
