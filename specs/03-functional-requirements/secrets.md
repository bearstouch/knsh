# Secrets

A **secret** is a named value stored in the Keychain (service `knsh`), or supplied by the authority with `secrets.provide` for a limited time and held only in memory. The definition format is in [../05-models/secret.md](../05-models/secret.md).

## Injection

| ID | Requirement |
| --- | --- |
| FR-SEC-01 | A secret must be injected as an environment variable only into supervised lines that match its `inject_for` patterns. |
| FR-SEC-02 | Lines that would receive a secret must ask unless a grant covers them. |
| FR-SEC-03 | A line that receives a secret must have its network narrowed to that secret's `hosts`, so the value can only be sent where it is meant to go. |
| FR-SEC-04 | Dynamic code must never receive secrets. |
| FR-SEC-05 | Profiles must limit process information to the command's own sandbox (proposed by decision 8, pending acceptance; a process group cannot be enforced safely), so other processes cannot read the injected environment or arguments. |
| FR-SEC-06 | `secret.injected` must report the secret's name and the command, never the value; the record's `secrets_injected` lists names only. |
| FR-SEC-07 | Authority-supplied secrets must be held only in memory, for the time given, and must be lost when `knshd` exits. `secrets.revoke` must remove them at once. |

Anything an injected line runs can read the secret, including npm lifecycle scripts. Prefer short-lived, narrowly scoped tokens supplied by the authority; presets can rewrite publishing commands to skip lifecycle scripts where the tool allows it.

## Redaction

| ID | Requirement |
| --- | --- |
| FR-SEC-10 | Redaction must replace the exact value and its base64, URL-encoded and hex forms, across chunk boundaries, with `«redacted:<name>»` (for example `«redacted:npm-token»`). |
| FR-SEC-11 | Redaction must run before anything is stored or emitted, including text sent to hooks and the authority. |

Redaction misses transformed values and files written to disk; it is a convenience, not a control.

### Redaction engine (KNSH-090)

The engine (`knsh_core::Redactor`) matches, for each secret value:

- the exact bytes;
- base64 in the standard and URL-safe alphabets, each with and without `=` padding;
- hex, lower and upper case;
- any percent-encoding: any subset of the bytes written as `%HH`, with hex digits of either case; or `+` for every
  space (a value whose spaces are written partly as `+` and partly otherwise is not matched). The standard base64 forms are also matched with their `+`, `/` and `=` escaped.

It works on a stream cut at arbitrary points. It holds back only the trailing bytes that could still begin a match: a
prefix of a form, or a `%` or `%H` not yet decoded. That is fewer than three times the longest decoded form (a fully
`%HH`-escaped value or its base64), so memory per stream stays bounded however much a command writes. Bytes that no
later match can reach are emitted at once, and the output is the same however the input was chunked.

- **Overlaps.** Overlapping matches, of two secrets or of two forms of one, are merged into one redacted span, so no
  byte of either is emitted. The marker names the secret of the longest match (ties: the earlier match).
- **End of a stream.** When a stream ends on a prefix of a form, the prefix is replaced by the marker too, so a stream
  cut mid-secret never emits part of it. A stream that ends with a byte that begins some secret's form therefore also
  ends with a marker. A lone trailing `%` is kept: it gives nothing away.
- **Not matched.** Substrings of a value; the value inside a longer text that was base64-encoded as a whole (for
  example `Authorization: Basic` of `user:token`), unless the value starts at a multiple of 3 bytes and ends the text
  or has a length that is a multiple of 3 (hex of a longer text is matched, since hex is byte-aligned); double
  encodings other than escaped standard base64; and, when a secret value itself holds `%`, an escape that a marker
  cut in two.
- **Size.** Values must be 1 byte to 64 KiB and at most 256 KiB together per redactor (`MAX_REDACTION_BYTES`); a
  larger set is refused, never partly built, so the caller can fail closed (KNSH-091). At the limit a redactor takes
  about 110 MB, and about 400 MB briefly while it is built.
- **Cost.** Linear in the output, except that output made of a secret's own hex-digit text in `%HH` escapes (which
  needs the secret) can cost up to the longest decoded form per byte.
