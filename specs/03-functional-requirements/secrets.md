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

### Injection (KNSH-092)

- **Which lines.** A command certainly matching an entry's `inject_for` (as an allow rule matches, FR-POL-16) makes
  the line receive that entry's secret as the entry's variable (FR-SEC-01). A line holding any dynamic code receives
  none, even approved or granted, and is not asked about one (FR-SEC-04).
- **Ask.** Such a command asks even when the rules allow it, with rule ID `secrets.env[N]` (the `N`-th variable in
  name order, zero-based): it runs with the secret only once the authority or the user approves it, or a grant covers
  it (FR-SEC-02). A command the rules deny stays denied. Under the `unattended` profile nobody can answer, so the line
  is denied unless a grant covers it.
- **Lookup.** After the decision and the checkpoint gate, each secret is looked up as KNSH-089 describes. The line
  is denied (`-32001`, source `standalone`, recorded) with a reason naming the secret when one is not found or
  cannot be read; when the entry's variable is one the engine sets (proxy settings, `DYLD_*`); when a value holds a
  NUL byte; or when the session's secrets changed since the line's redactor was taken, so the value would not be
  redacted from its output (the client sends the line again). A line never runs with some of its secrets missing.
- **Environment.** Each variable replaces any inherited one of the same name.
- **Network (FR-SEC-03, FR-NET-10).** The line reaches only a host the host rules open to it **and** that the
  `hosts` of every secret it receives list (matched like every host entry); any other is refused with
  `secret_hosts`. An entry with no `hosts` leaves the line no host. The narrowing applies to IP literals and
  internal addresses too (an address must also be listed in the secret's `hosts`), and the line gets no
  `network.loopback` ports, neither in its sandbox profile nor at the proxy.
- **Process information (FR-SEC-05).** Every line's profile limits process information to its own sandbox
  (decision 8), so no other process can read the injected environment.
- **Reporting (FR-SEC-06).** Once the line is spawned, `secret.injected` is published for each secret, after
  `command.started`, naming the secret and the line; its record's `secrets_injected` lists the secret names, sorted,
  each once. A line that was not spawned lists none.

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

### Redaction on every output path (KNSH-091)

- **The secret set.** A session redacts the secrets its profile names under `[secrets.env]` that `knshd` can read
  (as injection would read them, KNSH-089), and every live secret the authority provided with `secrets.provide`. A
  secret that cannot be read (not found, access denied) is left out: the engine never holds its value. A human
  session redacts the provided secrets.
- **One instance per session.** `knshd` keeps one redactor per session and reads the session's secrets again for
  each line: while they read the same, the same instance is used; a value provided, revoked, expired or changed in the
  Keychain gives a new one at once. The supervisor takes it once per line and uses that one instance on every path of
  the line, so hooks and the authority see exactly the text the record keeps (FR-REC-05). It is dropped when the
  session ends.
- **Paths.** The line text the pipeline gives hooks (their stdin), the authority (`decision.requested`), standalone
  approvals and `command.proposed`; the record's `command`, `rewritten_from`, `argv` names and `network` hosts; every
  lifecycle event (`command.started`, `command.long_running`, `command.finished`, `command.denied` with its rule and
  reason, `command.denied_repeatedly`, `proxy.denied`); `executed_command`; grant rules (a line holding a secret gets
  no grant); human records (`telemetry.command`). Captured output passes one redaction stream per output stream, so a
  secret split across two pipe reads is still replaced; the bytes a stream holds back are released, redacted, at end
  of file or when the capture is sealed. `command.output` chunks stay at most 8 KiB: a marker longer than what it
  replaced is split across chunks.
- **Rewrites (FR-AUTH-32).** A rewrite of a line whose redacted text holds a marker is refused and the line denied.
- **Fail closed.** A secret set the engine cannot redact (over the size limits above) denies every agent line of the
  session; what is recorded and published of the line is the plain `«redacted»` marker, nothing of its text. A human
  command is still recorded, as the marker, and never blocked. A line refused before its profile is loaded is
  redacted of the provided secrets only.
- **Not covered.** The caller's own descriptors under `knsh -c` get the line's raw output (FR-OUT-04: it never
  crosses the API). Reasons a hook or the authority write are redacted, but a `-32001` answer carries them as given.
