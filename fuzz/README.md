# Fuzz targets

Fuzzing for the hand-written parsers of untrusted input (KNSH-005; NFR-SUP-05, NFR-SUP-06;
[`specs/07-testing/fuzzing.md`](../specs/07-testing/fuzzing.md)). Test-only: this directory is its own Cargo workspace,
excluded from the shipped one, and its crates (`libfuzzer-sys` and its dependencies) are vendored in `../vendor/` like
everything else.

| Target | Properties (see `src/checks.rs`) |
| --- | --- |
| `json_reader` | No panic; rejections are parse errors (`-32700`); accepted input is UTF-8, at most 32 levels deep, and round-trips through the writer unchanged |
| `json_writer_roundtrip` | Values built from fuzzer bytes are written as strict JSON that reads back equal, or refused exactly when deeper than 32 levels |
| `frame_reader` | No panic; every delivered frame obeys the framing rules against an independent model of the open streams; every error is fatal and sticky; run with `-malloc_limit_mb=2`, so no allocation reaches 2 MiB (NFR-SEC-07) |
| `toml_parser` | No panic; rejections name a line and column inside the input; accepted input is UTF-8, at most 32 levels deep, with every position inside the input, and round-trips through an independent TOML writer to an equal tree (KNSH-006) |
| `bash_lex` | No panic; deterministic; accepted lines are tiled exactly by token spans, words by their segments and quoted bodies by their inner segments, all on character boundaries; operator tokens spell their operator; rejections point inside the input and unterminated constructs run to its end (KNSH-028) |
| `bash_parse` | No panic; deterministic; fails exactly when the lexer fails, with the same error; on success every word and redirection token outside an unsupported construct is claimed exactly once by the tree, each part lies inside its command, simple commands come in source order, and every function call names earlier definitions (KNSH-029, KNSH-030) |

| `sandbox_log` | No panic; deterministic; an attributed entry is within its size limit, has exactly a report line and a tag line, its tag is that last line and reads back to itself, and its process, operation and argument are bounded and free of control characters with a count of at least 1 (KNSH-047) |
| `proxy_handshake` | No panic; deterministic; the same bytes read as an HTTP request head and as a SOCKS5 handshake; a head is delimited within its limits and ends with CRLF CRLF; accepted requests are within the grammar; every accepted destination prints back to itself, names normalised (KNSH-059) |

## Running

Needs a nightly toolchain and `cargo install --locked cargo-fuzz@0.13.2`. From the repository root:

```sh
scripts/fuzz.sh                  # CI smoke run: every target for 60 s, seeds read-only
scripts/fuzz.sh 600 frame_reader # one target for 10 minutes
cargo +nightly fuzz run <target> # open-ended local run; grows fuzz/corpus/<target>/
cargo +nightly fuzz run frame_reader -- -malloc_limit_mb=2   # keep the allocation check on long runs
```

`scripts/fuzz.sh` uses the pinned nightly it names (`scripts/fuzz.sh --print-toolchain`); any recent nightly works for
local runs.

## Layout

- `fuzz_targets/` — one-line libFuzzer entry points.
- `src/checks.rs` — the JSON properties. Also compiled on stable by `crates/knsh-json/tests/fuzz_regressions.rs`, so
  it depends only on `knsh-json` and `std`.
- `src/bash_checks.rs` — the bash lexer property. Also compiled on stable by `crates/knsh-bash/tests/fuzz_regressions.rs`,
  so it depends only on `knsh-bash` and `std`.
- `src/toml_checks.rs` — the TOML property. Also compiled on stable by `crates/knsh-toml/tests/fuzz_regressions.rs`,
  so it depends only on `knsh-toml` and `std`.
- `corpus/<target>/` — checked-in seeds. `json_reader` holds every KNSH-003 accept/reject sample (prefixed `accept_` and
  `reject_`; a test checks none is missing); `frame_reader` holds valid, interleaved, oversized, truncated and
  rule-breaking frame sequences; `json_writer_roundtrip` holds byte strings that build interesting values; `toml_parser` holds the policy-profile and hook
  examples from the spec byte for byte (a test checks they match) plus accept and reject samples for each subset rule; `bash_lex` holds agent-style lines covering every quoting form,
  operator and substitution (`accept_`) and each rejection (`reject_`; a test checks the prefixes match).
- `src/sandbox_log_checks.rs` — the sandbox denial log property. Also compiled on stable by
  `crates/knsh-platform/tests/fuzz_regressions.rs`, so it depends only on `knsh-platform`, `knsh-core` and `std`.
  Its seeds in `corpus/sandbox_log/` are the captured log lines of `crates/knsh-platform/fixtures/sandbox-log/`, one per
  file.
- `src/proxy_checks.rs` — the proxy handshake property. Also compiled on stable by
  `crates/knsh-proxy/tests/fuzz_regressions.rs`, so it depends only on `knsh-proxy` and `std`. Its seeds in
  `corpus/proxy_handshake/` are CONNECT requests (with and without credentials, malformed and oversized) and SOCKS5
  handshakes (CONNECT by name and address, BIND, UDP ASSOCIATE, no-authentication greetings) and a SOCKS4 request.
- `regressions/<target>/` — crashing inputs kept forever. When a run fails, libFuzzer saves the input in
  `artifacts/<target>/` (CI uploads it as the `fuzz-crashes` artefact); fix the bug, copy the input here, and
  `cargo test` replays it on stable (`fuzz_regressions_replay`).
