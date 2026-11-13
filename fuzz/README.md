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

The TOML target arrives with KNSH-006 and the bash target in phase 2.

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
- `src/checks.rs` — the properties. Also compiled on stable by `crates/knsh-json/tests/fuzz_regressions.rs`, so it
  depends only on `knsh-json` and `std`.
- `corpus/<target>/` — checked-in seeds. `json_reader` holds every KNSH-003 accept/reject sample (prefixed `accept_` and
  `reject_`; a test checks none is missing); `frame_reader` holds valid, interleaved, oversized, truncated and
  rule-breaking frame sequences; `json_writer_roundtrip` holds byte strings that build interesting values.
- `regressions/<target>/` — crashing inputs kept forever. When a run fails, libFuzzer saves the input in
  `artifacts/<target>/` (CI uploads it as the `fuzz-crashes` artefact); fix the bug, copy the input here, and
  `cargo test` replays it on stable (`fuzz_regressions_replay`).
