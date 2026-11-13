# Fuzzing

Replacing well-tested crates with hand-written parsers moves the risk into our own code, so every parser of untrusted input is fuzzed continuously.

| Target | Input source | Properties to check |
| --- | --- | --- |
| JSON reader | Untrusted processes on `agent.sock` | Strict profile enforced: valid UTF-8, no unpaired surrogates, no duplicate keys, integers within ±2^53, depth ≤ 32; non-conforming input rejected with `-32700`; no panics |
| Frame reader | Sockets | Frames over 1 MB rejected before allocation; partial and interleaved streams |
| JSON writer | Engine output | Everything emitted conforms to the strict profile (round-trip) |
| TOML subset parser | Policy and configuration files | No panics; rejects anything outside the subset |
| Bash parser | Agent command lines | No panics; unparseable input classified as dynamic; differential checks against bash |
| TLS ClientHello reader | Proxy connections | Server name extracted correctly or connection refused; no panics |
| HTTP CONNECT and SOCKS handling | Proxy connections | No panics; malformed requests refused |

Test-only crates (fuzzers, property testing) are allowed under the [dependency policy](../04-non-functional-requirements/supply-chain.md).

## Harness

The targets live in `fuzz/`, a test-only workspace outside the shipped one (NFR-SUP-05); its crates are vendored like every other dependency. Each target's properties are a plain function in `fuzz/src/checks.rs` (JSON) or `fuzz/src/toml_checks.rs` (TOML), which the stable test suite also runs over every seed and every saved crash (`fuzz/regressions/<target>/`), so a crash found once stays a failing test until it is fixed.

- **CI:** every push runs each target for 60 seconds (`scripts/fuzz.sh`) on a pinned nightly. A crash, a hang (over 10 seconds on one input) or a property failure fails the pipeline, and the crashing inputs are uploaded as an artefact.
- **Local:** `cargo +nightly fuzz run <target>` runs open-ended and grows the checked-in corpus; `scripts/fuzz.sh <seconds> <target>` runs time-boxed.
- **Allocation limit:** the frame reader target runs with `-malloc_limit_mb=2`: libFuzzer treats any single allocation of 2 MiB or more as a crash, which checks that no length prefix can make the reader allocate beyond the 1 MB payload limit (NFR-SEC-07).
- **Seeds:** the JSON reader starts from every strict-profile accept and reject sample; the frame reader from valid, interleaved, oversized, truncated and rule-breaking frame sequences; the TOML parser from the policy-profile and hook examples on their spec pages and accept and reject samples for each subset rule.
- **TOML round trip:** every document the TOML parser accepts is written out again by an independent writer in the fuzz crate (all tables inline) and must read back to an equal tree.
