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

Test-only crates (fuzzers, property testing) are allowed under the [dependency policy](../nonfunctional-requirements/supply-chain.md).
