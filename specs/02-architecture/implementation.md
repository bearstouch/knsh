# Implementation

## Language

Kinetic Shell is written in **Rust** wherever possible, because the engine parses agent-controlled input in long-running, security-critical processes, and memory safety rules out the classic ways such tools are broken.

- `knsh`, `knshd` and `knsh-exec` are Rust.
- `knsh-exec` stays small and single-threaded, with no async runtime and no third-party dependencies.
- Concurrency and I/O use standard threads and kqueue; there is no async runtime anywhere.

## Platform interface

- macOS services (XPC, Keychain, LocalAuthentication, FSEvents, the sandbox entry points) sit behind **one internal platform interface**, reached through Rust bindings and direct calls to C functions.
- The Linux backends implement the same interface later ([platform support](platform-support.md)).
- If a macOS service is impractical to reach from Rust, that one piece may become a small **Swift helper** behind the same interface.
- Nothing on the decision or enforcement path leaves Rust.

## Bash parser

- The bash parser is written in-house.
- Existing Rust shells such as brush serve as references and test oracles, not dependencies.
- Anything the parser cannot read with confidence is classified as **dynamic code**, so gaps in the parser fail closed. Parser scope is defined in decision 6 ([decisions](../reference/decisions.md)) and its exit criterion in [conformance](../testing/conformance.md).

## Hand-written components

Because of the [dependency policy](../nonfunctional-requirements/supply-chain.md), the following are written in-house and fuzzed continuously ([fuzzing](../testing/fuzzing.md)):

- JSON-RPC reader and writer for the strict JSON profile and frame format
- Parser for the TOML subset used by policy and configuration files
- Bash parser
- HTTP CONNECT and SOCKS handling, and the TLS server name reader in the proxy
