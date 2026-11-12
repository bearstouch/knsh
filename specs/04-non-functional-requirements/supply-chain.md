# Supply chain and dependencies

Kinetic Shell keeps third-party code to a minimum: every crate is code that runs with the user's privileges inside a security tool, and a supply-chain risk.

| Need | Approach | Third-party crates |
| --- | --- | --- |
| System calls | `libc` bindings, or hand-written `extern` declarations in `knsh-exec` | `libc` only |
| Keychain, XPC, FSEvents, sandbox, logging | Direct calls to the system's C interfaces | None |
| Touch ID prompt (LocalAuthentication) | Minimal hand-written Objective-C runtime calls, or the Swift helper | None |
| Hashing and policy signatures | CommonCrypto on macOS | None |
| Record store | The system SQLite library, called directly | None |
| Concurrency and I/O | Standard threads and kqueue; no async runtime | None |
| Network proxy | Hand-written HTTP CONNECT and SOCKS handling; TLS server name read from the handshake without decrypting | None |
| JSON-RPC | Hand-written reader and writer for the strict JSON profile and frame format, fuzzed in CI | None |
| Policy files | Hand-written parser for the TOML subset the spec uses | None |
| Bash parsing | In-house parser | None |

## Requirements

| ID | Requirement |
| --- | --- |
| NFR-SUP-01 | `knsh-exec` must have no third-party dependencies at all. |
| NFR-SUP-02 | Any new runtime crate must have a written justification and review, be pinned to an exact version, and be vendored into the repository. |
| NFR-SUP-03 | Build scripts must not download anything. |
| NFR-SUP-04 | CI must run licence, advisory and duplicate-version checks on the dependency tree. These tools are not shipped. |
| NFR-SUP-05 | Test-only crates (fuzzers, property testing) are allowed. |
| NFR-SUP-06 | Hand-written parsers for untrusted input (JSON, the TOML subset, bash, TLS handshakes) must be fuzzed continuously, because replacing a well-tested crate moves the risk into our own code. |
| NFR-SUP-07 | The Linux port's replacements for CommonCrypto and the Keychain must follow the same rules. |
