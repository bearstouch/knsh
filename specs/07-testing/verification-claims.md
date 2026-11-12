# Claims to verify before phase 2

The design relies on these platform behaviours. Each must be verified before phase 2.

| # | Claim | Test |
| --- | --- | --- |
| C1 | A sandboxed process cannot apply a second sandbox | Run Chromium, Playwright, `swift build` and the agent CLIs inside an envelope on macOS 14, 15 and current |
| C2 | Sandbox denials can be read from the system log as a non-admin user | `log stream` with the knsh tag: latency, duplicates, format |
| C3 | Per-file copy-on-write cloning is fast enough | Time a 100,000-file root; check files with unflushed memory-mapped writes |
| C4 | Flushing file events catches writes made milliseconds earlier by another process | Stress test with concurrent writers |
| C5 | Keychain items stay readable only by `knshd` across updates and Homebrew builds | Access-control behaviour for ad-hoc and Developer ID signatures |
| C6 | A launchd user agent can show the Touch ID prompt | LocalAuthentication from `knshd` with and without a logged-in GUI session |
| C7 | XPC peer code-signing requirements work on macOS 14 | Both directions, including after the peer execs |
| C8 | Seatbelt can limit process information, signals and Unix-socket connections as specified | One test per rule |
| C9 | Common tools honour per-command proxy credentials | curl, git, npm, pip, cargo and Node's HTTP clients |
| C10 | The proxy can read the TLS server name without decrypting | Check against curl, git and npm |

## Endpoint Security (macOS 27+)

Before relying on the descendant client:

- Which events it can authorise beyond exec (file opens, network).
- What happens to pending and later operations if `knshd` exits.
