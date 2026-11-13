# Security

The engine protects the user from agents running as the same macOS user, not from other software the user runs outside the engine.

## Threat model

| Threat | Mitigation | Requirements |
| --- | --- | --- |
| An agent approves its own request | Control is an XPC service with a peer code-signing requirement; envelopes cannot look it up or reach `user.sock`; user approvals need Touch ID shown by `knshd` | FR-AUTH-12–16, FR-AUTH-41–43 |
| An agent slips past command rules (`eval`, interpreters, absolute paths, wrappers) | Command rules are intent filters. Hard limits are the envelope and per-command sandbox, kernel-enforced executable rules, the proxy and credential scoping; dynamic code never inherits network or secrets | FR-LC-05, FR-POL-20–21, FR-SBX-04 |
| A binary is swapped between classification and execution | Lines run with resolved absolute paths; executables must sit in trusted folders or paths the profile names | FR-LC-13, FR-LC-15 |
| An agent escapes through LaunchServices, Apple Events or launchd | Those system services are denied in every profile; `open`, `osascript` and `launchctl` are also denied by rule | FR-SBX-02 |
| An agent plants code that runs later outside the sandbox | Fixed write denies for git hooks and config, shell startup files and LaunchAgents | FR-SBX-02 |
| An agent edits policy, hooks or trust | Envelopes cannot write engine paths; policy files are signed by `knshd`; trust lives in the Keychain | FR-POL-40–42, FR-HOOK-07, FR-AUTH-11 |
| An agent kills `knshd` or squats its endpoints | Envelopes cannot signal outside their process group; launchd owns the endpoints; with `knshd` gone, no agent line runs | NFR-REL-01 |
| An impostor daemon or authority | launchd-owned names plus code-signing checks in both directions | FR-AUTH-12–15 |
| An agent leaks a secret | Secrets go only to approved matching lines, whose network is narrowed to the secret's hosts; process information is limited; redaction as a convenience | FR-SEC-01–05 |
| An agent sends data out | Per-command host rules, `approval_hosts`, name and address checks, no local DNS. Residual risk: allowlisted hosts that accept uploads | FR-NET-01–08 |
| Approval fatigue | Grants, `policy.check` dry runs, rate limiting of repeated denials, irreversible flags | FR-POL-60–70, FR-HOOK-20, FR-IRR-05 |

### Out of scope

- Malware running outside any session
- A compromised authority
- A malicious hook the user installed
- Flaws in the macOS sandbox itself

## Requirements

| ID | Requirement |
| --- | --- |
| NFR-SEC-01 | `knshd` must run with the user's permissions, with no root privileges, and never serve another macOS user. |
| NFR-SEC-02 | Every agent shell command must be spawned by the supervisor; nothing inside an envelope may grant itself more than the envelope allows. |
| NFR-SEC-03 | All hard limits must be enforced by the operating system (sandbox, executable rules), the proxy or credential scoping, never by command rules alone. |
| NFR-SEC-04 | Every security-changing action from a user process (approval, grant, policy edit, profile selection, authority trust) must require Touch ID or the user's password, checked inside `knshd`. |
| NFR-SEC-05 | Code that parses agent-controlled input must be memory-safe (Rust), and hand-written parsers for untrusted input must be fuzzed continuously ([fuzzing](../07-testing/fuzzing.md)). |
| NFR-SEC-06 | The JSON parser must enforce the strict JSON profile, including rejecting duplicate keys ([wire format](../06-api/wire-format.md)). |
| NFR-SEC-07 | Frames over the size limit must be rejected before memory is allocated for them. |
| NFR-SEC-08 | Engine files must be readable by the user only. |
| NFR-SEC-09 | Hooks are a trusted extension point: hook input contains agent-controlled text and hooks must never pass it to a shell ([hooks integration](../08-integrations/hooks.md)). |
| NFR-SEC-10 | The engine must report what it can guarantee on this machine (`hello` capabilities) instead of silently degrading. |
