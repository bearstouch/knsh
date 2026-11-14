# Claims to verify before phase 2

The design relies on these platform behaviours. Each must be verified before phase 2.

| # | Claim | Test |
| --- | --- | --- |
| C1 | A sandboxed process cannot apply a second sandbox | Run Chromium, Playwright, `swift build` and the agent CLIs inside an envelope on macOS 14, 15 and current. **Confirmed on macOS 26.6** ([results](#c1-sandbox-nesting)); macOS 14 and 15 and Codex CLI pending |
| C2 | Sandbox denials can be read from the system log as a non-admin user | `log stream` with the knsh tag: latency, duplicates, format. **Read without root on macOS 26.6, from an account in `admin`; best effort with gaps** ([results](#c2-denials-in-the-unified-log)); a standard (non-admin) account and macOS 14 and 15 pending |
| C3 | Per-file copy-on-write cloning is fast enough | Time a 100,000-file root; check files with unflushed memory-mapped writes |
| C4 | Flushing file events catches writes made milliseconds earlier by another process | Stress test with concurrent writers |
| C5 | Keychain items stay readable only by `knshd` across updates and Homebrew builds | Access-control behaviour for ad-hoc and Developer ID signatures |
| C6 | A launchd user agent can show the Touch ID prompt | LocalAuthentication from `knshd` with and without a logged-in GUI session |
| C7 | XPC peer code-signing requirements work on macOS 14 | Both directions, including after the peer execs |
| C8 | Seatbelt can limit process information, signals and Unix-socket connections as specified | One test per rule. **Enforceable on macOS 26.6, partly with different rule forms; gaps listed** ([results](#c8-process-information-signals-sockets-and-services)); macOS 14 and 15 pending |
| C9 | Common tools honour per-command proxy credentials | curl, git, npm, pip, cargo and Node's HTTP clients |
| C10 | The proxy can read the TLS server name without decrypting | Check against curl, git and npm |
| C11 | Engine directories are kept out of Spotlight (KNSH-011) | **Observed failing on macOS 26.6:** a uniquely named file in a non-hidden directory holding `.metadata_never_index` below the volume root was found by `mdfind`; files under a `*.noindex` directory, a hidden directory and `~/Library/Application Support/` were not. Choose a working mechanism, then check on macOS 14, 15 and current that `mdfind` does not find a file in each engine directory after indexing settles |

## Seatbelt results (KNSH-025: C1, C2, C8)

Observed on 2026-11-14 on an Apple M1 Pro, macOS 26.6.2 (25G83), SIP on. The account is a member of `admin`, but
nothing ran as root or through `sudo`. The harnesses, the hand-written envelope profile, raw results and log fixtures
are in [`spikes/knsh-025-seatbelt/`](../../spikes/knsh-025-seatbelt/README.md); rerun them on each macOS version.
Facts marked *(ad hoc)* were observed in exploratory runs on the same machine whose output is not kept in `results/`;
facts marked *(review)* were first observed by the independent review of KNSH-025, then added to the harness and
recorded in `results/`.

**Pending (not observed, not claimed):** macOS 14 and 15; a standard (non-admin) account for C2; Codex CLI for C1 (the
installed 0.165.0 binary is quarantined and stalls in `dyld` before `main`, even outside any sandbox, so it never ran).

Facts that hold across all three claims:

- **Canonical paths only.** `(literal "/etc/hosts")` does not match a read of `/etc/hosts`; `/private/etc/hosts`
  does *(ad hoc, confirmed in review)*. A symlink to a denied socket, or a `/var/…` spelling of a `/private/var/…`
  path, is still denied: the kernel checks the resolved path.
- **setuid binaries cannot run in any sandbox**, even `(allow default)`: `exec` of `/bin/ps` fails with `EPERM` and
  logs `forbidden-exec-sugid` (untagged).

### C1: sandbox nesting

Each tool ran three ways: unsandboxed (control), inside the envelope with its own sandbox on, and inside the envelope
with its own sandbox off. "Works" means it printed a random marker it could only produce by doing the work.

| Tool | Own sandbox on, in envelope | Own sandbox off, in envelope |
| --- | --- | --- |
| Chromium headless shell (Playwright build 1243) | **Fails:** every child prints `sandbox initialization failed: Operation not permitted`; exit 133 | Works (`--no-sandbox`) |
| Google Chrome.app, envelope as specified (LaunchServices denied) | Aborts at start-up (SIGABRT, exit 134), before any sandbox step | Aborts the same way: the app needs LaunchServices |
| Google Chrome.app, LaunchServices allowed | **Fails,** exit 133 (same as the headless shell) | Works (`--no-sandbox`) |
| Playwright (`playwright-core` 1.56.1, Node 22) | `chromiumSandbox: true`: **fails** (`Target page, context or browser has been closed`) | Works: `chromiumSandbox: false` is Playwright's default |
| `swift build` (Swift 6.4, Xcode, macOS 27.0 SDK) | **Fails:** `Invalid manifest … sandbox-exec: sandbox_apply: Operation not permitted` | Works (`--disable-sandbox`) |
| Claude Code 2.1.325 | **Fails:** each shell command gets `sandbox-exec: sandbox_apply: Operation not permitted` (exit 71) with `allowUnsandboxedCommands: false`. With default settings the model retried the command unsandboxed and succeeded *(earlier run, not kept in `results/`)* | Works (`sandbox.enabled: false`) |
| Codex CLI 0.165.0 | **Pending** (blocked, see above) | **Pending** |

- **Refinement of C1:** applying a profile with the same rules as the current one succeeds (exit 0), even when its
  text differs in comments; any profile with different rules, stricter or looser, fails with `sandbox_apply:
  Operation not permitted` (exit 71) *(ad hoc, confirmed in review)*. knsh never relies on this.
- SwiftPM sandboxes only manifest *evaluation*. A manifest cached by an earlier unsandboxed run
  (`~/Library/Caches/org.swift.swiftpm`) hides the failure, so `swift build` can pass once and fail later.
- An agent CLI with its own sandbox off runs correctly inside an envelope: **confirmed for Claude Code**; Codex CLI
  pending. Its denials did not stop it: `~/.local/state/claude/locks` writes, binding a Unix socket in
  `/private/tmp/cc-socks/`, `who` writing `utmpx`. It needs either DNS or the proxy (C9) to reach its API. Its
  process name in log entries is its version (`2.1.325`), not `claude`.
- Chrome also needs to bind its own `SingletonSocket` under `$TMPDIR` (`network-bind (local unix-socket …)`).
  Binding is separate from connecting and does not weaken the socket rules.

**Trusted-tools compatibility list (KNSH-076), from these results:** Chromium and Chrome must run with
`--no-sandbox`; Playwright with its default `chromiumSandbox: false`; `swift build`, `swift test` and `swift run` with
`--disable-sandbox`; Claude Code with `sandbox.enabled: false`; Codex CLI with `--sandbox danger-full-access` (pending
verification). Full app bundles (Chrome.app) also need LaunchServices, which the envelope denies: use the headless
shell, or list the app as a trusted tool (FR-SBX-09). Anything that runs a setuid binary (`ps`, `top`, `sudo`,
`login`) cannot run in any profile.

### C2: denials in the unified log

Reader: `/usr/bin/log stream --style ndjson --predicate 'sender == "Sandbox" AND eventMessage CONTAINS "knsh:"'`,
run as the logged-in user without `sudo`. It works, and `log show` reads the same entries afterwards.

**Format.** Entries come from the kernel: `processImagePath` is `/kernel`, `senderImagePath` is the Sandbox kext,
`processID` is 0, `messageType` is `Error` and `formatString` is `%s`. The pid is only inside the text:

```text
Sandbox: <process name>(<pid>) deny(1) <operation> [<argument>]\n<tag>
<N> duplicate report[s] for Sandbox: <process name>(<pid>) deny(1) <operation> [<argument>]\n<tag>
```

The argument depends on the operation:

| Operation | Argument | Example |
| --- | --- | --- |
| File | canonical path | `file-read-data /private/etc/hosts` |
| Mach lookup and register | service name | `mach-lookup com.knsh.control`, `mach-register com.apple.axserver (per-pid)` |
| Unix socket | socket path | `network-outbound /private/var/…/user.sock` |
| IP | port only, no address | `network-outbound remote:*:53` |
| Process info | target | `process-info-pidinfo others [sleep(38901)]`, `process-info-listpids` |
| Sysctl | name with pid | `sysctl-read kern.procargs2.38901` |
| Job creation | none | `job-creation` |

Real samples for each shape are kept in
[`spikes/knsh-025-seatbelt/fixtures/macos-26.6.2/`](../../spikes/knsh-025-seatbelt/fixtures/macos-26.6.2/) for KNSH-047.

**Tag.** The `(with message "…")` text becomes the last line of the entry, verbatim. A 97-character tag holding two
ULIDs, `/`, `;` and `"` survived intact. `(deny default (with message "…"))` tags default denials too, with two
exceptions: `job-creation` reached through the default was logged **untagged** (2 of 2 runs, while an explicit
tagged `deny job-creation` was tagged), and built-in refusals such as `forbidden-exec-sugid` are never tagged.

**Measurements (macOS 26.6.2):**

| Measure | Result |
| --- | --- |
| Latency from spawn to arrival in the stream, 50 single denials | p50 38 ms, p95 43 ms, max 44 ms (an earlier, unrecorded run: p50 23, p95 29). Includes starting `sandbox-exec`, so it is an upper bound |
| Same process, same operation and path, 20 times | 2 entries: the first at once, then `19 duplicate reports for <first entry>`, with the tag, 20 ms later. The delay varies: in the C8 run, summaries came 0.05 s to 2.4 s after the first entry |
| Same profile, 20 separate processes | 20 entries (no merging across processes) |
| One process, 300 distinct paths | 300 entries |
| 100 processes back to back, one denial each | 100 received |
| 50 processes each causing 11 denials (550 total) | All received |
| Time until `log stream` delivers | 0.27 s in the recorded run; over 2 s in earlier runs *(ad hoc)*. Denials before that never reach the stream |

**What is not reported (the reader must be best effort):**

- **Signal denials: never** (0 of 10 here, and 0 in every C8 run).
- **A denied access to a path that does not exist** returns `ENOENT`, not `EPERM`, and is not logged.
- **Intermittent loss:** in 3 of 4 C8 runs with a stream confirmed live, between 2 and 7 of about 30 expected entries
  never arrived, and they were missing from `log show` too, so the kernel or `logd` dropped them *(ad hoc: only the
  last run is kept)*. In the recorded run, the tagged entries of `svc-control-lookup` and
  `svc-named-lookup-registered` are missing, and so is the first entry of `svc-dns-localhost` (only its `1 duplicate
  report` arrived). It is not explained by bursts (see the 100-process run). Cause unknown.
- **One noisy process** can log hundreds of denials in a fraction of a second (the C8 LaunchServices query produced a
  `409 duplicate reports` entry for one service within 0.2 s), so the reader must merge entries and bound its memory.

**Exit question: can KNSH-047 attribute a denial by tag alone?** For **supervised lines, yes**, provided the compiler
puts the session and command (record) IDs and the rule in every tag, and gives every operation it relies on an
explicit tagged deny instead of depending on the default. Each line gets its own compiled profile anyway (FR-SBX-07).
For **commands run directly inside an envelope, only the session**: they share the envelope's profile, so the
command can only be guessed from the pid in the message. Signal denials, `ENOENT` cases, dropped entries and built-in
refusals cannot be attributed at all. The reader must also check that its stream is live (a canary denial) before
treating "no entries" as "no denials".

### C8: process information, signals, sockets and services

One case per rule, run under a deny-by-default base profile plus the rule under test: 47 cases, all matching the
expected outcomes in [`results/c8-26.6.2.tsv`](../../spikes/knsh-025-seatbelt/results/c8-26.6.2.tsv), including the
four the review added (`sig-pgrp-outside-group` and three `pinfo-procargs-env-nonplatform*` cases). The SBPL forms
below answer KNSH-045's question of which operations and filters to use for each rule.

| Spec rule ([sandbox profiles](../03-functional-requirements/sandbox-profiles.md)) | Result | SBPL form for KNSH-045 |
| --- | --- | --- |
| Signals: own process group only | **Enforceable differently.** `(target pgrp)` exists and works (it denies a process in another group *(review)*), but it also allows unsandboxed processes in the group, and a sandboxed process can `setpgid(2)` into another group of the same session and then signal it (observed). `same-sandbox` means the same sandbox *instance*: two applications of identical profile bytes are not peers *(ad hoc, confirmed in review)*. Signal denials are never logged | `(allow signal (target same-sandbox))` under `(deny default)` |
| Process information: own process group only | **Enforceable differently; needs two rules.** `(deny default)` does **not** cover it: `proc_pidinfo` of another process succeeds unless process-info is denied explicitly. Reading another process's argv (`KERN_PROCARGS2`) or `kinfo_proc` (`KERN_PROC_PID`, `KERN_PROC_ALL`) is allowed when *either* the process-info rule *or* the sysctl rule allows it; each rule on its own leaves them readable. `proc_listpids` has no per-target filter, so it is denied for everyone. With both rules, a process still sees itself and its own sandbox | `(deny process-info* (with message …))` `(allow process-info* (target same-sandbox))` `(deny sysctl-read (sysctl-name-prefix "kern.procargs") (sysctl-name-prefix "kern.proc.") (with message …))` |
| Other processes' arguments and environment stay hidden | **Enforceable** with the two rules above: `KERN_PROCARGS2` is denied as a whole, so neither arguments nor environment can be read. **The rules are needed for the environment too.** macOS 26.6 omits the environment from `KERN_PROCARGS2` only for Apple platform binaries (the recorded victim, `/bin/sleep`). For a non-platform binary of the same user (an ad-hoc-signed copy of `sleep`, Homebrew `python3`), any process allowed to read `KERN_PROCARGS2` sees the full environment, including the test secret *(review)*. `ps -E` cannot run in any sandbox (setuid) | As above |
| Unix sockets: `agent.sock` for envelopes, none for commands; `user.sock`, Docker and SSH agent denied | **Enforceable as specified.** The explicit `user.sock` deny wins over a broad `(allow network-outbound)`. A symlink or a non-canonical path is still denied | `(allow network-outbound (remote unix-socket (path-literal "<agent.sock>")))` `(deny network-outbound (remote unix-socket (path-literal "<user.sock>")) (with message …))`. Docker and SSH agent are covered by the default deny. Binding one's own socket is `network-bind (local unix-socket …)` |
| LaunchServices (`open`) denied | **Enforceable.** A LaunchServices query fails (`-10661`), and `open -g -a TextEdit` reports that it cannot find the app and launches nothing. `open -R <dir>` still exits 0; whether Finder revealed the folder was not observed. App bundles such as Chrome.app abort without LaunchServices | `(deny mach-lookup (global-name "com.apple.coreservices.launchservicesd" "com.apple.lsd.mapdb" "com.apple.lsd.modifydb" "com.apple.CoreServices.coreservicesd") (with message …))` |
| Apple Events denied | **Enforceable**, but `osascript` **hangs** (killed after 10 s) instead of failing fast | `(deny mach-lookup (global-name "com.apple.coreservices.appleevents") (with message …))` |
| launchd job submission denied | **Enforceable.** `launchctl submit`, `bootstrap` and `load` are all denied. `(deny default)` already covers it, but untagged | `(deny job-creation (with message …))` |
| The knsh control service and named Mach lookups denied | **Enforceable.** `bootstrap_look_up` returns 1100 (permission denied) instead of 1102 (unknown service) | `(deny mach-lookup (global-name "<service>") (with message …))` |
| DNS resolver denied | **Enforceable for the system resolver:** `curl` and `dscacheutil` cannot resolve. `getaddrinfo("localhost")` and numeric hosts still work. **Gap:** a tool that sends DNS over UDP itself (`host(1)`) bypasses it, and is stopped only by the network rule (outbound to the proxy port only), which was observed to deny `remote:*:53` | `(deny mach-lookup (global-name "com.apple.dnssd.service") (with message …))` `(deny network-outbound (remote unix-socket (path-literal "/private/var/run/mDNSResponder")) (with message …))` |

Proposed spec and decision changes from these results are in [decisions](../09-reference/decisions.md) (decisions 8 to
10) and the [sandbox profiles](../03-functional-requirements/sandbox-profiles.md) notes.

## Endpoint Security (macOS 27+)

Before relying on the descendant client:

- Which events it can authorise beyond exec (file opens, network).
- What happens to pending and later operations if `knshd` exits.
