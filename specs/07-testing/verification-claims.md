# Claims to verify before phase 2

The design relies on these platform behaviours. Each must be verified before phase 2.

| # | Claim | Test |
| --- | --- | --- |
| C1 | A sandboxed process cannot apply a second sandbox | Run Chromium, Playwright, `swift build` and the agent CLIs inside an envelope on macOS 14, 15 and current. **Confirmed on macOS 26.6** ([results](#c1-sandbox-nesting)); macOS 14 and 15 and Codex CLI pending |
| C2 | Sandbox denials can be read from the system log as a non-admin user | `log stream` with the knsh tag: latency, duplicates, format. **Read without root on macOS 26.6, from an account in `admin`; best effort with gaps** ([results](#c2-denials-in-the-unified-log)); a standard (non-admin) account and macOS 14 and 15 pending |
| C3 | Per-file copy-on-write cloning is fast enough | Time a 100,000-file root; check files with unflushed memory-mapped writes. **Partially verified on macOS 26.6 (warm cache): 7.3–7.7 s with 4 threads at normal or utility QoS, 11.6–12.4 s single-threaded, 33–51 s in the background band; a clone holds unflushed mapped stores, but mapped writes never change `mtime` and a clone during continuous stores is torn** ([results](#c3-copy-on-write-shadows)); macOS 14 and 15 and cold cache pending |
| C4 | Flushing file events catches writes made milliseconds earlier by another process | Stress test with concurrent writers. **Refuted for a flush alone on macOS 26.6 (26–99.9% of a line's events missed); verified for a marker file plus repeated flushes (no event missed in any round without a drop flag, 1, 4 and 16 writers); 16 writers cause `UserDropped\|MustScanSubDirs` on the root in 68–93% of lines** ([results](#c4-file-event-flushing-with-concurrent-writers)); macOS 14 and 15 pending |
| C5 | Keychain items stay readable only by `knshd` across updates and Homebrew builds | Access-control behaviour for ad-hoc and Developer ID signatures. **On macOS 26.6: holds across updates for Developer ID only; refuted for ad-hoc and Homebrew builds; any same-user process can overwrite the value unless sandboxed** ([results](#c5-keychain-access-control)); macOS 14 and 15 and the data-protection keychain with a provisioning profile pending |
| C6 | A launchd user agent can show the Touch ID prompt | LocalAuthentication from `knshd` with and without a logged-in GUI session. **Confirmed on macOS 26.6 with the password fallback (lid closed), custom text shown in full** ([results](#c6-localauthentication-from-a-launchd-agent)); the Touch ID sensor, an SSH login with nobody at the console, cancellation and timeout pending |
| C7 | XPC peer code-signing requirements work on macOS 14 | Both directions, including after the peer execs. **Confirmed on macOS 26.6 with APIs available since macOS 12 and earlier** ([results](#c7-xpc-peer-code-signing-requirements)); macOS 14 and 15 pending |
| C8 | Seatbelt can limit process information, signals and Unix-socket connections as specified | One test per rule. **Enforceable on macOS 26.6, partly with different rule forms; gaps listed** ([results](#c8-process-information-signals-sockets-and-services)); macOS 14 and 15 pending |
| C9 | Common tools honour per-command proxy credentials | curl, git, npm, pip, cargo and Node's HTTP clients. **Confirmed on macOS 26.6 for an HTTP proxy URL with user and password; Node needs `NODE_USE_ENV_PROXY=1` (22.23 and 24.21 observed; 22.20 ignores proxies), git sends credentials only after a `407` challenge; SOCKS5 fails for pip and Node** ([results](#c9-per-command-proxy-credentials)); macOS 14 and 15 and a real envelope pending |
| C10 | The proxy can read the TLS server name without decrypting | Check against curl, git and npm. **Confirmed on macOS 26.6 for curl, git, npm, pip, cargo and Node: every ClientHello names the requested host, none offers Encrypted Client Hello** ([results](#c10-tls-server-names)); macOS 14 and 15 pending |
| C12 | A Unix-socket peer's audit token names it by pid and pid version, and the process table can be walked by unique id (KNSH-048) | `getsockopt(LOCAL_PEERTOKEN)` pid version equals `proc_pidinfo(PROC_PIDUNIQIDENTIFIERINFO).p_idversion` for the same process; parents read with `PROC_PIDT_SHORTBSDINFO` and checked by unique id; both readable without an entitlement for the same user. **Observed on macOS 26.6.2 (Apple silicon) by the `knsh-platform` and `knshd` tests**, including a walk from a test process up to `launchd` (pid 1). **The pid version also changes on every `exec`, while `p_uniqueid` does not** (observed on macOS 26.6.2: `exec_changes_the_version_but_not_the_key`), so envelope roots and ancestors are matched by unique id and only the peer by pid version; macOS 14 and 15, and processes running inside a Seatbelt envelope, pending. Whether `p_puniqueid` follows a re-parenting to `launchd` was not observed: either way a re-parented process is refused, never matched to a wrong envelope |
| C13 | A process inside a Seatbelt envelope can pass its stdio to `knshd` over `agent.sock` with `SCM_RIGHTS`, and a line `knshd` starts on those descriptors writes to the caller's terminal or pipes (KNSH-049) | `sendmsg` with three descriptors from inside an envelope profile that allows connecting to `agent.sock`; the supervisor's child writes to the passed stdout. **Observed outside any sandbox on macOS 26.6.2 (Apple silicon)** by the `knsh-platform`, `knshd` and `knsh` tests (socket pairs, the real server reader, and the real `knsh` binary against a stand-in supervisor); inside a Seatbelt envelope (KNSH-057), and macOS 14 and 15, pending. **Observed on macOS 26.6.2 (KNSH-049 review): a truncated `SCM_RIGHTS` message installs the descriptors that did not fit in the receiver's buffer anyway, unreported**, and one `sendmsg` carries at most 254; so the receiver reads into room for 1024 (never truncated) and refuses, closing, any message of more than three. Recheck both on macOS 14 and 15 |
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
- **Case-insensitive matching** *(KNSH-044, ad hoc; the `.git` cases are in the `knsh-sandbox` integration test)*: on
  the case-insensitive data volume, `(regex #"/\.git/hooks(/|$)")` also denies `.GIT/HOOKS/x` and `.Git/hooks/x`, even
  when the directories are new, and `(literal "…/zshrc")` denies `…/ZSHRC`.
- **Renames into protected paths** *(KNSH-044, in the `knsh-sandbox` integration test)*: with only the `.git/hooks`
  and `.git/config` regexes, a directory holding `hooks/pre-commit` can be renamed to `<repo>/.git`, and the real
  `.git` renamed away. Adding `(regex #"/\.git$")` denies both, while `git commit`, `git checkout -b` and `git gc`
  still succeed.
- **Other git directories** *(KNSH-044; git 2.54, in the `knsh-sandbox` integration test)*: writing only
  `.git/commondir` (a path to a planted directory with `hooks/` and `config`) makes `git commit` run the planted
  hook, and submodule git directories in `.git/modules/<name>` have their own `hooks/` and `config`. The rules
  `(regex #"/\.git/(.+/)?hooks(/|$)")`, `(regex #"/\.git/(.+/)?(config|config\.worktree|commondir)$")` and
  `(regex #"/\.git/(.+/)?(modules|worktrees)(/[^/]+)?$")` deny those writes and renaming a submodule or worktree git
  directory out and back, while commits in the repository, a submodule and a linked worktree, `git checkout -b`,
  `git gc` and `git status` still succeed.
- **Renaming an ancestor** *(KNSH-044, in the `knsh-sandbox` integration test)*: a subpath deny does not cover its
  parent, so with a write root above it `~/.config` could be renamed away, the engine files read and changed at
  the new path, and the directory renamed back. `(deny file-write* (literal "<ancestor>"))` on each ancestor denies
  the rename while files can still be created and removed inside it. Hard links to a write-denied file fail
  (`ln` gets `EPERM`), so they need no rule.
- **String literals**: inside `"…"` only `\` and `"` need escaping. Paths holding `"`, `\`, `)`, `;`, a newline, a tab
  or `é` match exactly once escaped that way; an unescaped `"` ends the string, and the rest is read as profile code
  *(KNSH-044, ad hoc)*. APFS refuses names that are not UTF-8.
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

**KNSH-047 (2026-11-15, same machine, macOS 26.6.2, account in `admin`, no `sudo`):** samples with the compiler's tag
form `knsh:<session>:<record or env>:<rule>` were captured with `sandbox-exec -p` and `log stream --style ndjson`, and
are kept with the KNSH-025 ones in
[`crates/knsh-platform/fixtures/sandbox-log/macos-26.6.2/`](../../crates/knsh-platform/fixtures/sandbox-log/macos-26.6.2/)
(user folder names replaced by `XX`), where the parser's tests read them. Observed: `log stream` prints a non-JSON
header line (`Filtering the log data using …`) before any entry, even with `--style ndjson`; the tag of an `env`
command and of a rule name holding `[` `]` (`fs.deny[0]`) arrives verbatim; a path holding a space and `"` arrives
unescaped in the message; 9 reads of one denied file by one process gave one entry plus `8 duplicate reports`; the
`osascript` Apple Events lookup of that run was not logged (an instance of the intermittent loss above). The
`macos_denials` integration test sees its own canary come back through `log stream` (0.4 s in the recorded run)
and leaves no `log` process behind. Pending: a standard (non-admin) account, macOS 14 and 15.

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

#### Compiled profiles (KNSH-045)

Observed on the same machine (macOS 26.6.2) while compiling the rest of the table; the cases marked *(integration)* are
in the `knsh-sandbox` integration tests, which run the compiled profiles through `sandbox-exec -f`:

- **Exec rules match the resolved path** *(ad hoc)*: `(allow process-exec (subpath "/opt/homebrew/bin"))` does not
  let `/opt/homebrew/bin/python3` run (a link into `/opt/homebrew/Cellar`), and `/usr/bin/git`, `python3`, `clang`
  fail with `can't exec '/Applications/Xcode.app/Contents/Developer/usr/bin/…'` until the developer directory is
  allowed. With the system tool folders, `git status`, `clang --version`, `xcrun --find clang`, `make` and `python3`
  subprocesses run *(git: integration)*.
- **Project executables** *(integration)*: a script and an ad-hoc-signed binary in the project do not run, directly or
  from a child shell, with `project_executables = "deny"`, and run with `"allow"`. A plain copy of a platform binary
  (`cp /bin/echo`) is killed by the system (`SIGKILL`) even outside any sandbox, so it is no test. `sh x.sh` still runs
  a project script under `deny`: the script is read, not executed *(ad hoc)*.
- **Services** *(integration)*: `open -g -a Safari` fails (`Unable to find application`) and `osascript` sending an
  Apple Event to Finder hangs and is killed. `osascript -e 1` **succeeds**: it sends no Apple Event, so the story's
  check uses an event to Finder. `launchctl submit` fails; `curl` cannot resolve a name *(ad hoc)*.
- **Sockets** *(integration)*: under `(deny file-read* file-write* (subpath <engine data dir>))`, an envelope still
  connects to `run/agent.sock` through its `(remote unix-socket (path-literal …))` allow, while `user.sock` is refused;
  a command reaches neither. Binding a socket in an engine directory fails with `EPERM` *(ad hoc)*.
- **Network** *(integration)*: `nc -z` reaches the proxy's port on `127.0.0.1` (`(remote ip "localhost:<port>")`),
  but not another loopback port or `1.1.1.1:443`.
- **Signals and settings**: `kill -0` of an unsandboxed process fails *(integration)*; `defaults read` works and
  `defaults write` fails *(ad hoc)*.
- **Pending:** macOS 14 and 15; which Mach services command-line tools need (the profile allows all but the denied
  ones); Homebrew binaries started by a child by name (their Cellar targets are not covered by the trusted folder).

Proposed spec and decision changes from these results are in [decisions](../09-reference/decisions.md) (decisions 8 to
10) and the [sandbox profiles](../03-functional-requirements/sandbox-profiles.md) notes.

## Code-signed identity results (KNSH-026: C5, C6, C7)

Observed on 2026-11-14 on an Apple M1 Pro, macOS 26.6.2 (25G83), SIP on, from an account in `admin`; nothing ran as
root. The lid was closed (an external display was in use). Developer ID builds were signed with a real "Developer ID
Application" certificate, hardened runtime, no secure timestamp, and not notarized. The harnesses and raw results are
in [`spikes/knsh-026-identity/`](../../spikes/knsh-026-identity/README.md); rerun them on each macOS version.

**Pending (not observed, not claimed):** macOS 14 and 15 for all three claims; the Touch ID sensor itself (the lid was
closed, so every prompt offered only the password); C6 from an SSH login with nobody logged in at the console (Remote
Login was off); C6 cancellation and timeout outcomes (the person at the Mac typed the password every time); the
data-protection keychain with a provisioning profile; an App Store-signed authority.

### C5: Keychain access control

One probe binary, compiled twice ("build 1" and "build 2" differ by one constant, so their code hashes differ), signed
three ways with the same identifier. Every probe ran with Keychain user interaction disabled, so a would-be "allow
access" dialog came back as an error instead of appearing. Results in
[`results/c5-26.6.2.tsv`](../../spikes/knsh-026-identity/results/c5-26.6.2.tsv),
[`c5-26.6.2-homebrew.tsv`](../../spikes/knsh-026-identity/results/c5-26.6.2-homebrew.tsv) and the ACL dumps in
[`c5-26.6.2-acl.txt`](../../spikes/knsh-026-identity/results/c5-26.6.2-acl.txt).

**Which identity the item records.** `SecItemAdd` on the file-based (legacy) login keychain gives the item an ACL
whose decrypt entry trusts the creator's *designated requirement*, plus a *partition list*:

| Creator's signature | Trusted requirement | Partition list |
| --- | --- | --- |
| Developer ID | `identifier "<id>" and anchor apple generic and <Developer ID OIDs> and certificate leaf[subject.OU] = <team>` | `teamid:<team>` |
| Ad hoc (`codesign -s -`) | `cdhash H"<hash>"` | `cdhash:<hash>` |
| Homebrew build from source (linker-signed ad hoc, identifier = file name) | `cdhash H"<hash>"` | `cdhash:<hash>` |

**Reads, writes and deletes** (legacy keychain, default ACL; "fails" is `-25293`, the status a prompt would replace):

| Actor | Developer ID item | Ad-hoc item | Homebrew item |
| --- | --- | --- | --- |
| Build 1 (creator) reads | Reads | Reads | Reads |
| Build 2, same identifier, reads | **Reads** | **Fails** | **Fails** (`brew upgrade` 1.0 → 2.0); reads after `brew reinstall` of the same source (same code hash) |
| Unrelated binary of the same user reads (same team for Developer ID) | Fails | Fails | Fails |
| Unrelated binary deletes | Fails (`-25244`) | Fails | Fails |
| Unrelated binary **overwrites** the value (`SecItemUpdate`) | **Succeeds**, no prompt | **Succeeds** | **Succeeds** |
| Creator reads after that overwrite | Same-team writer: **reads the forged value**. Ad-hoc writer or `/usr/bin/security add-generic-password -U`: fails | Fails | Fails |
| Unrelated binary in a sandbox that denies `file-write*` under `~/Library/Keychains` overwrites | Fails (`EPERM`); the item is unchanged | Fails | Fails |
| Unrelated binary in that sandbox creates an item (pre-seeding) | Fails (`EPERM`) | Fails | Fails |
| Creator in that sandbox reads its own item | Reads | Reads | Reads |
| Unrelated binary creates the item first (pre-seeding) | `knshd` cannot read it, add over it (`-25299`) or delete it | Same | Same |
| Developer ID build reads an item made by a Homebrew build, or the reverse | Fails | | |

- **An overwrite replaces the partition list with the writer's** (`teamid:…`, `cdhash:…` or `apple-tool:`) and leaves
  the trusted-application list alone. So code outside the team cannot plant a value that a Developer ID `knshd` then
  reads silently: the read fails. Same-team code can, which is no weaker than the signature itself. The read failure
  still has to be treated as tampering, and `knshd` must fail closed on it.
- Limiting the item's *encrypt* ACL entry to the creator (instead of the default "any application") did **not** stop
  overwrites *(ad hoc)*.
- **Legacy keychain files are written by the client process itself.** A sandbox that denies `file-write*` under
  `~/Library/Keychains` stops every overwrite and creation while reads still work (table above). Denying `file-read*`
  too makes the keychain look empty (`-25300`), and denying the Mach service `com.apple.SecurityServer` breaks every
  Keychain call (`-50`) *(ad hoc)*.
- **Data-protection keychain:** without an entitlement, `SecItemAdd` fails with `-34018` (missing entitlement). With
  `keychain-access-groups` (team-prefixed group), both an ad-hoc and a Developer ID binary are **killed at launch**
  (`SIGKILL`, exit 137). AMFI logs "Code has restricted entitlements, but the validation of its code signature
  failed": the entitlement needs a provisioning profile, which a bare command-line binary cannot embed. It needs `knshd`
  inside an app bundle with a Developer ID provisioning profile from the Apple developer portal (**pending**).

**Exit question: which mechanism should `knsh-platform` use?** See proposed [decision 11](../09-reference/decisions.md):
the legacy keychain with the default ACL, from a Developer ID-signed `knshd`, never showing the "allow access" dialog;
writes under `~/Library/Keychains` denied in every profile; a read failure treated as tampering. The data-protection
keychain is preferred once `knshd` ships in an app bundle with a provisioning profile, but is not verified. Ad-hoc and
Homebrew builds lose their items on every upgrade.

### C6: LocalAuthentication from a launchd agent

The probe calls `LAContext evaluatePolicy` with `LAPolicyDeviceOwnerAuthentication` (Touch ID with password fallback)
and the reason text `approve the agent command: git push --force origin main (cwd ~/src/app, session
01JD3Q9ZKX8M4T2V6B7N5C1H0E)`. Results in [`results/c6-26.6.2-*.txt`](../../spikes/knsh-026-identity/results/).

| Case | Security session | Result |
| --- | --- | --- |
| Terminal, `interactionNotAllowed` | graphics, TTY | `-1004` (user interaction required) in 2 ms |
| launchd agent in `gui/<uid>`, `interactionNotAllowed` | graphics | `-1004` in 1 ms |
| launchd agent in `gui/<uid>` | graphics | **Prompt shown** (seen in a screenshot, confirmed by the user). Success after the user typed the password (16.6 s) |
| launchd agent in `user/<uid>` (background domain, `LimitLoadToSessionType` `Background`) | **no graphics access** (`attrs=0x0`) | **The same prompt appeared on the console** (screenshot). Success after the user typed the password (3.4 s in the recorded run; two more runs also succeeded *(ad hoc)*) |

- The prompt is a system dialog titled with the **process name** and reads "*<process> is trying to <reason>.* Enter
  the password for the user "<full name>" to allow this." The 107-character reason, with `--force`, `~`, parentheses
  and a ULID, was shown in full, wrapped, not truncated. So the reason must read naturally after "knshd is trying to".
  The length at which it is cut was not measured.
- With the lid closed, `canEvaluatePolicy` still reports Touch ID available (`biometryType` 1), but the dialog offers
  only the password.
- A `user/<uid>` job without `LimitLoadToSessionType` `Background` is refused by `launchctl bootstrap` ("5:
  Input/output error").
- **Without a GUI session:** a job whose security session has no graphics access still got its prompt onto the console
  while a user was logged in there. So a `knshd` started from an SSH login would show its prompt on the Mac's screen,
  not to the SSH user. With nobody logged in at the console, the result is **pending**.

**Exit question: what must approvals do without a GUI session?** See proposed [decision 12](../09-reference/decisions.md):
fail closed. `knshd` cannot rely on a "no GUI" error: the prompt went to the console even from a session without
graphics access. Every outcome other than success (cancel, error, no answer by `timeout_at`) denies with a reason
naming the cause, and the context is invalidated at the timeout.

**Implementation (KNSH-064):** `knsh-platform` `macos::LocalAuthentication` follows this. Its reply block was checked
against the real block runtime, and real `NSError` values were mapped to refusals, by unit tests on macOS 26.6.2. A
prompt shown by `knshd` itself, and the Touch ID, cancel, timeout and SSH cases, are still **pending** (manual:
`cargo test -p knsh-platform -- --ignored shows_the_system_prompt`).

### C7: XPC peer code-signing requirements

The service is a launchd agent declaring the Mach service in its plist (Developer ID, hardened runtime, version 1.0).
Clients are signed in seven ways. The client requirement (FR-AUTH-13) is:

```text
anchor apple generic and certificate leaf[subject.OU] = "<team>" and identifier "<authority id>"
and ((certificate 1[field.1.2.840.113635.100.6.2.6] exists and certificate leaf[field.1.2.840.113635.100.6.1.13] exists)
     or certificate leaf[field.1.2.840.113635.100.6.1.9] exists)
and !(entitlement["com.apple.security.get-task-allow"] exists)
```

The first branch is Developer ID, the second Mac App Store (not tested). Hardened runtime and the minimum version
cannot be written in the requirement language, so the service reads them from the sender's `SecCode` (FR-AUTH-14):
the signature flags (`0x10000` runtime), the live code-signing status (`CS_GET_TASK_ALLOW`, `CS_DEBUGGED`) and
`CFBundleVersion` from the Info.plist bound into the signature (embedded in a bare binary with `-sectcreate __TEXT
__info_plist`). Two service variants ran: **xpc**, with `xpc_connection_set_peer_code_signing_requirement` on each peer
(macOS 12+) plus the `SecCode` checks; and **secode**, with no XPC-level requirement and every check on
`SecCodeCreateWithXPCMessage` (builds without availability warnings for a macOS 12 deployment target, like the XPC call). Results in
[`results/c7-26.6.2.tsv`](../../spikes/knsh-026-identity/results/c7-26.6.2.tsv) and the service log.

| Client | xpc variant | secode variant |
| --- | --- | --- |
| Developer ID, right identifier, runtime, version 2.0 | Accepted | Accepted |
| Ad hoc, same identifier | **Rejected** by XPC before the handler (`XPC_ERROR_PEER_CODE_SIGNING_REQUIREMENT`); the client sees `CONNECTION_INTERRUPTED` | Rejected: requirement not met (`-67050`) |
| Developer ID, other identifier | Rejected by XPC | Rejected: requirement |
| Developer ID with `get-task-allow` | **Rejected** by XPC (the `!entitlement` clause) | Rejected: requirement; live status also has `CS_GET_TASK_ALLOW` |
| Developer ID without hardened runtime | Passes the requirement, **rejected** by the flag check | Same |
| Developer ID, version 0.9 (minimum 1.0) | Rejected: below minimum version | Same |
| Developer ID, no Info.plist | Rejected: no version | Same |

**After `exec`.** The client sends a message, waits until it has left (barrier), then `execv`s another binary in the
same process (same pid). The service handles the message 1 s later:

| Case | By audit token (`SecCodeCreateWithXPCMessage`) | By pid (`SecCodeCopyGuestWithAttributes`) | XPC requirement |
| --- | --- | --- | --- |
| Ad-hoc client sends, then execs the trusted client | **Rejected:** the code object no longer validates (`-67065`, no guest) | **Would accept** (sees the trusted binary) | Rejected |
| Trusted client sends, then execs an ad-hoc binary | Rejected (`-67065`) | Rejected | Rejected |

A pid-based check is exploitable; both audit-token-based checks fail closed when the sender has changed identity.

**The client checks the service (FR-AUTH-15).** With the real job unloaded, an impostor job declaring the same name
answers. A client that sets `xpc_connection_set_peer_code_signing_requirement` on its connection rejects the impostor
(ad-hoc same identifier, or Developer ID other identifier) with `XPC_ERROR_PEER_CODE_SIGNING_REQUIREMENT`; without the
requirement it talks to the impostor. **But the impostor received and processed the client's first message before
the client rejected the reply.** The client's requirement guards what it receives, not what it sends.

**Who can hold the name (FR-AUTH-12).** launchd gives a Mach name to the **first** job that declares it. A second job
declaring the same name still loads (`launchctl bootstrap` exits 0); launchd logs "The endpoint … already exists and
is owned by: <first label>", and the first job keeps answering. Loaded in the other order, the impostor holds the
name and `knshd`'s job loads without it. A listener started outside launchd gets `CONNECTION_INVALID` for a declared
name and for an undeclared one. So the name is safe from envelopes, which cannot submit launchd jobs or write
`~/Library/LaunchAgents` ([C8](#c8-process-information-signals-sockets-and-services)), but not from other software of
the same user (out of scope); the authority's check of `knshd` is what catches an impostor.

**Exit question: which API is used on macOS 14?** See proposed [decision 13](../09-reference/decisions.md):
`xpc_connection_set_peer_code_signing_requirement` (macOS 12+) on every peer connection, plus
`SecCodeCreateWithXPCMessage` on every message for hardened runtime, live status and version, never the pid. The
lightweight code requirements of macOS 14.4 and the `xpc_peer_requirement_t` API of macOS 26 were not tested and are
not needed.

**Implemented (KNSH-067).** `knsh-platform`'s `macos::XpcControlService` does exactly this. Observed in its tests on
macOS 26.6.2, in-process on an anonymous listener: with no trusted authority a connection cancelled before it is
resumed fails on the client side with no message delivered, and an ad-hoc-signed client is refused by
`xpc_connection_set_peer_code_signing_requirement` (`XPC_ERROR_PEER_CODE_SIGNING_REQUIREMENT` on the service side)
before any message reaches the handler. A Developer ID authority against an installed, signed `knshd` is pending.

## Proxy results (KNSH-027: C9, C10)

Observed on 2026-11-14 on an Apple M1 Pro, macOS 26.6.2 (25G83), from a normal account; nothing ran as root. Tools:
the system curl 8.7.1 (LibreSSL 3.3.6, its default TLS backend) and git 2.54.0 (Apple Git-157), npm 10.9.3 on Node
22.20.0, pip 26.1.1 on Python 3.14, cargo 1.99.0, and Node 22.20.0, 22.23.5 and 24.21.0. A throwaway recording proxy
(HTTP CONNECT, absolute-URI HTTP and SOCKS5 on one loopback port) required credentials, recorded what each connection
carried and forwarded to the real host. Each case ran with a clean environment, an empty home and its own user and
password. The harness and raw results are in [`spikes/knsh-027-proxy/`](../../spikes/knsh-027-proxy/README.md).

**Pending (not observed, not claimed):** macOS 14 and 15; a run inside a real envelope (no sandbox was applied, so a
tool that ignores the proxy went direct instead of failing); Homebrew curl and git, Yarn, pnpm, Bun, Deno, Go,
Python `urllib`, Java; credentials that need percent-encoding.

### C9: per-command proxy credentials

"HTTP env" is `HTTPS_PROXY`, `https_proxy`, `HTTP_PROXY` and `http_proxy` set to `http://user:pass@127.0.0.1:port`.
Every credential the proxy received was the case's own user and password.

| Tool | HTTP env | `ALL_PROXY=socks5h://…` | `HTTPS_PROXY=socks5h://…` | Tool's own setting (HTTP / SOCKS5) | Credentials sent |
| --- | --- | --- | --- | --- | --- |
| curl | yes | yes | yes | `-x`: yes / yes | Basic, up front; RFC 1929 for SOCKS5 |
| git (HTTPS) | yes | yes | yes | `http.proxy` (set as `GIT_CONFIG_COUNT`/`KEY`/`VALUE`): yes / yes | Basic **only after a `407` challenge**; up front with `GIT_HTTP_PROXY_AUTHMETHOD=basic`; RFC 1929 |
| npm | yes | **ignored** (went direct) | yes | `npm_config_https_proxy` and `npm_config_proxy`: yes / yes (`socks5h` and `socks5`) | Basic, up front; RFC 1929 |
| pip | yes | **fails**: "Missing dependencies for SOCKS support" | **fails** (same) | `PIP_PROXY`: yes / fails | Basic, up front |
| cargo | yes | yes | yes | `CARGO_HTTP_PROXY`: yes / yes | Basic, up front; RFC 1929 |
| Node 22.20 `fetch`, `https`, `http` | **ignored** | **ignored** | — | `NODE_USE_ENV_PROXY=1`: **ignored** | none |
| Node 22.23 and 24.21 `fetch`, `https`, `http` | **ignored** unless `NODE_USE_ENV_PROXY=1` | **ignored** | — | `NODE_USE_ENV_PROXY=1` with HTTP env: yes / SOCKS URL **fails** ("Invalid URL protocol") | Basic, up front |

- **CONNECT vs SOCKS5.** Every tool supports HTTP CONNECT (Node only from 22.23 with the opt-in). SOCKS5 with username and password works for curl, git,
  npm and cargo; pip lacks the optional PySocks dependency and Node's built-in proxy support takes only `http:` and
  `https:` proxy URLs. Both fail rather than going direct.
- **Missing credentials** (`http://127.0.0.1:port`): curl, git, npm, pip and cargo fail on the `407`, none goes
  direct (Node was not run without credentials). curl and git fail at once, npm reports `E407`, pip retries for
  about 8 seconds and cargo for about 11.
- **Name resolution.** With `socks5://` (not `socks5h://`), curl, git and npm resolve the name themselves and send an
  IPv4 or IPv6 address, which FR-NET-05 refuses; inside a profile, where DNS is denied (FR-NET-08), resolution fails
  first. HTTP CONNECT and `socks5h` send the name.
- **Plain HTTP.** curl and Node send `http://` URLs as absolute-URI requests (`GET http://example.com/`) over an HTTP
  proxy, with a matching `Host` header and Basic credentials; over SOCKS5 curl opens a tunnel to port 80 (Node
  cannot use SOCKS5). This is the
  case KNSH-059's spec gap asks about.
- The first Node release with `NODE_USE_ENV_PROXY` lies between 22.20 and 22.23 on the 22 line; it was not
  bisected. **Node 22.23** prints "EnvHttpProxyAgent is experimental" on stderr *(ad hoc: seen by hand, not kept in `results/`)* when `NODE_USE_ENV_PROXY=1`.

**Tools that ignore proxy settings, and what a preset can use instead (FR-NET-12):**

| Tool | Ignores | Setting a preset uses |
| --- | --- | --- |
| Node `fetch`, `https`, `http` (22.23 and 24.21 observed) | `HTTPS_PROXY`/`HTTP_PROXY` by default; `ALL_PROXY` always | `NODE_USE_ENV_PROXY=1` (or `node --use-env-proxy`) with the HTTP env; HTTP proxy only |
| Node 22.20 (the first version with `NODE_USE_ENV_PROXY` was not bisected) | every proxy setting | none built in: the program must bring its own agent; blocked inside an envelope |
| npm | `ALL_PROXY` | `HTTPS_PROXY` (already in the HTTP env), or `npm_config_https_proxy` and `npm_config_proxy` |
| pip | SOCKS proxies (without PySocks) | the HTTP env or `PIP_PROXY` with an HTTP proxy URL |
| git over SSH | every proxy setting (not tested here) | none; HTTPS remotes only (already a [known limit](../03-functional-requirements/network-proxy.md#known-limits)) |

**Exit question: which credential transport works across all tools?** The user and password in an **HTTP proxy
URL** (`http://user:token@127.0.0.1:port`), which every tool turns into `Proxy-Authorization: Basic` on the CONNECT
(or absolute-URI) request. It is the only transport that worked for all six tools; SOCKS5 usernames fail for pip and
Node. Two conditions: the proxy must answer a request without credentials with `407` and
`Proxy-Authenticate: Basic`, because git sends credentials only after that challenge; and Node must be opted in with
`NODE_USE_ENV_PROXY=1`. A `Proxy-Authorization` header set directly by the user is not a portable transport: no tool
in scope documents reading one from its environment (not tested). See proposed
[decision 14](../09-reference/decisions.md).

### C10: TLS server names

For every tunnel to port 443 the proxy read the first TLS record without decrypting and parsed the ClientHello.

- **curl, git and npm** (the story's three), and also **pip, cargo and Node** `fetch`/`https`: every ClientHello
  carried a server name equal to the CONNECT or SOCKS5 domain target (example.com, github.com, registry.npmjs.org,
  pypi.org, files.pythonhosted.org, index.crates.io). Each captured name is in
  `results/c9-c10-26.6.2-connections.jsonl`.
- Every ClientHello fitted in a single TLS record (`single_record`), offered TLS 1.3, and none offered **Encrypted
  Client Hello** (extension `0xfe0d`). curl, git and cargo offered ALPN `h2, http/1.1`; pip and Node `fetch` `http/1.1`;
  npm and Node `https` no ALPN.
- **Negative control:** curl with `--connect-to example.com:443:github.com:443` sent `CONNECT github.com:443` and a
  ClientHello naming `example.com`; the proxy saw the mismatch (`sni_matches: false`) before any certificate check.
- With `socks5://`, the target is an address, so the server name cannot be compared with it; FR-NET-05 already
  refuses such targets.
- **Risk:** a client that adopts Encrypted Client Hello sends the provider's public name in the outer ClientHello,
  which will not match the requested host. KNSH-061 refuses that (fail closed); a preset may need to turn ECH off for
  such a tool. None in scope offered it here.

## File-system results (KNSH-077: C3, C4)

Observed on 2026-11-18 on an Apple M1 Pro (8 CPUs, 16 GiB), macOS 26.6.2 (25G83), internal SSD, APFS, from a normal
account; nothing ran as root. Work files sat in a `*.noindex` folder on the data volume, out of Spotlight. The
harnesses and raw results are in [`spikes/knsh-077-fs/`](../../spikes/knsh-077-fs/README.md); rerun them on each
macOS version.

**Pending (not observed, not claimed):** macOS 14 and 15 for both claims; cold-cache shadow timings (`purge` needs
root, so every timing had a warm cache); roots on external or slower APFS volumes; very large or heavily fragmented
files; a real envelope (writers ran unsandboxed); `KernelDropped` (never produced here).

### C3: copy-on-write shadows

**Tree** (`gentree`, seed 77; [`results/c3-26.6.2-tree.txt`](../../spikes/knsh-077-fs/results/c3-26.6.2-tree.txt)):
100,000 regular files in 3,906 folders (fan-out 5, depth 0 to 5), 1 to 50 files per folder, 2.76 GiB in all
(mean 29.7 KB). Sizes: 2% empty, 30% up to 1 KiB, 43% 1–8 KiB, 20% 8–64 KiB, 5% 64 KiB–1 MiB, 0.2% 1–4 MiB.

**Timings**, three runs each, warm cache
([`results/c3-26.6.2-timings.tsv`](../../spikes/knsh-077-fs/results/c3-26.6.2-timings.tsv)). "Per file" walks the
tree with `readdir`, recreates folders with `mkdirat` and clones each file with `clonefileat(2)`; "directory" is one
`clonefile(2)` of the root. "Background" is the Darwin background band (`PRIO_DARWIN_BG`, throttled I/O), which
QoS background is documented to apply (QoS background itself was not run); "utility" is QoS utility on every thread.

| Strategy | Threads | Priority | Wall time, 3 runs (s) | CPU time (user + system, s) | Under 10 s? |
| --- | --- | --- | --- | --- | --- |
| Per file | 1 | normal | 12.36, 11.70, 11.63 | 10.3–10.5 | **no** |
| Per file | 4 | normal | 7.36, 7.39, 7.28 | 23.6–24.3 | yes |
| Per file | 4 | utility | 7.72, 7.43, 7.36 | 22.6–23.0 | yes |
| Per file | 8 | normal | 7.50, 7.51, 7.51 | 31.1–33.6 | yes |
| Per file | 8 | utility | 7.27, 7.18, 7.28 | 27.9–28.2 | yes |
| Per file | 1 | background | 49.23, 51.44, 51.22 | 25.8–31.3 | **no** |
| Per file | 4 | background | 38.02, 34.07, 33.29 | 25.7–26.1 | **no** |
| Directory | 1 call | normal | 1.57, 1.59, 1.61 | 0.92–0.93 | yes |
| Directory | 1 call | utility | 1.70, 1.69, 1.68 | 0.93–0.96 | yes |
| Directory | 1 call | background | 3.69, 4.23, 4.38 | 3.0–3.5 | yes |

- **Extra disk usage** (free space before and after, after `sync`): 29 to 40 MB per shadow, the same for every
  strategy, about 340 bytes per file; the data blocks are shared. Removing a shadow (`removefile`) took 4.8 to 5.8 s
  and gave the space back.
- **CPU** is almost all system time; per-file cloning is bound by metadata updates in the kernel, so threads beyond 4
  add CPU but no speed.

**Attributes** ([`verify-file`](../../spikes/knsh-077-fs/results/c3-26.6.2-verify-file.txt),
[`verify-dir`](../../spikes/knsh-077-fs/results/c3-26.6.2-verify-dir.txt),
[`attrs`](../../spikes/knsh-077-fs/results/c3-26.6.2-attrs.txt)). For all 100,000 files, with both strategies: size,
`mtime` and birth time (to the nanosecond), mode, flags, owner equal the source's, and the extended-attribute name list has the same length (names and values were compared only on the hand-made file below);
content equal for every 50th file checked; the inode always differs. On one hand-made file (mode 6755): setuid and
setgid are cleared on the clone (as `clonefile(2)` documents), `UF_HIDDEN` and a custom xattr are kept, a hard link is not (the
clone has one link), and `ctime` is the clone's creation time. Post-image identity can therefore use size and
`mtime` of the shadow copy; restoring a setuid file from a shadow would lose the bit.

**Clones during unflushed memory-mapped writes** ([`results/c3-26.6.2-mmap.txt`](../../spikes/knsh-077-fs/results/c3-26.6.2-mmap.txt)).
A separate process mapped a 16 MiB file `MAP_SHARED` and stored into it without `msync`:

- `read(2)` by another process and a clone both held the stored bytes. The clone took 2.4 ms in the recorded run (up to 3.7 ms in two earlier runs, *ad hoc*), against
  about 0.2 ms once the pages were clean: dirty pages are written back before cloning.
- The file's **`mtime` and size never changed**: not after the stores, not after `msync(MS_SYNC)`, not after the
  writer exited, and not during the 40 s after. Only `ctime` moved, when the writer exited. Extending with
  `ftruncate` changed size and `mtime` at once, and the clone held the stores past the old end.
- With a writer storing continuously (each pass stamps a generation into every 16 KiB page), **195 of 200 clones
  were torn**, with up to 182 runs of different generations across the pages (197 and 198 of 200 in two earlier runs, *ad hoc*, not in the results file). A `pwrite(2)` writer also left
  every clone mid-pass, but as one clean cut (two runs of generations).
- **Finding the writer**: while it held the file open for writing and mapped, and after it closed the descriptor
  but kept the mapping, `proc_listpidspath(3)` found it, and per-process `PROC_PIDLISTFDS` +
  `PROC_PIDFDVNODEPATHINFO` (open flags with `FWRITE`) and `PROC_PIDREGIONPATHINFO` (protection read/write) showed
  how, all as the same user without privileges. The region's share mode read `PRIVATE` for a `MAP_SHARED` mapping,
  so it cannot tell shared from private mappings. One `proc_listpidspath` over all processes took 284 to 620 ms.
  After the writer exited, nothing distinguished the file.

**Exit questions.**

- *Is per-file cloning within budget?* Per file on one thread, no: 11.6 to 12.4 s. Per file on 4 threads, yes on
  this machine with a warm cache: 7.3 to 7.7 s at normal priority or QoS utility, with no gain from 8 threads. In the
  Darwin background band (`PRIO_DARWIN_BG`; QoS background, documented to apply it, was not run) no strategy except the directory clone fits: 33 to 51 s. The
  margin is small and cold-cache and slower-machine runs are pending, so proposed
  [decision 15](../09-reference/decisions.md) keeps per-file cloning on a 4-thread pool at QoS utility, makes the
  shadow builder report its time, and records the directory clone (1.6 to 1.7 s) as the fallback to evaluate.
- *Can a torn memory-mapped write be detected after the fact?* No. Size, `mtime` and file events all miss a change
  made through a live mapping; only a content comparison sees it, and a torn state looks like any other content. It
  can be detected only by observing open and mapped files during the change (proposed
  [decision 17](../09-reference/decisions.md)).
- *Does cloning preserve the attributes post-image identity needs?* Yes: size, `mtime` (nanoseconds), mode except
  setuid (and, as documented but not observed, setgid), flags, owner and xattrs; the inode differs by design. But `mtime` does not move for memory-mapped
  writes, so identity of such files rests on the content hash (decision 17).

### C4: file-event flushing with concurrent writers

One FSEvents stream with file events watched an empty root; each **round** was one line: 1, 4 or 16 writer
processes started together, each made 50 creates (512 bytes), 8 appends to existing files, 13 renames and the removal
of its previous round's 50 files, logging the time after each call. The line ended when every writer had been reaped;
then a line-end procedure ran and every operation was checked against the events delivered so far (matched by path
and flag). 100 rounds per case, stream latency 0.5 s unless stated
([`results/c4-26.6.2-runs.txt`](../../spikes/knsh-077-fs/results/c4-26.6.2-runs.txt)). "Missed at line end" counts
operations whose event had not arrived when the procedure finished (late or never). A drop event is counted in the
round during which it arrived; without the marker, a drop can arrive after its round ended, which is why the flush-only
rows show events that never arrived even in rounds counted as without drop flags.

| Writers | Procedure at line end | Missed at line end | Rounds with drop flags | Missed in rounds without drop flags | Procedure time p50 / p95 / max |
| --- | --- | --- | --- | --- | --- |
| 1 | `FSEventStreamFlushSync` | 99.9% (13,342 of 13,350) | 0 | 99.9% | 0.08 / 0.11 / 1.62 ms |
| 4 | `FSEventStreamFlushSync` | 43.2% | 16 | 40.0% | 0.08 / 0.81 / 28.5 ms |
| 16 | `FSEventStreamFlushSync` | 44.0% | 92 | 53.5% | 0.09 / 5.35 / 30.2 ms |
| 16 | `FSEventStreamFlushSync`, latency 0.05 s | 26.3% | 93 | 13.5% | 0.10 / 0.58 / 8.09 ms |
| 4 | nothing (control) | 45.9% | 19 | 41.7% | 0 |
| 4 | marker file in the root, one flush | 50.5% | 22 | 46.5% | 0.15 / 0.62 / 11.7 ms |
| 4 | marker file in the root, wait for its event, no flush | 0.74% | 17 | **0** | 502 / 521 / 5,001 ms (marker not seen in 5 rounds) |
| 1 | **marker outside the root, flush every 1 ms until its event** | **0** | 0 | **0** | 6.57 / 12.95 / 18.5 ms |
| 4 | same | 0.20% | 4 | **0** | 9.23 / 13.25 / 5,001 ms (marker not seen in 1 round) |
| 16 | same | 10.7% | 68 | **0** | 9.33 / 15.81 / 5,000 ms (marker not seen in 1 round) |
| 16 | same, latency 0.05 s | 12.0% | 79 | **0** | 7.54 / 14.67 / 5,001 ms (marker not seen in 1 round) |
| 16 | same, latency 0, `NoDefer` | 11.8% | 78 | **0** | 6.58 / 14.55 / 29.7 ms |

The marker wait had a 5 s clock deadline; "5,000 ms" is a round whose marker event never came.

- **Latency** from an operation to its event, with the marker procedure: p50 5.4 / 8.2 / 18.1 ms and p95 11.1 /
  20.8 / 47.5 ms for 1 / 4 / 16 writers (latency 0.5 s). The last operation of each writer happened 0.5 ms (p50,
  1 writer) to 39 ms (p95, 16 writers) before the line end.
- **A flush is not enough.** `FSEventStreamFlushSync` returns in well under a millisecond at p50 and delivers only
  what the service already holds; events still on their way arrive after it, 12.6 to 145 ms later at p95 and up to
  0.11 to 0.58 s later (about one stream latency) when they miss the flush; some never arrive. A marker without a
  flush waits out the latency (502 ms p50).
- **The marker procedure** creates a file in a folder outside the root that the same stream also watches, then
  flushes every millisecond until the marker's event arrives (the stream callback notes the marker's arrival, so the
  check is free). In every round without a drop flag, in all five marker-loop cases (223,806 operations), every
  operation had arrived; late and missing events occurred only in rounds with drop flags. In 3 of 500 rounds the
  marker's event never came and the 5 s deadline expired; those cases had drop flags in other rounds, and the marker
  folder also receives the drop event (below), so a watcher can stop waiting as soon as a drop flag arrives.
- **Dropped events** ([`results/c4-26.6.2-overflow.txt`](../../spikes/knsh-077-fs/results/c4-26.6.2-overflow.txt)):
  every drop came as one event flagged `MustScanSubDirs|UserDropped` whose path is a **watched path itself** (the
  root, and the marker folder, each got one), never a sub-folder. `KernelDropped` was never seen. 16 concurrent
  writers (about 2,100 operations per line) caused drops in 68 to 93 of 100 rounds at every latency tried; 4 writers
  in 4 to 22 of 100; 1 writer never, not even 2,000 creates and removes in 0.26 s. Blocking the stream's callback for
  10 s while 16 writers created and removed 320,000 files gave 38 drop events; not blocking it gave 18. Drops are
  common under bursts of concurrent writers, so the rescan they force must be cheap.
- **Flags accumulate** per path: a file created, written and removed within one delivery shows
  `Created|Removed|Modified`; later events for a file still carry `Created`; every new file carries `XattrMod` (the
  system's `com.apple.provenance` attribute). Flags cannot say what happened, only that a path may have changed.
- **Root changes** ([`rootchange`](../../spikes/knsh-077-fs/results/c4-26.6.2-rootchange.txt)): with `WatchRoot`,
  renaming the watched folder away and back gave `RootChanged` each time, followed by a `Created|Renamed|XattrMod|IsDir`
  event on the root path.
- **Memory-mapped writers** ([`results/c4-26.6.2-mmap.txt`](../../spikes/knsh-077-fs/results/c4-26.6.2-mmap.txt)):
  a writer that stored through a shared mapping and stayed alive produced **no event for 40 s**, with or without
  `msync(MS_SYNC)`; it produced one `Modified` event when it exited. A writer that exited at once (with or without
  `msync`) produced its event by the line end, like a `pwrite` writer.

**Exit questions.**

- *After a flush, can the event set be treated as complete for a line?* Not after a flush alone. After the marker
  procedure, yes, unless a drop flag arrived in the line's window or the marker did not arrive before a deadline:
  then the line's checkpoints are uncertain and the root is rescanned. Changes through a mapping that is still alive
  at the line end are not in any event set; they are handled by decision 17. Proposed
  [decision 16](../09-reference/decisions.md).
- *Which flags must trigger a rescan and an `uncertain` mark?* `MustScanSubDirs`, `UserDropped`, `KernelDropped`
  (rescan the path given, observed to be the watched root), `EventIdsWrapped` (rescan every root) and `RootChanged`
  (re-resolve the root, then rescan it). Item flags never do.

## Endpoint Security (macOS 27+)

Before relying on the descendant client:

- Which events it can authorise beyond exec (file opens, network).
- What happens to pending and later operations if `knshd` exits.
- KNSH-094, before the macOS binding is written: the exact `es_new_descendants_client` signature and entitlement
  name; which subtree a client covers (only the envelope it is created for, or every later descendant of `knshd`,
  which would also cover supervised lines); whether the envelope's launch execs (`knsh-exec`, `sandbox-exec`, bash,
  the CLI) are reported, and with which pid and process group; the deadline Endpoint Security gives an exec and what
  happens to a client that misses it; whether the exec message carries the working directory and the environment.
- KNSH-094 integration check: `/bin/bash -c 'git push'` run by absolute path inside an envelope is decided by the
  supervisor (pending the entitlement and macOS 27 hardware).
