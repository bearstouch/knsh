# Developer tools

How common developer tools behave inside envelopes and per-command profiles.

## Proxy settings

Every envelope and supervised line gets its own proxy credentials in its proxy settings. All other network traffic is refused.

| Tool behaviour | Result |
| --- | --- |
| Honours standard proxy settings (curl, git over HTTPS, npm, pip, cargo) | Works, subject to host rules. Verified on macOS 26.6 with an HTTP proxy URL carrying the credentials (C9) |
| Node `fetch`, `https` and `http` | Use the proxy only with `NODE_USE_ENV_PROXY=1`, which every line's environment sets under proposed decision 14 (observed on 22.23 and 24.21; Node 22.20 ignores every proxy setting and is blocked) |
| Ignores proxy settings (ssh git remotes, some Java HTTP clients, older Node) | Blocked, not leaked. Observed inside envelopes and command profiles for ssh remotes and Node 22.20 (KNSH-076, [compatibility list](#compatibility-list)) |
| Has tool-specific proxy configuration | Presets set it: `npm_config_https_proxy`, `PIP_PROXY`, `CARGO_HTTP_PROXY`, `GIT_HTTP_PROXY_AUTHMETHOD=basic` (proposed [decision 14](../09-reference/decisions.md)) |
| Uses SOCKS5 | Works with RFC 1929 username and password (observed for curl, git, npm and cargo); pip without PySocks and Node cannot use SOCKS5 and need the HTTP proxy |
| Connects to a local dev server or database | Allowed on `network.loopback` ports |
| Uses DNS directly | Blocked; the resolver service is denied, the proxy resolves names |

## Tools that sandbox themselves

A process that is already sandboxed cannot apply another profile. These fail inside an envelope or command profile:

- Chromium and Playwright browsers
- `swift build`
- Some Bazel setups
- Agent CLIs' own sandboxes (which must be turned off inside an envelope)

A profile can name **trusted tools**, which the supervisor runs without a per-command profile, only after an approval or grant. Each release publishes a compatibility list.

## Compatibility list

Phase 2 (KNSH-076; FR-SBX-09, FR-NET-12). Tested on **macOS 26.6.2 (25G83)**, Apple M1 Pro, on 2026-11-18, with
`scripts/qualify-phase2.sh tools`. Each tool ran three times from a clean project: outside any sandbox (the positive
control, which passed for every tool below), as a supervised line under its per-command profile, and directly inside an
envelope. Network cases went through the real proxy to the real hosts. The full report, with the error each failure
gave and the names the proxy was asked for, is [qualification/phase-2-tools-2026-11-18.md](../07-testing/qualification/phase-2-tools-2026-11-18.md).

| Tool | Version tested | Command profile | Envelope | Status |
| --- | --- | --- | --- | --- |
| curl, HTTPS | curl 8.7.1 (system, LibreSSL 3.3.6) | works | works | **works** |
| git, HTTPS remote | git 2.54.0 (Apple Git-157) | works | works | **works** |
| git, ssh remote | git 2.54.0, OpenSSH 10.3p1 | fails (exit 128) | fails (exit 128) | **blocked** (ssh ignores the proxy; nothing leaves) |
| npm, registry read | npm 10.9.3 on Node 22.20.0 | works | works | **works** (its own proxy setting) |
| pip, package download | pip 26.1.1, Python 3.14.5 (Homebrew) | works | works | **works** |
| cargo, `cargo fetch` (sparse index and download) | cargo 1.99.0 | works | works | **works** |
| Node `fetch` and `https.get` | Node 22.20.0 | fails (`ENOTFOUND`) | fails | **blocked** (ignores every proxy setting) |
| Node `fetch` and `https.get` | Node 22.23.5, Node 24.21.0 | works | works | **works** (`NODE_USE_ENV_PROXY=1`) |
| Chromium, Playwright's build (`chrome-headless-shell`) | Chrome for Testing 153.0.8010.12 (`chromium_headless_shell-1243`) | crashes (SIGSEGV) | crashes | **needs a trusted tool** |
| Chromium, Google Chrome headless | Google Chrome 157.0.8103.79 | aborts (SIGABRT) | aborts | **needs a trusted tool** |
| Playwright (Node driver) | not installed | — | — | **pending**: not tested; expected to need a trusted tool, as the Chromium it launches does |
| `swift build` | Swift 6.4 (Xcode) | fails (SwiftPM internal error) | fails | **needs a trusted tool**; `--disable-sandbox` fails the same way, so turning SwiftPM's own sandbox off is not enough |
| Bazel | not installed | — | — | **pending**: not tested; expected to need a trusted tool for setups that sandbox their actions |

Notes from the run:

- **Pending:** running the tools marked *needs a trusted tool* as trusted tools (`exec.trusted_tools`) needs an
  approval or a grant made after Touch ID or the password, which the unattended run cannot give.
- Inside an envelope only programs in trusted folders run. npm's real entry point is
  `lib/node_modules/npm/bin/npm-cli.js`, beside the Node installation's `bin`, not inside it, so trust the whole
  installation folder (for example `~/.nvm/versions/node/v22.20.0`), not only its `bin`.
- Not tested yet: other macOS releases, Homebrew curl and git (OpenSSL), Yarn, pnpm, Bun, Deno, Go modules, Java.

## Project executables

Binaries in agent-writable places (`node_modules/.bin`, `./scripts`) never match name rules. They fall under `exec.project_executables` (`allow`, `ask` or `deny`).

## Unix sockets

The Docker socket and the SSH agent socket are denied unless the profile allows them.

## Checkpoint exclusions

`node_modules`, `target`, `.venv`, `dist` and `build` are excluded from checkpoints by default. Undoing an `npm install` leaves `node_modules` out of step with the lockfile until install runs again.

## Publishing commands

Lines that receive secrets can run lifecycle scripts that read them (for example npm). Presets can rewrite publishing commands to skip lifecycle scripts where the tool allows it.
