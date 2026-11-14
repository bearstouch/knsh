# KNSH-025 spike: Seatbelt behaviour (C1, C2, C8)

Throwaway prototypes that measure how Seatbelt behaves, so that the profile compiler (KNSH-044, KNSH-045), the
violation reader (KNSH-047) and the agent presets (KNSH-058, KNSH-076) rest on observed facts. Nothing here is
shipped, built by Cargo or called by the product.

**The written result is in [verification claims](../../specs/07-testing/verification-claims.md#seatbelt-results-knsh-025-c1-c2-c8)**,
with proposed decisions 8 to 10 in [decisions](../../specs/09-reference/decisions.md).

## Files

| Path | What it is |
| --- | --- |
| `c1-nesting.sh` | C1: runs Chromium (Playwright's headless shell and Google Chrome.app), Playwright, `swift build` and, with `--with-agents`, Claude Code and Codex CLI, each unsandboxed, in the envelope with its own sandbox on, and in the envelope with it off |
| `c8-rules.sh` | C8: one case per profile rule (signals, process information, Unix sockets, system services) under a deny-by-default base. Exits non-zero if any case differs from its expected outcome |
| `helpers/c2_latency.py` | C2: latency, duplicate merging, loss under bursts, and which denials are logged at all |
| `profiles/envelope.sb` | The hand-written envelope profile used by C1, with `@PLACEHOLDER@` paths |
| `helpers/render.sh` | Fills the placeholders with canonical paths |
| `helpers/probe.c` | A small C probe: `procargs`, `kproc`, `pidinfo`, `kill`, `connect`, `lookup`, `lsquery` and more (see its header) |
| `helpers/common.sh` | `limit` (a hard time limit), `wait_for_log` (waits until `log stream` is live, using a canary) and `scrub` (removes personal paths from results) |
| `helpers/make_fixtures.py` | Picks one real log entry per message shape and scrubs it |
| `results/` | Results per macOS version: `c1-<ver>.tsv`, `c1-<ver>-denials.txt`, `c2-<ver>.json`, `c8-<ver>.tsv`, `c8-<ver>-denials.log`. Raw stream dumps (`*-stream.ndjson`) are not committed |
| `fixtures/macos-<ver>/sandbox-denials.ndjson` | Real, scrubbed denial entries for KNSH-047's parser tests |

## Running

Run as a normal user, never with `sudo`. Every case has a hard time limit, so a hang is recorded as a result.

```sh
spikes/knsh-025-seatbelt/c8-rules.sh                      # about 1 minute
python3 -I spikes/knsh-025-seatbelt/helpers/c2_latency.py spikes/knsh-025-seatbelt/results 50
spikes/knsh-025-seatbelt/c1-nesting.sh                    # browsers and swift build, about 1 minute
spikes/knsh-025-seatbelt/c1-nesting.sh --with-agents      # also the agent CLIs (calls a model on your account)
spikes/knsh-025-seatbelt/c1-nesting.sh swift-build        # only the cases matching a regex
```

C1 needs Xcode (or the command-line tools), `/Applications/Google Chrome.app`, Playwright's Chromium cache
(`~/Library/Caches/ms-playwright/chromium_headless_shell-*`) and `playwright-core` installed outside the repository:

```sh
mkdir -p ~/.cache/knsh-spike-025-pw && cd ~/.cache/knsh-spike-025-pw &&
  PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1 npm install playwright-core@1.56.1
```

`--with-agents` runs Claude Code three times with `--model haiku`, and Codex CLI if it starts. Codex is skipped when
`codex --version` does not answer within 20 s: a quarantined binary stalls in `dyld` (seen with 0.165.0). Open it once
from Finder, or remove the `com.apple.quarantine` attribute, then rerun.

C8 creates and immediately removes test launchd jobs (`knsh.spike.c8*`) when the job-creation deny fails. It never
opens an app: LaunchServices is checked with a database query, and Apple Events only run under the deny rule.

## Still to do

- Rerun everything on macOS 14 and 15 and add a fixtures directory for each.
- Rerun C2 from a standard (non-admin) account.
- Run Codex CLI (C1) once its binary starts.
