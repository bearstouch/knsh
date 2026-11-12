# Decisions and open questions

## Decisions

| # | Question | Decision |
| --- | --- | --- |
| 1 | Seatbelt depends on deprecated Apple interfaces | Keep Seatbelt as the baseline on every supported macOS. Codex CLI, Claude Code, Chromium and VS Code rely on it, so removal without a replacement is unlikely. `knsh-exec` runs Apple's `sandbox-exec` tool with the profile in a private file (`-f`), as those projects do, instead of calling private functions; a file also avoids command-line length limits. On macOS 27 and later, the Endpoint Security descendant client (decision 3) is a second layer and the fallback if Seatbelt is ever removed. |
| 2 | Name checks | Not a design question; moved to the launch checklist: EU and US trademark searches for Kinetic Shell, domain, Homebrew formula name, the `kinetic-shell` crate and a GitHub organisation, all before any public announcement. |
| 3 | Per-command decisions for binaries run directly inside an envelope | Pursue on macOS 27 and later with `es_new_descendants_client`: an Endpoint Security client scoped to the process subtree it starts, needing neither root nor privacy approval, which Apple describes as built for constraining agents. `knshd` starts every envelope, so envelopes are its descendants, and it can decide every exec inside them, including `/bin/bash` by absolute path. It needs Apple's Endpoint Security entitlement: apply now. On macOS 14 to 26, the envelope alone confines direct execution. |
| 4 | Agents as a separate macOS user | Not in the first release. It needs a root helper, which breaks the no-root design, and causes file-ownership friction with projects, git and caches. Envelopes, per-command profiles and the descendant client cover most of the benefit. Revisit for managed enterprise deployments. |
| 5 | Encrypting the stores | FileVault plus user-only permissions is enough for records: they hold no secret values and output recording is off by default, and encrypting SQLite would need a third-party library. Checkpoints are the real exposure, because deleted secret files persist: files matching sensitive patterns (`.env*`, `*.pem`, `*.key`, `id_*`) are kept for 24 hours at most, and `knsh forget --with-checkpoints` removes them at once. |
| 6 | Parser scope for phase 2 | Exact: simple commands, assignments before a command, pipelines, `&&`, `\|\|`, `;`, `&`, redirections, every quoting form, command substitution and backticks (parsed recursively), subshells, `{ }` groups, `if`, `for`, `while`, `until`, `case` and function definitions. Dynamic: `eval`, `source` and `.`, command names built from expansions, `coproc`, here-documents fed to shells or interpreters, and anything the parser cannot read. Exit criterion: at least 95% of corpus lines parsed exactly, with every line's accept or reject verdict matching bash in differential tests. |
| 7 | Agent-command corpus | No user telemetry. Sources: published agent trajectories from public coding benchmarks where licences allow; traces from running supported agent CLIs on open-source repositories in CI; later, an opt-in `knsh corpus export` that shows the user every line before sharing. Every line is normalised: paths, user names, hosts and anything secret-like become placeholders. |

## Still open

1. Apple grants the Endpoint Security entitlement case by case. Whether it is granted for a broadly distributed developer tool is not yet known; the application should go in now.
2. Which events the descendant client can authorise beyond exec (file opens, network), and what happens to pending and later operations if `knshd` exits. Verify on macOS 27 before relying on it.

Platform claims to verify before phase 2 are in [../testing/verification-claims.md](../testing/verification-claims.md).
