# Test strategy

| Area | Approach | Document |
| --- | --- | --- |
| Platform assumptions | One test per claim, on macOS 14, 15 and current, before phase 2 | [verification-claims.md](verification-claims.md) |
| Bash compatibility and parser | Bash test suite, Oils cross-shell tests, agent-command corpus, differential tests against bash | [conformance.md](conformance.md) |
| Agent commands | Normalised corpus from public trajectories and CI runs of agent CLIs | [agent-command-corpus.md](agent-command-corpus.md) |
| Untrusted-input parsers | Continuous fuzzing | [fuzzing.md](fuzzing.md) |
| Performance | Benchmarks against the targets on Apple silicon | [performance-validation.md](performance-validation.md) |
| Sandbox rules | One test per rule (process information, signals, Unix sockets, fixed write denies, system services) | [verification-claims.md](verification-claims.md) |
| Agent CLI presets | Run each supported CLI (Claude Code, Codex CLI) per release; verify how it chooses its shell | [../08-integrations/agent-clis.md](../08-integrations/agent-clis.md) |
| Dependencies | Licence, advisory and duplicate-version checks | [../04-non-functional-requirements/supply-chain.md](../04-non-functional-requirements/supply-chain.md) |

## CI gates per release

- Conformance results against the bash test suite, the bash-compatible subset of the Oils tests, and the corpus.
- Parser exit criterion met (phase 2): at least 95% of corpus lines parsed exactly, every accept/reject verdict matching bash.
- Fuzzers running continuously for JSON, the TOML subset, bash and TLS handshake parsing.
- Dependency checks clean.
- Threat-model suite green (KNSH-075): `scripts/check.sh threat-model` on every macOS version with a runner, its
  report (`target/threat-model/report.md`) published, and its pending items listed.
- Compatibility list of tools published (self-sandboxing tools, proxy behaviour).

## Security test focus

Each row of the threat model ([security](../04-non-functional-requirements/security.md)) has at least one end-to-end
test showing the mitigation holds: the threat-model suite (KNSH-075, [tests/threat-model](../../tests/threat-model/README.md)),
which fails if a row is added without a case. Examples:

- An envelope process cannot connect to `user.sock` or look up the control service.
- `python3 -c "subprocess.run(['git','push'])"` cannot reach an `approval_hosts` host.
- A binary swapped after classification cannot execute.
- Writes to `.git/hooks/`, `.git/config`, shell startup files and `~/Library/LaunchAgents` are denied.
- A hook that times out denies the line.
- Duplicate JSON keys are rejected with `-32700`.
- `force` is refused on `agent.sock`.
