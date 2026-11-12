# Agent-command corpus

A corpus of agent-generated command lines used for parser, classifier and compatibility tests (decision 7).

## Sources

| Source | Status |
| --- | --- |
| Published agent trajectories from public coding benchmarks, where licences allow | Initial |
| Traces from running supported agent CLIs on open-source repositories in CI | Initial |
| Opt-in `knsh corpus export`, which shows the user every line before sharing | Later |

No user telemetry is used.

## Normalisation

Every line is normalised before it enters the corpus: paths, user names, hosts and anything secret-like become placeholders.

## Uses

- Parser exit criterion ([conformance.md](conformance.md))
- Native-mode compatibility target (99%)
- Bash 3.2 vs 5.2 differences agents rely on
- Classifier coverage: wrappers, dynamic code, irreversible commands
