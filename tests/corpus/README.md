# Agent-command corpus

Normalised command lines that agents run, used to measure the parser, classifier and interpreter (decision 7).
Format, normalisation rules, tags and provenance: [specs/07-testing/agent-command-corpus.md](../../specs/07-testing/agent-command-corpus.md).

- `sources.tsv`: every source with its licence and origin.
- `<source-id>.txt`: one entry per line, `source<TAB>licence<TAB>tags<TAB>command`.

Do not edit entries by hand unless you rerun the gate; add lines with the importer:

```sh
cargo run -p knsh-corpus -- import --source <id> [--tag TAG] <trace>
cargo run -p knsh-corpus -- check
```

No user telemetry: only published trajectories and CI traces whose licences allow redistribution.
