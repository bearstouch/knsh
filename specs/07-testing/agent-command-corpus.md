# Agent-command corpus

A corpus of agent-generated command lines used for parser, classifier and compatibility tests (decision 7).
Implemented by [KNSH-033](../00-stories/KNSH-033-agent-command-corpus-pipeline.md).

## Sources

| Source | Status |
| --- | --- |
| Hand-written seed (`knsh-seed`), modelled on common agent command shapes | Present |
| Published agent trajectories from public coding benchmarks, where licences allow | Pipeline ready; no source imported yet |
| Traces from running supported agent CLIs on open-source repositories in CI | Pipeline ready; no source imported yet |
| Opt-in `knsh corpus export`, which shows the user every line before sharing | Later ([KNSH-124](../00-stories/KNSH-124-opt-in-knsh-corpus-export.md)) |

No user telemetry is used (NFR-PRIV-08). Every source, its licence and its origin are listed in
`tests/corpus/sources.tsv`; that file is the provenance record.

### Provenance

| Source ID | Licence | Origin |
| --- | --- | --- |
| `knsh-seed` | MIT | Written by the Kinetic Shell maintainers for KNSH-033. Not copied from any trajectory, trace or user session. |

A new source is added by registering it in `sources.tsv` (ID, SPDX licence, origin with URL, benchmark or agent and
version, and any attribution the licence requires), then importing its trace. Allowed licences: MIT, Apache-2.0,
BSD-2-Clause, BSD-3-Clause, ISC, CC0-1.0, CC-BY-4.0, Unlicense. A source whose licence does not allow redistribution
with the repository is not imported.

## Format

Versioned text files under `tests/corpus/`:

- `sources.tsv`: header `# knsh-corpus sources 1`, then `id<TAB>licence<TAB>origin` per source.
- `<source-id>.txt`: header `# knsh-corpus 1`, then one entry per line: `source<TAB>licence<TAB>tags<TAB>command`.
  The command escapes `\`, newline, tab and carriage return as `\\`, `\n`, `\t`, `\r`, so multi-line commands stay on
  one line; other control characters are not allowed. Tags are sorted, comma-separated, or `-`. Commands are at most
  16 KiB, and a file holds no duplicate command.

Every entry records its source and licence, and both must match `sources.tsv`.

### Tags

| Tag | Meaning | Set by |
| --- | --- | --- |
| `b32-missing` | Uses a construct bash 3.2 lacks (associative arrays, namerefs, `mapfile`, `${x,,}`, `${x@Q}`, `\|&`, `&>>`, `;&`, `globstar`, `coproc`, `{01..10}`, `{1..9..2}`, …). NFR-COMPAT-05. | Importer; required by the gate |
| `b32-differs` | Parses in bash 3.2 but behaves differently from 5.2 (for example `set -u` with an empty array). NFR-COMPAT-05. | Hand |
| `multiline` | Spans several lines. | Importer; required by the gate |
| `heredoc` | Contains a here-document. | Importer |
| `wrapper`, `dynamic`, `irreversible`, `network` | Classifier coverage. | Hand (`--tag` on import) |

## Normalisation

Every line is normalised before it enters the corpus: paths, user names, hosts and anything secret-like become
placeholders. Normalisation is idempotent (the passes repeat until the line stops changing), and placeholders contain no shell metacharacters, so a line keeps its shell
structure.

| Value | Placeholder | Kept |
| --- | --- | --- |
| `/Users/<name>`, `/home/<name>`, `~name` | `/Users/__USER__`, `/home/__USER__`, `~__USER__` | `/Users/Shared`, `/Users/runner`, variables and globs |
| `/var/folders/<xx>/<id>` | `/var/folders/__TMP__` | |
| URL user info `user:password@` | `__USER__:__SECRET__@` | `git@`, `x-access-token@`, `$VAR` |
| E-mail addresses | `__EMAIL__` | `git@host:org/repo` |
| User name in `user@<IPv4>`; `user:password` after `-u`/`--user` | `__USER__@`, `__USER__:__SECRET__` | `git@`, numeric IDs (`-u 1000:1000`), `$VAR` |
| Hosts under `.internal`, `.lan`, `.corp`, `.intranet`, `.home.arpa`, `.localdomain`; `.local` after `://` or `@` | `__HOST__` | Public hosts (`github.com`) |
| IPv4 and IPv6 addresses | `__IP__` | Loopback and unspecified (`127.0.0.1`, `0.0.0.0`, `::1`, `::`) |
| Known token prefixes (`ghp_`, `github_pat_`, `sk-`, `xox?-`, `glpat-`, `npm_`, `pypi-`, `hf_`, `AKIA`, `AIza`, …), JWTs | `__SECRET__` | |
| Values of secret-named variables and flags (`*_TOKEN=`, `*PASSWORD=`, `*_API_KEY=`, `--password`, `--client-secret`) and `Bearer`/`Basic` credentials | `__SECRET__` | References (`$TOKEN`, `"$(cat key)"`), empty values |
| High-entropy strings (≥ 32 bytes, mixed case with digits, ≥ 4 bits per byte) and hex longer than 40 | `__SECRET__` | Commit IDs, UUIDs, identifiers |
| User and host names given to the importer (`--user`, `--host`) | `__USER__`, `__HOST__` | |

Known limits: a user name containing a space inside a quoted path keeps the part after the space; `user@host` without
a dotted domain is only caught when the names are given with `--user`/`--host`. CI traces must pass the runner's user
and host names.

## Tooling and CI gate

`tools/corpus` (`knsh-corpus`, dev-only, depends only on `knsh-json`; nothing may depend on it):

```sh
cargo run -p knsh-corpus -- import --source <id> [--format jsonl --field message.content.input.command] \
    [--user NAME] [--host NAME] [--tag TAG] <trace>
cargo run -p knsh-corpus -- check            # also run by `cargo test` and `scripts/check.sh corpus`
```

The gate fails CI when a file is malformed, an entry lacks a registered source or matching licence, a command changes
when normalised again, an independent leak scan finds a raw `/Users/<name>`, `/home/<name>`, token pattern or private
key, or a bash 4+ construct or multi-line command lacks its tag. Error messages never quote the raw command. Import
writes only entries that pass the gate, replaces files atomically, and never overwrites a file that fails it.

## Uses

- Parser exit criterion ([conformance.md](conformance.md))
- Native-mode compatibility target (99%)
- Bash 3.2 vs 5.2 differences agents rely on
- Classifier coverage: wrappers, dynamic code, irreversible commands
