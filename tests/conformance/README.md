# Native-mode conformance (KNSH-109)

Inputs of the phase 4 conformance gate (`tools/conformance`, `scripts/conformance.sh`):

- `fixture/`: the working directory of every corpus run. Each run gets a fresh copy, every timestamp fixed to
  2024-01-01T00:00:00Z. It is not a git repository, so `git` lines fail the same way under every shell.
- `known-differences.tsv`: the corpus lines, Oils cases and bash test drivers on which native mode is known not to
  behave as bash 5.2, each pointing to the heading of `specs/04-non-functional-requirements/compatibility.md` that
  documents it.

Comparison rules: [specs/07-testing/conformance.md](../../specs/07-testing/conformance.md#phase-4-native-mode).
