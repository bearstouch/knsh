#!/usr/bin/env bash
# Runs the quality gates: format, lint, build, docs, test, corpus, parser differential, dependency checks.
#
#   scripts/check.sh            run every step, in order (the same order as CI)
#   scripts/check.sh <step>...  run only the named steps (CI runs one step per job step)
#
# CI (.github/workflows/ci.yml) calls this script for every step, so local runs and CI
# cannot drift apart. Any failing step exits non-zero; there are no optional steps.
#
# Requires: the toolchain from rust-toolchain.toml (rustup installs it) and cargo-deny
# (`cargo install --locked cargo-deny`; a developer tool, never a workspace dependency).
set -euo pipefail

cd "$(dirname "$0")/.."

readonly ALL_STEPS=(fmt clippy build doc test corpus difftest deny)

# Belt and braces with .cargo/config.toml ([net] offline = true): cargo itself never
# touches the network (NFR-SUP-03).
export CARGO_NET_OFFLINE=true

# Seatbelt profile that refuses every IP connection, so a build script that tries to
# download anything fails instead of silently succeeding (NFR-SUP-03).
readonly NO_NETWORK_PROFILE='(version 1)(allow default)(deny network-outbound (remote ip))(deny network-inbound (local ip))'

step_fmt() {
    cargo fmt --all --check
}

step_clippy() {
    cargo clippy --workspace --all-targets --locked -- -D warnings
}

step_build() {
    # Clean first so every build script really runs under the no-network profile
    # instead of being skipped as up to date. `-D warnings` makes "zero warnings" a gate.
    cargo clean
    RUSTFLAGS="-D warnings" sandbox-exec -p "$NO_NETWORK_PROFILE" \
        cargo build --workspace --offline --locked
}

step_doc() {
    RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked
}

step_test() {
    cargo test --workspace --offline --locked
}

step_corpus() {
    # Agent-command corpus gate (KNSH-033, NFR-PRIV-08): fails on a malformed or unnormalised line, a raw home path
    # or token, or an entry without a registered source and licence. `cargo test` runs the same check; this step
    # prints the per-source and per-tag counts.
    cargo run --quiet --offline --locked -p knsh-corpus -- check --corpus tests/corpus
}

step_difftest() {
    # Parser differential against real bash over the corpus (KNSH-034, NFR-COMPAT-07): every line's accept or reject
    # verdict must match /bin/bash (3.2) and any Homebrew bash 5.x; a mismatch fails. The report (bash versions,
    # exact-parse share, mismatches) is written to target/difftest/report.md for CI to publish. The 95% exact gate
    # is enforced on release runs: a v* tag in CI, or KNSH_RELEASE=1 locally.
    local flags=(--report target/difftest/report.md)
    if [[ "${GITHUB_REF:-}" == refs/tags/v* || "${KNSH_RELEASE:-}" == 1 ]]; then
        flags+=(--enforce-exact)
    fi
    cargo run --quiet --offline --locked -p knsh-difftest -- "${flags[@]}"
}

step_deny() {
    # Licences, advisories and duplicate versions (NFR-SUP-04).
    if ! command -v cargo-deny >/dev/null 2>&1; then
        echo "cargo-deny is not installed: cargo install --locked cargo-deny" >&2
        return 1
    fi
    # Advisories need the RustSec database, so this is the only step with network access.
    # It runs from outside the repository so that .cargo/config.toml (crates.io replaced by
    # vendor/) does not apply: with the replacement active, cargo-deny cannot read the
    # crates.io index and `yanked = "deny"` silently degrades to an `index-failure` warning
    # on a fresh CARGO_HOME (as in CI). `--locked` keeps Cargo.lock unchanged.
    local root
    root="$(pwd)"
    (
        cd "${TMPDIR:-/tmp}"
        CARGO_NET_OFFLINE=false cargo deny --locked --manifest-path "$root/Cargo.toml" \
            --config "$root/deny.toml" check
    )
}

if [[ $# -eq 0 ]]; then
    set -- "${ALL_STEPS[@]}"
fi

for step in "$@"; do
    if ! declare -F "step_$step" >/dev/null; then
        echo "unknown step: $step (known: ${ALL_STEPS[*]})" >&2
        exit 2
    fi
done

for step in "$@"; do
    printf '\n==> %s\n' "$step"
    "step_$step"
done

printf '\nAll requested checks passed: %s\n' "$*"
