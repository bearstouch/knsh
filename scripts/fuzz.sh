#!/usr/bin/env bash
# Runs the fuzz targets in fuzz/ for a fixed time each (KNSH-005; NFR-SUP-06;
# specs/07-testing/fuzzing.md).
#
#   scripts/fuzz.sh                    every target, 60 s each (the CI smoke run)
#   scripts/fuzz.sh <seconds>          every target, <seconds> each
#   scripts/fuzz.sh <seconds> <target>...   only the named targets
#
# A crash, a hang (> 10 s on one input) or a property failure exits non-zero, and
# libFuzzer saves the input under fuzz/artifacts/<target>/. To keep it as a regression,
# copy it into fuzz/regressions/<target>/: `cargo test` then replays it on stable.
#
# New inputs the fuzzer finds go to a temporary corpus; the checked-in seeds in
# fuzz/corpus/<target>/ are read but never modified. For an open-ended local run that
# grows the checked-in corpus, use `cargo +nightly fuzz run <target>` (fuzz/README.md).
#
# Requires: the nightly toolchain below and cargo-fuzz (`cargo install --locked
# cargo-fuzz@0.13.2`), both developer tools, never workspace dependencies.
set -euo pipefail

cd "$(dirname "$0")/.."

# Pinned so a CI failure is reproducible; bump deliberately, like rust-toolchain.toml.
readonly TOOLCHAIN="${KNSH_FUZZ_TOOLCHAIN:-nightly-2026-11-01}"
readonly ALL_TARGETS=(json_reader json_writer_roundtrip frame_reader toml_parser bash_lex bash_parse sandbox_log proxy_handshake tls_client_hello redactor)

# The fuzz dependencies are vendored in vendor/ like everything else (NFR-SUP-03).
export CARGO_NET_OFFLINE=true

# CI installs exactly this toolchain: `rustup toolchain install "$(scripts/fuzz.sh --print-toolchain)"`.
if [[ "${1:-}" == --print-toolchain ]]; then
    echo "$TOOLCHAIN"
    exit 0
fi

seconds="${1:-60}"
if [[ $# -gt 0 ]]; then shift; fi
if [[ $# -gt 0 ]]; then targets=("$@"); else targets=("${ALL_TARGETS[@]}"); fi

# Extra libFuzzer flags per target, for properties a check cannot observe itself.
target_flags() {
    case "$1" in
        # NFR-SEC-07: a payload is at most 1 MiB, so no single allocation may reach
        # 2 MiB, whatever length prefix the input declares (libFuzzer counts whole MiB
        # and already flags an allocation of exactly 1 MiB at a 1 MiB limit).
        frame_reader) echo "-malloc_limit_mb=2" ;;
        # NFR-SEC-07: the ClientHello reader allocates at most one hello (16 KiB and its header),
        # whatever a length field claims, so no allocation may reach 1 MiB.
        tls_client_hello) echo "-malloc_limit_mb=1" ;;
        json_reader | json_writer_roundtrip | toml_parser | bash_lex | bash_parse | sandbox_log | proxy_handshake | redactor) echo "" ;;
        *) echo "unknown fuzz target: $1" >&2; exit 2 ;;
    esac
}

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

for target in "${targets[@]}"; do
    flags="$(target_flags "$target")"
    echo "==> fuzz $target for ${seconds}s"
    mkdir -p "$work/$target"
    # shellcheck disable=SC2086 # $flags is a list of flags
    cargo "+$TOOLCHAIN" fuzz run "$target" "$work/$target" "fuzz/corpus/$target" -- \
        -max_total_time="$seconds" -timeout=10 $flags
done
echo "All fuzz targets ran ${seconds}s without a failure: ${targets[*]}"
