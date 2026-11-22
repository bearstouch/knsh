#!/usr/bin/env bash
# Phase 4 conformance gate (KNSH-109, NFR-COMPAT-02, NFR-COMPAT-05, NFR-COMPAT-07, NFR-COMPAT-11): native mode against
# bash 5.2 over the agent-command corpus, the bash-compatible subset of the Oils spec tests and bash's own test suite.
#
#   scripts/conformance.sh             report only (the gate is measured, a shortfall does not fail)
#   KNSH_RELEASE=1 scripts/conformance.sh   enforce the gate, as CI does on a v* tag
#
# The reference bash 5.2 and the bash test suite come from the GNU bash 5.2.37 source, the Oils spec tests from a
# pinned Oils commit. Both are downloaded once into target/conformance/src/ and checked against their SHA-256 before
# anything is extracted or built; a mismatch stops the run. Bash 5.2 is built from that source with the test helpers
# (recho, zecho, printenv, xcase), so the reference is the exact release the gate is defined against (Homebrew ships
# newer bash). Cargo itself stays offline: only these two pinned archives are fetched, with curl.
#
# The report goes to target/conformance/report.md (CI adds it to the job summary and uploads it as the
# native-conformance-report artefact). Store a release's copy under specs/07-testing/qualification/.
#
# Settings: KNSH_CONFORMANCE_JOBS (parallel runs, default: CPU count), KNSH_CONFORMANCE_TIMEOUT (seconds per run,
# default 10).
#
# Needs: macOS (Seatbelt confines every run), a C compiler, curl, python3 (the Oils helpers), network for the first
# download.
#
# Exit status: 0 when the gate passes (report only: when the corpus ran); 1 otherwise, or when a download, build or
# run fails. The report is written before the exit whenever the runs completed.
set -euo pipefail

cd "$(dirname "$0")/.."

if [[ "$(uname -s)" != Darwin ]]; then
    echo "conformance: macOS only" >&2
    exit 1
fi

readonly BASH_RELEASE=5.2.37
readonly BASH_URL="https://ftp.gnu.org/gnu/bash/bash-${BASH_RELEASE}.tar.gz"
readonly BASH_SHA256=9599b22ecd1d5787ad7d3b7bf0c59f312b3396d1e281175dd1f8a4014da621ff
readonly OILS_COMMIT=d114978ca467143f171a835cbcbe8ab6ccc009a7
readonly OILS_URL="https://codeload.github.com/oils-for-unix/oils/tar.gz/${OILS_COMMIT}"
readonly OILS_SHA256=08ee1e0f8160288f9e9e8ee7816128ab6b3498276775baa9d3ba9cca2f002022

readonly ROOT="$PWD/target/conformance"
readonly SRC="$ROOT/src"
readonly PREFIX="$ROOT/bash-${BASH_RELEASE}"

export CARGO_NET_OFFLINE=true

# fetch URL SHA256 FILE: downloads URL to FILE unless FILE already has SHA256; fails on a checksum mismatch.
fetch() {
    local url="$1" sha="$2" file="$3"
    if [[ -f "$file" ]] && [[ "$(shasum -a 256 "$file" | cut -d' ' -f1)" == "$sha" ]]; then
        return 0
    fi
    rm -f "$file" "$file.part"
    curl -fsSL --retry 3 --max-time 300 -o "$file.part" "$url"
    local got
    got="$(shasum -a 256 "$file.part" | cut -d' ' -f1)"
    if [[ "$got" != "$sha" ]]; then
        rm -f "$file.part"
        echo "conformance: $url: SHA-256 $got, expected $sha" >&2
        return 1
    fi
    mv "$file.part" "$file"
}

mkdir -p "$SRC"
fetch "$BASH_URL" "$BASH_SHA256" "$SRC/bash-${BASH_RELEASE}.tar.gz"
fetch "$OILS_URL" "$OILS_SHA256" "$SRC/oils-${OILS_COMMIT}.tar.gz"

if [[ ! -d "$SRC/bash-${BASH_RELEASE}" ]]; then
    tar -xzf "$SRC/bash-${BASH_RELEASE}.tar.gz" -C "$SRC"
fi
if [[ ! -d "$SRC/oils-${OILS_COMMIT}" ]]; then
    tar -xzf "$SRC/oils-${OILS_COMMIT}.tar.gz" -C "$SRC"
fi

# The reference bash 5.2 and the test suite's helpers, built once.
if [[ ! -x "$PREFIX/bin/bash" || ! -x "$SRC/bash-${BASH_RELEASE}/recho" ]]; then
    (
        cd "$SRC/bash-${BASH_RELEASE}"
        ./configure --prefix="$PREFIX" --without-bash-malloc --disable-nls >/dev/null
        make -j"$(sysctl -n hw.ncpu)" >/dev/null
        make install >/dev/null
        make recho zecho printenv xcase >/dev/null
    )
fi
"$PREFIX/bin/bash" --version | head -1

# The suite's tests directory with its helpers beside the scripts (run-all puts `.` first in PATH for them).
rm -rf "$ROOT/bash-tests"
cp -R "$SRC/bash-${BASH_RELEASE}/tests" "$ROOT/bash-tests"
for helper in recho zecho printenv xcase; do
    cp "$SRC/bash-${BASH_RELEASE}/$helper" "$ROOT/bash-tests/"
done

cargo build --release --offline --locked -p knsh-conformance

flags=(
    --bash "$PREFIX/bin/bash"
    --oils "$SRC/oils-${OILS_COMMIT}"
    --bash-tests "$ROOT/bash-tests"
    --work "$ROOT/work"
    --report "$ROOT/report.md"
)
if [[ -n "${KNSH_CONFORMANCE_JOBS:-}" ]]; then
    flags+=(--jobs "$KNSH_CONFORMANCE_JOBS")
fi
if [[ -n "${KNSH_CONFORMANCE_TIMEOUT:-}" ]]; then
    flags+=(--timeout "$KNSH_CONFORMANCE_TIMEOUT")
fi
if [[ "${GITHUB_REF:-}" == refs/tags/v* || "${KNSH_RELEASE:-}" == 1 ]]; then
    flags+=(--enforce)
fi
target/release/knsh-conformance "${flags[@]}" >/dev/null
