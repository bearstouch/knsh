# Shared helpers for the KNSH-077 spike harnesses (sourced, bash 3.2 compatible).

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
RESULTS=$HERE/results

# Work files live outside the repository and outside Spotlight: the repository may sit under ~/Desktop (which
# iCloud may sync), and a 100,000-file tree indexed by Spotlight would load the machine during the timings and
# add file events. A `*.noindex` folder is skipped by Spotlight (observed in KNSH-011, C11). Must be on the APFS
# volume under test: checkpoints and their roots share a volume (FR-CKP-35).
OUT=${KNSH_SPIKE_077_DIR:-$HOME/.cache/knsh-spike-077.noindex}
# The harnesses delete folders under $OUT: refuse a work folder that is the root or the home folder itself.
case "$(cd "$OUT" 2>/dev/null && pwd -P || echo "$OUT")" in
/ | "$HOME" | "$(cd "$HOME" && pwd -P)") echo "refusing work folder $OUT" >&2; exit 2 ;;
esac
BIN=$OUT/bin
mkdir -p "$BIN" "$RESULTS"

OSVER=$(sw_vers -productVersion)

# cc_build <out> <source> <extra clang args...>
cc_build() {
    local out=$1 src=$2
    shift 2
    clang -O2 -Wall -Wextra -mmacosx-version-min=14.0 -o "$out" "$src" "$@"
}

# limit <seconds> <cmd...>: run cmd with a hard time limit (SIGALRM; exit 142 on expiry).
limit() { perl -e 'alarm shift; exec @ARGV or exit 127' "$@"; }

# machine: one header block describing where the run happened.
machine() {
    echo "# date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "# macOS: $(sw_vers -productVersion) ($(sw_vers -buildVersion)), $(uname -m)"
    echo "# cpu: $(sysctl -n machdep.cpu.brand_string), $(sysctl -n hw.ncpu) CPUs, $(($(sysctl -n hw.memsize) / 1073741824)) GiB"
    echo "# volume: $(diskutil info "$(df "$OUT" | awk 'NR==2 {print $1}')" 2>/dev/null |
        awk -F': *' '/File System Personality|Solid State|Protocol/ {printf "%s=%s; ", $1, $2}' | sed 's/  */ /g')"
}

# scrub: replace the home folder and user name with placeholders.
scrub() { sed -e "s|$HOME|~|g" -e "s|$(id -un)|<user>|g"; }
