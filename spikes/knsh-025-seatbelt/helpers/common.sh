# Shared helpers for the KNSH-025 spike harnesses (sourced, bash 3.2 compatible).

# limit <seconds> <cmd...>: run cmd with a hard time limit (SIGALRM; exit 142 on expiry).
# A hang is a result to record, never a stuck harness.
limit() { perl -e 'alarm shift; exec @ARGV or exit 127' "$@"; }

# wait_for_log <stream file> <tag prefix>: block until the running `log stream` is delivering
# Seatbelt denials, by repeatedly causing a tagged canary denial until it shows up.
#
# Why: `log stream` was observed to take more than 2 s to attach on macOS 26.6; denials before
# that are never delivered to the stream (they stay readable later with `log show`). A sleep is
# not enough, so the KNSH-047 reader needs the same readiness check.
wait_for_log() {
    local stream=$1 prefix=$2 dir canary prof i ready=1
    dir=$(mktemp -d)
    dir=$(cd "$dir" && pwd -P)
    canary=$dir/canary
    : >"$canary"
    prof=$dir/canary.sb
    printf '(version 1)\n(allow default)\n(deny file-read-data (literal "%s") (with message "%s:canary"))\n' \
        "$canary" "$prefix" >"$prof"
    for i in $(seq 1 60); do
        sandbox-exec -f "$prof" /bin/cat "$canary" >/dev/null 2>&1
        sleep 0.5
        if grep -q "$prefix:canary" "$stream" 2>/dev/null; then
            ready=0
            break
        fi
    done
    rm -rf "$dir"
    if ((ready == 0)); then
        echo "log stream ready after ~$((i / 2)) s" >&2
    else
        echo "log stream not ready after 30 s" >&2
    fi
    return $ready
}

# scrub <file>...: replace the repository location, the user's home, per-user temp directory
# and host name with placeholders in result files before they are committed (paths are
# personal; the formats are what matter).
scrub() {
    local home user repo
    home=$(cd "$HOME" && pwd -P)
    user=$(basename "$home")
    repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd -P)
    # The temp-dir pattern stops at '/' or '"' so truncated paths inside JSON strings match too.
    # zsh names its completion dump after the host: ~/.zcompdump-<host>-<zsh version>.
    sed -i '' -E -e 's#/(private/)?var/folders/[^/]+/[^/"]+#/\1var/folders/XX/XXXXXXXX#g' \
        -e "s#$repo#<repo>#g" -e "s#$home#/Users/USER#g" -e "s#[[:<:]]$user[[:>:]]#USER#g" \
        -e 's#\.zcompdump-[^/	]*-([0-9.]+)#.zcompdump-HOST-\1#g' "$@"
}
