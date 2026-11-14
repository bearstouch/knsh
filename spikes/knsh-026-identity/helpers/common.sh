# Shared helpers for the KNSH-026 spike harnesses (sourced, bash 3.2 compatible).

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
SRC=$HERE/src
RESULTS=$HERE/results

# Binaries live outside the repository: the repository may sit under ~/Desktop, and launchd
# blocks on a TCC consent prompt when a job's program is under ~/Desktop, ~/Documents or
# ~/Downloads (observed in KNSH-012).
OUT=${KNSH_SPIKE_026_DIR:-$HOME/.cache/knsh-spike-026}
mkdir -p "$OUT"

OSVER=$(sw_vers -productVersion)

# The Developer ID Application identity, or empty when none is installed. Override with
# KNSH_SPIKE_IDENTITY (a SHA-1 hash or a name).
IDENTITY=${KNSH_SPIKE_IDENTITY:-$(security find-identity -v -p codesigning |
    awk -F'"' '/Developer ID Application/ {print $2; exit}')}
TEAM=$(printf '%s' "$IDENTITY" | sed -nE 's/.*\(([A-Z0-9]{10})\)$/\1/p')

# limit <seconds> <cmd...>: run cmd with a hard time limit (SIGALRM; exit 142 on expiry).
limit() { perl -e 'alarm shift; exec @ARGV or exit 127' "$@"; }

# pause <seconds>: fractional sleep (perl, so it does not depend on which sleep(1) is first in PATH).
pause() { perl -e 'select undef, undef, undef, shift' "$1"; }

# write_plist <file>: write a plist whose top-level dict holds the XML read from stdin.
write_plist() {
    {
        echo '<?xml version="1.0" encoding="UTF-8"?>'
        echo '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">'
        echo '<plist version="1.0"><dict>'
        cat
        echo '</dict></plist>'
    } >"$1"
}

# cc_build <out> <source> <extra clang args...>: compile; the linker signs ad hoc on arm64.
cc_build() {
    local out=$1 src=$2
    shift 2
    clang -O1 -Wall -Wno-deprecated-declarations -mmacosx-version-min=14.0 -o "$out" "$src" "$@"
}

# codesign_quiet <codesign args...>: codesign without the "replacing existing signature" noise.
# Never fails the caller: a signing failure shows up in sig_summary and in the probe's result.
codesign_quiet() {
    codesign "$@" 2>&1 | grep -v 'replacing existing signature' || true
}

# sign_adhoc <binary> <identifier> [entitlements]
sign_adhoc() {
    local ent=()
    [ -n "${3:-}" ] && ent=(--entitlements "$3")
    codesign_quiet -f -s - -i "$2" "${ent[@]}" "$1"
}

# sign_devid <binary> <identifier> <runtime: yes|no> [entitlements]
# --timestamp=none: no network; a missing secure timestamp does not affect local checks.
sign_devid() {
    local opts=() ent=()
    [ "$3" = yes ] && opts=(-o runtime)
    [ -n "${4:-}" ] && ent=(--entitlements "$4")
    codesign_quiet -f -s "$IDENTITY" --timestamp=none -i "$2" "${opts[@]}" "${ent[@]}" "$1"
}

# sign_homebrew <binary>: the signature a Homebrew-built binary ends up with. The linker signs
# it ad hoc ("linker-signed", identifier = file name); when Homebrew patches a binary (bottle
# relocation) it re-signs it ad hoc (ruby-macho on Apple Silicon, `codesign --sign - --force
# --preserve-metadata=...` on Intel; Library/Homebrew/extend/os/mac/keg.rb). Either way the
# result is an ad-hoc signature whose only identity is its code hash.
sign_homebrew() {
    codesign_quiet --sign - --force --preserve-metadata=entitlements,requirements,flags,runtime "$1"
}

# sig_summary <binary>: one line with the signature facts that matter here.
sig_summary() {
    local d
    d=$(codesign -dvvv "$1" 2>&1)
    printf 'id=%s flags=%s team=%s auth=%s cdhash=%.12s\n' \
        "$(printf '%s\n' "$d" | sed -n 's/^Identifier=//p')" \
        "$(printf '%s\n' "$d" | sed -n 's/^CodeDirectory.*flags=\([^ ]*\).*/\1/p')" \
        "$(printf '%s\n' "$d" | sed -n 's/^TeamIdentifier=//p')" \
        "$(printf '%s\n' "$d" | sed -n 's/^Authority=//p' | head -1)" \
        "$(printf '%s\n' "$d" | sed -n 's/^CDHash=//p')"
}

# scrub <file>...: replace personal data (home, user, team ID, signing name, temp dirs)
# with placeholders before results are committed.
scrub() {
    local home user repo name
    home=$(cd "$HOME" && pwd -P)
    user=$(basename "$home")
    repo=$(cd "$HERE/../.." && pwd -P)
    name=$(printf '%s' "$IDENTITY" | sed -nE 's/^Developer ID Application: (.*) \([A-Z0-9]{10}\)$/\1/p')
    sed -i '' -E -e 's#/(private/)?var/folders/[^/]+/[^/"]+#/\1var/folders/XX/XXXXXXXX#g' \
        -e "s#$repo#<repo>#g" -e "s#$home#/Users/USER#g" -e "s#[[:<:]]$user[[:>:]]#USER#g" \
        ${TEAM:+-e "s#$TEAM#TEAMID0000#g"} ${name:+-e "s#$name#DEVELOPER NAME#g"} "$@"
}

# launchd helpers: a job in the GUI domain of the current user.
DOMAIN=gui/$(id -u)
job_up() { # job_up <plist>
    launchctl bootout "$DOMAIN" "$1" 2>/dev/null || true
    launchctl bootstrap "$DOMAIN" "$1"
}
job_down() { launchctl bootout "$DOMAIN" "$1" 2>/dev/null || true; }
