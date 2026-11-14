#!/bin/bash
# KNSH-026 C6: can a launchd user agent show the Touch ID / password prompt, with custom
# text holding a command line, and what happens without a GUI session?
#
#   c6-touchid.sh [case regex] [timeout seconds]
#
# Cases (each writes results/c6-<macOS>-<case>.txt):
#   terminal-noui   control: the probe from the terminal with interaction disallowed
#   agent-noui      as a launchd agent in the GUI domain, interaction disallowed
#   agent-prompt    as a launchd agent in the GUI domain: shows the prompt. A human must
#                   answer it (Touch ID, password or Cancel) before the timeout (default 120 s)
#   bg-prompt       as a launchd agent in the per-user background domain (user/<uid>), the
#                   domain that exists without a GUI login (SSH): does a prompt appear?
#
# With KNSH_SPIKE_SCREENSHOT=1, a screenshot is taken 4 s after a prompting case starts, to
# $OUT/c6-<case>.png (never committed: it shows the whole desktop).
set -o pipefail
source "$(dirname "$0")/helpers/common.sh"

FILTER=${1:-.}
TIMEOUT=${2:-120}
LA=$OUT/la
# The reason text a real approval would carry: the exact command, its directory and session.
REASON='approve the agent command: git push --force origin main (cwd ~/src/app, session 01JD3Q9ZKX8M4T2V6B7N5C1H0E)'

cc_build "$LA" "$SRC/la.m" -fobjc-arc -framework Foundation -framework LocalAuthentication \
    -framework Security || exit 1
if [ -n "$IDENTITY" ]; then sign_devid "$LA" knsh.spike.knshd yes; else sign_adhoc "$LA" knsh.spike.knshd; fi

# agent <case> <domain> <policy> <timeout>: run the probe as a launchd job and wait for it.
agent() {
    local case=$1 domain=$2 policy=$3 t=$4 label=knsh.spike.026.la.$1
    local plist=$OUT/$label.plist res=$OUT/c6-$case.out
    rm -f "$res"
    # The user/<uid> domain refuses a job without this key ("5: Input/output error", observed).
    local session_key=
    case $domain in user/*) session_key='<key>LimitLoadToSessionType</key><string>Background</string>' ;; esac
    write_plist "$plist" <<EOF
<key>Label</key><string>$label</string>
<key>ProgramArguments</key><array>
  <string>$LA</string><string>$res</string><string>$t</string><string>$policy</string><string>$REASON</string>
</array>
<key>RunAtLoad</key><true/>
<key>StandardErrorPath</key><string>$OUT/$label.err</string>
$session_key
EOF
    launchctl bootout "$domain" "$plist" 2>/dev/null
    if ! launchctl bootstrap "$domain" "$plist" 2>"$OUT/$label.bootstrap"; then
        echo "bootstrap_failed=$(tr '\n' ' ' <"$OUT/$label.bootstrap")" >"$res"
    elif [ "${KNSH_SPIKE_SCREENSHOT:-0}" = 1 ] && [ "$policy" != owner-noui ]; then
        pause "${KNSH_SPIKE_SCREENSHOT_DELAY:-4}"
        screencapture -x "$OUT/c6-$case.png"
    fi
    # Wait for the probe's final line: up to the timeout, plus its 5 s invalidate grace and
    # launch slack (polled every 0.5 s).
    local i
    for i in $(seq 1 $((t * 2 + 30))); do
        grep -q '^success=\|^bootstrap_failed=' "$res" 2>/dev/null && break
        pause 0.5
    done
    echo "launchd_domain=$domain label=$label" >>"$res"
    launchctl print "$domain/$label" 2>/dev/null | grep -m3 -E '^\s*(state|last exit code|domain) =' |
        sed 's/^[[:space:]]*/launchd_/' >>"$res"
    launchctl bootout "$domain" "$plist" 2>/dev/null
    finish "$case" "$res"
}

finish() { # finish <case> <raw result>
    local dst=$RESULTS/c6-$OSVER-$1.txt
    # With the lid closed the Touch ID sensor is unusable, so the prompt falls back to the
    # password even though biometry is reported available (observed).
    local clamshell
    clamshell=$(ioreg -r -k AppleClamshellState -d 4 | sed -nE 's/.*"AppleClamshellState" = (Yes|No).*/\1/p' | head -1)
    {
        echo "case=$1 macos=$OSVER date=$(date -u +%FT%TZ) clamshell_closed=${clamshell:-unknown}"
        echo "reason=$REASON"
        cat "$2"
    } >"$dst"
    scrub "$dst"
    echo "== $1"
    cat "$dst"
}

UIDN=$(id -u)
for case in terminal-noui agent-noui agent-prompt bg-prompt; do
    printf '%s\n' "$case" | grep -qE "$FILTER" || continue
    case $case in
        terminal-noui)
            "$LA" "$OUT/c6-$case.out" 5 owner-noui "$REASON"
            echo "launchd_domain=none (child of the terminal)" >>"$OUT/c6-$case.out"
            finish "$case" "$OUT/c6-$case.out"
            ;;
        agent-noui) agent "$case" "gui/$UIDN" owner-noui 5 ;;
        agent-prompt) agent "$case" "gui/$UIDN" owner "$TIMEOUT" ;;
        bg-prompt) agent "$case" "user/$UIDN" owner "$TIMEOUT" ;;
    esac
done
