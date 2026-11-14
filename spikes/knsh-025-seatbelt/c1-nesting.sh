#!/bin/bash
# KNSH-025 spike, claim C1: a sandboxed process cannot apply a second sandbox.
#
#   spikes/knsh-025-seatbelt/c1-nesting.sh [--with-agents] [case-filter-regex]
#
# Runs each tool three ways: unsandboxed (control), inside the envelope profile
# (profiles/envelope.sb) with the tool's own sandbox ON, and inside the envelope with the
# tool's own sandbox OFF. A case passes when its marker (a random string the tool can only
# print by actually doing the work) appears in the output. --with-agents also runs Claude
# Code and Codex CLI, which call a model with the user's own credentials (billed).
#
# Output: results/c1-<macOS version>.tsv (one row per case) and
# results/c1-<macOS version>-denials.txt (tagged denials seen during the run, de-duplicated).
# Throwaway spike code: never shipped, never called by the product.
set -uo pipefail

HERE=$(cd "$(dirname "$0")" && pwd -P)
OS=$(sw_vers -productVersion)
AGENTS=0
FILTER=.
for a in "$@"; do
    case $a in
        --with-agents) AGENTS=1 ;;
        *) FILTER=$a ;;
    esac
done

ROOT=$(mktemp -d -t knsh-c1)
ROOT=$(cd "$ROOT" && pwd -P)
WORK=$ROOT/work
mkdir -p "$WORK" "$ROOT/socks" "$ROOT/logs" "$HERE/results"
MARK="knsh-$(od -An -N6 -tx1 /dev/urandom | tr -d ' \n')"
echo "$MARK" > "$WORK/marker.txt"
OUT=$HERE/results/c1-$OS.tsv
printf 'case\tmode\trc\tmarker\tnote\n' > "$OUT"

# shellcheck source=helpers/common.sh
. "$HERE/helpers/common.sh"

envelope() { # envelope <session tag> -> path of rendered profile
    "$HERE/helpers/render.sh" "$HERE/profiles/envelope.sb" "$ROOT/$1.sb" "$WORK" "$ROOT/socks" "$1"
    # VARIANT=allow-ls drops the LaunchServices deny: app bundles such as Google Chrome.app
    # abort at start-up without LaunchServices (observed), which would hide the nesting result.
    if [[ ${VARIANT:-} == allow-ls ]]; then
        sed -i '' '/^;; BEGIN launchservices/,/^;; END launchservices/d' "$ROOT/$1.sb"
    fi
    echo "$ROOT/$1.sb"
}

# skip <case> <note>: record a case that could not run on this machine.
skip() { printf '%s\t-\t-\t-\t%s\n' "$1" "$2" | tee -a "$OUT"; }

# run <case> <mode: control|own-on|own-off> <timeout s> <cmd...>
run() {
    local name=$1 mode=$2 secs=$3
    shift 3
    [[ "$name" =~ $FILTER ]] || return 0
    local log=$ROOT/logs/$name-$mode.log rc
    if [[ $mode == control ]]; then
        (cd "$WORK" && limit "$secs" "$@") >"$log" 2>&1
        rc=$?
    else
        local prof
        prof=$(envelope "c1-$name-$mode") || return 1
        (cd "$WORK" && limit "$secs" sandbox-exec -f "$prof" "$@") >"$log" 2>&1
        rc=$?
    fi
    local found=no note
    grep -q "$MARK" "$log" && found=yes
    # The first line that explains a failure: nested sandbox errors first, then any error.
    note=$(grep -m1 -i -E 'sandbox[^ ]* (init|apply)|sandbox_apply|Operation not permitted|error' "$log" |
        cut -c1-160 | tr '\t' ' ')
    [[ $rc == 142 ]] && note="TIMEOUT after ${secs}s; $note"
    printf '%s\t%s\t%s\t%s\t%s\n' "$name" "$mode" "$rc" "$found" "$note" | tee -a "$OUT"
}

# Tagged denials for the whole run (C2 evidence as a by-product).
/usr/bin/log stream --style compact --predicate 'sender == "Sandbox" AND eventMessage CONTAINS "knsh:c1-"' \
    >"$ROOT/denials.log" 2>/dev/null &
LOGPID=$!
trap 'kill $LOGPID 2>/dev/null' EXIT
wait_for_log "$ROOT/denials.log" knsh:c1- || exit 1

PAGE="data:text/html,<p>$MARK</p>"

# --- Chromium: Playwright's headless shell build --------------------------------------
HS=$(ls -d "$HOME"/Library/Caches/ms-playwright/chromium_headless_shell-*/chrome-headless-shell-mac-arm64/chrome-headless-shell 2>/dev/null | tail -1)
if [[ -x "$HS" ]]; then
    run chromium-headless-shell control 60 "$HS" --headless --dump-dom "$PAGE"
    run chromium-headless-shell own-on 60 "$HS" --headless --dump-dom "$PAGE"
    run chromium-headless-shell own-off 60 "$HS" --headless --no-sandbox --dump-dom "$PAGE"
else
    skip chromium-headless-shell "not installed"
fi

# --- Chromium: the installed Google Chrome app, in a throwaway profile directory ---------
# (Playwright's "Chrome for Testing" bundle was not used: on the test machine its signature
# was invalid, so it hung or aborted even unsandboxed. Each run gets its own
# --user-data-dir, so the user's own Chrome profile is never touched.)
GC="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
if [[ -x "$GC" ]]; then
    for mode in control own-on own-off; do
        # Arguments after --user-data-dir, identical for both variants.
        rest=(--no-first-run --no-default-browser-check)
        [[ $mode == own-off ]] && rest+=(--no-sandbox)
        rest+=(--dump-dom "$PAGE")
        run google-chrome "$mode" 90 "$GC" --headless=new --user-data-dir="$WORK/gc-$mode" "${rest[@]}"
        [[ $mode == control ]] && continue
        VARIANT=allow-ls run google-chrome+ls "$mode" 90 "$GC" --headless=new --user-data-dir="$WORK/gcls-$mode" "${rest[@]}"
    done
else
    skip google-chrome "not installed"
fi

# --- Playwright (Node): chromiumSandbox false is its default ---------------------------
PW=$HOME/.cache/knsh-spike-025-pw
if [[ -d "$PW/node_modules/playwright-core" && -x "$HS" ]]; then
    cat >"$WORK/pw.js" <<EOF
const { chromium } = require('$PW/node_modules/playwright-core');
(async () => {
  const sandbox = process.argv[2] === 'sandbox';
  const b = await chromium.launch({ executablePath: '$HS', chromiumSandbox: sandbox });
  const p = await b.newPage();
  await p.goto('$PAGE');
  console.log(await p.textContent('p'));
  await b.close();
})().catch(e => { console.error('error: ' + e.message.split('\n')[0]); process.exit(1); });
EOF
    NODE=$(command -v node)
    run playwright control 90 "$NODE" "$WORK/pw.js" sandbox
    run playwright own-on 90 "$NODE" "$WORK/pw.js" sandbox
    run playwright own-off 90 "$NODE" "$WORK/pw.js" default
else
    skip playwright "playwright-core not installed in $PW"
fi

# --- swift build: SwiftPM compiles and runs Package.swift under its own sandbox ---------
mkdir -p "$WORK/swiftpkg/Sources/hello"
cat >"$WORK/swiftpkg/Package.swift" <<'EOF'
// swift-tools-version:5.9
import PackageDescription
let package = Package(name: "hello", targets: [.executableTarget(name: "hello")])
EOF
echo "print(\"$MARK\")" >"$WORK/swiftpkg/Sources/hello/main.swift"
SWIFT=/usr/bin/swift
swiftcase() { # swiftcase <mode> [--disable-sandbox]; fresh build dir per mode, then run the product
    local mode=$1
    shift
    rm -rf "$WORK/swiftpkg/.build"
    # --manifest-cache none: SwiftPM sandboxes only manifest *evaluation*; a manifest cached by
    # an earlier run skips it and hides the nesting failure (observed).
    run swift-build "$mode" 300 /bin/bash -c \
        "cd '$WORK/swiftpkg' && $SWIFT build --manifest-cache none $* 2>&1 && .build/debug/hello"
}
swiftcase control
swiftcase own-on
swiftcase own-off --disable-sandbox

# --- Agent CLIs (billed: they call a model with the user's credentials) -----------------
if ((AGENTS)); then
    PROMPT="Use your shell tool to run exactly: cat marker.txt  Then reply with only that command's output."
    CLAUDE=$(command -v claude)
    if [[ -n "$CLAUDE" ]]; then
        # allowUnsandboxedCommands=false: by default, when its sandbox fails Claude Code lets the
        # model retry the command unsandboxed (dangerouslyDisableSandbox), which hid the nesting
        # failure in an earlier run. Strict mode measures the sandbox itself.
        ON='{"sandbox":{"enabled":true,"autoAllowBashIfSandboxed":true,"allowUnsandboxedCommands":false}}'
        OFF='{"sandbox":{"enabled":false}}'
        run claude-code control 180 "$CLAUDE" -p "$PROMPT" --model haiku --settings "$ON" --allowedTools "Bash(cat:*)" </dev/null
        run claude-code own-on 180 "$CLAUDE" -p "$PROMPT" --model haiku --settings "$ON" --allowedTools "Bash(cat:*)" </dev/null
        run claude-code own-off 180 "$CLAUDE" -p "$PROMPT" --model haiku --settings "$OFF" --allowedTools "Bash(cat:*)" </dev/null
    fi
    CODEX=$(command -v codex)
    if [[ -n "$CODEX" ]]; then
        # Codex hangs before main() while its binary is still quarantined; a 20 s probe keeps
        # that from costing three full time-outs.
        if limit 20 "$CODEX" --version </dev/null >/dev/null 2>&1; then
            run codex control 180 "$CODEX" exec --skip-git-repo-check -s workspace-write "$PROMPT"
            run codex own-on 180 "$CODEX" exec --skip-git-repo-check -s workspace-write "$PROMPT"
            run codex own-off 180 "$CODEX" exec --skip-git-repo-check -s danger-full-access "$PROMPT"
        else
            skip codex "BLOCKED: codex --version does not start within 20 s outside any sandbox (quarantined binary, Gatekeeper)"
        fi
    fi
fi

sleep 3
kill $LOGPID 2>/dev/null
# De-duplicate denials: strip timestamps and pids, count each distinct message.
DENIALS=$HERE/results/c1-$OS-denials.txt
grep -A1 'Sandbox: ' "$ROOT/denials.log" | grep -v '^--$' | paste - - |
    sed -E 's/^.*Sandbox: //; s/\([0-9]+\)//' | sort | uniq -c | sort -rn >"$DENIALS"
scrub "$OUT" "$DENIALS"
echo "results: $OUT; logs kept in $ROOT/logs"
