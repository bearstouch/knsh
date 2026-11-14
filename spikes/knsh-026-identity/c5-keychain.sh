#!/bin/bash
# KNSH-026 C5: can a Keychain item be limited to knshd's code signature across updates and
# Homebrew builds, and kept from an unrelated binary of the same user?
#
# For each signing scheme, "build 1" creates a generic-password item and then build 2 (same
# identifier, different code), an unrelated binary, and an unrelated binary inside a sandbox
# try to read, overwrite and delete it. Every probe runs with user interaction disabled, so a
# would-be "allow access" dialog is reported as a status instead of blocking.
#
# Writes results/c5-<macOS version>.tsv. Items use the service prefix knsh.spike.026. and are
# deleted at the end (by the binary that can).
set -o pipefail
source "$(dirname "$0")/helpers/common.sh"

TSV=$RESULTS/c5-$OSVER.tsv
ACL=$RESULTS/c5-$OSVER-acl.txt
: >"$ACL"
printf 'scheme\tactor\top\tstatus\tdetail\n' >"$TSV"

# Keychain data lives in files the client library writes itself (observed: a sandbox
# file-write deny on this directory makes writes fail with EPERM while reads still work).
KCDIR=$(cd "$HOME/Library/Keychains" && pwd -P)

# build <output path> <BUILD number>: BUILD changes the code, so each build has its own hash.
build() {
    cc_build "$1" "$SRC/kc.c" -DBUILD="$2" -framework Security -framework CoreFoundation
}

# run <scheme> <actor label> <binary> <op> <store> <service> [value] [sandbox profile]
run() {
    local scheme=$1 actor=$2 bin=$3 op=$4 store=$5 svc=$6 value=${7:-} sb=${8:-} line rc sandbox=()
    [ -n "$sb" ] && sandbox=(sandbox-exec -f "$sb")
    # $value is unquoted on purpose: an empty value passes no argument, so kc writes its build tag.
    line=$(limit 20 "${sandbox[@]}" "$bin" "$op" "$store" "$svc" acct $value 2>&1)
    rc=$?
    # 137: killed (AMFI); 142: hung past the limit.
    case $rc in 137 | 142) line="exit=$rc $line" ;; esac
    printf '%s\t%s\t%s\t%s\t%s\n' "$scheme" "$actor" "$op" \
        "$(printf '%s' "$line" | sed -nE 's/.*(status=-?[0-9]+).*/\1/p;s/^(exit=[0-9]+).*/\1/p' | head -1)" \
        "$(printf '%s' "$line" | tr '\t\n' '  ')" >>"$TSV"
    printf '%-10s %-28s %s\n' "$scheme" "$actor" "$line"
}

# Sandbox profile for the "agent inside an envelope" actor: allow everything except writes
# to the Keychain directory (the KNSH-025 envelope already denies Keychain files to agents by
# default; this isolates the one rule under test).
SB_NOWRITE=$OUT/kc-nowrite.sb
printf '(version 1)\n(allow default)\n(deny file-write* (subpath "%s"))\n' "$KCDIR" >"$SB_NOWRITE"
SB_NONE=$OUT/kc-allow.sb
printf '(version 1)\n(allow default)\n' >"$SB_NONE"

build "$OUT/kc-b1" 1
build "$OUT/kc-b2" 2
build "$OUT/kc-other" 3

# Signing schemes. "homebrew" keeps the linker's ad-hoc signature (identifier = file name),
# which is what a formula built from source ends up with on Apple Silicon.
for scheme in adhoc homebrew devid; do
    if [ "$scheme" = devid ] && [ -z "$IDENTITY" ]; then
        echo "no Developer ID identity: devid scheme pending" >&2
        continue
    fi
    b1=$OUT/$scheme-1/knshd b2=$OUT/$scheme-2/knshd other=$OUT/$scheme-other/other
    mkdir -p "${b1%/*}" "${b2%/*}" "${other%/*}"
    cp "$OUT/kc-b1" "$b1"
    cp "$OUT/kc-b2" "$b2"
    cp "$OUT/kc-other" "$other"
    case $scheme in
        adhoc)
            sign_adhoc "$b1" knsh.spike.knshd
            sign_adhoc "$b2" knsh.spike.knshd
            sign_adhoc "$other" knsh.spike.other
            ;;
        homebrew)
            # Rebuild in place so the linker signature names the file (knshd), as Homebrew's does.
            build "$b1" 1
            build "$b2" 2
            sign_homebrew "$b2" # bottle relocation re-sign on build 2
            ;;
        devid)
            sign_devid "$b1" knsh.spike.knshd yes
            sign_devid "$b2" knsh.spike.knshd yes
            sign_devid "$other" knsh.spike.other yes # same team, different identifier
            ;;
    esac
    {
        echo "## $scheme"
        for b in "$b1" "$b2" "$other"; do echo "${b#$OUT/}: $(sig_summary "$b")"; done
    } >>"$ACL"

    svc=knsh.spike.026.$scheme
    # Leftovers from an interrupted run would turn "add" into a duplicate error.
    for b in "$b1" "$b2"; do "$b" delete legacy "$svc" acct >/dev/null 2>&1; done

    run "$scheme" build1-creates "$b1" add legacy "$svc"
    "$b1" acl legacy "$svc" acct >>"$ACL" 2>&1
    run "$scheme" build1-reads "$b1" read legacy "$svc"
    run "$scheme" build2-reads "$b2" read legacy "$svc"
    run "$scheme" unrelated-reads "$other" read legacy "$svc"
    run "$scheme" unrelated-sandboxed-reads "$other" read legacy "$svc" "" "$SB_NONE"
    run "$scheme" unrelated-deletes "$other" delete legacy "$svc"
    run "$scheme" sandboxed-no-kc-write-overwrites "$other" update legacy "$svc" forged-in-sandbox "$SB_NOWRITE"
    run "$scheme" build1-reads-after-sandbox "$b1" read legacy "$svc"
    # The same write deny must still let a process read its own item.
    run "$scheme" build1-reads-in-no-kc-write-sandbox "$b1" read legacy "$svc" "" "$SB_NOWRITE"
    run "$scheme" unrelated-overwrites "$other" update legacy "$svc" forged
    run "$scheme" build1-reads-after-overwrite "$b1" read legacy "$svc"
    run "$scheme" build2-overwrites "$b2" update legacy "$svc" written-by-build2
    run "$scheme" build1-deletes "$b1" delete legacy "$svc"

    # Pre-seeding: an unrelated binary creates the item before knshd ever runs.
    run "$scheme" unrelated-preseeds "$other" add legacy "$svc.seed" planted
    run "$scheme" build1-reads-preseeded "$b1" read legacy "$svc.seed"
    run "$scheme" build1-adds-over-preseeded "$b1" add legacy "$svc.seed"
    run "$scheme" build1-deletes-preseeded "$b1" delete legacy "$svc.seed"
    "$other" delete legacy "$svc.seed" acct >/dev/null 2>&1
    # Pre-seeding from inside the write-deny sandbox.
    run "$scheme" sandboxed-no-kc-write-preseeds "$other" add legacy "$svc.sbseed" planted "$SB_NOWRITE"
    "$other" delete legacy "$svc.sbseed" acct >/dev/null 2>&1
done

# Switching distribution: an item created by a Homebrew build, then read by the Developer ID
# release of the same identifier (and the reverse).
if [ -n "$IDENTITY" ]; then
    svc=knsh.spike.026.switch
    run switch homebrew-creates "$OUT/homebrew-1/knshd" add legacy "$svc"
    run switch devid-reads-homebrew-item "$OUT/devid-1/knshd" read legacy "$svc"
    run switch homebrew-deletes "$OUT/homebrew-1/knshd" delete legacy "$svc"
    run switch devid-creates "$OUT/devid-1/knshd" add legacy "$svc"
    run switch homebrew-reads-devid-item "$OUT/homebrew-1/knshd" read legacy "$svc"
    run switch devid-deletes "$OUT/devid-1/knshd" delete legacy "$svc"
fi

# Overwrites of a Developer ID item by code outside the team. An overwrite replaces the
# item's partition list with the writer's partition ID (observed), so these show whether the
# result is a silent forgery or a read failure in knshd.
if [ -n "$IDENTITY" ]; then
    svc=knsh.spike.026.cross
    K=$OUT/devid-1/knshd
    for writer in adhoc security-tool; do
        run cross devid-creates "$K" add legacy "$svc"
        if [ "$writer" = adhoc ]; then
            run cross "adhoc-unrelated-overwrites" "$OUT/adhoc-other/other" update legacy "$svc" forged
        else
            # Apple's own tool: its partition ID is apple-tool:, outside any team.
            out=$(limit 15 /usr/bin/security add-generic-password -U -s "$svc" -a acct -w forged 2>&1)
            printf 'cross\tsecurity-tool-overwrites\tupdate\texit=%s\t/usr/bin/security add-generic-password -U: %s\n' \
                "$?" "$out" >>"$TSV"
        fi
        echo "## cross: after $writer overwrote a devid item" >>"$ACL"
        "$K" acl legacy "$svc" acct | grep partition >>"$ACL"
        run cross "devid-reads-after-$writer-overwrite" "$K" read legacy "$svc"
        run cross "devid-deletes" "$K" delete legacy "$svc"
    done
fi

# Data-protection keychain: needs keychain-access-groups (or an application identifier),
# which AMFI treats as restricted entitlements that need a provisioning profile.
ENT_KAG=$OUT/kag.plist
write_plist "$ENT_KAG" <<EOF
<key>keychain-access-groups</key><array><string>${TEAM:-TEAMID0000}.knsh.spike</string></array>
EOF
svc=knsh.spike.026.dp
run dp no-entitlement-devid "$OUT/devid-1/knshd" add dp "$svc"
run dp no-entitlement-adhoc "$OUT/adhoc-1/knshd" add dp "$svc"
mkdir -p "$OUT/dp"
cp "$OUT/kc-b1" "$OUT/dp/knshd-adhoc-kag"
sign_adhoc "$OUT/dp/knshd-adhoc-kag" knsh.spike.knshd "$ENT_KAG"
run dp adhoc-with-access-group "$OUT/dp/knshd-adhoc-kag" add "dp:${TEAM:-TEAMID0000}.knsh.spike" "$svc"
if [ -n "$IDENTITY" ]; then
    cp "$OUT/kc-b1" "$OUT/dp/knshd-devid-kag"
    sign_devid "$OUT/dp/knshd-devid-kag" knsh.spike.knshd yes "$ENT_KAG"
    run dp devid-with-access-group-no-profile "$OUT/dp/knshd-devid-kag" add "dp:$TEAM.knsh.spike" "$svc"
fi
# Why the entitled builds die: AMFI's log line (kernel, not tagged by process).
/usr/bin/log show --last 1m --style compact 2>/dev/null |
    grep -A3 'AMFI: When validating .*knsh-spike-026/dp/' | head -6 >>"$ACL"

# Every item this run created must be gone (dump-keychain lists attributes only, no secrets).
left=$(security dump-keychain 2>/dev/null | grep -o '"knsh\.spike\.026[^"]*"' | sort -u | tr '\n' ' ')
[ -n "$left" ] && echo "LEFTOVER Keychain items: $left (delete them with the binary that created them)" >&2

scrub "$TSV" "$ACL"
echo "results: $TSV"
