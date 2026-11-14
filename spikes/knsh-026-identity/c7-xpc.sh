#!/bin/bash
# KNSH-026 C7: XPC peer code-signing requirements in both directions.
#
# A launchd-declared Mach service (stand-in for knshd's control service) checks clients
# signed in several ways; a client (stand-in for the authority) checks the service. Also
# covers exec after send, a second job claiming the same name, and a listener outside launchd.
#
# Writes results/c7-<macOS version>.tsv (one row per case) and results/c7-<ver>-service.log
# (what the service saw for each message). Needs a Developer ID Application identity.
set -o pipefail
source "$(dirname "$0")/helpers/common.sh"

if [ -z "$IDENTITY" ]; then
    echo "C7 needs a Developer ID Application identity (pending without one)" >&2
    exit 2
fi

NAME=knsh.spike.026.c7
LABEL=knsh.spike.026.c7
TSV=$RESULTS/c7-$OSVER.tsv
SLOG=$OUT/c7-service.log
D=$OUT/c7
mkdir -p "$D"
: >"$SLOG"
printf 'case\tservice mode\tclient\tclient result\tservice decision\n' >"$TSV"

# FR-AUTH-13: Developer ID (or Mac App Store), trusted team and identifier, and no debugging
# entitlement. Hardened runtime and minimum version cannot be written in the requirement
# language, so the service checks them from the message's SecCode (FR-AUTH-14).
CLIENT_REQ="anchor apple generic and certificate leaf[subject.OU] = \"$TEAM\" and identifier \"knsh.spike.authority\" and ((certificate 1[field.1.2.840.113635.100.6.2.6] exists and certificate leaf[field.1.2.840.113635.100.6.1.13] exists) or certificate leaf[field.1.2.840.113635.100.6.1.9] exists) and !(entitlement[\"com.apple.security.get-task-allow\"] exists)"
# FR-AUTH-15: the authority's requirement for knshd.
SERVICE_REQ="anchor apple generic and certificate leaf[subject.OU] = \"$TEAM\" and identifier \"knsh.spike.knshd\" and certificate 1[field.1.2.840.113635.100.6.2.6] exists and certificate leaf[field.1.2.840.113635.100.6.1.13] exists"
MIN_VERSION=1.0

# infoplist <file> <identifier> <version>: embedded in the binary (__TEXT,__info_plist), so the
# version is covered by the signature and the service can read it from the peer's SecCode.
infoplist() {
    write_plist "$1" <<EOF
<key>CFBundleIdentifier</key><string>$2</string>
<key>CFBundleVersion</key><string>$3</string>
EOF
}

# client <name> <identifier> <version or -> <signer: devid|devid-noruntime|adhoc> [entitlements]
client() {
    local bin=$D/$1 ip=$D/$1.Info.plist sect=()
    if [ "$3" != - ]; then
        infoplist "$ip" "$2" "$3"
        sect=(-Wl,-sectcreate,__TEXT,__info_plist,"$ip")
    fi
    cc_build "$bin" "$SRC/xpc_client.c" "${sect[@]}"
    case $4 in
        devid) sign_devid "$bin" "$2" yes "${5:-}" ;;
        devid-noruntime) sign_devid "$bin" "$2" no "${5:-}" ;;
        adhoc) sign_adhoc "$bin" "$2" "${5:-}" ;;
    esac
}

GTA=$D/get-task-allow.plist
write_plist "$GTA" <<EOF
<key>com.apple.security.get-task-allow</key><true/>
EOF

client good knsh.spike.authority 2.0 devid
client adhoc knsh.spike.authority 2.0 adhoc
client other-id knsh.spike.other 2.0 devid
client get-task-allow knsh.spike.authority 2.0 devid "$GTA"
client no-runtime knsh.spike.authority 2.0 devid-noruntime
client old-version knsh.spike.authority 0.9 devid
client no-version knsh.spike.authority - devid

# service_bin <name> <identifier> <signer: devid|adhoc>
service_bin() {
    local bin=$D/$1 ip=$D/$1.Info.plist
    infoplist "$ip" "$2" 1.0
    cc_build "$bin" "$SRC/xpc_service.c" -framework Security -framework CoreFoundation \
        -Wl,-sectcreate,__TEXT,__info_plist,"$ip"
    if [ "$3" = devid ]; then sign_devid "$bin" "$2" yes; else sign_adhoc "$bin" "$2"; fi
}
service_bin knshd knsh.spike.knshd devid
service_bin impostor-adhoc knsh.spike.knshd adhoc
service_bin impostor-other-id knsh.spike.impostor devid

{
    echo "# signatures"
    for b in "$D"/*; do
        [ -x "$b" ] && [ -f "$b" ] && echo "${b##*/}: $(sig_summary "$b")"
    done
    echo "# client requirement: $CLIENT_REQ"
    echo "# service requirement: $SERVICE_REQ"
} >"$RESULTS/c7-$OSVER-signatures.txt"

# plist <file> <label> <service binary> <mode> [delay ms]
plist() {
    write_plist "$1" <<EOF
<key>Label</key><string>$2</string>
<key>MachServices</key><dict><key>$NAME</key><true/></dict>
<key>ProgramArguments</key><array>
  <string>$3</string><string>$NAME</string><string>$SLOG</string><string>$4</string>
  <string>$CLIENT_REQ</string><string>$MIN_VERSION</string>
</array>
<key>EnvironmentVariables</key><dict><key>DELAY_MS</key><string>${5:-0}</string></dict>
EOF
}

REAL=$D/$LABEL.plist
IMPOSTOR=$D/$LABEL.impostor.plist

# start <binary> <mode> [delay]: (re)load the real job with a given binary and mode.
start() {
    job_down "$IMPOSTOR"
    plist "$REAL" "$LABEL" "$1" "$2" "${3:-0}"
    job_up "$REAL"
}

# slog_after <line count>: the service log lines written after the first <line count> lines.
slog_after() { tail -n +$(($1 + 1)) "$SLOG"; }

# case_ <case> <client binary> [client args...]: run one client, record both sides.
# MODE (global) labels the row with the mode the running service was started in.
case_() {
    local name=$1 bin=$2 before res svc i
    shift 2
    before=$(wc -l <"$SLOG")
    res=$(limit 15 "$bin" "$NAME" "$name" "$@" 2>&1 | tr '\n' ' ')
    # Exec cases: the service handles the message after DELAY_MS; wait for its decision.
    for i in $(seq 1 20); do
        slog_after "$before" | grep -q "decision:\|peer event" && break
        pause 0.25
    done
    pause 0.3 # let the trailing peer events (CONNECTION_INVALID) land in the log too
    {
        echo "== $name (mode $MODE, client ${bin##*/} $*)"
        slog_after "$before"
    } >>"$SLOG.cases"
    svc=$(slog_after "$before" | grep -E 'service start|decision:|pid-based|peer event|by-audit-token' |
        sed -E 's/^ +//; s/service start (server=[^ ]+).*/\1/' | tr '\n' ';' | sed 's/;$//')
    printf '%s\t%s\t%s\t%s\t%s\n' "$name" "$MODE" "${bin##*/} ${*}" "$res" "$svc" >>"$TSV"
    printf '%-34s %-7s %-16s | %s | %s\n' "$name" "$MODE" "${bin##*/}" "$res" "$svc"
}
: >"$SLOG.cases"

# 1. The service rejects clients that do not meet the requirement (FR-AUTH-13, FR-AUTH-14).
for MODE in xpc secode; do
    start "$D/knshd" $MODE
    case_ accept-good "$D/good"
    case_ reject-adhoc "$D/adhoc"
    case_ reject-other-identifier "$D/other-id"
    case_ reject-get-task-allow "$D/get-task-allow"
    case_ reject-no-hardened-runtime "$D/no-runtime"
    case_ reject-old-version "$D/old-version"
    case_ reject-no-version "$D/no-version"
done

# 2. Exec after send: the service handles the message 1 s later, after the sender has
# exec'd another binary in the same process (same pid).
for MODE in secode xpc; do
    start "$D/knshd" $MODE 1000
    case_ exec-untrusted-into-trusted "$D/adhoc" --exec "$D/good"
    case_ exec-trusted-into-untrusted "$D/good" --exec "$D/adhoc"
done

# 3. The client rejects a service that does not meet its requirement (FR-AUTH-15): an
# impostor answers on the same name (the real job is unloaded first).
MODE=secode
for imp in impostor-adhoc impostor-other-id knshd; do
    job_down "$REAL"
    plist "$IMPOSTOR" "$LABEL.impostor" "$D/$imp" secode
    job_up "$IMPOSTOR"
    case_ "client-checks-service:$imp" "$D/good" --service-req "$SERVICE_REQ"
    case_ "client-no-check:$imp" "$D/good"
    job_down "$IMPOSTOR"
done

# 4. FR-AUTH-12: can another job take the name? launchd gives it to whichever job declared
# it first; a later job still loads, with an inactive endpoint.

# owner_log: launchd's most recent refusal of a second declaration of NAME. bootstrap itself
# succeeds, so this log line is the only sign that the later job's endpoint is inactive.
owner_log() {
    /usr/bin/log show --last 15s --style compact --predicate 'process == "launchd"' 2>/dev/null |
        grep "endpoint \"$NAME\" defined in plist already exists" | tail -1 | sed -E 's/^.*\] //'
}

# launchd_row <case> <bootstrap rc> <bootstrap output> <launchd log line>
launchd_row() {
    printf '%s\t-\t-\t%s\t%s\n' "$1" "rc=$2 $(printf '%s' "$3" | tr '\n' ' ')" "launchd: $4" >>"$TSV"
}

MODE=xpc
start "$D/knshd" $MODE
plist "$IMPOSTOR" "$LABEL.impostor" "$D/impostor-adhoc" secode
dup=$(launchctl bootstrap "$DOMAIN" "$IMPOSTOR" 2>&1)
rc=$?
eps=$(owner_log)
echo "second job declaring $NAME: rc=$rc $dup; launchd: $eps" | tee -a "$SLOG.cases"
launchd_row second-job-same-name "$rc" "$dup" "$eps"
case_ after-second-job-good-client "$D/good"
# Reload order reversed: impostor first, then the real job.
job_down "$REAL"
job_down "$IMPOSTOR"
launchctl bootstrap "$DOMAIN" "$IMPOSTOR"
dup=$(launchctl bootstrap "$DOMAIN" "$REAL" 2>&1)
rc=$?
launchd_row real-job-after-impostor "$rc" "$dup" "$(owner_log)"
MODE=secode
case_ after-impostor-first-good-client "$D/good" --service-req "$SERVICE_REQ"
job_down "$IMPOSTOR"
# A listener started outside launchd, for a name launchd holds and for one it does not.
for n in "$NAME" knsh.spike.026.undeclared; do
    : >"$D/listen.log"
    limit 10 "$D/impostor-adhoc" "$n" "$D/listen.log" listen "$CLIENT_REQ" 1.0
    printf 'listener-outside-launchd:%s\t-\t-\texit=%s\t%s\n' "$n" "$?" "$(tr '\n' ' ' <"$D/listen.log")" >>"$TSV"
    echo "listener outside launchd for $n: $(tr '\n' ' ' <"$D/listen.log")"
done

job_down "$REAL"
job_down "$IMPOSTOR"
cp "$SLOG.cases" "$RESULTS/c7-$OSVER-service.log"
scrub "$TSV" "$RESULTS/c7-$OSVER-service.log" "$RESULTS/c7-$OSVER-signatures.txt"
echo "results: $TSV"
