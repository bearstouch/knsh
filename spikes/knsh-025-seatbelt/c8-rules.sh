#!/bin/bash
# KNSH-025 spike, claim C8: Seatbelt can limit process information, signals, Unix-socket
# connections and system services as sandbox-profiles.md specifies. One test per rule.
#
#   spikes/knsh-025-seatbelt/c8-rules.sh
#
# Each case runs a probe under a deny-by-default "command" base profile plus the rule under
# test, and compares the outcome with the expected one. A case also records whether a log
# entry carrying its unique tag was seen (C2: every deny must be reportable).
#
# Output: results/c8-<macOS version>.tsv. Exit status 0 when every case matched expectations
# (documented gaps are expected outcomes, not failures), 1 otherwise.
# Throwaway spike code: never shipped, never called by the product.
set -uo pipefail

HERE=$(cd "$(dirname "$0")" && pwd -P)
OS=$(sw_vers -productVersion)
mkdir -p "$HERE/.build" "$HERE/results"
clang -Wall -O1 -o "$HERE/.build/probe" "$HERE/helpers/probe.c" -framework CoreServices || exit 1
P=$HERE/.build/probe
# The real interpreter, not /usr/bin/python3 (an xcrun shim that needs caches and Xcode tools).
PY=$(command -v python3)

ROOT=$(mktemp -d -t knsh-c8)
ROOT=$(cd "$ROOT" && pwd -P)
TMP=$(cd "$(getconf DARWIN_USER_TEMP_DIR)" && pwd -P)
OUT=$HERE/results/c8-$OS.tsv
printf 'id\trule (SBPL)\tprobe\texpected\tobserved\tmatch\tlogged\n' >"$OUT"
FAILED=0

# shellcheck source=helpers/common.sh
. "$HERE/helpers/common.sh"

# Deny-by-default command base: what a supervised line gets before the rule under test.
base() {
    cat <<EOF
(version 1)
(deny default (with message "knsh:c8:$1:default"))
(allow process-exec process-fork file-read* file-ioctl sysctl-read mach-lookup
       ipc-posix-shm* ipc-posix-sem iokit-open user-preference-read system-socket)
(allow file-write* (literal "/dev/null") (literal "/dev/dtracehelper") (subpath "$TMP")
       (subpath "$ROOT"))
(allow network-outbound (remote ip))
EOF
}

# check <id> <expected allowed|denied> <rule, may use @TAG@> <description> <cmd...>
# A command "allowed" means exit 0; anything else (including a 10 s time-out) is "denied".
check() {
    local id=$1 expected=$2 rule=$3 desc=$4
    shift 4
    local tag="knsh:c8:$id" prof=$ROOT/$id.sb
    { base "$id"; echo "${rule//@TAG@/$tag}"; } >"$prof"
    local out rc observed
    out=$(limit 10 sandbox-exec -f "$prof" "$@" 2>&1)
    rc=$?
    if ((rc == 0)); then observed=allowed; else observed=denied; fi
    ((rc == 142)) && observed="denied (hung: killed after 10 s)"
    local match=yes
    [[ $observed == "$expected"* ]] || { match=NO; FAILED=1; }
    # One TSV row per case: multi-line rules are flattened.
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$id" "${rule//$'\n'/ }" "$desc" "$expected" \
        "$observed: $(echo "$out" | tail -1 | cut -c1-90)" "$match" "@LOG:$tag@" >>"$OUT"
    echo "$id: $observed (expected $expected)"
}

# --- Fixtures ------------------------------------------------------------------------------
# A victim in its own process group (outside ours), and one in our group but unsandboxed.
env KNSH_SPIKE_SECRET=hunter2 "$P" newpgrp /bin/sleep 300 &
OUTSIDE=$!
/bin/sleep 300 &
SAMEPG=$!
# /bin/sleep is an Apple platform binary, and macOS withholds the environment of platform
# binaries only. A non-platform victim (an ad-hoc-signed copy of sleep) shows what an agent's
# own tools (node, python, ...) expose (KNSH-025 review).
cp /bin/sleep "$ROOT/sleep-adhoc" && codesign -s - -f "$ROOT/sleep-adhoc" 2>/dev/null
env KNSH_SPIKE_SECRET=hunter2 "$P" newpgrp "$ROOT/sleep-adhoc" 300 &
NONPLATFORM=$!
# Unix socket servers: agent.sock (allowed) and user.sock (fixed deny).
for s in agent user; do
    "$PY" -I -c 'import socket,sys,time
s=socket.socket(socket.AF_UNIX); s.bind(sys.argv[1]); s.listen(64); time.sleep(300)' "$ROOT/$s.sock" &
done
ln -s "$ROOT/user.sock" "$ROOT/link-to-user.sock"
DOCKER=$(cd "$HOME/.docker/run" 2>/dev/null && pwd -P)/docker.sock
SSHAGENT=${SSH_AUTH_SOCK:-}
trap 'kill $OUTSIDE $SAMEPG $NONPLATFORM $(jobs -p) 2>/dev/null' EXIT
sleep 1

/usr/bin/log stream --style compact --predicate 'sender == "Sandbox" AND eventMessage CONTAINS "knsh:c8:"' \
    >"$ROOT/denials.log" 2>/dev/null &
LOGPID=$!
wait_for_log "$ROOT/denials.log" knsh:c8 || exit 1

SIG_SS='(allow signal (target same-sandbox))'
SIG_PG='(allow signal (target pgrp))'
# Process information needs two rules: reading another process's argv (KERN_PROCARGS2) or
# kinfo_proc (KERN_PROC_*) is allowed when EITHER process-info OR sysctl-read allows it
# (observed), so both are denied for targets outside the sandbox.
PI_ONLY='(deny process-info* (with message "@TAG@")) (allow process-info* (target same-sandbox))'
PI="$PI_ONLY
(deny sysctl-read (sysctl-name-prefix \"kern.procargs\") (sysctl-name-prefix \"kern.proc.\") (with message \"@TAG@\"))"

# --- Signals (spec: own process group only) ------------------------------------------------
check sig-outside-group denied "$SIG_SS" "kill -0 a process in another group" "$P" kill "$OUTSIDE" 0
check sig-own-child allowed "$SIG_SS" "fork a child and SIGTERM it" "$P" child-signal
check sig-same-group-unsandboxed denied "$SIG_SS" "kill -0 an unsandboxed process in our group" "$P" kill "$SAMEPG" 0
check sig-pgrp-same-group-unsandboxed allowed "$SIG_PG" "pgrp form: unsandboxed process in our group" "$P" kill "$SAMEPG" 0
# Control for the escape below: without setpgid, the pgrp form denies the outside process.
check sig-pgrp-outside-group denied "$SIG_PG" "pgrp form: kill -0 a process in another group (control)" "$P" kill "$OUTSIDE" 0
# Join the outside victim's process group, then signal it.
SETPGID_ESCAPE="import os; os.setpgid(0, $OUTSIDE); os.kill($OUTSIDE, 0)"
check sig-pgrp-setpgid-escape allowed "$SIG_PG" "pgrp form: setpgid into another group, then signal it (GAP)" \
    "$PY" -I -c "$SETPGID_ESCAPE"
check sig-same-sandbox-setpgid-escape denied "$SIG_SS" "same-sandbox form: setpgid escape attempt" \
    "$PY" -I -c "$SETPGID_ESCAPE"
check sig-no-rule denied "" "deny default alone: kill -0 outside" "$P" kill "$OUTSIDE" 0

# --- Process information (spec: own process group only; others' args and env hidden) ------
check pinfo-no-rule-pidinfo allowed "" "deny default alone: proc_pidinfo of outside process (GAP)" "$P" pidinfo "$OUTSIDE"
check pinfo-pidinfo denied "$PI" "proc_pidinfo of outside process" "$P" pidinfo "$OUTSIDE"
check pinfo-pidpath denied "$PI" "proc_pidpath of outside process" "$P" pidpath "$OUTSIDE"
check pinfo-self allowed "$PI" "proc_pidpath of self" /bin/bash -c "exec $P pidpath \$\$"
check pinfo-listpids denied "$PI" "proc_listpids (no per-target filter: all or nothing)" "$P" listpids
check pinfo-procargs-argv-partial allowed "$PI_ONLY" "KERN_PROCARGS2 argv of outside process, process-info rule alone (GAP)" "$P" procargs "$OUTSIDE"
check pinfo-procargs-sysctl-only allowed "(deny sysctl-read (sysctl-name-prefix \"kern.procargs\") (with message \"@TAG@\"))" \
    "KERN_PROCARGS2 argv of outside process, sysctl rule alone (GAP)" "$P" procargs "$OUTSIDE"
check pinfo-procargs-argv denied "$PI" "KERN_PROCARGS2 argv of outside process, both rules" "$P" procargs "$OUTSIDE"
check pinfo-procargs-self allowed "$PI" "KERN_PROCARGS2 of self, both rules" /bin/bash -c "exec $P procargs \$\$"
check pinfo-kproc-all-partial allowed "$PI_ONLY" "KERN_PROC_ALL process list, process-info rule alone (GAP)" "$P" kproc all
check pinfo-kproc-all denied "$PI" "KERN_PROC_ALL process list, both rules" "$P" kproc all
check pinfo-kproc-other denied "$PI" "KERN_PROC_PID of outside process, both rules" "$P" kproc "$OUTSIDE"
check pinfo-kproc-self allowed "$PI" "KERN_PROC_PID of self, both rules" /bin/bash -c "exec $P kproc \$\$"
# Environment: the OS omits a *platform* binary's environment from KERN_PROCARGS2, but not
# that of a non-platform binary of the same user (GAP), which the two rules must close.
# unsandboxed <id> <description> <expected> <pid> <expected secret_visible value>
unsandboxed_env() {
    local out match=yes
    out=$("$P" procargs "$4")
    [[ $out == *secret_visible=$5* ]] || { match=NO; FAILED=1; }
    printf '%s\t(none; unsandboxed)\t%s\t%s\t%s\t%s\t-\n' "$1" "$2" "$3" "$out" "$match" >>"$OUT"
    echo "$1: $out (expected $3)"
}
unsandboxed_env pinfo-procargs-env "KERN_PROCARGS2 env of another same-user process (platform binary /bin/sleep)" \
    "not visible" "$OUTSIDE" 0
unsandboxed_env pinfo-procargs-env-nonplatform \
    "KERN_PROCARGS2 env of another same-user process (non-platform binary) (GAP)" visible "$NONPLATFORM" 1
check pinfo-procargs-env-nonplatform-partial allowed "$PI_ONLY" "KERN_PROCARGS2 env of a non-platform outside process, process-info rule alone (GAP)" "$P" procargs "$NONPLATFORM"
check pinfo-procargs-env-nonplatform denied "$PI" "KERN_PROCARGS2 env of a non-platform outside process, both rules" "$P" procargs "$NONPLATFORM"
check pinfo-ps-exec denied "(allow default)" "exec /bin/ps (setuid root) in any sandbox, even allow-default" /bin/ps -E -p "$OUTSIDE"

# --- Unix sockets (spec: agent.sock for envelopes; user.sock, Docker, SSH agent denied) ----
SOCK="(allow network-outbound (remote unix-socket (path-literal \"$ROOT/agent.sock\")))
(deny network-outbound (remote unix-socket (path-literal \"$ROOT/user.sock\")) (with message \"@TAG@\"))"
check sock-agent allowed "$SOCK" "connect agent.sock" "$P" connect "$ROOT/agent.sock"
check sock-user denied "$SOCK" "connect user.sock (fixed deny)" "$P" connect "$ROOT/user.sock"
check sock-user-symlink denied "$SOCK" "connect user.sock through a symlink" "$P" connect "$ROOT/link-to-user.sock"
check sock-user-noncanonical denied "$SOCK" "connect user.sock by a /var (non-canonical) path" "$P" connect "${ROOT#/private}/user.sock"
[[ -S $DOCKER ]] && check sock-docker denied "$SOCK" "connect the Docker socket" "$P" connect "$DOCKER"
[[ -S $SSHAGENT ]] && check sock-ssh-agent denied "$SOCK" "connect the SSH agent socket" "$P" connect "$SSHAGENT"
check sock-user-under-allow-all denied "(allow network-outbound) (deny network-outbound (remote unix-socket (path-literal \"$ROOT/user.sock\")) (with message \"@TAG@\"))" \
    "user.sock deny wins over a broad network allow" "$P" connect "$ROOT/user.sock"

# --- System services ------------------------------------------------------------------------
LS='(deny mach-lookup (global-name "com.apple.coreservices.launchservicesd" "com.apple.lsd.mapdb" "com.apple.lsd.modifydb" "com.apple.CoreServices.coreservicesd") (with message "@TAG@"))'
check svc-ls-query denied "$LS" "LaunchServices database query" "$P" lsquery com.apple.Safari
check svc-ls-query-control allowed "" "same query without the rule (control)" "$P" lsquery com.apple.Safari
AE='(deny mach-lookup (global-name "com.apple.coreservices.appleevents") (with message "@TAG@"))'
check svc-ae-lookup denied "$AE" "look up the Apple Events service" "$P" lookup com.apple.coreservices.appleevents
check svc-ae-osascript denied "$AE $LS" "osascript sends an Apple Event to Finder" \
    /usr/bin/osascript -e 'tell application "Finder" to get version'
JOB='(deny job-creation (with message "@TAG@"))'
check svc-launchd-submit denied "$JOB" "launchctl submit" /bin/launchctl submit -l knsh.spike.c8 -- /usr/bin/true
cat >"$ROOT/job.plist" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>Label</key><string>knsh.spike.c8b</string>
<key>ProgramArguments</key><array><string>/usr/bin/true</string></array></dict></plist>
EOF
check svc-launchd-bootstrap denied "$JOB" "launchctl bootstrap gui/<uid> <plist>" /bin/launchctl bootstrap "gui/$(id -u)" "$ROOT/job.plist"
check svc-launchd-no-rule denied "" "deny default alone: launchctl submit" /bin/launchctl submit -l knsh.spike.c8c -- /usr/bin/true
# Whatever the outcome, never leave a job behind.
for job in knsh.spike.c8 knsh.spike.c8c; do launchctl remove "$job" 2>/dev/null; done
launchctl bootout "gui/$(id -u)/knsh.spike.c8b" 2>/dev/null
DNS='(deny mach-lookup (global-name "com.apple.dnssd.service") (with message "@TAG@"))
(deny network-outbound (remote unix-socket (path-literal "/private/var/run/mDNSResponder")) (with message "@TAG@"))'
check svc-dns-curl denied "$DNS" "curl resolves example.com (system resolver)" /usr/bin/curl -sS -m 5 -o /dev/null http://example.com
check svc-dns-localhost allowed "$DNS" "getaddrinfo(\"localhost\") still resolves with the resolver denied" \
    "$PY" -I -c 'import socket; socket.getaddrinfo("localhost", 80)'
check svc-dns-loopback-literal allowed "$DNS" "getaddrinfo(\"127.0.0.1\") (numeric: no resolver)" \
    "$PY" -I -c 'import socket; socket.getaddrinfo("127.0.0.1", 80, flags=socket.AI_NUMERICHOST)'
check svc-dns-host-direct-udp allowed "$DNS (allow network-bind network-inbound (local ip))" \
    "host(1) sends DNS over UDP itself, bypassing the resolver rule (GAP)" /usr/bin/host -W 3 example.com
check svc-dns-host-network-rule denied "$DNS (allow network-bind network-inbound (local ip)) (deny network-outbound (remote ip) (with message \"@TAG@\")) (allow network-outbound (remote ip \"localhost:*\"))" \
    "host(1) with outbound limited to loopback (the envelope's network rule)" /usr/bin/host -W 3 example.com
CTL='(deny mach-lookup (global-name "com.knsh.control") (with message "@TAG@"))'
check svc-control-lookup denied "$CTL" "look up the knsh control service by name" "$P" lookup com.knsh.control
check svc-named-lookup-registered denied '(deny mach-lookup (global-name "com.apple.coreservices.launchservicesd") (with message "@TAG@"))' \
    "named deny of a registered service" "$P" lookup com.apple.coreservices.launchservicesd

sleep 3
kill $LOGPID 2>/dev/null
# Fill the "logged" column: did a tagged entry for this case reach the log?
while IFS= read -r line; do
    if [[ $line =~ @LOG:(knsh:c8:[a-z0-9-]+)@ ]]; then
        t=${BASH_REMATCH[1]}
        if grep -q -E "^$t(:default)?\$" "$ROOT/denials.log"; then seen=yes; else seen=no; fi
        line=${line//@LOG:$t@/$seen}
    fi
    printf '%s\n' "$line"
done <"$OUT" >"$OUT.tmp" && mv "$OUT.tmp" "$OUT"
DENIALS=$HERE/results/c8-$OS-denials.log
cp "$ROOT/denials.log" "$DENIALS"
scrub "$OUT" "$DENIALS"
echo "results: $OUT"
exit $FAILED
