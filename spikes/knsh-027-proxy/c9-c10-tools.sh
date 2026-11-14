#!/bin/bash
# KNSH-027 spike (C9, C10): run common tools through a recording proxy with per-command credentials.
#
# For every case (tool x proxy setting) it starts the tool with a clean environment and an empty home, so no user
# configuration (~/.gitconfig, ~/.npmrc, pip.conf, ~/.curlrc, cargo config) can change the outcome, and with a
# unique user and password in the proxy setting. helpers/proxy.py records what each connection sent: protocol,
# credentials, SOCKS5 address type, and the TLS ClientHello server name. helpers/summarize.py then writes one row
# per case.
#
# Needs network access: the proxy forwards to the real hosts so tools run to completion.
# Usage: c9-c10-tools.sh [case-id-pattern]     (bash 3.2 compatible; never run with sudo)

set -u
HERE=$(cd "$(dirname "$0")" && pwd -P)
OSVER=$(sw_vers -productVersion)
RUN=$(mktemp -d "${TMPDIR:-/tmp}/knsh-027.XXXXXX")
RESULTS=$HERE/results
mkdir -p "$RESULTS" "$RUN/home"
FILTER=${1:-.}

# Node 22.20 predates NODE_USE_ENV_PROXY; 22.23 and 24 have it.
NODE22=${KNSH_SPIKE_NODE22:-$HOME/.nvm/versions/node/v22.20.0/bin}
NODE2223=${KNSH_SPIKE_NODE2223:-$HOME/.nvm/versions/node/v22.23.5/bin}
NODE24=${KNSH_SPIKE_NODE24:-$HOME/.nvm/versions/node/v24.21.0/bin}
PY=${KNSH_SPIKE_PYTHON:-/opt/homebrew/bin/python3}
CARGO=${KNSH_SPIKE_CARGO:-$HOME/.cargo/bin/cargo}

# macOS has no timeout(1), so time limits and timing go through the system perl.
# limit <seconds> <cmd...>: run cmd with a hard time limit (the alarm survives exec; exit 142 on expiry).
limit() { perl -e 'alarm shift; exec @ARGV or exit 127' "$@"; }
# nap <seconds>: sleep for a fractional number of seconds.
nap() { perl -e 'select undef, undef, undef, shift' "$1"; }
# now: wall-clock time in seconds with milliseconds, for the "seconds" column.
now() { perl -MTime::HiRes=time -e 'printf "%.3f", time'; }

# --- the recording proxy ------------------------------------------------------------------------------------------
LOG=$RUN/proxy.jsonl
: >"$LOG"
# The proxy reads this file at each accept to tag log lines; "setup" and "done" bracket the cases.
echo setup >"$RUN/case"
/usr/bin/python3 -I "$HERE/helpers/proxy.py" --port-file "$RUN/port" --log "$LOG" --case-file "$RUN/case" &
PROXY_PID=$!
trap 'kill $PROXY_PID 2>/dev/null; wait $PROXY_PID 2>/dev/null; rm -rf "$RUN"' EXIT
# The proxy binds port 0 and writes the chosen port once listening; wait up to 2 s for it.
for _ in 1 2 3 4 5 6 7 8 9 10; do [ -s "$RUN/port" ] && break; nap 0.2; done
PORT=$(cat "$RUN/port")

# --- tools: the command each case runs (one request to a known host) ----------------------------------------------
# Expected hosts: curl example.com; git github.com; npm registry.npmjs.org; pip pypi.org and files.pythonhosted.org;
# cargo index.crates.io; node registry.npmjs.org (https, fetch) or example.com (http).
tool_cmd() {
    case $1 in
    curl) echo 'curl -sS -o /dev/null --max-time 30 https://example.com/' ;;
    curl-plain) echo 'curl -sS -o /dev/null --max-time 30 http://example.com/' ;;
    # Negative control for the C10 check: CONNECT names github.com while the ClientHello names example.com.
    # The handshake then fails on the certificate, but the proxy must already have seen the mismatch.
    curl-fronted) echo 'curl -sS -o /dev/null --max-time 30 --connect-to example.com:443:github.com:443 https://example.com/' ;;
    git) echo 'git ls-remote https://github.com/octocat/Hello-World.git HEAD' ;;
    npm) echo 'npm view is-number@7.0.0 version --registry=https://registry.npmjs.org/ --prefer-online' ;;
    pip) echo "$PY -m pip download six==1.16.0 --no-deps --no-cache-dir -d \"\$TMPDIR/pip\"" ;;
    cargo) echo "cd \"\$TMPDIR/proj\" && $CARGO generate-lockfile" ;;
    node*-fetch) echo "node -e \"fetch('https://registry.npmjs.org/is-number').then(r=>console.log(r.status),e=>{console.error(String(e.cause||e));process.exit(1)})\"" ;;
    node*-https) echo "node -e \"require('https').get('https://registry.npmjs.org/is-number',r=>{console.log(r.statusCode);r.resume()}).on('error',e=>{console.error(e.message);process.exit(1)})\"" ;;
    node*-http) echo "node -e \"require('http').get('http://example.com/',r=>{console.log(r.statusCode);r.resume()}).on('error',e=>{console.error(e.message);process.exit(1)})\"" ;;
    esac
}

# transport_env <tool> <transport> <http-url> <socks5h-url> <socks5-url>: the variables for one proxy setting.
#   env-http          HTTPS_PROXY/HTTP_PROXY (both cases) = http://user:pass@127.0.0.1:port
#   env-http-nocreds  same, without user and password (shows the 407 path)
#   env-socks5h-all   ALL_PROXY = socks5h://user:pass@...  (proxy resolves names)
#   env-socks5-all    ALL_PROXY = socks5://user:pass@...   (client resolves names)
#   env-socks5h-https HTTPS_PROXY = socks5h://user:pass@...
#   tool-http         the tool's own setting, HTTP proxy URL
#   tool-socks5h      the tool's own setting, socks5h URL
#   tool-socks5       the tool's own setting, socks5 URL
#   tool-http-basic   git only: env-http plus GIT_HTTP_PROXY_AUTHMETHOD=basic (credentials sent up front)
transport_env() {
    local tool=$1 tr=$2 h=$3 s5h=$4 s5=$5 url
    case $tr in
    env-http) echo "HTTPS_PROXY=$h https_proxy=$h HTTP_PROXY=$h http_proxy=$h"; return ;;
    env-http-nocreds) url=http://127.0.0.1:$PORT
        echo "HTTPS_PROXY=$url https_proxy=$url HTTP_PROXY=$url http_proxy=$url"; return ;;
    env-socks5h-all) echo "ALL_PROXY=$s5h all_proxy=$s5h"; return ;;
    env-socks5-all) echo "ALL_PROXY=$s5 all_proxy=$s5"; return ;;
    env-socks5h-https) echo "HTTPS_PROXY=$s5h https_proxy=$s5h"; return ;;
    tool-http-basic) echo "GIT_HTTP_PROXY_AUTHMETHOD=basic HTTPS_PROXY=$h https_proxy=$h"; return ;;
    tool-http) url=$h ;;
    tool-socks5h) url=$s5h ;;
    tool-socks5) url=$s5 ;;
    esac
    case $tool in
    # curl has no proxy variable of its own (only the shared ones), so its setting is the -x flag; this marker
    # tells the case loop to rewrite the command line instead of exporting a variable.
    curl*) echo "CURL_PROXY_FLAG=$url" ;;
    git) echo "GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=http.proxy GIT_CONFIG_VALUE_0=$url" ;;
    npm) echo "npm_config_https_proxy=$url npm_config_proxy=$url" ;;
    pip) echo "PIP_PROXY=$url" ;;
    cargo) echo "CARGO_HTTP_PROXY=$url" ;;
    # Node has no setting of its own beyond opting in to the environment variables (NODE_USE_ENV_PROXY; absent in 22.20).
    node*) echo "NODE_USE_ENV_PROXY=1 HTTPS_PROXY=$url https_proxy=$url HTTP_PROXY=$url http_proxy=$url" ;;
    esac
}

CASES="
curl:env-http curl:env-http-nocreds curl:env-socks5h-all curl:env-socks5-all curl:env-socks5h-https
curl:tool-http curl:tool-socks5h curl-plain:env-http curl-plain:env-socks5h-all curl-fronted:env-http
git:env-http git:env-http-nocreds git:env-socks5h-all git:env-socks5-all git:env-socks5h-https
git:tool-http git:tool-socks5h git:tool-http-basic
npm:env-http npm:env-http-nocreds npm:env-socks5h-all npm:env-socks5h-https npm:tool-http npm:tool-socks5h
npm:tool-socks5
pip:env-http pip:env-http-nocreds pip:env-socks5h-all pip:env-socks5h-https pip:tool-http pip:tool-socks5h
cargo:env-http cargo:env-http-nocreds cargo:env-socks5h-all cargo:env-socks5h-https cargo:tool-http
cargo:tool-socks5h
"
for v in node22 node2223 node24; do
    for c in fetch https http; do
        CASES="$CASES $v-$c:env-http $v-$c:env-socks5h-all $v-$c:tool-http $v-$c:tool-socks5h"
    done
done

TSV=$RUN/cases.tsv
printf 'id\ttool\ttransport\texit\tseconds\tstderr\n' >"$TSV"
n=0
for c in $CASES; do
    tool=${c%%:*} tr=${c#*:}
    n=$((n + 1))
    id=$(printf 'c%02d' $n)
    printf '%s %s' "$id" "$c" | grep -Eq -- "$FILTER" || continue
    # Unique per case: KNSH-059 hands each line its own credentials. Hex keeps the URL free of escapes.
    user=knsh-$id
    pass=$(printf 'knsh-027:%s' "$id" | shasum -a 256 | cut -c1-40)
    h=http://$user:$pass@127.0.0.1:$PORT
    s5h=socks5h://$user:$pass@127.0.0.1:$PORT
    s5=socks5://$user:$pass@127.0.0.1:$PORT

    tmp=$RUN/$id
    mkdir -p "$tmp/home" "$tmp/pip" "$tmp/proj/src"
    printf '[package]\nname = "p"\nversion = "0.0.0"\nedition = "2021"\n[dependencies]\nitoa = "1"\n' >"$tmp/proj/Cargo.toml"
    : >"$tmp/proj/src/lib.rs"
    # Non-Node tools get Node 22.20 on PATH too: npm needs a node, and the others ignore it.
    case $tool in
    node24*) nodebin=$NODE24 ;;
    node2223*) nodebin=$NODE2223 ;;
    *) nodebin=$NODE22 ;;
    esac

    cmd=$(tool_cmd "$tool")
    vars=$(transport_env "$tool" "$tr" "$h" "$s5h" "$s5")
    case $vars in
    CURL_PROXY_FLAG=*) cmd=${cmd/curl /curl -x ${vars#CURL_PROXY_FLAG=} } vars= ;;
    esac

    echo "$id" >"$RUN/case"
    start=$(now)
    # shellcheck disable=SC2086 # $vars is a list of NAME=value words without spaces
    limit 90 env -i PATH="$nodebin:/usr/bin:/bin:/usr/sbin:/sbin" HOME="$tmp/home" TMPDIR="$tmp" LANG=C \
        RUSTUP_HOME="${RUSTUP_HOME:-$HOME/.rustup}" CARGO_HOME="$tmp/cargo" GIT_CONFIG_NOSYSTEM=1 \
        GIT_TERMINAL_PROMPT=0 PIP_CONFIG_FILE=/dev/null PIP_DISABLE_PIP_VERSION_CHECK=1 \
        npm_config_globalconfig=/dev/null npm_config_update_notifier=false npm_config_fund=false npm_config_audit=false $vars \
        /bin/bash -c "$cmd" >"$tmp/out" 2>"$tmp/err" </dev/null
    rc=$?
    end=$(now)
    # The first error-looking stderr line (else the last line), credentials masked, for the "why" column.
    err=$(grep -E 'rror|fatal|failed|ERR' "$tmp/err" | grep -v 'complete log' | head -1)
    [ -n "$err" ] || err=$(grep -v '^[[:space:]]*$' "$tmp/err" | tail -1)
    err=$(printf '%s' "$err" | sed -E "s/$pass/<pass>/g; s#$RUN#<run>#g; s/[[:cntrl:]]//g; s/^[[:space:]]+//" | cut -c1-160)
    printf '%s\t%s\t%s\t%s\t%.1f\t%s\n' "$id" "$tool" "$tr" "$rc" "$(echo "$end - $start" | bc)" "$err" >>"$TSV"
    printf '%s %-14s %-18s exit=%s\n' "$id" "$tool" "$tr" "$rc"
done
echo done >"$RUN/case"
nap 1 # relay threads may still be logging the last case's connections

OUT=$RESULTS/c9-c10-$OSVER
/usr/bin/python3 -I "$HERE/helpers/summarize.py" "$TSV" "$LOG" >"$OUT.tsv"
# The raw log, with passwords replaced by whether they matched (they are synthetic, but keep results small).
/usr/bin/python3 -I "$HERE/helpers/summarize.py" --raw "$TSV" "$LOG" >"$OUT-connections.jsonl"
sed -i '' -e "s#$HOME#/Users/USER#g" -e "s#$(basename "$HOME")#USER#g" "$OUT.tsv" "$OUT-connections.jsonl"
{
    echo "# macOS $OSVER ($(sw_vers -buildVersion)), $(date -u +%Y-%m-%d)"
    echo "# curl: $(curl --version | head -1)"
    echo "# git: $(/usr/bin/git --version)"
    echo "# npm: $(PATH=$NODE22:$PATH npm --version) (node $("$NODE22/node" --version)); node: $("$NODE2223/node" --version), $("$NODE24/node" --version)"
    echo "# pip: $($PY -m pip --version | sed "s#$HOME#/Users/USER#g")"
    echo "# cargo: $($CARGO --version)"
} >"$OUT-versions.txt"
column -t -s "$(printf '\t')" "$OUT.tsv"
