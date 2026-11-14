#!/bin/bash
# Render a profile template: render.sh <template> <out> <work-dir> <sock-dir> [session]
# Every path is canonicalised: Seatbelt literals and subpaths match canonical paths only.
set -euo pipefail
canon() { (cd "$1" && pwd -P); }
TPL=$1 OUT=$2 WORK=$(canon "$3") SOCKS=$(canon "$4") SESSION=${5:-s01}
TMP=$(canon "$(getconf DARWIN_USER_TEMP_DIR)"); TMP=${TMP%/}
CACHE=$(canon "$(getconf DARWIN_USER_CACHE_DIR)"); CACHE=${CACHE%/}
HOMEC=$(canon "$HOME")
sed -e "s|@SESSION@|$SESSION|g" -e "s|@WORK@|$WORK|g" -e "s|@HOME@|$HOMEC|g" \
    -e "s|@TMPDIR@|$TMP|g" -e "s|@CACHEDIR@|$CACHE|g" \
    -e "s|@AGENTSOCK@|$SOCKS/agent.sock|g" -e "s|@USERSOCK@|$SOCKS/user.sock|g" "$TPL" > "$OUT"
# Fail loudly on a placeholder the template has but this script does not know.
if grep -q '@[A-Z]*@' "$OUT"; then echo "render: unknown placeholder in $TPL" >&2; exit 1; fi
