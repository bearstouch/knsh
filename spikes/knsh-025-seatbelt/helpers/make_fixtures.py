#!/usr/bin/env python3
"""Pick one real log entry per denial shape, for KNSH-047's parser tests (throwaway).

  python3 -I helpers/make_fixtures.py <out.ndjson> <log ndjson>...

Input: `log stream|show --style ndjson` output (an "arrival" field, if present, is dropped).
Keeps the fields a reader needs, and replaces the user's home and per-user temp directory
with placeholders so no personal paths are committed. Message format is otherwise untouched.
"""
import json
import os
import re
import sys

KEEP = ("timestamp", "messageType", "eventType", "processID", "processImagePath",
        "senderImagePath", "subsystem", "category", "formatString", "eventMessage", "userID")
home = os.path.realpath(os.path.expanduser("~"))
user = os.path.basename(home)


def scrub(s):
    s = re.sub(r'/(private/)?var/folders/[^/]+/[^/"]+', r"/\1var/folders/XX/XXXXXXXX", s)
    s = s.replace(home, "/Users/USER")
    return re.sub(r"\b%s\b" % re.escape(user), "USER", s)


def shape(msg):
    """A key that groups messages of the same form: operation, tagged or not, summary or not."""
    first = msg.split("\n")[0]
    m = re.search(r"deny\(\d+\) (\S+)(?: (\S+))?", first)
    op = m.group(1) if m else "other"
    detail = ""
    if m and m.group(2):  # e.g. 'others' for process-info, 'remote:*:53' style for network
        d = m.group(2)
        detail = "path" if d.startswith("/") else re.sub(r"[0-9]+", "N", d)[:24]
    last = msg.rsplit("\n", 1)[-1]
    tagged = "\n" in msg and last.startswith("knsh:")
    default = tagged and last.endswith(":default")
    summary = "duplicate report" in first
    return (op, detail, tagged, default, summary)


seen, out = set(), []
for path in sys.argv[2:]:
    for line in open(path):
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        msg = rec.get("eventMessage", "")
        if "deny(" not in msg:
            continue
        key = shape(msg)
        if key in seen:
            continue
        seen.add(key)
        out.append({k: scrub(rec[k]) if isinstance(rec.get(k), str) else rec.get(k) for k in KEEP})
with open(sys.argv[1], "w") as f:
    for rec in out:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")
print(f"{len(out)} fixtures from {len(seen)} shapes")
