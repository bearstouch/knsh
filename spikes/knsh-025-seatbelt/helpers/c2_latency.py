#!/usr/bin/env python3
"""KNSH-025 spike, claim C2: Seatbelt denials in the unified log, read as the current user.

Throwaway spike code (never shipped). Runs `log stream` without sudo, causes tagged denials
and timestamps each matching log line on arrival. Measures latency, duplicate merging,
loss under bursts, and which denial kinds are reported at all.

  python3 -I helpers/c2_latency.py <out-dir> [n]

Writes <out-dir>/c2-<macOS>.json (the numbers) and <out-dir>/c2-<macOS>-stream.ndjson (every
received entry, with its arrival time), the raw material for KNSH-047's fixtures.
"""
import json
import os
import re
import subprocess
import sys
import tempfile
import threading
import time

OUT = sys.argv[1]
N = int(sys.argv[2]) if len(sys.argv) > 2 else 50
OS = subprocess.run(["sw_vers", "-productVersion"], capture_output=True, text=True).stdout.strip()
os.makedirs(OUT, exist_ok=True)
WORK = os.path.realpath(tempfile.mkdtemp(prefix="knsh-c2-"))  # canonical: Seatbelt needs it
TARGET = os.path.join(WORK, "secret")
DEVNULL = subprocess.DEVNULL


def write_file(path, text):
    with open(path, "w") as f:
        f.write(text)


write_file(TARGET, "x")
os.makedirs(os.path.join(WORK, "b"))
for i in range(300):
    write_file(os.path.join(WORK, "b", f"f{i}"), "x")


def profile(name, body):
    path = os.path.join(WORK, name + ".sb")
    write_file(path, "(version 1)\n(allow default)\n" + body + "\n")
    return path


def read_deny(tag):
    return profile(tag.replace(":", "_"),
                   f'(deny file-read-data (literal "{TARGET}") (with message "{tag}"))')


def sandboxed(prof, *cmd):
    subprocess.run(["sandbox-exec", "-f", prof, *cmd], stdout=DEVNULL, stderr=DEVNULL)


stream = subprocess.Popen(
    ["/usr/bin/log", "stream", "--style", "ndjson", "--predicate",
     'sender == "Sandbox" AND eventMessage CONTAINS "knsh:c2:"'],
    stdout=subprocess.PIPE, stderr=DEVNULL, text=True)
arrivals = []  # (arrival time, record)
lock = threading.Lock()


def reader():
    for line in stream.stdout:
        t = time.time()
        try:
            rec = json.loads(line)
        except ValueError:
            continue  # the "Filtering the log data using ..." banner is not JSON
        with lock:
            arrivals.append((t, rec))


threading.Thread(target=reader, daemon=True).start()


def tag_of(rec):
    """The knsh tag is the last line of the message: '<kernel text>\\n<tag>' (observed)."""
    msg = rec.get("eventMessage", "")
    return msg.rsplit("\n", 1)[-1] if "\n" in msg else None


def tagged(rec, prefix):
    return (tag_of(rec) or "").startswith(prefix)


def count(prefix):
    with lock:
        return sum(1 for _, r in arrivals if tagged(r, prefix))


# 0. Readiness: `log stream` takes a variable time to attach; denials before that are lost
#    to the stream. Repeat a canary denial until it arrives.
t0 = time.time()
canary = read_deny("knsh:c2:canary")
while count("knsh:c2:canary") == 0:
    if time.time() - t0 > 30:
        sys.exit("log stream did not deliver a canary within 30 s")
    sandboxed(canary, "/bin/cat", TARGET)
    time.sleep(0.25)
ready_s = time.time() - t0

# 1. Latency: one denial per process, spaced 100 ms apart.
sent = {}
for i in range(N):
    tag = f"knsh:c2:lat:{i:04d}"
    prof = read_deny(tag)
    sent[tag] = time.time()
    sandboxed(prof, "/bin/cat", TARGET)
    time.sleep(0.1)

# 2. Duplicates: one process denied 20 times on the same path and operation.
sandboxed(read_deny("knsh:c2:dup-same-proc"), "/bin/bash", "-c",
          f'for i in $(seq 20); do : < "{TARGET}"; done')

# 3. The same profile in 20 separate processes, back to back.
prof = read_deny("knsh:c2:dup-many-procs")
for _ in range(20):
    sandboxed(prof, "/bin/cat", TARGET)

# 4. Distinct paths: 300 denials from one process.
sandboxed(profile("burst-paths", f'(deny file-read-data (subpath "{WORK}/b") (with message "knsh:c2:burst-paths"))'),
          "/bin/bash", "-c", f'for i in $(seq 0 299); do : < "{WORK}/b/f$i"; done')
time.sleep(2)

# 5. Burst of processes: 100 processes back to back, one tagged denial each, no pause.
profs = [read_deny(f"knsh:c2:burst-procs:{i:03d}") for i in range(100)]
for p in profs:
    sandboxed(p, "/bin/cat", TARGET)
time.sleep(2)

# 6. The same burst, but each process also causes ~10 untagged-path denials of its own
#    (noise, like a real deny-default profile produces).
noisy = []
for i in range(50):
    tag = f"knsh:c2:burst-noisy:{i:03d}"
    noisy.append(profile(f"noisy{i}",
                         f'(deny file-read-data (literal "{TARGET}") (with message "{tag}"))\n'
                         f'(deny file-read-data (subpath "{WORK}/b") (with message "knsh:c2:noise"))'))
for p in noisy:
    sandboxed(p, "/bin/bash", "-c",
              f'for i in $(seq 0 9); do : < "{WORK}/b/f$i"; done; : < "{TARGET}"')
time.sleep(2)

# 7. Kinds that may never be reported: signals.
sig = profile("sig", '(deny signal (with message "knsh:c2:signal"))')
for _ in range(10):
    sandboxed(sig, "/bin/kill", "-0", "1")

# 8. A denied read of a path that does not exist (ENOENT is returned first?).
sandboxed(profile("enoent", f'(deny file-read* (subpath "{WORK}/b") (with message "knsh:c2:enoent"))'),
          "/bin/cat", f"{WORK}/b/missing")

time.sleep(10)  # delayed "N duplicate reports" summaries arrive ~1-2 s later (observed)
stream.terminate()

with lock:
    snapshot = list(arrivals)
with open(os.path.join(OUT, f"c2-{OS}-stream.ndjson"), "w") as f:
    for t, r in snapshot:
        f.write(json.dumps({"arrival": t, **r}) + "\n")

# Latency of the first arrival of each tag (later ones are duplicate reports).
lat = []
first_seen = set()
for t, r in snapshot:
    tag = tag_of(r)
    if tag and tag.startswith("knsh:c2:lat:") and tag not in first_seen:
        first_seen.add(tag)
        lat.append((t - sent[tag]) * 1000)
lat.sort()


def pct(p):
    """Nearest-rank percentile of the sorted latencies, in ms (None when nothing arrived)."""
    if not lat:
        return None
    rank = -(-p * len(lat) // 100)  # ceil(p * n / 100)
    index = min(len(lat) - 1, max(0, rank - 1))
    return round(lat[index], 1)


def entries(prefix):
    return [r.get("eventMessage", "") for _, r in snapshot if tagged(r, prefix)]


def distinct(prefix):
    return len({tag_of(r) for _, r in snapshot if tagged(r, prefix)})


dup_same = entries("knsh:c2:dup-same-proc")
report = {
    "macos": OS,
    "user_is_root": os.geteuid() == 0,
    "log_stream_ready_s": round(ready_s, 2),
    "latency": {"sent": N, "received": len(lat), "ms_p50": pct(50), "ms_p95": pct(95),
                "ms_max": round(lat[-1], 1) if lat else None,
                "note": "spawn of sandbox-exec + cat included: an upper bound"},
    "dup_same_process_20": {"entries": len(dup_same),
                            "messages": [m.split("\n")[0][:120] for m in dup_same]},
    "dup_20_processes": len(entries("knsh:c2:dup-many-procs")),
    "distinct_paths_one_process_300": len(entries("knsh:c2:burst-paths")),
    "burst_100_processes_received": distinct("knsh:c2:burst-procs:"),
    "burst_50_noisy_processes_received": distinct("knsh:c2:burst-noisy:"),
    "noise_entries": len(entries("knsh:c2:noise")),
    "signal_denials_10_received": len(entries("knsh:c2:signal")),
    "enoent_denial_received": len(entries("knsh:c2:enoent")),
}
# The committed report must not carry personal paths (the raw stream dump is gitignored).
HOME = os.path.realpath(os.path.expanduser("~"))
text = json.dumps(report, indent=1).replace(HOME, "/Users/USER")
text = re.sub(r'/(private/)?var/folders/[^/]+/[^/"]+', r"/\1var/folders/XX/XXXXXXXX", text)
with open(os.path.join(OUT, f"c2-{OS}.json"), "w") as f:
    f.write(text + "\n")
print(json.dumps(report, indent=1))
