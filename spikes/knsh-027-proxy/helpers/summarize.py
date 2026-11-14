"""KNSH-027: turn the case table and the proxy log into one row per case (throwaway; never shipped).

Usage: python3 -I summarize.py [--raw] cases.tsv proxy.jsonl

Columns:
  used_proxy   yes (the proxy saw the case), no-direct (exit 0 and nothing reached the proxy: the tool went
               around it), no (nothing reached the proxy and the tool failed)
  http_auth    preemptive (first request carried Proxy-Authorization), after-407 (first request had none, a later
               one did), none (never sent), - (no HTTP proxy request)
  socks_auth   userpass (offered and sent RFC 1929 username/password), noauth-only (offered only "no auth"), -
  creds_ok     every credential the proxy received was this case's own user and password
  targets      host:port per connection, with the SOCKS5 address type when it was not a domain name
  sni          ok (every port-443 ClientHello named the requested host), MISMATCH, none (no SNI), - (no TLS seen)
  ech          whether any ClientHello offered Encrypted Client Hello
With --raw, prints the log lines with passwords replaced by a match flag.
"""

import hashlib
import json
import sys


def expected(case_id):
    """The user and password c9-c10-tools.sh derived for this case (same hash, same 40 hex characters)."""
    pw = hashlib.sha256(("knsh-027:%s" % case_id).encode()).hexdigest()[:40]
    return "knsh-" + case_id, pw


def http_auth_of(http):
    """Classify how the case's HTTP proxy requests carried credentials (see the http_auth column)."""
    if not http:
        return "-"
    if http[0].get("auth") != "missing":
        return "preemptive"
    if any(e.get("auth") != "missing" for e in http):
        return "after-407"
    return "none"


def socks_auth_of(socks):
    """Classify the SOCKS5 greetings: all with username/password, all without, or a mix."""
    if not socks:
        return "-"
    if all(e.get("auth") == "userpass" for e in socks):
        return "userpass"
    if all(e.get("auth") == "missing" for e in socks):
        return "noauth-only"
    return "mixed"


def creds_ok_of(evs, user, pw):
    """Whether every credential the proxy received belongs to this case; "-" when none were sent."""
    authed = [e for e in evs if "user" in e]
    if not authed:
        return "-"
    if all(e["user"] == user and e.get("password") == pw for e in authed):
        return "yes"
    return "NO"


def targets_of(evs):
    """Distinct connection targets in first-seen order, as host:port with any extra facts appended."""
    targets = []
    for e in evs:
        if "host" not in e:
            continue
        t = "%s:%s" % (e["host"], e["port"])
        if e.get("atyp") in ("ipv4", "ipv6"):
            t += "(%s)" % e["atyp"]
        if e.get("method") not in (None, "CONNECT"):
            # Plain HTTP: the Host header is the only name the proxy can check (no TLS).
            host_header = "ok" if e.get("host_header") == e["host"] else e.get("host_header")
            t = "%s %s host-header=%s" % (e["method"], t, host_header)
        if t not in targets:
            targets.append(t)
    return " ".join(targets) or "-"


def sni_of(tls):
    """Summarise the port-443 ClientHellos' server names against the requested hosts (FR-NET-06)."""
    if not tls:
        return "-"
    if any(e.get("tls") and "sni" not in e for e in tls):
        return "none"
    if all(e.get("sni_matches") for e in tls):
        return "ok"
    # For a SOCKS5 IPv4/IPv6 target the "requested host" is an address, so the SNI cannot match it; say so.
    if all(e.get("atyp") in ("ipv4", "ipv6") for e in tls):
        return "name-vs-ip:" + ",".join(sorted({e.get("sni", "") for e in tls}))
    return "MISMATCH"


def ech_of(tls):
    """Whether any ClientHello offered Encrypted Client Hello; "-" when no TLS was seen."""
    if not tls:
        return "-"
    return "yes" if any(e.get("ech") for e in tls) else "no"


def print_raw(rows, events):
    """Print every log line in case order, tagged with tool and transport, passwords replaced by a match flag."""
    for row in rows:
        _, pw = expected(row[0])
        for ev in events.get(row[0], []):
            if "password" in ev:
                ev["password"] = "<matches>" if ev["password"] == pw else "<OTHER>"
            ev["tool"], ev["transport"] = row[1], row[2]
            print(json.dumps(ev, sort_keys=True))


def main():
    raw = sys.argv[1] == "--raw"
    cases_path, log_path = sys.argv[2:] if raw else sys.argv[1:]
    # Group log lines by the case the proxy was serving when it accepted the connection.
    events = {}
    with open(log_path, encoding="utf-8") as f:
        for line in f:
            ev = json.loads(line)
            events.setdefault(ev.get("case"), []).append(ev)

    with open(cases_path, encoding="utf-8") as f:
        rows = [line.rstrip("\n").split("\t") for line in f][1:]  # skip the header

    if raw:
        print_raw(rows, events)
        return

    print("\t".join(["id", "tool", "transport", "exit", "seconds", "used_proxy", "http_auth", "socks_auth",
                     "creds_ok", "targets", "sni", "ech", "stderr"]))
    for case_id, tool, transport, rc, secs, err in rows:
        evs = events.get(case_id, [])
        user, pw = expected(case_id)
        http = [e for e in evs if e.get("proto") == "http"]
        socks = [e for e in evs if e.get("proto") == "socks5"]
        tls = [e for e in evs if e.get("port") == 443 and ("sni" in e or "tls" in e)]
        if evs:
            used = "yes"
        elif rc == "0":
            used = "no-direct"  # succeeded without the proxy: the tool ignored the setting
        else:
            used = "no"
        print("\t".join([case_id, tool, transport, rc, secs, used, http_auth_of(http), socks_auth_of(socks),
                         creds_ok_of(evs, user, pw), targets_of(evs), sni_of(tls), ech_of(tls), err or "-"]))


if __name__ == "__main__":
    main()
