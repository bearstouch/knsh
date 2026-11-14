"""KNSH-027 recording proxy (throwaway; never shipped). Python 3 standard library only.

One loopback listener that speaks both HTTP proxy (CONNECT and absolute-URI requests) and SOCKS5, told apart by the
first byte (0x05 is SOCKS5). For every connection it records, as one JSON line:

- the protocol, and for HTTP the method and target, for SOCKS5 the offered methods, the address type and target;
- the credentials: HTTP `Proxy-Authorization` (scheme, and for Basic the user and password) or the RFC 1929
  username and password;
- for tunnels to port 443, the TLS ClientHello: server name (SNI), ALPN, whether Encrypted Client Hello is offered,
  and whether the SNI equals the requested host (case-insensitive, no trailing dot; FR-NET-06).

Authentication is required, as in the production proxy (KNSH-059): an HTTP request without `Proxy-Authorization`
gets `407` with a Basic challenge, so the log shows whether a tool sends credentials up front or only after the
challenge; a SOCKS5 greeting that does not offer username/password gets "no acceptable methods" (0xFF).

After recording, traffic is forwarded to the real host so tools behave as they would through a working proxy. The
current case name is read from --case-file at each accept, so one proxy serves a whole run.

Usage: python3 -I proxy.py --port-file F --log F --case-file F
"""

import argparse
import base64
import json
import socket
import struct
import threading
import time

MAX_HEADER = 16 * 1024
IO_TIMEOUT = 20

LOG_LOCK = threading.Lock()
CONN = threading.local()  # per connection-handler thread: the case it serves
ARGS = None


def current_case():
    """The case name in --case-file now; "?" if it cannot be read."""
    try:
        with open(ARGS.case_file, encoding="utf-8") as f:
            return f.read().strip()
    except OSError:
        return "?"


def log(event):
    """Append one JSON line to the log, tagged with the case current when the connection was accepted.

    The tag is taken at accept (in main), not when logging, so a line logged late (after the harness has moved on
    to the next case) is still attributed to the case that opened the connection.
    """
    event["case"] = getattr(CONN, "case", "?")
    event["t"] = round(time.time(), 3)
    with LOG_LOCK, open(ARGS.log, "a", encoding="utf-8") as f:
        f.write(json.dumps(event, sort_keys=True) + "\n")


def recv_exact(sock, n):
    """Read exactly n bytes; a peer that closes early is an error, not a short read."""
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise EOFError("peer closed")
        buf += chunk
    return buf


def norm_host(h):
    """Normalise a host name for the FR-NET-06 comparison: case-insensitive, no trailing dot."""
    return h.lower().rstrip(".") if h else h


def parse_client_hello(data):
    """Return SNI, ALPN and ECH facts from the first TLS handshake record, or an error string.

    Reads only what it needs; anything that does not parse is reported, never repaired.
    """
    out = {"tls": False}
    if len(data) < 5 or data[0] != 0x16:
        out["tls_error"] = "not a TLS handshake record (first byte 0x%02x)" % (data[0] if data else 0)
        return out
    rec_len = struct.unpack(">H", data[3:5])[0]
    body = data[5:5 + rec_len]
    if len(body) < rec_len or body[0] != 1:
        out["tls_error"] = "short record or not a ClientHello"
        return out
    out["tls"] = True
    # Whether the whole ClientHello (4-byte handshake header plus its length) fits in this first record.
    out["single_record"] = 4 + int.from_bytes(body[1:4], "big") <= rec_len
    out["record_version"] = "%d.%d" % (data[1], data[2])
    p = 4 + 2 + 32  # handshake header, legacy_version, random
    try:
        p += 1 + body[p]  # session id
        p += 2 + struct.unpack(">H", body[p:p + 2])[0]  # cipher suites
        p += 1 + body[p]  # compression methods
        ext_end = p + 2 + struct.unpack(">H", body[p:p + 2])[0]
        p += 2
        exts = []
        while p + 4 <= ext_end:
            etype, elen = struct.unpack(">HH", body[p:p + 4])
            edata = body[p + 4:p + 4 + elen]
            exts.append(etype)
            if etype == 0:  # server_name: list of (type, name)
                q = 2
                while q + 3 <= len(edata):
                    ntype, nlen = edata[q], struct.unpack(">H", edata[q + 1:q + 3])[0]
                    if ntype == 0:
                        out["sni"] = edata[q + 3:q + 3 + nlen].decode("ascii", "replace")
                    q += 3 + nlen
            elif etype == 16:  # ALPN
                q, protos = 2, []
                while q < len(edata):
                    n = edata[q]
                    protos.append(edata[q + 1:q + 1 + n].decode("ascii", "replace"))
                    q += 1 + n
                out["alpn"] = protos
            elif etype == 43:  # supported_versions
                out["tls13_offered"] = b"\x03\x04" in edata
            p += 4 + elen
        out["ech"] = 0xFE0D in exts
    except (IndexError, struct.error) as e:
        out["tls_error"] = "malformed ClientHello: %s" % e
    return out


def read_client_hello(sock):
    """Read one complete TLS record (the ClientHello) from the client, up to 16 KiB + header.

    A non-handshake first record is returned as is (5 bytes) so parse_client_hello reports it and the bytes are
    still forwarded. The cap bounds the read for a hostile length field (TLS limits a record to 2^14 + 256).
    """
    head = recv_exact(sock, 5)
    if head[0] != 0x16:
        return head
    n = struct.unpack(">H", head[3:5])[0]
    return head + recv_exact(sock, min(n, 16384 + 256))


def relay(a, b):
    """Copy bytes both ways until either side closes."""
    def pump(src, dst):
        try:
            while True:
                d = src.recv(65536)
                if not d:
                    break
                dst.sendall(d)
        except OSError:
            pass
        finally:
            try:
                dst.shutdown(socket.SHUT_WR)
            except OSError:
                pass

    t = threading.Thread(target=pump, args=(b, a), daemon=True)
    t.start()
    pump(a, b)
    t.join(IO_TIMEOUT)


def inspect_and_relay(client, upstream, host, port, ev):
    """Record the ClientHello of a tunnel to port 443 (and forward it), log the event, then relay."""
    if port == 443:
        hello = read_client_hello(client)
        info = parse_client_hello(hello)
        info["sni_matches"] = norm_host(info.get("sni")) == norm_host(host)
        ev.update(info)
        upstream.sendall(hello)
    log(ev)
    relay(client, upstream)


def header(headers, name):
    """Return the value of the first header called name (case-insensitive), or None."""
    return next((v for k, v in headers if k.lower() == name), None)


def socks5_reply(code):
    """A SOCKS5 reply with the given status and a zero IPv4 bound address (clients ignore it for CONNECT)."""
    return bytes([5, code, 0, 1]) + b"\0" * 6


def handle_http(client, first):
    """Handle an HTTP proxy request: CONNECT tunnels and absolute-URI plain HTTP requests."""
    buf = first
    while b"\r\n\r\n" not in buf:
        if len(buf) > MAX_HEADER:
            log({"proto": "http", "error": "header too large"})
            return
        chunk = client.recv(4096)
        if not chunk:
            log({"proto": "http", "error": "closed before end of headers"})
            return
        buf += chunk
    head, rest = buf.split(b"\r\n\r\n", 1)
    lines = head.decode("latin-1").split("\r\n")
    method, target, version = lines[0].split(" ", 2)
    headers = []
    for line in lines[1:]:
        k, _, v = line.partition(":")
        headers.append((k.strip(), v.strip()))
    ev = {"proto": "http", "method": method, "target": target, "http_version": version,
          "user_agent": header(headers, "user-agent")}
    auth = header(headers, "proxy-authorization")
    if auth is None:
        # Challenge instead of forwarding: a tool that retries with credentials shows up as a second event.
        ev["auth"] = "missing"
        log(ev)
        client.sendall(b"HTTP/1.1 407 Proxy Authentication Required\r\n"
                       b"Proxy-Authenticate: Basic realm=\"knsh-spike\"\r\n"
                       b"Content-Length: 0\r\nConnection: close\r\n\r\n")
        return
    scheme, _, cred = auth.partition(" ")
    ev["auth"] = scheme
    if scheme.lower() == "basic":
        try:
            user, _, pw = base64.b64decode(cred).decode("utf-8").partition(":")
            ev["user"], ev["password"] = user, pw
        except (ValueError, UnicodeDecodeError):
            ev["auth_error"] = "undecodable Basic credentials"

    if method == "CONNECT":
        host, _, port = target.rpartition(":")
        host, port = host.strip("[]"), int(port)
        ev["host"], ev["port"] = host, port
        try:
            upstream = socket.create_connection((host, port), timeout=IO_TIMEOUT)
        except OSError as e:
            ev["upstream_error"] = str(e)
            log(ev)
            client.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
            return
        client.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
        inspect_and_relay(client, upstream, host, port, ev)
        return

    # Absolute-URI request (plain HTTP through the proxy): forward in origin form.
    if not target.startswith("http://"):
        ev["error"] = "unsupported request target"
        log(ev)
        client.sendall(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
        return
    hostport, _, path = target[len("http://"):].partition("/")
    host, _, port = hostport.partition(":")
    ev["host"], ev["port"] = host, int(port or 80)
    ev["host_header"] = header(headers, "host")
    log(ev)
    # A connect failure here propagates to handle(), which logs it; the client just sees the connection close.
    upstream = socket.create_connection((host, ev["port"]), timeout=IO_TIMEOUT)
    # Proxy hop-by-hop headers stay here; "Connection: close" makes the origin end the relay after one response.
    kept = [(k, v) for k, v in headers
            if k.lower() not in ("proxy-authorization", "proxy-connection", "connection")]
    req = "%s /%s %s\r\n" % (method, path, version)
    req += "".join("%s: %s\r\n" % kv for kv in kept) + "Connection: close\r\n\r\n"
    upstream.sendall(req.encode("latin-1") + rest)
    relay(client, upstream)


def handle_socks5(client):
    """Handle a SOCKS5 session (the 0x05 version byte is already consumed): greeting, RFC 1929 auth, CONNECT."""
    n = recv_exact(client, 1)[0]
    methods = list(recv_exact(client, n))
    ev = {"proto": "socks5", "methods": methods}
    if 2 not in methods:  # 2 = username/password; refuse rather than fall back to "no auth"
        ev["auth"] = "missing"
        log(ev)
        client.sendall(b"\x05\xff")
        return
    client.sendall(b"\x05\x02")
    ver = recv_exact(client, 1)[0]
    ulen = recv_exact(client, 1)[0]
    user = recv_exact(client, ulen).decode("utf-8", "replace")
    plen = recv_exact(client, 1)[0]
    pw = recv_exact(client, plen).decode("utf-8", "replace")
    ev.update({"auth": "userpass", "auth_version": ver, "user": user, "password": pw})
    client.sendall(b"\x01\x00")  # accept any credentials: the point is to record them, not to check them
    _, cmd, _, atyp = recv_exact(client, 4)
    if atyp == 1:
        host = socket.inet_ntop(socket.AF_INET, recv_exact(client, 4))
        ev["atyp"] = "ipv4"
    elif atyp == 4:
        host = socket.inet_ntop(socket.AF_INET6, recv_exact(client, 16))
        ev["atyp"] = "ipv6"
    else:  # 3 = domain name, i.e. socks5h: the proxy, not the client, resolves it
        host = recv_exact(client, recv_exact(client, 1)[0]).decode("ascii", "replace")
        ev["atyp"] = "domain"
    port = struct.unpack(">H", recv_exact(client, 2))[0]
    ev.update({"cmd": cmd, "host": host, "port": port})
    if cmd != 1:
        ev["error"] = "only CONNECT is supported"
        log(ev)
        client.sendall(socks5_reply(7))  # command not supported
        return
    try:
        upstream = socket.create_connection((host, port), timeout=IO_TIMEOUT)
    except OSError as e:
        ev["upstream_error"] = str(e)
        log(ev)
        client.sendall(socks5_reply(4))  # host unreachable
        return
    client.sendall(socks5_reply(0))
    inspect_and_relay(client, upstream, host, port, ev)


def handle(client, case):
    """Serve one client connection; any protocol or I/O failure is logged and ends the connection."""
    CONN.case = case
    client.settimeout(IO_TIMEOUT)
    try:
        first = client.recv(1)
        if not first:
            return
        # SOCKS5 starts with its version byte; an HTTP request line starts with a method name.
        if first == b"\x05":
            handle_socks5(client)
        else:
            handle_http(client, first)
    except (OSError, EOFError, ValueError) as e:
        log({"proto": "?", "error": "%s: %s" % (type(e).__name__, e)})
    finally:
        client.close()


def main():
    global ARGS
    ap = argparse.ArgumentParser()
    ap.add_argument("--port-file", required=True)
    ap.add_argument("--log", required=True)
    ap.add_argument("--case-file", required=True)
    ARGS = ap.parse_args()
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(64)
    with open(ARGS.port_file, "w", encoding="utf-8") as f:
        f.write(str(srv.getsockname()[1]))
    while True:
        c, _ = srv.accept()
        threading.Thread(target=handle, args=(c, current_case()), daemon=True).start()


if __name__ == "__main__":
    main()
