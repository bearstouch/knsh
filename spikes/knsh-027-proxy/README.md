# KNSH-027 spike: per-command proxy credentials and TLS server names (C9, C10)

Throwaway prototypes that check whether common tools carry per-command proxy credentials (C9) and send a readable TLS
server name through the proxy (C10). The results feed the proxy core (KNSH-059), the server-name check (KNSH-061) and
the agent presets (KNSH-058, KNSH-076). Nothing here is shipped, built by Cargo or called by the product.

**The written result is in [verification claims](../../specs/07-testing/verification-claims.md#proxy-results-knsh-027-c9-c10)**,
with proposed decision 14 in [decisions](../../specs/09-reference/decisions.md).

## Files

| Path | What it is |
| --- | --- |
| `c9-c10-tools.sh` | Runs each tool once per proxy setting (environment variables for HTTP and SOCKS5, the tool's own setting) with a clean environment, an empty home and its own user and password, then summarises. Cases: curl, git (HTTPS), npm, pip, cargo, and Node's `fetch`, `https` and `http` on Node 22.20, 22.23 and 24.21 |
| `helpers/proxy.py` | Recording proxy (Python standard library): HTTP CONNECT, absolute-URI HTTP and SOCKS5 on one loopback port. Requires credentials (`407` with a Basic challenge; SOCKS5 "no acceptable methods"), records credentials, SOCKS5 address type and the ClientHello (SNI, ALPN, ECH, whether it fits one record), then forwards to the real host |
| `helpers/summarize.py` | One row per case from the case table and the proxy log; `--raw` prints the log with passwords replaced by a match flag |
| `results/c9-c10-<ver>.tsv` | One row per case (columns are described at the top of `summarize.py`) |
| `results/c9-c10-<ver>-connections.jsonl` | Every connection the proxy saw, including each captured server name |
| `results/c9-c10-<ver>-versions.txt` | Tool versions used |

## Running

Run as a normal user, never with `sudo`. Needs network access (the proxy forwards to example.com, github.com,
registry.npmjs.org, pypi.org, files.pythonhosted.org and index.crates.io). Each case has a 90-second limit; the whole
run takes about 45 seconds.

```sh
spikes/knsh-027-proxy/c9-c10-tools.sh            # every case
spikes/knsh-027-proxy/c9-c10-tools.sh 'git|npm'  # cases whose "id tool:transport" matches the pattern
```

Tool locations default to this machine's (`~/.nvm` Node versions, Homebrew `python3`, rustup `cargo`); override them
with `KNSH_SPIKE_NODE22`, `KNSH_SPIKE_NODE2223`, `KNSH_SPIKE_NODE24`, `KNSH_SPIKE_PYTHON` and `KNSH_SPIKE_CARGO`. The
credentials are synthetic (`knsh-<case>` and a hash of the case ID), so they are safe to keep in results; passwords
are still replaced by `<matches>` in the connection log.

A tool that ignores the proxy is seen as `used_proxy = no-direct`: it reached the host without the proxy, which the
spike allows (no sandbox here). Inside an envelope the same tool is refused, because profiles allow network only to
the proxy port.

## Still to do

- Rerun on macOS 14 and 15 (the system curl and git differ by macOS release).
- Inside a real envelope (KNSH-057), to confirm that the tools that ignore the proxy fail instead of going direct,
  and that no DNS is needed for the `socks5h` and HTTP CONNECT cases.
- Homebrew curl and git (OpenSSL instead of the system LibreSSL), Yarn, pnpm, Bun, Deno, Go modules, Python
  `urllib`/`httpx`, Java.
- Credentials that need percent-encoding (production tokens should avoid them; see decision 14).
