# Network access

An agent in an envelope has no direct network access. The sandbox allows connections only to a small proxy that `knshd` runs on your Mac (on `127.0.0.1`) and to the local ports your profile lists. Every outbound connection of an agent or one of its commands goes through that proxy, and the proxy applies your profile's host rules.

By default (`network.mode = "none"`) nothing is reachable. To let an agent talk to the network, switch the profile to an allowlist and name the hosts:

```toml
[network]
mode = "allowlist"
hosts = ["registry.npmjs.org", "pypi.org", "*.githubusercontent.com"]
approval_hosts = ["github.com"]
loopback = [3000, 5432]
```

## The three kinds of host

| Key | Who can reach it |
| --- | --- |
| `network.hosts` | Every command. Use it for registries and package indexes. |
| `network.approval_hosts` | Only commands you approved (or a grant covers), or whose *kind of action* the profile opens it for (see below). Use it for places where a mistake has consequences, such as `github.com`. |
| `network.loopback` | The agent and its commands, on those local ports only. Use it for dev servers and databases on your own Mac. |

Entries are host names, `*.example.com` wildcards (every name *below* `example.com`, not `example.com` itself), or IP addresses. A port isn't allowed in an entry. A command that tries any other host is refused.

!!! note "Approval hosts and the agent itself"
    The agent CLI process doesn't get approval hosts: it has no way to be approved. Only the commands it runs can reach them.

### Opening an approval host by what a command does

`knsh` knows what many commands do on the network: download (`fetch`, such as `git fetch` or `npm install`) or upload (`publish`, such as `git push` or `npm publish`). You can open an approval host for one kind only, so reads don't need an answer each time:

```toml
[network]
approval_hosts = ["github.com"]

[network.class_hosts]
fetch = ["github.com"]      # git fetch reaches github.com; git push still asks
```

Each host named under `class_hosts` must also be listed in `approval_hosts`.

## What the proxy checks

- **Names, not addresses.** Connections to a bare IP address are refused unless the profile lists that address.
- **Name resolution happens in the proxy.** Commands can't resolve names themselves, so DNS can't carry data out. The proxy resolves the name once and connects to the address it checked, so a later DNS answer can't redirect the connection.
- **No internal addresses.** A name that points to loopback, link-local or private addresses (`10.x`, `192.168.x`, `169.254.x`, and so on) is refused unless you listed it, which blocks DNS rebinding.
- **The TLS name must match.** The proxy reads the server name from the start of the TLS handshake (without decrypting anything). If it doesn't match the host the command asked for, the connection is closed. A handshake with no server name, or one that hides it (Encrypted Client Hello), is refused.
- **Non-TLS hosts.** Hosts that carry something other than TLS (plain HTTP, SSH, a database protocol) need to be listed in `network.non_tls_hosts` as well as `hosts`. Listing a host there never makes it reachable by itself.

Only HTTP `CONNECT` (what HTTPS clients use) and SOCKS5 with username and password are served. Plain `http://` requests that don't use `CONNECT` are refused.

## What this means for your tools

| Tool | Behavior |
| --- | --- |
| `curl`, `git` over HTTPS, `npm`, `pip`, `cargo` | Work, subject to your host rules. |
| Node.js `fetch`, `http` and `https` | Work on current versions (22.23 and 24.21 tested): `knsh` sets `NODE_USE_ENV_PROXY=1`. Node 22.20 ignores proxy settings and is blocked. |
| `git` over SSH, some Java HTTP clients | Blocked, not leaked: they ignore proxy settings, so they can't connect. Use HTTPS remotes. |
| Local dev server or database | Works on the ports in `network.loopback`. |

Anything that ignores the proxy simply can't connect. That is by design.

Tools that put themselves in a sandbox, such as Chromium and Playwright's browsers or `swift build`, fail inside an envelope because macOS can't nest sandboxes. A profile can list them under `exec.trusted_tools`: they then run without a per-command sandbox profile, only after you approve or grant them.

!!! tip "Trusted folders"
    Inside an envelope only programs in trusted folders run by name. Tools installed elsewhere, such as under `~/.nvm`, need their folder added with `exec.trusted_folders`. For npm, add the whole Node installation folder (for example `~/.nvm/versions/node/v22.20.0`), not just its `bin`.

## See what was blocked

A refused connection is reported as a `proxy.denied` event (watch with `knsh events`) and the hosts a command contacted or was refused appear in its record in `knsh history --json`. The refusal reason is one of: `network_off`, `host_not_allowed`, `approval_required`, `dynamic_code`, `ip_literal`, `address_not_allowed`, `server_name_mismatch`, `server_name_missing`, `not_tls` or `secret_hosts`.

## Dynamic code and secrets

Dynamic code (`bash -c`, `python -c`, …) can only reach `network.hosts`, never approval hosts, even if you approved it. A command that receives a [secret](secrets.md) can only reach the hosts that secret lists. Both limits are why one `python3 -c "…git push…"` can't reach GitHub.

## Limits

The proxy's limits are in [Limits and defaults](../reference/limits.md#network-proxy). In short: each connection must finish its handshake in 10 seconds, tunnels close after 5 idle minutes or 4 hours in total, and up to 512 connections are served at once.
