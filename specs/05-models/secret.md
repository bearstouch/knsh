# Secret

A secret is a named value stored in the Keychain (service `knsh`), or supplied by the authority with `secrets.provide` for a limited time and held only in memory. Behaviour is in [../03-functional-requirements/secrets.md](../03-functional-requirements/secrets.md).

## Profile definition

```toml
[secrets.env]
NPM_TOKEN = { secret = "npm-token", inject_for = ["npm publish"], hosts = ["registry.npmjs.org"] }
```

| Key | Type | Meaning |
| --- | --- | --- |
| Table key (`NPM_TOKEN`) | string | Environment variable name the value is injected as |
| `secret` | string | Secret name in the Keychain or supplied by the authority |
| `inject_for` | list of patterns | Supervised lines that receive it |
| `hosts` | list | The only hosts the receiving line can reach |

## Sources

| Source | Lifetime |
| --- | --- |
| Keychain, service `knsh` | Persistent |
| Authority, `secrets.provide` | Limited time, memory only, lost when `knshd` exits; removable with `secrets.revoke` |

## Lookup (KNSH-089)

`knshd`'s secrets broker looks a name up in this order:

1. A live secret the authority provided (not expired, not revoked). It takes the place of a Keychain item of the same
   name while it lives: the authority's short-lived token is preferred.
2. The Keychain: a generic-password item with service `knsh` and the secret's name as its account, read at each lookup
   and never cached. `knshd` never writes or deletes one.

The answer is the value, **not found**, or **access denied** (the item exists but `knshd` may not read it, the keychain
is locked, the item was overwritten by another program ([decision 11](../09-reference/decisions.md)), or the value is
empty or larger than 64 KiB). `knshd` never lets the Keychain show its "allow access" dialog: an item it is not trusted to read
is access denied. A line that needs a secret it cannot have is denied, never run without it (KNSH-092).

Values are held in a buffer that is zeroed when dropped and never printed (`Debug` shows only the length). Copies made
before that buffer, such as the Keychain's own result object and, for `secrets.provide`, the received message and its
parsed JSON, are released without zeroing.

### Adding a Keychain secret

An item created by another program trusts that program, not `knshd`, so `knshd` cannot read it until its access list
and partition list name `knshd` (KNSH-026, C5). For a Developer ID `knshd`:

```sh
security add-generic-password -s knsh -a npm-token -T "$(command -v knshd)" -w
security set-generic-password-partition-list -S apple-tool:,teamid:<TEAM> -s knsh -a npm-token
```

The second command asks for the keychain password. **Pending:** these steps are not yet verified end to end against a
Developer ID `knshd` (manual check in KNSH-089); an engine command that creates the item from `knshd` itself, so it
trusts `knshd` from the start, is a follow-up.

## Redaction marker

`«redacted:<name>»`, e.g. `«redacted:npm-token»`.
