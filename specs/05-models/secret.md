# Secret

A secret is a named value stored in the Keychain (service `knsh`), or supplied by the authority with `secrets.provide` for a limited time and held only in memory. Behaviour is in [../functional-requirements/secrets.md](../functional-requirements/secrets.md).

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

## Redaction marker

`«redacted:<name>»`, e.g. `«redacted:npm-token»`.
