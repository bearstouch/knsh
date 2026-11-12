# Capabilities

Returned by `hello`. The capability probe in `knshd` detects which backends work on this machine. A missing backend is reported as `none`, never silently replaced.

```json
"capabilities": {"sandbox": "seatbelt", "network_filter": "proxy", "file_events": "fsevents",
  "secrets": "keychain", "checkpoints": {"/Users/me/code/app": "apfs-clone"},
  "methods": ["exec.run", "records.query", "…"]}
```

| Field | macOS values | Linux values (later) | Effect of `none` |
| --- | --- | --- | --- |
| `sandbox` | `seatbelt` (plus Endpoint Security on macOS 27+), `none` | Landlock/seccomp | Agent sessions refuse to start |
| `network_filter` | `proxy`, `none` | `proxy` | — |
| `file_events` | `fsevents`, `none` | `inotify`, `fanotify` | — |
| `secrets` | `keychain`, `none` | Secret Service, authority-only | — |
| `checkpoints` | Per root: `apfs-clone`, plain copies, or `none` | Reflinks, plain copies | Per root; with `required = true`, lines touching the root cannot run |
| `methods` | List of available methods | | A method is available only if listed |

Calling an unavailable capability returns `-32005` with the capability name. Exact value strings for the plain-copy and Endpoint Security cases are to be fixed before phase 2.
