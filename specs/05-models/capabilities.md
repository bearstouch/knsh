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
| `deprecated` | Deprecated methods among `methods`: `{"<method>": {"since": "0.3", "earliest_removal": "0.6"}}` | | — |

Calling an unavailable capability returns `-32005` with the capability name. A method that needs a backend reported
as `none` is not listed in `methods`, and calling it returns `-32005` naming that backend.

## Probe

The probe runs once when `knshd` starts, before it serves anything, and its result is kept for that process's
lifetime; a restarted `knshd` probes again. Each check is real (never a version guess), bounded in time (2 s per
check, run in sequence; at most 8 s in all, including reaping a hung `sandbox-exec`), and any failure, error or timeout reports `none`. A hung check is abandoned; a hung `sandbox-exec` is killed.

| Capability | v1 check (phase 1) |
| --- | --- |
| `sandbox` | `/usr/bin/sandbox-exec -p '(version 1)(allow default)' /usr/bin/true` exits 0. Reported but unused in phase 1 |
| `file_events` | An `FSEvents` stream is created, started on a dispatch queue and stopped |
| `platform` | The OS major version from `sysctl kern.osproductversion` |
| `network_filter`, `secrets` | No backend yet: always `none` |
| `checkpoints` | No root configured yet: always `{}` |

Later phases extend the probe as backends arrive. Exact value strings for the plain-copy and Endpoint Security cases are to be fixed before phase 2.
