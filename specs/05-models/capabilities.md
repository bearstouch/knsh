# Capabilities

Returned by `hello`. The capability probe in `knshd` detects which backends work on this machine. A missing backend is reported as `none`, never silently replaced.

```json
"capabilities": {"sandbox": "seatbelt", "network_filter": "proxy", "file_events": "fsevents",
  "secrets": "keychain", "checkpoints": {"/Users/me/code/app": "apfs-clone"},
  "sandbox_violations": "unified_log", "methods": ["exec.run", "records.query", "…"]}
```

| Field | macOS values | Linux values (later) | Effect of `none` |
| --- | --- | --- | --- |
| `sandbox` | `seatbelt` (plus Endpoint Security on macOS 27+), `none` | Landlock/seccomp | Agent sessions refuse to start |
| `network_filter` | `proxy`, `none` | `proxy` | — |
| `file_events` | `fsevents`, `none` | `inotify`, `fanotify` | — |
| `secrets` | `keychain`, `none` | Secret Service, authority-only | — |
| `checkpoints` | Per root: `apfs-clone`, `plain-copy` (non-APFS or read-only volume, one mounted with ownership ignored, or no usable store on it: copies in the home store, 50 MiB per change, FR-CKP-35), or `none` (the root's volume cannot be read, or the home store cannot be used) | Reflinks, `plain-copy` | Per root; with `required = true`, lines touching the root cannot run |
| `sandbox_violations` | `unified_log`, `none` | journald (KNSH-117) | Denials the system reports are not emitted or attached (FR-SBX-08); nothing is blocked |
| `methods` | List of available methods | | A method is available only if listed |
| `deprecated` | Deprecated methods among `methods`: `{"<method>": {"since": "0.3", "earliest_removal": "0.6"}}` | | — |

Calling an unavailable capability returns `-32005` with the capability name. A method that needs a backend reported
as `none` is not listed in `methods`, and calling it returns `-32005` naming that backend.

## Probe

The probe runs once when `knshd` starts, before it serves anything, and its result is kept for that process's
lifetime (except `sandbox_violations`, below); a restarted `knshd` probes again. Each check is real (never a version guess), bounded in time (2 s per
check, run in sequence; at most 8 s in all, including reaping a hung `knsh-exec`), and any failure, error or timeout reports `none`. A hung check is abandoned; a hung `knsh-exec` is killed with its process group.

| Capability | Check |
| --- | --- |
| `sandbox` | Phase 2 (KNSH-046): `knshd` writes the profile `(version 1)(allow default)(deny file-write*)` to a new `0600` file in its private run directory, checks without a sandbox that a target file next to it can be created (then removes it), and runs the `knsh-exec` installed next to `knshd` with that profile, `/bin/sh` and a line that tries to create the target (named in `KNSH_PROBE_TARGET`). `seatbelt` only if the line exits 42 (its "write failed" code) **and** the target does not exist afterwards; anything else (no `knsh-exec`, a setup error, any other exit, a timeout, the file present) reports `none`. Both files are removed afterwards. Phase 1 ran `/usr/bin/sandbox-exec -p '(version 1)(allow default)' /usr/bin/true` instead |
| `file_events` | An `FSEvents` stream is created, started on a dispatch queue and stopped |
| `platform` | The OS major version from `sysctl kern.osproductversion` |
| `network_filter`, `secrets` | Always `none` for now: the proxy enforces host rules, address checks (KNSH-060) and the TLS server-name check (FR-NET-06, KNSH-061), but the probe does not claim `network_filter` yet; secrets have no backend yet |
| `sandbox_violations` | Not part of the probe: the one field `hello` reads live (KNSH-047). `unified_log` from the moment a canary denial the reader caused came back through its own `log stream` (run as the user, without admin rights) until that stream ends or a recheck fails; `none` before, after, and while the reader restarts. The reader causes a canary every 250 ms until one comes back (at most 40 per round), then rechecks every 5 minutes; a stream that ends or cannot start is reopened after 1 s, doubling to 60 s. No method depends on it |
| `checkpoints` | Not a probe: each root's method comes from preparing its store (KNSH-078, [checkpoint storage](checkpoint.md#storage)). `hello` reads it live and lists each root of a running agent session once its shadow has settled (KNSH-079): the method when the shadow is complete, `none` when the build failed or the root has no shadow. A root still being built is not listed yet; a root shared by two sessions shows the weaker value. Roots whose store would be `plain-copy` get no shadow yet and are listed as `none` until plain-copy shadows exist. The method list `hello` returns does not depend on it: the `checkpoint.*` methods are listed when `file_events` is not `none` (every root's watcher needs them), since the history they act on outlives the sessions whose roots it covers, and are `-32005` naming `checkpoints` otherwise (KNSH-088) |

Later phases extend the probe as backends arrive. The plain-copy value is `plain-copy` (KNSH-078). The exact value string for the Endpoint Security case is still to be fixed.
