# Irreversible actions

Checkpoints restore files. They cannot take back a push, a deploy, a payment, a database write or a sent message. The engine flags these so they can be approved before they run.

| ID | Requirement |
| --- | --- |
| FR-IRR-01 | **Before running:** classification must mark commands from a built-in list plus the profile's own list as irreversible. |
| FR-IRR-02 | The built-in list must include at least: `git push`, `npm publish`, `docker push`, `kubectl apply`, `terraform apply`, `gh pr merge`, `ssh`, `scp`, `rsync` to a remote host, and `curl` with `POST`, `PUT`, `PATCH` or `DELETE`. |
| FR-IRR-03 | **After running:** a line that reached an `approval_hosts` destination, any upload-capable host, or wrote outside the checkpoint roots must be marked irreversible too. |
| FR-IRR-04 | The record's `irreversible` field must hold a boolean and the reasons. |
| FR-IRR-05 | **Policy:** `approvals.irreversible = "ask"` must turn every flagged line into an ask, so the authority sees it with `irreversible.reasons` before it runs. |
| FR-IRR-06 | **Undo** of a flagged change must still restore its files, and its result must list what cannot be undone. |

## Before running (KNSH-093)

Each simple command of the line (a wrapper's command included) is matched against the built-in list and the profile's
`approvals.irreversible_commands` like an `exec.ask` pattern: over normalised arguments, so `git -c x=y push` is
`git push` (FR-POL-15), and a pattern that **may** match counts, so an argument built from an expansion cannot step
around a flag (`git $X` is flagged as `git push`). Patterns name trusted binaries and builtins only: a project
executable named `ssh` is not matched, and `exec.project_executables` decides it.

The built-in list: `git push`, `npm publish`, `pnpm publish`, `yarn publish`, `cargo publish`, `docker push`,
`kubectl apply`, `kubectl create`, `kubectl delete`, `kubectl replace`, `kubectl patch`, `terraform apply`,
`terraform destroy`, `tofu apply`, `tofu destroy`, `gh pr merge`, `gh release create`, `ssh`, `scp`, `sftp`. Two
commands are read by their arguments:

- `curl` is irreversible when it sends anything but a read: an explicit `-X`/`--request` other than `GET`, `HEAD`,
  `OPTIONS` or `TRACE`; otherwise `-T`/`--upload-file` (`PUT`), or a data or form option (`-d`, `--data*`, `--json`,
  `-F`, `--form*`) without `-G`/`--get` (`POST`). `curl URL` is a `GET` and is not flagged. Each request of the
  line (`-:`/`--next` starts another) is read on its own, and `--expand-<option>` is read as `--<option>`.
- `rsync` is irreversible when an operand names a remote host: `host:path`, `user@host:path`, `host::module` or
  `rsync://…` (a `:` before any `/`, as rsync reads it). Only local paths are not flagged.

An argument built from an expansion, a command whose arguments are completed at run time (`xargs`) and a `curl` config
file (`-K`) may set anything, so such a `curl` or `rsync` is flagged as `arguments not known` (fail closed). Dynamic
code (`bash -c 'git push'`) is not read: it is decided by `exec.default` and clamped (FR-POL-20, FR-POL-21), and what
it did is still marked after it runs. As every classifier result this is an intent filter, never a security boundary:
the proxy enforces what a line may reach.

## After running (KNSH-093)

Once a line has run, the supervisor adds what it was seen doing, before `command.finished` is published, to its record
and to its checkpoint (so the checkpoint's undo lists it, FR-IRR-06):

- **Network.** Every host the proxy reports the line contacted (refused connections reached nothing) that is in
  `network.approval_hosts`, or is upload-capable.
- **Upload-capable hosts** (this closes the spec gap on how a host is known to be one): the built-in list
  `uploads.github.com`, `upload.pypi.org`, `transfer.sh`, `0x0.st`, `file.io`, `pastebin.com`, `paste.rs`,
  `termbin.com`, `webhook.site`, plus the profile's `approvals.upload_hosts` (matched like `network.hosts` entries;
  never makes a host reachable; a child profile keeps every parent entry). Registries and git hosts accept uploads too:
  keep them in `network.approval_hosts` ([network proxy](network-proxy.md)), which marks them as well.
- **Writes outside the checkpoint roots.** Each path the line was seen writing outside every `checkpoints.roots` entry.

**Coverage limit.** Hosts come from the proxy's reports, and every connection of a line goes through the proxy
(FR-NET-01). A record keeps at most 256 distinct network entries (FR-NET-09), so an approval or upload
host contacted after that many others is not seen and not marked; a follow-up should mark a line whose network list
overflowed (fail closed). Writes are observable only where file events or sandbox reports cover them: the engine watches only the
checkpoint roots, and the sandbox reports denials, not writes, so a write outside the roots is **not observed yet** and
is never marked in practice. The marking takes any observed paths, so a later watcher of `fs.write` paths outside the
roots needs no other change.

## Reasons

The record's `irreversible` is `{"value", "reasons"}` (FR-IRR-04). `value` is `true` exactly when there is a reason.
Reasons are distinct, in the order first found, at most 64 (more are dropped; the flag stays set), each at most 1024
bytes:

| Reason | When |
| --- | --- |
| the pattern, e.g. `git push`, `terraform state rm` | a built-in or profile pattern matched before the line ran |
| `curl POST`, `curl PUT`, `curl PATCH`, `curl DELETE`, `curl CONNECT` | `curl` with that method |
| `curl (other method)` | `curl` with any other write method (never named: the method is text from the line) |
| `rsync to a remote host` | `rsync` with a remote operand |
| `curl (arguments not known)`, `rsync (arguments not known)` | the arguments were not known from the line |
| `network`, then the host | the line contacted an approval host or an upload-capable host |
| the path | the line was seen writing outside the checkpoint roots |

A line refused before it was classified has `null`. A refused line keeps its classification. `decision.requested`
carries the classification made before the line runs, with each reason redacted like the command.

## Policy (KNSH-093)

A command classified irreversible is treated at least as strictly as `approvals.irreversible` says, with rule ID
`approvals.irreversible`: with `ask` (the default) it asks even when `exec.allow` allows it, with `deny` it is refused,
with `allow` the rules alone decide. A deny rule still wins, and a grant covering the command may answer the ask
(FR-POL-60). Under the `unattended` profile (`irreversible = "deny"`) a flagged line is a deny by rule.
