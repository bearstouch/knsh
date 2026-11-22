# Undo and checkpoints

Agents sometimes change things you didn't want changed. Checkpoints record what each agent command or edit changed in your protected folders, so you can put those files back. Undo is best effort: when `knsh` can't be sure what a file should contain, it refuses rather than overwrite something it didn't record.

Checkpoints need an APFS volume (the default for Macs) and the background service.

## What is protected

Checkpoints cover the **roots** your profile names:

```toml
[checkpoints]
roots = ["${PROJECT}"]
required = true
```

When an agent session starts, `knshd` quietly builds a copy of each root in the background, using copy-on-write clones so it costs almost no space or time. It keeps that copy in step with the folder as files change. When something changes, the old version is kept as a *pre-image* for that change. The cost grows with the number of files that changed, not with the size of the project.

With `required = true`, a command that touches a root waits until the copy is ready. Without it, the command doesn't wait, but may not be fully protected if it starts straight away.

Changes are attributed to what caused them:

| Change | Where it comes from |
| --- | --- |
| A command | One supervised command ran in the root. |
| Concurrent commands | Several commands overlapped in time. They are undone together as one. |
| Agent edits | The agent changed files with its own built-in editing tools, outside any command. |

File events don't say which process wrote a file. If you edit a file at the same moment the agent changes something else in the same folder, `knsh` may count your edit as the agent's. Undo then refuses to overwrite it unless you force it (see below).

## List changes

```sh
knsh checkpoints
knsh checkpoints --session <session-id>
```

One line per change, oldest first: when, checkpoint ID, status, what caused it (or `revert of <id>`), how many files, the states it goes from and to, and the related records. The last line says `Current state: <id>.`

## Undo

Undo the files changed by a command from your history:

```sh
knsh history --text "npm install"      # find the command's record ID
knsh undo <record-id>
```

Undo a change that has no command, such as a run of agent edits, by its checkpoint ID:

```sh
knsh undo --checkpoint <checkpoint-id>
```

On success: `Undid change <id>: restored <n> file(s); now at state <s>.` It then lists anything that wasn't restored and why.

## Redo

Changed your mind? Redo puts the undone changes back:

```sh
knsh redo <record-id>
knsh redo --checkpoint <checkpoint-id>
```

Undo keeps the branch it left, so redo stays possible until you make a new change or the checkpoint expires. After you make a new change, going back to the old branch isn't a redo.

## When undo refuses

Undo checks every file first and changes nothing until all of them pass. A file is a *conflict* when it no longer holds what the change left there: it was edited since, deleted, replaced, or the old version was never captured. Any conflict stops the whole undo, with every conflicting path and the reason listed, and nothing is written. You never get a half-undone state.

| Reason | Meaning |
| --- | --- |
| `changed` | The file was modified after the change. |
| `missing` | The file is gone. |
| `exists` | Something new is there where the change deleted a file. |
| `unverifiable` | `knsh` couldn't read the file's state after the change. |
| `pre_image_lost` | The old version was never captured, or has expired (see below). |
| `folder_not_empty` | Undo would remove a folder that holds things the change didn't make. |
| `parent_missing` | A folder the file needs doesn't exist. |

To undo an *older* change when later changes touched the same files, undo the later ones first. If they didn't touch the same files, an older change can be undone on its own, and it is recorded like a `git revert`.

### Force

```sh
knsh undo --force <record-id>
```

`--force` restores files that changed since the change (**losing what is there now**) and files that might have been written half-way. Only you can use it: an agent never can. Even `--force` doesn't override `pre_image_lost`, `folder_not_empty` or `parent_missing`.

### Files that may be torn

If a file was open for writing, or memory-mapped for writing, when a command ended, or is a SQLite database with journal files (`-wal`, `-shm`, `-journal`), `knsh` marks it as *possibly torn*: it might have been captured mid-write. Undo skips it, restores the rest, and tells you. With `--force` it is restored and reported as forced.

### How files are restored

A file's old contents are written *into* the existing file, so its identity, hard links and any program that has it open stay valid. The modification time is set to now, so build tools notice. Undo also never follows a folder that was swapped for a symlink.

If `knshd` stops in the middle of an undo, it puts every file back the way it was at the next start. You never end up with some files undone and others not.

## What isn't protected

- **Excluded folders.** `node_modules`, `target`, `.venv`, `dist` and `build` by default (set `checkpoints.exclude` to change it). Undo lists these as *not restored*. So undoing an `npm install` leaves `node_modules` out of step with the lockfile until you run install again.
- **Files outside the roots.** The roots are what you named.
- **Non-APFS volumes.** Checkpoints must sit on the same volume as the files they protect. On other volumes, `knsh` keeps plain copies, limited to 50 MB per change, and larger changes are recorded as not protected.
- **Large files.** A file's contents are fingerprinted for files under 64 MiB. Bigger files are checked by size, time and inode only.

## How long checkpoints are kept

Whichever limit is reached first: 5 GB of checkpoint data per volume, 200 checkpoints per root, or 7 days. Older changes expire and can no longer be undone or redone.

**Sensitive files** (`.env*`, `*.pem`, `*.key`, `id_*`) are kept for 24 hours at most. After that their old versions are deleted, and undoing a change that touched one reports `pre_image_lost` for it. That protects secrets that an agent may have deleted from lingering on disk.

`knsh forget --with-checkpoints` removes checkpoints at once ([Recording and history](recording.md#delete-history)).

Checkpoints are stored on the same volume as the files they protect: in `~/Library/Application Support/knsh/checkpoints/` for your home volume, and in `.knsh-checkpoints/` at the top of other APFS volumes (for example `/Volumes/External/.knsh-checkpoints/`). They're private, and excluded from Spotlight and Time Machine. On an external disk that ignores ownership, owner-only permissions protect nothing, so `knsh` uses plain copies in your home store instead.

## Actions that can't be undone

Checkpoints restore files. They can't take back a push, a deploy, a payment, a database write or a message sent. `knsh` flags such commands so you can decide *before* they run.

**Before the command runs**, these are flagged as irreversible:

`git push`, `npm publish`, `pnpm publish`, `yarn publish`, `cargo publish`, `docker push`, `kubectl apply`, `kubectl create`, `kubectl delete`, `kubectl replace`, `kubectl patch`, `terraform apply`, `terraform destroy`, `tofu apply`, `tofu destroy`, `gh pr merge`, `gh release create`, `ssh`, `scp`, `sftp`.

Two are read by their arguments:

- `curl` is flagged when it sends something: `-X` with a method other than `GET`, `HEAD`, `OPTIONS` or `TRACE`, `-T`/`--upload-file`, or a data or form option (`-d`, `--data*`, `--json`, `-F`) without `-G`. A plain `curl URL` isn't flagged.
- `rsync` is flagged when it names a remote host (`host:path`, `user@host:path`, `rsync://…`).

A `curl` or `rsync` whose arguments can't be known from the line (they come from an expansion, `xargs` or a config file) is flagged too: when in doubt, `knsh` assumes the worst. Add your own with `approvals.irreversible_commands` in the profile.

**After the command runs**, a line is also marked irreversible if it contacted an approval host or a place data can be uploaded to (`uploads.github.com`, `upload.pypi.org`, `transfer.sh`, `0x0.st`, `file.io`, `pastebin.com`, `paste.rs`, `termbin.com`, `webhook.site`, plus your `approvals.upload_hosts`).

What `approvals.irreversible` does with a flagged command:

| Setting | Effect |
| --- | --- |
| `ask` (default) | It asks, even when `exec.allow` allows it. |
| `deny` | It is refused. |
| `allow` | Your rules alone decide. |

A `deny` rule always wins, and a [grant](approvals.md#grants-say-yes-for-a-while) can answer an ask. Under the built-in `unattended` profile, a flagged command is denied.

When you undo a change that included an irreversible action, its files are still restored, and the result lists what couldn't be taken back, with the reasons.

This classification is meant to catch honest mistakes. The hard limits are still the sandbox and the network proxy.
