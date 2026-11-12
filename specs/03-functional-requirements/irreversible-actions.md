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
