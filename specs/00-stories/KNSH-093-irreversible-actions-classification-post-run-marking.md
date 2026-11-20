# KNSH-093 — Irreversible actions: classification, post-run marking, approvals and undo reporting

[Phase 3](README.md#phase-3--reverse-and-protect) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 3 | Irreversible | XL (8) | [KNSH-037](KNSH-037-subcommand-normalisation-and-network-intent-classes.md), [KNSH-060](KNSH-060-proxy-connection-rules-host-rules-address-checks-and.md), [KNSH-082](KNSH-082-capture-pre-images-and-post-image-identity.md), [KNSH-084](KNSH-084-undo-and-redo.md) | `knsh-bash`, `knsh-core`, `knshd`, `knsh-checkpoint` | FR-IRR-01, FR-IRR-02, FR-IRR-04, FR-IRR-03, FR-IRR-05, FR-IRR-06, FR-CKP-36 |

**Description.** Merged from *Irreversible classification before running*, *Irreversible marking after running* and *Irreversible approvals and undo reporting*: they are done and validated together because one end-to-end flow validates flagging, approval and undo reporting.

*Irreversible classification before running.* As the supervisor, I want lines classified as irreversible before they run, from a built-in list and
the profile's own list, so that they can be approved first. Scope: built-in list, profile list, reasons, the record's
`irreversible` field. Out of scope: post-run marking (covered in this story).

*Irreversible marking after running.* As a user reviewing history, I want lines whose observed behaviour was irreversible marked after
they run, so that undo results are honest. Scope: reaching an `approval_hosts` destination, any upload-capable host,
or writing outside the checkpoint roots.

*Irreversible approvals and undo reporting.* As a user, I want flagged lines to ask before running and undo to tell me what it could not take
back, so that I am never misled about what was reversed.

**Acceptance criteria**
*Irreversible classification before running*

- [x] The built-in list marks at least `git push`, `npm publish`, `docker push`, `kubectl apply`, `terraform apply`,
      `gh pr merge`, `ssh`, `scp`, `rsync` to a remote host, and `curl` with `POST`, `PUT`, `PATCH` or `DELETE`
      (FR-IRR-02).
- [x] Matching uses normalised subcommands, so `git -c x=y push` is flagged.
- [x] `rsync` with only local paths is not flagged; `curl` without a method flag (`GET`) is not flagged.
- [x] Profile entries add to the built-in list.
- [x] The record's `irreversible` holds `value` and `reasons` (FR-IRR-04).

*Irreversible marking after running*

- [x] A line that reached an `approval_hosts` destination (from proxy reports) is marked irreversible with reason
      `network` and the host.
- [x] A line that reached an upload-capable host is marked irreversible.
- [ ] A line that wrote outside the checkpoint roots is marked irreversible with the paths as reasons.
      **Pending:** the marking takes observed paths and is unit-tested (`write_outside_roots_marks_irreversible`),
      but no source observes writes outside the roots yet (file events watch the roots only), so nothing is marked
      in practice. Recorded as a coverage limit in the irreversible-actions spec.
- [x] Marks are added to the record and to the checkpoint before `command.finished` is emitted.

*Irreversible approvals and undo reporting*

- [x] With `approvals.irreversible = "ask"`, every flagged line becomes an ask, and `decision.requested` carries
      `irreversible.reasons` (FR-IRR-05).
- [x] Undo of a flagged change restores its files and lists what cannot be undone (FR-IRR-06, FR-CKP-36).

**Unit tests**
*Irreversible classification before running*

- `git_push_with_global_options_is_irreversible` (FR-IRR-02)
- `curl_post_is_irreversible_and_get_is_not` (FR-IRR-02)
- `rsync_local_only_is_not_irreversible` (FR-IRR-02)
- `profile_list_extends_builtin_list` (FR-IRR-01)
- `reasons_are_recorded` (FR-IRR-04)

*Irreversible marking after running*

- `approval_host_contact_marks_irreversible` (FR-IRR-03)
- `write_outside_roots_marks_irreversible` (FR-IRR-03)
- `marks_present_before_command_finished`

*Irreversible approvals and undo reporting*

- `irreversible_line_asks_when_profile_says_ask` (FR-IRR-05)
- `decision_request_includes_irreversible_reasons` (FR-IRR-05)
- `undo_result_lists_irreversible_effects` (FR-IRR-06)

**Notes**
*Irreversible marking after running*

- Spec gap (resolved in KNSH-093): upload-capable hosts are a built-in list plus the profile's `approvals.upload_hosts`.
- Spec gap: how a host is known to be "upload-capable" is not defined. Propose a profile or preset list in
  [../03-functional-requirements/irreversible-actions.md](../03-functional-requirements/irreversible-actions.md) as part of this story.
- Writes outside checkpoint roots are only observable where file events or sandbox reports cover them; record the
  coverage limit.
