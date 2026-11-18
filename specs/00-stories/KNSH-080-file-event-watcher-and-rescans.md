# KNSH-080 — File-event watcher and rescans

[Phase 3](README.md#phase-3--reverse-and-protect) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 3 | Checkpoints | L (5) | [KNSH-077](KNSH-077-spike-file-system-behaviour-copy-on-write-cloning-memory.md), [KNSH-079](KNSH-079-shadow-builder.md) | `knsh-platform`, `knsh-checkpoint` | FR-CKP-03, FR-CKP-04, FR-EVT-08, NFR-REL-04 |

**Description.** As the checkpoint engine, I want the shadow kept in step with the live tree from FSEvents, with
rescans when events are dropped, so that pre-images are current. Scope: FSEvents stream per root behind a platform
trait, flush procedure from KNSH-077, dropped-event handling, `file.changed` events for changes by any process, and
the rescan after `knshd` returns from being unreachable. Out of scope: deciding attribution (KNSH-081).

**Acceptance criteria**
- [x] A change under a root by any process emits `file.changed` and updates the shadow (FR-EVT-08, FR-CKP-03).
- [x] When the system reports dropped events, the affected folder is rescanned and checkpoints taken in that window
      are marked uncertain, emitting `checkpoint.uncertain` (FR-CKP-04).
- [ ] After `knshd` restarts, every root is rescanned and the gap is marked (NFR-REL-04). **Partial:** the library
      takeover (`Watcher::resume`: full rescan, `restart_gap`) is done and tested; `knshd` has nothing to take over
      yet, because agent sessions do not survive a restart (pending, see Results).
- [x] The watcher runs on its own thread; the decision path never blocks on it except for the line-end flush.
- [x] Event bursts are coalesced with bounded memory.

**Unit tests**
- `dropped_event_flag_triggers_rescan_of_folder` (FR-CKP-04)
- `checkpoint_in_dropped_window_is_marked_uncertain` (FR-CKP-04)
- `restart_rescans_roots_and_marks_gap` (NFR-REL-04)
- `event_from_unrelated_process_emits_file_changed` (FR-EVT-08)
- `burst_of_events_is_coalesced_within_memory_bound`

**Integration tests**
- Real FSEvents stream on a temp root with concurrent writers; verify shadow equals live tree after flush.

**Notes**

- **Design** ([checkpoints](../03-functional-requirements/checkpoints.md#taking-checkpoints), decision 16): one
  FSEvents stream per protected root (the root and its marker folder `markers/<session>/<root index>/` in the store),
  started before the shadow build; the stream's thread only coalesces paths (at most 8,192 per root, then one root
  rescan); a worker thread compares each path's live entry with its shadow copy (kind, size, mtime) and clones,
  creates or removes accordingly; a line closes with a marker file and 1 ms flushes, within 1 s.
- **Events.** `file.changed {root, path}` and `checkpoint.uncertain {root, record_id, reason}`
  ([event model](../05-models/event.md#phase-3-payloads)).
- **Platform.** `knsh_platform::FileEvents` (`FsEventStreams` on macOS, `ScriptedFileEvents` fake); `Fs::remove_dir`.

**Results (2026-11-18, macOS 26.6.2).** `knsh_checkpoint::watcher`, the FSEvents backend, `knshd` wiring (watchers
per shadowed root, line open and close around each spawn, events). Observed: with a real FSEvents stream and 4
concurrent writer processes per line (creates, appends, renames, removals, nested folders), the shadow equalled the
live tree after each of 6 lines in every run; each line closed in 13 to 49 ms. Review fixes: a pending path below a
folder the agent replaced by a symlink could read, clone into or remove through the shadow's copy of that symlink
(outside the shadow); every folder above a path is now checked on both sides first. The worker's own writes to a
store inside the root are dropped at once instead of filling the pending set.

**Observed, environment:** `FSEventStreamStart` took 9 to 26 s for any binary run from this checkout's
`target/debug/deps` (a folder with tens of thousands of entries), and about 1 ms for the same binary elsewhere; the
time is spent in `fseventsd`'s client registration RPC. An installed `knshd` is not affected, but session start
creates streams synchronously, so this is recorded.

**Pending:** the `knshd` restart takeover (needs agent sessions re-adopted after a restart); macOS 14 and 15;
`KernelDropped` (never seen); a root on a second APFS volume; a real envelope end-to-end run. Known limits: a live
folder swapped for a symlink between the ancestor check and a clone makes the clone read through it (a read, never a
write outside the shadow); a `chmod` alone does not refresh a shadow copy (mode is not compared); marker folders are
not removed at session end (retention, KNSH-087); a panic in the spawner leaves a line open in its roots.
