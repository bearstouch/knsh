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
- [ ] A change under a root by any process emits `file.changed` and updates the shadow (FR-EVT-08, FR-CKP-03).
- [ ] When the system reports dropped events, the affected folder is rescanned and checkpoints taken in that window
      are marked uncertain, emitting `checkpoint.uncertain` (FR-CKP-04).
- [ ] After `knshd` restarts, every root is rescanned and the gap is marked (NFR-REL-04).
- [ ] The watcher runs on its own thread; the decision path never blocks on it except for the line-end flush.
- [ ] Event bursts are coalesced with bounded memory.

**Unit tests**
- `dropped_event_flag_triggers_rescan_of_folder` (FR-CKP-04)
- `checkpoint_in_dropped_window_is_marked_uncertain` (FR-CKP-04)
- `restart_rescans_roots_and_marks_gap` (NFR-REL-04)
- `event_from_unrelated_process_emits_file_changed` (FR-EVT-08)
- `burst_of_events_is_coalesced_within_memory_bound`

**Integration tests**
- Real FSEvents stream on a temp root with concurrent writers; verify shadow equals live tree after flush.
