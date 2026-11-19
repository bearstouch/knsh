//! Checkpoints and best-effort undo.
//!
//! Shadows, capture, post-image identity, the history tree and restore rules. KNSH-078 adds the foundations:
//!
//! - [`store`]: where each root's checkpoints live, one store per volume so clones stay on the volume of the files
//!   they protect, with plain copies in the home store where clones cannot work, and the per-root method the
//!   capability report shows ([`Method`], [`capability_report`]).
//! - [`identity`]: post-image identity (inode, size, modification time, and a content hash for files under 64 MiB).
//!
//! KNSH-079 adds [`shadow`]: the background, file-by-file copy-on-write shadow of each root built when an agent
//! session starts, and the gate that makes lines touching a root wait for it, fail with `-32010`, or be denied when
//! checkpoints are required and the root cannot be protected.
//!
//! KNSH-080 adds [`watcher`]: one file-event stream per root keeps its shadow in step with the live tree, emits
//! `file.changed` for changes by any process, rescans when events are lost and marks those windows uncertain, and
//! closes each line with the marker procedure of decision 16.
//!
//! KNSH-082 adds [`capture`]: before the watcher replaces or removes a shadow copy it moves it aside as the change's
//! pre-image, and reads the changed path's post-image identity; [`Captures`] keeps the first pre-image and the last
//! post-image of each path of an edge as that edge's [`Checkpoint`], uncertain (never wrong) when something could not
//! be captured.
//!
//! KNSH-084 adds [`mod@restore`] and [`undo`]: undo and redo through the history tree, restoring a path only while the
//! live file matches its post-image identity (FR-CKP-20), in place so inodes, hard links and open descriptors stay
//! valid (FR-CKP-22), with the modification time set to now (FR-CKP-23), after saving the current versions for redo.
//! Any conflict refuses the whole restore; a journal makes a failure or crash part-way end with every file as it was.
//! `force` is only for the user and the authority (FR-CKP-21); excluded folders are listed as not restored
//! (FR-CKP-31); `checkpoint.restored` is published (FR-CKP-25).
//!
//! KNSH-086 adds [`History::restore_state`] (`checkpoint.restore`: every root back to any state of the history at
//! once, checked whole before the first write, `-32004` and nothing changed on any conflict) and [`diff`]
//! (`checkpoint.diff`: the paths that differ between two states, with a unified diff of each text file).
//!
//! KNSH-085 adds [`torn`]: files held open for writing or mapped writable by the line's processes when it ends
//! ([`held_in_roots`], through `knsh_platform::WriteHolders`), and SQLite databases with journal files beside them,
//! are marked possibly torn in their checkpoint ([`Checkpoint::possibly_torn`]); undo and redo skip them and list
//! them with their reasons unless `force` is given, and then say they were forced (FR-CKP-24).
//!
//! KNSH-087 adds [`retention`]: checkpoints are kept until the first limit is reached (5 GB per volume, 200 per root,
//! 7 days, FR-CKP-32), sensitive files' pre-images at most 24 hours (FR-CKP-33, NFR-PRIV-07), and
//! [`History::forget`] removes a session's or a period's checkpoints at once (FR-CKP-34). A removed change is
//! expired in the history tree, so its undo or redo is refused as expired. Excluded folders (`checkpoints.exclude`,
//! FR-CKP-31) come from the profile (`knsh_core::DEFAULT_CHECKPOINT_EXCLUDES` unless a profile replaces the list).
//!
//! KNSH-081 adds [`attribution`]: each change in a root is attributed to the supervised line running there
//! (`command`), to the lines overlapping there as one set (`concurrent`), to the envelope's agent between lines
//! (`agent_edit`), or to nobody supervised (`external`), grouped into the edges the history tree will store. File
//! events carry no process ID, so a human editing at the same moment is attributed to the agent; the specification
//! accepts this because undo checks each path's post-image identity first (FR-CKP-20), so a wrong attribution can
//! refuse an undo but never overwrite work.
//!
//! # Boundaries
//!
//! Checkpoints live on the same APFS volume as the files they protect. Depends on `knsh-core` and `knsh-platform`:
//! every effect (files, clones, volumes, hashes, file events) goes through the `knsh_platform::Fs`,
//! `knsh_platform::Volumes` and `knsh_platform::FileEvents` traits, so this crate is tested with fakes and has no `unsafe`.
//!
//! # Specification
//!
//! - `specs/03-functional-requirements/checkpoints.md`: FR-CKP-01 to FR-CKP-11, FR-CKP-20 to FR-CKP-23, FR-CKP-25,
//!   FR-CKP-24, FR-CKP-30 to FR-CKP-36; history tree operations (`checkpoint.restore`,
//!   `checkpoint.diff`, KNSH-086)
//! - NFR-PRIV-07 (sensitive pre-images kept 24 hours at most), FR-REC-10 and NFR-PRIV-03 (forget with checkpoints)
//! - FR-EVT-08 (`file.changed`), NFR-REL-04 (rescan after a restart) and decision 16 (closing a line, dropped events)
//! - Decision 17: memory-mapped writes, possibly torn files
//! - NFR-PERF-06 and decision 15 (`specs/09-reference/decisions.md`): how the initial shadow is built and timed
//! - `specs/05-models/checkpoint.md` (storage), `specs/05-models/capabilities.md` (`checkpoints` per root)
//! - `specs/09-reference/file-locations.md`, NFR-PRIV-04 (owner-only stores, excluded from Spotlight and Time
//!   Machine, denied to envelopes and commands)

#![deny(missing_docs, unsafe_op_in_unsafe_fn, rust_2018_idioms)]
#![warn(clippy::pedantic)]
#![forbid(unsafe_code)]

pub mod attribution;
pub mod capture;
pub mod diff;
mod error;
pub mod identity;
pub mod restore;
pub mod retention;
pub mod shadow;
pub mod store;
pub mod torn;
pub mod undo;
pub mod watcher;

// Also built for `cargo doc`, so the fakes are documented.
#[cfg(any(test, doc, feature = "testing"))]
pub mod testing;

pub use attribution::{AgentEdits, Edge, EdgeId, Ledger, LineAttribution, MAX_EDGE_PATHS};
pub use capture::{
    CHECKPOINTS_DIR, CapturedPath, Captures, Change, Checkpoint, CheckpointSummary, MAX_CHECKPOINT_PATHS, MAX_EXCLUDED,
    PostImage, PreImage, RECENT_CHECKPOINTS, StoredPreImage, Ticket,
};
pub use diff::{DiffPage, DiffRequest, MAX_DIFF_PAGE, MAX_DIFF_PAGE_BYTES};
pub use error::CheckpointError;
pub use identity::{HASH_LIMIT, PostImageIdentity, post_image_identity};
pub use restore::{JOURNAL_FORMAT, RESTORES_DIR, RestoreOutcome, RestoreRequest, recover_restores, restore};
pub use retention::{
    Forget, RETAINED_AGE, RETAINED_BYTES_PER_VOLUME, RETAINED_PER_ROOT, Retention, SENSITIVE_AGE, Swept,
};
pub use shadow::{
    Gate, PlatformShadowFiles, RootReadiness, SHADOW_BUDGET, SHADOW_THREADS, Shadow, ShadowFailure, ShadowFiles,
    ShadowPlan, ShadowProgress, ShadowStatus, ShadowSummary, gate, line_touches_root, shadow_dir, start_shadow,
};
pub use store::{
    FORMAT_FILE, FORMAT_VERSION, Fallback, Method, PLAIN_COPY_LIMIT, Protection, RootStore, StoreFault, Unprotected,
    capability_report, place_roots,
};
pub use torn::{HeldScan, LineProcesses, MAX_TORN_PATHS, SQLITE_SIDECARS, held_in_roots, sqlite_marks};
pub use undo::{Caller, History, Request, RestoreEvents, Restored, StateRequest, StateRestored, Target};
pub use watcher::{
    FLUSH_DEADLINE, FLUSH_INTERVAL, HELD_DIR, LineClose, LineMark, MARKERS_DIR, MAX_PENDING_PATHS, STREAM_LATENCY,
    WatchPlan, WatchReport, Watcher, held_dir, marker_dir, start_watch,
};
