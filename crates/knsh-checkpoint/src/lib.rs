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
//! # Boundaries
//!
//! Checkpoints live on the same APFS volume as the files they protect. Depends on `knsh-core` and `knsh-platform`:
//! every effect (files, clones, volumes, hashes, file events) goes through the `knsh_platform::Fs`,
//! `knsh_platform::Volumes` and `knsh_platform::FileEvents` traits, so this crate is tested with fakes and has no `unsafe`.
//!
//! # Specification
//!
//! - `specs/03-functional-requirements/checkpoints.md`: FR-CKP-01 to FR-CKP-04, FR-CKP-09, FR-CKP-31, FR-CKP-35
//! - FR-EVT-08 (`file.changed`), NFR-REL-04 (rescan after a restart) and decision 16 (closing a line, dropped events)
//! - NFR-PERF-06 and decision 15 (`specs/09-reference/decisions.md`): how the initial shadow is built and timed
//! - `specs/05-models/checkpoint.md` (storage), `specs/05-models/capabilities.md` (`checkpoints` per root)
//! - `specs/09-reference/file-locations.md`, NFR-PRIV-04 (owner-only stores, excluded from Spotlight and Time
//!   Machine, denied to envelopes and commands)

#![deny(missing_docs, unsafe_op_in_unsafe_fn, rust_2018_idioms)]
#![warn(clippy::pedantic)]
#![forbid(unsafe_code)]

mod error;
pub mod identity;
pub mod shadow;
pub mod store;
pub mod watcher;

// Also built for `cargo doc`, so the fakes are documented.
#[cfg(any(test, doc, feature = "testing"))]
pub mod testing;

pub use error::CheckpointError;
pub use identity::{HASH_LIMIT, PostImageIdentity, post_image_identity};
pub use shadow::{
    Gate, PlatformShadowFiles, RootReadiness, SHADOW_BUDGET, SHADOW_THREADS, Shadow, ShadowFailure, ShadowFiles,
    ShadowPlan, ShadowProgress, ShadowStatus, ShadowSummary, gate, line_touches_root, shadow_dir, start_shadow,
};
pub use store::{
    FORMAT_FILE, FORMAT_VERSION, Fallback, Method, PLAIN_COPY_LIMIT, Protection, RootStore, StoreFault, Unprotected,
    capability_report, place_roots,
};
pub use watcher::{
    FLUSH_DEADLINE, FLUSH_INTERVAL, LineClose, LineMark, MARKERS_DIR, MAX_PENDING_PATHS, STREAM_LATENCY, WatchPlan,
    WatchReport, Watcher, marker_dir, start_watch,
};
