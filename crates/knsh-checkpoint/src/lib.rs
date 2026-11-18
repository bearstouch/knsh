//! Checkpoints and best-effort undo.
//!
//! Shadows, capture, post-image identity, the history tree and restore rules. KNSH-078 adds the foundations:
//!
//! - [`store`]: where each root's checkpoints live, one store per volume so clones stay on the volume of the files
//!   they protect, with plain copies in the home store where clones cannot work, and the per-root method the
//!   capability report shows ([`Method`], [`capability_report`]).
//! - [`identity`]: post-image identity (inode, size, modification time, and a content hash for files under 64 MiB).
//!
//! # Boundaries
//!
//! Checkpoints live on the same APFS volume as the files they protect. Depends on `knsh-core` and `knsh-platform`:
//! every effect (files, clones, volumes, hashes) goes through the `knsh_platform::Fs` and `knsh_platform::Volumes`
//! traits, so this crate is tested with fakes and has no `unsafe`.
//!
//! # Specification
//!
//! - `specs/03-functional-requirements/checkpoints.md`: FR-CKP-01, FR-CKP-09, FR-CKP-35
//! - `specs/05-models/checkpoint.md` (storage), `specs/05-models/capabilities.md` (`checkpoints` per root)
//! - `specs/09-reference/file-locations.md`, NFR-PRIV-04 (owner-only stores, excluded from Spotlight and Time
//!   Machine, denied to envelopes and commands)

#![deny(missing_docs, unsafe_op_in_unsafe_fn, rust_2018_idioms)]
#![warn(clippy::pedantic)]
#![forbid(unsafe_code)]

mod error;
pub mod identity;
pub mod store;

pub use error::CheckpointError;
pub use identity::{HASH_LIMIT, PostImageIdentity, post_image_identity};
pub use store::{
    FORMAT_FILE, FORMAT_VERSION, Fallback, Method, PLAIN_COPY_LIMIT, Protection, RootStore, StoreFault, Unprotected,
    capability_report, place_roots,
};
