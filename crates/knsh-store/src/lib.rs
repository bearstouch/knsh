//! Execution record store.
//!
//! Record store on the system SQLite library, retention, and redaction at write time.
//!
//! # Boundaries
//!
//! Redacts before anything is stored. Depends on `knsh-core` and `knsh-platform`. The SQLite file is an internal
//! format, never an API (FR-REC-08): records leave the engine only through `records.query` and `records.output`,
//! which `knshd` answers from [`RecordStore::query`] and [`RecordStore::output`].
//!
//! # Specification
//!
//! - `specs/03-functional-requirements/execution-records.md` (FR-REC-02, FR-REC-06, FR-REC-08, FR-REC-09,
//!   FR-REC-11)
//! - `specs/05-models/execution-record.md`
//! - `specs/04-non-functional-requirements/privacy.md`, `specs/04-non-functional-requirements/reliability.md`
//!   (NFR-REL-05)
//! - `specs/06-api/user-socket.md` (`records.query`, `records.output`)
//!
//! # Record store (KNSH-016)
//!
//! - **Schema.** Versioned in the file header (`user_version`, marked with an `application_id`); migrations run
//!   forward in one transaction; a newer or foreign file is reported and never written ([`StoreError::NewerSchema`],
//!   [`StoreError::ForeignDatabase`]). The file is owner-only `0600` ([`StoreError::UnsafeFile`] otherwise).
//! - **One writer.** [`RecordStore`] owns the connection on one thread; a write is answered after `COMMIT`.
//! - **What is kept.** Human records keep only `command`, `cwd`, times and `exit_code` (FR-REC-09); output is capped
//!   per stream with head and tail kept ([`StoreConfig::output_cap`], FR-REC-06); text arrives already
//!   [`Redacted`](knsh_core::Redacted) (FR-REC-11).
//! - **Reads.** [`RecordQuery`] filters by session, time range and command text, ordered by `record_id`, paged by
//!   cursor; [`OutputRequest`] reads a clamped byte range. Every read takes a [`Scope`], applied in SQL, so a
//!   session-scoped caller never sees another session's records.
//!
//! The store is built on macOS only until the Linux SQLite backend exists.

#![deny(missing_docs, unsafe_op_in_unsafe_fn, rust_2018_idioms)]
#![warn(clippy::pedantic)]
#![forbid(unsafe_code)]

#[cfg(target_os = "macos")]
mod db;
mod error;
mod output;
mod query;
#[cfg(target_os = "macos")]
mod schema;
#[cfg(target_os = "macos")]
mod store;
// Two attributes rather than `cfg(all(..))`: clippy allows `unwrap` only under a plain `#[cfg(test)]`.
#[cfg(test)]
#[cfg(target_os = "macos")]
mod testing;
#[cfg(test)]
#[cfg(target_os = "macos")]
mod tests;

#[cfg(target_os = "macos")]
pub use db::RecordedOutput;
pub use error::StoreError;
pub use output::DEFAULT_OUTPUT_CAP;
pub use query::{
    DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE, OutputRange, OutputRequest, Page, PageSize, RecordQuery, Scope, StoredRecord,
};
#[cfg(target_os = "macos")]
pub use schema::current_version as schema_version;
#[cfg(target_os = "macos")]
pub use store::{RecordStore, StoreConfig};

/// The record database's file name, inside the engine data directory (`specs/09-reference/file-locations.md`).
pub const DATABASE_FILE: &str = "records.db";
