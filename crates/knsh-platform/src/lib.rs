//! Platform interface and the macOS backend.
//!
//! Traits for every operating-system effect, so core logic is tested without clocks, real files, processes or
//! system services (CLAUDE.md "Inject effects"), and their macOS implementations. KNSH-007 defines the first set:
//!
//! | Trait | Effect | macOS backend | Fake ([`testing`]) |
//! | --- | --- | --- | --- |
//! | [`Clock`] | Wall and monotonic time | `SystemClock` | `FakeClock` |
//! | [`Random`] | Random bytes | `SystemRandom` (`arc4random_buf`) | `SeededRandom` |
//! | [`Fs`] | Files, directories, atomic replace, canonical paths | `RealFs` | `MemFs` (with fault injection) |
//! | [`Processes`] | Spawn in a new process group, signal the group, wait | `SystemProcesses` | `ScriptedProcesses` |
//! | [`SystemLog`] | Unified logging, subsystem `knsh` | `UnifiedLog` | `RecordingLog` |
//!
//! Later stories add Keychain, `LocalAuthentication`, XPC, `FSEvents` and APFS clones to the same interface.
//!
//! Every trait is object safe and `Send + Sync`, so the daemon holds each effect as `Arc<dyn Trait>` and tests swap
//! in a fake. All failures use the single crate error, [`PlatformError`], whose messages never echo paths or other
//! input (NFR-PRIV-02).
//!
//! # Boundaries
//!
//! One of only two crates allowed to use `unsafe` (with `knsh-exec`), and within it only the `macos` backend
//! module: the crate root denies `unsafe_code` and that module alone allows it. Every `unsafe` block needs a
//! `// SAFETY:` comment and every `unsafe fn` a `# Safety` doc section. The only third-party dependency is `libc`,
//! and no other crate may depend on it (NFR-SUP-02). The only workspace dependency is `knsh-core`, for
//! [`knsh_core::CanonicalPath`], [`knsh_core::Timestamp`] and [`knsh_core::Ulid`].
//!
//! The fakes in [`testing`] are compiled only for this crate's tests or with the `testing` cargo feature, which
//! other crates enable only in `[dev-dependencies]`.
//!
//! # Specification
//!
//! - `specs/02-architecture/implementation.md` (platform interface)
//! - `specs/02-architecture/platform-support.md`
//! - `specs/08-integrations/macos-services.md`
//! - FR-POL-11 (canonical paths), NFR-PRIV-02 (no secrets or output in logs), CLAUDE.md "Persistence" and
//!   "Concurrency" (atomic replace; never signal a reused pid)

#![deny(missing_docs, unsafe_op_in_unsafe_fn, rust_2018_idioms, unsafe_code)]
#![warn(clippy::pedantic)]

mod clock;
mod error;
mod fs;
mod log;
mod process;
mod random;

#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
pub mod macos;

// Also built for `cargo doc`, so the fakes are documented and intra-doc links to them resolve.
#[cfg(any(test, doc, feature = "testing"))]
pub mod testing;

pub use clock::{Clock, Monotonic};
pub use error::{Operation, PlatformError};
pub use fs::{FileKind, Fs, Metadata};
pub use log::{Field, Level, SystemLog, Value, render};
pub use process::{ExitStatus, ProcessGroupId, Processes, Signal, SpawnRequest, Stdio};
pub use random::Random;
