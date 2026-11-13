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
//! The [`sqlite`] module (KNSH-010) is a safe wrapper over the system SQLite library for the record store; it is not
//! a trait, because the record store always uses the real database (in a temporary directory under test).
//!
//! The [`engine_dirs`] module (KNSH-011) is the single source of engine paths ([`EnginePaths`]) and prepares them
//! owner-only and excluded from Spotlight and Time Machine ([`ensure_engine_dirs`]), through the [`Fs`] trait.
//!
//! The [`launchd`] module (KNSH-012) defines the launch agent that runs `knshd` and owns its sockets, and three
//! traits around it:
//!
//! | Trait | Effect | macOS backend | Fake ([`testing`]) |
//! | --- | --- | --- | --- |
//! | [`SocketActivation`] | Receive the sockets launchd created | `LaunchdSockets` | `FakeSocketActivation` |
//! | [`PeerCredentials`] | Uid of the process at the other end of a connection | `SystemPeerCredentials` | `FixedPeerCredentials` |
//! | [`ServiceManager`] | Load and unload the job | `Launchctl` | `RecordingServiceManager` |
//!
//! The macOS backend also offers `macos::Kqueue` (KNSH-013), the event queue behind `knshd`'s accept loop: readable
//! listeners, cross-thread wake-ups and termination signals (`SIGTERM` as an event, so shutdown is orderly). It is
//! concrete rather than a trait: the server is tested over real sockets in a temporary directory.
//!
//! The [`probe`] module (KNSH-014) holds the capability probes: real checks, each bounded in time on the injected
//! [`Clock`], that a backend works here (Seatbelt through `sandbox-exec`, `FSEvents`), plus the OS version.
//!
//! | Trait | Effect | macOS backend | Fake ([`testing`]) |
//! | --- | --- | --- | --- |
//! | [`SystemProbe`] | OS major version; start and stop a file-event stream | `SystemProbes` | `FakeSystemProbe` |
//!
//! Later stories add Keychain, `LocalAuthentication`, XPC, `FSEvents` and APFS clones to the same interface.
//!
//! Every trait is object safe and `Send + Sync`, so the daemon holds each effect as `Arc<dyn Trait>` and tests swap
//! in a fake. All failures use the single crate error, [`PlatformError`], whose messages never echo paths or other
//! input (NFR-PRIV-02).
//!
//! # Boundaries
//!
//! One of only two crates allowed to use `unsafe` (with `knsh-exec`), and within it only the `macos` backend and
//! `sqlite` modules: the crate root denies `unsafe_code` and those modules alone allow it. Every `unsafe` block needs a
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
//! - `specs/04-non-functional-requirements/supply-chain.md` (system SQLite, no crates), FR-REC-08 (KNSH-010)
//! - `specs/09-reference/file-locations.md`, NFR-PRIV-04, NFR-SEC-08 (engine directories, KNSH-011)
//! - `specs/02-architecture/process-model.md`, `specs/02-architecture/endpoints.md`, NFR-REL-03 (launchd agent,
//!   KNSH-012)
//! - `specs/05-models/capabilities.md`, NFR-SEC-10, NFR-REL-08 (capability probe, KNSH-014)
//! - FR-POL-11 (canonical paths), NFR-PRIV-02 (no secrets or output in logs), CLAUDE.md "Persistence" and
//!   "Concurrency" (atomic replace; never signal a reused pid)

#![deny(missing_docs, unsafe_op_in_unsafe_fn, rust_2018_idioms, unsafe_code)]
#![warn(clippy::pedantic)]

mod clock;
pub mod engine_dirs;
mod error;
mod fs;
pub mod launchd;
mod log;
pub mod probe;
mod process;
mod random;

#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
pub mod macos;

// Linked against the system `libsqlite3`; built on macOS only until the Linux backend exists.
#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
pub mod sqlite;

// Also built for `cargo doc`, so the fakes are documented and intra-doc links to them resolve.
#[cfg(any(test, doc, feature = "testing"))]
pub mod testing;

pub use clock::{Clock, Monotonic};
pub use engine_dirs::{EnginePaths, ensure_engine_dirs};
pub use error::{Operation, PlatformError, SqliteCode};
pub use fs::{FileKind, Fs, Metadata};
pub use launchd::{LaunchAgent, PeerCredentials, ServiceManager, SocketActivation, install_agent, uninstall_agent};
pub use log::{Field, Level, SystemLog, Value, render};
pub use probe::{ProbeFailure, SystemProbe};
pub use process::{ExitStatus, ProcessGroupId, Processes, Signal, SpawnRequest, Stdio};
pub use random::Random;
