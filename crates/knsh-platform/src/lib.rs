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
//! The `lookup` module (KNSH-035) implements [`knsh_core::BinaryLookup`] for every [`Fs`], so the supervisor
//! resolves command names with [`knsh_core::resolve`] against the real filesystem and tests do so against `MemFs`.
//!
//! The `policy_source` module (KNSH-039) implements [`knsh_core::PolicyFs`] for every [`Fs`] and reads profiles from
//! the policies directory ([`PolicyDirectory`], a [`knsh_core::ProfileSource`]), so the supervisor loads profiles
//! with [`knsh_core::load_profile`] from the real filesystem and tests do so from `MemFs`.
//!
//! For compiled sandbox profiles (KNSH-045), [`Fs::list_dir`] lists a directory (sweeping unused profile files),
//! [`EnginePaths::profiles_dir`] is their private directory, and `macos::sha256` hashes them with `CommonCrypto`, so a
//! record names exactly the profile that ran (FR-SBX-07).
//!
//! The [`violation`] module (KNSH-047) reads the system's sandbox denials. Its parser is pure and tested over
//! captured samples per macOS version (`fixtures/sandbox-log/`); the stream itself is a trait:
//!
//! | Trait | Effect | macOS backend | Fake ([`testing`]) |
//! | --- | --- | --- | --- |
//! | [`DenialLog`] | Stream sandbox denials; cause a canary denial | `UnifiedLogDenials` (`log stream`) | `ScriptedDenialLog` |
//!
//! The `ancestry` module (KNSH-048) names peer processes by audit token and walks the process tree one step at a
//! time, so `agent.sock` can match a caller without a session token to the envelope it runs in. A process is always
//! named with its pid version ([`ProcessIdentity`]) or its unique id ([`ProcessKey`], stable across `exec`), never by
//! a bare pid that may have been reused.
//!
//! | Trait | Effect | macOS backend | Fake ([`testing`]) |
//! | --- | --- | --- | --- |
//! | [`ProcessTree`] | Current identity of a pid; key of an identity; parent of a process | `SystemProcessTree` (`proc_pidinfo`) | `FakeProcessTree` |
//!
//! [`PeerCredentials::peer_audit_token`] reads the peer's [`AuditToken`] (`LOCAL_PEERTOKEN`).
//!
//! The macOS backend passes descriptors over Unix sockets (KNSH-049): `macos::send_with_descriptors` sends a frame
//! with `knsh -c`'s stdio attached (`SCM_RIGHTS`), and `macos::recv_with_descriptors` reads bytes and collects what
//! arrives, bounded and close-on-exec. Concrete, like the kqueue: tested over real socket pairs.
//! [`EnginePaths::shim_dir`] names the shim directory, the one engine-managed path outside the fixed denies.
//!
//! The `presence` module (KNSH-064) asks the person at the Mac for Touch ID or their password before a
//! security-changing action. `knshd` shows the prompt itself, with the exact command or change in it
//! ([`PromptReason`]); success is an [`Authenticated`] proof only this crate can make, and every other outcome is a
//! [`NotAuthenticated`] refusal.
//!
//! | Trait | Effect | macOS backend | Fake ([`testing`]) |
//! | --- | --- | --- | --- |
//! | [`UserPresence`] | Authenticate the user with a reason text | `LocalAuthentication` (`LAContext`) | `ScriptedPresence` |
//!
//! The `signing` module (KNSH-065) signs and verifies policy files: an HMAC-SHA-256 trailer on each file, made with a
//! key only `knshd` can read from the Keychain ([`PolicySigner`]). [`PolicyDirectory`] checks every file before the
//! loader sees it, and saves a signed file only with an [`Authenticated`] proof.
//!
//! | Trait | Effect | macOS backend | Fake ([`testing`]) |
//! | --- | --- | --- | --- |
//! | [`SigningKeyStore`] | Read or create the policy signing key | `KeychainSigningKey` (legacy login keychain) | `MemKeyStore` |
//!
//! `macos::hmac_sha256` is `CommonCrypto`'s HMAC, the MAC the signer uses.
//!
//! Later stories add XPC, `FSEvents` and APFS clones to the same interface.
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
//! and no other crate may depend on it (NFR-SUP-02). The workspace dependencies are `knsh-core`, for
//! [`knsh_core::CanonicalPath`], [`knsh_core::Timestamp`] and [`knsh_core::Ulid`], and `knsh-json`, for the log
//! entries the violation reader parses.
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
//! - `specs/08-integrations/terminals-and-shells.md`, FR-SES-22 (telemetry pipe, job-control signals and signal
//!   re-raising for a hosted shell, `macos::shell_host`, KNSH-019)
//! - FR-LC-03, FR-POL-13, FR-POL-14 (binary lookup for command resolution, KNSH-035)
//! - FR-SBX-07 (profile files: directory listing, profiles directory, SHA-256, KNSH-045)
//! - FR-POL-01, FR-POL-10, FR-POL-11 (profile source and path canonicalisation for the policy loader, KNSH-039)
//! - FR-SBX-06, FR-SBX-08, decision 9 (sandbox denials from the unified log, KNSH-047)
//! - FR-NET-07 (name resolution for the network proxy, KNSH-060)
//! - FR-AGT-23, `specs/02-architecture/endpoints.md` (audit tokens and process ancestry for `agent.sock`, KNSH-048)
//! - FR-AGT-10, FR-OUT-04, `specs/06-api/wire-format.md#descriptors` (descriptor passing and the shim directory,
//!   KNSH-049)
//! - NFR-SEC-04, FR-AUTH-41, FR-AUTH-42, decision 12 (user presence through `LocalAuthentication`, KNSH-064)
//! - FR-POL-40, FR-POL-41, FR-POL-42, decision 11 (policy file signatures, Keychain signing key, KNSH-065)
//! - FR-POL-11 (canonical paths), NFR-PRIV-02 (no secrets or output in logs), CLAUDE.md "Persistence" and
//!   "Concurrency" (atomic replace; never signal a reused pid)

#![deny(missing_docs, unsafe_op_in_unsafe_fn, rust_2018_idioms, unsafe_code)]
#![warn(clippy::pedantic)]

mod ancestry;
mod clock;
pub mod engine_dirs;
mod error;
mod fs;
pub mod launchd;
mod log;
mod lookup;
mod policy_source;
mod presence;
pub mod probe;
mod process;
mod random;
mod resolver;
mod signing;
pub mod violation;

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

pub use ancestry::{AuditToken, ProcessIdentity, ProcessKey, ProcessTree};
pub use clock::{Clock, Monotonic};
pub use engine_dirs::{EnginePaths, ensure_engine_dirs};
pub use error::{Operation, PlatformError, SqliteCode};
pub use fs::{FileKind, Fs, Metadata};
pub use launchd::{LaunchAgent, PeerCredentials, ServiceManager, SocketActivation, install_agent, uninstall_agent};
pub use log::{Field, Level, SystemLog, Value, render};
pub use policy_source::{EditableProfile, FileState, PolicyDirectory};
pub use presence::{Authenticated, NotAuthenticated, PromptReason, UserPresence};
pub use probe::{ProbeFailure, SystemProbe};
pub use process::{ExitStatus, ProcessGroupId, Processes, SharedFd, Signal, SpawnRequest, Stdio};
pub use random::Random;
pub use resolver::{MAX_ADDRESSES, Resolver};
pub use signing::{
    Mac, PolicySigner, SIGNATURE_LINE_LEN, SIGNATURE_PREFIX, SIGNING_KEY_LEN, SignatureFault, SigningKey,
    SigningKeyStore, constant_time_eq, split_signed, strip_signature,
};
pub use violation::{CanaryNonce, DenialLog, DenialStream, LogEntry, StreamStopper};
