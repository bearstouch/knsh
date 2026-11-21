//! Deterministic fakes for every platform trait (KNSH-007).
//!
//! Compiled only for this crate's own tests or with the `testing` cargo feature, which other crates enable in their
//! `[dev-dependencies]` only, so no fake can reach a shipped binary. The fakes never touch the real clock, disk,
//! process table or log; each is `Send + Sync` and can be shared as `Arc<dyn Trait>` like the real backend.
//!
//! - [`FakeClock`]: time moves only when the test says so.
//! - [`SeededRandom`]: a reproducible stream from a seed. Never use it for tokens.
//! - [`MemFs`]: an in-memory filesystem with symlinks and fault injection per [`Operation`](crate::Operation).
//! - [`ScriptedProcesses`]: processes whose outcome is scripted in advance; records spawns and signals.
//! - [`RecordingLog`]: keeps every entry for assertions.
//! - [`FakeSocketActivation`], [`FixedPeerCredentials`], [`RecordingServiceManager`]: launchd sockets, peer
//!   credentials and `launchctl`, without touching the real launchd (KNSH-012).
//! - [`FakeProcessTree`]: a process table the test builds, with processes that exit and pids that are reused
//!   (KNSH-048).
//! - [`FakeSystemProbe`]: OS version and file-event checks with set answers, counting calls (KNSH-014).
//!
//! - [`ScriptedDenialLog`]: sandbox denial entries written by the test, canaries echoed back, failing opens and
//!   ended streams (KNSH-047); [`kernel_entry`] writes one entry as the kernel logs it.
//!
//! - [`ScriptedPresence`]: the authentication prompt answered as the test scripts, refusing when nothing is
//!   scripted; records every prompt's reason and timeout (KNSH-064).
//!
//! - [`FakeResolver`]: host names resolved to the addresses the test sets, every question counted (KNSH-060).
//!
//! - [`MemKeyStore`]: the policy signing key in memory, with read and create failures injected as `OSStatus`
//!   values, every call counted (KNSH-065).
//!
//! - [`MemTrustStore`]: the authority trust record in memory, with read and write failures injected, every call
//!   counted (KNSH-068).
//!
//! - [`MemSecretStore`]: named secrets in memory, with reads denied per name as an `OSStatus`, every read counted
//!   (KNSH-089).
//!
//! - [`FakeCodeSigning`]: the code-signing facts of a control-service peer, scripted and changeable mid-test (a
//!   peer that exec'd), every inspection counted (KNSH-067).
//!
//! - [`FakeVolumes`]: volumes and files in memory for checkpoints: clones within or across volumes and file
//!   systems, injected clone failures, identity changes (write in place, replace, touch) and digests (KNSH-078).
//!
//! - [`ScriptedFileEvents`]: file-event streams whose events the test emits, with what a flush delivers scripted
//!   (a marker file's event) and failing starts (KNSH-080).
//!
//! - [`FakeWriteHolders`]: processes and the files they hold for writing, with failures for the table or one
//!   process, every question counted (KNSH-085).
//!
//! - [`ScriptedDescendantClients`]: Endpoint Security descendant clients that can or cannot be created, whose exec
//!   events the test delivers to the watched handler; counts checks and live clients (KNSH-094).
//!
//! - [`ScriptedCommands`]: external commands of the native interpreter answering with outcomes scripted per
//!   program, the last one repeated; records every run (KNSH-096).
//!
//! - [`FakeUserHomes`]: a user database of home directories the test fills in (KNSH-097).
//!
//! - [`FakeDescriptors`]: redirection files opened in a [`MemFs`], each descriptor telling what it stands for
//!   (KNSH-099).
//!
//! Locks in the fakes are independent (one per fake) and never held across calls into another fake.

mod ancestry;
mod clock;
mod collation;
mod command;
mod control;
mod denials;
mod descriptor;
mod endpoint_security;
mod file_events;
mod fs;
mod holders;
mod job;
mod keychain;
mod launchd;
mod local_time;
mod log;
mod presence;
mod probe;
mod process;
mod random;
mod resolver;
mod secrets;
mod users;
mod volumes;

pub use ancestry::FakeProcessTree;
pub use clock::FakeClock;
pub use collation::FakeCollation;
pub use command::ScriptedCommands;
pub use control::FakeCodeSigning;
pub use denials::{ScriptedDenialLog, kernel_entry};
pub use descriptor::{FakeDescriptors, FakeOpened};
pub use endpoint_security::ScriptedDescendantClients;
pub use file_events::{FlushHook, ScriptedFileEvents, watch_failure};
pub use fs::{DEFAULT_GID, DEFAULT_UID, MemFs};
pub use holders::FakeWriteHolders;
pub use job::{FakeShellTimes, FakeTerminal};
pub use keychain::{MemKeyStore, MemTrustStore};
pub use launchd::{FakeSocketActivation, FixedPeerCredentials, RecordingServiceManager, ServiceCall};
pub use local_time::FakeLocalTime;
pub use log::{Entry, RecordingLog};
pub use presence::{Prompt, ScriptedPresence};
pub use probe::FakeSystemProbe;
pub use process::{Script, ScriptedProcesses};
pub use random::SeededRandom;
pub use resolver::FakeResolver;
pub use secrets::MemSecretStore;
pub use users::FakeUserHomes;
pub use volumes::FakeVolumes;

use std::sync::{Mutex, MutexGuard, PoisonError};

/// Locks a fake's state. A panic in another test thread must not cascade, and every update in the fakes is a single
/// step that a panic cannot leave half done.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}
