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
//! Locks in the fakes are independent (one per fake) and never held across calls into another fake.

mod ancestry;
mod clock;
mod denials;
mod fs;
mod launchd;
mod log;
mod probe;
mod process;
mod random;

pub use ancestry::FakeProcessTree;
pub use clock::FakeClock;
pub use denials::{ScriptedDenialLog, kernel_entry};
pub use fs::{DEFAULT_UID, MemFs};
pub use launchd::{FakeSocketActivation, FixedPeerCredentials, RecordingServiceManager, ServiceCall};
pub use log::{Entry, RecordingLog};
pub use probe::FakeSystemProbe;
pub use process::{Script, ScriptedProcesses};
pub use random::SeededRandom;

use std::sync::{Mutex, MutexGuard, PoisonError};

/// Locks a fake's state. A panic in another test thread must not cascade, and every update in the fakes is a single
/// step that a panic cannot leave half done.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}
