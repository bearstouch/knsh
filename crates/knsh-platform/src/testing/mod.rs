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
//!
//! Locks in the fakes are independent (one per fake) and never held across calls into another fake.

mod clock;
mod fs;
mod log;
mod process;
mod random;

pub use clock::FakeClock;
pub use fs::MemFs;
pub use log::{Entry, RecordingLog};
pub use process::{Script, ScriptedProcesses};
pub use random::SeededRandom;

use std::sync::{Mutex, MutexGuard, PoisonError};

/// Locks a fake's state. A panic in another test thread must not cascade, and every update in the fakes is a single
/// step that a panic cannot leave half done.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}
