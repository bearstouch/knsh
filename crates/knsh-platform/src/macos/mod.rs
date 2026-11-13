//! The macOS backend: one implementation per platform trait.
//!
//! This is the only place in the crate where `unsafe` is allowed (the crate root denies `unsafe_code` and this
//! module opts back in). Each `unsafe` block carries a `// SAFETY:` comment. Where the standard library already
//! offers a safe wrapper for the system call (`realpath`, `open`, `rename`, `posix_spawn`), it is used instead.

mod clock;
mod fs;
mod log;
mod process;
mod random;

pub use clock::SystemClock;
pub use fs::RealFs;
pub use log::UnifiedLog;
pub use process::SystemProcesses;
pub use random::SystemRandom;
