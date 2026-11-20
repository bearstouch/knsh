//! The macOS backend: one implementation per platform trait.
//!
//! This is the only place in the crate where `unsafe` is allowed (the crate root denies `unsafe_code` and this
//! module opts back in). Each `unsafe` block carries a `// SAFETY:` comment. Where the standard library already
//! offers a safe wrapper for the system call (`realpath`, `open`, `rename`, `posix_spawn`), it is used instead.

mod ancestry;
mod clock;
mod denials;
mod descriptors;
mod digest;
mod endpoint_security;
mod fs;
mod fsevents;
mod holders;
mod keychain;
mod kqueue;
mod launchd;
mod log;
mod presence;
mod probe;
mod process;
mod random;
mod resolver;
mod shell_host;
mod thread;
mod volumes;
mod xpc;

pub use ancestry::SystemProcessTree;
pub use clock::SystemClock;
pub use denials::UnifiedLogDenials;
pub use descriptors::{MAX_PASSED_DESCRIPTORS, peer_closed, recv_with_descriptors, send_with_descriptors};
pub use digest::{SHA256_LEN, hmac_sha256, sha256, sha256_reader};
pub use endpoint_security::SystemDescendantClients;
pub use fs::RealFs;
pub use fsevents::{FsEventStreams, MAX_WATCHED_PATHS};
pub use holders::SystemWriteHolders;
pub use keychain::{
    KeychainSecrets, KeychainSigningKey, KeychainTrustStore, SECRET_SERVICE, SIGNING_KEY_ACCOUNT, SIGNING_KEY_SERVICE,
    TRUST_ACCOUNT, TRUST_SERVICE,
};
pub use kqueue::{Kqueue, Token};
pub use launchd::{Launchctl, LaunchdSockets, SystemPeerCredentials};
pub use log::UnifiedLog;
pub use presence::LocalAuthentication;
pub use probe::SystemProbes;
pub use process::SystemProcesses;
pub use random::SystemRandom;
pub use resolver::SystemResolver;
pub use shell_host::{JobSignalsIgnored, TelemetryPipe, reraise_default};
pub use thread::set_current_thread_utility_qos;
pub use volumes::SystemVolumes;
pub use xpc::{SecCodeSigning, XpcControlService, XpcMessage};

/// The effective user id of this process: the only owner whose engine paths are used (KNSH-011, NFR-SEC-08).
#[must_use]
pub fn effective_uid() -> u32 {
    // SAFETY: `geteuid` has no preconditions, touches no memory of ours and cannot fail.
    unsafe { libc::geteuid() }
}
