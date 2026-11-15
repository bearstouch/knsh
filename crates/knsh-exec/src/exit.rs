//! Why the trampoline did not run the line, and the exit code for each reason (KNSH-046).
//!
//! The codes follow `<sysexits.h>`, so they are distinct from each other and from the shell's own 126 and 127.
//! They can still collide with codes `sandbox-exec` or a command chooses (`sandbox-exec` uses 65 and 71); the
//! supervisor only needs to know that a non-zero exit before the command started is a deny, and the stderr line
//! names the reason.

use std::fmt;
use std::io;

use crate::args::UsageError;
use crate::descriptors::PlanError;
use crate::profile::ProfileError;

/// `EX_USAGE`: the arguments are malformed (including a `--keep-fd` descriptor that is not open).
pub(crate) const USAGE: u8 = 64;
/// `EX_NOINPUT`: the profile file is missing or unsafe.
pub(crate) const PROFILE: u8 = 66;
/// `EX_UNAVAILABLE`: `/usr/bin/sandbox-exec` could not be executed.
pub(crate) const EXEC: u8 = 69;
/// `EX_OSERR`: the process could not be set up (process group, descriptors, signals, threads), or this platform
/// has no sandbox backend.
pub(crate) const SETUP: u8 = 71;

/// A failed setup step.
#[derive(Debug)]
pub(crate) enum Setup {
    /// A system call failed; the text names it.
    Os(&'static str, io::Error),
    /// Stdio is not open.
    Descriptors(PlanError),
    /// The process has more than one thread just before the exec.
    Threads(usize),
}

/// Why nothing ran.
#[derive(Debug)]
pub(crate) enum Failure {
    /// Malformed arguments.
    Usage(UsageError),
    /// A `--keep-fd` descriptor is not open.
    Descriptors(PlanError),
    /// The profile file is not usable.
    Profile(ProfileError),
    /// A setup step failed.
    Setup(Setup),
    /// `execve` of `sandbox-exec` returned.
    Exec(io::Error),
    /// No sandbox backend on this platform.
    #[cfg_attr(target_os = "macos", allow(dead_code))]
    Unsupported,
}

impl Failure {
    /// The exit code for this failure.
    pub(crate) fn code(&self) -> u8 {
        match self {
            Self::Usage(_) | Self::Descriptors(_) => USAGE,
            Self::Profile(_) => PROFILE,
            Self::Exec(_) => EXEC,
            Self::Setup(_) | Self::Unsupported => SETUP,
        }
    }
}

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Usage(error) => write!(f, "{error}"),
            Self::Descriptors(error) | Self::Setup(Setup::Descriptors(error)) => write!(f, "{error}"),
            Self::Profile(error) => write!(f, "{error}"),
            Self::Setup(Setup::Os(call, error)) => write!(f, "{call} failed: {error}"),
            Self::Setup(Setup::Threads(count)) => write!(f, "{count} threads before exec, expected 1"),
            Self::Exec(error) => write!(f, "cannot execute sandbox-exec: {error}"),
            Self::Unsupported => f.write_str("no sandbox backend on this platform"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_class_of_failure_has_its_own_code() {
        let codes = [
            Failure::Usage(UsageError::Unexpected).code(),
            Failure::Profile(ProfileError::NotRegular).code(),
            Failure::Exec(io::Error::from_raw_os_error(2)).code(),
            Failure::Setup(Setup::Threads(2)).code(),
        ];
        assert_eq!(codes, [USAGE, PROFILE, EXEC, SETUP]);
        // Never 0, and never the shell's "cannot execute" or "not found", or the policy deny (126).
        assert!(codes.iter().all(|&code| code != 0 && code != 126 && code != 127));
    }
}
