//! Which descriptors survive the exec (KNSH-046).
//!
//! Only stdio (0, 1, 2) and the descriptors the supervisor lists with `--keep-fd` are inherited by the sandboxed
//! command. Every other open descriptor gets `FD_CLOEXEC`, so the kernel closes it at `execve`: a descriptor that
//! `knshd` leaked by mistake (a socket, the record database) never reaches agent code.
//!
//! [`plan`] is the pure decision; the caller applies it with `fcntl`.

use std::fmt;

/// What to do with each open descriptor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Plan {
    /// Descriptors whose `FD_CLOEXEC` is cleared: stdio and every listed descriptor.
    pub(crate) inherit: Vec<i32>,
    /// Descriptors whose `FD_CLOEXEC` is set: everything else that is open.
    pub(crate) close_on_exec: Vec<i32>,
}

/// Why the descriptors cannot be set up as asked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PlanError {
    /// One of stdio is closed. A file the command opens would then land on 0, 1 or 2 and be read or written as
    /// stdio, so the command does not run.
    StdioClosed(i32),
    /// A descriptor listed with `--keep-fd` is not open.
    KeptNotOpen(i32),
}

impl fmt::Display for PlanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StdioClosed(fd) => write!(f, "standard descriptor {fd} is closed"),
            Self::KeptNotOpen(fd) => write!(f, "descriptor {fd} given with --keep-fd is not open"),
        }
    }
}

impl std::error::Error for PlanError {}

/// Decides each of the `open` descriptors: stdio and `keep` are inherited, the rest closed on exec.
///
/// # Errors
///
/// [`PlanError`] if a stdio descriptor or a listed one is not open.
pub(crate) fn plan(open: &[i32], keep: &[i32]) -> Result<Plan, PlanError> {
    if let Some(&fd) = [0, 1, 2].iter().find(|fd| !open.contains(fd)) {
        return Err(PlanError::StdioClosed(fd));
    }
    if let Some(&fd) = keep.iter().find(|fd| !open.contains(fd)) {
        return Err(PlanError::KeptNotOpen(fd));
    }
    let (inherit, close_on_exec) = open.iter().partition(|&fd| (0..3).contains(fd) || keep.contains(fd));
    Ok(Plan { inherit, close_on_exec })
}

#[cfg(test)]
mod tests {
    use super::*;

    // KNSH-046: only stdio and listed descriptors are inherited.
    #[test]
    fn closes_unlisted_descriptors() {
        let plan = plan(&[0, 1, 2, 3, 5, 9, 200], &[9]).unwrap();
        assert_eq!(plan.inherit, [0, 1, 2, 9]);
        assert_eq!(plan.close_on_exec, [3, 5, 200]);
    }

    #[test]
    fn keeps_nothing_extra_by_default() {
        let plan = plan(&[0, 1, 2, 4], &[]).unwrap();
        assert_eq!(plan.inherit, [0, 1, 2]);
        assert_eq!(plan.close_on_exec, [4]);
    }

    #[test]
    fn refuses_closed_stdio_and_missing_kept_descriptors() {
        assert_eq!(plan(&[0, 2, 3], &[]), Err(PlanError::StdioClosed(1)));
        assert_eq!(plan(&[0, 1, 2, 3], &[4]), Err(PlanError::KeptNotOpen(4)));
    }
}
