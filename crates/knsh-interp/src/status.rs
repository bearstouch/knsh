//! Exit statuses, as bash reports them in `$?` (NFR-COMPAT-01, NFR-COMPAT-09).

use std::fmt;

/// The exit status of a command, list or script: 0 to 255, as `$?` shows it.
///
/// Bash's reserved values are named: 126 (found but cannot run), 127 (not found) and `128 + n` (killed by signal
/// `n`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Status(u8);

impl Status {
    /// 0: success.
    pub const SUCCESS: Self = Self(0);
    /// 1: general failure, as bash reports for an error inside a compound command (an invalid `for` variable).
    pub const FAILURE: Self = Self(1);
    /// 126: the command was found but cannot be executed (NFR-COMPAT-09).
    pub const NOT_EXECUTABLE: Self = Self(126);
    /// 127: the command was not found (NFR-COMPAT-09).
    pub const NOT_FOUND: Self = Self(127);

    /// The status `code`.
    #[must_use]
    pub const fn new(code: u8) -> Self {
        Self(code)
    }

    /// The status of a program that exited with `code`: its low eight bits, as `wait` reports them.
    #[must_use]
    pub const fn from_exit_code(code: i32) -> Self {
        Self(code.to_le_bytes()[0])
    }

    /// The status of a program killed by signal `signal`: `128 + signal`, kept to eight bits as bash does.
    #[must_use]
    pub const fn from_signal(signal: i32) -> Self {
        Self(128_i32.wrapping_add(signal).to_le_bytes()[0])
    }

    /// The numeric status.
    #[must_use]
    pub const fn code(self) -> u8 {
        self.0
    }

    /// Whether this is 0, the status `&&`, `if` and `while` treat as true.
    #[must_use]
    pub const fn is_success(self) -> bool {
        self.0 == 0
    }

    /// The status after `!`: 0 becomes 1, anything else 0.
    #[must_use]
    pub const fn negated(self) -> Self {
        if self.is_success() {
            Self::FAILURE
        } else {
            Self::SUCCESS
        }
    }
}

impl fmt::Display for Status {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_codes_keep_their_low_eight_bits() {
        assert_eq!(Status::from_exit_code(3), Status::new(3));
        assert_eq!(Status::from_exit_code(256 + 4), Status::new(4));
    }

    // NFR-COMPAT-01: a command killed by signal n yields 128 + n.
    #[test]
    fn signal_status_is_128_plus_signal() {
        assert_eq!(Status::from_signal(9), Status::new(137));
        assert_eq!(Status::from_signal(15), Status::new(143));
    }

    #[test]
    fn negation_maps_success_to_one_and_failure_to_zero() {
        assert_eq!(Status::SUCCESS.negated(), Status::FAILURE);
        assert_eq!(Status::new(42).negated(), Status::SUCCESS);
    }
}
