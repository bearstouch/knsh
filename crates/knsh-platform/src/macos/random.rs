//! Cryptographically secure random bytes.

use crate::error::PlatformError;
use crate::random::Random;

/// The system generator, `arc4random_buf` (a kernel-seeded `ChaCha20` generator on macOS). It never fails and never
/// blocks.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemRandom;

impl SystemRandom {
    /// The system generator.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl Random for SystemRandom {
    fn fill(&self, buf: &mut [u8]) -> Result<(), PlatformError> {
        // SAFETY: `buf` is a valid, writable region of exactly `buf.len()` bytes for the duration of the call, and
        // `arc4random_buf` writes only within it. It has no failure mode.
        unsafe { libc::arc4random_buf(buf.as_mut_ptr().cast(), buf.len()) };
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fills_with_distinct_bytes() {
        let random = SystemRandom::new();
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        random.fill(&mut a).unwrap();
        random.fill(&mut b).unwrap();
        // 2^-256 chance of a false failure.
        assert_ne!(a, b);
    }
}
