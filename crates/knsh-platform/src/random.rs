//! Random bytes.
//!
//! Used for ULIDs, session tokens and temporary names. The real backend is a cryptographically secure generator; the
//! test fake is seeded and reproducible, and must never be used for tokens.

use crate::error::PlatformError;

/// A source of random bytes. Object safe: hold it as `Arc<dyn Random>`.
pub trait Random: Send + Sync {
    /// Fills `buf` with random bytes.
    ///
    /// # Errors
    ///
    /// [`PlatformError::Os`] with [`Operation::Random`](crate::Operation::Random) if the system generator is
    /// unavailable. The macOS backend never fails. On error the contents of `buf` are unspecified and must not be
    /// used.
    fn fill(&self, buf: &mut [u8]) -> Result<(), PlatformError>;

    /// A random `u64`.
    ///
    /// # Errors
    ///
    /// As [`Random::fill`].
    fn next_u64(&self) -> Result<u64, PlatformError> {
        let mut bytes = [0; 8];
        self.fill(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }
}
