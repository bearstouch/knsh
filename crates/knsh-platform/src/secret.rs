//! Secret values and where they are read from (KNSH-089; FR-SEC-01, `specs/05-models/secret.md`).
//!
//! [`SecretValue`] holds a secret's bytes: it never prints them (`Debug` and `Display` show only the length), cannot
//! be cloned by accident, and overwrites its buffer with zeros when dropped. [`SecretStore`] reads a named secret from
//! a persistent store: the Keychain on macOS (`macos::KeychainSecrets`, service `knsh`), or `MemSecretStore` in tests.
//!
//! The engine never writes a secret: the user adds Keychain items, and the authority's `secrets.provide` values live
//! in `knshd`'s memory only (FR-SEC-07).
//!
//! # What zeroing covers
//!
//! Only the buffer a [`SecretValue`] owns. Copies made before the value reached it are outside its reach: the
//! Keychain's own `CFData`, and for `secrets.provide` the received frame and its parsed JSON. Those are released
//! without zeroing. Zeroing narrows how long the value stays in memory; it is not a guarantee that it never lingers.

use std::fmt;

use knsh_core::SecretName;

use crate::error::PlatformError;

/// A secret's value, in a buffer that is zeroed on drop.
///
/// # Invariants
///
/// - `Debug` and `Display` print `«secret: N bytes»`, never the value.
/// - Not `Clone`: a second copy takes a deliberate [`duplicate`](Self::duplicate) call, which is zeroed on drop too.
/// - The buffer never reallocates after construction, so no unzeroed copy is left behind by growth.
/// - No `PartialEq`: comparing secrets must be an explicit, constant-time decision
///   ([`constant_time_eq`](crate::constant_time_eq)).
pub struct SecretValue(Vec<u8>);

impl SecretValue {
    /// Takes ownership of `bytes` without copying them. Spare capacity is zeroed too, so call this with the buffer
    /// the value was first written into.
    #[must_use]
    pub fn from_vec(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Takes ownership of `text`'s buffer without copying it.
    #[must_use]
    pub fn from_string(text: String) -> Self {
        Self(text.into_bytes())
    }

    /// The value. Every call site is a place the value can leave this type: keep them few, and never log, store or
    /// emit what they read (NFR-PRIV-02).
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        &self.0
    }

    /// The value's length in bytes. Not secret: it is what `Debug` prints.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the value is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// A second, independent copy, for a caller that must keep one beyond this value (injection, KNSH-092).
    #[must_use]
    pub fn duplicate(&self) -> Self {
        Self(self.0.clone())
    }
}

impl Drop for SecretValue {
    fn drop(&mut self) {
        zero(&mut self.0);
    }
}

impl fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "«secret: {} bytes»", self.0.len())
    }
}

impl fmt::Display for SecretValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

/// Overwrites every byte of `buffer`'s allocation, spare capacity included, with zeros, in a way the compiler may not
/// remove as a dead store, then empties it.
#[allow(unsafe_code)]
fn zero(buffer: &mut Vec<u8>) {
    let capacity = buffer.capacity();
    let start = buffer.as_mut_ptr();
    for offset in 0..capacity {
        // SAFETY: `start` points to `buffer`'s allocation of `capacity` bytes, owned and exclusively borrowed here,
        // and `offset < capacity`, so each write stays inside it. Bytes past the length are uninitialised `u8`s,
        // which a write (unlike a read) may target. Volatile writes are never elided, even though the buffer is
        // freed right after.
        unsafe { std::ptr::write_volatile(start.add(offset), 0) };
    }
    // Keeps the writes ordered before the deallocation that follows.
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    buffer.clear();
}

/// A persistent store of named secrets that the engine reads and never writes (FR-SEC-01).
///
/// Object safe: hold it as `Arc<dyn SecretStore>`.
pub trait SecretStore: Send + Sync {
    /// The value of the secret `name`.
    ///
    /// # Errors
    ///
    /// - [`PlatformError::SecretNotFound`] when the store has no such secret.
    /// - [`PlatformError::SecretAccessDenied`] when it exists but cannot be read: not readable by this program, a
    ///   locked keychain, an item overwritten by another program (decision 11), or a value larger than
    ///   [`MAX_SECRET_VALUE_LEN`](knsh_core::MAX_SECRET_VALUE_LEN).
    ///
    /// Either way the caller has no value, and a line that needs it must be denied (fail closed).
    fn read(&self, name: &SecretName) -> Result<SecretValue, PlatformError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_value_debug_output_is_redacted() {
        #[derive(Debug)]
        struct Holder {
            #[allow(dead_code)]
            value: SecretValue,
        }

        let value = SecretValue::from_string("hunter2-token".to_owned());
        for shown in [
            format!("{value:?}"),
            format!("{value:#?}"),
            format!("{value}"),
            format!("{value:>40}"),
        ] {
            assert!(!shown.contains("hunter2"), "{shown}");
            assert!(shown.contains("13 bytes"), "{shown}");
        }
        // A containing type's derived `Debug` prints nothing of it either.
        assert!(!format!("{:?}", Holder { value }).contains("hunter2"));
    }

    #[test]
    fn secret_buffer_is_zeroed_on_drop() {
        // Observes the allocation the value owned through `zero` itself, since reading freed memory is undefined.
        let mut buffer = Vec::with_capacity(32);
        buffer.extend_from_slice(b"a-secret-value");
        let capacity = buffer.capacity();
        zero(&mut buffer);
        assert_eq!(buffer.len(), 0);
        assert_eq!(buffer.capacity(), capacity, "zeroing never reallocates");
        // SAFETY (test): every byte of the allocation was written by `zero`, so all are initialised.
        #[allow(unsafe_code)]
        let bytes = unsafe { std::slice::from_raw_parts(buffer.as_ptr(), capacity) };
        assert!(bytes.iter().all(|&b| b == 0));
        // `SecretValue`'s `Drop` is exactly this call; reading its buffer after the drop would be undefined.
    }

    #[test]
    fn duplicate_is_an_independent_copy() {
        let value = SecretValue::from_vec(b"abc".to_vec());
        let copy = value.duplicate();
        drop(value);
        assert_eq!(copy.expose(), b"abc");
        assert_eq!(copy.len(), 3);
        assert!(!copy.is_empty());
    }
}
