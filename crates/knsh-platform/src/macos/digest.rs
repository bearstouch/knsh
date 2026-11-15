//! SHA-256 through `CommonCrypto`, part of `libSystem` (no extra library, no crate).
//!
//! Used to name each compiled sandbox profile by the hash of its bytes (FR-SBX-07, KNSH-045), so a record's
//! `sandbox_profile` names exactly what ran. The incremental `Init`/`Update`/`Final` calls take lengths as 32-bit
//! values, so input is fed in chunks of at most `u32::MAX` bytes and any length is hashed whole.

use std::ffi::c_void;

/// Bytes in a SHA-256 digest (`CC_SHA256_DIGEST_LENGTH`).
pub const SHA256_LEN: usize = 32;

/// `CC_SHA256_CTX` from `<CommonCrypto/CommonDigest.h>`: `CC_LONG count[2], hash[8], wbuf[16]`, where `CC_LONG` is
/// `uint32_t`.
#[repr(C)]
struct Sha256Context {
    count: [u32; 2],
    hash: [u32; 8],
    wbuf: [u32; 16],
}

// CommonCrypto's digest functions: each returns 1 and has no failure mode for valid pointers.
unsafe extern "C" {
    fn CC_SHA256_Init(context: *mut Sha256Context) -> i32;
    fn CC_SHA256_Update(context: *mut Sha256Context, data: *const c_void, len: u32) -> i32;
    fn CC_SHA256_Final(digest: *mut u8, context: *mut Sha256Context) -> i32;
}

/// The SHA-256 digest of `data`.
#[must_use]
pub fn sha256(data: &[u8]) -> [u8; SHA256_LEN] {
    let mut context = Sha256Context {
        count: [0; 2],
        hash: [0; 8],
        wbuf: [0; 16],
    };
    let mut digest = [0u8; SHA256_LEN];
    // SAFETY: `context` is a live, writable `CC_SHA256_CTX` with the C layout (`repr(C)`, three `uint32_t` arrays)
    // for the whole sequence; `Init` fully initialises it before `Update` and `Final` read it.
    unsafe {
        CC_SHA256_Init(&raw mut context);
    }
    // A chunk of at most `u32::MAX` bytes: the length always fits in `CC_LONG`.
    for chunk in data.chunks(u32::MAX as usize) {
        let len = u32::try_from(chunk.len()).unwrap_or(u32::MAX);
        // SAFETY: `chunk` is a readable region of exactly `len` bytes that outlives the call, and `context` was
        // initialised by `Init` above.
        unsafe {
            CC_SHA256_Update(&raw mut context, chunk.as_ptr().cast(), len);
        }
    }
    // SAFETY: `digest` is a writable region of `CC_SHA256_DIGEST_LENGTH` (32) bytes, and `context` was initialised
    // by `Init`.
    unsafe {
        CC_SHA256_Final(digest.as_mut_ptr(), &raw mut context);
    }
    digest
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(digest: [u8; SHA256_LEN]) -> String {
        use std::fmt::Write as _;
        digest.iter().fold(String::new(), |mut text, byte| {
            let _ = write!(text, "{byte:02x}");
            text
        })
    }

    // FIPS 180-4 example vectors.
    #[test]
    fn matches_known_vectors() {
        assert_eq!(
            hex(sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hex(sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            hex(sha256(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
        assert_eq!(
            hex(sha256(&vec![b'a'; 1_000_000])),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        );
    }
}
