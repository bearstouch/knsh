//! SHA-256 and HMAC-SHA-256 through `CommonCrypto`, part of `libSystem` (no extra library, no crate).
//!
//! SHA-256 names each compiled sandbox profile by the hash of its bytes (FR-SBX-07, KNSH-045), so a record's
//! `sandbox_profile` names exactly what ran. The incremental `Init`/`Update`/`Final` calls take lengths as 32-bit
//! values, so input is fed in chunks of at most `u32::MAX` bytes and any length is hashed whole.
//!
//! [`sha256_reader`] streams a file's contents through the same calls for checkpoint post-image identity (FR-CKP-09,
//! KNSH-078), one bounded buffer at a time.
//!
//! HMAC-SHA-256 signs policy files with the key `knshd` keeps in the Keychain (FR-POL-40, KNSH-065). `CCHmac` takes
//! `size_t` lengths, so it is one call.

use std::ffi::c_void;
use std::io::{self, Read};

use crate::volume::HASH_CHUNK;

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
    fn CCHmac(
        algorithm: u32,
        key: *const c_void,
        key_length: usize,
        data: *const c_void,
        data_length: usize,
        mac_out: *mut c_void,
    );
}

/// `kCCHmacAlgSHA256` from `<CommonCrypto/CommonHMAC.h>`.
const CC_HMAC_ALG_SHA256: u32 = 2;

/// The HMAC-SHA-256 of `data` under `key` (RFC 2104). Any key length is accepted; the policy signing key is 32
/// bytes. No failure mode: `CCHmac` returns nothing and only reads its inputs.
#[must_use]
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; SHA256_LEN] {
    let mut mac = [0u8; SHA256_LEN];
    // SAFETY: `key` and `data` are readable regions of exactly the lengths passed, alive for the call (an empty
    // slice's dangling but non-null pointer is never read for length 0). `mac` is a writable region of
    // `CC_SHA256_DIGEST_LENGTH` (32) bytes, the size `CCHmac` writes for `kCCHmacAlgSHA256`.
    unsafe {
        CCHmac(
            CC_HMAC_ALG_SHA256,
            key.as_ptr().cast(),
            key.len(),
            data.as_ptr().cast(),
            data.len(),
            mac.as_mut_ptr().cast(),
        );
    }
    mac
}

/// The SHA-256 digest of `data`.
#[must_use]
pub fn sha256(data: &[u8]) -> [u8; SHA256_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finish()
}

/// The SHA-256 digest of everything `reader` yields, read through one buffer of [`HASH_CHUNK`] bytes, so memory
/// stays bounded whatever the stream's length (checkpoint post-image identity, FR-CKP-09, KNSH-078). Returns `None`
/// as soon as more than `limit` bytes have been read, without reading the rest: a caller's size limit holds even
/// for a file that grows while it is read.
///
/// # Errors
///
/// Any read error other than `Interrupted`, which is retried.
pub fn sha256_reader(reader: &mut dyn Read, limit: u64) -> io::Result<Option<[u8; SHA256_LEN]>> {
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; HASH_CHUNK];
    let mut total: u64 = 0;
    loop {
        let read = match reader.read(&mut buffer) {
            Ok(0) => return Ok(Some(hasher.finish())),
            Ok(read) => read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        };
        total = total.saturating_add(u64::try_from(read).unwrap_or(u64::MAX));
        if total > limit {
            return Ok(None);
        }
        hasher.update(&buffer[..read]);
    }
}

/// An incremental SHA-256 over `CommonCrypto`'s `Init`/`Update`/`Final`.
struct Sha256 {
    context: Sha256Context,
}

impl Sha256 {
    fn new() -> Self {
        let mut context = Sha256Context {
            count: [0; 2],
            hash: [0; 8],
            wbuf: [0; 16],
        };
        // SAFETY: `context` is a live, writable `CC_SHA256_CTX` with the C layout (`repr(C)`, three `uint32_t`
        // arrays); `Init` fully initialises it before `Update` and `Final` read it.
        unsafe {
            CC_SHA256_Init(&raw mut context);
        }
        Self { context }
    }

    fn update(&mut self, data: &[u8]) {
        // A chunk of at most `u32::MAX` bytes: the length always fits in `CC_LONG`.
        for chunk in data.chunks(u32::MAX as usize) {
            let len = u32::try_from(chunk.len()).unwrap_or(u32::MAX);
            // SAFETY: `chunk` is a readable region of exactly `len` bytes that outlives the call, and `context` was
            // initialised by `Init` in `new`.
            unsafe {
                CC_SHA256_Update(&raw mut self.context, chunk.as_ptr().cast(), len);
            }
        }
    }

    fn finish(mut self) -> [u8; SHA256_LEN] {
        let mut digest = [0u8; SHA256_LEN];
        // SAFETY: `digest` is a writable region of `CC_SHA256_DIGEST_LENGTH` (32) bytes, and `context` was
        // initialised by `Init` in `new`.
        unsafe {
            CC_SHA256_Final(digest.as_mut_ptr(), &raw mut self.context);
        }
        digest
    }
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

    // RFC 4231 test cases 1, 2 and 6 (a key longer than the block size). FR-POL-40.
    #[test]
    fn hmac_matches_rfc4231_vectors() {
        assert_eq!(
            hex(hmac_sha256(&[0x0b; 20], b"Hi There")),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
        assert_eq!(
            hex(hmac_sha256(b"Jefe", b"what do ya want for nothing?")),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
        assert_eq!(
            hex(hmac_sha256(
                &[0xaa; 131],
                b"Test Using Larger Than Block-Size Key - Hash Key First"
            )),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        );
    }

    /// A stream of `len` bytes generated on the fly (byte `i` is `i % 251`), never held in memory, that records
    /// the largest buffer it was asked to fill.
    struct Generated {
        len: u64,
        position: u64,
        largest_request: usize,
    }

    impl Read for Generated {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            self.largest_request = self.largest_request.max(buffer.len());
            let left = usize::try_from(self.len - self.position).unwrap_or(usize::MAX);
            let n = buffer.len().min(left);
            for slot in &mut buffer[..n] {
                *slot = u8::try_from(self.position % 251).unwrap();
                self.position += 1;
            }
            Ok(n)
        }
    }

    // FR-CKP-09: streaming gives the same digests as hashing at once, on the FIPS 180-4 vectors and across chunk
    // boundaries.
    #[test]
    fn hash_matches_known_sha256_vectors() {
        let stream = |data: &[u8]| {
            sha256_reader(&mut io::Cursor::new(data.to_vec()), u64::MAX)
                .unwrap()
                .unwrap()
        };
        assert_eq!(
            hex(stream(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hex(stream(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        // One million `a`: sixteen chunks, the last one partial.
        assert_eq!(
            hex(stream(&vec![b'a'; 1_000_000])),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        );
        for len in [HASH_CHUNK - 1, HASH_CHUNK, HASH_CHUNK + 1, 3 * HASH_CHUNK] {
            let data: Vec<u8> = (0..len).map(|i| u8::try_from(i % 251).unwrap()).collect();
            assert_eq!(stream(&data), sha256(&data), "{len}");
        }
    }

    // FR-CKP-09: a 256 MiB stream is hashed through one buffer of `HASH_CHUNK` bytes, never loaded whole.
    #[test]
    fn hash_streams_in_bounded_chunks() {
        let mut reader = Generated {
            len: 256 * 1024 * 1024,
            position: 0,
            largest_request: 0,
        };
        assert!(sha256_reader(&mut reader, u64::MAX).unwrap().is_some());
        assert_eq!(reader.position, reader.len, "the whole stream was read");
        assert_eq!(
            reader.largest_request, HASH_CHUNK,
            "never more than one chunk at a time"
        );
    }

    // A stream past the limit is not hashed, and reading stops at the first chunk that passes it.
    #[test]
    fn stops_reading_once_past_the_limit() {
        let limit = 10 * HASH_CHUNK as u64;
        let mut at_limit = Generated {
            len: limit,
            position: 0,
            largest_request: 0,
        };
        assert!(sha256_reader(&mut at_limit, limit).unwrap().is_some());
        let mut over = Generated {
            len: 1024 * 1024 * 1024,
            position: 0,
            largest_request: 0,
        };
        assert_eq!(sha256_reader(&mut over, limit).unwrap(), None);
        assert_eq!(over.position, limit + HASH_CHUNK as u64);
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
