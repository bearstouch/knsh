//! Policy file signatures (KNSH-065; FR-POL-40 to FR-POL-42, decision 11).
//!
//! Every profile file in the policies directory carries an HMAC-SHA-256 made by `knshd` with a 32-byte key that only
//! `knshd` can read from the Keychain. A file whose signature is missing or does not verify is ignored: the loader
//! never sees its text, and the session that needed it is refused rather than run under another profile.
//!
//! # Format
//!
//! The signature is an **embedded trailer**: the file's last line, exactly
//!
//! ```text
//! # knsh-signature: v1 hmac-sha256 <64 lowercase hex digits>
//! ```
//!
//! followed by one newline. Everything before that line is the **body**, the text the loader parses (the trailer is
//! a TOML comment, so the file stays readable). The MAC is computed over
//!
//! ```text
//! "knsh-policy-signature-v1" NUL <profile name> NUL <body bytes>
//! ```
//!
//! so it covers the exact bytes of the body (any change, even one byte, invalidates it) and binds the file to its
//! profile name, so a signed file renamed to another profile does not verify. One file holds text and signature,
//! so a save is one atomic replace: no reader ever sees new text with an old signature. A body that does not end in
//! a newline gets one before it is signed, so the trailer always starts its own line.
//!
//! Anything else is **missing** (no trailer, a malformed one, an uppercase digit, trailing bytes after it) or **bad**
//! (a well-formed trailer whose MAC does not match). Both are refused alike; the difference is only reported.
//!
//! # Key
//!
//! The key lives in a [`SigningKeyStore`]: on macOS a generic-password item in the file-based login keychain,
//! created by a Developer ID-signed `knshd`, so only `knshd`'s designated requirement can read it
//! (`macos::KeychainSigningKey`, decision 11). The key is created on first **signature**, never on a verification:
//! without a key nothing was ever signed, so every file is unsigned. Once read, the key is kept in memory for the
//! life of the process. A failure to read an item that exists is **tampering or a locked keychain**: no key is
//! used, every file is refused (fail closed), and nothing is signed. Recovery needs a new key, which needs the user
//! (pending, see the story).
//!
//! Signing takes an [`Authenticated`] proof by value: only a [`UserPresence`](crate::UserPresence) backend makes
//! one, after the user passed Touch ID or the password, so no code path can sign without that prompt (FR-POL-41).
//!
//! MAC comparison is constant time ([`constant_time_eq`]).

use std::fmt::{self, Write as _};
use std::sync::{Arc, Mutex, PoisonError};

use knsh_core::ProfileName;

use crate::error::PlatformError;
use crate::presence::Authenticated;
use crate::random::Random;

/// Bytes in the signing key and in a MAC (HMAC-SHA-256).
pub const SIGNING_KEY_LEN: usize = 32;

/// What precedes the hex MAC on the trailer line.
pub const SIGNATURE_PREFIX: &str = "# knsh-signature: v1 hmac-sha256 ";

/// Domain separation for the MAC input, so a policy MAC can never be confused with any other use of the key.
const MAC_CONTEXT: &[u8] = b"knsh-policy-signature-v1";

/// Bytes in the whole trailer line, newline included.
pub const SIGNATURE_LINE_LEN: usize = SIGNATURE_PREFIX.len() + 2 * SIGNING_KEY_LEN + 1;

/// HMAC-SHA-256: `(key, data) -> mac`. The real one is `CommonCrypto`'s (`macos::hmac_sha256`, FR-POL-40); kept as a
/// function pointer so this module stays free of foreign calls.
pub type Mac = fn(&[u8], &[u8]) -> [u8; SIGNING_KEY_LEN];

/// The policy signing key. Its bytes never leave this crate: there is no accessor, and `Debug` does not show them.
#[derive(Clone, PartialEq, Eq)]
pub struct SigningKey([u8; SIGNING_KEY_LEN]);

impl SigningKey {
    /// A key from raw bytes, as a [`SigningKeyStore`] read them.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; SIGNING_KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// The raw bytes, for a [`SigningKeyStore`] to store. Crate-private: no other crate can see the key.
    pub(crate) const fn bytes(&self) -> &[u8; SIGNING_KEY_LEN] {
        &self.0
    }
}

impl fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SigningKey(..)")
    }
}

/// Where the signing key is kept. Object safe: hold it as `Arc<dyn SigningKeyStore>`.
pub trait SigningKeyStore: Send + Sync {
    /// The stored key, or `None` when no item exists yet.
    ///
    /// # Errors
    ///
    /// Any failure to read an item that exists, or a value that is not a key: treated as tampering (or a locked
    /// keychain), so the caller fails closed (decision 11). Never shows a dialog.
    fn read(&self) -> Result<Option<SigningKey>, PlatformError>;

    /// Stores `key` as a new item.
    ///
    /// # Errors
    ///
    /// Any failure, including an item that already exists (someone created it first: never overwritten).
    fn create(&self, key: &SigningKey) -> Result<(), PlatformError>;
}

/// Why a policy file is not accepted (FR-POL-42). Every variant means the file is ignored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureFault {
    /// The file has no well-formed signature trailer.
    Missing,
    /// The trailer is well formed but the MAC does not match the body and name, or no key exists yet.
    Bad,
    /// The key could not be read: tampering or a locked keychain (decision 11). Nothing can be verified.
    KeyUnavailable(PlatformError),
}

impl SignatureFault {
    /// A fixed name for the system log and API answers (`signature_missing`, `signature_bad`, `key_unavailable`).
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Missing => "signature_missing",
            Self::Bad => "signature_bad",
            Self::KeyUnavailable(_) => "key_unavailable",
        }
    }
}

impl fmt::Display for SignatureFault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing => f.write_str("policy file has no signature"),
            Self::Bad => f.write_str("policy file signature does not verify"),
            Self::KeyUnavailable(error) => write!(f, "policy signing key is unavailable: {error}"),
        }
    }
}

impl std::error::Error for SignatureFault {}

/// Signs and verifies policy files (module documentation). One per `knshd`, shared by every thread.
pub struct PolicySigner {
    store: Arc<dyn SigningKeyStore>,
    random: Arc<dyn Random>,
    mac: Mac,
    /// The key once read or created. Lock order: only this lock, never held with another; Keychain calls happen
    /// under it, so two first signatures cannot both create a key.
    key: Mutex<Option<Arc<SigningKey>>>,
}

impl PolicySigner {
    /// A signer over the key in `store`, generating a new key from `random` on first signature, computing MACs with
    /// `mac`.
    #[must_use]
    pub fn new(store: Arc<dyn SigningKeyStore>, random: Arc<dyn Random>, mac: Mac) -> Self {
        Self {
            store,
            random,
            mac,
            key: Mutex::new(None),
        }
    }

    /// Checks the signed `file` of profile `name` and returns its body, the only part the loader may parse.
    ///
    /// # Errors
    ///
    /// A [`SignatureFault`] when the file must be ignored (FR-POL-42).
    pub fn verify<'a>(&self, name: &ProfileName, file: &'a [u8]) -> Result<&'a [u8], SignatureFault> {
        let (body, mac) = split_signed(file).ok_or(SignatureFault::Missing)?;
        // Without a key nothing was ever signed by this engine, so the trailer cannot be ours.
        let key = self
            .key(false)
            .map_err(SignatureFault::KeyUnavailable)?
            .ok_or(SignatureFault::Bad)?;
        let expected = (self.mac)(key.bytes(), &mac_input(name, body));
        if constant_time_eq(&expected, &mac) {
            Ok(body)
        } else {
            Err(SignatureFault::Bad)
        }
    }

    /// The signed file for `body` of profile `name`: the body (with a final newline added if it lacks one) and the
    /// trailer. Creates the key on first use (module documentation, "Key").
    ///
    /// Takes the user's [`Authenticated`] proof by value, so each signature costs one prompt (FR-POL-41).
    ///
    /// # Errors
    ///
    /// A [`PlatformError`] when the key cannot be read or created; nothing is signed then.
    pub fn sign(&self, name: &ProfileName, body: &[u8], proof: Authenticated) -> Result<Vec<u8>, PlatformError> {
        // The proof is spent here; holding it is what allowed this call.
        drop(proof);
        let key = self.key(true)?.ok_or(PlatformError::KeychainValueInvalid)?;
        let mut file = Vec::with_capacity(body.len() + 1 + SIGNATURE_LINE_LEN);
        file.extend_from_slice(body);
        if !file.is_empty() && !file.ends_with(b"\n") {
            file.push(b'\n');
        }
        let mac = (self.mac)(key.bytes(), &mac_input(name, &file));
        file.extend_from_slice(signature_line(&mac).as_bytes());
        Ok(file)
    }

    /// The key: from memory, else from the store, else (when `create`) a new one stored first.
    fn key(&self, create: bool) -> Result<Option<Arc<SigningKey>>, PlatformError> {
        let mut cached = self.key.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(key) = cached.as_ref() {
            return Ok(Some(Arc::clone(key)));
        }
        // A read failure is never cached: a keychain that was locked may be unlocked by the next call.
        let key = match self.store.read()? {
            Some(key) => key,
            None if create => {
                let mut bytes = [0u8; SIGNING_KEY_LEN];
                self.random.fill(&mut bytes)?;
                let key = SigningKey::from_bytes(bytes);
                // Stored before use: a key that was never stored would sign files nothing can verify later.
                self.store.create(&key)?;
                key
            }
            None => return Ok(None),
        };
        let key = Arc::new(key);
        *cached = Some(Arc::clone(&key));
        Ok(Some(key))
    }
}

/// The body of `file` when it ends with a well-formed signature trailer, and the MAC the trailer holds.
#[must_use]
pub fn split_signed(file: &[u8]) -> Option<(&[u8], [u8; SIGNING_KEY_LEN])> {
    let line_start = file.len().checked_sub(SIGNATURE_LINE_LEN)?;
    let (body, line) = file.split_at(line_start);
    // The trailer is a whole line: the body is empty or ends with a newline.
    if !(body.is_empty() || body.ends_with(b"\n")) {
        return None;
    }
    let hex = line.strip_prefix(SIGNATURE_PREFIX.as_bytes())?.strip_suffix(b"\n")?;
    // `line` is exactly `SIGNATURE_LINE_LEN` bytes, so `hex` is exactly two digits per MAC byte and the loop below
    // fills every byte of `mac`.
    let (pairs, _) = hex.as_chunks::<2>();
    let mut mac = [0u8; SIGNING_KEY_LEN];
    for (byte, [high, low]) in mac.iter_mut().zip(pairs) {
        *byte = hex_digit(*high)? << 4 | hex_digit(*low)?;
    }
    Some((body, mac))
}

/// `file` without its signature trailer, if it has a well-formed one: the text a user edits.
#[must_use]
pub fn strip_signature(file: &[u8]) -> &[u8] {
    split_signed(file).map_or(file, |(body, _)| body)
}

/// The value of one lowercase hex digit. Uppercase is refused, so each MAC has exactly one spelling.
const fn hex_digit(digit: u8) -> Option<u8> {
    match digit {
        b'0'..=b'9' => Some(digit - b'0'),
        b'a'..=b'f' => Some(digit - b'a' + 10),
        _ => None,
    }
}

/// The trailer line for `mac`, newline included.
fn signature_line(mac: &[u8; SIGNING_KEY_LEN]) -> String {
    let mut line = String::with_capacity(SIGNATURE_LINE_LEN);
    line.push_str(SIGNATURE_PREFIX);
    for byte in mac {
        let _ = write!(line, "{byte:02x}");
    }
    line.push('\n');
    line
}

/// The bytes the MAC covers (module documentation, "Format"). A profile name never holds NUL, so the fields cannot
/// run into each other.
fn mac_input(name: &ProfileName, body: &[u8]) -> Vec<u8> {
    let mut input = Vec::with_capacity(MAC_CONTEXT.len() + name.as_str().len() + body.len() + 2);
    input.extend_from_slice(MAC_CONTEXT);
    input.push(0);
    input.extend_from_slice(name.as_str().as_bytes());
    input.push(0);
    input.extend_from_slice(body);
    input
}

/// Whether `a` and `b` are equal, in time that depends only on their length, so a forger learns nothing from how
/// long a comparison took.
#[must_use]
pub fn constant_time_eq(a: &[u8; SIGNING_KEY_LEN], b: &[u8; SIGNING_KEY_LEN]) -> bool {
    let difference = a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y));
    std::hint::black_box(difference) == 0
}

// The MAC is CommonCrypto's, so these run where the macOS backend is built. `cfg(test)` stays its own attribute so
// clippy treats the module as test code (`allow-unwrap-in-tests`).
#[cfg(test)]
#[cfg(target_os = "macos")]
pub(crate) mod tests {
    use super::*;
    use crate::macos::hmac_sha256;
    use crate::testing::{MemKeyStore, SeededRandom};

    pub(crate) fn signer(store: &Arc<MemKeyStore>) -> PolicySigner {
        PolicySigner::new(store.clone(), Arc::new(SeededRandom::new(7)), hmac_sha256)
    }

    fn name(text: &str) -> ProfileName {
        ProfileName::new(text).unwrap()
    }

    const BODY: &[u8] = b"name = \"web\"\n[fs]\nwrite = [\"${PROJECT}\"]\n";

    // FR-POL-40: a file signed by this engine verifies and yields exactly its body.
    #[test]
    fn accepts_correctly_signed_file() {
        let store = Arc::new(MemKeyStore::new());
        let signer = signer(&store);
        let file = signer.sign(&name("web"), BODY, Authenticated::new()).unwrap();
        assert!(file.starts_with(BODY));
        assert_eq!(file.len(), BODY.len() + SIGNATURE_LINE_LEN);
        assert_eq!(signer.verify(&name("web"), &file), Ok(BODY));
        // A fresh signer (a restarted knshd) reads the same key and agrees.
        assert_eq!(super::tests::signer(&store).verify(&name("web"), &file), Ok(BODY));
    }

    // FR-POL-40: the signature covers every byte of the body, and the trailer itself.
    #[test]
    fn any_byte_change_invalidates_signature() {
        let store = Arc::new(MemKeyStore::new());
        let signer = signer(&store);
        let file = signer.sign(&name("web"), BODY, Authenticated::new()).unwrap();
        for index in 0..file.len() {
            for flip in [0x01, 0x20, 0x80] {
                let mut changed = file.clone();
                changed[index] ^= flip;
                assert!(
                    signer.verify(&name("web"), &changed).is_err(),
                    "byte {index} ^ {flip:#x}"
                );
            }
        }
        // Bytes added or removed anywhere.
        let mut longer = file.clone();
        longer.insert(0, b' ');
        assert!(signer.verify(&name("web"), &longer).is_err());
        let mut appended = file.clone();
        appended.push(b'\n');
        assert_eq!(signer.verify(&name("web"), &appended), Err(SignatureFault::Missing));
        assert!(signer.verify(&name("web"), &file[1..]).is_err());
        // The same file under another profile name.
        assert_eq!(signer.verify(&name("other"), &file), Err(SignatureFault::Bad));
    }

    // FR-POL-42: no trailer, or one that is not exactly the format, is missing; never parsed further.
    #[test]
    fn ignores_unsigned_file() {
        let store = Arc::new(MemKeyStore::new());
        let signer = signer(&store);
        assert_eq!(signer.verify(&name("web"), BODY), Err(SignatureFault::Missing));
        assert_eq!(signer.verify(&name("web"), b""), Err(SignatureFault::Missing));
        let file = signer.sign(&name("web"), BODY, Authenticated::new()).unwrap();
        let upper = String::from_utf8(file.clone()).unwrap();
        let hex_start = BODY.len() + SIGNATURE_PREFIX.len();
        let upper = format!("{}{}", &upper[..hex_start], upper[hex_start..].to_uppercase());
        assert_eq!(
            signer.verify(&name("web"), upper.as_bytes()),
            Err(SignatureFault::Missing)
        );
        let mut no_newline = file.clone();
        no_newline.pop();
        assert_eq!(signer.verify(&name("web"), &no_newline), Err(SignatureFault::Missing));
        // The trailer glued to a body line is not a line of its own.
        let glued = [&BODY[..BODY.len() - 1], &file[BODY.len()..]].concat();
        assert_eq!(signer.verify(&name("web"), &glued), Err(SignatureFault::Missing));
        // A trailer before any key exists is not ours.
        let fresh = super::tests::signer(&Arc::new(MemKeyStore::new()));
        assert_eq!(fresh.verify(&name("web"), &file), Err(SignatureFault::Bad));
    }

    // FR-POL-42: a MAC made with another key is bad.
    #[test]
    fn ignores_file_with_bad_signature() {
        let other = signer(&Arc::new(MemKeyStore::with_key([9; SIGNING_KEY_LEN])));
        let forged = other.sign(&name("web"), BODY, Authenticated::new()).unwrap();
        let store = Arc::new(MemKeyStore::new());
        let signer = signer(&store);
        let _ = signer.sign(&name("web"), BODY, Authenticated::new()).unwrap();
        assert_eq!(signer.verify(&name("web"), &forged), Err(SignatureFault::Bad));
    }

    // Decision 11: a key that cannot be read (tampering, locked keychain) refuses every file and every signature,
    // and is retried on the next call rather than remembered as missing.
    #[test]
    fn unreadable_key_fails_closed() {
        let store = Arc::new(MemKeyStore::new());
        let file = signer(&store).sign(&name("web"), BODY, Authenticated::new()).unwrap();
        let signer = signer(&store);
        store.fail_reads(-25293);
        assert!(matches!(
            signer.verify(&name("web"), &file),
            Err(SignatureFault::KeyUnavailable(PlatformError::Keychain {
                status: -25293,
                ..
            }))
        ));
        assert!(signer.sign(&name("web"), BODY, Authenticated::new()).is_err());
        assert_eq!(store.creates(), 1, "an unreadable key is never replaced");
        store.allow_reads();
        assert_eq!(signer.verify(&name("web"), &file), Ok(BODY));
    }

    // The key is created on first signature only, stored before use, and read once per process.
    #[test]
    fn creates_the_key_on_first_signature_only() {
        let store = Arc::new(MemKeyStore::new());
        let signer = signer(&store);
        assert_eq!(signer.verify(&name("web"), BODY), Err(SignatureFault::Missing));
        assert_eq!(store.creates(), 0, "verification never creates a key");
        let file = signer.sign(&name("web"), BODY, Authenticated::new()).unwrap();
        assert_eq!(store.creates(), 1);
        let _ = signer.sign(&name("web"), BODY, Authenticated::new()).unwrap();
        assert_eq!(store.creates(), 1);
        let reads = store.reads();
        assert_eq!(signer.verify(&name("web"), &file), Ok(BODY));
        assert_eq!(store.reads(), reads, "the key is kept in memory once read");

        // A store that refuses the new key signs nothing.
        let refusing = Arc::new(MemKeyStore::new());
        refusing.fail_creates(-25299);
        assert!(
            super::tests::signer(&refusing)
                .sign(&name("web"), BODY, Authenticated::new())
                .is_err()
        );
    }

    // The trailer always starts its own line; an empty body is signed as is.
    #[test]
    fn adds_a_final_newline_before_signing() {
        let signer = signer(&Arc::new(MemKeyStore::new()));
        let file = signer
            .sign(&name("web"), b"name = \"web\"", Authenticated::new())
            .unwrap();
        assert_eq!(signer.verify(&name("web"), &file), Ok(&b"name = \"web\"\n"[..]));
        let empty = signer.sign(&name("web"), b"", Authenticated::new()).unwrap();
        assert_eq!(empty.len(), SIGNATURE_LINE_LEN);
        assert_eq!(signer.verify(&name("web"), &empty), Ok(&b""[..]));
        assert_eq!(strip_signature(&file), b"name = \"web\"\n");
        assert_eq!(strip_signature(BODY), BODY);
    }

    #[test]
    fn constant_time_eq_compares_every_byte() {
        let a = [1u8; SIGNING_KEY_LEN];
        let mut b = a;
        assert!(constant_time_eq(&a, &b));
        b[SIGNING_KEY_LEN - 1] = 0;
        assert!(!constant_time_eq(&a, &b));
        assert_eq!(format!("{:?}", SigningKey::from_bytes(a)), "SigningKey(..)");
    }
}
