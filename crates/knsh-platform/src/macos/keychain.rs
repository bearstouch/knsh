//! Engine secrets in the Keychain: the policy signing key (KNSH-065, FR-POL-40) and the authority trust record
//! (KNSH-068, FR-AUTH-11), both under decision 11.
//!
//! Each is a generic-password item in the **file-based (legacy) login keychain**, created with `SecItemAdd` and the
//! default access list. Created by a Developer ID-signed `knshd`, the item trusts `knshd`'s designated requirement
//! (identifier and team) with partition `teamid:<team>`, so later Developer ID builds read it and nothing else does
//! (KNSH-026, claim C5). Ad-hoc and Homebrew-from-source builds are trusted by code hash, so each upgrade loses the
//! key: every policy file must then be signed again with `knsh policy edit`.
//!
//! Rules from decision 11:
//!
//! - **No dialog, ever.** Keychain user interaction is disabled for the process before every call, so a would-be
//!   "allow access" dialog comes back as an error (`-25293`): a click there would hand the key to another program.
//! - **A read failure on an existing item is tampering** (or a locked keychain). Any same-user process can overwrite
//!   the value; code outside the team then changes the partition list and the read fails. The error is returned and
//!   the caller fails closed; the item is never deleted or replaced from here.
//! - **Never overwrite.** The signing key is only ever created (`SecItemAdd`): an item that already exists
//!   (`-25299`), perhaps planted by someone else, is an error, not something to update.
//!
//! The trust record differs in one way: the user may replace it (`knsh authority trust` again, after Touch ID or the
//! password). `knshd` replaces only a record it has just read successfully, so the item is one its own code can
//! access, and uses `SecItemUpdate`, which keeps the item and its access list. A record that cannot be read is
//! tampering and is never replaced from here (the caller refuses); one that reads but does not decode is refused
//! the same way. Until the user removes such an item (`security delete-generic-password -s knsh.authority-trust`),
//! no authority is trusted.
//!
//! Named secrets (KNSH-089, FR-SEC-01) are generic-password items under service [`SECRET_SERVICE`] (`knsh`), with
//! the secret's name as the account. `knshd` only ever reads them ([`KeychainSecrets`]); the user adds them. Rule 1
//! applies: an item `knshd`'s code is not trusted to read comes back as an error, never a dialog, and is reported as
//! access denied. A missing item is "not found". Either way the caller has no value and fails closed.
//!
//! The data-protection keychain is not used: it needs `knshd` inside an app bundle with a provisioning profile.

use std::ffi::c_void;

use knsh_core::{MAX_SECRET_VALUE_LEN, MAX_TRUST_RECORD_LEN, SecretName, TrustedAuthority};

use crate::control::TrustStore;
use crate::error::{Operation, PlatformError};
use crate::presence::Authenticated;
use crate::secret::{SecretStore, SecretValue};
use crate::signing::{SIGNING_KEY_LEN, SigningKey, SigningKeyStore};

/// The item's service: names the engine and what the item is for.
pub const SIGNING_KEY_SERVICE: &str = "knsh.policy-signing";
/// The item's account: the key's format version, so a future key format can live beside this one.
pub const SIGNING_KEY_ACCOUNT: &str = "hmac-sha256-v1";

/// The trust record item's service (KNSH-068).
pub const TRUST_SERVICE: &str = "knsh.authority-trust";
/// The trust record item's account: the record's format version, as in its header line.
pub const TRUST_ACCOUNT: &str = "v1";

/// Named secrets' service (KNSH-089, `specs/09-reference/file-locations.md`); the account is the secret's name.
pub const SECRET_SERVICE: &str = "knsh";

/// `errSecSuccess`.
const ERR_SEC_SUCCESS: i32 = 0;
/// `errSecItemNotFound`: no item matches.
const ERR_SEC_ITEM_NOT_FOUND: i32 = -25300;
/// `errSecParam`: reported when a query cannot even be built (a string or dictionary Core Foundation refused), so
/// the caller sees one Keychain failure and fails closed like any other.
const ERR_SEC_PARAM: i32 = -50;

const K_CF_STRING_ENCODING_UTF8: u32 = 0x0800_0100;

/// A Core Foundation object (`CFTypeRef`).
type CfRef = *const c_void;

#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    /// `kCFTypeDictionaryKeyCallBacks`, a `CFDictionaryKeyCallBacks` (six pointer-sized fields); only its address is
    /// used.
    static kCFTypeDictionaryKeyCallBacks: [usize; 6];
    /// `kCFTypeDictionaryValueCallBacks`, a `CFDictionaryValueCallBacks` (five pointer-sized fields).
    static kCFTypeDictionaryValueCallBacks: [usize; 5];
    static kCFBooleanTrue: CfRef;

    fn CFDictionaryCreate(
        allocator: CfRef,
        keys: *const CfRef,
        values: *const CfRef,
        count: isize,
        key_callbacks: *const c_void,
        value_callbacks: *const c_void,
    ) -> CfRef;
    /// Declared exactly as in `presence` (a mutable object pointer), so the two declarations agree.
    fn CFStringCreateWithBytes(
        allocator: *const c_void,
        bytes: *const u8,
        length: isize,
        encoding: u32,
        is_external: u8,
    ) -> *mut c_void;
    fn CFDataCreate(allocator: CfRef, bytes: *const u8, length: isize) -> CfRef;
    fn CFDataGetLength(data: CfRef) -> isize;
    fn CFDataGetBytePtr(data: CfRef) -> *const u8;
    fn CFDataGetTypeID() -> usize;
    fn CFGetTypeID(object: CfRef) -> usize;
    fn CFRelease(object: CfRef);
}

#[link(name = "Security", kind = "framework")]
unsafe extern "C" {
    static kSecClass: CfRef;
    static kSecClassGenericPassword: CfRef;
    static kSecAttrService: CfRef;
    static kSecAttrAccount: CfRef;
    static kSecAttrLabel: CfRef;
    static kSecValueData: CfRef;
    static kSecReturnData: CfRef;
    static kSecMatchLimit: CfRef;
    static kSecMatchLimitOne: CfRef;

    fn SecItemCopyMatching(query: CfRef, result: *mut CfRef) -> i32;
    fn SecItemAdd(attributes: CfRef, result: *mut CfRef) -> i32;
    fn SecItemUpdate(query: CfRef, attributes: CfRef) -> i32;
    /// Deprecated, but the only switch for the legacy keychain's dialogs; process wide. Observed in KNSH-026.
    fn SecKeychainSetUserInteractionAllowed(allowed: u8) -> i32;
}

/// An owned Core Foundation object, released on drop. Never null.
struct Owned(CfRef);

impl Owned {
    /// Takes ownership of `object` (a "Create" or "Copy" result), or `None` if it is null.
    fn new(object: CfRef) -> Option<Self> {
        // Not `then_some`: its argument is built eagerly, so a null would be wrapped and then released on drop.
        if object.is_null() { None } else { Some(Self(object)) }
    }
}

impl Drop for Owned {
    fn drop(&mut self) {
        // SAFETY: `self.0` is a non-null object this value owns one reference to (from a Create or Copy call), and it
        // is released exactly once, here.
        unsafe { CFRelease(self.0) };
    }
}

/// A `CFString` holding `text`.
fn cf_string(text: &str) -> Option<Owned> {
    let length = isize::try_from(text.len()).ok()?;
    // SAFETY: `text` is a readable UTF-8 region of exactly `length` bytes, alive for the call; the function copies it
    // (`is_external` false) and returns a new string or null.
    Owned::new(
        unsafe { CFStringCreateWithBytes(std::ptr::null(), text.as_ptr(), length, K_CF_STRING_ENCODING_UTF8, 0) }
            .cast_const(),
    )
}

/// A `CFData` holding a copy of `bytes`.
fn cf_data(bytes: &[u8]) -> Option<Owned> {
    let length = isize::try_from(bytes.len()).ok()?;
    // SAFETY: `bytes` is a readable region of exactly `length` bytes, alive for the call; the function copies it.
    Owned::new(unsafe { CFDataCreate(std::ptr::null(), bytes.as_ptr(), length) })
}

/// A `CFDictionary` of `pairs`, retaining each key and value.
fn cf_dictionary(pairs: &[(CfRef, CfRef)]) -> Option<Owned> {
    let keys: Vec<CfRef> = pairs.iter().map(|(key, _)| *key).collect();
    let values: Vec<CfRef> = pairs.iter().map(|(_, value)| *value).collect();
    let count = isize::try_from(pairs.len()).ok()?;
    // SAFETY: `keys` and `values` hold `count` live, non-null CF objects each, alive for the call; the type callbacks
    // retain them, so the dictionary does not depend on the caller's references afterwards. The callback statics are
    // the framework's own and only their addresses are passed.
    Owned::new(unsafe {
        CFDictionaryCreate(
            std::ptr::null(),
            keys.as_ptr(),
            values.as_ptr(),
            count,
            (&raw const kCFTypeDictionaryKeyCallBacks).cast(),
            (&raw const kCFTypeDictionaryValueCallBacks).cast(),
        )
    })
}

/// One generic-password item, named by its service and account. Stateless: every call queries the Keychain, with
/// user interaction disabled first (decision 11, rule 1).
#[derive(Debug, Clone)]
struct Item {
    service: String,
    account: String,
}

impl Item {
    fn new(service: &str, account: &str) -> Self {
        Self {
            service: service.to_owned(),
            account: account.to_owned(),
        }
    }

    /// The service and account strings, which identify the item in every query.
    fn identity(&self, operation: Operation) -> Result<(Owned, Owned), PlatformError> {
        Ok((
            cf_string(&self.service).ok_or(unusable(operation))?,
            cf_string(&self.account).ok_or(unusable(operation))?,
        ))
    }

    /// The item's value, or `None` when no item exists. A value longer than `max_len` is refused before it is
    /// copied.
    ///
    /// # Errors
    ///
    /// Any other failure (tampering or a locked keychain, decision 11), or a value that is not data of at most
    /// `max_len` bytes ([`PlatformError::KeychainValueInvalid`]).
    fn read(&self, max_len: usize) -> Result<Option<Vec<u8>>, PlatformError> {
        let operation = Operation::KeychainRead;
        disable_user_interaction(operation)?;
        let (service, account) = self.identity(operation)?;
        // SAFETY: the `kSec…` and `kCFBooleanTrue` statics are constant objects the frameworks initialise before any
        // code runs; reading them is a plain load.
        let query = unsafe {
            cf_dictionary(&[
                (kSecClass, kSecClassGenericPassword),
                (kSecAttrService, service.0),
                (kSecAttrAccount, account.0),
                (kSecReturnData, kCFBooleanTrue),
                (kSecMatchLimit, kSecMatchLimitOne),
            ])
        }
        .ok_or(unusable(operation))?;
        let mut result: CfRef = std::ptr::null();
        // SAFETY: `query` is a live dictionary; `result` is a writable pointer that receives a +1 reference on
        // success (owned below) and is left untouched otherwise.
        let status = unsafe { SecItemCopyMatching(query.0, &raw mut result) };
        let result = Owned::new(result);
        match status {
            ERR_SEC_SUCCESS => {}
            ERR_SEC_ITEM_NOT_FOUND => return Ok(None),
            // Decision 11: any other failure on lookup is tampering or a locked keychain. Fail closed.
            status => return Err(PlatformError::Keychain { operation, status }),
        }
        let data = result.ok_or(PlatformError::KeychainValueInvalid)?;
        // SAFETY: `data.0` is a live CF object; asking its type has no preconditions.
        if unsafe { CFGetTypeID(data.0) != CFDataGetTypeID() } {
            return Err(PlatformError::KeychainValueInvalid);
        }
        // SAFETY: `data.0` is a live `CFData`; its length and byte pointer stay valid while `data` is alive, which
        // spans the copy below.
        let bytes = unsafe {
            let length = usize::try_from(CFDataGetLength(data.0)).map_err(|_| PlatformError::KeychainValueInvalid)?;
            if length > max_len {
                return Err(PlatformError::KeychainValueInvalid);
            }
            if length == 0 {
                return Ok(Some(Vec::new()));
            }
            let pointer = CFDataGetBytePtr(data.0);
            if pointer.is_null() {
                return Err(PlatformError::KeychainValueInvalid);
            }
            std::slice::from_raw_parts(pointer, length)
        };
        Ok(Some(bytes.to_vec()))
    }

    /// Creates the item with `value`, labelled `label`, with the default access list (this code's designated
    /// requirement).
    ///
    /// # Errors
    ///
    /// Any failure, including an item that already exists (`-25299`): never overwritten (decision 11, rule 3).
    fn add(&self, label: &str, value: &[u8]) -> Result<(), PlatformError> {
        let operation = Operation::KeychainAdd;
        disable_user_interaction(operation)?;
        let (service, account) = self.identity(operation)?;
        let label = cf_string(label).ok_or(unusable(operation))?;
        let value = cf_data(value).ok_or(unusable(operation))?;
        // SAFETY: as in `read`: the `kSec…` statics are constant framework objects.
        let attributes = unsafe {
            cf_dictionary(&[
                (kSecClass, kSecClassGenericPassword),
                (kSecAttrService, service.0),
                (kSecAttrAccount, account.0),
                (kSecAttrLabel, label.0),
                (kSecValueData, value.0),
            ])
        }
        .ok_or(unusable(operation))?;
        // SAFETY: `attributes` is a live dictionary; a null result pointer asks for no result object.
        let status = unsafe { SecItemAdd(attributes.0, std::ptr::null_mut()) };
        if status == ERR_SEC_SUCCESS {
            Ok(())
        } else {
            Err(PlatformError::Keychain { operation, status })
        }
    }

    /// Replaces the existing item's value with `value`. The item, its label and its access list are kept.
    ///
    /// # Errors
    ///
    /// Any failure, including no item (`-25300`): nothing is created here.
    fn update(&self, value: &[u8]) -> Result<(), PlatformError> {
        let operation = Operation::KeychainUpdate;
        disable_user_interaction(operation)?;
        let (service, account) = self.identity(operation)?;
        let value = cf_data(value).ok_or(unusable(operation))?;
        // SAFETY: as in `read`: the `kSec…` statics are constant framework objects.
        let (query, changes) = unsafe {
            (
                cf_dictionary(&[
                    (kSecClass, kSecClassGenericPassword),
                    (kSecAttrService, service.0),
                    (kSecAttrAccount, account.0),
                ]),
                cf_dictionary(&[(kSecValueData, value.0)]),
            )
        };
        let (Some(query), Some(changes)) = (query, changes) else {
            return Err(unusable(operation));
        };
        // SAFETY: both are live dictionaries for the call.
        let status = unsafe { SecItemUpdate(query.0, changes.0) };
        if status == ERR_SEC_SUCCESS {
            Ok(())
        } else {
            Err(PlatformError::Keychain { operation, status })
        }
    }
}

/// `errSecParam` for `operation`: a query that could not even be built.
const fn unusable(operation: Operation) -> PlatformError {
    PlatformError::Keychain {
        operation,
        status: ERR_SEC_PARAM,
    }
}

/// Turns the legacy keychain's "allow access" dialog into an error for the whole process (decision 11, rule 1).
///
/// # Errors
///
/// The `OSStatus` if the switch was refused: no Keychain call is made then, since it might show the dialog.
fn disable_user_interaction(operation: Operation) -> Result<(), PlatformError> {
    // SAFETY: takes a `Boolean` by value and touches no memory of ours.
    let status = unsafe { SecKeychainSetUserInteractionAllowed(0) };
    if status == ERR_SEC_SUCCESS {
        Ok(())
    } else {
        Err(PlatformError::Keychain { operation, status })
    }
}

/// The policy signing key as a Keychain item (module documentation). Stateless: every call queries the Keychain;
/// `PolicySigner` keeps the key in memory once read.
#[derive(Debug, Clone)]
pub struct KeychainSigningKey {
    item: Item,
}

impl KeychainSigningKey {
    /// The engine's item: [`SIGNING_KEY_SERVICE`], [`SIGNING_KEY_ACCOUNT`].
    #[must_use]
    pub fn new() -> Self {
        Self::named(SIGNING_KEY_SERVICE, SIGNING_KEY_ACCOUNT)
    }

    /// An item with another service and account: for a manual check against a throwaway item, never the engine's.
    #[must_use]
    pub fn named(service: &str, account: &str) -> Self {
        Self {
            item: Item::new(service, account),
        }
    }
}

impl Default for KeychainSigningKey {
    fn default() -> Self {
        Self::new()
    }
}

impl SigningKeyStore for KeychainSigningKey {
    fn read(&self) -> Result<Option<SigningKey>, PlatformError> {
        let Some(bytes) = self.item.read(SIGNING_KEY_LEN)? else {
            return Ok(None);
        };
        let key: [u8; SIGNING_KEY_LEN] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| PlatformError::KeychainValueInvalid)?;
        Ok(Some(SigningKey::from_bytes(key)))
    }

    fn create(&self, key: &SigningKey) -> Result<(), PlatformError> {
        // Including `errSecDuplicateItem`: never overwrite an item someone else may have planted (rule 3).
        self.item.add("knsh policy signing key", key.bytes())
    }
}

/// Named secrets as Keychain items: service [`SECRET_SERVICE`], account the secret's name (module documentation,
/// KNSH-089). Read only, stateless: every call queries the Keychain, so a secret the user changes or removes takes
/// effect at the next lookup.
#[derive(Debug, Clone)]
pub struct KeychainSecrets {
    service: String,
}

impl KeychainSecrets {
    /// The engine's secrets: service [`SECRET_SERVICE`].
    #[must_use]
    pub fn new() -> Self {
        Self::with_service(SECRET_SERVICE)
    }

    /// Secrets under another service: for a manual check against throwaway items, never the engine's.
    #[must_use]
    pub fn with_service(service: &str) -> Self {
        Self {
            service: service.to_owned(),
        }
    }
}

impl Default for KeychainSecrets {
    fn default() -> Self {
        Self::new()
    }
}

impl SecretStore for KeychainSecrets {
    fn read(&self, name: &SecretName) -> Result<SecretValue, PlatformError> {
        match Item::new(&self.service, name.as_str()).read(MAX_SECRET_VALUE_LEN) {
            // `read` copies the bytes into a vector of exactly their length, moved here without another copy.
            // An empty item is refused like an unreadable one: `secrets.provide` refuses empty values too.
            Ok(Some(bytes)) if bytes.is_empty() => Err(PlatformError::SecretAccessDenied { status: None }),
            Ok(Some(bytes)) => Ok(SecretValue::from_vec(bytes)),
            Ok(None) => Err(PlatformError::SecretNotFound),
            Err(PlatformError::Keychain { status, .. }) => {
                Err(PlatformError::SecretAccessDenied { status: Some(status) })
            }
            // `KeychainValueInvalid` (a value that is not data, or larger than the limit) is the only other failure
            // `Item::read` reports: refused like an unreadable one. Anything else would still mean no value.
            Err(_) => Err(PlatformError::SecretAccessDenied { status: None }),
        }
    }
}

/// The capability probe's item (KNSH-089): a service and account the engine never creates, so the lookup reads no
/// real secret.
const PROBE_SERVICE: &str = "knsh.probe";
/// See [`PROBE_SERVICE`].
const PROBE_ACCOUNT: &str = "never-created";

/// Whether the Keychain answers lookups here: one for an item that never exists, with user interaction disabled.
/// An answer of "not found" (or, should someone have created the item, any item) passes.
///
/// # Errors
///
/// The Keychain's failure: `secrets` is then reported as `none`.
pub(super) fn check_reachable() -> Result<(), PlatformError> {
    match Item::new(PROBE_SERVICE, PROBE_ACCOUNT).read(MAX_SECRET_VALUE_LEN) {
        Ok(_) | Err(PlatformError::KeychainValueInvalid) => Ok(()),
        Err(error) => Err(error),
    }
}

/// The authority trust record as a Keychain item (module documentation, FR-AUTH-11). Stateless: every call queries
/// the Keychain.
#[derive(Debug, Clone)]
pub struct KeychainTrustStore {
    item: Item,
}

impl KeychainTrustStore {
    /// The engine's item: [`TRUST_SERVICE`], [`TRUST_ACCOUNT`].
    #[must_use]
    pub fn new() -> Self {
        Self::named(TRUST_SERVICE, TRUST_ACCOUNT)
    }

    /// An item with another service and account: for a manual check against a throwaway item, never the engine's.
    #[must_use]
    pub fn named(service: &str, account: &str) -> Self {
        Self {
            item: Item::new(service, account),
        }
    }
}

impl Default for KeychainTrustStore {
    fn default() -> Self {
        Self::new()
    }
}

impl TrustStore for KeychainTrustStore {
    fn read(&self) -> Result<Option<TrustedAuthority>, PlatformError> {
        let Some(bytes) = self.item.read(MAX_TRUST_RECORD_LEN)? else {
            return Ok(None);
        };
        // A value the engine did not write is refused like an unreadable one: nothing is trusted (fail closed).
        TrustedAuthority::decode(&bytes)
            .map(Some)
            .map_err(|_| PlatformError::KeychainValueInvalid)
    }

    fn create(&self, record: &TrustedAuthority, _proof: Authenticated) -> Result<(), PlatformError> {
        self.item.add("knsh trusted authority", &record.encode())
    }

    fn replace(&self, record: &TrustedAuthority, _proof: Authenticated) -> Result<(), PlatformError> {
        self.item.update(&record.encode())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A missing item reads back as a null reference: it must be `None` and never be released. `CFRelease(NULL)` traps,
    // which crashed `knshd` at start-up whenever no authority was trusted (found by KNSH-076's idle-memory run).
    #[test]
    fn null_is_none_and_never_released() {
        assert!(Owned::new(std::ptr::null()).is_none());
    }

    // Manual (claim C5, pending): writes a throwaway item to the login keychain, so it never runs by default
    // (CLAUDE.md: tests never touch the user's real state). Run with `--ignored` on a test machine, then delete the
    // item with `security delete-generic-password -s knsh.test.policy-signing`.
    #[test]
    #[ignore = "writes to the login keychain; manual check only"]
    fn creates_then_reads_a_throwaway_item() {
        let store = KeychainSigningKey::named("knsh.test.policy-signing", "manual");
        let key = SigningKey::from_bytes([7; SIGNING_KEY_LEN]);
        store.create(&key).unwrap();
        assert_eq!(store.read().unwrap(), Some(key.clone()));
        assert!(matches!(
            store.create(&key),
            Err(PlatformError::Keychain { status: -25299, .. })
        ));
    }

    // Manual (KNSH-068, pending): creates, reads, replaces and reads a throwaway trust record. Delete it afterwards
    // with `security delete-generic-password -s knsh.test.authority-trust`.
    #[test]
    #[ignore = "writes to the login keychain; manual check only"]
    fn creates_replaces_and_reads_a_throwaway_trust_record() {
        use knsh_core::{BundleVersion, SigningIdentifier, TeamId};

        let store = KeychainTrustStore::named("knsh.test.authority-trust", "manual");
        let first = TrustedAuthority {
            team_id: TeamId::new("ABCDE12345").unwrap(),
            identifier: SigningIdentifier::new("com.example.authority").unwrap(),
            min_version: BundleVersion::parse("1.0").unwrap(),
        };
        store.create(&first, Authenticated::new()).unwrap();
        assert_eq!(store.read().unwrap(), Some(first.clone()));
        let second = TrustedAuthority {
            min_version: BundleVersion::parse("2.1").unwrap(),
            ..first
        };
        store.replace(&second, Authenticated::new()).unwrap();
        assert_eq!(store.read().unwrap(), Some(second));
    }

    // Manual (KNSH-089, pending): reads a secret the tester added to the login keychain under a throwaway service,
    // with `knshd`'s test binary allowed to read it:
    //   security add-generic-password -s knsh.test.secrets -a manual -w test-value -T <this test binary>
    // An item the binary is not trusted to read must come back as access denied, never a dialog.
    #[test]
    #[ignore = "reads the login keychain; manual check only"]
    fn reads_a_secret_added_to_a_throwaway_service() {
        let store = KeychainSecrets::with_service("knsh.test.secrets");
        let name = SecretName::new("manual").unwrap();
        assert_eq!(store.read(&name).unwrap().expose(), b"test-value");
        let missing = SecretName::new("never-created").unwrap();
        assert!(matches!(store.read(&missing), Err(PlatformError::SecretNotFound)));
    }

    #[test]
    #[ignore = "reads the login keychain; manual check only"]
    fn a_missing_item_reads_as_none() {
        let store = KeychainSigningKey::named("knsh.test.policy-signing", "never-created");
        assert_eq!(store.read().unwrap(), None);
    }
}
