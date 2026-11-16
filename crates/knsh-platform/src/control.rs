//! Who may talk to the control service, and what passes between them (KNSH-067).
//!
//! The control service is reachable only by the authority the user trusted (FR-AUTH-12 – FR-AUTH-14,
//! `specs/06-api/control-service.md`). This module is the platform-neutral half: the trust record's parts, the code
//! requirement built from them, the decision about a peer, and the interface between the XPC transport
//! (`macos::XpcControlService`) and the JSON-RPC session that serves it in `knshd`.
//!
//! # Verification (decision 13, KNSH-026 claim C7)
//!
//! Two layers, both required:
//!
//! 1. **The peer code-signing requirement** ([`peer_requirement`]), set by XPC on every peer connection: a Developer
//!    ID or Mac App Store signature, the trusted team and identifier, and no `get-task-allow` entitlement
//!    (FR-AUTH-13). XPC refuses a non-matching peer before any message reaches `knshd`.
//! 2. **Facts the requirement language cannot express** ([`SignatureFacts`]), read for **every message** from the
//!    code that sent it, by audit token (never by pid: a process can send, then exec a trusted binary under the same
//!    pid): hardened runtime, a live signature that is valid and neither debuggable nor debugged, and a
//!    `CFBundleVersion` at least the trusted minimum (FR-AUTH-14). [`PeerGate::admit`] decides; any doubt refuses.
//!
//! With no trusted authority, [`PeerGate::admit`] refuses everything and the transport cancels each connection
//! before it is resumed, so nothing is ever read from it.
//!
//! # Message shape (`specs/06-api/wire-format.md#control-service-xpc`)
//!
//! Each XPC message is a dictionary. [`JSON_KEY`] holds one JSON-RPC message as an XPC data value (the strict
//! profile applies exactly as on the sockets, and at most [`MAX_CONTROL_PAYLOAD`] bytes); [`BYTES_KEY`], only in
//! messages from `knshd`, holds the raw bytes of the stream the JSON names. A request with any other shape is a
//! transport violation: the connection is closed without an answer, like a framing violation on a socket.

use std::fmt;
use std::sync::Arc;

use crate::error::PlatformError;

/// The dictionary key of the JSON-RPC message, an XPC data value.
pub const JSON_KEY: &str = "json";

/// The dictionary key of the raw bytes that follow a JSON message (`records.output`, `command.output`), an XPC data
/// value. Sent by `knshd` only; a request carrying it is refused.
pub const BYTES_KEY: &str = "bytes";

/// Largest JSON payload either side may send, the same limit as a socket frame (NFR-SEC-07).
pub const MAX_CONTROL_PAYLOAD: usize = knsh_json::MAX_PAYLOAD;

// Code-signing flags from the kernel's `<kern/cs_blobs.h>` (not in the SDK's user headers). The same values appear in
// the signature's flags (`kSecCodeInfoFlags`) and the process's live status (`kSecCodeInfoStatus`).
/// The live signature is valid.
const CS_VALID: u32 = 0x0000_0001;
/// Ad-hoc signed: no certificate at all.
const CS_ADHOC: u32 = 0x0000_0002;
/// The process may be attached to by a debugger (`get-task-allow`).
const CS_GET_TASK_ALLOW: u32 = 0x0000_0004;
/// Hardened runtime.
const CS_RUNTIME: u32 = 0x0001_0000;
/// A debugger has attached, or the process was otherwise made debuggable at run time.
const CS_DEBUGGED: u32 = 0x1000_0000;

/// Longest signing identifier accepted. Bundle identifiers are limited to 255 characters by Apple.
const MAX_IDENTIFIER: usize = 255;

/// Most components a bundle version may have (`major.minor.patch`), as Apple documents `CFBundleVersion`.
const MAX_VERSION_PARTS: usize = 3;

/// Most digits in one version component, so every component fits a `u32`.
const MAX_VERSION_DIGITS: usize = 9;

/// Why a trust record's part was refused. Carries no input, so it can be shown and logged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustError {
    /// A team ID is exactly ten characters from `A-Z` and `0-9`.
    TeamId,
    /// An identifier is 1 to 255 characters from `A-Z`, `a-z`, `0-9`, `.` and `-`, not starting or ending with `.`.
    Identifier,
    /// A version is one to three dot-separated decimal numbers, each 1 to 9 digits (`2`, `1.4`, `10.0.3`).
    Version,
}

impl fmt::Display for TrustError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::TeamId => "a team ID is ten characters from A-Z and 0-9",
            Self::Identifier => "an identifier is 1 to 255 characters from A-Z, a-z, 0-9, '.' and '-'",
            Self::Version => "a version is one to three dot-separated numbers, such as 1.4.2",
        })
    }
}

impl std::error::Error for TrustError {}

/// An Apple developer team ID: ten characters from `A-Z` and `0-9`.
///
/// Invariant: only those characters, so it is safe inside a quoted string of the requirement language.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TeamId(String);

impl TeamId {
    /// Checks `text` and wraps it.
    ///
    /// # Errors
    ///
    /// [`TrustError::TeamId`] if `text` is not ten characters from `A-Z` and `0-9`.
    pub fn new(text: &str) -> Result<Self, TrustError> {
        let valid = text.len() == 10
            && text
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit());
        valid.then(|| Self(text.to_owned())).ok_or(TrustError::TeamId)
    }

    /// The team ID.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A code-signing identifier, the authority's bundle identifier (for example `com.example.authority`).
///
/// Invariant: 1 to 255 characters from `A-Z`, `a-z`, `0-9`, `.` and `-`, not starting or ending with `.`. In
/// particular no `"` or `\`, so it cannot end the quoted string it is written into and inject requirement clauses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigningIdentifier(String);

impl SigningIdentifier {
    /// Checks `text` and wraps it.
    ///
    /// # Errors
    ///
    /// [`TrustError::Identifier`] if `text` breaks the invariant.
    pub fn new(text: &str) -> Result<Self, TrustError> {
        let valid = !text.is_empty()
            && text.len() <= MAX_IDENTIFIER
            && !text.starts_with('.')
            && !text.ends_with('.')
            && text
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'.' || byte == b'-');
        valid.then(|| Self(text.to_owned())).ok_or(TrustError::Identifier)
    }

    /// The identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A `CFBundleVersion`: one to three dot-separated decimal numbers. Ordered numerically component by component, a
/// missing component counting as 0, so `1.10 > 1.9` and `2 == 2.0.0`.
///
/// Missing components are stored as 0, so the derived (lexicographic) order of the array is the version order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct BundleVersion([u32; MAX_VERSION_PARTS]);

impl BundleVersion {
    /// Parses `text`.
    ///
    /// Strict, because the peer's version comes from a signed `Info.plist` this process did not write: anything
    /// that is not exactly this grammar (signs, spaces, empty components, letters, more than three components) is
    /// refused rather than read leniently, so the peer is refused too.
    ///
    /// # Errors
    ///
    /// [`TrustError::Version`] if `text` does not match.
    pub fn parse(text: &str) -> Result<Self, TrustError> {
        let mut parts = [0_u32; MAX_VERSION_PARTS];
        for (index, part) in text.split('.').enumerate() {
            let digits_only =
                !part.is_empty() && part.len() <= MAX_VERSION_DIGITS && part.bytes().all(|b| b.is_ascii_digit());
            let slot = parts.get_mut(index).ok_or(TrustError::Version)?;
            if !digits_only {
                return Err(TrustError::Version);
            }
            // At most nine digits: always fits a `u32`.
            *slot = part.parse().map_err(|_| TrustError::Version)?;
        }
        Ok(Self(parts))
    }
}

impl fmt::Display for BundleVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [major, minor, patch] = self.0;
        write!(f, "{major}.{minor}.{patch}")
    }
}

/// The authority the user trusted with `knsh authority trust` (FR-AUTH-10): its team, its signing identifier and the
/// oldest version accepted. Stored by KNSH-068 as a Keychain item only `knshd` can read (FR-AUTH-11).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedAuthority {
    /// The Apple developer team that signs it.
    pub team_id: TeamId,
    /// Its signing identifier.
    pub identifier: SigningIdentifier,
    /// The oldest `CFBundleVersion` accepted (FR-AUTH-14).
    pub min_version: BundleVersion,
}

/// The XPC peer code-signing requirement for `trusted` (FR-AUTH-13): Apple-anchored, the trusted team and
/// identifier, a Developer ID (intermediate and leaf markers) or Mac App Store (leaf marker) certificate, and no
/// `get-task-allow` entitlement. This is the string tested in KNSH-026 (claim C7), on one line.
///
/// Pure. The parts' invariants keep every value inside its quotes, so the result is always one well-formed
/// requirement with exactly these clauses.
#[must_use]
pub fn peer_requirement(trusted: &TrustedAuthority) -> String {
    format!(
        "anchor apple generic and certificate leaf[subject.OU] = \"{team}\" and identifier \"{identifier}\" \
         and ((certificate 1[field.1.2.840.113635.100.6.2.6] exists and certificate leaf[field.1.2.840.113635.100.6.1.13] exists) \
         or certificate leaf[field.1.2.840.113635.100.6.1.9] exists) \
         and !(entitlement[\"com.apple.security.get-task-allow\"] exists)",
        team = trusted.team_id.as_str(),
        identifier = trusted.identifier.as_str(),
    )
}

/// What the code-signing service reports about the code that sent one message, read by the message's audit token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureFacts {
    /// Whether the code satisfies the [`peer_requirement`] (`SecCodeCheckValidity`). Checked again here, per
    /// message, although XPC already checked the connection: a peer that exec'd since no longer validates.
    pub requirement_met: bool,
    /// The flags in the signature itself (`kSecCodeInfoFlags`): hardened runtime, ad hoc.
    pub signature_flags: u32,
    /// The live code-signing status of the process (`kSecCodeInfoStatus`): valid, debuggable, debugged.
    pub status: u32,
    /// `CFBundleVersion` from the `Info.plist` bound into the signature, as text; `None` if there is none.
    pub bundle_version: Option<String>,
}

/// Why a control-service peer, or one of its messages, was refused. A fixed set, so it can be logged without content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerRejection {
    /// No authority is trusted: every connection is refused (FR-AUTH-12, KNSH-067).
    NoTrustedAuthority,
    /// The peer runs as another user (or root): only the user's own processes may reach the service.
    OtherUser,
    /// The sender's code could not be identified: it exited, exec'd another binary, or the Security framework failed.
    Unverifiable,
    /// The code does not satisfy the peer requirement (FR-AUTH-13).
    RequirementNotMet,
    /// The live signature is not valid any more.
    InvalidSignature,
    /// Ad-hoc signed. The requirement already excludes it; checked again so that no requirement mistake lets one in.
    AdHoc,
    /// Not built with the hardened runtime (FR-AUTH-14).
    NoHardenedRuntime,
    /// Debuggable or being debugged (FR-AUTH-13): `get-task-allow` or a debugger attached.
    Debuggable,
    /// No `CFBundleVersion` in the signature, or one that is not a valid version (FR-AUTH-14).
    NoVersion,
    /// Older than the trusted minimum version (FR-AUTH-14).
    BelowMinimumVersion,
}

impl PeerRejection {
    /// A fixed name, for the system log.
    #[must_use]
    pub const fn kind(self) -> &'static str {
        match self {
            Self::NoTrustedAuthority => "no_trusted_authority",
            Self::OtherUser => "other_user",
            Self::Unverifiable => "unverifiable",
            Self::RequirementNotMet => "requirement_not_met",
            Self::InvalidSignature => "invalid_signature",
            Self::AdHoc => "ad_hoc",
            Self::NoHardenedRuntime => "no_hardened_runtime",
            Self::Debuggable => "debuggable",
            Self::NoVersion => "no_version",
            Self::BelowMinimumVersion => "below_minimum_version",
        }
    }
}

impl fmt::Display for PeerRejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.kind())
    }
}

/// Reads the [`SignatureFacts`] of the code that sent a message of type `M`. The macOS backend
/// (`macos::SecCodeSigning`) reads them with `SecCodeCreateWithXPCMessage`, by the message's audit token; the fake
/// (`testing::FakeCodeSigning`) returns what the test scripted.
pub trait CodeSigning<M: ?Sized>: Send + Sync {
    /// The facts about the sender of `message`, checked against the requirement this service was made for.
    ///
    /// # Errors
    ///
    /// Any [`PlatformError`] if the sender's code cannot be read; the gate then refuses
    /// ([`PeerRejection::Unverifiable`]).
    fn inspect(&self, message: &M) -> Result<SignatureFacts, PlatformError>;
}

/// The decision about control-service peers, made from the trust record alone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerGate {
    trusted: Option<TrustedAuthority>,
    requirement: Option<String>,
}

impl PeerGate {
    /// A gate for `trusted`, or one that refuses everything when no authority is trusted (FR-AUTH-12).
    #[must_use]
    pub fn new(trusted: Option<TrustedAuthority>) -> Self {
        let requirement = trusted.as_ref().map(peer_requirement);
        Self { trusted, requirement }
    }

    /// The trusted authority, if any.
    #[must_use]
    pub fn trusted(&self) -> Option<&TrustedAuthority> {
        self.trusted.as_ref()
    }

    /// The peer code-signing requirement to set on every connection, or `None` when nothing is trusted (then no
    /// connection is ever resumed).
    #[must_use]
    pub fn requirement(&self) -> Option<&str> {
        self.requirement.as_deref()
    }

    /// Decides whether the sender of `message` may be served: always called before the message is read.
    ///
    /// The checks run in a fixed order and the first failure is the reason. The code-signing service is not asked
    /// at all when nothing is trusted.
    ///
    /// # Errors
    ///
    /// The [`PeerRejection`] that refuses the sender. The transport then closes the connection without reading the
    /// message.
    pub fn admit<M: ?Sized>(&self, signing: &dyn CodeSigning<M>, message: &M) -> Result<(), PeerRejection> {
        let trusted = self.trusted.as_ref().ok_or(PeerRejection::NoTrustedAuthority)?;
        let facts = signing.inspect(message).map_err(|_| PeerRejection::Unverifiable)?;
        verify(trusted, &facts)
    }
}

/// The checks of FR-AUTH-13 and FR-AUTH-14 on one sender's `facts`.
fn verify(trusted: &TrustedAuthority, facts: &SignatureFacts) -> Result<(), PeerRejection> {
    if !facts.requirement_met {
        return Err(PeerRejection::RequirementNotMet);
    }
    if facts.status & CS_VALID == 0 {
        return Err(PeerRejection::InvalidSignature);
    }
    if facts.signature_flags & CS_ADHOC != 0 {
        return Err(PeerRejection::AdHoc);
    }
    if facts.signature_flags & CS_RUNTIME == 0 {
        return Err(PeerRejection::NoHardenedRuntime);
    }
    // Both the signature and the live status: an entitlement shows in the status, and a debugger that attached
    // later only there.
    if (facts.status | facts.signature_flags) & (CS_GET_TASK_ALLOW | CS_DEBUGGED) != 0 {
        return Err(PeerRejection::Debuggable);
    }
    let version = facts
        .bundle_version
        .as_deref()
        .and_then(|text| BundleVersion::parse(text).ok())
        .ok_or(PeerRejection::NoVersion)?;
    if version < trusted.min_version {
        return Err(PeerRejection::BelowMinimumVersion);
    }
    Ok(())
}

/// Identifies one control connection for its lifetime in this process. Never reused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ConnectionId(pub u64);

/// Sends messages to one verified control peer, from any thread (event notifications, KNSH-018).
pub trait ControlPeer: Send + Sync {
    /// Sends one JSON message, with the raw bytes of the stream it names, if any.
    ///
    /// # Errors
    ///
    /// [`PlatformError::Xpc`] if the message could not be built or the connection is closed. A message sent just
    /// before the connection closes may be lost without an error, as with a socket.
    fn send(&self, json: &[u8], bytes: Option<&[u8]>) -> Result<(), PlatformError>;
}

/// What happens to a connection after one message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AfterMessage {
    /// It stays open.
    KeepOpen,
    /// It is closed (a failed handshake, malformed JSON, or a reply that could not be sent).
    Close,
}

/// Serves verified control messages: `knshd`'s JSON-RPC session. Only ever sees messages whose sender passed
/// [`PeerGate::admit`]; one connection's calls never overlap, and different connections' calls may run at once.
pub trait ControlHandler: Send + Sync {
    /// A connection's first message passed verification. `peer` sends to it until [`ControlHandler::closed`].
    fn opened(&self, connection: ConnectionId, peer: Arc<dyn ControlPeer>);

    /// One verified message's JSON payload, at most [`MAX_CONTROL_PAYLOAD`] bytes. `reply` sends the answer, at most
    /// once, as the XPC reply to this message (or as a plain message if the peer expects none). The handler sends
    /// it itself, so it can order it against the event notifications it sends through its [`ControlPeer`]: the
    /// answer to a subscribe precedes that subscription's events, as on the sockets.
    fn message(&self, connection: ConnectionId, json: &[u8], reply: &dyn ControlPeer) -> AfterMessage;

    /// The connection ended: the peer went away, the engine closed it, or a later message failed verification.
    /// Called once per opened connection, after its last [`ControlHandler::message`].
    fn closed(&self, connection: ConnectionId);

    /// A connection or message was refused, for the system log. Never carries message content.
    fn refused(&self, reason: PeerRejection);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::FakeCodeSigning;

    fn trusted() -> TrustedAuthority {
        TrustedAuthority {
            team_id: TeamId::new("ABCDE12345").unwrap(),
            identifier: SigningIdentifier::new("com.example.authority").unwrap(),
            min_version: BundleVersion::parse("1.0").unwrap(),
        }
    }

    /// What KNSH-026 observed for the accepted Developer ID client (`results/c7-26.6.2.tsv`, `accept-good`).
    fn good_facts() -> SignatureFacts {
        SignatureFacts {
            requirement_met: true,
            signature_flags: 0x1_0000,
            status: 0x2201_1311,
            bundle_version: Some("2.0".to_owned()),
        }
    }

    fn admit(facts: SignatureFacts) -> Result<(), PeerRejection> {
        PeerGate::new(Some(trusted())).admit(&FakeCodeSigning::answering(Ok(facts)), &())
    }

    // FR-AUTH-13: the tested requirement string (KNSH-026, C7), with the trust record's team and identifier.
    #[test]
    fn builds_requirement_from_trust_record() {
        assert_eq!(
            peer_requirement(&trusted()),
            "anchor apple generic and certificate leaf[subject.OU] = \"ABCDE12345\" and identifier \
             \"com.example.authority\" and ((certificate 1[field.1.2.840.113635.100.6.2.6] exists and certificate \
             leaf[field.1.2.840.113635.100.6.1.13] exists) or certificate leaf[field.1.2.840.113635.100.6.1.9] \
             exists) and !(entitlement[\"com.apple.security.get-task-allow\"] exists)"
        );
        assert_eq!(
            PeerGate::new(Some(trusted())).requirement(),
            Some(peer_requirement(&trusted()).as_str())
        );
    }

    // FR-AUTH-13: nothing that could end a quoted string or add a clause gets into the requirement.
    #[test]
    fn refuses_trust_parts_that_could_inject_requirement_clauses() {
        for bad in [
            "",
            "ABCDE1234",
            "ABCDE123456",
            "abcde12345",
            "ABCDE1234\"",
            "ABCDE 1234",
        ] {
            assert_eq!(TeamId::new(bad), Err(TrustError::TeamId), "{bad:?}");
        }
        let long = "a".repeat(256);
        for bad in [
            "",
            ".com.example",
            "com.example.",
            "com.example\" or anchor apple",
            "com\\example",
            "com example",
            "com.exämple",
            long.as_str(),
        ] {
            assert_eq!(SigningIdentifier::new(bad), Err(TrustError::Identifier), "{bad:?}");
        }
        assert!(SigningIdentifier::new(&"a".repeat(255)).is_ok());
        assert!(SigningIdentifier::new("com.example-app.Authority2").is_ok());
    }

    // FR-AUTH-14: versions compare numerically, a missing part counts as 0, and only the strict grammar parses.
    #[test]
    fn compares_bundle_versions_numerically() {
        let v = |text| BundleVersion::parse(text).unwrap();
        assert!(v("1.10") > v("1.9"));
        assert_eq!(v("2"), v("2.0.0"));
        assert!(v("0.9") < v("1.0"));
        assert!(v("10.0.3") > v("9.99.99"));
        assert_eq!(v("1.4.2").to_string(), "1.4.2");
        for bad in [
            "",
            "1.",
            ".1",
            "1..2",
            "1.2.3.4",
            "-1",
            "+1",
            "1.a",
            " 1",
            "1 ",
            "1234567890",
            "١",
        ] {
            assert_eq!(BundleVersion::parse(bad), Err(TrustError::Version), "{bad:?}");
        }
    }

    #[test]
    fn admits_a_verified_developer_id_peer() {
        assert_eq!(admit(good_facts()), Ok(()));
        // At exactly the minimum version.
        assert_eq!(
            admit(SignatureFacts {
                bundle_version: Some("1".to_owned()),
                ..good_facts()
            }),
            Ok(())
        );
    }

    // FR-AUTH-14: a peer without the hardened runtime satisfies the requirement but is refused (KNSH-026: flags 0x0).
    #[test]
    fn rejects_peer_without_hardened_runtime() {
        let facts = SignatureFacts {
            signature_flags: 0,
            status: 0x2200_0201,
            ..good_facts()
        };
        assert_eq!(admit(facts), Err(PeerRejection::NoHardenedRuntime));
    }

    // FR-AUTH-14: older than the trusted minimum, missing, or not a version at all.
    #[test]
    fn rejects_peer_below_min_version() {
        let with = |version: Option<&str>| SignatureFacts {
            bundle_version: version.map(str::to_owned),
            ..good_facts()
        };
        assert_eq!(admit(with(Some("0.9"))), Err(PeerRejection::BelowMinimumVersion));
        assert_eq!(admit(with(Some("0.99.99"))), Err(PeerRejection::BelowMinimumVersion));
        assert_eq!(admit(with(None)), Err(PeerRejection::NoVersion));
        assert_eq!(admit(with(Some("2.0-beta"))), Err(PeerRejection::NoVersion));
    }

    // FR-AUTH-13: `get-task-allow` in the signature or the live status, or a debugger attached, refuses even when the
    // requirement check (which excludes the entitlement) somehow passed.
    #[test]
    fn rejects_peer_with_debug_entitlement() {
        let observed = SignatureFacts {
            requirement_met: false,
            status: 0x2201_1315,
            ..good_facts()
        };
        assert_eq!(admit(observed), Err(PeerRejection::RequirementNotMet));
        for (flags, status) in [
            (0x1_0000, 0x2201_1315),
            (0x1_0000 | CS_GET_TASK_ALLOW, 0x2201_1311),
            (0x1_0000, 0x2201_1311 | CS_DEBUGGED),
        ] {
            let facts = SignatureFacts {
                signature_flags: flags,
                status,
                ..good_facts()
            };
            assert_eq!(admit(facts), Err(PeerRejection::Debuggable), "{flags:#x} {status:#x}");
        }
    }

    #[test]
    fn rejects_invalid_ad_hoc_and_unverifiable_peers() {
        let ad_hoc = SignatureFacts {
            signature_flags: CS_ADHOC | CS_RUNTIME,
            ..good_facts()
        };
        assert_eq!(admit(ad_hoc), Err(PeerRejection::AdHoc));
        let invalid = SignatureFacts {
            status: 0x2201_1310,
            ..good_facts()
        };
        assert_eq!(admit(invalid), Err(PeerRejection::InvalidSignature));
        // KNSH-026: after an exec the code object no longer validates (-67065): refused, never guessed.
        let gone = FakeCodeSigning::answering(Err(PlatformError::Security {
            operation: crate::Operation::CodeSigning,
            status: -67065,
        }));
        assert_eq!(
            PeerGate::new(Some(trusted())).admit(&gone, &()),
            Err(PeerRejection::Unverifiable)
        );
    }

    // FR-AUTH-12: with no trusted authority every connection is refused, without even asking for the signature.
    #[test]
    fn refuses_all_when_no_authority_trusted() {
        let gate = PeerGate::new(None);
        let signing = FakeCodeSigning::answering(Ok(good_facts()));
        assert_eq!(gate.requirement(), None);
        assert_eq!(gate.admit(&signing, &()), Err(PeerRejection::NoTrustedAuthority));
        assert_eq!(signing.calls(), 0);
    }
}
