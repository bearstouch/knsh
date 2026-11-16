//! The trusted authority: who it is, and how its trust record is stored (KNSH-067, KNSH-068).
//!
//! The user trusts one authority app with `knsh authority trust --team-id <id> --identifier <bundle-id>
//! --min-version <v>` (FR-AUTH-10). Its three parts are checked here, once, by the types that hold them, so every
//! later use (the code-signing requirement built from them, the prompt that names them, the Keychain item that stores
//! them) can rely on their invariants:
//!
//! - [`TeamId`]: ten characters from `A-Z` and `0-9`.
//! - [`SigningIdentifier`]: 1 to 255 characters from `A-Z`, `a-z`, `0-9`, `.` and `-`.
//! - [`BundleVersion`]: one to three dot-separated decimal numbers, compared numerically.
//!
//! None of them can hold a quote, a backslash, a space or a newline, so none can end the quoted string of the
//! code-signing requirement it is written into (FR-AUTH-13) or add a line to the stored record.
//!
//! # The stored record (FR-AUTH-11)
//!
//! [`TrustedAuthority::encode`] writes the record that the Keychain item holds, and [`TrustedAuthority::decode`]
//! reads it back strictly:
//!
//! ```text
//! knsh-authority-trust v1
//! team_id ABCDE12345
//! identifier com.example.authority
//! min_version 1.4.0
//! ```
//!
//! Every line ends with one newline, in exactly this order. The version is written in its full three-part form.
//! Anything else (another header, a missing or extra line, a part that does not validate, more than
//! [`MAX_TRUST_RECORD_LEN`] bytes) is refused: a record the engine did not write is never read leniently, and with no
//! valid record no authority is trusted (fail closed).

use std::fmt;

/// Longest signing identifier accepted. Bundle identifiers are limited to 255 characters by Apple.
const MAX_IDENTIFIER: usize = 255;

/// Most components a bundle version may have (`major.minor.patch`), as Apple documents `CFBundleVersion`.
const MAX_VERSION_PARTS: usize = 3;

/// Most digits in one version component, so every component fits a `u32`.
const MAX_VERSION_DIGITS: usize = 9;

/// The first line of a stored trust record: what it is, and its format version.
const RECORD_HEADER: &str = "knsh-authority-trust v1";

/// Longest stored trust record, in bytes. A valid one is at most 352; a store checks this before copying a value.
pub const MAX_TRUST_RECORD_LEN: usize = 512;

/// Why a trust record's part, or a stored record, was refused. Carries no input, so it can be shown and logged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustError {
    /// A team ID is exactly ten characters from `A-Z` and `0-9`.
    TeamId,
    /// An identifier is 1 to 255 characters from `A-Z`, `a-z`, `0-9`, `.` and `-`, not starting or ending with `.`.
    Identifier,
    /// A version is one to three dot-separated decimal numbers, each 1 to 9 digits (`2`, `1.4`, `10.0.3`).
    Version,
    /// A stored record is not exactly the format [`TrustedAuthority::encode`] writes.
    Record,
}

impl fmt::Display for TrustError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::TeamId => "a team ID is ten characters from A-Z and 0-9",
            Self::Identifier => "an identifier is 1 to 255 characters from A-Z, a-z, 0-9, '.' and '-'",
            Self::Version => "a version is one to three dot-separated numbers, such as 1.4.2",
            Self::Record => "the stored trust record is not in the engine's format",
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

impl fmt::Display for TeamId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
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

impl fmt::Display for SigningIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
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
/// oldest version accepted. Stored as a Keychain item only `knshd` can read (FR-AUTH-11).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedAuthority {
    /// The Apple developer team that signs it.
    pub team_id: TeamId,
    /// Its signing identifier.
    pub identifier: SigningIdentifier,
    /// The oldest `CFBundleVersion` accepted (FR-AUTH-14).
    pub min_version: BundleVersion,
}

impl TrustedAuthority {
    /// `<identifier> (team <team>, version <v> or later)`: how `knshd`'s prompt and the CLI name the authority
    /// (FR-AUTH-10). Every part is validated (letters, digits, `.` and `-` only), so nothing in it needs escaping.
    #[must_use]
    pub fn describe(&self) -> String {
        format!(
            "{} (team {}, version {} or later)",
            self.identifier, self.team_id, self.min_version
        )
    }

    /// The stored form of this record (module documentation). Pure; at most [`MAX_TRUST_RECORD_LEN`] bytes.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        format!(
            "{RECORD_HEADER}\nteam_id {}\nidentifier {}\nmin_version {}\n",
            self.team_id, self.identifier, self.min_version
        )
        .into_bytes()
    }

    /// Reads a stored record strictly (module documentation).
    ///
    /// # Errors
    ///
    /// [`TrustError::Record`] for anything that is not exactly the stored form of a valid record.
    pub fn decode(bytes: &[u8]) -> Result<Self, TrustError> {
        if bytes.len() > MAX_TRUST_RECORD_LEN {
            return Err(TrustError::Record);
        }
        let text = std::str::from_utf8(bytes).map_err(|_| TrustError::Record)?;
        // Every line ends with a newline, so the text after the last one is empty.
        let body = text.strip_suffix('\n').ok_or(TrustError::Record)?;
        let mut lines = body.split('\n');
        let mut field = |name: &str| {
            lines
                .next()
                .and_then(|line| line.strip_prefix(name))
                .and_then(|rest| rest.strip_prefix(' '))
                .ok_or(TrustError::Record)
        };
        if field("knsh-authority-trust")? != "v1" {
            return Err(TrustError::Record);
        }
        let team_id = TeamId::new(field("team_id")?).map_err(|_| TrustError::Record)?;
        let identifier = SigningIdentifier::new(field("identifier")?).map_err(|_| TrustError::Record)?;
        let min_version = BundleVersion::parse(field("min_version")?).map_err(|_| TrustError::Record)?;
        if lines.next().is_some() {
            return Err(TrustError::Record);
        }
        Ok(Self {
            team_id,
            identifier,
            min_version,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn trusted() -> TrustedAuthority {
        TrustedAuthority {
            team_id: TeamId::new("ABCDE12345").unwrap(),
            identifier: SigningIdentifier::new("com.example.authority").unwrap(),
            min_version: BundleVersion::parse("1.4").unwrap(),
        }
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
            "com.example\nteam_id X",
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

    // FR-AUTH-11: the stored record round-trips, in exactly the documented form.
    #[test]
    fn stored_record_round_trips() {
        let encoded = trusted().encode();
        assert_eq!(
            String::from_utf8(encoded.clone()).unwrap(),
            "knsh-authority-trust v1\nteam_id ABCDE12345\nidentifier com.example.authority\nmin_version 1.4.0\n"
        );
        assert_eq!(TrustedAuthority::decode(&encoded), Ok(trusted()));
        assert_eq!(
            trusted().describe(),
            "com.example.authority (team ABCDE12345, version 1.4.0 or later)"
        );
        let longest = TrustedAuthority {
            identifier: SigningIdentifier::new(&"a".repeat(255)).unwrap(),
            min_version: BundleVersion::parse("999999999.999999999.999999999").unwrap(),
            ..trusted()
        };
        assert!(longest.encode().len() <= MAX_TRUST_RECORD_LEN);
        assert_eq!(TrustedAuthority::decode(&longest.encode()), Ok(longest));
    }

    // FR-AUTH-11: a record the engine did not write is never read leniently.
    #[test]
    fn refuses_malformed_stored_records() {
        let good = "knsh-authority-trust v1\nteam_id ABCDE12345\nidentifier com.example.authority\nmin_version 1.4.0\n";
        let bad = [
            String::new(),
            good.trim_end().to_owned(),
            good.replace("v1", "v2"),
            good.replace("team_id ", "team_id  "),
            good.replace("team_id", "team"),
            good.replace("ABCDE12345", "abcde12345"),
            good.replace("com.example.authority", "com.example\"authority"),
            good.replace("1.4.0", "1.4.0.1"),
            format!("{good}extra 1\n"),
            format!("{good}\n"),
            good.replace('\n', "\r\n"),
            good.replacen("team_id ABCDE12345\n", "", 1),
            "x".repeat(MAX_TRUST_RECORD_LEN + 1),
        ];
        for record in bad {
            assert_eq!(
                TrustedAuthority::decode(record.as_bytes()),
                Err(TrustError::Record),
                "{record:?}"
            );
        }
        assert_eq!(TrustedAuthority::decode(&[0xff, b'\n']), Err(TrustError::Record));
    }
}
