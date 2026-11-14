//! The source registry, `tests/corpus/sources.tsv`: every source the corpus imports from, with its licence.
//!
//! KNSH-033: the corpus imports only where licences allow and records the licence of every line. The registry is the
//! list of licences; each entry repeats its source's licence, and the gate checks the two agree.
//!
//! Format (UTF-8, tab-separated, one source per line):
//!
//! ```text
//! # knsh-corpus sources 1
//! # id<TAB>licence<TAB>origin
//! knsh-seed<TAB>MIT<TAB>Hand-written by the knsh maintainers …
//! ```
//!
//! Lines starting with `#` after the header, and blank lines, are comments.

use std::collections::BTreeMap;

use crate::error::EntryError;

/// The first line of every registry file; the trailing number is the format version.
pub const SOURCES_HEADER: &str = "# knsh-corpus sources 1";

/// Licences corpus lines may carry (SPDX identifiers). All allow redistribution with the repository; the attribution
/// that `CC-BY-4.0` requires is the origin column of the registry.
pub const ALLOWED_LICENCES: &[&str] = &[
    "MIT",
    "Apache-2.0",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "ISC",
    "CC0-1.0",
    "CC-BY-4.0",
    "Unlicense",
];

/// Longest accepted source ID.
const MAX_SOURCE_ID_LEN: usize = 64;

/// One registered source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Source {
    /// The source ID, also the stem of its corpus file (`<id>.txt`).
    pub id: String,
    /// Its SPDX licence identifier, one of [`ALLOWED_LICENCES`].
    pub licence: String,
    /// Where the lines come from (URL, benchmark, agent and version) and any attribution the licence requires.
    pub origin: String,
}

/// The parsed registry, keyed by source ID.
#[derive(Debug, Clone, Default)]
pub struct Registry {
    sources: BTreeMap<String, Source>,
}

impl Registry {
    /// Parses a registry file.
    ///
    /// # Errors
    ///
    /// The 1-based line number and the reason for a missing header, a malformed row, an invalid source ID, a
    /// licence outside [`ALLOWED_LICENCES`], an empty origin or a source listed twice.
    pub fn parse(text: &str) -> Result<Self, (usize, EntryError)> {
        let mut lines = text.lines().enumerate().map(|(i, l)| (i + 1, l));
        match lines.next() {
            Some((_, SOURCES_HEADER)) => {}
            Some((n, header)) if header.starts_with("# knsh-corpus sources") => {
                return Err((n, EntryError::UnsupportedVersion(header.to_owned())));
            }
            Some((n, _)) => return Err((n, EntryError::MissingHeader)),
            None => return Err((1, EntryError::MissingHeader)),
        }
        let mut sources = BTreeMap::new();
        for (n, line) in lines {
            if line.trim().is_empty() || line.starts_with('#') {
                continue;
            }
            let fields: Vec<&str> = line.split('\t').collect();
            let [id, licence, origin] = fields[..] else {
                return Err((
                    n,
                    EntryError::FieldCount {
                        expected: 3,
                        found: fields.len(),
                    },
                ));
            };
            validate_source_id(id).map_err(|e| (n, e))?;
            validate_licence(licence).map_err(|e| (n, e))?;
            if origin.trim().is_empty() {
                return Err((n, EntryError::FieldCount { expected: 3, found: 2 }));
            }
            let source = Source {
                id: id.to_owned(),
                licence: licence.to_owned(),
                origin: origin.to_owned(),
            };
            if sources.insert(id.to_owned(), source).is_some() {
                return Err((n, EntryError::DuplicateSource(id.to_owned())));
            }
        }
        Ok(Self { sources })
    }

    /// The source registered under `id`.
    #[must_use]
    pub fn get(&self, id: &str) -> Option<&Source> {
        self.sources.get(id)
    }

    /// Every registered source, in ID order.
    pub fn iter(&self) -> impl Iterator<Item = &Source> {
        self.sources.values()
    }

    /// Checks that an entry's source is registered with the entry's licence.
    ///
    /// # Errors
    ///
    /// [`EntryError::UnknownSource`] or [`EntryError::LicenceMismatch`].
    pub fn check_entry(&self, source: &str, licence: &str) -> Result<(), EntryError> {
        let registered = self
            .get(source)
            .ok_or_else(|| EntryError::UnknownSource(source.to_owned()))?;
        if registered.licence != licence {
            return Err(EntryError::LicenceMismatch {
                source: source.to_owned(),
                registry: registered.licence.clone(),
                entry: licence.to_owned(),
            });
        }
        Ok(())
    }
}

/// Checks a source ID: non-empty, at most 64 bytes, lower-case ASCII letters, digits and `-`, starting with a letter
/// or digit. IDs name files, so nothing else is allowed.
///
/// # Errors
///
/// [`EntryError::MissingSource`] when empty, otherwise [`EntryError::InvalidSourceId`].
pub fn validate_source_id(id: &str) -> Result<(), EntryError> {
    if id.is_empty() {
        return Err(EntryError::MissingSource);
    }
    let valid = id.len() <= MAX_SOURCE_ID_LEN
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !id.starts_with('-');
    if valid {
        Ok(())
    } else {
        Err(EntryError::InvalidSourceId(id.to_owned()))
    }
}

/// Checks a licence: non-empty and on the allow-list.
///
/// # Errors
///
/// [`EntryError::MissingLicence`] when empty, otherwise [`EntryError::LicenceNotAllowed`].
pub fn validate_licence(licence: &str) -> Result<(), EntryError> {
    if licence.is_empty() {
        return Err(EntryError::MissingLicence);
    }
    if ALLOWED_LICENCES.contains(&licence) {
        Ok(())
    } else {
        Err(EntryError::LicenceNotAllowed(licence.to_owned()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_registry_rows() {
        let reg = Registry::parse("# knsh-corpus sources 1\n# comment\n\nseed\tMIT\tHand-written\n").unwrap();
        assert_eq!(reg.get("seed").unwrap().licence, "MIT");
        assert!(reg.check_entry("seed", "MIT").is_ok());
        assert_eq!(
            reg.check_entry("other", "MIT"),
            Err(EntryError::UnknownSource("other".into()))
        );
        assert!(matches!(
            reg.check_entry("seed", "ISC"),
            Err(EntryError::LicenceMismatch { .. })
        ));
    }

    #[test]
    fn rejects_bad_registries() {
        let cases = [
            ("seed\tMIT\tx\n", EntryError::MissingHeader),
            (
                "# knsh-corpus sources 2\n",
                EntryError::UnsupportedVersion("# knsh-corpus sources 2".into()),
            ),
            (
                "# knsh-corpus sources 1\nseed\tGPL-3.0\tx\n",
                EntryError::LicenceNotAllowed("GPL-3.0".into()),
            ),
            ("# knsh-corpus sources 1\nseed\t\tx\n", EntryError::MissingLicence),
            ("# knsh-corpus sources 1\n\tMIT\tx\n", EntryError::MissingSource),
            (
                "# knsh-corpus sources 1\nSeed\tMIT\tx\n",
                EntryError::InvalidSourceId("Seed".into()),
            ),
            (
                "# knsh-corpus sources 1\na\tMIT\tx\na\tMIT\ty\n",
                EntryError::DuplicateSource("a".into()),
            ),
            (
                "# knsh-corpus sources 1\na\tMIT\n",
                EntryError::FieldCount { expected: 3, found: 2 },
            ),
        ];
        for (text, expected) in cases {
            assert_eq!(Registry::parse(text).unwrap_err().1, expected, "{text:?}");
        }
    }
}
