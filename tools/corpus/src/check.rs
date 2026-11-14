//! The corpus gate: validates every file under `tests/corpus/` and fails on any raw personal or secret value.
//!
//! Run by `cargo test` (`tools/corpus/tests/corpus_files.rs`) and by `knsh-corpus check`, so CI fails when a corpus
//! line is malformed, lacks a registered source and licence, still changes when normalised, carries a raw
//! `/Users/<name>` or token pattern, or uses a bash 4+ construct without the `b32-missing` tag (KNSH-033,
//! NFR-PRIV-08, NFR-COMPAT-05).
//!
//! Two independent checks guard privacy: the normalisation fixpoint (the line must equal `normalise(line)`) and a
//! separate leak scan written without the normaliser's passes. A bug in one pass does not open both.
//!
//! Error messages never quote the raw command, so a leaking line is not copied into CI logs; only the normalised
//! form is shown.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use crate::compat::missing_in_bash32;
use crate::entry::{Entry, Tag, parse_file};
use crate::error::{CorpusError, EntryError};
use crate::normalise::{Scrub, USER, known_token_prefix, normalise};
use crate::sources::Registry;

/// The registry's file name inside the corpus directory.
pub const SOURCES_FILE: &str = "sources.tsv";
/// The extension of corpus files.
pub const CORPUS_EXTENSION: &str = "txt";
/// Largest corpus or registry file read, checked before reading.
pub const MAX_FILE_LEN: u64 = 16 * 1024 * 1024;

/// Counts from a successful check.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Report {
    /// Corpus files checked.
    pub files: usize,
    /// Entries checked.
    pub entries: usize,
    /// Entries per source ID.
    pub by_source: BTreeMap<String, usize>,
    /// Entries per tag.
    pub by_tag: BTreeMap<Tag, usize>,
}

/// Checks one entry found in the file of source `file_source`.
///
/// # Errors
///
/// The first failed rule: unregistered source or licence mismatch, wrong file, raw leak, not normalised, or a
/// missing `b32-missing` or `multiline` tag.
pub fn check_entry(entry: &Entry, registry: &Registry, file_source: &str) -> Result<(), EntryError> {
    registry.check_entry(&entry.source, &entry.licence)?;
    if entry.source != file_source {
        return Err(EntryError::SourceMismatch {
            file: file_source.to_owned(),
            entry: entry.source.clone(),
        });
    }
    leak_scan(&entry.command)?;
    let normalised = normalise(&entry.command, &Scrub::default());
    if normalised != entry.command {
        return Err(EntryError::NotNormalised { normalised });
    }
    if let Some(construct) = missing_in_bash32(&entry.command).first()
        && !entry.has(Tag::B32Missing)
    {
        return Err(EntryError::MissingCompatTag(construct));
    }
    if entry.command.contains('\n') && !entry.has(Tag::Multiline) {
        return Err(EntryError::MissingMultilineTag);
    }
    Ok(())
}

/// Home directory names that are allowed after `/Users/` or `/home/` (the placeholder and non-personal homes).
const ALLOWED_HOMES: &[&str] = &[USER, "Shared", "Guest", "runner"];

/// The independent leak scan: a raw home path, a known token prefix with a token after it, or a private key block.
///
/// # Errors
///
/// [`EntryError::RawLeak`] naming the kind of value found (never the value itself).
pub fn leak_scan(command: &str) -> Result<(), EntryError> {
    for root in ["/Users/", "/home/"] {
        for (pos, _) in command.match_indices(root) {
            let rest = &command[pos + root.len()..];
            let name: &str = rest
                .split(|c: char| c == '/' || c.is_whitespace() || "'\"`;|&()<>:,=\\".contains(c))
                .next()
                .unwrap_or_default();
            let variable_or_glob = name.starts_with('$') || name.contains(['*', '?', '[', '{']);
            if !name.is_empty() && !variable_or_glob && !ALLOWED_HOMES.contains(&name) {
                return Err(EntryError::RawLeak("home path"));
            }
        }
    }
    let bytes = command.as_bytes();
    let is_token = |b: u8| b.is_ascii_alphanumeric() || b == b'_' || b == b'-';
    let mut i = 0;
    while i < bytes.len() {
        if !is_token(bytes[i]) {
            i += 1;
            continue;
        }
        let start = i;
        while i < bytes.len() && is_token(bytes[i]) {
            i += 1;
        }
        if known_token_prefix(&command[start..i]).is_some() {
            return Err(EntryError::RawLeak("token"));
        }
    }
    if command.contains("-----BEGIN") && command.contains("PRIVATE KEY") {
        return Err(EntryError::RawLeak("private key"));
    }
    Ok(())
}

/// Reads a file of at most `limit` bytes as UTF-8, checking the size before reading it in full.
///
/// # Errors
///
/// [`CorpusError::Io`] (including invalid UTF-8) or [`CorpusError::FileTooLarge`].
pub fn read_bounded(path: &Path, limit: u64) -> Result<String, CorpusError> {
    let io = |source| CorpusError::Io {
        path: path.to_owned(),
        source,
    };
    let file = fs::File::open(path).map_err(io)?;
    let len = file.metadata().map_err(io)?.len();
    if len > limit {
        return Err(CorpusError::FileTooLarge {
            path: path.to_owned(),
            len,
            limit,
        });
    }
    let mut text = String::new();
    // `take` also bounds a file that grows between the size check and the read.
    file.take(limit.saturating_add(1))
        .read_to_string(&mut text)
        .map_err(io)?;
    if text.len() as u64 > limit {
        return Err(CorpusError::FileTooLarge {
            path: path.to_owned(),
            len: text.len() as u64,
            limit,
        });
    }
    Ok(text)
}

/// Reads and parses the registry in `dir`.
///
/// # Errors
///
/// An I/O error or the first invalid registry line.
pub fn load_registry(dir: &Path) -> Result<Registry, CorpusError> {
    let path = dir.join(SOURCES_FILE);
    let text = read_bounded(&path, MAX_FILE_LEN)?;
    Registry::parse(&text).map_err(|(line, error)| CorpusError::At { path, line, error })
}

/// The corpus files in `dir` (`*.txt`), sorted by name.
///
/// # Errors
///
/// [`CorpusError::Io`] if the directory cannot be listed.
pub fn corpus_files(dir: &Path) -> Result<Vec<PathBuf>, CorpusError> {
    let io = |source| CorpusError::Io {
        path: dir.to_owned(),
        source,
    };
    let mut files = Vec::new();
    for item in fs::read_dir(dir).map_err(io)? {
        let path = item.map_err(io)?.path();
        if path.is_file() && path.extension().is_some_and(|e| e == CORPUS_EXTENSION) {
            files.push(path);
        }
    }
    files.sort();
    Ok(files)
}

/// The source a corpus file belongs to: its file stem.
fn file_source(path: &Path) -> String {
    path.file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// Checks the whole corpus directory: the registry, then every corpus file and entry.
///
/// Every error is collected rather than stopping at the first, so one run lists everything to fix.
///
/// # Errors
///
/// Every error found, each with its file and line.
pub fn check_dir(dir: &Path) -> Result<Report, Vec<CorpusError>> {
    let registry = load_registry(dir).map_err(|e| vec![e])?;
    let mut errors = Vec::new();
    let mut report = Report::default();
    for path in corpus_files(dir).map_err(|e| vec![e])? {
        let source = file_source(&path);
        if registry.get(&source).is_none() {
            errors.push(CorpusError::At {
                path: path.clone(),
                line: 1,
                error: EntryError::UnknownSource(source),
            });
            continue;
        }
        let text = match read_bounded(&path, MAX_FILE_LEN) {
            Ok(text) => text,
            Err(e) => {
                errors.push(e);
                continue;
            }
        };
        let entries = match parse_file(&text) {
            Ok(entries) => entries,
            Err((line, error)) => {
                errors.push(CorpusError::At { path, line, error });
                continue;
            }
        };
        report.files += 1;
        let mut seen = BTreeSet::new();
        for (line, entry) in entries {
            let result = if seen.insert(entry.command.clone()) {
                check_entry(&entry, &registry, &source)
            } else {
                Err(EntryError::DuplicateEntry)
            };
            if let Err(error) = result {
                errors.push(CorpusError::At {
                    path: path.clone(),
                    line,
                    error,
                });
                continue;
            }
            report.entries += 1;
            *report.by_source.entry(entry.source.clone()).or_default() += 1;
            for tag in &entry.tags {
                *report.by_tag.entry(*tag).or_default() += 1;
            }
        }
    }
    if errors.is_empty() { Ok(report) } else { Err(errors) }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn registry() -> Registry {
        Registry::parse("# knsh-corpus sources 1\nseed\tMIT\tx\n").unwrap()
    }

    fn entry(tags: Vec<Tag>, command: &str) -> Entry {
        Entry::new("seed", "MIT", tags, command.into()).unwrap()
    }

    // KNSH-033: the gate fails if a raw `/Users/<name>` or token pattern remains.
    #[test]
    fn leak_scan_finds_raw_home_paths_and_tokens() {
        assert_eq!(leak_scan("cd /Users/alice"), Err(EntryError::RawLeak("home path")));
        assert_eq!(leak_scan("cat /home/bob/x"), Err(EntryError::RawLeak("home path")));
        assert_eq!(
            leak_scan("gh auth login ghp_A1b2C3d4E5f6G7h8I9j0K1l2"),
            Err(EntryError::RawLeak("token"))
        );
        assert_eq!(
            leak_scan("echo '-----BEGIN OPENSSH PRIVATE KEY-----'"),
            Err(EntryError::RawLeak("private key"))
        );
        for ok in [
            "cd /Users/__USER__/x",
            "ls /Users/Shared /home/$USER",
            "echo __SECRET__",
            "pip install sk-video",
        ] {
            assert_eq!(leak_scan(ok), Ok(()), "{ok}");
        }
    }

    #[test]
    fn check_entry_enforces_registry_normalisation_and_tags() {
        let reg = registry();
        assert_eq!(check_entry(&entry(vec![], "git status"), &reg, "seed"), Ok(()));
        assert_eq!(
            check_entry(&entry(vec![], "cd /Users/alice"), &reg, "seed"),
            Err(EntryError::RawLeak("home path"))
        );
        assert_eq!(
            check_entry(&entry(vec![], "ping 10.1.2.3"), &reg, "seed"),
            Err(EntryError::NotNormalised {
                normalised: "ping __IP__".into()
            })
        );
        assert_eq!(
            check_entry(&entry(vec![], "declare -A m"), &reg, "seed"),
            Err(EntryError::MissingCompatTag("associative arrays"))
        );
        assert_eq!(
            check_entry(&entry(vec![Tag::B32Missing], "declare -A m"), &reg, "seed"),
            Ok(())
        );
        assert_eq!(
            check_entry(&entry(vec![], "a\nb"), &reg, "seed"),
            Err(EntryError::MissingMultilineTag)
        );
        assert_eq!(
            check_entry(&entry(vec![], "ls"), &reg, "other"),
            Err(EntryError::SourceMismatch {
                file: "other".into(),
                entry: "seed".into()
            })
        );
        let unregistered = Entry::new("ghost", "MIT", vec![], "ls".into()).unwrap();
        assert_eq!(
            check_entry(&unregistered, &reg, "ghost"),
            Err(EntryError::UnknownSource("ghost".into()))
        );
        let wrong_licence = Entry::new("seed", "ISC", vec![], "ls".into()).unwrap();
        assert!(matches!(
            check_entry(&wrong_licence, &reg, "seed"),
            Err(EntryError::LicenceMismatch { .. })
        ));
    }
}
