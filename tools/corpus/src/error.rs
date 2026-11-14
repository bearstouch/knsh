//! The crate's error type: one enum for I/O, format, privacy and usage failures.

use std::fmt;
use std::path::PathBuf;

/// Why a corpus file, a source registry, a trace or a command line was rejected.
///
/// Every check fails closed: a malformed line is reported, never skipped or repaired, so a broken corpus cannot pass
/// the CI gate by accident.
#[derive(Debug)]
pub enum CorpusError {
    /// Reading or writing a file failed.
    Io {
        /// The file involved.
        path: PathBuf,
        /// The underlying error.
        source: std::io::Error,
    },
    /// A file is larger than the tool accepts (checked before it is read in full).
    FileTooLarge {
        /// The file involved.
        path: PathBuf,
        /// Its size in bytes.
        len: u64,
        /// The limit in bytes.
        limit: u64,
    },
    /// A line of a file is invalid; `line` is 1-based.
    At {
        /// The file involved.
        path: PathBuf,
        /// The 1-based line number.
        line: usize,
        /// What is wrong with it.
        error: EntryError,
    },
    /// A JSON line of an imported trace could not be parsed; `line` is 1-based.
    Json {
        /// The trace file.
        path: PathBuf,
        /// The 1-based line number.
        line: usize,
        /// The parser's error.
        source: knsh_json::JsonError,
    },
    /// An entry or source is invalid outside any file line (for example, importing into an unregistered source).
    Entry(EntryError),
    /// The command line of the `knsh-corpus` binary is invalid.
    Usage(String),
}

/// What is wrong with one corpus entry, source registry row or file header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntryError {
    /// The file does not start with the expected `# knsh-corpus …` header.
    MissingHeader,
    /// The header names a format version this tool does not read.
    UnsupportedVersion(String),
    /// The line does not have the expected number of tab-separated fields.
    FieldCount {
        /// Fields expected.
        expected: usize,
        /// Fields found.
        found: usize,
    },
    /// The source ID field is empty (KNSH-033: every entry records its source).
    MissingSource,
    /// The source ID is not lower-case ASCII letters, digits and `-`, or is too long.
    InvalidSourceId(String),
    /// The licence field is empty (KNSH-033: every entry records its licence).
    MissingLicence,
    /// The licence is not on the allow-list of licences the corpus may use.
    LicenceNotAllowed(String),
    /// The entry names a source the registry does not list.
    UnknownSource(String),
    /// The entry's licence differs from the licence the registry records for its source.
    LicenceMismatch {
        /// The source ID.
        source: String,
        /// The licence in the registry.
        registry: String,
        /// The licence on the entry.
        entry: String,
    },
    /// The entry sits in the file of another source (`<source>.txt` holds only that source's entries).
    SourceMismatch {
        /// The source the file is named after.
        file: String,
        /// The source on the entry.
        entry: String,
    },
    /// The registry lists a source twice.
    DuplicateSource(String),
    /// The command field has a backslash escape other than `\\`, `\n`, `\t` or `\r`.
    InvalidEscape,
    /// The line holds a raw control character; they must be escaped or are not allowed at all.
    ControlCharacter,
    /// The command is empty or only whitespace.
    EmptyCommand,
    /// The command is longer than the entry limit.
    TooLong {
        /// Its length in bytes.
        len: usize,
        /// The limit in bytes.
        limit: usize,
    },
    /// The tag is not one of the known tags.
    UnknownTag(String),
    /// Tags must be sorted, unique and written `-` when there are none, so a file has one spelling.
    TagsNotCanonical,
    /// The same command appears twice in one file.
    DuplicateEntry,
    /// The command changes when normalised again: it still holds a raw path, name, host, address or secret.
    NotNormalised {
        /// The command as it would be after normalisation.
        normalised: String,
    },
    /// The independent leak scan found a raw home path or token pattern.
    RawLeak(&'static str),
    /// The command uses a construct bash 3.2 lacks but is not tagged `b32-missing` (NFR-COMPAT-05).
    MissingCompatTag(&'static str),
    /// The command spans several lines but is not tagged `multiline`.
    MissingMultilineTag,
}

impl fmt::Display for CorpusError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, source } => write!(f, "{}: {source}", path.display()),
            Self::FileTooLarge { path, len, limit } => {
                write!(
                    f,
                    "{}: file is {len} bytes, above the {limit}-byte limit",
                    path.display()
                )
            }
            Self::At { path, line, error } => write!(f, "{}:{line}: {error}", path.display()),
            Self::Json { path, line, source } => write!(f, "{}:{line}: invalid JSON: {source}", path.display()),
            Self::Entry(error) => error.fmt(f),
            Self::Usage(message) => write!(f, "usage: {message}"),
        }
    }
}

impl std::error::Error for CorpusError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Json { source, .. } => Some(source),
            Self::Entry(error) => Some(error),
            Self::FileTooLarge { .. } | Self::At { .. } | Self::Usage(_) => None,
        }
    }
}

impl fmt::Display for EntryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingHeader => f.write_str("missing `# knsh-corpus` header on the first line"),
            Self::UnsupportedVersion(found) => write!(f, "unsupported format header {found:?}"),
            Self::FieldCount { expected, found } => {
                write!(f, "expected {expected} tab-separated fields, found {found}")
            }
            Self::MissingSource => f.write_str("entry has no source ID"),
            Self::InvalidSourceId(id) => write!(f, "invalid source ID {id:?} (lower-case letters, digits and '-')"),
            Self::MissingLicence => f.write_str("entry has no licence"),
            Self::LicenceNotAllowed(licence) => write!(f, "licence {licence:?} is not on the corpus allow-list"),
            Self::UnknownSource(id) => write!(f, "source {id:?} is not listed in sources.tsv"),
            Self::LicenceMismatch {
                source,
                registry,
                entry,
            } => write!(
                f,
                "licence {entry:?} differs from {registry:?} recorded for source {source:?}"
            ),
            Self::SourceMismatch { file, entry } => {
                write!(f, "entry of source {entry:?} in the file of source {file:?}")
            }
            Self::DuplicateSource(id) => write!(f, "source {id:?} is listed twice"),
            Self::InvalidEscape => f.write_str(r"invalid escape (only \\, \n, \t and \r are allowed)"),
            Self::ControlCharacter => f.write_str("raw control character"),
            Self::EmptyCommand => f.write_str("empty command"),
            Self::TooLong { len, limit } => write!(f, "command is {len} bytes, above the {limit}-byte limit"),
            Self::UnknownTag(tag) => write!(f, "unknown tag {tag:?}"),
            Self::TagsNotCanonical => f.write_str("tags must be sorted, unique and comma-separated, or '-'"),
            Self::DuplicateEntry => f.write_str("duplicate command in this file"),
            Self::NotNormalised { normalised } => {
                write!(f, "command is not normalised; normalised form: {normalised:?}")
            }
            Self::RawLeak(what) => write!(f, "raw {what} remains"),
            Self::MissingCompatTag(construct) => {
                write!(
                    f,
                    "uses {construct}, which bash 3.2 lacks, but is not tagged b32-missing"
                )
            }
            Self::MissingMultilineTag => f.write_str("command spans several lines but is not tagged multiline"),
        }
    }
}

impl std::error::Error for EntryError {}
