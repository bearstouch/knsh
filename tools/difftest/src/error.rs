//! The one error type of the harness.
//!
//! Every error fails the run: a corpus that cannot be read or a shell that cannot give a verdict never counts as a
//! pass, so the exit criterion cannot be met by accident.

use std::fmt;
use std::path::PathBuf;

use knsh_corpus::CorpusError;

/// Why the harness could not produce a result.
#[derive(Debug)]
pub enum DiffError {
    /// The corpus could not be read or parsed.
    Corpus(CorpusError),
    /// A shell could not be started, timed out, or ended in a way that is neither accept nor reject.
    Oracle {
        /// The shell's path.
        path: PathBuf,
        /// What went wrong. Never holds the command line or the shell's output.
        message: String,
    },
    /// Writing the report failed.
    Io {
        /// The file involved.
        path: PathBuf,
        /// The underlying error.
        source: std::io::Error,
    },
    /// The command line of the `knsh-difftest` binary is invalid.
    Usage(String),
}

impl fmt::Display for DiffError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Corpus(error) => write!(f, "corpus: {error}"),
            Self::Oracle { path, message } => write!(f, "{}: {message}", path.display()),
            Self::Io { path, source } => write!(f, "{}: {source}", path.display()),
            Self::Usage(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for DiffError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Corpus(error) => Some(error),
            Self::Io { source, .. } => Some(source),
            Self::Oracle { .. } | Self::Usage(_) => None,
        }
    }
}

impl From<CorpusError> for DiffError {
    fn from(error: CorpusError) -> Self {
        Self::Corpus(error)
    }
}
