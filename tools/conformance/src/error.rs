//! The one error type of the conformance gate.
//!
//! Every error fails the run: a corpus that cannot be read, a shell that cannot be started or a report that cannot be
//! written never counts as a pass, so the gate cannot be met by accident.

use std::fmt;
use std::path::PathBuf;

use knsh_corpus::CorpusError;

/// Why the gate could not produce a result.
#[derive(Debug)]
pub enum ConformanceError {
    /// The corpus could not be read or parsed.
    Corpus(CorpusError),
    /// A file or directory could not be read, written or prepared.
    Io {
        /// The path involved.
        path: PathBuf,
        /// The underlying error.
        source: std::io::Error,
    },
    /// A shell could not be started, or is not the shell the gate needs (for example not bash 5.2).
    Shell {
        /// The shell's path.
        path: PathBuf,
        /// What went wrong. Never holds a command line or the shell's output.
        message: String,
    },
    /// An input file (known differences, an Oils spec file) is malformed.
    Format {
        /// The file.
        path: PathBuf,
        /// The 1-based line number.
        line: usize,
        /// What is wrong.
        message: String,
    },
    /// The command line of the `knsh-conformance` binary is invalid.
    Usage(String),
}

impl ConformanceError {
    /// An [`Io`](Self::Io) error for `path`.
    pub fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        Self::Io {
            path: path.into(),
            source,
        }
    }

    /// A [`Shell`](Self::Shell) error for `path`.
    pub fn shell(path: impl Into<PathBuf>, message: impl Into<String>) -> Self {
        Self::Shell {
            path: path.into(),
            message: message.into(),
        }
    }
}

impl fmt::Display for ConformanceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Corpus(error) => write!(f, "corpus: {error}"),
            Self::Io { path, source } => write!(f, "{}: {source}", path.display()),
            Self::Shell { path, message } => write!(f, "{}: {message}", path.display()),
            Self::Format { path, line, message } => write!(f, "{}:{line}: {message}", path.display()),
            Self::Usage(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for ConformanceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Corpus(error) => Some(error),
            Self::Io { source, .. } => Some(source),
            Self::Shell { .. } | Self::Format { .. } | Self::Usage(_) => None,
        }
    }
}

impl From<CorpusError> for ConformanceError {
    fn from(error: CorpusError) -> Self {
        Self::Corpus(error)
    }
}
