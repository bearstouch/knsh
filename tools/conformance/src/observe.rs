//! What one run of a shell is observed to do, and the comparison that decides whether two runs behave the same.
//!
//! This module is the exact definition of "behaves as in bash" (`specs/07-testing/conformance.md`, "Comparison"),
//! as pure functions over [`Observation`]s:
//!
//! - **exit status:** the same [`Ending`]: the same exit status, or death by the same signal, or both past the
//!   deadline;
//! - **standard output:** the same bytes, after [`normalise`] replaced the run's own directory with `$RUN`;
//! - **standard error shape:** the same number of lines, and on each line the same speaker (the text before the
//!   first `": "`, for example `shell` in `shell: line 1: foo: command not found`): who complained, and how often,
//!   but not the wording, which differs between bash versions (`line 1:`) and between implementations;
//! - **file effects:** the same files, directories and symbolic links under the run's directory afterwards, each with
//!   the same permission bits, and the same contents (by length and hash) or link target. Timestamps, owners and
//!   inode numbers are not compared.
//!
//! Time and randomness: the reference runs every line twice, and an aspect that differs between those two runs
//! ([`Volatility`]) is not compared for that line (the output of `date`, `ps`, `$RANDOM`; a file whose contents
//! hold a time stamp). Two runs that both pass the deadline compare equal on status, and their streams and files
//! (cut off at an arbitrary point) are not compared.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

/// How a run ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Ending {
    /// It exited with this status.
    Exited(u8),
    /// It was killed by this signal.
    Signaled(i32),
    /// It was still running at the deadline and was killed.
    TimedOut,
}

impl fmt::Display for Ending {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Exited(code) => write!(f, "exit {code}"),
            Self::Signaled(signal) => write!(f, "signal {signal}"),
            Self::TimedOut => f.write_str("timeout"),
        }
    }
}

/// One entry of a [`Snapshot`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileState {
    /// A regular file: its permission bits, length and a hash of its (normalised) contents.
    File {
        /// `st_mode & 0o7777`.
        mode: u32,
        /// Length in bytes of the normalised contents.
        len: u64,
        /// FNV-1a 64 of the normalised contents: a comparison key, not a security measure.
        hash: u64,
    },
    /// A directory and its permission bits.
    Dir {
        /// `st_mode & 0o7777`.
        mode: u32,
    },
    /// A symbolic link and a hash of its (normalised) target.
    Symlink {
        /// FNV-1a 64 of the normalised target.
        target: u64,
    },
    /// Anything else (a FIFO, a socket).
    Other,
}

impl FileState {
    /// Whether two states are the same kind of entry (file, directory, link, other), whatever their contents.
    #[must_use]
    pub fn same_kind(&self, other: &Self) -> bool {
        std::mem::discriminant(self) == std::mem::discriminant(other)
    }
}

/// Every entry under a run's directory after the run, by path relative to it.
pub type Snapshot = BTreeMap<String, FileState>;

/// Everything the comparison looks at for one run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observation {
    /// How it ended.
    pub ending: Ending,
    /// Standard output, normalised, at most [`crate::run::MAX_STREAM`] bytes.
    pub stdout: Vec<u8>,
    /// Standard error, normalised, at most [`crate::run::MAX_STREAM`] bytes.
    pub stderr: Vec<u8>,
    /// The run's directory afterwards; empty when the suite does not compare files.
    pub files: Snapshot,
}

/// The aspects of a line the reference itself does not reproduce from one run to the next.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Volatility {
    /// The status differs between the two reference runs.
    pub status: bool,
    /// Standard output differs.
    pub stdout: bool,
    /// The shape of standard error differs.
    pub stderr: bool,
    /// Paths present after both runs whose state differs: only their presence and kind are compared.
    pub files: BTreeSet<String>,
    /// Paths present after one of the runs only: not compared at all.
    pub presence: BTreeSet<String>,
}

impl Volatility {
    /// Nothing is volatile: every aspect is compared.
    #[must_use]
    pub fn none() -> Self {
        Self::default()
    }

    /// What differs between two runs of the reference.
    #[must_use]
    pub fn between(first: &Observation, second: &Observation) -> Self {
        Self {
            status: first.ending != second.ending,
            stdout: first.stdout != second.stdout,
            stderr: stderr_shape(&first.stderr) != stderr_shape(&second.stderr),
            files: first
                .files
                .iter()
                .filter(|(path, state)| second.files.get(*path).is_some_and(|other| other != *state))
                .map(|(path, _)| path.clone())
                .collect(),
            presence: first
                .files
                .keys()
                .filter(|path| !second.files.contains_key(*path))
                .chain(second.files.keys().filter(|path| !first.files.contains_key(*path)))
                .cloned()
                .collect(),
        }
    }

    /// Whether any aspect is volatile.
    #[must_use]
    pub fn any(&self) -> bool {
        self.status || self.stdout || self.stderr || !self.files.is_empty() || !self.presence.is_empty()
    }
}

/// One way a candidate run differs from the reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Difference {
    /// A different [`Ending`].
    Status {
        /// The reference's.
        reference: Ending,
        /// The candidate's.
        candidate: Ending,
    },
    /// Different standard output.
    Stdout,
    /// A different standard error shape.
    StderrShape,
    /// Different file effects, at these paths.
    Files(Vec<String>),
}

impl Difference {
    /// The failure category this difference reports under: `status`, `stdout`, `stderr` or `files`.
    #[must_use]
    pub const fn category(&self) -> &'static str {
        match self {
            Self::Status { .. } => "status",
            Self::Stdout => "stdout",
            Self::StderrShape => "stderr",
            Self::Files(_) => "files",
        }
    }
}

impl fmt::Display for Difference {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Status { reference, candidate } => write!(f, "status {candidate}, bash {reference}"),
            Self::Stdout => f.write_str("stdout differs"),
            Self::StderrShape => f.write_str("stderr shape differs"),
            Self::Files(paths) => write!(f, "file effects differ ({})", paths.join(", ")),
        }
    }
}

/// Which aspects a suite compares.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Aspects {
    /// Compare the shape of standard error.
    pub stderr: bool,
    /// Compare file effects.
    pub files: bool,
}

impl Aspects {
    /// The corpus: status, standard output, standard error shape and file effects.
    pub const ALL: Self = Self {
        stderr: true,
        files: true,
    };
    /// Status and standard output only, as the Oils spec tests and the bash test suite check them.
    pub const STATUS_AND_STDOUT: Self = Self {
        stderr: false,
        files: false,
    };
}

/// Every way `candidate` differs from `reference`, leaving out what `volatile` says the reference does not
/// reproduce. Empty when the candidate behaves as the reference.
#[must_use]
pub fn compare(
    reference: &Observation,
    candidate: &Observation,
    volatile: &Volatility,
    aspects: Aspects,
) -> Vec<Difference> {
    let mut differences = Vec::new();
    if !volatile.status && reference.ending != candidate.ending {
        differences.push(Difference::Status {
            reference: reference.ending,
            candidate: candidate.ending,
        });
    }
    // A run cut off at the deadline stopped at an arbitrary point: only its status means anything.
    if reference.ending == Ending::TimedOut || candidate.ending == Ending::TimedOut {
        return differences;
    }
    if !volatile.stdout && reference.stdout != candidate.stdout {
        differences.push(Difference::Stdout);
    }
    if aspects.stderr && !volatile.stderr && stderr_shape(&reference.stderr) != stderr_shape(&candidate.stderr) {
        differences.push(Difference::StderrShape);
    }
    if aspects.files {
        let paths = differing_paths(&reference.files, &candidate.files, volatile);
        if !paths.is_empty() {
            differences.push(Difference::Files(paths));
        }
    }
    differences
}

/// The shape of standard error: one speaker per line, the text before the first `": "` (empty when there is none).
#[must_use]
pub fn stderr_shape(stderr: &[u8]) -> Vec<&[u8]> {
    if stderr.is_empty() {
        return Vec::new();
    }
    let text = stderr.strip_suffix(b"\n").unwrap_or(stderr);
    text.split(|&byte| byte == b'\n')
        .map(|line| {
            line.windows(2)
                .position(|pair| pair == b": ")
                .map_or(&line[..0], |end| &line[..end])
        })
        .collect()
}

/// The paths at which the candidate's snapshot differs from the reference's, in order. A path whose contents vary
/// between reference runs is compared by presence and kind only; one the reference creates only sometimes, not at
/// all.
fn differing_paths(reference: &Snapshot, candidate: &Snapshot, volatile: &Volatility) -> Vec<String> {
    let paths: BTreeSet<&String> = reference.keys().chain(candidate.keys()).collect();
    paths
        .into_iter()
        .filter(|path| !volatile.presence.contains(*path))
        .filter(|path| match (reference.get(*path), candidate.get(*path)) {
            (Some(a), Some(b)) if volatile.files.contains(*path) => !a.same_kind(b),
            (Some(a), Some(b)) => a != b,
            _ => true,
        })
        .cloned()
        .collect()
}

/// `bytes` with every occurrence of each of `paths` (longest first) replaced by `$RUN`, so a run's own directory,
/// different for every run, does not make two runs differ.
#[must_use]
pub fn normalise(bytes: &[u8], paths: &[&[u8]]) -> Vec<u8> {
    let mut paths: Vec<&[u8]> = paths.iter().copied().filter(|path| !path.is_empty()).collect();
    paths.sort_by_key(|path| std::cmp::Reverse(path.len()));
    let mut out = Vec::with_capacity(bytes.len());
    let mut rest = bytes;
    'outer: while !rest.is_empty() {
        for path in &paths {
            if rest.starts_with(path) {
                out.extend_from_slice(b"$RUN");
                rest = &rest[path.len()..];
                continue 'outer;
            }
        }
        out.push(rest[0]);
        rest = &rest[1..];
    }
    out
}

/// FNV-1a, 64 bits.
#[must_use]
pub fn fnv1a(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf2_9ce4_8422_2325, |hash, &byte| {
        (hash ^ u64::from(byte)).wrapping_mul(0x0100_0000_01b3)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// No difference.
    const NONE: Vec<Difference> = Vec::new();

    fn observation(ending: Ending, stdout: &str, stderr: &str) -> Observation {
        Observation {
            ending,
            stdout: stdout.as_bytes().to_vec(),
            stderr: stderr.as_bytes().to_vec(),
            files: Snapshot::new(),
        }
    }

    fn file(contents: &str) -> FileState {
        FileState::File {
            mode: 0o644,
            len: contents.len() as u64,
            hash: fnv1a(contents.as_bytes()),
        }
    }

    // KNSH-109, NFR-COMPAT-11: the same output with another exit status is a mismatch.
    #[test]
    fn corpus_comparison_detects_status_mismatch() {
        let bash = observation(Ending::Exited(1), "out\n", "");
        let knsh = observation(Ending::Exited(0), "out\n", "");
        assert_eq!(
            compare(&bash, &knsh, &Volatility::none(), Aspects::ALL),
            vec![Difference::Status {
                reference: Ending::Exited(1),
                candidate: Ending::Exited(0),
            }]
        );
        let killed = observation(Ending::Signaled(15), "out\n", "");
        assert_eq!(compare(&bash, &killed, &Volatility::none(), Aspects::ALL).len(), 1);
        assert_eq!(compare(&bash, &bash.clone(), &Volatility::none(), Aspects::ALL), NONE);
    }

    // KNSH-109, NFR-COMPAT-11: the same status with other output, stderr shape or files is a mismatch.
    #[test]
    fn corpus_comparison_detects_output_mismatch() {
        let bash = observation(Ending::Exited(0), "a\nb\n", "");
        let knsh = observation(Ending::Exited(0), "a\n", "");
        assert_eq!(
            compare(&bash, &knsh, &Volatility::none(), Aspects::ALL),
            vec![Difference::Stdout]
        );

        let bash = observation(Ending::Exited(127), "", "shell: line 1: nope: command not found\n");
        let reworded = observation(Ending::Exited(127), "", "shell: nope: command not found\n");
        assert_eq!(compare(&bash, &reworded, &Volatility::none(), Aspects::ALL), NONE);
        let other_speaker = observation(Ending::Exited(127), "", "knsh: nope: command not found\n");
        assert_eq!(
            compare(&bash, &other_speaker, &Volatility::none(), Aspects::ALL),
            vec![Difference::StderrShape]
        );
        let silent = observation(Ending::Exited(127), "", "");
        assert_eq!(
            compare(&bash, &silent, &Volatility::none(), Aspects::ALL),
            vec![Difference::StderrShape]
        );
        // Suites that compare status and stdout only ignore stderr.
        assert_eq!(
            compare(&bash, &silent, &Volatility::none(), Aspects::STATUS_AND_STDOUT),
            NONE
        );

        let mut bash = observation(Ending::Exited(0), "", "");
        bash.files.insert("work/out.txt".into(), file("a\n"));
        let mut knsh = bash.clone();
        knsh.files.insert("work/out.txt".into(), file("b\n"));
        knsh.files.insert("work/extra".into(), FileState::Dir { mode: 0o755 });
        assert_eq!(
            compare(&bash, &knsh, &Volatility::none(), Aspects::ALL),
            vec![Difference::Files(vec!["work/extra".into(), "work/out.txt".into()])]
        );
    }

    // What the reference does not reproduce is not compared; what it does is.
    #[test]
    fn volatile_aspects_are_not_compared() {
        let first = observation(Ending::Exited(0), "12:00:01\n", "");
        let second = observation(Ending::Exited(0), "12:00:02\n", "");
        let volatile = Volatility::between(&first, &second);
        assert!(volatile.stdout && !volatile.status && volatile.any());
        let knsh = observation(Ending::Exited(0), "12:00:03\n", "");
        assert_eq!(compare(&first, &knsh, &volatile, Aspects::ALL), NONE);
        let failed = observation(Ending::Exited(1), "12:00:03\n", "");
        assert_eq!(compare(&first, &failed, &volatile, Aspects::ALL).len(), 1);

        let mut first = observation(Ending::Exited(0), "", "");
        first.files.insert("work/stamp".into(), file("1"));
        let mut second = first.clone();
        second.files.insert("work/stamp".into(), file("2"));
        let volatile = Volatility::between(&first, &second);
        let mut knsh = first.clone();
        knsh.files.insert("work/stamp".into(), file("3"));
        assert_eq!(compare(&first, &knsh, &volatile, Aspects::ALL), NONE);
        knsh.files.remove("work/stamp");
        assert_eq!(compare(&first, &knsh, &volatile, Aspects::ALL).len(), 1);

        // A file the reference creates only sometimes is not compared at all.
        let mut second = first.clone();
        second.files.insert("work/sometimes".into(), file("x"));
        let volatile = Volatility::between(&first, &second);
        assert!(volatile.presence.contains("work/sometimes"));
        assert_eq!(compare(&second, &first, &volatile, Aspects::ALL), NONE);
    }

    #[test]
    fn timeouts_compare_by_status_only() {
        let bash = observation(Ending::TimedOut, "partial", "");
        let knsh = observation(Ending::TimedOut, "other partial", "x: y\n");
        assert_eq!(compare(&bash, &knsh, &Volatility::none(), Aspects::ALL), NONE);
        let finished = observation(Ending::Exited(0), "", "");
        assert_eq!(
            compare(&bash, &finished, &Volatility::none(), Aspects::ALL),
            vec![Difference::Status {
                reference: Ending::TimedOut,
                candidate: Ending::Exited(0),
            }]
        );
    }

    #[test]
    fn normalise_replaces_the_run_directory() {
        let out = normalise(
            b"/private/var/r/1/work and /var/r/1/work/x",
            &[b"/var/r/1", b"/private/var/r/1"],
        );
        assert_eq!(out, b"$RUN/work and $RUN/work/x");
        assert_eq!(normalise(b"plain", &[b""]), b"plain");
    }

    #[test]
    fn stderr_shape_keeps_speakers_and_line_count() {
        assert_eq!(stderr_shape(b""), Vec::<&[u8]>::new());
        assert_eq!(
            stderr_shape(b"ls: x: No such file\nplain line\n"),
            vec![&b"ls"[..], &b""[..]]
        );
    }
}
