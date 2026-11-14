//! The differential run: our verdict for each corpus line next to each oracle's.
//!
//! Our verdict comes from [`parse_line`]. A line is *accepted* when the parser read all of it, whether it is
//! [`Exact`](ParseOutcome::Exact) or dynamic in parts (`eval`, an expanded command name, …), because reading it
//! whole means our grammar accepts it. It is *rejected* when the whole line is dynamic for a
//! [`SyntaxError`](DynamicReason::SyntaxError). Any other whole-line reason (a limit, a construct refused before it
//! could be delimited, a reading bash versions disagree on) gives *no verdict*: the parser did not decide whether
//! the syntax is valid, and the line is already dynamic, so it is never `Exact`.
//!
//! Comparing the two (see [`compare`]):
//!
//! | Ours | Bash | Result |
//! | --- | --- | --- |
//! | `Exact` | rejects | [`Mismatch::ExactRejected`]: the story's named failure |
//! | dynamic in parts | rejects | [`Mismatch::ParsedRejected`]: our grammar is too lenient |
//! | syntax error | accepts | [`Mismatch::RejectedAccepted`]: we refuse valid bash |
//! | same verdict | | [`Comparison::Agree`] |
//! | not read | either | [`Comparison::NoVerdict`] |
//!
//! One difference is expected rather than a mismatch: bash 3.2 rejecting a line tagged `b32-missing`, which uses a
//! construct only bash 4+ has (NFR-COMPAT-05). That line is still compared with every newer bash.

use std::path::Path;

use knsh_bash::{DynamicReason, ParseOutcome, parse_line};
use knsh_corpus::CorpusError;
use knsh_corpus::check::{MAX_FILE_LEN, corpus_files, read_bounded};
use knsh_corpus::entry::{Entry, Tag, parse_file};

use crate::DiffError;
use crate::oracle::{Oracle, OracleInfo};

/// One corpus line to compare.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Line {
    /// The corpus file it comes from (its file name).
    pub file: String,
    /// Its 1-based line number in that file.
    pub line: usize,
    /// The entry: command and tags.
    pub entry: Entry,
}

/// Our verdict for a line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ours {
    /// Read whole, with no dynamic part.
    Exact,
    /// Read whole, with at least one dynamic part; the reasons in source order.
    DynamicParts(Vec<DynamicReason>),
    /// Not read; dynamic as a whole for this reason.
    WholeLine(DynamicReason),
}

impl Ours {
    /// Our verdict from the parser's outcome.
    #[must_use]
    pub fn of(outcome: &ParseOutcome) -> Self {
        match outcome {
            ParseOutcome::Exact(_) => Self::Exact,
            ParseOutcome::Dynamic(dynamic) => {
                let mut reasons = dynamic.parts().iter().map(|part| part.reason);
                if dynamic.is_whole_line() {
                    // A whole-line outcome has exactly one part (its cause); `SyntaxError` is the safe default if that
                    // invariant ever broke, since it can only add mismatches, never hide one.
                    Self::WholeLine(reasons.next().unwrap_or(DynamicReason::SyntaxError))
                } else {
                    Self::DynamicParts(reasons.collect())
                }
            }
        }
    }

    /// Whether we accept the line as valid bash: `Some(true)` when the parser read it whole, `Some(false)` for a
    /// syntax error, `None` when it was not read for another reason (see the module docs).
    #[must_use]
    pub const fn accepts(&self) -> Option<bool> {
        match self {
            Self::Exact | Self::DynamicParts(_) => Some(true),
            Self::WholeLine(DynamicReason::SyntaxError) => Some(false),
            Self::WholeLine(_) => None,
        }
    }

    /// Whether the line parsed `Exact`.
    #[must_use]
    pub const fn is_exact(&self) -> bool {
        matches!(self, Self::Exact)
    }

    /// The dynamic reasons, in source order; empty for `Exact`.
    #[must_use]
    pub fn reasons(&self) -> &[DynamicReason] {
        match self {
            Self::Exact => &[],
            Self::DynamicParts(reasons) => reasons,
            Self::WholeLine(reason) => std::slice::from_ref(reason),
        }
    }
}

/// A disagreement between our verdict and a bash's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mismatch {
    /// We parse the line `Exact`; bash rejects it.
    ExactRejected,
    /// We read the line whole (with dynamic parts); bash rejects it.
    ParsedRejected,
    /// We reject the line as a syntax error; bash accepts it.
    RejectedAccepted,
}

impl Mismatch {
    /// A stable name for the report.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::ExactRejected => "exact_but_shell_rejects",
            Self::ParsedRejected => "parsed_but_shell_rejects",
            Self::RejectedAccepted => "rejected_but_shell_accepts",
        }
    }
}

/// The result of comparing our verdict with one oracle's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Comparison {
    /// Same verdict.
    Agree,
    /// Different verdicts.
    Mismatch(Mismatch),
    /// Bash 3.2 rejects a line tagged `b32-missing` that we accept: an expected version difference (NFR-COMPAT-05).
    ExpectedBash32Missing,
    /// We did not read the line, so we gave no verdict to compare.
    NoVerdict,
}

/// One oracle's verdict on a line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Verdict {
    /// Whether the oracle accepts the line.
    pub accepted: bool,
    /// How that compares with ours.
    pub comparison: Comparison,
}

/// Every verdict for one line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LineResult {
    /// The line.
    pub line: Line,
    /// Our verdict.
    pub ours: Ours,
    /// One verdict per oracle, in the order of [`Run::oracles`].
    pub verdicts: Vec<Verdict>,
}

/// A whole differential run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Run {
    /// The oracles, in the order their verdicts appear in each [`LineResult`].
    pub oracles: Vec<OracleInfo>,
    /// One result per corpus line, in corpus order.
    pub results: Vec<LineResult>,
}

/// Compares our verdict on `line` with an oracle's.
#[must_use]
pub fn compare(ours: &Ours, oracle_accepts: bool, oracle: &OracleInfo, line: &Line) -> Comparison {
    let Some(we_accept) = ours.accepts() else {
        return Comparison::NoVerdict;
    };
    match (we_accept, oracle_accepts) {
        (true, true) | (false, false) => Comparison::Agree,
        // Bash 3.2 lacks the bash 4+ construct the line is tagged with: its reject is expected, and the newer bash
        // (when present) is the one that checks our verdict.
        (true, false) if oracle.is_bash3() && line.entry.has(Tag::B32Missing) => Comparison::ExpectedBash32Missing,
        (true, false) if ours.is_exact() => Comparison::Mismatch(Mismatch::ExactRejected),
        (true, false) => Comparison::Mismatch(Mismatch::ParsedRejected),
        (false, true) => Comparison::Mismatch(Mismatch::RejectedAccepted),
    }
}

/// Parses every line with [`parse_line`] and asks every oracle for its verdict.
///
/// # Errors
///
/// The first oracle that could give no verdict. A run is never partly compared.
pub fn run(lines: Vec<Line>, oracles: &[&dyn Oracle]) -> Result<Run, DiffError> {
    let mut results = Vec::with_capacity(lines.len());
    for line in lines {
        let ours = Ours::of(&parse_line(&line.entry.command));
        let mut verdicts = Vec::with_capacity(oracles.len());
        for oracle in oracles {
            let accepted = oracle.accepts(&line.entry.command)?;
            let comparison = compare(&ours, accepted, oracle.info(), &line);
            verdicts.push(Verdict { accepted, comparison });
        }
        results.push(LineResult { line, ours, verdicts });
    }
    Ok(Run {
        oracles: oracles.iter().map(|oracle| oracle.info().clone()).collect(),
        results,
    })
}

/// Reads every corpus file in `dir` (`*.txt`, sorted) into lines, in file order.
///
/// Only the format is checked here; provenance and normalisation are the corpus gate's job (`knsh-corpus check`).
///
/// # Errors
///
/// [`DiffError::Corpus`] when the directory or a file cannot be read, or a line is malformed.
pub fn load_corpus(dir: &Path) -> Result<Vec<Line>, DiffError> {
    let mut lines = Vec::new();
    for path in corpus_files(dir)? {
        let text = read_bounded(&path, MAX_FILE_LEN)?;
        let entries = parse_file(&text).map_err(|(line, error)| CorpusError::At {
            path: path.clone(),
            line,
            error,
        })?;
        let file = path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();
        lines.extend(entries.into_iter().map(|(line, entry)| Line {
            file: file.clone(),
            line,
            entry,
        }));
    }
    Ok(lines)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{FakeOracle, bash3, bash5, line};

    // KNSH-034: a synthetic mismatch (we parse `Exact`, bash rejects) is flagged and named.
    #[test]
    fn harness_flags_line_we_accept_and_bash_rejects() {
        let rejects_all = FakeOracle::new(bash5(), |_| false);
        let run = run(vec![line("ls -la")], &[&rejects_all]).unwrap();
        let result = &run.results[0];
        assert_eq!(result.ours, Ours::Exact);
        assert_eq!(
            result.verdicts[0].comparison,
            Comparison::Mismatch(Mismatch::ExactRejected)
        );
    }

    // KNSH-034: dynamic lines (in parts or whole) are never counted as exact.
    #[test]
    fn harness_counts_dynamic_lines_as_not_exact() {
        let accepts_all = FakeOracle::new(bash5(), |_| true);
        let run = run(
            vec![
                line("ls"),
                line("eval \"$cmd\""),
                line("$tool --version"),
                line("coproc cat"),
            ],
            &[&accepts_all],
        )
        .unwrap();
        let exact: Vec<bool> = run.results.iter().map(|r| r.ours.is_exact()).collect();
        assert_eq!(exact, [true, false, false, false]);
        assert_eq!(crate::Summary::of(&run).exact, 1);
        assert_eq!(run.results[1].ours, Ours::DynamicParts(vec![DynamicReason::Eval]));
        assert_eq!(run.results[3].ours, Ours::WholeLine(DynamicReason::Coproc));
        // `coproc` was not read: no verdict to compare, whatever bash says.
        assert_eq!(run.results[3].verdicts[0].comparison, Comparison::NoVerdict);
    }

    #[test]
    fn parsed_dynamic_line_rejected_by_bash_is_a_mismatch() {
        let rejects_all = FakeOracle::new(bash5(), |_| false);
        let run = run(vec![line("eval x")], &[&rejects_all]).unwrap();
        assert_eq!(
            run.results[0].verdicts[0].comparison,
            Comparison::Mismatch(Mismatch::ParsedRejected)
        );
    }

    #[test]
    fn syntax_error_bash_accepts_is_a_mismatch() {
        let accepts_all = FakeOracle::new(bash5(), |_| true);
        let run = run(vec![line("if true; then")], &[&accepts_all]).unwrap();
        assert_eq!(run.results[0].ours, Ours::WholeLine(DynamicReason::SyntaxError));
        assert_eq!(
            run.results[0].verdicts[0].comparison,
            Comparison::Mismatch(Mismatch::RejectedAccepted)
        );
    }

    // NFR-COMPAT-05: bash 3.2 rejecting a `b32-missing` line is expected; bash 5 still checks it, and an untagged
    // line gets no such pass.
    #[test]
    fn bash32_reject_of_b32_missing_line_is_expected_only_when_tagged() {
        let old = FakeOracle::new(bash3(), |_| false);
        let new = FakeOracle::new(bash5(), |_| false);
        let mut tagged = line("echo hi |& cat");
        tagged.entry.tags = vec![Tag::B32Missing];
        let run = run(vec![tagged, line("echo hi | cat")], &[&old, &new]).unwrap();
        assert_eq!(run.results[0].verdicts[0].comparison, Comparison::ExpectedBash32Missing);
        assert_eq!(
            run.results[0].verdicts[1].comparison,
            Comparison::Mismatch(Mismatch::ExactRejected)
        );
        assert_eq!(
            run.results[1].verdicts[0].comparison,
            Comparison::Mismatch(Mismatch::ExactRejected)
        );
    }

    #[test]
    fn oracle_failure_fails_the_run() {
        let broken = FakeOracle::failing(bash5());
        assert!(matches!(
            run(vec![line("ls")], &[&broken]),
            Err(DiffError::Oracle { .. })
        ));
    }
}
