//! The gate and the Markdown report of a conformance run.
//!
//! One [`SuiteReport`] per suite: how many lines, cases or drivers ran, how many behaved as in bash 5.2 (the pass
//! rate, in whole basis points, rounded down so rounding cannot pass a run that falls short), every failure with its
//! category and, when it is a known difference, where the compatibility page documents it.
//!
//! The gate ([`Report::passed`]) fails closed. On release runs ([`Gate::Enforce`], CI on a `v*` tag) it needs
//! every suite to have run, at least [`MIN_CORPUS_PERCENT`] of the corpus to behave as in bash 5.2 (NFR-COMPAT-11),
//! and every corpus line that does not to be documented. Other runs ([`Gate::ReportOnly`]) report the same numbers
//! and fail only when the corpus did not run at all.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use knsh_corpus::entry::escape;

use crate::Shell;
use crate::bash_suite::DriverResult;
use crate::corpus::{LineResult, tagged_bash32};
use crate::known::Known;
use crate::observe::Difference;
use crate::oils::CaseResult;

/// The share of corpus lines that must behave as in bash 5.2, in percent (NFR-COMPAT-11).
pub const MIN_CORPUS_PERCENT: usize = 99;

/// Whether the gate decides the result of this run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Gate {
    /// Release runs: the gate fails the run.
    Enforce,
    /// Every other run: the numbers are reported, a shortfall does not fail.
    ReportOnly,
}

/// The three suites.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Suite {
    /// The agent-command corpus.
    Corpus,
    /// The bash-compatible subset of the Oils spec tests.
    Oils,
    /// Bash's own test suite.
    BashSuite,
}

impl Suite {
    /// Every suite, in report order.
    pub const ALL: [Self; 3] = [Self::Corpus, Self::Oils, Self::BashSuite];

    /// The id used in the known-differences file and on the command line.
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::Corpus => "corpus",
            Self::Oils => "oils",
            Self::BashSuite => "bash-suite",
        }
    }

    /// The suite for `id`.
    #[must_use]
    pub fn from_id(id: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|suite| suite.id() == id)
    }

    /// The heading in the report.
    #[must_use]
    pub const fn title(self) -> &'static str {
        match self {
            Self::Corpus => "Agent-command corpus",
            Self::Oils => "Oils spec tests, bash-compatible subset",
            Self::BashSuite => "Bash test suite",
        }
    }
}

/// One line, case or driver that did not behave as in bash 5.2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Failure {
    /// Its id: the escaped corpus command, `file: case` for Oils, the driver for the bash suite.
    pub id: String,
    /// Its category: the first difference (`status`, `stdout`, `stderr`, `files`) for the corpus; the spec file for
    /// Oils; the driver for the bash suite.
    pub category: String,
    /// What differs.
    pub detail: String,
    /// Where the compatibility page documents it, when it is a known difference.
    pub documented: Option<String>,
}

/// The result of one suite.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SuiteReport {
    /// Which suite.
    pub suite: Suite,
    /// How many lines, cases or drivers ran.
    pub total: usize,
    /// Those that did not behave as in bash 5.2.
    pub failures: Vec<Failure>,
    /// Why the suite did not run, when it did not.
    pub not_run: Option<String>,
    /// Remarks for the report (for example drivers bash 5.2 itself does not run clean).
    pub notes: Vec<String>,
}

impl SuiteReport {
    /// A suite that did not run, and why.
    #[must_use]
    pub fn not_run(suite: Suite, reason: impl Into<String>) -> Self {
        Self {
            suite,
            total: 0,
            failures: Vec::new(),
            not_run: Some(reason.into()),
            notes: Vec::new(),
        }
    }

    /// How many behaved as in bash 5.2.
    #[must_use]
    pub fn passed(&self) -> usize {
        self.total.saturating_sub(self.failures.len())
    }

    /// The pass rate in basis points (hundredths of a percent), rounded down; `None` when nothing ran.
    #[must_use]
    pub fn pass_rate(&self) -> Option<usize> {
        (self.passed() * 10_000).checked_div(self.total)
    }

    /// Whether at least `percent` of a non-empty suite passed, in whole numbers.
    #[must_use]
    pub fn meets(&self, percent: usize) -> bool {
        self.not_run.is_none() && self.total > 0 && self.passed() * 100 >= self.total * percent
    }

    /// Failures per category.
    #[must_use]
    pub fn by_category(&self) -> BTreeMap<&str, usize> {
        let mut counts = BTreeMap::new();
        for failure in &self.failures {
            *counts.entry(failure.category.as_str()).or_default() += 1;
        }
        counts
    }

    /// The failures no known-differences entry documents.
    pub fn undocumented(&self) -> impl Iterator<Item = &Failure> {
        self.failures.iter().filter(|failure| failure.documented.is_none())
    }
}

/// A corpus line on which bash 3.2 does not behave as bash 5.2 (NFR-COMPAT-05).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bash32Difference {
    /// The escaped command.
    pub command: String,
    /// Whether the line is tagged `b32-missing` or `b32-differs`.
    pub tagged: bool,
    /// What differs.
    pub differences: Vec<Difference>,
}

/// Everything a conformance run found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    /// The shells, each with its role (`reference`, `candidate`, `bash 3.2`).
    pub shells: Vec<(String, Shell)>,
    /// One per suite, in [`Suite::ALL`] order.
    pub suites: Vec<SuiteReport>,
    /// The bash 3.2 vs 5.2 difference list, when bash 3.2 ran.
    pub bash32: Option<Vec<Bash32Difference>>,
    /// Known-differences entries for suites that ran whose line, case or driver now passes: fixed, to be removed.
    pub stale_known: Vec<(Suite, String)>,
}

impl Report {
    /// The report of `suite`.
    #[must_use]
    pub fn suite(&self, suite: Suite) -> Option<&SuiteReport> {
        self.suites.iter().find(|report| report.suite == suite)
    }

    /// The corpus gate: at least [`MIN_CORPUS_PERCENT`] behave as in bash 5.2 and every other line is documented.
    #[must_use]
    pub fn corpus_gate_passed(&self) -> bool {
        self.suite(Suite::Corpus)
            .is_some_and(|corpus| corpus.meets(MIN_CORPUS_PERCENT) && corpus.undocumented().next().is_none())
    }

    /// Whether the run passes under `gate`.
    #[must_use]
    pub fn passed(&self, gate: Gate) -> bool {
        match gate {
            Gate::Enforce => {
                // A suite that "ran" nothing (a checkout whose layout changed, a test directory without drivers)
                // was not measured: fail closed.
                self.corpus_gate_passed()
                    && Suite::ALL.iter().all(|suite| {
                        self.suite(*suite)
                            .is_some_and(|report| report.not_run.is_none() && report.total > 0)
                    })
            }
            Gate::ReportOnly => self
                .suite(Suite::Corpus)
                .is_some_and(|corpus| corpus.not_run.is_none() && corpus.total > 0),
        }
    }

    /// Fills in [`Report::stale_known`]: known entries of suites that ran that are no longer failures.
    pub fn find_stale(&mut self, known: &Known) {
        self.stale_known = known
            .iter()
            .filter(|(suite, id, _)| {
                self.suite(*suite).is_some_and(|report| {
                    report.not_run.is_none() && !report.failures.iter().any(|failure| failure.id == *id)
                })
            })
            .map(|(suite, id, _)| (suite, id.to_owned()))
            .collect();
    }
}

fn detail(differences: &[Difference]) -> String {
    differences
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("; ")
}

/// The corpus suite's report and the bash 3.2 vs 5.2 difference list (when bash 3.2 ran).
#[must_use]
pub fn corpus_report(results: &[LineResult], known: &Known) -> (SuiteReport, Option<Vec<Bash32Difference>>) {
    let mut failures = Vec::new();
    let mut bash32 = Vec::new();
    let mut ran_bash32 = false;
    let mut volatile = 0;
    for result in results {
        let id = escape(&result.line.entry.command);
        volatile += usize::from(result.volatile.any());
        if let Some(first) = result.knsh.first() {
            failures.push(Failure {
                category: first.category().to_owned(),
                detail: detail(&result.knsh),
                documented: known.documented(Suite::Corpus, &id).map(str::to_owned),
                id: id.clone(),
            });
        }
        if let Some(differences) = &result.bash32 {
            ran_bash32 = true;
            if !differences.is_empty() {
                bash32.push(Bash32Difference {
                    command: id,
                    tagged: tagged_bash32(&result.line),
                    differences: differences.clone(),
                });
            }
        }
    }
    let report = SuiteReport {
        suite: Suite::Corpus,
        total: results.len(),
        failures,
        not_run: None,
        notes: vec![format!(
            "{volatile} line(s) have an aspect bash 5.2 does not reproduce between two runs; it is not compared."
        )],
    };
    (report, ran_bash32.then_some(bash32))
}

/// The Oils subset's report.
#[must_use]
pub fn oils_report(results: &[CaseResult], known: &Known) -> SuiteReport {
    let failures = results
        .iter()
        .filter(|result| !result.differences.is_empty())
        .map(|result| {
            let id = format!("{}: {}", result.case.file, result.case.name);
            Failure {
                category: result.case.file.clone(),
                detail: detail(&result.differences),
                documented: known.documented(Suite::Oils, &id).map(str::to_owned),
                id,
            }
        })
        .collect();
    SuiteReport {
        suite: Suite::Oils,
        total: results.len(),
        failures,
        not_run: None,
        notes: Vec::new(),
    }
}

/// The bash test suite's report.
#[must_use]
pub fn bash_suite_report(results: &[DriverResult], known: &Known) -> SuiteReport {
    let failures = results
        .iter()
        .filter(|result| !result.differences.is_empty())
        .map(|result| Failure {
            id: result.driver.clone(),
            category: result.driver.trim_start_matches("run-").to_owned(),
            detail: detail(&result.differences),
            documented: known.documented(Suite::BashSuite, &result.driver).map(str::to_owned),
        })
        .collect();
    let unclean: Vec<&str> = results
        .iter()
        .filter(|result| !result.reference_clean)
        .map(|result| result.driver.as_str())
        .collect();
    let notes = if unclean.is_empty() {
        Vec::new()
    } else {
        vec![format!(
            "Not clean for bash 5.2 itself on this host (compared with bash 5.2's output, not the `.right` files): {}.",
            unclean.join(", ")
        )]
    };
    SuiteReport {
        suite: Suite::BashSuite,
        total: results.len(),
        failures,
        not_run: None,
        notes,
    }
}

/// `basis_points` as a percentage with two decimals.
fn percent(basis_points: Option<usize>) -> String {
    basis_points.map_or_else(|| "n/a".to_owned(), |bp| format!("{}.{:02}%", bp / 100, bp % 100))
}

const fn pass_fail(passed: bool) -> &'static str {
    if passed { "PASS" } else { "FAIL" }
}

/// Text safe inside a Markdown table cell and on one line.
fn cell(text: &str) -> String {
    text.replace('|', "\\|").replace('\n', " ")
}

/// `text` as inline code that no backtick inside it can close.
fn code(text: &str) -> String {
    let longest = text.split(|c| c != '`').map(str::len).max().unwrap_or(0);
    let fence = "`".repeat(longest + 1);
    let pad = if text.starts_with('`') || text.ends_with('`') {
        " "
    } else {
        ""
    };
    format!("{fence}{pad}{}{pad}{fence}", text.replace('|', "\\|"))
}

/// Renders the Markdown report.
#[must_use]
pub fn render(report: &Report, gate: Gate) -> String {
    let mut out = String::new();
    // Writing to a `String` cannot fail, so the `fmt::Result`s below are ignored.
    let _ = writeln!(out, "# Native-mode conformance report (KNSH-109)\n");
    let _ = writeln!(out, "**Result: {}**\n", pass_fail(report.passed(gate)));
    let _ = writeln!(out, "## Shells\n\n| Role | Program | Version |\n| --- | --- | --- |");
    for (role, shell) in &report.shells {
        let _ = writeln!(
            out,
            "| {role} | `{}` | {} |",
            shell.program.display(),
            cell(&shell.version)
        );
    }

    let _ = writeln!(
        out,
        "\n## Pass rates\n\n| Suite | Ran | Passed | Failed | Documented | Pass rate |\n| --- | --- | --- | --- | --- | --- |"
    );
    for suite in &report.suites {
        if let Some(reason) = &suite.not_run {
            let _ = writeln!(out, "| {} | not run: {} | | | | |", suite.suite.title(), cell(reason));
            continue;
        }
        let documented = suite.failures.len() - suite.undocumented().count();
        let _ = writeln!(
            out,
            "| {} | {} | {} | {} | {documented} | {} |",
            suite.suite.title(),
            suite.total,
            suite.passed(),
            suite.failures.len(),
            percent(suite.pass_rate())
        );
    }
    let enforcement = match gate {
        Gate::Enforce => "enforced",
        Gate::ReportOnly => "reported only; enforced on release runs",
    };
    let undocumented = report
        .suite(Suite::Corpus)
        .map_or(0, |corpus| corpus.undocumented().count());
    let _ = writeln!(
        out,
        "\nGate, at least {MIN_CORPUS_PERCENT}% of the corpus behaves as in bash 5.2 and every corpus difference is \
         documented ({enforcement}): **{}** ({} undocumented)",
        pass_fail(report.corpus_gate_passed()),
        undocumented
    );

    for suite in &report.suites {
        render_suite(&mut out, suite);
    }
    render_bash32(&mut out, report.bash32.as_deref());
    if !report.stale_known.is_empty() {
        let _ = writeln!(
            out,
            "\n## Known differences that now pass\n\nRemove them from the list:\n"
        );
        for (suite, id) in &report.stale_known {
            let _ = writeln!(out, "- {}: {}", suite.id(), code(id));
        }
    }
    out
}

/// One suite's section: its notes, failures by category and every failure (nothing for a suite that did not run).
fn render_suite(out: &mut String, suite: &SuiteReport) {
    if suite.not_run.is_some() {
        return;
    }
    let _ = writeln!(out, "\n## {}\n", suite.suite.title());
    for note in &suite.notes {
        let _ = writeln!(out, "{note}\n");
    }
    if suite.failures.is_empty() {
        let _ = writeln!(out, "No failures.");
        return;
    }
    let _ = writeln!(
        out,
        "### Failures by category\n\n| Category | Failures |\n| --- | --- |"
    );
    for (category, count) in suite.by_category() {
        let _ = writeln!(out, "| {} | {count} |", cell(category));
    }
    let _ = writeln!(
        out,
        "\n### Failures\n\n| Id | Difference | Known (documented at) |\n| --- | --- | --- |"
    );
    for failure in &suite.failures {
        let documented = failure
            .documented
            .as_deref()
            .map_or_else(|| "**no**".to_owned(), |doc| format!("`{doc}`"));
        let _ = writeln!(
            out,
            "| {} | {} | {documented} |",
            code(&failure.id),
            cell(&failure.detail)
        );
    }
}

/// The bash 3.2 vs 5.2 difference list (NFR-COMPAT-05).
fn render_bash32(out: &mut String, bash32: Option<&[Bash32Difference]>) {
    let _ = writeln!(out, "\n## Bash 3.2 vs 5.2 differences (NFR-COMPAT-05)\n");
    match bash32 {
        None => {
            let _ = writeln!(out, "Bash 3.2 did not run.");
        }
        Some([]) => {
            let _ = writeln!(out, "No corpus line behaves differently under bash 3.2.");
        }
        Some(list) => {
            let untagged = list.iter().filter(|difference| !difference.tagged).count();
            let _ = writeln!(
                out,
                "{} corpus line(s) behave differently under `/bin/bash` (3.2); {untagged} of them not tagged \
                 `b32-missing` or `b32-differs`.\n\n| Command | Tagged | Difference |\n| --- | --- | --- |",
                list.len()
            );
            for difference in list {
                let _ = writeln!(
                    out,
                    "| {} | {} | {} |",
                    code(&difference.command),
                    if difference.tagged { "yes" } else { "no" },
                    cell(&detail(&difference.differences))
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::observe::Ending;

    fn failure(id: &str, category: &str, documented: bool) -> Failure {
        Failure {
            id: id.to_owned(),
            category: category.to_owned(),
            detail: "stdout differs".to_owned(),
            documented: documented.then(|| "compatibility.md#x".to_owned()),
        }
    }

    fn suite(suite: Suite, total: usize, failures: Vec<Failure>) -> SuiteReport {
        SuiteReport {
            suite,
            total,
            failures,
            not_run: None,
            notes: Vec::new(),
        }
    }

    fn report(suites: Vec<SuiteReport>) -> Report {
        Report {
            shells: vec![(
                "reference".to_owned(),
                Shell {
                    program: PathBuf::from("/opt/bash-5.2/bin/bash"),
                    version: "GNU bash, version 5.2.37(1)-release".to_owned(),
                },
            )],
            suites,
            bash32: None,
            stale_known: Vec::new(),
        }
    }

    // KNSH-109: each suite's pass rate is computed on its own, rounded down, and shown in the report.
    #[test]
    fn report_computes_pass_rate_per_suite() {
        let corpus = suite(
            Suite::Corpus,
            200,
            vec![failure("a", "stdout", true), failure("b", "status", true)],
        );
        let oils = suite(
            Suite::Oils,
            3,
            vec![failure("arith: x", "arith", false), failure("arith: y", "arith", false)],
        );
        let bash = suite(Suite::BashSuite, 0, Vec::new());
        assert_eq!(corpus.pass_rate(), Some(9_900));
        assert_eq!(oils.pass_rate(), Some(3_333));
        assert_eq!(bash.pass_rate(), None);
        assert_eq!(oils.by_category(), BTreeMap::from([("arith", 2)]));
        let report = report(vec![
            corpus,
            oils,
            SuiteReport::not_run(Suite::BashSuite, "no bash source"),
        ]);
        let text = render(&report, Gate::ReportOnly);
        assert!(
            text.contains("| Agent-command corpus | 200 | 198 | 2 | 2 | 99.00% |"),
            "{text}"
        );
        assert!(
            text.contains("| Oils spec tests, bash-compatible subset | 3 | 1 | 2 | 0 | 33.33% |"),
            "{text}"
        );
        assert!(text.contains("| Bash test suite | not run: no bash source |"), "{text}");
        assert!(text.contains("| arith | 2 |"), "{text}");
        assert!(report.corpus_gate_passed());
        assert!(report.passed(Gate::ReportOnly));
        // A release run needs every suite.
        assert!(!report.passed(Gate::Enforce));
    }

    // NFR-COMPAT-11: 98.99% fails; so does an undocumented difference, or an empty or missing corpus.
    #[test]
    fn corpus_gate_fails_closed() {
        let failures = |n: usize| (0..n).map(|i| failure(&i.to_string(), "stdout", true)).collect();
        let short = report(vec![suite(Suite::Corpus, 10_000, failures(101))]);
        assert!(!short.corpus_gate_passed());
        let undocumented = report(vec![suite(Suite::Corpus, 10_000, vec![failure("x", "status", false)])]);
        assert!(!undocumented.corpus_gate_passed());
        let empty = report(vec![suite(Suite::Corpus, 0, Vec::new())]);
        assert!(!empty.corpus_gate_passed() && !empty.passed(Gate::ReportOnly));
        assert!(!report(Vec::new()).passed(Gate::ReportOnly));
        let full = report(vec![
            suite(Suite::Corpus, 100, failures(1)),
            suite(Suite::Oils, 10, vec![failure("o", "arith", false)]),
            suite(Suite::BashSuite, 5, Vec::new()),
        ]);
        assert!(full.passed(Gate::Enforce));
        // A release run with a suite that found nothing to run is not measured.
        let hollow = report(vec![
            suite(Suite::Corpus, 100, failures(1)),
            suite(Suite::Oils, 0, Vec::new()),
            suite(Suite::BashSuite, 5, Vec::new()),
        ]);
        assert!(!hollow.passed(Gate::Enforce));
    }

    #[test]
    fn lists_bash32_differences_and_stale_entries() {
        let mut report = report(vec![suite(Suite::Corpus, 1, Vec::new())]);
        report.bash32 = Some(vec![Bash32Difference {
            command: "echo ${x,,}".to_owned(),
            tagged: true,
            differences: vec![Difference::Status {
                reference: Ending::Exited(0),
                candidate: Ending::Exited(1),
            }],
        }]);
        let known = crate::known::parse(
            "# knsh-conformance known-differences 1\ncorpus\tfixed line\tcompatibility.md#x\noils\tnot run\tcompatibility.md#x\n",
            std::path::Path::new("k"),
            &["x".to_owned()],
        )
        .unwrap();
        report.find_stale(&known);
        assert_eq!(report.stale_known, vec![(Suite::Corpus, "fixed line".to_owned())]);
        let text = render(&report, Gate::ReportOnly);
        assert!(
            text.contains("| `echo ${x,,}` | yes | status exit 1, bash exit 0 |"),
            "{text}"
        );
        assert!(text.contains("- corpus: `fixed line`"), "{text}");
    }
}
