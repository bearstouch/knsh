//! The gates and the Markdown report of a differential run.
//!
//! Two gates decide the phase 2 exit criterion (`specs/07-testing/conformance.md`):
//!
//! - **exact:** at least [`MIN_EXACT_PERCENT`] of corpus lines parse `Exact`, computed in whole numbers so rounding
//!   cannot pass a run that falls short;
//! - **verdicts:** no [`Mismatch`] with any gating bash.
//!
//! Both fail closed: an empty corpus or a run with no gating bash does not pass. The verdict gate always decides the
//! result. The exact gate is always measured and reported, and decides the result only when [`ExactGate::Enforce`]d:
//! on release runs, which the phase 2 release waits for (`specs/00-stories/README.md`, phase gates). Until the corpus
//! and parser scope reach the threshold, ordinary CI runs stay green while the report shows the shortfall.
//!
//! The report records every shell's version (the story requires the bash version used), the percentages, the dynamic
//! reasons and every mismatch with its file and line. Corpus lines are normalised and public, so mismatching lines
//! are quoted (escaped, one line each) to make the report actionable.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use knsh_bash::DynamicReason;
use knsh_corpus::entry::escape;

use crate::harness::{Comparison, Mismatch, Ours, Run};
use crate::oracle::Role;

/// The share of corpus lines that must parse `Exact`, in percent (phase 2 exit criterion, decision 6).
pub const MIN_EXACT_PERCENT: usize = 95;

/// Whether the exact gate decides the result of this run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExactGate {
    /// A shortfall fails the run (release runs, `--enforce-exact`).
    Enforce,
    /// A shortfall is reported but does not fail the run (every other CI run and `cargo test`).
    ReportOnly,
}

/// One disagreement: which line, which oracle, which way.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Finding {
    /// Index into [`Run::results`].
    pub result: usize,
    /// Index into [`Run::oracles`].
    pub oracle: usize,
    /// The kind of disagreement.
    pub mismatch: Mismatch,
}

/// Per-oracle counts of each comparison result.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct OracleCounts {
    /// Same verdict as ours.
    pub agree: usize,
    /// Different verdict.
    pub mismatch: usize,
    /// Bash 3.2 rejecting a `b32-missing` line.
    pub expected_bash32: usize,
    /// Lines we did not read.
    pub no_verdict: usize,
}

/// The counts and findings of a run, and whether it passes the gates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Summary {
    /// Corpus lines compared.
    pub total: usize,
    /// Lines parsed `Exact`.
    pub exact: usize,
    /// Lines read whole with dynamic parts.
    pub dynamic_parts: usize,
    /// Lines rejected as a syntax error.
    pub syntax_errors: usize,
    /// Lines not read for another reason (limits, refused constructs).
    pub not_read: usize,
    /// Lines per dynamic reason (a line with two reasons counts under both).
    pub by_reason: BTreeMap<String, usize>,
    /// Counts per oracle, in the order of [`Run::oracles`].
    pub per_oracle: Vec<OracleCounts>,
    /// Disagreements with a gating bash; any one fails the run.
    pub mismatches: Vec<Finding>,
    /// Disagreements with a reference shell; listed, never gating.
    pub reference_disagreements: Vec<Finding>,
    /// Whether at least one gating oracle is a bash 4 or newer, which checks the `b32-missing` lines.
    pub has_modern_bash: bool,
    /// Whether at least one oracle gates the run.
    pub has_gate_oracle: bool,
}

impl Summary {
    /// Counts and collects the findings of `run`.
    #[must_use]
    pub fn of(run: &Run) -> Self {
        let mut summary = Self {
            total: run.results.len(),
            exact: 0,
            dynamic_parts: 0,
            syntax_errors: 0,
            not_read: 0,
            by_reason: BTreeMap::new(),
            per_oracle: vec![OracleCounts::default(); run.oracles.len()],
            mismatches: Vec::new(),
            reference_disagreements: Vec::new(),
            has_modern_bash: run
                .oracles
                .iter()
                .any(|o| o.role == Role::Gate && o.major.is_some_and(|major| major >= 4)),
            has_gate_oracle: run.oracles.iter().any(|o| o.role == Role::Gate),
        };
        for (index, result) in run.results.iter().enumerate() {
            summary.count_ours(&result.ours);
            for (oracle, verdict) in result.verdicts.iter().enumerate() {
                let counts = &mut summary.per_oracle[oracle];
                match verdict.comparison {
                    Comparison::Agree => counts.agree += 1,
                    Comparison::ExpectedBash32Missing => counts.expected_bash32 += 1,
                    Comparison::NoVerdict => counts.no_verdict += 1,
                    Comparison::Mismatch(mismatch) => {
                        counts.mismatch += 1;
                        let finding = Finding {
                            result: index,
                            oracle,
                            mismatch,
                        };
                        match run.oracles[oracle].role {
                            Role::Gate => summary.mismatches.push(finding),
                            Role::Reference => summary.reference_disagreements.push(finding),
                        }
                    }
                }
            }
        }
        summary
    }

    fn count_ours(&mut self, ours: &Ours) {
        match ours {
            Ours::Exact => self.exact += 1,
            Ours::DynamicParts(_) => self.dynamic_parts += 1,
            Ours::WholeLine(DynamicReason::SyntaxError) => self.syntax_errors += 1,
            Ours::WholeLine(_) => self.not_read += 1,
        }
        // A line with the same reason twice (two `eval`s) counts once under it.
        let mut reasons: Vec<String> = ours.reasons().iter().map(ToString::to_string).collect();
        reasons.sort();
        reasons.dedup();
        for reason in reasons {
            *self.by_reason.entry(reason).or_default() += 1;
        }
    }

    /// The exact gate: a non-empty corpus with at least [`MIN_EXACT_PERCENT`] of its lines `Exact`.
    #[must_use]
    pub fn exact_gate_passed(&self) -> bool {
        self.total > 0 && self.exact * 100 >= self.total * MIN_EXACT_PERCENT
    }

    /// The verdict gate: a non-empty corpus, at least one gating bash, and no mismatch with any of them. An empty
    /// corpus compares nothing, so it fails here too and fails every run, not only release runs.
    #[must_use]
    pub fn verdict_gate_passed(&self) -> bool {
        self.total > 0 && self.has_gate_oracle && self.mismatches.is_empty()
    }

    /// Whether the run passes: the verdict gate always, and the exact gate when it is enforced.
    #[must_use]
    pub fn passed(&self, exact_gate: ExactGate) -> bool {
        let exact_ok = match exact_gate {
            ExactGate::Enforce => self.exact_gate_passed(),
            ExactGate::ReportOnly => true,
        };
        exact_ok && self.verdict_gate_passed()
    }
}

/// Renders the Markdown report of `run`.
#[must_use]
pub fn render(run: &Run, summary: &Summary, exact_gate: ExactGate) -> String {
    let mut out = String::new();
    // Writing to a `String` cannot fail, so the `fmt::Result`s below are ignored.
    let _ = writeln!(out, "# Parser differential report (KNSH-034)\n");
    let _ = writeln!(out, "**Result: {}**\n", pass_fail(summary.passed(exact_gate)));

    let _ = writeln!(out, "## Shells\n");
    let _ = writeln!(out, "| Role | Shell | Version |\n| --- | --- | --- |");
    for oracle in &run.oracles {
        let role = match oracle.role {
            Role::Gate => "gate",
            Role::Reference => "reference (not gating)",
        };
        let _ = writeln!(
            out,
            "| {role} | `{}` | {} |",
            oracle.path.display(),
            cell(&oracle.version)
        );
    }
    if !summary.has_gate_oracle {
        let _ = writeln!(out, "\nNo gating bash: the verdict gate fails.");
    }
    if !summary.has_modern_bash {
        let _ = writeln!(
            out,
            "\nNo bash 4 or newer found: lines tagged `b32-missing` are checked against bash 3.2 only, where a \
             reject is expected."
        );
    }

    let _ = writeln!(out, "\n## Exact-parse coverage\n");
    let _ = writeln!(
        out,
        "| Lines | Exact | Dynamic in parts | Syntax error | Not read |\n| --- | --- | --- | --- | --- |"
    );
    let _ = writeln!(
        out,
        "| {} | {} ({}) | {} ({}) | {} ({}) | {} ({}) |",
        summary.total,
        summary.exact,
        percent(summary.exact, summary.total),
        summary.dynamic_parts,
        percent(summary.dynamic_parts, summary.total),
        summary.syntax_errors,
        percent(summary.syntax_errors, summary.total),
        summary.not_read,
        percent(summary.not_read, summary.total),
    );
    let enforcement = match exact_gate {
        ExactGate::Enforce => "enforced",
        ExactGate::ReportOnly => "reported only; enforced on release runs",
    };
    let _ = writeln!(
        out,
        "\nGate, at least {MIN_EXACT_PERCENT}% `Exact` ({enforcement}): **{}** ({})",
        pass_fail(summary.exact_gate_passed()),
        percent(summary.exact, summary.total)
    );
    if !summary.by_reason.is_empty() {
        let _ = writeln!(out, "\n### Dynamic reasons\n\n| Reason | Lines |\n| --- | --- |");
        for (reason, lines) in &summary.by_reason {
            let _ = writeln!(out, "| {} | {lines} |", cell(reason));
        }
    }

    let _ = writeln!(out, "\n## Verdicts\n");
    let _ = writeln!(
        out,
        "| Shell | Agree | Mismatch | Expected bash 3.2 difference | Not read by us |\n| --- | --- | --- | --- | --- |"
    );
    for (oracle, counts) in run.oracles.iter().zip(&summary.per_oracle) {
        let _ = writeln!(
            out,
            "| `{}` | {} | {} | {} | {} |",
            oracle.path.display(),
            counts.agree,
            counts.mismatch,
            counts.expected_bash32,
            counts.no_verdict
        );
    }
    let _ = writeln!(
        out,
        "\nGate, every verdict matches bash (no line `Exact` that bash rejects): **{}** ({} mismatch(es))",
        pass_fail(summary.verdict_gate_passed()),
        summary.mismatches.len()
    );
    write_findings(&mut out, "Mismatches", run, &summary.mismatches);
    write_findings(
        &mut out,
        "Reference shell disagreements (not gating)",
        run,
        &summary.reference_disagreements,
    );
    out
}

fn write_findings(out: &mut String, title: &str, run: &Run, findings: &[Finding]) {
    if findings.is_empty() {
        return;
    }
    let _ = writeln!(out, "\n### {title}\n");
    for finding in findings {
        let result = &run.results[finding.result];
        let oracle = &run.oracles[finding.oracle];
        let theirs = if result.verdicts[finding.oracle].accepted {
            "accepts"
        } else {
            "rejects"
        };
        let reasons: Vec<String> = result.ours.reasons().iter().map(ToString::to_string).collect();
        let ours = if reasons.is_empty() {
            "exact".to_owned()
        } else {
            reasons.join(", ")
        };
        let command = escape(&result.line.entry.command);
        // A fence longer than any backtick run in the command (and at least three) cannot be closed by it.
        let fence = "`".repeat(longest_backtick_run(&command).max(2) + 1);
        let _ = writeln!(
            out,
            "- `{}:{}` · {} · `{}`: {theirs} · ours: {ours}\n\n  {fence}text\n  {command}\n  {fence}\n",
            result.line.file,
            result.line.line,
            finding.mismatch.code(),
            oracle.path.display(),
        );
    }
}

/// `n` of `total` as a percentage with two decimals, rounded down (`0.00%` for an empty corpus).
fn percent(n: usize, total: usize) -> String {
    let basis_points = (n * 10_000).checked_div(total).unwrap_or(0);
    format!("{}.{:02}%", basis_points / 100, basis_points % 100)
}

const fn pass_fail(passed: bool) -> &'static str {
    if passed { "PASS" } else { "FAIL" }
}

/// Text safe inside a Markdown table cell.
fn cell(text: &str) -> String {
    text.replace('|', "\\|")
}

fn longest_backtick_run(text: &str) -> usize {
    text.split(|c| c != '`').map(str::len).max().unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::harness::run;
    use crate::testing::{FakeOracle, bash3, bash5, line, reference};

    fn lines(n_exact: usize, n_eval: usize) -> Vec<crate::harness::Line> {
        let mut lines: Vec<_> = (0..n_exact).map(|i| line(&format!("echo {i}"))).collect();
        lines.extend((0..n_eval).map(|i| line(&format!("eval {i}"))));
        lines
    }

    // KNSH-034: the report records each bash's version and the exact-parse percentages.
    #[test]
    fn report_includes_bash_version_and_percentages() {
        let old = FakeOracle::new(bash3(), |_| true);
        let new = FakeOracle::new(bash5(), |_| true);
        let run = run(lines(19, 1), &[&old, &new]).unwrap();
        let summary = Summary::of(&run);
        let report = render(&run, &summary, ExactGate::Enforce);
        assert!(report.contains("GNU bash, version 3.2.57(1)-release"), "{report}");
        assert!(report.contains("GNU bash, version 5.2.37(1)-release"), "{report}");
        assert!(
            report.contains("| 20 | 19 (95.00%) | 1 (5.00%) | 0 (0.00%) | 0 (0.00%) |"),
            "{report}"
        );
        assert!(
            report.contains("at least 95% `Exact` (enforced): **PASS** (95.00%)"),
            "{report}"
        );
        assert!(report.contains("| `eval` | 1 |"), "{report}");
        assert!(report.contains("**Result: PASS**"), "{report}");
        assert!(summary.passed(ExactGate::Enforce));
    }

    #[test]
    fn exact_gate_fails_below_threshold_without_rounding_up() {
        let bash = FakeOracle::new(bash5(), |_| true);
        // 1899 of 2000 is 94.95%: shown as 94.95%, and short of 95%.
        let run = run(lines(1899, 101), &[&bash]).unwrap();
        let summary = Summary::of(&run);
        assert!(!summary.exact_gate_passed());
        assert!(summary.verdict_gate_passed());
        assert!(!summary.passed(ExactGate::Enforce));
        assert!(render(&run, &summary, ExactGate::Enforce).contains("**FAIL** (94.95%)"));
        // Off release runs the shortfall is reported, not fatal.
        assert!(summary.passed(ExactGate::ReportOnly));
        let report = render(&run, &summary, ExactGate::ReportOnly);
        assert!(
            report.contains("(reported only; enforced on release runs): **FAIL** (94.95%)"),
            "{report}"
        );
        assert!(report.contains("**Result: PASS**"), "{report}");
    }

    #[test]
    fn empty_corpus_or_no_bash_fails_closed() {
        let bash = FakeOracle::new(bash5(), |_| true);
        let empty = Summary::of(&run(Vec::new(), &[&bash]).unwrap());
        assert!(!empty.exact_gate_passed());
        assert!(!empty.verdict_gate_passed());
        assert!(!empty.passed(ExactGate::ReportOnly));
        let unchecked = Summary::of(&run(lines(1, 0), &[]).unwrap());
        assert!(!unchecked.verdict_gate_passed());
    }

    // KNSH-034: any mismatch with a gating bash fails the run and is listed with its file, line and command.
    #[test]
    fn mismatch_fails_and_is_listed() {
        let bash = FakeOracle::new(bash5(), |command| command != "echo 3");
        let run = run(lines(20, 0), &[&bash]).unwrap();
        let summary = Summary::of(&run);
        assert!(summary.exact_gate_passed());
        assert!(!summary.passed(ExactGate::Enforce));
        assert!(!summary.passed(ExactGate::ReportOnly));
        assert_eq!(summary.mismatches.len(), 1);
        let report = render(&run, &summary, ExactGate::Enforce);
        assert!(report.contains("**Result: FAIL**"));
        assert!(report.contains("- `test.txt:3` · exact_but_shell_rejects · `/opt/homebrew/bin/bash`: rejects"));
        assert!(report.contains("  ```text\n  echo 3\n  ```"), "{report}");
    }

    #[test]
    fn reference_shell_disagreement_is_listed_but_does_not_gate() {
        let bash = FakeOracle::new(bash5(), |_| true);
        let brush = FakeOracle::new(reference(), |_| false);
        let run = run(lines(20, 0), &[&bash, &brush]).unwrap();
        let summary = Summary::of(&run);
        assert!(summary.passed(ExactGate::Enforce));
        assert_eq!(summary.reference_disagreements.len(), 20);
        assert!(render(&run, &summary, ExactGate::Enforce).contains("### Reference shell disagreements (not gating)"));
    }

    #[test]
    fn report_notes_missing_modern_bash() {
        let bash = FakeOracle::new(bash3(), |_| true);
        let run = run(lines(1, 0), &[&bash]).unwrap();
        let summary = Summary::of(&run);
        assert!(!summary.has_modern_bash);
        assert!(render(&run, &summary, ExactGate::Enforce).contains("No bash 4 or newer found"));
    }

    #[test]
    fn fences_commands_holding_backticks() {
        assert_eq!(longest_backtick_run("echo `date` ```x"), 3);
        assert_eq!(percent(1, 3), "33.33%");
        assert_eq!(percent(0, 0), "0.00%");
    }
}
