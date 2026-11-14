//! The differential gate over the checked-in corpus (`tests/corpus/`) against the host's real bash, so `cargo test`
//! fails on a parser change that makes us accept a line bash rejects, or reject one it accepts (KNSH-034,
//! NFR-COMPAT-07). The 95% exact gate is enforced on release runs by `scripts/check.sh difftest`; here its
//! measurement is only checked to be reported.

// The whole file is test code, so clippy's `allow-*-in-tests` settings cover the helpers too.
#![cfg(test)]

use std::path::{Path, PathBuf};

use knsh_difftest::harness::{load_corpus, run};
use knsh_difftest::oracle::{Oracle, Role, SYSTEM_BASH, ShellOracle, default_bashes};
use knsh_difftest::report::render;
use knsh_difftest::{ExactGate, Summary};

fn workspace_corpus() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/corpus")
}

// KNSH-034: every corpus line's accept or reject verdict matches every installed bash; no line is `Exact` while bash
// rejects it.
#[test]
fn corpus_verdicts_match_real_bash() {
    assert!(
        Path::new(SYSTEM_BASH).is_file(),
        "{SYSTEM_BASH} is required for the differential gate"
    );
    let lines = load_corpus(&workspace_corpus()).unwrap();
    assert_ne!(lines.len(), 0, "the corpus has lines");
    let oracles: Vec<ShellOracle> = default_bashes()
        .iter()
        .map(|path| ShellOracle::probe(path, Role::Gate).unwrap())
        .collect();
    let oracles: Vec<&dyn Oracle> = oracles.iter().map(|o| o as &dyn Oracle).collect();
    let run = run(lines, &oracles).unwrap();
    let summary = Summary::of(&run);
    let report = render(&run, &summary, ExactGate::ReportOnly);
    assert!(summary.verdict_gate_passed(), "{report}");
    // The report always records the bash version used and the measured exact share.
    assert!(report.contains("GNU bash, version"), "{report}");
    assert!(report.contains("`Exact` (reported only"), "{report}");
}
