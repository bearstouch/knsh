//! Replays the `arith_expr` fuzzing inputs as ordinary stable tests (KNSH-097, NFR-SEC-05,
//! `specs/07-testing/fuzzing.md`).
//!
//! The fuzz crate (`fuzz/`) is a separate, nightly-only workspace, so the target's property check is included here
//! by path: the same code that libFuzzer runs decides pass or fail here. Every saved crash in
//! `fuzz/regressions/arith_expr/` and every seed in `fuzz/corpus/arith_expr/` must pass.

// The whole file is test code: this lets clippy's `allow-*-in-tests` settings (clippy.toml) cover the included
// check too, which signals failure by panicking as libFuzzer expects.
#![cfg(test)]

#[path = "../../../fuzz/src/arith_checks.rs"]
mod arith_checks;

use std::fs;
use std::panic;
use std::path::{Path, PathBuf};

fn fuzz_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fuzz")
}

/// Runs the check on every input under `fuzz/<kind>/arith_expr/` and returns how many ran.
fn replay(kind: &str) -> usize {
    let dir = fuzz_dir().join(kind).join("arith_expr");
    let mut paths: Vec<PathBuf> = fs::read_dir(&dir)
        .map(|entries| entries.map(|entry| entry.unwrap().path()).collect())
        .unwrap_or_default();
    paths.retain(|path| {
        let name = path.file_name().unwrap().to_string_lossy();
        path.is_file() && !name.starts_with('.') && name != "README.md"
    });
    paths.sort();
    let failures: Vec<String> = paths
        .iter()
        .filter(|path| {
            let data = fs::read(path).unwrap();
            panic::catch_unwind(|| arith_checks::arith_expr(&data)).is_err()
        })
        .map(|path| path.display().to_string())
        .collect();
    assert!(failures.is_empty(), "inputs failing their fuzz property: {failures:#?}");
    paths.len()
}

#[test]
fn fuzz_regressions_replay() {
    replay("regressions");
}

#[test]
fn fuzz_seed_corpus_replay() {
    assert!(replay("corpus") >= 20, "fuzz/corpus/arith_expr/ shrank");
}

// Hostile shapes the fuzzer would take long to reach: deep nesting and recursion end in errors, not crashes.
#[test]
fn hostile_expressions_satisfy_the_property() {
    for expression in [
        "(".repeat(20_000),
        format!("{}1{}", "(".repeat(5000), ")".repeat(5000)),
        "-".repeat(20_000) + "1",
        "1?".repeat(5000) + "1" + &":1".repeat(5000),
        "r".to_owned(),
        "a=".repeat(5000) + "1",
    ] {
        arith_checks::arith_expr(expression.as_bytes());
    }
}
