//! Replays the `arith_expr` (KNSH-097) and `word_expansion` (KNSH-098) fuzzing inputs as ordinary stable tests
//! (NFR-SEC-05, `specs/07-testing/fuzzing.md`).
//!
//! The fuzz crate (`fuzz/`) is a separate, nightly-only workspace, so each target's property check is included here
//! by path: the same code that libFuzzer runs decides pass or fail here. Every saved crash in
//! `fuzz/regressions/<target>/` and every seed in `fuzz/corpus/<target>/` must pass.

// The whole file is test code: this lets clippy's `allow-*-in-tests` settings (clippy.toml) cover the included
// check too, which signals failure by panicking as libFuzzer expects.
#![cfg(test)]

#[path = "../../../fuzz/src/arith_checks.rs"]
mod arith_checks;
#[path = "../../../fuzz/src/word_checks.rs"]
mod word_checks;

use std::fs;
use std::panic;
use std::path::{Path, PathBuf};

fn fuzz_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fuzz")
}

/// Runs the `arith_expr` check on every input under `fuzz/<kind>/arith_expr/` and returns how many ran.
fn replay(kind: &str) -> usize {
    replay_target(kind, "arith_expr", arith_checks::arith_expr)
}

/// Runs `check` on every input under `fuzz/<kind>/<target>/` and returns how many ran.
fn replay_target(kind: &str, target: &str, check: fn(&[u8])) -> usize {
    let dir = fuzz_dir().join(kind).join(target);
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
            panic::catch_unwind(|| check(&data)).is_err()
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

#[test]
fn word_expansion_regressions_replay() {
    replay_target("regressions", "word_expansion", word_checks::word_expansion);
}

#[test]
fn word_expansion_seed_corpus_replay() {
    assert!(
        replay_target("corpus", "word_expansion", word_checks::word_expansion) >= 20,
        "fuzz/corpus/word_expansion/ shrank"
    );
}

// Hostile words the fuzzer would take long to reach: deep braces, huge products and sequences, pathological
// patterns, many braces that never expand. Each ends in a result or a limit, quickly.
#[test]
fn hostile_words_satisfy_the_property() {
    for (flags, text) in [
        (0_u8, "{".repeat(1000) + "a,b" + &"}".repeat(1000)),
        (0, "{a,b}".repeat(30)),
        (0, "{1..99999999999}".to_owned()),
        (0, "{".repeat(2000)),
        (1, "*(".repeat(60) + "a" + &")".repeat(60)),
        (1, format!("{}b", "*(a|aa)".repeat(40))),
        (2, "**/".repeat(30) + "x"),
        (0, "[".repeat(1000) + "]"),
    ] {
        let mut data = vec![flags];
        data.extend_from_slice(text.as_bytes());
        word_checks::word_expansion(&data);
    }
}
