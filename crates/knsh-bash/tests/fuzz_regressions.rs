//! Replays the `bash_lex` and `bash_parse` fuzzing inputs as ordinary stable tests (KNSH-028, KNSH-029,
//! NFR-SEC-05, `specs/07-testing/fuzzing.md`).
//!
//! The fuzz crate (`fuzz/`) is a separate, nightly-only workspace, so the target's property check is included here
//! by path: the same code that libFuzzer runs decides pass or fail here. Every saved crash in
//! `fuzz/regressions/<target>/` and every seed in `fuzz/corpus/<target>/` must pass. The lexer check also runs over
//! the parser's seeds and the other way round, since every command line is input to both.

// The whole file is test code: this lets clippy's `allow-*-in-tests` settings (clippy.toml) cover the included
// check too, which signals failure by panicking as libFuzzer expects.
#![cfg(test)]

#[path = "../../../fuzz/src/bash_checks.rs"]
mod bash_checks;

use std::fs;
use std::panic;
use std::path::{Path, PathBuf};

fn fuzz_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fuzz")
}

/// The input files in `dir`, sorted, skipping documentation and dotfiles. A missing directory has no inputs.
fn inputs(dir: &Path) -> Vec<PathBuf> {
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut paths: Vec<PathBuf> = entries
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.is_file())
        .filter(|path| {
            let name = path.file_name().unwrap().to_string_lossy();
            !name.starts_with('.') && name != "README.md"
        })
        .collect();
    paths.sort();
    paths
}

/// Runs both checks on every input under `fuzz/<kind>/<target>/`, fails naming each input that panicked, and returns
/// how many ran.
fn replay(kind: &str, target: &str) -> usize {
    let paths = inputs(&fuzz_dir().join(kind).join(target));
    let failures: Vec<String> = paths
        .iter()
        .filter(|path| {
            let data = fs::read(path).unwrap();
            panic::catch_unwind(|| {
                bash_checks::bash_lex(&data);
                bash_checks::bash_parse(&data);
            })
            .is_err()
        })
        .map(|path| path.display().to_string())
        .collect();
    assert!(failures.is_empty(), "inputs failing their fuzz property: {failures:#?}");
    paths.len()
}

#[test]
fn fuzz_regressions_replay() {
    // KNSH-028, KNSH-029 / KNSH-005: every saved crash input is replayed as an ordinary test.
    for target in ["bash_lex", "bash_parse"] {
        assert!(
            fuzz_dir().join("regressions").join(target).is_dir(),
            "fuzz/regressions/{target}/ went missing"
        );
        replay("regressions", target);
    }
}

#[test]
fn fuzz_seed_corpus_replay() {
    // The seeds must satisfy the properties too, so a broken check or seed fails here, not only under nightly.
    assert!(replay("corpus", "bash_lex") >= 17, "fuzz/corpus/bash_lex/ shrank");
    assert!(replay("corpus", "bash_parse") >= 16, "fuzz/corpus/bash_parse/ shrank");
}

#[test]
fn seed_corpus_accepts_and_rejects_as_named() {
    // `accept_` seeds lex (or parse), `reject_` seeds do not, so each corpus keeps covering both paths.
    type Accepts = fn(&str) -> bool;
    let checks: [(&str, Accepts); 2] = [
        ("bash_lex", |text| knsh_bash::lex(text).is_ok()),
        ("bash_parse", |text| knsh_bash::parse(text).is_ok()),
    ];
    for (target, accepts) in checks {
        for path in inputs(&fuzz_dir().join("corpus").join(target)) {
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            let text = fs::read_to_string(&path).unwrap();
            let accepted = accepts(&text);
            assert!(
                (name.starts_with("accept_") && accepted) || (name.starts_with("reject_") && !accepted),
                "{target}/{name}: accepted = {accepted}"
            );
        }
    }
}
