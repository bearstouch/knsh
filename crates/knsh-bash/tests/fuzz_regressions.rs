//! Replays the `bash_lex` fuzzing inputs as ordinary stable tests (KNSH-028, NFR-SEC-05,
//! `specs/07-testing/fuzzing.md`).
//!
//! The fuzz crate (`fuzz/`) is a separate, nightly-only workspace, so the target's property check is included here
//! by path: the same code that libFuzzer runs decides pass or fail here. Every saved crash in
//! `fuzz/regressions/bash_lex/` and every seed in `fuzz/corpus/bash_lex/` must pass.

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

/// Runs the check on every input under `fuzz/<kind>/bash_lex/`, fails naming each input that panicked, and returns
/// how many ran.
fn replay(kind: &str) -> usize {
    let paths = inputs(&fuzz_dir().join(kind).join("bash_lex"));
    let failures: Vec<String> = paths
        .iter()
        .filter(|path| {
            let data = fs::read(path).unwrap();
            panic::catch_unwind(|| bash_checks::bash_lex(&data)).is_err()
        })
        .map(|path| path.display().to_string())
        .collect();
    assert!(failures.is_empty(), "inputs failing their fuzz property: {failures:#?}");
    paths.len()
}

#[test]
fn fuzz_regressions_replay() {
    // KNSH-028 / KNSH-005: every saved crash input is replayed as an ordinary test.
    assert!(
        fuzz_dir().join("regressions/bash_lex").is_dir(),
        "fuzz/regressions/bash_lex/ went missing"
    );
    replay("regressions");
}

#[test]
fn fuzz_seed_corpus_replay() {
    // The seeds must satisfy the property too, so a broken check or seed fails here, not only under nightly.
    assert!(replay("corpus") >= 17, "fuzz/corpus/bash_lex/ shrank");
}

#[test]
fn seed_corpus_accepts_and_rejects_as_named() {
    // `accept_` seeds lex, `reject_` seeds do not, so the corpus keeps covering both paths.
    for path in inputs(&fuzz_dir().join("corpus/bash_lex")) {
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        let text = fs::read_to_string(&path).unwrap();
        let accepted = knsh_bash::lex(&text).is_ok();
        assert!(
            (name.starts_with("accept_") && accepted) || (name.starts_with("reject_") && !accepted),
            "{name}: lexed = {accepted}"
        );
    }
}
