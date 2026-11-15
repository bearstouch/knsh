//! Replays the `sandbox_log` fuzzing inputs as ordinary stable tests (KNSH-047, NFR-SUP-06,
//! `specs/07-testing/fuzzing.md`).
//!
//! The fuzz crate (`fuzz/`) is a separate, nightly-only workspace, so the target's property check is included here
//! by path: the same code that libFuzzer runs decides pass or fail here. Every saved crash in
//! `fuzz/regressions/sandbox_log/` and every seed in `fuzz/corpus/sandbox_log/` must pass.

// The whole file is test code: this lets clippy's `allow-*-in-tests` settings (clippy.toml) cover the included
// check too, which signals failure by panicking as libFuzzer expects.
#![cfg(test)]

#[path = "../../../fuzz/src/sandbox_log_checks.rs"]
mod sandbox_log_checks;

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

/// Runs the check on every input under `fuzz/<kind>/sandbox_log/`, fails naming each input that panicked, and
/// returns how many ran.
fn replay(kind: &str) -> usize {
    let paths = inputs(&fuzz_dir().join(kind).join("sandbox_log"));
    let failures: Vec<String> = paths
        .iter()
        .filter(|path| {
            let data = fs::read(path).unwrap();
            panic::catch_unwind(|| sandbox_log_checks::sandbox_log(&data)).is_err()
        })
        .map(|path| path.display().to_string())
        .collect();
    assert!(failures.is_empty(), "inputs failing their fuzz property: {failures:#?}");
    paths.len()
}

#[test]
fn fuzz_regressions_replay() {
    assert!(
        fuzz_dir().join("regressions/sandbox_log").is_dir(),
        "fuzz/regressions/sandbox_log/ went missing"
    );
    replay("regressions");
}

#[test]
fn fuzz_seed_corpus_replay() {
    // The seeds are the captured fixture lines, one per file; they must satisfy the property too.
    assert!(replay("corpus") >= 36, "fuzz/corpus/sandbox_log/ shrank");
}
