//! Replays the fuzzing inputs for this crate's targets as ordinary stable tests (KNSH-005, NFR-SUP-06,
//! `specs/07-testing/fuzzing.md`).
//!
//! The fuzz crate (`fuzz/`) is a separate, nightly-only workspace, so its property checks are included here by
//! path: the same code that libFuzzer runs decides pass or fail here, without libFuzzer. Every saved crash in
//! `fuzz/regressions/<target>/` and every seed in `fuzz/corpus/<target>/` must pass.

// The whole file is test code: this lets clippy's `allow-*-in-tests` settings (clippy.toml) cover the included
// checks too, which signal failure by panicking as libFuzzer expects.
#![cfg(test)]

#[path = "../../../fuzz/src/checks.rs"]
mod checks;

use std::fs;
use std::panic;
use std::path::{Path, PathBuf};

/// A fuzz target's property check: panics on failure.
type Check = fn(&[u8]);

/// Every fuzz target that exercises `knsh-json`, with its check. A new target is added here and in
/// `fuzz/Cargo.toml` together.
const TARGETS: &[(&str, Check)] = &[
    ("json_reader", checks::json_reader),
    ("json_writer_roundtrip", checks::json_writer_roundtrip),
    ("frame_reader", checks::frame_reader),
];

fn fuzz_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fuzz")
}

/// The input files in `dir`, sorted, skipping documentation and dotfiles (`README.md`, `.gitkeep`). A missing
/// directory has no inputs.
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

/// Runs each target's check on every input under `fuzz/<kind>/<target>/`, fails naming each input that panicked,
/// and returns how many inputs ran.
fn replay(kind: &str) -> usize {
    let mut failures = Vec::new();
    let mut count = 0;
    for &(target, check) in TARGETS {
        for path in inputs(&fuzz_dir().join(kind).join(target)) {
            let data = fs::read(&path).unwrap();
            count += 1;
            if panic::catch_unwind(|| check(&data)).is_err() {
                failures.push(path.display().to_string());
            }
        }
    }
    assert!(failures.is_empty(), "inputs failing their fuzz property: {failures:#?}");
    count
}

#[test]
fn fuzz_regressions_replay() {
    // KNSH-005: every saved crash input is replayed as an ordinary test. The directory may be empty when no crash
    // has been found yet; the seed replay below keeps the checks themselves exercised.
    for &(target, _) in TARGETS {
        assert!(
            fuzz_dir().join("regressions").join(target).is_dir(),
            "fuzz/regressions/{target}/ went missing"
        );
    }
    replay("regressions");
}

#[test]
fn fuzz_seed_corpora_replay() {
    // The seeds must satisfy the properties too, so a broken check or seed fails here, not only under nightly.
    let count = replay("corpus");
    for &(target, _) in TARGETS {
        assert!(
            !inputs(&fuzz_dir().join("corpus").join(target)).is_empty(),
            "fuzz/corpus/{target}/ has no seeds"
        );
    }
    assert!(count >= 90, "seed corpora shrank to {count} inputs");
}

#[test]
fn json_reader_corpus_includes_conformance_samples() {
    // KNSH-005: the json_reader seeds include every KNSH-003 accept/reject sample, byte for byte, so the fuzzer
    // starts from the hand-written edge cases and a new sample is not forgotten.
    let seeds: Vec<Vec<u8>> = inputs(&fuzz_dir().join("corpus/json_reader"))
        .iter()
        .map(|path| fs::read(path).unwrap())
        .collect();
    let samples = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/samples");
    for kind in ["accept", "reject"] {
        for path in inputs(&samples.join(kind)) {
            let sample = fs::read(&path).unwrap();
            assert!(
                seeds.contains(&sample),
                "{} is missing from fuzz/corpus/json_reader/",
                path.display()
            );
        }
    }
}
