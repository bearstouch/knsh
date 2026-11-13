//! Replays the `toml_parser` fuzzing inputs as ordinary stable tests (KNSH-006, NFR-SUP-06,
//! `specs/07-testing/fuzzing.md`).
//!
//! The fuzz crate (`fuzz/`) is a separate, nightly-only workspace, so the target's property check is included here
//! by path: the same code that libFuzzer runs decides pass or fail here. Every saved crash in
//! `fuzz/regressions/toml_parser/` and every seed in `fuzz/corpus/toml_parser/` must pass.

// The whole file is test code: this lets clippy's `allow-*-in-tests` settings (clippy.toml) cover the included
// check too, which signals failure by panicking as libFuzzer expects.
#![cfg(test)]

#[path = "../../../fuzz/src/toml_checks.rs"]
mod toml_checks;

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

/// Runs the check on every input under `fuzz/<kind>/toml_parser/`, fails naming each input that panicked, and
/// returns how many ran.
fn replay(kind: &str) -> usize {
    let paths = inputs(&fuzz_dir().join(kind).join("toml_parser"));
    let failures: Vec<String> = paths
        .iter()
        .filter(|path| {
            let data = fs::read(path).unwrap();
            panic::catch_unwind(|| toml_checks::toml_parser(&data)).is_err()
        })
        .map(|path| path.display().to_string())
        .collect();
    assert!(failures.is_empty(), "inputs failing their fuzz property: {failures:#?}");
    paths.len()
}

#[test]
fn fuzz_regressions_replay() {
    // KNSH-006 / KNSH-005: every saved crash input is replayed as an ordinary test.
    assert!(
        fuzz_dir().join("regressions/toml_parser").is_dir(),
        "fuzz/regressions/toml_parser/ went missing"
    );
    replay("regressions");
}

#[test]
fn fuzz_seed_corpus_replay() {
    // The seeds must satisfy the property too, so a broken check or seed fails here, not only under nightly.
    assert!(replay("corpus") >= 15, "fuzz/corpus/toml_parser/ shrank");
}

#[test]
fn seed_corpus_matches_spec_examples() {
    // The fuzzer starts from the spec examples byte for byte, so a changed example cannot drift from the seeds.
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    for (page, seed) in [
        ("specs/05-models/policy-profile.md", "accept_spec_policy_profile.toml"),
        ("specs/05-models/hook.md", "accept_spec_hook.toml"),
    ] {
        let page = fs::read_to_string(root.join(page)).unwrap();
        let start = page.find("```toml\n").unwrap() + "```toml\n".len();
        let example = &page[start..start + page[start..].find("```").unwrap()];
        let seed_text = fs::read_to_string(fuzz_dir().join("corpus/toml_parser").join(seed)).unwrap();
        assert_eq!(seed_text, example, "{seed} differs from the spec example");
        assert!(knsh_toml::parse(example.as_bytes()).is_ok());
    }
}
