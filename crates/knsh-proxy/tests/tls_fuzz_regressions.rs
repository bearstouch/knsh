//! Replays the `tls_client_hello` fuzzing inputs as ordinary stable tests (KNSH-061, NFR-SUP-06,
//! `specs/07-testing/fuzzing.md`).
//!
//! The fuzz crate (`fuzz/`) is a separate, nightly-only workspace, so the target's property check is included here
//! by path: the same code that libFuzzer runs decides pass or fail here. Every saved crash in
//! `fuzz/regressions/tls_client_hello/` and every seed in `fuzz/corpus/tls_client_hello/` must pass.

// The whole file is test code: this lets clippy's `allow-*-in-tests` settings (clippy.toml) cover the included
// check too, which signals failure by panicking as libFuzzer expects.
#![cfg(test)]

#[path = "../../../fuzz/src/tls_checks.rs"]
mod tls_checks;

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

/// Runs the check on every input under `fuzz/<kind>/tls_client_hello/`, fails naming each input that panicked, and
/// returns how many ran.
fn replay(kind: &str) -> usize {
    let paths = inputs(&fuzz_dir().join(kind).join("tls_client_hello"));
    let failures: Vec<String> = paths
        .iter()
        .filter(|path| {
            let data = fs::read(path).unwrap();
            panic::catch_unwind(|| tls_checks::tls_client_hello(&data)).is_err()
        })
        .map(|path| path.display().to_string())
        .collect();
    assert!(failures.is_empty(), "inputs failing their fuzz property: {failures:#?}");
    paths.len()
}

#[test]
fn fuzz_regressions_replay() {
    assert!(
        fuzz_dir().join("regressions/tls_client_hello").is_dir(),
        "fuzz/regressions/tls_client_hello/ went missing"
    );
    replay("regressions");
}

#[test]
fn fuzz_seed_corpus_replay() {
    assert!(replay("corpus") >= 16, "fuzz/corpus/tls_client_hello/ shrank");
}

// FR-NET-06, C10: the seed captured from the system curl on loopback is a real ClientHello, and the reader extracts
// the name curl was asked for.
#[test]
fn reads_real_curl_client_hello() {
    use knsh_proxy::tls::{HelloState, ServerName, read_client_hello};
    let data = fs::read(fuzz_dir().join("corpus/tls_client_hello/curl_real")).unwrap();
    assert_eq!(
        read_client_hello(&data),
        HelloState::Complete(ServerName::Name("tls.test".to_owned()))
    );
}
