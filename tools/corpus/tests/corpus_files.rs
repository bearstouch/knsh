//! The CI gate over the checked-in corpus (`tests/corpus/`), and end-to-end runs of the checker and importer on
//! temporary corpora (KNSH-033, NFR-PRIV-08, NFR-COMPAT-05).

// The whole file is test code, so clippy's `allow-*-in-tests` settings cover the helpers too.
#![cfg(test)]

use std::fs;
use std::path::{Path, PathBuf};

use knsh_corpus::check::check_dir;
use knsh_corpus::entry::Tag;
use knsh_corpus::import::{ImportOptions, InputFormat, import};
use knsh_corpus::{CorpusError, Scrub};

fn workspace_corpus() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/corpus")
}

/// A fresh directory under the target directory, removed when dropped. Never the user's real directories.
struct TempDir(PathBuf);

impl TempDir {
    fn new(name: &str) -> Self {
        let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("corpus-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

const REGISTRY: &str = "# knsh-corpus sources 1\nseed\tMIT\tTest source\n";

// KNSH-033: the checked-in corpus is clean, every line has a registered source and licence, and it covers the bash
// 3.2 vs 5.2 constructs NFR-COMPAT-05 relies on.
#[test]
fn checked_in_corpus_passes_the_gate() {
    let report = match check_dir(&workspace_corpus()) {
        Ok(report) => report,
        Err(errors) => panic!(
            "corpus check failed:\n{}",
            errors.iter().map(ToString::to_string).collect::<Vec<_>>().join("\n")
        ),
    };
    assert!(report.entries >= 200, "corpus unexpectedly small: {report:?}");
    for tag in [
        Tag::B32Missing,
        Tag::B32Differs,
        Tag::Wrapper,
        Tag::Dynamic,
        Tag::Irreversible,
        Tag::Multiline,
    ] {
        assert!(
            report.by_tag.get(&tag).copied().unwrap_or(0) > 0,
            "no entries tagged {tag}"
        );
    }
}

// KNSH-033: a raw `/Users/<name>` or token in a corpus file fails the gate, and the message does not echo it.
#[test]
fn gate_fails_on_raw_home_path_or_token() {
    let dir = TempDir::new("leak");
    fs::write(dir.0.join("sources.tsv"), REGISTRY).unwrap();
    fs::write(
        dir.0.join("seed.txt"),
        "# knsh-corpus 1\nseed\tMIT\t-\tcd /Users/alice\nseed\tMIT\t-\tgh auth login ghp_A1b2C3d4E5f6G7h8I9j0K1l2\nseed\tMIT\t-\tls\n",
    )
    .unwrap();
    let errors = check_dir(&dir.0).unwrap_err();
    assert_eq!(errors.len(), 2);
    let text = errors.iter().map(ToString::to_string).collect::<Vec<_>>().join("\n");
    assert!(text.contains("seed.txt:2: raw home path"), "{text}");
    assert!(text.contains("seed.txt:3: raw token"), "{text}");
    assert!(
        !text.contains("alice") && !text.contains("ghp_A1b2"),
        "error echoes the secret: {text}"
    );
}

// KNSH-033: an entry without a registered source and licence fails the gate.
#[test]
fn gate_fails_on_unregistered_source_or_missing_licence() {
    let dir = TempDir::new("source");
    fs::write(dir.0.join("sources.tsv"), REGISTRY).unwrap();
    fs::write(dir.0.join("seed.txt"), "# knsh-corpus 1\nseed\t\t-\tls\n").unwrap();
    fs::write(dir.0.join("ghost.txt"), "# knsh-corpus 1\nghost\tMIT\t-\tls\n").unwrap();
    let text = check_dir(&dir.0)
        .unwrap_err()
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("\n");
    assert!(text.contains("ghost.txt:1: source \"ghost\" is not listed"), "{text}");
    assert!(text.contains("seed.txt:2: entry has no licence"), "{text}");
}

#[test]
fn gate_fails_without_registry() {
    let dir = TempDir::new("noreg");
    assert!(matches!(check_dir(&dir.0).unwrap_err()[..], [CorpusError::Io { .. }]));
}

fn options(format: InputFormat) -> ImportOptions {
    ImportOptions {
        source: "seed".into(),
        format,
        scrub: Scrub {
            users: vec!["runner-bob".into()],
            hosts: vec!["ci-box-7".into()],
        },
        tags: vec![Tag::Network],
    }
}

#[test]
fn imports_a_trace_into_a_clean_corpus_file() {
    let dir = TempDir::new("import");
    fs::write(dir.0.join("sources.tsv"), REGISTRY).unwrap();
    let trace = dir.0.join("trace.jsonl");
    fs::write(
        &trace,
        concat!(
            r#"{"tool":{"command":"curl -H 'Authorization: Bearer abc123' https://ci-box-7:8443/x"}}"#,
            "\n",
            r#"{"tool":[{"command":"cd /home/runner-bob/repo && git push"},{"other":1}]}"#,
            "\n",
        ),
    )
    .unwrap();
    let summary = import(
        &dir.0,
        &trace,
        &options(InputFormat::JsonLines {
            field: vec!["tool".into(), "command".into()],
        }),
    )
    .unwrap();
    assert_eq!((summary.read, summary.added), (2, 2));
    let written = fs::read_to_string(dir.0.join("seed.txt")).unwrap();
    assert_eq!(
        written,
        "# knsh-corpus 1\n# source\tlicence\ttags\tcommand\n\
         seed\tMIT\tnetwork\tcurl -H 'Authorization: Bearer __SECRET__' https://__HOST__:8443/x\n\
         seed\tMIT\tnetwork\tcd /home/__USER__/repo && git push\n"
    );
    assert!(check_dir(&dir.0).is_ok());

    // Importing again adds nothing and keeps the file as it was.
    let again = import(
        &dir.0,
        &trace,
        &options(InputFormat::JsonLines {
            field: vec!["tool".into(), "command".into()],
        }),
    )
    .unwrap();
    assert_eq!((again.added, again.duplicates), (0, 2));
    assert_eq!(fs::read_to_string(dir.0.join("seed.txt")).unwrap(), written);
}

// Failure safety: a corpus file that fails the gate is never overwritten by an import.
#[test]
fn import_refuses_to_overwrite_an_invalid_corpus_file() {
    let dir = TempDir::new("corrupt");
    fs::write(dir.0.join("sources.tsv"), REGISTRY).unwrap();
    let corrupt = "# knsh-corpus 1\nseed\tMIT\t-\tcd /Users/alice\n";
    fs::write(dir.0.join("seed.txt"), corrupt).unwrap();
    let trace = dir.0.join("trace.txt");
    fs::write(&trace, "ls\n").unwrap();
    let err = import(&dir.0, &trace, &options(InputFormat::Lines)).unwrap_err();
    assert!(matches!(err, CorpusError::At { line: 2, .. }), "{err}");
    assert_eq!(fs::read_to_string(dir.0.join("seed.txt")).unwrap(), corrupt);
}

#[test]
fn import_rejects_unregistered_source_and_malformed_json() {
    let dir = TempDir::new("reject");
    fs::write(dir.0.join("sources.tsv"), REGISTRY).unwrap();
    let trace = dir.0.join("trace.jsonl");
    fs::write(&trace, "{\"command\":\"ls\"}\n{not json\n").unwrap();
    let mut opts = options(InputFormat::JsonLines {
        field: vec!["command".into()],
    });
    let err = import(&dir.0, &trace, &opts).unwrap_err();
    assert!(matches!(err, CorpusError::Json { line: 2, .. }), "{err}");
    assert!(!dir.0.join("seed.txt").exists());
    opts.source = "ghost".into();
    assert!(matches!(
        import(&dir.0, &trace, &opts).unwrap_err(),
        CorpusError::Entry(_)
    ));
}
