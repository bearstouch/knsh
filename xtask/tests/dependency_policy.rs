//! Dependency policy checks for the whole workspace (NFR-SUP-01, NFR-SUP-02).
//!
//! These tests read `Cargo.lock` and crate manifests directly. `cargo metadata` would be the natural tool, but parsing
//! the files by hand keeps the check free of extra crates (KNSH-001 notes). `Cargo.lock` is used rather than the
//! manifests because it is the resolved graph that actually gets built, including transitive dependencies.

// The whole file is test code: this lets clippy's `allow-*-in-tests` settings (clippy.toml) cover the helpers too,
// so `unwrap`, `expect` and `panic` stay denied everywhere outside tests.
#![cfg(test)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

/// The only third-party runtime crate allowed in the workspace (supply-chain.md).
const ALLOWED_THIRD_PARTY: &str = "libc";

/// The only registry third-party crates may come from (vendored in `vendor/`).
const CRATES_IO: &str = "registry+https://github.com/rust-lang/crates.io-index";

/// The only workspace crate allowed to depend on `libc` (CLAUDE.md workspace layout).
const LIBC_USER: &str = "knsh-platform";

/// The workspace layout table from `CLAUDE.md`: each crate and the workspace crates (or `libc`) it may depend on.
/// Dependencies point downwards only, so any edge not listed here (an upward edge or a cycle) fails the test.
const LAYOUT: &[(&str, &[&str])] = &[
    ("knsh-core", &["knsh-bash", "knsh-json", "knsh-toml"]),
    ("knsh-bash", &[]),
    ("knsh-json", &[]),
    ("knsh-toml", &[]),
    // knsh-bash only as a dev-dependency: a classified line for the hook input test (KNSH-062).
    ("knsh-proto", &["knsh-json", "knsh-core", "knsh-bash"]),
    // knsh-json reads the sandbox violation reader's `log stream` entries (KNSH-047).
    ("knsh-platform", &["knsh-core", "knsh-json", "libc"]),
    ("knsh-sandbox", &["knsh-core"]),
    ("knsh-proxy", &["knsh-core", "knsh-platform"]),
    ("knsh-store", &["knsh-core", "knsh-platform"]),
    ("knsh-checkpoint", &["knsh-core", "knsh-json", "knsh-platform"]),
    (
        "knshd",
        &[
            "knsh-core",
            // The frame codec and JSON values its connection server reads and writes (KNSH-013).
            "knsh-json",
            "knsh-proto",
            "knsh-platform",
            "knsh-sandbox",
            "knsh-proxy",
            "knsh-store",
            "knsh-checkpoint",
            // The `[[hooks]]` of the user's configuration file (KNSH-062).
            "knsh-toml",
            // Dev-dependency only: classified lines for the hook runner tests (KNSH-062).
            "knsh-bash",
        ],
    ),
    // knsh-platform for engine paths and the launchd agent behind `knsh daemon install` (KNSH-012).
    (
        "knsh",
        &["knsh-proto", "knsh-json", "knsh-core", "knsh-platform", "knsh-toml"],
    ),
    ("knsh-exec", &[]),
    // Dev-only checks crate: depends on nothing, and nothing may depend on it.
    ("xtask", &[]),
    // Dev-only corpus tool (KNSH-033): reads trajectory JSON; nothing may depend on it.
    ("knsh-corpus", &["knsh-json"]),
    // Dev-only differential harness (KNSH-034): parses corpus lines and compares with bash; nothing may depend on it.
    ("knsh-difftest", &["knsh-bash", "knsh-corpus"]),
];

/// One `[[package]]` entry of `Cargo.lock`.
#[derive(Debug)]
struct LockPackage {
    name: String,
    /// `None` for workspace (path) packages; `Some` for anything fetched from a registry or git.
    source: Option<String>,
    /// Names of the packages this one depends on (versions and sources stripped).
    dependencies: Vec<String>,
}

fn workspace_root() -> PathBuf {
    // xtask sits directly under the workspace root.
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask has a parent directory")
        .to_path_buf()
}

fn read(path: &Path) -> String {
    fs::read_to_string(path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()))
}

/// Returns the string value of a `key = "value"` line, or `None` if the line is not that key.
fn string_value<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let rest = line.strip_prefix(key)?.trim_start().strip_prefix('=')?.trim();
    rest.strip_prefix('"')?.strip_suffix('"')
}

/// Parses the subset of the `Cargo.lock` (version 3/4) format needed here: `[[package]]` tables with `name`,
/// `source` and a `dependencies` array that may span several lines. Unknown keys are ignored. Panics on anything it
/// does not understand inside a dependencies array, so a format change fails loudly instead of passing silently.
fn parse_lock(text: &str) -> Vec<LockPackage> {
    let mut packages = Vec::new();
    let mut current: Option<LockPackage> = None;
    let mut in_deps = false;

    for raw in text.lines() {
        let line = raw.trim();
        if in_deps {
            if line == "]" {
                in_deps = false;
                continue;
            }
            let entry = line
                .trim_end_matches(',')
                .strip_prefix('"')
                .and_then(|s| s.strip_suffix('"'))
                .unwrap_or_else(|| panic!("unexpected line in dependencies array: {raw:?}"));
            // Entries are `name`, `name version` or `name version (source)`; only the name matters here.
            let name = entry.split_whitespace().next().expect("dependency entry has a name");
            current
                .as_mut()
                .expect("dependencies inside a package")
                .dependencies
                .push(name.to_owned());
            continue;
        }
        // Any table header closes the current package; only `[[package]]` opens a new one, so the trailing
        // `[metadata]` table (older lock formats) is skipped.
        if line.starts_with('[') {
            packages.extend(current.take());
            if line == "[[package]]" {
                current = Some(LockPackage {
                    name: String::new(),
                    source: None,
                    dependencies: Vec::new(),
                });
            }
            continue;
        }
        let Some(pkg) = current.as_mut() else { continue };
        if let Some(name) = string_value(line, "name") {
            name.clone_into(&mut pkg.name);
        } else if let Some(source) = string_value(line, "source") {
            pkg.source = Some(source.to_owned());
        } else if line.starts_with("dependencies") {
            assert!(
                line.ends_with('['),
                "single-line dependencies arrays are not expected: {raw:?}"
            );
            in_deps = true;
        }
    }
    packages.extend(current);
    assert!(!in_deps, "unterminated dependencies array in Cargo.lock");
    assert!(
        packages.iter().all(|p| !p.name.is_empty()),
        "package without a name in Cargo.lock"
    );
    packages
}

fn lock_packages() -> Vec<LockPackage> {
    let packages = parse_lock(&read(&workspace_root().join("Cargo.lock")));
    // Guard against a vacuous pass on an empty or unparsed lock file.
    assert!(
        packages.iter().any(|p| p.name == LIBC_USER),
        "Cargo.lock does not list {LIBC_USER}"
    );
    packages
}

// NFR-SUP-01, NFR-SUP-02: `libc` is the only third-party crate, and only `knsh-platform` uses it.
#[test]
fn workspace_has_no_third_party_runtime_deps_except_libc() {
    let packages = lock_packages();

    // A package is allowed only if it is `libc` from crates.io: a `libc` from git or another registry is a different
    // crate under the same name and fails too.
    let forbidden: Vec<String> = packages
        .iter()
        .filter_map(|p| {
            let source = p.source.as_deref()?;
            (p.name != ALLOWED_THIRD_PARTY || source != CRATES_IO).then(|| format!("{} ({source})", p.name))
        })
        .collect();
    assert!(
        forbidden.is_empty(),
        "third-party crates other than {ALLOWED_THIRD_PARTY} from crates.io in Cargo.lock: {forbidden:?}"
    );

    let libc_users: Vec<&str> = packages
        .iter()
        .filter(|p| p.dependencies.iter().any(|d| d == ALLOWED_THIRD_PARTY))
        .map(|p| p.name.as_str())
        .collect();
    assert_eq!(
        libc_users,
        [LIBC_USER],
        "only {LIBC_USER} may depend on {ALLOWED_THIRD_PARTY}"
    );
}

// NFR-SUP-01: `knsh-exec` has no dependencies of any kind, not even workspace crates.
#[test]
fn knsh_exec_has_no_dependencies() {
    let manifest = read(&workspace_root().join("crates/knsh-exec/Cargo.toml"));

    // Any dependency table (`[dependencies]`, `[dev-dependencies]`, `[build-dependencies]`,
    // `[target.'cfg(..)'.dependencies]`) must be absent or empty.
    let mut table: Option<&str> = None;
    for raw in manifest.lines() {
        let line = raw.trim();
        if line.starts_with('[') {
            table = Some(line);
            continue;
        }
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(header) = table {
            // `contains`, not `ends_with`: `[dependencies.foo]` also declares a dependency.
            assert!(!header.contains("dependencies"), "knsh-exec declares {header}: {raw:?}");
        }
        // Catches dotted keys such as `dependencies.foo = ...` that declare a dependency without a table header.
        assert!(
            !line.contains("dependencies"),
            "knsh-exec manifest mentions dependencies: {raw:?}"
        );
    }

    let packages = lock_packages();
    let exec = packages
        .iter()
        .find(|p| p.name == "knsh-exec")
        .expect("knsh-exec is in Cargo.lock");
    assert!(
        exec.dependencies.is_empty(),
        "knsh-exec resolves dependencies: {:?}",
        exec.dependencies
    );
}

// CLAUDE.md workspace layout: dependencies point downwards only, with no cycles.
#[test]
fn workspace_dependency_graph_matches_layout_table() {
    let layout: BTreeMap<&str, BTreeSet<&str>> = LAYOUT
        .iter()
        .map(|(name, deps)| (*name, deps.iter().copied().collect()))
        .collect();
    let packages = lock_packages();
    let workspace: Vec<&LockPackage> = packages.iter().filter(|p| p.source.is_none()).collect();

    let found: BTreeSet<&str> = workspace.iter().map(|p| p.name.as_str()).collect();
    let expected: BTreeSet<&str> = layout.keys().copied().collect();
    assert_eq!(found, expected, "workspace crates differ from the layout table");

    for pkg in workspace {
        let allowed = &layout[pkg.name.as_str()];
        for dep in &pkg.dependencies {
            assert!(
                allowed.contains(dep.as_str()),
                "{} may not depend on {dep} (layout table)",
                pkg.name
            );
        }
    }
}

mod parser_tests {
    use super::parse_lock;

    const SAMPLE: &str = r#"
version = 4

[[package]]
name = "a"
version = "0.1.0"
dependencies = [
 "b",
 "libc 0.2.191 (registry+https://github.com/rust-lang/crates.io-index)",
]

[[package]]
name = "libc"
version = "0.2.191"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "00"

[metadata]
"#;

    #[test]
    fn parses_names_sources_and_multiline_dependencies() {
        let packages = parse_lock(SAMPLE);
        assert_eq!(packages.len(), 2);
        assert_eq!(packages[0].name, "a");
        assert_eq!(packages[0].source, None);
        assert_eq!(packages[0].dependencies, ["b", "libc"]);
        assert_eq!(packages[1].name, "libc");
        assert!(packages[1].source.is_some());
        assert_eq!(packages[1].dependencies.len(), 0);
    }

    #[test]
    #[should_panic(expected = "unterminated dependencies array")]
    fn rejects_unterminated_dependencies_array() {
        parse_lock("[[package]]\nname = \"a\"\ndependencies = [\n \"b\",\n");
    }
}
