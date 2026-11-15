//! Golden-file test (KNSH-044): the example profile of `specs/05-models/policy-profile.md`, compiled, is byte for byte
//! `tests/golden/web-app.sb`. A change to the compiler's output shows up as a diff of that file in review.
//!
//! To accept a deliberate change, run the test with `KNSH_BLESS=1` and review the rewritten file.

// Test helpers outside `#[test]` functions: a failed step should stop the test.
#![allow(clippy::unwrap_used)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use knsh_core::{
    CanonicalPath, LookupError, PathContext, PolicyFs, ProfileName, ProfileSource, RecordId, SessionId, Ulid,
    load_profile,
};
use knsh_sandbox::{CommandTag, ProfileInput, compile};

/// The policy profile models page; its first TOML block is the example profile.
const MODELS_PAGE: &str = include_str!("../../../specs/05-models/policy-profile.md");

/// Every path exists and is already canonical.
struct Canonical;

impl PolicyFs for Canonical {
    fn canonicalise(&self, path: &Path) -> Result<CanonicalPath, LookupError> {
        CanonicalPath::new(path).map_err(|_| LookupError::Failed)
    }
}

/// Profiles by name.
struct Source(BTreeMap<&'static str, String>);

impl ProfileSource for Source {
    fn read_profile(&self, name: &ProfileName) -> Result<Vec<u8>, LookupError> {
        self.0
            .get(name.as_str())
            .map(|text| text.clone().into_bytes())
            .ok_or(LookupError::NotFound)
    }
}

fn example() -> String {
    let start = MODELS_PAGE.find("```toml\n").unwrap() + "```toml\n".len();
    let len = MODELS_PAGE[start..].find("```").unwrap();
    MODELS_PAGE[start..start + len].to_owned()
}

#[test]
fn example_profile_matches_golden_file() {
    let source = Source(BTreeMap::from([
        ("web-app", example()),
        ("base", "name = \"base\"\n".to_owned()),
    ]));
    let context = PathContext {
        home: PathBuf::from("/Users/u"),
        tmpdir: PathBuf::from("/private/var/folders/xy/T"),
        start_dir: PathBuf::from("/Users/u/src/app"),
    };
    let profile = load_profile(&ProfileName::new("web-app").unwrap(), &source, &context, &Canonical).unwrap();
    let home = CanonicalPath::new("/Users/u").unwrap();
    let text = compile(&ProfileInput {
        session: SessionId::from_ulid(Ulid::from_u128(1)),
        command: CommandTag::Line(RecordId::from_ulid(Ulid::from_u128(2))),
        profile: &profile,
        home: &home,
    });

    let golden = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/golden/web-app.sb");
    if std::env::var_os("KNSH_BLESS").is_some() {
        std::fs::write(&golden, text.as_bytes()).unwrap();
    }
    let expected = std::fs::read(&golden).unwrap();
    assert_eq!(
        String::from_utf8_lossy(text.as_bytes()),
        String::from_utf8_lossy(&expected),
        "compiled profile differs from {}; rerun with KNSH_BLESS=1 to accept",
        golden.display()
    );
}
