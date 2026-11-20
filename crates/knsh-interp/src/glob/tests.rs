//! Pathname expansion over an in-memory tree (KNSH-098; NFR-COMPAT-02). Every expected list is bash 5.2's output for
//! the same tree, sorted as bash sorts in the C and UTF-8 locales on macOS.

use std::path::Path;

use knsh_platform::testing::MemFs;

use super::*;

/// A working directory `/w` holding `entries`: a name ending in `/` is a directory, `name -> target` a symlink,
/// anything else an empty file.
fn tree(entries: &[&str]) -> MemFs {
    let fs = MemFs::new();
    fs.add_dir_all(Path::new("/w")).unwrap();
    for entry in entries {
        let at = |name: &str| Path::new("/w").join(name);
        if let Some((name, target)) = entry.split_once(" -> ") {
            fs.add_symlink(&at(name), Path::new(target)).unwrap();
        } else if let Some(dir) = entry.strip_suffix('/') {
            fs.add_dir_all(&at(dir)).unwrap();
        } else {
            fs.write(&at(entry), b"", 0o644).unwrap();
        }
    }
    fs
}

/// A pattern with every character unquoted, except those after a backslash.
fn chars(text: &str) -> Vec<WordChar> {
    crate::pattern::tests::chars(text)
}

fn matches_with(fs: &MemFs, pattern: &str, options: &Options) -> Vec<String> {
    glob(fs, Path::new("/w"), &chars(pattern), options, Span::new(0, 0)).unwrap()
}

fn matches(fs: &MemFs, pattern: &str) -> Vec<String> {
    matches_with(fs, pattern, &Options::default())
}

/// No match.
const NONE: [&str; 0] = [];

const TREE: &[&str] = &[
    "a.rs",
    "b.rs",
    "B.txt",
    ".hidden",
    ".git/",
    ".git/config",
    "src/",
    "src/main.rs",
    "src/lib.rs",
    "src/deep/",
    "src/deep/x.rs",
    "src/.secret/",
    "src/.secret/y.rs",
    "docs/",
    "docs/readme.md",
    "link -> /w/src",
];

#[test]
fn stars_questions_and_brackets_match_names_sorted_bytewise() {
    let fs = tree(TREE);
    assert_eq!(matches(&fs, "*.rs"), ["a.rs", "b.rs"]);
    assert_eq!(matches(&fs, "?.*"), ["B.txt", "a.rs", "b.rs"]);
    assert_eq!(matches(&fs, "[ab].rs"), ["a.rs", "b.rs"]);
    assert_eq!(matches(&fs, "[!a]*"), ["B.txt", "b.rs", "docs", "link", "src"]);
    assert_eq!(matches(&fs, "*"), ["B.txt", "a.rs", "b.rs", "docs", "link", "src"]);
    assert_eq!(matches(&fs, "src/*.rs"), ["src/lib.rs", "src/main.rs"]);
    assert_eq!(
        matches(&fs, "*/*.rs"),
        ["link/lib.rs", "link/main.rs", "src/lib.rs", "src/main.rs"]
    );
    assert_eq!(matches(&fs, "*/deep/x.rs"), ["link/deep/x.rs", "src/deep/x.rs"]);
    // Quoted pattern characters match only themselves.
    assert_eq!(matches(&fs, r"\*.rs"), NONE);
}

#[test]
fn a_trailing_slash_matches_only_directories() {
    let fs = tree(TREE);
    // A symlink to a directory is one.
    assert_eq!(matches(&fs, "*/"), ["docs/", "link/", "src/"]);
    assert_eq!(matches(&fs, "s*//"), ["src//"]);
}

#[test]
fn absolute_patterns_keep_their_slashes() {
    let fs = tree(TREE);
    assert_eq!(matches(&fs, "/w/s*"), ["/w/src"]);
    assert_eq!(matches(&fs, "/w//src/m*"), ["/w//src/main.rs"]);
}

// KNSH-098 unit test named by the story: without nullglob or failglob the caller keeps the word as written.
#[test]
fn unmatched_glob_stays_literal() {
    let fs = tree(TREE);
    assert_eq!(matches(&fs, "*.zig"), NONE);
    assert_eq!(matches(&fs, "nope/*"), NONE);
    // A literal last component must exist; an earlier one need only lead somewhere.
    assert_eq!(matches(&fs, "*/main.zig"), NONE);
    assert_eq!(matches(&fs, "s?c/main.rs"), ["src/main.rs"]);
}

// KNSH-098 unit test named by the story.
#[test]
fn dotglob_includes_hidden_files() {
    let fs = tree(TREE);
    assert!(!matches(&fs, "*").iter().any(|name| name.starts_with('.')));
    assert_eq!(matches(&fs, ".*"), [".git", ".hidden"]);
    assert_eq!(matches(&fs, r"\.h*"), [".hidden"]);
    let dotglob = Options {
        dotglob: true,
        ..Options::default()
    };
    assert_eq!(
        matches_with(&fs, "*", &dotglob),
        [".git", ".hidden", "B.txt", "a.rs", "b.rs", "docs", "link", "src"]
    );
    assert_eq!(matches_with(&fs, "src/*/", &dotglob), ["src/.secret/", "src/deep/"]);
    // `.` and `..` never match (bash 5.2's globskipdots).
    assert_eq!(matches(&fs, ".*"), [".git", ".hidden"]);
}

#[test]
fn nocaseglob_ignores_case() {
    let fs = tree(TREE);
    let nocase = Options {
        nocaseglob: true,
        ..Options::default()
    };
    assert_eq!(matches_with(&fs, "b*", &nocase), ["B.txt", "b.rs"]);
    assert_eq!(matches(&fs, "b*"), ["b.rs"]);
}

// KNSH-098 unit test named by the story.
#[test]
fn globstar_matches_recursively() {
    let fs = tree(TREE);
    let globstar = Options {
        globstar: true,
        ..Options::default()
    };
    // Without globstar, `**` is `*`.
    assert_eq!(
        matches(&fs, "**/*.rs"),
        ["link/lib.rs", "link/main.rs", "src/lib.rs", "src/main.rs"]
    );
    // Any depth, none included; symlinks are not followed and hidden directories not entered.
    assert_eq!(
        matches_with(&fs, "**/*.rs", &globstar),
        ["a.rs", "b.rs", "src/deep/x.rs", "src/lib.rs", "src/main.rs"]
    );
    assert_eq!(
        matches_with(&fs, "**", &globstar),
        [
            "B.txt",
            "a.rs",
            "b.rs",
            "docs",
            "docs/readme.md",
            "link",
            "src",
            "src/deep",
            "src/deep/x.rs",
            "src/lib.rs",
            "src/main.rs"
        ]
    );
    assert_eq!(matches_with(&fs, "**/", &globstar), ["docs/", "src/", "src/deep/"]);
    assert_eq!(
        matches_with(&fs, "src/**", &globstar),
        ["src/", "src/deep", "src/deep/x.rs", "src/lib.rs", "src/main.rs"]
    );
    assert_eq!(matches_with(&fs, "src/**/x.rs", &globstar), ["src/deep/x.rs"]);
    assert_eq!(matches_with(&fs, "/w/**/x.rs", &globstar), ["/w/src/deep/x.rs"]);
    // With dotglob, hidden directories are entered too.
    let both = Options {
        globstar: true,
        dotglob: true,
        ..Options::default()
    };
    assert_eq!(
        matches_with(&fs, "**/*.rs", &both),
        [
            "a.rs",
            "b.rs",
            "src/.secret/y.rs",
            "src/deep/x.rs",
            "src/lib.rs",
            "src/main.rs"
        ]
    );
}

// KNSH-098 unit test named by the story.
#[test]
fn extglob_patterns_match_like_bash() {
    let fs = tree(TREE);
    let extglob = Options {
        extglob: true,
        ..Options::default()
    };
    assert_eq!(matches_with(&fs, "@(a|b).rs", &extglob), ["a.rs", "b.rs"]);
    assert_eq!(matches_with(&fs, "!(*.rs)", &extglob), ["B.txt", "docs", "link", "src"]);
    assert_eq!(matches_with(&fs, "+([a-z]).rs", &extglob), ["a.rs", "b.rs"]);
    assert_eq!(
        matches_with(&fs, "src/?(lib|main).rs", &extglob),
        ["src/lib.rs", "src/main.rs"]
    );
    assert_eq!(matches_with(&fs, "*(x)", &extglob), Vec::<String>::new());
    // A group with an alternative starting with `.` may match hidden names; `!(…)` never does.
    assert_eq!(matches_with(&fs, "@(.hidden|a.rs)", &extglob), [".hidden", "a.rs"]);
    assert!(
        !matches_with(&fs, "!(x)", &extglob)
            .iter()
            .any(|name| name.starts_with('.'))
    );
}

#[test]
fn globignore_removes_matches_and_implies_dotglob() {
    let fs = tree(TREE);
    let ignore = Options {
        ignore: vec![
            Pattern::new(&chars("*.rs"), Flags::default()),
            Pattern::new(&chars("l*"), Flags::default()),
        ],
        ..Options::default()
    };
    assert_eq!(
        matches_with(&fs, "*", &ignore),
        [".git", ".hidden", "B.txt", "docs", "src"]
    );
}

// Fail closed: a matching name that is not UTF-8 is refused rather than dropped or mangled.
#[test]
fn a_matching_name_that_is_not_utf8_is_refused() {
    use std::os::unix::ffi::OsStrExt;

    let fs = tree(&[]);
    fs.write(&Path::new("/w").join(std::ffi::OsStr::from_bytes(b"x\xff")), b"", 0o644)
        .unwrap();
    let found = glob(&fs, Path::new("/w"), &chars("x*"), &Options::default(), Span::new(3, 5));
    assert_eq!(
        found,
        Err(InterpError::Unsupported {
            feature: Unsupported::NonUtf8FileName,
            span: Span::new(3, 5)
        })
    );
    assert_eq!(matches(&fs, "y*"), NONE);
}

// A file name that is not UTF-8 only matters when it is matched: `**/` reaches directories, so a file below does
// not stop it, while a directory that is not UTF-8 is still refused (KNSH-098).
#[test]
fn globstar_ignores_non_utf8_names_it_does_not_reach() {
    use std::os::unix::ffi::OsStrExt;

    let fs = tree(&["src/", "src/a.rs"]);
    fs.write(
        &Path::new("/w/src").join(std::ffi::OsStr::from_bytes(b"x\xff")),
        b"",
        0o644,
    )
    .unwrap();
    let globstar = Options {
        globstar: true,
        ..Options::default()
    };
    assert_eq!(matches_with(&fs, "**/*.rs", &globstar), ["src/a.rs"]);
    assert_eq!(matches_with(&fs, "**/", &globstar), ["src/"]);
    assert!(matches!(
        glob(&fs, Path::new("/w"), &chars("**"), &globstar, Span::new(0, 0)),
        Err(InterpError::Unsupported {
            feature: Unsupported::NonUtf8FileName,
            ..
        })
    ));
    fs.add_dir_all(&Path::new("/w").join(std::ffi::OsStr::from_bytes(b"d\xff")))
        .unwrap();
    assert!(matches!(
        glob(&fs, Path::new("/w"), &chars("**/"), &globstar, Span::new(0, 0)),
        Err(InterpError::Unsupported {
            feature: Unsupported::NonUtf8FileName,
            ..
        })
    ));
}

// Bash skips a directory it cannot read: the pattern then matches nothing there.
#[test]
fn an_unreadable_directory_matches_nothing() {
    /// `EACCES` on macOS and Linux.
    const EACCES: i32 = 13;
    let fs = tree(TREE);
    fs.inject_fault(knsh_platform::Operation::ReadDirectory, EACCES);
    assert_eq!(matches(&fs, "*"), NONE);
}
