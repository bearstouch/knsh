//! File-rule compiler tests (KNSH-044): the story's unit tests, a property test over random paths, and a small SBPL
//! reader that checks every compiled profile is balanced and that each string decodes to the path it was given.

use std::path::{Path, PathBuf};

use knsh_core::{
    CanonicalPath, LookupError, PathContext, PolicyFs, Profile, ProfileName, ProfileSource, ReadScope, RecordId,
    SessionId, Ulid, load_profile_text,
};

use super::*;

/// Every path exists and is already canonical: the loader's view of a filesystem without symlinks.
struct Canonical;

impl PolicyFs for Canonical {
    fn canonicalise(&self, path: &Path) -> Result<CanonicalPath, LookupError> {
        CanonicalPath::new(path).map_err(|_| LookupError::Failed)
    }
}

/// No parents.
struct NoParents;

impl ProfileSource for NoParents {
    fn read_profile(&self, _name: &ProfileName) -> Result<Vec<u8>, LookupError> {
        Err(LookupError::NotFound)
    }
}

const HOME: &str = "/Users/u";

fn canonical(path: &str) -> CanonicalPath {
    CanonicalPath::new(path).unwrap()
}

/// A profile read through the real loader, with `~` at [`HOME`] and `${PROJECT}` at `/Users/u/app`.
fn profile(text: &str) -> Profile {
    let context = PathContext {
        home: PathBuf::from(HOME),
        tmpdir: PathBuf::from("/private/tmp"),
        start_dir: PathBuf::from("/Users/u/app"),
    };
    let text = format!("name = \"t\"\n{text}");
    load_profile_text(text.as_bytes(), &NoParents, &context, &Canonical).unwrap()
}

fn session() -> SessionId {
    SessionId::from_ulid(Ulid::from_u128(1))
}

fn record() -> RecordId {
    RecordId::from_ulid(Ulid::from_u128(2))
}

/// `profile` compiled for a supervised line of the test session, as text.
fn compiled(profile: &Profile) -> String {
    compiled_for(profile, CommandTag::Line(record()))
}

/// `profile` compiled for `command` in the test session, as text.
fn compiled_for(profile: &Profile, command: CommandTag) -> String {
    let home = canonical(HOME);
    let text = compile(&ProfileInput {
        session: session(),
        command,
        profile,
        home: &home,
    });
    String::from_utf8(text.into_bytes()).unwrap()
}

/// The prefix of every tag in [`compiled`] profiles.
fn tag() -> String {
    format!("knsh:{}:{}:", session(), record())
}

/// One top-level form of a profile, as read back: its words outside strings (operations, filters, parentheses
/// dropped), its decoded strings and its regex literals, in order.
#[derive(Debug, Default)]
struct Form {
    words: Vec<String>,
    strings: Vec<Vec<u8>>,
    regexes: Vec<String>,
}

/// Reads `text` as SBPL: top-level forms, with strings decoded (`\x` is `x`) and `#"…"` regex literals kept raw.
/// Panics on unbalanced parentheses, an unterminated string or text between forms, so a profile that reads back at
/// all is well formed.
fn read(text: &[u8]) -> Vec<Form> {
    let mut forms = Vec::new();
    let mut depth = 0usize;
    let mut form = Form::default();
    let mut word = String::new();
    let mut bytes = text.iter().copied();
    while let Some(byte) = bytes.next() {
        match byte {
            b'"' if word == "#" => {
                word.clear();
                let regex: Vec<u8> = bytes.by_ref().take_while(|&byte| byte != b'"').collect();
                form.regexes.push(String::from_utf8(regex).unwrap());
            }
            b'"' => {
                let mut string = Vec::new();
                loop {
                    match bytes.next().expect("unterminated string") {
                        b'"' => break,
                        b'\\' => string.push(bytes.next().expect("dangling escape")),
                        other => string.push(other),
                    }
                }
                form.strings.push(string);
            }
            b'(' | b')' | b' ' | b'\n' => {
                if !word.is_empty() {
                    form.words.push(std::mem::take(&mut word));
                }
                if byte == b'(' {
                    depth += 1;
                } else if byte == b')' {
                    depth = depth.checked_sub(1).expect("unbalanced )");
                    if depth == 0 {
                        forms.push(std::mem::take(&mut form));
                    }
                }
            }
            other => {
                assert!(depth > 0, "text outside a form");
                word.push(char::from(other));
            }
        }
    }
    assert_eq!(depth, 0, "unbalanced (");
    forms
}

/// The forms of `text` whose first word is `deny`.
fn denies(text: &str) -> Vec<Form> {
    read(text.as_bytes())
        .into_iter()
        .filter(|form| form.words.first().is_some_and(|word| word == "deny"))
        .collect()
}

/// The forms of `text` that allow writes.
fn write_allows(text: &str) -> Vec<Form> {
    read(text.as_bytes())
        .into_iter()
        .filter(|form| form.words.starts_with(&["allow".to_owned(), "file-write*".to_owned()]))
        .collect()
}

/// The deny whose tag names `rule`.
fn deny_tagged(text: &str, rule: &str) -> Form {
    let wanted = format!("{}{rule}", tag()).into_bytes();
    denies(text)
        .into_iter()
        .find(|form| form.strings.last() == Some(&wanted))
        .unwrap_or_else(|| panic!("no deny tagged {rule}"))
}

/// Tiny deterministic generator (xorshift64*), so the property test needs no test-only crate.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: usize) -> usize {
        usize::try_from(self.next() % u64::try_from(n).unwrap()).unwrap()
    }

    /// A canonical path of one to four components drawn from characters that mean something in SBPL or a shell.
    fn path(&mut self) -> CanonicalPath {
        const CHARS: &[char] = &[
            'a', 'Z', '0', ' ', '"', '\\', '(', ')', ';', '#', '\n', '\t', 'é', '$', '*', '.',
        ];
        let mut path = String::new();
        for _ in 0..=self.below(4) {
            path.push('/');
            for _ in 0..=self.below(6) {
                path.push(CHARS[self.below(CHARS.len())]);
            }
            // `.` and `..` components are not canonical; give them a letter.
            if path.ends_with("/.") || path.ends_with("/..") {
                path.push('x');
            }
        }
        canonical(&path)
    }

    fn paths(&mut self) -> Vec<CanonicalPath> {
        (0..self.below(5)).map(|_| self.path()).collect()
    }
}

// KNSH-044: compiling is pure. The same input gives the same bytes, every time and from a copy, and every path in it
// reads back exactly as it was given, whatever characters it holds.
#[test]
fn compiles_deterministically() {
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    let base = profile("");
    for _ in 0..500 {
        let mut profile = base.clone();
        profile.fs.write = rng.paths();
        profile.fs.deny = rng.paths();
        profile.fs.read = if rng.below(2) == 0 {
            ReadScope::All
        } else {
            ReadScope::Paths(rng.paths())
        };
        let first = compiled(&profile);
        assert_eq!(first, compiled(&profile.clone()));

        let strings: Vec<Vec<u8>> = read(first.as_bytes())
            .into_iter()
            .flat_map(|form| form.strings)
            .collect();
        let reads = match &profile.fs.read {
            ReadScope::All => Vec::new(),
            ReadScope::Paths(paths) => paths.clone(),
        };
        for path in reads.iter().chain(&profile.fs.write).chain(&profile.fs.deny) {
            let wanted = path.as_path().as_os_str().as_encoded_bytes();
            assert!(strings.iter().any(|s| s == wanted), "{path:?} does not read back");
        }
    }
}

// FR-SBX-02: each write root becomes a write allow, in order; without roots only the devices are writable.
#[test]
fn write_roots_become_write_allows() {
    let text = compiled(&profile("[fs]\nwrite = [\"${PROJECT}\", \"/private/tmp\"]\n"));
    let allows = write_allows(&text);
    assert_eq!(allows.len(), 2);
    assert_eq!(allows[0].words, ["allow", "file-write*", "subpath", "subpath"]);
    assert_eq!(allows[0].strings, [b"/Users/u/app".to_vec(), b"/private/tmp".to_vec()]);
    // The second allows only the null devices and the process's own streams.
    assert!(allows[1].strings.iter().all(|s| s.starts_with(b"/dev/")));
    assert_eq!(allows[1].regexes, ["^/dev/fd/[0-9]+$"]);

    let none = compiled(&profile(""));
    assert_eq!(write_allows(&none).len(), 1, "only the devices");
}

// FR-POL-12, FR-SBX-02: reads are everything (or the listed paths), except `fs.deny`, which is denied for reading
// and writing after the allows, one tagged rule per entry.
#[test]
fn fs_deny_paths_denied_for_read_and_write() {
    let text = compiled(&profile("[fs]\nwrite = [\"~\"]\ndeny = [\"~/.aws\", \"~/.netrc\"]\n"));
    assert!(text.contains("\n(allow file-read*)\n"));
    for (index, path) in ["/Users/u/.aws", "/Users/u/.netrc"].into_iter().enumerate() {
        let deny = deny_tagged(&text, &format!("fs.deny[{index}]"));
        assert_eq!(
            deny.words,
            ["deny", "file-read*", "file-write*", "subpath", "with", "message"]
        );
        assert_eq!(deny.strings[0], path.as_bytes());
    }
    let allow_at = text.find("(allow file-write* (subpath \"/Users/u\")").unwrap();
    assert!(text.find("fs.deny[0]").unwrap() > allow_at, "denies come after allows");

    let listed = compiled(&profile("[fs]\nread = [\"/usr\", \"${PROJECT}\"]\n"));
    assert!(listed.contains("(allow file-read* (subpath \"/usr\") (subpath \"/Users/u/app\"))"));
    assert!(!listed.contains("(allow file-read*)"));
    let nothing = compiled(&profile("[fs]\nread = []\n"));
    assert!(
        !nothing.contains("(allow file-read*"),
        "an empty read list allows no reads"
    );
}

// FR-SBX-02: the fixed write denies are in every profile, after every allow, even one that allows writing everywhere.
#[test]
fn fixed_write_denies_always_present() {
    for text in [compiled(&profile("")), compiled(&profile("[fs]\nwrite = [\"/\"]\n"))] {
        let git = deny_tagged(&text, "fixed.git");
        assert_eq!(git.words[..2], ["deny", "file-write*"]);
        assert_eq!(
            git.regexes,
            [
                r"/\.git$",
                r"/\.git/(.+/)?hooks(/|$)",
                r"/\.git/(.+/)?(config|config\.worktree|commondir)$",
                r"/\.git/(.+/)?(modules|worktrees)(/[^/]+)?$",
            ]
        );
        let startup = deny_tagged(&text, "fixed.shell-startup");
        for name in [".zshrc", ".zprofile", ".zshenv", ".bashrc", ".bash_profile", ".profile"] {
            let path = format!("{HOME}/{name}").into_bytes();
            assert!(startup.strings.contains(&path), "{name}");
        }
        assert_eq!(
            deny_tagged(&text, "fixed.launch-agents").strings[0],
            b"/Users/u/Library/LaunchAgents"
        );
        assert_eq!(deny_tagged(&text, "fixed.ssh").strings[0], b"/Users/u/.ssh");
        // Every directory above a protected path is protected itself, so it cannot be renamed away and back.
        let ancestors = deny_tagged(&text, "fixed.ancestors");
        assert!(
            ancestors.words[2..]
                .iter()
                .take(ancestors.strings.len() - 1)
                .all(|w| w == "literal")
        );
        for path in [
            "/",
            "/Users",
            "/Users/u",
            "/Users/u/Library",
            "/Users/u/Library/Application Support",
            "/Users/u/.config",
        ] {
            assert!(ancestors.strings.contains(&path.as_bytes().to_vec()), "{path}");
        }

        let last_allow = text.rfind("(allow").unwrap();
        let first_fixed = text.find("fixed.git").unwrap();
        assert!(first_fixed > last_allow, "fixed denies come after every allow");
    }
}

// FR-SBX-10, FR-POL-30: engine paths are denied for reading and writing, as the very last rule, even when the
// profile allows reading and writing the whole home.
#[test]
fn engine_paths_denied_even_if_input_allows() {
    let text = compiled(&profile("[fs]\nread = [\"~\"]\nwrite = [\"~\"]\n"));
    let engine = deny_tagged(&text, "fixed.engine");
    assert_eq!(engine.words[..3], ["deny", "file-read*", "file-write*"]);
    assert_eq!(
        engine.strings[..2],
        [
            b"/Users/u/Library/Application Support/knsh".to_vec(),
            b"/Users/u/.config/knsh".to_vec()
        ]
    );
    assert_eq!(
        text.lines().last().unwrap(),
        text.lines().find(|line| line.contains("fixed.engine")).unwrap()
    );
    // The input cannot add a rule after it: every profile ends with the engine deny.
    let mut profile = profile("");
    profile.fs.write = vec![canonical("/Users/u/Library/Application Support/knsh")];
    let text = compiled(&profile);
    assert!(text.trim_end().ends_with(&format!("{}fixed.engine\"))", tag())));
}

// NFR-SEC-03: a path is written as one string literal, with `\` and `"` escaped, so it can never end the string and
// be read as profile code.
#[test]
fn escapes_paths_with_quotes_and_backslashes() {
    let mut profile = profile("");
    let hostile = canonical(r#"/Users/u/a") (allow file-write* (subpath "/") \x"#);
    profile.fs.write = vec![hostile.clone()];
    profile.fs.deny = vec![canonical(r"/Users/u/back\slash")];
    let text = compiled(&profile);
    assert!(text.contains(r#"(subpath "/Users/u/a\") (allow file-write* (subpath \"/\") \\x")"#));
    assert!(text.contains(r#"(subpath "/Users/u/back\\slash")"#));
    // Read back, the hostile path is one string inside one allow; no extra allow appeared.
    let forms = read(text.as_bytes());
    let allows: Vec<&Form> = forms.iter().filter(|form| form.words[0] == "allow").collect();
    assert_eq!(allows.len(), 3, "reads, the write root, the devices");
    assert_eq!(
        allows[1].strings,
        [hostile.as_path().as_os_str().as_encoded_bytes().to_vec()]
    );
}

// FR-SBX-06: every deny, the default included, ends with a tag naming the session, the command and the rule.
#[test]
fn every_deny_rule_is_tagged() {
    let text = compiled(&profile("[fs]\nwrite = [\"~\"]\ndeny = [\"~/.aws\"]\n"));
    let denies = denies(&text);
    assert_eq!(
        denies.len(),
        8,
        "default, fs.deny[0], git, shell startup, launch agents, ssh, ancestors, engine"
    );
    let prefix = tag();
    for deny in &denies {
        let words = &deny.words;
        assert_eq!(words[words.len() - 2..], ["with", "message"], "{words:?}");
        let message = String::from_utf8(deny.strings.last().unwrap().clone()).unwrap();
        let rule = message.strip_prefix(&prefix).unwrap_or_else(|| panic!("{message}"));
        assert!(!rule.is_empty() && !rule.contains(':'), "{message}");
    }
    assert!(text.starts_with(&format!(
        "(version 1)\n(deny default (with message \"{prefix}default\"))\n"
    )));

    // The envelope is tagged `env` in place of a record.
    let envelope = compiled_for(&profile(""), CommandTag::Envelope);
    assert!(envelope.contains(&format!("\"knsh:{}:env:fixed.ssh\"", session())));
}
