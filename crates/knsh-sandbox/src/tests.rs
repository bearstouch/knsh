//! Compiler tests (KNSH-044, KNSH-045): the stories' unit tests, a property test over random paths, and a small SBPL
//! reader that checks every compiled profile is balanced and that each string decodes to the path it was given.

use std::num::NonZeroU16;
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
    compiled_with(profile, command, &[], None)
}

/// `profile` compiled for `command` with the supervisor's `executables` and proxy port, as text.
fn compiled_with(
    profile: &Profile,
    command: CommandTag,
    executables: &[CanonicalPath],
    proxy_port: Option<u16>,
) -> String {
    let home = canonical(HOME);
    let text = compile(&ProfileInput {
        session: session(),
        command,
        profile,
        home: &home,
        executables,
        proxy_port: proxy_port.map(|port| NonZeroU16::new(port).unwrap()),
    });
    String::from_utf8(text.into_bytes()).unwrap()
}

/// The prefix of every tag in [`compiled_for`] profiles of the envelope.
fn envelope_tag() -> String {
    format!("knsh:{}:env:", session())
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

/// Reads `text` as SBPL: top-level forms, with strings decoded (`\x` is `x`) and `#"…"` regex literals kept raw;
/// `;` comments (outside strings) run to the end of the line. Panics on unbalanced parentheses, an unterminated
/// string or text between forms, so a profile that reads back at all is well formed.
fn read(text: &[u8]) -> Vec<Form> {
    let mut forms = Vec::new();
    let mut depth = 0usize;
    let mut form = Form::default();
    let mut word = String::new();
    let mut bytes = text.iter().copied();
    while let Some(byte) = bytes.next() {
        match byte {
            b';' => {
                assert!(word.is_empty(), "comment inside a word");
                bytes.by_ref().take_while(|&byte| byte != b'\n').for_each(drop);
            }
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
    denies_tagged(text, rule)
        .into_iter()
        .next()
        .unwrap_or_else(|| panic!("no deny tagged {rule}"))
}

/// Every deny whose tag names `rule`, for a line or the envelope.
fn denies_tagged(text: &str, rule: &str) -> Vec<Form> {
    let wanted = [
        format!("{}{rule}", tag()).into_bytes(),
        format!("{}{rule}", envelope_tag()).into_bytes(),
    ];
    denies(text)
        .into_iter()
        .filter(|form| form.strings.last().is_some_and(|last| wanted.contains(last)))
        .collect()
}

/// The forms of `text` whose words start with `allow` and then `operation`.
fn allows_of(text: &str, operation: &str) -> Vec<Form> {
    read(text.as_bytes())
        .into_iter()
        .filter(|form| {
            form.words.first().is_some_and(|w| w == "allow") && form.words[1..].iter().any(|w| w == operation)
        })
        .collect()
}

/// The strings of every allow of `operation`, flattened.
fn allowed_strings(text: &str, operation: &str) -> Vec<Vec<u8>> {
    allows_of(text, operation)
        .into_iter()
        .flat_map(|form| form.strings)
        .collect()
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
        text.lines().find(|line| line.contains("fixed.engine\"")).unwrap()
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
    let hostile_bytes = hostile.as_path().as_os_str().as_encoded_bytes().to_vec();
    let forms = read(text.as_bytes());
    let writes: Vec<&Form> = forms
        .iter()
        .filter(|form| form.words.starts_with(&["allow".to_owned(), "file-write*".to_owned()]))
        .collect();
    assert_eq!(writes.len(), 2, "the write root, the devices");
    assert_eq!(writes[0].strings, std::slice::from_ref(&hostile_bytes));
    // It is a string everywhere it appears (the write root, its socket bind rule): never profile code.
    for form in &forms {
        if form.strings.contains(&hostile_bytes) {
            assert_eq!(form.words[0], "allow");
        }
    }
}

// FR-SBX-06: every deny, the default included, ends with a tag naming the session, the command and the rule.
#[test]
fn every_deny_rule_is_tagged() {
    let text = compiled(&profile("[fs]\nwrite = [\"~\"]\ndeny = [\"~/.aws\"]\n"));
    let denies = denies(&text);
    assert_eq!(
        denies.len(),
        19,
        "default, process.info, fs.deny[0], git, shell startup, launch agents, ssh, launch services, apple events, \
         launchd jobs, dns (2), control, process.sysctl, docker, ancestors, engine-bind, user-sock, engine"
    );
    let prefix = tag();
    for deny in &denies {
        let words = &deny.words;
        assert_eq!(words[words.len() - 2..], ["with", "message"], "{words:?}");
        let message = String::from_utf8(deny.strings.last().unwrap().clone()).unwrap();
        let rule = message.strip_prefix(&prefix).unwrap_or_else(|| panic!("{message}"));
        assert!(!rule.is_empty() && !rule.contains(':'), "{message}");
        // KNSH-047: the violation reader attributes a denial only by a tag `DenialTag` parses, back to these IDs.
        let parsed: knsh_core::DenialTag = message.parse().unwrap_or_else(|_| panic!("{message}"));
        assert_eq!(parsed.session_id, session());
        assert_eq!(parsed.rule.as_str(), rule);
        assert_eq!(parsed.to_string(), message);
    }
    assert!(text.starts_with("(version 1)\n;; knsh command profile t,"));
    assert!(text.contains(&format!("\n(deny default (with message \"{prefix}default\"))\n")));

    // The envelope is tagged `env` in place of a record.
    let envelope = compiled_for(&profile(""), CommandTag::Envelope);
    assert!(envelope.contains(&format!("\"knsh:{}:env:fixed.ssh\"", session())));
    let tag: knsh_core::DenialTag = format!("knsh:{}:env:fixed.ssh", session()).parse().unwrap();
    assert_eq!(tag.command, knsh_core::TaggedCommand::Envelope);
}

// FR-SBX-04, FR-LC-15: `exec` is allowed only from the trusted folders (defaults and the profile's), the system tool
// folders, `exec.bash` and the binaries the supervisor names; nothing else, not even the write roots by default.
#[test]
fn exec_allowed_only_from_trusted_and_named_paths() {
    let profile = profile(
        "[fs]\nwrite = [\"${PROJECT}\"]\n[exec]\ntrusted_folders = [\"/nix/bin\"]\nbash = \"/opt/bash/bin/bash\"\n\
         project_executables = \"deny\"\n",
    );
    let named = [canonical("/opt/homebrew/Cellar/node/25/bin/node")];
    let text = compiled_with(&profile, CommandTag::Line(record()), &named, None);
    let execs = allows_of(&text, "process-exec");
    assert_eq!(execs.len(), 1, "one exec allow");
    let exec = &execs[0];
    assert_eq!(exec.words[..2], ["allow", "process-exec"]);
    let mut wanted: Vec<(&str, &str)> = [
        "/usr/bin",
        "/bin",
        "/usr/sbin",
        "/opt/homebrew/bin",
        "/usr/local/bin",
        "/nix/bin",
    ]
    .into_iter()
    .map(|folder| ("subpath", folder))
    .collect();
    wanted.extend(SYSTEM_TOOL_FOLDERS.iter().map(|folder| ("subpath", *folder)));
    wanted.push(("literal", "/opt/bash/bin/bash"));
    wanted.push(("literal", "/opt/homebrew/Cellar/node/25/bin/node"));
    let found: Vec<(&str, &str)> = exec.words[2..]
        .iter()
        .map(String::as_str)
        .zip(exec.strings.iter().map(|s| std::str::from_utf8(s).unwrap()))
        .collect();
    assert_eq!(found, wanted);
    assert!(
        !exec.strings.contains(&b"/Users/u/app".to_vec()),
        "the project is not executable"
    );
    // Forking is allowed; nothing else names process-exec except the engine deny, which refuses.
    assert!(text.contains("\n(allow process-fork)\n"));
    let engine = deny_tagged(&text, "fixed.engine");
    assert!(engine.words.contains(&"process-exec*".to_owned()));
}

// FR-POL-14: `project_executables = "allow"` lets the write roots run; `ask` and `deny` do not (an approved binary
// arrives through `executables`).
#[test]
fn project_executables_follow_setting() {
    for (setting, runs) in [("allow", true), ("ask", false), ("deny", false)] {
        let profile = profile(&format!(
            "[fs]\nwrite = [\"${{PROJECT}}\", \"/private/tmp\"]\n[exec]\nproject_executables = \"{setting}\"\n"
        ));
        let text = compiled(&profile);
        let exec = allowed_strings(&text, "process-exec");
        for root in ["/Users/u/app", "/private/tmp"] {
            assert_eq!(exec.contains(&root.as_bytes().to_vec()), runs, "{setting}: {root}");
        }
    }
    // An approved project executable is named exactly, never as its folder.
    let approved = [canonical("/Users/u/app/scripts/build.sh")];
    let text = compiled_with(
        &profile("[fs]\nwrite = [\"${PROJECT}\"]\n[exec]\nproject_executables = \"ask\"\n"),
        CommandTag::Line(record()),
        &approved,
        None,
    );
    let exec = &allows_of(&text, "process-exec")[0];
    let at = exec
        .strings
        .iter()
        .position(|s| s == b"/Users/u/app/scripts/build.sh")
        .unwrap();
    assert_eq!(exec.words[2 + at], "literal");
    assert!(!exec.strings.contains(&b"/Users/u/app".to_vec()));
}

// FR-POL-30, FR-NET-08: the control service is denied by name in every profile, after the broad Mach-service allow,
// for envelopes and lines alike.
#[test]
fn control_service_lookup_always_denied() {
    for command in [CommandTag::Envelope, CommandTag::Line(record())] {
        let text = compiled_for(&profile(""), command);
        let control = deny_tagged(&text, "fixed.control");
        assert_eq!(control.words[..3], ["deny", "mach-lookup", "global-name"]);
        assert_eq!(control.strings[0], knsh_core::CONTROL_SERVICE.as_bytes());
        let allow_at = text.find("(allow mach-lookup)").unwrap();
        assert!(
            text.find("fixed.control").unwrap() > allow_at,
            "the deny comes after the allow"
        );
    }
}

// FR-NET-08: LaunchServices, Apple Events, launchd job submission and the DNS resolver (its service and its socket)
// are denied, each with its own tag (decision 9).
#[test]
fn system_services_denied() {
    let text = compiled(&profile(""));
    let launch = deny_tagged(&text, "services.launch-services");
    assert!(
        launch
            .strings
            .contains(&b"com.apple.coreservices.launchservicesd".to_vec())
    );
    assert!(launch.strings.contains(&b"com.apple.lsd.mapdb".to_vec()));
    assert_eq!(
        deny_tagged(&text, "services.apple-events").strings[0],
        b"com.apple.coreservices.appleevents"
    );
    assert_eq!(
        deny_tagged(&text, "services.launchd-jobs").words[..2],
        ["deny", "job-creation"]
    );
    let dns = denies_tagged(&text, "services.dns");
    assert_eq!(dns.len(), 2);
    assert_eq!(dns[0].strings[0], b"com.apple.dnssd.service");
    assert_eq!(dns[1].words[..2], ["deny", "network-outbound"]);
    assert_eq!(dns[1].strings[0], b"/private/var/run/mDNSResponder");
    // System settings are readable, never writable.
    assert!(text.contains("\n(allow user-preference-read)\n"));
    assert!(!text.contains("user-preference-write"));
}

// FR-SBX-05: `user.sock` is denied in every profile, after everything else that touches sockets, even for an
// envelope (which may connect to `agent.sock`) and whatever the profile allows.
#[test]
fn user_sock_always_denied() {
    let user_sock = b"/Users/u/Library/Application Support/knsh/run/user.sock".to_vec();
    for command in [CommandTag::Envelope, CommandTag::Line(record())] {
        let text = compiled_with(
            &profile("[fs]\nwrite = [\"~\"]\n[network]\nloopback = [3000]\n"),
            command,
            &[],
            Some(8080),
        );
        let deny = deny_tagged(&text, "fixed.user-sock");
        assert_eq!(
            deny.words[..5],
            ["deny", "network-outbound", "remote", "unix-socket", "path-literal"]
        );
        assert_eq!(deny.strings[0], user_sock);
        // Never allowed, and denied after every allow.
        assert!(!allowed_strings(&text, "network-outbound").contains(&user_sock));
        assert!(text.find("fixed.user-sock").unwrap() > text.rfind("(allow").unwrap());
        // No socket can be bound in an engine directory (squatting an endpoint), even with `~` writable.
        let bind = deny_tagged(&text, "fixed.engine-bind");
        assert_eq!(bind.words[..2], ["deny", "network-bind"]);
        assert_eq!(bind.strings[0], b"/Users/u/Library/Application Support/knsh");
    }
}

// FR-SBX-05: an envelope may connect to `agent.sock` and no other Unix socket; a command to none. Docker's sockets
// are denied explicitly (no profile key allows them); the SSH agent's falls under the default deny.
#[test]
fn command_profile_has_no_unix_socket_allow() {
    let profile = profile("[fs]\nwrite = [\"${PROJECT}\"]\n");
    let line = compiled(&profile);
    let outbound = allows_of(&line, "network-outbound");
    assert!(
        outbound
            .iter()
            .all(|form| !form.words.contains(&"unix-socket".to_owned())),
        "{outbound:?}"
    );
    // Binding one's own socket under the write roots is allowed; connecting is what is limited.
    let bind = allows_of(&line, "network-bind");
    assert_eq!(bind.len(), 1);
    assert_eq!(
        bind[0].words[..5],
        ["allow", "network-bind", "network-inbound", "local", "unix-socket"]
    );
    assert_eq!(bind[0].strings, [b"/Users/u/app".to_vec()]);

    let envelope = compiled_for(&profile, CommandTag::Envelope);
    let sockets: Vec<Form> = allows_of(&envelope, "network-outbound")
        .into_iter()
        .filter(|form| form.words.contains(&"unix-socket".to_owned()))
        .collect();
    assert_eq!(sockets.len(), 1);
    assert_eq!(
        sockets[0].strings,
        [b"/Users/u/Library/Application Support/knsh/run/agent.sock".to_vec()]
    );
    for text in [&line, &envelope] {
        let docker = deny_tagged(text, "sockets.docker");
        assert_eq!(
            docker.strings[..2],
            [
                b"/private/var/run/docker.sock".to_vec(),
                b"/Users/u/.docker/run/docker.sock".to_vec()
            ]
        );
    }
}

// FR-NET-01, FR-NET-08: outbound network only to the proxy's loopback port and the `network.loopback` ports (which
// may also be served); no other address, no other port, and nothing at all without either.
#[test]
fn network_limited_to_proxy_and_loopback_ports() {
    let text = compiled_with(
        &profile("[network]\nloopback = [3000, 5432]\n"),
        CommandTag::Line(record()),
        &[],
        Some(41_000),
    );
    let outbound = allows_of(&text, "network-outbound");
    assert_eq!(outbound.len(), 1);
    assert_eq!(
        outbound[0].words,
        [
            "allow",
            "network-outbound",
            "remote",
            "ip",
            "remote",
            "ip",
            "remote",
            "ip"
        ]
    );
    assert_eq!(
        outbound[0].strings,
        [
            b"localhost:41000".to_vec(),
            b"localhost:3000".to_vec(),
            b"localhost:5432".to_vec()
        ]
    );
    let served = allows_of(&text, "network-inbound");
    assert_eq!(served.len(), 1, "no write roots: no Unix socket binds");
    assert_eq!(
        served[0].strings,
        [b"localhost:3000".to_vec(), b"localhost:5432".to_vec()]
    );
    // Nothing broader: no bare `(allow network*)` and no `*` host or port.
    assert!(!text.contains("(allow network-outbound)") && !text.contains("(allow network*"));
    assert!(!text.contains("\"*:") && !text.contains(":*\""));

    let offline = compiled(&profile(""));
    assert!(allows_of(&offline, "network-outbound").is_empty());
    assert!(allows_of(&offline, "network-inbound").is_empty());
}

// Decision 8, FR-SEC-05: signals and process information only within this sandbox; other processes' arguments,
// environment and the process list are denied through `sysctl` too (KNSH-025, C8: either rule alone leaks them).
#[test]
fn process_info_and_signals_limited_to_own_sandbox() {
    let text = compiled(&profile(""));
    assert!(text.contains("\n(allow signal (target same-sandbox))\n"));
    let info = deny_tagged(&text, "process.info");
    assert_eq!(info.words[..2], ["deny", "process-info*"]);
    let deny_at = text.find("process.info").unwrap();
    let allow_at = text.find("(allow process-info* (target same-sandbox))").unwrap();
    assert!(allow_at > deny_at, "the narrower allow follows the deny");
    let sysctl = deny_tagged(&text, "process.sysctl");
    assert_eq!(sysctl.strings[..2], [b"kern.procargs".to_vec(), b"kern.proc.".to_vec()]);
    assert!(text.find("process.sysctl").unwrap() > text.find("(allow sysctl-read)").unwrap());
}

// Every gap is listed in the header comment, which names the profile and its kind and holds no rule.
#[test]
fn header_lists_known_gaps() {
    let text = compiled_for(&profile(""), CommandTag::Envelope);
    let mut lines = text.lines();
    assert_eq!(lines.next(), Some("(version 1)"));
    assert_eq!(
        lines.next(),
        Some(";; knsh envelope profile t, compiled by knsh-sandbox. Known gaps:")
    );
    for gap in GAPS {
        assert_eq!(lines.next(), Some(format!(";; - {gap}").as_str()));
    }
    assert!(lines.next().unwrap().starts_with("(deny default"));
}
