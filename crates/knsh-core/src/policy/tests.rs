//! Loader tests (KNSH-039): the story's unit tests and the merge, preset and default rules.

use std::collections::BTreeMap;
use std::path::PathBuf;

use knsh_bash::NetworkClass;

use super::paths::testing::FakeFs;
use super::*;

/// The policy profile models page; its first TOML block is the example every release must load.
const MODELS_PAGE: &str = include_str!("../../../../specs/05-models/policy-profile.md");

/// Profiles by name, as the policies directory would hold them.
#[derive(Default)]
struct Source(BTreeMap<String, String>);

impl Source {
    fn with(mut self, name: &str, text: &str) -> Self {
        self.0.insert(name.to_owned(), text.to_owned());
        self
    }
}

impl ProfileSource for Source {
    fn read_profile(&self, name: &ProfileName) -> Result<Vec<u8>, LookupError> {
        self.0
            .get(name.as_str())
            .map(|text| text.as_bytes().to_vec())
            .ok_or(LookupError::NotFound)
    }
}

fn name(text: &str) -> ProfileName {
    ProfileName::new(text).unwrap()
}

fn canonical(path: &str) -> CanonicalPath {
    CanonicalPath::new(path).unwrap()
}

/// A Mac-like filesystem: `/var` links to `/private/var`, the home is `/Users/u`, and the session starts in
/// `/Users/u/src/app/web`, inside a git repository rooted at `/Users/u/src/app`.
fn mac_fs() -> FakeFs {
    let mut fs = FakeFs::new();
    fs.add("/Users/u/src/app/.git")
        .add("/Users/u/src/app/web")
        .add("/private/var/folders/xy/T")
        .add("/bin/bash")
        .link("/var", "/private/var");
    fs
}

fn context() -> PathContext {
    PathContext {
        home: PathBuf::from("/Users/u"),
        tmpdir: PathBuf::from("/var/folders/xy/T/"),
        start_dir: PathBuf::from("/Users/u/src/app/web"),
    }
}

fn load(source: &Source, profile: &str) -> Result<Profile, ProfileError> {
    load_profile(&name(profile), source, &context(), &mac_fs())
}

fn example_text() -> &'static str {
    let start = MODELS_PAGE.find("```toml\n").unwrap() + "```toml\n".len();
    let len = MODELS_PAGE[start..].find("```").unwrap();
    &MODELS_PAGE[start..start + len]
}

// FR-POL-01, FR-POL-02: the example in the models page parses and resolves.
#[test]
fn loads_web_app_example_profile() {
    let source = Source::default()
        .with("web-app", example_text())
        .with("base", "name = \"base\"\n");
    let profile = load(&source, "web-app").unwrap();

    assert_eq!(profile.name, name("web-app"));
    assert_eq!(profile.extends, [name("base")]);
    assert_eq!(profile.preset.as_deref(), Some("claude-code"));
    assert_eq!(profile.fs.read, ReadScope::All);
    // `${PROJECT}` and `${TMPDIR}` expand canonically; the preset adds `~/.claude` and `~/.claude.json` after the
    // profile's own roots (the project is already there).
    assert_eq!(
        profile.fs.write,
        [
            canonical("/Users/u/src/app"),
            canonical("/private/var/folders/xy/T"),
            canonical("/Users/u/.claude"),
            canonical("/Users/u/.claude.json"),
        ]
    );
    assert_eq!(profile.fs.deny[0], canonical("/Users/u/.ssh"));
    assert_eq!(profile.fs.deny.len(), 6);
    assert_eq!(profile.exec.allow[0], "git");
    assert_eq!(profile.exec.ask, ["git push", "rm -rf *", "brew *"]);
    assert_eq!(profile.exec.deny.len(), 5);
    assert_eq!(profile.exec.project_executables, RuleAction::Allow);
    assert_eq!(profile.exec.default, RuleAction::Ask);
    assert_eq!(profile.network.mode, NetworkMode::Allowlist);
    assert_eq!(
        profile.network.hosts,
        [
            "registry.npmjs.org",
            "pypi.org",
            "api.anthropic.com",
            "platform.claude.com"
        ]
    );
    assert_eq!(profile.network.approval_hosts, ["github.com"]);
    assert_eq!(profile.network.loopback, [3000, 5432]);
    assert_eq!(profile.approvals.irreversible, RuleAction::Ask);
    assert_eq!(profile.checkpoints.roots, [canonical("/Users/u/src/app")]);
    assert!(profile.checkpoints.required);
    assert!(profile.recording.commands);
    assert!(!profile.recording.output);
    assert_eq!(profile.recording.retention_days, 30);
    let npm = &profile.secrets["NPM_TOKEN"];
    assert_eq!(npm.secret, "npm-token");
    assert_eq!(npm.inject_for, ["npm publish"]);
    assert_eq!(npm.hosts, ["registry.npmjs.org"]);
}

// KNSH-039: unknown keys are errors that name the key.
#[test]
fn rejects_unknown_key_with_name() {
    let source = Source::default().with("p", "name = \"p\"\n[fs]\nwrite = []\nwirte = [\"/tmp\"]\n");
    let error = load(&source, "p").unwrap_err();
    assert_eq!(error.kind(), &ProfileErrorKind::UnknownKey);
    assert_eq!(error.key(), Some("fs.wirte"));
    assert_eq!(error.origin(), Some(&ProfileOrigin::Profile(name("p"))));
    assert_eq!(error.position().map(|p| p.line), Some(4));
    assert_eq!(error.to_string(), "profile p: line 4, column 9: fs.wirte: unknown key");

    let top = Source::default().with("p", "name = \"p\"\n[sandbox]\n");
    assert_eq!(load(&top, "p").unwrap_err().key(), Some("sandbox"));
}

// FR-POL-02: a key the child sets replaces the parent's value whole; keys it leaves out are inherited.
#[test]
fn child_overrides_parent_exec_allow() {
    let source = Source::default()
        .with(
            "base",
            "name = \"base\"\n[exec]\nallow = [\"git\", \"npm\"]\ndeny = [\"sudo *\"]\ndefault = \"deny\"\n",
        )
        .with(
            "child",
            "name = \"child\"\nextends = \"base\"\n[exec]\nallow = [\"cargo\"]\n",
        );
    let profile = load(&source, "child").unwrap();
    assert_eq!(profile.exec.allow, ["cargo"]);
    assert_eq!(profile.exec.deny, ["sudo *"]);
    assert_eq!(profile.exec.default, RuleAction::Deny);
    assert_eq!(profile.extends, [name("base")]);
}

#[test]
fn keyed_tables_merge_per_entry_and_chains_resolve_nearest_first() {
    let source = Source::default()
        .with(
            "root",
            "name = \"root\"\n[secrets.env]\nA = { secret = \"a\" }\nB = { secret = \"b-root\" }\n[network]\nhosts = [\"r\"]\n",
        )
        .with(
            "mid",
            "name = \"mid\"\nextends = \"root\"\n[secrets.env]\nB = { secret = \"b-mid\" }\n",
        )
        .with("leaf", "name = \"leaf\"\nextends = \"mid\"\n");
    let profile = load(&source, "leaf").unwrap();
    assert_eq!(profile.extends, [name("mid"), name("root")]);
    assert_eq!(profile.secrets["A"].secret, "a");
    assert_eq!(profile.secrets["B"].secret, "b-mid");
    assert_eq!(profile.network.hosts, ["r"]);
}

// FR-POL-02: an `extends` cycle is an error, including a profile extending itself.
#[test]
fn detects_extends_cycle() {
    let source = Source::default()
        .with("a", "name = \"a\"\nextends = \"b\"\n")
        .with("b", "name = \"b\"\nextends = \"c\"\n")
        .with("c", "name = \"c\"\nextends = \"a\"\n")
        .with("self", "name = \"self\"\nextends = \"self\"\n");
    let error = load(&source, "a").unwrap_err();
    assert_eq!(error.kind(), &ProfileErrorKind::ExtendsCycle);
    assert_eq!(error.key(), Some("extends"));
    assert_eq!(error.origin(), Some(&ProfileOrigin::Profile(name("c"))));
    assert_eq!(
        load(&source, "self").unwrap_err().kind(),
        &ProfileErrorKind::ExtendsCycle
    );
}

#[test]
fn extends_chains_are_bounded_and_parents_must_exist_and_match() {
    let mut source = Source::default();
    for level in 0..=MAX_EXTENDS_DEPTH {
        source = source.with(
            &format!("p{level}"),
            &format!("name = \"p{level}\"\nextends = \"p{}\"\n", level + 1),
        );
    }
    assert_eq!(
        load(&source, "p0").unwrap_err().kind(),
        &ProfileErrorKind::ExtendsTooDeep
    );

    let missing = Source::default().with("a", "name = \"a\"\nextends = \"gone\"\n");
    let error = load(&missing, "a").unwrap_err();
    assert_eq!(error.kind(), &ProfileErrorKind::ProfileNotFound);
    assert_eq!(error.origin(), Some(&ProfileOrigin::Profile(name("gone"))));

    let mismatch = Source::default().with("a", "name = \"b\"\n");
    assert_eq!(
        load(&mismatch, "a").unwrap_err().kind(),
        &ProfileErrorKind::NameMismatch
    );
}

// FR-POL-12: `fs.read` defaults to "all"; the other defaults are those documented on the model.
#[test]
fn unset_keys_take_their_documented_defaults() {
    let source = Source::default().with("min", "name = \"min\"\n");
    let profile = load(&source, "min").unwrap();
    assert_eq!(profile.fs.read, ReadScope::All);
    assert!(profile.fs.write.is_empty() && profile.fs.deny.is_empty());
    assert_eq!(profile.exec.default, RuleAction::Ask);
    assert_eq!(profile.exec.project_executables, RuleAction::Ask);
    assert_eq!(profile.exec.trusted_folders, TrustedFolders::defaults());
    assert_eq!(profile.exec.bash, canonical(DEFAULT_AGENT_BASH));
    assert_eq!(profile.exec.interpreters, knsh_bash::Interpreters::defaults());
    assert_eq!(profile.network.mode, NetworkMode::None);
    assert_eq!(profile.approvals.irreversible, RuleAction::Ask);
    assert_eq!(profile.checkpoints.exclude, DEFAULT_CHECKPOINT_EXCLUDES);
    assert!(!profile.checkpoints.required);
    assert_eq!(profile.recording.retention_days, DEFAULT_RETENTION_DAYS);
    assert_eq!(profile.output.mode, OutputMode::Full);
    assert!(profile.preset.is_none() && profile.secrets.is_empty());
}

#[test]
fn proposed_keys_are_read() {
    let source = Source::default().with(
        "p",
        "name = \"p\"\n[exec]\ntrusted_folders = [\"/nix/bin\"]\ntrusted_tools = [\"chrome\"]\nbash = \"/opt/homebrew/bin/bash\"\n\
         [exec.interpreters.lua]\ncode_options = [\"-e\"]\n\
         [approvals]\nirreversible = \"deny\"\nirreversible_commands = [\"terraform destroy\"]\n\
         [output]\nmode = \"errors_only\"\n",
    );
    let profile = load(&source, "p").unwrap();
    assert!(profile.exec.trusted_folders.folders().contains(&canonical("/nix/bin")));
    assert_eq!(profile.exec.trusted_tools, ["chrome"]);
    assert_eq!(profile.exec.bash, canonical("/opt/homebrew/bin/bash"));
    assert_eq!(profile.exec.interpreters.find("lua").unwrap().code_options, ["-e"]);
    assert_eq!(profile.approvals.irreversible, RuleAction::Deny);
    assert_eq!(profile.approvals.irreversible_commands, ["terraform destroy"]);
    assert_eq!(profile.output.mode, OutputMode::ErrorsOnly);

    let bad = Source::default().with("p", "name = \"p\"\n[exec.interpreters.lua5]\n");
    assert_eq!(bad_key(&bad), "exec.interpreters.lua5");
}

fn bad_key(source: &Source) -> String {
    load(source, "p").unwrap_err().key().unwrap().to_owned()
}

// FR-POL-10: `${PROJECT}` is the git root above the start directory.
#[test]
fn project_variable_uses_git_root() {
    let source = Source::default().with("p", "name = \"p\"\n[fs]\nwrite = [\"${PROJECT}/build\"]\n");
    let profile = load(&source, "p").unwrap();
    assert_eq!(profile.fs.write, [canonical("/Users/u/src/app/build")]);
}

// FR-POL-10: without a git repository, `${PROJECT}` is the session's start directory.
#[test]
fn project_variable_falls_back_to_start_dir() {
    let mut fs = FakeFs::new();
    fs.add("/Users/u/scratch/notes")
        .add("/private/var/folders/xy/T")
        .link("/var", "/private/var");
    let context = PathContext {
        start_dir: PathBuf::from("/Users/u/scratch/notes"),
        ..context()
    };
    let source = Source::default().with("p", "name = \"p\"\n[checkpoints]\nroots = [\"${PROJECT}\"]\n");
    let profile = load_profile(&name("p"), &source, &context, &fs).unwrap();
    assert_eq!(profile.checkpoints.roots, [canonical("/Users/u/scratch/notes")]);
}

// FR-POL-11: `${TMPDIR}` under `/var` resolves to `/private/var`, as do literal paths through the link.
#[test]
fn canonicalises_tmpdir_to_private_var() {
    let source = Source::default().with(
        "p",
        "name = \"p\"\n[fs]\nwrite = [\"${TMPDIR}\", \"/var/folders/xy/T/cache\", \"/var/folders/xy/T\"]\n",
    );
    let profile = load(&source, "p").unwrap();
    // The third entry resolves to the same path as the first, so it appears once.
    assert_eq!(
        profile.fs.write,
        [
            canonical("/private/var/folders/xy/T"),
            canonical("/private/var/folders/xy/T/cache"),
        ]
    );
}

#[test]
fn unresolvable_paths_and_variables_are_errors_naming_the_key() {
    let mut fs = mac_fs();
    fs.fail("/Users/u/locked");
    let source = Source::default().with("p", "name = \"p\"\n[fs]\ndeny = [\"~/.ssh\", \"~/locked/x\"]\n");
    let error = load_profile(&name("p"), &source, &context(), &fs).unwrap_err();
    assert_eq!(error.kind(), &ProfileErrorKind::PathUnresolvable);
    assert_eq!(error.key(), Some("fs.deny[1]"));

    let relative = Source::default().with("p", "name = \"p\"\n[fs]\nwrite = [\"build\"]\n");
    let error = load(&relative, "p").unwrap_err();
    assert_eq!(error.kind(), &ProfileErrorKind::InvalidPath);
    assert_eq!(error.key(), Some("fs.write[0]"));

    let unknown = Source::default().with("p", "name = \"p\"\n[fs]\nwrite = [\"${CWD}\"]\n");
    assert_eq!(
        load(&unknown, "p").unwrap_err().kind(),
        &ProfileErrorKind::UnknownVariable
    );

    let no_home = PathContext {
        home: PathBuf::from("/Users/nobody"),
        ..context()
    };
    let error = load_profile(
        &name("p"),
        &Source::default().with("p", "name = \"p\"\n"),
        &no_home,
        &mac_fs(),
    )
    .unwrap_err();
    assert_eq!(error.kind(), &ProfileErrorKind::VariableUnresolvable);
    assert_eq!(error.key(), Some("${HOME}"));
}

// KNSH-039: an invalid profile is never partially applied. The loader returns a whole profile or nothing; a caller
// replacing its active profile only on success keeps the previous one intact, even when the error is found in the
// last step (path resolution) after every key parsed.
#[test]
fn invalid_profile_is_not_partially_applied() {
    let source = Source::default()
        .with("good", "name = \"good\"\n[exec]\nallow = [\"git\"]\n")
        .with(
            "bad",
            "name = \"bad\"\n[exec]\nallow = [\"rm\"]\ndefault = \"allow\"\n[fs]\nwrite = [\"~/ok\", \"${NOPE}\"]\n",
        )
        .with(
            "late",
            "name = \"late\"\n[exec]\nallow = [\"rm\"]\n[fs]\ndeny = [\"~/locked/x\"]\n",
        );
    let mut active = load(&source, "good").unwrap();
    let before = active.clone();

    let mut fs = mac_fs();
    fs.fail("/Users/u/locked");
    for candidate in ["bad", "late"] {
        match load_profile(&name(candidate), &source, &context(), &fs) {
            Ok(profile) => active = profile,
            Err(error) => assert!(error.key().is_some(), "{candidate}: {error}"),
        }
    }
    assert_eq!(active, before);
    assert_eq!(active.exec.allow, ["git"]);
    assert_eq!(active.exec.default, RuleAction::Ask);
}

// FR-POL-02, FR-POL-03: presets are data shipped with the engine; each one loads, and they only add to lists.
#[test]
fn presets_are_shipped_data_and_only_add() {
    for (preset, _) in PRESETS {
        let text = format!(
            "name = \"p\"\npreset = \"{preset}\"\n[network]\nmode = \"allowlist\"\nhosts = [\"own.example\"]\n"
        );
        let profile = load(&Source::default().with("p", &text), "p").unwrap();
        assert_eq!(profile.network.hosts[0], "own.example", "{preset}");
        assert!(profile.fs.write.contains(&canonical("/Users/u/src/app")), "{preset}");
        assert_eq!(profile.exec.default, RuleAction::Ask, "{preset}");
    }

    let unknown = Source::default().with("p", "name = \"p\"\npreset = \"made-up\"\n");
    let error = load(&unknown, "p").unwrap_err();
    assert_eq!(error.kind(), &ProfileErrorKind::UnknownPreset);
    assert_eq!(error.key(), Some("preset"));
}

#[test]
fn preset_is_inherited_and_overridable_through_extends() {
    let source = Source::default()
        .with("base", "name = \"base\"\npreset = \"claude-code\"\n")
        .with("child", "name = \"child\"\nextends = \"base\"\n")
        .with("other", "name = \"other\"\nextends = \"base\"\npreset = \"generic\"\n");
    assert_eq!(load(&source, "child").unwrap().preset.as_deref(), Some("claude-code"));
    // `generic` grants no model host, and `other` names none (FR-AGT-32).
    let error = load(&source, "other").unwrap_err();
    assert_eq!(error.kind(), &ProfileErrorKind::MissingKey);
    assert_eq!(error.key(), Some("network.hosts"));
}

// KNSH-039: the resolved profile is a value type that can be compared and hashed.
#[test]
fn resolved_profiles_compare_and_hash_by_value() {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let hash = |profile: &Profile| {
        let mut hasher = DefaultHasher::new();
        profile.hash(&mut hasher);
        hasher.finish()
    };
    let source = Source::default()
        .with("a", "name = \"a\"\n[fs]\nwrite = [\"${PROJECT}\"]\n")
        .with("b", "name = \"a\"\n[fs]\nwrite = [\"/Users/u/src/app\"]\n");
    let first = load(&source, "a").unwrap();
    let again = load(&source, "a").unwrap();
    assert_eq!(first, again);
    assert_eq!(hash(&first), hash(&again));
    // Written differently, resolved the same: equal once paths are canonical.
    let snapshot = load_profile_text(source.0["b"].as_bytes(), &source, &context(), &mac_fs()).unwrap();
    assert_eq!(snapshot, first);
}

#[test]
fn snapshots_load_from_text_with_parents_from_the_source() {
    let source = Source::default().with("base", "name = \"base\"\n[exec]\ndeny = [\"sudo *\"]\n");
    let profile = load_profile_text(
        b"name = \"pushed\"\nextends = \"base\"\n",
        &source,
        &context(),
        &mac_fs(),
    )
    .unwrap();
    assert_eq!(profile.name, name("pushed"));
    assert_eq!(profile.exec.deny, ["sudo *"]);
    let error = load_profile_text(b"name = 1\n", &source, &context(), &mac_fs()).unwrap_err();
    assert_eq!(error.key(), Some("name"));
}

// KNSH-040: a command pattern that could never match (no words, or a path as its name) refuses the profile, so a deny
// rule never silently names nothing.
#[test]
fn patterns_that_can_never_match_are_refused() {
    for (rules, key) in [
        ("[exec]\ndeny = [\"sudo *\", \"   \"]", "exec.deny[1]"),
        ("[exec]\nask = [\"/usr/bin/git push\"]", "exec.ask[0]"),
        ("[exec]\nallow = [\"./x\"]", "exec.allow[0]"),
        (
            "[approvals]\nirreversible_commands = [\" \"]",
            "approvals.irreversible_commands[0]",
        ),
    ] {
        let source = Source::default().with("p", &format!("name = \"p\"\n{rules}"));
        let error = load(&source, "p").unwrap_err();
        assert!(
            matches!(error.kind(), ProfileErrorKind::InvalidValue { .. }),
            "{rules}: {error}"
        );
        assert_eq!(error.key(), Some(key), "{rules}");
    }
    let source = Source::default().with("p", "name = \"p\"\n[exec]\ndeny = [\"  rm  -rf  * \", \"git*\"]");
    assert_eq!(load(&source, "p").unwrap().exec.deny, ["  rm  -rf  * ", "git*"]);
}

// FR-POL-30: a key that grants access may not name an engine path or one below it, however it is spelled; a path
// above one, and `fs.deny`, are accepted (the sandbox compiler carves the fixed denies out of the former).
#[test]
fn profile_allowing_engine_path_is_rejected() {
    let mut fs = mac_fs();
    fs.add("/Users/u/Library/Application Support/knsh/run")
        .add("/Users/u/.config/knsh")
        .link("/Users/u/src/app/engine", "/Users/u/Library/Application Support/knsh");
    let load_text = |text: &str| load_profile_text(text.as_bytes(), &Source::default(), &context(), &fs);
    for (text, key) in [
        (
            "[fs]\nwrite = [\"${PROJECT}\", \"~/Library/Application Support/knsh/run\"]",
            "fs.write[1]",
        ),
        ("[fs]\nwrite = [\"~/.config/knsh\"]", "fs.write[0]"),
        ("[fs]\nread = [\"~/.config/knsh/policies\"]", "fs.read[0]"),
        // Through a symlink in the project, and in another case (the home volume ignores case).
        ("[fs]\nwrite = [\"${PROJECT}/engine\"]", "fs.write[0]"),
        ("[fs]\nwrite = [\"~/library/application support/KNSH\"]", "fs.write[0]"),
        (
            "[fs]\nwrite = [\"~/Library/Application Support/knsh/run/user.sock\"]",
            "fs.write[0]",
        ),
        (
            "[exec]\ntrusted_folders = [\"~/.config/knsh/bin\"]",
            "exec.trusted_folders[0]",
        ),
        ("[exec]\nbash = \"~/.config/knsh/bash\"", "exec.bash"),
        (
            "[checkpoints]\nroots = [\"~/Library/Application Support/knsh\"]",
            "checkpoints.roots[0]",
        ),
    ] {
        let error = load_text(&format!("name = \"p\"\n{text}")).unwrap_err();
        assert_eq!(error.kind(), &ProfileErrorKind::FixedDeny, "{text}");
        assert_eq!(error.key(), Some(key), "{text}");
    }
    // A path above the engine paths is accepted (the fixed denies are carved out of it), and `fs.deny` may name them.
    let profile =
        load_text("name = \"p\"\n[fs]\nwrite = [\"~\"]\ndeny = [\"~/.config/knsh\"]\nread = [\"~\"]").unwrap();
    assert_eq!(profile.fs.write, [canonical("/Users/u")]);
    assert_eq!(profile.fs.deny, [canonical("/Users/u/.config/knsh")]);
}

// FR-AGT-21: the built-in profile loads from the binary, with no parents, and matches its documented contents.
#[test]
fn unattended_profile_is_built_in_and_strict() {
    let profile = load_unattended(&context(), &mac_fs()).unwrap();
    assert_eq!(profile.name.as_str(), UNATTENDED_PROFILE);
    assert_eq!(profile.extends.len(), 0);
    assert_eq!(profile.preset, None);
    assert_eq!(profile.fs.read, ReadScope::All);
    assert_eq!(profile.fs.write, [canonical("/private/var/folders/xy/T")]);
    assert!(profile.fs.deny.contains(&canonical("/Users/u/.ssh")));
    assert_eq!(profile.exec.default, RuleAction::Ask);
    assert_eq!(profile.exec.project_executables, RuleAction::Ask);
    assert_eq!(profile.network.mode, NetworkMode::None);
    assert!(profile.network.hosts.is_empty() && profile.network.approval_hosts.is_empty());
    assert_eq!(profile.network.loopback.len(), 0);
    assert!(
        profile.network.non_tls_hosts.is_empty(),
        "every tunnel is TLS-checked by default (FR-NET-06)"
    );
    assert_eq!(profile.approvals.irreversible, RuleAction::Deny);
    assert_eq!(profile.secrets.len(), 0);
    // A file of the same name in the policies directory is never read in its place.
    let source = Source::default().with("unattended", "name = \"unattended\"\n[exec]\ndefault = \"allow\"\n");
    assert_eq!(load_unattended(&context(), &mac_fs()).unwrap(), profile);
    assert_ne!(load(&source, "unattended").unwrap(), profile);
}

// FR-AGT-04: the `claude-code` preset grants the model API host (and the OAuth refresh host), and read and write to
// `~/.claude`, `~/.claude.json` and the project, even under a profile that lists its reads.
#[test]
fn claude_code_preset_grants_api_host_and_config_folder() {
    let text = "name = \"p\"\npreset = \"claude-code\"\n[fs]\nread = [\"/usr\"]\nwrite = []\n";
    let profile = load(&Source::default().with("p", text), "p").unwrap();
    let granted = [
        canonical("/Users/u/src/app"),
        canonical("/Users/u/.claude"),
        canonical("/Users/u/.claude.json"),
    ];
    assert_eq!(profile.fs.write, granted);
    let mut read = vec![canonical("/usr")];
    read.extend(granted);
    assert_eq!(profile.fs.read, ReadScope::Paths(read));
    assert_eq!(profile.network.hosts, ["api.anthropic.com", "platform.claude.com"]);
    // A preset grants hosts, never a mode: the profile still decides whether the network is on at all.
    assert_eq!(profile.network.mode, NetworkMode::None);
    assert_eq!(profile.network.approval_hosts.len(), 0);
}

// FR-AGT-04, FR-AGT-32: the `codex-cli` preset grants its model hosts (API key and ChatGPT sign-in), its sign-in
// refresh host, `~/.codex` and the project.
#[test]
fn codex_cli_preset_grants_model_hosts_and_config_folder() {
    let text = "name = \"p\"\npreset = \"codex-cli\"\n";
    let profile = load(&Source::default().with("p", text), "p").unwrap();
    assert_eq!(
        profile.fs.write,
        [canonical("/Users/u/src/app"), canonical("/Users/u/.codex")]
    );
    assert_eq!(
        profile.network.hosts,
        ["api.openai.com", "chatgpt.com", "auth.openai.com"]
    );
}

// FR-AGT-32: `generic` grants only the project, and the profile must name the model host itself: a remote one under
// `allowlist`, or a local model's loopback port.
#[test]
fn generic_preset_grants_no_model_host() {
    let load_text = |text: &str| {
        load(
            &Source::default().with("p", &format!("name = \"p\"\npreset = \"generic\"\n{text}")),
            "p",
        )
    };

    let profile = load_text("[network]\nmode = \"allowlist\"\nhosts = [\"api.example.com\"]\n").unwrap();
    assert_eq!(profile.network.hosts, ["api.example.com"]);
    assert_eq!(profile.fs.write, [canonical("/Users/u/src/app")]);
    assert_eq!(profile.network.approval_hosts.len(), 0);
    let local = load_text("[network]\nloopback = [11434]\n").unwrap();
    assert_eq!(local.network.hosts.len(), 0);

    // No host at all, a host the network mode keeps closed, and a model host only behind approval: all refused.
    for text in [
        "",
        "[network]\nhosts = [\"api.example.com\"]\n",
        "[network]\nmode = \"allowlist\"\nhosts = []\napproval_hosts = [\"api.example.com\"]\n",
    ] {
        let error = load_text(text).unwrap_err();
        assert_eq!(error.kind(), &ProfileErrorKind::MissingKey, "{text}");
        assert_eq!(error.key(), Some("network.hosts"), "{text}");
    }
}

/// A preset as the engine would ship it, applied to `profile` (which must not name a preset of its own).
fn load_with_preset(profile: &str, preset: &str) -> Result<Profile, ProfileError> {
    let mut layer = Layer::parse(profile.as_bytes(), LayerKind::Profile)?;
    merge_preset(&mut layer, Layer::parse(preset.as_bytes(), LayerKind::Preset)?);
    build(layer, name("p"), Vec::new(), &context(), &mac_fs())
}

// FR-NET-03: a preset can let a class reach an approval host: `network:fetch` lines (`git fetch`) reach github.com
// without an approval, while `network:publish` (`git push`) and a line presenting both still need one.
#[test]
fn preset_class_allows_git_fetch_to_github() {
    let preset = "[network]\napproval_hosts = [\"github.com\"]\n[network.class_hosts]\nfetch = [\"github.com\"]\n";
    let profile = load_with_preset("name = \"p\"\n[network]\nmode = \"allowlist\"\n", preset).unwrap();
    let rules = &profile.network.class_hosts;
    assert_eq!(rules.fetch, ["github.com"]);
    assert_eq!(rules.publish.len(), 0);
    assert!(rules.allows(&[NetworkClass::Fetch], "github.com"));
    assert!(rules.allows(&[NetworkClass::None, NetworkClass::Fetch], "github.com"));
    assert!(!rules.allows(&[NetworkClass::Fetch], "gitlab.com"));
    assert!(!rules.allows(&[NetworkClass::Publish], "github.com"));
    assert!(!rules.allows(&[NetworkClass::Fetch, NetworkClass::Publish], "github.com"));
    // No class that connects, no class at all (dynamic code, unclassified programs): never by class.
    assert!(!rules.allows(&[NetworkClass::None], "github.com"));
    assert!(!rules.allows(&[], "github.com"));

    // A profile's own class rules are appended to, not replaced, by the preset's.
    let own =
        "name = \"p\"\n[network]\napproval_hosts = [\"gitlab.com\"]\n[network.class_hosts]\nfetch = [\"gitlab.com\"]\n";
    let merged = load_with_preset(own, preset).unwrap();
    assert_eq!(merged.network.class_hosts.fetch, ["gitlab.com", "github.com"]);
}

// FR-NET-03: a class rule must name an approval host, so it never opens a host the profile does not name; and only
// the classes that connect have a key.
#[test]
fn class_hosts_must_be_approval_hosts() {
    let source = Source::default().with(
        "p",
        "name = \"p\"\n[network]\napproval_hosts = [\"github.com\"]\n[network.class_hosts]\nfetch = [\"github.com\"]\npublish = [\"evil.example\"]\n",
    );
    let error = load(&source, "p").unwrap_err();
    assert_eq!(
        error.kind(),
        &ProfileErrorKind::InvalidValue {
            expected: "a host listed in network.approval_hosts"
        }
    );
    assert_eq!(error.key(), Some("network.class_hosts.publish[0]"));

    let source = Source::default().with("p", "name = \"p\"\n[network.class_hosts]\nnone = []\n");
    assert_eq!(load(&source, "p").unwrap_err().key(), Some("network.class_hosts.none"));
    // An approval host inherited from a parent counts.
    let source = Source::default()
        .with(
            "base",
            "name = \"base\"\n[network]\napproval_hosts = [\"github.com\"]\n",
        )
        .with(
            "p",
            "name = \"p\"\nextends = \"base\"\n[network.class_hosts]\nfetch = [\"github.com\"]\n",
        );
    assert_eq!(load(&source, "p").unwrap().network.class_hosts.fetch, ["github.com"]);
}

// FR-NET-06 (KNSH-061): `network.non_tls_hosts` is read as a host list and inherited like the other host lists.
#[test]
fn reads_non_tls_hosts() {
    let load_text = |text: &str| load(&Source::default().with("p", &format!("name = \"p\"\n{text}")), "p");
    let profile =
        load_text("[network]\nmode = \"allowlist\"\nhosts = [\"git.corp\"]\nnon_tls_hosts = [\"git.corp\"]\n").unwrap();
    assert_eq!(profile.network.non_tls_hosts, ["git.corp"]);
    assert!(load_text("[network]\nnon_tls_hosts = [3]\n").is_err());
}

// FR-CKP-31 (KNSH-087): `checkpoints.exclude` replaces the default list rather than adding to it.
#[test]
fn checkpoint_exclude_replaces_the_defaults() {
    let source = Source::default().with(
        "own",
        "name = \"own\"\n[checkpoints]\nexclude = [\"vendor\", \"node_modules\"]\n",
    );
    let profile = load(&source, "own").unwrap();
    assert_eq!(profile.checkpoints.exclude, ["vendor", "node_modules"]);
    assert!(!profile.checkpoints.exclude.iter().any(|name| name == "target"));

    let source = Source::default().with("none", "name = \"none\"\n[checkpoints]\nexclude = []\n");
    assert_eq!(load(&source, "none").unwrap().checkpoints.exclude, Vec::<String>::new());
}
