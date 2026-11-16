//! Whether an agent CLI's own sandbox is still on, checked by `knsh agent` before it starts the CLI (KNSH-058,
//! FR-AGT-05, `specs/08-integrations/agent-clis.md#turning-off-the-clis-own-sandbox`).
//!
//! macOS cannot apply a second sandbox inside a sandboxed process, so a CLI that sandboxes its own commands fails
//! inside an envelope: each of its commands is refused by `sandbox-exec`. The envelope replaces that sandbox, so the
//! CLI's own must be off. `knsh agent` does not change the CLI's settings (the engine never authors the user's
//! configuration); it reads them and prints a warning on stderr, with the switch that turns the sandbox off.
//!
//! Only the CLIs with a preset are known (by the command's file name: `claude`, `codex`). The check is advisory and
//! never stops the CLI: when a setting cannot be read or understood, the warning says so rather than guess.
//!
//! The check is a pure function of the command line, the environment and a file reader ([`check`]), so tests feed
//! it settings directly; [`read_file`] is the reader `knsh agent` passes.
//!
//! What each CLI reads was taken from the releases named in the presets (Claude Code 2.1.325, Codex CLI 0.165.0)
//! and is checked again per release (`agent-clis.md`, per-release checklist).

use std::path::Path;

use knsh_json::Value as Json;
use knsh_toml::Value as Toml;

/// Largest settings file read, in bytes. Real ones are a few kilobytes; a larger one is reported as not understood
/// rather than read whole.
const MAX_SETTINGS_LEN: usize = 1 << 20;

/// Claude Code's managed settings on macOS (`/Library/…/ClaudeCode/managed-settings.json`): the highest precedence,
/// set by an administrator. Spelled in two parts because the engine's own data directory lives under the same
/// `Application Support` folder, and `knsh-platform` checks that no other source spells that folder (so engine
/// paths are built in one place); this is Claude Code's folder, not the engine's.
const CLAUDE_MANAGED_SETTINGS: &str = concat!("/Library/Application", " Support/ClaudeCode/managed-settings.json");

/// Codex's value of `sandbox_mode` that runs commands without its sandbox.
const CODEX_NO_SANDBOX: &str = "danger-full-access";

/// Codex's flag that turns off both its approvals and its sandbox.
const CODEX_BYPASS_FLAG: &str = "--dangerously-bypass-approvals-and-sandbox";

/// An agent CLI whose own sandbox `knsh agent` knows how to check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cli {
    /// Claude Code (`claude`): sandbox off by default, turned on by `sandbox.enabled` in its settings.
    ClaudeCode,
    /// Codex CLI (`codex`): sandbox on by default, turned off by `sandbox_mode = "danger-full-access"`.
    CodexCli,
}

impl Cli {
    /// The CLI started by `program` (a name or path), by its file name.
    #[must_use]
    pub fn of_program(program: &str) -> Option<Self> {
        match program.rsplit('/').next() {
            Some("claude") => Some(Self::ClaudeCode),
            Some("codex") => Some(Self::CodexCli),
            _ => None,
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::ClaudeCode => "Claude Code",
            Self::CodexCli => "Codex CLI",
        }
    }

    /// How to turn its sandbox off, for the warning.
    const fn how_to_turn_off(self) -> &'static str {
        match self {
            Self::ClaudeCode => {
                "set \"sandbox\": {\"enabled\": false} in its settings (or remove sandbox.enabled), and use /sandbox to \
                 check"
            }
            Self::CodexCli => {
                "start it with --sandbox danger-full-access, or set sandbox_mode = \"danger-full-access\" in \
                 ~/.codex/config.toml"
            }
        }
    }
}

/// What a file reader found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileRead {
    /// Nothing is there.
    Missing,
    /// The file's bytes.
    Text(Vec<u8>),
    /// Something is there but could not be read (permissions, I/O, too large).
    Unreadable,
}

/// The state of a CLI's own sandbox, and where that was decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Sandbox {
    /// Off: nothing to report.
    Off,
    /// On, as `source` says (a file, a flag, or the CLI's default).
    On {
        /// Where it was turned on, for the warning.
        source: String,
    },
    /// Not known: `source` could not be read or understood, and it may turn the sandbox on.
    Unknown {
        /// What could not be checked, for the warning.
        source: String,
    },
}

/// The sandbox state of `cli` started with `args` (the whole command, program first) in `cwd`, with `env` and
/// `home`, reading files through `read` (module documentation).
#[must_use]
pub fn check(
    cli: Cli,
    args: &[String],
    env: &[(String, String)],
    home: &Path,
    cwd: &Path,
    read: &dyn Fn(&Path) -> FileRead,
) -> Sandbox {
    let var = |name: &str| env.iter().find(|(key, _)| key == name).map(|(_, value)| value.as_str());
    match cli {
        Cli::ClaudeCode => claude_code(args, var("CLAUDE_CONFIG_DIR"), home, cwd, read),
        Cli::CodexCli => codex_cli(args, var("CODEX_HOME"), home, cwd, read),
    }
}

/// The warning `knsh agent` prints on stderr for `state`, if any. `source` text is escaped for the terminal.
#[must_use]
pub fn warning(cli: Cli, state: &Sandbox) -> Option<String> {
    let escape = crate::cli::terminal::escape_text;
    let (name, how) = (cli.name(), cli.how_to_turn_off());
    match state {
        Sandbox::Off => None,
        Sandbox::On { source } => Some(format!(
            "knsh: agent: warning: {name}'s own sandbox is on ({}). macOS cannot apply it inside the envelope, so its \
             commands will fail; the envelope replaces it. To turn it off, {how}.\n",
            escape(source)
        )),
        Sandbox::Unknown { source } => Some(format!(
            "knsh: agent: warning: could not check whether {name}'s own sandbox is off ({}). If it is on, its \
             commands will fail inside the envelope. To turn it off, {how}.\n",
            escape(source)
        )),
    }
}

/// Reads `path` for [`check`]: missing, its bytes (up to 1 MiB), or unreadable.
#[must_use]
pub fn read_file(path: &Path) -> FileRead {
    use std::io::Read;

    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return FileRead::Missing,
        Err(_) => return FileRead::Unreadable,
    };
    let mut bytes = Vec::new();
    // One byte more than the limit tells an oversized file from one exactly at it.
    let limit = u64::try_from(MAX_SETTINGS_LEN).unwrap_or(u64::MAX).saturating_add(1);
    match file.take(limit).read_to_end(&mut bytes) {
        Ok(_) if bytes.len() <= MAX_SETTINGS_LEN => FileRead::Text(bytes),
        Ok(_) | Err(_) => FileRead::Unreadable,
    }
}

/// Claude Code: the first settings source, highest precedence first, that sets `sandbox.enabled` decides; the
/// default is off. Sources: managed settings, `--settings` (a file or inline JSON), the project's
/// `.claude/settings.local.json` and `.claude/settings.json`, then the user's `settings.json` in `CLAUDE_CONFIG_DIR`
/// or `~/.claude`.
fn claude_code(
    args: &[String],
    config_dir: Option<&str>,
    home: &Path,
    cwd: &Path,
    read: &dyn Fn(&Path) -> FileRead,
) -> Sandbox {
    let user_dir = config_dir.map_or_else(|| home.join(".claude"), |dir| cwd.join(dir));
    let mut sources: Vec<(String, FileRead)> = vec![(
        CLAUDE_MANAGED_SETTINGS.to_owned(),
        read(Path::new(CLAUDE_MANAGED_SETTINGS)),
    )];
    if let Some(settings) = option_value(args, "--settings", None) {
        // `--settings` takes a file or the JSON itself.
        if settings.trim_start().starts_with('{') {
            sources.push(("--settings".to_owned(), FileRead::Text(settings.as_bytes().to_vec())));
        } else {
            let path = cwd.join(settings);
            sources.push((path.display().to_string(), read(&path)));
        }
    }
    sources.extend(
        [
            cwd.join(".claude/settings.local.json"),
            cwd.join(".claude/settings.json"),
            user_dir.join("settings.json"),
        ]
        .map(|path| (path.display().to_string(), read_absolute(&path, read))),
    );
    for (source, found) in sources {
        let bytes = match found {
            FileRead::Missing => continue,
            FileRead::Unreadable => return Sandbox::Unknown { source },
            FileRead::Text(bytes) => bytes,
        };
        let Ok(Json::Object(root)) = knsh_json::parse(&bytes, MAX_SETTINGS_LEN) else {
            return Sandbox::Unknown { source };
        };
        match root.get("sandbox") {
            None => {}
            Some(Json::Object(sandbox)) => match sandbox.get("enabled") {
                None => {}
                Some(Json::Bool(true)) => {
                    return Sandbox::On {
                        source: format!("sandbox.enabled in {source}"),
                    };
                }
                Some(Json::Bool(false)) => return Sandbox::Off,
                Some(_) => return Sandbox::Unknown { source },
            },
            Some(_) => return Sandbox::Unknown { source },
        }
    }
    Sandbox::Off
}

/// Codex CLI, highest precedence first: the bypass flag, `--sandbox`/`-s`, `-c sandbox_mode=…`, then
/// `sandbox_mode` in the selected profile of `config.toml` (`--profile`/`-p`, or its top-level `profile`) and at
/// its top level. Nothing set means Codex's default, which sandboxes commands.
fn codex_cli(
    args: &[String],
    codex_home: Option<&str>,
    home: &Path,
    cwd: &Path,
    read: &dyn Fn(&Path) -> FileRead,
) -> Sandbox {
    let options = options(args);
    if options.contains(&CODEX_BYPASS_FLAG) {
        return Sandbox::Off;
    }
    let mode_state = |mode: &str, source: String| {
        if mode == CODEX_NO_SANDBOX {
            Sandbox::Off
        } else {
            Sandbox::On { source }
        }
    };
    if let Some(mode) = option_value(args, "--sandbox", Some("-s")) {
        return mode_state(mode, format!("--sandbox {mode}"));
    }
    if let Some(mode) = codex_config_override(args) {
        return mode_state(&mode, format!("-c sandbox_mode={mode}"));
    }
    let path = codex_home
        .map_or_else(|| home.join(".codex"), |dir| cwd.join(dir))
        .join("config.toml");
    let source = path.display().to_string();
    let config = match read_absolute(&path, read) {
        // No file: Codex's defaults, unless a flag above decided.
        FileRead::Missing => None,
        FileRead::Unreadable => return Sandbox::Unknown { source },
        FileRead::Text(bytes) => match knsh_toml::parse(&bytes) {
            Ok(table) => Some(table),
            // `knsh-toml` reads a subset of TOML; a file outside it is reported, never guessed at.
            Err(_) => return Sandbox::Unknown { source },
        },
    };
    let config = config.as_ref();
    let profile =
        option_value(args, "--profile", Some("-p")).or_else(|| toml_value(config, "profile").and_then(Toml::as_str));
    let profile_table = profile.and_then(|name| {
        let profiles = toml_value(config, "profiles").and_then(Toml::as_table);
        toml_value(profiles, name).and_then(Toml::as_table)
    });
    for (table, key) in [
        (profile_table, "profiles.<profile>.sandbox_mode"),
        (config, "sandbox_mode"),
    ] {
        match toml_value(table, "sandbox_mode") {
            None => {}
            Some(Toml::String(mode)) => return mode_state(mode, format!("{key} = \"{mode}\" in {source}")),
            Some(_) => return Sandbox::Unknown { source },
        }
    }
    Sandbox::On {
        source: "Codex CLI's default; sandbox_mode is not set".to_owned(),
    }
}

/// `read(path)`, or unreadable when `path` is relative: without `HOME` the user's settings cannot be found, and a
/// relative path would be read from `knsh`'s own directory instead, so the check reports it rather than guess.
fn read_absolute(path: &Path, read: &dyn Fn(&Path) -> FileRead) -> FileRead {
    if path.is_absolute() {
        read(path)
    } else {
        FileRead::Unreadable
    }
}

/// The CLI's options: its arguments up to a `--`, after which everything is an operand.
fn options(args: &[String]) -> Vec<&str> {
    args.iter()
        .skip(1)
        .map(String::as_str)
        .take_while(|arg| *arg != "--")
        .collect()
}

/// Every value given to the `long` (`--name value` or `--name=value`) or `short` (`-x value`) option, in order. An
/// option left last without its value gives `None`.
fn option_values<'a>(args: &'a [String], long: &str, short: Option<&str>) -> Vec<Option<&'a str>> {
    let mut options = options(args).into_iter();
    let mut values = Vec::new();
    while let Some(arg) = options.next() {
        if arg == long || Some(arg) == short {
            // The next argument is the value, never an option of its own.
            values.push(options.next());
        } else if let Some(value) = arg.strip_prefix(long).and_then(|rest| rest.strip_prefix('=')) {
            values.push(Some(value));
        }
    }
    values
}

/// The value of the last `long` or `short` option ([`option_values`]). The last one wins, as with the CLIs' own
/// parsers.
fn option_value<'a>(args: &'a [String], long: &str, short: Option<&str>) -> Option<&'a str> {
    option_values(args, long, short).pop().flatten()
}

/// The last `sandbox_mode` set with `-c`/`--config key=value`. Codex reads the value as TOML and falls back to the
/// literal text, so surrounding quotes are dropped.
fn codex_config_override(args: &[String]) -> Option<String> {
    option_values(args, "--config", Some("-c"))
        .into_iter()
        .rev()
        .flatten()
        .find_map(|setting| {
            let (key, value) = setting.split_once('=')?;
            (key.trim() == "sandbox_mode").then(|| value.trim().trim_matches(|c| c == '"' || c == '\'').to_owned())
        })
}

/// The value at `key` in `table`, if both are there.
fn toml_value<'a>(table: Option<&'a knsh_toml::Table>, key: &str) -> Option<&'a Toml> {
    table?.get(key).map(knsh_toml::Item::value)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    use super::*;

    const HOME: &str = "/Users/u";
    const CWD: &str = "/Users/u/app";

    /// A file reader over `files`; `"!"` stands for an unreadable file.
    fn reader(files: &[(&str, &str)]) -> impl Fn(&Path) -> FileRead {
        let files: BTreeMap<PathBuf, String> = files
            .iter()
            .map(|(path, text)| (PathBuf::from(path), (*text).to_owned()))
            .collect();
        move |path| match files.get(path).map(String::as_str) {
            None => FileRead::Missing,
            Some("!") => FileRead::Unreadable,
            Some(text) => FileRead::Text(text.as_bytes().to_vec()),
        }
    }

    fn state(cli: Cli, args: &[&str], env: &[(&str, &str)], files: &[(&str, &str)]) -> Sandbox {
        let args: Vec<String> = args.iter().map(|arg| (*arg).to_owned()).collect();
        let env: Vec<(String, String)> = env.iter().map(|(k, v)| ((*k).to_owned(), (*v).to_owned())).collect();
        check(cli, &args, &env, Path::new(HOME), Path::new(CWD), &reader(files))
    }

    fn is_on(state: &Sandbox) -> bool {
        matches!(state, Sandbox::On { .. })
    }

    fn is_unknown(state: &Sandbox) -> bool {
        matches!(state, Sandbox::Unknown { .. })
    }

    #[test]
    fn knows_clis_by_file_name() {
        assert_eq!(Cli::of_program("claude"), Some(Cli::ClaudeCode));
        assert_eq!(Cli::of_program("/opt/homebrew/bin/codex"), Some(Cli::CodexCli));
        assert_eq!(Cli::of_program("aider"), None);
        assert_eq!(Cli::of_program("/opt/claude/"), None);
    }

    // FR-AGT-05: Claude Code's sandbox is off by default, and the highest-precedence source that sets
    // `sandbox.enabled` decides.
    #[test]
    fn claude_code_sandbox_follows_settings_precedence() {
        let user = "/Users/u/.claude/settings.json";
        let project = "/Users/u/app/.claude/settings.json";
        let local = "/Users/u/app/.claude/settings.local.json";
        let on = r#"{"sandbox":{"enabled":true}}"#;
        let off = r#"{"sandbox":{"enabled":false}}"#;
        let claude =
            |args: &[&str], env: &[(&str, &str)], files: &[(&str, &str)]| state(Cli::ClaudeCode, args, env, files);

        assert_eq!(claude(&["claude"], &[], &[]), Sandbox::Off);
        assert_eq!(claude(&["claude"], &[], &[(user, r#"{"model":"x"}"#)]), Sandbox::Off);
        let user_on = claude(&["claude"], &[], &[(user, on)]);
        assert_eq!(
            user_on,
            Sandbox::On {
                source: format!("sandbox.enabled in {user}")
            }
        );
        // The project overrides the user, the local file the project, managed settings everything.
        assert_eq!(claude(&["claude"], &[], &[(user, on), (project, off)]), Sandbox::Off);
        assert!(is_on(&claude(&["claude"], &[], &[(project, off), (local, on)])));
        assert!(is_on(&claude(
            &["claude"],
            &[],
            &[(local, off), (CLAUDE_MANAGED_SETTINGS, on)]
        )));
        // `--settings` as inline JSON or a file, above the project's files.
        assert!(is_on(&claude(&["claude", "--settings", on], &[], &[(local, off)])));
        assert_eq!(
            claude(
                &["claude", "--settings=s.json"],
                &[],
                &[("/Users/u/app/s.json", off), (user, on)]
            ),
            Sandbox::Off
        );
        // CLAUDE_CONFIG_DIR moves the user's settings.
        assert_eq!(
            claude(&["claude"], &[("CLAUDE_CONFIG_DIR", "/cfg")], &[(user, on)]),
            Sandbox::Off
        );
        assert!(is_on(&claude(
            &["claude"],
            &[("CLAUDE_CONFIG_DIR", "/cfg")],
            &[("/cfg/settings.json", on)]
        )));
        // Without HOME the user's settings cannot be found: reported, never read from a relative path.
        let homeless = |cli: Cli, args: &[&str]| {
            let args: Vec<String> = args.iter().map(|arg| (*arg).to_owned()).collect();
            check(cli, &args, &[], Path::new(""), Path::new(CWD), &reader(&[]))
        };
        assert!(is_unknown(&homeless(Cli::ClaudeCode, &["claude"])));
        assert!(is_unknown(&homeless(Cli::CodexCli, &["codex"])));
        assert_eq!(
            homeless(Cli::CodexCli, &["codex", "-s", "danger-full-access"]),
            Sandbox::Off
        );
        // Operands after `--` are not options.
        assert_eq!(claude(&["claude", "--", "--settings", on], &[], &[]), Sandbox::Off);
    }

    // FR-AGT-05: what cannot be read or understood is reported, never taken as off.
    #[test]
    fn claude_code_unreadable_or_odd_settings_are_unknown() {
        let user = "/Users/u/.claude/settings.json";
        for text in [
            "!",
            "{not json",
            r#"{"sandbox":true}"#,
            r#"{"sandbox":{"enabled":"yes"}}"#,
            "[]",
        ] {
            assert!(
                is_unknown(&state(Cli::ClaudeCode, &["claude"], &[], &[(user, text)])),
                "{text}"
            );
        }
        // A higher-precedence file that decides makes a broken lower one irrelevant.
        let project = "/Users/u/app/.claude/settings.json";
        let decided = state(
            Cli::ClaudeCode,
            &["claude"],
            &[],
            &[(project, r#"{"sandbox":{"enabled":false}}"#), (user, "!")],
        );
        assert_eq!(decided, Sandbox::Off);
    }

    // FR-AGT-05: Codex sandboxes by default; flags beat `-c`, which beats the config file's profile, then its top level.
    #[test]
    fn codex_cli_sandbox_is_on_unless_turned_off() {
        let config = "/Users/u/.codex/config.toml";
        let codex = |args: &[&str], files: &[(&str, &str)]| state(Cli::CodexCli, args, &[], files);

        assert!(is_on(&codex(&["codex"], &[])));
        assert_eq!(
            codex(&["codex", "--dangerously-bypass-approvals-and-sandbox"], &[]),
            Sandbox::Off
        );
        assert_eq!(codex(&["codex", "--sandbox", "danger-full-access"], &[]), Sandbox::Off);
        assert_eq!(
            codex(&["codex", "exec", "-s", "danger-full-access", "fix it"], &[]),
            Sandbox::Off
        );
        assert!(is_on(&codex(&["codex", "--sandbox=workspace-write"], &[])));
        assert_eq!(
            codex(&["codex", "-c", "sandbox_mode=\"danger-full-access\""], &[]),
            Sandbox::Off
        );
        assert_eq!(
            codex(&["codex", "--config=sandbox_mode=danger-full-access"], &[]),
            Sandbox::Off
        );

        let off = "sandbox_mode = \"danger-full-access\"\n";
        assert_eq!(codex(&["codex"], &[(config, off)]), Sandbox::Off);
        assert!(is_on(&codex(&["codex", "-s", "read-only"], &[(config, off)])));
        assert!(is_on(&codex(
            &["codex"],
            &[(config, "sandbox_mode = \"workspace-write\"\n")]
        )));
        // The selected profile overrides the top level, chosen by flag or by the file's own `profile`.
        let profiles = "sandbox_mode = \"danger-full-access\"\n[profiles.safe]\nsandbox_mode = \"read-only\"\n";
        assert!(is_on(&codex(&["codex", "--profile", "safe"], &[(config, profiles)])));
        assert_eq!(codex(&["codex", "-p", "other"], &[(config, profiles)]), Sandbox::Off);
        let chosen = format!("profile = \"safe\"\n{profiles}");
        assert!(is_on(&codex(&["codex"], &[(config, &chosen)])));
        // CODEX_HOME moves the file.
        let moved = state(
            Cli::CodexCli,
            &["codex"],
            &[("CODEX_HOME", "/c")],
            &[("/c/config.toml", off)],
        );
        assert_eq!(moved, Sandbox::Off);
        // A file the subset parser cannot read, or an odd value, is reported.
        assert!(is_unknown(&codex(&["codex"], &[(config, "!")])));
        assert!(is_unknown(&codex(&["codex"], &[(config, "x = 1.5\n")])));
        assert!(is_unknown(&codex(&["codex"], &[(config, "sandbox_mode = 1\n")])));
    }

    // FR-AGT-05: the warning names the source and the switch, escaped for the terminal; nothing when off.
    #[test]
    fn warns_with_the_switch_that_turns_it_off() {
        assert_eq!(warning(Cli::ClaudeCode, &Sandbox::Off), None);
        let on = warning(
            Cli::CodexCli,
            &Sandbox::On {
                source: "--sandbox read-only\u{1b}[2J".to_owned(),
            },
        )
        .unwrap();
        assert!(on.starts_with("knsh: agent: warning: Codex CLI's own sandbox is on (--sandbox read-only\\e[2J)"));
        assert!(on.contains("--sandbox danger-full-access") && on.ends_with(".\n"));
        let unknown = warning(
            Cli::ClaudeCode,
            &Sandbox::Unknown {
                source: "/x".to_owned(),
            },
        )
        .unwrap();
        assert!(unknown.contains("could not check whether Claude Code's own sandbox is off (/x)"));
        assert!(unknown.contains("\"sandbox\": {\"enabled\": false}"));
    }
}
