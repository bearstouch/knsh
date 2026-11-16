//! One profile file (or preset) read into a [`Layer`]: every key checked against the model, typed and validated, but
//! nothing merged, defaulted or expanded yet.
//!
//! A layer keeps `None` for every key the file does not set, so merging an `extends` chain is "child's value if set,
//! else parent's" per key (KNSH-039). Every refusal names the dotted key (with the list index for an element) and its
//! position in the file.

use std::collections::BTreeMap;

use knsh_bash::Interpreter;
use knsh_toml::{Item, Table, Value};

use super::model::{NetworkMode, OutputMode, RETENTION_DAYS_RANGE, RuleAction};
use super::paths::PathTemplate;
use crate::error::{ProfileError, ProfileErrorKind};
use crate::session::ProfileName;

/// Longest command pattern, host or other free-form string a profile list accepts, in bytes.
const MAX_STRING_LEN: usize = 4096;

/// Longest host name (RFC 1035 limit on the presentation form).
const MAX_HOST_LEN: usize = 253;

/// Longest environment variable name accepted under `secrets.env`.
const MAX_ENV_NAME_LEN: usize = 255;

/// Whether the file is a profile (which must have a `name`) or a preset shipped with the engine (which must not).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LayerKind {
    Profile,
    Preset,
}

/// `fs.read` as written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ReadTemplate {
    All,
    Paths(Vec<PathTemplate>),
}

/// One `secrets.env.<VAR>` entry as written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SecretTemplate {
    pub(crate) secret: String,
    pub(crate) inject_for: Vec<String>,
    pub(crate) hosts: Vec<String>,
}

/// One profile file, typed (module documentation). Field names follow the dotted keys.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Layer {
    pub(crate) name: Option<ProfileName>,
    pub(crate) extends: Option<ProfileName>,
    pub(crate) preset: Option<String>,
    pub(crate) fs_read: Option<ReadTemplate>,
    pub(crate) fs_write: Option<Vec<PathTemplate>>,
    pub(crate) fs_deny: Option<Vec<PathTemplate>>,
    pub(crate) exec_allow: Option<Vec<String>>,
    pub(crate) exec_ask: Option<Vec<String>>,
    pub(crate) exec_deny: Option<Vec<String>>,
    pub(crate) exec_project_executables: Option<RuleAction>,
    pub(crate) exec_default: Option<RuleAction>,
    /// Per family: a child's entry for a family replaces its parent's entry for that family.
    pub(crate) exec_interpreters: BTreeMap<String, Interpreter>,
    pub(crate) exec_trusted_folders: Option<Vec<PathTemplate>>,
    pub(crate) exec_trusted_tools: Option<Vec<String>>,
    pub(crate) exec_bash: Option<PathTemplate>,
    pub(crate) network_mode: Option<NetworkMode>,
    pub(crate) network_hosts: Option<Vec<String>>,
    pub(crate) network_approval_hosts: Option<Vec<String>>,
    /// `network.class_hosts.fetch`: approval hosts that `network:fetch` lines reach without an approval.
    pub(crate) network_class_hosts_fetch: Option<Vec<String>>,
    /// `network.class_hosts.publish`: approval hosts that `network:publish` lines reach without an approval.
    pub(crate) network_class_hosts_publish: Option<Vec<String>>,
    pub(crate) network_loopback: Option<Vec<u16>>,
    /// `network.non_tls_hosts`: hosts exempt from the TLS server-name check (FR-NET-06).
    pub(crate) network_non_tls_hosts: Option<Vec<String>>,
    pub(crate) approvals_irreversible: Option<RuleAction>,
    pub(crate) approvals_irreversible_commands: Option<Vec<String>>,
    pub(crate) checkpoints_roots: Option<Vec<PathTemplate>>,
    pub(crate) checkpoints_required: Option<bool>,
    pub(crate) checkpoints_exclude: Option<Vec<String>>,
    pub(crate) recording_commands: Option<bool>,
    pub(crate) recording_output: Option<bool>,
    pub(crate) recording_retention_days: Option<u32>,
    pub(crate) output_mode: Option<OutputMode>,
    /// Per variable: a child's entry for a variable replaces its parent's entry for that variable.
    pub(crate) secrets_env: BTreeMap<String, SecretTemplate>,
}

impl Layer {
    /// Parses and validates one file.
    pub(crate) fn parse(text: &[u8], kind: LayerKind) -> Result<Self, ProfileError> {
        let root = knsh_toml::parse(text).map_err(syntax_error)?;
        let root = Section::root(&root);
        root.check_keys(&[
            "name",
            "extends",
            "preset",
            "fs",
            "exec",
            "network",
            "approvals",
            "checkpoints",
            "recording",
            "output",
            "secrets",
        ])?;
        let mut layer = Self {
            name: root.optional("name", profile_name)?,
            extends: root.optional("extends", profile_name)?,
            preset: root.optional("preset", name_string)?,
            ..Self::default()
        };
        // A profile is loaded by name and must say which one it is; a preset is identified by the engine, and a
        // `name` in one would be a second, unchecked identity.
        match (kind, &layer.name) {
            (LayerKind::Profile, None) => return Err(ProfileError::new(ProfileErrorKind::MissingKey).at_key("name")),
            (LayerKind::Profile, Some(_)) | (LayerKind::Preset, None) => {}
            (LayerKind::Preset, Some(_)) => {
                return Err(ProfileError::new(ProfileErrorKind::NotAllowedInPreset).at_key("name"));
            }
        }
        if let Some(fs) = root.section("fs")? {
            layer.read_fs(&fs)?;
        }
        if let Some(exec) = root.section("exec")? {
            layer.read_exec(&exec)?;
        }
        if let Some(network) = root.section("network")? {
            layer.read_network(&network)?;
        }
        if let Some(approvals) = root.section("approvals")? {
            approvals.check_keys(&["irreversible", "irreversible_commands"])?;
            layer.approvals_irreversible = approvals.optional("irreversible", rule_action)?;
            layer.approvals_irreversible_commands = approvals.list("irreversible_commands", pattern)?;
        }
        if let Some(checkpoints) = root.section("checkpoints")? {
            checkpoints.check_keys(&["roots", "required", "exclude"])?;
            layer.checkpoints_roots = checkpoints.list("roots", path)?;
            layer.checkpoints_required = checkpoints.optional("required", boolean)?;
            layer.checkpoints_exclude = checkpoints.list("exclude", folder_name)?;
        }
        if let Some(recording) = root.section("recording")? {
            recording.check_keys(&["commands", "output", "retention_days"])?;
            layer.recording_commands = recording.optional("commands", boolean)?;
            layer.recording_output = recording.optional("output", boolean)?;
            layer.recording_retention_days = recording.optional("retention_days", retention_days)?;
        }
        if let Some(output) = root.section("output")? {
            output.check_keys(&["mode"])?;
            layer.output_mode = output.optional("mode", output_mode)?;
        }
        if let Some(secrets) = root.section("secrets")? {
            secrets.check_keys(&["env"])?;
            if let Some(env) = secrets.section("env")? {
                layer.read_secrets(&env)?;
            }
        }
        if kind == LayerKind::Preset {
            layer.check_preset_keys()?;
        }
        Ok(layer)
    }

    fn read_fs(&mut self, fs: &Section<'_>) -> Result<(), ProfileError> {
        fs.check_keys(&["read", "write", "deny"])?;
        if let Some(item) = fs.table.get("read") {
            // `fs.read` is the one key with two types: the string `"all"` or a list of paths.
            self.fs_read = Some(match item.value() {
                Value::String(text) if text == "all" => ReadTemplate::All,
                Value::String(_) => {
                    return Err(fs.invalid("read", item, "\"all\" or a list of paths"));
                }
                Value::Array(_) => ReadTemplate::Paths(fs.list("read", path)?.unwrap_or_default()),
                Value::Integer(_) | Value::Boolean(_) | Value::Table(_) => {
                    return Err(fs.wrong_type("read", item, "\"all\" or a list of paths"));
                }
            });
        }
        self.fs_write = fs.list("write", path)?;
        self.fs_deny = fs.list("deny", path)?;
        Ok(())
    }

    fn read_exec(&mut self, exec: &Section<'_>) -> Result<(), ProfileError> {
        exec.check_keys(&[
            "allow",
            "ask",
            "deny",
            "project_executables",
            "default",
            "interpreters",
            "trusted_folders",
            "trusted_tools",
            "bash",
        ])?;
        self.exec_allow = exec.list("allow", pattern)?;
        self.exec_ask = exec.list("ask", pattern)?;
        self.exec_deny = exec.list("deny", pattern)?;
        self.exec_project_executables = exec.optional("project_executables", rule_action)?;
        self.exec_default = exec.optional("default", rule_action)?;
        self.exec_trusted_folders = exec.list("trusted_folders", path)?;
        self.exec_trusted_tools = exec.list("trusted_tools", pattern)?;
        self.exec_bash = exec.optional("bash", path)?;
        if let Some(interpreters) = exec.section("interpreters")? {
            for (family, item) in interpreters.table {
                let entry = interpreters.child(family, item)?;
                self.exec_interpreters
                    .insert(family.to_owned(), read_interpreter(family, &entry)?);
            }
        }
        Ok(())
    }

    fn read_network(&mut self, network: &Section<'_>) -> Result<(), ProfileError> {
        network.check_keys(&[
            "mode",
            "hosts",
            "approval_hosts",
            "class_hosts",
            "loopback",
            "non_tls_hosts",
        ])?;
        self.network_mode = network.optional("mode", network_mode)?;
        self.network_hosts = network.list("hosts", host)?;
        self.network_approval_hosts = network.list("approval_hosts", host)?;
        // FR-NET-03: one list per class that connects. `network:none` connects nowhere, so it has no key.
        if let Some(class_hosts) = network.section("class_hosts")? {
            class_hosts.check_keys(&["fetch", "publish"])?;
            self.network_class_hosts_fetch = class_hosts.list("fetch", host)?;
            self.network_class_hosts_publish = class_hosts.list("publish", host)?;
        }
        self.network_loopback = network.list("loopback", port)?;
        self.network_non_tls_hosts = network.list("non_tls_hosts", host)?;
        Ok(())
    }

    fn read_secrets(&mut self, env: &Section<'_>) -> Result<(), ProfileError> {
        for (variable, item) in env.table {
            let entry = env.child(variable, item)?;
            // The table key becomes an environment variable name in the agent's process, so it must be one.
            if !is_env_name(variable) {
                return Err(env.invalid(variable, item, "an environment variable name ([A-Za-z_][A-Za-z0-9_]*)"));
            }
            entry.check_keys(&["secret", "inject_for", "hosts"])?;
            let Some(secret) = entry.optional("secret", name_string)? else {
                return Err(error_at(&entry.key("secret"), item, ProfileErrorKind::MissingKey));
            };
            let template = SecretTemplate {
                secret,
                inject_for: entry.list("inject_for", pattern)?.unwrap_or_default(),
                hosts: entry.list("hosts", host)?.unwrap_or_default(),
            };
            self.secrets_env.insert(variable.to_owned(), template);
        }
        Ok(())
    }

    /// Presets may only add to the path and host lists (`fs.read` as a list, `fs.write`, `fs.deny`,
    /// `exec.trusted_folders`, `network.hosts`, `network.approval_hosts`, `network.class_hosts`, `network.loopback`,
    /// `checkpoints.roots`):
    /// they grant what an agent CLI itself needs and must never weaken a profile's choices.
    fn check_preset_keys(&self) -> Result<(), ProfileError> {
        let forbidden: &[(&str, bool)] = &[
            ("extends", self.extends.is_some()),
            ("preset", self.preset.is_some()),
            ("fs.read", matches!(self.fs_read, Some(ReadTemplate::All))),
            ("exec.allow", self.exec_allow.is_some()),
            ("exec.ask", self.exec_ask.is_some()),
            ("exec.deny", self.exec_deny.is_some()),
            ("exec.project_executables", self.exec_project_executables.is_some()),
            ("exec.default", self.exec_default.is_some()),
            ("exec.interpreters", !self.exec_interpreters.is_empty()),
            ("exec.trusted_tools", self.exec_trusted_tools.is_some()),
            ("exec.bash", self.exec_bash.is_some()),
            ("network.mode", self.network_mode.is_some()),
            // Lifting the server-name check weakens the proxy: a profile's choice, never a preset's.
            ("network.non_tls_hosts", self.network_non_tls_hosts.is_some()),
            ("approvals.irreversible", self.approvals_irreversible.is_some()),
            (
                "approvals.irreversible_commands",
                self.approvals_irreversible_commands.is_some(),
            ),
            ("checkpoints.required", self.checkpoints_required.is_some()),
            ("checkpoints.exclude", self.checkpoints_exclude.is_some()),
            ("recording.commands", self.recording_commands.is_some()),
            ("recording.output", self.recording_output.is_some()),
            ("recording.retention_days", self.recording_retention_days.is_some()),
            ("output.mode", self.output_mode.is_some()),
            ("secrets.env", !self.secrets_env.is_empty()),
        ];
        match forbidden.iter().find(|(_, set)| *set) {
            Some((key, _)) => Err(ProfileError::new(ProfileErrorKind::NotAllowedInPreset).at_key(key)),
            None => Ok(()),
        }
    }
}

/// One `[exec.interpreters.<family>]` table. The family name and options are validated when the table is built
/// (`knsh_bash::Interpreters::extend`), where the error names this key.
fn read_interpreter(family: &str, entry: &Section<'_>) -> Result<Interpreter, ProfileError> {
    entry.check_keys(&[
        "code_options",
        "value_options",
        "stdin_options",
        "script_options",
        "info_options",
        "code_subcommands",
        "reads_stdin_without_script",
        "cluster_values_from_next",
    ])?;
    let options = |key| entry.list(key, plain_string).map(Option::unwrap_or_default);
    let mut interpreter = Interpreter::new(family);
    interpreter.code_options = options("code_options")?;
    interpreter.value_options = options("value_options")?;
    interpreter.stdin_options = options("stdin_options")?;
    interpreter.script_options = options("script_options")?;
    interpreter.info_options = options("info_options")?;
    interpreter.code_subcommands = options("code_subcommands")?;
    if let Some(flag) = entry.optional("reads_stdin_without_script", boolean)? {
        interpreter.reads_stdin_without_script = flag;
    }
    if let Some(flag) = entry.optional("cluster_values_from_next", boolean)? {
        interpreter.cluster_values_from_next = flag;
    }
    Ok(interpreter)
}

/// Turns a TOML syntax error into a profile error, keeping its position when the parser reports one (an oversized
/// input is refused before any position exists).
fn syntax_error(error: knsh_toml::TomlError) -> ProfileError {
    let position = match error {
        knsh_toml::TomlError::Parse { position, .. } => Some(position),
        knsh_toml::TomlError::InputTooLarge { .. } => None,
    };
    let refused = ProfileError::new(ProfileErrorKind::Syntax(error));
    match position {
        Some(position) => refused.at(position),
        None => refused,
    }
}

/// Why a single value was refused, before the key is attached.
enum Refusal {
    WrongType(&'static str),
    Invalid(&'static str),
    Kind(ProfileErrorKind),
}

/// One table of the file and its dotted key, for error messages.
struct Section<'a> {
    table: &'a Table,
    /// The dotted key of this table (empty for the root).
    prefix: String,
}

impl<'a> Section<'a> {
    fn root(table: &'a Table) -> Self {
        Self {
            table,
            prefix: String::new(),
        }
    }

    fn key(&self, key: &str) -> String {
        if self.prefix.is_empty() {
            key.to_owned()
        } else {
            format!("{}.{key}", self.prefix)
        }
    }

    fn wrong_type(&self, key: &str, item: &Item, expected: &'static str) -> ProfileError {
        error_at(&self.key(key), item, ProfileErrorKind::WrongType { expected })
    }

    fn invalid(&self, key: &str, item: &Item, expected: &'static str) -> ProfileError {
        error_at(&self.key(key), item, ProfileErrorKind::InvalidValue { expected })
    }

    /// Refuses the first key not in `allowed`.
    fn check_keys(&self, allowed: &[&str]) -> Result<(), ProfileError> {
        match self.table.iter().find(|(key, _)| !allowed.contains(key)) {
            Some((key, item)) => Err(error_at(&self.key(key), item, ProfileErrorKind::UnknownKey)),
            None => Ok(()),
        }
    }

    /// The sub-table under `key`, if set.
    fn section(&self, key: &str) -> Result<Option<Section<'a>>, ProfileError> {
        self.table.get(key).map(|item| self.child(key, item)).transpose()
    }

    /// `item`, which sits under `key`, as a table.
    fn child(&self, key: &str, item: &'a Item) -> Result<Section<'a>, ProfileError> {
        match item.value() {
            Value::Table(table) => Ok(Section {
                table,
                prefix: self.key(key),
            }),
            Value::String(_) | Value::Integer(_) | Value::Boolean(_) | Value::Array(_) => {
                Err(self.wrong_type(key, item, "a table"))
            }
        }
    }

    /// The value under `key`, converted by `convert`, if set.
    fn optional<T>(&self, key: &str, convert: fn(&Value) -> Result<T, Refusal>) -> Result<Option<T>, ProfileError> {
        self.table
            .get(key)
            .map(|item| convert(item.value()).map_err(|refusal| refuse(&self.key(key), item, refusal)))
            .transpose()
    }

    /// The list under `key`, each element converted by `convert`, if set. Element errors name `key[index]`.
    fn list<T>(&self, key: &str, convert: fn(&Value) -> Result<T, Refusal>) -> Result<Option<Vec<T>>, ProfileError> {
        let Some(item) = self.table.get(key) else {
            return Ok(None);
        };
        let Value::Array(array) = item.value() else {
            return Err(self.wrong_type(key, item, "a list"));
        };
        array
            .iter()
            .enumerate()
            .map(|(index, element)| {
                convert(element.value())
                    .map_err(|refusal| refuse(&format!("{}[{index}]", self.key(key)), element, refusal))
            })
            .collect::<Result<Vec<_>, _>>()
            .map(Some)
    }
}

/// Turns a value's refusal into the profile error for `full_key`.
fn refuse(full_key: &str, item: &Item, refusal: Refusal) -> ProfileError {
    let kind = match refusal {
        Refusal::WrongType(expected) => ProfileErrorKind::WrongType { expected },
        Refusal::Invalid(expected) => ProfileErrorKind::InvalidValue { expected },
        Refusal::Kind(kind) => kind,
    };
    error_at(full_key, item, kind)
}

/// A `kind` error naming `full_key` at `item`'s position in the file.
fn error_at(full_key: &str, item: &Item, kind: ProfileErrorKind) -> ProfileError {
    ProfileError::new(kind).at_key(full_key).at(item.position())
}

fn string(value: &Value) -> Result<&str, Refusal> {
    value.as_str().ok_or(Refusal::WrongType("a string"))
}

/// The string `value`, owned, if `valid` accepts it; otherwise refused as not being `expected`.
fn checked_string(value: &Value, valid: impl Fn(&str) -> bool, expected: &'static str) -> Result<String, Refusal> {
    let text = string(value)?;
    if valid(text) {
        Ok(text.to_owned())
    } else {
        Err(Refusal::Invalid(expected))
    }
}

/// Bounded and free of control characters, so a value can never inject terminal escapes or line breaks into
/// messages, records or the profiles compiled from it.
fn is_free_form(text: &str) -> bool {
    !text.is_empty() && text.len() <= MAX_STRING_LEN && !text.chars().any(char::is_control)
}

fn plain_string(value: &Value) -> Result<String, Refusal> {
    checked_string(value, is_free_form, "a non-empty string without control characters")
}

fn pattern(value: &Value) -> Result<String, Refusal> {
    checked_string(
        value,
        is_pattern,
        "a command pattern without control characters: a program name without `/`, then its arguments",
    )
}

/// A command pattern (KNSH-040): at least one word, and a first word naming a program rather than a path. Rules match
/// programs by name only (FR-POL-13), so a blank pattern or a path there would never match, and a deny rule that can
/// never match is a silent hole; refusing the profile makes the mistake visible.
pub(crate) fn is_pattern(text: &str) -> bool {
    is_free_form(text)
        && text
            .split(' ')
            .find(|word| !word.is_empty())
            .is_some_and(|name| !name.contains('/'))
}

fn profile_name(value: &Value) -> Result<ProfileName, Refusal> {
    ProfileName::new(string(value)?).map_err(|_| Refusal::Invalid("a name of 1 to 64 characters from [A-Za-z0-9._-]"))
}

/// A preset or secret name: held as a `String`, but spelled under the same rules as a profile name.
fn name_string(value: &Value) -> Result<String, Refusal> {
    profile_name(value).map(|name| name.as_str().to_owned())
}

fn rule_action(value: &Value) -> Result<RuleAction, Refusal> {
    RuleAction::parse(string(value)?).ok_or(Refusal::Invalid("allow, ask or deny"))
}

fn network_mode(value: &Value) -> Result<NetworkMode, Refusal> {
    match string(value)? {
        "none" => Ok(NetworkMode::None),
        "allowlist" => Ok(NetworkMode::Allowlist),
        _ => Err(Refusal::Invalid("none or allowlist")),
    }
}

fn output_mode(value: &Value) -> Result<OutputMode, Refusal> {
    OutputMode::parse(string(value)?).ok_or(Refusal::Invalid("full, truncate, head_tail, errors_only or ref"))
}

fn boolean(value: &Value) -> Result<bool, Refusal> {
    value.as_bool().ok_or(Refusal::WrongType("true or false"))
}

fn retention_days(value: &Value) -> Result<u32, Refusal> {
    let days = value.as_integer().ok_or(Refusal::WrongType("an integer"))?;
    u32::try_from(days)
        .ok()
        .filter(|days| RETENTION_DAYS_RANGE.contains(days))
        .ok_or(Refusal::Invalid("a number of days from 1 to 36500"))
}

fn port(value: &Value) -> Result<u16, Refusal> {
    let port = value.as_integer().ok_or(Refusal::WrongType("an integer"))?;
    u16::try_from(port)
        .ok()
        .filter(|port| *port != 0)
        .ok_or(Refusal::Invalid("a port from 1 to 65535"))
}

fn path(value: &Value) -> Result<PathTemplate, Refusal> {
    PathTemplate::parse(string(value)?).map_err(Refusal::Kind)
}

/// A host as the proxy will match it: letters, digits, `.`, `-`, `_`, a `*` wildcard, and `:` `[` `]` for IPv6
/// literals. Matching semantics are the proxy's (KNSH-060); this only keeps junk out.
fn host(value: &Value) -> Result<String, Refusal> {
    checked_string(value, is_host, "a host name")
}

fn is_host(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= MAX_HOST_LEN
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b'*' | b':' | b'[' | b']'))
}

/// A folder name for `checkpoints.exclude`: one path component, never `.` or `..`.
fn folder_name(value: &Value) -> Result<String, Refusal> {
    checked_string(
        value,
        |text| is_free_form(text) && !text.contains('/') && text != "." && text != "..",
        "a folder name without '/'",
    )
}

fn is_env_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    name.len() <= MAX_ENV_NAME_LEN
        && bytes.next().is_some_and(|b| b.is_ascii_alphabetic() || b == b'_')
        && bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

#[cfg(test)]
mod tests {
    use knsh_toml::Position;

    use super::*;

    fn parse(text: &str) -> Result<Layer, ProfileError> {
        Layer::parse(text.as_bytes(), LayerKind::Profile)
    }

    fn refused(text: &str) -> ProfileError {
        parse(text).unwrap_err()
    }

    #[test]
    fn a_profile_needs_a_name() {
        let error = refused("extends = \"base\"\n");
        assert_eq!(error.kind(), &ProfileErrorKind::MissingKey);
        assert_eq!(error.key(), Some("name"));
    }

    #[test]
    fn wrong_types_name_the_key() {
        let error = refused("name = \"p\"\n[exec]\nallow = \"git\"\n");
        assert_eq!(error.kind(), &ProfileErrorKind::WrongType { expected: "a list" });
        assert_eq!(error.key(), Some("exec.allow"));
        assert_eq!(error.position(), Some(Position { line: 3, column: 9 }));

        let error = refused("name = \"p\"\n[exec]\nallow = [\"git\", 3]\n");
        assert_eq!(error.key(), Some("exec.allow[1]"));

        let error = refused("name = \"p\"\nfs = 1\n");
        assert_eq!(error.key(), Some("fs"));
    }

    #[test]
    fn invalid_enum_values_name_the_key() {
        let error = refused("name = \"p\"\n[exec]\ndefault = \"maybe\"\n");
        assert_eq!(
            error.kind(),
            &ProfileErrorKind::InvalidValue {
                expected: "allow, ask or deny"
            }
        );
        assert_eq!(error.key(), Some("exec.default"));
        for (text, key) in [
            ("[network]\nmode = \"open\"", "network.mode"),
            ("[fs]\nread = \"some\"", "fs.read"),
            ("[network]\nloopback = [0]", "network.loopback[0]"),
            ("[network]\nloopback = [70000]", "network.loopback[0]"),
            ("[recording]\nretention_days = 0", "recording.retention_days"),
            ("[output]\nmode = \"brief\"", "output.mode"),
            ("[network]\nhosts = [\"a b\"]", "network.hosts[0]"),
            ("[checkpoints]\nexclude = [\"a/b\"]", "checkpoints.exclude[0]"),
        ] {
            let error = refused(&format!("name = \"p\"\n{text}\n"));
            assert!(matches!(error.kind(), ProfileErrorKind::InvalidValue { .. }), "{text}");
            assert_eq!(error.key(), Some(key), "{text}");
        }
    }

    #[test]
    fn secrets_need_a_secret_and_a_valid_variable() {
        let error = refused("name = \"p\"\n[secrets.env]\nTOKEN = { hosts = [\"h\"] }\n");
        assert_eq!(error.kind(), &ProfileErrorKind::MissingKey);
        assert_eq!(error.key(), Some("secrets.env.TOKEN.secret"));
        let error = refused("name = \"p\"\n[secrets.env]\n\"1X\" = { secret = \"s\" }\n");
        assert_eq!(error.key(), Some("secrets.env.1X"));
        let error = refused("name = \"p\"\n[secrets.env]\nX = { secret = \"s\", ttl = 1 }\n");
        assert_eq!(error.kind(), &ProfileErrorKind::UnknownKey);
        assert_eq!(error.key(), Some("secrets.env.X.ttl"));
    }

    #[test]
    fn interpreter_tables_are_read() {
        let layer = parse(
            "name = \"p\"\n[exec.interpreters.lua]\ncode_options = [\"-e\"]\nreads_stdin_without_script = false\n",
        )
        .unwrap();
        let lua = &layer.exec_interpreters["lua"];
        assert_eq!(lua.code_options, ["-e"]);
        assert!(!lua.reads_stdin_without_script);
        let error = refused("name = \"p\"\n[exec.interpreters.lua]\neval = [\"-e\"]\n");
        assert_eq!(error.key(), Some("exec.interpreters.lua.eval"));
    }

    #[test]
    fn unknown_keys_are_escaped_in_messages() {
        let error = refused("name = \"p\"\n\"bad\\u001b[31m\" = 1\n");
        assert_eq!(error.kind(), &ProfileErrorKind::UnknownKey);
        assert_eq!(error.key(), Some("bad\\u{1b}[31m"));
    }

    #[test]
    fn syntax_errors_carry_the_position() {
        let error = refused("name = \"p\"\nx = 1.5\n");
        assert!(matches!(error.kind(), ProfileErrorKind::Syntax(_)));
        assert_eq!(error.position().map(|p| p.line), Some(2));
    }

    #[test]
    fn presets_may_only_add_to_lists() {
        let ok = Layer::parse(b"[fs]\nwrite = [\"~/.claude\"]\n", LayerKind::Preset).unwrap();
        assert_eq!(ok.fs_write.map(|w| w.len()), Some(1));
        for (text, key) in [
            ("name = \"x\"", "name"),
            ("[exec]\ndefault = \"allow\"", "exec.default"),
            ("[fs]\nread = \"all\"", "fs.read"),
            ("[network]\nmode = \"allowlist\"", "network.mode"),
            ("[network]\nnon_tls_hosts = [\"x.test\"]", "network.non_tls_hosts"),
        ] {
            let error = Layer::parse(text.as_bytes(), LayerKind::Preset).unwrap_err();
            assert_eq!(error.kind(), &ProfileErrorKind::NotAllowedInPreset, "{text}");
            assert_eq!(error.key(), Some(key), "{text}");
        }
    }
}
