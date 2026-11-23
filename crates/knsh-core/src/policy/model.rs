//! The resolved policy profile: one typed value per key of `specs/05-models/policy-profile.md#keys`, after
//! `extends` and `preset` are applied, defaults filled in and every path expanded to canonical form.
//!
//! The types are plain values (`Clone`, `Eq`, `Hash`), so two resolved profiles can be compared (a child agent's
//! profile against its parent's, FR-SES-03) or hashed (records and caches). They are built by
//! [`load_profile`](crate::load_profile) from profile text and the presets shipped as data; the engine never
//! authors one itself (FR-POL-03).

use std::collections::BTreeMap;

use knsh_bash::{Interpreters, NetworkClass};

use crate::id::SessionId;
use crate::path::CanonicalPath;
use crate::resolve::TrustedFolders;
use crate::session::ProfileName;

/// The agent bash used when the profile names none: macOS's `/bin/bash` 3.2
/// (`specs/09-reference/defaults-and-limits.md`, "Agent bash").
pub const DEFAULT_AGENT_BASH: &str = "/bin/bash";

/// Folder names never captured in checkpoints unless `checkpoints.exclude` replaces the list
/// (`specs/09-reference/defaults-and-limits.md`, "Checkpoint excludes").
pub const DEFAULT_CHECKPOINT_EXCLUDES: &[&str] = &["node_modules", "target", ".venv", "dist", "build"];

/// Days a record is kept when `recording.retention_days` is not set (`specs/09-reference/defaults-and-limits.md`).
pub const DEFAULT_RETENTION_DAYS: u32 = 30;

/// The range `recording.retention_days` accepts (`specs/09-reference/defaults-and-limits.md`).
pub const RETENTION_DAYS_RANGE: std::ops::RangeInclusive<u32> = 1..=36_500;

/// A fully resolved policy profile (module documentation).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Profile {
    /// `name`: the profile's name.
    pub name: ProfileName,
    /// The profiles merged into this one by `extends`, nearest parent first. Empty when it extends nothing.
    pub extends: Vec<ProfileName>,
    /// `preset`: the preset applied on top, if any.
    pub preset: Option<String>,
    /// The preset's `[env]`: environment variables of the agent CLI, each naming a parent folder reached from its
    /// variable with no symlink (FR-AGT-33). Each agent session gets its own folder below each parent
    /// ([`Profile::session_folders`]). Empty without a preset or when the preset sets none; a profile cannot set it.
    pub env: BTreeMap<String, CanonicalPath>,
    /// `[fs]`.
    pub fs: FsPolicy,
    /// `[exec]`.
    pub exec: ExecPolicy,
    /// `[network]`.
    pub network: NetworkPolicy,
    /// `[approvals]`.
    pub approvals: ApprovalsPolicy,
    /// `[checkpoints]`.
    pub checkpoints: CheckpointPolicy,
    /// `[recording]`.
    pub recording: RecordingPolicy,
    /// `[output]`.
    pub output: OutputPolicy,
    /// `[secrets.env]`: secret injections by environment variable name.
    pub secrets: BTreeMap<String, SecretInjection>,
}

/// Prefix of an agent session's own folder below each `env` parent (FR-AGT-33): `knsh-session-<session-id>`.
const SESSION_FOLDER_PREFIX: &str = "knsh-session-";

impl Profile {
    /// The session's own folder for each `env` variable (FR-AGT-33): `<parent>/knsh-session-<session_id>`, by
    /// variable name. Pure: the same profile and session give the same folders, so every line of the session is
    /// granted the folder its envelope was given.
    #[must_use]
    pub fn session_folders(&self, session_id: SessionId) -> BTreeMap<String, CanonicalPath> {
        self.env
            .iter()
            .filter_map(|(variable, parent)| {
                // A canonical parent joined with one plain component is canonical; `filter_map` only keeps the type
                // honest, and a folder that is not granted is one the CLI cannot use, never one it may misuse.
                let folder = parent.as_path().join(format!("{SESSION_FOLDER_PREFIX}{session_id}"));
                CanonicalPath::new(folder).ok().map(|folder| (variable.clone(), folder))
            })
            .collect()
    }

    /// This profile with the session's own folders ([`session_folders`](Self::session_folders)) added to
    /// `fs.write`, and to `fs.read` when it lists its reads: what the session's envelope and lines are compiled from.
    /// Kept out of the loaded profile, so strictness between nested sessions compares what their profiles say.
    #[must_use]
    pub fn with_session_folders(&self, session_id: SessionId) -> Self {
        let mut granted = self.clone();
        for folder in self.session_folders(session_id).into_values() {
            if let ReadScope::Paths(paths) = &mut granted.fs.read
                && !paths.contains(&folder)
            {
                paths.push(folder.clone());
            }
            if !granted.fs.write.contains(&folder) {
                granted.fs.write.push(folder);
            }
        }
        granted
    }
}

/// What a rule or setting does with a matching command: run it, ask the authority, or refuse it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RuleAction {
    /// Run it.
    Allow,
    /// Ask the authority first.
    Ask,
    /// Refuse it.
    Deny,
}

impl RuleAction {
    /// The profile spelling: `allow`, `ask` or `deny`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Ask => "ask",
            Self::Deny => "deny",
        }
    }

    pub(crate) fn parse(text: &str) -> Option<Self> {
        match text {
            "allow" => Some(Self::Allow),
            "ask" => Some(Self::Ask),
            "deny" => Some(Self::Deny),
            _ => None,
        }
    }
}

/// `fs.read`: what an agent may read.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ReadScope {
    /// `"all"`: everything except `fs.deny` (the default, FR-POL-12).
    All,
    /// Only these paths (and what is below them), except `fs.deny`.
    Paths(Vec<CanonicalPath>),
}

/// `[fs]`: filesystem access. Every path is canonical (FR-POL-11) and appears once per list.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FsPolicy {
    /// `fs.read`. Default [`ReadScope::All`] (FR-POL-12).
    pub read: ReadScope,
    /// `fs.write`: write roots. Default none.
    pub write: Vec<CanonicalPath>,
    /// `fs.deny`: never readable or writable. Default none (the fixed engine denies of FR-POL-30 are added by the
    /// sandbox compiler, never by the profile).
    pub deny: Vec<CanonicalPath>,
}

/// `[exec]`: command rules and how commands are found and run.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ExecPolicy {
    /// `exec.allow` patterns, in source order (rule IDs `exec.allow[N]`). Default none.
    pub allow: Vec<String>,
    /// `exec.ask` patterns, in source order. Default none.
    pub ask: Vec<String>,
    /// `exec.deny` patterns, in source order. Default none.
    pub deny: Vec<String>,
    /// `exec.project_executables`: binaries from agent-writable places (FR-POL-14). Default [`RuleAction::Ask`].
    pub project_executables: RuleAction,
    /// `exec.default`: when no rule matches (FR-POL-17). Default [`RuleAction::Ask`], so an unlisted command is
    /// never run without a decision.
    pub default: RuleAction,
    /// `exec.interpreters`: the built-in interpreter table extended by the profile (KNSH-036).
    pub interpreters: Interpreters,
    /// `exec.trusted_folders` (proposed): the default trusted folders plus the profile's (FR-POL-13).
    pub trusted_folders: TrustedFolders,
    /// `exec.trusted_tools` (proposed): tools run without a per-command profile after approval (FR-SBX-09).
    /// Default none.
    pub trusted_tools: Vec<String>,
    /// `exec.bash` (proposed): the bash that runs agent lines. Default [`DEFAULT_AGENT_BASH`].
    pub bash: CanonicalPath,
    /// `exec.mode`: how agent lines are decided and run (FR-LC-50, KNSH-108). Default [`ExecMode::Line`].
    pub mode: ExecMode,
}

/// `exec.mode` (FR-LC-50, KNSH-108): how a session's agent lines are decided and run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum ExecMode {
    /// `line`: the whole line is decided, then run by a stock interpreter (phase 2). The default.
    #[default]
    Line,
    /// `native`: the line runs in `knsh`'s own interpreter and every simple command it starts is decided.
    Native,
}

impl ExecMode {
    /// The profile spelling: `line` or `native`.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Line => "line",
            Self::Native => "native",
        }
    }

    /// The mode spelled `code`, or `None` for any other text.
    #[must_use]
    pub fn parse(code: &str) -> Option<Self> {
        [Self::Line, Self::Native].into_iter().find(|mode| mode.code() == code)
    }
}

/// `network.mode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NetworkMode {
    /// `none`: no network at all (the default).
    None,
    /// `allowlist`: only the listed hosts.
    Allowlist,
}

/// `[network]`: what commands may reach.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NetworkPolicy {
    /// `network.mode`. Default [`NetworkMode::None`].
    pub mode: NetworkMode,
    /// `network.hosts`: open to every command. Default none.
    pub hosts: Vec<String>,
    /// `network.approval_hosts`: only for commands whose class or approval includes them (FR-NET-03). Default
    /// none.
    pub approval_hosts: Vec<String>,
    /// `network.class_hosts`: which approval hosts each network class reaches without an approval (FR-NET-03).
    /// Default none.
    pub class_hosts: ClassHosts,
    /// `network.loopback`: loopback ports allowed. Default none.
    pub loopback: Vec<u16>,
    /// `network.non_tls_hosts`: hosts whose tunnels may carry anything, not only TLS naming the host, so the proxy
    /// skips the server-name check for them (FR-NET-06). Matched like every host entry; listing a host here never
    /// lets a command reach it. Default none.
    pub non_tls_hosts: Vec<String>,
}

/// `[network.class_hosts]`: the approval hosts a line reaches by its network classes alone, without an approval
/// (FR-NET-03, `specs/03-functional-requirements/policy.md`, "Class host rules").
///
/// A host is listed per class, and a line reaches it only when it presents a class that connects and **every** class
/// that connects lists the host: classes list everything a command may do, so `git fetch` reaches a host listed under
/// `fetch`, while a line presenting `network:fetch` and `network:publish` also needs it under `publish`.
/// `network:none` connects nowhere and needs no host.
///
/// Invariant (checked by the loader): every host listed is one of the profile's `network.approval_hosts`. A class
/// rule therefore never opens a host the profile does not already name for approval-gated use.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct ClassHosts {
    /// `network.class_hosts.fetch`: hosts open to `network:fetch` lines.
    pub fetch: Vec<String>,
    /// `network.class_hosts.publish`: hosts open to `network:publish` lines.
    pub publish: Vec<String>,
}

impl ClassHosts {
    /// The hosts listed for `class`; none for [`NetworkClass::None`], which connects nowhere.
    #[must_use]
    pub fn for_class(&self, class: NetworkClass) -> &[String] {
        match class {
            NetworkClass::None => &[],
            NetworkClass::Fetch => &self.fetch,
            NetworkClass::Publish => &self.publish,
        }
    }

    /// Whether a line presenting `classes` reaches `host` without an approval (type documentation). `false` when
    /// `classes` holds no class that connects: a line with no classes (dynamic code, an unclassified program) or only
    /// `network:none` never reaches an approval host by class.
    #[must_use]
    pub fn allows(&self, classes: &[NetworkClass], host: &str) -> bool {
        let mut connecting = classes.iter().filter(|class| **class != NetworkClass::None).peekable();
        connecting.peek().is_some()
            && connecting.all(|class| self.for_class(*class).iter().any(|listed| listed == host))
    }
}

/// `[approvals]`: how flagged lines are treated.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ApprovalsPolicy {
    /// `approvals.irreversible`: lines classified as irreversible (FR-IRR-05). Default [`RuleAction::Ask`].
    pub irreversible: RuleAction,
    /// `approvals.irreversible_commands` (proposed): patterns the profile adds to the irreversible list. Default
    /// none.
    pub irreversible_commands: Vec<String>,
    /// `approvals.upload_hosts` (KNSH-093): hosts the profile adds to the built-in upload-capable list
    /// ([`BUILTIN_UPLOAD_HOSTS`](crate::BUILTIN_UPLOAD_HOSTS)); a line that reached one is marked irreversible after it
    /// runs (FR-IRR-03). Matched like every host entry. Default none.
    pub upload_hosts: Vec<String>,
}

/// `[checkpoints]`: protected roots.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CheckpointPolicy {
    /// `checkpoints.roots`. Default none.
    pub roots: Vec<CanonicalPath>,
    /// `checkpoints.required`: lines touching a root wait for its shadow. Default `false`.
    pub required: bool,
    /// `checkpoints.exclude`: folder names never captured. Default [`DEFAULT_CHECKPOINT_EXCLUDES`]; a profile's
    /// list replaces it.
    pub exclude: Vec<String>,
}

/// `[recording]`: what agent records keep.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RecordingPolicy {
    /// `recording.commands`. Default `true` (agent recording default, NFR-PRIV).
    pub commands: bool,
    /// `recording.output`. Default `false`.
    pub output: bool,
    /// `recording.retention_days`, within [`RETENTION_DAYS_RANGE`]. Default [`DEFAULT_RETENTION_DAYS`].
    pub retention_days: u32,
}

/// An `exec.run` output mode (`specs/03-functional-requirements/output-modes.md`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OutputMode {
    /// `full`.
    Full,
    /// `truncate`.
    Truncate,
    /// `head_tail`.
    HeadTail,
    /// `errors_only`.
    ErrorsOnly,
    /// `ref`.
    Ref,
}

impl OutputMode {
    /// Every mode, in declaration order.
    pub const ALL: [Self; 5] = [Self::Full, Self::Truncate, Self::HeadTail, Self::ErrorsOnly, Self::Ref];

    /// The name in profiles and on the wire.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::Truncate => "truncate",
            Self::HeadTail => "head_tail",
            Self::ErrorsOnly => "errors_only",
            Self::Ref => "ref",
        }
    }

    /// The mode named `text` exactly.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "full" => Some(Self::Full),
            "truncate" => Some(Self::Truncate),
            "head_tail" => Some(Self::HeadTail),
            "errors_only" => Some(Self::ErrorsOnly),
            "ref" => Some(Self::Ref),
            _ => None,
        }
    }
}

/// `[output]` (proposed): defaults for `exec.run`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OutputPolicy {
    /// `output.mode`: the default output mode (FR-OUT-02). Default [`OutputMode::Full`].
    pub mode: OutputMode,
}

/// One `secrets.env.<VAR>` entry (`specs/05-models/secret.md`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SecretInjection {
    /// `secret`: the secret's name in the Keychain or as supplied by the authority.
    pub secret: String,
    /// `inject_for`: patterns of the lines that receive it. Default none.
    pub inject_for: Vec<String>,
    /// `hosts`: the only hosts a receiving line can reach. Default none.
    pub hosts: Vec<String>,
}
