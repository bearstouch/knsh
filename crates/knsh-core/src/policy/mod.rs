//! Policy profile model and loader (KNSH-039; FR-POL-01, FR-POL-02, FR-POL-03, FR-POL-10, FR-POL-11, FR-POL-12), and
//! command rule matching (KNSH-040; FR-POL-13 to FR-POL-17, in the `rules` module: [`evaluate_command`]).
//!
//! [`load_profile`] (by name) and [`load_profile_text`] (a snapshot pushed with `policy.set`) turn profile text into
//! one resolved [`Profile`]:
//!
//! 1. **Read.** Each file is parsed with `knsh-toml` and every key is checked against
//!    `specs/05-models/policy-profile.md#keys`. Unknown keys, wrong types and invalid enum values are errors naming
//!    the dotted key ([`ProfileError::key`]).
//! 2. **`extends`.** Parents are read from the [`ProfileSource`] by name, up to [`MAX_EXTENDS_DEPTH`] profiles, and
//!    merged per key: a key the child sets replaces the parent's value whole (`exec.allow` replaces `exec.allow`; it
//!    is not appended to), and keyed tables (`exec.interpreters.<family>`, `secrets.env.<VAR>`) are merged per
//!    entry. A cycle is an error.
//! 3. **`preset`.** The merged profile's preset, one of the [`PRESETS`] shipped as data, is read by the same parser
//!    and its path and host lists are appended (FR-POL-02). A preset sets nothing else, so it never weakens a profile.
//! 4. **Defaults** fill every unset key (documented on each field of the model; `fs.read` is `"all"`, FR-POL-12, and
//!    `exec.default` is `ask`).
//! 5. **Paths.** `~`, `${HOME}`, `${TMPDIR}` and `${PROJECT}` (the git root, or the session's start directory,
//!    FR-POL-10) are expanded and every path is canonicalised with symlinks followed (FR-POL-11), through
//!    [`PolicyFs`].
//!
//! Loading is all or nothing: every step works on new values, and the profile is returned only when all succeed, so
//! an invalid profile is never partially applied. Signature checks (FR-POL-40) are KNSH-065's, in the profile source.
//!
//! # Proposed keys
//!
//! The spec lists settings without keys (`policy-profile.md`, "Profiles may also set"). This module reads them as
//! proposed in the models page: `exec.trusted_folders`, `exec.trusted_tools`, `exec.bash`,
//! `approvals.irreversible_commands` and `output.mode`.

mod layer;
mod model;
mod paths;
mod presets;
mod rules;

#[cfg(test)]
mod tests;

use layer::{Layer, LayerKind, ReadTemplate};
pub use model::{
    ApprovalsPolicy, CheckpointPolicy, DEFAULT_AGENT_BASH, DEFAULT_CHECKPOINT_EXCLUDES, DEFAULT_RETENTION_DAYS,
    ExecPolicy, FsPolicy, NetworkMode, NetworkPolicy, OutputMode, OutputPolicy, Profile, RETENTION_DAYS_RANGE,
    ReadScope, RecordingPolicy, RuleAction, SecretInjection,
};
pub use paths::{LookupError, PathContext, PolicyFs, project_root};
use paths::{PathTemplate, Variables};
pub use presets::PRESETS;
pub use rules::{CommandVerdict, RuleId, evaluate_command};

use crate::error::{ProfileError, ProfileErrorKind, ProfileOrigin};
use crate::path::CanonicalPath;
use crate::resolve::TrustedFolders;
use crate::session::ProfileName;

/// Largest profile text the loader reads, in bytes: the TOML parser's input limit. Profile sources should refuse a
/// larger file before reading it.
pub const MAX_PROFILE_LEN: usize = knsh_toml::MAX_INPUT_LEN;

/// Most profiles in one `extends` chain, the loaded profile included. Bounds the reads a chain can cause.
pub const MAX_EXTENDS_DEPTH: usize = 8;

/// Where profiles are read from by name: `<name>.toml` in the policies directory in `knsh-platform` (FR-POL-01), an
/// in-memory map in tests. Signature checks (KNSH-065) belong here, so the loader only ever sees accepted text.
pub trait ProfileSource {
    /// The text of the profile called `name`.
    ///
    /// # Errors
    ///
    /// [`LookupError::NotFound`] if there is no such profile; [`LookupError::Failed`] if it exists but cannot be
    /// read (or is larger than [`MAX_PROFILE_LEN`]).
    fn read_profile(&self, name: &ProfileName) -> Result<Vec<u8>, LookupError>;
}

/// Loads the profile called `name` from `source` and resolves it (module documentation).
///
/// # Errors
///
/// [`ProfileError`] naming the profile, key and position at fault: not found or unreadable, invalid TOML, unknown
/// key, wrong type, invalid value, a `name` that differs from `name`, an `extends` cycle or overlong chain, an
/// unknown preset, or a path that cannot be expanded or resolved. No partial profile is ever returned.
pub fn load_profile<S, F>(
    name: &ProfileName,
    source: &S,
    context: &PathContext,
    fs: &F,
) -> Result<Profile, ProfileError>
where
    S: ProfileSource + ?Sized,
    F: PolicyFs + ?Sized,
{
    let root = read_named(name, source)?;
    resolve(root, source, context, fs)
}

/// Loads a profile from its text (a snapshot pushed with `policy.set`, FR-POL-01), reading any parents it
/// `extends` from `source`, and resolves it (module documentation).
///
/// # Errors
///
/// As [`load_profile`], except that the profile's own `name` is not checked against a file name.
pub fn load_profile_text<S, F>(text: &[u8], source: &S, context: &PathContext, fs: &F) -> Result<Profile, ProfileError>
where
    S: ProfileSource + ?Sized,
    F: PolicyFs + ?Sized,
{
    let root = Layer::parse(text, LayerKind::Profile)?;
    resolve(root, source, context, fs)
}

/// Reads and parses the profile `name`, checking that it calls itself `name`.
fn read_named<S: ProfileSource + ?Sized>(name: &ProfileName, source: &S) -> Result<Layer, ProfileError> {
    let origin = ProfileOrigin::Profile(name.clone());
    let text = source.read_profile(name).map_err(|error| {
        let kind = match error {
            LookupError::NotFound => ProfileErrorKind::ProfileNotFound,
            LookupError::Failed => ProfileErrorKind::ProfileUnreadable,
        };
        ProfileError::new(kind).in_origin(&origin)
    })?;
    let layer = Layer::parse(&text, LayerKind::Profile).map_err(|error| error.in_origin(&origin))?;
    // A file whose contents name another profile would make records and `extends` chains lie about what applied.
    if layer.name.as_ref() != Some(name) {
        return Err(ProfileError::new(ProfileErrorKind::NameMismatch)
            .at_key("name")
            .in_origin(&origin));
    }
    Ok(layer)
}

/// Steps 2 to 5 of the module documentation, for a root layer that was read successfully.
fn resolve<S, F>(root: Layer, source: &S, context: &PathContext, fs: &F) -> Result<Profile, ProfileError>
where
    S: ProfileSource + ?Sized,
    F: PolicyFs + ?Sized,
{
    // `Layer::parse` refuses a profile without a name, so this only guards the invariant.
    let name = root
        .name
        .clone()
        .ok_or_else(|| ProfileError::new(ProfileErrorKind::MissingKey).at_key("name"))?;
    let origin = ProfileOrigin::Profile(name.clone());
    let (mut merged, extends) = merge_chain(root, &name, source)?;
    if let Some(preset) = merged.preset.clone() {
        apply_preset(&mut merged, &preset).map_err(|error| error.in_origin(&origin))?;
    }
    build(merged, name, extends, context, fs).map_err(|error| error.in_origin(&origin))
}

/// Follows `extends` from `root` and merges the chain, child over parent. Returns the merged layer and the parents'
/// names, nearest first.
fn merge_chain<S: ProfileSource + ?Sized>(
    root: Layer,
    name: &ProfileName,
    source: &S,
) -> Result<(Layer, Vec<ProfileName>), ProfileError> {
    let mut names = vec![name.clone()];
    let mut chain = vec![root];
    while let Some(parent) = chain.last().and_then(|layer| layer.extends.clone()) {
        // Errors point at the `extends` key of the profile that names the bad parent, not at the root profile.
        let child = ProfileOrigin::Profile(names[names.len() - 1].clone());
        if names.contains(&parent) {
            return Err(ProfileError::new(ProfileErrorKind::ExtendsCycle)
                .at_key("extends")
                .in_origin(&child));
        }
        if chain.len() == MAX_EXTENDS_DEPTH {
            return Err(ProfileError::new(ProfileErrorKind::ExtendsTooDeep)
                .at_key("extends")
                .in_origin(&child));
        }
        chain.push(read_named(&parent, source)?);
        names.push(parent);
    }
    // Fold from the furthest ancestor down, so each child overrides everything above it. `chain` always holds the
    // root, so the default base is never used.
    let mut layers = chain.into_iter().rev();
    let base = layers.next().unwrap_or_default();
    let merged = layers.fold(base, override_layer);
    // The first name is the root's own; `Profile::extends` lists only its parents.
    names.remove(0);
    Ok((merged, names))
}

/// `child` over `parent`, per key (module documentation, step 2).
fn override_layer(parent: Layer, child: Layer) -> Layer {
    let mut exec_interpreters = parent.exec_interpreters;
    exec_interpreters.extend(child.exec_interpreters);
    let mut secrets_env = parent.secrets_env;
    secrets_env.extend(child.secrets_env);
    Layer {
        name: child.name,
        extends: child.extends,
        preset: child.preset.or(parent.preset),
        fs_read: child.fs_read.or(parent.fs_read),
        fs_write: child.fs_write.or(parent.fs_write),
        fs_deny: child.fs_deny.or(parent.fs_deny),
        exec_allow: child.exec_allow.or(parent.exec_allow),
        exec_ask: child.exec_ask.or(parent.exec_ask),
        exec_deny: child.exec_deny.or(parent.exec_deny),
        exec_project_executables: child.exec_project_executables.or(parent.exec_project_executables),
        exec_default: child.exec_default.or(parent.exec_default),
        exec_interpreters,
        exec_trusted_folders: child.exec_trusted_folders.or(parent.exec_trusted_folders),
        exec_trusted_tools: child.exec_trusted_tools.or(parent.exec_trusted_tools),
        exec_bash: child.exec_bash.or(parent.exec_bash),
        network_mode: child.network_mode.or(parent.network_mode),
        network_hosts: child.network_hosts.or(parent.network_hosts),
        network_approval_hosts: child.network_approval_hosts.or(parent.network_approval_hosts),
        network_loopback: child.network_loopback.or(parent.network_loopback),
        approvals_irreversible: child.approvals_irreversible.or(parent.approvals_irreversible),
        approvals_irreversible_commands: child
            .approvals_irreversible_commands
            .or(parent.approvals_irreversible_commands),
        checkpoints_roots: child.checkpoints_roots.or(parent.checkpoints_roots),
        checkpoints_required: child.checkpoints_required.or(parent.checkpoints_required),
        checkpoints_exclude: child.checkpoints_exclude.or(parent.checkpoints_exclude),
        recording_commands: child.recording_commands.or(parent.recording_commands),
        recording_output: child.recording_output.or(parent.recording_output),
        recording_retention_days: child.recording_retention_days.or(parent.recording_retention_days),
        output_mode: child.output_mode.or(parent.output_mode),
        secrets_env,
    }
}

/// Appends the preset's lists to `layer`'s (module documentation, step 3).
fn apply_preset(layer: &mut Layer, name: &str) -> Result<(), ProfileError> {
    let Some((name, text)) = presets::find(name) else {
        return Err(ProfileError::new(ProfileErrorKind::UnknownPreset).at_key("preset"));
    };
    let preset = Layer::parse(text.as_bytes(), LayerKind::Preset)
        .map_err(|error| error.in_origin(&ProfileOrigin::Preset(name)))?;
    // `fs.read = "all"` already covers whatever the preset reads; only an explicit list grows.
    if let (Some(ReadTemplate::Paths(paths)), Some(ReadTemplate::Paths(added))) = (&mut layer.fs_read, preset.fs_read) {
        union(paths, added);
    }
    append(&mut layer.fs_write, preset.fs_write);
    append(&mut layer.fs_deny, preset.fs_deny);
    append(&mut layer.exec_trusted_folders, preset.exec_trusted_folders);
    append(&mut layer.network_hosts, preset.network_hosts);
    append(&mut layer.network_approval_hosts, preset.network_approval_hosts);
    append(&mut layer.network_loopback, preset.network_loopback);
    append(&mut layer.checkpoints_roots, preset.checkpoints_roots);
    Ok(())
}

/// Appends `added` to `list`, treating an unset list as its default (empty for every list a preset may set).
fn append<T: PartialEq>(list: &mut Option<Vec<T>>, added: Option<Vec<T>>) {
    if let Some(added) = added {
        union(list.get_or_insert_with(Vec::new), added);
    }
}

/// Appends each element of `added` that `list` does not already hold.
fn union<T: PartialEq>(list: &mut Vec<T>, added: Vec<T>) {
    for item in added {
        if !list.contains(&item) {
            list.push(item);
        }
    }
}

/// Fills defaults and expands paths (module documentation, steps 4 and 5).
fn build<F: PolicyFs + ?Sized>(
    layer: Layer,
    name: ProfileName,
    extends: Vec<ProfileName>,
    context: &PathContext,
    fs: &F,
) -> Result<Profile, ProfileError> {
    let variables = Variables::resolve(context, fs)?;
    let paths = |templates: Option<Vec<PathTemplate>>, key: &str| expand_all(templates, key, &variables, fs);

    let read = match layer.fs_read {
        None | Some(ReadTemplate::All) => ReadScope::All,
        Some(ReadTemplate::Paths(templates)) => ReadScope::Paths(paths(Some(templates), "fs.read")?),
    };
    let mut trusted_folders = TrustedFolders::defaults();
    for folder in paths(layer.exec_trusted_folders, "exec.trusted_folders")? {
        trusted_folders.add(folder);
    }
    let bash = match layer.exec_bash {
        Some(template) => template
            .expand(&variables, fs)
            .map_err(|kind| ProfileError::new(kind).at_key("exec.bash"))?,
        None => CanonicalPath::new(DEFAULT_AGENT_BASH)
            .map_err(|_| ProfileError::new(ProfileErrorKind::PathUnresolvable).at_key("exec.bash"))?,
    };
    let mut interpreters = knsh_bash::Interpreters::defaults();
    for (family, entry) in layer.exec_interpreters {
        interpreters.extend(entry).map_err(|_| {
            ProfileError::new(ProfileErrorKind::InvalidValue {
                expected: "a family base name without a version suffix and options spelled -x or --name",
            })
            .at_key(&format!("exec.interpreters.{family}"))
        })?;
    }

    Ok(Profile {
        name,
        extends,
        preset: layer.preset,
        fs: FsPolicy {
            read,
            write: paths(layer.fs_write, "fs.write")?,
            deny: paths(layer.fs_deny, "fs.deny")?,
        },
        exec: ExecPolicy {
            allow: layer.exec_allow.unwrap_or_default(),
            ask: layer.exec_ask.unwrap_or_default(),
            deny: layer.exec_deny.unwrap_or_default(),
            project_executables: layer.exec_project_executables.unwrap_or(RuleAction::Ask),
            default: layer.exec_default.unwrap_or(RuleAction::Ask),
            interpreters,
            trusted_folders,
            trusted_tools: layer.exec_trusted_tools.unwrap_or_default(),
            bash,
        },
        network: NetworkPolicy {
            mode: layer.network_mode.unwrap_or(NetworkMode::None),
            hosts: layer.network_hosts.unwrap_or_default(),
            approval_hosts: layer.network_approval_hosts.unwrap_or_default(),
            loopback: layer.network_loopback.unwrap_or_default(),
        },
        approvals: ApprovalsPolicy {
            irreversible: layer.approvals_irreversible.unwrap_or(RuleAction::Ask),
            irreversible_commands: layer.approvals_irreversible_commands.unwrap_or_default(),
        },
        checkpoints: CheckpointPolicy {
            roots: paths(layer.checkpoints_roots, "checkpoints.roots")?,
            required: layer.checkpoints_required.unwrap_or(false),
            exclude: layer.checkpoints_exclude.unwrap_or_else(|| {
                DEFAULT_CHECKPOINT_EXCLUDES
                    .iter()
                    .map(|name| (*name).to_owned())
                    .collect()
            }),
        },
        recording: RecordingPolicy {
            commands: layer.recording_commands.unwrap_or(true),
            output: layer.recording_output.unwrap_or(false),
            retention_days: layer.recording_retention_days.unwrap_or(DEFAULT_RETENTION_DAYS),
        },
        output: OutputPolicy {
            mode: layer.output_mode.unwrap_or(OutputMode::Full),
        },
        secrets: layer
            .secrets_env
            .into_iter()
            .map(|(variable, entry)| {
                let injection = SecretInjection {
                    secret: entry.secret,
                    inject_for: entry.inject_for,
                    hosts: entry.hosts,
                };
                (variable, injection)
            })
            .collect(),
    })
}

/// Expands and canonicalises a path list, keeping the first copy of any path two entries resolve to. Errors name
/// `key[index]`.
fn expand_all<F: PolicyFs + ?Sized>(
    templates: Option<Vec<PathTemplate>>,
    key: &str,
    variables: &Variables,
    fs: &F,
) -> Result<Vec<CanonicalPath>, ProfileError> {
    let mut expanded = Vec::new();
    // A set, not `Vec::contains`: a 1 MiB profile can hold hundreds of thousands of entries, and a quadratic scan
    // over them would let one file stall the loader.
    let mut seen = std::collections::HashSet::new();
    for (index, template) in templates.unwrap_or_default().iter().enumerate() {
        let path = template
            .expand(variables, fs)
            .map_err(|kind| ProfileError::new(kind).at_key(&format!("{key}[{index}]")))?;
        // Two entries can name one place (`~/x` and a symlink to it); the list keeps each canonical path once.
        if seen.insert(path.clone()) {
            expanded.push(path);
        }
    }
    Ok(expanded)
}
