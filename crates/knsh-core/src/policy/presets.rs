//! The presets the engine ships, as data (FR-POL-02, FR-POL-03, FR-AGT-04, FR-AGT-32, KNSH-058).
//!
//! A preset is a profile fragment for what an agent CLI itself needs: its model API host, its configuration folder
//! and the project. It is TOML text compiled into the binary and read by the same loader as any profile, so the
//! engine never generates policy in code. A preset may only add to path and host lists (see
//! [`Layer::parse`](super::layer::Layer::parse)), including `network.class_hosts`; its entries are appended to the
//! resolved profile's lists.
//!
//! Each preset's hosts and folders were read from the CLI release named in its file, and are checked again per
//! release (`specs/08-integrations/agent-clis.md#per-release-checklist`): a CLI that moves its model host or
//! configuration folder fails closed inside its envelope until its preset follows.

/// Every preset by name, with its TOML text.
pub const PRESETS: &[(&str, &str)] = &[
    ("claude-code", include_str!("presets/claude-code.toml")),
    ("codex-cli", include_str!("presets/codex-cli.toml")),
    ("generic", include_str!("presets/generic.toml")),
];

/// Presets that grant no model host, so the profile must name the one its CLI uses (FR-AGT-32).
const NO_MODEL_HOST: &[&str] = &["generic"];

/// The text and static name of the preset called `name`, if the engine ships one.
pub(crate) fn find(name: &str) -> Option<(&'static str, &'static str)> {
    PRESETS.iter().find(|(preset, _)| *preset == name).copied()
}

/// Whether a profile naming the preset `name` must itself name its CLI's model host (FR-AGT-32).
pub(crate) fn profile_names_model_host(name: &str) -> bool {
    NO_MODEL_HOST.contains(&name)
}
