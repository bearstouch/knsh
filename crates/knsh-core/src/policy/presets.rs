//! The presets the engine ships, as data (FR-POL-02, FR-POL-03, FR-AGT-04).
//!
//! A preset is a profile fragment for what an agent CLI itself needs: its model API host, its configuration folder
//! and the project. It is TOML text compiled into the binary and read by the same loader as any profile, so the
//! engine never generates policy in code. A preset may only add to path and host lists (see
//! [`Layer::parse`](super::layer::Layer::parse)); its entries are appended to the resolved profile's lists.
//!
//! The contents are provisional until KNSH-058 tests each preset against its CLI.

/// Every preset by name, with its TOML text.
pub const PRESETS: &[(&str, &str)] = &[
    ("claude-code", include_str!("presets/claude-code.toml")),
    ("codex-cli", include_str!("presets/codex-cli.toml")),
    ("generic", include_str!("presets/generic.toml")),
];

/// The text and static name of the preset called `name`, if the engine ships one.
pub(crate) fn find(name: &str) -> Option<(&'static str, &'static str)> {
    PRESETS.iter().find(|(preset, _)| *preset == name).copied()
}
