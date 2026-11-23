//! `knsh --version` (KNSH-024): the version banner, and the advisory label every pre-phase 2 build carries.
//!
//! Until the phase 2 gates are met (`specs/01-overview/roadmap.md`) the engine enforces nothing. Its release is labelled
//! advisory wherever a user or a client looks at what they are running: here, in `hello` (`advisory: true`, served by
//! `knshd`, `specs/06-api/handshake.md`) and in the README. The label goes when phase 2 qualifies.

/// Whether this build is advisory only. Builds before the phase 2 release always are; `knshd` reports the same value in `hello`.
pub const ADVISORY: bool = true;

/// The notice printed under the copyright line of an advisory build. Says both halves of the roadmap's gate: no
/// security guarantees, and not for running agents unattended.
pub const ADVISORY_LABEL: &str = "Advisory build: no security guarantees; not for running agents unattended.";

/// The `arch-vendor-os` triple of this build, in the style of GNU bash's `--version` (`arm64-apple-darwin`).
fn platform() -> String {
    let arch = match std::env::consts::ARCH {
        "aarch64" => "arm64",
        other => other,
    };
    let rest = match std::env::consts::OS {
        "macos" => "apple-darwin",
        "linux" => "unknown-linux-gnu",
        other => other,
    };
    format!("{arch}-{rest}")
}

/// The first line of `knsh --version`, without a newline: `Kinetic Shell (knsh), version 0.1.0 (arm64-apple-darwin)`.
#[must_use]
pub fn headline() -> String {
    format!(
        "Kinetic Shell (knsh), version {} ({})",
        env!("CARGO_PKG_VERSION"),
        platform()
    )
}

/// The text `knsh --version` prints, modelled on GNU bash: a banner with the version and platform, the copyright
/// and licence, then the advisory notice when [`ADVISORY`] holds. Ends with a newline.
#[must_use]
pub fn text() -> String {
    let mut text = format!(
        "{}\n\
         Copyright (C) 2026 bearstouch and Kinetic Shell contributors\n\
         License: MIT\n",
        headline(),
    );
    if ADVISORY {
        text.push('\n');
        text.push_str(ADVISORY_LABEL);
        text.push('\n');
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    // KNSH-024 acceptance: `knsh --version` states that the build is advisory, with no security guarantees and not for
    // running agents unattended.
    #[test]
    fn version_output_contains_advisory_label() {
        let text = text();
        assert!(
            text.starts_with(&format!(
                "Kinetic Shell (knsh), version {} (",
                env!("CARGO_PKG_VERSION")
            )),
            "{text}"
        );
        let lower = text.to_lowercase();
        for phrase in [
            "advisory",
            "no security guarantees",
            "not for running agents unattended",
        ] {
            assert!(lower.contains(phrase), "missing {phrase:?} in {text}");
        }
        assert!(text.ends_with('\n'));
    }
}
