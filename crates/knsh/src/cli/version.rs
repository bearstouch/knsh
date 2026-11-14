//! `knsh --version` (KNSH-024): the version, and the advisory label every phase 1 build carries.
//!
//! Phase 1 observes and records; it enforces nothing (`specs/01-overview/roadmap.md`). Its release is labelled
//! advisory wherever a user or a client looks at what they are running: here, in `hello` (`advisory: true`, served by
//! `knshd`, `specs/06-api/handshake.md`) and in the README. The label goes when phase 2 qualifies.

/// Whether this build is advisory only. Phase 1 builds always are; `knshd` reports the same value in `hello`.
pub const ADVISORY: bool = true;

/// The label printed under the version of an advisory build. Says both halves of the roadmap's phase 1 gate: no
/// security guarantees, and not for running agents unattended.
pub const ADVISORY_LABEL: &str =
    "ADVISORY BUILD (phase 1, observe only): no security guarantees; not for running agents unattended.";

/// The text `knsh --version` prints: the program and package version on the first line, then the advisory label
/// when [`ADVISORY`] holds. Ends with a newline.
#[must_use]
pub fn text() -> String {
    let mut text = format!("knsh {}\n", env!("CARGO_PKG_VERSION"));
    if ADVISORY {
        text.push_str(ADVISORY_LABEL);
        text.push('\n');
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    // KNSH-024 acceptance: `knsh --version` states that phase 1 is advisory, with no security guarantees and not for
    // running agents unattended.
    #[test]
    fn version_output_contains_advisory_label() {
        let text = text();
        assert!(
            text.starts_with(&format!("knsh {}\n", env!("CARGO_PKG_VERSION"))),
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
