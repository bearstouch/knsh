//! The message a human sees when an interactive `knsh` session opens and when it ends.
//!
//! Pure text: the caller decides whether to print it (a terminal on standard error, `[shell] banner` not `false`,
//! see `crate::integration::config`) so scripts and pipes never see it. The start message is the first line of
//! `knsh --version`, so what a user sees is what the build reports.

use super::version::headline;

/// Whether colour is wanted: `NO_COLOR` (any non-empty value) and `TERM=dumb` switch it off.
#[must_use]
pub fn wants_color(no_color: Option<&str>, term: Option<&str>) -> bool {
    no_color.is_none_or(str::is_empty) && term.is_some_and(|term| term != "dumb")
}

/// Wraps `text` in the SGR sequence `code` when `color` holds.
fn paint(text: &str, code: &str, color: bool) -> String {
    if color {
        format!("\x1b[{code}m{text}\x1b[0m")
    } else {
        text.to_owned()
    }
}

/// The line printed when the session opens: `Kinetic Shell (knsh), version 0.1.0 (arm64-apple-darwin)`.
#[must_use]
pub fn start_text(color: bool) -> String {
    format!("{}\n", paint(&headline(), "1", color))
}

/// The line printed when the session ends.
#[must_use]
pub fn end_text(color: bool) -> String {
    format!("{}\n", paint("Kinetic Shell: session ended. Goodbye.", "2", color))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn start_text_is_the_single_version_headline() {
        let text = start_text(false);
        assert_eq!(text, format!("{}\n", headline()));
        assert!(text.starts_with("Kinetic Shell (knsh), version "));
        assert_eq!(text.lines().count(), 1);
    }

    #[test]
    fn plain_text_has_no_escape_sequences_and_colour_adds_them() {
        assert!(!start_text(false).contains('\x1b'));
        assert!(!end_text(false).contains('\x1b'));
        assert!(start_text(true).contains('\x1b'));
        assert!(end_text(true).contains('\x1b'));
    }

    #[test]
    fn color_is_off_for_no_color_and_dumb_terminals() {
        assert!(wants_color(None, Some("xterm-256color")));
        assert!(wants_color(Some(""), Some("xterm")));
        assert!(!wants_color(Some("1"), Some("xterm")));
        assert!(!wants_color(None, Some("dumb")));
        assert!(!wants_color(None, None));
    }
}
