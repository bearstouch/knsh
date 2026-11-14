//! Terminal marks: OSC 7 (working directory) and OSC 133 (prompt, command, output and exit code), KNSH-022,
//! NFR-COMPAT-10, `specs/08-integrations/terminals-and-shells.md#terminal-markup`.
//!
//! In integration mode the hosted shell's own hooks write the marks, because only the shell knows when a prompt is
//! drawn and when a command starts; `knsh` decides only whether they are wanted and says so in [`MARKS_VAR`]. The
//! hooks live in the zsh and bash wrappers ([`super::zsh::ZSHENV`], [`super::bash::BASHRC`]), are installed whether or
//! not recording is on, and write nothing unless standard output is a terminal at that moment.
//!
//! This module is the reference for what the hooks write: the byte sequences and the `file://` URL encoding. Tests
//! compare the hooks' real output with it; the native interpreter (KNSH-101, KNSH-107) will write the same bytes.
//!
//! For one command line, the terminal sees, in this order:
//!
//! 1. [`COMMAND_END`] with the exit status of the previous line (only when a line ran), OSC 7 for the working
//!    directory, then [`PROMPT_START`] — written just before the prompt;
//! 2. [`COMMAND_START`] — at the end of the prompt, where the user's input begins (part of `PS1`);
//! 3. [`OUTPUT_START`] — when the line is about to run;
//! 4. [`COMMAND_END`]`;<exit>` — when the prompt comes back.

use std::fmt::Write as _;

/// Set to `1` in the hosted shell's environment when `knsh` wants the marks (its standard output is a terminal).
/// The wrapper removes it, so no command inherits it.
pub const MARKS_VAR: &str = "KNSH_TERMINAL_MARKS";

/// OSC 133 `A`: a prompt starts.
pub const PROMPT_START: &str = "\x1b]133;A\x07";

/// OSC 133 `B`: the prompt ends and the command line the user types starts.
pub const COMMAND_START: &str = "\x1b]133;B\x07";

/// OSC 133 `C`: the command line runs; its output starts.
pub const OUTPUT_START: &str = "\x1b]133;C\x07";

/// OSC 133 `D`, followed by `;<exit>` and BEL ([`command_end`]): the command line has ended.
pub const COMMAND_END: &str = "\x1b]133;D";

/// Whether `knsh` asks the hosted shell for marks: only when its standard output is a terminal, so that output
/// redirected to a file or a pipe never carries escape sequences (KNSH-022).
#[must_use]
pub fn wanted(stdout_is_terminal: bool) -> bool {
    stdout_is_terminal
}

/// OSC 133 `D;<exit>`.
#[must_use]
pub fn command_end(exit: i32) -> String {
    format!("{COMMAND_END};{exit}\x07")
}

/// OSC 7 for the working directory `path` on `host`: `ESC ] 7 ; file://<host><path> BEL`, both percent-encoded
/// ([`percent_encode_path`]).
#[must_use]
pub fn working_directory(host: &[u8], path: &[u8]) -> String {
    format!(
        "\x1b]7;file://{}{}\x07",
        percent_encode_path(host),
        percent_encode_path(path)
    )
}

/// `path` with every byte outside `A-Z a-z 0-9 / . _ ~ -` written as `%XX` (upper-case hex), so that spaces,
/// non-ASCII bytes (as their UTF-8 bytes), `%`, `#`, `?`, control characters and the terminator itself can never end
/// or change the URL. `/` is kept as the path separator.
#[must_use]
pub fn percent_encode_path(path: &[u8]) -> String {
    let mut encoded = String::with_capacity(path.len());
    for &byte in path {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b'~' | b'-') {
            encoded.push(char::from(byte));
        } else {
            // Writing to a String cannot fail.
            let _ = write!(encoded, "%{byte:02X}");
        }
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    // KNSH-022 unit test (NFR-COMPAT-10): the working directory is a percent-encoded `file://host/path` URL. The
    // hooks' own encoders are compared with this one on real zsh and bash in tests/terminal_integration.rs.
    #[test]
    fn osc7_percent_encodes_path() {
        assert_eq!(
            percent_encode_path(b"/Users/u/src/knsh-1.0_x~y"),
            "/Users/u/src/knsh-1.0_x~y"
        );
        assert_eq!(
            percent_encode_path("/tmp/a b/é%#?".as_bytes()),
            "/tmp/a%20b/%C3%A9%25%23%3F"
        );
        // Control characters, including the BEL and ESC that would end or break the sequence, and non-UTF-8 bytes.
        assert_eq!(percent_encode_path(b"/x\x07\x1b\n\x7f\xff"), "/x%07%1B%0A%7F%FF");
        assert_eq!(
            working_directory(b"mac.local", b"/tmp/a b"),
            "\x1b]7;file://mac.local/tmp/a%20b\x07"
        );
    }

    #[test]
    fn command_end_carries_the_exit_status() {
        assert_eq!(command_end(0), "\x1b]133;D;0\x07");
        assert_eq!(command_end(130), "\x1b]133;D;130\x07");
    }

    // KNSH-022: marks only when standard output is a terminal.
    #[test]
    fn marks_are_wanted_only_on_a_terminal() {
        assert!(wanted(true));
        assert!(!wanted(false));
    }
}
