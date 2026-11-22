//! OSC 133 terminal marks (KNSH-107, NFR-COMPAT-10): the same bytes `knsh`'s integration mode writes through the
//! hosted shell's hooks (`knsh::integration::marks`), written here by the native shell itself.
//!
//! For one command line, the terminal sees, in this order: [`command_end`] with the previous line's status (only
//! when a line ran), OSC 7 and [`PROMPT_START`] before the prompt; [`COMMAND_START`] at the end of the prompt,
//! where the user's input begins; [`OUTPUT_START`] when the line is about to run.

/// OSC 133 `A`: a prompt starts.
pub const PROMPT_START: &str = "\x1b]133;A\x07";

/// OSC 133 `B`: the prompt ends and the command line the user types starts.
pub const COMMAND_START: &str = "\x1b]133;B\x07";

/// OSC 133 `C`: the command line runs; its output starts.
pub const OUTPUT_START: &str = "\x1b]133;C\x07";

/// OSC 133 `D;<exit>`: the command line has ended with status `exit`.
#[must_use]
pub fn command_end(exit: i32) -> String {
    format!("\x1b]133;D;{exit}\x07")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn marks_are_osc_133() {
        assert_eq!(command_end(0), "\x1b]133;D;0\x07");
        assert_eq!(command_end(130), "\x1b]133;D;130\x07");
        for mark in [PROMPT_START, COMMAND_START, OUTPUT_START] {
            assert!(mark.starts_with("\x1b]133;") && mark.ends_with('\x07'));
        }
    }
}
