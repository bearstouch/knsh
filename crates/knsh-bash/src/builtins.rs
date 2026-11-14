//! The builtin commands bash runs without looking a name up on `PATH` (KNSH-035; FR-LC-03).
//!
//! The supervisor resolves every simple command's name to a binary, except names bash handles itself. Getting this
//! wrong in one direction is dangerous: a name taken for a builtin that bash actually looks up on `PATH` would hide a
//! program (`./node_modules/.bin/mapfile`) from resolution and policy. Getting it wrong in the other direction is
//! harmless: a real builtin resolved on `PATH` is at worst `NotFound` (the line fails closed) or a binary that policy
//! decides anyway. So the list is the builtins of bash 3.2, which `/bin/bash` on macOS is and which every later bash
//! keeps; builtins added in bash 4 and 5 (`mapfile`, `readarray`, `compopt`) are left out and resolved on `PATH`.
//!
//! Reserved words (`if`, `time`, `[[`, …) are not here: the parser consumes them where they act as keywords
//! ([`ReservedWord`](crate::ReservedWord)), so one that reaches a simple command's name was quoted or escaped
//! (`"time" ls`, `\if`), and bash then looks it up as an ordinary command, on `PATH`.

/// The builtins of bash 3.2, sorted for binary search. Every one is also a builtin in bash 4 and 5.
const BUILTINS: &[&str] = &[
    ".", ":", "[", "alias", "bg", "bind", "break", "builtin", "caller", "cd", "command", "compgen", "complete",
    "continue", "declare", "dirs", "disown", "echo", "enable", "eval", "exec", "exit", "export", "false", "fc", "fg",
    "getopts", "hash", "help", "history", "jobs", "kill", "let", "local", "logout", "popd", "printf", "pushd", "pwd",
    "read", "readonly", "return", "set", "shift", "shopt", "source", "suspend", "test", "times", "trap", "true",
    "type", "typeset", "ulimit", "umask", "unalias", "unset", "wait",
];

/// Whether bash 3.2 (and every later bash) runs `name` as a builtin, without a `PATH` lookup.
///
/// `name` is the command name after quote removal. A name containing `/` is never a builtin: bash executes it as a
/// path.
///
/// # Examples
///
/// ```
/// assert!(knsh_bash::is_builtin("cd"));
/// assert!(knsh_bash::is_builtin("export"));
/// assert!(!knsh_bash::is_builtin("git"));
/// assert!(!knsh_bash::is_builtin("mapfile")); // bash 4 and later only
/// ```
#[must_use]
pub fn is_builtin(name: &str) -> bool {
    BUILTINS.binary_search(&name).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_list_is_sorted_for_binary_search() {
        assert!(BUILTINS.windows(2).all(|pair| pair[0] < pair[1]));
    }

    // FR-LC-03: builtins are not resolved as binaries.
    #[test]
    fn recognises_bash_3_2_builtins() {
        for name in [
            "cd", "export", ".", ":", "[", "source", "eval", "exec", "test", "true", "printf",
        ] {
            assert!(is_builtin(name), "{name}");
        }
    }

    // Names bash 3.2 looks up on PATH must never be taken for builtins, or a program would escape resolution.
    #[test]
    fn programs_keywords_and_newer_builtins_are_not_builtins() {
        for name in [
            "git",
            "ls",
            "",
            "mapfile",
            "readarray",
            "compopt",
            "coproc",
            "if",
            "time",
            "[[",
            "{",
            "!",
            "/bin/cd",
            "./cd",
            "CD",
            "cd ",
        ] {
            assert!(!is_builtin(name), "{name}");
        }
    }
}
