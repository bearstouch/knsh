//! Bash 5.2's shell options: the `set -o` names and letters and the `shopt` names, with what the interpreter holds of
//! each (KNSH-104; NFR-COMPAT-02).
//!
//! An option the interpreter implements is read from and written to [`ShellOptions`]. Every other option bash has is
//! listed with the value it always has here (bash's default for a shell started as `bash -c`), so `set -o`, `set +o`,
//! `shopt`, `shopt -p` and `test -o` print bash's whole table; changing one of those to the other value is refused
//! ([`Unsupported::ShellOption`]), since the interpreter would not then behave as bash does. Setting such an option to
//! the value it already has is accepted, as it changes nothing.
//!
//! The functions here are pure: the builtins in `eval::options` do the reporting.

use crate::error::Unsupported;
use crate::state::ShellOptions;

/// What the interpreter holds of one option.
#[derive(Clone, Copy)]
enum Held {
    /// Implemented: read and written in [`ShellOptions`].
    Field(fn(&mut ShellOptions) -> &mut bool),
    /// Not implemented: always this value.
    Fixed(bool),
    /// Not implemented, and its value differs in an interactive shell, where the line editor and history keep it
    /// (KNSH-107): this value in a non-interactive shell, refused in an interactive one.
    Editing(bool),
}

/// One `set -o` option: its name, its letter (for `set -x` and `$-`), and what is held of it.
struct SetOption {
    name: &'static str,
    letter: Option<char>,
    held: Held,
}

/// Bash 5.2's `set -o` options, in its listing order (alphabetical).
const SET_OPTIONS: &[SetOption] = &[
    SetOption {
        name: "allexport",
        letter: Some('a'),
        held: Held::Fixed(false),
    },
    SetOption {
        name: "braceexpand",
        letter: Some('B'),
        held: Held::Fixed(true),
    },
    SetOption {
        name: "emacs",
        letter: None,
        held: Held::Editing(false),
    },
    SetOption {
        name: "errexit",
        letter: Some('e'),
        held: Held::Field(|options| &mut options.errexit),
    },
    SetOption {
        name: "errtrace",
        letter: Some('E'),
        held: Held::Field(|options| &mut options.errtrace),
    },
    SetOption {
        name: "functrace",
        letter: Some('T'),
        held: Held::Field(|options| &mut options.functrace),
    },
    SetOption {
        name: "hashall",
        letter: Some('h'),
        held: Held::Fixed(true),
    },
    SetOption {
        name: "histexpand",
        letter: Some('H'),
        held: Held::Editing(false),
    },
    SetOption {
        name: "history",
        letter: None,
        held: Held::Editing(false),
    },
    SetOption {
        name: "ignoreeof",
        letter: None,
        held: Held::Fixed(false),
    },
    SetOption {
        name: "interactive-comments",
        letter: None,
        held: Held::Fixed(true),
    },
    SetOption {
        name: "keyword",
        letter: Some('k'),
        held: Held::Fixed(false),
    },
    SetOption {
        name: "monitor",
        letter: Some('m'),
        held: Held::Field(|options| &mut options.monitor),
    },
    SetOption {
        name: "noclobber",
        letter: Some('C'),
        held: Held::Field(|options| &mut options.noclobber),
    },
    SetOption {
        name: "noexec",
        letter: Some('n'),
        held: Held::Field(|options| &mut options.noexec),
    },
    SetOption {
        name: "noglob",
        letter: Some('f'),
        held: Held::Field(|options| &mut options.noglob),
    },
    SetOption {
        name: "nolog",
        letter: None,
        held: Held::Fixed(false),
    },
    SetOption {
        name: "notify",
        letter: Some('b'),
        held: Held::Fixed(false),
    },
    SetOption {
        name: "nounset",
        letter: Some('u'),
        held: Held::Field(|options| &mut options.nounset),
    },
    SetOption {
        name: "onecmd",
        letter: Some('t'),
        held: Held::Fixed(false),
    },
    SetOption {
        name: "physical",
        letter: Some('P'),
        held: Held::Field(|options| &mut options.physical),
    },
    SetOption {
        name: "pipefail",
        letter: None,
        held: Held::Field(|options| &mut options.pipefail),
    },
    // POSIX mode is KNSH-106.
    SetOption {
        name: "posix",
        letter: None,
        held: Held::Fixed(false),
    },
    SetOption {
        name: "privileged",
        letter: Some('p'),
        held: Held::Fixed(false),
    },
    SetOption {
        name: "verbose",
        letter: Some('v'),
        held: Held::Field(|options| &mut options.verbose),
    },
    SetOption {
        name: "vi",
        letter: None,
        held: Held::Editing(false),
    },
    SetOption {
        name: "xtrace",
        letter: Some('x'),
        held: Held::Field(|options| &mut options.xtrace),
    },
];

/// Bash 5.2's `shopt` options (alphabetical, its listing order), with what is held of each: the ones KNSH-098 to
/// KNSH-104 implement, and every other at bash 5.2's default for `bash -c`.
const SHOPT_OPTIONS: &[(&str, Held)] = &[
    ("assoc_expand_once", Held::Fixed(false)),
    ("autocd", Held::Fixed(false)),
    ("cdable_vars", Held::Fixed(false)),
    ("cdspell", Held::Fixed(false)),
    ("checkhash", Held::Fixed(false)),
    ("checkjobs", Held::Fixed(false)),
    ("checkwinsize", Held::Fixed(true)),
    ("cmdhist", Held::Fixed(true)),
    ("compat31", Held::Fixed(false)),
    ("compat32", Held::Fixed(false)),
    ("compat40", Held::Fixed(false)),
    ("compat41", Held::Fixed(false)),
    ("compat42", Held::Fixed(false)),
    ("compat43", Held::Fixed(false)),
    ("compat44", Held::Fixed(false)),
    ("complete_fullquote", Held::Fixed(true)),
    ("direxpand", Held::Fixed(false)),
    ("dirspell", Held::Fixed(false)),
    ("dotglob", Held::Field(|options| &mut options.dotglob)),
    ("execfail", Held::Fixed(false)),
    ("expand_aliases", Held::Field(|options| &mut options.expand_aliases)),
    ("extdebug", Held::Fixed(false)),
    ("extglob", Held::Field(|options| &mut options.extglob)),
    ("extquote", Held::Fixed(true)),
    ("failglob", Held::Field(|options| &mut options.failglob)),
    ("force_fignore", Held::Fixed(true)),
    ("globasciiranges", Held::Fixed(true)),
    ("globskipdots", Held::Fixed(true)),
    ("globstar", Held::Field(|options| &mut options.globstar)),
    ("gnu_errfmt", Held::Fixed(false)),
    ("histappend", Held::Fixed(false)),
    ("histreedit", Held::Fixed(false)),
    ("histverify", Held::Fixed(false)),
    ("hostcomplete", Held::Fixed(true)),
    ("huponexit", Held::Fixed(false)),
    ("inherit_errexit", Held::Field(|options| &mut options.inherit_errexit)),
    ("interactive_comments", Held::Fixed(true)),
    ("lastpipe", Held::Field(|options| &mut options.lastpipe)),
    ("lithist", Held::Fixed(false)),
    ("localvar_inherit", Held::Fixed(false)),
    ("localvar_unset", Held::Fixed(false)),
    ("login_shell", Held::Fixed(false)),
    ("mailwarn", Held::Fixed(false)),
    ("no_empty_cmd_completion", Held::Fixed(false)),
    ("nocaseglob", Held::Field(|options| &mut options.nocaseglob)),
    // `[[` and `case` matching without case: not implemented.
    ("nocasematch", Held::Fixed(false)),
    ("noexpand_translation", Held::Fixed(false)),
    ("nullglob", Held::Field(|options| &mut options.nullglob)),
    ("patsub_replacement", Held::Fixed(true)),
    ("progcomp", Held::Fixed(true)),
    ("progcomp_alias", Held::Fixed(false)),
    ("promptvars", Held::Fixed(true)),
    ("restricted_shell", Held::Fixed(false)),
    ("shift_verbose", Held::Fixed(false)),
    ("sourcepath", Held::Fixed(true)),
    ("varredir_close", Held::Fixed(false)),
    ("xpg_echo", Held::Field(|options| &mut options.xpg_echo)),
];

/// Why an option could not be read or changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OptionError {
    /// Bash has no option of that name: its error, `invalid option name` (`set -o`) or `invalid shell option name`
    /// (`shopt`).
    Unknown,
    /// An option the interpreter does not implement, or does not know the value of in this shell.
    Refused(Unsupported),
}

/// The value of `held` in `options` (`interactive`: the shell is interactive).
fn value(held: Held, options: &ShellOptions, interactive: bool) -> Result<bool, OptionError> {
    match held {
        Held::Field(field) => {
            let mut copy = options.clone();
            Ok(*field(&mut copy))
        }
        Held::Editing(_) if interactive => Err(OptionError::Refused(Unsupported::ShellOption)),
        Held::Fixed(value) | Held::Editing(value) => Ok(value),
    }
}

/// Sets `held` in `options` to `on`: refused for an option not implemented, unless it already has that value.
fn change(held: Held, options: &mut ShellOptions, interactive: bool, on: bool) -> Result<(), OptionError> {
    match held {
        Held::Field(field) => {
            *field(options) = on;
            Ok(())
        }
        Held::Fixed(_) | Held::Editing(_) if value(held, options, interactive)? == on => Ok(()),
        Held::Fixed(_) | Held::Editing(_) => Err(OptionError::Refused(Unsupported::ShellOption)),
    }
}

fn set_option(name: &str) -> Option<&'static SetOption> {
    SET_OPTIONS.iter().find(|option| option.name == name)
}

fn shopt_option(name: &str) -> Option<Held> {
    SHOPT_OPTIONS
        .iter()
        .find(|(option, _)| *option == name)
        .map(|(_, held)| *held)
}

/// The value of `set -o` option `name`.
///
/// # Errors
///
/// [`OptionError::Unknown`] for a name bash does not have; [`OptionError::Refused`] for a line-editing or history
/// option of an interactive shell (KNSH-107).
pub(crate) fn set_o(options: &ShellOptions, interactive: bool, name: &str) -> Result<bool, OptionError> {
    let option = set_option(name).ok_or(OptionError::Unknown)?;
    value(option.held, options, interactive)
}

/// Sets `set -o` option `name` to `on`.
///
/// # Errors
///
/// [`OptionError::Unknown`] for a name bash does not have; [`OptionError::Refused`] to change an option the
/// interpreter does not implement.
pub(crate) fn change_set_o(
    options: &mut ShellOptions,
    interactive: bool,
    name: &str,
    on: bool,
) -> Result<(), OptionError> {
    let option = set_option(name).ok_or(OptionError::Unknown)?;
    change(option.held, options, interactive, on)
}

/// Sets the option of `set` letter `letter` (`set -e`, `set +x`) to `on`.
///
/// # Errors
///
/// [`OptionError::Unknown`] for a letter `set` does not take (bash's `invalid option`); [`OptionError::Refused`] to
/// change an option the interpreter does not implement, and for `-i` and `-r`, which bash takes only in particular
/// shells.
pub(crate) fn change_letter(
    options: &mut ShellOptions,
    interactive: bool,
    letter: char,
    on: bool,
) -> Result<(), OptionError> {
    if matches!(letter, 'i' | 'r') {
        return Err(OptionError::Refused(Unsupported::ShellOption));
    }
    let option = SET_OPTIONS
        .iter()
        .find(|option| option.letter == Some(letter))
        .ok_or(OptionError::Unknown)?;
    change(option.held, options, interactive, on)
}

/// Every `set -o` option with its value, in bash's order: what `set -o` and `set +o` list.
///
/// # Errors
///
/// [`OptionError::Refused`] in an interactive shell, whose line-editing and history options the interpreter does not
/// know (KNSH-107).
pub(crate) fn set_o_listing(
    options: &ShellOptions,
    interactive: bool,
) -> Result<Vec<(&'static str, bool)>, OptionError> {
    SET_OPTIONS
        .iter()
        .map(|option| Ok((option.name, value(option.held, options, interactive)?)))
        .collect()
}

/// The value of `shopt` option `name`.
///
/// # Errors
///
/// [`OptionError::Unknown`] for a name bash does not have.
pub(crate) fn shopt(options: &ShellOptions, name: &str) -> Result<bool, OptionError> {
    let held = shopt_option(name).ok_or(OptionError::Unknown)?;
    value(held, options, false)
}

/// Sets `shopt` option `name` to `on`.
///
/// # Errors
///
/// [`OptionError::Unknown`] for a name bash does not have; [`OptionError::Refused`] to change an option the
/// interpreter does not implement.
pub(crate) fn change_shopt(options: &mut ShellOptions, name: &str, on: bool) -> Result<(), OptionError> {
    let held = shopt_option(name).ok_or(OptionError::Unknown)?;
    change(held, options, false, on)
}

/// Every `shopt` option with its value, in bash's order.
pub(crate) fn shopt_listing(options: &ShellOptions) -> Vec<(&'static str, bool)> {
    SHOPT_OPTIONS
        .iter()
        .map(|(name, held)| (*name, value(*held, options, false).unwrap_or(false)))
        .collect()
}

/// The first option letter `set` does not take among `args` (with its sign, `true` for `-`), found as bash 5.2's
/// `set_builtin` checks every option with `internal_getopt` before it changes any: so `set -e -q` changes nothing.
/// The scan ends at the first word that is not an option, at `-` or `--`; `-o` takes the rest of its word, or the
/// next word unless that starts with `-` (bash's optional argument, `o;`). `-i` and `-r` are left for
/// [`change_letter`], which refuses them.
pub(crate) fn first_invalid_letter(args: &[String]) -> Option<(bool, char)> {
    let mut rest = args;
    while let Some((arg, after)) = rest.split_first() {
        let on = match arg.as_bytes().first() {
            Some(b'-') => true,
            Some(b'+') => false,
            _ => return None,
        };
        if arg.len() == 1 || arg == "--" {
            return None;
        }
        rest = after;
        let letters: Vec<char> = arg.chars().skip(1).collect();
        for (index, &letter) in letters.iter().enumerate() {
            if letter == 'o' {
                if index + 1 == letters.len()
                    && let Some((_, after)) = rest.split_first().filter(|(name, _)| !name.starts_with('-'))
                {
                    rest = after;
                }
                break;
            }
            let known = matches!(letter, 'i' | 'r') || SET_OPTIONS.iter().any(|option| option.letter == Some(letter));
            if !known {
                return Some((on, letter));
            }
        }
    }
    None
}

/// Whether a `set` with these literal arguments would be refused whatever the state (checked before the script runs):
/// listing every variable (`set` alone), or changing an option the interpreter does not implement. Errors bash
/// reports (an unknown option) are left for the builtin.
pub(crate) fn set_refusal(args: &[String]) -> Option<Unsupported> {
    if args.is_empty() {
        return Some(Unsupported::ShellVariable);
    }
    let mut scratch = ShellOptions::default();
    let mut rest = args;
    while let Some((arg, after)) = rest.split_first() {
        let Some(on) = arg.chars().next().and_then(|sign| match sign {
            '-' => Some(true),
            '+' => Some(false),
            _ => None,
        }) else {
            break;
        };
        if arg.len() == 1 || arg == "--" {
            break;
        }
        rest = after;
        for letter in arg.chars().skip(1) {
            if letter == 'o' {
                match rest.split_first() {
                    Some((name, after)) if !name.starts_with(['-', '+']) && !name.is_empty() => {
                        rest = after;
                        if let Err(OptionError::Refused(feature)) = change_set_o(&mut scratch, false, name, on) {
                            return Some(feature);
                        }
                    }
                    _ => {}
                }
            } else if let Err(OptionError::Refused(feature)) = change_letter(&mut scratch, false, letter, on) {
                return Some(feature);
            }
        }
    }
    None
}

/// Whether a `shopt` with these literal arguments would be refused whatever the state: changing an option the
/// interpreter does not implement (`shopt -s nocasematch`), or with `-o` a `set -o` one.
pub(crate) fn shopt_refusal(args: &[String]) -> Option<Unsupported> {
    let mut on: Option<bool> = None;
    let mut set_o_names = false;
    let mut names = args;
    while let Some((arg, after)) = names.split_first() {
        if arg == "--" {
            names = after;
            break;
        }
        if !arg.starts_with('-') || arg.len() == 1 {
            break;
        }
        for letter in arg.chars().skip(1) {
            match letter {
                's' => on = Some(true),
                'u' => on = Some(false),
                'o' => set_o_names = true,
                _ => {}
            }
        }
        names = after;
    }
    let on = on?;
    let mut scratch = ShellOptions::default();
    names.iter().find_map(|name| {
        let result = if set_o_names {
            change_set_o(&mut scratch, false, name, on)
        } else {
            change_shopt(&mut scratch, name, on)
        };
        match result {
            Err(OptionError::Refused(feature)) => Some(feature),
            Ok(()) | Err(OptionError::Unknown) => None,
        }
    })
}

/// `$-`: the letters of the options that are on, in bash's order (`flags.c`'s `shell_flags`), with `i` in an
/// interactive shell, then `c` for a shell running a `-c` string (every non-interactive run here).
pub(crate) fn dash_flags(options: &ShellOptions, interactive: bool) -> String {
    const ORDER: &str = "abefhikmnprtuvxBCEHPT";
    let mut flags = String::new();
    for letter in ORDER.chars() {
        let on = if letter == 'i' {
            interactive
        } else {
            SET_OPTIONS
                .iter()
                .find(|option| option.letter == Some(letter))
                .is_some_and(|option| value(option.held, options, interactive).unwrap_or(false))
        };
        if on {
            flags.push(letter);
        }
    }
    if !interactive {
        flags.push('c');
    }
    flags
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(args: &[&str]) -> Vec<String> {
        args.iter().map(|arg| (*arg).to_owned()).collect()
    }

    // KNSH-104: the listings hold bash 5.2's options in its order.
    #[test]
    fn listings_follow_bash_order() {
        let options = ShellOptions::default();
        let names: Vec<&str> = set_o_listing(&options, false)
            .unwrap()
            .into_iter()
            .map(|(name, _)| name)
            .collect();
        let mut sorted = names.clone();
        sorted.sort_unstable();
        assert_eq!(names, sorted);
        assert_eq!(names.len(), 27);
        let shopts = shopt_listing(&options);
        assert!(shopts.windows(2).all(|pair| pair[0].0 < pair[1].0));
        assert!(shopts.contains(&("checkwinsize", true)));
        assert!(set_o_listing(&options, true).is_err());
    }

    // KNSH-104: `$-` holds the letters of the options that are on, in bash's order.
    #[test]
    fn dash_flags_follow_bash_order() {
        let mut options = ShellOptions::default();
        assert_eq!(dash_flags(&options, false), "hBc");
        options.errexit = true;
        options.xtrace = true;
        options.nounset = true;
        options.errtrace = true;
        options.physical = true;
        assert_eq!(dash_flags(&options, false), "ehuxBEPc");
        options.monitor = true;
        assert_eq!(dash_flags(&options, true), "ehimuxBEP");
    }

    // KNSH-104: implemented options change; others are refused unless already at the value asked for.
    #[test]
    fn changes_are_refused_only_for_options_not_held() {
        let mut options = ShellOptions::default();
        assert_eq!(change_letter(&mut options, false, 'e', true), Ok(()));
        assert!(options.errexit);
        assert_eq!(change_letter(&mut options, false, 'h', true), Ok(()));
        assert_eq!(
            change_letter(&mut options, false, 'h', false),
            Err(OptionError::Refused(Unsupported::ShellOption))
        );
        assert_eq!(change_letter(&mut options, false, 'q', true), Err(OptionError::Unknown));
        assert_eq!(
            change_set_o(&mut options, false, "bogus", true),
            Err(OptionError::Unknown)
        );
        assert_eq!(change_shopt(&mut options, "extglob", true), Ok(()));
        assert!(options.extglob);
        assert_eq!(
            change_shopt(&mut options, "nocasematch", true),
            Err(OptionError::Refused(Unsupported::ShellOption))
        );
        assert_eq!(change_shopt(&mut options, "nocasematch", false), Ok(()));
        assert_eq!(shopt(&options, "bogus"), Err(OptionError::Unknown));
    }

    // KNSH-104: literal forms refused before the script runs.
    #[test]
    fn literal_refusals() {
        assert_eq!(set_refusal(&[]), Some(Unsupported::ShellVariable));
        assert_eq!(set_refusal(&strings(&["-eux", "-o", "pipefail"])), None);
        assert_eq!(set_refusal(&strings(&["-a"])), Some(Unsupported::ShellOption));
        assert_eq!(set_refusal(&strings(&["-o", "posix"])), Some(Unsupported::ShellOption));
        assert_eq!(set_refusal(&strings(&["--", "-a"])), None);
        assert_eq!(set_refusal(&strings(&["-e", "x", "-a"])), None);
        assert_eq!(set_refusal(&strings(&["-q"])), None);
        assert_eq!(
            shopt_refusal(&strings(&["-s", "nocasematch"])),
            Some(Unsupported::ShellOption)
        );
        assert_eq!(shopt_refusal(&strings(&["-s", "extglob", "bogus"])), None);
        assert_eq!(
            shopt_refusal(&strings(&["-so", "posix"])),
            Some(Unsupported::ShellOption)
        );
        assert_eq!(shopt_refusal(&strings(&["nocasematch"])), None);
    }
}
