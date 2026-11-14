//! The known wrappers and their option grammars (KNSH-036; FR-LC-04).
//!
//! A wrapper runs another command given as its arguments: `env FOO=1 nice -n 5 git push` runs `git push`. The
//! classifier unwraps it, so the command is decided as what it runs, and records the wrapper as class `wrapper`. The
//! wrappers are those FR-LC-04 names, `env`, `command`, `exec`, `nice`, `nohup`, `time` (the program; the keyword is
//! read by the parser, [`TimeKeyword`](crate::TimeKeyword)), `timeout` and `xargs`, plus the `builtin` builtin, which
//! runs a builtin the same way `command` does (`builtin eval …` would otherwise hide an `eval`). The GNU coreutils
//! names Homebrew installs (`gtimeout`, `genv`, …) are the same programs.
//!
//! Each grammar is written out explicitly from the manual pages of macOS and GNU coreutils and findutils, as the union
//! of both where they agree; every wrapper here stops reading options at its first operand, as both do (`getopt` with
//! `+`, never permuting). An option outside the grammar makes the command dynamic
//! ([`UnknownWrapperOption`](crate::DynamicReason::UnknownWrapperOption)) instead of being guessed at: `env -S 'sh -c
//! x'` or `env -P /tmp/evil git` must never be read as something harmless. An option or operand built from an
//! expansion ([`ExpandedArgument`](crate::DynamicReason::ExpandedArgument)) is dynamic too: unquoted, it may split into
//! several words and so move the command (`nice -n $N git` with `N='5 sh -c x'`).

use crate::classify::Lookup;
use crate::interpreter_table::ArgumentText;
use crate::outcome::DynamicReason;

/// The known wrappers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Wrapper {
    /// `env [-iv] [-u name] [name=value …] [utility …]`; `-` alone is `-i`.
    Env,
    /// The `command [-pvV] [name …]` builtin. `-v` and `-V` only describe the name and run nothing.
    Command,
    /// The `builtin [name …]` builtin.
    Builtin,
    /// The `exec [-cl] [-a name] [command …]` builtin. Without a command it only applies its redirections.
    Exec,
    /// `nice [-n increment] [utility …]`, with the obsolete `-increment` and GNU's `--adjustment`.
    Nice,
    /// `nohup [--] utility …`.
    Nohup,
    /// The `time` program: macOS `time [-al] [-h | -p] [-o file]`, GNU `time [-apqv] [-f format] [-o file]`.
    Time,
    /// `timeout [-fpv] [-k duration] [-s signal] duration utility …`, with GNU's long options.
    Timeout,
    /// `xargs [options] [utility …]`; with no utility it runs `echo`.
    Xargs,
}

impl Wrapper {
    /// The wrapper a program's base name (or a builtin's name) is, if any.
    pub(crate) fn from_name(name: &str) -> Option<Self> {
        let base = name.rsplit('/').next().unwrap_or(name);
        match base {
            "env" | "genv" => Some(Self::Env),
            "command" => Some(Self::Command),
            "builtin" => Some(Self::Builtin),
            "exec" => Some(Self::Exec),
            "nice" | "gnice" => Some(Self::Nice),
            "nohup" | "gnohup" => Some(Self::Nohup),
            "time" | "gtime" => Some(Self::Time),
            "timeout" | "gtimeout" => Some(Self::Timeout),
            "xargs" | "gxargs" => Some(Self::Xargs),
            _ => None,
        }
    }

    /// How the wrapper runs its command: `command` and `builtin` reach builtins (never functions), and so does the
    /// `/usr/bin/command` script macOS ships, which runs the builtin; `exec` and the programs run a binary found on
    /// `PATH`, as `execvp` does.
    pub(crate) const fn inner_lookup(self) -> Lookup {
        match self {
            Self::Command | Self::Builtin => Lookup::Shell,
            Self::Env | Self::Exec | Self::Nice | Self::Nohup | Self::Time | Self::Timeout | Self::Xargs => {
                Lookup::Program
            }
        }
    }

    /// The option grammar.
    const fn grammar(self) -> Grammar {
        match self {
            Self::Env => Grammar {
                flags: "iv",
                valued: "u",
                long_flags: &["ignore-environment"],
                long_valued: &["unset"],
                ..Grammar::NONE
            },
            Self::Command => Grammar {
                flags: "pvV",
                ..Grammar::NONE
            },
            Self::Builtin | Self::Nohup => Grammar::NONE,
            Self::Exec => Grammar {
                flags: "cl",
                valued: "a",
                ..Grammar::NONE
            },
            Self::Nice => Grammar {
                valued: "n",
                long_valued: &["adjustment"],
                numeric: true,
                ..Grammar::NONE
            },
            Self::Time => Grammar {
                flags: "ahlpqv",
                valued: "fo",
                long_flags: &["append", "portability", "quiet", "verbose"],
                long_valued: &["format", "output"],
                ..Grammar::NONE
            },
            Self::Timeout => Grammar {
                flags: "fpv",
                valued: "ks",
                long_flags: &["foreground", "preserve-status", "verbose"],
                long_valued: &["kill-after", "signal"],
                ..Grammar::NONE
            },
            Self::Xargs => Grammar {
                flags: "0oprtx",
                valued: "EIJLPRSadns",
                optional: "eil",
                long_flags: &["exit", "interactive", "no-run-if-empty", "null", "open-tty", "verbose"],
                long_valued: &[
                    "arg-file",
                    "delimiter",
                    "max-args",
                    "max-chars",
                    "max-procs",
                    "process-slot-var",
                ],
                long_optional: &["eof", "max-lines", "replace"],
                ..Grammar::NONE
            },
        }
    }

    /// Reads the wrapper's arguments (the words after its name) and finds the command it runs.
    pub(crate) fn unwrap(self, arguments: &[ArgumentText<'_>]) -> Unwrap {
        let mut arguments = arguments.to_vec();
        if self == Self::Env {
            // `env -` is the obsolete spelling of `env -i`.
            for argument in arguments
                .iter_mut()
                .take_while(|argument| argument.is_some_and(|text| text.starts_with('-')))
            {
                if *argument == Some("-") {
                    *argument = Some("-i");
                }
            }
        }
        let (options, mut index) = match self.grammar().read(&arguments) {
            Ok(read) => read,
            Err(reason) => return Unwrap::Dynamic(reason),
        };
        match self {
            Self::Env => {
                // Every operand holding `=` is an assignment, as `env` reads it; the first without one is the command.
                while let Some(argument) = arguments.get(index) {
                    match argument {
                        Some(text) if text.contains('=') => index += 1,
                        Some(_) => break,
                        None => return Unwrap::Dynamic(DynamicReason::ExpandedArgument),
                    }
                }
            }
            Self::Command
                if options
                    .iter()
                    .any(|option| matches!(option.name, Name::Short('v' | 'V'))) =>
            {
                // `command -v x` describes `x` and runs nothing (FR-LC-04).
                return Unwrap::Nothing;
            }
            Self::Timeout => {
                // The duration, then the command.
                match arguments.get(index) {
                    Some(Some(_)) => index += 1,
                    Some(None) => return Unwrap::Dynamic(DynamicReason::ExpandedArgument),
                    None => return Unwrap::Nothing,
                }
            }
            Self::Xargs => {
                let placeholder = options.iter().find_map(Opt::placeholder);
                return match arguments.get(index) {
                    Some(_) => Unwrap::Runs {
                        index,
                        xargs: Some(Xargs { placeholder }),
                    },
                    None => Unwrap::Echo(Xargs { placeholder }),
                };
            }
            Self::Command | Self::Builtin | Self::Exec | Self::Nice | Self::Nohup | Self::Time => {}
        }
        match arguments.get(index) {
            Some(_) => Unwrap::Runs { index, xargs: None },
            // `env` prints the environment, `exec` applies its redirections, `nice` prints the niceness, and the
            // others fail: nothing else runs.
            None => Unwrap::Nothing,
        }
    }
}

/// What `xargs` adds to the command it runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Xargs {
    /// The replacement string of `-I`, `-J`, `-i` or `--replace`: words holding it are replaced by input at run time.
    pub(crate) placeholder: Option<String>,
}

/// What a wrapper runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Unwrap {
    /// The command whose name is the argument at `index` (counted from the first argument after the wrapper's name).
    Runs {
        /// Where the command's name is among the wrapper's arguments.
        index: usize,
        /// Set for `xargs`, which appends arguments read at run time.
        xargs: Option<Xargs>,
    },
    /// `xargs` with no command, which runs `echo`.
    Echo(Xargs),
    /// No other command (`command -v x`, `env` alone, `exec >log`).
    Nothing,
    /// The wrapper's arguments cannot be read with confidence.
    Dynamic(DynamicReason),
}

/// An option grammar: the short options as letters, the long ones without their `--`.
#[derive(Debug, Clone, Copy)]
struct Grammar {
    /// Short options without a value.
    flags: &'static str,
    /// Short options with a value, attached or the next argument.
    valued: &'static str,
    /// Short options with an optional value, attached only (GNU `xargs -i[replace]`).
    optional: &'static str,
    /// Long options without a value.
    long_flags: &'static [&'static str],
    /// Long options with a value, after `=` or the next argument.
    long_valued: &'static [&'static str],
    /// Long options with an optional value, after `=` only.
    long_optional: &'static [&'static str],
    /// Whether `-NUMBER` is an option (the obsolete `nice -5`).
    numeric: bool,
}

/// An option read by [`Grammar::read`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Opt<'a> {
    /// Which option.
    name: Name<'a>,
    /// Its value, if it took one.
    value: Option<&'a str>,
}

impl Opt<'_> {
    /// The replacement string an `xargs` option sets: `-I` and `-J` take one, `-i` and `--replace` default to `{}`.
    fn placeholder(&self) -> Option<String> {
        match self.name {
            Name::Short('I' | 'J') => self.value.map(str::to_owned),
            Name::Short('i') | Name::Long("replace") => {
                Some(self.value.filter(|value| !value.is_empty()).unwrap_or("{}").to_owned())
            }
            Name::Short(_) | Name::Long(_) | Name::Numeric => None,
        }
    }
}

/// An option's name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Name<'a> {
    /// `-x`.
    Short(char),
    /// `--name`.
    Long(&'a str),
    /// `-NUMBER`.
    Numeric,
}

impl Grammar {
    /// No options at all: only `--`.
    const NONE: Self = Self {
        flags: "",
        valued: "",
        optional: "",
        long_flags: &[],
        long_valued: &[],
        long_optional: &[],
        numeric: false,
    };

    /// Reads the options at the start of `arguments`, as `getopt` with `+` does: up to the first operand, `-` (an
    /// operand) or after `--`. Returns them and the index of the first operand.
    fn read<'a>(&self, arguments: &[ArgumentText<'a>]) -> Result<(Vec<Opt<'a>>, usize), DynamicReason> {
        let mut options = Vec::new();
        let mut index = 0;
        while let Some(argument) = arguments.get(index) {
            let Some(argument) = *argument else {
                return Err(DynamicReason::ExpandedArgument);
            };
            if argument == "--" {
                return Ok((options, index + 1));
            }
            if !argument.starts_with('-') || argument == "-" {
                break;
            }
            index += 1;
            if let Some(long) = argument.strip_prefix("--") {
                let (mut option, takes_next) = self.long(long)?;
                if takes_next {
                    option.value = Some(value_at(arguments, index)?);
                    index += 1;
                }
                options.push(option);
                continue;
            }
            let cluster = &argument[1..];
            if self.numeric && cluster.bytes().all(|byte| byte.is_ascii_digit()) {
                options.push(Opt {
                    name: Name::Numeric,
                    value: Some(cluster),
                });
                continue;
            }
            for (offset, letter) in cluster.char_indices() {
                let rest = &cluster[offset + letter.len_utf8()..];
                if self.flags.contains(letter) {
                    options.push(Opt {
                        name: Name::Short(letter),
                        value: None,
                    });
                } else if self.valued.contains(letter) {
                    let value = if rest.is_empty() {
                        let value = value_at(arguments, index)?;
                        index += 1;
                        value
                    } else {
                        rest
                    };
                    options.push(Opt {
                        name: Name::Short(letter),
                        value: Some(value),
                    });
                    break;
                } else if self.optional.contains(letter) {
                    options.push(Opt {
                        name: Name::Short(letter),
                        value: Some(rest),
                    });
                    break;
                } else {
                    return Err(DynamicReason::UnknownWrapperOption);
                }
            }
        }
        Ok((options, index))
    }

    /// Reads `--name`, `--name=value`: the option, and whether its value is the next argument.
    fn long<'a>(&self, long: &'a str) -> Result<(Opt<'a>, bool), DynamicReason> {
        let (name, value) = match long.split_once('=') {
            Some((name, value)) => (name, Some(value)),
            None => (long, None),
        };
        let option = Opt {
            name: Name::Long(name),
            value,
        };
        if self.long_flags.contains(&name) && value.is_none() {
            Ok((option, false))
        } else if self.long_valued.contains(&name) {
            Ok((option, value.is_none()))
        } else if self.long_optional.contains(&name) {
            Ok((option, false))
        } else {
            Err(DynamicReason::UnknownWrapperOption)
        }
    }
}

/// The value at `index`, for an option that takes the next argument.
fn value_at<'a>(arguments: &[ArgumentText<'a>], index: usize) -> Result<&'a str, DynamicReason> {
    match arguments.get(index) {
        Some(Some(value)) => Ok(value),
        Some(None) => Err(DynamicReason::ExpandedArgument),
        // The wrapper reports a missing value and runs nothing; the line is not read further.
        None => Err(DynamicReason::UnknownWrapperOption),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Unwraps `wrapper` with `line` split on blanks; a word holding `$` stands for an expansion.
    fn unwrap(wrapper: Wrapper, line: &str) -> Unwrap {
        let words: Vec<ArgumentText<'_>> = line
            .split_whitespace()
            .map(|word| (!word.contains('$')).then_some(word))
            .collect();
        wrapper.unwrap(&words)
    }

    fn runs(index: usize) -> Unwrap {
        Unwrap::Runs { index, xargs: None }
    }

    // FR-LC-04: `env` with assignments, `-i`, `-u`.
    #[test]
    fn env_grammar() {
        assert_eq!(unwrap(Wrapper::Env, "FOO=1 git push"), runs(1));
        assert_eq!(unwrap(Wrapper::Env, "-i FOO=1 BAR= git"), runs(3));
        assert_eq!(unwrap(Wrapper::Env, "- git"), runs(1));
        assert_eq!(unwrap(Wrapper::Env, "-u HOME -uPATH git"), runs(3));
        assert_eq!(unwrap(Wrapper::Env, "-iu HOME git"), runs(2));
        assert_eq!(unwrap(Wrapper::Env, "--unset=HOME --ignore-environment git"), runs(2));
        assert_eq!(unwrap(Wrapper::Env, "--unset HOME -- A=1 git"), runs(4));
        assert_eq!(unwrap(Wrapper::Env, "FOO=1"), Unwrap::Nothing);
        assert_eq!(unwrap(Wrapper::Env, ""), Unwrap::Nothing);
        // Options that change what runs or how it is found are not in the grammar.
        for line in [
            "-S x",
            "-P /tmp git",
            "-C /tmp git",
            "--split-string=x",
            "-0",
            "--chdir=/ git",
        ] {
            assert_eq!(
                unwrap(Wrapper::Env, line),
                Unwrap::Dynamic(DynamicReason::UnknownWrapperOption),
                "{line}"
            );
        }
        assert_eq!(
            unwrap(Wrapper::Env, "FOO=$X git"),
            Unwrap::Dynamic(DynamicReason::ExpandedArgument)
        );
        assert_eq!(
            unwrap(Wrapper::Env, "$X"),
            Unwrap::Dynamic(DynamicReason::ExpandedArgument)
        );
        assert_eq!(
            unwrap(Wrapper::Env, "-u"),
            Unwrap::Dynamic(DynamicReason::UnknownWrapperOption)
        );
    }

    #[test]
    fn command_builtin_and_exec_grammars() {
        assert_eq!(unwrap(Wrapper::Command, "git"), runs(0));
        assert_eq!(unwrap(Wrapper::Command, "-p git"), runs(1));
        assert_eq!(unwrap(Wrapper::Command, "-- git"), runs(1));
        assert_eq!(unwrap(Wrapper::Command, "-v git"), Unwrap::Nothing);
        assert_eq!(unwrap(Wrapper::Command, "-pV git"), Unwrap::Nothing);
        assert_eq!(unwrap(Wrapper::Command, ""), Unwrap::Nothing);
        assert_eq!(
            unwrap(Wrapper::Command, "-x git"),
            Unwrap::Dynamic(DynamicReason::UnknownWrapperOption)
        );
        assert_eq!(unwrap(Wrapper::Builtin, "eval x"), runs(0));
        assert_eq!(
            unwrap(Wrapper::Builtin, "-x eval"),
            Unwrap::Dynamic(DynamicReason::UnknownWrapperOption)
        );
        assert_eq!(unwrap(Wrapper::Exec, "-cl -a name git"), runs(3));
        assert_eq!(unwrap(Wrapper::Exec, "-aname git"), runs(1));
        assert_eq!(unwrap(Wrapper::Exec, ""), Unwrap::Nothing);
    }

    #[test]
    fn nice_nohup_and_time_grammars() {
        assert_eq!(unwrap(Wrapper::Nice, "-n 5 git"), runs(2));
        assert_eq!(unwrap(Wrapper::Nice, "-n5 git"), runs(1));
        assert_eq!(unwrap(Wrapper::Nice, "-5 git"), runs(1));
        assert_eq!(unwrap(Wrapper::Nice, "--adjustment=5 git"), runs(1));
        assert_eq!(unwrap(Wrapper::Nice, "git"), runs(0));
        assert_eq!(
            unwrap(Wrapper::Nice, "-n $N git"),
            Unwrap::Dynamic(DynamicReason::ExpandedArgument)
        );
        assert_eq!(unwrap(Wrapper::Nohup, "git"), runs(0));
        assert_eq!(unwrap(Wrapper::Nohup, "-- git"), runs(1));
        assert_eq!(
            unwrap(Wrapper::Nohup, "-p git"),
            Unwrap::Dynamic(DynamicReason::UnknownWrapperOption)
        );
        assert_eq!(unwrap(Wrapper::Time, "-p git"), runs(1));
        assert_eq!(unwrap(Wrapper::Time, "-al -o out git"), runs(3));
        assert_eq!(unwrap(Wrapper::Time, "-f %e --output=x git"), runs(3));
    }

    // FR-LC-04: `timeout` with a duration and options.
    #[test]
    fn timeout_grammar() {
        assert_eq!(unwrap(Wrapper::Timeout, "5 git push"), runs(1));
        assert_eq!(unwrap(Wrapper::Timeout, "-s KILL 5 git"), runs(3));
        assert_eq!(unwrap(Wrapper::Timeout, "-sKILL -k 2 5m git"), runs(4));
        assert_eq!(
            unwrap(Wrapper::Timeout, "--signal=TERM --preserve-status 5 git"),
            runs(3)
        );
        assert_eq!(unwrap(Wrapper::Timeout, "--kill-after 1 -v 5 git"), runs(4));
        assert_eq!(unwrap(Wrapper::Timeout, "5"), Unwrap::Nothing);
        assert_eq!(
            unwrap(Wrapper::Timeout, "$T git"),
            Unwrap::Dynamic(DynamicReason::ExpandedArgument)
        );
        assert_eq!(
            unwrap(Wrapper::Timeout, "--bogus 5 git"),
            Unwrap::Dynamic(DynamicReason::UnknownWrapperOption)
        );
    }

    #[test]
    fn xargs_grammar_and_placeholders() {
        let with = |index, placeholder: Option<&str>| Unwrap::Runs {
            index,
            xargs: Some(Xargs {
                placeholder: placeholder.map(str::to_owned),
            }),
        };
        assert_eq!(unwrap(Wrapper::Xargs, "rm"), with(0, None));
        assert_eq!(unwrap(Wrapper::Xargs, "-0 -n 1 -P4 rm -f"), with(4, None));
        assert_eq!(unwrap(Wrapper::Xargs, "-I {} mv {} x"), with(2, Some("{}")));
        assert_eq!(unwrap(Wrapper::Xargs, "-J% cp % x"), with(1, Some("%")));
        assert_eq!(unwrap(Wrapper::Xargs, "-i rm {}"), with(1, Some("{}")));
        assert_eq!(unwrap(Wrapper::Xargs, "--replace=@ rm @"), with(1, Some("@")));
        assert_eq!(unwrap(Wrapper::Xargs, "--null --max-args 2 rm"), with(3, None));
        assert_eq!(unwrap(Wrapper::Xargs, ""), Unwrap::Echo(Xargs { placeholder: None }));
        assert_eq!(unwrap(Wrapper::Xargs, "-0"), Unwrap::Echo(Xargs { placeholder: None }));
        assert_eq!(
            unwrap(Wrapper::Xargs, "-Q x"),
            Unwrap::Dynamic(DynamicReason::UnknownWrapperOption)
        );
    }

    #[test]
    fn wrapper_names() {
        assert_eq!(Wrapper::from_name("/usr/bin/env"), Some(Wrapper::Env));
        assert_eq!(Wrapper::from_name("gtimeout"), Some(Wrapper::Timeout));
        assert_eq!(Wrapper::from_name("sudo"), None);
        assert_eq!(Wrapper::from_name("environment"), None);
    }
}
