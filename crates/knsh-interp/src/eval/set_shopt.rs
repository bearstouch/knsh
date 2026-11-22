//! The `set` and `shopt` builtins (KNSH-104; NFR-COMPAT-02), as bash 5.2's `set.def` and `shopt.def` read their
//! arguments and report errors. Which options exist and what the interpreter holds of each is `crate::options`.

use std::fmt::Write as _;

use knsh_bash::Span;

use super::{Flow, Interpreter, Run, unsupported};
use crate::error::Unsupported;
use crate::options::{self, OptionError};
use crate::status::Status;

/// Bash 5.2's `set` usage line.
const SET_USAGE: &str = "set: usage: set [-abefhkmnptuvxBCEHPT] [-o option-name] [--] [-] [arg ...]";

/// Bash 5.2's `shopt` usage line.
const SHOPT_USAGE: &str = "shopt: usage: shopt [-pqsu] [-o] [optname ...]";

/// `set -o` (`commands` false) or `set +o` (true): every option, as a table or as the commands that set it.
fn set_o_text(listing: &[(&str, bool)], commands: bool) -> String {
    let mut text = String::new();
    for (name, on) in listing {
        if commands {
            let _ = writeln!(text, "set {}o {name}", if *on { '-' } else { '+' });
        } else {
            let _ = writeln!(text, "{name:<15}\t{}", if *on { "on" } else { "off" });
        }
    }
    text
}

/// One `shopt` line: `name<tab>on`, or with `-p` the command that sets it (`set -o` for a `set -o` option).
fn shopt_line(text: &mut String, name: &str, on: bool, print: bool, set_o: bool) {
    let _ = match (print, set_o) {
        (false, _) => writeln!(text, "{name:<15}\t{}", if on { "on" } else { "off" }),
        (true, false) => writeln!(text, "shopt {} {name}", if on { "-s" } else { "-u" }),
        (true, true) => writeln!(text, "set {}o {name}", if on { '-' } else { '+' }),
    };
}

/// What `shopt`'s options asked for.
#[derive(Default)]
#[allow(clippy::struct_excessive_bools)] // `shopt`'s independent option letters, as bash keeps them.
struct ShoptFlags {
    print: bool,
    quiet: bool,
    set: bool,
    unset: bool,
    set_o: bool,
}

/// `shopt`'s options and the names after them, or the first letter it does not take.
fn shopt_flags(args: &[String]) -> Result<(ShoptFlags, &[String]), char> {
    let mut flags = ShoptFlags::default();
    let mut names = args;
    while let Some((arg, after)) = names.split_first() {
        if arg == "--" {
            names = after;
            break;
        }
        if arg.len() < 2 || !arg.starts_with('-') {
            break;
        }
        for letter in arg.chars().skip(1) {
            match letter {
                'p' => flags.print = true,
                'q' => flags.quiet = true,
                's' => flags.set = true,
                'u' => flags.unset = true,
                'o' => flags.set_o = true,
                other => return Err(other),
            }
        }
        names = after;
    }
    Ok((flags, names))
}

impl Interpreter {
    /// Sets `set -o` option `name` to `on`; turning POSIX mode on or off also sets or removes `POSIXLY_CORRECT`, as
    /// bash's `set_posix_mode` does (KNSH-106).
    fn change_set_o(&mut self, name: &str, on: bool) -> Result<(), OptionError> {
        let interactive = self.state.is_interactive();
        let before = self.state.options().posix();
        options::change_set_o(self.state.options_mut(), interactive, name, on)?;
        let after = self.state.options().posix();
        if before != after {
            self.state.bind_posix_variable(after);
        }
        Ok(())
    }

    /// A refusal or bash's `invalid option name`, from reading or changing option `name` for `builtin`.
    fn option_error(
        &mut self,
        error: OptionError,
        builtin: &str,
        message: &str,
        name: &str,
        span: Span,
        run: &Run<'_>,
    ) -> Flow<()> {
        match error {
            OptionError::Unknown => {
                self.report(span, run, format_args!("{builtin}: {name}: {message}"));
                Ok(())
            }
            OptionError::Refused(feature) => Err(unsupported(feature, span).into()),
        }
    }

    /// `set [-abefhkmnptuvxBCEHPT] [-o name] [--] [-] [arg …]`: options on with `-`, off with `+`, `-o`/`+o` alone
    /// listing them; then the arguments left, if any (or after `--`, even none), become the positional parameters.
    /// `-` alone turns `-x` and `-v` off and ends the options. `set` alone, which lists every variable, is refused.
    pub(super) fn set_builtin(&mut self, args: &[String], span: Span, run: &Run<'_>) -> Flow<Status> {
        if args.is_empty() {
            return Err(unsupported(Unsupported::ShellVariable, span).into());
        }
        // Bash checks every option letter before it changes any.
        if let Some((on, letter)) = options::first_invalid_letter(args) {
            let sign = if on { '-' } else { '+' };
            self.report(span, run, format_args!("set: {sign}{letter}: invalid option"));
            self.report_plain(format_args!("{SET_USAGE}"));
            self.usage_error = true;
            return Ok(Status::new(2));
        }
        let interactive = self.state.is_interactive();
        let mut rest = args;
        let mut assign = false;
        while let Some((arg, after)) = rest.split_first() {
            let on = match arg.as_bytes().first() {
                Some(b'-') => true,
                Some(b'+') => false,
                _ => break,
            };
            rest = after;
            if arg == "-" || arg == "--" {
                if arg == "--" {
                    assign = true;
                } else {
                    let options = self.state.options_mut();
                    options.xtrace = false;
                    options.verbose = false;
                }
                break;
            }
            for letter in arg.chars().skip(1) {
                if letter != 'o' {
                    match options::change_letter(self.state.options_mut(), interactive, letter, on) {
                        Ok(()) => continue,
                        Err(OptionError::Unknown) => {
                            let sign = if on { '-' } else { '+' };
                            self.report(span, run, format_args!("set: {sign}{letter}: invalid option"));
                            self.report_plain(format_args!("{SET_USAGE}"));
                            self.usage_error = true;
                            return Ok(Status::new(2));
                        }
                        Err(OptionError::Refused(feature)) => return Err(unsupported(feature, span).into()),
                    }
                }
                match rest.split_first() {
                    Some((name, after)) if !name.is_empty() && !name.starts_with(['-', '+']) => {
                        rest = after;
                        if let Err(error) = self.change_set_o(name, on) {
                            self.option_error(error, "set", "invalid option name", name, span, run)?;
                            // Bash 5.2's `set_minus_o_option` returns `EX_USAGE` (KNSH-106: fatal in POSIX mode).
                            self.usage_error = true;
                            return Ok(Status::FAILURE);
                        }
                    }
                    _ => {
                        let listing = options::set_o_listing(self.state.options());
                        let text = set_o_text(&listing, !on);
                        if !self.print("set", text.as_bytes(), span, run).is_success() {
                            return Ok(Status::FAILURE);
                        }
                    }
                }
            }
        }
        if assign || !rest.is_empty() {
            self.state.set_positional(rest.to_vec());
        }
        Ok(Status::SUCCESS)
    }

    /// `shopt [-pqsu] [-o] [name …]`: `-s` and `-u` set and unset the options named; otherwise each is reported
    /// (`-q`: only through the status, 0 when every one is on), or every option is listed (`-p`: as commands).
    /// `-o` names `set -o` options instead. An unknown name is bash's `invalid shell option name`, status 1.
    pub(super) fn shopt_builtin(&mut self, args: &[String], span: Span, run: &Run<'_>) -> Flow<Status> {
        let (flags, names) = match shopt_flags(args) {
            Ok(parsed) => parsed,
            Err(letter) => {
                self.report(span, run, format_args!("shopt: -{letter}: invalid option"));
                self.report_plain(format_args!("{SHOPT_USAGE}"));
                return Ok(Status::new(2));
            }
        };
        if flags.set && flags.unset {
            self.report(
                span,
                run,
                format_args!("shopt: cannot set and unset shell options simultaneously"),
            );
            return Ok(Status::FAILURE);
        }
        let message = if flags.set_o {
            "invalid option name"
        } else {
            "invalid shell option name"
        };
        if (flags.set || flags.unset) && !names.is_empty() {
            let mut status = Status::SUCCESS;
            for name in names {
                let result = if flags.set_o {
                    self.change_set_o(name, flags.set)
                } else {
                    options::change_shopt(self.state.options_mut(), name, flags.set)
                };
                if let Err(error) = result {
                    self.option_error(error, "shopt", message, name, span, run)?;
                    status = Status::FAILURE;
                }
            }
            return Ok(status);
        }
        let listing: Vec<(String, bool)> = if names.is_empty() {
            let all = if flags.set_o {
                options::set_o_listing(self.state.options())
            } else {
                options::shopt_listing(self.state.options())
            };
            // `shopt -s` and `shopt -u` alone list only the options that are on, or off.
            all.into_iter()
                .filter(|(_, on)| (!flags.set || *on) && (!flags.unset || !*on))
                .map(|(name, on)| (name.to_owned(), on))
                .collect()
        } else {
            let mut found = Vec::with_capacity(names.len());
            let mut status = Status::SUCCESS;
            for name in names {
                let value = if flags.set_o {
                    options::set_o(self.state.options(), name)
                } else {
                    options::shopt(self.state.options(), name)
                };
                match value {
                    Ok(on) => found.push((name.clone(), on)),
                    Err(error) => {
                        self.option_error(error, "shopt", message, name, span, run)?;
                        status = Status::FAILURE;
                    }
                }
            }
            if !status.is_success() {
                // Bash still reports the names it knows.
                self.print_shopt(&found, &flags, span, run);
                return Ok(status);
            }
            found
        };
        let status = self.print_shopt(&listing, &flags, span, run);
        if !status.is_success() {
            return Ok(status);
        }
        // Asked by name: 0 only when every option named is on.
        let all_on = names.is_empty() || listing.iter().all(|(_, on)| *on);
        Ok(if all_on { Status::SUCCESS } else { Status::FAILURE })
    }

    /// Writes `listing` as `shopt` reports it, unless `-q`.
    fn print_shopt(&mut self, listing: &[(String, bool)], flags: &ShoptFlags, span: Span, run: &Run<'_>) -> Status {
        if flags.quiet {
            return Status::SUCCESS;
        }
        let mut text = String::new();
        for (name, on) in listing {
            shopt_line(&mut text, name, *on, flags.print, flags.set_o);
        }
        self.print("shopt", text.as_bytes(), span, run)
    }
}
