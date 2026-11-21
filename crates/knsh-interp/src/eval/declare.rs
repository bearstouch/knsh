//! `declare` and `typeset`, `export`, `readonly` and `unset` (KNSH-101; NFR-COMPAT-02), following bash 5.2's
//! `declare.def` and `setattr.def`.
//!
//! The attributes kept are those of [`Attributes`]: `-x`, `-r`, `-i`, `-l`, `-u` and `-t`. Arrays (`-a`, `-A`,
//! `name[…]`) and name references (`-n`) arrive with functions and scopes (KNSH-103) and are refused; so is any
//! use of a variable bash maintains itself, and a listing that would include them (`declare -p` without names,
//! `readonly -p`), since this interpreter does not hold them. Functions cannot be defined yet (KNSH-103), so `-f`
//! and `-F` find none, as bash finds none in a shell that defined none.
//!
//! The arguments of these builtins that look like assignments (`export x=$y`) were expanded as assignments: no
//! word splitting or pathname expansion of the value (`eval::Interpreter::command_arguments`).

use std::ffi::OsString;

use knsh_bash::Span;

use super::{Flow, Interpreter, Run, Stop, unsupported};
use crate::arith::Failure;
use crate::error::Unsupported;
use crate::quote;
use crate::state::{AssignError, Attributes, is_name, refuses_assignment};
use crate::status::Status;

/// Bash's usage line for each declaration builtin.
fn usage(name: &str) -> &'static str {
    match name {
        "export" => "[-fn] [name[=value] ...] or export -p",
        "readonly" => "[-aAf] [name[=value] ...] or readonly -p",
        "typeset" => "[-aAfFgiIlnrtux] name[=value] ... or typeset -p [-aAfFilnrtux] [name ...]",
        _ => "[-aAfFgiIlnrtux] [name[=value] ...] or declare -p [-aAfFilnrtux] [name ...]",
    }
}

/// The option letters each declaration builtin takes.
fn allowed(name: &str) -> &'static str {
    match name {
        "export" => "fnp",
        "readonly" => "aAfp",
        _ => "aAfFgiIlnprtux",
    }
}

/// The options given to a declaration builtin: letters turned on (`-x`) and off (`+x`).
#[derive(Debug, Default)]
struct Given {
    on: String,
    off: String,
}

impl Given {
    fn has(&self, letter: char) -> bool {
        self.on.contains(letter) || self.off.contains(letter)
    }
}

/// One operand: `name`, `name=value` or `name+=value`.
struct Operand<'a> {
    name: &'a str,
    value: Option<&'a str>,
    append: bool,
}

fn operand(arg: &str) -> Operand<'_> {
    match arg.split_once('=') {
        Some((name, value)) => match name.strip_suffix('+') {
            Some(name) => Operand {
                name,
                value: Some(value),
                append: true,
            },
            None => Operand {
                name,
                value: Some(value),
                append: false,
            },
        },
        None => Operand {
            name: arg,
            value: None,
            append: false,
        },
    }
}

impl Interpreter {
    /// Whether `name` is a variable bash maintains itself or sets by default and the interpreter does not hold, so
    /// a builtin acting on it must be refused (`value`: the builtin assigns it a value of its own).
    fn bash_maintains(&self, name: &str, value: bool) -> bool {
        refuses_assignment(name) || (!value && self.state.is_unemulated(name))
    }

    /// `export`, `readonly`, `declare` and `typeset` (`name`) with `args`.
    pub(super) fn declare_builtin(&mut self, name: &str, args: &[String], span: Span, run: &Run<'_>) -> Flow<Status> {
        let (given, operands) = match self.declaration_options(name, args, span, run) {
            Ok(parsed) => parsed,
            Err(status) => return Ok(status),
        };
        if given.has('a') || given.has('A') {
            return Err(unsupported(Unsupported::Array, span).into());
        }
        if given.has('n') && name != "export" {
            return Err(unsupported(Unsupported::Nameref, span).into());
        }
        if given.has('f') || given.has('F') {
            return Ok(self.declare_functions(name, operands, span, run));
        }
        let declares = matches!(name, "declare" | "typeset");
        if operands.is_empty() {
            return self.declare_listing(name, &given, span, run);
        }
        if declares && given.on.contains('p') {
            return self.declare_print(name, operands, span, run);
        }
        let mut status = Status::SUCCESS;
        for arg in operands {
            let operand = operand(arg);
            if operand.name.contains('[') {
                return Err(unsupported(Unsupported::Array, span).into());
            }
            if !is_name(operand.name) {
                self.report(span, run, format_args!("{name}: `{arg}': not a valid identifier"));
                status = Status::FAILURE;
                continue;
            }
            if self.bash_maintains(operand.name, operand.value.is_some()) {
                return Err(unsupported(Unsupported::ShellVariable, span).into());
            }
            if !self.declare_one(name, &given, &operand, span, run)? {
                status = Status::FAILURE;
            }
        }
        Ok(status)
    }

    /// Reads the options of declaration builtin `name`: `-x` and (for `declare`) `+x` words, up to `--` or the
    /// first operand. `Err` with status 2 after bash's message for a letter it does not take.
    fn declaration_options<'a>(
        &mut self,
        name: &str,
        args: &'a [String],
        span: Span,
        run: &Run<'_>,
    ) -> Result<(Given, &'a [String]), Status> {
        let mut given = Given::default();
        let mut rest = args;
        let plus_allowed = matches!(name, "declare" | "typeset");
        while let Some(first) = rest.first() {
            if first == "--" {
                rest = &rest[1..];
                break;
            }
            let (on, letters) = match first.as_bytes().first() {
                Some(b'-') if first.len() > 1 => (true, &first[1..]),
                Some(b'+') if first.len() > 1 && plus_allowed => (false, &first[1..]),
                _ => break,
            };
            for letter in letters.chars() {
                if !allowed(name).contains(letter) || (!on && letter == 'p') {
                    let sign = if on { '-' } else { '+' };
                    self.report(span, run, format_args!("{name}: {sign}{letter}: invalid option"));
                    self.report_plain(format_args!("{name}: usage: {name} {}", usage(name)));
                    return Err(Status::new(2));
                }
                if on {
                    given.on.push(letter);
                } else {
                    given.off.push(letter);
                }
            }
            rest = &rest[1..];
        }
        Ok((given, rest))
    }

    /// `-f` and `-F`: no function can be defined yet (KNSH-103), so none is listed, and naming one fails as bash's
    /// does for a name that is not a function.
    fn declare_functions(&mut self, name: &str, operands: &[String], span: Span, run: &Run<'_>) -> Status {
        if operands.is_empty() {
            return Status::SUCCESS;
        }
        if matches!(name, "export" | "readonly") {
            for function in operands {
                let function = operand(function).name;
                self.report(span, run, format_args!("{name}: {function}: not a function"));
            }
        }
        Status::FAILURE
    }

    /// A declaration builtin without operands: the variables with the attributes asked for, as `declare -p` prints
    /// them. Only the exported ones can be listed as bash would: every other listing would include variables bash
    /// maintains itself.
    fn declare_listing(&mut self, name: &str, given: &Given, span: Span, run: &Run<'_>) -> Flow<Status> {
        let exported_only = match name {
            "export" => !given.on.contains('n'),
            "readonly" => false,
            _ => given.on.chars().filter(|letter| *letter != 'p').eq(['x']) && given.off.is_empty(),
        };
        if !exported_only {
            return Err(unsupported(Unsupported::ShellVariable, span).into());
        }
        let mut text = String::new();
        let listed: Vec<(String, Option<String>, Attributes)> = self
            .state
            .all_variables()
            .filter(|(_, _, attributes)| attributes.exported)
            .map(|(name, value, attributes)| {
                (
                    name.to_owned(),
                    value.map(|value| value.to_string_lossy().into_owned()),
                    attributes,
                )
            })
            .collect();
        for (variable, value, attributes) in listed {
            if self.state.is_unemulated(&variable) || refuses_assignment(&variable) {
                return Err(unsupported(Unsupported::ShellVariable, span).into());
            }
            text.push_str(&declaration(&variable, value.as_deref(), attributes));
        }
        Ok(self.print(name, text.as_bytes(), span, run))
    }

    /// `declare -p name …`: each variable as a `declare` command that recreates it.
    fn declare_print(&mut self, name: &str, operands: &[String], span: Span, run: &Run<'_>) -> Flow<Status> {
        let mut status = Status::SUCCESS;
        let mut text = String::new();
        for variable in operands {
            if variable.contains('[') {
                return Err(unsupported(Unsupported::Array, span).into());
            }
            if self.bash_maintains(variable, false) {
                return Err(unsupported(Unsupported::ShellVariable, span).into());
            }
            if let Some(attributes) = self.state.attributes(variable) {
                let value = self
                    .state
                    .variable(variable)
                    .map(|value| value.to_string_lossy().into_owned());
                text.push_str(&declaration(variable, value.as_deref(), attributes));
            } else {
                // Printed before the message, as bash prints each variable as it goes.
                let _ = self.print(name, text.as_bytes(), span, run);
                text.clear();
                self.report(span, run, format_args!("{name}: {variable}: not found"));
                status = Status::FAILURE;
            }
        }
        if self.print(name, text.as_bytes(), span, run) != Status::SUCCESS {
            status = Status::FAILURE;
        }
        Ok(status)
    }

    /// One operand of declaration builtin `builtin`: its attributes changed as `given` says and its value
    /// assigned. `false` after reporting bash's error.
    fn declare_one(
        &mut self,
        builtin: &str,
        given: &Given,
        operand: &Operand<'_>,
        span: Span,
        run: &Run<'_>,
    ) -> Flow<bool> {
        let name = operand.name;
        let declares = matches!(builtin, "declare" | "typeset");
        let readonly = self.state.is_readonly(name);
        if readonly && (operand.value.is_some() || given.off.contains('r')) {
            // Bash's `declare` names itself in the message; `export` and `readonly` report as an assignment does.
            if declares {
                self.report(span, run, format_args!("{builtin}: {name}: readonly variable"));
            } else {
                self.report(span, run, format_args!("{name}: readonly variable"));
            }
            return Ok(false);
        }
        let (on, off) = match builtin {
            "export" if given.on.contains('n') => (String::new(), "x".to_owned()),
            "export" => ("x".to_owned(), String::new()),
            "readonly" => ("r".to_owned(), String::new()),
            _ => (given.on.clone(), given.off.clone()),
        };
        // Everything but read-only is set before the value is assigned, so `-i`, `-l` and `-u` apply to it.
        self.state.change_attributes(name, |attributes| {
            apply(attributes, &on, &off, false);
        });
        if let Some(value) = operand.value {
            match self.state.assign(name, OsString::from(value), operand.append) {
                Ok(()) => {}
                Err(AssignError::Arithmetic(failure)) => {
                    return Err(self.arithmetic_failed(builtin, failure, span, run));
                }
                Err(AssignError::Unsupported(feature)) => return Err(unsupported(feature, span).into()),
                Err(AssignError::Readonly | AssignError::Invalid) => {
                    self.report(span, run, format_args!("{name}: readonly variable"));
                    return Ok(false);
                }
            }
        }
        self.state.change_attributes(name, |attributes| {
            apply(attributes, &on, &off, true);
        });
        Ok(true)
    }

    /// An arithmetic error assigning an integer variable for `builtin`: reported, and the line abandoned, as bash's
    /// `evalexp` does.
    fn arithmetic_failed(&mut self, builtin: &str, failure: Failure, span: Span, run: &Run<'_>) -> Stop {
        match failure {
            Failure::Error(message) => {
                self.report(span, run, format_args!("{builtin}: {message}"));
            }
            Failure::Readonly(variable) => {
                self.report(span, run, format_args!("{variable}: readonly variable"));
            }
            Failure::Unbound(variable) => {
                self.report(span, run, format_args!("{variable}: unbound variable"));
                return Stop::Exit(Status::FAILURE);
            }
            Failure::Unsupported(feature) => return unsupported(feature, span).into(),
        }
        self.state.set_last_status(Status::FAILURE);
        Stop::Discard
    }

    /// `unset [-fvn] name …`.
    pub(super) fn unset_builtin(&mut self, args: &[String], span: Span, run: &Run<'_>) -> Flow<Status> {
        let (options, names) = match self.options("unset", "[-f] [-v] [-n] [name ...]", "fvn", args, span, run) {
            Ok(parsed) => parsed,
            Err(status) => return Ok(status),
        };
        // `-f`: no function can be defined yet (KNSH-103), and unsetting one that does not exist succeeds.
        if options.contains('f') && !options.contains('v') {
            return Ok(Status::SUCCESS);
        }
        let mut status = Status::SUCCESS;
        for name in names {
            if name.contains('[') {
                return Err(unsupported(Unsupported::Array, span).into());
            }
            if is_name(name) && self.bash_maintains(name, false) {
                return Err(unsupported(Unsupported::ShellVariable, span).into());
            }
            match self.state.unset(name) {
                Ok(()) => {}
                Err(AssignError::Invalid) => {
                    self.report(span, run, format_args!("unset: `{name}': not a valid identifier"));
                    status = Status::FAILURE;
                }
                Err(AssignError::Readonly | AssignError::Arithmetic(_) | AssignError::Unsupported(_)) => {
                    self.report(
                        span,
                        run,
                        format_args!("unset: {name}: cannot unset: readonly variable"),
                    );
                    status = Status::FAILURE;
                }
            }
        }
        Ok(status)
    }
}

/// Applies option letters `on` and `off` to `attributes`: read-only only when `readonly_too` (it is set after the
/// value is assigned). `-l` and `-u` exclude each other, the last given winning.
fn apply(attributes: &mut Attributes, on: &str, off: &str, readonly_too: bool) {
    for letter in on.chars() {
        match letter {
            'x' => attributes.exported = true,
            'r' if readonly_too => attributes.readonly = true,
            'i' => attributes.integer = true,
            'l' => {
                attributes.lowercase = true;
                attributes.uppercase = false;
            }
            'u' => {
                attributes.uppercase = true;
                attributes.lowercase = false;
            }
            't' => attributes.trace = true,
            _ => {}
        }
    }
    for letter in off.chars() {
        match letter {
            'x' => attributes.exported = false,
            'i' => attributes.integer = false,
            'l' => attributes.lowercase = false,
            'u' => attributes.uppercase = false,
            't' => attributes.trace = false,
            _ => {}
        }
    }
}

/// The `declare` command that recreates a variable, as `declare -p` prints it: `declare -rx name="value"`, or
/// without `=` for a variable declared without a value.
fn declaration(name: &str, value: Option<&str>, attributes: Attributes) -> String {
    let letters = attributes.letters();
    let flags = if letters.is_empty() {
        "--".to_owned()
    } else {
        format!("-{letters}")
    };
    match value {
        Some(value) => format!("declare {flags} {name}={}\n", quote::declare_value(value)),
        None => format!("declare {flags} {name}\n"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // KNSH-101: `declare -p` lines, checked against bash.
    #[test]
    fn declarations_print_like_declare_p() {
        let exported = Attributes {
            exported: true,
            ..Attributes::default()
        };
        assert_eq!(
            declaration("x", Some("1"), Attributes::default()),
            "declare -- x=\"1\"\n"
        );
        assert_eq!(declaration("OLDPWD", None, exported), "declare -x OLDPWD\n");
        let both = Attributes {
            readonly: true,
            exported: true,
            integer: true,
            ..Attributes::default()
        };
        assert_eq!(declaration("n", Some("7"), both), "declare -irx n=\"7\"\n");
    }

    #[test]
    fn options_apply_with_lower_and_upper_exclusive() {
        let mut attributes = Attributes::default();
        apply(&mut attributes, "lxr", "", false);
        assert!(attributes.lowercase && attributes.exported && !attributes.readonly);
        apply(&mut attributes, "u", "x", true);
        assert!(attributes.uppercase && !attributes.lowercase && !attributes.exported);
    }
}
