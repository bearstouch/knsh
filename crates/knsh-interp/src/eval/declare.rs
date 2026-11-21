//! `declare` and `typeset`, `local`, `export`, `readonly` and `unset` (KNSH-101, KNSH-103; NFR-COMPAT-02), following
//! bash 5.2's `declare.def` and `setattr.def`.
//!
//! The attributes kept are those of [`Attributes`] (`-x`, `-r`, `-i`, `-l`, `-u`, `-t`, `-n`) and the kinds of
//! array (`-a`, `-A`). Inside a function `declare` and `typeset` make their variables local, as `local` does, unless
//! given `-g`; a name reference (`-n`) stores the name of the variable it stands for, which may not be itself. A
//! `name=(…)` argument is a compound assignment, its list expanded here once the attributes are known. Any use of
//! a variable bash maintains itself is refused, and so is a listing that would include them (`declare -p` without
//! names, `readonly -p`), since this interpreter does not hold them. Functions are listed by name (`declare -F`) and
//! take `-r` and `-t`; printing a definition (`declare -f name`) is refused: bash re-formats it with a
//! pretty-printer this interpreter does not reproduce.
//!
//! The arguments of these builtins that look like assignments (`export x=$y`) were expanded as assignments: no
//! word splitting or pathname expansion of the value (`eval::Interpreter::command_arguments`).

use std::ffi::OsString;
use std::fmt::Write as _;

use knsh_bash::Span;

use super::{Flow, Interpreter, Run, Stop, unsupported};
use crate::arith::Failure;
use crate::error::Unsupported;
use crate::quote;
use crate::state::{AssignError, Attributes, Key, Kind, Value, Variable, is_name, refuses_assignment};
use crate::status::Status;

/// Bash's usage line for each declaration builtin.
fn usage(name: &str) -> &'static str {
    match name {
        "export" => "[-fn] [name[=value] ...] or export -p",
        "readonly" => "[-aAf] [name[=value] ...] or readonly -p",
        "local" => "[option] name[=value] ...",
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

    /// `export`, `readonly`, `declare`, `typeset` and `local` (`name`) with `args`.
    pub(super) fn declare_builtin(&mut self, name: &str, args: &[String], span: Span, run: &Run<'_>) -> Flow<Status> {
        let lists = std::mem::take(&mut self.declaration_lists);
        if name == "local" && !self.state.in_function() {
            self.report(span, run, format_args!("local: can only be used in a function"));
            return Ok(Status::FAILURE);
        }
        let (given, operands) = match self.declaration_options(name, args, span, run) {
            Ok(parsed) => parsed,
            Err(status) => return Ok(status),
        };
        if given.has('I') {
            return Err(unsupported(Unsupported::Builtin, span).into());
        }
        if given.has('f') || given.has('F') {
            return self.declare_functions(name, &given, operands, span, run);
        }
        let declares = matches!(name, "declare" | "typeset" | "local");
        if operands.is_empty() {
            return self.declare_listing(name, &given, span, run);
        }
        if declares && given.on.contains('p') {
            return self.declare_print(name, operands, span, run);
        }
        // Each list belongs to the argument at its index (the builtin's own name being word 0).
        let first = args.len() - operands.len();
        let mut status = Status::SUCCESS;
        for (at, arg) in operands.iter().enumerate() {
            let list = lists
                .iter()
                .find(|(index, _)| *index == first + at + 1)
                .map(|(_, list)| list);
            let operand = operand(arg);
            if operand.name.contains('[') {
                return Err(unsupported(Unsupported::Array, span).into());
            }
            // Bash's `assign_error` (`EX_BADASSIGN`): `export` or `readonly` failing to make an assignment it was
            // given, which POSIX mode makes fatal for these special builtins (KNSH-106).
            let assigns = !declares && operand.value.is_some();
            if !is_name(operand.name) {
                self.report(span, run, format_args!("{name}: `{arg}': not a valid identifier"));
                status = Status::FAILURE;
                self.bad_assignment |= assigns;
                continue;
            }
            if self.bash_maintains(operand.name, operand.value.is_some()) {
                return Err(unsupported(Unsupported::ShellVariable, span).into());
            }
            // `declare -g` inside a function: the global variable, whatever a scope holds.
            let global = declares && given.on.contains('g') && self.state.in_function();
            let mut hidden = global.then(|| self.state.hide_scopes());
            let result = self.declare_one(name, &given, &operand, list, &mut hidden, span, run);
            if let Some(scopes) = hidden {
                self.state.show_scopes(scopes);
            }
            if !result? {
                status = Status::FAILURE;
                self.bad_assignment |= assigns;
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
        let plus_allowed = matches!(name, "declare" | "typeset" | "local");
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
                    self.usage_error = true;
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

    /// `-f` and `-F`: functions. `-F` lists names (`declare -f name` lines without operands); `-r` and `-t` with
    /// `-f` change a function's attributes. Printing a definition is refused (bash's pretty-printer), and so is
    /// `export -f` (bash's environment encoding).
    fn declare_functions(
        &mut self,
        name: &str,
        given: &Given,
        operands: &[String],
        span: Span,
        run: &Run<'_>,
    ) -> Flow<Status> {
        let attributes: String = given
            .on
            .chars()
            .filter(|letter| !matches!(letter, 'f' | 'F' | 'p'))
            .collect();
        let only_names = given.on.contains('F') || given.off.contains('F');
        if name == "export" || attributes.contains('x') || given.off.contains('x') {
            return Err(unsupported(Unsupported::FunctionPrint, span).into());
        }
        let readonly = name == "readonly" || attributes.contains('r');
        let changes = readonly || attributes.contains('t') || given.off.contains('t');
        if !changes && !only_names {
            // Printing definitions: refused once there is one to print (none: nothing, or status 1 for names).
            let prints = if operands.is_empty() {
                !self.state.functions().is_empty()
            } else {
                operands.iter().any(|function| self.state.function(function).is_some())
            };
            if prints {
                return Err(unsupported(Unsupported::FunctionPrint, span).into());
            }
            return Ok(if operands.is_empty() {
                Status::SUCCESS
            } else {
                Status::FAILURE
            });
        }
        if operands.is_empty() {
            if changes {
                return Err(unsupported(Unsupported::FunctionPrint, span).into());
            }
            let mut text = String::new();
            for (function, attributes) in self.state.functions() {
                let readonly = if attributes.readonly { "r" } else { "" };
                let trace = if attributes.trace { "t" } else { "" };
                let _ = writeln!(text, "declare -f{readonly}{trace} {function}");
            }
            return Ok(self.print(name, text.as_bytes(), span, run));
        }
        let mut status = Status::SUCCESS;
        for operand in operands {
            let function = self::operand(operand).name;
            let Some(held) = self.state.function_mut(function) else {
                if changes {
                    self.report(span, run, format_args!("{name}: {function}: not a function"));
                }
                status = Status::FAILURE;
                continue;
            };
            if changes {
                held.readonly |= readonly;
                if attributes.contains('t') {
                    held.trace = true;
                }
                if given.off.contains('t') {
                    held.trace = false;
                }
            } else {
                let line = format!("{function}\n");
                if self.print(name, line.as_bytes(), span, run) != Status::SUCCESS {
                    status = Status::FAILURE;
                }
            }
        }
        Ok(status)
    }

    /// A declaration builtin without operands: the variables with the attributes asked for, as `declare -p` prints
    /// them. Only the exported ones can be listed as bash would: every other listing would include variables bash
    /// maintains itself.
    fn declare_listing(&mut self, name: &str, given: &Given, span: Span, run: &Run<'_>) -> Flow<Status> {
        let exported_only = match name {
            "export" => !given.on.contains('n'),
            "readonly" | "local" => false,
            _ => given.on.chars().filter(|letter| *letter != 'p').eq(['x']) && given.off.is_empty(),
        };
        if !exported_only {
            return Err(unsupported(Unsupported::ShellVariable, span).into());
        }
        let mut text = String::new();
        let listed: Vec<(String, Variable)> = self
            .state
            .all_variables()
            .into_iter()
            .filter(|(_, variable)| variable.attributes.exported)
            .map(|(name, variable)| (name.to_owned(), variable.clone()))
            .collect();
        // KNSH-106: in POSIX mode `export` and `readonly` list as themselves (bash's `show_var_attributes` with
        // `pattr`).
        let builtin = (self.state.options().posix() && matches!(name, "export" | "readonly")).then_some(name);
        for (variable, held) in listed {
            if self.state.is_unemulated(&variable) || refuses_assignment(&variable) {
                return Err(unsupported(Unsupported::ShellVariable, span).into());
            }
            text.push_str(&listing_line(builtin, &variable, &held));
        }
        Ok(self.print(name, text.as_bytes(), span, run))
    }

    /// `declare -p name …`: each variable as a `declare` command that recreates it (a name reference itself, not
    /// the variable it refers to).
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
            let held = self
                .state
                .all_variables()
                .into_iter()
                .find(|(held, _)| held == variable);
            if let Some((_, held)) = held {
                text.push_str(&declaration(variable, held));
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

    /// One operand of declaration builtin `builtin`: made local when it must be, its attributes changed as `given`
    /// says and its value (or `list`) assigned. `hidden` holds the function scopes `declare -g` hid while it acts on
    /// the global variables. `false` after reporting bash's error.
    #[allow(clippy::too_many_arguments)]
    fn declare_one(
        &mut self,
        builtin: &str,
        given: &Given,
        operand: &Operand<'_>,
        list: Option<&knsh_bash::ArrayValue>,
        hidden: &mut Option<Vec<std::collections::BTreeMap<String, Variable>>>,
        span: Span,
        run: &Run<'_>,
    ) -> Flow<bool> {
        let name = operand.name;
        let declares = matches!(builtin, "declare" | "typeset" | "local");
        if declares && self.state.in_function() && self.state.make_local(name).is_err() {
            self.report(span, run, format_args!("{builtin}: {name}: readonly variable"));
            return Ok(false);
        }
        if given.has('n') && builtin != "export" {
            return self.declare_reference(builtin, given, operand, list, span, run);
        }
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
            "readonly" => {
                let kinds: String = given.on.chars().filter(|letter| matches!(letter, 'a' | 'A')).collect();
                (format!("r{kinds}"), String::new())
            }
            _ => (given.on.clone(), given.off.clone()),
        };
        if off.contains(['a', 'A']) && self.state.kind(name) != Kind::Unset {
            self.report(
                span,
                run,
                format_args!("{builtin}: {name}: cannot destroy array variables in this way"),
            );
            return Ok(false);
        }
        if on.contains(['a', 'A']) || list.is_some() {
            let assoc = on.contains('A');
            match self.state.make_array(name, assoc) {
                Ok(()) => {}
                Err(AssignError::Kind) => {
                    let (from, to) = if assoc {
                        ("indexed", "associative")
                    } else {
                        ("associative", "indexed")
                    };
                    self.report(
                        span,
                        run,
                        format_args!("{builtin}: {name}: cannot convert {from} to {to} array"),
                    );
                    return Ok(false);
                }
                Err(_) => return Err(unsupported(Unsupported::Nameref, span).into()),
            }
        }
        // Everything but read-only is set before the value is assigned, so `-i`, `-l` and `-u` apply to it.
        self.state.change_attributes(name, false, |attributes| {
            apply(attributes, &on, &off, false);
        });
        if let Some(list) = list {
            let assoc = self.state.kind(name) == Kind::Assoc;
            // The list is expanded where the command is, the function's variables visible (`declare -g a=($v)`
            // with `v` local), even when the variable assigned is the global one.
            let items = match hidden.take() {
                Some(scopes) => {
                    self.state.show_scopes(scopes);
                    let items = self.array_items(list, assoc, run);
                    *hidden = Some(self.state.hide_scopes());
                    items?
                }
                None => self.array_items(list, assoc, run)?,
            };
            let result = self.state.assign_list(name, items, operand.append, assoc);
            if self.declared(builtin, name, result, span, run)?.is_some() {
                return Ok(false);
            }
        } else if let Some(value) = operand.value {
            let result = self.state.assign(name, OsString::from(value), operand.append);
            if self.declared(builtin, name, result, span, run)?.is_some() {
                return Ok(false);
            }
        }
        self.state.change_attributes(name, false, |attributes| {
            apply(attributes, &on, &off, true);
        });
        Ok(true)
    }

    /// The outcome of a declaration builtin's assignment: `Ok(None)` when done, `Ok(Some(1))` after bash's message.
    fn declared(
        &mut self,
        builtin: &str,
        name: &str,
        result: Result<(), AssignError>,
        span: Span,
        run: &Run<'_>,
    ) -> Flow<Option<Status>> {
        match result {
            Ok(()) => Ok(None),
            Err(AssignError::Arithmetic(failure)) => Err(self.arithmetic_failed(builtin, failure, span, run)),
            Err(AssignError::Unsupported(feature)) => Err(unsupported(feature, span).into()),
            Err(AssignError::BadSubscript | AssignError::Kind) => Err(unsupported(Unsupported::Array, span).into()),
            Err(AssignError::Readonly | AssignError::Invalid) => {
                self.report(span, run, format_args!("{name}: readonly variable"));
                Ok(Some(Status::FAILURE))
            }
        }
    }

    /// `declare -n name[=target]` and `declare +n name`: the reference itself, never the variable it refers to.
    fn declare_reference(
        &mut self,
        builtin: &str,
        given: &Given,
        operand: &Operand<'_>,
        list: Option<&knsh_bash::ArrayValue>,
        span: Span,
        run: &Run<'_>,
    ) -> Flow<bool> {
        let name = operand.name;
        if list.is_some() || operand.append || given.on.contains(['a', 'A']) {
            return Err(unsupported(Unsupported::Nameref, span).into());
        }
        if given.off.contains('n') {
            self.state
                .change_attributes(name, true, |attributes| attributes.nameref = false);
            let (on, off) = (given.on.clone(), given.off.clone());
            self.state
                .change_attributes(name, true, |attributes| apply(attributes, &on, &off, true));
            return Ok(true);
        }
        let own = self.state.own_attributes(name).unwrap_or_default();
        if own.readonly && operand.value.is_some() {
            self.report(span, run, format_args!("{builtin}: {name}: readonly variable"));
            return Ok(false);
        }
        if matches!(self.state.own_value(name), Some(Value::Indexed(_) | Value::Assoc(_))) {
            // Bash's `reference variable cannot be an array`: refused.
            return Err(unsupported(Unsupported::Nameref, span).into());
        }
        let target = match operand.value {
            Some(value) => Some(value.to_owned()),
            None => self
                .state
                .own_value(name)
                .and_then(Value::first)
                .map(|value| value.to_string_lossy().into_owned()),
        };
        if let Some(target) = &target {
            if target.contains('[') {
                return Err(unsupported(Unsupported::Nameref, span).into());
            }
            if !is_name(target) {
                self.report(
                    span,
                    run,
                    format_args!("{builtin}: `{target}': invalid variable name for name reference"),
                );
                return Ok(false);
            }
            if target == name {
                self.report(
                    span,
                    run,
                    format_args!("{builtin}: {name}: nameref variable self references not allowed"),
                );
                return Ok(false);
            }
            if refuses_assignment(target) || self.state.is_unemulated(target) {
                return Err(unsupported(Unsupported::ShellVariable, span).into());
            }
        }
        let (on, off) = (given.on.clone(), given.off.clone());
        self.state.change_attributes(name, true, |attributes| {
            attributes.nameref = true;
            apply(attributes, &on, &off, false);
        });
        if let Some(target) = target
            && self.state.assign_own(name, OsString::from(target)).is_err()
        {
            self.report(span, run, format_args!("{builtin}: {name}: readonly variable"));
            return Ok(false);
        }
        self.state
            .change_attributes(name, true, |attributes| apply(attributes, &on, &off, true));
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

    /// `unset [-fvn] name …`: a variable (an array element for `name[subscript]`, the reference itself with `-n`),
    /// or with `-f` a function; without `-f` or `-v`, a function when no variable has that name, as in bash.
    pub(super) fn unset_builtin(&mut self, args: &[String], span: Span, run: &Run<'_>) -> Flow<Status> {
        let (options, names) = match self.options("unset", "[-f] [-v] [-n] [name ...]", "fvn", args, span, run) {
            Ok(parsed) => parsed,
            Err(status) => return Ok(status),
        };
        let functions = options.contains('f') && !options.contains('v');
        let mut status = Status::SUCCESS;
        for name in names {
            if functions {
                if self.state.remove_function(name).is_err() {
                    self.report(
                        span,
                        run,
                        format_args!("unset: {name}: cannot unset: readonly function"),
                    );
                    status = Status::FAILURE;
                }
                continue;
            }
            if let Some((array, rest)) = name.split_once('[')
                && is_name(array)
            {
                if self.bash_maintains(array, false) {
                    return Err(unsupported(Unsupported::ShellVariable, span).into());
                }
                if !self.unset_element(array, rest, name, span, run)? {
                    status = Status::FAILURE;
                }
                continue;
            }
            if is_name(name) && self.bash_maintains(name, false) {
                return Err(unsupported(Unsupported::ShellVariable, span).into());
            }
            let exists = self.state.own_attributes(name).is_some();
            if !exists && !options.contains('v') && !options.contains('n') && self.state.function(name).is_some() {
                if self.state.remove_function(name).is_err() {
                    self.report(
                        span,
                        run,
                        format_args!("unset: {name}: cannot unset: readonly function"),
                    );
                    status = Status::FAILURE;
                }
                continue;
            }
            let result = if options.contains('n') {
                self.state.unset_own(name)
            } else {
                self.state.unset(name)
            };
            match result {
                Ok(()) => {}
                Err(AssignError::Invalid) => {
                    self.report(span, run, format_args!("unset: `{name}': not a valid identifier"));
                    status = Status::FAILURE;
                }
                Err(AssignError::Unsupported(feature)) => return Err(unsupported(feature, span).into()),
                Err(
                    AssignError::Readonly | AssignError::Arithmetic(_) | AssignError::BadSubscript | AssignError::Kind,
                ) => {
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

    /// `unset 'array[subscript]'` (`rest` is what follows the `[`, `whole` the argument): `[@]` and `[*]` unset the
    /// whole array; a subscript is evaluated as an arithmetic expression (an indexed array's) or taken as a key. A
    /// subscript holding an expansion is refused: bash expands it again here. `false` after bash's error.
    fn unset_element(&mut self, array: &str, rest: &str, whole: &str, span: Span, run: &Run<'_>) -> Flow<bool> {
        let subscript = match rest.strip_suffix(']') {
            Some(subscript) if !subscript.is_empty() => subscript,
            _ => {
                self.report(span, run, format_args!("unset: `{whole}': not a valid identifier"));
                return Ok(false);
            }
        };
        if subscript.contains(['$', '`']) {
            return Err(unsupported(Unsupported::Array, span).into());
        }
        let result = if matches!(subscript, "@" | "*") {
            self.state.unset(array)
        } else {
            let key = if self.state.kind(array) == Kind::Assoc {
                Key::Name(subscript.to_owned())
            } else {
                let result = self.expander(run, &[]).evaluate(subscript);
                match result {
                    Ok(index) => Key::Index(index),
                    Err(failure) => {
                        let result = Err(crate::expand::failed(failure, span));
                        return self.expanded(result, span, run);
                    }
                }
            };
            self.state.unset_element(array, &key)
        };
        match result {
            Ok(()) => Ok(true),
            Err(AssignError::BadSubscript) => {
                self.report(span, run, format_args!("unset: {array}: bad array subscript"));
                Ok(false)
            }
            Err(AssignError::Unsupported(feature)) => Err(unsupported(feature, span).into()),
            Err(_) => {
                self.report(
                    span,
                    run,
                    format_args!("unset: {array}: cannot unset: readonly variable"),
                );
                Ok(false)
            }
        }
    }
}

/// Applies option letters `on` and `off` to `attributes`: read-only only when `readonly_too` (it is set after the
/// value is assigned). `-l` and `-u` exclude each other, the last given winning. The kinds (`a`, `A`), name
/// references (`n`) and the builtin's own letters are handled by the caller.
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

/// An associative array's key as bash 5.2's `assoc_to_assign` writes it: `$'…'` with a control character,
/// double-quoted with a character the shell reads specially (`sh_contains_shell_metas`) or when it is `@` or `*`,
/// bare otherwise.
fn assoc_key(key: &str) -> String {
    let special = |at: usize, ch: char| match ch {
        ' ' | '\t' | '\n' | '\'' | '"' | '\\' | '|' | '&' | ';' | '(' | ')' | '<' | '>' | '!' | '{' | '}' | '*'
        | '[' | '?' | ']' | '^' | '$' | '`' => true,
        '~' => at == 0 || key[..at].ends_with(['=', ':']),
        '#' => at == 0,
        _ => false,
    };
    if key.chars().any(char::is_control) || key.char_indices().any(|(at, ch)| special(at, ch)) || key == "@" {
        quote::declare_value(key)
    } else {
        key.to_owned()
    }
}

/// [`declaration`], or in POSIX mode for `export` and `readonly` (`builtin`) the line bash 5.2 prints then: the
/// builtin's name, only the array attributes, then the name and value (`export PATH="/bin"`) (KNSH-106).
fn listing_line(builtin: Option<&str>, name: &str, variable: &Variable) -> String {
    let Some(builtin) = builtin else {
        return declaration(name, variable);
    };
    let line = declaration(name, variable);
    let rest = line
        .strip_prefix("declare ")
        .and_then(|rest| rest.split_once(' '))
        .map_or("", |(_, rest)| rest);
    let arrays: String = variable
        .attributes
        .letters(variable.kind())
        .chars()
        .filter(|letter| matches!(letter, 'a' | 'A'))
        .collect();
    if arrays.is_empty() {
        format!("{builtin} {rest}")
    } else {
        format!("{builtin} -{arrays} {rest}")
    }
}

/// The `declare` command that recreates `variable` named `name`, as bash 5.2's `declare -p` prints it:
/// `declare -rx name="value"`, `declare -a name=([0]="x" [2]="y")`, `declare -A name=([key]="v" )` (bash leaves a
/// blank before an associative array's `)`), or without `=` for a variable declared without a value.
fn declaration(name: &str, variable: &Variable) -> String {
    let letters = variable.attributes.letters(variable.kind());
    let flags = if letters.is_empty() {
        "--".to_owned()
    } else {
        format!("-{letters}")
    };
    let text = |value: &OsString| quote::declare_value(&value.to_string_lossy());
    match &variable.value {
        None => format!("declare {flags} {name}\n"),
        Some(Value::Scalar(value)) => format!("declare {flags} {name}={}\n", text(value)),
        Some(Value::Indexed(elements)) => {
            let items: Vec<String> = elements
                .iter()
                .map(|(index, value)| format!("[{index}]={}", text(value)))
                .collect();
            format!("declare {flags} {name}=({})\n", items.join(" "))
        }
        Some(Value::Assoc(entries)) => {
            let mut items = String::new();
            for (key, value) in entries.iter() {
                let _ = write!(items, "[{}]={} ", assoc_key(key), text(value));
            }
            format!("declare {flags} {name}=({items})\n")
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::state::Assoc;

    fn scalar(value: Option<&str>, attributes: Attributes) -> Variable {
        Variable {
            value: value.map(|value| Value::Scalar(value.into())),
            attributes,
        }
    }

    // KNSH-101: `declare -p` lines, checked against bash.
    #[test]
    fn declarations_print_like_declare_p() {
        let exported = Attributes {
            exported: true,
            ..Attributes::default()
        };
        assert_eq!(
            declaration("x", &scalar(Some("1"), Attributes::default())),
            "declare -- x=\"1\"\n"
        );
        assert_eq!(declaration("OLDPWD", &scalar(None, exported)), "declare -x OLDPWD\n");
        let both = Attributes {
            readonly: true,
            exported: true,
            integer: true,
            ..Attributes::default()
        };
        assert_eq!(declaration("n", &scalar(Some("7"), both)), "declare -irx n=\"7\"\n");
    }

    // KNSH-103: arrays print as bash 5.2 prints them, an associative array with its blank before `)`.
    #[test]
    fn arrays_print_like_bash_5_2() {
        let indexed = Variable {
            value: Some(Value::Indexed(BTreeMap::from([
                (0, OsString::from("x")),
                (2, OsString::from("a \"b\"")),
            ]))),
            attributes: Attributes::default(),
        };
        assert_eq!(
            declaration("a", &indexed),
            "declare -a a=([0]=\"x\" [2]=\"a \\\"b\\\"\")\n"
        );
        let empty = Variable {
            value: Some(Value::Indexed(BTreeMap::new())),
            attributes: Attributes::default(),
        };
        assert_eq!(declaration("e", &empty), "declare -a e=()\n");
        let mut entries = Assoc::default();
        entries.insert("k", OsString::from("v"));
        let assoc = Variable {
            value: Some(Value::Assoc(entries)),
            attributes: Attributes {
                readonly: true,
                ..Attributes::default()
            },
        };
        assert_eq!(declaration("h", &assoc), "declare -Ar h=([k]=\"v\" )\n");
        let reference = scalar(
            Some("target"),
            Attributes {
                nameref: true,
                ..Attributes::default()
            },
        );
        assert_eq!(declaration("r", &reference), "declare -n r=\"target\"\n");
        assert_eq!(assoc_key("a b"), "\"a b\"");
        assert_eq!(assoc_key("@"), "\"@\"");
        assert_eq!(assoc_key("x~y"), "x~y");
        assert_eq!(assoc_key("~y"), "\"~y\"");
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
