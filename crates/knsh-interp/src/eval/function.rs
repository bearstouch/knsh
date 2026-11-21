//! Shell functions and array assignments (KNSH-103; NFR-COMPAT-02), following bash 5.2's `execute_function` and
//! `assign_compound_array_list`.
//!
//! - Defining a function keeps its body with the text it was parsed from (a function defined by `eval` or in a
//!   sourced file outlives that text), and its file for `BASH_SOURCE`. A name bash refuses (quoted, holding an
//!   expansion, all digits) is bash's `not a valid identifier`, status 1; a read-only function is `readonly
//!   function`, status 1.
//! - A call pushes a scope (holding the assignments written before it, exported, as bash's temporary environment),
//!   a call-stack frame (`FUNCNAME`, `BASH_SOURCE`, `BASH_LINENO`) and the arguments as positional parameters
//!   (`$0` unchanged); it resets the loop count, so `break` inside it is not the caller's (bash 4.4 and later); and
//!   it applies the body's redirections. `return` ends it; everything is put back however it ends. Past a positive
//!   `FUNCNEST`, a call is bash's `maximum function nesting level exceeded` and the line is abandoned; without one,
//!   the evaluator's own nesting limit applies ([`MAX_EVAL_DEPTH`](crate::MAX_EVAL_DEPTH)).
//! - `name=(…)` and `name+=(…)` expand each element as bash does (a plain element of an indexed array is split and
//!   matched against file names; `[key]=value`, and an associative array's key-value words, are expanded as an
//!   assignment's value), then assign them in order.

use std::ffi::OsString;
use std::sync::Arc;

use knsh_bash::{ArrayValue, Assignment, CommandWord, CompoundKind, FunctionDefinition, Pipeline, Span};

use super::{Flow, Interpreter, Run, Sink, Stop, unsupported};
use crate::error::Unsupported;
use crate::param::Subscript;
use crate::scan;
use crate::state::{AssignError, Frame, FunctionBody, Key, Kind, is_name};
use crate::status::Status;
use crate::word;

/// A variable a builtin's argument names (`test -v`, `printf -v`).
pub(super) enum Named {
    /// `name`.
    Variable(String),
    /// `name[subscript]`.
    Element(String, Key),
    /// `name[@]` or `name[*]`.
    All(String),
}

/// One element of a compound assignment once expanded.
enum Item {
    /// `[subscript]=value` (`append` for `+=`), the subscript not yet evaluated.
    Keyed {
        subscript: Span,
        text: String,
        value: OsString,
        append: bool,
    },
    /// A plain value.
    Plain(OsString),
}

/// Where the subscript of a list element `[subscript]=value` is, whether it appends, and where its value starts, if
/// the element is spelled that way (its `[` unquoted).
fn keyed_element(element: &CommandWord, source: &str) -> Option<(Span, bool, usize)> {
    let first = element.word.segments.first()?;
    if first.kind != knsh_bash::SegmentKind::Literal || first.body.start != element.span.start {
        return None;
    }
    let text = element.span.text(source)?;
    let inner = text.strip_prefix('[')?;
    let close = scan::subscript_end(inner)?;
    let after = &inner[close + 1..];
    let start = element.span.start + 1;
    let subscript = Span::new(start, start + close);
    if after.starts_with('=') {
        Some((subscript, false, subscript.end + 2))
    } else if after.starts_with("+=") {
        Some((subscript, true, subscript.end + 3))
    } else {
        None
    }
}

/// Bash's `legal_number` for `FUNCNEST`: blanks around an optional sign and digits.
fn legal_number(text: &str) -> Option<i64> {
    let trimmed = text.trim_matches([' ', '\t', '\n']);
    let digits = trimmed.strip_prefix(['-', '+']).unwrap_or(trimmed);
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    trimmed.parse().ok()
}

impl Interpreter {
    /// Writes out what reading variables noted (`warning: x: circular name reference`, `a: bad array subscript`):
    /// bash reports those and goes on.
    pub(super) fn flush_notes(&mut self, span: Span, run: &Run<'_>) {
        for note in self.state.take_notes() {
            self.report(span, run, format_args!("{note}"));
        }
    }

    /// `name () body` and `function name body`: keeps the function; 0, or 1 after bash's error.
    pub(super) fn define_function(&mut self, definition: &FunctionDefinition, run: &Run<'_>) -> Status {
        let text = definition.name.span.text(run.source).unwrap_or_default().to_owned();
        let literal = super::alias::literal_text(&definition.name, run.source);
        let Some(name) = literal.filter(|name| !name.bytes().all(|byte| byte.is_ascii_digit())) else {
            self.report(definition.span, run, format_args!("`{text}': not a valid identifier"));
            return Status::FAILURE;
        };
        let body = Arc::new(FunctionBody {
            body: definition.body.clone(),
            source: run.source_arc(),
            origin: run.origin.map(Arc::from),
            line_base: run.line_base,
        });
        if self.state.define_function(name, body).is_ok() {
            Status::SUCCESS
        } else {
            self.report(definition.span, run, format_args!("{name}: readonly function"));
            Status::FAILURE
        }
    }

    /// The `FUNCNEST` limit, if it is set to a positive number.
    fn function_nesting_limit(&self) -> Option<usize> {
        let value = self.state.variable("FUNCNEST")?.to_str()?;
        legal_number(value)
            .filter(|limit| *limit > 0)
            .and_then(|limit| usize::try_from(limit).ok())
    }

    /// Calls function `name` with `args`, `assignments` written before it, from the command at `span`.
    pub(super) fn call_function(
        &mut self,
        name: &str,
        args: &[String],
        assignments: &[(String, OsString)],
        span: Span,
        run: &Run<'_>,
    ) -> Flow<Status> {
        let Some(function) = self.state.function(name).map(|function| Arc::clone(&function.body)) else {
            return Err(unsupported(Unsupported::Builtin, span).into());
        };
        if self.sink == Sink::Open && self.forked_stage {
            // A stage's function must run beside the other stages, on a thread of its own: decided before the
            // stage starts for a name written literally; one an expansion produced is refused here.
            return Err(unsupported(Unsupported::PipelineFunction, span).into());
        }
        let depth = self.state.function_depth();
        if let Some(limit) = self.function_nesting_limit()
            && depth >= limit
        {
            self.report(
                span,
                run,
                format_args!("{name}: maximum function nesting level exceeded ({depth})"),
            );
            self.state.set_last_status(Status::FAILURE);
            return Err(Stop::Discard);
        }
        let frame = Frame {
            function: Some(name.to_owned()),
            file: function.origin.as_deref().map(str::to_owned),
            line: run.line(span),
        };
        let positional = std::mem::replace(self.state.positional_mut(), args.to_vec());
        self.state.push_scope(assignments);
        self.state.push_frame(frame);
        let loops = std::mem::take(&mut self.loops);
        let sink = std::mem::take(&mut self.sink);
        let body_run = Run::shared(&function.source, function.origin.as_deref(), function.line_base);
        let result = if matches!(function.body.kind, CompoundKind::Subshell(_)) {
            // `f() ( … )`: the body is a subshell, as `( … )` alone.
            let pipeline = Pipeline {
                time: None,
                negation: None,
                first: knsh_bash::Command::Compound(function.body.clone()),
                rest: Vec::new(),
                span: function.body.span,
            };
            self.pipeline(&pipeline, &body_run)
        } else {
            self.compound(&function.body, &body_run)
        };
        self.flush_notes(function.body.span, &body_run);
        self.sink = sink;
        self.loops = loops;
        self.state.pop_frame();
        self.state.pop_scope();
        *self.state.positional_mut() = positional;
        match result {
            Err(Stop::Return(status)) => Ok(status),
            other => other,
        }
    }

    /// The variable `text` names, `name` or `name[subscript]`, its subscript evaluated as an arithmetic expression
    /// (an indexed array's) or taken as a key; `None` when it is not one. A subscript holding an expansion is
    /// refused: bash would expand it again here.
    pub(super) fn named(&mut self, text: &str, span: Span, run: &Run<'_>) -> Flow<Option<Named>> {
        if is_name(text) {
            return Ok(Some(Named::Variable(text.to_owned())));
        }
        let Some((name, rest)) = text.split_once('[') else {
            return Ok(None);
        };
        let Some(subscript) = rest.strip_suffix(']').filter(|subscript| !subscript.is_empty()) else {
            return Ok(None);
        };
        if !is_name(name) || scan::subscript_end(rest) != Some(subscript.len()) {
            return Ok(None);
        }
        if matches!(subscript, "@" | "*") {
            return Ok(Some(Named::All(name.to_owned())));
        }
        if subscript.contains(['$', '`']) {
            return Err(unsupported(Unsupported::Array, span).into());
        }
        let key = if self.state.kind(name) == Kind::Assoc {
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
        Ok(Some(Named::Element(name.to_owned(), key)))
    }

    // ---- Array assignments ----

    /// `name[subscript]=value`, `name=(…)` and their `+=` forms, without a command: `Ok(None)` when done,
    /// `Ok(Some(1))` after reporting bash's error.
    pub(super) fn array_assignment(&mut self, assignment: &Assignment, run: &Run<'_>) -> Flow<Option<Status>> {
        let name = assignment.name.as_str();
        if crate::state::refuses_assignment(name) {
            return Err(unsupported(Unsupported::ShellVariable, assignment.span).into());
        }
        if let Some(array) = &assignment.array {
            let assoc = self.state.kind(name) == Kind::Assoc;
            let items = self.array_items(array, assoc, run)?;
            let result = self.state.assign_list(name, items, assignment.append, assoc);
            return self.assigned(name, name, result, assignment.span, run);
        }
        let Some(subscript) = assignment.subscript else {
            return Ok(None);
        };
        let parts = word::parts(&assignment.word.segments, run.source, assignment.value.start)?;
        let result = self.expander(run, &[]).assignment_value(&parts, assignment.span);
        let value = OsString::from(self.expanded(result, assignment.span, run)?);
        let key = self.subscript_key(name, subscript, assignment.span, run)?;
        let label = format!("{name}[{}]", subscript.text(run.source).unwrap_or_default());
        let result = self.state.assign_element(name, &key, value, assignment.append);
        self.assigned(name, &label, result, assignment.span, run)
    }

    /// The element the subscript at `subscript` names in array `name`.
    pub(super) fn subscript_key(&mut self, name: &str, subscript: Span, span: Span, run: &Run<'_>) -> Flow<Key> {
        let text = subscript.text(run.source).unwrap_or_default().to_owned();
        let assoc = self.state.kind(name) == Kind::Assoc;
        let result = self
            .expander(run, &[])
            .subscript(assoc, &Subscript::Source { span: subscript, text }, span);
        self.expanded(result, span, run)
    }

    /// The outcome of an array assignment to `name` (called `label` in a bad subscript's message).
    pub(super) fn assigned(
        &mut self,
        name: &str,
        label: &str,
        result: Result<(), AssignError>,
        span: Span,
        run: &Run<'_>,
    ) -> Flow<Option<Status>> {
        match result {
            Ok(()) => Ok(None),
            Err(AssignError::Readonly) => {
                self.report(span, run, format_args!("{name}: readonly variable"));
                Ok(Some(Status::FAILURE))
            }
            Err(AssignError::BadSubscript) if label != name => {
                self.report(span, run, format_args!("{label}: bad array subscript"));
                Ok(Some(Status::FAILURE))
            }
            Err(AssignError::Invalid) => {
                self.report(span, run, format_args!("`{name}': not a valid identifier"));
                Ok(Some(Status::FAILURE))
            }
            Err(AssignError::Arithmetic(failure)) => {
                let result = Err(crate::expand::failed(failure, span));
                self.expanded(result, span, run)
            }
            Err(AssignError::Unsupported(feature)) => Err(unsupported(feature, span).into()),
            Err(AssignError::BadSubscript | AssignError::Kind) => Err(unsupported(Unsupported::Array, span).into()),
        }
    }

    /// The elements of the list `array` for array `name` (`assoc`: an associative array), expanded and keyed: a
    /// plain element of an indexed array is split and matched against file names; `[subscript]=value` has its value
    /// expanded as an assignment's, then its subscript. An associative array given only plain elements takes them
    /// as key-value pairs (bash 5.1 and later), each expanded as an assignment's value.
    pub(super) fn array_items(
        &mut self,
        array: &ArrayValue,
        assoc: bool,
        run: &Run<'_>,
    ) -> Flow<Vec<(Option<Key>, OsString, bool)>> {
        let mut expanded = Vec::new();
        for element in &array.elements {
            if let Some((subscript, append, value_start)) = keyed_element(element, run.source) {
                if subscript.start == subscript.end {
                    return Err(unsupported(Unsupported::Array, element.span).into());
                }
                let parts = word::parts(&element.word.segments, run.source, value_start)?;
                let result = self.expander(run, &[]).assignment_value(&parts, element.span);
                let value = OsString::from(self.expanded(result, element.span, run)?);
                let text = subscript.text(run.source).unwrap_or_default().to_owned();
                expanded.push(Item::Keyed {
                    subscript,
                    text,
                    value,
                    append,
                });
            } else if assoc {
                // Bash 5.2 expands an associative list's words as assignment values, one string each, never
                // split or matched against file names (`assign_assoc_from_kvlist`).
                let parts = word::parts(&element.word.segments, run.source, element.span.start)?;
                let result = self.expander(run, &[]).assignment_value(&parts, element.span);
                let value = OsString::from(self.expanded(result, element.span, run)?);
                expanded.push(Item::Plain(value));
            } else {
                for value in self.arguments(std::slice::from_ref(element), run)? {
                    expanded.push(Item::Plain(OsString::from(value)));
                }
            }
        }
        let all_plain = expanded.iter().all(|item| matches!(item, Item::Plain(_)));
        if assoc && all_plain {
            let mut items = Vec::new();
            let mut values = expanded.into_iter().map(|item| match item {
                Item::Plain(value) | Item::Keyed { value, .. } => value,
            });
            while let Some(key) = values.next() {
                let value = values.next().unwrap_or_default();
                let key = key
                    .into_string()
                    .map_err(|_| unsupported(Unsupported::NonUtf8Value, array.open))?;
                if key.is_empty() {
                    // Bash's `bad array subscript` for an empty key, which it reports and skips: refused.
                    return Err(unsupported(Unsupported::Array, array.open).into());
                }
                items.push((Some(Key::Name(key)), value, false));
            }
            return Ok(items);
        }
        let mut items = Vec::with_capacity(expanded.len());
        for item in expanded {
            match item {
                Item::Plain(_) if assoc => {
                    // Bash's `must use subscript when assigning associative array`: refused.
                    return Err(unsupported(Unsupported::Array, array.open).into());
                }
                Item::Plain(value) => items.push((None, value, false)),
                Item::Keyed {
                    subscript,
                    text,
                    value,
                    append,
                } => {
                    let result = self.expander(run, &[]).subscript(
                        assoc,
                        &Subscript::Source { span: subscript, text },
                        array.open,
                    );
                    let key = self.expanded(result, array.open, run)?;
                    if matches!(&key, Key::Name(key) if key.is_empty()) {
                        return Err(unsupported(Unsupported::Array, array.open).into());
                    }
                    items.push((Some(key), value, append));
                }
            }
        }
        Ok(items)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn funcnest_reads_as_bash_reads_numbers() {
        assert_eq!(legal_number(" 3 "), Some(3));
        assert_eq!(legal_number("+2"), Some(2));
        assert_eq!(legal_number("-1"), Some(-1));
        assert_eq!(legal_number("x"), None);
        assert_eq!(legal_number(""), None);
    }
}
