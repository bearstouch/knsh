//! Line re-serialisation with resolved absolute paths (KNSH-038; FR-LC-13, FR-LC-15).
//!
//! [`reserialise`] re-emits a classified line with the name of every command that resolved to a binary
//! ([`Program::Trusted`] or [`Program::ProjectExecutable`]) replaced by the binary's canonical absolute path, and
//! nothing else changed. The supervisor runs that line, so bash never searches `PATH` again and the binary that runs
//! is the one that was classified (FR-LC-13). A binary swapped at that path after classification is the sandbox's
//! concern: its executable rules allow only trusted folders and the paths the profile names (FR-LC-15).
//!
//! # What is replaced
//!
//! Only the command-name word of each [`ClassifiedCommand`] whose program has a path, by span: the whole word, quotes
//! included (`"git"` becomes `/usr/bin/git`). Commands run by wrappers (`env git`, `xargs rm`), and commands inside
//! compound commands, function bodies, command and process substitutions and here-documents are replaced too.
//!
//! Left untouched, byte for byte:
//!
//! - builtins, calls to functions of the line, and names that were not found (the supervisor fails those lines,
//!   KNSH-035);
//! - every dynamic part of the line ([`Classification::dynamic_parts`]): a command name inside one is not replaced,
//!   since dynamic code is decided by its own rules (FR-POL-20, FR-POL-21), and a line the parser could not read is
//!   returned as it is;
//! - the `echo` that `xargs` runs when given no command, which has no name on the line.
//!
//! A path is written as it is when it holds only `[A-Za-z0-9/._+-]`, and single-quoted otherwise, with each `'`
//! written `'\''`, so spaces, globs, `$`, `;` and the like are literal.
//!
//! # Fail closed
//!
//! Any replacement that cannot be done safely is an error, and the supervisor denies the line
//! ([`ReserialiseError`]): a path that is not valid UTF-8, not absolute, or holds a control character, a backslash
//! or a backtick (which bash would read differently inside a backtick substitution); a name inside a backtick
//! substitution bash un-escapes before reading, whose spans do not index the line; a path holding the replacement
//! string of an `xargs` that runs the command (GNU `xargs -I` replaces it in the utility's name too); a function of
//! the line named like the path (bash calls it for that name before any binary); two different replacements for one
//! name; an output over [`MAX_INPUT_LEN`]. Finally the output is parsed again and must have the same shape: the same
//! commands, words, assignments, redirections and dynamic parts at the same places (shifted by the replacements),
//! with each replaced name now reading as its path. Any difference is an error, never a line run with a guess.

use std::path::{Component, Path};
use std::slice;

use crate::ast::{
    Command, CommandWord, CompoundCommand, CompoundKind, DeepCommand, Redirect, Script, SimpleCommand, Substitution,
};
use crate::classify::{Classification, Program, wrapper_of};
use crate::error::ReserialiseError;
use crate::functions::static_text;
use crate::limits::MAX_INPUT_LEN;
use crate::outcome::{ParseOutcome, command_name_text, parse_line};
use crate::token::Span;
use crate::wrappers::{Unwrap, Wrapper, Xargs};

/// Re-emits `input` with every resolved command name replaced by its absolute canonical path (see the module
/// documentation). `outcome` is [`parse_line`]'s result for `input`, and `classification` is
/// [`classify`](crate::classify)'s result for both.
///
/// A line the parser could not read is dynamic as a whole and has no classified commands: it is returned unchanged.
///
/// # Errors
///
/// [`ReserialiseError`] when any replacement cannot be done safely or the output does not parse to the same shape;
/// the supervisor must then deny the line (fail closed).
///
/// # Example
///
/// ```
/// use std::path::PathBuf;
/// use knsh_bash::{classify, parse_line, reserialise, Interpreters, Lookup, Program, Resolver, SourceFile};
///
/// struct Session;
/// impl Resolver for Session {
///     fn resolve(&self, name: &str, lookup: Lookup) -> Program {
///         if lookup == Lookup::Shell && knsh_bash::is_builtin(name) {
///             Program::Builtin
///         } else {
///             Program::Trusted(PathBuf::from("/usr/bin").join(name))
///         }
///     }
///     fn source_file(&self, _path: &str) -> SourceFile {
///         SourceFile::Unresolved
///     }
/// }
///
/// let line = "cd src && git log | grep fix";
/// let outcome = parse_line(line);
/// let classification = classify(&outcome, line, &Session, &Interpreters::defaults());
/// assert_eq!(
///     reserialise(line, &outcome, &classification).unwrap(),
///     "cd src && /usr/bin/git log | /usr/bin/grep fix",
/// );
/// ```
pub fn reserialise(
    input: &str,
    outcome: &ParseOutcome,
    classification: &Classification,
) -> Result<String, ReserialiseError> {
    let Some(script) = outcome.script() else {
        // Nothing of the line was read, so nothing was resolved: it stays as it is, and is decided as dynamic code.
        return if classification.is_whole_line() {
            Ok(input.to_owned())
        } else {
            Err(ReserialiseError::Mismatch)
        };
    };
    if classification.is_whole_line() {
        return Err(ReserialiseError::Mismatch);
    }
    let edits = edits(classification, &line_words(script, input))?;
    unshadowed(script, input, &edits)?;
    let output = apply(input, &edits)?;
    if output.len() > MAX_INPUT_LEN {
        return Err(ReserialiseError::OutputTooLarge);
    }
    verify(input, outcome, script, &output, &edits)?;
    Ok(output)
}

/// One replacement: the word at `span` on the line becomes `replacement`, which reads as `path`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Edit {
    /// The command-name word on the line.
    span: Span,
    /// What is written instead: the path, quoted if needed.
    replacement: String,
    /// The path the replacement must read as after quote removal.
    path: String,
}

/// Every word of every simple command whose spans index the line, in order of span, with the text it has as a
/// command name ([`command_name_text`]). A command inside a backtick substitution bash un-escapes is left out: its
/// spans index the un-escaped text, not the line.
fn line_words(script: &Script, input: &str) -> Vec<(Span, Option<String>)> {
    let mut words: Vec<(Span, Option<String>)> = script
        .deep_commands(input)
        .iter()
        .filter(|deep| deep.anchor.is_none())
        .filter_map(|deep| match deep.command {
            Command::Simple(simple) => Some(simple),
            Command::Compound(_) | Command::FunctionDefinition(_) | Command::Unsupported(_) => None,
        })
        .flat_map(|simple| simple.words.iter())
        .map(|word| (word.span, command_name_text(&word.word, input)))
        .collect();
    words.sort_by_key(|(span, _)| (span.start, span.end));
    words
}

/// The replacements for `classification`, in source order, without duplicates. `words` is [`line_words`].
fn edits(classification: &Classification, words: &[(Span, Option<String>)]) -> Result<Vec<Edit>, ReserialiseError> {
    let mut edits = Vec::new();
    for command in classification.commands() {
        // Builtins, functions, names not found and unresolved names have no path: nothing to replace.
        let Some(path) = command.program.as_ref().and_then(Program::path) else {
            continue;
        };
        // `xargs`'s default `echo` has no name on the line; `xargs` itself looks it up.
        let Some(span) = command.name_span else {
            continue;
        };
        // Dynamic parts stay as written: their own rules decide them (FR-POL-20).
        if classification
            .dynamic_parts()
            .iter()
            .any(|part| overlaps(part.span, span))
        {
            continue;
        }
        // The name must be a whole word of the line. Inside a backtick substitution bash un-escapes, the entry's
        // span is the whole substitution, and a replacement there cannot be placed safely. A word holding only that
        // substitution has the same span, so matching the span is not enough: the word must also read as the
        // classified name, which a substitution never does.
        let on_line = words
            .binary_search_by_key(&(span.start, span.end), |(word, _)| (word.start, word.end))
            .ok()
            .and_then(|index| words.get(index))
            .is_some_and(|(_, name)| name.is_some() && *name == command.name);
        if !on_line {
            return Err(ReserialiseError::NameNotOnLine { span });
        }
        let path = path_text(path, span)?;
        // GNU `xargs -I` replaces its placeholder in the utility's name too, so a path holding it would name a
        // binary chosen by the input at run time (`xargs -I bin git` becoming `/usr/<input>/git`).
        let placeholders = xargs_placeholders(classification, command.wrapper)
            .ok_or(ReserialiseError::PathHoldsPlaceholder { span })?;
        if placeholders
            .iter()
            .any(|placeholder| path.contains(placeholder.as_str()))
        {
            return Err(ReserialiseError::PathHoldsPlaceholder { span });
        }
        edits.push(Edit {
            span,
            replacement: quote(path),
            path: path.to_owned(),
        });
    }
    edits.sort_by_key(|edit| (edit.span.start, edit.span.end));
    edits.dedup();
    // After sorting and removing identical entries, any overlap is two different replacements for one name.
    if let Some(pair) = edits.windows(2).find(|pair| pair[1].span.start < pair[0].span.end) {
        return Err(ReserialiseError::ConflictingReplacements { span: pair[1].span });
    }
    Ok(edits)
}

/// The replacement strings of every `xargs` running the command whose wrapper is `parent`, directly or through other
/// wrappers (`xargs -I % env git %`). `None` when the chain cannot be followed or an `xargs`'s options cannot be read
/// again, which the caller treats as unsafe.
fn xargs_placeholders(classification: &Classification, mut parent: Option<usize>) -> Option<Vec<String>> {
    let commands = classification.commands();
    let mut placeholders = Vec::new();
    // A wrapper is always recorded before the command it runs, so each step moves to a lower index; the bound only
    // guards against a classification that breaks that.
    for _ in 0..=commands.len() {
        let Some(index) = parent else {
            return Some(placeholders);
        };
        let wrapper = commands.get(index)?;
        let name = wrapper.name.as_deref()?;
        let program = wrapper.program.as_ref()?;
        if let Some((Wrapper::Xargs, _)) = wrapper_of(program, name) {
            // The entry keeps only the options, so reading them again ends at the default `echo`.
            let texts: Vec<Option<&str>> = wrapper
                .arguments
                .iter()
                .map(|argument| argument.text.as_deref())
                .collect();
            match Wrapper::Xargs.unwrap(&texts) {
                Unwrap::Echo(Xargs { placeholder })
                | Unwrap::Runs {
                    xargs: Some(Xargs { placeholder }),
                    ..
                } => {
                    placeholders.extend(placeholder);
                }
                Unwrap::Runs { xargs: None, .. } | Unwrap::Nothing | Unwrap::Dynamic(_) => return None,
            }
        }
        parent = wrapper.wrapper.filter(|next| *next < index);
        if parent.is_none() && wrapper.wrapper.is_some() {
            return None;
        }
    }
    None
}

/// Checks that no function of the line is named like a replacement path. Outside POSIX mode bash accepts a function
/// named `/usr/bin/git` and calls it for that name, quoted or not, before any binary, so the replacement would run the
/// function where the binary was classified (`/usr/bin/git() { …; }; git status`).
fn unshadowed(script: &Script, input: &str, edits: &[Edit]) -> Result<(), ReserialiseError> {
    for deep in script.deep_commands(input) {
        let definition = match deep.command {
            Command::FunctionDefinition(definition) => definition,
            Command::Simple(_) | Command::Compound(_) | Command::Unsupported(_) => continue,
        };
        // Bash refuses a quoted or expanded function name, so only a static one can be defined.
        let Some(name) = static_text(&definition.name.word, deep.source) else {
            continue;
        };
        if let Some(edit) = edits.iter().find(|edit| edit.path == name) {
            return Err(ReserialiseError::FunctionShadowsPath { span: edit.span });
        }
    }
    Ok(())
}

/// Whether two spans share at least one byte.
const fn overlaps(a: Span, b: Span) -> bool {
    a.start < b.end && b.start < a.end
}

/// The text of a resolved path, if it can be written safely for the name at `span`.
///
/// Backslashes and backticks are refused because a backtick substitution un-escapes or ends at them, so the same
/// quoted text would read differently there; control characters because bash may read them differently by version
/// and they have no place in a binary's path.
fn path_text(path: &Path, span: Span) -> Result<&str, ReserialiseError> {
    let text = path.to_str().ok_or(ReserialiseError::PathNotUtf8 { span })?;
    let canonical = path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, Component::RootDir | Component::Normal(_)));
    if !canonical {
        return Err(ReserialiseError::PathNotAbsolute { span });
    }
    if text.chars().any(|c| c.is_control() || c == '\\' || c == '`') {
        return Err(ReserialiseError::PathNotQuotable { span });
    }
    Ok(text)
}

/// `path` as one shell word that reads as `path` after quote removal: as it is when every byte is in
/// `[A-Za-z0-9/._+-]`, which bash never expands or splits, otherwise in single quotes, with each `'` closed, escaped
/// and reopened (`'\''`).
fn quote(path: &str) -> String {
    let plain = path
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b'+' | b'-'));
    if plain {
        return path.to_owned();
    }
    let mut quoted = String::with_capacity(path.len() + 2);
    quoted.push('\'');
    for c in path.chars() {
        if c == '\'' {
            quoted.push_str("'\\''");
        } else {
            quoted.push(c);
        }
    }
    quoted.push('\'');
    quoted
}

/// `input` with every edit applied. The edits are sorted and disjoint, and each span is a word of the line, so it
/// falls on character boundaries; a span that does not is refused rather than sliced.
fn apply(input: &str, edits: &[Edit]) -> Result<String, ReserialiseError> {
    let added: usize = edits.iter().map(|edit| edit.replacement.len()).sum();
    let mut output = String::with_capacity(input.len() + added);
    let mut at = 0;
    for edit in edits {
        let before = input
            .get(at..edit.span.start)
            .ok_or(ReserialiseError::NameNotOnLine { span: edit.span })?;
        output.push_str(before);
        output.push_str(&edit.replacement);
        at = edit.span.end;
    }
    output.push_str(input.get(at..).ok_or(ReserialiseError::Mismatch)?);
    Ok(output)
}

/// Where offsets of the input land in the output, given the edits applied to it.
struct Shift<'a> {
    /// The edits, sorted and disjoint.
    edits: &'a [Edit],
}

impl Shift<'_> {
    /// Where input offset `at` lands: moved by every edit that ends at or before it. Only meaningful outside the
    /// edited words, or at their ends.
    fn offset(&self, at: usize) -> usize {
        let (added, removed) = self
            .edits
            .iter()
            .take_while(|edit| edit.span.end <= at)
            .fold((0, 0), |(added, removed), edit| {
                (added + edit.replacement.len(), removed + edit.span.len())
            });
        // `removed` counts bytes before `at`, so it never exceeds it.
        at + added - removed
    }

    /// Where an input span lands.
    fn span(&self, span: Span) -> Span {
        Span::new(self.offset(span.start), self.offset(span.end))
    }

    /// The edit replacing exactly the word at `span`, if any.
    fn edit_at(&self, span: Span) -> Option<&Edit> {
        self.edits.iter().find(|edit| edit.span == span)
    }
}

/// Checks that `output` parses to the shape of `script` (see the module documentation): every command, word,
/// assignment, redirection and dynamic part at the shifted place, and every replaced name reading as its path.
fn verify(
    input: &str,
    outcome: &ParseOutcome,
    script: &Script,
    output: &str,
    edits: &[Edit],
) -> Result<(), ReserialiseError> {
    let shift = Shift { edits };
    let reparsed = parse_line(output);
    let Some(new_script) = reparsed.script() else {
        return Err(ReserialiseError::RoundTrip);
    };
    let (old_parts, new_parts) = (outcome.dynamic_parts(), reparsed.dynamic_parts());
    check(
        reparsed.is_exact() == outcome.is_exact()
            && old_parts.len() == new_parts.len()
            && old_parts
                .iter()
                .zip(new_parts)
                .all(|(old, new)| old.reason == new.reason && shift.span(old.span) == new.span),
    )?;
    let old_commands = script.deep_commands(input);
    let new_commands = new_script.deep_commands(output);
    check(old_commands.len() == new_commands.len())?;
    let mut replaced = 0;
    for (old, new) in old_commands.iter().zip(&new_commands) {
        replaced += same_command(old, new, &shift)?;
    }
    // Every replacement was found where it was made, as a command's word.
    check(replaced == edits.len())
}

/// `Ok` when `same` holds, otherwise the round-trip error.
fn check(same: bool) -> Result<(), ReserialiseError> {
    if same { Ok(()) } else { Err(ReserialiseError::RoundTrip) }
}

/// Checks that `new` is `old` after the edits, and returns how many replaced names it holds.
fn same_command(old: &DeepCommand<'_>, new: &DeepCommand<'_>, shift: &Shift<'_>) -> Result<usize, ReserialiseError> {
    match (old.anchor, new.anchor) {
        // Inside a backtick substitution bash un-escapes nothing is replaced, so its text, and everything parsed
        // from it, is unchanged; only its place on the line moves.
        (Some(old_anchor), Some(new_anchor)) => {
            check(
                shift.span(old_anchor) == new_anchor
                    && old.source == new.source
                    && old.time == new.time
                    && old.command == new.command,
            )?;
            return Ok(0);
        }
        (None, None) => {}
        (Some(_), None) | (None, Some(_)) => return Err(ReserialiseError::RoundTrip),
    }
    let old_time = old
        .time
        .map(|time| (shift.span(time.keyword), time.posix.map(|posix| shift.span(posix))));
    let new_time = new.time.map(|time| (time.keyword, time.posix));
    check(old_time == new_time && shift.span(old.command.span()) == new.command.span())?;
    match (old.command, new.command) {
        (Command::Simple(old_simple), Command::Simple(new_simple)) => {
            same_simple(old_simple, new_simple, new.source, shift)
        }
        (Command::Compound(old_compound), Command::Compound(new_compound)) => {
            same_compound(old_compound, new_compound, shift)?;
            Ok(0)
        }
        (Command::FunctionDefinition(old_definition), Command::FunctionDefinition(new_definition)) => {
            check(
                old_definition.keyword.map(|keyword| shift.span(keyword)) == new_definition.keyword
                    && old_definition.parens.map(|parens| shift.span(parens)) == new_definition.parens
                    && same_word(&old_definition.name, &new_definition.name, shift),
            )?;
            same_compound(&old_definition.body, &new_definition.body, shift)?;
            Ok(0)
        }
        (Command::Unsupported(old_unsupported), Command::Unsupported(new_unsupported)) => {
            check(old_unsupported.construct == new_unsupported.construct)?;
            Ok(0)
        }
        (Command::Simple(_) | Command::Compound(_) | Command::FunctionDefinition(_) | Command::Unsupported(_), _) => {
            Err(ReserialiseError::RoundTrip)
        }
    }
}

/// Checks a simple command's parts, and returns how many replaced names it holds. `output` is the text the new
/// command's spans index.
fn same_simple(
    old: &SimpleCommand,
    new: &SimpleCommand,
    output: &str,
    shift: &Shift<'_>,
) -> Result<usize, ReserialiseError> {
    let same_assignments = old.assignments.len() == new.assignments.len()
        && old.assignments.iter().zip(&new.assignments).all(|(old, new)| {
            old.name == new.name
                && old.append == new.append
                && shift.span(old.span) == new.span
                && shift.span(old.value) == new.value
                && same_substitutions(&old.substitutions, &new.substitutions, shift)
        });
    let same_calls = match (&old.function_call, &new.function_call) {
        (None, None) => true,
        (Some(old_call), Some(new_call)) => {
            old_call.definitions.len() == new_call.definitions.len()
                && old_call
                    .definitions
                    .iter()
                    .zip(&new_call.definitions)
                    .all(|(old, new)| shift.span(*old) == *new)
        }
        (Some(_), None) | (None, Some(_)) => false,
    };
    check(
        same_assignments
            && same_calls
            && same_redirections(&old.redirections, &new.redirections, shift)
            && old.words.len() == new.words.len(),
    )?;
    let mut replaced = 0;
    for (old_word, new_word) in old.words.iter().zip(&new.words) {
        check(shift.span(old_word.span) == new_word.span)?;
        if let Some(edit) = shift.edit_at(old_word.span) {
            // The replaced name must read as exactly its path: one word, no expansion, nothing else.
            check(
                new_word.substitutions.is_empty()
                    && static_text(&new_word.word, output).as_deref() == Some(edit.path.as_str()),
            )?;
            replaced += 1;
        } else {
            check(same_substitutions(
                &old_word.substitutions,
                &new_word.substitutions,
                shift,
            ))?;
        }
    }
    Ok(replaced)
}

/// Checks a compound command's kind, header words, list sizes and redirections. The commands inside are compared
/// one by one by [`verify`].
fn same_compound(old: &CompoundCommand, new: &CompoundCommand, shift: &Shift<'_>) -> Result<(), ReserialiseError> {
    let same_header = match (&old.kind, &new.kind) {
        (CompoundKind::For(old_for), CompoundKind::For(new_for)) => {
            let old_items = old_for.items.as_ref().map(|items| items.words.as_slice());
            let new_items = new_for.items.as_ref().map(|items| items.words.as_slice());
            same_word(&old_for.variable, &new_for.variable, shift)
                && match (old_items, new_items) {
                    (None, None) => true,
                    (Some(old_words), Some(new_words)) => same_words(old_words, new_words, shift),
                    (Some(_), None) | (None, Some(_)) => false,
                }
        }
        (CompoundKind::Case(old_case), CompoundKind::Case(new_case)) => {
            same_word(&old_case.subject, &new_case.subject, shift)
                && old_case.clauses.len() == new_case.clauses.len()
                && old_case
                    .clauses
                    .iter()
                    .zip(&new_case.clauses)
                    .all(|(old, new)| same_words(&old.patterns, &new.patterns, shift))
        }
        (CompoundKind::Subshell(_), CompoundKind::Subshell(_))
        | (CompoundKind::Group(_), CompoundKind::Group(_))
        | (CompoundKind::If(_), CompoundKind::If(_))
        | (CompoundKind::While(_), CompoundKind::While(_))
        | (CompoundKind::Until(_), CompoundKind::Until(_)) => true,
        (
            CompoundKind::Subshell(_)
            | CompoundKind::Group(_)
            | CompoundKind::If(_)
            | CompoundKind::For(_)
            | CompoundKind::While(_)
            | CompoundKind::Until(_)
            | CompoundKind::Case(_),
            _,
        ) => false,
    };
    let (old_lists, new_lists) = (old.kind.lists(), new.kind.lists());
    check(
        same_header
            && old_lists.len() == new_lists.len()
            && old_lists
                .iter()
                .zip(&new_lists)
                .all(|(old, new)| old.len() == new.len())
            && shift.span(old.span) == new.span
            && same_redirections(&old.redirections, &new.redirections, shift),
    )
}

/// Whether words that are never command names (headers, patterns, a function's name) are unchanged but for their
/// place.
fn same_words(old: &[CommandWord], new: &[CommandWord], shift: &Shift<'_>) -> bool {
    old.len() == new.len()
        && old.iter().zip(new).all(|(old, new)| {
            shift.span(old.span) == new.span && same_substitutions(&old.substitutions, &new.substitutions, shift)
        })
}

/// [`same_words`] for a single word.
fn same_word(old: &CommandWord, new: &CommandWord, shift: &Shift<'_>) -> bool {
    same_words(slice::from_ref(old), slice::from_ref(new), shift)
}

/// Whether the redirections are the same, at the shifted places.
fn same_redirections(old: &[Redirect], new: &[Redirect], shift: &Shift<'_>) -> bool {
    old.len() == new.len()
        && old.iter().zip(new).all(|(old, new)| {
            let same_documents = match (&old.here_document, &new.here_document) {
                (None, None) => true,
                (Some(old_document), Some(new_document)) => {
                    old_document.strip_tabs == new_document.strip_tabs
                        && old_document.quoted == new_document.quoted
                        && shift.span(old_document.body) == new_document.body
                        && shift.span(old_document.delimiter) == new_document.delimiter
                        && same_substitutions(&old_document.substitutions, &new_document.substitutions, shift)
                }
                (Some(_), None) | (None, Some(_)) => false,
            };
            old.operator == new.operator
                && old.feeds_interpreter == new.feeds_interpreter
                && old.fd.map(|fd| (shift.span(fd.span), fd.value)) == new.fd.map(|fd| (fd.span, fd.value))
                && shift.span(old.span) == new.span
                && same_documents
                && same_word(&old.target, &new.target, shift)
        })
}

/// Whether the substitutions have the same kinds and places. Their commands are compared one by one by [`verify`].
fn same_substitutions(old: &[Substitution], new: &[Substitution], shift: &Shift<'_>) -> bool {
    old.len() == new.len()
        && old.iter().zip(new).all(|(old, new)| {
            old.kind == new.kind
                && old.text == new.text
                && old.script.items.len() == new.script.items.len()
                && shift.span(old.span) == new.span
        })
}

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;
    use std::path::PathBuf;

    use super::*;
    use crate::classify::{Lookup, Resolver, SourceFile, classify};
    use crate::interpreter_table::Interpreters;

    /// A session: the usual tools in `/usr/bin`, a project binary under `/p`, and a few binaries whose paths need
    /// quoting or cannot be written at all.
    struct Session;

    impl Resolver for Session {
        fn resolve(&self, name: &str, lookup: Lookup) -> Program {
            if lookup == Lookup::Shell && crate::is_builtin(name) {
                return Program::Builtin;
            }
            let trusted = |path: &str| Program::Trusted(PathBuf::from(path));
            match name {
                "spaced" => trusted("/Applications/My Tools/bin/spaced"),
                "quoted" => trusted("/opt/it's $HOME; *rm*/quoted"),
                "unicode" => trusted("/opt/ferramentas/ação"),
                "slashed" => trusted("/opt/a\\b/slashed"),
                "ticked" => trusted("/opt/a`b`/ticked"),
                "newline" => trusted("/opt/a\nb/newline"),
                "relative" => trusted("bin/relative"),
                "dotted" => trusted("/opt/../bin/dotted"),
                "latin1" => Program::Trusted(PathBuf::from(OsStr::from_bytes(b"/opt/\xe9/latin1"))),
                "tool" | "./tool" => Program::ProjectExecutable(PathBuf::from("/p/node_modules/.bin/tool")),
                "missing" => Program::NotFound,
                _ => trusted(&format!("/usr/bin/{name}")),
            }
        }

        fn source_file(&self, _path: &str) -> SourceFile {
            SourceFile::Unresolved
        }
    }

    fn run(line: &str) -> Result<String, ReserialiseError> {
        let outcome = parse_line(line);
        let classification = classify(&outcome, line, &Session, &Interpreters::defaults());
        reserialise(line, &outcome, &classification)
    }

    // FR-LC-13: a bare name is replaced by its binary's absolute path, and nothing else changes.
    #[test]
    fn replaces_bare_name_with_absolute_path() {
        assert_eq!(run("git push origin main").unwrap(), "/usr/bin/git push origin main");
        assert_eq!(
            run("X=1 git -C 'a b' log >out 2>&1 | head -n 5; ls &").unwrap(),
            "X=1 /usr/bin/git -C 'a b' log >out 2>&1 | /usr/bin/head -n 5; /usr/bin/ls &"
        );
        // The whole word is replaced, quotes included.
        assert_eq!(run("\"git\" status").unwrap(), "/usr/bin/git status");
        assert_eq!(run("g\\it status").unwrap(), "/usr/bin/git status");
        // A project executable is replaced by its canonical path too, however it was named.
        assert_eq!(run("./tool --fix").unwrap(), "/p/node_modules/.bin/tool --fix");
        // Wrappers and the commands they run are both replaced.
        assert_eq!(
            run("env FOO=1 nice -n 5 git push").unwrap(),
            "/usr/bin/env FOO=1 /usr/bin/nice -n 5 /usr/bin/git push"
        );
        assert_eq!(
            run("find . -name x | xargs rm").unwrap(),
            "/usr/bin/find . -name x | /usr/bin/xargs /usr/bin/rm"
        );
        // An argument that only looks like a command is not a command name.
        assert_eq!(run("echo git").unwrap(), "echo git");
    }

    // FR-LC-03, KNSH-038: builtins, function calls and names not found keep their names.
    #[test]
    fn leaves_builtins_and_functions_unchanged() {
        assert_eq!(run("cd src && echo hi; pwd").unwrap(), "cd src && echo hi; pwd");
        assert_eq!(
            run("f() { git status; }; f").unwrap(),
            "f() { /usr/bin/git status; }; f"
        );
        assert_eq!(
            run("command git log; command -v git; builtin echo x").unwrap(),
            "command /usr/bin/git log; command -v git; builtin echo x"
        );
        // A call the parser is not certain reaches the function is resolved as a program, so it is replaced: what
        // runs is what was classified (`command` could run a program of that name, so the call is not marked).
        assert_eq!(
            run("f() { :; }; f; command f").unwrap(),
            "f() { :; }; /usr/bin/f; command /usr/bin/f"
        );
        assert_eq!(run("time -p ls").unwrap(), "time -p /usr/bin/ls");
        assert_eq!(run("missing --flag").unwrap(), "missing --flag");
        // `xargs`'s default `echo` has no name on the line to replace.
        assert_eq!(run("ls | xargs").unwrap(), "/usr/bin/ls | /usr/bin/xargs");
    }

    // FR-LC-09, FR-LC-13: commands inside substitutions, compound commands and function bodies are replaced too.
    #[test]
    fn rewrites_inside_command_substitution() {
        assert_eq!(
            run("echo \"$(git rev-parse HEAD)\" $(ls $(pwd))").unwrap(),
            "echo \"$(/usr/bin/git rev-parse HEAD)\" $(/usr/bin/ls $(pwd))"
        );
        assert_eq!(run("echo `date`").unwrap(), "echo `/usr/bin/date`");
        assert_eq!(
            run("diff <(sort a) >(tee b)").unwrap(),
            "/usr/bin/diff <(/usr/bin/sort a) >(/usr/bin/tee b)"
        );
        assert_eq!(run("X=$(whoami) make").unwrap(), "X=$(/usr/bin/whoami) /usr/bin/make");
        assert_eq!(
            run("cat <in >\"$(mktemp)\"").unwrap(),
            "/usr/bin/cat <in >\"$(/usr/bin/mktemp)\""
        );
        assert_eq!(
            run("if test -f x; then rm x; elif ls; then :; else touch x; fi").unwrap(),
            "if test -f x; then /usr/bin/rm x; elif /usr/bin/ls; then :; else /usr/bin/touch x; fi"
        );
        assert_eq!(
            run("for f in $(ls); do wc -l \"$f\"; done; while read l; do grep x; done <f").unwrap(),
            "for f in $(/usr/bin/ls); do /usr/bin/wc -l \"$f\"; done; while read l; do /usr/bin/grep x; done <f"
        );
        assert_eq!(
            run("case $(uname) in Darwin) sw_vers;; *) (lsb_release -a);; esac").unwrap(),
            "case $(/usr/bin/uname) in Darwin) /usr/bin/sw_vers;; *) (/usr/bin/lsb_release -a);; esac"
        );
        assert_eq!(
            run("function f { { git add .; git commit; } 2>/dev/null; }").unwrap(),
            "function f { { /usr/bin/git add .; /usr/bin/git commit; } 2>/dev/null; }"
        );
        // An unquoted here-document's substitutions run, so they are replaced; the body's other text is not.
        assert_eq!(
            run("cat <<EOF\nls $(date)\nEOF\necho done").unwrap(),
            "/usr/bin/cat <<EOF\nls $(/usr/bin/date)\nEOF\necho done"
        );
    }

    // KNSH-038: paths with spaces or shell metacharacters are single-quoted, so they read as one literal word.
    #[test]
    fn quotes_path_with_space() {
        assert_eq!(
            run("spaced --version").unwrap(),
            "'/Applications/My Tools/bin/spaced' --version"
        );
        assert_eq!(run("quoted x").unwrap(), "'/opt/it'\\''s $HOME; *rm*/quoted' x");
        assert_eq!(run("unicode").unwrap(), "'/opt/ferramentas/ação'");
        assert_eq!(
            run("echo $(spaced) `quoted`").unwrap(),
            "echo $('/Applications/My Tools/bin/spaced') `'/opt/it'\\''s $HOME; *rm*/quoted'`"
        );
        assert_eq!(quote("/usr/bin/g++-14"), "/usr/bin/g++-14");
        assert_eq!(quote("/a~b"), "'/a~b'");
    }

    // KNSH-038 fuzz regression: a quoted path before a here-document or here-string keeps the line's shape (the
    // marker reads `a~` as the classifier does, so the quotes change nothing).
    #[test]
    fn quoted_path_before_here_document_round_trips() {
        assert_eq!(run("a~ <<X\nX\n").unwrap(), "'/usr/bin/a~' <<X\nX\n");
        assert_eq!(
            run("cat <$(ca~ <<X\n\tX\nX\n)\nO\n").unwrap(),
            "/usr/bin/cat <$('/usr/bin/ca~' <<X\n\tX\nX\n)\n/usr/bin/O\n"
        );
        assert_eq!(run("e~c <<< x").unwrap(), "'/usr/bin/e~c' <<< x");
        assert_eq!(
            run("spaced <<X\nX\n").unwrap(),
            "'/Applications/My Tools/bin/spaced' <<X\nX\n"
        );
    }

    // FR-POL-20, KNSH-038: dynamic parts are left as written; only names outside them are replaced.
    #[test]
    fn does_not_touch_dynamic_parts() {
        assert_eq!(run("bash -c \"$x\"").unwrap(), "bash -c \"$x\"");
        assert_eq!(run("eval \"$cmd\"; ls").unwrap(), "eval \"$cmd\"; /usr/bin/ls");
        assert_eq!(run("$tool --x && git log").unwrap(), "$tool --x && /usr/bin/git log");
        assert_eq!(
            run("curl -s https://x | sh; [[ -f x ]] && ls").unwrap(),
            "/usr/bin/curl -s https://x | sh; [[ -f x ]] && /usr/bin/ls"
        );
        assert_eq!(run("env -S 'git log'").unwrap(), "env -S 'git log'");
        assert_eq!(run("source ./env.sh; make").unwrap(), "source ./env.sh; /usr/bin/make");
        // A line the parser could not read is dynamic as a whole and returned unchanged.
        assert_eq!(run("echo 'unterminated").unwrap(), "echo 'unterminated");
    }

    // KNSH-038: a replacement that cannot be done safely is an error, so the supervisor denies the line.
    #[test]
    fn fails_closed_when_a_replacement_is_unsafe() {
        let span = |start, end| Span::new(start, end);
        assert_eq!(
            run("slashed"),
            Err(ReserialiseError::PathNotQuotable { span: span(0, 7) })
        );
        assert_eq!(
            run("echo; ticked"),
            Err(ReserialiseError::PathNotQuotable { span: span(6, 12) })
        );
        assert_eq!(
            run("newline"),
            Err(ReserialiseError::PathNotQuotable { span: span(0, 7) })
        );
        assert_eq!(
            run("relative"),
            Err(ReserialiseError::PathNotAbsolute { span: span(0, 8) })
        );
        assert_eq!(
            run("dotted"),
            Err(ReserialiseError::PathNotAbsolute { span: span(0, 6) })
        );
        assert_eq!(run("latin1"), Err(ReserialiseError::PathNotUtf8 { span: span(0, 6) }));
        // Inside a backtick substitution bash un-escapes, the name has no span on the line.
        let line = "echo `ls \\$HOME`";
        assert_eq!(
            run(line),
            Err(ReserialiseError::NameNotOnLine {
                span: span(5, line.len())
            })
        );
        // ...but a builtin there needs no replacement.
        assert_eq!(run("echo `echo \\$HOME`").unwrap(), "echo `echo \\$HOME`");
    }

    // KNSH-038, FR-LC-13: GNU `xargs -I` replaces its placeholder in the utility's name too, so a path holding it
    // would let the input pick the binary. Paths without it are still replaced.
    #[test]
    fn fails_closed_when_the_path_holds_an_xargs_placeholder() {
        let span = |start, end| Span::new(start, end);
        assert_eq!(
            run("xargs -I bin git x"),
            Err(ReserialiseError::PathHoldsPlaceholder { span: span(13, 16) })
        );
        assert_eq!(
            run("gxargs --replace=usr env git"),
            Err(ReserialiseError::PathHoldsPlaceholder { span: span(21, 24) })
        );
        assert_eq!(
            run("xargs -J /usr cp"),
            Err(ReserialiseError::PathHoldsPlaceholder { span: span(14, 16) })
        );
        assert_eq!(
            run("xargs -I {} git add {}").unwrap(),
            "/usr/bin/xargs -I {} /usr/bin/git add {}"
        );
    }

    // KNSH-038, FR-LC-13: bash calls a function named like the path before the binary, so replacing the name would
    // run the function where the binary was classified.
    #[test]
    fn fails_closed_when_a_function_is_named_like_the_path() {
        let line = "/usr/bin/git() { rm -rf x; }; git status";
        assert_eq!(
            run(line),
            Err(ReserialiseError::FunctionShadowsPath {
                span: Span::new(30, 33)
            })
        );
        assert_eq!(
            run("echo $(function /usr/bin/ls { :; }); ls"),
            Err(ReserialiseError::FunctionShadowsPath {
                span: Span::new(37, 39)
            })
        );
        // A function with another name changes nothing.
        assert_eq!(
            run("/usr/bin/gitx() { :; }; git status").unwrap(),
            "/usr/bin/gitx() { :; }; /usr/bin/git status"
        );
    }

    // KNSH-038: a classification of another line is refused rather than applied.
    #[test]
    fn refuses_a_classification_of_another_line() {
        let line = "git status";
        let other = "echo 'unterminated";
        let classification = classify(&parse_line(line), line, &Session, &Interpreters::defaults());
        assert_eq!(
            reserialise(other, &parse_line(other), &classification),
            Err(ReserialiseError::Mismatch)
        );
        let classification = classify(&parse_line(other), other, &Session, &Interpreters::defaults());
        assert_eq!(
            reserialise(line, &parse_line(line), &classification),
            Err(ReserialiseError::Mismatch)
        );
        // A classification whose names are not words of this line is refused too.
        let longer = "echo hello; git status";
        let classification = classify(&parse_line(longer), longer, &Session, &Interpreters::defaults());
        assert!(reserialise(line, &parse_line(line), &classification).is_err());
    }

    // KNSH-038: the round-trip check catches a replacement that changes how the line reads.
    #[test]
    fn round_trip_check_rejects_a_changed_shape() {
        let line = "ls x";
        let outcome = parse_line(line);
        let script = outcome.script().unwrap();
        let edit = |replacement: &str| Edit {
            span: Span::new(0, 2),
            replacement: replacement.to_owned(),
            path: "/bin/ls".to_owned(),
        };
        for bad in ["/bin/ls;", "/bin/ls y", "'/bin/ls", "/bin/l", "$(/bin/ls)"] {
            let edits = [edit(bad)];
            let output = apply(line, &edits).unwrap();
            assert_eq!(
                verify(line, &outcome, script, &output, &edits),
                Err(ReserialiseError::RoundTrip),
                "{bad}"
            );
        }
        let edits = [edit("'/bin/ls'")];
        let output = apply(line, &edits).unwrap();
        assert_eq!(verify(line, &outcome, script, &output, &edits), Ok(()));
    }
}
