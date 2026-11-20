//! The expansion engine: tilde, parameter and arithmetic expansion of a word (KNSH-097), then word splitting,
//! pathname expansion and quote removal (KNSH-098), in bash 5.2's order (NFR-COMPAT-02).
//!
//! A word is first turned into [`Part`]s (by [`crate::word::parts`] from the parser's segments, or by
//! [`crate::scan`] for the words inside `${…}`); brace expansion ([`crate::brace`]) has already made one word into
//! several where it applies. Tilde expansion rewrites the leading literal text. Each part is then expanded into
//! [`Fields`]: characters marked as quoted or not and as expanded or literal. `"$@"` and the unquoted `$@` and `$*`
//! start a new field for each positional parameter after the first, as bash does.
//!
//! What happens to the fields depends on where the word is ([`Context`]). As arguments:
//!
//! 1. Word splitting: the unquoted characters an expansion produced that are in `IFS` (space, tab and newline when it
//!    is unset; nothing splits when it is empty) separate fields. A run of `IFS` white space (space, tab, newline)
//!    is one separator and is dropped at the start and end; every other `IFS` character is a separator of its own,
//!    together with the white space around it, so two in a row delimit an empty field. Literal text never splits.
//! 2. A field that is empty and was never quoted is removed (an unquoted `$x` with `x` empty passes no argument). A
//!    quoted empty string in a word that is only partly quoted (`""$x`) is dropped before splitting, as bash drops
//!    it, so it only keeps the word when the word expands to nothing at all.
//! 3. Pathname expansion ([`crate::glob`]), unless `set -f`: a field with an unquoted `*`, `?`, `[…]` (or, with
//!    `extglob`, a group) becomes the sorted file names it matches; with none, it stays as written, is removed
//!    (`nullglob`), or abandons the command with bash's `no match` error (`failglob`).
//! 4. Quote removal: what is left are the characters themselves.
//!
//! Bash's own expansion errors come back as [`ExpandError::Discard`] (bash abandons the command and the rest of its
//! line: a bad substitution, an arithmetic error, an invalid indirection, `${1:=x}`) or [`ExpandError::Fatal`]
//! (bash exits: an unset parameter under `set -u`, `${x?}`), with bash's message.

use std::ffi::OsString;
use std::fmt::Write as _;

use knsh_bash::Span;
use knsh_platform::{Collation, Fs, UserHomes};

use crate::arith::{self, Failure};
use crate::error::{InterpError, Unsupported};
use crate::glob;
use crate::param::{self, CaseKind, DefaultKind, Name, Op, Parsed, ReplaceMode};
use crate::pattern::{self, Flags, Pattern};
use crate::scan::{self, Mode, Part};
use crate::state::{DEFAULT_IFS, ShellState, is_always_unemulated};
use crate::word::{self, WordChar, assignment_value_start};

/// Deepest nesting of `${…}` and `$((…))` inside one another. The parser's own limits keep real scripts far below
/// it; past it the run fails with [`InterpError::DepthExceeded`] rather than overflowing the stack.
pub(crate) const MAX_EXPANSION_DEPTH: usize = 256;

/// How expanding a word failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ExpandError {
    /// Something the interpreter does not evaluate, or a source mismatch: the run stops.
    Interp(InterpError),
    /// A bash error that abandons the command and the rest of its line, with status 1. The message is bash's,
    /// without the `name: line n: ` prefix.
    Discard(String),
    /// A bash error that ends a non-interactive shell with status 1.
    Fatal(String),
}

impl From<InterpError> for ExpandError {
    fn from(error: InterpError) -> Self {
        Self::Interp(error)
    }
}

type Result<T> = std::result::Result<T, ExpandError>;

/// One field of an expanded word.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Field {
    /// Its characters.
    pub(crate) chars: Vec<WordChar>,
    /// Whether any part of it was quoted, even an empty one (`""`): such a field is kept when empty.
    pub(crate) quoted: bool,
}

/// The fields a word expands into, the last one being built.
#[derive(Debug)]
struct Fields {
    /// Never empty.
    list: Vec<Field>,
    /// How many `$@`-like lists expanded to no parameters at all.
    vanished: usize,
    /// Whether an unquoted `$@`-like list started a field: where the fields are joined again, bash joins those
    /// with a separator that depends on `IFS`, the context and its version.
    unquoted_breaks: bool,
}

impl Fields {
    fn new() -> Self {
        Self {
            list: vec![Field::default()],
            vanished: 0,
            unquoted_breaks: false,
        }
    }

    fn current(&mut self) -> &mut Field {
        if self.list.is_empty() {
            self.list.push(Field::default());
        }
        let last = self.list.len() - 1;
        &mut self.list[last]
    }

    fn push_str(&mut self, text: &str, quoted: bool, expanded: bool) {
        let field = self.current();
        field
            .chars
            .extend(text.chars().map(|ch| WordChar { ch, quoted, expanded }));
    }

    fn mark_quoted(&mut self) {
        self.current().quoted = true;
    }

    fn break_field(&mut self) {
        self.list.push(Field::default());
    }

    /// All fields joined by single spaces, as bash joins `$@` where no splitting happens.
    fn joined(self) -> Vec<WordChar> {
        let mut out = Vec::new();
        for (i, field) in self.list.into_iter().enumerate() {
            if i > 0 {
                out.push(WordChar {
                    ch: ' ',
                    quoted: true,
                    expanded: true,
                });
            }
            out.extend(field.chars);
        }
        out
    }
}

/// A parameter's value.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Value {
    /// A string.
    Str(String),
    /// A list (`$@`, `$*`, `${!prefix*}`); `star` for the `*` forms, joined with the first character of `IFS`
    /// inside double quotes.
    List { items: Vec<String>, star: bool },
}

impl Value {
    /// `f` applied to the string, or to each item of the list.
    fn map(self, mut f: impl FnMut(&str) -> Result<String>) -> Result<Self> {
        Ok(match self {
            Self::Str(text) => Self::Str(f(&text)?),
            Self::List { items, star } => Self::List {
                items: items.iter().map(|item| f(item)).collect::<Result<_>>()?,
                star,
            },
        })
    }
}

/// Expands words against the shell state.
pub(crate) struct Expander<'a> {
    state: &'a mut ShellState,
    homes: &'a dyn UserHomes,
    /// Where pathname expansion reads directories.
    fs: &'a dyn Fs,
    /// How pathname expansion results are sorted.
    collation: &'a dyn Collation,
    /// The text every span indexes.
    source: &'a str,
    /// The assignments of the command being expanded (`a=1 b=$a cmd`), seen before the shell's variables.
    overlay: &'a [(String, OsString)],
    /// `${…}` and `$((…))` currently being expanded.
    depth: usize,
}

impl<'a> Expander<'a> {
    /// An expander over `state`, finding home directories through `homes` and file names through `fs`, sorting them
    /// with `collation`, reading spans of `source`, with `overlay` as the command's own assignments.
    pub(crate) fn new(
        state: &'a mut ShellState,
        homes: &'a dyn UserHomes,
        fs: &'a dyn Fs,
        collation: &'a dyn Collation,
        source: &'a str,
        overlay: &'a [(String, OsString)],
    ) -> Self {
        Self {
            state,
            homes,
            fs,
            collation,
            source,
            overlay,
            depth: 0,
        }
    }

    // ---- Words, by context ----

    /// The arguments `parts` (one word, after brace expansion, spanning `span`) expand into: split on `IFS`, empty
    /// unquoted fields removed, matched against file names, quotes removed.
    pub(crate) fn arguments(&mut self, parts: &[Part], span: Span) -> Result<Vec<String>> {
        let parts = self.tilde_word(parts, true, span)?;
        let mut fields = Fields::new();
        self.expand(&parts, false, false, &mut fields)?;
        let ifs = self.ifs();
        let options = self.state.options().clone();
        let mut globbing: Option<glob::Options> = None;
        let mut out = Vec::new();
        for mut field in fields.list.into_iter().flat_map(|field| split(field, &ifs)) {
            if field.chars.is_empty() && !field.quoted {
                continue;
            }
            // Bash quotes an unquoted literal character that is in `IFS` as it reads the word (`expand_word_internal`
            // adds it with `CTLESC`), so with `IFS='*'` a literal `*` matches no file name.
            for c in &mut field.chars {
                if !c.expanded && !c.quoted && ifs.contains(c.ch) {
                    c.quoted = true;
                }
            }
            let text: String = field.chars.iter().map(|c| c.ch).collect();
            if options.noglob || !pattern::has_glob(&field.chars, options.extglob) {
                out.push(text);
                continue;
            }
            let glob_options = match &globbing {
                Some(glob_options) => glob_options,
                None => globbing.insert(self.glob_options(span)?),
            };
            let mut matches = glob::glob(self.fs, self.state.cwd(), &field.chars, glob_options, span)?;
            if !matches.is_empty() {
                // Bash sorts with `strcoll`; a locale the system lacks leaves the C order, as in bash.
                let locale = self.collation_locale(span)?;
                self.collation.sort(&locale, &mut matches);
                out.extend(matches);
            } else if options.failglob {
                return Err(ExpandError::Discard(format!("no match: {text}")));
            } else if !options.nullglob {
                out.push(text);
            }
        }
        Ok(out)
    }

    /// How pathname expansion matches names: the `shopt` options, and the patterns of a non-empty `GLOBIGNORE`.
    fn glob_options(&self, span: Span) -> Result<glob::Options> {
        let options = self.state.options();
        let ignore = self
            .variable("GLOBIGNORE")
            .map_err(|feature| InterpError::Unsupported { feature, span })?
            .filter(|value| !value.is_empty())
            .map(|value| {
                let flags = Flags {
                    extglob: options.extglob,
                    nocase: options.nocaseglob,
                };
                value
                    .split(':')
                    .map(|pattern| {
                        let chars: Vec<WordChar> = pattern
                            .chars()
                            .map(|ch| WordChar {
                                ch,
                                quoted: false,
                                expanded: false,
                            })
                            .collect();
                        Pattern::new(&chars, flags)
                    })
                    .collect()
            })
            .unwrap_or_default();
        Ok(glob::Options {
            dotglob: options.dotglob,
            nocaseglob: options.nocaseglob,
            globstar: options.globstar,
            extglob: options.extglob,
            ignore,
        })
    }

    /// The locale bash collates in: the first of `LC_ALL`, `LC_COLLATE` and `LANG` that is set and not empty, or
    /// the C locale.
    fn collation_locale(&self, span: Span) -> Result<String> {
        for name in ["LC_ALL", "LC_COLLATE", "LANG"] {
            let value = self
                .variable(name)
                .map_err(|feature| InterpError::Unsupported { feature, span })?;
            if let Some(value) = value.filter(|value| !value.is_empty()) {
                return Ok(value);
            }
        }
        Ok("C".to_owned())
    }

    /// How `case` patterns and the pattern operators of `${…}` are read: with `extglob` when it is on.
    pub(crate) fn pattern_flags(&self) -> Flags {
        Flags {
            extglob: self.state.options().extglob,
            nocase: false,
        }
    }

    /// The single string `parts` expand into where bash neither splits nor matches file names (a `case` subject, a
    /// `for` variable).
    pub(crate) fn string(&mut self, parts: &[Part], span: Span) -> Result<String> {
        Ok(self.pattern(parts, span)?.into_iter().map(|c| c.ch).collect())
    }

    /// The characters of a `case` pattern, quoted ones marked.
    pub(crate) fn pattern(&mut self, parts: &[Part], span: Span) -> Result<Vec<WordChar>> {
        let parts = self.tilde_word(parts, false, span)?;
        let mut fields = Fields::new();
        self.expand(&parts, false, false, &mut fields)?;
        self.join(fields, span)
    }

    /// The value of an assignment, from its parts: tilde expansion after the `=` and after each unquoted `:`, then
    /// parameter and arithmetic expansion, without splitting.
    pub(crate) fn assignment_value(&mut self, parts: &[Part], span: Span) -> Result<String> {
        let parts = self.tilde_text(parts, Some(0), true, span)?;
        let mut fields = Fields::new();
        self.expand(&parts, false, false, &mut fields)?;
        Ok(self.join(fields, span)?.into_iter().map(|c| c.ch).collect())
    }

    /// The text of an arithmetic expression spanning `span` after expansion, as bash expands it: as if inside
    /// double quotes, with double quotes removed.
    pub(crate) fn arithmetic_text(&mut self, span: Span) -> Result<String> {
        let parts = scan::scan(self.source, span, Mode::Double)?;
        let mut fields = Fields::new();
        self.expand(&parts, true, false, &mut fields)?;
        Ok(self.join(fields, span)?.into_iter().map(|c| c.ch).collect())
    }

    /// Evaluates the already expanded arithmetic `expression` against the shell's variables.
    ///
    /// # Errors
    ///
    /// See [`Failure`].
    pub(crate) fn evaluate(&mut self, expression: &str) -> std::result::Result<i64, Failure> {
        arith::evaluate(expression, &mut ArithVariables { expander: self })
    }

    // ---- Parts ----

    /// Expands `parts` into `out`. `quoted`: inside double quotes. `literal_expands`: literal text counts as
    /// expanded (the words of `${x:-a b}`, which bash splits).
    fn expand(&mut self, parts: &[Part], quoted: bool, literal_expands: bool, out: &mut Fields) -> Result<()> {
        for part in parts {
            match part {
                Part::Text(text) => out.push_str(text, quoted, literal_expands && !quoted),
                Part::Quoted(text) => {
                    out.push_str(text, true, false);
                    out.mark_quoted();
                }
                Part::Double(inner) => {
                    let before = out.vanished;
                    self.expand(inner, true, literal_expands, out)?;
                    // `"$@"` with no parameters leaves no field at all, not an empty one.
                    let vanished = inner.len() == 1 && out.vanished > before;
                    if !vanished {
                        out.mark_quoted();
                    }
                }
                Part::Param { name, span } => {
                    let parsed = Name::parse(name).ok_or(InterpError::SourceMismatch { span: *span })?;
                    let value = self.lookup(&parsed, *span)?;
                    // `$1` is named `$1` in bash's message; `$x` is named `x`.
                    let label = match &parsed {
                        Name::Variable(variable) => variable.clone(),
                        Name::Positional(_) | Name::Special(_) => format!("${parsed}"),
                    };
                    let value = self.require(value, &parsed, &label)?;
                    self.emit(value, quoted, out);
                }
                Part::Brace { body, span } => {
                    self.enter()?;
                    let result = self.brace(*body, *span, quoted, out);
                    self.depth -= 1;
                    result?;
                }
                Part::Arith { body, span } => {
                    self.enter()?;
                    let result = self.arithmetic(*body, *span);
                    self.depth -= 1;
                    out.push_str(&result?.to_string(), quoted, true);
                }
            }
        }
        Ok(())
    }

    fn enter(&mut self) -> Result<()> {
        if self.depth >= MAX_EXPANSION_DEPTH {
            return Err(InterpError::DepthExceeded {
                limit: MAX_EXPANSION_DEPTH,
            }
            .into());
        }
        self.depth += 1;
        Ok(())
    }

    /// The fields of a word spanning `span` joined into one, where bash does not split: by single spaces. An
    /// unquoted `$*` or `$@` with several parameters is joined there with the first character of `IFS` or a space
    /// depending on the context and bash's version (bash 3.2 joins `x=$*` with `:` but `${x:?$*}` with a space when
    /// `IFS` is `:`), so unless that character is a space, which every form agrees on, it is refused
    /// ([`Unsupported::UnsplitJoin`]).
    fn join(&self, fields: Fields, span: Span) -> Result<Vec<WordChar>> {
        if fields.unquoted_breaks && !self.ifs().starts_with(' ') {
            return Err(InterpError::Unsupported {
                feature: Unsupported::UnsplitJoin,
                span,
            }
            .into());
        }
        Ok(fields.joined())
    }

    /// `$((…))`: the body expanded, then evaluated.
    fn arithmetic(&mut self, body: Span, span: Span) -> Result<i64> {
        let text = self.arithmetic_text(body)?;
        self.evaluate(&text).map_err(|failure| failed(failure, span))
    }

    /// Appends `value` to `out`: a string as one piece; `"$@"` and the unquoted lists as one field per item;
    /// `"$*"` joined with the first character of `IFS`.
    fn emit(&self, value: Option<Value>, quoted: bool, out: &mut Fields) {
        match value {
            None => {}
            Some(Value::Str(text)) => out.push_str(&text, quoted, true),
            Some(Value::List { items, star: true }) if quoted => {
                let separator = self.ifs().chars().next().map(String::from).unwrap_or_default();
                out.push_str(&items.join(&separator), true, true);
            }
            Some(Value::List { items, .. }) => {
                if items.is_empty() {
                    out.vanished += 1;
                }
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        out.break_field();
                        out.unquoted_breaks |= !quoted;
                    }
                    out.push_str(item, quoted, true);
                    if quoted {
                        out.mark_quoted();
                    }
                }
            }
        }
    }

    // ---- Parameters ----

    /// `IFS`, or bash's default when it is unset.
    fn ifs(&self) -> String {
        match self.state.variable("IFS") {
            Some(value) => value.to_string_lossy().into_owned(),
            None => DEFAULT_IFS.to_owned(),
        }
    }

    /// The value of variable `name`: the command's own assignment first, then the shell's.
    fn variable(&self, name: &str) -> std::result::Result<Option<String>, Unsupported> {
        if self.state.is_unemulated(name) {
            return Err(Unsupported::ShellVariable);
        }
        let value = self
            .overlay
            .iter()
            .rev()
            .find(|(assigned, _)| assigned == name)
            .map(|(_, value)| value.as_os_str())
            .or_else(|| self.state.variable(name));
        value
            .map(|value| value.to_str().map(str::to_owned).ok_or(Unsupported::NonUtf8Value))
            .transpose()
    }

    /// Whether variable `name` is exported (or is one of the command's own assignments, which are).
    fn is_exported(&self, name: &str) -> bool {
        self.overlay.iter().any(|(assigned, _)| assigned == name) || self.state.is_exported(name)
    }

    /// The value of parameter `name`, or `None` if it is unset.
    fn lookup(&self, name: &Name, span: Span) -> Result<Option<Value>> {
        let state = &*self.state;
        Ok(match name {
            Name::Variable(variable) => self
                .variable(variable)
                .map_err(|feature| InterpError::Unsupported { feature, span })?
                .map(Value::Str),
            Name::Positional(0) => Some(Value::Str(state.name().to_owned())),
            Name::Positional(n) => state.positional().get(n - 1).cloned().map(Value::Str),
            Name::Special(special) => match special {
                '@' | '*' => Some(Value::List {
                    items: state.positional().to_vec(),
                    star: *special == '*',
                }),
                '#' => Some(Value::Str(state.positional().len().to_string())),
                '?' => Some(Value::Str(state.last_status().to_string())),
                '$' => Some(Value::Str(state.pid().to_string())),
                '-' => Some(Value::Str(self.flags())),
                // No background job has run (`&` is refused until KNSH-100), so `$!` is unset.
                _ => None,
            },
        })
    }

    /// `$-`: the option letters of a shell started as `bash -c` (`h` hashing, `B` brace expansion, `c`), with `f`
    /// under `set -f`, `u` under `set -u` and `C` under `set -C`, in bash's order.
    fn flags(&self) -> String {
        let mut flags = String::new();
        if self.state.options().noglob {
            flags.push('f');
        }
        flags.push('h');
        if self.state.options().nounset {
            flags.push('u');
        }
        flags.push('B');
        if self.state.options().noclobber {
            flags.push('C');
        }
        flags.push('c');
        flags
    }

    /// `value`, or the `set -u` error for parameter `name` (called `label` in the message) if it is unset.
    fn require(&self, value: Option<Value>, name: &Name, label: &str) -> Result<Option<Value>> {
        if value.is_none() && self.state.options().nounset && !name.is_list() {
            return Err(ExpandError::Fatal(format!("{label}: unbound variable")));
        }
        Ok(value)
    }

    // ---- ${…} ----

    fn brace(&mut self, body: Span, span: Span, quoted: bool, out: &mut Fields) -> Result<()> {
        let text = word::text(body, self.source)?;
        let whole = word::text(span, self.source)?;
        match param::parse(text, body) {
            Parsed::Bad => Err(ExpandError::Discard(format!("{whole}: bad substitution"))),
            Parsed::Unsupported(feature) => Err(InterpError::Unsupported { feature, span }.into()),
            Parsed::Length(name) => {
                let length = match self.lookup(&name, span)? {
                    Some(Value::List { items, .. }) => items.len(),
                    Some(Value::Str(value)) => value.chars().count(),
                    None => {
                        self.require(None, &name, &name.to_string())?;
                        0
                    }
                };
                out.push_str(&length.to_string(), quoted, true);
                Ok(())
            }
            Parsed::Names { prefix, at } => {
                if self.state.lists_unemulated(&prefix) {
                    return Err(InterpError::Unsupported {
                        feature: Unsupported::ShellVariable,
                        span,
                    }
                    .into());
                }
                let items = self
                    .state
                    .variable_names()
                    .filter(|name| name.starts_with(prefix.as_str()))
                    .map(str::to_owned)
                    .collect();
                self.emit(Some(Value::List { items, star: !at }), quoted, out);
                Ok(())
            }
            Parsed::Param { name, indirect, op } => {
                let (label, target) = if indirect {
                    self.indirect(&name, span)?
                } else {
                    (name.to_string(), name)
                };
                let value = self.lookup(&target, span)?;
                self.operate(&op, &label, &target, value, quoted, span, out)
            }
        }
    }

    /// `${!name}`: the parameter the value of `name` names.
    fn indirect(&self, name: &Name, span: Span) -> Result<(String, Name)> {
        let text = match self.lookup(name, span)? {
            None => return Err(ExpandError::Discard(format!("{name}: invalid indirect expansion"))),
            Some(Value::Str(text)) => text,
            Some(Value::List { items, .. }) => items.join(" "),
        };
        if let Some((array, _)) = text.split_once('[')
            && Name::parse(array).is_some()
        {
            return Err(InterpError::Unsupported {
                feature: Unsupported::Array,
                span,
            }
            .into());
        }
        match Name::parse(&text) {
            Some(target) => Ok((text, target)),
            None => Err(ExpandError::Discard(format!("{text}: invalid variable name"))),
        }
    }

    /// Applies `op` to `value`, the value of `target` (named `label` in messages), and appends the result.
    #[allow(clippy::too_many_arguments)]
    fn operate(
        &mut self,
        op: &Op,
        label: &str,
        target: &Name,
        value: Option<Value>,
        quoted: bool,
        span: Span,
        out: &mut Fields,
    ) -> Result<()> {
        let result = match op {
            Op::None => self.require(value, target, label)?,
            Op::Default { kind, colon, word } => {
                return self.default(*kind, *colon, *word, label, target, value, quoted, out);
            }
            Op::Substring { offset, length } => {
                let value = self.require(value, target, label)?;
                match value {
                    None => None,
                    Some(value) => Some(self.substring(value, target, *offset, *length, span)?),
                }
            }
            Op::Remove {
                suffix,
                longest,
                pattern,
            } => {
                let value = self.require(value, target, label)?;
                let pattern = Pattern::new(&self.pattern_word(*pattern)?, self.pattern_flags());
                value
                    .map(|value| value.map(|text| Ok(remove(text, &pattern, *suffix, *longest))))
                    .transpose()?
            }
            Op::Replace {
                mode,
                pattern,
                replacement,
            } => {
                let value = self.require(value, target, label)?;
                let pattern = Pattern::new(&self.pattern_word(*pattern)?, self.pattern_flags());
                let replacement = match replacement {
                    Some(span) => self.pattern_word(*span)?,
                    None => Vec::new(),
                };
                value
                    .map(|value| value.map(|text| Ok(replace(text, &pattern, &replacement, *mode))))
                    .transpose()?
            }
            Op::Case { kind, all, pattern } => {
                let value = self.require(value, target, label)?;
                let pattern = Pattern::new(&self.pattern_word(*pattern)?, self.pattern_flags());
                value
                    .map(|value| value.map(|text| Ok(modify_case(text, &pattern, *kind, *all))))
                    .transpose()?
            }
            Op::Transform(op) => {
                if *op == 'P' {
                    return Err(InterpError::Unsupported {
                        feature: Unsupported::PromptExpansion,
                        span,
                    }
                    .into());
                }
                let value = self.require(value, target, label)?;
                let exported = matches!(target, Name::Variable(name) if self.is_exported(name));
                value
                    .map(|value| value.map(|text| Ok(transform(*op, text, target, exported))))
                    .transpose()?
            }
        };
        self.emit(result, quoted, out);
        Ok(())
    }

    /// `${name-word}`, `${name=word}`, `${name?word}`, `${name+word}` and their `:` forms.
    #[allow(clippy::too_many_arguments)]
    fn default(
        &mut self,
        kind: DefaultKind,
        colon: bool,
        word: Span,
        label: &str,
        target: &Name,
        value: Option<Value>,
        quoted: bool,
        out: &mut Fields,
    ) -> Result<()> {
        let unset = match &value {
            None => true,
            Some(Value::List { items, .. }) => items.is_empty(),
            Some(Value::Str(_)) => false,
        };
        let null = match &value {
            None => true,
            Some(Value::Str(text)) => text.is_empty(),
            Some(Value::List { items, .. }) => {
                let separator = self.ifs().chars().next().map(String::from).unwrap_or_default();
                items.join(&separator).is_empty()
            }
        };
        let missing = unset || (colon && null);
        match kind {
            DefaultKind::Use if missing => self.word(word, quoted, out),
            DefaultKind::Alternative if !missing => self.word(word, quoted, out),
            DefaultKind::Alternative => Ok(()),
            DefaultKind::Assign if missing => {
                let Name::Variable(variable) = target else {
                    return Err(ExpandError::Discard(format!("${label}: cannot assign in this way")));
                };
                let assigned = self.word_string(word, quoted)?;
                self.state.set_variable(variable, assigned.as_str());
                out.push_str(&assigned, quoted, true);
                Ok(())
            }
            DefaultKind::Error if missing => {
                let message = self.word_string(word, quoted)?;
                let message = match (message.is_empty(), colon) {
                    (false, _) => message,
                    (true, true) => "parameter null or not set".to_owned(),
                    (true, false) => "parameter not set".to_owned(),
                };
                Err(ExpandError::Fatal(format!("{label}: {message}")))
            }
            DefaultKind::Use | DefaultKind::Assign | DefaultKind::Error => {
                self.emit(value, quoted, out);
                Ok(())
            }
        }
    }

    /// The word of `${x:-word}` and the like, expanded into `out`: read as inside double quotes when the expansion
    /// is, and split like an expansion when it is not.
    fn word(&mut self, span: Span, quoted: bool, out: &mut Fields) -> Result<()> {
        let mode = if quoted { Mode::Double } else { Mode::Unquoted };
        let parts = scan::scan(self.source, span, mode)?;
        let parts = if quoted {
            parts
        } else {
            self.tilde_word(&parts, false, span)?
        };
        self.expand(&parts, quoted, true, out)
    }

    /// The word of `${x:=word}` or `${x:?word}` as one string.
    fn word_string(&mut self, span: Span, quoted: bool) -> Result<String> {
        let mut fields = Fields::new();
        self.word(span, quoted, &mut fields)?;
        Ok(self.join(fields, span)?.into_iter().map(|c| c.ch).collect())
    }

    /// A pattern or replacement inside `${…}`, expanded with its quoting marked. Bash reads quotes in it whether or
    /// not the expansion is inside double quotes (`"${path##*/}"` still matches `*`).
    fn pattern_word(&mut self, span: Span) -> Result<Vec<WordChar>> {
        let parts = scan::scan(self.source, span, Mode::Unquoted)?;
        let parts = self.tilde_word(&parts, false, span)?;
        let mut fields = Fields::new();
        self.expand(&parts, false, false, &mut fields)?;
        self.join(fields, span)
    }

    /// `${name:offset:length}` of a string (by characters) or of the positional parameters.
    fn substring(
        &mut self,
        value: Value,
        target: &Name,
        offset: Span,
        length: Option<Span>,
        span: Span,
    ) -> Result<Value> {
        let start = self.substring_number(offset, span)?;
        // Each expression is expanded once, as bash does; bash's message names the length as written, before
        // expansion and untrimmed.
        let length = match length {
            Some(length_span) => Some((
                self.substring_number(length_span, span)?,
                word::text(length_span, self.source)?.to_owned(),
            )),
            None => None,
        };
        let negative = |text: &str| ExpandError::Discard(format!("{text}: substring expression < 0"));
        match value {
            Value::Str(text) => {
                let chars: Vec<char> = text.chars().collect();
                let len = to_i64(chars.len());
                let Some(start) = clamp_start(start, len) else {
                    return Ok(Value::Str(String::new()));
                };
                let end = match length {
                    None => len,
                    Some((length, text)) if length < 0 => {
                        let end = len.saturating_add(length);
                        if end < start {
                            return Err(negative(&text));
                        }
                        end
                    }
                    Some((length, _)) => start.saturating_add(length).min(len),
                };
                Ok(Value::Str(slice(&chars, start, end).iter().collect()))
            }
            Value::List { items, star } => {
                // `${@:0}` starts with `$0`; a negative offset counts back from the last parameter.
                let mut all = Vec::with_capacity(items.len() + 1);
                if target.is_list() {
                    all.push(self.state.name().to_owned());
                }
                all.extend(items);
                let count = to_i64(all.len());
                let start = if start < 0 { start.saturating_add(count) } else { start };
                if start < 0 || start > count {
                    return Ok(Value::List {
                        items: Vec::new(),
                        star,
                    });
                }
                let end = match length {
                    None => count,
                    Some((length, text)) if length < 0 => return Err(negative(&text)),
                    Some((length, _)) => start.saturating_add(length).min(count),
                };
                Ok(Value::List {
                    items: slice(&all, start, end).to_vec(),
                    star,
                })
            }
        }
    }

    /// An offset or length of `${name:offset:length}`: an arithmetic expression.
    fn substring_number(&mut self, expression: Span, span: Span) -> Result<i64> {
        let text = self.arithmetic_text(expression)?;
        self.evaluate(&text).map_err(|failure| failed(failure, span))
    }

    // ---- Tilde expansion ----

    /// Tilde expansion of a word: a leading `~` prefix, and (as arguments) the forms after the `=` of a word
    /// spelled like an assignment.
    fn tilde_word(&mut self, parts: &[Part], arguments: bool, span: Span) -> Result<Vec<Part>> {
        let Some(Part::Text(first)) = parts.first() else {
            return Ok(parts.to_vec());
        };
        if arguments && let Some(value_start) = assignment_value_start(first) {
            return self.tilde_text(parts, Some(value_start), true, span);
        }
        self.tilde_text(parts, Some(0), false, span)
    }

    /// Rewrites the literal text of `parts`: a `~` at `first` in the first part (if it is literal text), and with
    /// `colons` a `~` after each unquoted `:` in any literal text, ends its prefix at the next `/` (or `:` with
    /// `colons`). A prefix that would run into a quoted part or an expansion is not expanded, as in bash.
    fn tilde_text(&mut self, parts: &[Part], first: Option<usize>, colons: bool, span: Span) -> Result<Vec<Part>> {
        let mut out = Vec::with_capacity(parts.len());
        let last = parts.len().saturating_sub(1);
        for (index, part) in parts.iter().enumerate() {
            let Part::Text(text) = part else {
                out.push(part.clone());
                continue;
            };
            let mut starts: Vec<usize> = Vec::new();
            if index == 0
                && let Some(at) = first
            {
                starts.push(at);
            }
            if colons {
                starts.extend(text.match_indices(':').map(|(at, _)| at + 1));
            }
            let mut pieces = Vec::new();
            let mut done = 0;
            for start in starts {
                if start < done || text.as_bytes().get(start) != Some(&b'~') {
                    continue;
                }
                let rest = &text[start + 1..];
                let end = rest
                    .find(|ch| ch == '/' || (colons && ch == ':'))
                    .map(|at| start + 1 + at);
                // The prefix must end inside this literal text, or the word must end with it.
                let end = match end {
                    Some(end) => end,
                    None if index == last => text.len(),
                    None => continue,
                };
                let home = self
                    .tilde_prefix(&text[start + 1..end])
                    .map_err(|feature| InterpError::Unsupported { feature, span })?;
                if let Some(home) = home {
                    pieces.push(Part::Text(text[done..start].to_owned()));
                    pieces.push(Part::Quoted(home));
                    done = end;
                }
            }
            if pieces.is_empty() {
                out.push(part.clone());
            } else {
                pieces.push(Part::Text(text[done..].to_owned()));
                out.extend(
                    pieces
                        .into_iter()
                        .filter(|piece| !matches!(piece, Part::Text(t) if t.is_empty())),
                );
            }
        }
        Ok(out)
    }

    /// What the tilde prefix `~prefix` expands to, or `None` to leave it as written.
    fn tilde_prefix(&self, prefix: &str) -> std::result::Result<Option<String>, Unsupported> {
        // A home directory that is not UTF-8 is refused: leaving `~name` as written would differ from bash.
        let utf8 = |path: Option<std::path::PathBuf>| {
            path.map(|path| {
                path.into_os_string()
                    .into_string()
                    .map_err(|_| Unsupported::NonUtf8Value)
            })
            .transpose()
        };
        Ok(match prefix {
            "" => match self.variable("HOME")? {
                Some(home) => Some(home),
                None => utf8(self.homes.current_home())?,
            },
            "+" => self.variable("PWD")?,
            "-" => return Err(Unsupported::DirectoryStack),
            _ if is_directory_stack(prefix) => return Err(Unsupported::DirectoryStack),
            user => utf8(self.homes.home_of(user))?,
        })
    }
}

/// `~N`, `~+N`, `~-N`: entries of the directory stack.
fn is_directory_stack(prefix: &str) -> bool {
    let digits = prefix.strip_prefix(['+', '-']).unwrap_or(prefix);
    !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit())
}

/// The expansion error for an arithmetic failure inside a word at `span`.
fn failed(failure: Failure, span: Span) -> ExpandError {
    match failure {
        Failure::Error(message) => ExpandError::Discard(message),
        Failure::Unbound(name) => ExpandError::Fatal(format!("{name}: unbound variable")),
        Failure::Unsupported(feature) => InterpError::Unsupported { feature, span }.into(),
    }
}

/// The variables an arithmetic expression inside a word reads and assigns.
struct ArithVariables<'e, 'a> {
    expander: &'e mut Expander<'a>,
}

impl arith::Variables for ArithVariables<'_, '_> {
    fn get(&mut self, name: &str) -> std::result::Result<Option<String>, Failure> {
        let value = self.expander.variable(name).map_err(Failure::Unsupported)?;
        if value.is_none() && self.expander.state.options().nounset {
            return Err(Failure::Unbound(name.to_owned()));
        }
        Ok(value)
    }

    fn set(&mut self, name: &str, value: i64) -> std::result::Result<(), Failure> {
        if is_always_unemulated(name) {
            return Err(Failure::Unsupported(Unsupported::ShellVariable));
        }
        self.expander
            .state
            .set_variable(name, OsString::from(value.to_string()));
        Ok(())
    }
}

/// Bash's word splitting of one field (`list_string`), on the unquoted characters an expansion produced that are
/// in `ifs`. A field with no such character comes back unchanged; the fields split from one are never empty unless
/// a separator other than white space delimits an empty one.
fn split(field: Field, ifs: &str) -> Vec<Field> {
    let is_separator = |c: &WordChar| c.expanded && !c.quoted && ifs.contains(c.ch);
    if !field.chars.iter().any(is_separator) {
        return vec![field];
    }
    let chars = field.chars;
    let is_blank = |ch: char| matches!(ch, ' ' | '\t' | '\n');
    let separator = |i: usize| chars.get(i).filter(|c| is_separator(c)).map(|c| c.ch);
    let skip_blanks = |mut i: usize| {
        while separator(i).is_some_and(is_blank) {
            i += 1;
        }
        i
    };
    let mut out = Vec::new();
    // Leading `IFS` white space never delimits a field.
    let mut i = skip_blanks(0);
    while i < chars.len() {
        let start = i;
        while i < chars.len() && separator(i).is_none() {
            i += 1;
        }
        let ended_by = separator(i);
        // An empty field only before a separator that is not white space (`a::b` with `IFS=:`).
        if i > start || ended_by.is_some_and(|ch| !is_blank(ch)) {
            out.push(Field {
                chars: chars[start..i].to_vec(),
                quoted: true,
            });
        }
        let Some(ch) = ended_by else {
            break;
        };
        i = skip_blanks(i + 1);
        // White space then one other separator delimit a single field.
        if is_blank(ch) && separator(i).is_some_and(|next| !is_blank(next)) {
            i = skip_blanks(i + 1);
        }
    }
    out
}

fn to_i64(len: usize) -> i64 {
    i64::try_from(len).unwrap_or(i64::MAX)
}

/// The start of a substring of a value `len` long at `offset` (from the end when negative), or `None` when it lies
/// outside the value and the result is empty.
fn clamp_start(offset: i64, len: i64) -> Option<i64> {
    let start = if offset < 0 { offset.saturating_add(len) } else { offset };
    (0..=len).contains(&start).then_some(start)
}

/// `items[start..end]`, both already within bounds.
fn slice<T>(items: &[T], start: i64, end: i64) -> &[T] {
    let start = usize::try_from(start).unwrap_or(0).min(items.len());
    let end = usize::try_from(end).unwrap_or(0).clamp(start, items.len());
    &items[start..end]
}

/// `${x#p}`, `${x##p}`, `${x%p}`, `${x%%p}`.
fn remove(text: &str, pattern: &Pattern, suffix: bool, longest: bool) -> String {
    let chars: Vec<char> = text.chars().collect();
    let n = chars.len();
    let ends: Box<dyn Iterator<Item = usize>> = match (suffix, longest) {
        // Prefixes: shortest first, or longest first.
        (false, false) | (true, true) => Box::new(0..=n),
        (false, true) | (true, false) => Box::new((0..=n).rev()),
    };
    for at in ends {
        if suffix {
            if pattern.matches(&chars[at..]) {
                return chars[..at].iter().collect();
            }
        } else if pattern.matches(&chars[..at]) {
            return chars[at..].iter().collect();
        }
    }
    text.to_owned()
}

/// `replacement` with each unquoted `&` replaced by `matched`: bash 5.2's `patsub_replacement`, on by default.
fn substitute(replacement: &[WordChar], matched: &[char], out: &mut String) {
    for c in replacement {
        if c.ch == '&' && !c.quoted {
            out.extend(matched);
        } else {
            out.push(c.ch);
        }
    }
}

/// `${x/p/r}`, `${x//p/r}`, `${x/#p/r}`, `${x/%p/r}`: the longest match at each place, as bash.
fn replace(text: &str, pattern: &Pattern, replacement: &[WordChar], mode: ReplaceMode) -> String {
    let chars: Vec<char> = text.chars().collect();
    let n = chars.len();
    let mut out = String::new();
    match mode {
        ReplaceMode::Prefix => {
            for end in (0..=n).rev() {
                if pattern.matches(&chars[..end]) {
                    substitute(replacement, &chars[..end], &mut out);
                    out.extend(&chars[end..]);
                    return out;
                }
            }
        }
        ReplaceMode::Suffix => {
            for start in 0..=n {
                if pattern.matches(&chars[start..]) {
                    out.extend(&chars[..start]);
                    substitute(replacement, &chars[start..], &mut out);
                    return out;
                }
            }
        }
        ReplaceMode::First | ReplaceMode::All => {
            // An empty pattern matches nothing here, as in bash.
            if pattern.is_empty() {
                return text.to_owned();
            }
            let mut i = 0;
            let mut replaced = false;
            while i < n {
                if replaced && mode == ReplaceMode::First {
                    out.extend(&chars[i..]);
                    return out;
                }
                if let Some(end) = ((i + 1)..=n).rev().find(|&end| pattern.matches(&chars[i..end])) {
                    substitute(replacement, &chars[i..end], &mut out);
                    i = end;
                    replaced = true;
                } else {
                    out.push(chars[i]);
                    i += 1;
                }
            }
            return out;
        }
    }
    text.to_owned()
}

/// `${x^p}`, `${x^^p}`, `${x,p}`, `${x,,p}`, `${x~p}`, `${x~~p}`: the first character (or each) that matches `pattern`
/// (any character when it is empty) changes case.
fn modify_case(text: &str, pattern: &Pattern, kind: CaseKind, all: bool) -> String {
    let mut out = String::with_capacity(text.len());
    for (i, ch) in text.chars().enumerate() {
        let applies = (all || i == 0) && (pattern.is_empty() || pattern.matches(&[ch]));
        if !applies {
            out.push(ch);
            continue;
        }
        let upper = match kind {
            CaseKind::Upper => true,
            CaseKind::Lower => false,
            CaseKind::Toggle => !ch.is_uppercase(),
        };
        if upper {
            out.extend(ch.to_uppercase());
        } else {
            out.extend(ch.to_lowercase());
        }
    }
    out
}

/// `${x@op}` for one value of parameter `target`.
fn transform(op: char, text: &str, target: &Name, exported: bool) -> String {
    match op {
        'U' => text.to_uppercase(),
        'L' => text.to_lowercase(),
        'u' => {
            let mut chars = text.chars();
            chars
                .next()
                .map(|first| first.to_uppercase().chain(chars).collect())
                .unwrap_or_default()
        }
        'E' => decode_escapes(text),
        'A' => match target {
            Name::Variable(name) if exported => format!("declare -x {name}={}", quote(text)),
            Name::Variable(name) => format!("{name}={}", quote(text)),
            Name::Positional(_) | Name::Special(_) => String::new(),
        },
        'a' => if exported { "x" } else { "" }.to_owned(),
        // `Q`, and `K` and `k`, which quote a scalar the same way.
        _ => quote(text),
    }
}

/// Bash's `sh_quote_reusable`: single quotes, or `$'…'` when the text holds a control character.
pub(crate) fn quote(text: &str) -> String {
    if text.is_empty() {
        return "''".to_owned();
    }
    if text.chars().any(|ch| ch.is_ascii_control()) {
        let mut out = String::from("$'");
        for ch in text.chars() {
            match ch {
                '\x07' => out.push_str("\\a"),
                '\x08' => out.push_str("\\b"),
                '\x1b' => out.push_str("\\E"),
                '\x0c' => out.push_str("\\f"),
                '\n' => out.push_str("\\n"),
                '\r' => out.push_str("\\r"),
                '\t' => out.push_str("\\t"),
                '\x0b' => out.push_str("\\v"),
                '\\' | '\'' => {
                    out.push('\\');
                    out.push(ch);
                }
                _ if ch.is_ascii_control() => {
                    let _ = write!(out, "\\{:03o}", u32::from(ch));
                }
                _ => out.push(ch),
            }
        }
        out.push('\'');
        return out;
    }
    format!("'{}'", text.replace('\'', "'\\''"))
}

/// The text of `$'…'` (its body `body`): the backslash escapes decoded, and cut at the first NUL character, as bash
/// keeps strings (KNSH-098).
pub(crate) fn decode_ansi_c(body: &str) -> String {
    let mut decoded = decode_escapes(body);
    if let Some(nul) = decoded.find('\0') {
        decoded.truncate(nul);
    }
    decoded
}

/// `${x@E}`: the backslash escapes `$'…'` decodes.
fn decode_escapes(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            out.push(ch);
            continue;
        }
        let Some(escape) = chars.next() else {
            out.push('\\');
            break;
        };
        let mut digits = |radix: u32, max: usize, first: Option<char>| {
            let mut value = 0_u32;
            let mut count = 0;
            if let Some(first) = first {
                value = first.to_digit(radix).unwrap_or(0);
                count = 1;
            }
            while count < max {
                match chars.peek().and_then(|c| c.to_digit(radix)) {
                    Some(digit) => {
                        value = value * radix + digit;
                        count += 1;
                        chars.next();
                    }
                    None => break,
                }
            }
            (value, count)
        };
        match escape {
            'a' => out.push('\x07'),
            'b' => out.push('\x08'),
            'e' | 'E' => out.push('\x1b'),
            'f' => out.push('\x0c'),
            'n' => out.push('\n'),
            'r' => out.push('\r'),
            't' => out.push('\t'),
            'v' => out.push('\x0b'),
            '\\' | '\'' | '"' | '?' => out.push(escape),
            '0'..='7' => {
                let (value, _) = digits(8, 3, Some(escape));
                out.push(char::from_u32(value & 0xff).unwrap_or('\u{fffd}'));
            }
            'x' | 'u' | 'U' => {
                let max = match escape {
                    'x' => 2,
                    'u' => 4,
                    _ => 8,
                };
                let (value, count) = digits(16, max, None);
                if count == 0 {
                    out.push('\\');
                    out.push(escape);
                } else {
                    out.push(char::from_u32(value).unwrap_or('\u{fffd}'));
                }
            }
            // Bash's `TOCTRL`: `\c?` is DEL, anything else its control character.
            'c' => match chars.next() {
                Some('?') => out.push('\x7f'),
                Some(control) => out.push(char::from(u8::try_from(u32::from(control) & 0x1f).unwrap_or(0))),
                None => out.push_str("\\c"),
            },
            other => {
                out.push('\\');
                out.push(other);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests;
