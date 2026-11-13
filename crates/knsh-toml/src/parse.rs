//! The parser: reads the supported TOML subset into a [`Table`] and rejects everything else.
//!
//! Policy and configuration files can be written by anyone who can write the user's configuration folder, and
//! profiles can arrive from the authority, so the input is untrusted (NFR-SUP-06):
//!
//! - The size limit is checked before anything else, and the whole input is validated as UTF-8 up front, so no
//!   later step can see an invalid sequence.
//! - Recursion goes one level per array or inline table and stops at [`MAX_DEPTH`]; table depth reached through
//!   headers and dotted keys is held to the same limit, so the stack and the tree are bounded whatever the input.
//! - The first problem ends the parse: there is no recovery and no partial result.
//! - No indexing that can panic: the cursor reads with `get` and only ever stops on character boundaries.
//!
//! Table definition follows TOML 1.0 ("Table", "Inline Table", "Array of Tables"): a table is defined once, by a
//! header, by dotted keys or inline, and the rules for adding to it afterwards depend on which ([`TableKind`]).

use std::collections::btree_map::Entry;

use crate::error::{Construct, Position, Reason, TomlError};
use crate::value::{Array, Item, Table, TableKind, Value};

/// Largest input [`parse`] reads, in bytes. Policy and configuration files are a few kilobytes; anything near this
/// size is not a hand-written file and is refused before parsing.
pub const MAX_INPUT_LEN: usize = 1024 * 1024;

/// Deepest nesting of tables and arrays the parser accepts. The root table has depth 0; each table or array below
/// it adds one, and an element of an array of tables is two below the table holding the array. Scalars do not
/// count, so `a.b = 1` has depth 1 (the table `a`).
pub const MAX_DEPTH: usize = 32;

/// Parses a document in the supported TOML subset (crate header) into its root table.
///
/// # Errors
///
/// [`TomlError::InputTooLarge`] above [`MAX_INPUT_LEN`]; otherwise [`TomlError::Parse`] with the line and column
/// of the first problem and its [`Reason`] — including [`Reason::OutsideSubset`] for valid TOML that the subset
/// does not read.
///
/// # Example
///
/// ```
/// let root = knsh_toml::parse(b"[[hooks]]\nevent = \"command.proposed\"\ntimeout_ms = 2000\n")?;
/// let hooks = root.get("hooks").and_then(|item| item.value().as_array()).map(knsh_toml::Array::len);
/// assert_eq!(hooks, Some(1));
///
/// let error = knsh_toml::parse(b"when = 1979-05-27\n").unwrap_err();
/// assert_eq!(error.position(), Some(knsh_toml::Position { line: 1, column: 8 }));
/// # Ok::<(), knsh_toml::TomlError>(())
/// ```
pub fn parse(input: &[u8]) -> Result<Table, TomlError> {
    if input.len() > MAX_INPUT_LEN {
        return Err(TomlError::InputTooLarge {
            len: input.len(),
            limit: MAX_INPUT_LEN,
        });
    }
    let text = match std::str::from_utf8(input) {
        Ok(text) => text,
        Err(error) => {
            // Report where the invalid sequence starts, counted over the valid prefix like every other position.
            let valid = input
                .get(..error.valid_up_to())
                .and_then(|prefix| std::str::from_utf8(prefix).ok());
            return Err(TomlError::Parse {
                position: end_position(valid.unwrap_or("")),
                reason: Reason::InvalidUtf8,
            });
        }
    };
    let mut root = Table::new(TableKind::Header);
    Parser::new(text).document(&mut root)?;
    Ok(root)
}

/// The position just after `text`.
fn end_position(text: &str) -> Position {
    let line = 1 + text.matches('\n').count();
    let last_line = text.rsplit('\n').next().unwrap_or("");
    Position {
        line,
        column: 1 + last_line.chars().count(),
    }
}

/// One part of a dotted key, with where it was written (for errors and implicitly created tables).
struct Segment {
    name: String,
    position: Position,
}

type Result<T, E = TomlError> = std::result::Result<T, E>;

/// Cursor over input already known to be valid UTF-8. `pos` is a byte offset that only ever moves by whole
/// characters, so it always lies on a character boundary; `line` and `column` track it for error reporting.
struct Parser<'a> {
    text: &'a str,
    pos: usize,
    line: usize,
    column: usize,
}

impl<'a> Parser<'a> {
    const fn new(text: &'a str) -> Self {
        Self {
            text,
            pos: 0,
            line: 1,
            column: 1,
        }
    }

    // ---- Cursor ----

    fn rest(&self) -> &'a str {
        self.text.get(self.pos..).unwrap_or("")
    }

    fn peek(&self) -> Option<char> {
        self.rest().chars().next()
    }

    const fn position(&self) -> Position {
        Position {
            line: self.line,
            column: self.column,
        }
    }

    /// Consumes one character and returns it.
    fn bump(&mut self) -> Option<char> {
        let c = self.peek()?;
        self.pos += c.len_utf8();
        if c == '\n' {
            self.line += 1;
            self.column = 1;
        } else {
            self.column += 1;
        }
        Some(c)
    }

    /// Consumes `expected` if it is next.
    fn eat(&mut self, expected: char) -> bool {
        let found = self.peek() == Some(expected);
        if found {
            self.bump();
        }
        found
    }

    const fn error_at(position: Position, reason: Reason) -> TomlError {
        TomlError::Parse { position, reason }
    }

    const fn error(&self, reason: Reason) -> TomlError {
        Self::error_at(self.position(), reason)
    }

    /// The error for a character that does not fit here: running out of input is reported as such.
    fn unexpected(&self) -> TomlError {
        self.error(if self.peek().is_none() {
            Reason::UnexpectedEnd
        } else {
            Reason::UnexpectedCharacter
        })
    }

    /// Fails with `reason` when a container at `depth` would exceed [`MAX_DEPTH`].
    const fn check_depth(depth: usize, position: Position) -> Result<()> {
        if depth > MAX_DEPTH {
            Err(Self::error_at(position, Reason::TooDeep))
        } else {
            Ok(())
        }
    }

    // ---- Whitespace, comments, line ends ----

    /// Skips spaces and tabs (TOML whitespace); never a line break.
    fn skip_whitespace(&mut self) {
        while matches!(self.peek(), Some(' ' | '\t')) {
            self.bump();
        }
    }

    /// Consumes a line break: `\n` or `\r\n`. A lone `\r` is a control character.
    fn newline(&mut self) -> Result<()> {
        if self.eat('\n') {
            return Ok(());
        }
        let position = self.position();
        if self.eat('\r') && self.eat('\n') {
            return Ok(());
        }
        Err(Self::error_at(position, Reason::ControlCharacter))
    }

    /// Consumes a `#` comment up to, not including, the line break. TOML forbids control characters other than tab
    /// in comments.
    fn comment(&mut self) -> Result<()> {
        self.bump();
        loop {
            match self.peek() {
                None | Some('\n') => return Ok(()),
                Some('\r') if self.rest().starts_with("\r\n") => return Ok(()),
                Some(c) if is_control(c) => return Err(self.error(Reason::ControlCharacter)),
                Some(_) => {
                    self.bump();
                }
            }
        }
    }

    /// After a key/value pair or a header: optional whitespace and comment, then a line break or the end.
    fn end_of_line(&mut self) -> Result<()> {
        self.skip_whitespace();
        if self.peek() == Some('#') {
            self.comment()?;
        }
        match self.peek() {
            None => Ok(()),
            Some('\n' | '\r') => self.newline(),
            Some(_) => Err(self.error(Reason::ExpectedEndOfLine)),
        }
    }

    // ---- Document structure ----

    /// The whole document: blank lines, comments, key/value pairs and headers. Key/value pairs go into the table
    /// opened by the latest header (the root before any header).
    fn document(&mut self, root: &mut Table) -> Result<()> {
        let mut current: &mut Table = root;
        let mut depth = 0;
        loop {
            self.skip_whitespace();
            match self.peek() {
                None => return Ok(()),
                Some('#') => self.end_of_line()?,
                Some('\n' | '\r') => self.newline()?,
                Some('[') => {
                    let (table, table_depth) = self.header(root)?;
                    current = table;
                    depth = table_depth;
                    self.end_of_line()?;
                }
                Some(_) => {
                    self.key_value(current, depth)?;
                    self.end_of_line()?;
                }
            }
        }
    }

    /// A `[table]` or `[[array-of-tables]]` header. Returns the table that following key/value pairs go into, and
    /// its depth.
    fn header<'t>(&mut self, root: &'t mut Table) -> Result<(&'t mut Table, usize)> {
        let position = self.position();
        self.bump();
        // `[[` must be adjacent: `[ [a]]` is not an array-of-tables header, and is rejected by `key` below.
        let array = self.eat('[');
        self.skip_whitespace();
        let key = self.key()?;
        if !self.eat(']') || (array && !self.eat(']')) {
            return Err(self.unexpected());
        }
        define_table(root, &key, position, array)
    }

    /// `key = value`, added to `table` (at `depth`). Dotted keys create tables below `table`.
    fn key_value(&mut self, table: &mut Table, depth: usize) -> Result<()> {
        let key = self.key()?;
        if !self.eat('=') {
            return Err(self.error(Reason::ExpectedEquals));
        }
        self.skip_whitespace();
        // The value sits one level below each key segment; only a container value counts towards the depth.
        let item = self.value(depth + key.len())?;
        insert_value(table, &key, item, depth)
    }

    /// A key: one or more bare or quoted segments separated by `.`, with optional whitespace around the dots.
    /// Consumes trailing whitespace. Stops early on absurdly long paths, which could never pass the depth limit.
    fn key(&mut self) -> Result<Vec<Segment>> {
        let mut segments = Vec::new();
        loop {
            let position = self.position();
            if segments.len() > MAX_DEPTH {
                return Err(Self::error_at(position, Reason::TooDeep));
            }
            let name = match self.peek() {
                Some('"') => self.basic_string()?,
                Some('\'') => self.literal_string()?,
                Some(c) if is_bare_key_char(c) => self.bare_key(),
                _ => return Err(self.unexpected()),
            };
            segments.push(Segment { name, position });
            self.skip_whitespace();
            if !self.eat('.') {
                return Ok(segments);
            }
            self.skip_whitespace();
        }
    }

    fn bare_key(&mut self) -> String {
        let start = self.pos;
        while self.peek().is_some_and(is_bare_key_char) {
            self.bump();
        }
        self.text.get(start..self.pos).unwrap_or("").to_owned()
    }

    // ---- Values ----

    /// A value whose container, if it is one, sits at `depth`.
    fn value(&mut self, depth: usize) -> Result<Item> {
        let position = self.position();
        let value = match self.peek() {
            None | Some('\n' | '\r' | '#') => return Err(self.error(Reason::MissingValue)),
            Some('"') => Value::String(self.basic_string()?),
            Some('\'') => Value::String(self.literal_string()?),
            Some('[') => Value::Array(self.array(depth)?),
            Some('{') => Value::Table(self.inline_table(depth)?),
            Some(c) if c.is_ascii_alphanumeric() || c == '+' || c == '-' => self.word()?,
            Some(_) => return Err(self.error(Reason::UnexpectedCharacter)),
        };
        Ok(Item { value, position })
    }

    /// A boolean or a decimal integer. Reads the whole token first, so that dates, floats and non-decimal integers
    /// are recognised and named as outside the subset instead of failing on their second character.
    fn word(&mut self) -> Result<Value> {
        let position = self.position();
        let start = self.pos;
        while self
            .peek()
            .is_some_and(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '+' | '-' | '.' | ':'))
        {
            self.bump();
        }
        let token = self.text.get(start..self.pos).unwrap_or("");
        match token {
            "true" => return Ok(Value::Boolean(true)),
            "false" => return Ok(Value::Boolean(false)),
            _ => {}
        }
        if let Some(construct) = outside_subset(token) {
            return Err(Self::error_at(position, Reason::OutsideSubset(construct)));
        }
        decimal_integer(token)
            .map(Value::Integer)
            .map_err(|reason| Self::error_at(position, reason))
    }

    /// A static array at `depth`: may span lines and hold comments, and may end with a comma (TOML 1.0).
    fn array(&mut self, depth: usize) -> Result<Array> {
        Self::check_depth(depth, self.position())?;
        self.bump();
        let mut items = Vec::new();
        loop {
            self.skip_array_space()?;
            if self.eat(']') {
                break;
            }
            if self.peek().is_none() {
                return Err(self.error(Reason::UnexpectedEnd));
            }
            items.push(self.value(depth + 1)?);
            self.skip_array_space()?;
            match self.peek() {
                Some(',') => {
                    self.bump();
                }
                Some(']') => {
                    self.bump();
                    break;
                }
                _ => return Err(self.unexpected()),
            }
        }
        Ok(Array {
            items,
            of_tables: false,
        })
    }

    /// Whitespace, line breaks and comments between array elements.
    fn skip_array_space(&mut self) -> Result<()> {
        loop {
            match self.peek() {
                Some(' ' | '\t') => {
                    self.bump();
                }
                Some('\n' | '\r') => self.newline()?,
                Some('#') => self.comment()?,
                _ => return Ok(()),
            }
        }
    }

    /// An inline table at `depth`: one line, no trailing comma (TOML 1.0). Dotted keys inside it create
    /// sub-tables; once the closing brace is read the table is sealed ([`TableKind::Inline`]).
    fn inline_table(&mut self, depth: usize) -> Result<Table> {
        Self::check_depth(depth, self.position())?;
        self.bump();
        // `Dotted` while open, so that `{ a.b = 1, a.c = 2 }` can add to `a`; nothing outside can reach it yet.
        let mut table = Table::new(TableKind::Dotted);
        self.skip_inline_space()?;
        if !self.eat('}') {
            loop {
                self.key_value(&mut table, depth)?;
                self.skip_inline_space()?;
                match self.peek() {
                    Some(',') => {
                        self.bump();
                        self.skip_inline_space()?;
                        if self.peek() == Some('}') {
                            return Err(self.error(Reason::TrailingComma));
                        }
                    }
                    Some('}') => {
                        self.bump();
                        break;
                    }
                    _ => return Err(self.unexpected()),
                }
            }
        }
        table.kind = TableKind::Inline;
        Ok(table)
    }

    /// Spaces and tabs inside an inline table; a line break there is an error of its own.
    fn skip_inline_space(&mut self) -> Result<()> {
        self.skip_whitespace();
        if matches!(self.peek(), Some('\n' | '\r')) {
            return Err(self.error(Reason::NewlineInInlineTable));
        }
        Ok(())
    }

    // ---- Strings ----

    /// A single-line basic string, `"…"`, with escapes resolved.
    fn basic_string(&mut self) -> Result<String> {
        let start = self.position();
        self.bump();
        if self.rest().starts_with("\"\"") {
            return Err(Self::error_at(start, Reason::OutsideSubset(Construct::MultiLineString)));
        }
        let mut text = String::new();
        loop {
            let position = self.position();
            match self.bump() {
                None | Some('\n') => return Err(Self::error_at(start, Reason::UnterminatedString)),
                Some('"') => return Ok(text),
                Some('\\') => text.push(self.escape(position)?),
                Some(c) if is_control(c) => return Err(Self::error_at(position, Reason::ControlCharacter)),
                Some(c) => text.push(c),
            }
        }
    }

    /// The character an escape stands for; the backslash (at `position`) is already consumed.
    fn escape(&mut self, position: Position) -> Result<char> {
        let digits = match self.bump() {
            Some('b') => return Ok('\u{8}'),
            Some('t') => return Ok('\t'),
            Some('n') => return Ok('\n'),
            Some('f') => return Ok('\u{c}'),
            Some('r') => return Ok('\r'),
            Some('"') => return Ok('"'),
            Some('\\') => return Ok('\\'),
            Some('u') => 4,
            Some('U') => 8,
            _ => return Err(Self::error_at(position, Reason::InvalidEscape)),
        };
        let mut code: u32 = 0;
        for _ in 0..digits {
            let Some(digit) = self.peek().and_then(|c| c.to_digit(16)) else {
                return Err(Self::error_at(position, Reason::InvalidEscape));
            };
            self.bump();
            code = code << 4 | digit;
        }
        // Surrogates and values above U+10FFFF are not Unicode scalar values, which TOML requires.
        char::from_u32(code).ok_or_else(|| Self::error_at(position, Reason::InvalidEscape))
    }

    /// A single-line literal string, `'…'`, taken verbatim.
    fn literal_string(&mut self) -> Result<String> {
        let start = self.position();
        self.bump();
        if self.rest().starts_with("''") {
            return Err(Self::error_at(start, Reason::OutsideSubset(Construct::MultiLineString)));
        }
        let mut text = String::new();
        loop {
            let position = self.position();
            match self.bump() {
                None | Some('\n') => return Err(Self::error_at(start, Reason::UnterminatedString)),
                Some('\'') => return Ok(text),
                Some(c) if is_control(c) => return Err(Self::error_at(position, Reason::ControlCharacter)),
                Some(c) => text.push(c),
            }
        }
    }
}

// ---- Table definition rules ----

/// Resolves a `[key]` or `[[key]]` header (at `header`) against the tree: walks the key path from the root,
/// creating implicit tables as needed, then defines the last table or appends a new element to the array of
/// tables. Returns the table that following key/value pairs go into, and its depth.
fn define_table<'t>(
    root: &'t mut Table,
    key: &[Segment],
    header: Position,
    array: bool,
) -> Result<(&'t mut Table, usize)> {
    let Some((last, parents)) = key.split_last() else {
        return Err(Parser::error_at(header, Reason::UnexpectedCharacter));
    };
    let mut table = root;
    let mut depth = 0;
    for segment in parents {
        depth += 1;
        Parser::check_depth(depth, segment.position)?;
        let item = table.entries.entry(segment.name.clone()).or_insert_with(|| Item {
            value: Value::Table(Table::new(TableKind::Implicit)),
            position: segment.position,
        });
        table = match &mut item.value {
            // A header may define sub-tables in any open table, including ones created by dotted keys.
            Value::Table(next) if next.kind != TableKind::Inline => next,
            // Through an array of tables, a header path continues in its latest element.
            Value::Array(Array { items, of_tables: true }) => {
                depth += 1;
                Parser::check_depth(depth, segment.position)?;
                latest_element(items).ok_or_else(|| Parser::error_at(segment.position, Reason::NotATable))?
            }
            Value::Table(_) | Value::Array(_) | Value::String(_) | Value::Integer(_) | Value::Boolean(_) => {
                return Err(Parser::error_at(segment.position, Reason::NotATable));
            }
        };
    }

    depth += if array { 2 } else { 1 };
    Parser::check_depth(depth, last.position)?;
    let element = || Item {
        value: Value::Table(Table::new(TableKind::Header)),
        position: header,
    };
    let item = match table.entries.entry(last.name.clone()) {
        Entry::Vacant(vacant) if array => vacant.insert(Item {
            value: Value::Array(Array {
                items: vec![element()],
                of_tables: true,
            }),
            position: header,
        }),
        Entry::Vacant(vacant) => vacant.insert(element()),
        Entry::Occupied(occupied) => {
            let item = occupied.into_mut();
            match (&mut item.value, array) {
                // `[a]` after `[a.b]`: the implicit table is now defined, once.
                (Value::Table(existing), false) if existing.kind == TableKind::Implicit => {
                    existing.kind = TableKind::Header;
                    item.position = header;
                }
                (Value::Array(existing), true) if existing.of_tables => existing.items.push(element()),
                // Any other table or array of tables is already defined.
                (Value::Table(_) | Value::Array(Array { of_tables: true, .. }), _) => {
                    return Err(Parser::error_at(last.position, Reason::TableRedefined));
                }
                (Value::Array(_) | Value::String(_) | Value::Integer(_) | Value::Boolean(_), _) => {
                    return Err(Parser::error_at(last.position, Reason::DuplicateKey));
                }
            }
            item
        }
    };
    let target = match &mut item.value {
        Value::Table(table) => Some(table),
        Value::Array(Array { items, .. }) => latest_element(items),
        Value::String(_) | Value::Integer(_) | Value::Boolean(_) => None,
    };
    // `None` is unreachable by construction (the match above only lets tables and arrays of tables through); refuse
    // rather than panic.
    target
        .map(|table| (table, depth))
        .ok_or_else(|| Parser::error_at(header, Reason::NotATable))
}

/// The element a header path continues in: the table most recently appended to an array of tables.
fn latest_element(items: &mut [Item]) -> Option<&mut Table> {
    match items.last_mut().map(|element| &mut element.value) {
        Some(Value::Table(table)) => Some(table),
        Some(Value::String(_) | Value::Integer(_) | Value::Boolean(_) | Value::Array(_)) | None => None,
    }
}

/// Adds `item` under the dotted `key` to `table` (at `depth`), creating tables for all but the last segment.
fn insert_value(mut table: &mut Table, key: &[Segment], item: Item, mut depth: usize) -> Result<()> {
    let Some((last, parents)) = key.split_last() else {
        return Err(Parser::error_at(item.position, Reason::UnexpectedCharacter));
    };
    for segment in parents {
        depth += 1;
        Parser::check_depth(depth, segment.position)?;
        let entry = table.entries.entry(segment.name.clone()).or_insert_with(|| Item {
            value: Value::Table(Table::new(TableKind::Dotted)),
            position: segment.position,
        });
        table = match &mut entry.value {
            Value::Table(next) => match next.kind {
                TableKind::Dotted => next,
                // TOML 1.0: dotted keys may not add to a table defined by a header, or created by one.
                TableKind::Header | TableKind::Implicit => {
                    return Err(Parser::error_at(segment.position, Reason::TableRedefined));
                }
                TableKind::Inline => return Err(Parser::error_at(segment.position, Reason::NotATable)),
            },
            Value::Array(_) | Value::String(_) | Value::Integer(_) | Value::Boolean(_) => {
                return Err(Parser::error_at(segment.position, Reason::NotATable));
            }
        };
    }
    match table.entries.entry(last.name.clone()) {
        Entry::Vacant(vacant) => {
            vacant.insert(item);
            Ok(())
        }
        Entry::Occupied(_) => Err(Parser::error_at(last.position, Reason::DuplicateKey)),
    }
}

// ---- Character classes and number tokens ----

/// Control characters TOML forbids in strings and comments: U+0000 to U+001F except tab, and U+007F.
const fn is_control(c: char) -> bool {
    (c < ' ' && c != '\t') || c == '\u{7f}'
}

const fn is_bare_key_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_' || c == '-'
}

/// Recognises a number-like token that is valid TOML but outside the subset.
fn outside_subset(token: &str) -> Option<Construct> {
    let unsigned = token.strip_prefix(['+', '-']).unwrap_or(token);
    let bytes = unsigned.as_bytes();
    // Times contain `:`; dates start with four digits and a dash (`1979-05-27`).
    let date = bytes.len() > 4 && bytes.iter().take(4).all(u8::is_ascii_digit) && bytes.get(4) == Some(&b'-');
    if token.contains(':') || date {
        return Some(Construct::DateTime);
    }
    if ["0x", "0o", "0b"].iter().any(|prefix| unsigned.starts_with(prefix)) {
        return Some(Construct::NonDecimalInteger);
    }
    // Only a token that starts like a number can be a float: `True` contains an `e` but is a misspelt boolean.
    let numeric = bytes.first().is_some_and(u8::is_ascii_digit);
    if unsigned == "inf" || unsigned == "nan" || (numeric && unsigned.contains(['.', 'e', 'E'])) {
        return Some(Construct::Float);
    }
    None
}

/// A TOML decimal integer: optional sign, digits with single underscores between them, no leading zero.
fn decimal_integer(token: &str) -> Result<i64, Reason> {
    let (negative, digits) = match token.as_bytes().first() {
        Some(b'-') => (true, token.get(1..).unwrap_or("")),
        Some(b'+') => (false, token.get(1..).unwrap_or("")),
        _ => (false, token),
    };
    let bytes = digits.as_bytes();
    let well_formed = bytes.first().is_some_and(u8::is_ascii_digit)
        && bytes.last().is_some_and(u8::is_ascii_digit)
        && bytes.iter().all(|b| b.is_ascii_digit() || *b == b'_')
        && !digits.contains("__")
        && !(bytes.len() > 1 && bytes.first() == Some(&b'0'));
    if !well_formed {
        return Err(Reason::InvalidInteger);
    }
    // Accumulate the magnitude in i128 so that i64::MIN (whose magnitude does not fit i64) is accepted; stop as
    // soon as the magnitude passes 2^63, so arbitrarily long digit strings cannot overflow.
    let mut magnitude: i128 = 0;
    for digit in bytes.iter().filter(|b| b.is_ascii_digit()) {
        magnitude = magnitude * 10 + i128::from(digit - b'0');
        if magnitude > 1 << 63 {
            return Err(Reason::IntegerOutOfRange);
        }
    }
    let value = if negative { -magnitude } else { magnitude };
    i64::try_from(value).map_err(|_| Reason::IntegerOutOfRange)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The first fenced `toml` block of a spec page, so the tests follow the spec rather than a copy of it.
    fn spec_example(page: &str) -> &str {
        let start = page.find("```toml\n").unwrap() + "```toml\n".len();
        let len = page[start..].find("```").unwrap();
        &page[start..start + len]
    }

    const POLICY_PROFILE: &str = include_str!("../../../specs/05-models/policy-profile.md");
    const HOOK: &str = include_str!("../../../specs/05-models/hook.md");

    fn parse_str(text: &str) -> Result<Table> {
        parse(text.as_bytes())
    }

    fn reason(text: &str) -> Reason {
        match parse_str(text) {
            Err(TomlError::Parse { reason, .. }) => reason,
            other => panic!("expected a parse error for {text:?}, got {other:?}"),
        }
    }

    fn error_at(text: &str) -> (Reason, usize, usize) {
        match parse_str(text) {
            Err(TomlError::Parse { reason, position }) => (reason, position.line, position.column),
            other => panic!("expected a parse error for {text:?}, got {other:?}"),
        }
    }

    fn get<'t>(table: &'t Table, path: &str) -> &'t Item {
        let mut parts = path.split('.');
        let mut item = table.get(parts.next().unwrap()).unwrap();
        for part in parts {
            item = item.value().as_table().unwrap().get(part).unwrap();
        }
        item
    }

    fn strings(item: &Item) -> Vec<&str> {
        item.value()
            .as_array()
            .unwrap()
            .iter()
            .map(|item| item.value().as_str().unwrap())
            .collect()
    }

    fn pos(line: usize, column: usize) -> Position {
        Position { line, column }
    }

    #[test]
    fn parses_policy_profile_example() {
        // KNSH-006: the full example from specs/05-models/policy-profile.md, with positions.
        let root = parse_str(spec_example(POLICY_PROFILE)).unwrap();
        assert_eq!(get(&root, "name").value().as_str(), Some("web-app"));
        assert_eq!(get(&root, "name").position(), pos(1, 8));
        assert_eq!(get(&root, "preset").value().as_str(), Some("claude-code"));
        assert_eq!(get(&root, "fs.read").value().as_str(), Some("all"));
        assert_eq!(strings(get(&root, "fs.write")), ["${PROJECT}", "${TMPDIR}"]);
        assert_eq!(strings(get(&root, "fs.deny")).len(), 6);
        assert_eq!(get(&root, "fs").position(), pos(5, 1));
        assert_eq!(strings(get(&root, "exec.allow"))[1], "npm");
        assert_eq!(
            get(&root, "exec.allow")
                .value()
                .as_array()
                .unwrap()
                .get(1)
                .unwrap()
                .position(),
            pos(11, 19)
        );
        assert_eq!(strings(get(&root, "exec.ask")), ["git push", "rm -rf *", "brew *"]);
        assert_eq!(get(&root, "exec.default").value().as_str(), Some("ask"));
        let loopback: Vec<i64> = get(&root, "network.loopback")
            .value()
            .as_array()
            .unwrap()
            .iter()
            .map(|item| item.value().as_integer().unwrap())
            .collect();
        assert_eq!(loopback, [3000, 5432]);
        assert_eq!(get(&root, "checkpoints.required").value().as_bool(), Some(true));
        assert_eq!(get(&root, "recording.output").value().as_bool(), Some(false));
        assert_eq!(get(&root, "recording.retention_days").value().as_integer(), Some(30));
        let token = get(&root, "secrets.env.NPM_TOKEN");
        assert!(token.value().as_table().unwrap().is_inline());
        assert_eq!(
            get(&root, "secrets.env.NPM_TOKEN.secret").value().as_str(),
            Some("npm-token")
        );
        assert_eq!(strings(get(&root, "secrets.env.NPM_TOKEN.inject_for")), ["npm publish"]);
        assert_eq!(
            strings(get(&root, "secrets.env.NPM_TOKEN.hosts")),
            ["registry.npmjs.org"]
        );
        let top: Vec<&str> = root.iter().map(|(key, _)| key).collect();
        assert_eq!(
            top,
            [
                "approvals",
                "checkpoints",
                "exec",
                "extends",
                "fs",
                "name",
                "network",
                "preset",
                "recording",
                "secrets"
            ]
        );
    }

    #[test]
    fn parses_hooks_array_of_tables() {
        // KNSH-006: the hook example from specs/05-models/hook.md, plus a second [[hooks]] element.
        let text = format!(
            "{}\n[[hooks]]\nevent = \"command.proposed\"\nrun = \"b\"\n",
            spec_example(HOOK)
        );
        let root = parse_str(&text).unwrap();
        let hooks = root.get("hooks").unwrap().value().as_array().unwrap();
        assert!(hooks.is_array_of_tables());
        assert_eq!(hooks.len(), 2);
        let first = hooks.get(0).unwrap();
        assert_eq!(first.position(), pos(1, 1));
        let first = first.value().as_table().unwrap();
        assert_eq!(first.get("event").unwrap().value().as_str(), Some("command.proposed"));
        let matcher = first.get("match").unwrap();
        assert!(matcher.value().as_table().unwrap().is_inline());
        assert_eq!(matcher.position(), pos(3, 9));
        assert_eq!(
            strings(matcher.value().as_table().unwrap().get("binary").unwrap()),
            ["rm", "git"]
        );
        assert_eq!(first.get("timeout_ms").unwrap().value().as_integer(), Some(2000));
        let second = hooks.get(1).unwrap();
        assert_eq!(second.position(), pos(7, 1));
        assert!(second.value().as_table().unwrap().get("match").is_none());
    }

    #[test]
    fn rejects_duplicate_key() {
        // KNSH-006: duplicate keys are rejected, as TOML requires, at the second definition.
        assert_eq!(error_at("a = 1\na = 2\n"), (Reason::DuplicateKey, 2, 1));
        assert_eq!(reason("a = 1\n\"a\" = 2\n"), Reason::DuplicateKey);
        assert_eq!(reason("'a' = 1\na = 2\n"), Reason::DuplicateKey);
        assert_eq!(reason("t = { x = 1, x = 2 }\n"), Reason::DuplicateKey);
        assert_eq!(reason("a.b = 1\na.b = 2\n"), Reason::DuplicateKey);
        assert_eq!(reason("[t]\nx = 1\nx = 2\n"), Reason::DuplicateKey);
        assert_eq!(reason("a = 1\n[a]\n"), Reason::DuplicateKey);
        assert_eq!(reason("a = [1]\n[[a]]\n"), Reason::DuplicateKey);
    }

    #[test]
    fn rejects_table_redefinition() {
        // KNSH-006: a table is defined once, by a header, by dotted keys or inline (TOML 1.0 "Table").
        assert_eq!(error_at("[a]\nx = 1\n[a]\n"), (Reason::TableRedefined, 3, 2));
        assert_eq!(reason("[a.b]\n[a]\n[a]\n"), Reason::TableRedefined);
        assert_eq!(reason("[a]\nb.c = 1\n[a.b]\n"), Reason::TableRedefined);
        assert_eq!(reason("a.b = 1\n[a]\n"), Reason::TableRedefined);
        assert_eq!(reason("[a.b]\nc = 1\n[a]\nb.d = 1\n"), Reason::TableRedefined);
        assert_eq!(reason("a = {}\n[a]\n"), Reason::TableRedefined);
        assert_eq!(reason("[[a]]\n[a]\n"), Reason::TableRedefined);
        assert_eq!(reason("[a]\n[[a]]\n"), Reason::TableRedefined);
        assert_eq!(reason("a = { b = 1 }\n[a.c]\n"), Reason::NotATable);
        assert_eq!(reason("a = { b = 1 }\na.c = 2\n"), Reason::NotATable);
        assert_eq!(reason("a = 1\na.b = 2\n"), Reason::NotATable);
        assert_eq!(reason("[[a]]\n[x]\na.b = 1\n[a]\n"), Reason::TableRedefined);
        assert_eq!(reason("a = [ { b = 1 } ]\n[a.c]\n"), Reason::NotATable);
    }

    #[test]
    fn accepts_valid_table_definitions() {
        // The legal ways to add to a table, which the strictness above must not break.
        let root = parse_str("[a.b]\nx = 1\n[a]\ny = 2\n").unwrap();
        assert_eq!(get(&root, "a.b.x").value().as_integer(), Some(1));
        assert_eq!(get(&root, "a.y").value().as_integer(), Some(2));
        assert_eq!(get(&root, "a").position(), pos(3, 1));
        let root = parse_str("[a]\nb.c = 1\nb.d = 2\n[a.b.e]\nf = 3\n").unwrap();
        assert_eq!(get(&root, "a.b.e.f").value().as_integer(), Some(3));
        let root = parse_str("[[a]]\nx = 1\n[a.b]\ny = 2\n[[a]]\nx = 3\n").unwrap();
        let a = root.get("a").unwrap().value().as_array().unwrap();
        assert_eq!(a.len(), 2);
        assert!(a.get(0).unwrap().value().as_table().unwrap().contains_key("b"));
        let root = parse_str("t = { a.b = 1, a.c = 2 }\n").unwrap();
        assert_eq!(get(&root, "t.a.c").value().as_integer(), Some(2));
        // A header path through an array of tables continues in its latest element.
        let root = parse_str("[[a]]\n[[a]]\n[a.b]\nx = 1\n").unwrap();
        let a = root.get("a").unwrap().value().as_array().unwrap();
        assert!(!a.get(0).unwrap().value().as_table().unwrap().contains_key("b"));
        assert!(a.get(1).unwrap().value().as_table().unwrap().contains_key("b"));
        let root = parse_str("[[a.b]]\n[[a.b]]\n[a.c]\n").unwrap();
        assert_eq!(get(&root, "a.b").value().as_array().unwrap().len(), 2);
    }

    #[test]
    fn rejects_datetime_outside_subset_with_position() {
        // KNSH-006: valid TOML outside the subset is named and located, never guessed.
        let dt = Reason::OutsideSubset(Construct::DateTime);
        assert_eq!(error_at("name = \"x\"\nwhen = 1979-05-27T07:32:00Z\n"), (dt, 2, 8));
        assert_eq!(error_at("when = 1979-05-27\n"), (dt, 1, 8));
        assert_eq!(error_at("when = 1979-05-27 07:32:00\n"), (dt, 1, 8));
        assert_eq!(error_at("when = 07:32:00\n"), (dt, 1, 8));
        assert_eq!(error_at("a = [1,\n  2023-01-01]\n"), (dt, 2, 3));
        let err = parse_str("when = 1979-05-27\n").unwrap_err();
        assert_eq!(
            err.to_string(),
            "date-time is outside the supported TOML subset at line 1, column 8"
        );
    }

    #[test]
    fn rejects_other_constructs_outside_subset() {
        let float = Reason::OutsideSubset(Construct::Float);
        for text in [
            "x = 3.14",
            "x = 1e6",
            "x = -1E2",
            "x = inf",
            "x = +nan",
            "x = -inf",
            "x = 6.626e-34",
        ] {
            assert_eq!(reason(text), float, "{text}");
        }
        for text in ["x = 0xff", "x = 0o755", "x = 0b1010"] {
            assert_eq!(
                reason(text),
                Reason::OutsideSubset(Construct::NonDecimalInteger),
                "{text}"
            );
        }
        let multi = Reason::OutsideSubset(Construct::MultiLineString);
        assert_eq!(error_at("x = \"\"\"a\"\"\""), (multi, 1, 5));
        assert_eq!(reason("x = '''a'''"), multi);
    }

    #[test]
    fn rejects_excessive_nesting() {
        // KNSH-006: depth is bounded for arrays, inline tables, headers and dotted keys, so input cannot exhaust
        // the stack or build an unbounded tree.
        let ok = format!("x = {}{}", "[".repeat(MAX_DEPTH), "]".repeat(MAX_DEPTH));
        assert!(parse_str(&ok).is_ok());
        let deep = format!("x = {}{}", "[".repeat(MAX_DEPTH + 1), "]".repeat(MAX_DEPTH + 1));
        assert_eq!(error_at(&deep), (Reason::TooDeep, 1, 5 + MAX_DEPTH));
        let deep = format!("x = {}{}", "{a = ".repeat(MAX_DEPTH + 1), "}".repeat(MAX_DEPTH + 1));
        assert_eq!(reason(&deep), Reason::TooDeep);
        let deep = format!("x = {}", "[".repeat(100_000));
        assert_eq!(reason(&deep), Reason::TooDeep);
        let ok = format!("{} = 1", vec!["k"; MAX_DEPTH + 1].join("."));
        assert!(parse_str(&ok).is_ok());
        let deep = format!("{} = 1", vec!["k"; MAX_DEPTH + 2].join("."));
        assert_eq!(reason(&deep), Reason::TooDeep);
        let deep = format!("[{}]", vec!["k"; MAX_DEPTH + 1].join("."));
        assert_eq!(reason(&deep), Reason::TooDeep);
        // Every element of an array of tables is two levels down: the array, then the element table.
        let ok = format!("[[{}]]", vec!["k"; MAX_DEPTH - 1].join("."));
        assert!(parse_str(&ok).is_ok());
        let deep = format!("[[{}]]", vec!["k"; MAX_DEPTH].join("."));
        assert_eq!(reason(&deep), Reason::TooDeep);
        let ok = format!("{}[a.a]\n", "[[a]]\n".repeat(3));
        assert!(parse_str(&ok).is_ok());
        let chain: Vec<String> = (1..=MAX_DEPTH / 2 + 1)
            .map(|n| format!("[[{}]]\n", vec!["a"; n].join(".")))
            .collect();
        assert_eq!(reason(&chain.concat()), Reason::TooDeep);
        // Header depth plus dotted key depth plus value depth add up.
        let deep = format!("[{}]\nx.y = [[]]\n", vec!["k"; MAX_DEPTH - 2].join("."));
        assert_eq!(reason(&deep), Reason::TooDeep);
    }

    #[test]
    fn rejects_oversized_input_before_parsing() {
        let input = vec![b'#'; MAX_INPUT_LEN + 1];
        assert_eq!(
            parse(&input),
            Err(TomlError::InputTooLarge {
                len: MAX_INPUT_LEN + 1,
                limit: MAX_INPUT_LEN
            })
        );
        assert_eq!(parse(&input).unwrap_err().position(), None);
    }

    #[test]
    fn parses_scalars_strings_and_keys() {
        let root = parse_str(concat!(
            "bare-key_1 = 'C:\\path'\n",
            "\"quoted key\" = \"tab\\there \\\"q\\\" \\u00e9 \\U0001F600 \\\\\"\n",
            "'' = 1\n",
            "a . \"b.c\" . d = true\n",
            "i = [+17, -0, 1_000, -9_223_372_036_854_775_808, 9223372036854775807,]\n",
            "mixed = [ \"x\", 1, [ ], { } ]\n",
            "e = \"\"\n",
            "\r\n",
            "  # comment with ünïcode\n",
        ))
        .unwrap();
        assert_eq!(get(&root, "bare-key_1").value().as_str(), Some("C:\\path"));
        assert_eq!(
            root.get("quoted key").unwrap().value().as_str(),
            Some("tab\there \"q\" é 😀 \\")
        );
        assert_eq!(root.get("").unwrap().value().as_integer(), Some(1));
        let a = root.get("a").unwrap().value().as_table().unwrap();
        let bc = a.get("b.c").unwrap().value().as_table().unwrap();
        assert_eq!(bc.get("d").unwrap().value().as_bool(), Some(true));
        let ints: Vec<i64> = get(&root, "i")
            .value()
            .as_array()
            .unwrap()
            .iter()
            .map(|i| i.value().as_integer().unwrap())
            .collect();
        assert_eq!(ints, [17, 0, 1000, i64::MIN, i64::MAX]);
        assert_eq!(get(&root, "mixed").value().as_array().unwrap().len(), 4);
        assert_eq!(get(&root, "e").value().as_str(), Some(""));
        assert!(parse_str("").unwrap().is_empty());
    }

    #[test]
    fn parses_multi_line_arrays_with_comments() {
        let root = parse_str("a = [ # first\n  1, # one\n\n  2 , # two\n] # end\nb = 3").unwrap();
        assert_eq!(get(&root, "a").value().as_array().unwrap().len(), 2);
        assert_eq!(get(&root, "b").position(), pos(6, 5));
    }

    #[test]
    fn rejects_malformed_input_with_position() {
        // KNSH-006: every rejection names a line and column.
        let cases: &[(&str, Reason, usize, usize)] = &[
            ("a = \"x\" b\n", Reason::ExpectedEndOfLine, 1, 9),
            ("a 1\n", Reason::ExpectedEquals, 1, 3),
            ("a =\n", Reason::MissingValue, 1, 4),
            ("a = # c\n", Reason::MissingValue, 1, 5),
            ("a = \"x\n", Reason::UnterminatedString, 1, 5),
            ("a = 'x", Reason::UnterminatedString, 1, 5),
            ("a = \"\\x\"", Reason::InvalidEscape, 1, 6),
            ("a = \"\\ud800\"", Reason::InvalidEscape, 1, 6),
            ("a = \"\\U00110000\"", Reason::InvalidEscape, 1, 6),
            ("a = \"\\u12\"", Reason::InvalidEscape, 1, 6),
            ("a = \"x\u{1}\"", Reason::ControlCharacter, 1, 7),
            ("a = 'x\u{7f}'", Reason::ControlCharacter, 1, 7),
            ("# x\u{0}\n", Reason::ControlCharacter, 1, 4),
            ("a = 1\rb = 2", Reason::ControlCharacter, 1, 6),
            ("a = 01", Reason::InvalidInteger, 1, 5),
            ("a = 1__0", Reason::InvalidInteger, 1, 5),
            ("a = 1_", Reason::InvalidInteger, 1, 5),
            ("a = _1", Reason::UnexpectedCharacter, 1, 5),
            ("a = +", Reason::InvalidInteger, 1, 5),
            ("a = 12abc", Reason::InvalidInteger, 1, 5),
            ("a = tru", Reason::InvalidInteger, 1, 5),
            ("a = True", Reason::InvalidInteger, 1, 5),
            ("a = 9223372036854775808", Reason::IntegerOutOfRange, 1, 5),
            ("a = -9223372036854775809", Reason::IntegerOutOfRange, 1, 5),
            (
                "a = 99999999999999999999999999999999999999999999",
                Reason::IntegerOutOfRange,
                1,
                5,
            ),
            ("a = { b = 1, }", Reason::TrailingComma, 1, 14),
            ("a = { b = 1,\n c = 2 }", Reason::NewlineInInlineTable, 1, 13),
            ("a = { b = 1", Reason::UnexpectedEnd, 1, 12),
            ("a = [1 2]", Reason::UnexpectedCharacter, 1, 8),
            ("a = [1,,2]", Reason::UnexpectedCharacter, 1, 8),
            ("a = [,]", Reason::UnexpectedCharacter, 1, 6),
            ("a = [1,\n", Reason::UnexpectedEnd, 2, 1),
            ("a = bare", Reason::InvalidInteger, 1, 5),
            ("[a\n", Reason::UnexpectedCharacter, 1, 3),
            ("[[a]\n", Reason::UnexpectedCharacter, 1, 5),
            ("[ [a]]\n", Reason::UnexpectedCharacter, 1, 3),
            ("[]\n", Reason::UnexpectedCharacter, 1, 2),
            ("[a] x = 1\n", Reason::ExpectedEndOfLine, 1, 5),
            ("a.= 1", Reason::UnexpectedCharacter, 1, 3),
            ("= 1", Reason::UnexpectedCharacter, 1, 1),
            ("\u{feff}a = 1", Reason::UnexpectedCharacter, 1, 1),
            ("ä = 1", Reason::UnexpectedCharacter, 1, 1),
            ("a = 1\n  b = é", Reason::UnexpectedCharacter, 2, 7),
        ];
        for &(text, expected, line, column) in cases {
            assert_eq!(error_at(text), (expected, line, column), "{text:?}");
        }
    }

    #[test]
    fn reports_invalid_utf8_position() {
        assert_eq!(
            parse(b"a = 1\nbb = \"\xff\""),
            Err(TomlError::Parse {
                position: pos(2, 7),
                reason: Reason::InvalidUtf8
            })
        );
    }

    #[test]
    fn counts_columns_in_characters() {
        // Multi-byte characters count as one column, so editors and error messages agree.
        assert_eq!(error_at("a = \"éé\" x"), (Reason::ExpectedEndOfLine, 1, 10));
    }

    #[test]
    fn errors_do_not_echo_input() {
        // Configuration may hold secret names and paths (NFR-PRIV-02): messages carry positions only.
        let message = parse_str("secret_token_name = 1979-05-27").unwrap_err().to_string();
        assert!(!message.contains("secret_token_name"));
        assert!(!message.contains("1979"));
    }
}
