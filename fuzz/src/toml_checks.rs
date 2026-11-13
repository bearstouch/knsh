//! The properties of the `toml_parser` fuzz target (KNSH-006; `specs/07-testing/fuzzing.md`, NFR-SUP-06).
//!
//! Kept apart from `checks.rs` because each file is also compiled on stable by the test suite of the crate it
//! exercises: this one by `crates/knsh-toml/tests/fuzz_regressions.rs`, which includes it by path. It must
//! therefore depend on nothing but `knsh-toml` and `std`. A failed property panics, which libFuzzer records as a
//! crash.

use std::fmt::Write as _;

use knsh_toml::{Item, MAX_DEPTH, MAX_INPUT_LEN, Position, Table, TomlError, Value, parse};

/// `toml_parser`: the parser never panics; a rejection names a line and column inside the input (or is the size
/// limit, exactly when the input is over it); an accepted document is valid UTF-8, holds positions inside the input,
/// nests no deeper than [`MAX_DEPTH`], and reads back to the same tree when written out again as TOML (a round trip
/// through an independent writer below, so parser and writer must agree on strings, integers, keys and nesting).
pub fn toml_parser(data: &[u8]) {
    let bounds = Bounds::of(data);
    let root = match parse(data) {
        Ok(root) => root,
        Err(TomlError::InputTooLarge { len, limit }) => {
            assert!(
                len == data.len() && limit == MAX_INPUT_LEN && len > limit,
                "wrong size rejection"
            );
            return;
        }
        Err(TomlError::Parse { position, .. }) => {
            assert!(
                bounds.contains(position),
                "error position {position:?} outside the input"
            );
            return;
        }
    };
    assert!(data.len() <= MAX_INPUT_LEN, "accepted input over the size limit");
    assert!(std::str::from_utf8(data).is_ok(), "accepted invalid UTF-8");
    check_table(&root, 0, &bounds);

    let mut text = String::new();
    write_root(&root, &mut text);
    // Quoting every key and inlining every table can make the text longer than the input.
    if text.len() > MAX_INPUT_LEN {
        return;
    }
    let reread = parse(text.as_bytes()).unwrap_or_else(|error| panic!("written TOML was rejected: {error}"));
    assert!(same_table(&root, &reread), "accepted document did not round-trip");
}

/// Where a position may point: lines 1 to the number of lines, columns 1 to one past the longest line. Counted
/// in bytes for the column, which is an upper bound for the parser's character count.
struct Bounds {
    lines: usize,
    longest: usize,
}

impl Bounds {
    fn of(data: &[u8]) -> Self {
        let lines = data.split(|&byte| byte == b'\n');
        let longest = lines.clone().map(<[u8]>::len).max().unwrap_or(0);
        Self {
            lines: lines.count(),
            longest,
        }
    }

    fn contains(&self, position: Position) -> bool {
        (1..=self.lines).contains(&position.line) && (1..=self.longest + 1).contains(&position.column)
    }
}

/// Checks every item's position and the nesting depth: a table or array at `depth` is within [`MAX_DEPTH`].
fn check_table(table: &Table, depth: usize, bounds: &Bounds) {
    assert!(depth <= MAX_DEPTH, "accepted nesting deeper than {MAX_DEPTH}");
    for (_, item) in table {
        check_item(item, depth + 1, bounds);
    }
}

fn check_item(item: &Item, depth: usize, bounds: &Bounds) {
    assert!(
        bounds.contains(item.position()),
        "item position {:?} outside the input",
        item.position()
    );
    match item.value() {
        Value::String(_) | Value::Integer(_) | Value::Boolean(_) => {}
        Value::Table(table) => check_table(table, depth, bounds),
        Value::Array(array) => {
            assert!(depth <= MAX_DEPTH, "accepted nesting deeper than {MAX_DEPTH}");
            for element in array {
                check_item(element, depth + 1, bounds);
            }
        }
    }
}

/// Writes the root table as one `"key" = value` line per key, with every nested table inline and every array of
/// tables as a static array of inline tables. The nesting depth is unchanged, so the result is within the limit.
fn write_root(root: &Table, out: &mut String) {
    for (key, item) in root {
        write_string(key, out);
        out.push_str(" = ");
        write_value(item.value(), out);
        out.push('\n');
    }
}

fn write_value(value: &Value, out: &mut String) {
    match value {
        Value::String(text) => write_string(text, out),
        Value::Integer(number) => write!(out, "{number}").unwrap(),
        Value::Boolean(flag) => out.push_str(if *flag { "true" } else { "false" }),
        Value::Array(array) => {
            out.push('[');
            for (index, element) in array.iter().enumerate() {
                if index > 0 {
                    out.push_str(", ");
                }
                write_value(element.value(), out);
            }
            out.push(']');
        }
        Value::Table(table) => {
            out.push('{');
            for (index, (key, item)) in table.iter().enumerate() {
                out.push_str(if index > 0 { ", " } else { " " });
                write_string(key, out);
                out.push_str(" = ");
                write_value(item.value(), out);
            }
            out.push_str(if table.is_empty() { "}" } else { " }" });
        }
    }
}

/// A basic string: quote and backslash escaped, control characters as `\uXXXX`, everything else verbatim.
fn write_string(text: &str, out: &mut String) {
    out.push('"');
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if (c < ' ' && c != '\t') || c == '\u{7f}' => write!(out, "\\u{:04X}", u32::from(c)).unwrap(),
            c => out.push(c),
        }
    }
    out.push('"');
}

/// Structural equality, ignoring positions and how each table or array was written (header, dotted, inline).
fn same_table(a: &Table, b: &Table) -> bool {
    a.len() == b.len()
        && a.iter()
            .zip(b.iter())
            .all(|((key_a, item_a), (key_b, item_b))| key_a == key_b && same_value(item_a.value(), item_b.value()))
}

fn same_value(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::String(a), Value::String(b)) => a == b,
        (Value::Integer(a), Value::Integer(b)) => a == b,
        (Value::Boolean(a), Value::Boolean(b)) => a == b,
        (Value::Array(a), Value::Array(b)) => {
            a.len() == b.len() && a.iter().zip(b.iter()).all(|(a, b)| same_value(a.value(), b.value()))
        }
        (Value::Table(a), Value::Table(b)) => same_table(a, b),
        _ => false,
    }
}
