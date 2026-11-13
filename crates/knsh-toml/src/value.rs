//! The value tree produced by [`parse`](crate::parse): tables, arrays and scalars, each with its source position.
//!
//! The tree can only be built by the parser, so it always satisfies the parser's invariants: no duplicate keys, at
//! most [`MAX_DEPTH`](crate::MAX_DEPTH) levels of nesting, integers within `i64`.

use std::collections::BTreeMap;
use std::collections::btree_map;

use crate::error::Position;

/// A value and the position where it is defined.
///
/// For a scalar, array or inline table this is its first character. For a table opened by a `[header]` (or an
/// element of an array of tables, `[[header]]`) it is the header's opening bracket. For a table that only exists
/// because a dotted key or a header path runs through it, it is the key segment that created it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Item {
    pub(crate) value: Value,
    pub(crate) position: Position,
}

impl Item {
    /// The value.
    #[must_use]
    pub const fn value(&self) -> &Value {
        &self.value
    }

    /// Where the value is defined (see the type documentation).
    #[must_use]
    pub const fn position(&self) -> Position {
        self.position
    }
}

/// A TOML value from the supported subset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    /// A basic (`"…"`) or literal (`'…'`) string, with escapes resolved.
    String(String),
    /// A decimal integer.
    Integer(i64),
    /// `true` or `false`.
    Boolean(bool),
    /// A static array (`[1, 2]`) or an array of tables (`[[name]]`).
    Array(Array),
    /// A table: the root, a `[header]` table, an inline table or a table created by dotted keys.
    Table(Table),
}

impl Value {
    /// The string, if this is one.
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(text) => Some(text),
            Self::Integer(_) | Self::Boolean(_) | Self::Array(_) | Self::Table(_) => None,
        }
    }

    /// The integer, if this is one.
    #[must_use]
    pub const fn as_integer(&self) -> Option<i64> {
        match self {
            Self::Integer(number) => Some(*number),
            Self::String(_) | Self::Boolean(_) | Self::Array(_) | Self::Table(_) => None,
        }
    }

    /// The boolean, if this is one.
    #[must_use]
    pub const fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Boolean(flag) => Some(*flag),
            Self::String(_) | Self::Integer(_) | Self::Array(_) | Self::Table(_) => None,
        }
    }

    /// The array, if this is one.
    #[must_use]
    pub const fn as_array(&self) -> Option<&Array> {
        match self {
            Self::Array(array) => Some(array),
            Self::String(_) | Self::Integer(_) | Self::Boolean(_) | Self::Table(_) => None,
        }
    }

    /// The table, if this is one.
    #[must_use]
    pub const fn as_table(&self) -> Option<&Table> {
        match self {
            Self::Table(table) => Some(table),
            Self::String(_) | Self::Integer(_) | Self::Boolean(_) | Self::Array(_) => None,
        }
    }
}

/// An ordered list of items. Elements may have different types, as in TOML 1.0.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Array {
    pub(crate) items: Vec<Item>,
    /// Built by `[[header]]` lines, so later `[[header]]` lines may append to it. A static array (`[…]`) is complete
    /// once written and can never be extended.
    pub(crate) of_tables: bool,
}

impl Array {
    /// Number of elements.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.items.len()
    }

    /// Whether there are no elements.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// The element at `index`, if any. Indexes are the source order, as used in rule IDs (`exec.allow[1]`).
    #[must_use]
    pub fn get(&self, index: usize) -> Option<&Item> {
        self.items.get(index)
    }

    /// The elements in source order.
    pub fn iter(&self) -> std::slice::Iter<'_, Item> {
        self.items.iter()
    }

    /// Whether the array was built by `[[header]]` lines rather than written as `[…]`.
    #[must_use]
    pub const fn is_array_of_tables(&self) -> bool {
        self.of_tables
    }
}

impl<'a> IntoIterator for &'a Array {
    type Item = &'a Item;
    type IntoIter = std::slice::Iter<'a, Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// How a table came to exist. Decides whether a later header or dotted key may add to it (TOML 1.0, "Table").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TableKind {
    /// Created only because a header path ran through it (`a` in `[a.b]`). A later `[a]` may define it once.
    Implicit,
    /// Defined by its own `[header]`, or an element of an array of tables (`[[header]]`), or the document root.
    /// Only sub-tables may be added later, by other headers.
    Header,
    /// Created by a dotted key (`a.b = 1` creates `a`). Dotted keys in the same section may add to it; headers may
    /// define sub-tables in it, but never the table itself.
    Dotted,
    /// An inline table (`{ … }`): complete once written, nothing may be added to it.
    Inline,
}

/// A table: keys mapped to items. Keys are unique; iteration is in key order (byte-wise), not source order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Table {
    pub(crate) entries: BTreeMap<String, Item>,
    pub(crate) kind: TableKind,
}

impl Table {
    pub(crate) const fn new(kind: TableKind) -> Self {
        Self {
            entries: BTreeMap::new(),
            kind,
        }
    }

    /// The item stored under `key`, if any.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&Item> {
        self.entries.get(key)
    }

    /// Whether `key` is present.
    #[must_use]
    pub fn contains_key(&self, key: &str) -> bool {
        self.entries.contains_key(key)
    }

    /// Number of keys.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the table has no keys.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The keys and items, in key order.
    #[must_use]
    pub fn iter(&self) -> Iter<'_> {
        Iter(self.entries.iter())
    }

    /// Whether the table was written inline (`{ … }`).
    #[must_use]
    pub fn is_inline(&self) -> bool {
        self.kind == TableKind::Inline
    }
}

impl<'a> IntoIterator for &'a Table {
    type Item = (&'a str, &'a Item);
    type IntoIter = Iter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// Iterator over a [`Table`]'s keys and items, in key order.
#[derive(Debug, Clone)]
pub struct Iter<'a>(btree_map::Iter<'a, String, Item>);

impl<'a> Iterator for Iter<'a> {
    type Item = (&'a str, &'a Item);

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next().map(|(key, item)| (key.as_str(), item))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.0.size_hint()
    }
}
