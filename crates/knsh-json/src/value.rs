//! The JSON value model: [`Value`] and the insertion-ordered, duplicate-free [`Object`].
//!
//! Every value that can be built here is strict-profile JSON except for nesting depth, which only the writer can
//! see and therefore checks ([`write`](crate::write())).

use std::collections::BTreeMap;

use crate::error::{JsonError, Kind};
use crate::number::Number;

/// A JSON value.
///
/// Strings are Rust `String`s, so they are valid UTF-8 and cannot hold unpaired surrogates. Numbers obey the
/// ±2^53 rule ([`Number`]). Objects cannot hold duplicate keys ([`Object`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    /// `null`.
    Null,
    /// `true` or `false`.
    Bool(bool),
    /// A number.
    Number(Number),
    /// A string.
    String(String),
    /// An array.
    Array(Vec<Value>),
    /// An object.
    Object(Object),
}

impl Value {
    /// An integer number value.
    ///
    /// # Errors
    ///
    /// [`JsonError::IntegerOutOfRange`] outside ±2^53; such values must be sent as strings
    /// ([`Value::int_string`]).
    pub fn int(value: i64) -> Result<Self, JsonError> {
        Number::int(value).map(Self::Number)
    }

    /// An integer as a decimal string, the strict profile's representation for values that may exceed ±2^53, such
    /// as byte counts (`specs/06-api/wire-format.md`). Read it back with [`Value::as_int_string`].
    #[must_use]
    pub fn int_string(value: i128) -> Self {
        Self::String(value.to_string())
    }

    /// The JSON type of this value. Never returns [`Kind::Integer`], which only describes an expectation.
    #[must_use]
    pub const fn kind(&self) -> Kind {
        match self {
            Self::Null => Kind::Null,
            Self::Bool(_) => Kind::Bool,
            Self::Number(_) => Kind::Number,
            Self::String(_) => Kind::String,
            Self::Array(_) => Kind::Array,
            Self::Object(_) => Kind::Object,
        }
    }

    /// Whether this is `null`.
    #[must_use]
    pub const fn is_null(&self) -> bool {
        matches!(self, Self::Null)
    }

    /// The boolean, if this is one.
    #[must_use]
    pub const fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Bool(value) => Some(*value),
            _ => None,
        }
    }

    /// The number, if this is one.
    #[must_use]
    pub const fn as_number(&self) -> Option<&Number> {
        match self {
            Self::Number(number) => Some(number),
            _ => None,
        }
    }

    /// The integer, if this is a number that is exactly an integer within ±2^53 (see [`Number::as_i64`]).
    #[must_use]
    pub fn as_i64(&self) -> Option<i64> {
        self.as_number().and_then(Number::as_i64)
    }

    /// The string, if this is one.
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(text) => Some(text),
            _ => None,
        }
    }

    /// The integer held in a string written by [`Value::int_string`]. Only the canonical form is accepted
    /// (`-?(0|[1-9][0-9]*)`, no `-0`, no `+`, no spaces), so that each integer has exactly one representation.
    #[must_use]
    pub fn as_int_string(&self) -> Option<i128> {
        let text = self.as_str()?;
        let digits = text.strip_prefix('-').unwrap_or(text);
        let canonical = !digits.is_empty()
            && digits.bytes().all(|b| b.is_ascii_digit())
            && (digits == "0" || !digits.starts_with('0'))
            && text != "-0";
        // `i128::from_str` rejects overflow, so a long digit run fails instead of wrapping.
        if canonical { text.parse().ok() } else { None }
    }

    /// The elements, if this is an array.
    #[must_use]
    pub const fn as_array(&self) -> Option<&Vec<Self>> {
        match self {
            Self::Array(items) => Some(items),
            _ => None,
        }
    }

    /// The object, if this is one.
    #[must_use]
    pub const fn as_object(&self) -> Option<&Object> {
        match self {
            Self::Object(object) => Some(object),
            _ => None,
        }
    }
}

impl From<bool> for Value {
    fn from(value: bool) -> Self {
        Self::Bool(value)
    }
}

impl From<String> for Value {
    fn from(value: String) -> Self {
        Self::String(value)
    }
}

impl From<&str> for Value {
    fn from(value: &str) -> Self {
        Self::String(value.to_owned())
    }
}

/// Every `i32`, `u32` and smaller integer is within ±2^53, so these conversions cannot fail. Wider types go through
/// [`Value::int`], which can.
macro_rules! from_small_int {
    ($($ty:ty),*) => {$(
        impl From<$ty> for Value {
            fn from(value: $ty) -> Self {
                Self::Number(Number::from_small(i64::from(value)))
            }
        }
    )*};
}
from_small_int!(i8, i16, i32, u8, u16, u32);

impl From<Number> for Value {
    fn from(value: Number) -> Self {
        Self::Number(value)
    }
}

impl From<Vec<Value>> for Value {
    fn from(value: Vec<Value>) -> Self {
        Self::Array(value)
    }
}

impl From<Object> for Value {
    fn from(value: Object) -> Self {
        Self::Object(value)
    }
}

/// A JSON object: fields in insertion order, with no duplicate keys.
///
/// # Invariants
///
/// - Keys are unique (compared as unescaped strings). [`Object::insert`] refuses an existing key instead of
///   replacing it, so no code path can produce or accept an object that two parsers could read two ways
///   (NFR-SEC-06).
/// - Iteration and writing follow insertion order; equality compares fields in order.
#[derive(Debug, Clone, Default)]
pub struct Object {
    entries: Vec<(String, Value)>,
    /// Key → position in `entries`. Makes duplicate detection O(log n) per key: a linear scan would let a 1 MB frame
    /// with ~100k keys cost ~10^10 comparisons. A B-tree needs no hash seed, so its cost cannot be steered by input.
    index: BTreeMap<String, usize>,
}

impl Object {
    /// An empty object.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Appends a field.
    ///
    /// # Errors
    ///
    /// [`JsonError::DuplicateKey`] if the object already holds `key`; the object is left unchanged.
    pub fn insert(&mut self, key: impl Into<String>, value: Value) -> Result<(), JsonError> {
        let key = key.into();
        if self.index.contains_key(&key) {
            return Err(JsonError::DuplicateKey);
        }
        self.index.insert(key.clone(), self.entries.len());
        self.entries.push((key, value));
        Ok(())
    }

    /// Builder form of [`Object::insert`].
    ///
    /// # Errors
    ///
    /// [`JsonError::DuplicateKey`] if the object already holds `key`.
    pub fn with(mut self, key: impl Into<String>, value: impl Into<Value>) -> Result<Self, JsonError> {
        self.insert(key, value.into())?;
        Ok(self)
    }

    /// The value of `key`, if present.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&Value> {
        self.position(key)
            .and_then(|i| self.entries.get(i))
            .map(|(_, value)| value)
    }

    /// Whether `key` is present.
    #[must_use]
    pub fn contains_key(&self, key: &str) -> bool {
        self.index.contains_key(key)
    }

    /// Number of fields.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the object has no fields.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The fields in insertion order.
    pub fn iter(&self) -> impl ExactSizeIterator<Item = (&str, &Value)> {
        self.entries.iter().map(|(key, value)| (key.as_str(), value))
    }

    /// Position of `key` in insertion order, used by [`Fields`](crate::Fields) to track which fields were read.
    pub(crate) fn position(&self, key: &str) -> Option<usize> {
        self.index.get(key).copied()
    }
}

impl PartialEq for Object {
    /// Fields compared in order; the index is derived from them and needs no comparison.
    fn eq(&self, other: &Self) -> bool {
        self.entries == other.entries
    }
}

impl Eq for Object {}

impl<'a> IntoIterator for &'a Object {
    type Item = (&'a str, &'a Value);
    type IntoIter = Box<dyn ExactSizeIterator<Item = (&'a str, &'a Value)> + 'a>;

    fn into_iter(self) -> Self::IntoIter {
        Box::new(self.iter())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn object_insert_rejects_duplicate_key() {
        let mut object = Object::new();
        object.insert("a", Value::from(1)).unwrap();
        assert_eq!(object.insert("a", Value::from(2)), Err(JsonError::DuplicateKey));
        // The rejected insert left the object unchanged.
        assert_eq!(object.len(), 1);
        assert_eq!(object.get("a"), Some(&Value::from(1)));
    }

    #[test]
    fn object_preserves_insertion_order() {
        let object = Object::new()
            .with("z", 1)
            .unwrap()
            .with("a", 2)
            .unwrap()
            .with("m", 3)
            .unwrap();
        let keys: Vec<&str> = object.iter().map(|(key, _)| key).collect();
        assert_eq!(keys, ["z", "a", "m"]);
    }

    #[test]
    fn int_string_reads_back_only_canonical_form() {
        let big = i128::from(u64::MAX);
        assert_eq!(Value::int_string(big).as_int_string(), Some(big));
        assert_eq!(Value::int_string(-5).as_int_string(), Some(-5));
        for bad in [
            "",
            "-",
            "-0",
            "+1",
            "01",
            " 1",
            "1.0",
            "1e3",
            "99999999999999999999999999999999999999999",
        ] {
            assert_eq!(Value::from(bad).as_int_string(), None, "{bad:?}");
        }
    }
}
