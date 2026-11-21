//! Variable values: strings, indexed arrays and associative arrays (KNSH-103; NFR-COMPAT-02).
//!
//! An indexed array is sparse: its elements are kept by index, in index order, as bash's `ARRAY` lists them. An
//! associative array is kept as bash 5.2 keeps it (`assoc.c` over `hashlib.c`), so that `${!h[@]}` and `${h[@]}`
//! list its elements in the order bash does: a table of 1,024 buckets chosen by bash's FNV-1 string hash, each
//! bucket listing its newest key first, the buckets walked in order; past two entries per bucket the table grows
//! four times, re-inserting each bucket's entries in turn, as bash's `hash_rehash` does. Bash does not document
//! this order; scripts that print associative arrays see it, so it is reproduced rather than replaced by another.

use std::collections::BTreeMap;
use std::ffi::OsString;

/// Buckets of a new associative array: bash's `ASSOC_HASH_BUCKETS`.
const ASSOC_BUCKETS: u32 = 1024;

/// Bash's `HASH_REHASH_FACTOR`: a table grows once it holds this many entries per bucket.
const REHASH_FACTOR: usize = 2;

/// Bash's `HASH_REHASH_MULTIPLIER`: how many times larger a table grows.
const REHASH_MULTIPLIER: u32 = 4;

/// Bash's `hash_string`: FNV-1 (multiply, then exclusive-or) over the key's bytes.
pub(crate) fn bash_hash(key: &[u8]) -> u32 {
    let mut hash: u32 = 2_166_136_261;
    for &byte in key {
        hash = hash.wrapping_mul(16_777_619);
        hash ^= u32::from(byte);
    }
    hash
}

/// An associative array, in bash's bucket order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Assoc {
    /// The non-empty buckets by number, each newest key first.
    buckets: BTreeMap<u32, Vec<(String, OsString)>>,
    /// Buckets in the table, a power of two.
    size: u32,
    /// Entries held.
    len: usize,
}

impl Default for Assoc {
    fn default() -> Self {
        Self::with_size(ASSOC_BUCKETS)
    }
}

impl Assoc {
    /// An empty array of `size` buckets.
    fn with_size(size: u32) -> Self {
        Self {
            buckets: BTreeMap::new(),
            size,
            len: 0,
        }
    }

    /// An empty array the size of this one, as bash makes the table a whole-array assignment fills
    /// (`assoc_create (h->nbuckets)`).
    pub(crate) fn emptied(&self) -> Self {
        Self::with_size(self.size)
    }

    fn bucket(&self, key: &str) -> u32 {
        bash_hash(key.as_bytes()) & (self.size - 1)
    }

    /// The value of `key`.
    pub(crate) fn get(&self, key: &str) -> Option<&OsString> {
        self.buckets
            .get(&self.bucket(key))?
            .iter()
            .find(|(held, _)| held == key)
            .map(|(_, value)| value)
    }

    /// Sets `key` to `value`: an existing key keeps its place; a new one goes first in its bucket.
    pub(crate) fn insert(&mut self, key: &str, value: OsString) {
        let bucket = self.bucket(key);
        if let Some(entry) = self
            .buckets
            .get_mut(&bucket)
            .and_then(|entries| entries.iter_mut().find(|(held, _)| held == key))
        {
            entry.1 = value;
            return;
        }
        if self.len >= (self.size as usize).saturating_mul(REHASH_FACTOR) {
            self.grow();
        }
        let bucket = self.bucket(key);
        self.buckets
            .entry(bucket)
            .or_default()
            .insert(0, (key.to_owned(), value));
        self.len += 1;
    }

    /// Bash's `hash_rehash`: each old bucket in turn, its entries in order, each put first in its new bucket.
    fn grow(&mut self) {
        let Some(size) = self.size.checked_mul(REHASH_MULTIPLIER) else {
            return;
        };
        let old = std::mem::take(&mut self.buckets);
        self.size = size;
        for (_, entries) in old {
            for (key, value) in entries {
                let bucket = self.bucket(&key);
                self.buckets.entry(bucket).or_default().insert(0, (key, value));
            }
        }
    }

    /// Removes `key`; whether it was there.
    pub(crate) fn remove(&mut self, key: &str) -> bool {
        let bucket = self.bucket(key);
        let Some(entries) = self.buckets.get_mut(&bucket) else {
            return false;
        };
        let Some(at) = entries.iter().position(|(held, _)| held == key) else {
            return false;
        };
        entries.remove(at);
        if entries.is_empty() {
            self.buckets.remove(&bucket);
        }
        self.len -= 1;
        true
    }

    /// Entries held.
    pub(crate) const fn len(&self) -> usize {
        self.len
    }

    /// The entries in bash's order.
    pub(crate) fn iter(&self) -> impl Iterator<Item = (&str, &OsString)> {
        self.buckets
            .values()
            .flat_map(|entries| entries.iter().map(|(key, value)| (key.as_str(), value)))
    }
}

/// A variable's value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Value {
    /// A string.
    Scalar(OsString),
    /// An indexed array: elements by index (never negative), in index order.
    Indexed(BTreeMap<i64, OsString>),
    /// An associative array.
    Assoc(Assoc),
}

/// What kind of value a variable holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    /// No such variable.
    Unset,
    /// A string, or a variable declared without a value.
    Scalar,
    /// An indexed array.
    Indexed,
    /// An associative array.
    Assoc,
}

/// An element of an array: an index of an indexed array or a key of an associative one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Key {
    /// An index, from the end when negative (bash 4.3 and later).
    Index(i64),
    /// A key.
    Name(String),
}

impl Value {
    /// Its kind.
    pub(crate) const fn kind(&self) -> Kind {
        match self {
            Self::Scalar(_) => Kind::Scalar,
            Self::Indexed(_) => Kind::Indexed,
            Self::Assoc(_) => Kind::Assoc,
        }
    }

    /// The value `$name` reads: the string, element 0, or key `0` (bash reads an array's name as its element 0).
    pub(crate) fn first(&self) -> Option<&OsString> {
        match self {
            Self::Scalar(text) => Some(text),
            Self::Indexed(elements) => elements.get(&0),
            Self::Assoc(entries) => entries.get("0"),
        }
    }

    /// The element `key` names. A string is element 0 of itself, as in bash; a negative index counts back from one
    /// past the greatest index. `Err(())` for a negative index before the first element (bash's `bad array
    /// subscript`).
    pub(crate) fn element(&self, key: &Key) -> Result<Option<&OsString>, ()> {
        match (self, key) {
            (Self::Scalar(text), Key::Index(index)) => Ok(match index {
                0 | -1 => Some(text),
                _ if *index < -1 => return Err(()),
                _ => None,
            }),
            (Self::Indexed(elements), Key::Index(index)) => {
                let index = resolve_index(elements, *index)?;
                Ok(elements.get(&index))
            }
            (Self::Assoc(entries), Key::Name(name)) => Ok(entries.get(name)),
            (Self::Assoc(entries), Key::Index(index)) => Ok(entries.get(&index.to_string())),
            (Self::Scalar(text), Key::Name(name)) => Ok((name == "0").then_some(text)),
            (Self::Indexed(elements), Key::Name(name)) => Ok(name.parse().ok().and_then(|index| elements.get(&index))),
        }
    }

    /// Every element in order, with its key: a string is element 0.
    pub(crate) fn elements(&self) -> Vec<(Key, OsString)> {
        match self {
            Self::Scalar(text) => vec![(Key::Index(0), text.clone())],
            Self::Indexed(elements) => elements
                .iter()
                .map(|(index, value)| (Key::Index(*index), value.clone()))
                .collect(),
            Self::Assoc(entries) => entries
                .iter()
                .map(|(key, value)| (Key::Name(key.to_owned()), value.clone()))
                .collect(),
        }
    }

    /// How many elements it has (a string has one).
    pub(crate) fn count(&self) -> usize {
        match self {
            Self::Scalar(_) => 1,
            Self::Indexed(elements) => elements.len(),
            Self::Assoc(entries) => entries.len(),
        }
    }

    /// This value as an indexed array, a string becoming its element 0 (bash's `convert_var_to_array`).
    pub(crate) fn into_indexed(self) -> BTreeMap<i64, OsString> {
        match self {
            Self::Scalar(text) => BTreeMap::from([(0, text)]),
            Self::Indexed(elements) => elements,
            // Callers convert an associative array never: bash refuses that conversion.
            Self::Assoc(entries) => entries
                .iter()
                .enumerate()
                .map(|(at, (_, value))| (i64::try_from(at).unwrap_or(i64::MAX), value.clone()))
                .collect(),
        }
    }
}

/// `index` of `elements`, counted back from one past the greatest index when negative. `Err(())` when that is still
/// negative.
pub(crate) fn resolve_index(elements: &BTreeMap<i64, OsString>, index: i64) -> Result<i64, ()> {
    if index >= 0 {
        return Ok(index);
    }
    let end = elements.keys().next_back().map_or(0, |last| last.saturating_add(1));
    let resolved = end.saturating_add(index);
    if resolved < 0 { Err(()) } else { Ok(resolved) }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys(assoc: &Assoc) -> Vec<&str> {
        assoc.iter().map(|(key, _)| key).collect()
    }

    // KNSH-103: associative arrays list their keys in bash's bucket order, newest first within a bucket, and an
    // existing key keeps its place when assigned again.
    #[test]
    fn associative_order_follows_bash_buckets() {
        let mut assoc = Assoc::default();
        for key in ["a", "b", "c", "apple", "banana"] {
            assoc.insert(key, OsString::from(key));
        }
        let mut expected: Vec<&str> = vec!["a", "b", "c", "apple", "banana"];
        expected.sort_by_key(|key| bash_hash(key.as_bytes()) & 1023);
        assert_eq!(keys(&assoc), expected);
        assoc.insert("a", OsString::from("again"));
        assert_eq!(keys(&assoc), expected);
        assert_eq!(assoc.get("a"), Some(&OsString::from("again")));
        assert!(assoc.remove("b"));
        assert!(!assoc.remove("b"));
        assert_eq!(assoc.len(), 4);
    }

    #[test]
    fn keys_sharing_a_bucket_list_newest_first() {
        // Find two keys in one bucket, then insert them in turn.
        let first = "k0".to_owned();
        let bucket = bash_hash(first.as_bytes()) & 1023;
        let second = (1..100_000)
            .map(|n| format!("k{n}"))
            .find(|key| bash_hash(key.as_bytes()) & 1023 == bucket)
            .unwrap();
        let mut assoc = Assoc::default();
        assoc.insert(&first, OsString::new());
        assoc.insert(&second, OsString::new());
        assert_eq!(keys(&assoc), [second.as_str(), first.as_str()]);
    }

    #[test]
    fn a_full_table_grows_and_keeps_every_entry() {
        let mut assoc = Assoc::default();
        for n in 0..2100 {
            assoc.insert(&n.to_string(), OsString::from(n.to_string()));
        }
        assert_eq!(assoc.size, 4096);
        assert_eq!(assoc.len(), 2100);
        assert_eq!(assoc.iter().count(), 2100);
        assert_eq!(assoc.get("2049"), Some(&OsString::from("2049")));
    }

    #[test]
    fn negative_indices_count_back_from_the_end() {
        let elements = BTreeMap::from([(0, OsString::from("a")), (5, OsString::from("f"))]);
        assert_eq!(resolve_index(&elements, -1), Ok(5));
        assert_eq!(resolve_index(&elements, -6), Ok(0));
        assert_eq!(resolve_index(&elements, -7), Err(()));
        let value = Value::Indexed(elements);
        assert_eq!(value.element(&Key::Index(-2)), Ok(None));
    }
}
