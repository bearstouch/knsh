//! Hand-written conversions between Rust types and [`Value`], in place of `serde` (CLAUDE.md "Dependencies").
//!
//! Protocol structs implement [`ToJson`] and [`FromJson`] by hand, reading objects through [`Fields`]. Errors are
//! typed: a missing field, a wrong type, an out-of-range integer and (for closed objects) an unknown field each have
//! their own [`JsonError`] variant, naming the field from our code, never text from the input.
//!
//! Unknown fields are ignored by default because the protocol is additive within a version
//! (`specs/06-api/handshake.md#rules`: "clients ignore fields they do not know").

use crate::error::{JsonError, Kind};
use crate::value::{Object, Value};

/// Converts a Rust value into a JSON [`Value`].
pub trait ToJson {
    /// The JSON form of `self`.
    ///
    /// # Errors
    ///
    /// Any [`JsonError`] from building the value, typically [`JsonError::IntegerOutOfRange`] for an integer that
    /// must be sent as a string instead ([`IntString`]).
    fn to_json(&self) -> Result<Value, JsonError>;
}

/// Reads a Rust value from a JSON [`Value`].
pub trait FromJson: Sized {
    /// Reads `value`.
    ///
    /// # Errors
    ///
    /// [`JsonError::WrongType`], [`JsonError::OutOfRange`], [`JsonError::MissingField`] or
    /// [`JsonError::UnknownField`] when `value` does not have the expected shape.
    fn from_json(value: &Value) -> Result<Self, JsonError>;
}

/// An integer that travels as a decimal string because it may exceed ±2^53, such as a byte count
/// (`specs/06-api/wire-format.md`). Always written as a string; read only from a canonical decimal string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct IntString(pub i128);

/// Reads the fields of a JSON object into a typed struct.
///
/// Tracks which fields were read, so that [`Fields::finish_closed`] can reject an object with fields the reader
/// does not know, while [`Fields::finish`] ignores them (the additive-protocol default).
///
/// # Example
///
/// ```
/// use knsh_json::{Fields, FromJson, JsonError, Value};
///
/// struct Hello { protocol: u32, client: Option<String> }
///
/// impl FromJson for Hello {
///     fn from_json(value: &Value) -> Result<Self, JsonError> {
///         let mut fields = Fields::new(value)?;
///         let hello = Hello { protocol: fields.required("protocol")?, client: fields.optional("client")? };
///         fields.finish()?;
///         Ok(hello)
///     }
/// }
///
/// let value = knsh_json::parse(br#"{"protocol":1,"future":true}"#, 1024)?;
/// let hello = Hello::from_json(&value)?;
/// assert_eq!((hello.protocol, hello.client), (1, None));
/// # Ok::<(), JsonError>(())
/// ```
#[derive(Debug)]
pub struct Fields<'a> {
    object: &'a Object,
    /// `read[i]` is true once the field at position `i` has been looked up.
    read: Vec<bool>,
}

impl<'a> Fields<'a> {
    /// Starts reading `value`, which must be an object.
    ///
    /// # Errors
    ///
    /// [`JsonError::WrongType`] (expected [`Kind::Object`]) if `value` is not an object.
    pub fn new(value: &'a Value) -> Result<Self, JsonError> {
        let object = value.as_object().ok_or(JsonError::WrongType {
            field: None,
            expected: Kind::Object,
        })?;
        Ok(Self {
            object,
            read: vec![false; object.len()],
        })
    }

    /// Looks up `name` and marks it as known.
    fn take(&mut self, name: &'static str) -> Option<&'a Value> {
        let position = self.object.position(name)?;
        if let Some(flag) = self.read.get_mut(position) {
            *flag = true;
        }
        self.object.get(name)
    }

    /// Reads a field that must be present. An explicit `null` is passed to `T`, so `T = Option<U>` makes a
    /// required-but-nullable field.
    ///
    /// # Errors
    ///
    /// [`JsonError::MissingField`] if absent; otherwise any error from `T::from_json`, with `name` attached.
    pub fn required<T: FromJson>(&mut self, name: &'static str) -> Result<T, JsonError> {
        let value = self.take(name).ok_or(JsonError::MissingField(name))?;
        T::from_json(value).map_err(|error| error.in_field(name))
    }

    /// Reads a field that may be absent. Absent and `null` both give `None`.
    ///
    /// # Errors
    ///
    /// Any error from `T::from_json` when the field holds a non-null value, with `name` attached.
    pub fn optional<T: FromJson>(&mut self, name: &'static str) -> Result<Option<T>, JsonError> {
        match self.take(name) {
            None | Some(Value::Null) => Ok(None),
            Some(value) => T::from_json(value).map(Some).map_err(|error| error.in_field(name)),
        }
    }

    /// Finishes reading, ignoring fields that were never read: the protocol is additive, so a newer peer may send
    /// fields this version does not know (`specs/06-api/handshake.md#rules`).
    ///
    /// # Errors
    ///
    /// None today; returns `Result` so callers handle both finishing modes the same way.
    pub fn finish(self) -> Result<(), JsonError> {
        Ok(())
    }

    /// Finishes reading a closed object, one whose every field must be known to the reader (for example a value
    /// whose meaning would change if an unknown field were ignored).
    ///
    /// # Errors
    ///
    /// [`JsonError::UnknownField`] if any field was never read.
    pub fn finish_closed(self) -> Result<(), JsonError> {
        if self.read.iter().all(|&read| read) {
            Ok(())
        } else {
            Err(JsonError::UnknownField)
        }
    }
}

const fn wrong_type(expected: Kind) -> JsonError {
    JsonError::WrongType { field: None, expected }
}

impl ToJson for Value {
    fn to_json(&self) -> Result<Value, JsonError> {
        Ok(self.clone())
    }
}

impl FromJson for Value {
    fn from_json(value: &Value) -> Result<Self, JsonError> {
        Ok(value.clone())
    }
}

impl ToJson for bool {
    fn to_json(&self) -> Result<Value, JsonError> {
        Ok(Value::Bool(*self))
    }
}

impl FromJson for bool {
    fn from_json(value: &Value) -> Result<Self, JsonError> {
        value.as_bool().ok_or(wrong_type(Kind::Bool))
    }
}

impl ToJson for String {
    fn to_json(&self) -> Result<Value, JsonError> {
        Ok(Value::String(self.clone()))
    }
}

impl ToJson for str {
    fn to_json(&self) -> Result<Value, JsonError> {
        Ok(Value::from(self))
    }
}

impl FromJson for String {
    fn from_json(value: &Value) -> Result<Self, JsonError> {
        value.as_str().map(str::to_owned).ok_or(wrong_type(Kind::String))
    }
}

impl ToJson for IntString {
    fn to_json(&self) -> Result<Value, JsonError> {
        Ok(Value::int_string(self.0))
    }
}

impl FromJson for IntString {
    fn from_json(value: &Value) -> Result<Self, JsonError> {
        match value {
            Value::String(_) => value
                .as_int_string()
                .map(Self)
                .ok_or(JsonError::OutOfRange { field: None }),
            _ => Err(wrong_type(Kind::String)),
        }
    }
}

/// Integers: written through [`Value::int`] (so out-of-range values fail instead of being sent as numbers), read
/// only from numbers that are exactly an integer in range of both ±2^53 and the target type. Never rounded.
macro_rules! integer_conversions {
    ($($ty:ty),*) => {$(
        impl ToJson for $ty {
            fn to_json(&self) -> Result<Value, JsonError> {
                let value = i64::try_from(*self).map_err(|_| JsonError::IntegerOutOfRange)?;
                Value::int(value)
            }
        }

        impl FromJson for $ty {
            fn from_json(value: &Value) -> Result<Self, JsonError> {
                let integer = value.as_i64().ok_or(wrong_type(Kind::Integer))?;
                <$ty>::try_from(integer).map_err(|_| JsonError::OutOfRange { field: None })
            }
        }
    )*};
}
integer_conversions!(i8, i16, i32, i64, u8, u16, u32, u64, usize);

impl<T: ToJson> ToJson for Option<T> {
    /// `None` is written as `null`.
    fn to_json(&self) -> Result<Value, JsonError> {
        match self {
            None => Ok(Value::Null),
            Some(inner) => inner.to_json(),
        }
    }
}

impl<T: FromJson> FromJson for Option<T> {
    fn from_json(value: &Value) -> Result<Self, JsonError> {
        match value {
            Value::Null => Ok(None),
            other => T::from_json(other).map(Some),
        }
    }
}

impl<T: ToJson> ToJson for [T] {
    fn to_json(&self) -> Result<Value, JsonError> {
        self.iter()
            .map(ToJson::to_json)
            .collect::<Result<Vec<_>, _>>()
            .map(Value::Array)
    }
}

impl<T: ToJson> ToJson for Vec<T> {
    fn to_json(&self) -> Result<Value, JsonError> {
        self.as_slice().to_json()
    }
}

impl<T: FromJson> FromJson for Vec<T> {
    fn from_json(value: &Value) -> Result<Self, JsonError> {
        let items = value.as_array().ok_or(wrong_type(Kind::Array))?;
        items.iter().map(T::from_json).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{parse, write};

    /// A typical protocol struct, written by hand the way `knsh-proto` will.
    #[derive(Debug, PartialEq)]
    struct Params {
        session: String,
        limit: u32,
        bytes: IntString,
        tags: Vec<String>,
        note: Option<String>,
    }

    impl ToJson for Params {
        fn to_json(&self) -> Result<Value, JsonError> {
            let mut object = Object::new();
            object.insert("session", self.session.to_json()?)?;
            object.insert("limit", self.limit.to_json()?)?;
            object.insert("bytes", self.bytes.to_json()?)?;
            object.insert("tags", self.tags.to_json()?)?;
            if let Some(note) = &self.note {
                object.insert("note", note.to_json()?)?;
            }
            Ok(Value::Object(object))
        }
    }

    impl FromJson for Params {
        fn from_json(value: &Value) -> Result<Self, JsonError> {
            let mut fields = Fields::new(value)?;
            let params = Self {
                session: fields.required("session")?,
                limit: fields.required("limit")?,
                bytes: fields.required("bytes")?,
                tags: fields.required("tags")?,
                note: fields.optional("note")?,
            };
            fields.finish()?;
            Ok(params)
        }
    }

    fn read(json: &str) -> Result<Params, JsonError> {
        Params::from_json(&parse(json.as_bytes(), 4096).unwrap())
    }

    #[test]
    fn typed_struct_round_trips() {
        let params = Params {
            session: "s".into(),
            limit: 7,
            bytes: IntString(i128::from(u64::MAX)),
            tags: vec!["a".into(), "b".into()],
            note: Some("n".into()),
        };
        let text = write(&params.to_json().unwrap()).unwrap();
        assert_eq!(
            text,
            r#"{"session":"s","limit":7,"bytes":"18446744073709551615","tags":["a","b"],"note":"n"}"#
        );
        assert_eq!(read(&text), Ok(params));
    }

    #[test]
    fn from_json_reports_missing_field_by_name() {
        let error = read(r#"{"session":"s","bytes":"1","tags":[]}"#).unwrap_err();
        assert_eq!(error, JsonError::MissingField("limit"));
        assert_eq!(error.to_string(), "missing field `limit`");
    }

    #[test]
    fn from_json_reports_wrong_type_and_range_by_name() {
        let base = r#""session":"s","bytes":"1","tags":[]"#;
        let wrong = |limit: &str| read(&format!("{{{base},\"limit\":{limit}}}")).unwrap_err();
        let expected_integer = JsonError::WrongType {
            field: Some("limit"),
            expected: Kind::Integer,
        };
        assert_eq!(wrong(r#""7""#), expected_integer);
        assert_eq!(wrong("1.5"), expected_integer);
        assert_eq!(wrong("-1"), JsonError::OutOfRange { field: Some("limit") });
        assert_eq!(wrong("4294967296"), JsonError::OutOfRange { field: Some("limit") });
        assert_eq!(
            read(r#"{"session":"s","limit":1,"bytes":"1","tags":[1]}"#),
            Err(JsonError::WrongType {
                field: Some("tags"),
                expected: Kind::String
            })
        );
        assert_eq!(
            read(r#"{"session":"s","limit":1,"bytes":"01","tags":[]}"#),
            Err(JsonError::OutOfRange { field: Some("bytes") })
        );
        assert_eq!(
            Params::from_json(&Value::Null),
            Err(JsonError::WrongType {
                field: None,
                expected: Kind::Object
            })
        );
    }

    #[test]
    fn from_json_ignores_unknown_optional_fields() {
        // Additive protocol (handshake.md "Rules"): a newer peer's extra fields are ignored.
        let params = read(r#"{"session":"s","limit":2.0,"bytes":"5","tags":[],"added_later":{"x":[1]}}"#).unwrap();
        assert_eq!(params.limit, 2);
        assert_eq!(params.note, None);
        let params = read(r#"{"session":"s","limit":1,"bytes":"5","tags":[],"note":null}"#).unwrap();
        assert_eq!(params.note, None);
    }

    #[test]
    fn closed_object_reports_unknown_field() {
        let value = parse(br#"{"known":1,"unknown":2}"#, 64).unwrap();
        let mut fields = Fields::new(&value).unwrap();
        let _: u8 = fields.required("known").unwrap();
        assert_eq!(fields.finish_closed(), Err(JsonError::UnknownField));

        let mut fields = Fields::new(&value).unwrap();
        let _: u8 = fields.required("known").unwrap();
        let _: Option<u8> = fields.optional("unknown").unwrap();
        assert_eq!(fields.finish_closed(), Ok(()));
    }

    #[test]
    fn wide_integers_refuse_number_form() {
        assert_eq!(u64::MAX.to_json(), Err(JsonError::IntegerOutOfRange));
        assert_eq!((1_u64 << 53).to_json(), Value::int(1 << 53));
        assert_eq!(((1_u64 << 53) + 1).to_json(), Err(JsonError::IntegerOutOfRange));
    }
}
