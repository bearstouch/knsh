//! Typed identifiers over [`Ulid`].
//!
//! Each kind of identifier is its own newtype, so passing a [`RecordId`] where a [`SessionId`] is expected fails to
//! compile. There is deliberately no `From`/`Into` between ID types, nor from or to [`Ulid`]: wrapping and unwrapping
//! go through the named [`from_ulid`](SessionId::from_ulid) and [`ulid`](SessionId::ulid) methods, so every
//! conversion is visible at the call site.
//!
//! Specification: `specs/05-models/session.md` (`session_id`), `specs/05-models/execution-record.md` (`record_id`,
//! `checkpoint_id`).

use std::fmt;
use std::str::FromStr;

use crate::error::CoreError;
use crate::ulid::Ulid;

/// Defines one ID newtype with its docs, explicit conversions, text form and parsing.
macro_rules! ulid_id {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        ///
        /// # Invariants
        ///
        /// Wraps exactly one [`Ulid`], so it orders by creation time, displays as 26 uppercase Crockford characters
        /// and parses only that form. It converts to and from other ID types only through an explicit [`Ulid`].
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(Ulid);

        impl $name {
            /// Wraps a ULID as this kind of identifier.
            #[must_use]
            pub const fn from_ulid(ulid: Ulid) -> Self {
                Self(ulid)
            }

            /// The underlying ULID.
            #[must_use]
            pub const fn ulid(self) -> Ulid {
                self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Display::fmt(&self.0, f)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, concat!(stringify!($name), "({})"), self.0)
            }
        }

        impl FromStr for $name {
            type Err = CoreError;

            /// Parses the canonical ULID text form; see [`Ulid`]'s `FromStr` for the rules and errors.
            fn from_str(s: &str) -> Result<Self, Self::Err> {
                s.parse().map(Self)
            }
        }
    };
}

ulid_id! {
    /// Identifies a session (`session_id`).
    SessionId
}

ulid_id! {
    /// Identifies an execution record (`record_id`).
    RecordId
}

ulid_id! {
    /// Identifies an event on the event bus.
    EventId
}

ulid_id! {
    /// Identifies an approval request sent to the authority.
    RequestId
}

ulid_id! {
    /// Identifies a checkpoint holding pre-images (`checkpoint_id`).
    CheckpointId
}

ulid_id! {
    /// Identifies a grant issued by the authority.
    GrantId
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_wrap_ulid_and_share_its_text_form() {
        let ulid = Ulid::new(1_700_000_000_000, [7; 10]).unwrap();
        let session = SessionId::from_ulid(ulid);
        assert_eq!(session.ulid(), ulid);
        assert_eq!(session.to_string(), ulid.to_string());
        assert_eq!(session.to_string().parse::<SessionId>().unwrap(), session);
        assert_eq!(format!("{session:?}"), format!("SessionId({ulid})"));
        assert_eq!(format!("{:?}", GrantId::from_ulid(ulid)), format!("GrantId({ulid})"));
        assert_eq!("bad".parse::<RecordId>(), Err(CoreError::UlidLength(3)));
    }

    #[test]
    fn ids_order_by_creation_time() {
        let older = EventId::from_ulid(Ulid::new(1, [0xFF; 10]).unwrap());
        let newer = EventId::from_ulid(Ulid::new(2, [0; 10]).unwrap());
        assert!(older < newer);
    }

    // There is no runtime test that `SessionId` and `RecordId` cannot be mixed: that is a compile-time property.
    // The doctest below fails to compile if anyone adds an implicit conversion.
}

/// Compile-time check that ID types do not convert implicitly.
///
/// ```compile_fail
/// use knsh_core::{RecordId, SessionId, Ulid};
/// fn takes_session(_: SessionId) {}
/// let record = RecordId::from_ulid(Ulid::from_u128(1));
/// takes_session(record);
/// ```
///
/// ```compile_fail
/// use knsh_core::{SessionId, Ulid};
/// let _: SessionId = Ulid::from_u128(1).into();
/// ```
#[cfg(doctest)]
pub struct NoImplicitIdConversion;
