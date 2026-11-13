//! The crate's single error type.
//!
//! Messages never echo the rejected input: a path or identifier may come from an untrusted agent line or carry
//! private data, and errors are logged and sent over the wire (NFR-PRIV-02).

use std::fmt;

use crate::session::{SessionState, Transition};

/// Every way a `knsh-core` constructor or parser can refuse its input.
///
/// Variants carry only positions and lengths, never the offending text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoreError {
    /// A ULID string did not have exactly 26 characters. Carries the length that was seen, in bytes.
    UlidLength(usize),
    /// A ULID string held a character outside the uppercase Crockford base32 alphabet. Carries its byte index.
    UlidInvalidChar(usize),
    /// A ULID string's first character was above `7`, so the value would not fit in 128 bits.
    UlidOverflow,
    /// A ULID time was above the 48-bit maximum (`2^48 - 1` milliseconds).
    UlidTimeOutOfRange,
    /// A canonical path was empty.
    PathEmpty,
    /// A canonical path did not start with `/`.
    PathRelative,
    /// A canonical path contained a `.` or `..` component.
    PathDotComponent,
    /// A canonical path contained an empty component (`//`) or a trailing `/`.
    PathEmptyComponent,
    /// A canonical path contained a NUL byte, which no real path can contain.
    PathNul,
    /// A timestamp was outside the range RFC 3339 can express (years 1970 to 9999 here).
    TimestampOutOfRange,
    /// A timestamp text was not in the engine's RFC 3339 form (`YYYY-MM-DDTHH:MM:SS[.ffffff]Z`) or named an
    /// impossible date or time.
    InvalidTimestamp,
    /// A record or output stream name was not one the model defines (`stdout` or `stderr`).
    InvalidOutputStream,
    /// An agent identifier was empty, too long or held a character outside `[A-Za-z0-9._-]`.
    InvalidAgentId,
    /// A profile name was empty, too long or held a character outside `[A-Za-z0-9._-]`.
    InvalidProfileName,
    /// An agent actor had no `agent_id` (`specs/05-models/session.md`).
    AgentIdRequired,
    /// A human actor carried an `agent_id`, which only agents have.
    AgentIdForHuman,
    /// A human session asked for an envelope; envelopes exist only for agent sessions.
    EnvelopeForHuman,
    /// The state diagram has no edge for this transition from this state. The session is unchanged.
    InvalidTransition {
        /// The state the session was, and still is, in.
        from: SessionState,
        /// The transition that was refused.
        transition: Transition,
    },
    /// No live session has this identifier: it never existed or has ended (`-32006`).
    SessionNotFoundOrEnded,
    /// A live session already has this identifier.
    SessionExists,
    /// The parent named by `parent_session_id` is not a live session (FR-SES-03).
    ParentNotFoundOrEnded,
    /// An agent child's profile is not equal to or stricter than its parent's (FR-SES-03).
    ProfileNotStricter,
    /// A human session named an agent session as its parent; a human session inside an agent session would escape
    /// the agent's profile (FR-SES-03, FR-SES-12).
    HumanChildOfAgent,
    /// An event named a different actor than the one its session started with (FR-SES-01).
    EventActorMismatch,
    /// `since_seq` was given without a session, or is newer than the session's latest event (KNSH-018).
    InvalidSinceSeq,
}

impl fmt::Display for CoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UlidLength(len) => write!(f, "ULID must be 26 characters, got {len}"),
            Self::UlidInvalidChar(index) => write!(f, "ULID has an invalid character at index {index}"),
            Self::UlidOverflow => f.write_str("ULID overflows 128 bits (first character above 7)"),
            Self::UlidTimeOutOfRange => f.write_str("ULID time exceeds 48 bits"),
            Self::PathEmpty => f.write_str("canonical path is empty"),
            Self::PathRelative => f.write_str("canonical path is not absolute"),
            Self::PathDotComponent => f.write_str("canonical path contains a '.' or '..' component"),
            Self::PathEmptyComponent => f.write_str("canonical path contains an empty component or trailing '/'"),
            Self::PathNul => f.write_str("canonical path contains a NUL byte"),
            Self::TimestampOutOfRange => f.write_str("timestamp is outside 1970-01-01 to 9999-12-31 UTC"),
            Self::InvalidTimestamp => f.write_str("timestamp must be YYYY-MM-DDTHH:MM:SS[.ffffff]Z"),
            Self::InvalidOutputStream => f.write_str("output stream must be stdout or stderr"),
            Self::InvalidAgentId => f.write_str("agent_id must be 1 to 64 characters from [A-Za-z0-9._-]"),
            Self::InvalidProfileName => f.write_str("profile name must be 1 to 64 characters from [A-Za-z0-9._-]"),
            Self::AgentIdRequired => f.write_str("an agent session requires actor.agent_id"),
            Self::AgentIdForHuman => f.write_str("a human session must not have actor.agent_id"),
            Self::EnvelopeForHuman => f.write_str("a human session cannot have an envelope"),
            Self::InvalidTransition { from, transition } => {
                write!(f, "cannot {} a session that is {from}", transition.as_str())
            }
            Self::SessionNotFoundOrEnded => f.write_str("session not found or ended"),
            Self::SessionExists => f.write_str("a session with this id already exists"),
            Self::ParentNotFoundOrEnded => f.write_str("parent session not found or ended"),
            Self::ProfileNotStricter => {
                f.write_str("a child agent's profile must equal or be stricter than its parent's")
            }
            Self::HumanChildOfAgent => f.write_str("a human session cannot be started inside an agent session"),
            Self::EventActorMismatch => f.write_str("an event's actor must be its session's actor"),
            Self::InvalidSinceSeq => {
                f.write_str("since_seq needs a session and must not be newer than its latest event")
            }
        }
    }
}

impl std::error::Error for CoreError {}
