//! The crate's error types: [`CoreError`] for every constructor and parser, and [`ProfileError`] for the policy
//! profile loader (KNSH-039), which must name the key at fault and so cannot be `Copy` like `CoreError`.
//!
//! Messages never echo the rejected input: a path or identifier may come from an untrusted agent line or carry
//! private data, and errors are logged and sent over the wire (NFR-PRIV-02).

use std::fmt;

use crate::session::{ProfileName, SessionState, Transition};

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
    /// A record's decision verdict was not `allow`, `deny` or `rewrite`.
    InvalidDecision,
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
    /// A grant's rule is not a command pattern: blank, too long, holding a control character, or naming a path
    /// rather than a program (KNSH-042).
    InvalidGrantRule,
    /// A grant was created already expired, so it could never apply (KNSH-042).
    GrantExpired,
    /// A live grant already has this identifier (KNSH-042).
    GrantExists,
    /// No live grant has this identifier: it never existed, was revoked, or has expired (`policy.revoke`, FR-POL-61).
    GrantNotFound,
    /// The grant set already holds its maximum number of live grants (KNSH-042).
    TooManyGrants,
    /// Text is not a knsh sandbox tag `knsh:<session>:<command>:<rule>` (FR-SBX-06, KNSH-047).
    InvalidDenialTag,
    /// A stored list of sandbox violations is not in the form the engine writes (KNSH-047).
    InvalidViolation,
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
            Self::InvalidDecision => f.write_str("decision verdict must be allow, deny or rewrite"),
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
            Self::InvalidGrantRule => {
                f.write_str("a grant rule must be a command pattern: a program name without '/', then its arguments")
            }
            Self::GrantExpired => f.write_str("the grant has already expired"),
            Self::GrantExists => f.write_str("a grant with this id already exists"),
            Self::GrantNotFound => f.write_str("grant not found, revoked or expired"),
            Self::TooManyGrants => f.write_str("too many live grants"),
            Self::InvalidDenialTag => f.write_str("not a knsh sandbox tag"),
            Self::InvalidViolation => f.write_str("not a stored list of sandbox violations"),
        }
    }
}

impl std::error::Error for CoreError {}

/// Why a policy profile was refused (KNSH-039). Wrapped in [`ProfileError`] with where it happened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProfileErrorKind {
    /// The text is not valid TOML from the supported subset.
    Syntax(knsh_toml::TomlError),
    /// A key the profile model does not define (`specs/05-models/policy-profile.md#keys`).
    UnknownKey,
    /// A key has a value of the wrong TOML type. Carries what was expected.
    WrongType {
        /// The expected type, for example `"a list of strings"`.
        expected: &'static str,
    },
    /// A value has the right type but is not one the key accepts. Carries what was expected.
    InvalidValue {
        /// What the key accepts, for example `"allow, ask or deny"`.
        expected: &'static str,
    },
    /// A required key is missing (a profile's `name`, a secret's `secret`).
    MissingKey,
    /// A profile loaded by name says a different `name`, so its file and its contents disagree.
    NameMismatch,
    /// `extends` leads back to a profile already in the chain.
    ExtendsCycle,
    /// The `extends` chain is longer than [`MAX_EXTENDS_DEPTH`](crate::MAX_EXTENDS_DEPTH).
    ExtendsTooDeep,
    /// No profile with this name exists in the profile source.
    ProfileNotFound,
    /// The profile source has the profile but could not read it.
    ProfileUnreadable,
    /// `preset` names no preset the engine ships.
    UnknownPreset,
    /// A preset sets a key presets may not set: presets only add to lists (`fs.write`, `network.hosts`, …).
    NotAllowedInPreset,
    /// A path uses a variable other than `${PROJECT}`, `${HOME}` and `${TMPDIR}`, or uses one anywhere but at its
    /// start.
    UnknownVariable,
    /// A path is not absolute after expansion, holds a `..` component or a NUL byte, uses `~user`, or is longer
    /// than 4096 bytes.
    InvalidPath,
    /// A path could not be resolved to canonical form: the filesystem refused a lookup other than "not found".
    PathUnresolvable,
    /// `${HOME}`, `${TMPDIR}` or the session's start directory could not be resolved to an existing canonical
    /// directory, so no path using them can be expanded.
    VariableUnresolvable,
    /// A key that grants access (`fs.read` as a list, `fs.write`, `exec.trusted_folders`, `exec.bash`,
    /// `checkpoints.roots`) names an engine path or a path below one, which every profile must deny (FR-POL-30).
    FixedDeny,
}

impl fmt::Display for ProfileErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Syntax(error) => write!(f, "invalid TOML: {error}"),
            Self::UnknownKey => f.write_str("unknown key"),
            Self::WrongType { expected } => write!(f, "wrong type, expected {expected}"),
            Self::InvalidValue { expected } => write!(f, "invalid value, expected {expected}"),
            Self::MissingKey => f.write_str("required key is missing"),
            Self::NameMismatch => f.write_str("name does not match the name the profile was loaded by"),
            Self::ExtendsCycle => f.write_str("extends chain forms a cycle"),
            Self::ExtendsTooDeep => write!(f, "extends chain is longer than {} profiles", crate::MAX_EXTENDS_DEPTH),
            Self::ProfileNotFound => f.write_str("profile not found"),
            Self::ProfileUnreadable => f.write_str("profile could not be read"),
            Self::UnknownPreset => f.write_str("unknown preset"),
            Self::NotAllowedInPreset => f.write_str("presets may only add to path and host lists"),
            Self::UnknownVariable => {
                f.write_str("unknown variable: only ${PROJECT}, ${HOME} and ${TMPDIR}, at the start of a path")
            }
            Self::InvalidPath => f.write_str("path must be absolute after expansion, without '..', '~user' or NUL"),
            Self::PathUnresolvable => f.write_str("path could not be resolved to canonical form"),
            Self::VariableUnresolvable => f.write_str("path variable could not be resolved to an existing directory"),
            Self::FixedDeny => f.write_str("path is an engine path, which every profile denies (FR-POL-30)"),
        }
    }
}

/// Where a profile error was found: which profile or preset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProfileOrigin {
    /// A profile, by name.
    Profile(ProfileName),
    /// A preset the engine ships, by name.
    Preset(&'static str),
}

impl fmt::Display for ProfileOrigin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Profile(name) => write!(f, "profile {name}"),
            Self::Preset(name) => write!(f, "preset {name}"),
        }
    }
}

/// A policy profile that was refused, and where (KNSH-039).
///
/// Loading is all or nothing: when this is returned, no part of the profile is in effect (the loader builds a new
/// value and never mutates one in place).
///
/// Unlike [`CoreError`], this names the offending key (`fs.write[1]`, `exec.interpreters.lua`): a profile is the
/// user's own configuration, not an agent command line, and the acceptance criteria require the key to be named.
/// Values are still never echoed. A key the model does not define is shown escaped and cut to
/// [`MAX_KEY_DISPLAY_LEN`] characters, so a hostile file cannot inject control characters into logs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileError {
    kind: ProfileErrorKind,
    origin: Option<ProfileOrigin>,
    key: Option<String>,
    position: Option<knsh_toml::Position>,
}

/// Longest key text a [`ProfileError`] shows, in characters, before it is cut with `…`.
pub const MAX_KEY_DISPLAY_LEN: usize = 128;

impl ProfileError {
    pub(crate) fn new(kind: ProfileErrorKind) -> Self {
        Self {
            kind,
            origin: None,
            key: None,
            position: None,
        }
    }

    pub(crate) fn at_key(mut self, key: &str) -> Self {
        self.key = Some(display_key(key));
        self
    }

    pub(crate) fn at(mut self, position: knsh_toml::Position) -> Self {
        self.position = Some(position);
        self
    }

    /// Sets the origin unless an inner step already did: the innermost origin is the most precise.
    pub(crate) fn in_origin(mut self, origin: &ProfileOrigin) -> Self {
        if self.origin.is_none() {
            self.origin = Some(origin.clone());
        }
        self
    }

    /// Why the profile was refused.
    #[must_use]
    pub fn kind(&self) -> &ProfileErrorKind {
        &self.kind
    }

    /// The profile or preset at fault, when known (a syntax error in a snapshot comes before its name is read).
    #[must_use]
    pub fn origin(&self) -> Option<&ProfileOrigin> {
        self.origin.as_ref()
    }

    /// The dotted key at fault, with a list index where one applies (`fs.write[1]`), when there is one.
    #[must_use]
    pub fn key(&self) -> Option<&str> {
        self.key.as_deref()
    }

    /// Where in the file the problem is, when known.
    #[must_use]
    pub fn position(&self) -> Option<knsh_toml::Position> {
        self.position
    }
}

/// Escapes control and non-ASCII characters in a key and cuts it to [`MAX_KEY_DISPLAY_LEN`] characters.
fn display_key(key: &str) -> String {
    let mut shown = String::new();
    for (count, c) in key.chars().enumerate() {
        if count == MAX_KEY_DISPLAY_LEN {
            shown.push('…');
            break;
        }
        if c.is_ascii_graphic() || c == ' ' {
            shown.push(c);
        } else {
            shown.extend(c.escape_default());
        }
    }
    shown
}

impl fmt::Display for ProfileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(origin) = &self.origin {
            write!(f, "{origin}: ")?;
        }
        if let Some(position) = &self.position {
            write!(f, "{position}: ")?;
        }
        if let Some(key) = &self.key {
            write!(f, "{key}: ")?;
        }
        write!(f, "{}", self.kind)
    }
}

impl std::error::Error for ProfileError {}
