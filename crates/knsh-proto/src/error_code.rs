//! The JSON-RPC error codes: the five standard ones and the engine's `-32001`…`-32011`.
//!
//! [`ErrorCode`] is the only place in the workspace where these numbers appear (CLAUDE.md "Errors"); every other crate
//! names a code by its variant. Meanings and `data` fields follow `specs/06-api/errors.md`, and the unit test
//! `error_codes_match_spec_table` reads that page to keep the two in step.

use std::fmt;

/// A JSON-RPC error code the engine sends or understands.
///
/// The set is closed: a response with any other code is refused when read
/// ([`EnvelopeFault::UnknownErrorCode`](crate::EnvelopeFault::UnknownErrorCode)), so a peer cannot make a client act
/// on a code it does not know.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErrorCode {
    /// `-32700`: the message is not strict-profile JSON (`specs/06-api/wire-format.md#strict-json-profile`).
    ParseError,
    /// `-32600`: strict JSON, but not a valid JSON-RPC envelope (`specs/06-api/README.md#envelope`).
    InvalidRequest,
    /// `-32601`: the method name is malformed, unknown or not available on this endpoint.
    MethodNotFound,
    /// `-32602`: `params` does not match the method's parameters.
    InvalidParams,
    /// `-32603`: the engine failed to build its answer.
    InternalError,
    /// `-32001`: denied by policy, hook, authority or rate limit. `data`: `rule_id`, `reason`, `source`.
    Denied,
    /// `-32002`: no decision before the timeout (FR-AUTH-23). `data`: `request_id`.
    DecisionTimeout,
    /// `-32003`: caller not allowed on this endpoint or session. No `data`.
    NotAllowed,
    /// `-32004`: undo, redo or restore conflict (FR-CKP-20, KNSH-086). `data`: `conflicts`.
    UndoConflict,
    /// `-32005`: capability not available on this machine. `data`: `capability`.
    CapabilityUnavailable,
    /// `-32006`: session not found or ended. `data`: `session_id`.
    SessionNotFound,
    /// `-32007`: session paused or under human control; the line is held (FR-SES-10, FR-SES-12). `data`: `state`.
    SessionHeld,
    /// `-32008`: the line exceeded its timeout and was killed (FR-LC-40). `data`: `record_id`.
    LineTimedOut,
    /// `-32009`: session token missing, invalid or expired (FR-AGT-23). No `data`.
    InvalidSessionToken,
    /// `-32010`: checkpoint not ready, the root's shadow is still being built (FR-CKP-02). `data`: `root`, `progress`.
    CheckpointNotReady,
    /// `-32011`: request cancelled. `data`: `request_id`.
    Cancelled,
}

impl ErrorCode {
    /// Every code, standard ones first, then the engine codes in numeric order.
    pub const ALL: [Self; 16] = [
        Self::ParseError,
        Self::InvalidRequest,
        Self::MethodNotFound,
        Self::InvalidParams,
        Self::InternalError,
        Self::Denied,
        Self::DecisionTimeout,
        Self::NotAllowed,
        Self::UndoConflict,
        Self::CapabilityUnavailable,
        Self::SessionNotFound,
        Self::SessionHeld,
        Self::LineTimedOut,
        Self::InvalidSessionToken,
        Self::CheckpointNotReady,
        Self::Cancelled,
    ];

    /// The number sent in the `code` member.
    #[must_use]
    pub const fn code(self) -> i32 {
        match self {
            Self::ParseError => -32700,
            Self::InvalidRequest => -32600,
            Self::MethodNotFound => -32601,
            Self::InvalidParams => -32602,
            Self::InternalError => -32603,
            Self::Denied => -32001,
            Self::DecisionTimeout => -32002,
            Self::NotAllowed => -32003,
            Self::UndoConflict => -32004,
            Self::CapabilityUnavailable => -32005,
            Self::SessionNotFound => -32006,
            Self::SessionHeld => -32007,
            Self::LineTimedOut => -32008,
            Self::InvalidSessionToken => -32009,
            Self::CheckpointNotReady => -32010,
            Self::Cancelled => -32011,
        }
    }

    /// The code for `code`, or `None` if it is not one of ours. Takes `i64` because that is how JSON integers are
    /// read, so an out-of-`i32` value is simply unknown rather than truncated into a known one.
    #[must_use]
    pub fn from_code(code: i64) -> Option<Self> {
        Self::ALL.into_iter().find(|known| i64::from(known.code()) == code)
    }

    /// The meaning, word for word as in the tables of `specs/06-api/errors.md`. It is also the error's `message`, so
    /// the message is fixed text and never echoes anything from the request.
    #[must_use]
    pub const fn meaning(self) -> &'static str {
        match self {
            Self::ParseError => "Parse error",
            Self::InvalidRequest => "Invalid Request",
            Self::MethodNotFound => "Method not found",
            Self::InvalidParams => "Invalid params",
            Self::InternalError => "Internal error",
            Self::Denied => "Denied by policy, hook, authority or rate limit",
            Self::DecisionTimeout => "No decision before the timeout",
            Self::NotAllowed => "Caller not allowed on this endpoint or session",
            Self::UndoConflict => "Undo, redo or restore conflict",
            Self::CapabilityUnavailable => "Capability not available on this machine",
            Self::SessionNotFound => "Session not found or ended",
            Self::SessionHeld => "Session paused or under human control; the line is held",
            Self::LineTimedOut => "The line exceeded its timeout and was killed",
            Self::InvalidSessionToken => "Session token missing, invalid or expired",
            Self::CheckpointNotReady => "Checkpoint not ready: the root's shadow is still being built",
            Self::Cancelled => "Request cancelled",
        }
    }

    /// The top-level fields of this code's `data` object (`specs/06-api/errors.md`), empty when the code carries no
    /// `data`. The stories that raise each engine error build `data` with exactly these fields.
    #[must_use]
    pub const fn data_fields(self) -> &'static [&'static str] {
        match self {
            Self::ParseError
            | Self::InvalidRequest
            | Self::MethodNotFound
            | Self::InvalidParams
            | Self::InternalError
            | Self::NotAllowed
            | Self::InvalidSessionToken => &[],
            Self::Denied => &["rule_id", "reason", "source"],
            Self::DecisionTimeout | Self::Cancelled => &["request_id"],
            Self::UndoConflict => &["conflicts"],
            Self::CapabilityUnavailable => &["capability"],
            Self::SessionNotFound => &["session_id"],
            Self::SessionHeld => &["state"],
            Self::LineTimedOut => &["record_id"],
            Self::CheckpointNotReady => &["root", "progress"],
        }
    }

    /// Whether this is an engine-specific code (`-32001`…`-32011`) rather than a standard JSON-RPC one.
    #[must_use]
    pub const fn is_engine(self) -> bool {
        match self {
            Self::ParseError
            | Self::InvalidRequest
            | Self::MethodNotFound
            | Self::InvalidParams
            | Self::InternalError => false,
            Self::Denied
            | Self::DecisionTimeout
            | Self::NotAllowed
            | Self::UndoConflict
            | Self::CapabilityUnavailable
            | Self::SessionNotFound
            | Self::SessionHeld
            | Self::LineTimedOut
            | Self::InvalidSessionToken
            | Self::CheckpointNotReady
            | Self::Cancelled => true,
        }
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.meaning(), self.code())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One row of a table in `errors.md`: code, meaning, and the backticked names in the third column.
    struct SpecRow {
        code: i64,
        meaning: String,
        data: Vec<String>,
    }

    /// The rows of every table in `errors.md` whose first cell is a number. Reading the page itself (rather than a
    /// copy) is what makes this a conformance test: editing either side alone fails it.
    fn spec_rows() -> Vec<SpecRow> {
        let page = include_str!("../../../specs/06-api/errors.md");
        page.lines()
            .filter_map(|line| {
                let cells: Vec<&str> = line.trim().strip_prefix('|')?.split('|').map(str::trim).collect();
                let code = cells.first()?.parse().ok()?;
                let backticked = |cell: &str| cell.split('`').skip(1).step_by(2).map(str::to_owned).collect();
                Some(SpecRow {
                    code,
                    meaning: (*cells.get(1)?).to_owned(),
                    data: cells.get(2).map(|cell| backticked(cell)).unwrap_or_default(),
                })
            })
            .collect()
    }

    #[test]
    fn error_codes_match_spec_table() {
        let rows = spec_rows();
        assert_eq!(rows.len(), ErrorCode::ALL.len(), "one spec row per code");
        for code in ErrorCode::ALL {
            let matching: Vec<&SpecRow> = rows.iter().filter(|row| row.code == i64::from(code.code())).collect();
            assert_eq!(matching.len(), 1, "{code} appears exactly once in errors.md");
            let row = matching[0];
            assert_eq!(row.meaning, code.meaning(), "meaning of {}", code.code());
            assert_eq!(ErrorCode::from_code(row.code), Some(code));
            // Only the engine table's third column lists `data`; the standard table's says when the code applies.
            if code.is_engine() {
                assert_eq!(row.data, code.data_fields(), "data fields of {}", code.code());
            } else {
                assert_eq!(code.data_fields(), &[] as &[&str]);
            }
        }
    }

    #[test]
    fn engine_codes_are_the_contiguous_range() {
        let engine: Vec<i32> = ErrorCode::ALL
            .iter()
            .filter(|c| c.is_engine())
            .map(|c| c.code())
            .collect();
        assert_eq!(engine, (-32011..=-32001).rev().collect::<Vec<_>>());
    }

    #[test]
    fn unknown_codes_are_not_mapped() {
        for code in [0, -32000, -32012, -32099, -32604, 32700, i64::from(i32::MIN) - 32700] {
            assert_eq!(ErrorCode::from_code(code), None, "{code}");
        }
    }
}
