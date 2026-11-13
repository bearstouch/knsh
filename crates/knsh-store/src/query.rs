//! What a caller may ask of the store: the scope it sees, record filters with paging, and output ranges.
//!
//! Pure values with no I/O; the store turns them into bound SQL parameters.

use knsh_core::{ExecutionRecord, OutputInfo, OutputStream, RecordId, SessionId, Timestamp};

/// The default number of records per page.
pub const DEFAULT_PAGE_SIZE: u32 = 100;

/// The largest page a caller may ask for. Bounds the memory and time of one query.
pub const MAX_PAGE_SIZE: u32 = 1_000;

/// Which records a caller can see.
///
/// The store applies the scope inside every query, so a handler cannot return records outside it by building the
/// wrong filter: `user.sock` sees [`Scope::All`]; `agent.sock` (phase 2) sees only [`Scope::Session`] of its own
/// session (`specs/06-api/agent-socket.md`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Scope {
    /// Every session (read-only observers and the CLI on `user.sock`).
    All,
    /// Only this session's records.
    Session(SessionId),
}

/// A page size between 1 and [`MAX_PAGE_SIZE`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PageSize(u32);

impl PageSize {
    /// A page size, or `None` outside `1..=MAX_PAGE_SIZE`.
    #[must_use]
    pub const fn new(size: u32) -> Option<Self> {
        if size == 0 || size > MAX_PAGE_SIZE {
            None
        } else {
            Some(Self(size))
        }
    }

    /// The size.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

impl Default for PageSize {
    fn default() -> Self {
        Self(DEFAULT_PAGE_SIZE)
    }
}

/// Filters for one page of records. All filters combine with AND; results are ordered by `record_id`.
#[derive(Debug, Clone, Default)]
pub struct RecordQuery {
    /// Only this session's records.
    pub session: Option<SessionId>,
    /// Only records started at or after this instant (inclusive).
    pub since: Option<Timestamp>,
    /// Only records started before this instant (exclusive).
    pub until: Option<Timestamp>,
    /// Only records whose `command` contains this text, case-sensitively. The API bounds its length.
    pub text: Option<String>,
    /// The cursor: only records after this one. Pass the previous page's [`Page::next_cursor`].
    pub after: Option<RecordId>,
    /// How many records at most.
    pub limit: PageSize,
}

/// A record as stored, with what was kept of its output.
#[derive(Debug, Clone)]
pub struct StoredRecord {
    /// The record.
    pub record: ExecutionRecord,
    /// The stored standard output, if output was recorded.
    pub stdout: Option<OutputInfo>,
    /// The stored standard error, if output was recorded.
    pub stderr: Option<OutputInfo>,
}

/// One page of records.
#[derive(Debug, Clone)]
pub struct Page {
    /// The records, ordered by `record_id`.
    pub records: Vec<StoredRecord>,
    /// The cursor for the next page, or `None` when this page is the last.
    pub next_cursor: Option<RecordId>,
}

/// Which records `forget` deletes (FR-REC-10): a session's, those started at or after an instant, or both
/// combined with AND.
///
/// At least one selector is always set: there is no way to build a selector that matches every record by accident.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ForgetSelector {
    session: Option<SessionId>,
    since: Option<Timestamp>,
}

impl ForgetSelector {
    /// A selector, or `None` when neither `session` nor `since` is given.
    #[must_use]
    pub const fn new(session: Option<SessionId>, since: Option<Timestamp>) -> Option<Self> {
        if session.is_none() && since.is_none() {
            None
        } else {
            Some(Self { session, since })
        }
    }

    /// Only this session's records.
    #[must_use]
    pub const fn session(&self) -> Option<SessionId> {
        self.session
    }

    /// Only records started at or after this instant (inclusive).
    #[must_use]
    pub const fn since(&self) -> Option<Timestamp> {
        self.since
    }
}

/// A byte range of one record's stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct OutputRequest {
    /// The record.
    pub record_id: RecordId,
    /// The stream.
    pub stream: OutputStream,
    /// The first byte, in the stored bytes.
    pub offset: u64,
    /// At most this many bytes; `None` reads to the end.
    pub length: Option<u64>,
}

/// The bytes of a range, clamped to what is stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutputRange {
    /// What was kept of the stream; `None` when no output was recorded for it (all sizes then read as zero).
    pub info: Option<OutputInfo>,
    /// The offset actually read: the requested one, clamped to the stored size.
    pub offset: u64,
    /// The bytes, at most the requested length.
    pub data: Vec<u8>,
}

/// Clamps `offset` and `length` to a stream of `size` bytes: ranges beyond the end are cut, never refused.
#[must_use]
pub(crate) fn clamp(size: u64, offset: u64, length: Option<u64>) -> (u64, u64) {
    let offset = offset.min(size);
    let available = size - offset;
    (offset, length.map_or(available, |length| length.min(available)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn page_size_is_bounded() {
        assert_eq!(PageSize::new(0), None);
        assert_eq!(PageSize::new(MAX_PAGE_SIZE + 1), None);
        assert_eq!(PageSize::new(1).map(PageSize::get), Some(1));
        assert_eq!(PageSize::default().get(), DEFAULT_PAGE_SIZE);
    }

    // `forget` can never match every record by accident: one selector is required.
    #[test]
    fn forget_selector_requires_a_selector() {
        assert_eq!(ForgetSelector::new(None, None), None);
        let session = SessionId::from_ulid(knsh_core::Ulid::from_u128(1));
        let selector = ForgetSelector::new(Some(session), None).unwrap();
        assert_eq!((selector.session(), selector.since()), (Some(session), None));
        let since = ForgetSelector::new(None, Some(Timestamp::UNIX_EPOCH)).unwrap();
        assert_eq!(since.since(), Some(Timestamp::UNIX_EPOCH));
    }

    #[test]
    fn ranges_beyond_the_end_are_clamped() {
        assert_eq!(clamp(10, 0, None), (0, 10));
        assert_eq!(clamp(10, 4, Some(3)), (4, 3));
        assert_eq!(clamp(10, 8, Some(5)), (8, 2));
        assert_eq!(clamp(10, 50, Some(5)), (10, 0));
        assert_eq!(clamp(10, u64::MAX, None), (10, 0));
        assert_eq!(clamp(0, 0, Some(1)), (0, 0));
    }
}
