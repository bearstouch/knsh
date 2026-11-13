//! Record retention settings and the pure arithmetic behind them (FR-REC-07, KNSH-017).
//!
//! Records are removed when they are older than their retention period or when the store grows past its size limit,
//! whichever comes first. The period is configurable per profile (`recording.retention_days`); the size limit is one
//! limit for the whole store, because the store is one file shared by every session.
//!
//! # Which period applies to a record
//!
//! A store holds records of sessions with different profiles. Each record is kept for the period of **its own
//! session's profile** ([`Retention::per_profile`]), falling back to [`Retention::days`] when the profile has no
//! override or the session row is missing. So shortening one profile's retention never removes another profile's
//! records early (`specs/03-functional-requirements/execution-records.md#retention`).
//!
//! # Size
//!
//! The size of the store is the space its live pages take: `(page_count - freelist_count) * page_size`. Deleting
//! records returns their pages to SQLite's free list, which new records reuse, so the file stays bounded near the
//! limit without a `VACUUM` (which would rewrite the whole file and block writes).
//!
//! Nothing here does I/O: the store thread ([`crate::RecordStore`]) runs the deletes, and time comes from the clock
//! injected into it.

use std::collections::BTreeMap;
use std::time::Duration;

use knsh_core::{ProfileName, Timestamp};

/// The default retention period, in days (`specs/09-reference/defaults-and-limits.md`).
pub const DEFAULT_RETENTION_DAYS: u32 = 30;

/// The longest retention period a profile may set, in days (100 years). Bounds the arithmetic, and no longer period
/// is meaningful for a record store.
pub const MAX_RETENTION_DAYS: u32 = 36_500;

/// The default size limit of the store: 2 GB (`specs/09-reference/defaults-and-limits.md`).
pub const DEFAULT_MAX_BYTES: u64 = 2 << 30;

/// How often retention runs while `knshd` is up. It also runs once when the store opens.
pub const RETENTION_INTERVAL: Duration = Duration::from_hours(1);

/// The most records one retention batch deletes. Each batch is its own transaction, and queued reads and writes are
/// served between batches, so a large clean-up never holds the store for long.
pub const RETENTION_BATCH: u32 = 500;

const MICROS_PER_DAY: u64 = 86_400 * 1_000_000;

/// A retention period in days, between 1 and [`MAX_RETENTION_DAYS`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RetentionDays(u32);

impl RetentionDays {
    /// A period of `days`, or `None` outside `1..=MAX_RETENTION_DAYS`. Zero is refused: a profile cannot ask for
    /// records to be deleted as soon as they are written (it turns recording off instead).
    #[must_use]
    pub const fn new(days: u32) -> Option<Self> {
        if days == 0 || days > MAX_RETENTION_DAYS {
            None
        } else {
            Some(Self(days))
        }
    }

    /// The number of days.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }

    /// The instant before which a record started `now` has expired: `now` minus the period, or the epoch if the
    /// period reaches further back.
    #[must_use]
    pub fn cutoff(self, now: Timestamp) -> Timestamp {
        let period = u64::from(self.0) * MICROS_PER_DAY;
        let micros = now.as_unix_micros().saturating_sub(period);
        // Any value between the epoch and a valid `now` is a valid timestamp. The fallback is the epoch, before which no
        // record starts: on any doubt, delete nothing.
        Timestamp::from_unix_micros(micros).unwrap_or(Timestamp::UNIX_EPOCH)
    }
}

impl Default for RetentionDays {
    fn default() -> Self {
        Self(DEFAULT_RETENTION_DAYS)
    }
}

/// When records are deleted automatically (FR-REC-07).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Retention {
    /// The period for records whose session's profile has no override, or whose session is unknown.
    pub days: RetentionDays,
    /// Per-profile periods (`recording.retention_days`), applied to each record by its session's profile.
    pub per_profile: BTreeMap<ProfileName, RetentionDays>,
    /// The most bytes the store's live pages may take; beyond it the oldest records are deleted.
    pub max_bytes: u64,
}

impl Default for Retention {
    /// 30 days or 2 GB, whichever comes first, with no per-profile overrides.
    fn default() -> Self {
        Self {
            days: RetentionDays::default(),
            per_profile: BTreeMap::new(),
            max_bytes: DEFAULT_MAX_BYTES,
        }
    }
}

/// The cutoffs of one retention pass, all taken from a single reading of the clock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Cutoffs {
    /// The cutoff for records without a per-profile override.
    pub(crate) default: Timestamp,
    /// The cutoff of each profile with an override.
    pub(crate) per_profile: Vec<(ProfileName, Timestamp)>,
}

impl Cutoffs {
    /// The cutoffs of `retention` at `now`.
    pub(crate) fn at(retention: &Retention, now: Timestamp) -> Self {
        Self {
            default: retention.days.cutoff(now),
            per_profile: retention
                .per_profile
                .iter()
                .map(|(profile, days)| (profile.clone(), days.cutoff(now)))
                .collect(),
        }
    }

    /// The latest cutoff of all: no record started at or after it can have expired. Lets the delete use the
    /// `started_at` index instead of reading every record.
    pub(crate) fn latest(&self) -> Timestamp {
        self.per_profile
            .iter()
            .map(|(_, cutoff)| *cutoff)
            .fold(self.default, Timestamp::max)
    }
}

/// What one retention pass deleted.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RetentionReport {
    /// Records deleted because they were older than their retention period.
    pub expired: u64,
    /// Records deleted, oldest first, to bring the store under its size limit.
    pub trimmed: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at_day(day: u64) -> Timestamp {
        Timestamp::from_unix_micros(day * MICROS_PER_DAY).unwrap()
    }

    // FR-REC-07 defaults: 30 days or 2 GB.
    #[test]
    fn defaults_are_thirty_days_or_two_gigabytes() {
        let retention = Retention::default();
        assert_eq!(retention.days.get(), 30);
        assert_eq!(retention.max_bytes, 2 * 1024 * 1024 * 1024);
        assert!(retention.per_profile.is_empty());
    }

    #[test]
    fn retention_days_are_bounded() {
        assert_eq!(RetentionDays::new(0), None);
        assert_eq!(RetentionDays::new(MAX_RETENTION_DAYS + 1), None);
        assert_eq!(RetentionDays::new(7).map(RetentionDays::get), Some(7));
        assert_eq!(RetentionDays::default().get(), DEFAULT_RETENTION_DAYS);
    }

    #[test]
    fn cutoff_is_now_minus_the_period_and_never_before_the_epoch() {
        let thirty = RetentionDays::new(30).unwrap();
        assert_eq!(thirty.cutoff(at_day(100)), at_day(70));
        assert_eq!(thirty.cutoff(at_day(10)), at_day(0));
    }

    #[test]
    fn latest_cutoff_covers_every_profile() {
        let mut retention = Retention::default();
        retention
            .per_profile
            .insert(ProfileName::new("short").unwrap(), RetentionDays::new(1).unwrap());
        retention
            .per_profile
            .insert(ProfileName::new("long").unwrap(), RetentionDays::new(90).unwrap());
        let cutoffs = Cutoffs::at(&retention, at_day(100));
        assert_eq!(cutoffs.default, at_day(70));
        assert_eq!(
            cutoffs.latest(),
            at_day(99),
            "the shortest period sets the latest cutoff"
        );
    }
}
