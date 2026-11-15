//! Rate limiting of repeated denials (KNSH-055; FR-HOOK-20, FR-HOOK-21).
//!
//! A looping agent that keeps sending a line that is denied must stop reaching the authority (or the user) with it.
//! [`DenialLimiter`] counts denials per session and per normalised line ([`LineKey`]): once the same line has been
//! denied [`LIMIT_DENIALS`] times within [`LIMIT_WINDOW`], it is limited for [`LIMIT_DURATION`], and the supervisor
//! denies it with `decision.source = rate_limit` without running hooks or asking anyone.
//! [`DenialLimiter::record_denial`] says when limiting starts ([`Counted::Started`]), exactly once per limiting period,
//! so `command.denied_repeatedly` is emitted once (FR-HOOK-21).
//!
//! # The normalised line
//!
//! The spec does not define "normalised line" (story note, KNSH-055). The key is the line re-serialised with every
//! resolved command's canonical absolute path (KNSH-038, FR-LC-13), trimmed: `ls` and `/bin/ls` reached through
//! `PATH` count as one line, while a different structure, argument or redirection is a different line. A line that
//! cannot be re-serialised is keyed by its text as received. Subcommand options are **not** merged (`git -c a=b push`
//! and `git push` are two lines): merging them would let one denied line limit others that were never denied.
//!
//! # Time
//!
//! Every method takes `now` from the caller's injected clock; nothing here reads a clock. A clock that steps back
//! never extends a limit beyond [`LIMIT_DURATION`] from the time read: such a limit is treated as lifted, and the line
//! goes back to ordinary policy, which can still deny or ask. Rate limiting only keeps asks from flooding the
//! authority; it is never a security boundary.
//!
//! # Memory
//!
//! Bounded for a hostile agent: a key is a 64-bit hash, not the line (lines reach 64 KiB), each session keeps at most
//! [`MAX_TRACKED_LINES`] lines with at most [`LIMIT_DENIALS`] timestamps each, and at most [`MAX_TRACKED_SESSIONS`]
//! sessions are kept. Past a bound, expired entries are dropped first, then the least recently denied one (for lines,
//! one that is not limited first). Losing an entry can only lift a limit early, never deny a line that was not
//! denied.

use std::collections::hash_map::DefaultHasher;
use std::collections::{BTreeMap, VecDeque};
use std::hash::{Hash, Hasher};
use std::time::Duration;

use crate::id::SessionId;
use crate::time::Timestamp;

/// Denials of one line within [`LIMIT_WINDOW`] that start limiting it (FR-HOOK-20).
pub const LIMIT_DENIALS: usize = 5;

/// The window the [`LIMIT_DENIALS`] denials must fall within (FR-HOOK-20). The first and the last must be **less**
/// than this apart: denials exactly 60 s apart from first to last are not within it.
pub const LIMIT_WINDOW: Duration = Duration::from_secs(60);

/// How long a limited line stays limited (FR-HOOK-20).
pub const LIMIT_DURATION: Duration = Duration::from_secs(600);

/// Lines tracked per session. A looping agent repeats few lines; more than this are forgotten oldest first.
pub const MAX_TRACKED_LINES: usize = 256;

/// Sessions tracked at once. The least recently denied session is forgotten first.
pub const MAX_TRACKED_SESSIONS: usize = 1024;

/// One normalised line, as the limiter tells lines apart (module documentation, "The normalised line").
///
/// A hash, so the limiter never holds line text (which could carry a secret) or more than eight bytes per line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LineKey(u64);

impl LineKey {
    /// The key of `normalised`, the re-serialised line (or the received one when it cannot be re-serialised).
    /// Leading and trailing whitespace does not change the line bash runs, so it does not change the key either.
    #[must_use]
    pub fn of(normalised: &str) -> Self {
        // `DefaultHasher::new` is SipHash with fixed keys: deterministic within a build, which is all an in-memory
        // key needs. A collision could only limit another line of the same agent's own session (2^-64 odds).
        let mut hasher = DefaultHasher::new();
        normalised.trim().hash(&mut hasher);
        Self(hasher.finish())
    }
}

/// What [`DenialLimiter::record_denial`] did with a denial.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Counted {
    /// The denial was counted; the line is not limited (or was already limited).
    Counted,
    /// This denial started limiting the line, until the given time: emit `command.denied_repeatedly` (FR-HOOK-21).
    Started {
        /// When the limit lifts.
        until: Timestamp,
    },
}

/// The denials of one line in one session.
#[derive(Debug, Default)]
struct LineDenials {
    /// The times of the latest denials, oldest first: at most [`LIMIT_DENIALS`], all within the window of the latest.
    recent: VecDeque<u64>,
    /// When the current limit lifts, in microseconds, while the line is limited.
    limited_until: Option<u64>,
    /// The latest time this entry was touched, for eviction.
    last_seen: u64,
}

impl LineDenials {
    /// Whether the line is limited at `now` (module documentation, "Time").
    fn limited(&self, now: u64) -> bool {
        self.limited_until
            .is_some_and(|until| now < until && until - now <= micros(LIMIT_DURATION))
    }

    /// Whether nothing about the line matters at `now` any more: no limit, and no denial inside the window.
    fn expired(&self, now: u64) -> bool {
        !self.limited(now) && self.recent.iter().all(|&at| !within_window(at, now))
    }
}

/// The denials of one session.
#[derive(Debug, Default)]
struct SessionDenials {
    lines: BTreeMap<LineKey, LineDenials>,
    /// The latest time any of its lines was touched, for eviction.
    last_seen: u64,
}

/// Counts repeated denials and says which lines are limited (module documentation).
///
/// Pure: no clock, no I/O. `knshd` owns one behind a lock.
#[derive(Debug, Default)]
pub struct DenialLimiter {
    sessions: BTreeMap<SessionId, SessionDenials>,
}

impl DenialLimiter {
    /// An empty limiter: no line is limited.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether `line` is limited in `session_id` at `now` (FR-HOOK-20). Other sessions never affect the answer.
    #[must_use]
    pub fn limited(&self, session_id: SessionId, line: LineKey, now: Timestamp) -> bool {
        self.sessions
            .get(&session_id)
            .and_then(|session| session.lines.get(&line))
            .is_some_and(|denials| denials.limited(now.as_unix_micros()))
    }

    /// Counts one denial of `line` in `session_id` at `now`, and starts limiting the line when this is the
    /// [`LIMIT_DENIALS`]th within [`LIMIT_WINDOW`] (FR-HOOK-20). Returns [`Counted::Started`] exactly once per
    /// limiting period (FR-HOOK-21).
    ///
    /// The caller must not count a denial the limiter itself caused (`decision.source = rate_limit`): it is a
    /// consequence of the limit, not one more attempt to judge. Counting one anyway does nothing while the line is
    /// limited.
    pub fn record_denial(&mut self, session_id: SessionId, line: LineKey, now: Timestamp) -> Counted {
        let now_us = now.as_unix_micros();
        self.make_room_for_session(session_id, now_us);
        let session = self.sessions.entry(session_id).or_default();
        session.last_seen = now_us;
        make_room_for_line(&mut session.lines, line, now_us);
        let denials = session.lines.entry(line).or_default();
        denials.last_seen = now_us;

        // A limited line is already denied without asking; its denials start no new period.
        if denials.limited(now_us) {
            return Counted::Counted;
        }
        // A limit that lifted (or that a clock step back voided) is forgotten, and counting starts afresh.
        denials.limited_until = None;
        denials.recent.retain(|&at| within_window(at, now_us));
        denials.recent.push_back(now_us);
        if denials.recent.len() < LIMIT_DENIALS {
            return Counted::Counted;
        }
        denials.recent.clear();
        let until_us = now_us.saturating_add(micros(LIMIT_DURATION));
        // Past year 9999 the end cannot be written as a timestamp; the line is limited anyway, and `now` is
        // reported as its end.
        let until = Timestamp::from_unix_micros(until_us).unwrap_or(now);
        denials.limited_until = Some(until_us);
        Counted::Started { until }
    }

    /// Forgets everything about `session_id`, for example once it ended.
    pub fn forget(&mut self, session_id: SessionId) {
        self.sessions.remove(&session_id);
    }

    /// Keeps the session count within [`MAX_TRACKED_SESSIONS`] before `session_id` is added: drops sessions with
    /// nothing left that matters, then the least recently denied one.
    fn make_room_for_session(&mut self, session_id: SessionId, now: u64) {
        if self.sessions.len() < MAX_TRACKED_SESSIONS || self.sessions.contains_key(&session_id) {
            return;
        }
        self.sessions
            .retain(|_, session| session.lines.values().any(|denials| !denials.expired(now)));
        if self.sessions.len() < MAX_TRACKED_SESSIONS {
            return;
        }
        let oldest = self
            .sessions
            .iter()
            .min_by_key(|(_, session)| session.last_seen)
            .map(|(&id, _)| id);
        if let Some(oldest) = oldest {
            self.sessions.remove(&oldest);
        }
    }
}

/// Keeps a session's lines within [`MAX_TRACKED_LINES`] before `line` is added: drops expired lines, then the least
/// recently denied line that is not limited (a limited one only when every line is).
fn make_room_for_line(lines: &mut BTreeMap<LineKey, LineDenials>, line: LineKey, now: u64) {
    if lines.len() < MAX_TRACKED_LINES || lines.contains_key(&line) {
        return;
    }
    lines.retain(|_, denials| !denials.expired(now));
    if lines.len() < MAX_TRACKED_LINES {
        return;
    }
    let oldest = lines
        .iter()
        // A limited line is kept over any line that is only being counted: losing it would let the loop through.
        .min_by_key(|(_, denials)| (denials.limited(now), denials.last_seen))
        .map(|(&key, _)| key);
    if let Some(oldest) = oldest {
        lines.remove(&oldest);
    }
}

/// Whether a denial at `at` is within [`LIMIT_WINDOW`] of `now`. A denial "after" `now` (the clock stepped back) is
/// within it: it is recent, as far as anyone can tell.
fn within_window(at: u64, now: u64) -> bool {
    now.saturating_sub(at) < micros(LIMIT_WINDOW)
}

/// `duration` in microseconds. The constants are minutes, far below `u64::MAX` microseconds.
fn micros(duration: Duration) -> u64 {
    u64::try_from(duration.as_micros()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ulid::Ulid;

    fn session(n: u8) -> SessionId {
        SessionId::from_ulid(Ulid::new(1, [n; 10]).unwrap())
    }

    fn at(seconds: u64) -> Timestamp {
        Timestamp::from_unix_micros(1_700_000_000_000_000 + seconds * 1_000_000).unwrap()
    }

    fn line() -> LineKey {
        LineKey::of("/bin/rm -rf /")
    }

    /// Denies `line()` in `session` at each of `times`, and returns what the last denial did.
    fn deny_at(limiter: &mut DenialLimiter, session: SessionId, times: &[u64]) -> Counted {
        let mut last = Counted::Counted;
        for &t in times {
            last = limiter.record_denial(session, line(), at(t));
        }
        last
    }

    // FR-HOOK-20
    #[test]
    fn limits_after_five_denials_within_sixty_seconds() {
        let mut limiter = DenialLimiter::new();
        assert_eq!(deny_at(&mut limiter, session(1), &[0, 10, 20, 30]), Counted::Counted);
        assert!(!limiter.limited(session(1), line(), at(31)));
        assert_eq!(
            deny_at(&mut limiter, session(1), &[59]),
            Counted::Started { until: at(59 + 600) }
        );
        assert!(limiter.limited(session(1), line(), at(60)));
        // Another line of the same session is not limited.
        assert!(!limiter.limited(session(1), LineKey::of("/bin/ls"), at(60)));
    }

    // FR-HOOK-20
    #[test]
    fn does_not_limit_when_denials_spread_over_sixty_seconds() {
        let mut limiter = DenialLimiter::new();
        // First to fifth exactly 60 s apart: not within the window.
        assert_eq!(
            deny_at(&mut limiter, session(1), &[0, 15, 30, 45, 60]),
            Counted::Counted
        );
        assert!(!limiter.limited(session(1), line(), at(61)));
        // The sixth makes five within 60 s (15 to 74).
        assert!(matches!(
            deny_at(&mut limiter, session(1), &[74]),
            Counted::Started { .. }
        ));
    }

    // FR-HOOK-20
    #[test]
    fn lifts_limit_after_ten_minutes() {
        let mut limiter = DenialLimiter::new();
        deny_at(&mut limiter, session(1), &[0, 1, 2, 3, 4]);
        assert!(limiter.limited(session(1), line(), at(4 + 599)));
        assert!(!limiter.limited(session(1), line(), at(4 + 600)));
        // Counting starts afresh: one more denial does not limit it again.
        assert_eq!(deny_at(&mut limiter, session(1), &[700]), Counted::Counted);
        assert!(!limiter.limited(session(1), line(), at(701)));
        // Five more do, and start a new period that is reported again.
        assert!(matches!(
            deny_at(&mut limiter, session(1), &[701, 702, 703, 704]),
            Counted::Started { .. }
        ));
    }

    // FR-HOOK-21
    #[test]
    fn emits_denied_repeatedly_once() {
        let mut limiter = DenialLimiter::new();
        let started = (0..20)
            .map(|t| limiter.record_denial(session(1), line(), at(t)))
            .filter(|counted| matches!(counted, Counted::Started { .. }))
            .count();
        assert_eq!(started, 1);
    }

    // FR-HOOK-20
    #[test]
    fn limits_are_per_session() {
        let mut limiter = DenialLimiter::new();
        deny_at(&mut limiter, session(1), &[0, 1, 2, 3, 4]);
        assert!(limiter.limited(session(1), line(), at(5)));
        assert!(!limiter.limited(session(2), line(), at(5)));
        // Denials in another session do not add up with these.
        deny_at(&mut limiter, session(2), &[5, 6, 7, 8]);
        assert!(!limiter.limited(session(2), line(), at(9)));
        limiter.forget(session(1));
        assert!(!limiter.limited(session(1), line(), at(9)));
    }

    #[test]
    fn a_clock_step_back_never_extends_a_limit() {
        let mut limiter = DenialLimiter::new();
        deny_at(&mut limiter, session(1), &[1000, 1001, 1002, 1003, 1004]);
        assert!(limiter.limited(session(1), line(), at(1005)));
        // An hour back: the limit would last 70 minutes from here, so it is treated as lifted.
        assert!(!limiter.limited(session(1), line(), at(0)));
    }

    #[test]
    fn key_ignores_surrounding_whitespace_only() {
        assert_eq!(LineKey::of("  /bin/ls -l \n"), LineKey::of("/bin/ls -l"));
        assert_ne!(LineKey::of("/bin/ls -l"), LineKey::of("/bin/ls  -l"));
        assert_ne!(LineKey::of("/bin/ls -l"), LineKey::of("/bin/ls -la"));
    }

    #[test]
    fn memory_stays_bounded() {
        let mut limiter = DenialLimiter::new();
        for n in 0..(MAX_TRACKED_LINES + 10) {
            limiter.record_denial(session(1), LineKey::of(&n.to_string()), at(0));
        }
        assert_eq!(limiter.sessions[&session(1)].lines.len(), MAX_TRACKED_LINES);
        for n in 0..=MAX_TRACKED_SESSIONS {
            let id = SessionId::from_ulid(
                Ulid::new(2, u128::try_from(n).unwrap().to_be_bytes()[6..].try_into().unwrap()).unwrap(),
            );
            limiter.record_denial(id, line(), at(0));
        }
        assert_eq!(limiter.sessions.len(), MAX_TRACKED_SESSIONS);
    }

    #[test]
    fn a_limited_line_survives_eviction_of_expired_lines() {
        let mut limiter = DenialLimiter::new();
        deny_at(&mut limiter, session(1), &[0, 1, 2, 3, 4]);
        // Fill the session with lines denied once, long enough ago to have expired.
        for n in 0..MAX_TRACKED_LINES {
            limiter.record_denial(session(1), LineKey::of(&format!("other {n}")), at(5));
        }
        limiter.record_denial(session(1), LineKey::of("new"), at(100));
        assert!(limiter.limited(session(1), line(), at(100)));
    }
}
