//! Sandbox violations: the knsh tag, one reported denial, and merging repeats (KNSH-047; FR-SBX-06, FR-SBX-08).
//!
//! # Tag
//!
//! Every deny rule the Seatbelt compiler writes ends with `(with message "knsh:<session>:<command>:<rule>")`
//! (FR-SBX-06, KNSH-044), where `<command>` is the record ID of a supervised line or `env` for an envelope, and
//! `<rule>` is a constant rule name such as `fixed.engine` or `fs.deny[0]`. The system appends that text verbatim
//! as the last line of the denial it logs (KNSH-025, C2). [`DenialTag`] is that text, parsed strictly: anything else
//! (no tag, a spike tag such as `knsh:c8:canary`, a malformed ID) is not a tag, so a denial is attributed only when
//! its tag names a session exactly, never by guesswork.
//!
//! # Violation
//!
//! A [`DenialReport`] is one denial as the platform reader parsed it (a pure function in `knsh-platform`). A
//! [`SandboxViolation`] is what the engine emits as `sandbox.violation` and attaches to the record's
//! `sandbox_violations`: the report, when it was first seen, and how many identical denials it stands for.
//!
//! # Merging
//!
//! The system already folds repeats in one process into a later "N duplicate reports for …" entry, which can arrive
//! seconds after the first (0.05 s to 2.4 s observed, KNSH-025). [`ViolationMerger`] holds each new denial for
//! [`MERGE_WINDOW`], adding every identical report that arrives meanwhile to its count, then releases it once. It is
//! pure: the caller passes the time and decides what to do with what is released. Its memory is bounded by
//! [`MAX_PENDING`]: past that, the oldest pending violation is released early rather than anything being kept
//! without bound (one noisy process can log hundreds of denials in a fraction of a second).
//!
//! Violations are informational. They are never an input to a decision: a forged or lost entry can mislead a reader
//! but can never allow anything.

use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;
use std::time::Duration;

use knsh_json::{Fields, FromJson, JsonError, Object, ToJson, Value};

use crate::error::CoreError;
use crate::id::{RecordId, SessionId};
use crate::redacted::Redacted;
use crate::time::Timestamp;

/// The prefix of every knsh tag.
pub const TAG_PREFIX: &str = "knsh:";

/// The command part of an envelope's tag: commands run directly inside an envelope share its profile, so only the
/// session can be named (KNSH-025, C2).
pub const ENVELOPE_COMMAND: &str = "env";

/// The longest rule name a tag may carry. The compiler's names are short constants (`fs.deny[12]`).
pub const MAX_RULE_LEN: usize = 64;

/// How long a new denial waits for identical ones before it is released. Covers the delay of the system's own
/// "N duplicate reports" entries observed on macOS 26.6 (up to 2.4 s, KNSH-025).
pub const MERGE_WINDOW: Duration = Duration::from_secs(3);

/// The most distinct violations [`ViolationMerger`] holds at once.
pub const MAX_PENDING: usize = 1024;

/// What a tag says ran under the profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum TaggedCommand {
    /// An envelope: the command inside it cannot be named.
    Envelope,
    /// A supervised line and its record.
    Line(RecordId),
}

impl TaggedCommand {
    /// The record the denial belongs to, if the tag names one.
    #[must_use]
    pub const fn record_id(self) -> Option<RecordId> {
        match self {
            Self::Envelope => None,
            Self::Line(record_id) => Some(record_id),
        }
    }
}

/// The rule part of a tag: 1 to [`MAX_RULE_LEN`] ASCII letters, digits and `.`, `_`, `-`, `[`, `]`.
///
/// # Invariants
///
/// Always within those limits, so it can be stored, emitted and logged as is.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RuleName(String);

impl RuleName {
    /// The name as text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for RuleName {
    type Err = CoreError;

    /// # Errors
    ///
    /// [`CoreError::InvalidDenialTag`] if the name is empty, too long or holds another character.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let allowed = |byte: u8| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'[' | b']');
        if s.is_empty() || s.len() > MAX_RULE_LEN || !s.bytes().all(allowed) {
            return Err(CoreError::InvalidDenialTag);
        }
        Ok(Self(s.to_owned()))
    }
}

impl fmt::Display for RuleName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A parsed knsh tag: `knsh:<session>:<command>:<rule>` (FR-SBX-06).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DenialTag {
    /// The session whose profile denied the operation.
    pub session_id: SessionId,
    /// The line (or the envelope) the profile was compiled for.
    pub command: TaggedCommand,
    /// The deny rule that matched.
    pub rule: RuleName,
}

impl FromStr for DenialTag {
    type Err = CoreError;

    /// Parses the exact form the compiler writes; [`fmt::Display`] writes it back byte for byte.
    ///
    /// # Errors
    ///
    /// [`CoreError::InvalidDenialTag`] for anything else: a missing prefix or part, an ID that is not a canonical
    /// ULID, or an invalid rule name.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let rest = s.strip_prefix(TAG_PREFIX).ok_or(CoreError::InvalidDenialTag)?;
        // IDs never hold `:`, and rule names cannot, so splitting on the first two is exact.
        let mut parts = rest.splitn(3, ':');
        let (Some(session), Some(command), Some(rule)) = (parts.next(), parts.next(), parts.next()) else {
            return Err(CoreError::InvalidDenialTag);
        };
        let session_id = session.parse().map_err(|_| CoreError::InvalidDenialTag)?;
        let command = if command == ENVELOPE_COMMAND {
            TaggedCommand::Envelope
        } else {
            TaggedCommand::Line(command.parse().map_err(|_| CoreError::InvalidDenialTag)?)
        };
        Ok(Self {
            session_id,
            command,
            rule: rule.parse()?,
        })
    }
}

impl fmt::Display for DenialTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{TAG_PREFIX}{}:", self.session_id)?;
        match self.command {
            TaggedCommand::Envelope => f.write_str(ENVELOPE_COMMAND)?,
            TaggedCommand::Line(record_id) => write!(f, "{record_id}")?,
        }
        write!(f, ":{}", self.rule)
    }
}

/// One denial as the system reported it, attributed by its tag.
///
/// `process` and `argument` come from the denied process (its name, the path it asked for), so they are untrusted
/// text: the parser bounds them and refuses control characters, and they are held [`Redacted`] so they reach
/// events and records only through the paths built for it (FR-EVT-07).
#[derive(Debug, Clone)]
pub struct DenialReport {
    /// Whom the denial is attributed to.
    pub tag: DenialTag,
    /// The denied process's name, as the system logged it.
    pub process: Redacted<String>,
    /// The denied process's id. Informational only: it may have been reused since, so nothing ever signals it.
    pub pid: u32,
    /// The Seatbelt operation, for example `file-read-data` or `mach-lookup`.
    pub operation: String,
    /// What was denied, when the system names it: a canonical path, a service name, `remote:*:53`.
    pub argument: Option<Redacted<String>>,
    /// How many denials this report stands for: 1, or N for an "N duplicate reports" entry.
    pub count: u32,
}

impl DenialReport {
    /// What identifies repeats of the same denial: everything except the count.
    fn key(&self) -> MergeKey {
        MergeKey {
            tag: self.tag.clone(),
            process: self.process.expose().clone(),
            pid: self.pid,
            operation: self.operation.clone(),
            argument: self.argument.as_ref().map(|argument| argument.expose().clone()),
        }
    }
}

/// A violation as emitted in `sandbox.violation` and kept in a record's `sandbox_violations` (FR-SBX-08).
#[derive(Debug, Clone)]
pub struct SandboxViolation {
    /// When the first of the merged denials reached the engine.
    pub at: Timestamp,
    /// The merged denials: their report, with `count` summed.
    pub report: DenialReport,
}

impl SandboxViolation {
    /// Whether `other` is a repeat of the same denial (same tag, process, operation and argument).
    #[must_use]
    pub fn same_denial(&self, other: &Self) -> bool {
        self.report.key() == other.report.key()
    }

    /// Adds `count` more identical denials, saturating: a count is informational and must never wrap.
    pub fn add(&mut self, count: u32) {
        self.report.count = self.report.count.saturating_add(count);
    }

    /// `{session_id, record_id, rule, operation, argument, process, pid, count, at}`; `record_id` and `argument`
    /// may be `null`. The same object is the event's `data`, an element of the record's `sandbox_violations` and the
    /// stored form.
    ///
    /// # Errors
    ///
    /// [`JsonError`] only if the object cannot be built (it always can for these fixed keys and bounded values).
    pub fn to_object(&self) -> Result<Object, JsonError> {
        let report = &self.report;
        Object::new()
            .with("session_id", report.tag.session_id.to_string())?
            .with(
                "record_id",
                report.tag.command.record_id().map(|id| id.to_string()).to_json()?,
            )?
            .with("rule", report.tag.rule.as_str())?
            .with("operation", report.operation.as_str())?
            // Reaches the wire only here (FR-EVT-07): the parser bounded it and refused control characters.
            .with(
                "argument",
                report
                    .argument
                    .as_ref()
                    .map(|argument| argument.expose().clone())
                    .to_json()?,
            )?
            .with("process", report.process.expose().as_str())?
            .with("pid", report.pid.to_json()?)?
            .with("count", report.count.to_json()?)?
            .with("at", self.at.to_string())
    }
}

impl ToJson for SandboxViolation {
    /// [`SandboxViolation::to_object`].
    fn to_json(&self) -> Result<Value, JsonError> {
        self.to_object().map(Value::Object)
    }
}

impl FromJson for SandboxViolation {
    /// Reads the form [`ToJson`] writes, checking every ID, the rule name and that the count is at least 1.
    fn from_json(value: &Value) -> Result<Self, JsonError> {
        let invalid = |field| JsonError::OutOfRange { field: Some(field) };
        let mut fields = Fields::new(value)?;
        let session: String = fields.required("session_id")?;
        let record: Option<String> = fields.optional("record_id")?;
        let rule: String = fields.required("rule")?;
        let operation: String = fields.required("operation")?;
        let argument: Option<String> = fields.optional("argument")?;
        let process: String = fields.required("process")?;
        let pid: u32 = fields.required("pid")?;
        let count: u32 = fields.required("count")?;
        let at: String = fields.required("at")?;
        fields.finish_closed()?;
        let command = match record {
            None => TaggedCommand::Envelope,
            Some(record) => TaggedCommand::Line(record.parse().map_err(|_| invalid("record_id"))?),
        };
        // A violation stands for at least one denial; zero can only come from text the engine did not write.
        if count == 0 {
            return Err(invalid("count"));
        }
        Ok(Self {
            at: at.parse().map_err(|_| invalid("at"))?,
            report: DenialReport {
                tag: DenialTag {
                    session_id: session.parse().map_err(|_| invalid("session_id"))?,
                    command,
                    rule: rule.parse().map_err(|_| invalid("rule"))?,
                },
                process: Redacted::new(process),
                pid,
                operation,
                argument: argument.map(Redacted::new),
                count,
            },
        })
    }
}

/// The identity of a denial for merging. Holds exposed text, so it is private and never printed.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
struct MergeKey {
    tag: DenialTag,
    process: String,
    pid: u32,
    operation: String,
    argument: Option<String>,
}

/// A violation waiting for repeats.
struct Pending {
    violation: SandboxViolation,
    /// When it is released, on the caller's monotonic time line.
    due: Duration,
    /// Arrival order, so the oldest is released first when the merger is full.
    order: u64,
}

/// Merges identical denials that arrive within [`MERGE_WINDOW`] of the first (module documentation).
///
/// Times are durations on one monotonic time line the caller chooses (for example, since the reader started), so
/// the merger is pure and tests need no clock.
#[derive(Default)]
pub struct ViolationMerger {
    pending: BTreeMap<MergeKey, Pending>,
    next_order: u64,
}

impl ViolationMerger {
    /// An empty merger.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Takes one report that arrived at `now` (wall time `at`). A repeat of a pending violation only adds to its
    /// count; a new denial becomes pending until `now + MERGE_WINDOW`.
    ///
    /// Returns the violation released early to make room, if the merger was full: the caller handles it like any
    /// other released violation.
    pub fn push(&mut self, report: DenialReport, at: Timestamp, now: Duration) -> Option<SandboxViolation> {
        let key = report.key();
        if let Some(pending) = self.pending.get_mut(&key) {
            pending.violation.add(report.count);
            return None;
        }
        let evicted = if self.pending.len() >= MAX_PENDING {
            self.release_oldest()
        } else {
            None
        };
        let order = self.next_order;
        self.next_order += 1;
        self.pending.insert(
            key,
            Pending {
                violation: SandboxViolation { at, report },
                due: now.saturating_add(MERGE_WINDOW),
                order,
            },
        );
        evicted
    }

    /// Releases every violation whose window has passed at `now`, oldest first.
    pub fn due(&mut self, now: Duration) -> Vec<SandboxViolation> {
        let mut released: Vec<Pending> = self
            .pending
            .extract_if(.., |_, pending| pending.due <= now)
            .map(|(_, pending)| pending)
            .collect();
        // The map is ordered by key; release in arrival order instead.
        released.sort_by_key(|pending| pending.order);
        released.into_iter().map(|pending| pending.violation).collect()
    }

    /// Releases everything still pending, oldest first (the reader is stopping).
    pub fn drain(&mut self) -> Vec<SandboxViolation> {
        self.due(Duration::MAX)
    }

    /// When the next pending violation is due, if any.
    #[must_use]
    pub fn next_due(&self) -> Option<Duration> {
        self.pending.values().map(|pending| pending.due).min()
    }

    /// How many violations are pending.
    #[must_use]
    pub fn len(&self) -> usize {
        self.pending.len()
    }

    /// Whether nothing is pending.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }

    /// Removes and returns the oldest pending violation.
    fn release_oldest(&mut self) -> Option<SandboxViolation> {
        let oldest = self
            .pending
            .iter()
            .min_by_key(|(_, pending)| pending.order)
            .map(|(key, _)| key.clone())?;
        self.pending.remove(&oldest).map(|pending| pending.violation)
    }
}

/// Adds `incoming` to `kept`, merging repeats of a violation already there and keeping at most `limit` distinct
/// ones. Returns how many distinct violations did not fit and were dropped.
///
/// Used when a late denial is appended to a finished record (FR-SBX-08), so a record's list stays bounded however
/// noisy its command was.
pub fn merge_into(kept: &mut Vec<SandboxViolation>, incoming: Vec<SandboxViolation>, limit: usize) -> usize {
    let mut dropped = 0;
    for violation in incoming {
        if let Some(existing) = kept.iter_mut().find(|existing| existing.same_denial(&violation)) {
            existing.add(violation.report.count);
        } else if kept.len() < limit {
            kept.push(violation);
        } else {
            dropped += 1;
        }
    }
    dropped
}

/// Writes `violations` as a JSON array, the stored form of a record's `sandbox_violations`.
///
/// # Errors
///
/// [`CoreError::InvalidViolation`] only if a value cannot be written (it always can for violations built here).
pub fn encode_violations(violations: &[SandboxViolation]) -> Result<String, CoreError> {
    let values = violations
        .iter()
        .map(ToJson::to_json)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| CoreError::InvalidViolation)?;
    knsh_json::write(&Value::Array(values)).map_err(|_| CoreError::InvalidViolation)
}

/// Reads the stored form written by [`encode_violations`].
///
/// # Errors
///
/// [`CoreError::InvalidViolation`] for text that is not such an array.
pub fn decode_violations(text: &str) -> Result<Vec<SandboxViolation>, CoreError> {
    let value = knsh_json::parse(text.as_bytes(), text.len()).map_err(|_| CoreError::InvalidViolation)?;
    let Value::Array(items) = value else {
        return Err(CoreError::InvalidViolation);
    };
    items
        .iter()
        .map(SandboxViolation::from_json)
        .collect::<Result<_, _>>()
        .map_err(|_| CoreError::InvalidViolation)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SESSION: &str = "01JC0000000000000000000000";
    const RECORD: &str = "01JC1111111111111111111111";

    fn tag(command: TaggedCommand) -> DenialTag {
        DenialTag {
            session_id: SESSION.parse().unwrap(),
            command,
            rule: "fs.deny[0]".parse().unwrap(),
        }
    }

    fn record() -> RecordId {
        RECORD.parse().unwrap()
    }

    fn report(pid: u32, count: u32) -> DenialReport {
        DenialReport {
            tag: tag(TaggedCommand::Line(record())),
            process: Redacted::new(String::from("cat")),
            pid,
            operation: String::from("file-read-data"),
            argument: Some(Redacted::new(String::from("/private/etc/hosts"))),
            count,
        }
    }

    fn at() -> Timestamp {
        Timestamp::from_unix_micros(1_763_200_000_000_000).unwrap()
    }

    const fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    // FR-SBX-06: the tag the compiler writes parses back, and prints byte for byte.
    #[test]
    fn tag_round_trips() {
        for text in [
            format!("knsh:{SESSION}:{RECORD}:fs.deny[0]"),
            format!("knsh:{SESSION}:env:services.dns"),
        ] {
            let parsed: DenialTag = text.parse().unwrap();
            assert_eq!(parsed.to_string(), text);
        }
        let line: DenialTag = format!("knsh:{SESSION}:{RECORD}:fixed.engine").parse().unwrap();
        assert_eq!(line.command, TaggedCommand::Line(record()));
        assert_eq!(line.rule.as_str(), "fixed.engine");
    }

    // KNSH-047: a tag that does not name a session exactly is not a tag, so it is never mis-attributed.
    #[test]
    fn refuses_tags_that_are_not_exact() {
        for text in [
            "knsh:c8:canary",
            "knsh:c8:pinfo-self:default",
            "",
            "knsh:",
            &format!("{SESSION}:{RECORD}:default"),
            &format!("knsh:{SESSION}:{RECORD}"),
            &format!("knsh:{SESSION}:{RECORD}:"),
            &format!("knsh:{SESSION}:ENV:default"),
            &format!("knsh:{SESSION}:{RECORD}:has space"),
            &format!("knsh:{SESSION}:{RECORD}:a:b"),
            &format!("knsh:{}:{RECORD}:default", SESSION.to_lowercase()),
            &format!("knsh:{SESSION}:{RECORD}:{}", "r".repeat(MAX_RULE_LEN + 1)),
            &format!("knsh:{SESSION}:{RECORD}:default\n"),
        ] {
            assert_eq!(text.parse::<DenialTag>(), Err(CoreError::InvalidDenialTag), "{text:?}");
        }
    }

    // KNSH-047 merges_duplicate_denials: repeats within the window become one violation with the summed count, a
    // system "N duplicate reports" entry included.
    #[test]
    fn merges_duplicate_denials() {
        let mut merger = ViolationMerger::new();
        assert!(merger.push(report(7, 1), at(), secs(0)).is_none());
        assert!(merger.push(report(7, 1), at(), secs(1)).is_none());
        assert!(merger.push(report(7, 8), at(), secs(2)).is_none());
        assert_eq!(merger.len(), 1);
        assert!(merger.due(secs(2)).is_empty(), "held until the window passes");
        let released = merger.due(MERGE_WINDOW);
        assert_eq!(released.len(), 1);
        assert_eq!(released[0].report.count, 10);
        assert!(merger.is_empty());
        // After the window, a repeat is a new violation.
        assert!(merger.push(report(7, 1), at(), secs(10)).is_none());
        assert_eq!(merger.drain().len(), 1);
    }

    // Different processes (the system never merges across them either) or different paths stay apart.
    #[test]
    fn keeps_distinct_denials_apart() {
        let mut merger = ViolationMerger::new();
        merger.push(report(7, 1), at(), secs(0));
        merger.push(report(8, 1), at(), secs(0));
        let mut other_path = report(7, 1);
        other_path.argument = Some(Redacted::new(String::from("/private/etc/passwd")));
        merger.push(other_path, at(), secs(0));
        let mut envelope = report(7, 1);
        envelope.tag = tag(TaggedCommand::Envelope);
        merger.push(envelope, at(), secs(0));
        assert_eq!(merger.next_due(), Some(MERGE_WINDOW));
        let released = merger.due(MERGE_WINDOW);
        assert_eq!(released.len(), 4);
        assert!(released.iter().all(|violation| violation.report.count == 1));
        assert_eq!(released[1].report.pid, 8, "released in arrival order");
    }

    // Memory stays bounded: a full merger releases its oldest violation instead of growing.
    #[test]
    fn full_merger_releases_the_oldest() {
        let mut merger = ViolationMerger::new();
        for pid in 0..u32::try_from(MAX_PENDING).unwrap() {
            assert!(merger.push(report(pid, 1), at(), secs(0)).is_none());
        }
        let evicted = merger.push(report(u32::MAX, 1), at(), secs(0)).unwrap();
        assert_eq!(evicted.report.pid, 0);
        assert_eq!(merger.len(), MAX_PENDING);
    }

    #[test]
    fn counts_saturate() {
        let mut merger = ViolationMerger::new();
        merger.push(report(7, u32::MAX), at(), secs(0));
        merger.push(report(7, 5), at(), secs(0));
        assert_eq!(merger.drain()[0].report.count, u32::MAX);
    }

    // A late denial merges into what a record already holds, and the list stays bounded.
    #[test]
    fn merge_into_is_bounded() {
        let first = SandboxViolation {
            at: at(),
            report: report(7, 1),
        };
        let mut kept = vec![first.clone()];
        assert_eq!(merge_into(&mut kept, vec![first.clone()], 2), 0);
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].report.count, 2);
        let second = SandboxViolation {
            at: at(),
            report: report(8, 1),
        };
        let third = SandboxViolation {
            at: at(),
            report: report(9, 1),
        };
        assert_eq!(merge_into(&mut kept, vec![second, third], 2), 1);
        assert_eq!(kept.len(), 2);
    }

    #[test]
    fn stored_form_round_trips() {
        let mut envelope = report(9, 3);
        envelope.tag = tag(TaggedCommand::Envelope);
        envelope.argument = None;
        let violations = vec![
            SandboxViolation {
                at: at(),
                report: report(7, 1),
            },
            SandboxViolation {
                at: at(),
                report: envelope,
            },
        ];
        let text = encode_violations(&violations).unwrap();
        let read = decode_violations(&text).unwrap();
        assert_eq!(read.len(), 2);
        assert!(read[0].same_denial(&violations[0]));
        assert!(read[1].same_denial(&violations[1]));
        assert_eq!(read[1].report.count, 3);
        assert_eq!(read[0].at, at());
        assert_eq!(encode_violations(&read).unwrap(), text);
    }

    #[test]
    fn refuses_stored_text_the_engine_could_not_write() {
        for text in [
            "",
            "{}",
            "[1]",
            r#"[{"session_id":"x","record_id":null,"rule":"r","operation":"o","argument":null,"process":"p","pid":1,"count":1,"at":"2026-01-01T00:00:00.000000Z"}]"#,
        ] {
            assert_eq!(
                decode_violations(text).err(),
                Some(CoreError::InvalidViolation),
                "{text}"
            );
        }
        let valid = encode_violations(&[SandboxViolation {
            at: at(),
            report: report(7, 1),
        }])
        .unwrap();
        assert_eq!(
            decode_violations(&valid.replace("\"count\":1", "\"count\":0")).err(),
            Some(CoreError::InvalidViolation)
        );
    }
}
