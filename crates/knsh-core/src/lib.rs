//! Pure domain model of Kinetic Shell.
//!
//! Sessions, records, events, the policy model and its evaluation, verdict combining, grants and rate limiting.
//!
//! # Boundaries
//!
//! No I/O of any kind: effects are injected by callers. Depends only on the parser crates.
//!
//! # Specification
//!
//! - `specs/03-functional-requirements/policy.md`
//! - `specs/03-functional-requirements/sessions.md`
//! - `specs/05-models/session.md`
//! - `specs/05-models/policy-profile.md`
//! - `specs/05-models/grant.md`
//! - `specs/05-models/execution-record.md`
//! - `specs/05-models/event.md`, `specs/03-functional-requirements/events.md`
//! - `specs/03-functional-requirements/command-lifecycle.md` (FR-LC-03: resolve each command to a canonical path;
//!   FR-LC-09: decide the whole line before anything runs)
//! - `specs/03-functional-requirements/agent-integration.md` (FR-AGT-21: the `unattended` profile)
//!
//! # Value types (KNSH-002)
//!
//! Typed building blocks that make common mix-ups fail to compile:
//!
//! - [`Ulid`] and the ID newtypes over it ([`SessionId`], [`RecordId`], [`EventId`], [`RequestId`],
//!   [`CheckpointId`], [`GrantId`]), which never convert into one another implicitly.
//! - [`CanonicalPath`], an absolute, already-resolved path (FR-POL-11).
//! - [`Redacted`], which never prints its inner value (NFR-PRIV-02).
//! - [`Timestamp`], UTC microseconds formatted as RFC 3339.
//!
//! # Sessions (KNSH-015)
//!
//! - [`Session`]: one actor fixed at creation (FR-SES-01), recording defaults per actor (FR-SES-04), and the state
//!   machine of `specs/03-functional-requirements/sessions.md#states`, where every change yields a
//!   [`StateChanged`] value (FR-SES-14) and a refused transition leaves the state unchanged.
//! - [`SessionRegistry`]: the live sessions, unique IDs, parent links (FR-SES-03) with the [`ProfileOrder`] hook
//!   for agent children, and "not found or ended" for sessions that have ended (`-32006`).
//!
//! # Execution records (KNSH-016)
//!
//! [`ExecutionRecord`] is one record of `specs/05-models/execution-record.md`: its text fields are [`Redacted`] or
//! typed (FR-REC-11), and the agent-only fields sit in [`RecordDetails`] so a human record can drop them as one unit
//! (FR-REC-09). [`OutputInfo`] describes a capped output stream (FR-REC-06) and [`OutputStream`] names it.
//! [`Timestamp`] also parses its own text form, for time filters.
//!
//! # Events (KNSH-018)
//!
//! [`Event`] is the event envelope of `specs/05-models/event.md`, with an [`EventData`] payload whose text fields
//! are all [`Redacted`] or typed (FR-EVT-07). [`EventBus`] numbers each session's events gaplessly (FR-EVT-02), keeps
//! the last [`EVENT_BUFFER_LEN`] per session for `since_seq` resumes (FR-EVT-03), and gives each subscription a
//! bounded queue that drops its oldest events and reports them as [`Lost`] instead of ever making a publisher wait
//! (FR-EVT-04). [`EventScope`] limits a subscription to one session (FR-EVT-01).
//!
//! # Binary resolution (KNSH-035)
//!
//! [`resolve`] turns a simple command's name into a [`Resolution`] the way bash would run it: a function, a builtin,
//! or a binary found by path or on the caller's `PATH` and classified by its canonical path as [`Resolution::Trusted`]
//! (directly in one of the [`TrustedFolders`], FR-POL-13) or [`Resolution::ProjectExecutable`] (anywhere else,
//! FR-POL-14), or [`Resolution::NotFound`] so the line fails with 127 (FR-LC-03, FR-POL-11). The filesystem is
//! reached only through [`BinaryLookup`], which `knsh-platform` implements over its `Fs` trait.
//!
//! # Policy profiles (KNSH-039)
//!
//! [`load_profile`] and [`load_profile_text`] read a profile from the TOML subset into one resolved [`Profile`]:
//! every key typed and checked (an unknown key, wrong type or invalid value is a [`ProfileError`] naming the key),
//! `extends` chains merged child over parent per key, the named preset from [`PRESETS`] (shipped as data, FR-POL-03)
//! added, defaults filled (`fs.read = "all"`, FR-POL-12), and every path expanded (`~`, `${HOME}`, `${TMPDIR}`,
//! `${PROJECT}`, FR-POL-10) and canonicalised with symlinks followed (FR-POL-11) through [`PolicyFs`]. Profiles are
//! read by name through [`ProfileSource`]. A load either returns the whole profile or an error, never part of one.
//!
//! # Command rules (KNSH-040)
//!
//! [`evaluate_command`] decides one classified simple command against a profile's `exec` rules and returns a
//! [`CommandVerdict`] naming the deciding rule ([`RuleId`], `exec.allow[1]`). Patterns are globs over the
//! normalised arguments (FR-POL-15), a pattern without `*` also matches with more arguments (FR-POL-16), names match
//! only trusted binaries and builtins (FR-POL-13) while other binaries get `exec.project_executables` (FR-POL-14), and
//! deny beats ask beats allow, with `exec.default` when nothing matches (FR-POL-17).
//!
//! # Line verdicts, dynamic code, fixed denies and `unattended` (KNSH-041)
//!
//! [`evaluate_line`] decides a whole classified line before any of it runs (FR-LC-09): deny if any part is denied,
//! ask if any part asks (FR-POL-18), with every part's rule in [`LineDecision::matched_rules`] and what the line may
//! receive in [`LineCapabilities`]. A line holding dynamic code is clamped to `network.hosts`, with no approval hosts,
//! secrets or classes (FR-POL-20, FR-POL-21). Any failure inside is a deny ([`LineReason::EvaluationFailed`]). The
//! fixed denies of FR-POL-30 ([`FixedDenies`]: engine directories, sockets, the control service) are compiled in, and
//! the loader refuses a profile that would allow one ([`ProfileErrorKind::FixedDeny`]). The built-in
//! [`UNATTENDED_PROFILE`] ([`load_unattended`]) turns every ask into a deny by the standalone rules (FR-AGT-21).
//!
//! # Grants (KNSH-042)
//!
//! A [`Grant`] is a time-limited command rule on top of a profile, scoped to one session or one profile
//! ([`GrantScope`], FR-POL-60). [`GrantSet`] holds the live grants, lists and revokes them (FR-POL-61), and ignores a
//! grant from its `expires_at` on; time is passed in from the injected clock. [`evaluate_line_with_grants`] turns an
//! `ask` into `allow` (source [`DecisionSource::Grant`]) when grants cover every asking part, never overrides a deny,
//! and leaves the dynamic-code clamps in place.
//!
//! Failures are reported through [`CoreError`], except the profile loader's, which are [`ProfileError`] because they
//! must name the key at fault.

#![deny(missing_docs, unsafe_op_in_unsafe_fn, rust_2018_idioms)]
#![warn(clippy::pedantic)]
#![forbid(unsafe_code)]

mod error;
mod event;
mod id;
mod path;
mod policy;
mod record;
mod redacted;
mod registry;
mod resolve;
mod session;
mod time;
mod ulid;

pub use error::{CoreError, MAX_KEY_DISPLAY_LEN, ProfileError, ProfileErrorKind, ProfileOrigin};
pub use event::{
    BusLimits, Delivery, EVENT_BUFFER_LEN, Event, EventBus, EventData, EventScope, Lost, MAX_ENDED_BUFFERS, Published,
    Subscribed, SubscriptionId,
};
pub use id::{CheckpointId, EventId, GrantId, RecordId, RequestId, SessionId};
pub use path::CanonicalPath;
pub use policy::{
    ApprovalsPolicy, CONTROL_SERVICE, CheckpointPolicy, CommandVerdict, DEFAULT_AGENT_BASH,
    DEFAULT_CHECKPOINT_EXCLUDES, DEFAULT_RETENTION_DAYS, DecisionSource, ENGINE_CONFIG_DIR, ENGINE_DATA_DIR,
    ExecPolicy, FixedDenies, FsPolicy, Grant, GrantScope, GrantSet, LineCapabilities, LineDecision, LineReason,
    LookupError, MAX_EXTENDS_DEPTH, MAX_GRANTS, MAX_PROFILE_LEN, MatchedRule, NetworkMode, NetworkPolicy, OutputMode,
    OutputPolicy, PRESETS, PathContext, PolicyFs, Profile, ProfileSource, RETENTION_DAYS_RANGE, ReadScope,
    RecordingPolicy, RuleAction, RuleId, SecretInjection, UNATTENDED_PROFILE, UNATTENDED_PROFILE_TEXT,
    evaluate_command, evaluate_line, evaluate_line_with_grants, load_profile, load_profile_text, load_unattended,
    project_root,
};
pub use record::{ExecutionRecord, OutputInfo, OutputStream, RecordDetails};
pub use redacted::{REDACTED_MARKER, Redacted};
pub use registry::{EqualProfileOnly, ProfileOrder, SessionRegistry};
pub use resolve::{
    BinaryLookup, CommandName, DEFAULT_TRUSTED_FOLDERS, MAX_PATH_ENTRIES, Resolution, TrustedFolders, resolve,
};
pub use session::{
    Actor, ActorKind, AgentId, MAX_NAME_LEN, ProfileName, STATE_CHANGED_EVENT, Session, SessionSpec, SessionState,
    StateChanged, Transition, default_recording,
};
pub use time::Timestamp;
pub use ulid::{MAX_MILLIS, Ulid};
