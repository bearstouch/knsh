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
//! # The trusted authority (KNSH-067, KNSH-068)
//!
//! [`TrustedAuthority`] is the authority the user trusted: a [`TeamId`], a [`SigningIdentifier`] and a minimum
//! [`BundleVersion`], each validated by its type so none can inject code-signing requirement clauses (FR-AUTH-13),
//! and the strict stored form of the record the Keychain item holds (FR-AUTH-11).
//!
//! # Events (KNSH-018)
//!
//! [`Event`] is the event envelope of `specs/05-models/event.md`, with an [`EventData`] payload whose text fields
//! are all [`Redacted`] or typed (FR-EVT-07). [`EventBus`] numbers each session's events gaplessly (FR-EVT-02), keeps
//! the last [`EVENT_BUFFER_LEN`] per session for `since_seq` resumes (FR-EVT-03), and gives each subscription a
//! bounded queue that drops its oldest events and reports them as [`Lost`] instead of ever making a publisher wait
//! (FR-EVT-04). [`EventScope`] limits a subscription to one session (FR-EVT-01).
//!
//! # Output capture and modes (KNSH-053)
//!
//! [`OutputCapture`] keeps a stream's head and tail within a cap as it is read, with its size and line count
//! (FR-REC-06); [`CappedOutput`] is what is kept. [`shape`] selects what an `exec.run` caller gets back in each
//! [`OutputMode`] (FR-OUT-01) without ever rewriting it (FR-OUT-05). Every chunk passes through the
//! [`OutputRedaction`] hook first (FR-EVT-07), a pass-through until secret redaction arrives (KNSH-091).
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
//! # Dry runs (KNSH-043)
//!
//! [`check_line`] parses, resolves ([`LineResolver`]), classifies and decides a line against a profile without
//! running it (FR-POL-70), for `policy.check`. It reads the filesystem only through [`BinaryLookup`]; hooks, the
//! authority and grants are not consulted.
//!
//! # Sandbox violations (KNSH-047)
//!
//! [`DenialTag`] parses the tag every deny rule carries (`knsh:<session>:<command>:<rule>`, FR-SBX-06), so a
//! denial the system reports is attributed only when its tag names a session exactly. [`ViolationMerger`] folds
//! repeats that arrive within [`MERGE_WINDOW`] into one [`SandboxViolation`], with bounded memory, and
//! [`merge_into`] appends late ones to a finished record's bounded list (FR-SBX-08).
//!
//! # Rate limiting of repeated denials (KNSH-055)
//!
//! [`DenialLimiter`] counts denials per session and per normalised line ([`LineKey`]: the line re-serialised with
//! absolute paths). [`LIMIT_DENIALS`] denials within [`LIMIT_WINDOW`] limit the line for [`LIMIT_DURATION`]
//! (FR-HOOK-20), and [`Counted::Started`] says, once per limit, that `command.denied_repeatedly` is due (FR-HOOK-21).
//! [`decide`] asks [`RateLimits`] right after the parse and denies a limited line with source `rate_limit`, before
//! hooks or asks. Time comes from the caller's injected clock.
//!
//! # Hooks (KNSH-062)
//!
//! [`parse_hooks`] reads the `[[hooks]]` registrations of the user's configuration into a [`HookConfig`], keeping a
//! registration it cannot use as invalid so it denies every line it would match (FR-HOOK-04). [`run_hooks`] runs the
//! matching hooks of one evaluation pass in declared order through a [`HookExecutor`] (processes are `knshd`'s), reads
//! each answer with [`judge`], and returns the chain's [`HookOutcome`] with every hook's run time ([`HookRun`],
//! FR-HOOK-05), which the pipeline puts in the record's `decision.hooks`. Human sessions run no hooks (FR-HOOK-01).
//!
//! Failures are reported through [`CoreError`], except the profile loader's, which are [`ProfileError`] because they
//! must name the key at fault.

#![deny(missing_docs, unsafe_op_in_unsafe_fn, rust_2018_idioms)]
#![warn(clippy::pedantic)]
#![forbid(unsafe_code)]

mod authority;
mod error;
mod event;
mod hook;
mod id;
mod lifecycle;
mod output;
mod path;
mod policy;
mod ratelimit;
mod record;
mod redacted;
mod registry;
mod resolve;
mod session;
mod time;
mod ulid;
mod violation;

pub use authority::{BundleVersion, MAX_TRUST_RECORD_LEN, SigningIdentifier, TeamId, TrustError, TrustedAuthority};
pub use error::{CoreError, MAX_KEY_DISPLAY_LEN, ProfileError, ProfileErrorKind, ProfileOrigin};
pub use event::{
    AGENT_EDIT_PATHS, BusLimits, CancelReason, Delivery, EVENT_BUFFER_LEN, EngineEvent, EngineEventData, EngineLost,
    Event, EventBus, EventData, EventScope, Lost, MAX_ENDED_BUFFERS, Published, PublishedEngine, Subscribed,
    SubscriptionId, UncertainReason,
};
pub use hook::{
    ConfigProblem, Ended, Execution, HOOK_EVENT, HOOKS_KEY, HookConfig, HookEntry, HookExecutor, HookExit, HookId,
    HookMatch, HookProblem, HookReply, HookSpec, MAX_HOOK_LABEL_LEN, MAX_HOOK_LABELS, MAX_HOOK_OUTPUT,
    MAX_HOOK_REASON_LEN, MAX_HOOK_TIMEOUT_MS, MAX_HOOKS, MAX_MATCH_BINARIES, judge, parse_hooks, run_hooks,
};
pub use id::{CheckpointId, EventId, GrantId, RecordId, RequestId, SessionId};
/// The network classes of the subcommand table (FR-LC-06), as lines present them to host rules ([`LineAccess`]).
pub use knsh_bash::NetworkClass;
pub use lifecycle::{
    Allowed, AskAnswer, AskReply, AskRequest, Authority, Caller, Decision, Effects, HookOutcome, HookVerdict, Hooks,
    INTERNAL_ERROR, LineInput, LineProfile, LocalApprovals, MAX_LINE_LEN, MAX_REWRITES, NoAuthority, NoHooks,
    NoRateLimits, Observer, Outcome, Proposal, RateLimits, Refusal, RefusalKind, StillWaiting, decide, redact,
};
pub use output::{
    CappedOutput, CapturedStream, DEFAULT_HEAD_TAIL_LINES, DEFAULT_OUTPUT_CAP, DEFAULT_TRUNCATE_BYTES,
    ERRORS_ONLY_STDOUT_LINES, Excerpt, HeadTail, MAX_HEAD_TAIL_LINES, MAX_TRUNCATE_BYTES, NoOutputRedaction,
    OutputCapture, OutputRedaction, OutputRequest, ShapedOutput, shape,
};
pub use path::CanonicalPath;
pub use policy::{
    AGENT_SOCKET, ApprovalsPolicy, CONTROL_SERVICE, CheckpointPolicy, ClassHosts, CommandVerdict, DEFAULT_AGENT_BASH,
    DEFAULT_CHECKPOINT_EXCLUDES, DEFAULT_RETENTION_DAYS, DecisionSource, ENGINE_CONFIG_DIR, ENGINE_DATA_DIR,
    ENGINE_RUN_DIR, ExecPolicy, FixedDenies, FsPolicy, Grant, GrantScope, GrantSet, HostAccess, HostRefusal,
    LineAccess, LineCapabilities, LineCheck, LineDecision, LineReason, LineResolver, LoadedProfiles, LookupError,
    MAX_EXTENDS_DEPTH, MAX_GRANTS, MAX_PROFILE_LEN, MatchedRule, NetworkMode, NetworkPolicy, OutputMode, OutputPolicy,
    PRESETS, PathContext, PolicyFs, Profile, ProfileSource, RETENTION_DAYS_RANGE, ReadScope, RecordingPolicy,
    Requester, RuleAction, RuleId, SecretInjection, UNATTENDED_PROFILE, UNATTENDED_PROFILE_TEXT, USER_SOCKET,
    VOLUME_CHECKPOINT_DIR, at_least_as_strict, check_host, check_line, evaluate_command, evaluate_line,
    evaluate_line_with_grants, host_matches, is_non_tls_host, line_grant_rule, load_profile, load_profile_text,
    load_unattended, project_root,
};
pub use ratelimit::{
    Counted, DenialLimiter, LIMIT_DENIALS, LIMIT_DURATION, LIMIT_WINDOW, LineKey, MAX_TRACKED_LINES,
    MAX_TRACKED_SESSIONS,
};
pub use record::{
    ArgvClass, ArgvEntry, Attribution, ChangedFile, DecisionVerdict, ExecutionRecord, FileChange, HookResult, HookRun,
    MAX_HOOK_RUNS, MAX_NETWORK_ENTRIES, MAX_RECORD_FILES_CHANGED, NetworkEntry, NetworkResult, OutputInfo,
    OutputStream, RecordDecision, RecordDetails, RecordedIdentity, UnprotectedReason, UnprotectedRoot, argv_of,
    decode_argv, decode_decision, decode_files_changed, decode_network, decode_unprotected, encode_argv,
    encode_decision, encode_files_changed, encode_network, encode_unprotected, merge_network,
};
pub use redacted::{REDACTED_MARKER, Redacted};
pub use registry::{EqualProfileOnly, ProfileOrder, SessionRegistry};
pub use resolve::{
    BinaryLookup, CommandName, DEFAULT_TRUSTED_FOLDERS, MAX_PATH_ENTRIES, Resolution, TrustedFolders, resolve,
};
pub use session::{
    Actor, ActorKind, AgentId, DERIVED_AGENT_IDS, MAX_NAME_LEN, ProfileName, STATE_CHANGED_EVENT, Session, SessionSpec,
    SessionState, StateChanged, Transition, default_recording,
};
pub use time::Timestamp;
pub use ulid::{MAX_MILLIS, Ulid};
pub use violation::{
    DenialReport, DenialTag, ENVELOPE_COMMAND, MAX_PENDING, MAX_RULE_LEN, MERGE_WINDOW, RuleName, SandboxViolation,
    TAG_PREFIX, TaggedCommand, ViolationMerger, decode_violations, encode_violations, merge_into,
};
