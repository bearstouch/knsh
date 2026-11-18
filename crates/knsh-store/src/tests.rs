//! Behaviour of the record store against the real system SQLite, each test in its own temporary directory.

use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;

use knsh_core::{
    Actor, AgentId, ArgvClass, ArgvEntry, CanonicalPath, CheckpointId, DecisionSource, DecisionVerdict, DenialReport,
    DenialTag, ExecutionRecord, NetworkEntry, NetworkResult, OutputStream, ProfileName, RecordDecision, RecordDetails,
    RecordId, Redacted, SandboxViolation, Session, SessionId, SessionSpec, TaggedCommand, Timestamp, Ulid,
    UnprotectedReason, UnprotectedRoot, encode_decision,
};
use knsh_platform::macos::{RealFs, effective_uid};
use knsh_platform::sqlite::{Connection, DEFAULT_BUSY_TIMEOUT, Step, Value};
use knsh_platform::testing::FakeClock;

use crate::testing::TempDir;
use crate::{
    ForgetSelector, MAX_VIOLATIONS_PER_RECORD, OutputRequest, PageSize, RecordQuery, RecordStore, RecordedOutput,
    Retention, RetentionDays, RetentionReport, Scope, StoreConfig, StoreError, schema_version,
};

const BASE_MILLIS: u64 = 1_794_506_531_000;

fn open(dir: &TempDir) -> RecordStore {
    open_with(dir, StoreConfig::default())
}

fn open_with(dir: &TempDir, config: StoreConfig) -> RecordStore {
    open_at(dir, &clock(), config)
}

/// A fake clock at the base instant: every test record is younger than any retention period, so the pass that runs
/// when a store opens deletes nothing unless a test moves the clock.
fn clock() -> Arc<FakeClock> {
    Arc::new(FakeClock::new(at(0)))
}

fn open_at(dir: &TempDir, clock: &Arc<FakeClock>, config: StoreConfig) -> RecordStore {
    try_open(dir, clock, effective_uid(), config).unwrap()
}

/// [`open_at`], then waits for the pass that runs at open to finish. A later [`RecordStore::run_retention`] joins a
/// pass that is still running, whose cutoffs come from the clock when it started, so a test that moves the clock
/// after opening must start from a settled store or, on a slow machine, see the open pass's report instead of a new
/// one (seen in CI as `expired == 0`).
fn open_settled(dir: &TempDir, clock: &Arc<FakeClock>, config: StoreConfig) -> RecordStore {
    let store = open_at(dir, clock, config);
    store.run_retention().unwrap();
    store
}

fn try_open(dir: &TempDir, clock: &Arc<FakeClock>, uid: u32, config: StoreConfig) -> Result<RecordStore, StoreError> {
    let clock: Arc<dyn knsh_platform::Clock> = clock.clone();
    RecordStore::open(&RealFs::new(), &dir.db(), uid, clock, config)
}

fn session_id(n: u128) -> SessionId {
    SessionId::from_ulid(Ulid::from_u128(n))
}

/// Record IDs that sort in `n` order, created `n` milliseconds after the base.
fn record_id(n: u64) -> RecordId {
    RecordId::from_ulid(Ulid::new(BASE_MILLIS + n, [0; 10]).unwrap())
}

fn at(seconds: u64) -> Timestamp {
    Timestamp::from_unix_micros((BASE_MILLIS / 1_000 + seconds) * 1_000_000).unwrap()
}

fn agent() -> Actor {
    Actor::Agent(AgentId::new("claude-code").unwrap())
}

/// A finished record of `session`, started at `at(n)`.
fn record(n: u64, session: SessionId, actor: Actor, command: &str) -> ExecutionRecord {
    ExecutionRecord {
        record_id: record_id(n),
        session_id: session,
        actor,
        command: Redacted::new(command.to_owned()),
        cwd: CanonicalPath::new("/Users/someone/project").unwrap(),
        started_at: at(n),
        ended_at: Some(at(n + 1)),
        exit_code: Some(0),
        details: RecordDetails::default(),
    }
}

/// `(name, path, class, wrapper)` of one `argv` entry.
type ArgvSummary = (Option<String>, Option<String>, ArgvClass, Option<usize>);

/// The summary of each `argv` entry: `ArgvEntry` has no `PartialEq`, as its name is redacted.
fn argv_summary(argv: &[ArgvEntry]) -> Vec<ArgvSummary> {
    argv.iter()
        .map(|entry| {
            (
                entry.name.as_ref().map(|name| name.expose().clone()),
                entry.path.clone(),
                entry.class.clone(),
                entry.wrapper,
            )
        })
        .collect()
}

fn full_details() -> RecordDetails {
    RecordDetails {
        rewritten_from: Some(Redacted::new(String::from("npm  test"))),
        pipestatus: vec![0, 1],
        signal: Some(String::from("SIGKILL")),
        sandbox_profile: Some(String::from("default:abc123")),
        secrets_injected: vec![String::from("NPM_TOKEN")],
        checkpoint_id: Some(CheckpointId::from_ulid(Ulid::from_u128(9))),
        sandbox_violations: vec![violation(2, 2, 7)],
        decision: Some(RecordDecision {
            verdict: DecisionVerdict::Rewrite,
            source: DecisionSource::Authority,
            rule_id: Some(String::from("exec.ask[0]")),
            decided_by: Some(String::from("Example Authority")),
            latency_ms: 1200,
            hooks: Vec::new(),
        }),
        argv: vec![
            ArgvEntry {
                name: Some(Redacted::new(String::from("env"))),
                path: Some(String::from("/usr/bin/env")),
                class: ArgvClass::Wrapper,
                wrapper: None,
                arguments_complete: true,
            },
            ArgvEntry {
                name: Some(Redacted::new(String::from("npm"))),
                path: Some(String::from("/opt/homebrew/bin/npm")),
                class: ArgvClass::Static,
                wrapper: Some(0),
                arguments_complete: true,
            },
            ArgvEntry {
                name: None,
                path: None,
                class: ArgvClass::Dynamic {
                    reason: String::from("expanded_command_name"),
                },
                wrapper: None,
                arguments_complete: true,
            },
        ],
        network: vec![
            NetworkEntry::new(
                Redacted::new(String::from("registry.npmjs.org")),
                443,
                NetworkResult::Contacted,
            ),
            NetworkEntry::new(
                Redacted::new(String::from("github.com")),
                443,
                NetworkResult::Refused(String::from("approval_required")),
            ),
            // A repeat of the first: written merged, with its count.
            NetworkEntry::new(
                Redacted::new(String::from("registry.npmjs.org")),
                443,
                NetworkResult::Contacted,
            ),
        ],
        unprotected: vec![UnprotectedRoot {
            root: CanonicalPath::new("/code/app").unwrap(),
            reason: UnprotectedReason::ShadowBuilding,
        }],
        attribution: Some(knsh_core::Attribution::Concurrent),
    }
}

/// A violation of record `n` of `session`, from process `pid`.
fn violation(session: u128, n: u64, pid: u32) -> SandboxViolation {
    SandboxViolation {
        at: at(n),
        report: DenialReport {
            tag: DenialTag {
                session_id: session_id(session),
                command: TaggedCommand::Line(record_id(n)),
                rule: "fs.deny[0]".parse().unwrap(),
            },
            process: Redacted::new(String::from("cat")),
            pid,
            operation: String::from("file-read-data"),
            argument: Some(Redacted::new(String::from("/private/etc/hosts"))),
            count: 1,
        },
    }
}

/// The violations stored with record `n`.
fn stored_violations(store: &RecordStore, n: u64) -> Vec<SandboxViolation> {
    store
        .query(Scope::All, RecordQuery::default())
        .unwrap()
        .records
        .into_iter()
        .find(|stored| stored.record.record_id == record_id(n))
        .unwrap()
        .record
        .details
        .sandbox_violations
}

fn output(stdout: &[u8], stderr: &[u8]) -> RecordedOutput {
    RecordedOutput::whole(Redacted::new(stdout.to_vec()), Redacted::new(stderr.to_vec()))
}

fn ids(page: &crate::Page) -> Vec<RecordId> {
    page.records.iter().map(|stored| stored.record.record_id).collect()
}

fn query(store: &RecordStore, scope: Scope, query: RecordQuery) -> Vec<RecordId> {
    ids(&store.query(scope, query).unwrap())
}

// FR-REC-09: a human record keeps only command, cwd, times and exit code, even when the caller supplies more.
#[test]
fn human_record_drops_non_telemetry_fields() {
    let dir = TempDir::new("human");
    let store = open(&dir);
    let human = ExecutionRecord {
        details: full_details(),
        ..record(1, session_id(1), Actor::Human, "ls -la")
    };
    store.write_record(human, output(b"out", b"err")).unwrap();

    let page = store.query(Scope::All, RecordQuery::default()).unwrap();
    let stored = &page.records[0];
    assert_eq!(stored.record.command.expose(), "ls -la");
    assert_eq!(stored.record.cwd.as_path().to_str(), Some("/Users/someone/project"));
    assert_eq!(stored.record.started_at, at(1));
    assert_eq!(stored.record.ended_at, Some(at(2)));
    assert_eq!(stored.record.exit_code, Some(0));
    assert!(stored.record.details.is_empty(), "{:?}", stored.record.details);
    assert_eq!((stored.stdout, stored.stderr), (None, None), "no output for humans");

    // At the storage level too: every non-telemetry column is NULL and no output row exists.
    let raw = Connection::open(&RealFs::new(), &dir.db(), DEFAULT_BUSY_TIMEOUT).unwrap();
    let mut statement = raw
        .prepare(
            "SELECT rewritten_from, pipestatus, signal, sandbox_profile, secrets_injected, checkpoint_id, agent_id, \
             argv, decision, attribution, children, files_changed, network, irreversible, sandbox_violations, \
             (SELECT count(*) FROM outputs) FROM records",
        )
        .unwrap();
    assert_eq!(statement.step().unwrap(), Step::Row);
    for column in 0..15 {
        assert_eq!(
            statement.column_type(column).unwrap(),
            knsh_platform::sqlite::ColumnType::Null,
            "column {column}"
        );
    }
    assert_eq!(statement.column_i64(15).unwrap(), Some(0));

    // An agent record keeps every field it was given.
    let agent_record = ExecutionRecord {
        details: full_details(),
        ..record(2, session_id(2), agent(), "npm test")
    };
    store.write_record(agent_record, output(b"out", b"")).unwrap();
    let page = store
        .query(
            Scope::All,
            RecordQuery {
                session: Some(session_id(2)),
                ..RecordQuery::default()
            },
        )
        .unwrap();
    let stored = &page.records[0];
    assert_eq!(stored.record.actor.agent_id().map(AgentId::as_str), Some("claude-code"));
    let details = &stored.record.details;
    assert_eq!(
        details.rewritten_from.as_ref().map(|t| t.expose().as_str()),
        Some("npm  test")
    );
    assert_eq!(details.pipestatus, [0, 1]);
    assert_eq!(details.signal.as_deref(), Some("SIGKILL"));
    assert_eq!(details.sandbox_profile.as_deref(), Some("default:abc123"));
    assert_eq!(details.secrets_injected, ["NPM_TOKEN"]);
    assert_eq!(details.checkpoint_id, full_details().checkpoint_id);
    assert_eq!(details.sandbox_violations.len(), 1);
    assert!(details.sandbox_violations[0].same_denial(&violation(2, 2, 7)));
    // KNSH-050: the decision object reads back exactly as written.
    assert_eq!(details.decision, full_details().decision);
    // KNSH-052: each argv entry reads back with its path, class, reason and wrapper link.
    assert_eq!(argv_summary(&details.argv), argv_summary(&full_details().argv));
    // KNSH-060: the network list reads back merged, in order, with counts and reasons.
    let network: Vec<(&str, u16, Option<&str>, u32)> = details
        .network
        .iter()
        .map(|entry| {
            (
                entry.host.expose().as_str(),
                entry.port,
                entry.result.reason(),
                entry.count,
            )
        })
        .collect();
    assert_eq!(
        network,
        [
            ("registry.npmjs.org", 443, None, 2),
            ("github.com", 443, Some("approval_required"), 1)
        ]
    );
    // KNSH-079: the roots whose changes were not protected read back as written.
    assert_eq!(details.unprotected, full_details().unprotected);
    // KNSH-081: the attribution reads back as written.
    assert_eq!(details.attribution, Some(knsh_core::Attribution::Concurrent));
    assert_eq!(stored.stdout.map(|info| info.stored), Some(3));
    assert_eq!(stored.stderr.map(|info| info.stored), Some(0));
}

// FR-REC-02, NFR-REL-05: when `write_record` returns, the record is committed: an independent connection sees it.
#[test]
fn record_committed_before_reply() {
    let dir = TempDir::new("commit");
    let store = open(&dir);
    let observer = Connection::open(&RealFs::new(), &dir.db(), DEFAULT_BUSY_TIMEOUT).unwrap();
    let count = || {
        let mut statement = observer
            .prepare("SELECT count(*) FROM records WHERE record_id = ?1")
            .unwrap();
        statement.bind_all(&[Value::Text(&record_id(1).to_string())]).unwrap();
        assert_eq!(statement.step().unwrap(), Step::Row);
        statement.column_i64(0).unwrap()
    };
    assert_eq!(count(), Some(0));
    store
        .write_record(record(1, session_id(1), agent(), "make"), RecordedOutput::default())
        .unwrap();
    assert_eq!(
        count(),
        Some(1),
        "visible to another connection as soon as the write is answered"
    );

    // A failed write (duplicate id) leaves nothing half-written and is reported.
    let error = store
        .write_record(record(1, session_id(1), agent(), "again"), output(b"x", b"y"))
        .unwrap_err();
    assert!(matches!(error, StoreError::Platform(_)), "{error:?}");
    let mut outputs = observer.prepare("SELECT count(*) FROM outputs").unwrap();
    assert_eq!(outputs.step().unwrap(), Step::Row);
    assert_eq!(outputs.column_i64(0).unwrap(), Some(0));
    store.sync().unwrap();
}

// Persistence rule: a database from a newer engine is reported and never written.
#[test]
fn newer_schema_is_not_overwritten() {
    let dir = TempDir::new("newer");
    {
        // The database directly rather than a `RecordStore`: dropping it closes the connection here, so no store
        // thread can still be checkpointing the file while its bytes are compared below.
        let mut database =
            crate::db::Database::open(&RealFs::new(), &dir.db(), effective_uid(), crate::DEFAULT_OUTPUT_CAP).unwrap();
        database
            .write_record(record(1, session_id(1), agent(), "keep me"), RecordedOutput::default())
            .unwrap();
    }
    {
        let raw = Connection::open(&RealFs::new(), &dir.db(), DEFAULT_BUSY_TIMEOUT).unwrap();
        raw.exec(&format!("PRAGMA user_version = {}", schema_version() + 1))
            .unwrap();
    }
    let before = std::fs::read(dir.db()).unwrap();

    let error = try_open(&dir, &clock(), effective_uid(), StoreConfig::default()).unwrap_err();
    assert_eq!(
        error,
        StoreError::NewerSchema {
            found: schema_version() + 1,
            supported: schema_version(),
        }
    );
    assert_eq!(std::fs::read(dir.db()).unwrap(), before, "file bytes unchanged");

    let raw = Connection::open(&RealFs::new(), &dir.db(), DEFAULT_BUSY_TIMEOUT).unwrap();
    let mut statement = raw.prepare("SELECT command FROM records").unwrap();
    assert_eq!(statement.step().unwrap(), Step::Row);
    assert_eq!(statement.column_text(0).unwrap().as_deref(), Some("keep me"));
}

// Engine files are owner-only: an existing database readable by others is refused, not repaired.
#[test]
fn database_must_be_owner_only() {
    let dir = TempDir::new("mode");
    drop(open(&dir));
    let mode = std::fs::metadata(dir.db()).unwrap().permissions().mode() & 0o7777;
    assert_eq!(mode, 0o600, "created owner-only");

    std::fs::set_permissions(dir.db(), std::fs::Permissions::from_mode(0o644)).unwrap();
    let error = try_open(&dir, &clock(), effective_uid(), StoreConfig::default()).unwrap_err();
    assert_eq!(error, StoreError::UnsafeFile);
    let error = try_open(&dir, &clock(), effective_uid() + 1, StoreConfig::default());
    assert!(error.is_err());
}

// FR-REC-06: output beyond the cap keeps head and tail and reports the skipped bytes; ranges read the stored bytes.
#[test]
fn output_over_cap_keeps_head_and_tail() {
    let dir = TempDir::new("cap");
    let store = open_with(
        &dir,
        StoreConfig {
            output_cap: 10,
            ..StoreConfig::default()
        },
    );
    let written: Vec<u8> = (b'a'..=b'z').collect();
    store
        .write_record(record(1, session_id(1), agent(), "yes"), output(&written, b"short"))
        .unwrap();

    let read = |stream, offset, length| {
        store
            .output(
                Scope::All,
                OutputRequest {
                    record_id: record_id(1),
                    stream,
                    offset,
                    length,
                },
            )
            .unwrap()
    };
    let whole = read(OutputStream::Stdout, 0, None);
    assert_eq!(whole.data, b"abcdevwxyz");
    let info = whole.info.unwrap();
    assert_eq!(
        (info.stored, info.original, info.skipped, info.skipped_at),
        (10, 26, 16, 5)
    );
    assert_eq!(read(OutputStream::Stderr, 0, None).data, b"short");
}

#[test]
fn output_ranges_are_clamped() {
    let dir = TempDir::new("range");
    let store = open(&dir);
    store
        .write_record(record(1, session_id(1), agent(), "cat"), output(b"0123456789", b""))
        .unwrap();
    let read = |offset, length| {
        let range = store
            .output(
                Scope::All,
                OutputRequest {
                    record_id: record_id(1),
                    stream: OutputStream::Stdout,
                    offset,
                    length,
                },
            )
            .unwrap();
        (range.offset, range.data)
    };
    assert_eq!(read(2, Some(3)), (2, b"234".to_vec()));
    assert_eq!(read(8, Some(100)), (8, b"89".to_vec()));
    assert_eq!(read(100, Some(5)), (10, Vec::new()));
    assert_eq!(read(0, Some(0)), (0, Vec::new()));

    // Not recorded: empty, no sizes. Unknown record: not found.
    store
        .write_record(record(2, session_id(1), agent(), "true"), RecordedOutput::default())
        .unwrap();
    let range = store
        .output(
            Scope::All,
            OutputRequest {
                record_id: record_id(2),
                stream: OutputStream::Stdout,
                offset: 0,
                length: None,
            },
        )
        .unwrap();
    assert_eq!((range.info, range.data.len()), (None, 0));
    let missing = store.output(
        Scope::All,
        OutputRequest {
            record_id: record_id(99),
            stream: OutputStream::Stdout,
            offset: 0,
            length: None,
        },
    );
    assert_eq!(missing.unwrap_err(), StoreError::RecordNotFound);
}

// KNSH-016: filters by session, by time range (since inclusive, until exclusive) and by command text.
#[test]
fn query_filters_by_session_and_time() {
    let dir = TempDir::new("filter");
    let store = open(&dir);
    let (a, b) = (session_id(1), session_id(2));
    for (n, session, command) in [
        (1, a, "git status"),
        (2, b, "npm test"),
        (3, a, "git commit -m 'x%_'"),
        (4, b, "cargo build"),
        (5, a, "ls"),
    ] {
        store
            .write_record(record(n, session, agent(), command), RecordedOutput::default())
            .unwrap();
    }
    let filtered = |query| self::query(&store, Scope::All, query);

    assert_eq!(
        filtered(RecordQuery::default()),
        (1..=5).map(record_id).collect::<Vec<_>>()
    );
    assert_eq!(
        filtered(RecordQuery {
            session: Some(a),
            ..RecordQuery::default()
        }),
        [record_id(1), record_id(3), record_id(5)]
    );
    assert_eq!(
        filtered(RecordQuery {
            since: Some(at(2)),
            until: Some(at(4)),
            ..RecordQuery::default()
        }),
        [record_id(2), record_id(3)]
    );
    assert_eq!(
        filtered(RecordQuery {
            session: Some(a),
            since: Some(at(2)),
            ..RecordQuery::default()
        }),
        [record_id(3), record_id(5)]
    );
    // Text match is a plain substring: `%` and `_` are not wildcards.
    assert_eq!(
        filtered(RecordQuery {
            text: Some(String::from("git")),
            ..RecordQuery::default()
        }),
        [record_id(1), record_id(3)]
    );
    assert_eq!(
        filtered(RecordQuery {
            text: Some(String::from("%_")),
            ..RecordQuery::default()
        }),
        [record_id(3)]
    );
    assert_eq!(
        filtered(RecordQuery {
            text: Some(String::from("_")),
            ..RecordQuery::default()
        }),
        [record_id(3)]
    );
    assert_eq!(
        filtered(RecordQuery {
            session: Some(session_id(3)),
            ..RecordQuery::default()
        }),
        Vec::<RecordId>::new()
    );
}

// KNSH-016: paging by cursor returns every record exactly once, in `record_id` order, even when records are added
// between pages.
#[test]
fn query_pagination_is_stable() {
    let dir = TempDir::new("page");
    let store = open(&dir);
    for n in 1..=7 {
        store
            .write_record(record(n, session_id(1), agent(), "echo"), RecordedOutput::default())
            .unwrap();
    }
    let page_of = |after| {
        store
            .query(
                Scope::All,
                RecordQuery {
                    after,
                    limit: PageSize::new(3).unwrap(),
                    ..RecordQuery::default()
                },
            )
            .unwrap()
    };
    let first = page_of(None);
    assert_eq!(ids(&first), [record_id(1), record_id(2), record_id(3)]);
    assert_eq!(first.next_cursor, Some(record_id(3)));

    // A new record arrives between pages; it sorts last, so no earlier page shifts.
    store
        .write_record(record(8, session_id(1), agent(), "echo"), RecordedOutput::default())
        .unwrap();
    let second = page_of(first.next_cursor);
    assert_eq!(ids(&second), [record_id(4), record_id(5), record_id(6)]);
    let third = page_of(second.next_cursor);
    assert_eq!(ids(&third), [record_id(7), record_id(8)]);
    assert_eq!(third.next_cursor, None, "last page");

    // Asking the same cursor again gives the same page.
    assert_eq!(ids(&page_of(first.next_cursor)), ids(&second));
    // An exactly full last page also ends with no cursor.
    let exact = store
        .query(
            Scope::All,
            RecordQuery {
                limit: PageSize::new(8).unwrap(),
                ..RecordQuery::default()
            },
        )
        .unwrap();
    assert_eq!((exact.records.len(), exact.next_cursor), (8, None));
}

// Scoping for `agent.sock`: a session-scoped caller never receives another session's records or output, whatever
// filters it sends.
#[test]
fn scoped_query_never_returns_other_sessions() {
    let dir = TempDir::new("scope");
    let store = open(&dir);
    let (own, other) = (session_id(1), session_id(2));
    for (n, session) in [(1, own), (2, other), (3, own), (4, other)] {
        store
            .write_record(record(n, session, agent(), "make"), output(b"secret-ish", b""))
            .unwrap();
    }
    let scope = Scope::Session(own);
    for filter in [
        RecordQuery::default(),
        RecordQuery {
            session: Some(own),
            ..RecordQuery::default()
        },
        RecordQuery {
            text: Some(String::from("make")),
            since: Some(at(0)),
            ..RecordQuery::default()
        },
        RecordQuery {
            after: Some(record_id(1)),
            ..RecordQuery::default()
        },
    ] {
        let page = store.query(scope, filter).unwrap();
        assert!(page.records.iter().all(|stored| stored.record.session_id == own));
    }
    assert_eq!(
        query(&store, scope, RecordQuery::default()),
        [record_id(1), record_id(3)]
    );

    // Asking for another session is refused outright.
    let refused = store.query(
        scope,
        RecordQuery {
            session: Some(other),
            ..RecordQuery::default()
        },
    );
    assert_eq!(refused.unwrap_err(), StoreError::OutOfScope);

    // Another session's output looks exactly like a missing record.
    let output_of = |record| {
        store.output(
            scope,
            OutputRequest {
                record_id: record,
                stream: OutputStream::Stdout,
                offset: 0,
                length: None,
            },
        )
    };
    assert_eq!(output_of(record_id(2)).unwrap_err(), StoreError::RecordNotFound);
    assert_eq!(output_of(record_id(1)).unwrap().data, b"secret-ish");
}

#[test]
fn sessions_are_written_and_updated() {
    let dir = TempDir::new("sessions");
    let store = open(&dir);
    let mut session = Session::new(SessionSpec {
        session_id: session_id(1),
        actor: agent(),
        profile: ProfileName::new("default").unwrap(),
        envelope: true,
        recording: None,
        parent_session_id: None,
    })
    .unwrap();
    store.write_session(&session, at(0)).unwrap();
    session.apply(knsh_core::Transition::Pause).unwrap();
    store.write_session(&session, at(5)).unwrap();

    let raw = Connection::open(&RealFs::new(), &dir.db(), DEFAULT_BUSY_TIMEOUT).unwrap();
    let mut statement = raw
        .prepare("SELECT actor_kind, agent_id, state, created_at < updated_at FROM sessions")
        .unwrap();
    assert_eq!(statement.step().unwrap(), Step::Row);
    assert_eq!(statement.column_text(0).unwrap().as_deref(), Some("agent"));
    assert_eq!(statement.column_text(1).unwrap().as_deref(), Some("claude-code"));
    assert_eq!(statement.column_text(2).unwrap().as_deref(), Some("paused"));
    assert_eq!(statement.column_i64(3).unwrap(), Some(1));
    assert_eq!(statement.step().unwrap(), Step::Done, "one row per session");
}

#[test]
fn secret_names_that_could_split_are_refused() {
    let dir = TempDir::new("names");
    let store = open(&dir);
    for bad in ["", "A\nB"] {
        let bad_record = ExecutionRecord {
            details: RecordDetails {
                secrets_injected: vec![bad.to_owned()],
                ..RecordDetails::default()
            },
            ..record(1, session_id(1), agent(), "deploy")
        };
        assert_eq!(
            store.write_record(bad_record, RecordedOutput::default()),
            Err(StoreError::InvalidRecord("secrets_injected"))
        );
    }
}

// --- Retention and forget (KNSH-017) ---

const DAY_MICROS: u64 = 86_400 * 1_000_000;

/// Moves the wall clock to `days` days and `seconds` seconds after the base instant. Only the wall clock moves, so no
/// automatic pass falls due: each test runs its pass explicitly and reads its report.
fn set_days_after_base(clock: &FakeClock, days: u64, seconds: u64) {
    clock.set_wall(at(seconds).as_unix_micros() + days * DAY_MICROS);
}

/// One integer from constant `sql`, read through an independent connection.
fn count(dir: &TempDir, sql: &str) -> i64 {
    let raw = Connection::open(&RealFs::new(), &dir.db(), DEFAULT_BUSY_TIMEOUT).unwrap();
    let mut statement = raw.prepare(sql).unwrap();
    assert_eq!(statement.step().unwrap(), Step::Row);
    statement.column_i64(0).unwrap().unwrap()
}

/// The bytes the store's live pages take, read independently of the store: its pages less those on the free list.
fn used_bytes(dir: &TempDir) -> i64 {
    count(
        dir,
        "SELECT ((SELECT page_count FROM pragma_page_count) - (SELECT freelist_count FROM pragma_freelist_count)) \
         * (SELECT page_size FROM pragma_page_size)",
    )
}

/// Every record ID left in the store, in order.
fn all_ids(store: &RecordStore) -> Vec<RecordId> {
    query(
        store,
        Scope::All,
        RecordQuery {
            limit: PageSize::new(1_000).unwrap(),
            ..RecordQuery::default()
        },
    )
}

/// Writes records `ns` of `session`, each with a stdout and stderr row.
fn write_records(store: &RecordStore, session: SessionId, ns: impl IntoIterator<Item = u64>) {
    for n in ns {
        store
            .write_record(
                record(n, session, agent(), &format!("cmd-{n}")),
                output(format!("out-{n}").as_bytes(), b"err"),
            )
            .unwrap();
    }
}

fn session_with_profile(n: u128, profile: &str) -> Session {
    Session::new(SessionSpec {
        session_id: session_id(n),
        actor: agent(),
        profile: ProfileName::new(profile).unwrap(),
        envelope: true,
        recording: None,
        parent_session_id: None,
    })
    .unwrap()
}

fn days(n: u32) -> RetentionDays {
    RetentionDays::new(n).unwrap()
}

// FR-REC-07: records older than the retention period are deleted, judged by the injected clock; younger ones stay.
#[test]
fn deletes_records_older_than_retention() {
    let dir = TempDir::new("expire");
    let clock = clock();
    let store = open_at(&dir, &clock, StoreConfig::default());
    write_records(&store, session_id(1), 1..=8);

    // At the base instant nothing is 30 days old.
    assert_eq!(store.run_retention().unwrap(), RetentionReport::default());
    assert_eq!(all_ids(&store).len(), 8);

    // 30 days and 5 seconds later, records started before second 5 have expired; the one at second 5 is exactly 30
    // days old and stays (the cutoff is exclusive).
    set_days_after_base(&clock, 30, 5);
    let report = store.run_retention().unwrap();
    assert_eq!(report, RetentionReport { expired: 4, trimmed: 0 });
    assert_eq!(all_ids(&store), (5..=8).map(record_id).collect::<Vec<_>>());

    // A clock that cannot be read deletes nothing: retention never guesses the time.
    clock.set_wall(u64::MAX);
    let error = store.run_retention().unwrap_err();
    assert!(matches!(error, StoreError::Platform(_)), "{error:?}");
    assert_eq!(all_ids(&store).len(), 4);
}

// FR-REC-07: no orphaned output. Deleting a record deletes its stored streams.
#[test]
fn retention_deletes_output_blobs_with_records() {
    let dir = TempDir::new("expire-output");
    let clock = clock();
    let store = open_settled(&dir, &clock, StoreConfig::default());
    write_records(&store, session_id(1), 1..=4);
    assert_eq!(count(&dir, "SELECT count(*) FROM outputs"), 8);

    set_days_after_base(&clock, 30, 3);
    assert_eq!(store.run_retention().unwrap().expired, 2);
    assert_eq!(
        count(&dir, "SELECT count(*) FROM outputs"),
        4,
        "two streams per remaining record"
    );
    assert_eq!(
        count(
            &dir,
            "SELECT count(*) FROM outputs WHERE record_id NOT IN (SELECT record_id FROM records)"
        ),
        0
    );
}

// FR-REC-07: denials and approvals are kept no longer than other records.
#[test]
fn denials_and_approvals_follow_the_same_retention() {
    let dir = TempDir::new("expire-decisions");
    let clock = clock();
    let store = open_settled(&dir, &clock, StoreConfig::default());
    write_records(&store, session_id(1), 1..=2);
    {
        // Mark the records as a denial and an approval directly, in the stored form the supervisor writes.
        let decided = |verdict, source| {
            encode_decision(&RecordDecision {
                verdict,
                source,
                rule_id: None,
                decided_by: None,
                latency_ms: 1,
                hooks: Vec::new(),
            })
            .unwrap()
        };
        let deny = decided(DecisionVerdict::Deny, DecisionSource::Rule);
        let approved = decided(DecisionVerdict::Allow, DecisionSource::User);
        let raw = Connection::open(&RealFs::new(), &dir.db(), DEFAULT_BUSY_TIMEOUT).unwrap();
        raw.execute(
            "UPDATE records SET decision = ?1 WHERE record_id = ?2",
            &[Value::Text(&deny), Value::Text(&record_id(1).to_string())],
        )
        .unwrap();
        raw.execute(
            "UPDATE records SET decision = ?1 WHERE record_id = ?2",
            &[Value::Text(&approved), Value::Text(&record_id(2).to_string())],
        )
        .unwrap();
    }
    set_days_after_base(&clock, 31, 0);
    assert_eq!(store.run_retention().unwrap().expired, 2);
    assert_eq!(count(&dir, "SELECT count(*) FROM records"), 0);
}

// KNSH-052: a stored `argv` the engine could not have written (not JSON, an unknown class, a reason on a static
// entry, a dynamic entry without one, a wrapper link that does not point back) is reported as corrupt, never repaired
// or guessed at.
#[test]
fn corrupt_argv_is_reported_not_repaired() {
    let dir = TempDir::new("corrupt-argv");
    let store = open(&dir);
    let agent_record = ExecutionRecord {
        details: full_details(),
        ..record(1, session_id(1), agent(), "npm test")
    };
    store.write_record(agent_record, RecordedOutput::default()).unwrap();
    let entry = |class: &str, reason: &str, wrapper: &str| {
        format!(
            r#"[{{"name":null,"path":null,"class":"{class}","reason":{reason},"wrapper":{wrapper},"arguments_complete":true}}]"#
        )
    };
    for bad in [
        "not json".to_owned(),
        "{}".to_owned(),
        entry("magic", "null", "null"),
        entry("static", r#""eval""#, "null"),
        entry("dynamic", "null", "null"),
        entry("dynamic", r#""""#, "null"),
        entry("static", "null", "0"),
    ] {
        {
            let raw = Connection::open(&RealFs::new(), &dir.db(), DEFAULT_BUSY_TIMEOUT).unwrap();
            raw.execute(
                "UPDATE records SET argv = ?1 WHERE record_id = ?2",
                &[Value::Text(&bad), Value::Text(&record_id(1).to_string())],
            )
            .unwrap();
        }
        let read = store.query(Scope::All, RecordQuery::default());
        assert!(matches!(read, Err(StoreError::Corrupt)), "{bad}");
    }
}

// KNSH-081: a stored `attribution` the engine could not have written is reported as corrupt, never guessed at.
#[test]
fn corrupt_attribution_is_reported_not_repaired() {
    let dir = TempDir::new("corrupt-attribution");
    let store = open(&dir);
    let agent_record = ExecutionRecord {
        details: full_details(),
        ..record(1, session_id(1), agent(), "npm test")
    };
    store.write_record(agent_record, RecordedOutput::default()).unwrap();
    {
        let raw = Connection::open(&RealFs::new(), &dir.db(), DEFAULT_BUSY_TIMEOUT).unwrap();
        raw.execute(
            "UPDATE records SET attribution = 'human' WHERE record_id = ?1",
            &[Value::Text(&record_id(1).to_string())],
        )
        .unwrap();
    }
    let read = store.query(Scope::All, RecordQuery::default());
    assert!(matches!(read, Err(StoreError::Corrupt)));
}

// FR-REC-07, configurability: each record is kept for the period of its own session's profile; profiles without an
// override, and records whose session is unknown, use the default.
#[test]
fn per_profile_retention_overrides_default() {
    let dir = TempDir::new("profiles");
    let clock = clock();
    let mut retention = Retention::default();
    retention
        .per_profile
        .insert(ProfileName::new("short").unwrap(), days(1));
    retention
        .per_profile
        .insert(ProfileName::new("long").unwrap(), days(90));
    let store = open_settled(
        &dir,
        &clock,
        StoreConfig {
            retention,
            ..StoreConfig::default()
        },
    );
    for (n, profile) in [(1, "short"), (2, "default"), (3, "long")] {
        store.write_session(&session_with_profile(n, profile), at(0)).unwrap();
    }
    // Record n belongs to session n; record 4's session has no row.
    for n in 1..=4u64 {
        write_records(&store, session_id(u128::from(n)), [n]);
    }

    set_days_after_base(&clock, 10, 0);
    assert_eq!(store.run_retention().unwrap().expired, 1);
    assert_eq!(
        all_ids(&store),
        [record_id(2), record_id(3), record_id(4)],
        "only the 1-day profile"
    );

    set_days_after_base(&clock, 31, 0);
    assert_eq!(store.run_retention().unwrap().expired, 2);
    assert_eq!(
        all_ids(&store),
        [record_id(3)],
        "the 90-day profile outlives the default"
    );

    set_days_after_base(&clock, 91, 0);
    assert_eq!(store.run_retention().unwrap().expired, 1);
    assert_eq!(all_ids(&store), Vec::<RecordId>::new());
}

// FR-REC-07: over the size limit, the oldest records go first, until the store is under the limit.
#[test]
fn size_limit_deletes_oldest_first() {
    let dir = TempDir::new("size");
    let clock = clock();
    let blob = |n: u64| -> Vec<u8> { (0..64 * 1024u64).map(|i| ((i * 31 + n) % 251) as u8).collect() };
    let used_with_all = {
        let store = open_at(&dir, &clock, StoreConfig::default());
        for n in 1..=10 {
            let stdout = Redacted::new(blob(n));
            let recorded = RecordedOutput {
                stdout: Some(knsh_core::CappedOutput::whole(stdout)),
                stderr: None,
            };
            store
                .write_record(record(n, session_id(1), agent(), "build"), recorded)
                .unwrap();
        }
        store.sync().unwrap();
        used_bytes(&dir)
    };
    // Room for all but about three records.
    let max_bytes = u64::try_from(used_with_all).unwrap() - 3 * 64 * 1024 - 1024;
    let store = open_at(
        &dir,
        &clock,
        StoreConfig {
            retention: Retention {
                max_bytes,
                ..Retention::default()
            },
            ..StoreConfig::default()
        },
    );
    // The pass that ran at open may already have trimmed; this one finishes it (or joins it) and finds no excess.
    store.run_retention().unwrap();
    assert_eq!(
        store.run_retention().unwrap(),
        RetentionReport::default(),
        "already under the limit"
    );

    let left = all_ids(&store);
    let first = (1..=10).find(|n| left.first() == Some(&record_id(*n))).unwrap();
    assert_eq!(
        left,
        (first..=10).map(record_id).collect::<Vec<_>>(),
        "oldest deleted first"
    );
    assert!(
        (4..=6).contains(&first),
        "about three records deleted, not more: first kept is {first}"
    );
    let used = used_bytes(&dir);
    assert!(u64::try_from(used).unwrap() <= max_bytes, "{used} > {max_bytes}");
    assert_eq!(
        count(&dir, "SELECT count(*) FROM outputs"),
        i64::try_from(left.len()).unwrap(),
        "no orphaned output"
    );
}

// A pass deletes in batches of RETENTION_BATCH and keeps going until nothing expired is left.
#[test]
fn retention_runs_in_batches_until_done() {
    let dir = TempDir::new("batches");
    let clock = clock();
    let store = open_settled(&dir, &clock, StoreConfig::default());
    let total = u64::from(crate::RETENTION_BATCH) * 2 + 7;
    {
        // Many records quickly: one transaction on a side connection rather than one fsync per record.
        let mut raw = Connection::open(&RealFs::new(), &dir.db(), DEFAULT_BUSY_TIMEOUT).unwrap();
        let transaction = raw.transaction().unwrap();
        let session = session_id(1).to_string();
        for n in 1..=total {
            transaction
                .execute(
                    "INSERT INTO records (record_id, session_id, actor_kind, command, cwd, started_at) \
                     VALUES (?1, ?2, 'human', 'ls', X'2F', ?3)",
                    &[
                        Value::Text(&record_id(n).to_string()),
                        Value::Text(&session),
                        Value::Integer(i64::try_from(at(n).as_unix_micros()).unwrap()),
                    ],
                )
                .unwrap();
        }
        transaction.commit().unwrap();
    }
    clock.set_wall(at(0).as_unix_micros() + 40 * DAY_MICROS);
    assert_eq!(store.run_retention().unwrap().expired, total);
    assert_eq!(count(&dir, "SELECT count(*) FROM records"), 0);
}

// FR-REC-10, NFR-PRIV-03: forgetting a session deletes its records and their output, and nothing else.
#[test]
fn forget_session_deletes_records_and_blobs() {
    let dir = TempDir::new("forget");
    let store = open(&dir);
    write_records(&store, session_id(1), [1, 3, 5]);
    write_records(&store, session_id(2), [2, 4]);

    let selector = ForgetSelector::new(Some(session_id(1)), None).unwrap();
    assert_eq!(store.forget(selector).unwrap(), 3);
    assert_eq!(all_ids(&store), [record_id(2), record_id(4)]);
    assert_eq!(
        count(&dir, "SELECT count(*) FROM outputs"),
        4,
        "only session 2's streams remain"
    );
    // Nothing matched any more: forgetting again deletes nothing.
    assert_eq!(store.forget(selector).unwrap(), 0);
}

// FR-REC-10: `since` is inclusive, and combined with a session both must match.
#[test]
fn forget_since_deletes_records_started_from_that_instant() {
    let dir = TempDir::new("forget-since");
    let store = open(&dir);
    write_records(&store, session_id(1), 1..=4);
    write_records(&store, session_id(2), 5..=6);

    let both = ForgetSelector::new(Some(session_id(1)), Some(at(3))).unwrap();
    assert_eq!(store.forget(both).unwrap(), 2);
    assert_eq!(
        all_ids(&store),
        [record_id(1), record_id(2), record_id(5), record_id(6)]
    );

    let since = ForgetSelector::new(None, Some(at(2))).unwrap();
    assert_eq!(store.forget(since).unwrap(), 3);
    assert_eq!(all_ids(&store), [record_id(1)]);
    assert_eq!(count(&dir, "SELECT count(*) FROM outputs"), 2);
}

// Failure safety: if any delete fails, the whole forget is rolled back and nothing is deleted.
#[test]
fn forget_is_atomic_on_error() {
    let dir = TempDir::new("forget-atomic");
    let store = open(&dir);
    write_records(&store, session_id(1), 1..=3);
    {
        // Make deleting the second record fail half way through the statement.
        let raw = Connection::open(&RealFs::new(), &dir.db(), DEFAULT_BUSY_TIMEOUT).unwrap();
        raw.exec(&format!(
            "CREATE TRIGGER refuse BEFORE DELETE ON records WHEN old.record_id = '{}' \
             BEGIN SELECT RAISE(ABORT, 'refused'); END",
            record_id(2)
        ))
        .unwrap();
    }
    let error = store
        .forget(ForgetSelector::new(Some(session_id(1)), None).unwrap())
        .unwrap_err();
    assert!(matches!(error, StoreError::Platform(_)), "{error:?}");
    assert_eq!(all_ids(&store), (1..=3).map(record_id).collect::<Vec<_>>());
    assert_eq!(count(&dir, "SELECT count(*) FROM outputs"), 6, "every stream kept");
}

/// Polls `done` for up to five seconds: for passes the store thread starts on its own, which no call waits for.
fn eventually(mut done: impl FnMut() -> bool) -> bool {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while std::time::Instant::now() < deadline {
        if done() {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    false
}

// FR-REC-07: retention runs when the store opens, without being asked.
#[test]
fn retention_runs_at_start() {
    let dir = TempDir::new("at-start");
    drop({
        let store = open(&dir);
        write_records(&store, session_id(1), 1..=3);
        store.sync().unwrap();
        store
    });
    // Reopened 40 days later: the pass at open deletes every record, with no call to `run_retention`.
    let clock = clock();
    set_days_after_base(&clock, 40, 0);
    let store = open_at(&dir, &clock, StoreConfig::default());
    assert!(
        eventually(|| all_ids(&store).is_empty()),
        "the pass at open did not run"
    );
    assert_eq!(count(&dir, "SELECT count(*) FROM outputs"), 0);
}

// FR-REC-07: retention runs periodically while the store is open, timed by the injected monotonic clock, and writes
// keep being served.
#[test]
fn retention_runs_periodically() {
    let dir = TempDir::new("periodic");
    let clock = clock();
    let store = open_at(&dir, &clock, StoreConfig::default());
    write_records(&store, session_id(1), 1..=3);
    set_days_after_base(&clock, 40, 0);
    store.sync().unwrap();
    assert_eq!(all_ids(&store).len(), 3, "no pass is due before the interval elapses");

    // One interval later on the monotonic clock: the next time the thread wakes (here, on the next job), a pass is
    // due and starts by itself.
    clock.advance(crate::RETENTION_INTERVAL);
    assert!(eventually(|| all_ids(&store).is_empty()), "no periodic pass ran");
    // The store still takes writes after its passes.
    write_records(&store, session_id(1), [100]);
    assert_eq!(all_ids(&store), [record_id(100)]);
}

// KNSH-047 (FR-SBX-08): a denial reported after a record was written is appended to it; a repeat only adds to the
// count, and the list stays bounded.
#[test]
fn appends_late_violations_to_a_finished_record() {
    let dir = TempDir::new("violations");
    let store = open(&dir);
    store
        .write_record(record(1, session_id(1), agent(), "cat x"), RecordedOutput::default())
        .unwrap();
    assert!(stored_violations(&store, 1).is_empty());

    assert!(
        store
            .append_sandbox_violations(session_id(1), record_id(1), vec![violation(1, 1, 7)])
            .unwrap()
    );
    let mut repeat = violation(1, 1, 7);
    repeat.report.count = 4;
    assert!(
        store
            .append_sandbox_violations(session_id(1), record_id(1), vec![repeat, violation(1, 1, 8)])
            .unwrap()
    );
    let kept = stored_violations(&store, 1);
    assert_eq!(kept.len(), 2);
    assert_eq!(kept[0].report.count, 5);
    assert_eq!(kept[1].report.pid, 8);

    let many = (0..u32::try_from(MAX_VIOLATIONS_PER_RECORD).unwrap() + 10)
        .map(|pid| violation(1, 1, 1_000 + pid))
        .collect();
    assert!(
        store
            .append_sandbox_violations(session_id(1), record_id(1), many)
            .unwrap()
    );
    assert_eq!(stored_violations(&store, 1).len(), MAX_VIOLATIONS_PER_RECORD);
}

// KNSH-047: a violation is attached only to the agent record of the session its tag names, never elsewhere.
#[test]
fn refuses_violations_for_records_the_tag_does_not_name() {
    let dir = TempDir::new("violations-scope");
    let store = open(&dir);
    store
        .write_record(record(1, session_id(1), agent(), "cat x"), RecordedOutput::default())
        .unwrap();
    store
        .write_record(record(2, session_id(1), Actor::Human, "ls"), RecordedOutput::default())
        .unwrap();
    // Another session's record, a human record and an unknown record.
    for (session, n) in [(2, 1), (1, 2), (1, 3)] {
        assert!(
            !store
                .append_sandbox_violations(session_id(session), record_id(n), vec![violation(session, n, 7)])
                .unwrap(),
            "session {session} record {n}"
        );
    }
    assert!(stored_violations(&store, 1).is_empty());
    assert!(stored_violations(&store, 2).is_empty());
}
