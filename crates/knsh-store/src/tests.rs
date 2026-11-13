//! Behaviour of the record store against the real system SQLite, each test in its own temporary directory.

use std::os::unix::fs::PermissionsExt;

use knsh_core::{
    Actor, AgentId, CanonicalPath, CheckpointId, ExecutionRecord, OutputStream, ProfileName, RecordDetails, RecordId,
    Redacted, Session, SessionId, SessionSpec, Timestamp, Ulid,
};
use knsh_platform::macos::{RealFs, effective_uid};
use knsh_platform::sqlite::{Connection, DEFAULT_BUSY_TIMEOUT, Step, Value};

use crate::testing::TempDir;
use crate::{
    OutputRequest, PageSize, RecordQuery, RecordStore, RecordedOutput, Scope, StoreConfig, StoreError, schema_version,
};

const BASE_MILLIS: u64 = 1_794_506_531_000;

fn open(dir: &TempDir) -> RecordStore {
    open_with(dir, StoreConfig::default())
}

fn open_with(dir: &TempDir, config: StoreConfig) -> RecordStore {
    RecordStore::open(&RealFs::new(), &dir.db(), effective_uid(), config).unwrap()
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

fn full_details() -> RecordDetails {
    RecordDetails {
        rewritten_from: Some(Redacted::new(String::from("npm  test"))),
        pipestatus: vec![0, 1],
        signal: Some(String::from("SIGKILL")),
        sandbox_profile: Some(String::from("default:abc123")),
        secrets_injected: vec![String::from("NPM_TOKEN")],
        checkpoint_id: Some(CheckpointId::from_ulid(Ulid::from_u128(9))),
    }
}

fn output(stdout: &[u8], stderr: &[u8]) -> RecordedOutput {
    RecordedOutput {
        stdout: Some(Redacted::new(stdout.to_vec())),
        stderr: Some(Redacted::new(stderr.to_vec())),
    }
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

    let error = RecordStore::open(&RealFs::new(), &dir.db(), effective_uid(), StoreConfig::default()).unwrap_err();
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
    let error = RecordStore::open(&RealFs::new(), &dir.db(), effective_uid(), StoreConfig::default()).unwrap_err();
    assert_eq!(error, StoreError::UnsafeFile);
    let error = RecordStore::open(&RealFs::new(), &dir.db(), effective_uid() + 1, StoreConfig::default());
    assert!(error.is_err());
}

// FR-REC-06: output beyond the cap keeps head and tail and reports the skipped bytes; ranges read the stored bytes.
#[test]
fn output_over_cap_keeps_head_and_tail() {
    let dir = TempDir::new("cap");
    let store = open_with(&dir, StoreConfig { output_cap: 10 });
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
